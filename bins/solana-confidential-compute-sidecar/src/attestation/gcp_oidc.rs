//! Google Cloud Confidential Space launcher OIDC attestation client.
//!
//! @spec SCC-SIDECAR-003

use std::future::Future;
use std::pin::Pin;
#[cfg(unix)]
use std::time::Duration;

use base64::Engine;
use reqwest::Client;
use solana_confidential_compute_core::types::EnclaveType;
use solana_sdk::pubkey::Pubkey;

use super::{AttestationProvider, AttestationReport};
use crate::error::SidecarError;

const DEFAULT_TEE_SOCKET: &str = "/run/container_launcher/teeserver.sock";
const TOKEN_URL: &str = "http://localhost/v1/token";
const DEFAULT_AUDIENCE: &str = "solana-confidential-compute-verifier";

pub struct GcpOidcProvider {
    socket_path: String,
    audience: String,
    /// `None` leaves measurement enforcement to the on-chain allowlist.
    /// @spec SCC-SIDECAR-003
    expected_image_digest: Option<[u8; 32]>,
}

impl GcpOidcProvider {
    /// `socket_path` overrides the launcher Unix socket, never an HTTP endpoint.
    pub fn new(socket_path: Option<&str>, audience: Option<&str>) -> Self {
        Self {
            socket_path: socket_path.unwrap_or(DEFAULT_TEE_SOCKET).to_string(),
            audience: audience.unwrap_or(DEFAULT_AUDIENCE).to_string(),
            expected_image_digest: None,
        }
    }

    /// `image_digest` is `SOLANA_CC_CONTAINER_IMAGE_DIGEST` (`sha256:` + 64 hex).
    /// A set value that does not parse fails closed.
    /// @spec SCC-SIDECAR-003
    pub fn with_image_digest(
        socket_path: Option<&str>,
        audience: Option<&str>,
        image_digest: Option<&str>,
    ) -> Result<Self, SidecarError> {
        let expected_image_digest = match image_digest {
            Some(raw) => Some(parse_image_digest_config(raw)?),
            None => None,
        };
        Ok(Self {
            socket_path: socket_path.unwrap_or(DEFAULT_TEE_SOCKET).to_string(),
            audience: audience.unwrap_or(DEFAULT_AUDIENCE).to_string(),
            expected_image_digest,
        })
    }
}

impl Default for GcpOidcProvider {
    fn default() -> Self {
        Self::new(None, None)
    }
}

/// Unpadded base64url of the workload pubkey and the slot hash.
///
/// These two strings are the launcher `nonces` array and the token's
/// `eat_nonce` array. There is no UTF-8 or hex fallback.
/// @spec SCC-SIDECAR-003 SCC-JWT-005
pub fn mode_a_eat_nonces(workload_signer: &Pubkey, slot_hash: &[u8; 32]) -> (String, String) {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    (
        engine.encode(workload_signer.as_ref()),
        engine.encode(slot_hash),
    )
}

/// Unauthenticated claims preflight before submitting a Mode A registration.
///
/// This does not verify RS256. Only successful live on-chain verification can
/// establish a signing session; dry-run is simulation and cannot authorize signing.
///
/// This helper expects the default audience `solana-confidential-compute-verifier`; the provider checks its configured audience.
/// When `expected_image_digest` is unset, the on-chain allowlist stays the only measurement gate.
/// @spec SCC-SIDECAR-003
pub fn validate_gcp_token(
    jwt: &str,
    workload_signer: &Pubkey,
    slot_hash: &[u8; 32],
    expected_image_digest: Option<[u8; 32]>,
) -> Result<(), SidecarError> {
    validate_gcp_token_for_audience(
        jwt,
        workload_signer,
        slot_hash,
        expected_image_digest,
        DEFAULT_AUDIENCE,
    )
}

fn validate_gcp_token_for_audience(
    jwt: &str,
    workload_signer: &Pubkey,
    slot_hash: &[u8; 32],
    expected_image_digest: Option<[u8; 32]>,
    audience: &str,
) -> Result<(), SidecarError> {
    let view = solana_confidential_compute_crypto::jwt::JwtView::parse(jwt).map_err(|e| {
        SidecarError::AttestationError(format!("Invalid JWT returned by launcher: {e:?}"))
    })?;
    let claims = solana_confidential_compute_crypto::jwt::parse_google_claims_b64(view.payload_b64)
        .map_err(|e| {
            SidecarError::AttestationError(format!("Invalid Google claims in JWT: {e:?}"))
        })?;
    solana_confidential_compute_crypto::jwt::enforce_google_policy(&claims, None).map_err(|e| {
        SidecarError::AttestationError(format!("Invalid Confidential Space claims: {e:?}"))
    })?;
    if claims.aud() != audience.as_bytes() {
        return Err(SidecarError::AttestationError(
            "Launcher token audience does not match requested audience".to_string(),
        ));
    }
    enforce_image_digest(&claims.image_digest, expected_image_digest)?;
    let raw = claims.decode_mode_a_binding().map_err(|_| {
        SidecarError::AttestationError("Launcher token eat_nonce is not a Mode A pair".to_string())
    })?;
    if raw[..32] != workload_signer.to_bytes() || raw[32..] != *slot_hash {
        return Err(SidecarError::AttestationError(
            "Launcher token eat_nonce does not bind this key and slot hash".to_string(),
        ));
    }
    Ok(())
}

/// When `expected` is set, the token `image_digest` must match or attest fails closed.
/// @spec SCC-SIDECAR-003
fn enforce_image_digest(
    token_digest: &[u8; 32],
    expected: Option<[u8; 32]>,
) -> Result<(), SidecarError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if token_digest != &expected {
        return Err(SidecarError::AttestationError(
            "token image_digest does not match SOLANA_CC_CONTAINER_IMAGE_DIGEST".to_string(),
        ));
    }
    Ok(())
}

fn parse_image_digest_config(raw: &str) -> Result<[u8; 32], SidecarError> {
    let Some(hex) = raw.strip_prefix("sha256:") else {
        return Err(SidecarError::InvalidConfig(
            "SOLANA_CC_CONTAINER_IMAGE_DIGEST must be sha256: followed by 64 hex characters"
                .to_string(),
        ));
    };
    if hex.len() != 64 {
        return Err(SidecarError::InvalidConfig(
            "SOLANA_CC_CONTAINER_IMAGE_DIGEST must be sha256: followed by 64 hex characters"
                .to_string(),
        ));
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, SidecarError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(SidecarError::InvalidConfig(
            "SOLANA_CC_CONTAINER_IMAGE_DIGEST must be sha256: followed by 64 hex characters"
                .to_string(),
        )),
    }
}

/// Build the launcher request without sending it.
/// See Google's Confidential Space external-resource token API.
pub fn token_request(
    client: &Client,
    audience: &str,
    nonce0: &str,
    nonce1: &str,
) -> Result<reqwest::Request, SidecarError> {
    client
        .post(TOKEN_URL)
        .json(&serde_json::json!({
            "audience": audience,
            "token_type": "OIDC",
            "nonces": [nonce0, nonce1],
        }))
        .build()
        .map_err(|e| SidecarError::MetadataError(format!("Failed to build launcher request: {e}")))
}

#[cfg(unix)]
fn launcher_client(socket_path: &str) -> Result<Client, SidecarError> {
    Client::builder()
        .unix_socket(socket_path)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| SidecarError::MetadataError(format!("Failed to build launcher client: {e}")))
}

#[cfg(not(unix))]
fn launcher_client(_socket_path: &str) -> Result<Client, SidecarError> {
    Err(SidecarError::InvalidConfig(
        "Confidential Space attestation requires a Unix launcher socket".to_string(),
    ))
}

impl AttestationProvider for GcpOidcProvider {
    fn enclave_type(&self) -> EnclaveType {
        EnclaveType::GcpConfidentialSpace
    }

    fn request_attestation<'a>(
        &'a self,
        workload_signer: &'a Pubkey,
        slot_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<AttestationReport, SidecarError>> + Send + 'a>> {
        Box::pin(async move {
            let (nonce0, nonce1) = mode_a_eat_nonces(workload_signer, slot_hash);
            let client = launcher_client(&self.socket_path)?;
            let request = token_request(&client, &self.audience, &nonce0, &nonce1)?;
            let response = client.execute(request).await.map_err(|e| {
                SidecarError::MetadataError(format!("Launcher request failed: {e}"))
            })?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(SidecarError::MetadataError(format!(
                    "Confidential Space launcher returned HTTP {status}: {body}"
                )));
            }

            let jwt = response.text().await.map_err(|e| {
                SidecarError::MetadataError(format!("Failed to read launcher JWT response: {e}"))
            })?;

            validate_gcp_token_for_audience(
                &jwt,
                workload_signer,
                slot_hash,
                self.expected_image_digest,
                &self.audience,
            )?;

            Ok(AttestationReport::GcpJwt { jwt })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_provider_uses_confidential_space_launcher() {
        let provider = GcpOidcProvider::default();
        assert_eq!(
            provider.socket_path,
            "/run/container_launcher/teeserver.sock"
        );
        assert_eq!(provider.audience, "solana-confidential-compute-verifier");
    }

    #[test]
    fn nonce_array_is_two_unpadded_base64url_values() {
        let signer = Pubkey::new_from_array([0x80; 32]);
        let slot_hash = [0x5au8; 32];
        let (n0, n1) = mode_a_eat_nonces(&signer, &slot_hash);
        assert_eq!(n0.len(), 43);
        assert_eq!(n1.len(), 43);
        assert!(!n0.contains('='));
        assert!(!n1.contains('='));
        assert!(!n0.contains('+') && !n0.contains('/'));

        let request = token_request(
            &Client::new(),
            "solana-confidential-compute-verifier",
            &n0,
            &n1,
        )
        .expect("build");
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().as_str(), TOKEN_URL);
        assert_eq!(request.headers()["content-type"], "application/json");
        let body: serde_json::Value =
            serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "audience": "solana-confidential-compute-verifier", "token_type": "OIDC", "nonces": [n0, n1],
            })
        );
    }

    fn token(signer: &Pubkey, slot_hash: &[u8; 32], digest_hex: &str) -> String {
        let (n0, n1) = mode_a_eat_nonces(signer, slot_hash);
        let payload = format!(
            r#"{{"aud":"solana-confidential-compute-verifier","dbgstat":"disabled-since-boot","eat_nonce":["{n0}","{n1}"],"exp":4102444800,"iat":1700000000,"iss":"https://confidentialcomputing.googleapis.com","secboot":true,"sub":"s","submods":{{"container":{{"image_digest":"sha256:{digest_hex}"}}}}}}"#
        );
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(r#"{"alg":"RS256","kid":"teton-test","typ":"JWT"}"#);
        let body = engine.encode(payload);
        format!("{header}.{body}.e30")
    }

    #[test]
    fn unset_image_digest_keeps_the_on_chain_allowlist() {
        let signer = Pubkey::new_from_array([0x80; 32]);
        let slot_hash = [0x5au8; 32];
        let digest = "ab".repeat(32);
        let jwt = token(&signer, &slot_hash, &digest);
        validate_gcp_token(&jwt, &signer, &slot_hash, None).expect("unset digest");
    }

    #[test]
    fn image_digest_must_match_when_the_flag_is_set() {
        let signer = Pubkey::new_from_array([0x80; 32]);
        let slot_hash = [0x5au8; 32];
        let digest = "ab".repeat(32);
        let jwt = token(&signer, &slot_hash, &digest);
        let expected = parse_image_digest_config(&format!("sha256:{digest}")).expect("parse");
        validate_gcp_token(&jwt, &signer, &slot_hash, Some(expected)).expect("match");

        let other =
            parse_image_digest_config(&format!("sha256:{}", "11".repeat(32))).expect("parse");
        let err = validate_gcp_token(&jwt, &signer, &slot_hash, Some(other)).unwrap_err();
        assert!(err.to_string().contains("image_digest"));
    }

    #[test]
    fn image_digest_flag_rejects_a_malformed_value() {
        assert!(parse_image_digest_config("abab").is_err());
        assert!(parse_image_digest_config(&format!("sha256:{}", "zz".repeat(32))).is_err());
        assert!(parse_image_digest_config(&"ab".repeat(32)).is_err());
    }
}
