//! Controlled launcher simulation only: no Google signature or hardware proof.
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    routing::post,
    Json, Router,
};
use base64::Engine;
use serde_json::{json, Value};
use solana_confidential_compute_sidecar::attestation::{
    gcp_oidc::{mode_a_eat_nonces, GcpOidcProvider},
    AttestationProvider, AttestationReport,
};
use solana_sdk::pubkey::Pubkey;
use tokio::net::UnixListener;

struct Launcher {
    path: PathBuf,
    requests: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

/// `SystemTime` granularity is coarser than the gap between two launchers
/// started from parallel tests, so the clock alone collides and `bind` fails
/// with `AlreadyExists`. The counter makes the path unique within the process;
/// the pid makes it unique across concurrent `cargo test` invocations.
static LAUNCHER_SEQ: AtomicU64 = AtomicU64::new(0);

impl Launcher {
    async fn start(status: StatusCode, response: String) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = LAUNCHER_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "scc-295-{}-{unique}-{seq}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let router = Router::new()
            .route(
                "/v1/token",
                post(
                    move |State(requests): State<Arc<Mutex<Vec<Value>>>>,
                          Json(body): Json<Value>| {
                        let response = response.clone();
                        async move {
                            requests.lock().unwrap().push(body);
                            let mut headers = HeaderMap::new();
                            if status.is_redirection() {
                                headers.insert(
                                    header::LOCATION,
                                    HeaderValue::from_static("http://localhost/redirected"),
                                );
                            }
                            (status, headers, response)
                        }
                    },
                ),
            )
            .with_state(Arc::clone(&requests));
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            path,
            requests,
            task,
        }
    }

    fn provider(&self) -> GcpOidcProvider {
        GcpOidcProvider::new(
            Some(self.path.to_str().unwrap()),
            Some("solana-confidential-compute-verifier"),
        )
    }
}

impl Drop for Launcher {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

fn controlled_token(signer: &Pubkey, slot_hash: &[u8; 32]) -> String {
    controlled_token_with(signer, slot_hash, |_| {})
}

fn controlled_token_with(
    signer: &Pubkey,
    slot_hash: &[u8; 32],
    mutate: impl FnOnce(&mut Value),
) -> String {
    let (n0, n1) = mode_a_eat_nonces(signer, slot_hash);
    let mut payload = json!({
        "aud": "solana-confidential-compute-verifier", "dbgstat": "disabled-since-boot",
        "eat_nonce": [n0, n1], "exp": 4102444800u64, "iat": 1700000000u64,
        "iss": "https://confidentialcomputing.googleapis.com", "secboot": true, "sub": "s",
        "submods": {"container": {"image_digest": format!("sha256:{}", "ab".repeat(32))}}
    });
    mutate(&mut payload);
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.e30",
        engine.encode(r#"{"alg":"RS256","kid":"controlled","typ":"JWT"}"#),
        engine.encode(payload.to_string())
    )
}

#[tokio::test]
async fn launcher_socket_receives_oidc_audience_and_mode_a_nonces() {
    let signer = Pubkey::new_from_array([0x80; 32]);
    let slot_hash = [0x5a; 32];
    let jwt = controlled_token(&signer, &slot_hash);
    let launcher = Launcher::start(StatusCode::OK, jwt.clone()).await;
    let report = tokio::time::timeout(
        Duration::from_secs(3),
        launcher.provider().request_attestation(&signer, &slot_hash),
    )
    .await
    .expect("bounded socket request")
    .expect("launcher token");
    assert!(matches!(report, AttestationReport::GcpJwt { jwt: actual } if actual == jwt));
    let (n0, n1) = mode_a_eat_nonces(&signer, &slot_hash);
    assert_eq!(
        *launcher.requests.lock().unwrap(),
        vec![json!({
            "audience": "solana-confidential-compute-verifier", "token_type": "OIDC", "nonces": [n0, n1]
        })]
    );
}

#[tokio::test]
async fn launcher_failure_and_mismatched_binding_fail_closed() {
    let signer = Pubkey::new_from_array([0x80; 32]);
    let slot_hash = [0x5a; 32];
    let failed = Launcher::start(
        StatusCode::SERVICE_UNAVAILABLE,
        "controlled launcher failure".into(),
    )
    .await;
    let err = failed
        .provider()
        .request_attestation(&signer, &slot_hash)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("503"));
    let wrong = Launcher::start(
        StatusCode::OK,
        controlled_token(&Pubkey::new_unique(), &slot_hash),
    )
    .await;
    let err = wrong
        .provider()
        .request_attestation(&signer, &slot_hash)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("does not bind"));
    assert_eq!(wrong.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn launcher_response_requires_exact_requested_audience() {
    let signer = Pubkey::new_from_array([0x80; 32]);
    let slot_hash = [0x5a; 32];
    let custom = "solana-confidential-compute-verifier/custom";
    let jwt = controlled_token_with(&signer, &slot_hash, |claims| claims["aud"] = json!(custom));
    let launcher = Launcher::start(StatusCode::OK, jwt).await;
    let err = launcher
        .provider()
        .request_attestation(&signer, &slot_hash)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("audience"));
    let provider = GcpOidcProvider::new(Some(launcher.path.to_str().unwrap()), Some(custom));
    provider
        .request_attestation(&signer, &slot_hash)
        .await
        .expect("exact custom audience");
    assert_eq!(launcher.requests.lock().unwrap()[1]["audience"], custom);
}

#[tokio::test]
async fn launcher_claim_controls_reject_issuer_boot_and_nonce_substitution() {
    let signer = Pubkey::new_from_array([0x80; 32]);
    let slot_hash = [0x5a; 32];
    for (field, value) in [
        ("iss", json!("https://accounts.google.com")),
        ("secboot", json!(false)),
        ("dbgstat", json!("enabled")),
        ("eat_nonce", json!(["invalid-nonce", "invalid-nonce"])),
    ] {
        let jwt = controlled_token_with(&signer, &slot_hash, |claims| claims[field] = value);
        let launcher = Launcher::start(StatusCode::OK, jwt).await;
        assert!(
            launcher
                .provider()
                .request_attestation(&signer, &slot_hash)
                .await
                .is_err(),
            "{field}"
        );
        assert_eq!(launcher.requests.lock().unwrap().len(), 1);
    }
    let wrong_slot = Launcher::start(StatusCode::OK, controlled_token(&signer, &[0x5b; 32])).await;
    let err = wrong_slot
        .provider()
        .request_attestation(&signer, &slot_hash)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("does not bind"));
    let swapped = controlled_token_with(&signer, &slot_hash, |claims| {
        claims["eat_nonce"].as_array_mut().unwrap().swap(0, 1)
    });
    let launcher = Launcher::start(StatusCode::OK, swapped).await;
    assert!(launcher
        .provider()
        .request_attestation(&signer, &slot_hash)
        .await
        .is_err());
}

#[tokio::test]
async fn launcher_rejects_redirects_malformed_tokens_and_missing_socket() {
    let signer = Pubkey::new_from_array([0x80; 32]);
    let slot_hash = [0x5a; 32];
    let redirect = Launcher::start(StatusCode::TEMPORARY_REDIRECT, String::new()).await;
    let err = redirect
        .provider()
        .request_attestation(&signer, &slot_hash)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("307"));
    assert_eq!(redirect.requests.lock().unwrap().len(), 1);
    let malformed = Launcher::start(StatusCode::OK, "not a jwt".into()).await;
    assert!(malformed
        .provider()
        .request_attestation(&signer, &slot_hash)
        .await
        .is_err());
    let unavailable_provider = malformed.provider();
    drop(malformed);
    assert!(unavailable_provider
        .request_attestation(&signer, &slot_hash)
        .await
        .is_err());
}

#[tokio::test]
async fn launcher_token_must_match_configured_image_digest() {
    let signer = Pubkey::new_from_array([0x80; 32]);
    let slot_hash = [0x5a; 32];
    let launcher = Launcher::start(StatusCode::OK, controlled_token(&signer, &slot_hash)).await;
    let other_image = format!("sha256:{}", "cd".repeat(32));
    let provider = GcpOidcProvider::with_image_digest(
        Some(launcher.path.to_str().unwrap()),
        None,
        Some(&other_image),
    )
    .unwrap();
    let err = provider
        .request_attestation(&signer, &slot_hash)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("image_digest"));
}
