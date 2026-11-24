//! Synthetic mock attestation provider for testing, CI, and local devnet.
//!
//! @spec SCC-SIDECAR-004

use solana_confidential_compute_core::{types::EnclaveType, SNP_REPORT_SIZE};
use solana_sdk::pubkey::Pubkey;
use std::future::Future;
use std::pin::Pin;

use super::gcp_oidc::mode_a_eat_nonces;
use super::{AttestationProvider, AttestationReport};
use crate::error::SidecarError;

pub struct MockAttestationProvider {
    enclave_type: EnclaveType,
    custom_jwt: Option<String>,
}

impl MockAttestationProvider {
    pub fn new_sev_snp() -> Self {
        Self { enclave_type: EnclaveType::AmdSevSnp, custom_jwt: None }
    }

    pub fn new_gcp(custom_jwt: Option<&str>) -> Self {
        Self { enclave_type: EnclaveType::GcpConfidentialSpace, custom_jwt: custom_jwt.map(|s| s.to_string()) }
    }
}

impl Default for MockAttestationProvider {
    fn default() -> Self {
        Self::new_sev_snp()
    }
}

impl AttestationProvider for MockAttestationProvider {
    fn enclave_type(&self) -> EnclaveType {
        self.enclave_type
    }

    fn request_attestation<'a>(
        &'a self,
        workload_signer: &'a Pubkey,
        slot_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<AttestationReport, SidecarError>> + Send + 'a>> {
        Box::pin(async move {
            match self.enclave_type {
                EnclaveType::AmdSevSnp | EnclaveType::Mock => {
                    let mut report = vec![0u8; SNP_REPORT_SIZE];
                    // Model VCEK explicitly; this synthetic ID is not hardware
                    // evidence. Zero chip would require a VLEK endorsement key.
                    report[0x1a0..0x1e0].fill(9);
                    // Version = 2
                    report[0..4].copy_from_slice(&2u32.to_le_bytes());
                    // Policy: bit 17 (GUEST_POLICY_RESERVED_MUST_BE_ONE) set, DEBUG (19) & MIGRATE_MA (18) clear
                    report[8..16].copy_from_slice(&(1u64 << 17).to_le_bytes());
                    // Signature algo = 1 (ECDSA P-384 with SHA-384)
                    report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
                    // Measurement at offset 0x90..0xC0 (144..192, 48 bytes)
                    report[0x90..0xC0].fill(0xab);
                    // REPORT_DATA at offset 0x50 (80..144)
                    // user_data[0..32] = workload_signer
                    report[0x50..0x70].copy_from_slice(workload_signer.as_ref());
                    // user_data[32..64] = slot_hash
                    report[0x70..0x90].copy_from_slice(slot_hash);

                    Ok(AttestationReport::SevSnp { report, vcek_cert: None })
                }
                EnclaveType::GcpConfidentialSpace => {
                    if let Some(jwt) = &self.custom_jwt {
                        return Ok(AttestationReport::GcpJwt { jwt: jwt.clone() });
                    }

                    // Fallback synthetic JWT for local mock testing.
                    // The signature is a placeholder; callers that need RS256 use a custom token.
                    let header = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ";
                    let (nonce0, nonce1) = mode_a_eat_nonces(workload_signer, slot_hash);
                    let payload_json = format!(
                        r#"{{"aud":"solana-confidential-compute-verifier","dbgstat":"disabled-since-boot","eat_nonce":["{nonce0}","{nonce1}"],"exp":4102444800,"iat":1700000000,"iss":"https://confidentialcomputing.googleapis.com","secboot":true,"sub":"https://www.googleapis.com/compute/v1/projects/solana-confidential-compute/zones/us/instances/vm","submods":{{"container":{{"image_digest":"sha256:abababababababababababababababababababababababababababababababab"}}}}}}"#
                    );
                    let payload = base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        payload_json.as_bytes(),
                    );
                    let sig = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [0u8; 256]);
                    let jwt = format!("{header}.{payload}.{sig}");

                    Ok(AttestationReport::GcpJwt { jwt })
                }
                _ => Err(SidecarError::AttestationError(format!(
                    "Unsupported mock enclave type {:?}",
                    self.enclave_type
                ))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_confidential_compute_core::SnpReportView;

    #[tokio::test]
    async fn test_mock_sev_snp_passes_security_invariants() {
        let provider = MockAttestationProvider::new_sev_snp();
        let signer = Pubkey::new_unique();
        let slot_hash = [0x55u8; 32];
        let report = provider.request_attestation(&signer, &slot_hash).await.expect("attestation succeeds");

        match report {
            AttestationReport::SevSnp { report, .. } => {
                let view = SnpReportView::try_from_slice(&report).expect("valid snp report size");
                view.validate_security_invariants().expect("passes security invariants");
                assert_eq!(view.version(), 2);
                assert!(!view.is_vlek());
                assert_eq!(view.policy(), 1 << 17);
                assert_eq!(view.measurement(), [0xab; 48]);
                assert_eq!(view.pubkey(), signer.to_bytes());
                assert_eq!(view.nonce(), slot_hash);
            }
            _ => panic!("expected SevSnp report"),
        }
    }
}
