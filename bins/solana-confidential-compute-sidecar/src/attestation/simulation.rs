//! Select local simulation evidence before any GCP metadata request is built.

use solana_confidential_compute_core::types::EnclaveType;
use solana_sdk::pubkey::Pubkey;

use super::{mock::MockAttestationProvider, AttestationProvider, AttestationReport};
use crate::error::SidecarError;

/// Request evidence for registration construction.
///
/// GCP dry run uses a local synthetic JWT with a placeholder signature. It is
/// construction evidence only, never verified enrollment. Live mode always
/// delegates to the configured provider and retains its binding/digest checks.
/// Other hardware providers retain their existing behavior.
pub async fn request_for_submission(
    provider: &dyn AttestationProvider,
    dry_run: bool,
    workload: &Pubkey,
    slot_hash: &[u8; 32],
) -> Result<AttestationReport, SidecarError> {
    if dry_run && provider.enclave_type() == EnclaveType::GcpConfidentialSpace {
        return MockAttestationProvider::new_gcp(None).request_attestation(workload, slot_hash).await;
    }
    provider.request_attestation(workload, slot_hash).await
}
