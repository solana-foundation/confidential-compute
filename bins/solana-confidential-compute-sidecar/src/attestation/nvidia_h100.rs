//! NVIDIA Confidential GPU (Hopper H100/H200 / Blackwell B200) attestation provider.
//!
//! @spec SCC-NVIDIA-001 SCC-NVIDIA-002 SCC-NVIDIA-005

use std::future::Future;
use std::pin::Pin;

use solana_confidential_compute_core::types::EnclaveType;
use solana_sdk::hash::hashv;
use solana_sdk::pubkey::Pubkey;

use super::{AttestationProvider, AttestationReport};
use crate::error::SidecarError;

/// Dry-run placeholder RIM. It is not a VBIOS, driver, or model digest.
pub const DEFAULT_H100_GOLDEN_RIM: [u8; 32] = [
    0x4e, 0x56, 0x49, 0x44, 0x49, 0x41, 0x5f, 0x48, 0x31, 0x30, 0x30, 0x5f, 0x43, 0x43, 0x5f, 0x52,
    0x49, 0x4d, 0x5f, 0x56, 0x42, 0x49, 0x4f, 0x53, 0x5f, 0x44, 0x52, 0x49, 0x56, 0x45, 0x52, 0x31,
];

/// Prefix on the SPDM buffer this provider fabricates for dry-run construction.
/// A live submission must not treat that buffer as hardware evidence.
pub const SYNTHETIC_SPDM_PREFIX: &[u8] = b"NVIDIA-SPDM-v1.2";

/// `true` when `spdm_report` was built by the dry-run provider.
pub fn synthetic_spdm_evidence(spdm_report: &[u8]) -> bool {
    spdm_report.starts_with(SYNTHETIC_SPDM_PREFIX)
}

/// Computes the dual CPU+GPU composite nonce.
/// @spec SCC-NVIDIA-002
pub fn compute_composite_nonce(
    workload_signer: &Pubkey,
    gpu_measurement: &[u8; 32],
    slot_hash: &[u8; 32],
) -> [u8; 32] {
    hashv(&[workload_signer.as_ref(), gpu_measurement, slot_hash]).to_bytes()
}

pub struct NvidiaH100Provider {
    expected_gpu_measurement: [u8; 32],
    simulated: bool,
}

impl NvidiaH100Provider {
    pub fn new(expected_gpu_measurement: Option<[u8; 32]>, simulated: bool) -> Self {
        Self {
            expected_gpu_measurement: expected_gpu_measurement.unwrap_or(DEFAULT_H100_GOLDEN_RIM),
            simulated,
        }
    }

    /// Daemon constructor.
    ///
    /// `dry_run` selects the local golden RIM. Live mode keeps the fail-closed
    /// appraiser, so the synthetic measurement cannot be broadcast.
    /// @spec SCC-NVIDIA-001
    pub fn for_daemon(dry_run: bool) -> Result<Self, SidecarError> {
        let provider = Self::new(None, dry_run);
        provider.reject_simulated_live(dry_run)?;
        Ok(provider)
    }

    /// Synthetic GPU evidence is a dry-run construction aid.
    pub fn reject_simulated_live(&self, dry_run: bool) -> Result<(), SidecarError> {
        if self.simulated && !dry_run {
            return Err(SidecarError::InvalidConfig(
                "simulated NVIDIA GPU evidence cannot be used when dry_run is false".to_string(),
            ));
        }
        Ok(())
    }

    /// Returns the configured measurement in simulation, or fails closed.
    ///
    /// Live NVML/SPDM appraisal against the NVIDIA root is not performed here.
    /// A non-simulated provider must not present the golden RIM as hardware evidence.
    /// @spec SCC-NVIDIA-001
    pub fn query_gpu_measurement(&self) -> Result<[u8; 32], SidecarError> {
        if self.simulated {
            return Ok(self.expected_gpu_measurement);
        }
        Err(SidecarError::GpuAttestationFailed)
    }
}

impl Default for NvidiaH100Provider {
    fn default() -> Self {
        Self::new(None, false)
    }
}

impl AttestationProvider for NvidiaH100Provider {
    fn enclave_type(&self) -> EnclaveType {
        EnclaveType::NvidiaGpu
    }

    fn request_attestation<'a>(
        &'a self,
        workload_signer: &'a Pubkey,
        slot_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<AttestationReport, SidecarError>> + Send + 'a>> {
        Box::pin(async move {
            let gpu_measurement = self.query_gpu_measurement()?;
            let composite_nonce =
                compute_composite_nonce(workload_signer, &gpu_measurement, slot_hash);

            // Dry-run construction evidence. Live appraisal never reaches here.
            let mut spdm_report = Vec::with_capacity(128);
            spdm_report.extend_from_slice(SYNTHETIC_SPDM_PREFIX);
            spdm_report.extend_from_slice(&gpu_measurement);
            spdm_report.extend_from_slice(&composite_nonce);

            Ok(AttestationReport::NvidiaH100 {
                composite_report: composite_nonce.to_vec(),
                gpu_measurement,
                spdm_report,
            })
        })
    }
}
