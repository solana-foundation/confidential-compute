//! Error definitions for the Solana Confidential Compute Enclave Sidecar Daemon.
//!
//! @spec SCC-SIDECAR-001 SCC-SIDECAR-004

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SidecarError {
    #[error("Key management error: {0}")]
    KeyError(String),

    #[error("Attestation failure: {0}")]
    AttestationError(String),

    #[error("On-chain registration error: {0}")]
    OnchainError(String),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("Attestation expired: current slot {current_slot} > expires slot {expires_slot}")]
    AttestationExpired { current_slot: u64, expires_slot: u64 },

    #[error("Unauthorized signer in transaction: {0}")]
    UnauthorizedSigner(String),

    #[error("Hardware ioctl error: {0}")]
    IoctlError(String),

    #[error("Cloud metadata service error: {0}")]
    MetadataError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// The guest produced no usable Intel TDX quote, or produced synthetic
    /// evidence while running in live mode.
    #[error("Intel TDX attestation failed")]
    TdxAttestationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// NVIDIA Confidential GPU appraisal failed closed.
    /// @spec SCC-NVIDIA-001
    #[error("NVIDIA GPU attestation failed")]
    GpuAttestationFailed,
}
