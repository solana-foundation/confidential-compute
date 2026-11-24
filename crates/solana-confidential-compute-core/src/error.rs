//! Error types for Solana Confidential Compute Core.

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ConfidentialComputeError {
    #[error("Invalid attestation signature")]
    InvalidSignature,

    #[error("Invalid measurement digest")]
    InvalidMeasurement,

    #[error("Certificate chain verification failed: {0}")]
    CertificateChainInvalid(&'static str),

    #[error("Attestation report expired or nonce stale")]
    StaleAttestation,

    #[error("Serialization error")]
    SerializationError,

    #[error("Unauthorized enclave policy")]
    UnauthorizedPolicy,

    #[error("Enclave debug mode prohibited by security policy")]
    DebugModeProhibited,

    #[error("AMD SEV-SNP signature contains non-zero padding")]
    InvalidSignaturePadding,

    #[error("Unsupported signature algorithm")]
    InvalidSignatureAlgorithm,

    #[error("Report payload size invalid: expected 1184 bytes")]
    ReportSizeInvalid,

    #[error("Nonce already consumed in current window")]
    NonceAlreadyUsed,

    #[error("Reported hardware TCB version is below minimum governance threshold")]
    TcbBelowMinimum,
}
