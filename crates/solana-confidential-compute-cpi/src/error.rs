//! Consumer CPI errors.
//!
//! Codes that match `solana_confidential_compute_verifier::VerifierError` keep the same numeric value.
//! `ConsumerProgramMismatch` is CPI-only and does not reuse custom `7`
//! (`UnauthorizedPolicy`).

use solana_program::program_error::ProgramError;
use thiserror::Error;

/// Error codes aligned with `solana_confidential_compute_verifier::VerifierError`, plus CPI-only variants.
#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum CpiError {
    #[error("Workload binary measurement not on approved allowlist")]
    DisallowedMeasurement = 3,
    #[error("Unauthorized enclave policy")]
    UnauthorizedPolicy = 7,
    #[error("Signer attestation has expired")]
    AttestationExpired = 8,
    #[error("Action commitment does not match header binding")]
    ActionHashMismatch = 12,
    #[error("Workload signer does not match expectation")]
    SignerMismatch = 13,
    #[error("Mode B atomic attestation requires nonce consumption")]
    NonceRequired = 16,
    /// Header `consumer_program_id` is not the program calling
    /// `assert_attestation_atomic`. Distinct from `UnauthorizedPolicy` (7).
    #[error("Attestation consumer_program_id does not match this program")]
    ConsumerProgramMismatch = 17,
    #[error("Unsupported attestation platform")]
    UnsupportedPlatform = 1000,
    #[error("Attestation platform does not match consumer expectation")]
    PlatformMismatch = 1001,
    #[error("Attestation does not carry a workload signing key")]
    SignerIdentityUnavailable = 1002,
    #[error("Solana Confidential Compute attestation must immediately precede the consumer")]
    InvalidAttestationIndex = 1010,
    #[error("Unsupported Solana Confidential Compute attestation instruction")]
    UnsupportedAttestationInstruction = 1011,
    #[error("Malformed attestation instruction length or header")]
    MalformedAttestationEnvelope = 1012,
    #[error("Expected nonce-protected Mode B attestation")]
    WrongAttestationMode = 1013,
    #[error("Malformed SNP report")]
    MalformedSnpReport = 1014,
    #[error("Malformed Nitro COSE/CBOR document")]
    MalformedNitroDocument = 1015,
    #[error("Malformed Google JWT or claims")]
    MalformedGoogleJwt = 1016,
    #[error("Malformed instructions sysvar")]
    MalformedInstructionsSysvar = 1017,
    #[error("Atomic attestation requires a top-level consumer instruction")]
    InvalidConsumerStackHeight = 1018,
}

impl From<CpiError> for ProgramError {
    fn from(e: CpiError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
