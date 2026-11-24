//! Error definitions for the Solana Confidential Compute verifier on-chain program.

use solana_program::program_error::ProgramError;
use thiserror::Error;

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum VerifierError {
    #[error("Invalid instruction data")]
    InvalidInstruction = 0,

    #[error("Instruction discriminator does not match Anchor ABI")]
    InvalidDiscriminator = 1,

    #[error("Attestation report verification failed")]
    VerificationFailed = 2,

    #[error("Workload binary measurement not on approved allowlist")]
    DisallowedMeasurement = 3,

    #[error("Attestation nonce does not match a recent slot blockhash")]
    StaleNonce = 4,

    #[error("Nonce already consumed in current anti-replay window")]
    NonceAlreadyUsed = 5,

    #[error("Hardware TCB level is below minimum governance policy")]
    TcbBelowMinimum = 6,

    #[error("Unauthorized enclave policy (e.g. debug mode enabled)")]
    UnauthorizedPolicy = 7,

    #[error("Signer attestation has expired")]
    AttestationExpired = 8,

    #[error("Invalid account address or unpinned sysvar")]
    InvalidAccountAddress = 9,

    // Custom(10) was `SignerAlreadyAttested` and is retired. Do not reuse it.
    // The attested-signer path returns `AccountAlreadyInitialized`.
    /// AMD P-384 signature padding, algorithm, or ECDSA check failed.
    /// @spec SCC-SEC-009
    #[error("Invalid AMD P-384 report signature")]
    InvalidSignature = 11,

    /// Mode B REPORT_DATA[32..64] does not match the action commitment.
    /// @spec SCC-VERIFY-012
    #[error("Action commitment does not match header binding")]
    ActionHashMismatch = 12,

    /// Consumer expected signer does not match the report pubkey.
    /// @spec SCC-VERIFY-013
    #[error("Workload signer does not match expectation")]
    SignerMismatch = 13,

    /// Groth16 / alt_bn128 pairing check failed.
    /// @spec SCC-VERIFY-017
    #[error("Invalid Groth16 proof")]
    InvalidProof = 14,

    /// Authority does not match instruction signer or is default.
    /// @spec SCC-SEC-001
    #[error("Authority does not match instruction signer")]
    InvalidAuthority = 15,

    /// Mode B `verify_atomic` without nonce consumption is fail-closed.
    /// @spec SCC-SEC-005
    #[error("Mode B atomic attestation requires nonce consumption")]
    NonceRequired = 16,

    /// The legacy NVIDIA packet carries no authenticated evidence.
    /// 17 is already used by the consumer helper's ConsumerProgramMismatch.
    #[error("NVIDIA attestation requires an authenticated evidence adapter")]
    NvidiaAttestationUnavailable = 18,
}

impl From<VerifierError> for ProgramError {
    fn from(e: VerifierError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
