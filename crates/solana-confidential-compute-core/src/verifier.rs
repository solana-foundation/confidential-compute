//! Pluggable P-384 signature verification backends.
//!
//! @spec SCC-ARCH-003

use solana_program::{account_info::AccountInfo, program_error::ProgramError};

/// Verifies an ECDSA P-384 signature over a SHA-384 message digest.
///
/// Orchestrator policy, replay, and Mode A/B lifecycle logic stay independent of
/// the concrete backend (`MockVerifier`, software P-384, Groth16, or introspection).
/// @spec SCC-ARCH-003
pub trait SignatureVerifier {
    fn verify_p384(
        &self,
        public_key_xy: &[u8; 96],
        message_digest: &[u8; 48],
        signature_rs: &[u8; 96],
        instructions_sysvar: Option<&AccountInfo>,
    ) -> Result<(), ProgramError>;
}

/// Native test double that skips curve arithmetic. Unavailable on Solana SBF.
/// @spec SCC-ARCH-003
#[cfg(not(target_os = "solana"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockVerifier {
    succeed: bool,
}

#[cfg(not(target_os = "solana"))]
impl MockVerifier {
    /// Always returns `Ok(())`.
    pub const fn succeeding() -> Self {
        Self { succeed: true }
    }

    /// Always returns `ProgramError::InvalidInstructionData`.
    pub const fn failing() -> Self {
        Self { succeed: false }
    }
}

#[cfg(not(target_os = "solana"))]
impl Default for MockVerifier {
    fn default() -> Self {
        Self::succeeding()
    }
}

#[cfg(not(target_os = "solana"))]
impl SignatureVerifier for MockVerifier {
    fn verify_p384(
        &self,
        public_key_xy: &[u8; 96],
        message_digest: &[u8; 48],
        signature_rs: &[u8; 96],
        instructions_sysvar: Option<&AccountInfo>,
    ) -> Result<(), ProgramError> {
        let _ = (public_key_xy, message_digest, signature_rs, instructions_sysvar);
        if self.succeed {
            Ok(())
        } else {
            Err(ProgramError::InvalidInstructionData)
        }
    }
}
