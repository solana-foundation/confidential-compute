//! Reference consumer demonstrating third-party Mode A and Mode B Solana Confidential Compute checks.
//!
//! @spec SCC-CONSUMER-001 SCC-CONSUMER-002
#![allow(unexpected_cfgs, deprecated)]

use solana_confidential_compute_cpi::anchor::assert_attestation_atomic_ctx;
use solana_confidential_compute_cpi::{AtomicAttestationExpectation, AttestationPlatform};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey,
};
use thiserror::Error;

solana_program::declare_id!("A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ");

/// Allowlisted SHA-384 measurement accepted by this reference consumer.
///
/// # This value is a PLACEHOLDER. Replace it before deploying.
///
/// `[0x42; 48]` is not a real enclave measurement and no genuine hardware will
/// ever produce it. It exists so the reference program and its tests have a
/// fixed value to assert against.
///
/// This constant is the security boundary of a consumer: it is what decides
/// which enclave image a consumer is willing to trust. A fork that deploys with
/// this value unchanged accepts no real workload (fail-closed), but it also has
/// no measurement policy of its own. Replace it with the SHA-384 measurement of
/// your own enclave image, and keep it in sync with the `BackendPolicy` the
/// verifier admits against.
pub const EXPECTED_MEASUREMENT: [u8; 48] = [0x42; 48];

/// Mode A consumer-check ceiling (@spec SCC-CONSUMER-001).
pub const MODE_A_CU_CEILING: u64 = 1_500;
/// Mode B consumer-check ceiling (@spec SCC-CONSUMER-002).
pub const MODE_B_CU_CEILING: u64 = 2_500;

pub const IX_EXECUTE_SESSION_ACTION: u8 = 0;
pub const IX_EXECUTE_ATOMIC_ACTION: u8 = 1;
pub const IX_EXECUTE_NVIDIA_SESSION_ACTION: u8 = 2;

/// Default synthetic Hopper H100 Golden Reference Integrity Manifest (RIM) measurement.
pub const DEFAULT_H100_GOLDEN_RIM: [u8; 32] = [
    0x4e, 0x56, 0x49, 0x44, 0x49, 0x41, 0x5f, 0x48, 0x31, 0x30, 0x30, 0x5f, 0x43, 0x43, 0x5f, 0x52, 0x49, 0x4d, 0x5f,
    0x56, 0x42, 0x49, 0x4f, 0x53, 0x5f, 0x44, 0x52, 0x49, 0x56, 0x45, 0x52, 0x31,
];

pub use solana_confidential_compute_cpi::{
    hash_action, hash_action_account_infos, AttestedSignerAccount, CpiError, ID as VERIFIER_PROGRAM_ID,
    VERIFY_ATOMIC_DISCRIMINATOR, VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
};

/// Stack cap for Mode B account binding. A legacy transaction holds at most 64 keys.
const MAX_BOUND_ACCOUNTS: usize = 64;

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum ConsumerError {
    #[error("Invalid instruction")]
    InvalidInstruction = 0,
}

impl From<ConsumerError> for ProgramError {
    fn from(e: ConsumerError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[cfg(all(target_os = "solana", not(feature = "no-entrypoint")))]
solana_program::entrypoint!(process_instruction);

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    match instruction_data.first().copied() {
        Some(IX_EXECUTE_SESSION_ACTION) => execute_session_action(accounts),
        Some(IX_EXECUTE_ATOMIC_ACTION) => execute_atomic_action(program_id, accounts, instruction_data),
        Some(IX_EXECUTE_NVIDIA_SESSION_ACTION) => execute_nvidia_session_action(accounts),
        _ => Err(ConsumerError::InvalidInstruction.into()),
    }
}

/// Mode A (NVIDIA H100): bind workload signer, assert H100 platform + Golden RIM measurement.
fn execute_nvidia_session_action(accounts: &[AccountInfo]) -> ProgramResult {
    let attested_info = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let workload_signer = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !workload_signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let attested = AttestedSignerAccount::try_from_account_info(attested_info)?;
    if attested.signer_pubkey != workload_signer.key.to_bytes() {
        return Err(CpiError::SignerMismatch.into());
    }
    let mut expected = [0u8; 48];
    expected[..32].copy_from_slice(&DEFAULT_H100_GOLDEN_RIM);
    attested.validate(&expected, AttestationPlatform::NvidiaH100)?;
    Ok(())
}

/// Mode A: bind the workload signer, then validate measurement + expiry.
///
/// Record authenticity is owner + discriminator. Caller authenticity is
/// `workload_signer.is_signer` plus pubkey equality with `attested.signer_pubkey`.
///
/// @spec SCC-CONSUMER-001 SCC-SEC-004 SCC-ANCHOR-001
fn execute_session_action(accounts: &[AccountInfo]) -> ProgramResult {
    let attested_info = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let workload_signer = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !workload_signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let attested = AttestedSignerAccount::try_from_account_info(attested_info)?;
    if attested.signer_pubkey != workload_signer.key.to_bytes() {
        return Err(CpiError::SignerMismatch.into());
    }
    attested.validate(&EXPECTED_MEASUREMENT, AttestationPlatform::AmdSevSnp)?;
    Ok(())
}

/// Mode B: bind this instruction with `hash_action`, then introspect Solana Confidential Compute.
///
/// The attested digest covers the discriminator, every ordered account pubkey and its effective signer/writable bits, and the
/// payload (`instruction_data[1..]`). A caller-supplied hash is not accepted.
/// `expected_signer` stays unset: this sample does not name a replica.
///
/// @spec SCC-CONSUMER-002 SCC-SEC-005 SCC-ANCHOR-002 SCC-VERIFY-013 SCC-VERIFY-014
fn execute_atomic_action(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let instructions_sysvar = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let payload = instruction_data.get(1..).unwrap_or(&[]);
    let action_hash = bound_action_hash(accounts, payload)?;
    let expectation = AtomicAttestationExpectation {
        expected_platform: AttestationPlatform::AmdSevSnp,
        action_hash,
        expected_measurement: EXPECTED_MEASUREMENT,
        expected_signer: None,
        require_nonce: true,
        verifier_ix_index: None,
    };
    assert_attestation_atomic_ctx(instructions_sysvar, &expectation, program_id)?;
    Ok(())
}

/// Stack-only `hash_action` over this instruction. No heap allocation.
fn bound_action_hash(accounts: &[AccountInfo], payload: &[u8]) -> Result<[u8; 32], ProgramError> {
    if accounts.is_empty() || accounts.len() > MAX_BOUND_ACCOUNTS {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(hash_action_account_infos(&[IX_EXECUTE_ATOMIC_ACTION], accounts, payload))
}
