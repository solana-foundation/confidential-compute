//! Anchor-compatible zero-copy adapters for Solana Confidential Compute consumer programs.
//!
//! @spec SCC-ANCHOR-001 SCC-ANCHOR-002

use bytemuck::{Pod, Zeroable};
use solana_program::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, sysvar::clock::Clock, sysvar::Sysvar,
};

use crate::{
    assert_attestation_atomic, AtomicAttestationExpectation, AttestationClaims, AttestationPlatform, CpiError,
    ATTESTED_SIGNER_ACCOUNT_SIZE, ATTESTED_SIGNER_DISCRIMINATOR,
};

/// Anchor consumer entry point binding the AccountInfo privileges received at
/// the attested top-level instruction. Pass ALL ordered instruction accounts,
/// including duplicates and infrastructure accounts, before making any CPI.
/// The supplied expectation's action_hash is replaced with the V3 full-wire digest.
pub fn assert_attestation_atomic_action_ctx(
    instructions_sysvar: &AccountInfo,
    expectation: &AtomicAttestationExpectation,
    current_program_id: &Pubkey,
    discriminator: &[u8],
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<AttestationClaims, ProgramError> {
    let mut bound = expectation.clone();
    bound.action_hash = crate::hash_action_account_infos(discriminator, accounts, payload);
    assert_attestation_atomic_ctx(instructions_sysvar, &bound, current_program_id)
}

/// Packed 154-byte V2 Mode A PDA. `u64` fields are LE bytes so the type is align-1 `Pod`
/// (on-chain tcb/slot integers sit at unaligned offsets 121/129/137).
///
/// @spec SCC-ANCHOR-001
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct AttestedSignerAccount {
    pub discriminator: [u8; 8],
    pub signer_pubkey: [u8; 32],
    pub enclave_type: u8,
    pub measurement: [u8; 48],
    pub chip_id_hash: [u8; 32],
    pub tcb_version: [u8; 8],
    pub registered_slot: [u8; 8],
    pub expires_slot: [u8; 8],
    pub bump: u8,
    pub expires_unix_timestamp: [u8; 8],
}

const _: () = {
    assert!(core::mem::size_of::<AttestedSignerAccount>() == ATTESTED_SIGNER_ACCOUNT_SIZE);
    assert!(core::mem::align_of::<AttestedSignerAccount>() == 1);
};

impl AttestedSignerAccount {
    pub const SIZE: usize = ATTESTED_SIGNER_ACCOUNT_SIZE;
    pub const DISCRIMINATOR: [u8; 8] = ATTESTED_SIGNER_DISCRIMINATOR;

    #[inline]
    pub fn owner() -> Pubkey {
        crate::ID
    }

    #[inline]
    pub fn expires_slot(&self) -> u64 {
        u64::from_le_bytes(self.expires_slot)
    }

    #[inline]
    pub fn expires_unix_timestamp(&self) -> i64 {
        i64::from_le_bytes(self.expires_unix_timestamp)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    /// Zero-copy decode. Rejects short buffers and a mismatched discriminator.
    ///
    /// @spec SCC-ANCHOR-001
    #[inline]
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidAccountData);
        }
        let account: Self = bytemuck::pod_read_unaligned(&data[..Self::SIZE]);
        if account.discriminator != Self::DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(account)
    }

    /// Decode after asserting `account.owner == solana_confidential_compute_verifier::ID`.
    ///
    /// @spec SCC-ANCHOR-001
    #[inline]
    pub fn try_from_account_info(account: &AccountInfo) -> Result<Self, ProgramError> {
        if account.owner != &crate::ID {
            return Err(ProgramError::IncorrectProgramId);
        }
        Self::try_from_slice(&account.try_borrow_data()?)
    }

    /// Measurement + expiry. Slot comes from `Clock::get()?.slot` only.
    ///
    /// @spec SCC-ANCHOR-001 SCC-SEC-004 SCC-VERIFY-008
    #[inline]
    pub fn validate(
        &self,
        expected_measurement: &[u8; 48],
        expected_platform: AttestationPlatform,
    ) -> Result<(), ProgramError> {
        let clock = Clock::get()?;
        self.validate_inner(expected_measurement, clock.slot, expected_platform, clock.unix_timestamp)
    }

    /// Test helper that injects both slot and Unix timestamp from a simulated Clock.
    ///
    /// @spec SCC-SEC-004
    #[cfg(any(test, feature = "test-bpf"))]
    pub fn validate_at_slot(
        &self,
        expected_measurement: &[u8; 48],
        clock_slot: u64,
        expected_platform: AttestationPlatform,
        clock_unix_timestamp: i64,
    ) -> Result<(), ProgramError> {
        self.validate_inner(expected_measurement, clock_slot, expected_platform, clock_unix_timestamp)
    }

    /// Mode A session bind: require `workload_signer.is_signer` and pubkey
    /// equality with `signer_pubkey`, then measurement + expiry.
    ///
    /// Does not re-derive the attested-signer PDA (that syscall is 1,500 CUs).
    /// Record authenticity remains owner + discriminator via `try_from_account_info`.
    ///
    /// @spec SCC-ANCHOR-001 SCC-CONSUMER-001 SCC-SEC-004
    #[inline]
    pub fn validate_session_signer(
        &self,
        workload_signer: &AccountInfo,
        expected_measurement: &[u8; 48],
        expected_platform: AttestationPlatform,
    ) -> Result<(), ProgramError> {
        let clock = Clock::get()?;
        self.validate_session_signer_inner(
            workload_signer,
            expected_measurement,
            clock.slot,
            expected_platform,
            clock.unix_timestamp,
        )
    }

    /// Test helper that injects both slot and Unix timestamp from a simulated Clock.
    ///
    /// @spec SCC-ANCHOR-001 SCC-SEC-004
    #[cfg(any(test, feature = "test-bpf"))]
    pub fn validate_session_signer_at_slot(
        &self,
        workload_signer: &AccountInfo,
        expected_measurement: &[u8; 48],
        clock_slot: u64,
        expected_platform: AttestationPlatform,
        clock_unix_timestamp: i64,
    ) -> Result<(), ProgramError> {
        self.validate_session_signer_inner(
            workload_signer,
            expected_measurement,
            clock_slot,
            expected_platform,
            clock_unix_timestamp,
        )
    }

    fn validate_session_signer_inner(
        &self,
        workload_signer: &AccountInfo,
        expected_measurement: &[u8; 48],
        clock_slot: u64,
        expected_platform: AttestationPlatform,
        clock_unix_timestamp: i64,
    ) -> Result<(), ProgramError> {
        if !workload_signer.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if self.signer_pubkey != workload_signer.key.to_bytes() {
            return Err(CpiError::SignerMismatch.into());
        }
        self.validate_inner(expected_measurement, clock_slot, expected_platform, clock_unix_timestamp)
    }

    fn validate_inner(
        &self,
        expected_measurement: &[u8; 48],
        clock_slot: u64,
        expected_platform: AttestationPlatform,
        clock_unix_timestamp: i64,
    ) -> Result<(), ProgramError> {
        if self.discriminator != Self::DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        expected_platform.check(self.enclave_type)?;
        if &self.measurement != expected_measurement {
            return Err(CpiError::DisallowedMeasurement.into());
        }
        if clock_unix_timestamp < 0 || clock_unix_timestamp >= self.expires_unix_timestamp() {
            return Err(CpiError::AttestationExpired.into());
        }
        if self.expires_slot() == 0 || clock_slot > self.expires_slot() {
            return Err(CpiError::AttestationExpired.into());
        }
        Ok(())
    }
}

/// Mode B Anchor adapter. Enforces `require_nonce == true` (@spec SCC-SEC-005).
///
/// @spec SCC-ANCHOR-002 SCC-VERIFY-013
#[inline]
pub fn assert_attestation_atomic_ctx(
    instructions_sysvar: &AccountInfo,
    expectation: &AtomicAttestationExpectation,
    current_program_id: &Pubkey,
) -> Result<AttestationClaims, ProgramError> {
    assert_attestation_atomic(instructions_sysvar, expectation, current_program_id)
}

/// Bind a Mode B Solana Confidential Compute attestation from an Anchor `Context`.
///
/// Two-arg form expects `ctx.accounts.instructions` (`to_account_info()`) and `ctx.program_id`.
///
/// @spec SCC-ANCHOR-002 SCC-SEC-005
#[macro_export]
macro_rules! assert_attestation_atomic_ctx {
    ($ctx:expr, $expectation:expr) => {
        $crate::anchor::assert_attestation_atomic_ctx(
            &$ctx.accounts.instructions.to_account_info(),
            $expectation,
            $ctx.program_id,
        )
    };
    ($instructions_sysvar:expr, $expectation:expr, $program_id:expr) => {
        $crate::anchor::assert_attestation_atomic_ctx($instructions_sysvar, $expectation, $program_id)
    };
}
