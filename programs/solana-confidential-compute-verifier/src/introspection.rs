//! Native precompile adapter via `sysvar::instructions`.
//!
//! @spec SCC-VERIFY-016

use solana_confidential_compute_core::SignatureVerifier;
use solana_program::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::instructions::{self, load_current_index_checked, load_instruction_at_checked},
};

use crate::error::VerifierError;

/// Uncompressed P-384 public key (X || Y) at the start of sigverify ix data.
pub const PUBKEY_OFFSET: usize = 0;
/// SHA-384 message digest immediately after the public key.
pub const DIGEST_OFFSET: usize = 96;
/// ECDSA `(r || s)` immediately after the digest.
pub const SIGNATURE_OFFSET: usize = 144;
/// `pubkey (96) || digest (48) || signature (96)`.
pub const SIGVERIFY_IX_DATA_LEN: usize = 240;

/// Validates a P-384 signature by scanning preceding sigverify instructions.
/// @spec SCC-VERIFY-016
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionIntrospectionVerifier {
    expected_program_id: Pubkey,
}

impl InstructionIntrospectionVerifier {
    pub const fn new(expected_program_id: Pubkey) -> Self {
        Self { expected_program_id }
    }
}

impl SignatureVerifier for InstructionIntrospectionVerifier {
    fn verify_p384(
        &self,
        public_key_xy: &[u8; 96],
        message_digest: &[u8; 48],
        signature_rs: &[u8; 96],
        instructions_sysvar: Option<&AccountInfo>,
    ) -> Result<(), ProgramError> {
        let instructions_sysvar = instructions_sysvar.ok_or(ProgramError::InvalidInstructionData)?;
        if instructions_sysvar.key != &instructions::ID {
            return Err(ProgramError::IncorrectProgramId);
        }

        let current_index = load_current_index_checked(instructions_sysvar)?;
        if current_index == 0 {
            return Err(VerifierError::InvalidInstruction.into());
        }

        // Nitro checks the cert chain and the COSE payload in this same
        // instruction, so the matching precompile may sit anywhere before it.
        for idx in (0..current_index).rev() {
            let ix = load_instruction_at_checked(idx as usize, instructions_sysvar)?;
            if ix.program_id != self.expected_program_id || ix.data.len() != SIGVERIFY_IX_DATA_LEN {
                continue;
            }

            let ix_pubkey = &ix.data[PUBKEY_OFFSET..DIGEST_OFFSET];
            let ix_digest = &ix.data[DIGEST_OFFSET..SIGNATURE_OFFSET];
            let ix_sig = &ix.data[SIGNATURE_OFFSET..SIGVERIFY_IX_DATA_LEN];
            if ix_pubkey == public_key_xy && ix_digest == message_digest && ix_sig == signature_rs {
                return Ok(());
            }
        }
        Err(VerifierError::InvalidSignature.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::pubkey::Pubkey;

    const PUBKEY: [u8; 96] = [0x11; 96];
    const DIGEST: [u8; 48] = [0x22; 48];
    const SIG: [u8; 96] = [0x33; 96];

    fn serialize_instructions(ixs: &[(Pubkey, &[u8])], current_index: u16) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(ixs.len() as u16).to_le_bytes());
        let offsets_at = data.len();
        data.extend(vec![0u8; ixs.len() * 2]);
        for (i, (program_id, ix_data)) in ixs.iter().enumerate() {
            let offset = data.len() as u16;
            let start = offsets_at + i * 2;
            data[start..start + 2].copy_from_slice(&offset.to_le_bytes());
            data.extend_from_slice(&0u16.to_le_bytes());
            data.extend_from_slice(program_id.as_ref());
            data.extend_from_slice(&(ix_data.len() as u16).to_le_bytes());
            data.extend_from_slice(ix_data);
        }
        data.extend_from_slice(&current_index.to_le_bytes());
        data
    }

    fn sigverify_data_for(pubkey: &[u8; 96], digest: &[u8; 48], signature: &[u8; 96]) -> Vec<u8> {
        let mut data = vec![0u8; SIGVERIFY_IX_DATA_LEN];
        data[PUBKEY_OFFSET..DIGEST_OFFSET].copy_from_slice(pubkey);
        data[DIGEST_OFFSET..SIGNATURE_OFFSET].copy_from_slice(digest);
        data[SIGNATURE_OFFSET..SIGVERIFY_IX_DATA_LEN].copy_from_slice(signature);
        data
    }

    fn sigverify_data(digest: &[u8; 48]) -> Vec<u8> {
        sigverify_data_for(&PUBKEY, digest, &SIG)
    }

    fn sysvar_account<'a>(key: &'a Pubkey, lamports: &'a mut u64, data: &'a mut [u8]) -> AccountInfo<'a> {
        AccountInfo::new(key, false, false, lamports, data, key, false)
    }

    fn check(
        verifier: &InstructionIntrospectionVerifier,
        sysvar: Option<&AccountInfo>,
        digest: &[u8; 48],
    ) -> Result<(), ProgramError> {
        verifier.verify_p384(&PUBKEY, digest, &SIG, sysvar)
    }

    #[test]
    fn happy_path_binds_preceding_precompile() {
        let program_id = Pubkey::new_unique();
        let verifier = InstructionIntrospectionVerifier::new(program_id);
        let data = sigverify_data(&DIGEST);
        let current = [0u8; 1];
        let mut sysvar_data = serialize_instructions(&[(program_id, &data), (Pubkey::new_unique(), &current)], 1);
        let sysvar_key = instructions::ID;
        let mut lamports = 1;
        let acc = sysvar_account(&sysvar_key, &mut lamports, &mut sysvar_data);
        assert!(check(&verifier, Some(&acc), &DIGEST).is_ok());
    }

    #[test]
    fn rejects_wrong_sysvar_key() {
        let program_id = Pubkey::new_unique();
        let verifier = InstructionIntrospectionVerifier::new(program_id);
        let data = sigverify_data(&DIGEST);
        let current = [0u8; 1];
        let mut sysvar_data = serialize_instructions(&[(program_id, &data), (Pubkey::new_unique(), &current)], 1);
        let fake_key = Pubkey::new_unique();
        let mut lamports = 1;
        let acc = sysvar_account(&fake_key, &mut lamports, &mut sysvar_data);
        assert_eq!(check(&verifier, Some(&acc), &DIGEST), Err(ProgramError::IncorrectProgramId));
    }

    #[test]
    fn rejects_current_index_zero() {
        let program_id = Pubkey::new_unique();
        let verifier = InstructionIntrospectionVerifier::new(program_id);
        let current = [0u8; 1];
        let mut sysvar_data = serialize_instructions(&[(program_id, &current)], 0);
        let sysvar_key = instructions::ID;
        let mut lamports = 1;
        let acc = sysvar_account(&sysvar_key, &mut lamports, &mut sysvar_data);
        assert_eq!(check(&verifier, Some(&acc), &DIGEST), Err(VerifierError::InvalidInstruction.into()));
    }

    #[test]
    fn rejects_program_id_mismatch() {
        let expected = Pubkey::new_unique();
        let verifier = InstructionIntrospectionVerifier::new(expected);
        let data = sigverify_data(&DIGEST);
        let current = [0u8; 1];
        let mut sysvar_data =
            serialize_instructions(&[(Pubkey::new_unique(), &data), (Pubkey::new_unique(), &current)], 1);
        let sysvar_key = instructions::ID;
        let mut lamports = 1;
        let acc = sysvar_account(&sysvar_key, &mut lamports, &mut sysvar_data);
        assert_eq!(check(&verifier, Some(&acc), &DIGEST), Err(VerifierError::InvalidSignature.into()));
    }

    #[test]
    fn rejects_message_digest_mismatch() {
        let program_id = Pubkey::new_unique();
        let verifier = InstructionIntrospectionVerifier::new(program_id);
        let data = sigverify_data(&[0x44; 48]);
        let current = [0u8; 1];
        let mut sysvar_data = serialize_instructions(&[(program_id, &data), (Pubkey::new_unique(), &current)], 1);
        let sysvar_key = instructions::ID;
        let mut lamports = 1;
        let acc = sysvar_account(&sysvar_key, &mut lamports, &mut sysvar_data);
        assert_eq!(check(&verifier, Some(&acc), &DIGEST), Err(VerifierError::InvalidSignature.into()));
    }

    fn instructions_account(ixs: &[(Pubkey, &[u8])], current_index: u16) -> (Vec<u8>, u64) {
        (serialize_instructions(ixs, current_index), 1)
    }

    #[test]
    fn verifies_both_signatures_in_a_multi_sigverify_transaction() {
        let program_id = Pubkey::new_unique();
        let verifier = InstructionIntrospectionVerifier::new(program_id);
        const PUBKEY_0: [u8; 96] = [0x11; 96];
        const DIGEST_0: [u8; 48] = [0x22; 48];
        const SIG_0: [u8; 96] = [0x33; 96];
        const PUBKEY_1: [u8; 96] = [0x44; 96];
        const DIGEST_1: [u8; 48] = [0x55; 48];
        const SIG_1: [u8; 96] = [0x66; 96];
        let data_0 = sigverify_data_for(&PUBKEY_0, &DIGEST_0, &SIG_0);
        let data_1 = sigverify_data_for(&PUBKEY_1, &DIGEST_1, &SIG_1);
        let current = [0u8; 1];
        let (mut sysvar_data, mut lamports) =
            instructions_account(&[(program_id, &data_0), (program_id, &data_1), (Pubkey::new_unique(), &current)], 2);
        let sysvar_key = instructions::ID;
        let acc = sysvar_account(&sysvar_key, &mut lamports, &mut sysvar_data);
        assert!(verifier.verify_p384(&PUBKEY_0, &DIGEST_0, &SIG_0, Some(&acc)).is_ok());
        assert!(verifier.verify_p384(&PUBKEY_1, &DIGEST_1, &SIG_1, Some(&acc)).is_ok());
    }

    #[test]
    fn finds_non_adjacent_preceding_precompile() {
        let program_id = Pubkey::new_unique();
        let verifier = InstructionIntrospectionVerifier::new(program_id);
        let data = sigverify_data(&DIGEST);
        let unrelated = [0xAB; 4];
        let current = [0u8; 1];
        let (mut sysvar_data, mut lamports) = instructions_account(
            &[(program_id, &data), (Pubkey::new_unique(), &unrelated), (Pubkey::new_unique(), &current)],
            2,
        );
        let sysvar_key = instructions::ID;
        let acc = sysvar_account(&sysvar_key, &mut lamports, &mut sysvar_data);
        assert!(check(&verifier, Some(&acc), &DIGEST).is_ok());
    }

    #[test]
    fn rejects_when_no_preceding_instruction_matches() {
        let program_id = Pubkey::new_unique();
        let verifier = InstructionIntrospectionVerifier::new(program_id);
        let data_0 = sigverify_data_for(&[0x11; 96], &[0x22; 48], &[0x33; 96]);
        let data_1 = sigverify_data_for(&[0x44; 96], &[0x55; 48], &[0x66; 96]);
        let current = [0u8; 1];
        let (mut sysvar_data, mut lamports) =
            instructions_account(&[(program_id, &data_0), (program_id, &data_1), (Pubkey::new_unique(), &current)], 2);
        let sysvar_key = instructions::ID;
        let acc = sysvar_account(&sysvar_key, &mut lamports, &mut sysvar_data);
        assert_eq!(
            verifier.verify_p384(&[0x77; 96], &[0x88; 48], &[0x99; 96], Some(&acc)),
            Err(VerifierError::InvalidSignature.into())
        );
    }

    #[test]
    fn ignores_sigverify_that_has_not_executed() {
        let program_id = Pubkey::new_unique();
        let verifier = InstructionIntrospectionVerifier::new(program_id);
        let data = sigverify_data(&DIGEST);
        let current = [0u8; 1];
        let (mut sysvar_data, mut lamports) = instructions_account(
            &[(Pubkey::new_unique(), &current), (Pubkey::new_unique(), &current), (program_id, &data)],
            1,
        );
        let sysvar_key = instructions::ID;
        let acc = sysvar_account(&sysvar_key, &mut lamports, &mut sysvar_data);
        assert_eq!(check(&verifier, Some(&acc), &DIGEST), Err(VerifierError::InvalidSignature.into()));
    }

    #[test]
    fn rejects_precompile_data_longer_than_sigverify_len() {
        let program_id = Pubkey::new_unique();
        let verifier = InstructionIntrospectionVerifier::new(program_id);
        let mut data = sigverify_data(&DIGEST);
        data.push(0xFF);
        assert!(data.len() > SIGVERIFY_IX_DATA_LEN);
        let current = [0u8; 1];
        let mut sysvar_data = serialize_instructions(&[(program_id, &data), (Pubkey::new_unique(), &current)], 1);
        let sysvar_key = instructions::ID;
        let mut lamports = 1;
        let acc = sysvar_account(&sysvar_key, &mut lamports, &mut sysvar_data);
        assert_eq!(check(&verifier, Some(&acc), &DIGEST), Err(VerifierError::InvalidSignature.into()));
    }
}
