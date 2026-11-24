//! NVIDIA Hopper `verify_nvidia_attestation` builders.
//!
//! Legacy packet/PDA construction for local fixtures. Both NVIDIA modes are
//! disabled on chain with `NvidiaAttestationUnavailable` (custom 18). These
//! builders provide no hardware evidence or enrollment authority.
//!
//! @spec SCC-NVIDIA-002 SCC-NVIDIA-003 SCC-NVIDIA-004 SCC-NVIDIA-005

use solana_confidential_compute_cpi::ID as SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID;
use solana_sdk::hash::hashv;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;

use crate::backend_policy::{derive_backend_policy_pda, NVIDIA_SOURCE};
use crate::builder::{
    compute_commitment, derive_policy_registry_pda, derive_signer_pda, ensure_ix_packet_fits, SdkError,
};

/// `sha256("global:verify_nvidia_attestation")[..8]`.
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR: [u8; 8] = [31, 2, 40, 104, 69, 155, 234, 120];

/// Mode A (`verify_and_register_nvidia`).
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_MODE_A: u8 = 0;
/// Mode B (`verify_atomic_nvidia`).
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_MODE_B: u8 = 1;

/// Discriminator (8) + mode (1) + nonce slot (8) + action hash (32) + measurement (32).
pub const VERIFY_NVIDIA_ATTESTATION_LEN: usize = 8 + 1 + 8 + 32 + 32;

/// Read-only attested-signer account passed in Mode B. The program does not write it.
const MODE_B_ATTESTED_SIGNER_PLACEHOLDER: Pubkey = Pubkey::new_from_array([0xff; 32]);

/// Mode A nonce PDA.
///
/// `seed = SHA-256(workload_signer || gpu_measurement || slot_hash)`, then
/// `["nonce", 4, seed]`.
///
/// @spec SCC-NVIDIA-002 SCC-NVIDIA-004
pub fn derive_nvidia_nonce_pda(
    program_id: &Pubkey,
    workload_signer: &Pubkey,
    gpu_measurement: &[u8; 32],
    slot_hash: &[u8; 32],
) -> (Pubkey, u8) {
    let seed = hashv(&[workload_signer.as_ref(), gpu_measurement, slot_hash]).to_bytes();
    nvidia_nonce_pda(program_id, &seed)
}

fn nvidia_nonce_pda(program_id: &Pubkey, seed: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nonce", &[NVIDIA_SOURCE], seed], program_id)
}

fn require_mode(mode: u8) -> Result<u8, SdkError> {
    if mode != VERIFY_NVIDIA_MODE_A && mode != VERIFY_NVIDIA_MODE_B {
        return Err(SdkError::InvalidNvidiaMode);
    }
    Ok(mode)
}

/// Packs `verify_nvidia_attestation` against the canonical verifier id.
///
/// `slot_hash` is the `SlotHashes` entry for `nonce_slot`. Mode A derives the
/// nonce from the workload signer. Mode B derives it from
/// `SHA-256(slot_hash || action_hash || consumer_program_id)` and requires
/// `consumer_program_id`. Mode A ignores that argument.
///
/// @spec SCC-NVIDIA-003 SCC-NVIDIA-004 SCC-NVIDIA-005
#[allow(clippy::too_many_arguments)]
pub fn build_verify_nvidia_attestation_ix(
    payer: &Pubkey,
    workload_signer: &Pubkey,
    mode: u8,
    nonce_slot: u64,
    expected_action_hash: &[u8; 32],
    gpu_measurement: &[u8; 32],
    slot_hash: &[u8; 32],
    consumer_program_id: Option<&Pubkey>,
) -> Result<Instruction, SdkError> {
    build_verify_nvidia_attestation_ix_for_program(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        payer,
        workload_signer,
        mode,
        nonce_slot,
        expected_action_hash,
        gpu_measurement,
        slot_hash,
        consumer_program_id,
    )
}

/// Packs `verify_nvidia_attestation` against `program_id`.
///
/// @spec SCC-NVIDIA-003 SCC-NVIDIA-004 SCC-NVIDIA-005
#[allow(clippy::too_many_arguments)]
pub fn build_verify_nvidia_attestation_ix_for_program(
    program_id: &Pubkey,
    payer: &Pubkey,
    workload_signer: &Pubkey,
    mode: u8,
    nonce_slot: u64,
    expected_action_hash: &[u8; 32],
    gpu_measurement: &[u8; 32],
    slot_hash: &[u8; 32],
    consumer_program_id: Option<&Pubkey>,
) -> Result<Instruction, SdkError> {
    let mode = require_mode(mode)?;
    let (nonce_pda, _) = if mode == VERIFY_NVIDIA_MODE_A {
        derive_nvidia_nonce_pda(program_id, workload_signer, gpu_measurement, slot_hash)
    } else {
        let consumer = consumer_program_id.ok_or(SdkError::MissingNvidiaConsumerProgram)?;
        let commitment = compute_commitment(slot_hash, expected_action_hash, consumer);
        let seed = hashv(&[&commitment, gpu_measurement, slot_hash]).to_bytes();
        nvidia_nonce_pda(program_id, &seed)
    };
    let attested_signer = if mode == VERIFY_NVIDIA_MODE_A {
        let (signer_pda, _) = derive_signer_pda(program_id, &workload_signer.to_bytes());
        AccountMeta::new(signer_pda, false)
    } else {
        AccountMeta::new_readonly(MODE_B_ATTESTED_SIGNER_PLACEHOLDER, false)
    };
    let backend =
        derive_backend_policy_pda(program_id, NVIDIA_SOURCE).expect("NVIDIA source 4 is a supported backend").0;
    let mut data = Vec::with_capacity(VERIFY_NVIDIA_ATTESTATION_LEN);
    data.extend_from_slice(&VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR);
    data.push(mode);
    data.extend_from_slice(&nonce_slot.to_le_bytes());
    data.extend_from_slice(expected_action_hash);
    data.extend_from_slice(gpu_measurement);
    let mut accounts = vec![
        attested_signer,
        AccountMeta::new_readonly(derive_policy_registry_pda(program_id), false),
        AccountMeta::new(nonce_pda, false),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
    ];
    if mode == VERIFY_NVIDIA_MODE_A {
        accounts.push(AccountMeta::new_readonly(*workload_signer, true));
    } else {
        accounts.push(AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false));
    }
    accounts.push(AccountMeta::new_readonly(backend, false));
    let ix = Instruction { program_id: *program_id, accounts, data };
    ensure_ix_packet_fits(payer, &ix)?;
    Ok(ix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminator_matches_verifier() {
        assert_eq!(
            VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR,
            solana_confidential_compute_verifier::payload::VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR
        );
        assert_eq!(VERIFY_NVIDIA_MODE_A, solana_confidential_compute_verifier::payload::VERIFY_NVIDIA_MODE_A);
        assert_eq!(VERIFY_NVIDIA_MODE_B, solana_confidential_compute_verifier::payload::VERIFY_NVIDIA_MODE_B);
    }

    #[test]
    fn mode_a_bytes_accounts_and_nonce_match_processor() {
        let program_id = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let workload = Pubkey::new_unique();
        let slot_hash = [0x5a; 32];
        let gpu = [0x11; 32];
        let action = [0u8; 32];
        let ix = build_verify_nvidia_attestation_ix_for_program(
            &program_id,
            &payer,
            &workload,
            VERIFY_NVIDIA_MODE_A,
            105,
            &action,
            &gpu,
            &slot_hash,
            None,
        )
        .expect("mode A");
        assert_eq!(ix.data.len(), VERIFY_NVIDIA_ATTESTATION_LEN);
        assert_eq!(&ix.data[..8], &VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR);
        assert_eq!(ix.data[8], 0);
        assert_eq!(&ix.data[9..17], &105u64.to_le_bytes());
        assert_eq!(&ix.data[17..49], &action);
        assert_eq!(&ix.data[49..81], &gpu);
        let (nonce, _) = derive_nvidia_nonce_pda(&program_id, &workload, &gpu, &slot_hash);
        let (signer, _) = derive_signer_pda(&program_id, &workload.to_bytes());
        let backend = derive_backend_policy_pda(&program_id, NVIDIA_SOURCE).unwrap().0;
        assert_eq!(ix.accounts[0].pubkey, signer);
        assert!(ix.accounts[0].is_writable);
        assert_eq!(ix.accounts[2].pubkey, nonce);
        assert_eq!(ix.accounts[3].pubkey, payer);
        assert!(ix.accounts[3].is_signer && ix.accounts[3].is_writable);
        assert_eq!(ix.accounts[7].pubkey, workload);
        assert!(ix.accounts[7].is_signer && !ix.accounts[7].is_writable);
        assert_eq!(ix.accounts[8].pubkey, backend);
        assert!(!ix.accounts[8].is_writable);
        let zero = derive_nvidia_nonce_pda(&program_id, &workload, &gpu, &[0u8; 32]);
        assert_ne!(nonce, zero.0);
    }

    #[test]
    fn mode_b_binds_consumer_commitment_and_rejects_a_missing_consumer() {
        let program_id = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let workload = Pubkey::new_unique();
        let consumer = Pubkey::new_unique();
        let slot_hash = [0x22; 32];
        let gpu = [0x33; 32];
        let action = [0x44; 32];
        let missing = build_verify_nvidia_attestation_ix_for_program(
            &program_id,
            &payer,
            &workload,
            VERIFY_NVIDIA_MODE_B,
            9,
            &action,
            &gpu,
            &slot_hash,
            None,
        );
        assert_eq!(missing, Err(SdkError::MissingNvidiaConsumerProgram));
        let ix = build_verify_nvidia_attestation_ix_for_program(
            &program_id,
            &payer,
            &workload,
            VERIFY_NVIDIA_MODE_B,
            9,
            &action,
            &gpu,
            &slot_hash,
            Some(&consumer),
        )
        .expect("mode B");
        let commitment = compute_commitment(&slot_hash, &action, &consumer);
        let seed = hashv(&[&commitment, &gpu, &slot_hash]).to_bytes();
        let (nonce, _) = nvidia_nonce_pda(&program_id, &seed);
        assert_eq!(ix.accounts[2].pubkey, nonce);
        assert_eq!(ix.accounts[0].pubkey, MODE_B_ATTESTED_SIGNER_PLACEHOLDER);
        assert!(!ix.accounts[0].is_writable);
        assert_eq!(ix.accounts[7].pubkey, solana_sdk::sysvar::instructions::ID);
        assert_ne!(nonce, derive_nvidia_nonce_pda(&program_id, &workload, &gpu, &slot_hash).0);
    }

    #[test]
    fn unknown_mode_fails_closed() {
        let program_id = Pubkey::new_unique();
        let err = build_verify_nvidia_attestation_ix_for_program(
            &program_id,
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            2,
            1,
            &[0; 32],
            &[0; 32],
            &[0; 32],
            None,
        );
        assert_eq!(err, Err(SdkError::InvalidNvidiaMode));
    }
}
