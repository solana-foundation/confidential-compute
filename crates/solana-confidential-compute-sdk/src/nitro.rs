//! AWS Nitro Enclave instruction and transaction builders.
//!
//! Packs `verify_nitro_attestation` for Mode A registration and Mode B atomic
//! execution. Layout matches the TypeScript client and the on-chain zero-copy
//! parser: discriminator, mode, nonce slot, action hash, document length, document.
//!
//! @spec SCC-NITRO-008 SCC-SDK-001 SCC-PERF-002

use solana_confidential_compute_core::MAX_NITRO_DOCUMENT_LEN;
use solana_confidential_compute_cpi::ID as SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;

use crate::builder::{
    derive_policy_registry_pda, derive_signer_pda, ensure_ix_packet_fits, ensure_packet_fits, SdkError,
};

pub use solana_confidential_compute_cpi::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR;

/// Mode A (`verify_and_register_nitro`): register `AttestedSignerAccount`.
/// @spec SCC-NITRO-008
pub const VERIFY_NITRO_MODE_A: u8 = 0;
/// Mode B (`verify_atomic_nitro`): action commitment + nonce tombstone.
/// @spec SCC-NITRO-008
pub const VERIFY_NITRO_MODE_B: u8 = 1;

/// Discriminator (8) + mode (1) + nonce_slot (8) + action hash (32) + doc_len (4).
pub const VERIFY_NITRO_ATTESTATION_HEADER_LEN: usize = 8 + 1 + 8 + 32 + 4;

/// Uninitialized attested-signer account passed in Mode B. The program does not write it.
///
/// Read-only so Sealevel does not take a cluster-wide write lock on this address.
/// @spec SCC-PERF-002
pub const NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER: Pubkey = Pubkey::new_from_array([0xff; 32]);

fn require_nitro_mode(mode: u8) -> Result<u8, SdkError> {
    if mode != VERIFY_NITRO_MODE_A && mode != VERIFY_NITRO_MODE_B {
        return Err(SdkError::InvalidNitroMode);
    }
    Ok(mode)
}

fn require_nitro_document(document: &[u8]) -> Result<&[u8], SdkError> {
    if document.is_empty() || document.len() > MAX_NITRO_DOCUMENT_LEN {
        return Err(SdkError::InvalidNitroDocument);
    }
    Ok(document)
}

fn nitro_accounts(
    program_id: &Pubkey,
    payer: &Pubkey,
    workload_signer: &Pubkey,
    mode: u8,
    nonce: &[u8; 32],
) -> Vec<AccountMeta> {
    let signer_bytes = workload_signer.to_bytes();
    let policy_registry = derive_policy_registry_pda(program_id);
    // Nitro instruction data does not carry bump bytes. The program derives them.
    let (used_nonce, _) = crate::nonce::derive_used_nonce_pda_for_source(program_id, 2, &signer_bytes, nonce)
        .expect("fixed Nitro source");
    let attested_signer = if mode == VERIFY_NITRO_MODE_A {
        let (attested_signer, _) = derive_signer_pda(program_id, &signer_bytes);
        AccountMeta::new(attested_signer, false)
    } else {
        AccountMeta::new_readonly(NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER, false)
    };

    let mut accounts = vec![
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(policy_registry, false),
        attested_signer,
        AccountMeta::new(used_nonce, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
    ];
    if mode == VERIFY_NITRO_MODE_A {
        accounts.push(AccountMeta::new_readonly(*workload_signer, true));
    }
    if mode == VERIFY_NITRO_MODE_B {
        accounts.push(AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false));
    }
    accounts
}

fn nitro_instruction_data(
    mode: u8,
    nonce_slot: u64,
    expected_action_hash: &[u8; 32],
    document: &[u8],
) -> Result<Vec<u8>, SdkError> {
    let doc_len = u32::try_from(document.len()).map_err(|_| SdkError::InvalidNitroDocument)?;
    let mut data = Vec::with_capacity(VERIFY_NITRO_ATTESTATION_HEADER_LEN + document.len());
    data.extend_from_slice(&VERIFY_NITRO_ATTESTATION_DISCRIMINATOR);
    data.push(mode);
    data.extend_from_slice(&nonce_slot.to_le_bytes());
    data.extend_from_slice(expected_action_hash);
    data.extend_from_slice(&doc_len.to_le_bytes());
    data.extend_from_slice(document);
    Ok(data)
}

/// Packs `verify_nitro_attestation` (Mode A or Mode B) against `program_id`.
///
/// Returns [`SdkError::PacketTooLarge`] when the legacy packet exceeds
/// [`crate::PACKET_DATA_SIZE`]. `nonce` is the 32-byte document nonce: the
/// SlotHashes entry in Mode A, and the action commitment in Mode B.
///
/// @spec SCC-NITRO-008 SCC-SDK-001 SCC-PERF-002
#[allow(clippy::too_many_arguments)]
pub fn build_verify_nitro_attestation_ix_for_program(
    program_id: &Pubkey,
    payer: &Pubkey,
    workload_signer: &Pubkey,
    mode: u8,
    nonce_slot: u64,
    expected_action_hash: [u8; 32],
    document: &[u8],
    nonce: &[u8; 32],
) -> Result<Instruction, SdkError> {
    let ix = build_verify_nitro_attestation_ix_for_program_oversized(
        program_id,
        payer,
        workload_signer,
        mode,
        nonce_slot,
        expected_action_hash,
        document,
        nonce,
    )?;
    ensure_ix_packet_fits(payer, &ix)?;
    Ok(ix)
}

/// Packs `verify_nitro_attestation` (Mode A or Mode B).
///
/// Returns [`SdkError::PacketTooLarge`] when the legacy packet exceeds
/// [`crate::PACKET_DATA_SIZE`].
///
/// @spec SCC-NITRO-008 SCC-SDK-001 SCC-PERF-002
pub fn build_verify_nitro_attestation_ix(
    payer: &Pubkey,
    workload_signer: &Pubkey,
    mode: u8,
    nonce_slot: u64,
    expected_action_hash: [u8; 32],
    document: &[u8],
    nonce: &[u8; 32],
) -> Result<Instruction, SdkError> {
    build_verify_nitro_attestation_ix_for_program(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        payer,
        workload_signer,
        mode,
        nonce_slot,
        expected_action_hash,
        document,
        nonce,
    )
}

fn pack_nitro_tx(
    payer: &Pubkey,
    confidential_compute_ix: Instruction,
    mode: u8,
    consumer_ix: Option<Instruction>,
    recent_blockhash: Hash,
) -> Result<Transaction, SdkError> {
    let mut instructions = vec![confidential_compute_ix];
    match (mode, consumer_ix) {
        (VERIFY_NITRO_MODE_B, None) => return Err(SdkError::MissingConsumerInstruction),
        (_, Some(consumer_ix)) => instructions.push(consumer_ix),
        (_, None) => {}
    }
    let mut tx = Transaction::new_with_payer(&instructions, Some(payer));
    tx.message.recent_blockhash = recent_blockhash;
    Ok(tx)
}

/// Builds a `verify_nitro_attestation` transaction against `program_id`.
///
/// Mode B packs the Solana Confidential Compute instruction at index 0 and the consumer instruction
/// at index 1. Mode A packs the Solana Confidential Compute instruction and appends `consumer_ix`
/// when the caller provides one. Returns [`SdkError::PacketTooLarge`] when the
/// legacy packet exceeds [`crate::PACKET_DATA_SIZE`].
///
/// @spec SCC-NITRO-008 SCC-SDK-001 SCC-SEC-005 SCC-PERF-002
#[allow(clippy::too_many_arguments)]
pub fn build_verify_nitro_attestation_tx_for_program(
    program_id: &Pubkey,
    payer: &Pubkey,
    workload_signer: &Pubkey,
    mode: u8,
    nonce_slot: u64,
    expected_action_hash: [u8; 32],
    document: &[u8],
    nonce: &[u8; 32],
    recent_blockhash: Hash,
    consumer_ix: Option<Instruction>,
) -> Result<Transaction, SdkError> {
    let tx = build_verify_nitro_attestation_tx_for_program_oversized(
        program_id,
        payer,
        workload_signer,
        mode,
        nonce_slot,
        expected_action_hash,
        document,
        nonce,
        recent_blockhash,
        consumer_ix,
    )?;
    ensure_packet_fits(&tx)?;
    if mode == VERIFY_NITRO_MODE_B {
        crate::validate_compiled_action(
            &solana_sdk::message::VersionedMessage::Legacy(tx.message.clone()),
            1,
            &expected_action_hash,
        )
        .map_err(|_| SdkError::DisallowedInstruction)?;
    }
    Ok(tx)
}

/// Builds a `verify_nitro_attestation` transaction.
///
/// Mode B packs the Solana Confidential Compute instruction at index 0 and the consumer instruction
/// at index 1. Mode A packs the Solana Confidential Compute instruction and appends `consumer_ix`
/// when the caller provides one.
///
/// @spec SCC-NITRO-008 SCC-SDK-001 SCC-SEC-005 SCC-PERF-002
#[allow(clippy::too_many_arguments)]
pub fn build_verify_nitro_attestation_tx(
    payer: &Pubkey,
    workload_signer: &Pubkey,
    mode: u8,
    nonce_slot: u64,
    expected_action_hash: [u8; 32],
    document: &[u8],
    nonce: &[u8; 32],
    recent_blockhash: Hash,
    consumer_ix: Option<Instruction>,
) -> Result<Transaction, SdkError> {
    build_verify_nitro_attestation_tx_for_program(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        payer,
        workload_signer,
        mode,
        nonce_slot,
        expected_action_hash,
        document,
        nonce,
        recent_blockhash,
        consumer_ix,
    )
}

#[allow(dead_code)]
mod oversized {
    use super::*;
    /// Quarantined `verify_nitro_attestation` packer against `program_id`.
    ///
    /// Program-test and dry-run only. Do not submit the instruction to a live cluster.
    ///
    /// @spec SCC-NITRO-008 SCC-SDK-001
    #[allow(clippy::too_many_arguments)]
    pub fn build_verify_nitro_attestation_ix_for_program_oversized(
        program_id: &Pubkey,
        payer: &Pubkey,
        workload_signer: &Pubkey,
        mode: u8,
        nonce_slot: u64,
        expected_action_hash: [u8; 32],
        document: &[u8],
        nonce: &[u8; 32],
    ) -> Result<Instruction, SdkError> {
        let mode = require_nitro_mode(mode)?;
        let document = require_nitro_document(document)?;
        Ok(crate::nonce::with_legacy_nonce(
            crate::backend_policy::with_backend_policy(
                Instruction {
                    program_id: *program_id,
                    accounts: nitro_accounts(program_id, payer, workload_signer, mode, nonce),
                    data: nitro_instruction_data(mode, nonce_slot, &expected_action_hash, document)?,
                },
                crate::backend_policy::NITRO_SOURCE,
            ),
            crate::nonce::derive_legacy_used_nonce_pda(program_id, &workload_signer.to_bytes(), nonce).0,
        ))
    }

    /// Quarantined `verify_nitro_attestation` packer.
    ///
    /// Program-test and dry-run only. Do not submit the instruction to a live cluster.
    ///
    /// @spec SCC-NITRO-008 SCC-SDK-001
    pub fn build_verify_nitro_attestation_ix_oversized(
        payer: &Pubkey,
        workload_signer: &Pubkey,
        mode: u8,
        nonce_slot: u64,
        expected_action_hash: [u8; 32],
        document: &[u8],
        nonce: &[u8; 32],
    ) -> Result<Instruction, SdkError> {
        build_verify_nitro_attestation_ix_for_program_oversized(
            &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
            payer,
            workload_signer,
            mode,
            nonce_slot,
            expected_action_hash,
            document,
            nonce,
        )
    }

    /// Quarantined Nitro transaction against `program_id`.
    ///
    /// Mode B places the Solana Confidential Compute instruction at index 0 and the consumer at index 1.
    /// Mode A appends `consumer_ix` when it is `Some`. Program-test only.
    ///
    /// @spec SCC-NITRO-008 SCC-SDK-001 SCC-SEC-005
    #[allow(clippy::too_many_arguments)]
    pub fn build_verify_nitro_attestation_tx_for_program_oversized(
        program_id: &Pubkey,
        payer: &Pubkey,
        workload_signer: &Pubkey,
        mode: u8,
        nonce_slot: u64,
        expected_action_hash: [u8; 32],
        document: &[u8],
        nonce: &[u8; 32],
        recent_blockhash: Hash,
        consumer_ix: Option<Instruction>,
    ) -> Result<Transaction, SdkError> {
        let mode = require_nitro_mode(mode)?;
        if mode == VERIFY_NITRO_MODE_B && consumer_ix.is_none() {
            return Err(SdkError::MissingConsumerInstruction);
        }
        let confidential_compute_ix = build_verify_nitro_attestation_ix_for_program_oversized(
            program_id,
            payer,
            workload_signer,
            mode,
            nonce_slot,
            expected_action_hash,
            document,
            nonce,
        )?;
        pack_nitro_tx(payer, confidential_compute_ix, mode, consumer_ix, recent_blockhash)
    }

    /// Quarantined Nitro transaction.
    ///
    /// Program-test only. Do not submit the transaction to a live cluster.
    ///
    /// @spec SCC-NITRO-008 SCC-SDK-001 SCC-SEC-005
    #[allow(clippy::too_many_arguments)]
    pub fn build_verify_nitro_attestation_tx_oversized(
        payer: &Pubkey,
        workload_signer: &Pubkey,
        mode: u8,
        nonce_slot: u64,
        expected_action_hash: [u8; 32],
        document: &[u8],
        nonce: &[u8; 32],
        recent_blockhash: Hash,
        consumer_ix: Option<Instruction>,
    ) -> Result<Transaction, SdkError> {
        build_verify_nitro_attestation_tx_for_program_oversized(
            &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
            payer,
            workload_signer,
            mode,
            nonce_slot,
            expected_action_hash,
            document,
            nonce,
            recent_blockhash,
            consumer_ix,
        )
    }
}

#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub use oversized::{
    build_verify_nitro_attestation_ix_for_program_oversized, build_verify_nitro_attestation_ix_oversized,
    build_verify_nitro_attestation_tx_for_program_oversized, build_verify_nitro_attestation_tx_oversized,
};
#[cfg(not(feature = "test-utils"))]
#[allow(unused_imports)]
pub(crate) use oversized::{
    build_verify_nitro_attestation_ix_for_program_oversized, build_verify_nitro_attestation_ix_oversized,
    build_verify_nitro_attestation_tx_for_program_oversized, build_verify_nitro_attestation_tx_oversized,
};
