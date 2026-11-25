//! Off-chain instruction and transaction builders for Mode A and Mode B.
//!
//! @spec SCC-SDK-001 SCC-SEC-005

use solana_confidential_compute_core::{
    compute_action_commitment, SnpReportView, MAX_NITRO_DOCUMENT_LEN, SNP_REPORT_SIZE,
};
use solana_confidential_compute_cpi::{ATTESTED_SIGNER_SEED, ID as SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID};
use solana_sdk::hash::{hash, Hash};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use thiserror::Error;

/// Versioned cache namespace; legacy caches require full chain revalidation.
pub const VCEK_SEED: &[u8] = b"vcek_v2";

/// Anchor discriminator for `verify_and_register`.
pub const VERIFY_AND_REGISTER_DISCRIMINATOR: [u8; 8] = [246, 249, 100, 14, 102, 116, 92, 145];

/// On-chain TTL applied by `verify_and_register` (`clock.slot + TTL`).
pub const ATTESTATION_TTL_SLOTS: u64 = 216_000;

/// Discriminator (8) + `nonce_slot` (8) + report (1184) + `nonce_bump` + `signer_bump`.
///
/// On-chain rest length is `8 + SNP_REPORT_SIZE + 2`. With the discriminator the
/// instruction is 1,202 bytes.
/// @spec SCC-SEC-008 SCC-ARCH-001 SCC-SDK-001
pub const VERIFY_AND_REGISTER_IX_LEN: usize = 8 + 8 + SNP_REPORT_SIZE + 2;

/// Discriminator (8) + `VerifyAtomicHeader` (72) + report (1184) + `nonce_bump`.
///
/// On-chain rest length is `VerifyAtomicHeader::SIZE + SNP_REPORT_SIZE + 1`.
/// With the discriminator the instruction is 1,265 bytes.
/// @spec SCC-SEC-008 SCC-ARCH-001 SCC-SDK-001
pub const VERIFY_ATOMIC_WITH_NONCE_IX_LEN: usize = 8 + 72 + SNP_REPORT_SIZE + 1;

/// Legacy cluster UDP cap (`solana_packet::PACKET_DATA_SIZE`).
pub const PACKET_DATA_SIZE: usize = solana_packet::PACKET_DATA_SIZE;

/// Builder failures for malformed reports, signing, or an unsendable packet.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SdkError {
    #[error("workload keys must not sign System Program instructions")]
    DisallowedInstruction,
    #[error("SNP report must be exactly {SNP_REPORT_SIZE} bytes")]
    InvalidReportSize,
    #[error("VLEK reports require the endorsement P-384 public key (96-byte X || Y)")]
    MissingEndorsementKey,
    #[error("report measurement does not match expected measurement")]
    MeasurementMismatch,
    #[error("report workload signer does not match signer pubkey")]
    SignerMismatch,
    #[error("Nitro mode must be 0 (Mode A) or 1 (Mode B)")]
    InvalidNitroMode,
    #[error("NVIDIA mode must be 0 (Mode A) or 1 (Mode B)")]
    InvalidNvidiaMode,
    #[error("NVIDIA Mode B requires the next consumer program id")]
    MissingNvidiaConsumerProgram,
    #[error("Nitro document must be 1 to {MAX_NITRO_DOCUMENT_LEN} bytes")]
    InvalidNitroDocument,
    #[error("Mode B requires a consumer instruction at index 1")]
    MissingConsumerInstruction,
    #[error("failed to sign transaction")]
    SignError,
    /// Raw 1,184-byte reports do not fit in a 1,232-byte legacy packet.
    #[error("serialized transaction is {len} bytes and exceeds the 1232-byte packet limit")]
    PacketTooLarge { len: usize },
    #[error("instruction data is {actual} bytes, expected {expected}")]
    InstructionDataLengthMismatch { expected: usize, actual: usize },
}

pub(crate) fn ensure_packet_fits(tx: &Transaction) -> Result<(), SdkError> {
    let len = bincode::serialized_size(tx).map_err(|_| SdkError::SignError)? as usize;
    if len > PACKET_DATA_SIZE {
        return Err(SdkError::PacketTooLarge { len });
    }
    Ok(())
}

pub(crate) fn ensure_ix_packet_fits(payer: &Pubkey, ix: &Instruction) -> Result<(), SdkError> {
    let tx = Transaction::new_with_payer(std::slice::from_ref(ix), Some(payer));
    ensure_packet_fits(&tx)
}

pub(crate) fn parse_report(report: &[u8]) -> Result<SnpReportView<'_>, SdkError> {
    SnpReportView::try_from_slice(report).map_err(|_| SdkError::InvalidReportSize)
}

pub(crate) fn chip_id_hash(view: &SnpReportView<'_>, endorsement_xy: Option<&[u8; 96]>) -> Result<[u8; 32], SdkError> {
    if view.is_vlek() {
        Ok(hash(endorsement_xy.ok_or(SdkError::MissingEndorsementKey)?).to_bytes())
    } else {
        Ok(hash(view.chip_id()).to_bytes())
    }
}

pub(crate) fn derive_signer_pda(program_id: &Pubkey, signer: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ATTESTED_SIGNER_SEED, signer], program_id)
}

pub(crate) fn derive_policy_registry_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"policy_registry"], program_id).0
}

pub(crate) fn derive_vcek_pda(program_id: &Pubkey, chip_id_hash: &[u8; 32], tcb_version: u64) -> Pubkey {
    Pubkey::find_program_address(&[VCEK_SEED, chip_id_hash, &tcb_version.to_le_bytes()], program_id).0
}

/// SHA-256(`slot_hash || action_hash || consumer_program_id`).
///
/// @spec SCC-VERIFY-012 SCC-SDK-001
pub fn compute_commitment(slot_hash: &[u8; 32], action_hash: &[u8; 32], consumer_program_id: &Pubkey) -> [u8; 32] {
    compute_action_commitment(slot_hash, action_hash, &consumer_program_id.to_bytes())
}

/// Mode A enrollment: `verify_and_register` with nonce slot 0.
///
/// Returns [`SdkError::PacketTooLarge`] for a raw 1,184-byte report. The
/// quarantined packer is `internal::build_register_signer_ix_oversized` (requires `test-utils`).
///
/// `expires_slot` is caller-side bookkeeping only; on-chain expiry is computed
/// by `clock.slot + ATTESTATION_TTL_SLOTS`. The verifier writes that TTL from
/// `Clock` and does not read this argument.
///
/// @spec SCC-SDK-001
pub fn build_register_signer_ix(
    payer: &Pubkey,
    signer: &Pubkey,
    report_data: &[u8],
    expires_slot: u64,
) -> Result<Instruction, SdkError> {
    build_register_signer_ix_for_program(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        payer,
        signer,
        report_data,
        expires_slot,
        0,
    )
}

/// Mode A enrollment against `program_id` at `nonce_slot`.
///
/// Returns [`SdkError::PacketTooLarge`] for a raw 1,184-byte report.
///
/// `_expires_slot` is caller-side bookkeeping only; on-chain expiry is computed
/// by `clock.slot + ATTESTATION_TTL_SLOTS`.
///
/// @spec SCC-SDK-001
pub fn build_register_signer_ix_for_program(
    program_id: &Pubkey,
    payer: &Pubkey,
    signer: &Pubkey,
    report_data: &[u8],
    expires_slot: u64,
    nonce_slot: u64,
) -> Result<Instruction, SdkError> {
    let ix = crate::internal::build_register_signer_ix_for_program_oversized(
        program_id,
        payer,
        signer,
        report_data,
        expires_slot,
        nonce_slot,
    )?;
    ensure_ix_packet_fits(payer, &ix)?;
    Ok(ix)
}

/// Mode A execution: consumer instruction signed by the attested workload key.
///
/// The workload key must stay inside the enclave. Production callers should use
/// the sidecar `/v1/sign` boundary. This local signing helper rejects every System
/// Program instruction but does not authenticate a custom consumer or validate
/// its instruction data. Callers must enforce their application policy before
/// passing an instruction here; this is not the sidecar transaction screen.
///
/// @spec SCC-SDK-001
pub fn build_session_action_tx(
    payer: &Pubkey,
    signer_keypair: &Keypair,
    consumer_ix: Instruction,
    recent_blockhash: Hash,
) -> Result<Transaction, SdkError> {
    if consumer_ix.program_id == solana_sdk_ids::system_program::ID {
        return Err(SdkError::DisallowedInstruction);
    }
    let mut ix = consumer_ix;
    let signer_pk = signer_keypair.pubkey();
    let mut found = false;
    for meta in &mut ix.accounts {
        if meta.pubkey == signer_pk {
            meta.is_signer = true;
            found = true;
        }
    }
    if !found && signer_pk != *payer {
        ix.accounts.push(AccountMeta::new_readonly(signer_pk, true));
    }
    let mut tx = Transaction::new_with_payer(&[ix], Some(payer));
    tx.try_partial_sign(&[signer_keypair], recent_blockhash).map_err(|_| SdkError::SignError)?;
    ensure_packet_fits(&tx)?;
    Ok(tx)
}

/// Mode B atomic transaction: `verify_atomic_with_nonce` at index 0, consumer at index 1.
///
/// Always packs [`VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR`] (`require_nonce == true`).
/// Returns [`SdkError::PacketTooLarge`] for a raw 1,184-byte report. The
/// quarantined packer is `internal::build_atomic_attestation_tx_oversized` (requires `test-utils`).
///
/// @spec SCC-SDK-001 SCC-SEC-005
#[allow(clippy::too_many_arguments)]
pub fn build_atomic_attestation_tx(
    payer: &Pubkey,
    consumer_program_id: &Pubkey,
    action_hash: [u8; 32],
    measurement: [u8; 48],
    report: &[u8],
    consumer_ix: Instruction,
    recent_blockhash: Hash,
) -> Result<Transaction, SdkError> {
    build_atomic_attestation_tx_for_program(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        payer,
        consumer_program_id,
        action_hash,
        measurement,
        report,
        consumer_ix,
        recent_blockhash,
        0,
    )
}

/// Mode B atomic transaction against `program_id` at `nonce_slot`.
///
/// Returns [`SdkError::PacketTooLarge`] for a raw 1,184-byte report.
///
/// @spec SCC-SDK-001 SCC-SEC-005
#[allow(clippy::too_many_arguments)]
pub fn build_atomic_attestation_tx_for_program(
    program_id: &Pubkey,
    payer: &Pubkey,
    consumer_program_id: &Pubkey,
    action_hash: [u8; 32],
    measurement: [u8; 48],
    report: &[u8],
    consumer_ix: Instruction,
    recent_blockhash: Hash,
    nonce_slot: u64,
) -> Result<Transaction, SdkError> {
    let tx = crate::internal::build_atomic_attestation_tx_for_program_oversized(
        program_id,
        payer,
        consumer_program_id,
        action_hash,
        measurement,
        report,
        consumer_ix,
        recent_blockhash,
        nonce_slot,
    )?;
    ensure_packet_fits(&tx)?;
    Ok(tx)
}

/// Packs `verify_atomic_with_nonce` (never the fail-closed `verify_atomic` path).
///
/// Returns [`SdkError::PacketTooLarge`] for a raw 1,184-byte report.
///
/// @spec SCC-SDK-001 SCC-SEC-005
#[allow(clippy::too_many_arguments)]
pub fn build_verify_atomic_with_nonce_ix(
    program_id: &Pubkey,
    payer: &Pubkey,
    consumer_program_id: &Pubkey,
    action_hash: [u8; 32],
    measurement: [u8; 48],
    report: &[u8],
    nonce_slot: u64,
) -> Result<Instruction, SdkError> {
    let ix = crate::internal::build_verify_atomic_with_nonce_ix_oversized(
        program_id,
        payer,
        consumer_program_id,
        action_hash,
        measurement,
        report,
        nonce_slot,
    )?;
    ensure_ix_packet_fits(payer, &ix)?;
    Ok(ix)
}

/// Explicit endorsement XY for VLEK; chain trust remains the verifier's job.
/// Raw reports still fail the cluster packet bound.
#[allow(clippy::too_many_arguments)]
pub fn build_register_signer_ix_for_program_with_endorsement(
    program_id: &Pubkey,
    payer: &Pubkey,
    signer: &Pubkey,
    report_data: &[u8],
    expires_slot: u64,
    nonce_slot: u64,
    endorsement_xy: &[u8; 96],
) -> Result<Instruction, SdkError> {
    let result = crate::internal::build_register_signer_ix_for_program_oversized_with_endorsement(
        program_id,
        payer,
        signer,
        report_data,
        expires_slot,
        nonce_slot,
        Some(endorsement_xy),
    )?;
    ensure_ix_packet_fits(payer, &result)?;
    Ok(result)
}

/// Explicit endorsement XY for VLEK; chain trust remains the verifier's job.
/// Raw reports still fail the cluster packet bound.
#[allow(clippy::too_many_arguments)]
pub fn build_verify_atomic_with_nonce_ix_with_endorsement(
    program_id: &Pubkey,
    payer: &Pubkey,
    consumer_program_id: &Pubkey,
    action_hash: [u8; 32],
    measurement: [u8; 48],
    report: &[u8],
    nonce_slot: u64,
    endorsement_xy: &[u8; 96],
) -> Result<Instruction, SdkError> {
    let result = crate::internal::build_verify_atomic_with_nonce_ix_oversized_with_endorsement(
        program_id,
        payer,
        consumer_program_id,
        action_hash,
        measurement,
        report,
        nonce_slot,
        Some(endorsement_xy),
    )?;
    ensure_ix_packet_fits(payer, &result)?;
    Ok(result)
}

/// Explicit endorsement XY for VLEK; chain trust remains the verifier's job.
/// Raw reports still fail the cluster packet bound.
#[allow(clippy::too_many_arguments)]
pub fn build_atomic_attestation_tx_for_program_with_endorsement(
    program_id: &Pubkey,
    payer: &Pubkey,
    consumer_program_id: &Pubkey,
    action_hash: [u8; 32],
    measurement: [u8; 48],
    report: &[u8],
    consumer_ix: Instruction,
    recent_blockhash: Hash,
    nonce_slot: u64,
    endorsement_xy: &[u8; 96],
) -> Result<Transaction, SdkError> {
    let result = crate::internal::build_atomic_attestation_tx_for_program_oversized_with_endorsement(
        program_id,
        payer,
        consumer_program_id,
        action_hash,
        measurement,
        report,
        consumer_ix,
        recent_blockhash,
        nonce_slot,
        Some(endorsement_xy),
    )?;
    ensure_packet_fits(&result)?;
    Ok(result)
}
