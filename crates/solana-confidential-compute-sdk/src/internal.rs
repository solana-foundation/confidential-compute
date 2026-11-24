//! Quarantined raw-report packers.
//!
//! These builders emit instruction data that does not fit in the 1,232-byte
//! cluster packet. Program-test and dry-run only. They are not part of the
//! supported client API (`solana_confidential_compute_sdk::internal::*`, matching the TypeScript
//! `internal/oversized` module).
//!
//! Mode B digests must use the V3 compiled-privilege contract. These raw
//! packers intentionally only serialize harness bytes; they do not authorize
//! execution. Call `validate_compiled_action` on the final message, and the
//! consumer must recompute V3 from AccountInfo. There is no V1 consumer fallback.
//!
//! @spec SCC-SDK-001 SCC-ANCHOR-001

use solana_confidential_compute_core::SNP_REPORT_SIZE;
use solana_confidential_compute_cpi::{
    ID as SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID, VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
};
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;

use crate::builder::{
    chip_id_hash, derive_policy_registry_pda, derive_signer_pda, derive_vcek_pda, parse_report, SdkError,
    VERIFY_AND_REGISTER_DISCRIMINATOR, VERIFY_AND_REGISTER_IX_LEN, VERIFY_ATOMIC_WITH_NONCE_IX_LEN,
};

/// Quarantined Mode A packer. The raw report does not fit in [`crate::builder::PACKET_DATA_SIZE`].
///
/// Program-test and dry-run only. Do not submit the instruction to a live cluster.
///
/// @spec SCC-SDK-001
pub fn build_register_signer_ix_oversized(
    payer: &Pubkey,
    signer: &Pubkey,
    report_data: &[u8],
    expires_slot: u64,
) -> Result<Instruction, SdkError> {
    build_register_signer_ix_for_program_oversized(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        payer,
        signer,
        report_data,
        expires_slot,
        0,
    )
}

/// Quarantined Mode A packer against `program_id`.
///
/// @spec SCC-SDK-001
pub fn build_register_signer_ix_for_program_oversized(
    program_id: &Pubkey,
    payer: &Pubkey,
    signer: &Pubkey,
    report_data: &[u8],
    _expires_slot: u64,
    nonce_slot: u64,
) -> Result<Instruction, SdkError> {
    build_register_signer_ix_for_program_oversized_with_endorsement(
        program_id,
        payer,
        signer,
        report_data,
        _expires_slot,
        nonce_slot,
        None,
    )
}

/// Explicit endorsement-key variant for VLEK component harnesses.
#[allow(clippy::too_many_arguments)]
pub fn build_register_signer_ix_for_program_oversized_with_endorsement(
    program_id: &Pubkey,
    payer: &Pubkey,
    signer: &Pubkey,
    report_data: &[u8],
    _expires_slot: u64,
    nonce_slot: u64,
    endorsement_xy: Option<&[u8; 96]>,
) -> Result<Instruction, SdkError> {
    let view = parse_report(report_data)?;
    if view.pubkey() != signer.to_bytes() {
        return Err(SdkError::SignerMismatch);
    }

    let signer_pubkey = signer.to_bytes();
    let nonce = view.nonce();
    let policy_registry = derive_policy_registry_pda(program_id);
    let vcek = derive_vcek_pda(program_id, &chip_id_hash(&view, endorsement_xy)?, view.reported_tcb());
    let (signer_pda, signer_bump) = derive_signer_pda(program_id, &signer_pubkey);
    let (nonce_pda, nonce_bump) = crate::nonce::derive_used_nonce_pda_for_source(program_id, 1, &signer_pubkey, &nonce)
        .expect("fixed AMD source");

    let mut data = Vec::with_capacity(VERIFY_AND_REGISTER_IX_LEN);
    data.extend_from_slice(&VERIFY_AND_REGISTER_DISCRIMINATOR);
    data.extend_from_slice(&nonce_slot.to_le_bytes());
    data.extend_from_slice(&report_data[..SNP_REPORT_SIZE]);
    // Canonical bumps. Order is nonce then attested signer.
    // @spec SCC-SEC-008 SCC-ARCH-001 SCC-SDK-001
    data.push(nonce_bump);
    data.push(signer_bump);
    assert_eq!(data.len(), VERIFY_AND_REGISTER_IX_LEN);

    Ok(crate::amd::with_amd_revocation(
        crate::nonce::with_legacy_nonce(
            crate::backend_policy::with_backend_policy(
                Instruction {
                    program_id: *program_id,
                    accounts: vec![
                        AccountMeta::new(*payer, true),
                        AccountMeta::new_readonly(policy_registry, false),
                        AccountMeta::new_readonly(vcek, false),
                        AccountMeta::new(signer_pda, false),
                        AccountMeta::new(nonce_pda, false),
                        AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
                        AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
                        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
                        AccountMeta::new_readonly(*signer, true),
                    ],
                    data,
                },
                crate::backend_policy::AMD_SOURCE,
            ),
            crate::nonce::derive_legacy_used_nonce_pda(program_id, &signer_pubkey, &nonce).0,
        ),
        &chip_id_hash(&view, endorsement_xy)?,
    ))
}

/// Quarantined Mode B transaction. The raw report does not fit in [`crate::builder::PACKET_DATA_SIZE`].
///
/// Program-test only. Do not submit the transaction to a live cluster.
///
/// @spec SCC-SDK-001 SCC-SEC-005
#[allow(clippy::too_many_arguments)]
pub fn build_atomic_attestation_tx_oversized(
    payer: &Pubkey,
    consumer_program_id: &Pubkey,
    action_hash: [u8; 32],
    measurement: [u8; 48],
    report: &[u8],
    consumer_ix: Instruction,
    recent_blockhash: Hash,
) -> Result<Transaction, SdkError> {
    build_atomic_attestation_tx_for_program_oversized(
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

/// Quarantined Mode B transaction against `program_id`.
///
/// @spec SCC-SDK-001 SCC-SEC-005
#[allow(clippy::too_many_arguments)]
pub fn build_atomic_attestation_tx_for_program_oversized(
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
    build_atomic_attestation_tx_for_program_oversized_with_endorsement(
        program_id,
        payer,
        consumer_program_id,
        action_hash,
        measurement,
        report,
        consumer_ix,
        recent_blockhash,
        nonce_slot,
        None,
    )
}

/// Explicit endorsement-key variant for VLEK component harnesses.
#[allow(clippy::too_many_arguments)]
pub fn build_atomic_attestation_tx_for_program_oversized_with_endorsement(
    program_id: &Pubkey,
    payer: &Pubkey,
    consumer_program_id: &Pubkey,
    action_hash: [u8; 32],
    measurement: [u8; 48],
    report: &[u8],
    consumer_ix: Instruction,
    recent_blockhash: Hash,
    nonce_slot: u64,
    endorsement_xy: Option<&[u8; 96]>,
) -> Result<Transaction, SdkError> {
    let confidential_compute_ix = build_verify_atomic_with_nonce_ix_oversized_with_endorsement(
        program_id,
        payer,
        consumer_program_id,
        action_hash,
        measurement,
        report,
        nonce_slot,
        endorsement_xy,
    )?;
    let mut tx = Transaction::new_with_payer(&[confidential_compute_ix, consumer_ix], Some(payer));
    tx.message.recent_blockhash = recent_blockhash;
    Ok(tx)
}

/// Quarantined `verify_atomic_with_nonce` packer.
///
/// @spec SCC-SDK-001 SCC-SEC-005
#[allow(clippy::too_many_arguments)]
pub fn build_verify_atomic_with_nonce_ix_oversized(
    program_id: &Pubkey,
    payer: &Pubkey,
    consumer_program_id: &Pubkey,
    action_hash: [u8; 32],
    measurement: [u8; 48],
    report: &[u8],
    nonce_slot: u64,
) -> Result<Instruction, SdkError> {
    build_verify_atomic_with_nonce_ix_oversized_with_endorsement(
        program_id,
        payer,
        consumer_program_id,
        action_hash,
        measurement,
        report,
        nonce_slot,
        None,
    )
}

/// Explicit endorsement-key variant for VLEK component harnesses.
#[allow(clippy::too_many_arguments)]
pub fn build_verify_atomic_with_nonce_ix_oversized_with_endorsement(
    program_id: &Pubkey,
    payer: &Pubkey,
    consumer_program_id: &Pubkey,
    action_hash: [u8; 32],
    measurement: [u8; 48],
    report: &[u8],
    nonce_slot: u64,
    endorsement_xy: Option<&[u8; 96]>,
) -> Result<Instruction, SdkError> {
    let view = parse_report(report)?;
    if view.measurement() != measurement {
        return Err(SdkError::MeasurementMismatch);
    }

    let signer_pubkey = view.pubkey();
    // The enclave writes the action commitment into the report nonce. The
    // verifier derives the UsedNonceAccount from that same digest.
    let expected_commitment = view.nonce();
    let policy_registry = derive_policy_registry_pda(program_id);
    let vcek = derive_vcek_pda(program_id, &chip_id_hash(&view, endorsement_xy)?, view.reported_tcb());
    let (nonce_pda, nonce_bump) =
        crate::nonce::derive_used_nonce_pda_for_source(program_id, 1, &signer_pubkey, &expected_commitment)
            .expect("fixed AMD source");

    let mut data = Vec::with_capacity(VERIFY_ATOMIC_WITH_NONCE_IX_LEN);
    data.extend_from_slice(&VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
    data.extend_from_slice(&nonce_slot.to_le_bytes());
    data.extend_from_slice(&action_hash);
    data.extend_from_slice(consumer_program_id.as_ref());
    data.extend_from_slice(&report[..SNP_REPORT_SIZE]);
    // @spec SCC-SEC-008 SCC-ARCH-001 SCC-SDK-001
    data.push(nonce_bump);
    assert_eq!(data.len(), VERIFY_ATOMIC_WITH_NONCE_IX_LEN);

    Ok(crate::amd::with_amd_revocation(
        crate::nonce::with_legacy_nonce(
            crate::backend_policy::with_backend_policy(
                Instruction {
                    program_id: *program_id,
                    accounts: vec![
                        AccountMeta::new(*payer, true),
                        AccountMeta::new_readonly(policy_registry, false),
                        AccountMeta::new_readonly(vcek, false),
                        AccountMeta::new(nonce_pda, false),
                        AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
                        AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
                        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
                        AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
                    ],
                    data,
                },
                crate::backend_policy::AMD_SOURCE,
            ),
            crate::nonce::derive_legacy_used_nonce_pda(program_id, &signer_pubkey, &expected_commitment).0,
        ),
        &chip_id_hash(&view, endorsement_xy)?,
    ))
}
