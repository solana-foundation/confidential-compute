//! Intel TDX enrolment instruction and transaction builders.
//!
//! Three instructions make up an enrolment:
//!
//! 1. `issue_tdx_challenge` pins a recent slot hash under a caller-chosen
//!    nonce. Permissionless, and necessarily its own transaction: the enclave
//!    has to read the slot hash back out before it can produce a quote.
//! 2. `verify_tdx_qe_report` certifies the attestation key, from a QE report
//!    the platform's PCK key signed.
//! 3. `verify_tdx_quote` admits the workload signer, from a quote body the
//!    certified attestation key signed.
//!
//! Steps 2 and 3 each need a secp256r1 precompile instruction ahead of them
//! carrying the signed bytes as its message -- the program reads the message
//! back out of that instruction rather than from an account. That costs 497
//! and 745 bytes respectively, which is why this path never fit a 1,232-byte
//! legacy packet. Under transaction v1 (SIMD-0385) the budget is 4,096 bytes
//! and both halves fit in a single transaction; see
//! [`build_tdx_enrolment_tx_for_program`].
//!
//! @spec SCC-TDX-001 SCC-TDX-002 SCC-TDX-005 SCC-SDK-001

use std::sync::LazyLock;

use solana_confidential_compute_cpi::{ATTESTED_SIGNER_SEED, ID as SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID};
use solana_message::v1::{self, TransactionConfig, MAX_TRANSACTION_SIZE};
use solana_sdk::hash::{hash, hashv, Hash};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::VersionedMessage;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::VersionedTransaction;

use crate::backend_policy::backend_policy_pda;

/// Backend policy source and nonce seed tag for Intel TDX.
/// @spec SCC-TDX-001
pub const TDX_SOURCE: u8 = 5;

/// Mode A (`verify_tdx_quote`): register an `AttestedSignerAccount`.
/// The handler rejects every other value.
/// @spec SCC-TDX-002
pub const VERIFY_TDX_MODE_A: u8 = 0;

/// `EnclaveReportBody`: the message the PCK key signs.
pub const QE_REPORT_LEN: usize = 384;
/// TDX v4 `header || td_report_body`: the message the attestation key signs.
pub const ISV_SIGNED_LEN: usize = 632;
/// Intel caps QE auth data well below this; the program rejects more.
pub const MAX_QE_AUTH_DATA_LEN: usize = 256;

/// PDA seed prefix for `ChallengeAccount`.
pub const CHALLENGE_SEED: &[u8] = b"challenge";
/// PDA seed prefix for `TdxSessionAccount`.
pub const TDX_SESSION_SEED: &[u8] = b"tdx_session";
/// PDA seed prefix for `UsedNonceAccount`.
pub const USED_NONCE_SEED: &[u8] = b"nonce";

/// `num_signatures (1) + padding (1) + offsets (14) + pubkey (33) + signature (64)`.
pub const SECP256R1_PRECOMPILE_OVERHEAD: usize = 16 + 33 + 64;
/// Maximum serialized size of a v1 transaction (SIMD-0385).
pub const V1_MAX_TRANSACTION_SIZE: usize = MAX_TRANSACTION_SIZE;
/// Loaded accounts budget applied when the caller leaves it unset, in bytes.
///
/// Enough for the verifier program plus the enrolment's accounts with room to
/// spare, and far below the 64 MiB ceiling. It exists because an unset field
/// means zero under v1, not because 2 MiB is significant.
pub const DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_LIMIT: u32 = 2 * 1024 * 1024;

/// Exact lengths of the two precompile instructions this module emits.
pub const QE_PRECOMPILE_IX_LEN: usize = SECP256R1_PRECOMPILE_OVERHEAD + QE_REPORT_LEN;
/// See [`QE_PRECOMPILE_IX_LEN`].
pub const QUOTE_PRECOMPILE_IX_LEN: usize = SECP256R1_PRECOMPILE_OVERHEAD + ISV_SIGNED_LEN;

/// Wire offsets `extract_secp256r1_verified` pins. Any other layout is skipped
/// by the program, so these are not free parameters.
const PRECOMPILE_PUBKEY_OFFSET: u16 = 16;
const PRECOMPILE_SIGNATURE_OFFSET: u16 = 49;
const PRECOMPILE_MESSAGE_OFFSET: u16 = 113;
/// `u16::MAX` means "this instruction", the only index the program accepts.
const PRECOMPILE_SELF_INDEX: u16 = u16::MAX;

/// `discriminator || mode (1) || nonce_slot (8)`.
pub const VERIFY_TDX_QUOTE_IX_LEN: usize = 8 + 1 + 8;

/// Anchor's `sha256("global:<name>")[..8]`.
///
/// Derived rather than transcribed so a rename on chain cannot silently
/// desynchronise the client; the unit tests pin each one against the
/// verifier's own constant.
fn anchor_discriminator(name: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash(name.as_bytes()).to_bytes()[..8]);
    out
}

/// `sha256("global:issue_tdx_challenge")[..8]`.
/// @spec SCC-TDX-005
pub static ISSUE_TDX_CHALLENGE_DISCRIMINATOR: LazyLock<[u8; 8]> =
    LazyLock::new(|| anchor_discriminator("global:issue_tdx_challenge"));
/// `sha256("global:verify_tdx_qe_report")[..8]`.
/// @spec SCC-TDX-001
pub static VERIFY_TDX_QE_REPORT_DISCRIMINATOR: LazyLock<[u8; 8]> =
    LazyLock::new(|| anchor_discriminator("global:verify_tdx_qe_report"));
/// `sha256("global:verify_tdx_quote")[..8]`.
/// @spec SCC-TDX-002
pub static VERIFY_TDX_QUOTE_DISCRIMINATOR: LazyLock<[u8; 8]> =
    LazyLock::new(|| anchor_discriminator("global:verify_tdx_quote"));

/// Failure modes a caller can hit before anything reaches the cluster.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TdxError {
    #[error("QE report must be exactly {QE_REPORT_LEN} bytes, got {len}")]
    InvalidQeReportLen { len: usize },
    #[error("signed quote region must be exactly {ISV_SIGNED_LEN} bytes, got {len}")]
    InvalidIsvSignedLen { len: usize },
    #[error("QE auth data must be at most {MAX_QE_AUTH_DATA_LEN} bytes, got {len}")]
    QeAuthDataTooLong { len: usize },
    #[error("PCK public key must be SEC1-compressed: a 0x02 or 0x03 prefix")]
    InvalidPckPubkey,
    #[error("TDX mode must be 0 (Mode A)")]
    InvalidTdxMode,
    #[error("failed to compile a v1 message: {0}")]
    Compile(String),
    #[error("serialized v1 transaction is {len} bytes and exceeds the {max}-byte limit")]
    TransactionTooLarge { len: usize, max: usize },
    #[error("secp256r1 message must be at most {max} bytes, got {len}")]
    PrecompileMessageTooLong { len: usize, max: usize },
}

// ---------------------------------------------------------------------------
// PDA derivations
// ---------------------------------------------------------------------------

/// `ChallengeAccount` at `["challenge", 5, nonce]`.
/// @spec SCC-TDX-005
pub fn derive_tdx_challenge_pda(program_id: &Pubkey, nonce: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CHALLENGE_SEED, &[TDX_SOURCE], nonce], program_id)
}

/// `TdxSessionAccount` at `["tdx_session", sha256(compressed attestation key)]`.
///
/// A PDA seed caps at 32 bytes and a compressed point is 33, so the seed is a
/// digest. Using only X would let the two parities share a session.
/// @spec SCC-TDX-001
pub fn derive_tdx_session_pda(program_id: &Pubkey, attestation_pubkey: &[u8; 33]) -> (Pubkey, u8) {
    let seed = hashv(&[attestation_pubkey]).to_bytes();
    Pubkey::find_program_address(&[TDX_SESSION_SEED, &seed], program_id)
}

/// [`derive_tdx_session_pda`] from the uncompressed `X || Y` the quote carries.
/// @spec SCC-TDX-001
pub fn derive_tdx_session_pda_from_xy(program_id: &Pubkey, attestation_pubkey_xy: &[u8; 64]) -> (Pubkey, u8) {
    derive_tdx_session_pda(program_id, &compress_p256(attestation_pubkey_xy))
}

/// Source-5 `UsedNonceAccount` at `["nonce", 5, seed]`.
///
/// [`crate::nonce::derive_used_nonce_pda_for_source`] fails closed on source 5,
/// so TDX gets its own entry point rather than a relaxed bound there.
/// @spec SCC-TDX-002
pub fn derive_tdx_used_nonce_pda(program_id: &Pubkey, seed: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[USED_NONCE_SEED, &[TDX_SOURCE], seed], program_id)
}

/// `AttestedSignerAccount` at `["attested_signer_v2", signer]`.
pub fn derive_attested_signer_pda(program_id: &Pubkey, signer: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ATTESTED_SIGNER_SEED, signer.as_ref()], program_id)
}

/// Source-5 backend policy, which holds the PCK, QE, platform and GPU allowlists.
pub fn derive_tdx_backend_policy_pda(program_id: &Pubkey) -> Pubkey {
    backend_policy_pda(program_id, TDX_SOURCE).0
}

/// `SHA-256(subject || quote_body_digest || slot_hash || challenge_nonce)`.
///
/// Seeds the source-5 nonce PDA. Including the body digest means two quotes
/// from the same signer against the same challenge cannot both be consumed.
/// @spec SCC-TDX-002
pub fn tdx_nonce_seed(
    subject: &[u8; 32],
    quote_body_digest: &[u8; 32],
    slot_hash: &[u8; 32],
    challenge_nonce: &[u8; 32],
) -> [u8; 32] {
    hashv(&[subject, quote_body_digest, slot_hash, challenge_nonce]).to_bytes()
}

/// The nonce PDA `verify_tdx_quote` will consume, from the signed quote region.
/// @spec SCC-TDX-002
pub fn derive_tdx_quote_nonce_pda(
    program_id: &Pubkey,
    workload_signer: &Pubkey,
    isv_signed: &[u8],
    slot_hash: &[u8; 32],
    challenge_nonce: &[u8; 32],
) -> Result<(Pubkey, u8), TdxError> {
    require_isv_signed(isv_signed)?;
    let quote_body_digest = hashv(&[isv_signed]).to_bytes();
    let seed = tdx_nonce_seed(&workload_signer.to_bytes(), &quote_body_digest, slot_hash, challenge_nonce);
    Ok(derive_tdx_used_nonce_pda(program_id, &seed))
}

// ---------------------------------------------------------------------------
// secp256r1 precompile
// ---------------------------------------------------------------------------

/// SEC1-compress an uncompressed P-256 point.
pub fn compress_p256(xy: &[u8; 64]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 2 + (xy[63] & 1);
    out[1..].copy_from_slice(&xy[..32]);
    out
}

/// The P-256 group order `n`, big-endian.
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA,
    0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];
/// `floor(n / 2)`, big-endian.
const P256_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xDE, 0x73, 0x7D,
    0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

fn is_low_s(s: &[u8]) -> bool {
    for (a, b) in s.iter().zip(P256_HALF_ORDER.iter()) {
        if a != b {
            return a < b;
        }
    }
    true
}

/// Normalize an ECDSA signature to low-S form.
///
/// The precompile rejects high-S outright, and a quote carries whatever form
/// the signer produced, so normalizing is not optional on the client side.
pub fn normalize_low_s(signature: &[u8; 64]) -> [u8; 64] {
    let mut out = *signature;
    if !is_low_s(&out[32..]) {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = i16::from(P256_ORDER[i]) - i16::from(out[32 + i]) - borrow;
            if diff < 0 {
                out[32 + i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                out[32 + i] = diff as u8;
                borrow = 0;
            }
        }
    }
    out
}

/// Build the secp256r1 precompile instruction the TDX handlers read back.
///
/// The layout is the one `extract_secp256r1_verified` pins: one signature, a
/// pad byte, 14 bytes of offsets all naming this instruction, then the
/// compressed pubkey at 16, the signature at 49 and the message at 113. The
/// signature is low-S normalized here because the precompile rejects the
/// other form.
///
/// @spec SCC-TDX-001
pub fn build_secp256r1_verify_ix(
    compressed_pubkey: &[u8; 33],
    signature: &[u8; 64],
    message: &[u8],
) -> Result<Instruction, TdxError> {
    let message_size = u16::try_from(message.len())
        .map_err(|_| TdxError::PrecompileMessageTooLong { len: message.len(), max: usize::from(u16::MAX) })?;
    let mut data = Vec::with_capacity(SECP256R1_PRECOMPILE_OVERHEAD + message.len());
    data.push(1); // num_signatures
    data.push(0); // padding
    data.extend_from_slice(&PRECOMPILE_SIGNATURE_OFFSET.to_le_bytes());
    data.extend_from_slice(&PRECOMPILE_SELF_INDEX.to_le_bytes());
    data.extend_from_slice(&PRECOMPILE_PUBKEY_OFFSET.to_le_bytes());
    data.extend_from_slice(&PRECOMPILE_SELF_INDEX.to_le_bytes());
    data.extend_from_slice(&PRECOMPILE_MESSAGE_OFFSET.to_le_bytes());
    data.extend_from_slice(&message_size.to_le_bytes());
    data.extend_from_slice(&PRECOMPILE_SELF_INDEX.to_le_bytes());
    data.extend_from_slice(compressed_pubkey);
    data.extend_from_slice(&normalize_low_s(signature));
    data.extend_from_slice(message);
    Ok(Instruction { program_id: solana_sdk_ids::secp256r1_program::ID, accounts: vec![], data })
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

fn require_qe_report(report: &[u8]) -> Result<&[u8], TdxError> {
    if report.len() != QE_REPORT_LEN {
        return Err(TdxError::InvalidQeReportLen { len: report.len() });
    }
    Ok(report)
}

fn require_isv_signed(isv_signed: &[u8]) -> Result<&[u8], TdxError> {
    if isv_signed.len() != ISV_SIGNED_LEN {
        return Err(TdxError::InvalidIsvSignedLen { len: isv_signed.len() });
    }
    Ok(isv_signed)
}

fn require_pck_pubkey(pck: &[u8; 33]) -> Result<&[u8; 33], TdxError> {
    if pck[0] != 0x02 && pck[0] != 0x03 {
        return Err(TdxError::InvalidPckPubkey);
    }
    Ok(pck)
}

fn require_tdx_mode(mode: u8) -> Result<u8, TdxError> {
    if mode != VERIFY_TDX_MODE_A {
        return Err(TdxError::InvalidTdxMode);
    }
    Ok(mode)
}

// ---------------------------------------------------------------------------
// 1. issue_tdx_challenge
// ---------------------------------------------------------------------------

/// Packs `issue_tdx_challenge` against `program_id`.
///
/// Permissionless. The nonce only has to be unique -- it selects the PDA.
/// Freshness comes from the slot hash, which the program reads from the
/// SlotHashes sysvar rather than taking from the caller, so an enclave cannot
/// pre-compute a quote for a challenge that has not been issued.
///
/// Accounts: challenge PDA (writable), payer (signer, writable), system
/// program, clock, SlotHashes.
///
/// @spec SCC-TDX-005 SCC-SDK-001
pub fn build_issue_tdx_challenge_ix_for_program(
    program_id: &Pubkey,
    payer: &Pubkey,
    nonce: &[u8; 32],
    nonce_slot: u64,
) -> Instruction {
    let (challenge, _) = derive_tdx_challenge_pda(program_id, nonce);

    let mut data = Vec::with_capacity(8 + 32 + 8);
    data.extend_from_slice(&*ISSUE_TDX_CHALLENGE_DISCRIMINATOR);
    data.extend_from_slice(nonce);
    data.extend_from_slice(&nonce_slot.to_le_bytes());

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(challenge, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
        ],
        data,
    }
}

/// [`build_issue_tdx_challenge_ix_for_program`] against the canonical program.
/// @spec SCC-TDX-005 SCC-SDK-001
pub fn build_issue_tdx_challenge_ix(payer: &Pubkey, nonce: &[u8; 32], nonce_slot: u64) -> Instruction {
    build_issue_tdx_challenge_ix_for_program(&SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID, payer, nonce, nonce_slot)
}

// ---------------------------------------------------------------------------
// 2. verify_tdx_qe_report
// ---------------------------------------------------------------------------

/// Packs `verify_tdx_qe_report` against `program_id`.
///
/// **Must be preceded in the same transaction** by the secp256r1 instruction
/// [`build_secp256r1_verify_ix`] carrying the 384-byte QE report as its
/// message and the PCK key as its pubkey. The QE report is not repeated in
/// this instruction's data: the handler reads it back out of the precompile.
///
/// Accounts: session PDA (writable), source-5 backend policy, payer (signer,
/// writable), system program, clock, instructions sysvar.
///
/// @spec SCC-TDX-001 SCC-SDK-001
pub fn build_verify_tdx_qe_report_ix_for_program(
    program_id: &Pubkey,
    payer: &Pubkey,
    attestation_pubkey_xy: &[u8; 64],
    pck_pubkey: &[u8; 33],
    gpu_rim_digest: &[u8; 32],
    model_digest: &[u8; 32],
    qe_auth_data: &[u8],
) -> Result<Instruction, TdxError> {
    require_pck_pubkey(pck_pubkey)?;
    if qe_auth_data.len() > MAX_QE_AUTH_DATA_LEN {
        return Err(TdxError::QeAuthDataTooLong { len: qe_auth_data.len() });
    }
    let auth_len =
        u16::try_from(qe_auth_data.len()).map_err(|_| TdxError::QeAuthDataTooLong { len: qe_auth_data.len() })?;

    let (session, _) = derive_tdx_session_pda_from_xy(program_id, attestation_pubkey_xy);

    let mut data = Vec::with_capacity(8 + 64 + 33 + 32 + 32 + 2 + qe_auth_data.len());
    data.extend_from_slice(&*VERIFY_TDX_QE_REPORT_DISCRIMINATOR);
    data.extend_from_slice(attestation_pubkey_xy);
    data.extend_from_slice(pck_pubkey);
    data.extend_from_slice(gpu_rim_digest);
    data.extend_from_slice(model_digest);
    data.extend_from_slice(&auth_len.to_le_bytes());
    data.extend_from_slice(qe_auth_data);

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(derive_tdx_backend_policy_pda(program_id), false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ],
        data,
    })
}

/// [`build_verify_tdx_qe_report_ix_for_program`] against the canonical program.
/// @spec SCC-TDX-001 SCC-SDK-001
pub fn build_verify_tdx_qe_report_ix(
    payer: &Pubkey,
    attestation_pubkey_xy: &[u8; 64],
    pck_pubkey: &[u8; 33],
    gpu_rim_digest: &[u8; 32],
    model_digest: &[u8; 32],
    qe_auth_data: &[u8],
) -> Result<Instruction, TdxError> {
    build_verify_tdx_qe_report_ix_for_program(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        payer,
        attestation_pubkey_xy,
        pck_pubkey,
        gpu_rim_digest,
        model_digest,
        qe_auth_data,
    )
}

// ---------------------------------------------------------------------------
// 3. verify_tdx_quote
// ---------------------------------------------------------------------------

/// Packs `verify_tdx_quote` against `program_id`.
///
/// **Must be preceded in the same transaction** by the secp256r1 instruction
/// [`build_secp256r1_verify_ix`] carrying the 632-byte `header ||
/// td_report_body` as its message and the attestation key as its pubkey.
///
/// The payload is nine bytes, `mode || nonce_slot`. Everything else the
/// handler needs it reads from an account: the challenge nonce and slot hash
/// from the challenge PDA, and the GPU RIM and model digest from the session
/// the QE step wrote. `isv_signed`, `slot_hash` and `challenge_nonce` are
/// taken here only to derive the nonce PDA; none of them reach the wire.
///
/// Accounts, in handler order: attested signer PDA (writable), session PDA,
/// source-5 backend policy, nonce PDA (writable), payer (signer, writable),
/// system program, clock, challenge PDA (writable), workload signer (signer),
/// instructions sysvar.
///
/// @spec SCC-TDX-002 SCC-SDK-001
#[allow(clippy::too_many_arguments)]
pub fn build_verify_tdx_quote_ix_for_program(
    program_id: &Pubkey,
    payer: &Pubkey,
    workload_signer: &Pubkey,
    attestation_pubkey_xy: &[u8; 64],
    mode: u8,
    nonce_slot: u64,
    isv_signed: &[u8],
    slot_hash: &[u8; 32],
    challenge_nonce: &[u8; 32],
) -> Result<Instruction, TdxError> {
    let mode = require_tdx_mode(mode)?;
    require_isv_signed(isv_signed)?;

    let (attested_signer, _) = derive_attested_signer_pda(program_id, workload_signer);
    let (session, _) = derive_tdx_session_pda_from_xy(program_id, attestation_pubkey_xy);
    let (used_nonce, _) =
        derive_tdx_quote_nonce_pda(program_id, workload_signer, isv_signed, slot_hash, challenge_nonce)?;
    let (challenge, _) = derive_tdx_challenge_pda(program_id, challenge_nonce);

    let mut data = Vec::with_capacity(VERIFY_TDX_QUOTE_IX_LEN);
    data.extend_from_slice(&*VERIFY_TDX_QUOTE_DISCRIMINATOR);
    data.push(mode);
    data.extend_from_slice(&nonce_slot.to_le_bytes());

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(attested_signer, false),
            AccountMeta::new_readonly(session, false),
            AccountMeta::new_readonly(derive_tdx_backend_policy_pda(program_id), false),
            AccountMeta::new(used_nonce, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
            // Writable: the handler tombstones the challenge on acceptance.
            AccountMeta::new(challenge, false),
            AccountMeta::new_readonly(*workload_signer, true),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
        ],
        data,
    })
}

/// [`build_verify_tdx_quote_ix_for_program`] against the canonical program.
/// @spec SCC-TDX-002 SCC-SDK-001
#[allow(clippy::too_many_arguments)]
pub fn build_verify_tdx_quote_ix(
    payer: &Pubkey,
    workload_signer: &Pubkey,
    attestation_pubkey_xy: &[u8; 64],
    mode: u8,
    nonce_slot: u64,
    isv_signed: &[u8],
    slot_hash: &[u8; 32],
    challenge_nonce: &[u8; 32],
) -> Result<Instruction, TdxError> {
    build_verify_tdx_quote_ix_for_program(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        payer,
        workload_signer,
        attestation_pubkey_xy,
        mode,
        nonce_slot,
        isv_signed,
        slot_hash,
        challenge_nonce,
    )
}

// ---------------------------------------------------------------------------
// Whole-enrolment assembly
// ---------------------------------------------------------------------------

/// Everything the two verification halves need, gathered from one quote.
///
/// Field names match the quote's own vocabulary: `qe_report` and
/// `qe_report_signature` are the `EnclaveReportBody` and the PCK signature
/// over it; `isv_signed` and `isv_signature` are `header || td_report_body`
/// and the attestation key's signature over it. `slot_hash` and
/// `challenge_nonce` are the values a prior `issue_tdx_challenge` recorded --
/// they never travel on the wire, only into PDA derivation.
///
/// @spec SCC-TDX-001 SCC-TDX-002
#[derive(Debug, Clone, Copy)]
pub struct TdxEnrolment<'a> {
    pub payer: Pubkey,
    pub workload_signer: Pubkey,
    /// Uncompressed `X || Y`, exactly as the quote carries it.
    pub attestation_pubkey_xy: &'a [u8; 64],
    pub pck_pubkey: &'a [u8; 33],
    pub gpu_rim_digest: &'a [u8; 32],
    pub model_digest: &'a [u8; 32],
    pub qe_auth_data: &'a [u8],
    /// `EnclaveReportBody`, exactly [`QE_REPORT_LEN`] bytes.
    pub qe_report: &'a [u8],
    pub qe_report_signature: &'a [u8; 64],
    /// `header || td_report_body`, exactly [`ISV_SIGNED_LEN`] bytes.
    pub isv_signed: &'a [u8],
    pub isv_signature: &'a [u8; 64],
    /// From the challenge account the enclave answered.
    pub slot_hash: &'a [u8; 32],
    pub challenge_nonce: &'a [u8; 32],
    /// The slot the challenge pinned. Checked for equality on chain.
    pub nonce_slot: u64,
}

/// The four instructions of a complete enrolment, in order.
///
/// `[secp256r1(QE report), verify_tdx_qe_report, secp256r1(quote body),
/// verify_tdx_quote]`. Each handler scans backwards for a precompile whose
/// data length matches the message length it expects -- 497 bytes for the QE
/// report, 745 for the quote body -- so the two cannot be confused for one
/// another even sharing a transaction.
///
/// @spec SCC-TDX-001 SCC-TDX-002
pub fn build_tdx_enrolment_instructions_for_program(
    program_id: &Pubkey,
    enrolment: &TdxEnrolment<'_>,
) -> Result<Vec<Instruction>, TdxError> {
    let qe_report = require_qe_report(enrolment.qe_report)?;
    let isv_signed = require_isv_signed(enrolment.isv_signed)?;
    let pck_pubkey = require_pck_pubkey(enrolment.pck_pubkey)?;
    let attestation_pubkey = compress_p256(enrolment.attestation_pubkey_xy);

    Ok(vec![
        build_secp256r1_verify_ix(pck_pubkey, enrolment.qe_report_signature, qe_report)?,
        build_verify_tdx_qe_report_ix_for_program(
            program_id,
            &enrolment.payer,
            enrolment.attestation_pubkey_xy,
            pck_pubkey,
            enrolment.gpu_rim_digest,
            enrolment.model_digest,
            enrolment.qe_auth_data,
        )?,
        build_secp256r1_verify_ix(&attestation_pubkey, enrolment.isv_signature, isv_signed)?,
        build_verify_tdx_quote_ix_for_program(
            program_id,
            &enrolment.payer,
            &enrolment.workload_signer,
            enrolment.attestation_pubkey_xy,
            VERIFY_TDX_MODE_A,
            enrolment.nonce_slot,
            isv_signed,
            enrolment.slot_hash,
            enrolment.challenge_nonce,
        )?,
    ])
}

/// Serialized size of an unsigned v1 transaction.
///
/// V1 writes signatures as a fixed-length array sized by the header, with no
/// length prefix, and prefixes the message with one version byte -- so the
/// total is `1 + message + 64 * signatures`, not the `bincode` shape legacy
/// and v0 use.
pub fn v1_transaction_size(message: &v1::Message) -> usize {
    1 + message.size() + usize::from(message.header.num_required_signatures) * 64
}

/// Assembles a complete TDX enrolment as **one v1 transaction**.
///
/// Both precompile messages ride inline, 497 and 745 bytes, which is why this
/// never fit a 1,232-byte legacy packet. Transaction v1 raises the limit to
/// 4,096 and the whole enrolment fits with room to spare. V1 does not support
/// address lookup tables and does not need them here.
///
/// The returned transaction is unsigned: its signature slots are zeroed and
/// the caller signs with the payer and, if they differ, the workload key.
/// Compute budget is a v1 message config field rather than an instruction, so
/// pass it in `config`.
///
/// `issue_tdx_challenge` is deliberately not part of this: the enclave has to
/// read the recorded slot hash before it can produce a quote, so the
/// challenge is always an earlier transaction.
///
/// @spec SCC-TDX-001 SCC-TDX-002 SCC-PERF-002
pub fn build_tdx_enrolment_tx_for_program(
    program_id: &Pubkey,
    enrolment: &TdxEnrolment<'_>,
    recent_blockhash: Hash,
    config: TransactionConfig,
) -> Result<VersionedTransaction, TdxError> {
    let instructions = build_tdx_enrolment_instructions_for_program(program_id, enrolment)?;

    // v1 carries the loaded accounts budget as a message field and the runtime
    // reads it straight off, treating absence as zero. Legacy and v0 behave the
    // opposite way: no compute budget instruction means the 64 MiB default. So
    // a caller who simply does not mention this field gets a transaction that
    // is rejected with `MaxLoadedAccountsDataSizeExceeded` before the program
    // runs, which no amount of on-chain testing would surface. Fill it in when
    // the caller left it unset; the verifier's own `.so` is around 630 KiB of
    // the budget on its own.
    let config = if config.loaded_accounts_data_size_limit.is_none() {
        config.with_loaded_accounts_data_size_limit(DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_LIMIT)
    } else {
        config
    };

    let message = v1::Message::try_compile_with_config(&enrolment.payer, &instructions, recent_blockhash, config)
        .map_err(|e| TdxError::Compile(e.to_string()))?;

    let len = v1_transaction_size(&message);
    if len > V1_MAX_TRANSACTION_SIZE {
        return Err(TdxError::TransactionTooLarge { len, max: V1_MAX_TRANSACTION_SIZE });
    }

    let signatures = vec![Signature::default(); usize::from(message.header.num_required_signatures)];
    Ok(VersionedTransaction { signatures, message: VersionedMessage::V1(message) })
}

/// [`build_tdx_enrolment_tx_for_program`] against the canonical program.
/// @spec SCC-TDX-001 SCC-TDX-002
pub fn build_tdx_enrolment_tx(
    enrolment: &TdxEnrolment<'_>,
    recent_blockhash: Hash,
    config: TransactionConfig,
) -> Result<VersionedTransaction, TdxError> {
    build_tdx_enrolment_tx_for_program(&SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID, enrolment, recent_blockhash, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_confidential_compute_verifier::payload as vix;
    use solana_confidential_compute_verifier::state::{ChallengeAccount, TdxSessionAccount};
    use solana_confidential_compute_verifier::tdx as vtdx;

    fn program_id() -> Pubkey {
        Pubkey::new_unique()
    }

    /// Owned stand-ins for the pieces a real quote is split into. The values
    /// are not valid cryptographic material -- nothing here verifies a
    /// signature. What these tests pin is layout: offsets, lengths, account
    /// order and flags, all against the verifier's own parsers.
    struct Fixture {
        att_xy: [u8; 64],
        pck: [u8; 33],
        gpu: [u8; 32],
        model: [u8; 32],
        auth: Vec<u8>,
        qe_report: Vec<u8>,
        qe_sig: [u8; 64],
        isv_signed: Vec<u8>,
        isv_sig: [u8; 64],
        nonce: [u8; 32],
        slot_hash: [u8; 32],
    }

    fn fixture() -> Fixture {
        let mut att_xy = [7u8; 64];
        att_xy[63] = 1; // odd Y, so the compressed prefix is 0x03
        let mut pck = [0u8; 33];
        pck[0] = 0x02;
        pck[1..].copy_from_slice(&[9u8; 32]);
        Fixture {
            att_xy,
            pck,
            gpu: [1u8; 32],
            model: [2u8; 32],
            auth: vec![3u8; 32],
            qe_report: vec![4u8; QE_REPORT_LEN],
            qe_sig: [5u8; 64],
            isv_signed: vec![6u8; ISV_SIGNED_LEN],
            isv_sig: [8u8; 64],
            nonce: [0xaa; 32],
            slot_hash: [0xbb; 32],
        }
    }

    impl Fixture {
        fn enrolment(&self, payer: Pubkey, workload_signer: Pubkey) -> TdxEnrolment<'_> {
            TdxEnrolment {
                payer,
                workload_signer,
                attestation_pubkey_xy: &self.att_xy,
                pck_pubkey: &self.pck,
                gpu_rim_digest: &self.gpu,
                model_digest: &self.model,
                qe_auth_data: &self.auth,
                qe_report: &self.qe_report,
                qe_report_signature: &self.qe_sig,
                isv_signed: &self.isv_signed,
                isv_signature: &self.isv_sig,
                slot_hash: &self.slot_hash,
                challenge_nonce: &self.nonce,
                nonce_slot: 99,
            }
        }
    }

    /// The discriminators are derived, so a drift from the program's own
    /// constants is a test failure rather than a runtime `InvalidInstruction`.
    #[test]
    fn tdx_discriminators_match_the_program() {
        assert_eq!(*ISSUE_TDX_CHALLENGE_DISCRIMINATOR, vix::ISSUE_TDX_CHALLENGE_DISCRIMINATOR);
        assert_eq!(*VERIFY_TDX_QE_REPORT_DISCRIMINATOR, vix::VERIFY_TDX_QE_REPORT_DISCRIMINATOR);
        assert_eq!(*VERIFY_TDX_QUOTE_DISCRIMINATOR, vix::VERIFY_TDX_QUOTE_DISCRIMINATOR);
    }

    #[test]
    fn tdx_constants_match_the_program() {
        assert_eq!(TDX_SOURCE, vix::TDX_ATTESTATION_SOURCE);
        assert_eq!(VERIFY_TDX_MODE_A, vix::VERIFY_TDX_MODE_A);
        assert_eq!(QE_REPORT_LEN, vtdx::QE_REPORT_LEN);
        assert_eq!(ISV_SIGNED_LEN, vtdx::ISV_SIGNED_LEN);
        assert_eq!(MAX_QE_AUTH_DATA_LEN, vix::MAX_QE_AUTH_DATA_LEN);
        assert_eq!(VERIFY_TDX_QUOTE_IX_LEN, 8 + vix::VERIFY_TDX_QUOTE_ARGS_LEN);
        assert_eq!(CHALLENGE_SEED, ChallengeAccount::SEED);
        assert_eq!(TDX_SESSION_SEED, TdxSessionAccount::SEED);
        assert_eq!(solana_sdk_ids::secp256r1_program::ID, vtdx::SECP256R1_PROGRAM_ID);
    }

    /// Getting these wrong fails at runtime with no useful error, so they are
    /// checked against the program's own compression and seeding.
    #[test]
    fn tdx_pdas_match_the_program_derivations() {
        let program = program_id();
        let f = fixture();

        assert_eq!(compress_p256(&f.att_xy), vtdx::compress_p256(&f.att_xy));

        let compressed = compress_p256(&f.att_xy);
        let expected_session = Pubkey::find_program_address(
            &[TdxSessionAccount::SEED, &TdxSessionAccount::seed_for(&compressed)],
            &program,
        );
        assert_eq!(derive_tdx_session_pda(&program, &compressed), expected_session);
        assert_eq!(derive_tdx_session_pda_from_xy(&program, &f.att_xy), expected_session);

        assert_eq!(
            derive_tdx_challenge_pda(&program, &f.nonce),
            Pubkey::find_program_address(&[ChallengeAccount::SEED, &[vix::TDX_ATTESTATION_SOURCE], &f.nonce], &program,)
        );

        let signer = Pubkey::new_unique();
        assert_eq!(
            derive_attested_signer_pda(&program, &signer),
            Pubkey::find_program_address(&[b"attested_signer_v2", signer.as_ref()], &program)
        );
    }

    #[test]
    fn tdx_nonce_seed_matches_the_program() {
        let program = program_id();
        let f = fixture();
        let signer = Pubkey::new_unique();
        let digest = hashv(&[f.isv_signed.as_slice()]).to_bytes();

        let expected_seed = vix::tdx_nonce_seed(&signer.to_bytes(), &digest, &f.slot_hash, &f.nonce);
        assert_eq!(tdx_nonce_seed(&signer.to_bytes(), &digest, &f.slot_hash, &f.nonce), expected_seed);
        assert_eq!(
            derive_tdx_quote_nonce_pda(&program, &signer, &f.isv_signed, &f.slot_hash, &f.nonce).unwrap(),
            Pubkey::find_program_address(&[b"nonce", &[vix::TDX_ATTESTATION_SOURCE], &expected_seed], &program)
        );
    }

    #[test]
    fn tdx_instruction_payloads_round_trip_through_the_program_parsers() {
        let program = program_id();
        let payer = Pubkey::new_unique();
        let signer = Pubkey::new_unique();
        let f = fixture();

        let issue = build_issue_tdx_challenge_ix_for_program(&program, &payer, &f.nonce, 42);
        let parsed = vix::parse_issue_tdx_challenge_args(&issue.data[8..]).unwrap();
        assert_eq!(parsed.nonce, &f.nonce);
        assert_eq!(parsed.nonce_slot, 42);

        let qe =
            build_verify_tdx_qe_report_ix_for_program(&program, &payer, &f.att_xy, &f.pck, &f.gpu, &f.model, &f.auth)
                .unwrap();
        let parsed = vix::parse_tdx_qe_report_args(&qe.data[8..]).unwrap();
        assert_eq!(parsed.attestation_pubkey_xy, &f.att_xy);
        assert_eq!(parsed.pck_pubkey, &f.pck);
        assert_eq!(parsed.gpu_rim_digest, &f.gpu);
        assert_eq!(parsed.model_digest, &f.model);
        assert_eq!(parsed.qe_auth_data, f.auth.as_slice());

        let quote = build_verify_tdx_quote_ix_for_program(
            &program,
            &payer,
            &signer,
            &f.att_xy,
            VERIFY_TDX_MODE_A,
            42,
            &f.isv_signed,
            &f.slot_hash,
            &f.nonce,
        )
        .unwrap();
        assert_eq!(quote.data.len(), VERIFY_TDX_QUOTE_IX_LEN);
        let parsed = vix::parse_tdx_quote_args(&quote.data[8..]).unwrap();
        assert_eq!(parsed.mode, VERIFY_TDX_MODE_A);
        assert_eq!(parsed.nonce_slot, 42);
    }

    /// The handler destructures a fixed-length slice pattern, so one wrong
    /// position or flag is a runtime failure with no diagnostic.
    #[test]
    fn tdx_quote_account_list_is_in_handler_order() {
        let program = program_id();
        let payer = Pubkey::new_unique();
        let signer = Pubkey::new_unique();
        let f = fixture();

        let ix = build_verify_tdx_quote_ix_for_program(
            &program,
            &payer,
            &signer,
            &f.att_xy,
            VERIFY_TDX_MODE_A,
            7,
            &f.isv_signed,
            &f.slot_hash,
            &f.nonce,
        )
        .unwrap();

        let metas = &ix.accounts;
        assert_eq!(metas.len(), 10);
        assert_eq!(metas[0].pubkey, derive_attested_signer_pda(&program, &signer).0);
        assert!(metas[0].is_writable && !metas[0].is_signer);
        assert_eq!(metas[1].pubkey, derive_tdx_session_pda_from_xy(&program, &f.att_xy).0);
        assert!(!metas[1].is_writable);
        assert_eq!(metas[2].pubkey, derive_tdx_backend_policy_pda(&program));
        assert!(!metas[2].is_writable);
        assert_eq!(
            metas[3].pubkey,
            derive_tdx_quote_nonce_pda(&program, &signer, &f.isv_signed, &f.slot_hash, &f.nonce).unwrap().0
        );
        assert!(metas[3].is_writable);
        assert_eq!(metas[4].pubkey, payer);
        assert!(metas[4].is_writable && metas[4].is_signer);
        assert_eq!(metas[5].pubkey, solana_sdk_ids::system_program::ID);
        assert_eq!(metas[6].pubkey, solana_sdk::sysvar::clock::ID);
        assert_eq!(metas[7].pubkey, derive_tdx_challenge_pda(&program, &f.nonce).0);
        assert!(metas[7].is_writable, "the handler tombstones the challenge");
        assert_eq!(metas[8].pubkey, signer);
        assert!(metas[8].is_signer && !metas[8].is_writable);
        assert_eq!(metas[9].pubkey, solana_sdk::sysvar::instructions::ID);
    }

    #[test]
    fn tdx_qe_report_account_list_is_in_handler_order() {
        let program = program_id();
        let payer = Pubkey::new_unique();
        let f = fixture();

        let ix =
            build_verify_tdx_qe_report_ix_for_program(&program, &payer, &f.att_xy, &f.pck, &f.gpu, &f.model, &f.auth)
                .unwrap();
        let metas = &ix.accounts;
        assert_eq!(metas.len(), 6);
        assert_eq!(metas[0].pubkey, derive_tdx_session_pda_from_xy(&program, &f.att_xy).0);
        assert!(metas[0].is_writable);
        assert_eq!(metas[1].pubkey, derive_tdx_backend_policy_pda(&program));
        assert_eq!(metas[2].pubkey, payer);
        assert!(metas[2].is_writable && metas[2].is_signer);
        assert_eq!(metas[3].pubkey, solana_sdk_ids::system_program::ID);
        assert_eq!(metas[4].pubkey, solana_sdk::sysvar::clock::ID);
        assert_eq!(metas[5].pubkey, solana_sdk::sysvar::instructions::ID);
    }

    #[test]
    fn tdx_challenge_account_list_is_in_handler_order() {
        let program = program_id();
        let payer = Pubkey::new_unique();
        let nonce = [0xcd; 32];
        let ix = build_issue_tdx_challenge_ix_for_program(&program, &payer, &nonce, 11);
        let metas = &ix.accounts;
        assert_eq!(metas.len(), 5);
        assert_eq!(metas[0].pubkey, derive_tdx_challenge_pda(&program, &nonce).0);
        assert!(metas[0].is_writable);
        assert_eq!(metas[1].pubkey, payer);
        assert!(metas[1].is_writable && metas[1].is_signer);
        assert_eq!(metas[2].pubkey, solana_sdk_ids::system_program::ID);
        assert_eq!(metas[3].pubkey, solana_sdk::sysvar::clock::ID);
        assert_eq!(metas[4].pubkey, solana_sdk::sysvar::slot_hashes::ID);
    }

    /// The precompile layout is the one thing here with no runtime diagnostic:
    /// a wrong offset makes the handler skip the instruction and report
    /// `InvalidSignature`. Checked against the program's own reader.
    #[test]
    fn precompile_instructions_use_the_layout_the_program_pins() {
        let f = fixture();

        let qe_ix = build_secp256r1_verify_ix(&f.pck, &f.qe_sig, &f.qe_report).unwrap();
        assert_eq!(qe_ix.program_id, vtdx::SECP256R1_PROGRAM_ID);
        assert!(qe_ix.accounts.is_empty());
        assert_eq!(qe_ix.data.len(), QE_PRECOMPILE_IX_LEN);
        assert_eq!(qe_ix.data.len(), 497);
        assert_eq!(qe_ix.data[0], 1);
        // signature_offset, signature_index, pubkey_offset, pubkey_index,
        // message_offset, message_size, message_index.
        assert_eq!(&qe_ix.data[2..4], &49u16.to_le_bytes());
        assert_eq!(&qe_ix.data[4..6], &u16::MAX.to_le_bytes());
        assert_eq!(&qe_ix.data[6..8], &16u16.to_le_bytes());
        assert_eq!(&qe_ix.data[8..10], &u16::MAX.to_le_bytes());
        assert_eq!(&qe_ix.data[10..12], &113u16.to_le_bytes());
        assert_eq!(&qe_ix.data[12..14], &(QE_REPORT_LEN as u16).to_le_bytes());
        assert_eq!(&qe_ix.data[14..16], &u16::MAX.to_le_bytes());
        assert_eq!(&qe_ix.data[16..49], &f.pck[..]);
        assert_eq!(&qe_ix.data[49..113], &normalize_low_s(&f.qe_sig)[..]);
        assert_eq!(&qe_ix.data[113..], &f.qe_report[..]);

        let quote_ix = build_secp256r1_verify_ix(&compress_p256(&f.att_xy), &f.isv_sig, &f.isv_signed).unwrap();
        assert_eq!(quote_ix.data.len(), QUOTE_PRECOMPILE_IX_LEN);
        assert_eq!(quote_ix.data.len(), 745);
        assert_eq!(&quote_ix.data[113..], &f.isv_signed[..]);
    }

    #[test]
    fn precompile_signatures_are_normalized_to_low_s() {
        let mut high_s = [0u8; 64];
        high_s[32..].copy_from_slice(&P256_ORDER);
        high_s[63] -= 1; // n - 1, unambiguously high-S
        assert_eq!(normalize_low_s(&high_s), vtdx::normalize_low_s(&high_s));

        let low_s = [1u8; 64];
        assert_eq!(normalize_low_s(&low_s), low_s);
        assert_eq!(normalize_low_s(&low_s), vtdx::normalize_low_s(&low_s));
    }

    /// The headline claim: both halves of enrolment fit one v1 transaction,
    /// with no address lookup table. The figure is recorded so a regression
    /// shows up as a number.
    #[test]
    fn tdx_enrolment_fits_one_v1_transaction() {
        let program = program_id();
        let payer = Pubkey::new_unique();
        let signer = Pubkey::new_unique();
        let f = fixture();
        let enrolment = f.enrolment(payer, signer);

        let ixs = build_tdx_enrolment_instructions_for_program(&program, &enrolment).unwrap();
        assert_eq!(ixs.len(), 4);
        assert_eq!(ixs[0].data.len(), 497);
        assert_eq!(ixs[2].data.len(), 745);

        let message =
            v1::Message::try_compile_with_config(&payer, &ixs, Hash::default(), TransactionConfig::empty()).unwrap();
        let size = v1_transaction_size(&message);
        eprintln!("TDX enrolment v1 transaction: {size} bytes (limit {V1_MAX_TRANSACTION_SIZE})");
        assert!(
            size <= V1_MAX_TRANSACTION_SIZE,
            "enrolment is {size} bytes, over the {V1_MAX_TRANSACTION_SIZE}-byte v1 limit",
        );
        assert_eq!(size, 2048, "v1 enrolment transaction size changed");

        let tx = build_tdx_enrolment_tx_for_program(&program, &enrolment, Hash::default(), TransactionConfig::empty())
            .unwrap();
        // Sponsor and workload key: two signatures.
        assert_eq!(tx.signatures.len(), 2);
        assert!(matches!(tx.message, VersionedMessage::V1(_)));
    }

    /// Self-paying enrolment: one signature, one fewer account.
    #[test]
    fn a_self_paying_tdx_enrolment_fits_one_v1_transaction() {
        let program = program_id();
        let signer = Pubkey::new_unique();
        let f = fixture();
        let enrolment = f.enrolment(signer, signer);

        let tx = build_tdx_enrolment_tx_for_program(&program, &enrolment, Hash::default(), TransactionConfig::empty())
            .unwrap();
        assert_eq!(tx.signatures.len(), 1);
        let VersionedMessage::V1(message) = &tx.message else {
            panic!("expected a v1 message");
        };
        let size = v1_transaction_size(message);
        eprintln!("self-paying TDX enrolment: {size} bytes");
        assert!(size <= V1_MAX_TRANSACTION_SIZE);
        // 1,956 rather than the 1,952 this measured before the builder started
        // filling in the loaded accounts budget: that field costs four bytes,
        // the same as the compute unit limit below.
        assert_eq!(size, 1956, "self-paying v1 enrolment size changed");
    }

    /// A compute unit limit is a v1 config field, not a prepended instruction,
    /// so it costs four bytes rather than a whole instruction and account.
    #[test]
    fn a_compute_budget_costs_four_bytes_under_v1() {
        let program = program_id();
        let payer = Pubkey::new_unique();
        let signer = Pubkey::new_unique();
        let f = fixture();
        let enrolment = f.enrolment(payer, signer);

        let plain =
            build_tdx_enrolment_tx_for_program(&program, &enrolment, Hash::default(), TransactionConfig::empty())
                .unwrap();
        let budgeted = build_tdx_enrolment_tx_for_program(
            &program,
            &enrolment,
            Hash::default(),
            TransactionConfig::empty().with_compute_unit_limit(400_000),
        )
        .unwrap();

        let size_of = |tx: &VersionedTransaction| match &tx.message {
            VersionedMessage::V1(m) => v1_transaction_size(m),
            _ => panic!("expected a v1 message"),
        };
        assert_eq!(size_of(&budgeted), size_of(&plain) + 4);
        assert!(size_of(&budgeted) <= V1_MAX_TRANSACTION_SIZE);
    }

    #[test]
    fn malformed_arguments_are_rejected_before_the_wire() {
        let program = program_id();
        let payer = Pubkey::new_unique();
        let signer = Pubkey::new_unique();
        let f = fixture();

        let mut bad_pck = f.pck;
        bad_pck[0] = 0x04;
        assert_eq!(
            build_verify_tdx_qe_report_ix_for_program(&program, &payer, &f.att_xy, &bad_pck, &f.gpu, &f.model, &[],),
            Err(TdxError::InvalidPckPubkey)
        );

        assert_eq!(
            build_verify_tdx_qe_report_ix_for_program(
                &program,
                &payer,
                &f.att_xy,
                &f.pck,
                &f.gpu,
                &f.model,
                &vec![0u8; MAX_QE_AUTH_DATA_LEN + 1],
            ),
            Err(TdxError::QeAuthDataTooLong { len: MAX_QE_AUTH_DATA_LEN + 1 })
        );

        assert_eq!(
            build_verify_tdx_quote_ix_for_program(
                &program,
                &payer,
                &signer,
                &f.att_xy,
                1,
                0,
                &f.isv_signed,
                &f.slot_hash,
                &f.nonce,
            ),
            Err(TdxError::InvalidTdxMode)
        );

        assert_eq!(
            build_verify_tdx_quote_ix_for_program(
                &program,
                &payer,
                &signer,
                &f.att_xy,
                VERIFY_TDX_MODE_A,
                0,
                &f.isv_signed[..ISV_SIGNED_LEN - 1],
                &f.slot_hash,
                &f.nonce,
            ),
            Err(TdxError::InvalidIsvSignedLen { len: ISV_SIGNED_LEN - 1 })
        );
    }

    // An unset loaded accounts budget means zero under v1, not the 64 MiB that
    // legacy and v0 fall back to. A caller who never mentions the field would
    // otherwise build a transaction the runtime rejects with
    // `MaxLoadedAccountsDataSizeExceeded` before the program ever runs, and no
    // on-chain assertion could catch that.
    #[test]
    fn an_unset_loaded_accounts_budget_is_filled_in() {
        let program = program_id();
        let payer = Pubkey::new_unique();
        let f = fixture();
        let enrolment = f.enrolment(payer, Pubkey::new_unique());

        let tx = build_tdx_enrolment_tx_for_program(&program, &enrolment, Hash::default(), TransactionConfig::empty())
            .unwrap();

        let VersionedMessage::V1(message) = tx.message else {
            panic!("the enrolment must compile to a v1 message");
        };
        assert_eq!(message.config.loaded_accounts_data_size_limit, Some(DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_LIMIT),);
    }

    // Filling in the default must not overwrite a caller who chose a value,
    // including one deliberately smaller than the default.
    #[test]
    fn an_explicit_loaded_accounts_budget_is_left_alone() {
        let program = program_id();
        let payer = Pubkey::new_unique();
        let f = fixture();
        let enrolment = f.enrolment(payer, Pubkey::new_unique());

        let tx = build_tdx_enrolment_tx_for_program(
            &program,
            &enrolment,
            Hash::default(),
            TransactionConfig::empty().with_loaded_accounts_data_size_limit(777_216),
        )
        .unwrap();

        let VersionedMessage::V1(message) = tx.message else {
            panic!("the enrolment must compile to a v1 message");
        };
        assert_eq!(message.config.loaded_accounts_data_size_limit, Some(777_216));
    }
}
