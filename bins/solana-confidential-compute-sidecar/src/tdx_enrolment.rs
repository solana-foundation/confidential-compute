//! Client-side pieces the Intel TDX enrolment pipeline needs that neither the
//! attestation report nor the SDK carries.
//!
//! Two jobs:
//!
//! 1. **Split a DCAP v4 quote.** `AttestationReport::IntelTdx` carries the raw
//!    quote and its measurements. `solana_confidential_compute_sdk::tdx::TdxEnrolment` wants the
//!    quote already taken apart: the two signed regions, the two signatures,
//!    the attestation key, the QE auth data, and the PCK leaf key. The offsets
//!    below mirror `solana_confidential_compute_verifier::tdx`'s, which is the parser that will read
//!    these bytes back on chain. They are duplicated rather than imported
//!    because the sidecar does not depend on the program crate; the constants
//!    are pinned by test instead.
//!
//! 2. **Decode a `ChallengeAccount`.** The pipeline must read back what
//!    `issue_tdx_challenge` actually recorded before it asks the enclave for a
//!    quote. The record is a fixed-size Borsh struct, decoded here by offset
//!    for the same reason.
//!
//! @spec SCC-TDX-001 SCC-TDX-002 SCC-TDX-005

use base64::Engine;

use crate::error::SidecarError;

// ---------------------------------------------------------------------------
// DCAP v4 quote layout
// ---------------------------------------------------------------------------

/// Quote header length.
pub const QUOTE_HEADER_LEN: usize = 48;
/// `Td10ReportBody` length.
pub const TD10_BODY_LEN: usize = 584;
/// Bytes covered by the attestation key's signature: `header || td_report_body`.
pub const ISV_SIGNED_LEN: usize = QUOTE_HEADER_LEN + TD10_BODY_LEN;
/// `EnclaveReportBody` length. This is the message the PCK leaf key signs.
pub const QE_REPORT_LEN: usize = 384;
/// `report_data` offset inside `Td10ReportBody`.
pub const BODY_REPORT_DATA: usize = 520;

/// Intel's QE vendor id. Any other value is not an Intel quote.
const INTEL_QE_VENDOR_ID: [u8; 16] =
    [0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07];
/// `ECDSA-256-with-P-256`.
const ATTESTATION_KEY_TYPE_ECDSA_P256: u16 = 2;
/// TEE type discriminator for TDX.
const TDX_TEE_TYPE: u32 = 0x0000_0081;

const OFF_VERSION: usize = 0;
const OFF_ATT_KEY_TYPE: usize = 2;
const OFF_TEE_TYPE: usize = 4;
const OFF_QE_VENDOR_ID: usize = 12;
const OFF_SIG_DATA_LEN: usize = ISV_SIGNED_LEN; // 632
const OFF_ISV_SIGNATURE: usize = 636;
const OFF_ATTESTATION_PUBKEY: usize = 700;
/// The ECDSA signature-data header is 6 bytes before the QE report begins.
const OFF_QE_REPORT: usize = 764 + 6;
const OFF_QE_REPORT_SIGNATURE: usize = OFF_QE_REPORT + QE_REPORT_LEN; // 1154
const OFF_QE_AUTH_DATA_LEN: usize = OFF_QE_REPORT_SIGNATURE + 64; // 1218
const OFF_QE_AUTH_DATA: usize = OFF_QE_AUTH_DATA_LEN + 2; // 1220

/// `PCK_CERT_CHAIN`. The only certification-data type this splitter reads.
const CERT_DATA_TYPE_PCK_CHAIN: u16 = 5;

/// DER prefix of a `SubjectPublicKeyInfo` for `id-ecPublicKey` over
/// `prime256v1`, up to and including the `0x04` uncompressed-point tag.
/// Exactly 64 bytes of `X || Y` follow it.
///
/// Matching on this is how the PCK leaf key is lifted out of the certificate
/// without a full X.509 parser. A certificate carries exactly one
/// `SubjectPublicKeyInfo`, and no other DER field in a PCK certificate shares
/// this byte sequence -- the signature `AlgorithmIdentifier` uses
/// `ecdsa-with-SHA256`, a different OID.
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// Everything `solana_confidential_compute_sdk::tdx::TdxEnrolment` needs out of one quote.
///
/// Owned rather than borrowed: the enrolment is assembled after the provider
/// call returns, and the quote buffer does not outlive it cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxQuoteParts {
    /// Uncompressed `X || Y`, as the quote carries it.
    pub attestation_pubkey_xy: [u8; 64],
    /// SEC1-compressed PCK leaf key, lifted from the certificate chain.
    pub pck_pubkey: [u8; 33],
    /// `EnclaveReportBody`, exactly [`QE_REPORT_LEN`] bytes.
    pub qe_report: Vec<u8>,
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: Vec<u8>,
    /// `header || td_report_body`, exactly [`ISV_SIGNED_LEN`] bytes.
    pub isv_signed: Vec<u8>,
    pub isv_signature: [u8; 64],
}

fn bad(reason: &str) -> SidecarError {
    SidecarError::AttestationError(format!("Intel TDX quote: {reason}"))
}

fn take(raw: &[u8], offset: usize, len: usize) -> Result<&[u8], SidecarError> {
    raw.get(offset..offset.saturating_add(len)).ok_or_else(|| bad("truncated before a required field"))
}

fn take64(raw: &[u8], offset: usize) -> Result<[u8; 64], SidecarError> {
    take(raw, offset, 64)?.try_into().map_err(|_| bad("a 64-byte field was short"))
}

fn u16_at(raw: &[u8], offset: usize) -> Result<u16, SidecarError> {
    let bytes = take(raw, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(raw: &[u8], offset: usize) -> Result<u32, SidecarError> {
    let bytes = take(raw, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// SEC1-compress an uncompressed P-256 point.
///
/// The prefix encodes the parity of Y, which is what lets X alone identify
/// the point.
fn compress_p256(xy: &[u8; 64]) -> [u8; 33] {
    let mut out = [2 + (xy[63] & 1); 33];
    out[1..].copy_from_slice(&xy[..32]);
    out
}

/// Take a genuine Intel TDX v4 quote apart.
///
/// Validates the header the same way the on-chain parser does, so a quote this
/// accepts is one the program will also parse. It does **not** verify either
/// signature -- that is the precompile's job, on chain.
///
/// @spec SCC-TDX-001 SCC-TDX-002
pub fn split_tdx_quote(raw: &[u8]) -> Result<TdxQuoteParts, SidecarError> {
    if u16_at(raw, OFF_VERSION)? != 4 {
        return Err(bad("not a version 4 quote"));
    }
    if u16_at(raw, OFF_ATT_KEY_TYPE)? != ATTESTATION_KEY_TYPE_ECDSA_P256 {
        return Err(bad("attestation key is not ECDSA P-256"));
    }
    if u32_at(raw, OFF_TEE_TYPE)? != TDX_TEE_TYPE {
        return Err(bad("TEE type is not TDX"));
    }
    if take(raw, OFF_QE_VENDOR_ID, 16)? != INTEL_QE_VENDOR_ID {
        return Err(bad("QE vendor id is not Intel's"));
    }

    // The declared signature-data length must cover everything read below.
    let sig_data_len = u32_at(raw, OFF_SIG_DATA_LEN)? as usize;
    let sig_data_end = OFF_SIG_DATA_LEN
        .checked_add(4)
        .and_then(|v| v.checked_add(sig_data_len))
        .ok_or_else(|| bad("signature data length overflows"))?;
    if sig_data_end > raw.len() {
        return Err(bad("signature data runs past the end of the quote"));
    }

    let qe_auth_data_len = u16_at(raw, OFF_QE_AUTH_DATA_LEN)? as usize;
    let qe_auth_end =
        OFF_QE_AUTH_DATA.checked_add(qe_auth_data_len).ok_or_else(|| bad("QE auth data length overflows"))?;
    if qe_auth_end > sig_data_end {
        return Err(bad("QE auth data runs past the signature data"));
    }

    let pck_pubkey = extract_pck_pubkey(raw, qe_auth_end, sig_data_end)?;

    Ok(TdxQuoteParts {
        attestation_pubkey_xy: take64(raw, OFF_ATTESTATION_PUBKEY)?,
        pck_pubkey,
        qe_report: take(raw, OFF_QE_REPORT, QE_REPORT_LEN)?.to_vec(),
        qe_report_signature: take64(raw, OFF_QE_REPORT_SIGNATURE)?,
        qe_auth_data: take(raw, OFF_QE_AUTH_DATA, qe_auth_data_len)?.to_vec(),
        isv_signed: take(raw, 0, ISV_SIGNED_LEN)?.to_vec(),
        isv_signature: take64(raw, OFF_ISV_SIGNATURE)?,
    })
}

/// Lift the PCK leaf public key out of the quote's certification data.
///
/// The on-chain `verify_tdx_qe_report` takes the compressed PCK key as an
/// instruction argument, checks it against the key the precompile verified
/// with, and then against the source-5 allowlist. The client therefore has to
/// name the same key the Quoting Enclave's platform used, and the only place
/// it appears is the leaf certificate in the chain appended to the quote.
fn extract_pck_pubkey(raw: &[u8], cert_data_start: usize, sig_data_end: usize) -> Result<[u8; 33], SidecarError> {
    let cert_type = u16_at(raw, cert_data_start)?;
    if cert_type != CERT_DATA_TYPE_PCK_CHAIN {
        return Err(bad(&format!(
            "certification data type {cert_type} is not a PCK certificate chain (5); \
             this quote carries no leaf key to name on chain"
        )));
    }
    let cert_len = u32_at(raw, cert_data_start + 2)? as usize;
    let body_start = cert_data_start + 6;
    let body_end = body_start.checked_add(cert_len).ok_or_else(|| bad("certification data length overflows"))?;
    if body_end > sig_data_end || body_end > raw.len() {
        return Err(bad("certification data runs past the end of the quote"));
    }

    let pem = std::str::from_utf8(&raw[body_start..body_end]).map_err(|_| bad("certificate chain is not UTF-8 PEM"))?;
    let leaf_der = first_pem_certificate(pem)?;

    let offset = leaf_der
        .windows(P256_SPKI_PREFIX.len())
        .position(|window| window == P256_SPKI_PREFIX)
        .ok_or_else(|| bad("leaf certificate carries no uncompressed P-256 public key"))?;
    let point_start = offset + P256_SPKI_PREFIX.len();
    let xy: [u8; 64] = leaf_der
        .get(point_start..point_start + 64)
        .ok_or_else(|| bad("leaf certificate public key is truncated"))?
        .try_into()
        .expect("64-byte slice");
    Ok(compress_p256(&xy))
}

/// DER bytes of the first certificate in a PEM chain. That is the leaf.
fn first_pem_certificate(pem: &str) -> Result<Vec<u8>, SidecarError> {
    let begin = pem.find(PEM_BEGIN).ok_or_else(|| bad("certificate chain has no PEM header"))? + PEM_BEGIN.len();
    let end = pem[begin..].find(PEM_END).ok_or_else(|| bad("certificate chain has no PEM footer"))? + begin;
    let body: String = pem[begin..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| bad("leaf certificate is not valid base64"))
}

/// Correctly-shaped placeholder parts for the dry-run synthetic quote.
///
/// The dry-run provider does not produce a DCAP quote, so there is nothing to
/// split. These bytes exist only so the enrolment transaction can be built and
/// size-checked without a cluster or a TD. They are **not** evidence, and
/// `enrol_intel_tdx` refuses to reach this function when `dry_run` is false.
///
/// `report_data` is written into the body at the offset the verifier reads it
/// from, so the artifact at least names the key the dry run was about.
pub fn dry_run_quote_parts(report_data: &[u8; 64]) -> TdxQuoteParts {
    let mut isv_signed = vec![0u8; ISV_SIGNED_LEN];
    isv_signed[..2].copy_from_slice(&4u16.to_le_bytes());
    isv_signed[2..4].copy_from_slice(&ATTESTATION_KEY_TYPE_ECDSA_P256.to_le_bytes());
    isv_signed[4..8].copy_from_slice(&TDX_TEE_TYPE.to_le_bytes());
    isv_signed[OFF_QE_VENDOR_ID..OFF_QE_VENDOR_ID + 16].copy_from_slice(&INTEL_QE_VENDOR_ID);
    let report_data_at = QUOTE_HEADER_LEN + BODY_REPORT_DATA;
    isv_signed[report_data_at..report_data_at + 64].copy_from_slice(report_data);

    let mut attestation_pubkey_xy = [0u8; 64];
    attestation_pubkey_xy[..32].copy_from_slice(&report_data[..32]);

    TdxQuoteParts {
        pck_pubkey: compress_p256(&[0u8; 64]),
        attestation_pubkey_xy,
        qe_report: vec![0u8; QE_REPORT_LEN],
        qe_report_signature: [0u8; 64],
        qe_auth_data: vec![0u8; 32],
        isv_signed,
        isv_signature: [0u8; 64],
    }
}

// ---------------------------------------------------------------------------
// ChallengeAccount read-back
// ---------------------------------------------------------------------------

/// `sha256("account:ChallengeAccount")[..8]`.
pub const CHALLENGE_DISCRIMINATOR: [u8; 8] = [96, 128, 44, 165, 71, 172, 60, 12];
/// `discriminator || source || challenge_slot || slot_hash || nonce || expires_slot || bump`.
pub const CHALLENGE_ACCOUNT_LEN: usize = 8 + 1 + 8 + 32 + 32 + 8 + 1;

/// What `issue_tdx_challenge` recorded, as read back from the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeRecord {
    pub source: u8,
    pub challenge_slot: u64,
    pub slot_hash: [u8; 32],
    pub nonce: [u8; 32],
    pub expires_slot: u64,
    pub bump: u8,
}

impl ChallengeRecord {
    /// `expires_slot == 0` is the tombstone a consumed quote writes.
    pub fn is_consumed(&self) -> bool {
        self.expires_slot == 0
    }
}

/// Decode a `ChallengeAccount` from raw account data.
pub fn decode_challenge_account(data: &[u8]) -> Result<ChallengeRecord, SidecarError> {
    if data.len() < CHALLENGE_ACCOUNT_LEN {
        return Err(SidecarError::OnchainError(format!(
            "challenge account is {} bytes, expected at least {CHALLENGE_ACCOUNT_LEN}",
            data.len()
        )));
    }
    if data[..8] != CHALLENGE_DISCRIMINATOR {
        return Err(SidecarError::OnchainError(
            "challenge account discriminator does not match ChallengeAccount".to_string(),
        ));
    }
    let mut slot_hash = [0u8; 32];
    slot_hash.copy_from_slice(&data[17..49]);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[49..81]);
    Ok(ChallengeRecord {
        source: data[8],
        challenge_slot: u64::from_le_bytes(data[9..17].try_into().expect("8 bytes")),
        slot_hash,
        nonce,
        expires_slot: u64::from_le_bytes(data[81..89].try_into().expect("8 bytes")),
        bump: data[89],
    })
}

/// Refuse to build a quote request against a challenge that is not the one
/// this process issued.
///
/// The enclave binds `slot_hash` and `nonce` into hardware-signed bytes, and
/// the program recomputes that binding from the account. If the account says
/// anything other than what was issued -- a different nonce, a different slot,
/// a slot hash the sysvar did not report, an already-consumed record -- the
/// quote would be built against the wrong challenge and rejected on chain.
/// Refusing here costs one failed challenge; submitting costs a quote and a
/// consumed nonce.
///
/// @spec SCC-TDX-005
pub fn validate_challenge_readback(
    record: &ChallengeRecord,
    expected_source: u8,
    expected_nonce: &[u8; 32],
    expected_slot: u64,
    expected_slot_hash: &[u8; 32],
) -> Result<(), SidecarError> {
    let refuse = |reason: String| Err(SidecarError::OnchainError(reason));
    if record.source != expected_source {
        return refuse(format!("challenge read back with source {} rather than {expected_source}", record.source));
    }
    if &record.nonce != expected_nonce {
        return refuse("challenge read back with a nonce this process did not issue".to_string());
    }
    if record.challenge_slot != expected_slot {
        return refuse(format!(
            "challenge read back pinning slot {} rather than {expected_slot}",
            record.challenge_slot
        ));
    }
    if &record.slot_hash != expected_slot_hash {
        return refuse("challenge read back with a slot hash the SlotHashes sysvar did not report".to_string());
    }
    if record.is_consumed() {
        return refuse("challenge read back already consumed".to_string());
    }
    Ok(())
}
