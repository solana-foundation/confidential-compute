//! Intel TDX DCAP quote parsing and secp256r1 precompile introspection.
//!
//! A TDX quote is signed with ECDSA P-256, which Solana verifies natively
//! through the `Secp256r1SigVerify1111111111111111111111111` precompile
//! (SIMD-0075, active on mainnet-beta, devnet and testnet). No zero-knowledge
//! proof is needed for the two signatures this module covers.
//!
//! The precompile reads its message from instruction data only -- never from an
//! account -- so every message it checks has to fit inside a 1,232-byte
//! transaction. That budget is what splits the work across two instructions:
//!
//! | signature | signer | message | precompile ix |
//! |---|---|---:|---:|
//! | QE report | PCK leaf key | `qe_report_body` (384 B) | 497 B |
//! | ISV | attestation key | `header \|\| td_report_body` (632 B) | 745 B |
//!
//! Together they are 1,242 bytes, which does not fit, so the QE step runs
//! first and records the attestation key it certified; the ISV step then uses
//! that recorded key. Neither step alone is meaningful: the QE step says the
//! platform certified a key, the ISV step says that key signed a body.
//!
//! @spec SCC-TDX-001 SCC-TDX-002

use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use solana_program::sysvar::instructions::{self, load_current_index_checked, load_instruction_at_checked};

use crate::error::VerifierError;

/// Solana's native secp256r1 precompile (SIMD-0075).
///
/// Base58 `Secp256r1SigVerify1111111111111111111111111`. Unlike the P-384
/// placeholder this program is deployed and its feature gate is active on
/// mainnet-beta, devnet and testnet.
/// @spec SCC-TDX-001
pub const SECP256R1_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x06, 0x92, 0x0d, 0xec, 0x2f, 0xea, 0x71, 0xb5, 0xb7, 0x23, 0x81, 0x4d, 0x74, 0x2d, 0xa9, 0x03, 0x1c, 0x83, 0xe7,
    0x5f, 0xdb, 0x79, 0x5d, 0x56, 0x8e, 0x75, 0x47, 0x80, 0x20, 0x00, 0x00, 0x00,
]);

/// Quote header length.
pub const QUOTE_HEADER_LEN: usize = 48;
/// `Td10ReportBody` length.
pub const TD10_BODY_LEN: usize = 584;
/// Bytes covered by the ISV (attestation-key) signature: header then body.
pub const ISV_SIGNED_LEN: usize = QUOTE_HEADER_LEN + TD10_BODY_LEN;
/// `EnclaveReportBody` length. This is the QE report message.
pub const QE_REPORT_LEN: usize = 384;

/// Intel's QE vendor id. A quote carrying any other value is not an Intel quote.
const INTEL_QE_VENDOR_ID: [u8; 16] =
    [0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07];

/// `ECDSA-256-with-P-256`. The only attestation key type this module accepts.
const ATTESTATION_KEY_TYPE_ECDSA_P256: u16 = 2;
/// TEE type discriminator for TDX.
pub const TDX_TEE_TYPE: u32 = 0x0000_0081;

// Absolute offsets into the raw quote. Verified against Intel's v4 layout and
// against the reference fixture shipped by Automata.
const OFF_VERSION: usize = 0;
const OFF_ATT_KEY_TYPE: usize = 2;
const OFF_TEE_TYPE: usize = 4;
const OFF_QE_VENDOR_ID: usize = 12;
const OFF_SIG_DATA_LEN: usize = ISV_SIGNED_LEN; // 632
const OFF_ISV_SIGNATURE: usize = 636;
const OFF_ATTESTATION_PUBKEY: usize = 700;
const OFF_QE_REPORT: usize = 764 + 6; // cert-data header is 6 bytes
const OFF_QE_REPORT_SIGNATURE: usize = OFF_QE_REPORT + QE_REPORT_LEN; // 1154
const OFF_QE_AUTH_DATA_LEN: usize = OFF_QE_REPORT_SIGNATURE + 64; // 1218
const OFF_QE_AUTH_DATA: usize = OFF_QE_AUTH_DATA_LEN + 2; // 1220

/// `user_report_data` offset inside `EnclaveReportBody`.
pub const QE_REPORT_DATA_OFFSET: usize = 320;

// Field offsets inside `Td10ReportBody`, relative to the start of the body.
const BODY_MR_TD: usize = 136;
const BODY_MR_CONFIG_ID: usize = 184;
const BODY_RTMR0: usize = 328;
/// One runtime measurement register. There are four, `RTMR0..3`.
pub const RTMR_LEN: usize = 48;
const BODY_REPORT_DATA: usize = 520;

/// Borrowed view over a validated Intel TDX v4 quote.
///
/// Construction validates the header and every offset this type exposes, so
/// the accessors cannot panic once a `TdxQuote` exists.
/// @spec SCC-TDX-001
#[derive(Debug, Clone, Copy)]
pub struct TdxQuote<'a> {
    raw: &'a [u8],
    qe_auth_data_len: usize,
}

impl<'a> TdxQuote<'a> {
    /// Validate the header and bounds of a raw quote.
    ///
    /// Rejects anything that is not an Intel TDX v4 quote signed with
    /// ECDSA P-256, and anything too short for the fields below.
    pub fn parse(raw: &'a [u8]) -> Result<Self, ProgramError> {
        // Enough for the fixed prefix through the QE auth-data length field.
        if raw.len() < OFF_QE_AUTH_DATA {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let version = u16::from_le_bytes(array2(raw, OFF_VERSION)?);
        if version != 4 {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let key_type = u16::from_le_bytes(array2(raw, OFF_ATT_KEY_TYPE)?);
        if key_type != ATTESTATION_KEY_TYPE_ECDSA_P256 {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let tee_type = u32::from_le_bytes(array4(raw, OFF_TEE_TYPE)?);
        if tee_type != TDX_TEE_TYPE {
            return Err(VerifierError::InvalidInstruction.into());
        }
        if slice(raw, OFF_QE_VENDOR_ID, 16)? != INTEL_QE_VENDOR_ID {
            return Err(VerifierError::InvalidInstruction.into());
        }

        // The declared signature-data length must cover everything we read.
        let sig_data_len = u32::from_le_bytes(array4(raw, OFF_SIG_DATA_LEN)?) as usize;
        let sig_data_end = OFF_SIG_DATA_LEN
            .checked_add(4)
            .and_then(|v| v.checked_add(sig_data_len))
            .ok_or(VerifierError::InvalidInstruction)?;
        if sig_data_end > raw.len() {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let qe_auth_data_len = u16::from_le_bytes(array2(raw, OFF_QE_AUTH_DATA_LEN)?) as usize;
        let qe_auth_end = OFF_QE_AUTH_DATA.checked_add(qe_auth_data_len).ok_or(VerifierError::InvalidInstruction)?;
        if qe_auth_end > sig_data_end {
            return Err(VerifierError::InvalidInstruction.into());
        }

        Ok(Self { raw, qe_auth_data_len })
    }

    /// Bytes covered by the ISV signature: `header || td_report_body`.
    pub fn isv_signed_region(&self) -> &'a [u8] {
        &self.raw[..ISV_SIGNED_LEN]
    }

    /// ECDSA `r || s` produced by the attestation key over the signed region.
    pub fn isv_signature(&self) -> &'a [u8; 64] {
        array_ref64(self.raw, OFF_ISV_SIGNATURE)
    }

    /// Attestation public key as raw uncompressed `X || Y`, without the
    /// `0x04` SEC1 prefix.
    pub fn attestation_pubkey_xy(&self) -> &'a [u8; 64] {
        array_ref64(self.raw, OFF_ATTESTATION_PUBKEY)
    }

    /// The QE report. This is the message the PCK leaf key signs.
    pub fn qe_report(&self) -> &'a [u8] {
        &self.raw[OFF_QE_REPORT..OFF_QE_REPORT + QE_REPORT_LEN]
    }

    /// ECDSA `r || s` produced by the PCK leaf key over [`Self::qe_report`].
    pub fn qe_report_signature(&self) -> &'a [u8; 64] {
        array_ref64(self.raw, OFF_QE_REPORT_SIGNATURE)
    }

    /// QE authentication data, length-prefixed in the quote.
    pub fn qe_auth_data(&self) -> &'a [u8] {
        &self.raw[OFF_QE_AUTH_DATA..OFF_QE_AUTH_DATA + self.qe_auth_data_len]
    }

    /// `user_report_data` of the QE report: `SHA-256(att_key || auth_data)`
    /// followed by 32 zero bytes.
    pub fn qe_report_data(&self) -> &'a [u8; 64] {
        array_ref64(self.raw, OFF_QE_REPORT + QE_REPORT_DATA_OFFSET)
    }

    fn body(&self) -> &'a [u8] {
        &self.raw[QUOTE_HEADER_LEN..QUOTE_HEADER_LEN + TD10_BODY_LEN]
    }

    /// `MRTD` -- the measurement of the Trust Domain's initial contents.
    pub fn mr_td(&self) -> &'a [u8; 48] {
        array_ref48(self.body(), BODY_MR_TD)
    }

    /// `MRCONFIGID`.
    pub fn mr_config_id(&self) -> &'a [u8; 48] {
        array_ref48(self.body(), BODY_MR_CONFIG_ID)
    }

    /// The four runtime measurement registers, in order.
    pub fn rtmrs(&self) -> [&'a [u8; 48]; 4] {
        [
            array_ref48(self.body(), BODY_RTMR0),
            array_ref48(self.body(), BODY_RTMR0 + 48),
            array_ref48(self.body(), BODY_RTMR0 + 96),
            array_ref48(self.body(), BODY_RTMR0 + 144),
        ]
    }

    /// The 64-byte `REPORTDATA` the guest asked the hardware to sign.
    ///
    /// This is the only field an enclave controls, and therefore the only
    /// place a workload signer can be bound into hardware evidence.
    pub fn report_data(&self) -> &'a [u8; 64] {
        array_ref64(self.body(), BODY_REPORT_DATA)
    }

    /// Verify that the QE report commits to the attestation key.
    ///
    /// Intel specifies `user_report_data = SHA-256(att_key || auth_data)`
    /// followed by 32 zero bytes. Both halves matter: without the first the
    /// attestation key is unbound from the platform-certified QE, and without
    /// the second a 32-byte suffix is free space an attacker controls.
    /// @spec SCC-TDX-002
    pub fn verify_qe_binding(&self) -> Result<(), ProgramError> {
        let digest = solana_program::hash::hashv(&[self.attestation_pubkey_xy().as_slice(), self.qe_auth_data()]);
        let report_data = self.qe_report_data();
        if digest.to_bytes() != report_data[..32] {
            return Err(VerifierError::InvalidSignature.into());
        }
        if report_data[32..] != [0u8; 32] {
            return Err(VerifierError::InvalidSignature.into());
        }
        Ok(())
    }
}

/// Borsh domain for the `REPORTDATA` preimage. Must equal the sidecar's
/// `REPORT_DATA_DOMAIN`, and the length assertion below pins that.
pub const REPORT_DATA_DOMAIN: &str = "solana-confidential-compute/v1/report-data";

/// The 64-byte `REPORTDATA` an honest enclave must have asked for.
///
/// This mirrors the sidecar's `report_data_commitment` byte for byte. It is
/// the one field an enclave controls, and therefore the only place a workload
/// signer can be written into hardware evidence. Recomputing it here and
/// insisting the quote matches is what turns "genuine hardware ran a known
/// measurement" into "genuine hardware vouched for *this key*".
///
/// ```text
/// composite  = SHA-256(signer || slot_hash || gpu_rim || model)
/// REPORTDATA = SHA-512(len || domain || signer || composite
///                      || slot_hash || gpu_rim || model || challenge_nonce)
/// ```
///
/// The signer appears twice -- directly and through the composite -- because
/// the sidecar writes it both ways, so a reader of the signed bytes can see
/// the bound key without recomputing anything.
/// The nonce distinguishes challenges that pin the same slot hash, so a quote
/// accepted for one challenge cannot be replayed through another challenge.
///
/// @spec SCC-TDX-002
pub fn expected_report_data(
    workload_signer: &[u8; 32],
    slot_hash: &[u8; 32],
    gpu_rim_digest: &[u8; 32],
    model_digest: &[u8; 32],
    challenge_nonce: &[u8; 32],
) -> [u8; 64] {
    const _: () = assert!(REPORT_DATA_DOMAIN.len() == 42);
    let composite = solana_program::hash::hashv(&[workload_signer, slot_hash, gpu_rim_digest, model_digest]).to_bytes();

    let domain_len = 42u32.to_le_bytes();
    let preimage: [&[u8]; 8] = [
        &domain_len,
        REPORT_DATA_DOMAIN.as_bytes(),
        workload_signer,
        &composite,
        slot_hash,
        gpu_rim_digest,
        model_digest,
        challenge_nonce,
    ];

    // SHA-512 is not a Solana syscall, so it is built from two SHA-256 halves
    // the same way the sidecar's `Sha512` output is consumed: the sidecar
    // hashes once with SHA-512 and the verifier must match it exactly, so
    // this uses the same primitive rather than an approximation.
    sha512(&preimage)
}

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

// SGX `EnclaveReportBody` field offsets, used to read the QE's own identity.
const QE_ATTRIBUTES: usize = 48;
const QE_MR_SIGNER: usize = 128;
const QE_ISV_PROD_ID: usize = 256;
const QE_ISV_SVN: usize = 258;

/// SGX `ATTRIBUTES.FLAGS` bit 1. A debug enclave's memory is inspectable.
const SGX_ATTRIBUTE_DEBUG: u8 = 0x02;
/// TDX `TD_ATTRIBUTES` bit 0, `TUD.DEBUG`. A debug TD offers no protection
/// against the host at all.
const TD_ATTRIBUTE_DEBUG: u8 = 0x01;

// `Td10ReportBody` offsets for the fields governance needs to pin.
const BODY_TEE_TCB_SVN: usize = 0;
const BODY_MR_SEAM: usize = 16;
const BODY_TD_ATTRIBUTES: usize = 120;
const BODY_XFAM: usize = 128;

/// Reject a QE running in debug mode.
///
/// A debug enclave can be single-stepped and have its memory read by the
/// host, so a QE in that state will certify any attestation key an attacker
/// asks it to. Intel ships the production QE with this bit clear; nothing
/// else in the quote distinguishes the two.
///
/// @spec SCC-TDX-001
pub fn reject_debug_qe(qe_report: &[u8]) -> Result<(), ProgramError> {
    let flags = qe_report.get(QE_ATTRIBUTES).ok_or(VerifierError::InvalidInstruction)?;
    if flags & SGX_ATTRIBUTE_DEBUG != 0 {
        return Err(VerifierError::DisallowedMeasurement.into());
    }
    Ok(())
}

/// Digest of the QE's identity, for the source-5 allowlist.
///
/// The PCK key signs **every** enclave on its platform, not only the Quoting
/// Enclave. Checking the PCK key alone therefore says "some enclave on an
/// approved machine signed this" -- an attacker running their own enclave on
/// that machine could certify any attestation key they liked.
///
/// `MRSIGNER` identifies who built the enclave, `ISVPRODID` which product it
/// is, and `ISVSVN` its version. Requiring governance to allowlist the
/// combination is what narrows "some enclave" to "Intel's TDX Quoting
/// Enclave at an approved revision".
///
/// Hashing rather than listing three values keeps one allowlist entry per
/// approved QE, and avoids the all-zero rejection that catches
/// legitimately-zero fields elsewhere.
///
/// @spec SCC-TDX-001
pub fn qe_identity_digest(qe_report: &[u8]) -> Result<[u8; 32], ProgramError> {
    let mr_signer = qe_report.get(QE_MR_SIGNER..QE_MR_SIGNER + 32).ok_or(VerifierError::InvalidInstruction)?;
    let isv_prod_id = qe_report.get(QE_ISV_PROD_ID..QE_ISV_PROD_ID + 2).ok_or(VerifierError::InvalidInstruction)?;
    let isv_svn = qe_report.get(QE_ISV_SVN..QE_ISV_SVN + 2).ok_or(VerifierError::InvalidInstruction)?;
    Ok(solana_program::hash::hashv(&[mr_signer, isv_prod_id, isv_svn]).to_bytes())
}

/// Reject a Trust Domain running in debug mode.
///
/// `TD_ATTRIBUTES.TUD.DEBUG` lets the host read and modify TD memory. A debug
/// TD with a production measurement is byte-identical to the real thing
/// everywhere except this bit, so without the check an attacker boots the
/// approved image in debug mode and reads the workload's keys out of memory.
///
/// @spec SCC-TDX-002
pub fn reject_debug_td(body: &[u8]) -> Result<(), ProgramError> {
    let attributes = body.get(BODY_TD_ATTRIBUTES).ok_or(VerifierError::InvalidInstruction)?;
    if attributes & TD_ATTRIBUTE_DEBUG != 0 {
        return Err(VerifierError::DisallowedMeasurement.into());
    }
    Ok(())
}

/// Digest of everything about a Trust Domain that governance should pin.
///
/// Covers:
///
/// - `TEE_TCB_SVN` and `MRSEAM` -- which TDX module is running. Without them
///   an approved workload measurement would be accepted under a down-level
///   or non-production module.
/// - `TD_ATTRIBUTES` and `XFAM` -- the execution environment. The debug bit
///   is rejected outright above, but the remaining bits still change what the
///   TD can do, and an allowlist entry should mean one configuration.
/// - `MRTD` and `RTMR0..2` -- the boot chain and the image.
/// - `MRCONFIGID` -- the launch configuration. On a dstack deployment this is
///   what binds the MrConfigV3 document, and therefore the GPU policy the
///   guest enforces at boot. It is the stable carrier for configuration that
///   RTMR3 carries unstably.
///
/// **`RTMR3` is deliberately excluded.** It is the runtime event register, and
/// on a real deployment it changes on every boot: dstack extends `instance-id`
/// into it, and the `gpu-attestation` event payload commits to an `nvattest`
/// run whose nonce is fresh each time. Hashing it into an allowlisted digest
/// would mean a new governance entry per boot, which is not an allowlist. The
/// reference quote has all-zero RTMRs, so a test fixture cannot show this --
/// only a quote from a running deployment would.
///
/// Excluding it means the runtime events are *not* pinned here. Reaching them
/// requires replaying the event log against the signed `RTMR3` and reading the
/// payloads, which is a separate piece of work. `rtmrs_hash` on the attested
/// signer still records all four registers for off-chain inspection.
///
/// @spec SCC-TDX-002
pub fn td_platform_digest(body: &[u8]) -> Result<[u8; 32], ProgramError> {
    let field = |offset: usize, len: usize| {
        body.get(offset..offset + len).ok_or(ProgramError::from(VerifierError::InvalidInstruction))
    };
    Ok(solana_program::hash::hashv(&[
        field(BODY_TEE_TCB_SVN, 16)?,
        field(BODY_MR_SEAM, 48)?,
        field(BODY_TD_ATTRIBUTES, 8)?,
        field(BODY_XFAM, 8)?,
        field(BODY_MR_TD, 48)?,
        field(BODY_MR_CONFIG_ID, 48)?,
        field(BODY_RTMR0, RTMR_LEN * 3)?,
    ])
    .to_bytes())
}

/// SEC1-compress an uncompressed P-256 point given as raw `X || Y`.
///
/// The precompile wants 33 bytes. Deriving the prefix from the parity of `Y`
/// is pure byte arithmetic -- decoding the point through a curve library to
/// re-encode it would cost compute units and prove nothing, since the
/// precompile validates the point itself.
pub fn compress_p256(xy: &[u8; 64]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 2 + (xy[63] & 1);
    out[1..].copy_from_slice(&xy[..32]);
    out
}

/// `floor(n / 2)` for the P-256 group order, big-endian.
const P256_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xDE, 0x73, 0x7D,
    0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

/// The P-256 group order `n`, big-endian.
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA,
    0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Normalize an ECDSA signature to low-S form.
///
/// The precompile rejects `s > n/2`, so a quote carrying the high-S form of an
/// otherwise valid signature would fail. Normalizing here keeps that a
/// non-issue, and the comparison the caller performs is against the same
/// normalized bytes the client put in the precompile instruction.
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

fn is_low_s(s: &[u8]) -> bool {
    for (a, b) in s.iter().zip(P256_HALF_ORDER.iter()) {
        if a != b {
            return a < b;
        }
    }
    true
}

// Canonical offsets produced by `solana_secp256r1_program`'s instruction
// builder. Pinning them means an attacker cannot point the declared regions at
// bytes other than the ones immediately following the offset block.
const PRECOMPILE_OFFSETS_START: usize = 2;
const PRECOMPILE_DATA_START: usize = 16;
const PRECOMPILE_PUBKEY_OFFSET: u16 = 16;
const PRECOMPILE_SIGNATURE_OFFSET: u16 = 49;
const PRECOMPILE_MESSAGE_OFFSET: u16 = 113;
/// `u16::MAX` means "this instruction's own data".
const PRECOMPILE_SELF_INDEX: u16 = u16::MAX;

/// Assert that some earlier instruction had the secp256r1 precompile verify
/// exactly `(pubkey, message, signature)`.
///
/// The precompile runs before the program and aborts the transaction when a
/// signature does not check out, so finding a matching instruction is
/// equivalent to the signature being valid. What this function has to
/// establish is that the instruction the precompile verified is the one
/// carrying *our* bytes.
///
/// Three properties make that binding sound, and the third is easy to miss:
///
/// 1. the instruction belongs to the precompile program and has the exact
///    canonical length, so no trailing or shadow data is present,
/// 2. the pubkey, signature and message regions byte-match values the caller
///    re-derived from the quote, and
/// 3. every `*_instruction_index` is `u16::MAX`.
///
/// Without (3) the offsets may name a *different* instruction in the same
/// transaction. The precompile would then verify an attacker's triple while
/// this function compares against bytes that were never verified, and both
/// would succeed. Automata's equivalent helper parses those three fields and
/// never checks them.
///
/// @spec SCC-TDX-001
pub fn assert_secp256r1_verified(
    instructions_sysvar: &AccountInfo,
    compressed_pubkey: &[u8; 33],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), ProgramError> {
    let verified = extract_secp256r1_verified(instructions_sysvar, message.len())?;
    if &verified.compressed_pubkey == compressed_pubkey
        && verified.message == message
        && &verified.signature == signature
    {
        return Ok(());
    }
    Err(VerifierError::InvalidSignature.into())
}

/// One `(pubkey, message, signature)` triple the precompile verified.
pub struct VerifiedSecp256r1 {
    pub compressed_pubkey: [u8; 33],
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

/// Read back what the secp256r1 precompile verified in an earlier instruction.
///
/// A TDX quote is roughly 5 KB and does not fit in a transaction. But the
/// precompile already requires its message inline, so the bytes the program
/// needs are in the transaction anyway: rather than uploading the quote to an
/// account and verifying a signature over part of it, the caller puts exactly
/// the signed region in the precompile instruction and the program reads it
/// back. Nothing is stored, and the two transactions carry 497 and 745 bytes
/// instead of fifteen chunk uploads.
///
/// `message_len` is pinned by the caller because every use here has a fixed
/// size -- 384 for a QE report, 632 for a TDX v4 signed region. Accepting a
/// caller-chosen length would let a short message slip past a later parse.
///
/// # What this establishes, and what it does not
///
/// The returned triple was verified by the precompile, so the signature is
/// valid for that key over those bytes. It says **nothing about whose key it
/// is.** The caller must settle that separately -- against a policy allowlist,
/// or against a key an earlier step recorded. A caller that skips it accepts
/// a well-formed signature from any key at all.
///
/// @spec SCC-TDX-001
pub fn extract_secp256r1_verified(
    instructions_sysvar: &AccountInfo,
    message_len: usize,
) -> Result<VerifiedSecp256r1, ProgramError> {
    if instructions_sysvar.key != &instructions::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    let current_index = load_current_index_checked(instructions_sysvar)?;
    if current_index == 0 {
        return Err(VerifierError::InvalidInstruction.into());
    }

    let expected_len = PRECOMPILE_DATA_START + 33 + 64 + message_len;

    // The precompile may sit anywhere before this instruction: a caller can
    // legitimately prepend a compute-budget instruction.
    for idx in (0..current_index).rev() {
        let ix = load_instruction_at_checked(idx as usize, instructions_sysvar)?;
        if ix.program_id != SECP256R1_PROGRAM_ID
            || !ix.accounts.is_empty()
            || ix.data.len() != expected_len
            || ix.data.first() != Some(&1)
        {
            continue;
        }

        let offsets = &ix.data[PRECOMPILE_OFFSETS_START..PRECOMPILE_DATA_START];
        let signature_offset = u16::from_le_bytes([offsets[0], offsets[1]]);
        let signature_index = u16::from_le_bytes([offsets[2], offsets[3]]);
        let pubkey_offset = u16::from_le_bytes([offsets[4], offsets[5]]);
        let pubkey_index = u16::from_le_bytes([offsets[6], offsets[7]]);
        let message_offset = u16::from_le_bytes([offsets[8], offsets[9]]);
        let message_size = u16::from_le_bytes([offsets[10], offsets[11]]);
        let message_index = u16::from_le_bytes([offsets[12], offsets[13]]);

        // (3) above. Any other index resolves the region against a different
        // instruction, so the bytes the precompile checked are not these.
        if signature_index != PRECOMPILE_SELF_INDEX
            || pubkey_index != PRECOMPILE_SELF_INDEX
            || message_index != PRECOMPILE_SELF_INDEX
        {
            continue;
        }
        if pubkey_offset != PRECOMPILE_PUBKEY_OFFSET
            || signature_offset != PRECOMPILE_SIGNATURE_OFFSET
            || message_offset != PRECOMPILE_MESSAGE_OFFSET
            || usize::from(message_size) != message_len
        {
            continue;
        }

        let mut compressed_pubkey = [0u8; 33];
        compressed_pubkey.copy_from_slice(&ix.data[16..49]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&ix.data[49..113]);
        return Ok(VerifiedSecp256r1 { compressed_pubkey, message: ix.data[113..].to_vec(), signature });
    }

    Err(VerifierError::InvalidSignature.into())
}

fn slice(buf: &[u8], offset: usize, len: usize) -> Result<&[u8], ProgramError> {
    let end = offset.checked_add(len).ok_or(VerifierError::InvalidInstruction)?;
    buf.get(offset..end).ok_or_else(|| VerifierError::InvalidInstruction.into())
}

fn array2(buf: &[u8], offset: usize) -> Result<[u8; 2], ProgramError> {
    let s = slice(buf, offset, 2)?;
    Ok([s[0], s[1]])
}

fn array4(buf: &[u8], offset: usize) -> Result<[u8; 4], ProgramError> {
    let s = slice(buf, offset, 4)?;
    Ok([s[0], s[1], s[2], s[3]])
}

// The two helpers below are only reachable from `TdxQuote`, whose constructor
// has already bounds-checked every offset they are called with.
fn array_ref48(buf: &[u8], offset: usize) -> &[u8; 48] {
    buf[offset..offset + 48].try_into().expect("offset validated by TdxQuote::parse")
}

fn array_ref64(buf: &[u8], offset: usize) -> &[u8; 64] {
    buf[offset..offset + 64].try_into().expect("offset validated by TdxQuote::parse")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hardcoded program id must match the documented base58 address. A
    /// transposed byte here would silently disable every signature check,
    /// because the loop would simply never find a matching instruction.
    #[test]
    fn secp256r1_program_id_matches_the_published_address() {
        assert_eq!(SECP256R1_PROGRAM_ID.to_string(), "Secp256r1SigVerify1111111111111111111111111");
    }

    #[test]
    fn compression_follows_the_parity_of_y() {
        let mut xy = [0u8; 64];
        xy[0] = 0xaa;
        xy[63] = 0x02; // even
        assert_eq!(compress_p256(&xy)[0], 0x02);
        xy[63] = 0x03; // odd
        assert_eq!(compress_p256(&xy)[0], 0x03);
        assert_eq!(&compress_p256(&xy)[1..], &xy[..32]);
    }

    #[test]
    fn low_s_signatures_are_left_alone() {
        let mut sig = [0u8; 64];
        sig[32] = 0x01;
        assert_eq!(normalize_low_s(&sig), sig);
    }

    #[test]
    fn high_s_signatures_are_reflected_about_the_order() {
        // s = n - 1 is high; normalizing must yield exactly 1.
        let mut sig = [0u8; 64];
        sig[32..].copy_from_slice(&P256_ORDER);
        sig[63] -= 1;
        let normalized = normalize_low_s(&sig);
        let mut expected = [0u8; 64];
        expected[63] = 1;
        assert_eq!(normalized, expected);
        // Normalizing twice is a no-op: the result is already low-S.
        assert_eq!(normalize_low_s(&normalized), normalized);
    }

    #[test]
    fn half_order_itself_counts_as_low_s() {
        assert!(is_low_s(&P256_HALF_ORDER));
        let mut one_above = P256_HALF_ORDER;
        one_above[31] += 1;
        assert!(!is_low_s(&one_above));
    }

    #[test]
    fn a_truncated_quote_is_rejected_rather_than_panicking() {
        for len in 0..OFF_QE_AUTH_DATA {
            let raw = vec![0u8; len];
            assert!(TdxQuote::parse(&raw).is_err(), "length {len} must reject");
        }
    }
}
