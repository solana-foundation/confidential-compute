//! On-chain CPI helpers for Solana Confidential Compute consumer programs.
//!
//! This crate depends on `solana-program`, `solana-confidential-compute-core`, and `bytemuck`. It does not depend on `solana-sdk`.
// SDLC 3.2.1: this crate runs on chain, so all arithmetic is checked.
#![deny(clippy::arithmetic_side_effects)]

pub mod anchor;
pub mod error;
pub use anchor::AttestedSignerAccount;
pub use error::CpiError;

use solana_confidential_compute_core::{
    report::SnpReportView, MAX_NITRO_DOCUMENT_LEN, NITRO_PCR_LEN, NITRO_USER_DATA_LEN, SNP_REPORT_SIZE,
};
use solana_program::{
    account_info::AccountInfo,
    instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT},
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::{
        clock::Clock,
        instructions::{self, load_current_index_checked, load_instruction_at_checked},
        Sysvar,
    },
};
solana_program::declare_id!("EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh");

/// 8-byte Anchor discriminator for `verify_atomic`.
pub const VERIFY_ATOMIC_DISCRIMINATOR: [u8; 8] = [65, 19, 195, 149, 67, 219, 25, 75];
/// 8-byte Anchor discriminator for `verify_atomic_with_nonce`.
pub const VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR: [u8; 8] = [209, 4, 10, 239, 3, 142, 223, 250];
/// 8-byte Anchor discriminator for `verify_nitro_attestation`.
/// @spec SCC-NITRO-008
pub const VERIFY_NITRO_ATTESTATION_DISCRIMINATOR: [u8; 8] = [107, 76, 178, 169, 215, 146, 23, 95];
/// Mode B (`verify_atomic_nitro`): action commitment + nonce tombstone.
/// @spec SCC-NITRO-008
pub const VERIFY_NITRO_MODE_B: u8 = 1;
/// 8-byte Anchor discriminator for `verify_google_jwt`.
/// @spec SCC-VERIFY-013
pub const VERIFY_GOOGLE_JWT_DISCRIMINATOR: [u8; 8] = [104, 38, 12, 199, 131, 240, 78, 165];
/// Mode B (`verify_google_jwt`): action commitment + nonce tombstone.
/// @spec SCC-VERIFY-013
pub const VERIFY_GOOGLE_JWT_MODE_B: u8 = 1;
/// 8-byte Anchor discriminator for `verify_nvidia_attestation`.
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR: [u8; 8] = [31, 2, 40, 104, 69, 155, 234, 120];
/// Mode B (`verify_nvidia_attestation`): action commitment + nonce tombstone.
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_MODE_B: u8 = 1;
/// 8-byte Anchor discriminator for `AttestedSignerAccountV2`.
pub const ATTESTED_SIGNER_DISCRIMINATOR: [u8; 8] = [43, 255, 114, 40, 233, 28, 127, 238];
/// PDA seed prefix for `AttestedSignerAccount`.
pub const ATTESTED_SIGNER_SEED: &[u8] = b"attested_signer_v2";
/// Serialized size of `AttestedSignerAccount`.
pub const ATTESTED_SIGNER_ACCOUNT_SIZE: usize = 154;
/// Mode B allocates a nonce PDA unless the caller marks the action idempotent.
pub const MODE_B_REQUIRE_NONCE_DEFAULT: bool = true;

const SIGNER_PUBKEY_OFFSET: usize = 8;
const MEASUREMENT_OFFSET: usize = 41;
const EXPIRES_SLOT_OFFSET: usize = 137;
const BUMP_OFFSET: usize = 145;

/// `verify_nitro_attestation` wire offsets in full instruction data.
/// `mode` @ 8, `nonce_slot` @ 9..17, `action_hash` @ 17..49, `doc_len` @ 49..53.
/// @spec SCC-NITRO-008
const NITRO_MODE_OFFSET: usize = 8;
const NITRO_NONCE_SLOT_OFFSET: usize = 9;
const NITRO_ACTION_HASH_OFFSET: usize = 17;
const NITRO_DOC_LEN_OFFSET: usize = 49;
const NITRO_DOCUMENT_OFFSET: usize = 53;
const SNP_HEADER_LEN: usize = 80;
/// `verify_google_jwt` wire offsets in full instruction data.
/// `mode` @ 8, `nonce_slot` @ 9..17, `action_hash` @ 17..49, `jwt_len` @ 49..53.
/// @spec SCC-VERIFY-013
const JWT_MODE_OFFSET: usize = 8;
const JWT_NONCE_SLOT_OFFSET: usize = 9;
const JWT_ACTION_HASH_OFFSET: usize = 17;
const JWT_LEN_OFFSET: usize = 49;
const JWT_OFFSET: usize = 53;
/// Compact JWS ceiling. Matches `solana_confidential_compute_crypto::jwt::MAX_JWT_LEN`.
const MAX_JWT_LEN: usize = 4096;
/// Maximum nesting depth allowed when skipping arbitrary CBOR values.
const MAX_CBOR_SKIP_DEPTH: u8 = 8;
/// CBOR tag for COSE_Sign1 (RFC 9052).
const COSE_SIGN1_TAG: u64 = 18;

/// Attestation wire tags. NVIDIA is reserved and rejected, like mock/unknown tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttestationPlatform {
    AmdSevSnp = 1,
    AwsNitro = 2,
    GcpConfidentialSpace = 3,
    /// Reserved: legacy NVIDIA records contain no authenticated evidence.
    NvidiaH100 = 4,
    /// Intel TDX, written by `verify_tdx_quote`.
    IntelTdx = 5,
}

impl AttestationPlatform {
    /// Tags a consumer may gate on.
    ///
    /// `NvidiaH100` (4) is deliberately absent: the records carrying that tag
    /// hold no authenticated evidence, so accepting one would mean accepting
    /// an assertion. Leaving a gap in the middle of the range is why this is a
    /// list rather than `1..=5`.
    const ACCEPTED: [u8; 4] =
        [Self::AmdSevSnp as u8, Self::AwsNitro as u8, Self::GcpConfidentialSpace as u8, Self::IntelTdx as u8];

    fn check(self, actual: u8) -> Result<(), ProgramError> {
        if !Self::ACCEPTED.contains(&actual) {
            return Err(CpiError::UnsupportedPlatform.into());
        }
        if actual != self as u8 {
            return Err(CpiError::PlatformMismatch.into());
        }
        Ok(())
    }
}

/// Consumer-side Mode B expectation.
///
/// @spec SCC-VERIFY-013
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicAttestationExpectation {
    pub expected_platform: AttestationPlatform,
    pub action_hash: [u8; 32],
    pub expected_measurement: [u8; 48],
    /// Require an attested workload key (SNP/Nitro only). Google Mode B has no
    /// workload key and rejects every `Some`, including its image digest.
    pub expected_signer: Option<[u8; 32]>,
    /// Must be `true`. `false` is rejected so Mode B is replay-protected.
    /// @spec SCC-SEC-005
    pub require_nonce: bool,
    /// Index of the Solana Confidential Compute instruction. `None` selects the preceding instruction.
    /// An explicit index is accepted only when it equals `current_index - 1`.
    pub verifier_ix_index: Option<u16>,
}

impl Default for AtomicAttestationExpectation {
    fn default() -> Self {
        Self {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash: [0u8; 32],
            expected_measurement: [0u8; 48],
            expected_signer: None,
            require_nonce: MODE_B_REQUIRE_NONCE_DEFAULT,
            verifier_ix_index: None,
        }
    }
}

/// The identity material actually carried by an attestation.
/// A workload key is a key assertion, not proof of a unique physical replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationIdentity {
    WorkloadKey([u8; 32]),
    /// Shared by all deployments of this image; never a signing key.
    ImageDigest([u8; 32]),
}

/// Claims extracted from a verified Mode B Solana Confidential Compute instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationClaims {
    pub platform: AttestationPlatform,
    pub identity: AttestationIdentity,
    pub measurement: [u8; 48],
    pub nonce_slot: u64,
}

/// Canonical full-wire V3 action commitment. No legacy digest fallback.
pub use solana_confidential_compute_core::action::ACTION_COMMITMENT_DOMAIN;

/// Hash ordered effective account privileges, discriminator and payload.
/// AccountMeta flags here MUST come from the compiled message or AccountInfo,
/// never from an isolated instruction's declared metas. Includes duplicate keys.
/// No legacy digest fallback is supported.
pub fn hash_action(
    discriminator: &[u8],
    accounts: &[solana_program::instruction::AccountMeta],
    data: &[u8],
) -> [u8; 32] {
    hash_action_parts(
        discriminator,
        accounts.len(),
        accounts.iter().map(|a| (&a.pubkey, a.is_signer, a.is_writable)),
        data,
    )
}

/// On-chain counterpart: bind the privileges actually received by the consumer.
/// Call at the attested top-level consumer, before CPIs; inner CPI privileges
/// can be reduced or extended by invoke_signed and describe a different action.
pub fn hash_action_account_infos(discriminator: &[u8], accounts: &[AccountInfo], data: &[u8]) -> [u8; 32] {
    hash_action_parts(discriminator, accounts.len(), accounts.iter().map(|a| (a.key, a.is_signer, a.is_writable)), data)
}

use solana_confidential_compute_core::action::hash_action_parts;

/// Introspect a prior Solana Confidential Compute Mode B instruction in this transaction.
///
/// This check is permitted only in the top-level consumer instruction. CPI
/// frames (including self-CPI) are rejected for every platform. Validate once
/// before executing the committed operation; this read-only helper does not
/// count business operations or repeated calls within the same handler.
///
/// Call this before any inner `invoke`. The Instructions sysvar lists only
/// top-level instructions, so a Solana Confidential Compute CPI made after this program has already
/// called out is not visible here.
///
/// Loads the current instruction index from the Instructions sysvar.
/// `expectation.verifier_ix_index = None` selects the preceding instruction.
/// An explicit index must equal `current_index - 1`. A later consumer cannot
/// reuse an earlier attestation instruction in the same transaction.
/// Supports AMD SEV-SNP (`verify_atomic_with_nonce`), AWS Nitro Mode B
/// (`verify_nitro_attestation` with `mode == 1`), Google JWT Mode B
/// (`verify_google_jwt` with `mode == 1`). NVIDIA packets fail closed.
/// The attested instruction's program id is pinned to [`ID`].
///
/// @spec SCC-VERIFY-013 SCC-NITRO-008 SCC-NVIDIA-005 SCC-SEC-005 SCC-ARCH-002
pub fn assert_attestation_atomic(
    instructions_sysvar: &AccountInfo,
    expectation: &AtomicAttestationExpectation,
    current_program_id: &Pubkey,
) -> Result<AttestationClaims, ProgramError> {
    if get_stack_height() != TRANSACTION_LEVEL_STACK_HEIGHT {
        return Err(CpiError::InvalidConsumerStackHeight.into());
    }
    if instructions_sysvar.key != &instructions::ID {
        return Err(ProgramError::InvalidArgument);
    }
    let current_index =
        load_current_index_checked(instructions_sysvar).map_err(|_| CpiError::MalformedInstructionsSysvar)?;
    let verifier_ix_index = current_index.checked_sub(1).ok_or(CpiError::InvalidAttestationIndex)?;
    let requested = expectation.verifier_ix_index.unwrap_or(verifier_ix_index);
    if requested != verifier_ix_index {
        return Err(CpiError::InvalidAttestationIndex.into());
    }
    let verifier_ix = load_instruction_at_checked(verifier_ix_index as usize, instructions_sysvar)
        .map_err(|_| CpiError::MalformedInstructionsSysvar)?;
    if verifier_ix.program_id != ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !expectation.require_nonce {
        return Err(CpiError::NonceRequired.into());
    }
    if verifier_ix.data.starts_with(&VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR) {
        expectation.expected_platform.check(AttestationPlatform::AmdSevSnp as u8)?;
        return assert_snp_mode_b(&verifier_ix.data, expectation, current_program_id);
    }
    if verifier_ix.data.starts_with(&VERIFY_NITRO_ATTESTATION_DISCRIMINATOR) {
        expectation.expected_platform.check(AttestationPlatform::AwsNitro as u8)?;
        return assert_nitro_mode_b(
            instructions_sysvar,
            &verifier_ix.data,
            verifier_ix_index,
            current_index,
            expectation,
            current_program_id,
        );
    }
    if verifier_ix.data.starts_with(&VERIFY_GOOGLE_JWT_DISCRIMINATOR) {
        expectation.expected_platform.check(AttestationPlatform::GcpConfidentialSpace as u8)?;
        return assert_google_jwt_mode_b(
            instructions_sysvar,
            &verifier_ix.data,
            verifier_ix_index,
            current_index,
            expectation,
            current_program_id,
        );
    }
    if verifier_ix.data.starts_with(&VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR) {
        // The legacy packet authenticates no NVIDIA evidence. Reject even when
        // action, measurement and consumer match; introspection cannot supply it.
        return Err(CpiError::UnsupportedPlatform.into());
    }
    Err(CpiError::UnsupportedAttestationInstruction.into())
}

/// AMD SEV-SNP Mode B: header at 0..80, report at 80..1264.
/// @spec SCC-VERIFY-013 SCC-ARCH-002
fn assert_snp_mode_b(
    data: &[u8],
    expectation: &AtomicAttestationExpectation,
    current_program_id: &Pubkey,
) -> Result<AttestationClaims, ProgramError> {
    if data.len() < SNP_HEADER_LEN + SNP_REPORT_SIZE {
        return Err(ProgramError::from(CpiError::MalformedAttestationEnvelope));
    }
    if data[0x30..0x50] != current_program_id.to_bytes() {
        return Err(CpiError::ConsumerProgramMismatch.into());
    }
    if data[0x10..0x30] != expectation.action_hash {
        return Err(CpiError::ActionHashMismatch.into());
    }
    let view = SnpReportView::try_from_slice(&data[SNP_HEADER_LEN..SNP_HEADER_LEN + SNP_REPORT_SIZE])
        .map_err(|_| ProgramError::from(CpiError::MalformedSnpReport))?;
    if view.measurement() != expectation.expected_measurement {
        return Err(CpiError::DisallowedMeasurement.into());
    }
    if let Some(expected) = expectation.expected_signer {
        if view.pubkey() != expected {
            return Err(CpiError::SignerMismatch.into());
        }
    }
    let mut nonce_slot = [0u8; 8];
    nonce_slot.copy_from_slice(&data[8..16]);
    Ok(AttestationClaims {
        platform: AttestationPlatform::AmdSevSnp,
        identity: AttestationIdentity::WorkloadKey(view.pubkey()),
        measurement: view.measurement(),
        nonce_slot: u64::from_le_bytes(nonce_slot),
    })
}

/// AWS Nitro Mode B: `mode` @ 8, `nonce_slot` @ 9..17, `action_hash` @ 17..49,
/// length-prefixed COSE Sign1 starting at offset 49.
/// Consumer program id is the instruction immediately after Solana Confidential Compute.
/// @spec SCC-NITRO-008 SCC-ARCH-002
fn assert_nitro_mode_b(
    instructions_sysvar: &AccountInfo,
    data: &[u8],
    verifier_ix_index: u16,
    current_index: u16,
    expectation: &AtomicAttestationExpectation,
    current_program_id: &Pubkey,
) -> Result<AttestationClaims, ProgramError> {
    if data.len() < NITRO_DOCUMENT_OFFSET {
        return Err(ProgramError::from(CpiError::MalformedAttestationEnvelope));
    }
    if data[NITRO_MODE_OFFSET] != VERIFY_NITRO_MODE_B {
        return Err(CpiError::WrongAttestationMode.into());
    }
    let mut doc_len_bytes = [0u8; 4];
    doc_len_bytes.copy_from_slice(&data[NITRO_DOC_LEN_OFFSET..NITRO_DOCUMENT_OFFSET]);
    let doc_len = u32::from_le_bytes(doc_len_bytes) as usize;
    let expected_len =
        NITRO_DOCUMENT_OFFSET.checked_add(doc_len).ok_or(ProgramError::from(CpiError::MalformedAttestationEnvelope))?;
    if data.len() != expected_len || doc_len == 0 || doc_len > MAX_NITRO_DOCUMENT_LEN {
        return Err(ProgramError::from(CpiError::MalformedAttestationEnvelope));
    }
    if data[NITRO_ACTION_HASH_OFFSET..NITRO_DOC_LEN_OFFSET] != expectation.action_hash {
        return Err(CpiError::ActionHashMismatch.into());
    }
    let next_index =
        verifier_ix_index.checked_add(1).ok_or(ProgramError::from(CpiError::MalformedAttestationEnvelope))?;
    if next_index != current_index {
        return Err(CpiError::InvalidAttestationIndex.into());
    }
    let next_ix = load_instruction_at_checked(next_index as usize, instructions_sysvar)
        .map_err(|_| CpiError::MalformedInstructionsSysvar)?;
    if next_ix.program_id != *current_program_id {
        return Err(CpiError::ConsumerProgramMismatch.into());
    }
    let document = &data[NITRO_DOCUMENT_OFFSET..expected_len];
    let view = parse_nitro_document_view(document).map_err(|_| CpiError::MalformedNitroDocument)?;
    if view.measurement() != expectation.expected_measurement {
        return Err(CpiError::DisallowedMeasurement.into());
    }
    if let Some(expected) = expectation.expected_signer {
        if view.pubkey() != expected {
            return Err(CpiError::SignerMismatch.into());
        }
    }
    let mut nonce_slot = [0u8; 8];
    nonce_slot.copy_from_slice(&data[NITRO_NONCE_SLOT_OFFSET..NITRO_ACTION_HASH_OFFSET]);
    Ok(AttestationClaims {
        platform: AttestationPlatform::AwsNitro,
        identity: AttestationIdentity::WorkloadKey(view.pubkey()),
        measurement: view.measurement(),
        nonce_slot: u64::from_le_bytes(nonce_slot),
    })
}

/// Google JWT Mode B. The consumer is the instruction at `current_index`.
/// Measurement is the 32-byte `image_digest` padded with 16 zero bytes, matching
/// `process_verify_google_jwt`. The identity is an image digest, not a workload key.
/// @spec SCC-VERIFY-013 SCC-ARCH-002
fn assert_google_jwt_mode_b(
    instructions_sysvar: &AccountInfo,
    data: &[u8],
    verifier_ix_index: u16,
    current_index: u16,
    expectation: &AtomicAttestationExpectation,
    current_program_id: &Pubkey,
) -> Result<AttestationClaims, ProgramError> {
    if data.len() < JWT_OFFSET {
        return Err(ProgramError::from(CpiError::MalformedAttestationEnvelope));
    }
    if data[JWT_MODE_OFFSET] != VERIFY_GOOGLE_JWT_MODE_B {
        return Err(CpiError::WrongAttestationMode.into());
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&data[JWT_LEN_OFFSET..JWT_OFFSET]);
    let jwt_len = u32::from_le_bytes(len_bytes) as usize;
    let expected_len =
        JWT_OFFSET.checked_add(jwt_len).ok_or(ProgramError::from(CpiError::MalformedAttestationEnvelope))?;
    if data.len() != expected_len || jwt_len == 0 || jwt_len > MAX_JWT_LEN {
        return Err(ProgramError::from(CpiError::MalformedAttestationEnvelope));
    }
    if data[JWT_ACTION_HASH_OFFSET..JWT_LEN_OFFSET] != expectation.action_hash {
        return Err(CpiError::ActionHashMismatch.into());
    }
    let next_index =
        verifier_ix_index.checked_add(1).ok_or(ProgramError::from(CpiError::MalformedAttestationEnvelope))?;
    if next_index != current_index {
        return Err(CpiError::InvalidAttestationIndex.into());
    }
    let next_ix = load_instruction_at_checked(next_index as usize, instructions_sysvar)
        .map_err(|_| CpiError::MalformedInstructionsSysvar)?;
    if next_ix.program_id != *current_program_id {
        return Err(CpiError::ConsumerProgramMismatch.into());
    }
    let jwt = core::str::from_utf8(&data[JWT_OFFSET..expected_len])
        .map_err(|_| ProgramError::from(CpiError::MalformedGoogleJwt))?;
    let view = solana_confidential_compute_crypto::JwtView::parse(jwt)
        .map_err(|_| ProgramError::from(CpiError::MalformedGoogleJwt))?;
    let claims = solana_confidential_compute_crypto::jwt::parse_google_claims_b64(view.payload_b64)
        .map_err(|_| ProgramError::from(CpiError::MalformedGoogleJwt))?;
    let mut measurement = [0u8; 48];
    measurement[..32].copy_from_slice(&claims.image_digest);
    if measurement != expectation.expected_measurement {
        return Err(CpiError::DisallowedMeasurement.into());
    }
    if expectation.expected_signer.is_some() {
        return Err(CpiError::SignerIdentityUnavailable.into());
    }
    let mut nonce_slot = [0u8; 8];
    nonce_slot.copy_from_slice(&data[JWT_NONCE_SLOT_OFFSET..JWT_ACTION_HASH_OFFSET]);
    Ok(AttestationClaims {
        platform: AttestationPlatform::GcpConfidentialSpace,
        identity: AttestationIdentity::ImageDigest(claims.image_digest),
        measurement,
        nonce_slot: u64::from_le_bytes(nonce_slot),
    })
}

/// Zero-copy COSE Sign1 view over a Nitro document: `user_data` and PCR0 only.
/// @spec SCC-NITRO-008 SCC-ARCH-002
struct NitroDocumentView {
    user_data: [u8; NITRO_USER_DATA_LEN],
    pcr0: [u8; NITRO_PCR_LEN],
}

impl NitroDocumentView {
    #[inline]
    fn pubkey(&self) -> [u8; NITRO_USER_DATA_LEN] {
        self.user_data
    }

    #[inline]
    fn measurement(&self) -> [u8; NITRO_PCR_LEN] {
        self.pcr0
    }
}

fn parse_nitro_document_view(document: &[u8]) -> Result<NitroDocumentView, ProgramError> {
    let mut cur = CborCursor::new(document);
    if cur.peek_major()? == 6 {
        let tag = cur.read_tag()?;
        if tag != COSE_SIGN1_TAG {
            return Err(ProgramError::InvalidInstructionData);
        }
    }
    let n = cur.read_array_len()?;
    if n != 4 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let _protected = cur.read_bstr()?;
    let unprot_len = cur.read_map_len()?;
    for _ in 0..unprot_len {
        skip_cbor_value(&mut cur)?;
        skip_cbor_value(&mut cur)?;
    }
    let payload = cur.read_bstr()?;
    let _signature = cur.read_bstr()?;
    if !cur.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    parse_nitro_payload(payload)
}

/// Reads `user_data` and PCR0 from a definite map or an indefinite map (`0xbf` … `0xff`).
///
/// @spec SCC-NITRO-001 SCC-NITRO-003 SCC-ARCH-002
fn parse_nitro_payload(payload: &[u8]) -> Result<NitroDocumentView, ProgramError> {
    let mut cur = CborCursor::new(payload);
    let (major, additional) = cur.read_initial()?;
    if major != 5 {
        return Err(ProgramError::InvalidInstructionData);
    }
    // `None` is an indefinite map. `Some(n)` is the remaining pair count.
    let mut remaining: Option<usize> =
        if additional == 31 { None } else { Some(arg_to_len(cur.read_argument(additional)?)?) };
    let mut user_data: Option<[u8; NITRO_USER_DATA_LEN]> = None;
    let mut pcr0: Option<[u8; NITRO_PCR_LEN]> = None;
    loop {
        match remaining {
            Some(0) => break,
            Some(left) => remaining = Some(left.checked_sub(1).ok_or(ProgramError::InvalidInstructionData)?),
            None if cur.is_break() => {
                cur.read_break()?;
                break;
            }
            None => {}
        }
        let key = cur.read_tstr()?;
        match key {
            "user_data" => {
                if user_data.is_some() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let raw = cur.read_bstr()?;
                if raw.len() != NITRO_USER_DATA_LEN {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let mut pk = [0u8; NITRO_USER_DATA_LEN];
                pk.copy_from_slice(raw);
                user_data = Some(pk);
            }
            "pcrs" => {
                if pcr0.is_some() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                pcr0 = Some(parse_pcr0(&mut cur)?);
            }
            _ => skip_cbor_value(&mut cur)?,
        }
    }
    if !cur.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(NitroDocumentView {
        user_data: user_data.ok_or(ProgramError::InvalidInstructionData)?,
        pcr0: pcr0.ok_or(ProgramError::InvalidInstructionData)?,
    })
}

fn parse_pcr0(cur: &mut CborCursor<'_>) -> Result<[u8; NITRO_PCR_LEN], ProgramError> {
    let n = cur.read_map_len()?;
    let mut pcr0 = None;
    for _ in 0..n {
        let idx = cur.read_unsigned()?;
        let val = cur.read_bstr()?;
        if idx == 0 {
            if val.len() != NITRO_PCR_LEN || pcr0.is_some() {
                return Err(ProgramError::InvalidInstructionData);
            }
            let mut digest = [0u8; NITRO_PCR_LEN];
            digest.copy_from_slice(val);
            pcr0 = Some(digest);
        }
    }
    pcr0.ok_or(ProgramError::InvalidInstructionData)
}

/// Streaming, allocation-free cursor over a CBOR buffer.
/// @spec SCC-ARCH-002
struct CborCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CborCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// True when the next byte is the CBOR break stop (`0xff`).
    fn is_break(&self) -> bool {
        self.buf.get(self.pos).copied() == Some(0xff)
    }

    /// Consumes one CBOR break stop (`0xff`).
    fn read_break(&mut self) -> Result<(), ProgramError> {
        if self.is_break() {
            self.skip(1)
        } else {
            Err(ProgramError::InvalidInstructionData)
        }
    }

    fn peek_major(&self) -> Result<u8, ProgramError> {
        let b = self.buf.get(self.pos).ok_or(ProgramError::InvalidInstructionData)?;
        Ok(b >> 5)
    }

    fn read_tag(&mut self) -> Result<u64, ProgramError> {
        let (major, additional) = self.read_initial()?;
        if major != 6 {
            return Err(ProgramError::InvalidInstructionData);
        }
        self.read_argument(additional)
    }

    fn read_unsigned(&mut self) -> Result<u64, ProgramError> {
        let (major, additional) = self.read_initial()?;
        if major != 0 {
            return Err(ProgramError::InvalidInstructionData);
        }
        self.read_argument(additional)
    }

    fn read_bstr(&mut self) -> Result<&'a [u8], ProgramError> {
        let (major, additional) = self.read_initial()?;
        if major != 2 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let len = arg_to_len(self.read_argument(additional)?)?;
        self.read_exact(len)
    }

    fn read_tstr(&mut self) -> Result<&'a str, ProgramError> {
        let (major, additional) = self.read_initial()?;
        if major != 3 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let len = arg_to_len(self.read_argument(additional)?)?;
        let bytes = self.read_exact(len)?;
        core::str::from_utf8(bytes).map_err(|_| ProgramError::InvalidInstructionData)
    }

    fn read_array_len(&mut self) -> Result<usize, ProgramError> {
        let (major, additional) = self.read_initial()?;
        if major != 4 {
            return Err(ProgramError::InvalidInstructionData);
        }
        arg_to_len(self.read_argument(additional)?)
    }

    fn read_map_len(&mut self) -> Result<usize, ProgramError> {
        let (major, additional) = self.read_initial()?;
        if major != 5 {
            return Err(ProgramError::InvalidInstructionData);
        }
        arg_to_len(self.read_argument(additional)?)
    }

    fn skip(&mut self, len: usize) -> Result<(), ProgramError> {
        let _ = self.read_exact(len)?;
        Ok(())
    }

    fn read_initial(&mut self) -> Result<(u8, u8), ProgramError> {
        let &[b] = self.read_exact(1)? else {
            return Err(ProgramError::InvalidInstructionData);
        };
        Ok((b >> 5, b & 0x1f))
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, ProgramError> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => {
                let b = self.read_exact(1)?;
                Ok(b[0] as u64)
            }
            25 => {
                let b = self.read_exact(2)?;
                Ok(u16::from_be_bytes([b[0], b[1]]) as u64)
            }
            26 => {
                let b = self.read_exact(4)?;
                Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64)
            }
            27 => {
                let b = self.read_exact(8)?;
                Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            }
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], ProgramError> {
        let end = self.pos.checked_add(len).ok_or(ProgramError::InvalidInstructionData)?;
        if end > self.buf.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
}

fn arg_to_len(arg: u64) -> Result<usize, ProgramError> {
    usize::try_from(arg).map_err(|_| ProgramError::InvalidInstructionData)
}

/// Skips one well-formed CBOR value, including indefinite maps and arrays.
///
/// @spec SCC-NITRO-001 SCC-NITRO-003 SCC-ARCH-002
fn skip_cbor_value(cur: &mut CborCursor<'_>) -> Result<(), ProgramError> {
    skip_cbor_value_depth(cur, MAX_CBOR_SKIP_DEPTH)
}

fn skip_cbor_value_depth(cur: &mut CborCursor<'_>, remaining_depth: u8) -> Result<(), ProgramError> {
    if remaining_depth == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (major, additional) = cur.read_initial()?;
    // Additional info 31 is indefinite length on arrays (`0x9f`) and maps (`0xbf`),
    // and the break stop on major type 7 (`0xff`).
    if additional == 31 {
        let child_depth = remaining_depth.saturating_sub(1);
        return match major {
            4 => {
                while !cur.is_break() {
                    skip_cbor_value_depth(cur, child_depth)?;
                }
                cur.read_break()
            }
            5 => loop {
                if cur.is_break() {
                    return cur.read_break();
                }
                skip_cbor_value_depth(cur, child_depth)?;
                // A break on a value boundary is malformed. Leave that byte unread.
                if cur.is_break() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                skip_cbor_value_depth(cur, child_depth)?;
            },
            _ => Err(ProgramError::InvalidInstructionData),
        };
    }
    // Simple values 0..=23 are carried in the initial byte (`false` 0xf4, `true` 0xf5, `null` 0xf6).
    if major == 7 {
        if additional <= 23 {
            return Ok(());
        }
        return Err(ProgramError::InvalidInstructionData);
    }
    let arg = cur.read_argument(additional)?;
    match major {
        0 | 1 => Ok(()),
        2 | 3 => cur.skip(arg_to_len(arg)?),
        4 => {
            let n = arg_to_len(arg)?;
            for _ in 0..n {
                skip_cbor_value_depth(cur, remaining_depth.saturating_sub(1))?;
            }
            Ok(())
        }
        5 => {
            let n = arg_to_len(arg)?;
            for _ in 0..n.saturating_mul(2) {
                skip_cbor_value_depth(cur, remaining_depth.saturating_sub(1))?;
            }
            Ok(())
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Validates a Mode A `AttestedSignerAccount` PDA for a stateful consumer.
///
/// Requires `workload_signer` to be a signer on the transaction, and verifies
/// that `attested_record` is the valid PDA owned by [`ID`] (`solana_confidential_compute_cpi::ID`).
/// Callers cannot pass a substitute verifier program id.
/// Loads the current slot from `Clock::get()`; callers cannot supply a timestamp.
///
/// Returns `expires_slot` when every check passes.
///
/// @spec SCC-VERIFY-015 SCC-SEC-002 SCC-SEC-004
pub fn assert_attestation_signer(
    attested_record: &AccountInfo,
    workload_signer: &AccountInfo,
    expected_measurement: &[u8; 48],
    expected_platform: AttestationPlatform,
) -> Result<u64, ProgramError> {
    let clock = Clock::get()?;
    assert_attestation_signer_inner(
        attested_record,
        workload_signer,
        clock.slot,
        expected_measurement,
        expected_platform,
        clock.unix_timestamp,
    )
}

/// Test helper that injects both slot and Unix timestamp from a simulated Clock.
///
/// @spec SCC-SEC-004
#[cfg(any(test, feature = "test-bpf"))]
pub fn assert_attestation_signer_at_slot(
    attested_record: &AccountInfo,
    workload_signer: &AccountInfo,
    clock_slot: u64,
    expected_measurement: &[u8; 48],
    expected_platform: AttestationPlatform,
    clock_unix_timestamp: i64,
) -> Result<u64, ProgramError> {
    assert_attestation_signer_inner(
        attested_record,
        workload_signer,
        clock_slot,
        expected_measurement,
        expected_platform,
        clock_unix_timestamp,
    )
}

fn assert_attestation_signer_inner(
    attested_record: &AccountInfo,
    workload_signer: &AccountInfo,
    clock_slot: u64,
    expected_measurement: &[u8; 48],
    expected_platform: AttestationPlatform,
    clock_unix_timestamp: i64,
) -> Result<u64, ProgramError> {
    if !workload_signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if attested_record.owner != &ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    let data = attested_record.try_borrow_data()?;
    if data.len() < ATTESTED_SIGNER_ACCOUNT_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }
    if data[0..8] != ATTESTED_SIGNER_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    expected_platform.check(data[40])?;
    let mut stored_signer = [0u8; 32];
    stored_signer.copy_from_slice(&data[SIGNER_PUBKEY_OFFSET..SIGNER_PUBKEY_OFFSET + 32]);
    if stored_signer != workload_signer.key.to_bytes() {
        return Err(CpiError::SignerMismatch.into());
    }
    let bump = data[BUMP_OFFSET];
    let expected_key =
        Pubkey::create_program_address(&[ATTESTED_SIGNER_SEED, workload_signer.key.as_ref(), &[bump]], &ID)
            .map_err(|_| ProgramError::InvalidSeeds)?;
    if attested_record.key != &expected_key {
        return Err(ProgramError::InvalidSeeds);
    }
    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(&data[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + 48]);
    if measurement != *expected_measurement {
        return Err(CpiError::DisallowedMeasurement.into());
    }
    let mut expires_bytes = [0u8; 8];
    expires_bytes.copy_from_slice(&data[EXPIRES_SLOT_OFFSET..EXPIRES_SLOT_OFFSET + 8]);
    let expires_slot = u64::from_le_bytes(expires_bytes);
    let expires_unix = i64::from_le_bytes(data[146..154].try_into().map_err(|_| ProgramError::InvalidAccountData)?);
    if clock_unix_timestamp < 0 || clock_unix_timestamp >= expires_unix {
        return Err(CpiError::AttestationExpired.into());
    }
    if expires_slot == 0 || clock_slot > expires_slot {
        return Err(CpiError::AttestationExpired.into());
    }
    Ok(expires_slot)
}

#[cfg(test)]
// Test-only fixture builders. SDLC 3.2.1 covers program code, not tests.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn serialize_instructions(ixs: &[(Pubkey, &[u8])], current_index: u16) -> Vec<u8> {
        // Native unit fixtures model a direct top-level consumer. ProgramTest
        // regressions separately exercise actual nested runtime call frames.
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            struct TopLevel;
            impl solana_program::program_stubs::SyscallStubs for TopLevel {
                fn sol_get_stack_height(&self) -> u64 {
                    1
                }
            }
            solana_program::program_stubs::set_syscall_stubs(Box::new(TopLevel));
        });
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

    fn atomic_ix_data(
        require_nonce: bool,
        nonce_slot: u64,
        action_hash: [u8; 32],
        consumer: &Pubkey,
        measurement: [u8; 48],
        signer: [u8; 32],
    ) -> Vec<u8> {
        let disc = if require_nonce { VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR } else { VERIFY_ATOMIC_DISCRIMINATOR };
        let mut data = Vec::with_capacity(80 + SNP_REPORT_SIZE);
        data.extend_from_slice(&disc);
        data.extend_from_slice(&nonce_slot.to_le_bytes());
        data.extend_from_slice(&action_hash);
        data.extend_from_slice(consumer.as_ref());
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[0x50..0x70].copy_from_slice(&signer);
        report[0x90..0xC0].copy_from_slice(&measurement);
        data.extend_from_slice(&report);
        data
    }

    fn cbor_header(major: u8, len: usize) -> Vec<u8> {
        if len <= 23 {
            vec![(major << 5) | (len as u8)]
        } else if len <= 0xff {
            vec![(major << 5) | 24, len as u8]
        } else {
            let b = (len as u16).to_be_bytes();
            vec![(major << 5) | 25, b[0], b[1]]
        }
    }

    fn cbor_bstr(bytes: &[u8]) -> Vec<u8> {
        let mut out = cbor_header(2, bytes.len());
        out.extend_from_slice(bytes);
        out
    }

    fn cbor_tstr(s: &str) -> Vec<u8> {
        let mut out = cbor_header(3, s.len());
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn cbor_uint(n: u64) -> Vec<u8> {
        if n <= 23 {
            vec![n as u8]
        } else {
            vec![0x18, n as u8]
        }
    }

    fn cbor_array(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = cbor_header(4, items.len());
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    fn cbor_map_text(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = cbor_header(5, pairs.len());
        for (k, v) in pairs {
            out.extend_from_slice(&cbor_tstr(k));
            out.extend_from_slice(v);
        }
        out
    }

    fn cbor_map_int(pairs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = cbor_header(5, pairs.len());
        for (k, v) in pairs {
            out.extend_from_slice(&cbor_uint(*k));
            out.extend_from_slice(v);
        }
        out
    }

    fn encode_nitro_document(signer: [u8; 32], measurement: [u8; 48]) -> Vec<u8> {
        let pcrs = cbor_map_int(&[
            (0, cbor_bstr(&measurement)),
            (1, cbor_bstr(&[1u8; 48])),
            (2, cbor_bstr(&[2u8; 48])),
            (8, cbor_bstr(&[8u8; 48])),
        ]);
        let payload = cbor_map_text(&[
            ("module_id", cbor_tstr("i-teton-nitro-0")),
            ("digest", cbor_tstr("SHA384")),
            ("pcrs", pcrs),
            ("user_data", cbor_bstr(&signer)),
            ("nonce", cbor_bstr(&[0x22u8; 32])),
        ]);
        let protected = vec![0xa1, 0x01, 0x38, 0x22];
        let sig = [0u8; 96];
        let mut doc = vec![0xd2];
        doc.extend_from_slice(&cbor_array(&[cbor_bstr(&protected), vec![0xa0], cbor_bstr(&payload), cbor_bstr(&sig)]));
        doc
    }

    /// The definite-map countdown and the break read now use checked
    /// arithmetic. The pair count still bounds the walk, and a truncated
    /// map still fails closed.
    #[test]
    fn nitro_payload_map_count_bounds_the_walk() {
        let pcrs = cbor_map_int(&[(0, cbor_bstr(&[7u8; 48]))]);
        let pairs = [("user_data", cbor_bstr(&[9u8; 32])), ("pcrs", pcrs)];
        let payload = cbor_map_text(&pairs);
        assert_eq!(payload[0], 0xa2);
        let view = parse_nitro_payload(&payload).unwrap();
        assert_eq!(view.user_data, [9u8; 32]);
        assert_eq!(view.pcr0, [7u8; 48]);

        let mut too_many = payload.clone();
        too_many[0] = 0xa3;
        assert_eq!(parse_nitro_payload(&too_many).err(), Some(ProgramError::InvalidInstructionData));
        let mut too_few = payload.clone();
        too_few[0] = 0xa1;
        assert_eq!(parse_nitro_payload(&too_few).err(), Some(ProgramError::InvalidInstructionData));

        let mut indefinite = payload.clone();
        indefinite[0] = 0xbf;
        assert_eq!(parse_nitro_payload(&indefinite).err(), Some(ProgramError::InvalidInstructionData));
        indefinite.push(0xff);
        assert!(parse_nitro_payload(&indefinite).is_ok());
        assert_eq!(parse_nitro_payload(&[]).err(), Some(ProgramError::InvalidInstructionData));
    }

    /// Indefinite payload map with `public_key: null` (`0xf6`), matching the hardware shape.
    fn encode_indefinite_nitro_document(signer: [u8; 32], measurement: [u8; 48]) -> Vec<u8> {
        let pcrs = cbor_map_int(&[
            (0, cbor_bstr(&measurement)),
            (1, cbor_bstr(&[1u8; 48])),
            (2, cbor_bstr(&[2u8; 48])),
            (8, cbor_bstr(&[8u8; 48])),
        ]);
        let mut payload = vec![0xbf];
        payload.extend(cbor_tstr("module_id"));
        payload.extend(cbor_tstr("i-teton-nitro-0"));
        payload.extend(cbor_tstr("public_key"));
        payload.push(0xf6);
        payload.extend(cbor_tstr("pcrs"));
        payload.extend(pcrs);
        payload.extend(cbor_tstr("user_data"));
        payload.extend(cbor_bstr(&signer));
        payload.extend(cbor_tstr("nonce"));
        payload.extend(cbor_bstr(&[0x77u8; 32]));
        payload.push(0xff);
        let protected = vec![0xa1, 0x01, 0x38, 0x22];
        let sig = [0u8; 96];
        cbor_array(&[cbor_bstr(&protected), vec![0xa0], cbor_bstr(&payload), cbor_bstr(&sig)])
    }

    fn nitro_ix_data(mode: u8, nonce_slot: u64, action_hash: [u8; 32], document: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&VERIFY_NITRO_ATTESTATION_DISCRIMINATOR);
        data.push(mode);
        data.extend_from_slice(&nonce_slot.to_le_bytes());
        data.extend_from_slice(&action_hash);
        data.extend_from_slice(&(document.len() as u32).to_le_bytes());
        data.extend_from_slice(document);
        data
    }

    fn sysvar_account<'a>(
        key: &'a Pubkey,
        owner: &'a Pubkey,
        lamports: &'a mut u64,
        data: &'a mut [u8],
    ) -> AccountInfo<'a> {
        AccountInfo::new(key, false, false, lamports, data, owner, false)
    }

    fn attested_signer_bytes(
        signer: &[u8; 32],
        measurement: &[u8; 48],
        expires_slot: u64,
        bump: u8,
    ) -> [u8; ATTESTED_SIGNER_ACCOUNT_SIZE] {
        let mut data = [0u8; ATTESTED_SIGNER_ACCOUNT_SIZE];
        data[146..154].copy_from_slice(&1000i64.to_le_bytes());
        data[0..8].copy_from_slice(&ATTESTED_SIGNER_DISCRIMINATOR);
        data[SIGNER_PUBKEY_OFFSET..SIGNER_PUBKEY_OFFSET + 32].copy_from_slice(signer);
        data[40] = 1;
        data[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + 48].copy_from_slice(measurement);
        data[EXPIRES_SLOT_OFFSET..EXPIRES_SLOT_OFFSET + 8].copy_from_slice(&expires_slot.to_le_bytes());
        data[BUMP_OFFSET] = bump;
        data
    }

    #[test]
    fn test_hash_action_binds_accounts_and_args() {
        let vault = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let disc = [7u8; 8];
        let amount = 100u64.to_le_bytes();
        let hash = hash_action(
            &disc,
            &[
                solana_program::instruction::AccountMeta::new_readonly(vault, false),
                solana_program::instruction::AccountMeta::new_readonly(recipient, false),
            ],
            &amount,
        );
        assert_eq!(
            hash,
            hash_action(
                &disc,
                &[
                    solana_program::instruction::AccountMeta::new_readonly(vault, false),
                    solana_program::instruction::AccountMeta::new_readonly(recipient, false)
                ],
                &amount
            )
        );
        assert_ne!(
            hash,
            hash_action(
                &disc,
                &[
                    solana_program::instruction::AccountMeta::new_readonly(recipient, false),
                    solana_program::instruction::AccountMeta::new_readonly(vault, false)
                ],
                &amount
            )
        );
        assert_ne!(
            hash,
            hash_action(
                &disc,
                &[
                    solana_program::instruction::AccountMeta::new_readonly(vault, false),
                    solana_program::instruction::AccountMeta::new_readonly(recipient, false)
                ],
                &200u64.to_le_bytes()
            )
        );
        assert_ne!(
            hash,
            hash_action(
                &[8u8; 8],
                &[
                    solana_program::instruction::AccountMeta::new_readonly(vault, false),
                    solana_program::instruction::AccountMeta::new_readonly(recipient, false)
                ],
                &amount
            )
        );
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_action_canonicalizes_identical_wire_splits() {
        let disc_a = [1u8, 2, 3];
        let disc_b = [1u8, 2];
        let pubkey = Pubkey::new_unique();
        let data_a = [4u8, 5];
        let data_b = [3u8, 4, 5];
        let hash_a =
            hash_action(&disc_a, &[solana_program::instruction::AccountMeta::new_readonly(pubkey, false)], &data_a);
        let hash_b =
            hash_action(&disc_b, &[solana_program::instruction::AccountMeta::new_readonly(pubkey, false)], &data_b);
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn test_hash_action_prevents_account_count_concatenation_collision() {
        let disc = [7u8; 8];
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        let data: &[u8] = &[9u8, 8, 7, 6];
        assert_ne!(
            hash_action(
                &disc,
                &[
                    solana_program::instruction::AccountMeta::new_readonly(a, false),
                    solana_program::instruction::AccountMeta::new_readonly(b, false)
                ],
                data
            ),
            hash_action(
                &disc,
                &[solana_program::instruction::AccountMeta::new_readonly(a, false)],
                &[b.to_bytes().as_slice(), data].concat()
            )
        );
    }

    #[test]
    fn test_mode_b_require_nonce_defaults_true() {
        const { assert!(MODE_B_REQUIRE_NONCE_DEFAULT) };
        assert!(AtomicAttestationExpectation::default().require_nonce);
        assert_eq!(AtomicAttestationExpectation::default().verifier_ix_index, None);
    }

    #[test]
    fn test_assert_atomic_accepts_preceding_instruction() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let signer = [0x33u8; 32];
        let confidential_compute_data = atomic_ix_data(true, 500, action_hash, &consumer, measurement, signer);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash,
            expected_measurement: measurement,
            expected_signer: Some(signer),
            require_nonce: true,
            verifier_ix_index: None,
        };
        let claims = assert_attestation_atomic(&acc, &expectation, &consumer).expect("preceding");
        assert_eq!(claims.identity, AttestationIdentity::WorkloadKey(signer));
        assert_eq!(claims.measurement, measurement);
        assert_eq!(claims.nonce_slot, 500);
    }

    #[test]
    fn test_assert_atomic_rejects_same_index() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let confidential_compute_data = atomic_ix_data(true, 1, [0u8; 32], &consumer, [0u8; 48], [0u8; 32]);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash: [0u8; 32],
            expected_measurement: [0u8; 48],
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: Some(1),
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            CpiError::InvalidAttestationIndex.into()
        );
    }

    #[test]
    fn test_assert_atomic_rejects_forward_index() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let confidential_compute_data = atomic_ix_data(true, 1, [0u8; 32], &consumer, [0u8; 48], [0u8; 32]);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(consumer, &dummy), (ID, &confidential_compute_data)], 0);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash: [0u8; 32],
            expected_measurement: [0u8; 48],
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: Some(1),
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            CpiError::InvalidAttestationIndex.into()
        );
    }

    #[test]
    fn test_assert_atomic_rejects_imposter_program() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let imposter = Pubkey::new_unique();
        let confidential_compute_data = atomic_ix_data(true, 1, [0u8; 32], &consumer, [0u8; 48], [0u8; 32]);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(imposter, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash: [0u8; 32],
            expected_measurement: [0u8; 48],
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::IncorrectProgramId
        );
    }

    #[test]
    fn test_assert_atomic_rejects_consumer_program_mismatch() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let confidential_compute_data = atomic_ix_data(true, 1, [0u8; 32], &consumer, [0u8; 48], [0u8; 32]);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (other, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash: [0u8; 32],
            expected_measurement: [0u8; 48],
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &other).unwrap_err(),
            ProgramError::from(CpiError::ConsumerProgramMismatch)
        );
    }

    #[test]
    fn test_assert_atomic_rejects_tampered_action_hash() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let vault = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let disc = [9u8; 8];
        let amount = 50u64.to_le_bytes();
        let action_hash = hash_action(
            &disc,
            &[
                solana_program::instruction::AccountMeta::new_readonly(vault, false),
                solana_program::instruction::AccountMeta::new_readonly(recipient, false),
            ],
            &amount,
        );
        let tampered = hash_action(
            &disc,
            &[
                solana_program::instruction::AccountMeta::new_readonly(recipient, false),
                solana_program::instruction::AccountMeta::new_readonly(vault, false),
            ],
            &amount,
        );
        let measurement = [0x44u8; 48];
        let confidential_compute_data = atomic_ix_data(true, 9, action_hash, &consumer, measurement, [0u8; 32]);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash: tampered,
            expected_measurement: measurement,
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::from(CpiError::ActionHashMismatch)
        );
    }

    #[test]
    fn test_assert_atomic_rejects_require_nonce_false() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let confidential_compute_data = atomic_ix_data(true, 1, [0u8; 32], &consumer, [0u8; 48], [0u8; 32]);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash: [0u8; 32],
            expected_measurement: [0u8; 48],
            expected_signer: None,
            require_nonce: false,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::from(CpiError::NonceRequired)
        );
    }

    #[test]
    fn test_assert_atomic_rejects_discriminator_mismatch() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let confidential_compute_data = atomic_ix_data(false, 1, [0u8; 32], &consumer, [0u8; 48], [0u8; 32]);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash: [0u8; 32],
            expected_measurement: [0u8; 48],
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            CpiError::UnsupportedAttestationInstruction.into()
        );
    }

    #[test]
    fn test_assert_atomic_rejects_measurement_mismatch() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let confidential_compute_data = atomic_ix_data(true, 7, action_hash, &consumer, measurement, [0u8; 32]);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash,
            expected_measurement: [0x99u8; 48],
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::from(CpiError::DisallowedMeasurement)
        );
    }

    #[test]
    fn test_assert_nitro_mode_b_accepts_preceding_instruction() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let signer = [0x33u8; 32];
        let document = encode_nitro_document(signer, measurement);
        let confidential_compute_data = nitro_ix_data(VERIFY_NITRO_MODE_B, 500, action_hash, &document);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AwsNitro,
            action_hash,
            expected_measurement: measurement,
            expected_signer: Some(signer),
            require_nonce: true,
            verifier_ix_index: None,
        };
        let claims = assert_attestation_atomic(&acc, &expectation, &consumer).expect("nitro mode b");
        assert_eq!(claims.identity, AttestationIdentity::WorkloadKey(signer));
        assert_eq!(claims.measurement, measurement);
        assert_eq!(claims.nonce_slot, 500);
    }

    #[test]
    fn test_assert_nitro_mode_b_rejects_action_hash_mismatch() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let signer = [0x33u8; 32];
        let document = encode_nitro_document(signer, measurement);
        let confidential_compute_data = nitro_ix_data(VERIFY_NITRO_MODE_B, 9, action_hash, &document);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AwsNitro,
            action_hash: [0xAAu8; 32],
            expected_measurement: measurement,
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::from(CpiError::ActionHashMismatch)
        );
    }

    #[test]
    fn test_assert_nitro_mode_b_rejects_measurement_mismatch() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let signer = [0x33u8; 32];
        let document = encode_nitro_document(signer, measurement);
        let confidential_compute_data = nitro_ix_data(VERIFY_NITRO_MODE_B, 9, action_hash, &document);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AwsNitro,
            action_hash,
            expected_measurement: [0x99u8; 48],
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::from(CpiError::DisallowedMeasurement)
        );
    }

    #[test]
    fn test_assert_nitro_mode_b_rejects_mode_a() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let signer = [0x33u8; 32];
        let document = encode_nitro_document(signer, measurement);
        let confidential_compute_data = nitro_ix_data(0, 9, action_hash, &document);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AwsNitro,
            action_hash,
            expected_measurement: measurement,
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            CpiError::WrongAttestationMode.into()
        );
    }

    #[test]
    fn test_assert_nitro_mode_b_rejects_consumer_mismatch() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let signer = [0x33u8; 32];
        let document = encode_nitro_document(signer, measurement);
        let confidential_compute_data = nitro_ix_data(VERIFY_NITRO_MODE_B, 9, action_hash, &document);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (other, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AwsNitro,
            action_hash,
            expected_measurement: measurement,
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::from(CpiError::ConsumerProgramMismatch)
        );
    }

    #[test]
    fn test_assert_nitro_mode_b_rejects_signer_mismatch() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let signer = [0x33u8; 32];
        let document = encode_nitro_document(signer, measurement);
        let confidential_compute_data = nitro_ix_data(VERIFY_NITRO_MODE_B, 9, action_hash, &document);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AwsNitro,
            action_hash,
            expected_measurement: measurement,
            expected_signer: Some([0x44u8; 32]),
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::from(CpiError::SignerMismatch)
        );
    }

    #[test]
    fn test_assert_nitro_mode_b_accepts_indefinite_map_and_null_public_key() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let signer = [0x55u8; 32];
        let document = encode_indefinite_nitro_document(signer, measurement);
        let confidential_compute_data = nitro_ix_data(VERIFY_NITRO_MODE_B, 42, action_hash, &document);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AwsNitro,
            action_hash,
            expected_measurement: measurement,
            expected_signer: Some(signer),
            require_nonce: true,
            verifier_ix_index: None,
        };
        let claims = assert_attestation_atomic(&acc, &expectation, &consumer).expect("indefinite nitro");
        assert_eq!(claims.identity, AttestationIdentity::WorkloadKey(signer));
        assert_eq!(claims.measurement, measurement);
        assert_eq!(claims.nonce_slot, 42);
    }

    #[test]
    fn test_assert_nitro_mode_b_accepts_hardware_document() {
        let document = include_bytes!("../../../fixtures/nitro_hardware_document.cose");
        assert_eq!(document.len(), 4526);
        let signer = [0x55u8; 32];
        let pcr0 = hex::decode(
            "2a86e61029832fc64b047e727b2f2265eb07215d073cd458bf6debf5e557a43a146916546030cf5dd8398175f8441e66",
        )
        .unwrap();
        let mut measurement = [0u8; 48];
        measurement.copy_from_slice(&pcr0);

        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let confidential_compute_data = nitro_ix_data(VERIFY_NITRO_MODE_B, 500, action_hash, document);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AwsNitro,
            action_hash,
            expected_measurement: measurement,
            expected_signer: Some(signer),
            require_nonce: true,
            verifier_ix_index: None,
        };
        let claims = assert_attestation_atomic(&acc, &expectation, &consumer).expect("hardware nitro document");
        assert_eq!(claims.identity, AttestationIdentity::WorkloadKey(signer));
        assert_eq!(claims.measurement, measurement);
        assert_eq!(claims.nonce_slot, 500);
    }

    #[test]
    fn skip_major_type_7_simple_values_and_indefinite_containers() {
        for byte in [0xf4u8, 0xf5, 0xf6, 0xf7] {
            let buf = [byte, 0x01];
            let mut cur = CborCursor::new(&buf);
            skip_cbor_value(&mut cur).unwrap();
            assert_eq!(cur.pos, 1);
            assert_eq!(cur.read_unsigned().unwrap(), 1);
        }

        // Break (`0xff`) is a delimiter, not simple value 31.
        let mut cur = CborCursor::new(&[0xff]);
        assert_eq!(skip_cbor_value(&mut cur).unwrap_err(), ProgramError::InvalidInstructionData);

        // {_ 1: 2} then sibling 3.
        let buf = [0xbf, 0x01, 0x02, 0xff, 0x03];
        let mut cur = CborCursor::new(&buf);
        skip_cbor_value(&mut cur).unwrap();
        assert_eq!(cur.pos, 4);
        assert_eq!(cur.read_unsigned().unwrap(), 3);

        // [_ 1, 2] then sibling 3.
        let buf = [0x9f, 0x01, 0x02, 0xff, 0x03];
        let mut cur = CborCursor::new(&buf);
        skip_cbor_value(&mut cur).unwrap();
        assert_eq!(cur.pos, 4);
        assert_eq!(cur.read_unsigned().unwrap(), 3);

        // {_ 1: <break>} does not consume the sibling.
        let buf = [0xbf, 0x01, 0xff, 0x18, 0x2a];
        let mut cur = CborCursor::new(&buf);
        assert_eq!(skip_cbor_value(&mut cur).unwrap_err(), ProgramError::InvalidInstructionData);
        assert_eq!(cur.pos, 2);
        assert_eq!(&cur.buf[cur.pos..], &[0xff, 0x18, 0x2a]);
    }

    #[test]
    fn test_assert_attestation_signer_accepts_valid_pda() {
        let verifier = ID;
        let signer = Pubkey::new_unique();
        let (pda, bump) = Pubkey::find_program_address(&[ATTESTED_SIGNER_SEED, signer.as_ref()], &ID);
        let measurement = [0x55u8; 48];
        let mut data = attested_signer_bytes(&signer.to_bytes(), &measurement, 200, bump);
        let mut pda_lamports = 1u64;
        let pda_acc = AccountInfo::new(&pda, false, false, &mut pda_lamports, &mut data, &verifier, false);
        let mut signer_lamports = 1u64;
        let mut signer_data = vec![];
        let default_owner = Pubkey::default();
        let signer_acc =
            AccountInfo::new(&signer, true, false, &mut signer_lamports, &mut signer_data, &default_owner, false);
        let expires = assert_attestation_signer_at_slot(
            &pda_acc,
            &signer_acc,
            150,
            &measurement,
            AttestationPlatform::AmdSevSnp,
            100,
        )
        .expect("valid attested signer");
        assert_eq!(expires, 200);
        assert_eq!(
            assert_attestation_signer_at_slot(
                &pda_acc,
                &signer_acc,
                200,
                &measurement,
                AttestationPlatform::AmdSevSnp,
                100
            )
            .expect("equal slot"),
            200
        );
    }

    #[test]
    fn test_assert_attestation_signer_rejects_failures() {
        let verifier = ID;
        let signer = Pubkey::new_unique();
        let (pda, bump) = Pubkey::find_program_address(&[ATTESTED_SIGNER_SEED, signer.as_ref()], &ID);
        let measurement = [0x55u8; 48];
        let mut data = attested_signer_bytes(&signer.to_bytes(), &measurement, 200, bump);
        let mut pda_lamports = 1u64;
        let pda_acc = AccountInfo::new(&pda, false, false, &mut pda_lamports, &mut data, &verifier, false);

        let default_owner = Pubkey::default();

        // Failure 1: workload_signer is not a signer -> MissingRequiredSignature
        let mut signer_lamports = 1u64;
        let mut signer_data = vec![];
        let signer_unsigned =
            AccountInfo::new(&signer, false, false, &mut signer_lamports, &mut signer_data, &default_owner, false);
        assert_eq!(
            assert_attestation_signer_at_slot(
                &pda_acc,
                &signer_unsigned,
                150,
                &measurement,
                AttestationPlatform::AmdSevSnp,
                100
            )
            .unwrap_err(),
            ProgramError::MissingRequiredSignature
        );

        // Standard valid signer account for following tests
        let mut valid_signer_lamports = 1u64;
        let mut valid_signer_data = vec![];
        let valid_signer_acc = AccountInfo::new(
            &signer,
            true,
            false,
            &mut valid_signer_lamports,
            &mut valid_signer_data,
            &default_owner,
            false,
        );

        // Failure 2: workload_signer pubkey does not match stored signer -> SignerMismatch
        let other_signer = Pubkey::new_unique();
        let mut other_signer_lamports = 1u64;
        let mut other_signer_data = vec![];
        let other_signer_acc = AccountInfo::new(
            &other_signer,
            true,
            false,
            &mut other_signer_lamports,
            &mut other_signer_data,
            &default_owner,
            false,
        );
        assert_eq!(
            assert_attestation_signer_at_slot(
                &pda_acc,
                &other_signer_acc,
                150,
                &measurement,
                AttestationPlatform::AmdSevSnp,
                100
            )
            .unwrap_err(),
            ProgramError::from(CpiError::SignerMismatch)
        );

        // Failure 3: pda account has wrong owner -> IncorrectProgramId
        let other_owner = Pubkey::new_unique();
        let mut owned = data;
        let mut lamports2 = 1u64;
        let acc_owner = AccountInfo::new(&pda, false, false, &mut lamports2, &mut owned, &other_owner, false);
        assert_eq!(
            assert_attestation_signer_at_slot(
                &acc_owner,
                &valid_signer_acc,
                150,
                &measurement,
                AttestationPlatform::AmdSevSnp,
                100
            )
            .unwrap_err(),
            ProgramError::IncorrectProgramId
        );

        // Failure 4: attestation expired -> AttestationExpired
        let mut expired = data;
        let mut lamports3 = 1u64;
        let acc_expired = AccountInfo::new(&pda, false, false, &mut lamports3, &mut expired, &verifier, false);
        assert_eq!(
            assert_attestation_signer_at_slot(
                &acc_expired,
                &valid_signer_acc,
                201,
                &measurement,
                AttestationPlatform::AmdSevSnp,
                100
            )
            .unwrap_err(),
            ProgramError::from(CpiError::AttestationExpired)
        );

        // Failure 5: measurement mismatch -> DisallowedMeasurement
        let mut wrong_m = data;
        let mut lamports4 = 1u64;
        let acc_m = AccountInfo::new(&pda, false, false, &mut lamports4, &mut wrong_m, &verifier, false);
        assert_eq!(
            assert_attestation_signer_at_slot(
                &acc_m,
                &valid_signer_acc,
                150,
                &[0x66u8; 48],
                AttestationPlatform::AmdSevSnp,
                100
            )
            .unwrap_err(),
            ProgramError::from(CpiError::DisallowedMeasurement)
        );

        // Failure 6: discriminator corrupted -> InvalidAccountData
        let mut bad_disc = data;
        bad_disc[0] ^= 0xff;
        let mut lamports5 = 1u64;
        let acc_disc = AccountInfo::new(&pda, false, false, &mut lamports5, &mut bad_disc, &verifier, false);
        assert_eq!(
            assert_attestation_signer_at_slot(
                &acc_disc,
                &valid_signer_acc,
                150,
                &measurement,
                AttestationPlatform::AmdSevSnp,
                100
            )
            .unwrap_err(),
            ProgramError::InvalidAccountData
        );

        // Failure 7: wrong PDA address/seeds -> InvalidSeeds
        let wrong_pda = Pubkey::new_unique();
        let mut lamports6 = 1u64;
        let acc_seeds = AccountInfo::new(&wrong_pda, false, false, &mut lamports6, &mut data, &verifier, false);
        assert_eq!(
            assert_attestation_signer_at_slot(
                &acc_seeds,
                &valid_signer_acc,
                150,
                &measurement,
                AttestationPlatform::AmdSevSnp,
                100
            )
            .unwrap_err(),
            ProgramError::InvalidSeeds
        );
    }

    #[test]
    fn test_attested_signer_account_zero_copy_validate() {
        let measurement = [0x55u8; 48];
        let signer = [0x33u8; 32];
        let data = attested_signer_bytes(&signer, &measurement, 200, 255);
        let account = AttestedSignerAccount::try_from_slice(&data).unwrap();
        assert_eq!(AttestedSignerAccount::owner(), ID);
        assert_eq!(account.as_bytes(), &data[..]);
        assert_eq!(account.signer_pubkey, signer);
        assert_eq!(account.expires_slot(), 200);
        account.validate_at_slot(&measurement, 200, AttestationPlatform::AmdSevSnp, 100).unwrap();
        assert_eq!(
            account.validate_at_slot(&measurement, 201, AttestationPlatform::AmdSevSnp, 100).unwrap_err(),
            ProgramError::from(CpiError::AttestationExpired)
        );
        assert_eq!(
            account.validate_at_slot(&[0x66u8; 48], 150, AttestationPlatform::AmdSevSnp, 100).unwrap_err(),
            ProgramError::from(CpiError::DisallowedMeasurement)
        );
        assert!(account.validate(&measurement, AttestationPlatform::AmdSevSnp).is_err());
        let mut bad = data;
        bad[0] ^= 0xff;
        assert_eq!(AttestedSignerAccount::try_from_slice(&bad).unwrap_err(), ProgramError::InvalidAccountData);
        assert_eq!(AttestedSignerAccount::try_from_slice(&data[..145]).unwrap_err(), ProgramError::InvalidAccountData);
        let other = Pubkey::new_unique();
        let mut lamports = 1u64;
        let mut owned = data;
        let acc = sysvar_account(&other, &other, &mut lamports, &mut owned);
        assert_eq!(AttestedSignerAccount::try_from_account_info(&acc).unwrap_err(), ProgramError::IncorrectProgramId);
        let mut lamports_ok = 1u64;
        let mut owned_ok = data;
        let acc_ok = sysvar_account(&other, &ID, &mut lamports_ok, &mut owned_ok);
        AttestedSignerAccount::try_from_account_info(&acc_ok).unwrap();

        let signer_pk = Pubkey::from(signer);
        let mut signer_lamports = 1u64;
        let mut signer_data = vec![];
        let signer_acc = AccountInfo::new(&signer_pk, true, false, &mut signer_lamports, &mut signer_data, &ID, false);
        account
            .validate_session_signer_at_slot(&signer_acc, &measurement, 200, AttestationPlatform::AmdSevSnp, 100)
            .unwrap();

        let mut unsigned_lamports = 1u64;
        let mut unsigned_data = vec![];
        let unsigned_acc =
            AccountInfo::new(&signer_pk, false, false, &mut unsigned_lamports, &mut unsigned_data, &ID, false);
        assert_eq!(
            account
                .validate_session_signer_at_slot(&unsigned_acc, &measurement, 150, AttestationPlatform::AmdSevSnp, 100)
                .unwrap_err(),
            ProgramError::MissingRequiredSignature
        );

        let other_signer = Pubkey::new_unique();
        let mut mismatch_lamports = 1u64;
        let mut mismatch_data = vec![];
        let mismatch_acc =
            AccountInfo::new(&other_signer, true, false, &mut mismatch_lamports, &mut mismatch_data, &ID, false);
        assert_eq!(
            account
                .validate_session_signer_at_slot(&mismatch_acc, &measurement, 150, AttestationPlatform::AmdSevSnp, 100)
                .unwrap_err(),
            ProgramError::from(CpiError::SignerMismatch)
        );
    }

    #[test]
    fn test_assert_attestation_atomic_ctx_adapter() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let signer = [0x33u8; 32];
        let confidential_compute_data = atomic_ix_data(true, 500, action_hash, &consumer, measurement, signer);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash,
            expected_measurement: measurement,
            expected_signer: Some(signer),
            require_nonce: false,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic_ctx!(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::from(CpiError::NonceRequired)
        );
    }

    #[test]
    fn test_assert_atomic_accepts_explicit_adjacent_index() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let measurement = [0x22u8; 48];
        let signer = [0x33u8; 32];
        let confidential_compute_data = atomic_ix_data(true, 500, action_hash, &consumer, measurement, signer);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash,
            expected_measurement: measurement,
            expected_signer: Some(signer),
            require_nonce: true,
            verifier_ix_index: Some(0),
        };
        let claims = assert_attestation_atomic(&acc, &expectation, &consumer).expect("adjacent");
        assert_eq!(claims.identity, AttestationIdentity::WorkloadKey(signer));
    }

    #[test]
    fn test_assert_atomic_rejects_non_adjacent_index() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let decoy = Pubkey::new_unique();
        let confidential_compute_data = atomic_ix_data(true, 1, [0u8; 32], &consumer, [0u8; 48], [0u8; 32]);
        let dummy = [0u8; 8];
        let mut sysvar =
            serialize_instructions(&[(ID, &confidential_compute_data), (decoy, &dummy), (consumer, &dummy)], 2);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::AmdSevSnp,
            action_hash: [0u8; 32],
            expected_measurement: [0u8; 48],
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: Some(0),
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            CpiError::InvalidAttestationIndex.into()
        );
    }

    fn b64url(input: &[u8]) -> Vec<u8> {
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = Vec::new();
        let mut i = 0;
        while i + 3 <= input.len() {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
            out.push(ALPHA[((n >> 18) & 63) as usize]);
            out.push(ALPHA[((n >> 12) & 63) as usize]);
            out.push(ALPHA[((n >> 6) & 63) as usize]);
            out.push(ALPHA[(n & 63) as usize]);
            i += 3;
        }
        let rest = input.len() - i;
        if rest == 1 {
            let n = (input[i] as u32) << 16;
            out.push(ALPHA[((n >> 18) & 63) as usize]);
            out.push(ALPHA[((n >> 12) & 63) as usize]);
        } else if rest == 2 {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(ALPHA[((n >> 18) & 63) as usize]);
            out.push(ALPHA[((n >> 12) & 63) as usize]);
            out.push(ALPHA[((n >> 6) & 63) as usize]);
        }
        out
    }

    fn google_jwt(image_hex: &str) -> Vec<u8> {
        let header = b64url(br#"{"alg":"RS256","kid":"teton-test"}"#);
        let payload = format!(
            concat!(
                r#"{{"iss":"https://confidentialcomputing.googleapis.com","sub":"sub","aud":"aud","#,
                r#""exp":4102444800,"iat":1700000000,"secboot":true,"dbgstat":"disabled-since-boot","#,
                r#""eat_nonce":"0123456789abcd","image_digest":"sha256:{}"}}"#
            ),
            image_hex
        );
        let payload_b64 = b64url(payload.as_bytes());
        let mut jwt = header;
        jwt.push(b'.');
        jwt.extend_from_slice(&payload_b64);
        jwt.extend_from_slice(b".c2ln");
        jwt
    }

    fn nvidia_ix_data(mode: u8, nonce_slot: u64, action_hash: [u8; 32], gpu_measurement: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR);
        data.push(mode);
        data.extend_from_slice(&nonce_slot.to_le_bytes());
        data.extend_from_slice(&action_hash);
        data.extend_from_slice(gpu_measurement);
        data
    }

    fn google_ix_data(mode: u8, nonce_slot: u64, action_hash: [u8; 32], jwt: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&VERIFY_GOOGLE_JWT_DISCRIMINATOR);
        data.push(mode);
        data.extend_from_slice(&nonce_slot.to_le_bytes());
        data.extend_from_slice(&action_hash);
        data.extend_from_slice(&(jwt.len() as u32).to_le_bytes());
        data.extend_from_slice(jwt);
        data
    }

    #[test]
    fn test_assert_google_jwt_mode_b_accepts_preceding_instruction() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let digest = [0xABu8; 32];
        let mut measurement = [0u8; 48];
        measurement[..32].copy_from_slice(&digest);
        let jwt = google_jwt(&"ab".repeat(32));
        let confidential_compute_data = google_ix_data(VERIFY_GOOGLE_JWT_MODE_B, 500, action_hash, &jwt);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &confidential_compute_data), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::GcpConfidentialSpace,
            action_hash,
            expected_measurement: measurement,
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        let claims = assert_attestation_atomic(&acc, &expectation, &consumer).expect("jwt mode b");
        assert_eq!(claims.identity, AttestationIdentity::ImageDigest(digest));
        assert_eq!(claims.measurement, measurement);
        assert_eq!(claims.nonce_slot, 500);
    }

    #[test]
    fn test_assert_google_jwt_mode_b_rejects_mode_a_and_mismatch() {
        let ix_key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let consumer = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let action_hash = [0x11u8; 32];
        let digest = [0xABu8; 32];
        let mut measurement = [0u8; 48];
        measurement[..32].copy_from_slice(&digest);
        let jwt = google_jwt(&"ab".repeat(32));
        let mode_a = google_ix_data(0, 9, action_hash, &jwt);
        let dummy = [0u8; 8];
        let mut sysvar = serialize_instructions(&[(ID, &mode_a), (consumer, &dummy)], 1);
        let mut lamports = 1u64;
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::GcpConfidentialSpace,
            action_hash,
            expected_measurement: measurement,
            expected_signer: None,
            require_nonce: true,
            verifier_ix_index: None,
        };
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            CpiError::WrongAttestationMode.into()
        );

        let mismatched = google_ix_data(VERIFY_GOOGLE_JWT_MODE_B, 9, [0x22u8; 32], &jwt);
        let mut sysvar = serialize_instructions(&[(ID, &mismatched), (consumer, &dummy)], 1);
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::from(CpiError::ActionHashMismatch)
        );

        let bound = google_ix_data(VERIFY_GOOGLE_JWT_MODE_B, 9, action_hash, &jwt);
        let mut sysvar = serialize_instructions(&[(ID, &bound), (other, &dummy)], 1);
        let acc = sysvar_account(&ix_key, &owner, &mut lamports, &mut sysvar);
        assert_eq!(
            assert_attestation_atomic(&acc, &expectation, &consumer).unwrap_err(),
            ProgramError::from(CpiError::ConsumerProgramMismatch)
        );
    }

    #[test]
    fn issue_210_public_error_categories_and_stable_codes() {
        let consumer = Pubkey::new_unique();
        let expectation = AtomicAttestationExpectation::default();
        let valid = atomic_ix_data(true, 7, [0; 32], &consumer, [0; 48], [0; 32]);
        let short = VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec();
        let nitro_bad = nitro_ix_data(1, 7, [0; 32], &[0xff]);
        let nitro_mode_a = nitro_ix_data(0, 7, [0; 32], &[0xff]);
        let jwt_bad = google_ix_data(1, 7, [0; 32], b"invalid");
        let jwt_mode_a = google_ix_data(0, 7, [0; 32], b"invalid");
        let nitro = AtomicAttestationExpectation { expected_platform: AttestationPlatform::AwsNitro, ..expectation };
        let gcp = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::GcpConfidentialSpace,
            ..expectation
        };
        for (data, case_expectation, expected_error) in [
            (short, expectation.clone(), CpiError::MalformedAttestationEnvelope),
            (vec![0xff; 8], expectation.clone(), CpiError::UnsupportedAttestationInstruction),
            (nitro_bad, nitro.clone(), CpiError::MalformedNitroDocument),
            (nitro_mode_a, nitro, CpiError::WrongAttestationMode),
            (jwt_bad, gcp.clone(), CpiError::MalformedGoogleJwt),
            (jwt_mode_a, gcp, CpiError::WrongAttestationMode),
        ] {
            let mut wire = serialize_instructions(&[(ID, &data), (consumer, &[])], 1);
            let key = instructions::ID;
            let owner = solana_program::sysvar::ID;
            let mut lamports = 1;
            let info = sysvar_account(&key, &owner, &mut lamports, &mut wire);
            assert_eq!(assert_attestation_atomic(&info, &case_expectation, &consumer), Err(expected_error.into()));
        }
        let mut wire = serialize_instructions(&[(ID, &valid), (consumer, &[])], 1);
        let key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let mut lamports = 1;
        let info = sysvar_account(&key, &owner, &mut lamports, &mut wire);
        assert_attestation_atomic(&info, &expectation, &consumer).unwrap();
        let wrong_index = AtomicAttestationExpectation { verifier_ix_index: Some(1), ..expectation };
        assert_eq!(
            assert_attestation_atomic(&info, &wrong_index, &consumer),
            Err(CpiError::InvalidAttestationIndex.into())
        );
        for (error, code) in [
            (CpiError::DisallowedMeasurement, 3),
            (CpiError::UnauthorizedPolicy, 7),
            (CpiError::AttestationExpired, 8),
            (CpiError::ActionHashMismatch, 12),
            (CpiError::SignerMismatch, 13),
            (CpiError::NonceRequired, 16),
            (CpiError::ConsumerProgramMismatch, 17),
            (CpiError::InvalidAttestationIndex, 1010),
            (CpiError::UnsupportedAttestationInstruction, 1011),
            (CpiError::MalformedAttestationEnvelope, 1012),
            (CpiError::WrongAttestationMode, 1013),
            (CpiError::MalformedSnpReport, 1014),
            (CpiError::MalformedNitroDocument, 1015),
            (CpiError::MalformedGoogleJwt, 1016),
            (CpiError::MalformedInstructionsSysvar, 1017),
        ] {
            assert_eq!(ProgramError::from(error), ProgramError::Custom(code));
        }
    }

    #[test]
    fn issue_179_mode_a_requires_matching_supported_platform() {
        let measurement = [0x42; 48];
        let signer = Pubkey::new_unique();
        let (pda, bump) = Pubkey::find_program_address(&[ATTESTED_SIGNER_SEED, signer.as_ref()], &ID);
        let platforms = [
            AttestationPlatform::AmdSevSnp,
            AttestationPlatform::AwsNitro,
            AttestationPlatform::GcpConfidentialSpace,
            AttestationPlatform::NvidiaH100,
        ];
        let mut signer_lamports = 1;
        let mut signer_data = [];
        let signer_acc = AccountInfo::new(&signer, true, false, &mut signer_lamports, &mut signer_data, &ID, false);
        for wire_tag in [1, 2, 3, 0, 4, 255] {
            let mut data = attested_signer_bytes(&signer.to_bytes(), &measurement, 200, bump);
            data[40] = wire_tag;
            let record = AttestedSignerAccount::try_from_slice(&data).unwrap();
            let mut lamports = 1;
            let info = sysvar_account(&pda, &ID, &mut lamports, &mut data);
            for expected in platforms {
                let result = if !matches!(wire_tag, 1..=3) {
                    Err(CpiError::UnsupportedPlatform.into())
                } else if wire_tag == expected as u8 {
                    Ok(())
                } else {
                    Err(CpiError::PlatformMismatch.into())
                };
                assert_eq!(record.validate_at_slot(&measurement, 150, expected, 100), result);
                assert_eq!(
                    record.validate_session_signer_at_slot(&signer_acc, &measurement, 150, expected, 100),
                    result
                );
                assert_eq!(
                    assert_attestation_signer_at_slot(&info, &signer_acc, 150, &measurement, expected, 100).map(|_| ()),
                    result
                );
            }
        }
    }

    #[test]
    fn issue_179_mode_b_platform_matrix() {
        let consumer = Pubkey::new_unique();
        let signer = [0x33; 32];
        let mut measurement = [0; 48];
        measurement[..32].fill(0xab);
        let action_hash = [0x11; 32];
        let fixtures = [
            (AttestationPlatform::AmdSevSnp, atomic_ix_data(true, 7, action_hash, &consumer, measurement, signer)),
            (
                AttestationPlatform::AwsNitro,
                nitro_ix_data(1, 7, action_hash, &encode_nitro_document(signer, measurement)),
            ),
            (
                AttestationPlatform::GcpConfidentialSpace,
                google_ix_data(1, 7, action_hash, &google_jwt(&"ab".repeat(32))),
            ),
            (AttestationPlatform::NvidiaH100, nvidia_ix_data(VERIFY_NVIDIA_MODE_B, 7, action_hash, &measurement[..32])),
        ];
        for (actual, data) in fixtures {
            let mut wire = serialize_instructions(&[(ID, &data), (consumer, &[])], 1);
            let mut lamports = 1;
            let key = instructions::ID;
            let owner = solana_program::sysvar::ID;
            let info = sysvar_account(&key, &owner, &mut lamports, &mut wire);
            for expected in [
                AttestationPlatform::AmdSevSnp,
                AttestationPlatform::AwsNitro,
                AttestationPlatform::GcpConfidentialSpace,
                AttestationPlatform::NvidiaH100,
            ] {
                let expectation = AtomicAttestationExpectation {
                    action_hash,
                    expected_measurement: measurement,
                    expected_platform: expected,
                    ..Default::default()
                };
                let result = assert_attestation_atomic(&info, &expectation, &consumer);
                if actual == AttestationPlatform::NvidiaH100 {
                    assert_eq!(result, Err(CpiError::UnsupportedPlatform.into()));
                } else if actual == expected {
                    assert_eq!(result.unwrap().platform, actual);
                } else {
                    assert_eq!(result, Err(CpiError::PlatformMismatch.into()));
                }
            }
        }
    }

    #[test]
    fn nvidia_mode_b_copied_measurement_cannot_authorize_action() {
        let consumer = Pubkey::new_unique();
        let action_hash = [0x44; 32];
        let gpu = [0xab; 32];
        let mut measurement = [0u8; 48];
        measurement[..32].copy_from_slice(&gpu);
        let expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::NvidiaH100,
            action_hash,
            expected_measurement: measurement,
            ..Default::default()
        };
        let bound = nvidia_ix_data(VERIFY_NVIDIA_MODE_B, 7, action_hash, &gpu);
        let mut wire = serialize_instructions(&[(ID, &bound), (consumer, &[])], 1);
        let mut lamports = 1;
        let key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let info = sysvar_account(&key, &owner, &mut lamports, &mut wire);
        assert_eq!(
            assert_attestation_atomic(&info, &expectation, &consumer),
            Err(CpiError::UnsupportedPlatform.into())
        );
    }

    #[test]
    fn issue_180_google_digest_cannot_satisfy_workload_key_expectation() {
        let digest = [0xab; 32];
        let mut measurement = [0; 48];
        measurement[..32].copy_from_slice(&digest);
        let mut expectation = AtomicAttestationExpectation {
            expected_platform: AttestationPlatform::GcpConfidentialSpace,
            expected_measurement: measurement,
            ..Default::default()
        };
        let consumer = Pubkey::new_unique();
        let jwt = google_jwt(&"ab".repeat(32));
        let data = google_ix_data(1, 7, expectation.action_hash, &jwt);
        let mut sysvar = serialize_instructions(&[(ID, &data), (consumer, &[])], 1);
        let mut lamports = 1;
        let key = instructions::ID;
        let owner = solana_program::sysvar::ID;
        let acc = sysvar_account(&key, &owner, &mut lamports, &mut sysvar);
        let claims = assert_attestation_atomic(&acc, &expectation, &consumer).unwrap();
        assert_eq!(claims.identity, AttestationIdentity::ImageDigest(digest));
        for key in [digest, [0xcd; 32], [0; 32]] {
            expectation.expected_signer = Some(key);
            assert_eq!(
                assert_attestation_atomic(&acc, &expectation, &consumer),
                Err(CpiError::SignerIdentityUnavailable.into())
            );
        }
    }

    #[test]
    fn issue_288_governance_tombstone_rejects_every_platform_even_at_slot_zero() {
        let signer = Pubkey::new_unique();
        let measurement = [7; 48];
        let (pda, bump) = Pubkey::find_program_address(&[ATTESTED_SIGNER_SEED, signer.as_ref()], &ID);
        let mut sl = 1;
        let mut sd = [];
        let signer_acc = AccountInfo::new(&signer, true, false, &mut sl, &mut sd, &ID, false);
        for platform in
            [AttestationPlatform::AmdSevSnp, AttestationPlatform::AwsNitro, AttestationPlatform::GcpConfidentialSpace]
        {
            // Legacy revocation can still carry a future Unix deadline.
            let mut bytes = attested_signer_bytes(&signer.to_bytes(), &measurement, 0, bump);
            bytes[40] = platform as u8;
            let view = AttestedSignerAccount::try_from_slice(&bytes).unwrap();
            assert_eq!(
                view.validate_session_signer_at_slot(&signer_acc, &measurement, 0, platform, 100),
                Err(CpiError::AttestationExpired.into())
            );
            let mut l = 1;
            let info = sysvar_account(&pda, &ID, &mut l, &mut bytes);
            assert_eq!(
                assert_attestation_signer_at_slot(&info, &signer_acc, 0, &measurement, platform, 100),
                Err(CpiError::AttestationExpired.into())
            );
        }
    }

    #[test]
    fn issue_182_v2_requires_slot_and_exclusive_unix_deadline() {
        let signer = Pubkey::new_unique();
        let measurement = [0x42; 48];
        let (pda, bump) = Pubkey::find_program_address(&[ATTESTED_SIGNER_SEED, signer.as_ref()], &ID);
        let mut data = attested_signer_bytes(&signer.to_bytes(), &measurement, 200, bump);
        let record = AttestedSignerAccount::try_from_slice(&data).unwrap();
        assert_eq!(record.expires_unix_timestamp(), 1000);
        assert_eq!(ATTESTED_SIGNER_ACCOUNT_SIZE, 154);
        let mut lamports = 1;
        let mut signer_lamports = 1;
        let mut signer_data = [];
        let info = sysvar_account(&pda, &ID, &mut lamports, &mut data);
        let workload = AccountInfo::new(&signer, true, false, &mut signer_lamports, &mut signer_data, &ID, false);
        for (slot, unix, valid) in [
            (200, 999, true),
            (150, 1000, false),
            (150, 1001, false),
            (150, -1, false),
            (201, 999, false),
            (150, 0, true),
        ] {
            let expected = if valid { Ok(()) } else { Err(CpiError::AttestationExpired.into()) };
            assert_eq!(record.validate_at_slot(&measurement, slot, AttestationPlatform::AmdSevSnp, unix), expected);
            assert_eq!(
                record.validate_session_signer_at_slot(
                    &workload,
                    &measurement,
                    slot,
                    AttestationPlatform::AmdSevSnp,
                    unix
                ),
                expected
            );
            assert_eq!(
                assert_attestation_signer_at_slot(
                    &info,
                    &workload,
                    slot,
                    &measurement,
                    AttestationPlatform::AmdSevSnp,
                    unix
                )
                .map(|_| ()),
                expected
            );
        }
        drop(info);
        assert_eq!(AttestedSignerAccount::try_from_slice(&data[..146]), Err(ProgramError::InvalidAccountData));
        data[..8].copy_from_slice(&[97, 156, 233, 39, 50, 169, 179, 13]);
        assert_eq!(AttestedSignerAccount::try_from_slice(&data), Err(ProgramError::InvalidAccountData));
    }
}
