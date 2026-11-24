//! Program instruction definitions and 8-byte Anchor discriminators for Solana Confidential Compute Verifier.

#[cfg(not(feature = "anchor"))]
use borsh::{BorshDeserialize, BorshSerialize};
// Anchor's derives are borsh's plus the type definitions its IDL generator
// needs, so binding the same names keeps every `#[derive(..)]` below unchanged
// while making these payloads describable in the IDL.
#[cfg(feature = "anchor")]
use anchor_lang::{AnchorDeserialize as BorshDeserialize, AnchorSerialize as BorshSerialize};
use solana_program::{hash::hashv, program_error::ProgramError};

use crate::error::VerifierError;

/// Anchor instruction discriminators (sha256("global:<name>")[..8]).
pub const INIT_POLICY_REGISTRY_DISCRIMINATOR: [u8; 8] = [90, 53, 0, 89, 164, 70, 107, 186];
pub const UPDATE_POLICY_DISCRIMINATOR: [u8; 8] = [227, 150, 114, 217, 142, 172, 100, 228];
pub const REGISTER_VCEK_DISCRIMINATOR: [u8; 8] = [228, 65, 209, 71, 242, 135, 131, 17];
pub const VERIFY_AND_REGISTER_DISCRIMINATOR: [u8; 8] = [246, 249, 100, 14, 102, 116, 92, 145];
pub const VERIFY_ATOMIC_DISCRIMINATOR: [u8; 8] = [65, 19, 195, 149, 67, 219, 25, 75];
pub const VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR: [u8; 8] = [209, 4, 10, 239, 3, 142, 223, 250];
pub const ROTATE_ROOT_CERT_DISCRIMINATOR: [u8; 8] = [137, 212, 96, 71, 222, 5, 133, 104];
/// @spec SCC-JWT-006
pub const REGISTER_JWKS_KEY_DISCRIMINATOR: [u8; 8] = [122, 195, 232, 116, 203, 137, 219, 14];
/// @spec SCC-JWT-006
pub const REVOKE_JWKS_KEY_DISCRIMINATOR: [u8; 8] = [184, 102, 12, 45, 99, 128, 41, 16];
/// @spec SCC-JWT-001 SCC-JWT-005
pub const VERIFY_GOOGLE_JWT_DISCRIMINATOR: [u8; 8] = [104, 38, 12, 199, 131, 240, 78, 165];
/// @spec SCC-NITRO-008
pub const VERIFY_NITRO_ATTESTATION_DISCRIMINATOR: [u8; 8] = [107, 76, 178, 169, 215, 146, 23, 95];
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR: [u8; 8] = [31, 2, 40, 104, 69, 155, 234, 120];

/// Mode A: register an attested session signer.
pub const VERIFY_GOOGLE_JWT_MODE_A: u8 = 0;
/// Mode B: atomic action commitment + nonce tombstone.
pub const VERIFY_GOOGLE_JWT_MODE_B: u8 = 1;

/// Mode A (`verify_and_register_nitro`): register `AttestedSignerAccount`.
/// @spec SCC-NITRO-008
pub const VERIFY_NITRO_MODE_A: u8 = 0;
/// Mode B (`verify_atomic_nitro`): action commitment + nonce tombstone.
/// @spec SCC-NITRO-008
pub const VERIFY_NITRO_MODE_B: u8 = 1;

/// Mode A. The 73-byte legacy packet rejects. A proof packet registers a signer.
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_MODE_A: u8 = 0;
/// Mode B. The 73-byte legacy packet rejects. A proof packet binds the next instruction.
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_MODE_B: u8 = 1;

/// Backend policy source and nonce seed tag for NVIDIA Hopper.
/// @spec SCC-NVIDIA-003
pub const NVIDIA_ATTESTATION_SOURCE: u8 = 4;

/// Domain string mixed into the proof statement.
/// @spec SCC-NVIDIA-002
pub const NVIDIA_STATEMENT_DOMAIN: &[u8] = b"solana-confidential-compute-nvidia-h100/v1";

/// `mode || nonce_slot || action_hash || measurement`.
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_LEGACY_LEN: usize = 1 + 8 + 32 + 32;
/// Two 128-bit public-input limbs.
pub const VERIFY_NVIDIA_PUBLIC_INPUT_LEN: usize = 16 * 2;
/// Uncompressed BN254 Groth16 points: `A` (64) || `B` (128) || `C` (64).
pub const VERIFY_NVIDIA_GROTH16_POINTS_LEN: usize = 64 + 128 + 64;
/// Legacy header plus public inputs plus the 256-byte proof.
/// @spec SCC-NVIDIA-001
pub const VERIFY_NVIDIA_PROOF_PACKET_LEN: usize =
    VERIFY_NVIDIA_LEGACY_LEN + VERIFY_NVIDIA_PUBLIC_INPUT_LEN + VERIFY_NVIDIA_GROTH16_POINTS_LEN;

/// BN254 base-field modulus `p`, big-endian.
const BN254_BASE_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x97, 0x81, 0x6a,
    0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// BN254 scalar-field modulus `r`, big-endian.
const BN254_SCALAR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8,
    0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Zero-copy view of a proof-backed `verify_nvidia_attestation` payload.
///
/// @spec SCC-NVIDIA-001 SCC-NVIDIA-002 SCC-NVIDIA-004
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvidiaProofPacket<'a> {
    pub mode: u8,
    pub nonce_slot: u64,
    pub expected_action_hash: &'a [u8; 32],
    pub measurement: &'a [u8; 32],
    /// Limb 0 is the high 128 bits. Limb 1 is the low 128 bits. Both are big-endian.
    pub public_inputs: [[u8; 16]; 2],
    pub proof_a: &'a [u8; 64],
    pub proof_b: &'a [u8; 128],
    pub proof_c: &'a [u8; 64],
}

/// Fields bound by the proof statement.
/// @spec SCC-NVIDIA-002
pub struct NvidiaStatement<'a> {
    pub program_id: &'a [u8],
    pub mode: u8,
    pub nonce_slot: u64,
    pub expected_action_hash: &'a [u8; 32],
    pub measurement: &'a [u8; 32],
    pub slot_hash: &'a [u8; 32],
    pub subject: &'a [u8; 32],
}

/// Bytes passed to `SignatureVerifier::verify_p384` for one NVIDIA statement.
/// @spec SCC-NVIDIA-001
pub struct NvidiaVerifierMessage {
    pub public_key_xy: [u8; 96],
    pub message_digest: [u8; 48],
    pub signature_rs: [u8; 96],
}

fn read_array<'a, const N: usize>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8; N], ProgramError> {
    let start = *offset;
    let end = start.checked_add(N).ok_or(VerifierError::InvalidInstruction)?;
    let bytes = data.get(start..end).ok_or(VerifierError::InvalidInstruction)?;
    *offset = end;
    bytes.try_into().map_err(|_| VerifierError::InvalidInstruction.into())
}

/// Parse a proof packet. The length must be exact. A short or long buffer is rejected.
/// @spec SCC-NVIDIA-001 SCC-NVIDIA-005
pub fn parse_nvidia_proof_packet(rest: &[u8]) -> Result<NvidiaProofPacket<'_>, ProgramError> {
    if rest.len() != VERIFY_NVIDIA_PROOF_PACKET_LEN {
        return Err(VerifierError::InvalidInstruction.into());
    }
    let mut offset = 0usize;
    let mode = read_array::<1>(rest, &mut offset)?[0];
    if mode != VERIFY_NVIDIA_MODE_A && mode != VERIFY_NVIDIA_MODE_B {
        return Err(VerifierError::InvalidInstruction.into());
    }
    let nonce_slot = u64::from_le_bytes(*read_array::<8>(rest, &mut offset)?);
    let expected_action_hash = read_array::<32>(rest, &mut offset)?;
    let measurement = read_array::<32>(rest, &mut offset)?;
    let limb_0 = *read_array::<16>(rest, &mut offset)?;
    let limb_1 = *read_array::<16>(rest, &mut offset)?;
    let proof_a = read_array::<64>(rest, &mut offset)?;
    let proof_b = read_array::<128>(rest, &mut offset)?;
    let proof_c = read_array::<64>(rest, &mut offset)?;
    if offset != rest.len() {
        return Err(VerifierError::InvalidInstruction.into());
    }
    Ok(NvidiaProofPacket {
        mode,
        nonce_slot,
        expected_action_hash,
        measurement,
        public_inputs: [limb_0, limb_1],
        proof_a,
        proof_b,
        proof_c,
    })
}

/// SHA-256 of the enrollment statement.
///
/// The byte order is domain, program id, mode, nonce slot, action hash,
/// measurement, slot hash, then subject.
/// @spec SCC-NVIDIA-002
pub fn nvidia_attestation_statement(parts: &NvidiaStatement<'_>) -> [u8; 32] {
    let mode = [parts.mode];
    let nonce_slot = parts.nonce_slot.to_le_bytes();
    hashv(&[
        NVIDIA_STATEMENT_DOMAIN,
        parts.program_id,
        &mode,
        &nonce_slot,
        parts.expected_action_hash,
        parts.measurement,
        parts.slot_hash,
        parts.subject,
    ])
    .to_bytes()
}

/// Split a statement into the two public-input limbs.
pub fn nvidia_public_inputs_from_statement(statement: &[u8; 32]) -> [[u8; 16]; 2] {
    let mut inputs = [[0u8; 16]; 2];
    inputs[0].copy_from_slice(&statement[..16]);
    inputs[1].copy_from_slice(&statement[16..]);
    inputs
}

fn scalar_below_r(scalar: &[u8; 32]) -> bool {
    scalar.as_slice() < BN254_SCALAR_MODULUS_BE.as_slice()
}

fn limb_below_r(limb: &[u8; 16]) -> bool {
    let mut scalar = [0u8; 32];
    scalar[16..].copy_from_slice(limb);
    scalar_below_r(&scalar)
}

/// Return true when each 128-bit limb and their concatenation are strictly below `r`.
///
/// A single 128-bit limb is below the 254-bit scalar modulus. The check still
/// compares that limb. The 32-byte concatenation must also be strictly below `r`.
/// @spec SCC-NVIDIA-001
pub fn nvidia_public_inputs_canonical(inputs: &[[u8; 16]; 2]) -> bool {
    if !limb_below_r(&inputs[0]) || !limb_below_r(&inputs[1]) {
        return false;
    }
    let mut scalar = [0u8; 32];
    scalar[..16].copy_from_slice(&inputs[0]);
    scalar[16..].copy_from_slice(&inputs[1]);
    scalar_below_r(&scalar)
}

fn coordinate_below_base_field(coord: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 32]>::try_from(coord) else {
        return false;
    };
    bytes.as_slice() < BN254_BASE_MODULUS_BE.as_slice()
}

fn affine_point_well_formed(point: &[u8]) -> bool {
    if point.is_empty() || point.iter().all(|byte| *byte == 0) || !point.len().is_multiple_of(32) {
        return false;
    }
    point.chunks(32).all(coordinate_below_base_field)
}

/// Accept uncompressed `A`, `B`, and `C` when each coordinate is below `p` and no point is the identity.
/// @spec SCC-NVIDIA-001
pub fn nvidia_proof_points_well_formed(proof_a: &[u8; 64], proof_b: &[u8; 128], proof_c: &[u8; 64]) -> bool {
    affine_point_well_formed(proof_a) && affine_point_well_formed(proof_b) && affine_point_well_formed(proof_c)
}

/// Nonce seed `SHA-256(subject || measurement || slot_hash)`.
///
/// Mode A uses the workload signer as `subject`. Mode B uses the action commitment.
/// @spec SCC-NVIDIA-002 SCC-NVIDIA-004
pub fn nvidia_nonce_seed(subject: &[u8; 32], measurement: &[u8; 32], slot_hash: &[u8; 32]) -> [u8; 32] {
    hashv(&[subject, measurement, slot_hash]).to_bytes()
}

/// Pack the statement and proof into the verifier message.
/// @spec SCC-NVIDIA-001 SCC-NVIDIA-002
pub fn nvidia_verifier_message(
    statement: &[u8; 32],
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
) -> NvidiaVerifierMessage {
    let binding = hashv(&[proof_a, proof_b, proof_c]).to_bytes();
    let mut public_key_xy = [0u8; 96];
    public_key_xy[..32].copy_from_slice(statement);
    public_key_xy[32..64].copy_from_slice(&binding);
    let mut message_digest = [0u8; 48];
    message_digest[..32].copy_from_slice(statement);
    message_digest[32..].copy_from_slice(&binding[..16]);
    let mut signature_rs = [0u8; 96];
    signature_rs[..32].copy_from_slice(&binding);
    signature_rs[32..64].copy_from_slice(statement);
    NvidiaVerifierMessage { public_key_xy, message_digest, signature_rs }
}

/// Maximum DER length accepted for ASK or VCEK certificates.
pub const MAX_VCEK_CERT_LEN: u16 = 4096;

/// Byte size of `RegisterVcekArgs` (chip_id + tcb + pubkey + two u16 lengths).
/// Trailing ASK and VCEK DER follow this header in instruction data.
pub const REGISTER_VCEK_HEADER_SIZE: usize = 64 + 8 + 96 + 2 + 2;

/// Instruction payload for `verify_and_register`.
///
/// On-chain, the processor does **not** Borsh-deserialize this struct. It reads
/// `nonce_slot` from `rest[0..8]` and borrows `rest[8..8+1184]` as the report
/// (`@spec SCC-PERF-001`). Off-chain clients still serialize this layout.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VerifyAndRegisterArgs {
    /// Slot number at which the nonce was sampled.
    pub nonce_slot: u64,
    /// Exact 1,184-byte AMD SEV-SNP attestation report.
    pub report: [u8; 1184],
}

/// Instruction payload for `init_policy_registry`.
/// Global measurements are legacy ABI storage, not runtime admission controls.
/// Configure each backend with `SetBackendPolicyArgs` before admitting workloads.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct InitPolicyRegistryArgs {
    pub authority: [u8; 32],
    pub ark_pubkey_xy: [u8; 96],
    pub min_tcb_boot_loader: u8,
    pub min_tcb_tee: u8,
    pub min_tcb_snp: u8,
    pub min_tcb_microcode: u8,
    pub measurement_count: u32,
    pub measurements: [[u8; 48]; 8],
}

/// Update monotonic AMD TCB floors and legacy global measurement storage.
/// Measurements are deprecated as runtime controls; zero does not halt admission.
/// To halt new admission, set each relevant backend policy's count to zero.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UpdatePolicyArgs {
    pub min_tcb_boot_loader: u8,
    pub min_tcb_tee: u8,
    pub min_tcb_snp: u8,
    pub min_tcb_microcode: u8,
    pub measurement_count: u32,
    pub measurements: [[u8; 48]; 8],
}

/// Instruction payload header for `register_vcek`.
/// ASK DER (`ask_cert_len` bytes) then VCEK DER (`vcek_cert_len` bytes) follow.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RegisterVcekArgs {
    pub chip_id: [u8; 64],
    pub tcb_version: u64,
    pub public_key_xy: [u8; 96],
    pub ask_cert_len: u16,
    pub vcek_cert_len: u16,
}

/// Instruction payload for `rotate_root_cert`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RotateRootCertArgs {
    pub new_ark_pubkey_xy: [u8; 96],
}

/// Instruction payload for `register_jwks_key`.
/// @spec SCC-JWT-006
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RegisterJwksKeyArgs {
    pub kid: Vec<u8>,
    pub modulus: [u8; 256],
    pub exponent: u32,
}

/// Instruction payload for `revoke_jwks_key`.
/// @spec SCC-JWT-006
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevokeJwksKeyArgs {
    pub kid_hash: [u8; 32],
}

/// Instruction payload for `verify_google_jwt`.
/// @spec SCC-JWT-001 SCC-JWT-005
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VerifyGoogleJwtArgs {
    pub mode: u8,
    pub nonce_slot: u64,
    pub expected_action_hash: [u8; 32],
    pub jwt: String,
}

/// Instruction payload for `verify_nitro_attestation`.
///
/// On-chain the processor reads this layout zero-copy (`mode`, `nonce_slot`,
/// `expected_action_hash`, `u32` length, document bytes).
/// @spec SCC-NITRO-006 SCC-NITRO-007 SCC-NITRO-008
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VerifyNitroAttestationArgs {
    pub mode: u8,
    pub nonce_slot: u64,
    pub expected_action_hash: [u8; 32],
    pub document: Vec<u8>,
}

/// Set the exact accepted GCP audience and subject. Empty values fail closed.
pub const SET_GCP_TENANT_POLICY_DISCRIMINATOR: [u8; 8] = [253, 197, 211, 209, 205, 86, 22, 43];
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SetGcpTenantPolicyArgs {
    pub expected_audience: String,
    pub expected_subject: String,
}

/// Immediately expire a canonical Mode A record under registry governance.
pub const REVOKE_ATTESTED_SIGNER_DISCRIMINATOR: [u8; 8] = [174, 9, 66, 138, 2, 191, 81, 61];
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevokeAttestedSignerArgs {
    pub signer_pubkey: [u8; 32],
}

/// Accounts: current authority signer, global registry, canonical V2 cache writable.
pub const REVOKE_VCEK_DISCRIMINATOR: [u8; 8] = [81, 34, 243, 59, 64, 69, 29, 89];
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevokeVcekArgs {
    pub chip_id_hash: [u8; 32],
    pub tcb_version: u64,
}
/// No payload. Accounts: nonce writable, original payer/refund writable, Clock.
pub const CLOSE_STALE_NONCE_DISCRIMINATOR: [u8; 8] = [29, 255, 42, 68, 101, 76, 161, 110];
/// No payload. Accounts: signer record writable, workload signer writable+signer, Clock.
pub const CLOSE_ATTESTED_SIGNER_DISCRIMINATOR: [u8; 8] = [133, 48, 83, 164, 186, 133, 18, 227];

/// Accounts: authority signer, global registry, backend policy writable,
/// payer signer writable, system program. Source: AMD=1, Nitro=2, GCP=3.
pub const SET_BACKEND_POLICY_DISCRIMINATOR: [u8; 8] = [21, 155, 245, 154, 100, 138, 42, 166];
/// Replace the authoritative list for one backend. Zero halts new admission for
/// that backend; it does not revoke existing Mode A signer records.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SetBackendPolicyArgs {
    pub source: u8,
    pub measurement_count: u32,
    pub measurements: [[u8; 48]; 8],
}

/// `sha256("global:verify_tdx_qe_report")[..8]`.
/// @spec SCC-TDX-001
pub const VERIFY_TDX_QE_REPORT_DISCRIMINATOR: [u8; 8] = [210, 155, 95, 37, 125, 174, 77, 73];
/// `sha256("global:verify_tdx_quote")[..8]`.
/// @spec SCC-TDX-002
pub const VERIFY_TDX_QUOTE_DISCRIMINATOR: [u8; 8] = [173, 239, 124, 214, 245, 185, 23, 137];

/// Backend policy source and nonce seed tag for Intel TDX.
/// @spec SCC-TDX-001
pub const TDX_ATTESTATION_SOURCE: u8 = 5;

/// Mode A: register an attested signer.
pub const VERIFY_TDX_MODE_A: u8 = 0;

/// `attestation_pubkey_xy (64) || pck_pubkey (33) || qe_auth_data_len (2) || qe_auth_data`.
///
/// The QE report itself is not here: it is the precompile's message, and the
/// handler reads it back from that instruction. Repeating 384 bytes would
/// cost transaction space for nothing.
///
/// The attestation key is supplied rather than derived: the QE report commits
/// to `SHA-256(attestation_pubkey_xy || qe_auth_data)`, which is a digest and
/// cannot be inverted. Supplying it is safe because the handler recomputes
/// that digest and refuses anything that does not match.
/// @spec SCC-TDX-001
pub struct VerifyTdxQeReportArgs<'a> {
    /// Uncompressed `X || Y`, exactly as the quote carries it.
    pub attestation_pubkey_xy: &'a [u8; 64],
    pub pck_pubkey: &'a [u8; 33],
    /// Recorded in the session for the second half, which has no room for it.
    pub gpu_rim_digest: &'a [u8; 32],
    pub model_digest: &'a [u8; 32],
    pub qe_auth_data: &'a [u8],
}

/// `sha256("global:issue_tdx_challenge")[..8]`.
/// @spec SCC-TDX-005
pub const ISSUE_TDX_CHALLENGE_DISCRIMINATOR: [u8; 8] = [70, 183, 171, 140, 168, 137, 54, 149];

/// Arguments to `issue_tdx_challenge`.
///
/// The nonce only has to be unique; it selects the PDA. Unpredictability
/// comes from `slot_hash`, which the program reads from the SlotHashes sysvar
/// rather than taking from the caller, so an enclave cannot pre-compute a
/// quote for a challenge that has not been issued yet.
pub struct IssueTdxChallengeArgs<'a> {
    pub nonce: &'a [u8; 32],
    /// Which recent slot's hash to pin. Must be within the sysvar's window.
    pub nonce_slot: u64,
}

/// Parse `issue_tdx_challenge`.
/// @spec SCC-TDX-005
pub fn parse_issue_tdx_challenge_args(rest: &[u8]) -> Result<IssueTdxChallengeArgs<'_>, ProgramError> {
    let mut offset = 0usize;
    let nonce = read_array::<32>(rest, &mut offset)?;
    let nonce_slot = u64::from_le_bytes(*read_array::<8>(rest, &mut offset)?);
    if offset != rest.len() {
        return Err(VerifierError::InvalidInstruction.into());
    }
    Ok(IssueTdxChallengeArgs { nonce, nonce_slot })
}

/// Intel caps QE auth data well below this; the bound exists so a caller
/// cannot pad the instruction to crowd out the precompile.
pub const MAX_QE_AUTH_DATA_LEN: usize = 256;

/// Parse `verify_tdx_qe_report`.
/// @spec SCC-TDX-001
pub fn parse_tdx_qe_report_args(rest: &[u8]) -> Result<VerifyTdxQeReportArgs<'_>, ProgramError> {
    let mut offset = 0usize;
    let attestation_pubkey_xy = read_array::<64>(rest, &mut offset)?;
    let pck_pubkey = read_array::<33>(rest, &mut offset)?;
    let gpu_rim_digest = read_array::<32>(rest, &mut offset)?;
    let model_digest = read_array::<32>(rest, &mut offset)?;
    let auth_len = u16::from_le_bytes(*read_array::<2>(rest, &mut offset)?) as usize;
    if auth_len > MAX_QE_AUTH_DATA_LEN {
        return Err(VerifierError::InvalidInstruction.into());
    }
    let end = offset.checked_add(auth_len).ok_or(VerifierError::InvalidInstruction)?;
    let qe_auth_data = rest.get(offset..end).ok_or(VerifierError::InvalidInstruction)?;
    if end != rest.len() {
        return Err(VerifierError::InvalidInstruction.into());
    }
    // A compressed SEC1 point starts 0x02 or 0x03. Rejecting anything else
    // here keeps a malformed key from reaching the allowlist comparison.
    if pck_pubkey[0] != 0x02 && pck_pubkey[0] != 0x03 {
        return Err(VerifierError::InvalidInstruction.into());
    }
    Ok(VerifyTdxQeReportArgs { attestation_pubkey_xy, pck_pubkey, gpu_rim_digest, model_digest, qe_auth_data })
}

/// `mode (1) || nonce_slot (8)`.
///
/// The quote body is the precompile's message and is read back from there.
///
/// Deliberately tiny. The 745-byte precompile instruction leaves almost no
/// room, so everything the handler can read from an account is read from one:
/// the challenge nonce comes from the challenge account, and the GPU RIM and
/// model digest from the session the QE step wrote.
/// @spec SCC-TDX-002
pub struct VerifyTdxQuoteArgs {
    pub mode: u8,
    pub nonce_slot: u64,
}

/// Exact length of the `verify_tdx_quote` payload after the discriminator.
pub const VERIFY_TDX_QUOTE_ARGS_LEN: usize = 1 + 8;

/// Parse `verify_tdx_quote`. The length must be exact.
/// @spec SCC-TDX-002
pub fn parse_tdx_quote_args(rest: &[u8]) -> Result<VerifyTdxQuoteArgs, ProgramError> {
    if rest.len() != VERIFY_TDX_QUOTE_ARGS_LEN {
        return Err(VerifierError::InvalidInstruction.into());
    }
    let mut offset = 0usize;
    let mode = read_array::<1>(rest, &mut offset)?[0];
    if mode != VERIFY_TDX_MODE_A {
        return Err(VerifierError::InvalidInstruction.into());
    }
    let nonce_slot = u64::from_le_bytes(*read_array::<8>(rest, &mut offset)?);
    Ok(VerifyTdxQuoteArgs { mode, nonce_slot })
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
