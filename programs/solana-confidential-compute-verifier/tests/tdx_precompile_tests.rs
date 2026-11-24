//! Binding checks for the secp256r1 precompile.
//!
//! The precompile runs before the program and aborts the transaction when a
//! signature does not verify, so finding a matching instruction is equivalent
//! to the signature being valid. Everything here is about the other half:
//! proving the instruction the precompile checked is the one carrying *our*
//! bytes.
//!
//! These are the tests that matter most in this crate. `assert_secp256r1_verified`
//! is the only thing standing between a quote and a forged attestation, and a
//! bug in it fails open -- the program would accept a signature nothing
//! verified.
//!
//! @spec SCC-TDX-001

use solana_confidential_compute_verifier::error::VerifierError;
use solana_confidential_compute_verifier::tdx::{assert_secp256r1_verified, SECP256R1_PROGRAM_ID};
use solana_program::instruction::AccountMeta;
use solana_program::pubkey::Pubkey;
use solana_program::sysvar::instructions;

const PUBKEY: [u8; 33] = [0x02; 33];
const SIGNATURE: [u8; 64] = [0x44; 64];

fn message() -> Vec<u8> {
    (0..632u16).map(|i| (i % 251) as u8).collect()
}

/// Lay out instruction data exactly as `solana_secp256r1_program`'s builder
/// does: `num_signatures`, a pad byte, 14 bytes of offsets, then pubkey,
/// signature and message at offsets 16 / 49 / 113.
fn precompile_data(
    pubkey: &[u8; 33],
    signature: &[u8; 64],
    message: &[u8],
    instruction_index: u16,
    num_signatures: u8,
) -> Vec<u8> {
    let mut data = vec![num_signatures, 0];
    data.extend_from_slice(&49u16.to_le_bytes()); // signature_offset
    data.extend_from_slice(&instruction_index.to_le_bytes());
    data.extend_from_slice(&16u16.to_le_bytes()); // public_key_offset
    data.extend_from_slice(&instruction_index.to_le_bytes());
    data.extend_from_slice(&113u16.to_le_bytes()); // message_data_offset
    data.extend_from_slice(&(message.len() as u16).to_le_bytes());
    data.extend_from_slice(&instruction_index.to_le_bytes());
    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    data
}

fn canonical(message: &[u8]) -> Vec<u8> {
    precompile_data(&PUBKEY, &SIGNATURE, message, u16::MAX, 1)
}

fn serialize_instructions(ixs: &[(Pubkey, &[u8])], current_index: u16) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&(ixs.len() as u16).to_le_bytes());
    let offsets_at = data.len();
    data.extend(vec![0u8; ixs.len() * 2]);
    for (i, (program_id, ix_data)) in ixs.iter().enumerate() {
        let offset = data.len() as u16;
        let start = offsets_at + i * 2;
        data[start..start + 2].copy_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // zero accounts
        data.extend_from_slice(program_id.as_ref());
        data.extend_from_slice(&(ix_data.len() as u16).to_le_bytes());
        data.extend_from_slice(ix_data);
    }
    data.extend_from_slice(&current_index.to_le_bytes());
    data
}

/// Run the binding check with `ixs` preceding our instruction.
fn check_with(
    ixs: &[(Pubkey, &[u8])],
    message: &[u8],
) -> Result<(), solana_program::program_error::ProgramError> {
    let current_index = ixs.len() as u16;
    let mut all: Vec<(Pubkey, &[u8])> = ixs.to_vec();
    all.push((Pubkey::new_unique(), &[]));
    let sysvar_data = serialize_instructions(&all, current_index);

    let key = instructions::ID;
    let owner = solana_program::sysvar::ID;
    let mut lamports = 0u64;
    let mut data = sysvar_data;
    let account = solana_program::account_info::AccountInfo::new(
        &key,
        false,
        false,
        &mut lamports,
        &mut data,
        &owner,
        false,
    );
    assert_secp256r1_verified(&account, &PUBKEY, message, &SIGNATURE)
}

#[test]
fn a_canonical_precompile_instruction_is_accepted() {
    let message = message();
    let data = canonical(&message);
    check_with(&[(SECP256R1_PROGRAM_ID, &data)], &message)
        .expect("a correctly formed precompile instruction must bind");
}

/// A caller may legitimately prepend a compute-budget instruction, so the
/// scan must not assume the precompile sits at index 0. Automata's
/// equivalent hardcodes index 0 and cannot batch.
#[test]
fn the_precompile_may_sit_behind_other_instructions() {
    let message = message();
    let data = canonical(&message);
    let filler = Pubkey::new_unique();
    check_with(
        &[(filler, &[1, 2, 3]), (SECP256R1_PROGRAM_ID, &data)],
        &message,
    )
    .expect("a prepended instruction must not break the scan");
}

/// THE test. `Secp256r1SignatureOffsets` carries three `*_instruction_index`
/// fields; when one is not `u16::MAX`, the precompile resolves that region
/// against a *different* instruction in the transaction.
///
/// An attacker puts their own valid (pubkey, signature, message) triple in
/// instruction N at the same offsets, points the indexes at N, and places the
/// quote's bytes in the precompile instruction's own data. The precompile
/// verifies the attacker's triple and succeeds. A program that only
/// byte-compares the regions -- which is what Automata's
/// `verify_secp256r1_program_instruction_fields` does -- then compares
/// against quote bytes nothing ever verified, and also succeeds.
///
/// Rejecting any index other than `u16::MAX` is what closes that.
#[test]
fn an_instruction_index_pointing_elsewhere_is_rejected() {
    let message = message();
    for redirected in [0u16, 1, 2, 7] {
        let data = precompile_data(&PUBKEY, &SIGNATURE, &message, redirected, 1);
        let result = check_with(&[(SECP256R1_PROGRAM_ID, &data)], &message);
        assert_eq!(
            result,
            Err(VerifierError::InvalidSignature.into()),
            "index {redirected} redirects the verified region and must be refused",
        );
    }
}

/// Only one of the three indexes needs to be redirected for the attack to
/// work, so each must be checked on its own.
#[test]
fn redirecting_any_single_index_is_rejected() {
    let message = message();
    for field in 0..3 {
        let mut data = canonical(&message);
        // offsets block: sig_off, sig_idx, pk_off, pk_idx, msg_off, msg_len, msg_idx
        let index_at = match field {
            0 => 4,  // signature_instruction_index
            1 => 8,  // public_key_instruction_index
            _ => 14, // message_instruction_index
        };
        data[index_at..index_at + 2].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            check_with(&[(SECP256R1_PROGRAM_ID, &data)], &message),
            Err(VerifierError::InvalidSignature.into()),
            "redirecting field {field} alone must be refused",
        );
    }
}

#[test]
fn an_instruction_from_another_program_does_not_count() {
    let message = message();
    let data = canonical(&message);
    let impostor = Pubkey::new_unique();
    assert_eq!(
        check_with(&[(impostor, &data)], &message),
        Err(VerifierError::InvalidSignature.into()),
    );
}

/// Byte-comparing the regions is only meaningful if they are the values the
/// program derived from the quote.
#[test]
fn mismatched_material_is_rejected() {
    let message = message();

    let mut other_pubkey = PUBKEY;
    other_pubkey[1] ^= 0xff;
    let data = precompile_data(&other_pubkey, &SIGNATURE, &message, u16::MAX, 1);
    assert_eq!(
        check_with(&[(SECP256R1_PROGRAM_ID, &data)], &message),
        Err(VerifierError::InvalidSignature.into()),
        "a different public key must not bind",
    );

    let mut other_signature = SIGNATURE;
    other_signature[0] ^= 0xff;
    let data = precompile_data(&PUBKEY, &other_signature, &message, u16::MAX, 1);
    assert_eq!(
        check_with(&[(SECP256R1_PROGRAM_ID, &data)], &message),
        Err(VerifierError::InvalidSignature.into()),
        "a different signature must not bind",
    );

    let mut other_message = message.clone();
    other_message[100] ^= 0xff;
    let data = precompile_data(&PUBKEY, &SIGNATURE, &other_message, u16::MAX, 1);
    assert_eq!(
        check_with(&[(SECP256R1_PROGRAM_ID, &data)], &message),
        Err(VerifierError::InvalidSignature.into()),
        "a different message must not bind",
    );
}

/// Extra bytes past the canonical length could carry a second, unchecked
/// region, so the length is pinned exactly rather than as a minimum.
#[test]
fn a_non_canonical_length_is_rejected() {
    let message = message();

    let mut padded = canonical(&message);
    padded.push(0);
    assert_eq!(
        check_with(&[(SECP256R1_PROGRAM_ID, &padded)], &message),
        Err(VerifierError::InvalidSignature.into()),
        "trailing bytes must be refused",
    );

    let mut truncated = canonical(&message);
    truncated.pop();
    assert_eq!(
        check_with(&[(SECP256R1_PROGRAM_ID, &truncated)], &message),
        Err(VerifierError::InvalidSignature.into()),
        "a short instruction must be refused",
    );
}

/// The length check is what makes the fixed-offset slicing safe.
///
/// `ix.data[16..49]`, `[49..113]` and `[113..]` are unchecked slices. Any
/// instruction attributed to the precompile program that is shorter than 113
/// bytes would panic them, and a panic inside a Solana program is an abort,
/// not a rejected instruction. An attacker needs nothing but the ability to
/// add a short instruction to the transaction.
///
/// A mutation sweep found this: deleting the length check still passed the
/// trailing-byte and one-byte-short cases, because the message comparison
/// catches those on its own. Only a genuinely short instruction isolates it.
#[test]
fn an_instruction_too_short_to_slice_is_rejected_not_panicked() {
    let message = message();
    for len in [0usize, 1, 2, 15, 16, 48, 49, 112] {
        let data = vec![1u8; len];
        assert_eq!(
            check_with(&[(SECP256R1_PROGRAM_ID, &data)], &message),
            Err(VerifierError::InvalidSignature.into()),
            "a {len}-byte instruction must be refused rather than panic the program",
        );
    }
}

/// The precompile supports batching. A second signature would occupy regions
/// this check never looks at, so anything but exactly one is refused.
#[test]
fn more_than_one_declared_signature_is_rejected() {
    let message = message();
    for count in [0u8, 2, 255] {
        let data = precompile_data(&PUBKEY, &SIGNATURE, &message, u16::MAX, count);
        assert_eq!(
            check_with(&[(SECP256R1_PROGRAM_ID, &data)], &message),
            Err(VerifierError::InvalidSignature.into()),
            "num_signatures = {count} must be refused",
        );
    }
}

/// Trusting attacker-supplied offsets would let the declared regions point at
/// bytes other than the ones the canonical layout places there.
#[test]
fn non_canonical_offsets_are_rejected() {
    let message = message();
    for (name, at, value) in [
        ("signature_offset", 2usize, 50u16),
        ("public_key_offset", 6, 17),
        ("message_data_offset", 10, 114),
    ] {
        let mut data = canonical(&message);
        data[at..at + 2].copy_from_slice(&value.to_le_bytes());
        assert_eq!(
            check_with(&[(SECP256R1_PROGRAM_ID, &data)], &message),
            Err(VerifierError::InvalidSignature.into()),
            "a shifted {name} must be refused",
        );
    }
}

/// A declared size shorter than the message would leave the tail unverified.
#[test]
fn a_short_declared_message_size_is_rejected() {
    let message = message();
    let mut data = canonical(&message);
    data[12..14].copy_from_slice(&((message.len() - 1) as u16).to_le_bytes());
    assert_eq!(
        check_with(&[(SECP256R1_PROGRAM_ID, &data)], &message),
        Err(VerifierError::InvalidSignature.into()),
    );
}

#[test]
fn no_preceding_instruction_means_nothing_was_verified() {
    let message = message();
    assert_eq!(
        check_with(&[], &message),
        Err(VerifierError::InvalidInstruction.into()),
        "at index 0 there is nothing before us to have verified anything",
    );
}

/// The precompile instruction takes no accounts. One that does is not the
/// instruction the runtime verified.
#[test]
fn an_instruction_carrying_accounts_is_rejected() {
    let message = message();
    let data = canonical(&message);

    // Hand-roll a sysvar blob with one account on the precompile instruction.
    let mut blob = Vec::new();
    blob.extend_from_slice(&2u16.to_le_bytes());
    let offsets_at = blob.len();
    blob.extend(vec![0u8; 4]);

    let offset = blob.len() as u16;
    blob[offsets_at..offsets_at + 2].copy_from_slice(&offset.to_le_bytes());
    blob.extend_from_slice(&1u16.to_le_bytes()); // one account
    let meta = AccountMeta::new_readonly(Pubkey::new_unique(), false);
    blob.push(0); // flags: not signer, not writable
    blob.extend_from_slice(meta.pubkey.as_ref());
    blob.extend_from_slice(SECP256R1_PROGRAM_ID.as_ref());
    blob.extend_from_slice(&(data.len() as u16).to_le_bytes());
    blob.extend_from_slice(&data);

    let offset = blob.len() as u16;
    blob[offsets_at + 2..offsets_at + 4].copy_from_slice(&offset.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(Pubkey::new_unique().as_ref());
    blob.extend_from_slice(&0u16.to_le_bytes());

    blob.extend_from_slice(&1u16.to_le_bytes()); // current index

    let key = instructions::ID;
    let owner = solana_program::sysvar::ID;
    let mut lamports = 0u64;
    let account = solana_program::account_info::AccountInfo::new(
        &key,
        false,
        false,
        &mut lamports,
        &mut blob,
        &owner,
        false,
    );
    assert_eq!(
        assert_secp256r1_verified(&account, &PUBKEY, &message, &SIGNATURE),
        Err(VerifierError::InvalidSignature.into()),
    );
}

/// Reading the wrong account would let a caller supply their own "sysvar".
#[test]
fn an_account_that_is_not_the_instructions_sysvar_is_rejected() {
    let message = message();
    let data = canonical(&message);
    let blob = serialize_instructions(
        &[(SECP256R1_PROGRAM_ID, &data), (Pubkey::new_unique(), &[])],
        1,
    );

    let key = Pubkey::new_unique();
    let owner = solana_program::sysvar::ID;
    let mut lamports = 0u64;
    let mut bytes = blob;
    let account = solana_program::account_info::AccountInfo::new(
        &key,
        false,
        false,
        &mut lamports,
        &mut bytes,
        &owner,
        false,
    );
    assert_eq!(
        assert_secp256r1_verified(&account, &PUBKEY, &message, &SIGNATURE),
        Err(solana_program::program_error::ProgramError::IncorrectProgramId),
    );
}
