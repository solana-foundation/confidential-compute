// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Regression for #213: a native accepting verifier cannot authorize a forged
//! Nitro workload identity without that workload signing. No SBF/hardware claim.
#![allow(deprecated)]
use borsh::BorshDeserialize;
use solana_confidential_compute_verifier::{
    error::VerifierError,
    payload::{VerifyNitroAttestationArgs, VERIFY_NITRO_ATTESTATION_DISCRIMINATOR, VERIFY_NITRO_MODE_A},
    state::{AttestedSignerAccount, PolicyRegistry, UsedNonceAccount, POLICY_REGISTRY_DISCRIMINATOR},
    DirectCryptoVerifier, MockVerifier,
};
use solana_program::{
    account_info::AccountInfo,
    hash::Hash,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::{clock, slot_hashes},
};
#[path = "common/legacy_nonce.rs"]
mod legacy_nonce_fixture;
use legacy_nonce_fixture::TestProcessor as Processor;
const VICTIM: [u8; 32] = [0x99; 32];
const SLOT: u64 = 520;
const NONCE_SLOT: u64 = 500;
// Certificate validity instant from the committed fixture's existing crypto test.
const UNIX_TIME: i64 = 1_790_375_400;
fn account(key: Pubkey, owner: Pubkey, signer: bool, writable: bool, data: Vec<u8>) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        signer,
        writable,
        Box::leak(Box::new(1000)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
    )
}
fn replace_claim(document: &mut [u8], key: &[u8], value: [u8; 32]) {
    let positions: Vec<_> =
        document.windows(key.len()).enumerate().filter_map(|(i, w)| (w == key).then_some(i)).collect();
    assert_eq!(positions.len(), 1, "fixture field must be unambiguous");
    let offset = positions[0] + key.len();
    assert_eq!(&document[offset..offset + 2], &[0x58, 0x20]);
    document[offset + 2..offset + 34].copy_from_slice(&value);
}
fn forged_document(nonce: [u8; 32]) -> Vec<u8> {
    // Mutating signed claims invalidates the genuine fixture signature. This is
    // intentionally a forgery, never described as a fresh hardware attestation.
    let mut document = include_bytes!("../../../fixtures/nitro_hardware_document.cose").to_vec();
    replace_claim(&mut document, b"\x69user_data", VICTIM);
    replace_claim(&mut document, b"\x65nonce", nonce);
    let (_, view) = solana_confidential_compute_crypto::parse_nitro_attestation(&document).unwrap();
    assert_eq!(view.user_data, VICTIM);
    assert_eq!(view.nonce, nonce);
    document
}
fn instruction(document: Vec<u8>) -> Vec<u8> {
    let mut ix = VERIFY_NITRO_ATTESTATION_DISCRIMINATOR.to_vec();
    ix.extend(
        borsh::to_vec(&VerifyNitroAttestationArgs {
            mode: VERIFY_NITRO_MODE_A,
            nonce_slot: NONCE_SLOT,
            expected_action_hash: [0; 32],
            document,
        })
        .unwrap(),
    );
    ix
}
fn fixture(document: &[u8]) -> (Pubkey, Vec<AccountInfo<'static>>) {
    let pid = Pubkey::new_unique();
    let (_, view) = solana_confidential_compute_crypto::parse_nitro_attestation(document).unwrap();
    // The recent slot hash is the document's own nonce, so freshness passes and
    // rejection can only come from the consent/signature checks under test.
    let slot_hash = view.nonce;
    let (registry, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (record, _) = Pubkey::find_program_address(&[b"attested_signer_v2", &VICTIM], &pid);
    let (nonce, _) = Pubkey::find_program_address(&[b"nonce", &[2], &VICTIM, &slot_hash], &pid);
    let mut measurements = [[0; 48]; 8];
    measurements[0] = view.pcrs.pcr0;
    let policy = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: Pubkey::new_unique().to_bytes(),
        ark_pubkey_xy: [1; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 1,
        measurements,
        bump,
    };
    let mut clock_data = vec![0; 40];
    clock_data[..8].copy_from_slice(&SLOT.to_le_bytes());
    clock_data[32..40].copy_from_slice(&UNIX_TIME.to_le_bytes());
    let mut hashes = vec![0; 48];
    hashes[..8].copy_from_slice(&1u64.to_le_bytes());
    hashes[8..16].copy_from_slice(&NONCE_SLOT.to_le_bytes());
    hashes[16..48].copy_from_slice(&slot_hash);
    let sys = solana_sdk_ids::system_program::ID;
    (
        pid,
        vec![
            account(Pubkey::new_unique(), sys, true, true, vec![]),
            account(registry, pid, false, false, borsh::to_vec(&policy).unwrap()),
            account(record, pid, false, true, vec![0; AttestedSignerAccount::SIZE]),
            account(nonce, pid, false, true, vec![0; UsedNonceAccount::SIZE]),
            account(slot_hashes::ID, solana_program::sysvar::ID, false, false, hashes),
            account(clock::ID, solana_program::sysvar::ID, false, false, clock_data),
            account(sys, sys, false, false, vec![]),
        ],
    )
}
#[test]
fn forged_registration_requires_consent_before_writes_even_with_accepting_crypto() {
    let slot_hash = Hash::new_unique().to_bytes();
    let doc = forged_document(slot_hash);
    let (pid, mut accounts) = fixture(&doc);
    let ix = instruction(doc);
    let empty_record = accounts[2].try_borrow_data().unwrap().to_vec();
    let empty_nonce = accounts[3].try_borrow_data().unwrap().to_vec();
    assert!(Processor::process_with(&DirectCryptoVerifier, &pid, &accounts, &ix).is_err());
    assert_eq!(accounts[2].try_borrow_data().unwrap().to_vec(), empty_record);
    assert_eq!(accounts[3].try_borrow_data().unwrap().to_vec(), empty_nonce);
    let verifier = MockVerifier::succeeding();
    assert_eq!(Processor::process_with(&verifier, &pid, &accounts, &ix), Err(VerifierError::SignerMismatch.into()));
    assert_eq!(accounts[2].try_borrow_data().unwrap().to_vec(), empty_record);
    assert_eq!(accounts[3].try_borrow_data().unwrap().to_vec(), empty_nonce);
    accounts.push(account(Pubkey::new_from_array(VICTIM), pid, false, false, vec![]));
    assert_eq!(Processor::process_with(&verifier, &pid, &accounts, &ix), Err(ProgramError::MissingRequiredSignature));
    assert_eq!(accounts[2].try_borrow_data().unwrap().to_vec(), empty_record);
    assert_eq!(accounts[3].try_borrow_data().unwrap().to_vec(), empty_nonce);
    accounts.last_mut().unwrap().is_signer = true;
    assert_eq!(Processor::process_with(&verifier, &pid, &accounts, &ix), Ok(()));
    let saved = AttestedSignerAccount::try_from_slice(&accounts[2].try_borrow_data().unwrap()).unwrap();
    assert_eq!(saved.record.signer_pubkey, VICTIM);
    assert_eq!(Processor::process_with(&verifier, &pid, &accounts, &ix), Err(VerifierError::NonceAlreadyUsed.into()));
    // Narrow the audit's TTL-squat claim: same-source registration is refreshable
    // before expiry if the authorized workload supplies a fresh nonce.
    let fresh = Hash::new_unique().to_bytes();
    assert_ne!(fresh, slot_hash);
    let fresh_ix = instruction(forged_document(fresh));
    accounts[4].try_borrow_mut_data().unwrap()[16..48].copy_from_slice(&fresh);
    let (fresh_nonce, _) = Pubkey::find_program_address(&[b"nonce", &[2], &VICTIM, &fresh], &pid);
    accounts[3] = account(fresh_nonce, pid, false, true, vec![0; UsedNonceAccount::SIZE]);
    assert_eq!(Processor::process_with(&verifier, &pid, &accounts, &fresh_ix), Ok(()));
}
