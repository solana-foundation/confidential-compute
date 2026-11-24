//! End-to-end coverage of the two Intel TDX instructions.
//!
//! The quote bytes come from the real fixture, so the measurements, the QE
//! report and the attestation key are Intel's. The signatures that the
//! precompile would check are not re-derived here -- the precompile is a
//! native program and does the actual curve work; these tests drive the
//! program's half, which is deciding *whose* key signed and *what* it means.
//!
//! The negative cases are the point. Each one removes exactly one link in the
//! chain and asserts the program refuses, because every one of them is a way
//! an attacker could get a signer admitted.
//!
//! @spec SCC-TDX-001 SCC-TDX-002

use borsh::BorshDeserialize;
use solana_confidential_compute_core::types::EnclaveType;
use solana_confidential_compute_verifier::error::VerifierError;
use solana_confidential_compute_verifier::payload::{
    TDX_ATTESTATION_SOURCE, VERIFY_TDX_MODE_A, VERIFY_TDX_QE_REPORT_DISCRIMINATOR, VERIFY_TDX_QUOTE_DISCRIMINATOR,
};
use solana_confidential_compute_verifier::processor::Processor;
use solana_confidential_compute_verifier::state::{
    AttestedSignerAccount, BackendPolicy, ChallengeAccount, TdxSessionAccount, UsedNonceAccount,
    ATTESTED_SIGNER_DISCRIMINATOR,
};
use solana_confidential_compute_verifier::tdx::{
    compress_p256, expected_report_data, qe_identity_digest, td_platform_digest, TdxQuote, SECP256R1_PROGRAM_ID,
};
use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use solana_program::sysvar::{clock, instructions};

const QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote_v4.bin");
const SLOT: u64 = 995;
const CLOCK_SLOT: u64 = 1_000;
const CHALLENGE_NONCE: [u8; 32] = [0x42; 32];
const SLOT_HASH: [u8; 32] = [0x77; 32];
const GPU_RIM: [u8; 32] = [0x33; 32];
const MODEL: [u8; 32] = [0x44; 32];
const PCK_PUBKEY: [u8; 33] = [0x02; 33];

fn account(key: Pubkey, owner: Pubkey, signer: bool, writable: bool, data: Vec<u8>) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        signer,
        writable,
        Box::leak(Box::new(10_000_000)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
    )
}

fn clock_data(slot: u64) -> Vec<u8> {
    let mut data = vec![0; 40];
    data[..8].copy_from_slice(&slot.to_le_bytes());
    data[32..].copy_from_slice(&1_700_000_000i64.to_le_bytes());
    data
}

fn precompile_data(pubkey: &[u8; 33], signature: &[u8; 64], message: &[u8]) -> Vec<u8> {
    let mut data = vec![1u8, 0];
    data.extend_from_slice(&49u16.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&16u16.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&113u16.to_le_bytes());
    data.extend_from_slice(&(message.len() as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    data
}

fn instructions_sysvar(ixs: &[(Pubkey, &[u8])], current_index: u16) -> AccountInfo<'static> {
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
    account(instructions::ID, solana_program::sysvar::ID, false, false, data)
}

fn policy(pid: &Pubkey, measurements: Vec<[u8; 48]>) -> AccountInfo<'static> {
    let (key, bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[TDX_ATTESTATION_SOURCE]], pid);
    let mut slots = [[0u8; 48]; 8];
    for (i, m) in measurements.iter().take(8).enumerate() {
        slots[i] = *m;
    }
    let record = BackendPolicy {
        discriminator: BackendPolicy::DISCRIMINATOR,
        source: TDX_ATTESTATION_SOURCE,
        measurement_count: measurements.len().min(8) as u32,
        measurements: slots,
        bump,
    };
    account(key, *pid, false, false, borsh::to_vec(&record).unwrap())
}

fn pad32(value: &[u8; 32]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..32].copy_from_slice(value);
    out
}

fn pad33(value: &[u8; 33]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..33].copy_from_slice(value);
    out
}

// ---------------------------------------------------------------- QE report

struct QeOpts {
    pck_on_policy: bool,
    tamper_attestation_key: bool,
    tamper_auth_data: bool,
    /// Have the precompile verify a key other than the one the arguments
    /// name. The named key is still the allowlisted one.
    precompile_key_differs: bool,
    qe_identity_on_policy: bool,
    debug_qe: bool,
}

impl Default for QeOpts {
    fn default() -> Self {
        Self {
            pck_on_policy: true,
            tamper_attestation_key: false,
            tamper_auth_data: false,
            precompile_key_differs: false,
            qe_identity_on_policy: true,
            debug_qe: false,
        }
    }
}

fn run_qe(opts: &QeOpts) -> (Pubkey, Result<(), ProgramError>, Vec<AccountInfo<'static>>) {
    let pid = Pubkey::new_unique();
    let quote = TdxQuote::parse(QUOTE).unwrap();

    let mut att_key = *quote.attestation_pubkey_xy();
    if opts.tamper_attestation_key {
        att_key[0] ^= 0x01;
    }
    let mut auth = quote.qe_auth_data().to_vec();
    if opts.tamper_auth_data {
        auth.push(0xff);
    }

    let mut rest = Vec::new();
    rest.extend_from_slice(&att_key);
    rest.extend_from_slice(&PCK_PUBKEY);
    rest.extend_from_slice(&GPU_RIM);
    rest.extend_from_slice(&MODEL);
    rest.extend_from_slice(&(auth.len() as u16).to_le_bytes());
    rest.extend_from_slice(&auth);
    let mut data = VERIFY_TDX_QE_REPORT_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&rest);

    let precompile_pck = if opts.precompile_key_differs {
        let mut other = PCK_PUBKEY;
        other[1] ^= 0x01;
        other
    } else {
        PCK_PUBKEY
    };
    let mut qe_report = quote.qe_report().to_vec();
    if opts.debug_qe {
        qe_report[48] |= 0x02; // SGX ATTRIBUTES.FLAGS DEBUG
    }
    let precompile = precompile_data(&precompile_pck, quote.qe_report_signature(), &qe_report);
    let sysvar = instructions_sysvar(&[(SECP256R1_PROGRAM_ID, &precompile), (pid, &data)], 1);

    let compressed = compress_p256(quote.attestation_pubkey_xy());
    let (session_key, _) =
        Pubkey::find_program_address(&[TdxSessionAccount::SEED, &TdxSessionAccount::seed_for(&compressed)], &pid);

    let mut measurements = Vec::new();
    if opts.pck_on_policy {
        measurements.push(pad33(&PCK_PUBKEY));
    } else {
        measurements.push(pad32(&[0x99; 32]));
    }
    if opts.qe_identity_on_policy {
        measurements.push(pad32(&qe_identity_digest(&qe_report).unwrap()));
    }

    let accounts = vec![
        account(session_key, pid, false, true, vec![0; TdxSessionAccount::SIZE]),
        policy(&pid, measurements),
        account(Pubkey::new_unique(), solana_sdk_ids::system_program::ID, true, true, vec![]),
        account(solana_sdk_ids::system_program::ID, solana_sdk_ids::system_program::ID, false, false, vec![]),
        account(clock::ID, solana_program::sysvar::ID, false, false, clock_data(CLOCK_SLOT)),
        sysvar,
    ];
    let result = Processor::process(&pid, &accounts, &data);
    (pid, result, accounts)
}

#[test]
fn a_genuine_qe_report_certifies_the_attestation_key() {
    let (_, result, accounts) = run_qe(&QeOpts::default());
    result.expect("a real QE report with an allowlisted PCK key must certify");

    let session = TdxSessionAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
    let quote = TdxQuote::parse(QUOTE).unwrap();
    assert_eq!(
        session.attestation_pubkey,
        compress_p256(quote.attestation_pubkey_xy()),
        "the session must name the key the QE report committed to"
    );
    assert_eq!(session.slot, CLOCK_SLOT);
}

/// Without the allowlist, a self-signed QE report certifies any key at all.
#[test]
fn an_unlisted_platform_key_certifies_nothing() {
    let (_, result, _) = run_qe(&QeOpts { pck_on_policy: false, ..QeOpts::default() });
    assert_eq!(result, Err(VerifierError::DisallowedMeasurement.into()));
}

/// The QE report commits to SHA-256(att_key || auth_data). Claiming a
/// different key breaks that commitment, which is the only thing tying a
/// signing key to platform-vouched hardware.
#[test]
fn a_substituted_attestation_key_is_refused() {
    let (_, result, _) = run_qe(&QeOpts { tamper_attestation_key: true, ..QeOpts::default() });
    assert_eq!(result, Err(VerifierError::InvalidSignature.into()));
}

/// The allowlist is checked against the key the *arguments* name, and the
/// precompile verified whatever key its own data carried. If those two are
/// not tied together, an attacker names any allowlisted platform key, has
/// the precompile verify a signature from a key they control, and both
/// checks pass over different keys.
#[test]
fn naming_an_allowlisted_key_the_precompile_did_not_verify_is_refused() {
    let (_, result, _) = run_qe(&QeOpts { precompile_key_differs: true, ..QeOpts::default() });
    assert_eq!(
        result,
        Err(VerifierError::InvalidSignature.into()),
        "the allowlisted key must be the one the precompile actually verified",
    );
}

/// The PCK key signs every enclave on its platform, not only the Quoting
/// Enclave. Checking it alone says "some enclave on an approved machine" --
/// an attacker running their own enclave there could certify any key.
#[test]
fn an_enclave_that_is_not_the_approved_qe_is_refused() {
    let (_, result, _) = run_qe(&QeOpts { qe_identity_on_policy: false, ..QeOpts::default() });
    assert_eq!(result, Err(VerifierError::DisallowedMeasurement.into()), "governance must pin which enclave is the QE",);
}

/// A debug enclave can be single-stepped and have its memory read, so a QE
/// in that state certifies whatever an attacker asks it to. Nothing else in
/// the quote distinguishes it from the production QE.
#[test]
fn a_debug_quoting_enclave_is_refused() {
    let (_, result, _) = run_qe(&QeOpts { debug_qe: true, ..QeOpts::default() });
    assert_eq!(result, Err(VerifierError::DisallowedMeasurement.into()));
}

#[test]
fn altered_auth_data_is_refused() {
    let (_, result, _) = run_qe(&QeOpts { tamper_auth_data: true, ..QeOpts::default() });
    assert_eq!(result, Err(VerifierError::InvalidSignature.into()));
}

// -------------------------------------------------------------- quote body

struct QuoteOpts {
    session_present: bool,
    session_slot: u64,
    session_key_matches: bool,
    measurements_on_policy: bool,
    gpu_rim_on_policy: bool,
    debug_td: bool,
    workload_signs: bool,
    correct_report_data: bool,
}

impl Default for QuoteOpts {
    fn default() -> Self {
        Self {
            session_present: true,
            session_slot: CLOCK_SLOT,
            session_key_matches: true,
            measurements_on_policy: true,
            gpu_rim_on_policy: true,
            debug_td: false,
            workload_signs: true,
            correct_report_data: true,
        }
    }
}

/// Build a quote body whose REPORTDATA binds `signer`, reusing the fixture's
/// real measurements so the allowlist checks exercise genuine Intel values.
fn body_for(signer: &Pubkey, correct: bool, debug_td: bool) -> Vec<u8> {
    let mut body = QUOTE[..632].to_vec();
    if debug_td {
        body[48 + 120] |= 0x01; // TD_ATTRIBUTES TUD.DEBUG
    }
    let report_data = if correct {
        expected_report_data(&signer.to_bytes(), &SLOT_HASH, &GPU_RIM, &MODEL, &CHALLENGE_NONCE)
    } else {
        [0u8; 64]
    };
    body[48 + 520..48 + 584].copy_from_slice(&report_data);
    body
}

fn run_quote(opts: &QuoteOpts) -> (Result<(), ProgramError>, Vec<AccountInfo<'static>>) {
    let (result, accounts, _data) = run_quote_replayable(opts);
    (result, accounts)
}

/// Same as [`run_quote`] but hands back the instruction data so a test can
/// submit the identical transaction a second time.
#[allow(clippy::type_complexity)]
fn run_quote_replayable(opts: &QuoteOpts) -> (Result<(), ProgramError>, Vec<AccountInfo<'static>>, Vec<u8>) {
    let pid = Pubkey::new_unique();
    let quote = TdxQuote::parse(QUOTE).unwrap();
    let workload = Pubkey::new_unique();
    let body = body_for(&workload, opts.correct_report_data, opts.debug_td);

    let attestation_key = compress_p256(quote.attestation_pubkey_xy());
    let precompile_key = if opts.session_key_matches {
        attestation_key
    } else {
        let mut other = attestation_key;
        other[1] ^= 0x01;
        other
    };
    let precompile = precompile_data(&precompile_key, quote.isv_signature(), &body);

    let mut rest = vec![VERIFY_TDX_MODE_A];
    rest.extend_from_slice(&SLOT.to_le_bytes());
    let mut data = VERIFY_TDX_QUOTE_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&rest);

    let sysvar = instructions_sysvar(&[(SECP256R1_PROGRAM_ID, &precompile), (pid, &data)], 1);

    // Session as the QE step would have left it.
    // The session is always written for the genuinely certified key. When
    // `session_key_matches` is false the precompile verifies a different key,
    // so the program derives a different session address and finds nothing --
    // which is the whole point: a key nobody certified must not be usable.
    let (session_key, session_bump) =
        Pubkey::find_program_address(&[TdxSessionAccount::SEED, &TdxSessionAccount::seed_for(&attestation_key)], &pid);
    let session_data = if opts.session_present {
        borsh::to_vec(&TdxSessionAccount {
            discriminator: TdxSessionAccount::DISCRIMINATOR,
            attestation_pubkey: attestation_key,
            qe_report_digest: [0u8; 32],
            gpu_rim_digest: GPU_RIM,
            model_digest: MODEL,
            slot: opts.session_slot,
            bump: session_bump,
        })
        .unwrap()
    } else {
        vec![0; TdxSessionAccount::SIZE]
    };

    let mut measurements = Vec::new();
    if opts.measurements_on_policy {
        // The policy carries one entry covering the whole TD measurement
        // tuple. Listing the three fields separately cannot work: this
        // fixture's MRCONFIGID and RTMRs are all-zero, and a zero
        // measurement is rejected before the list is even scanned.
        measurements.push(pad32(&td_platform_digest(&body[48..]).unwrap()));
    }
    if opts.gpu_rim_on_policy {
        measurements.push(pad32(&GPU_RIM));
    }

    let (challenge_key, challenge_bump) =
        Pubkey::find_program_address(&[ChallengeAccount::SEED, &[TDX_ATTESTATION_SOURCE], &CHALLENGE_NONCE], &pid);
    let challenge = ChallengeAccount {
        discriminator: ChallengeAccount::DISCRIMINATOR,
        source: TDX_ATTESTATION_SOURCE,
        challenge_slot: SLOT,
        slot_hash: SLOT_HASH,
        nonce: CHALLENGE_NONCE,
        expires_slot: CLOCK_SLOT + 1_000,
        bump: challenge_bump,
    };

    let (signer_pda, _) = Pubkey::find_program_address(&[b"attested_signer_v2", &workload.to_bytes()], &pid);
    let quote_body_digest = solana_program::hash::hashv(&[body.as_slice()]).to_bytes();
    let seed = solana_confidential_compute_verifier::payload::tdx_nonce_seed(
        &workload.to_bytes(),
        &quote_body_digest,
        &SLOT_HASH,
        &CHALLENGE_NONCE,
    );
    let (nonce_pda, _) = Pubkey::find_program_address(&[b"nonce", &[TDX_ATTESTATION_SOURCE], &seed], &pid);

    let accounts = vec![
        account(signer_pda, pid, false, true, vec![0; AttestedSignerAccount::SIZE]),
        account(session_key, pid, false, false, session_data),
        policy(&pid, measurements),
        account(nonce_pda, pid, false, true, vec![0; UsedNonceAccount::SIZE]),
        account(Pubkey::new_unique(), solana_sdk_ids::system_program::ID, true, true, vec![]),
        account(solana_sdk_ids::system_program::ID, solana_sdk_ids::system_program::ID, false, false, vec![]),
        account(clock::ID, solana_program::sysvar::ID, false, false, clock_data(CLOCK_SLOT)),
        // Writable: acceptance retires the challenge in place.
        account(challenge_key, pid, false, true, borsh::to_vec(&challenge).unwrap()),
        account(workload, pid, opts.workload_signs, false, vec![]),
        sysvar,
    ];
    let result = Processor::process(&pid, &accounts, &data);
    (result, accounts, data)
}

#[test]
fn a_certified_quote_admits_the_workload_signer() {
    let (result, accounts) = run_quote(&QuoteOpts::default());
    result.expect("a certified key signing a bound body must admit the signer");

    let record = AttestedSignerAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
    assert_eq!(record.discriminator, ATTESTED_SIGNER_DISCRIMINATOR);
    assert_eq!(record.record.enclave_type, EnclaveType::IntelTdx);
    assert_eq!(record.record.registered_slot, CLOCK_SLOT);
    assert!(record.record.expires_slot > CLOCK_SLOT);
    assert!(!record.is_revoked());
}

/// Without the QE step there is nothing saying this key belongs to real
/// hardware. The precompile will happily verify an attacker's own signature.
#[test]
fn a_quote_with_no_certified_session_is_refused() {
    let (result, _) = run_quote(&QuoteOpts { session_present: false, ..QuoteOpts::default() });
    assert!(result.is_err(), "an uncertified key must not admit a signer");
}

#[test]
fn a_session_for_a_different_key_is_refused() {
    let (result, _) = run_quote(&QuoteOpts { session_key_matches: false, ..QuoteOpts::default() });
    assert!(result.is_err());
}

/// A half-finished verification must not wait indefinitely for a quote body
/// chosen later.
#[test]
fn a_stale_session_is_refused() {
    let (result, _) = run_quote(&QuoteOpts {
        session_slot: CLOCK_SLOT.saturating_sub(TdxSessionAccount::TTL_SLOTS + 1),
        ..QuoteOpts::default()
    });
    assert_eq!(result, Err(VerifierError::StaleNonce.into()));
}

#[test]
fn unlisted_measurements_are_refused() {
    let (result, _) = run_quote(&QuoteOpts { measurements_on_policy: false, ..QuoteOpts::default() });
    assert_eq!(result, Err(VerifierError::DisallowedMeasurement.into()));
}

/// The GPU RIM rides in the same REPORTDATA, so one TDX quote covers the GPU
/// too -- but only if governance approved that RIM.
#[test]
fn an_unlisted_gpu_rim_is_refused() {
    let (result, _) = run_quote(&QuoteOpts { gpu_rim_on_policy: false, ..QuoteOpts::default() });
    assert_eq!(result, Err(VerifierError::DisallowedMeasurement.into()));
}

/// This is the binding the whole design rests on. A quote that does not name
/// the signer in REPORTDATA proves hardware ran *something*, not that it
/// vouched for this key.
#[test]
fn a_quote_that_does_not_bind_the_signer_is_refused() {
    let (result, _) = run_quote(&QuoteOpts { correct_report_data: false, ..QuoteOpts::default() });
    assert_eq!(result, Err(VerifierError::InvalidSignature.into()));
}

/// `TD_ATTRIBUTES.TUD.DEBUG` lets the host read and modify TD memory. A debug
/// TD carries the approved measurement and offers no protection at all, so
/// an attacker would boot the allowlisted image in debug mode and read the
/// workload's keys straight out of memory.
#[test]
fn a_debug_trust_domain_is_refused() {
    let (result, _) = run_quote(&QuoteOpts { debug_td: true, ..QuoteOpts::default() });
    assert_eq!(result, Err(VerifierError::DisallowedMeasurement.into()), "a debug TD must never be admitted",);
}

/// Mode A enrols a key into an account the holder is expected to control.
#[test]
fn an_unsigned_workload_key_cannot_be_enrolled() {
    let (result, _) = run_quote(&QuoteOpts { workload_signs: false, ..QuoteOpts::default() });
    assert_eq!(result, Err(ProgramError::MissingRequiredSignature));
}

/// Replaying the same quote must not mint a second registration.
#[test]
fn the_same_quote_cannot_be_consumed_twice() {
    let (result, accounts, data) = run_quote_replayable(&QuoteOpts::default());
    result.expect("first consumption");
    let pid = *accounts[0].owner;

    let nonce = UsedNonceAccount::try_from_slice(&accounts[3].data.borrow()).unwrap();
    assert_eq!(nonce.slot, CLOCK_SLOT, "the tombstone records the slot");

    // Submitting the identical instruction again must fail.
    assert!(Processor::process(&pid, &accounts, &data).is_err(), "the same signed quote was accepted twice");
}

/// Distinct nonces may pin the same slot hash. Refreshing the public QE
/// session must not let evidence accepted for A renew the signer through B.
#[test]
fn a_quote_cannot_be_replayed_against_another_challenge_with_the_same_hash() {
    let (result, mut accounts, data) = run_quote_replayable(&QuoteOpts::default());
    result.expect("first consumption against challenge A");
    let pid = *accounts[0].owner;
    let original_signer = accounts[0].data.borrow().to_vec();
    let challenge_a = ChallengeAccount::try_from_slice(&accounts[7].data.borrow()).unwrap();
    assert!(challenge_a.is_consumed());

    let nonce_b = [0x43; 32];
    let (challenge_b_key, _) =
        Pubkey::find_program_address(&[ChallengeAccount::SEED, &[TDX_ATTESTATION_SOURCE], &nonce_b], &pid);
    assert_ne!(*accounts[7].key, challenge_b_key);
    let issue_accounts = vec![
        account(challenge_b_key, pid, false, true, vec![0; ChallengeAccount::SIZE]),
        accounts[4].clone(),
        accounts[5].clone(),
        accounts[6].clone(),
        slot_hashes_sysvar(&[(SLOT, SLOT_HASH)]),
    ];
    let mut issue_data = solana_confidential_compute_verifier::payload::ISSUE_TDX_CHALLENGE_DISCRIMINATOR.to_vec();
    issue_data.extend_from_slice(&nonce_b);
    issue_data.extend_from_slice(&SLOT.to_le_bytes());
    Processor::process(&pid, &issue_accounts, &issue_data).expect("issue challenge B");
    let challenge_b = ChallengeAccount::try_from_slice(&issue_accounts[0].data.borrow()).unwrap();
    assert_ne!(challenge_a.nonce, challenge_b.nonce);
    assert_eq!(challenge_a.slot_hash, challenge_b.slot_hash);

    // Model a replayed QE report refreshing the certified session after its
    // original TTL. B is still live, and has its own empty used-nonce PDA.
    let replay_slot = CLOCK_SLOT + TdxSessionAccount::TTL_SLOTS + 1;
    assert!(challenge_b.is_live_at(replay_slot));
    let mut session = TdxSessionAccount::try_from_slice(&accounts[1].data.borrow()).unwrap();
    session.slot = replay_slot;
    accounts[1].data.borrow_mut().copy_from_slice(&borsh::to_vec(&session).unwrap());
    accounts[6].data.borrow_mut().copy_from_slice(&clock_data(replay_slot));

    let quote_body = body_for(accounts[8].key, true, false);
    let quote_digest = solana_program::hash::hashv(&[&quote_body]).to_bytes();
    let seed_b = solana_confidential_compute_verifier::payload::tdx_nonce_seed(
        &accounts[8].key.to_bytes(),
        &quote_digest,
        &SLOT_HASH,
        &nonce_b,
    );
    let (nonce_b_key, _) = Pubkey::find_program_address(&[b"nonce", &[TDX_ATTESTATION_SOURCE], &seed_b], &pid);
    assert_ne!(*accounts[3].key, nonce_b_key);
    accounts[3] = account(nonce_b_key, pid, false, true, vec![0; UsedNonceAccount::SIZE]);
    accounts[7] = issue_accounts[0].clone();
    let instructions_before = accounts[9].data.borrow().to_vec();

    assert_eq!(
        Processor::process(&pid, &accounts, &data),
        Err(VerifierError::InvalidSignature.into()),
        "the identical signed quote for A must not be accepted for B",
    );
    assert_eq!(*accounts[9].data.borrow(), instructions_before.as_slice());
    assert_eq!(*accounts[0].data.borrow(), original_signer.as_slice());
    assert!(accounts[3].data.borrow().iter().all(|byte| *byte == 0));
    assert!(!ChallengeAccount::try_from_slice(&accounts[7].data.borrow()).unwrap().is_consumed());
}

/// The replay that the nonce tombstone alone does not stop.
///
/// `UsedNonceAccount` is reclaimable 150 slots after consumption, but a TDX
/// challenge lives for 1,500. Inside that gap an attacker can have the
/// tombstone cleaned up permissionlessly, replay the public QE report to
/// refresh the session, and resubmit the same signed quote against a
/// challenge that is still live. Clearing the nonce PDA below is exactly what
/// `close_stale_nonce` leaves behind.
///
/// The challenge tombstone is what closes this, so this test fails if that
/// tombstone is ever removed.
#[test]
fn a_cleaned_up_nonce_does_not_reopen_a_spent_challenge() {
    let (result, accounts, data) = run_quote_replayable(&QuoteOpts::default());
    result.expect("first consumption");
    let pid = *accounts[0].owner;

    // Simulate permissionless cleanup: the nonce PDA is emptied.
    accounts[3].data.borrow_mut().fill(0);
    let challenge = ChallengeAccount::try_from_slice(&accounts[7].data.borrow()).expect("challenge decodes");
    assert!(challenge.is_consumed(), "acceptance must retire the challenge");
    assert!(!challenge.is_live_at(CLOCK_SLOT), "a consumed challenge is never live, even inside its original window");

    assert!(
        Processor::process(&pid, &accounts, &data).is_err(),
        "a spent challenge was reopened once the nonce tombstone was reclaimed"
    );
}

// ---------------------------------------------------------- challenge issuer

/// SlotHashes sysvar wire layout: `u64` count, then 40-byte `(slot, hash)`.
fn slot_hashes_sysvar(entries: &[(u64, [u8; 32])]) -> AccountInfo<'static> {
    let mut data = (entries.len() as u64).to_le_bytes().to_vec();
    for (slot, hash) in entries {
        data.extend_from_slice(&slot.to_le_bytes());
        data.extend_from_slice(hash);
    }
    account(solana_program::sysvar::slot_hashes::ID, solana_program::sysvar::ID, false, false, data)
}

/// Runs `issue_tdx_challenge` against an account in the given starting state.
fn run_issue(
    existing: Option<ChallengeAccount>,
    nonce_slot: u64,
    clock_slot: u64,
) -> (Result<(), ProgramError>, Vec<AccountInfo<'static>>) {
    let pid = Pubkey::new_unique();
    let (challenge_key, _bump) =
        Pubkey::find_program_address(&[ChallengeAccount::SEED, &[TDX_ATTESTATION_SOURCE], &CHALLENGE_NONCE], &pid);
    // Pre-allocated at the exact size so `create_pda_if_needed` takes the
    // no-CPI path; an all-zero buffer stands in for "never issued".
    let data = match existing {
        Some(record) => borsh::to_vec(&record).unwrap(),
        None => vec![0u8; ChallengeAccount::SIZE],
    };

    let mut ix = solana_confidential_compute_verifier::payload::ISSUE_TDX_CHALLENGE_DISCRIMINATOR.to_vec();
    ix.extend_from_slice(&CHALLENGE_NONCE);
    ix.extend_from_slice(&nonce_slot.to_le_bytes());

    let accounts = vec![
        account(challenge_key, pid, false, true, data),
        account(Pubkey::new_unique(), pid, true, true, vec![]),
        account(solana_sdk_ids::system_program::ID, solana_sdk_ids::system_program::ID, false, false, vec![]),
        account(clock::ID, solana_program::sysvar::ID, false, false, clock_data(clock_slot)),
        slot_hashes_sysvar(&[(nonce_slot, SLOT_HASH)]),
    ];
    let result = Processor::process(&pid, &accounts, &ix);
    (result, accounts)
}

/// The path that did not exist: a challenge created from an uninitialized
/// account, with the slot hash taken from the sysvar rather than the caller.
#[test]
fn a_challenge_can_be_issued_from_an_uninitialized_account() {
    let (result, accounts) = run_issue(None, SLOT, CLOCK_SLOT);
    result.expect("issuing a challenge must succeed");

    let record = ChallengeAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
    assert_eq!(record.discriminator, ChallengeAccount::DISCRIMINATOR);
    assert_eq!(record.source, TDX_ATTESTATION_SOURCE);
    assert_eq!(record.nonce, CHALLENGE_NONCE);
    assert_eq!(record.challenge_slot, SLOT);
    assert_eq!(record.slot_hash, SLOT_HASH, "the hash must come from the sysvar, not from the caller");
    assert_eq!(record.expires_slot, CLOCK_SLOT + ChallengeAccount::TTL_SLOTS, "expiry is bounded by TTL_SLOTS");
    assert!(record.is_live_at(CLOCK_SLOT));
    assert!(!record.is_live_at(record.expires_slot + 1));
}

/// A slot outside the sysvar's window has no hash to pin.
#[test]
fn a_challenge_cannot_pin_a_slot_hash_that_is_too_old() {
    let (result, _) = run_issue(None, 10, 10_000);
    assert_eq!(result, Err(VerifierError::StaleNonce.into()));
}

/// Reissuing over a live challenge would extend it without bound.
#[test]
fn a_live_challenge_cannot_be_reissued() {
    let live = ChallengeAccount {
        discriminator: ChallengeAccount::DISCRIMINATOR,
        source: TDX_ATTESTATION_SOURCE,
        challenge_slot: SLOT,
        slot_hash: SLOT_HASH,
        nonce: CHALLENGE_NONCE,
        expires_slot: CLOCK_SLOT + 10,
        bump: 0,
    };
    let (result, _) = run_issue(Some(live), SLOT, CLOCK_SLOT);
    assert_eq!(result, Err(VerifierError::StaleNonce.into()));
}

/// A spent challenge must stay spent; reissuing it would undo the tombstone
/// that stops the cleanup replay.
#[test]
fn a_consumed_challenge_cannot_be_reissued() {
    let spent = ChallengeAccount {
        discriminator: ChallengeAccount::DISCRIMINATOR,
        source: TDX_ATTESTATION_SOURCE,
        challenge_slot: SLOT,
        slot_hash: SLOT_HASH,
        nonce: CHALLENGE_NONCE,
        expires_slot: 0,
        bump: 0,
    };
    assert!(spent.is_consumed());
    let (result, _) = run_issue(Some(spent), SLOT, CLOCK_SLOT);
    assert_eq!(result, Err(VerifierError::StaleNonce.into()));
}

/// Step one is permissionless, so it must not be able to rewrite a live
/// session's bindings.
///
/// The QE report and the PCK signature over it both travel in the public
/// quote, so anyone can replay step one. Without a guard, an observer who
/// sees a pending step two front-runs it with a step one for the same
/// attestation key carrying different GPU and model digests. Step two then
/// recomputes `expected_report_data` from the rewritten session, it no longer
/// matches the signed REPORTDATA, and the honest enrolment fails. Free,
/// repeatable denial of service on every enrolment.
#[test]
fn a_live_session_cannot_have_its_digests_rewritten() {
    let (pid, first, accounts) = run_qe(&QeOpts::default());
    first.expect("the first step one must succeed");

    let session = TdxSessionAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
    assert_eq!(session.gpu_rim_digest, GPU_RIM);
    assert!(session.is_live_at(CLOCK_SLOT), "the session is live");

    // Same key, same QE report, different bindings.
    let quote = TdxQuote::parse(QUOTE).unwrap();
    let mut rest = Vec::new();
    rest.extend_from_slice(quote.attestation_pubkey_xy());
    rest.extend_from_slice(&PCK_PUBKEY);
    rest.extend_from_slice(&[0xee; 32]); // attacker's GPU digest
    rest.extend_from_slice(&[0xdd; 32]); // attacker's model digest
    rest.extend_from_slice(&(quote.qe_auth_data().len() as u16).to_le_bytes());
    rest.extend_from_slice(quote.qe_auth_data());
    let mut data = VERIFY_TDX_QE_REPORT_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&rest);

    let result = Processor::process(&pid, &accounts, &data);
    assert!(result.is_err(), "a live session's bindings were rewritten");

    let after = TdxSessionAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
    assert_eq!(after.gpu_rim_digest, GPU_RIM, "the stored GPU digest must be untouched");
    assert_eq!(after.model_digest, MODEL, "the stored model digest must be untouched");
}

/// An honest retry after a dropped transaction still works.
#[test]
fn replaying_step_one_with_the_same_bindings_is_allowed() {
    let (pid, first, accounts) = run_qe(&QeOpts::default());
    first.expect("first");

    let quote = TdxQuote::parse(QUOTE).unwrap();
    let mut rest = Vec::new();
    rest.extend_from_slice(quote.attestation_pubkey_xy());
    rest.extend_from_slice(&PCK_PUBKEY);
    rest.extend_from_slice(&GPU_RIM);
    rest.extend_from_slice(&MODEL);
    rest.extend_from_slice(&(quote.qe_auth_data().len() as u16).to_le_bytes());
    rest.extend_from_slice(quote.qe_auth_data());
    let mut data = VERIFY_TDX_QE_REPORT_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&rest);

    Processor::process(&pid, &accounts, &data).expect("an identical retry must be accepted");
}
