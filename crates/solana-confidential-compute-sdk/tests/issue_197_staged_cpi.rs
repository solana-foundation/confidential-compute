//! Native AccountInfo test of authentic Nitro -> minted V2 -> actual CPI checks.
//! The fixture's public workload key has no private key here: signer flags model
//! the runtime's signature check, not a real workload-signed hardware transaction.
//!
//! MIGRATION (solana 2.2 -> 4.x): NOT PORTED. This test is unrunnable, and the
//! path it covers is unreachable on-chain. It is kept, unaltered and ignored,
//! because the assertions still describe the intended Nitro Mode A contract.
//!
//! Why it cannot run natively: in 4.x `Clock::get()` resolves through
//! `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch is a hardcoded
//! `UNSUPPORTED_SYSVAR` that never consults `program_stubs`. A natively linked
//! program can no longer read any sysvar, and `stage_plan` dies on the very
//! first `BEGIN`. The `Stub`/`Restore` machinery below is dead code.
//!
//! Why it cannot be moved to SBF either: Nitro Mode A calls
//! `assert_workload_consent(accounts, &view.user_data)` (processor.rs), which
//! requires a *transaction signer* whose key equals the document's `user_data`.
//! In `fixtures/nitro_hardware_document.cose` that field is `0x55 x 32` (byte
//! 4355). No private key exists for it, and it is not a derivable PDA -- making
//! it one would be a SHA-256 preimage attack. A real runtime verifies
//! signatures, so the consume step can never be submitted.
//!
//! Why the fixture cannot be regenerated with a signable key, as issue_211 does
//! for its JWT: the JWT's issuer key is governance-registered and therefore
//! replaceable, but `verify_nitro_cert_chain` pins
//! `solana_confidential_compute_crypto::AWS_NITRO_ROOT_CA_PUBKEY_XY` (nitro.rs:30), a hardcoded
//! constant. Every accepted document must chain to the real AWS Nitro Root CA,
//! which we cannot sign under.
//!
//! And independently of all of the above: on SBF the backend is
//! `SolanaDefaultVerifier`, which performs no P-384 arithmetic. It introspects
//! `sysvar::instructions` for a preceding instruction to
//! `EXPECTED_SIGVERIFY_PROGRAM_ID` (ASCII `SECP384R1SIGVERIFY`) -- a program id
//! that is unassigned and deployed on no cluster. Nitro verification is
//! therefore fail-closed on-chain today regardless of the signing problem, and
//! stays that way until a secp384r1 precompile ships.
//!
//! Un-ignore when a secp384r1 precompile exists AND the fixture is replaced by
//! a document whose `user_data` is a keypair the test controls.
use solana_confidential_compute_sdk::staged::*;
use solana_confidential_compute_verifier::{
    processor::{transport::HEADER, Processor},
    state::{AttestedSignerAccount, BackendPolicy, PolicyRegistry, UsedNonceAccount, POLICY_REGISTRY_DISCRIMINATOR},
};
use solana_program::{
    account_info::AccountInfo,
    program_stubs::{set_syscall_stubs, SyscallStubs},
    sysvar,
};
use solana_sdk::{clock::Clock, pubkey::Pubkey};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
static SLOT: AtomicU64 = AtomicU64::new(520);
static UNIX: AtomicI64 = AtomicI64::new(1790375264);
struct Stub;
impl SyscallStubs for Stub {
    fn sol_get_clock_sysvar(&self, p: *mut u8) -> u64 {
        let c = current_clock();
        unsafe {
            std::ptr::copy_nonoverlapping((&c as *const Clock).cast::<u8>(), p, std::mem::size_of::<Clock>());
        }
        0
    }
}
struct Restore(Option<Box<dyn SyscallStubs>>);
impl Drop for Restore {
    fn drop(&mut self) {
        set_syscall_stubs(self.0.take().unwrap());
    }
}
fn current_clock() -> Clock {
    Clock { slot: SLOT.load(Ordering::SeqCst), unix_timestamp: UNIX.load(Ordering::SeqCst), ..Clock::default() }
}
fn account(key: Pubkey, owner: Pubkey, signer: bool, data: Vec<u8>) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        signer,
        true,
        Box::leak(Box::new(100000000)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
    )
}
fn run(
    pid: &Pubkey,
    ix: &solana_sdk::instruction::Instruction,
    accounts: &[AccountInfo],
) -> solana_program::entrypoint::ProgramResult {
    Processor::process(pid, accounts, &ix.data)
}
fn stage_plan(plan: &StagePlan, payer: &AccountInfo<'static>, payload_len: usize) -> AccountInfo<'static> {
    let pid = plan.begin.program_id;
    let stage = account(plan.address, pid, false, vec![0; HEADER + payload_len]);
    let pair = [payer.clone(), stage.clone()];
    run(&pid, &plan.begin, &pair).unwrap();
    for ix in &plan.uploads {
        run(&pid, ix, &pair).unwrap();
    }
    stage
}
fn set_time(clock: &AccountInfo, slot: u64, unix: i64) {
    SLOT.store(slot, Ordering::SeqCst);
    UNIX.store(unix, Ordering::SeqCst);
    clock.try_borrow_mut_data().unwrap().copy_from_slice(&bincode::serialize(&current_clock()).unwrap());
}
/// The slot hash signed inside the authentic document (CBOR `nonce` bstr).
fn signed_nonce(doc: &[u8]) -> [u8; 32] {
    let key = b"\x65nonce\x58\x20";
    let at = doc.windows(key.len()).position(|w| w == key).expect("fixture carries a 32-byte nonce") + key.len();
    doc[at..at + 32].try_into().unwrap()
}
#[test]
#[ignore = "unrunnable and unreachable on-chain; see the module header. (1) Natively, \
            solana 4.x `Clock::get()` always returns UNSUPPORTED_SYSVAR, so the staged \
            BEGIN fails immediately. (2) On SBF, Nitro Mode A requires a transaction \
            signer equal to the document's user_data, which is 0x55 x 32 at byte 4355 of \
            nitro_hardware_document.cose -- no private key, not a derivable PDA. (3) The \
            document cannot be regenerated: verify_nitro_cert_chain pins the real AWS \
            Nitro Root CA (nitro.rs:30). (4) Regardless, SolanaDefaultVerifier does no \
            P-384 and introspects for EXPECTED_SIGVERIFY_PROGRAM_ID (SECP384R1SIGVERIFY), \
            an unassigned program id deployed nowhere, so Nitro is fail-closed on every \
            cluster pending a secp384r1 precompile."]
fn real_nitro_staged_mode_a_mints_v2_and_preserves_cpi_boundaries() {
    let _restore = Restore(Some(set_syscall_stubs(Box::new(Stub))));
    SLOT.store(520, Ordering::SeqCst);
    UNIX.store(1790375264, Ordering::SeqCst);
    let pid = solana_confidential_compute_verifier::id();
    let doc = include_bytes!("../../../fixtures/nitro_hardware_document.cose");
    // Public claims in this authentic fixture; real crypto handler verifies every byte.
    let workload_key = Pubkey::new_from_array([0x55; 32]);
    let nonce = signed_nonce(doc);
    let pcr: [u8; 48] = [
        0x2a, 0x86, 0xe6, 0x10, 0x29, 0x83, 0x2f, 0xc6, 0x4b, 0x04, 0x7e, 0x72, 0x7b, 0x2f, 0x22, 0x65, 0xeb, 0x07,
        0x21, 0x5d, 0x07, 0x3c, 0xd4, 0x58, 0xbf, 0x6d, 0xeb, 0xf5, 0xe5, 0x57, 0xa4, 0x3a, 0x14, 0x69, 0x16, 0x54,
        0x60, 0x30, 0xcf, 0x5d, 0xd8, 0x39, 0x81, 0x75, 0xf8, 0x44, 0x1e, 0x66,
    ];
    let payer = account(Pubkey::new_unique(), solana_sdk_ids::system_program::ID, true, vec![]);
    let plan = build_staged_nitro_registration(pid, *payer.key, workload_key, 400, doc, nonce, 520, 650).unwrap();
    let stage = stage_plan(&plan, &payer, 53 + doc.len());
    let pair = [payer.clone(), stage.clone()];
    run(&pid, &plan.seal, &pair).unwrap();
    let (registry_key, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let mut registry = vec![0; PolicyRegistry::SIZE];
    registry[..8].copy_from_slice(&POLICY_REGISTRY_DISCRIMINATOR);
    registry[140..144].copy_from_slice(&1u32.to_le_bytes());
    registry[144..192].copy_from_slice(&pcr);
    registry[528] = bump;
    let registry = account(registry_key, pid, false, registry);
    let (signer_key, _) = Pubkey::find_program_address(
        &[solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED, workload_key.as_ref()],
        &pid,
    );
    let record = account(signer_key, pid, false, vec![0; AttestedSignerAccount::SIZE]);
    let (nonce_key, _) = Pubkey::find_program_address(&[b"nonce", &[2], workload_key.as_ref(), &nonce], &pid);
    let tombstone = account(nonce_key, pid, false, vec![0; UsedNonceAccount::SIZE]);
    let mut slots = 1u64.to_le_bytes().to_vec();
    slots.extend(400u64.to_le_bytes());
    slots.extend(nonce);
    let slots = account(sysvar::slot_hashes::ID, sysvar::ID, false, slots);
    let clock = account(sysvar::clock::ID, sysvar::ID, false, bincode::serialize(&current_clock()).unwrap());
    let system = account(solana_sdk_ids::system_program::ID, solana_sdk_ids::system_program::ID, false, vec![]);
    let workload = account(workload_key, solana_sdk_ids::system_program::ID, true, vec![]);
    let (backend_key, backend_bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[2]], &pid);
    let mut backend_bytes = vec![0; BackendPolicy::SIZE];
    backend_bytes[..8].copy_from_slice(&BackendPolicy::DISCRIMINATOR);
    backend_bytes[8] = 2;
    backend_bytes[9..13].copy_from_slice(&1u32.to_le_bytes());
    backend_bytes[13..61].copy_from_slice(&pcr);
    backend_bytes[397] = backend_bump;
    let backend = account(backend_key, pid, false, backend_bytes);
    let (legacy_key, _) = Pubkey::find_program_address(&[b"nonce", workload_key.as_ref(), &nonce], &pid);
    let legacy = account(legacy_key, solana_sdk_ids::system_program::ID, false, vec![]);
    let all = [
        payer.clone(),
        stage.clone(),
        payer.clone(),
        registry,
        record.clone(),
        tombstone.clone(),
        slots,
        clock.clone(),
        system,
        workload.clone(),
        backend,
        legacy,
    ];
    // Explicit B rejection happens before any handler nonce/signer writes.
    let mut b_payload = plan.uploads.iter().flat_map(|i| i.data[12..].iter().copied()).collect::<Vec<_>>();
    b_payload[8] = 1;
    let mut b_source = solana_sdk::instruction::Instruction {
        program_id: pid,
        accounts: plan.consume.accounts[2..].to_vec(),
        data: b_payload.clone(),
    };
    assert!(matches!(
        stage_nitro_registration(b_source.clone(), *payer.key, 520, 650),
        Err(StageError::UnsupportedInstruction)
    ));
    // Construct raw storage operations to exercise the program's independent gate.
    let digest = solana_sdk::hash::hash(&b_payload);
    let (bad_key, _) = Pubkey::find_program_address(&[b"attestation_stage", payer.key.as_ref(), digest.as_ref()], &pid);
    let bad = account(bad_key, pid, false, vec![0; HEADER + b_payload.len()]);
    let mut args = digest.to_bytes().to_vec();
    args.extend((b_payload.len() as u32).to_le_bytes());
    args.extend(650u64.to_le_bytes());
    let mut begin = BEGIN.to_vec();
    begin.extend(args);
    Processor::process(&pid, &[payer.clone(), bad.clone()], &begin).unwrap();
    for (i, c) in b_payload.chunks(MAX_CHUNK).enumerate() {
        let mut d = UPLOAD.to_vec();
        d.extend(((i * MAX_CHUNK) as u32).to_le_bytes());
        d.extend(c);
        Processor::process(&pid, &[payer.clone(), bad.clone()], &d).unwrap();
    }
    assert!(Processor::process(&pid, &[payer.clone(), bad.clone()], &SEAL).is_err());
    assert_eq!(bad.try_borrow_data().unwrap()[88], 0);
    assert!(tombstone.try_borrow_data().unwrap().iter().all(|b| *b == 0));
    assert!(record.try_borrow_data().unwrap().iter().all(|b| *b == 0));
    // Even a pre-existing sealed B state cannot enter the A handler.
    bad.try_borrow_mut_data().unwrap()[88] = 1;
    let mut sealed_b = all.clone();
    sealed_b[1] = bad.clone();
    assert!(run(&pid, &plan.consume, &sealed_b).is_err());
    assert!(tombstone.try_borrow_data().unwrap().iter().all(|b| *b == 0));
    assert!(record.try_borrow_data().unwrap().iter().all(|b| *b == 0));
    // The uploader cannot substitute for missing/mismatched workload consent.
    assert!(run(&pid, &plan.consume, &all[..9]).is_err());
    let mut unsigned = all.clone();
    unsigned[9].is_signer = false;
    assert!(run(&pid, &plan.consume, &unsigned).is_err());
    let mut wrong = all.clone();
    wrong[9] = account(Pubkey::new_unique(), solana_sdk_ids::system_program::ID, true, vec![]);
    assert!(run(&pid, &plan.consume, &wrong).is_err());
    assert_eq!(stage.try_borrow_data().unwrap()[88], 1);
    assert!(tombstone.try_borrow_data().unwrap().iter().all(|b| *b == 0));
    assert!(record.try_borrow_data().unwrap().iter().all(|b| *b == 0));
    // Stale nonce while the upload itself remains unexpired; no freshness bypass.
    set_time(&clock, 551, 1790375264);
    assert!(run(&pid, &plan.consume, &all).is_err());
    assert!(tombstone.try_borrow_data().unwrap().iter().all(|b| *b == 0));
    set_time(&clock, 520, 1790375264);
    // A valid chain and workload consent do not replace governed source policy.
    assert!(run(&pid, &plan.consume, &all[..10]).is_err());
    assert!(record.try_borrow_data().unwrap().iter().all(|b| *b == 0));
    assert!(run(&pid, &plan.consume, &all[..11]).is_err());
    assert!(record.try_borrow_data().unwrap().iter().all(|b| *b == 0));
    run(&pid, &plan.consume, &all).unwrap();
    assert_eq!(stage.try_borrow_data().unwrap()[88], 2);
    assert_eq!(record.data_len(), 154);
    use solana_confidential_compute_cpi::{assert_attestation_signer, AttestationPlatform};
    assert!(assert_attestation_signer(&record, &workload, &pcr, AttestationPlatform::AwsNitro).is_ok());
    assert!(assert_attestation_signer(&record, &workload, &pcr, AttestationPlatform::AmdSevSnp).is_err());
    assert!(assert_attestation_signer(&record, &unsigned[9], &pcr, AttestationPlatform::AwsNitro).is_err());
    assert!(assert_attestation_signer(&record, &wrong[9], &pcr, AttestationPlatform::AwsNitro).is_err());
    let expiry = i64::from_le_bytes(record.try_borrow_data().unwrap()[146..154].try_into().unwrap());
    set_time(&clock, 520, expiry);
    assert!(assert_attestation_signer(&record, &workload, &pcr, AttestationPlatform::AwsNitro).is_err());
    set_time(&clock, 520, -1);
    assert!(assert_attestation_signer(&record, &workload, &pcr, AttestationPlatform::AwsNitro).is_err());
    set_time(&clock, 520, 1790375264);
    assert!(run(&pid, &plan.consume, &all).is_err());
    // A new uploader and fresh stage cannot replay the already-used attestation.
    let second = account(Pubkey::new_unique(), solana_sdk_ids::system_program::ID, true, vec![]);
    let again = build_staged_nitro_registration(pid, *second.key, workload_key, 400, doc, nonce, 520, 650).unwrap();
    let second_stage = stage_plan(&again, &second, 53 + doc.len());
    run(&pid, &again.seal, &[second.clone(), second_stage.clone()]).unwrap();
    let mut replay = all.clone();
    replay[0] = second.clone();
    replay[1] = second_stage.clone();
    replay[2] = second;
    assert!(run(&pid, &again.consume, &replay).is_err());
    assert_eq!(second_stage.try_borrow_data().unwrap()[88], 1);
    // Literal payload tampering is still checked by actual COSE/chain verification.
    b_source.data[8] = 0;
    *b_source.data.last_mut().unwrap() ^= 1;
    let bad_plan = stage_nitro_registration(b_source, *payer.key, 520, 650).unwrap();
    let corrupt = stage_plan(&bad_plan, &payer, 53 + doc.len());
    run(&pid, &bad_plan.seal, &[payer.clone(), corrupt.clone()]).unwrap();
    let mut hostile = all.clone();
    hostile[1] = corrupt.clone();
    assert!(run(&pid, &bad_plan.consume, &hostile).is_err());
    assert_eq!(corrupt.try_borrow_data().unwrap()[88], 1);
}
