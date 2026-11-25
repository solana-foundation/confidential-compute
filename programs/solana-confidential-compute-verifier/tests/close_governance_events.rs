// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Rent cleanup closes emit `solana-confidential-compute:governance:v1` only after a successful close.
//! The new-state hash is SHA-256 of the closed account's empty data.
use borsh::BorshDeserialize;
use solana_confidential_compute_core::types::{AttestedSigner, EnclaveType, MeasurementDigest};
use solana_confidential_compute_verifier::{error::VerifierError, payload::*, processor::Processor, state::*};
use solana_program::program_stubs::{set_syscall_stubs, SyscallStubs};
use solana_program::{account_info::AccountInfo, hash::hashv, program_error::ProgramError, pubkey::Pubkey, sysvar};
use std::sync::{Arc, Mutex};

type Events = Vec<Vec<Vec<u8>>>;
static STUB_LOCK: Mutex<()> = Mutex::new(());
struct Logs(Arc<Mutex<Events>>);
impl SyscallStubs for Logs {
    fn sol_log_data(&self, fields: &[&[u8]]) {
        self.0.lock().unwrap().push(fields.iter().map(|x| x.to_vec()).collect());
    }
}
struct Guard(Option<Box<dyn SyscallStubs>>);
impl Drop for Guard {
    fn drop(&mut self) {
        set_syscall_stubs(self.0.take().unwrap());
    }
}

/// `AccountInfo::resize` reads the original length 4 bytes before the key.
#[repr(C)]
struct Key {
    original_len: u32,
    key: Pubkey,
}

/// `AccountInfo::resize` writes the serialized length 8 bytes before the data.
#[repr(C, align(8))]
struct Data<const N: usize> {
    len: u64,
    bytes: [u8; N],
}

fn key(key: Pubkey, len: usize) -> Key {
    Key { original_len: len as u32, key }
}

fn data<const N: usize>(bytes: &[u8]) -> Data<N> {
    Data { len: N as u64, bytes: bytes.try_into().unwrap() }
}

fn clock_data(slot: u64) -> Vec<u8> {
    let mut bytes = slot.to_le_bytes().to_vec();
    bytes.resize(40, 0);
    bytes
}

/// Runs one close; returns the result, the closed account's final data and
/// lamports, the actor's lamports and the logged events.
fn close<const N: usize>(
    logs: &Arc<Mutex<Events>>,
    ix: [u8; 8],
    program: &Pubkey,
    record: (&Key, &[u8], &Pubkey),
    actor: (&Key, bool),
    slot: u64,
) -> (Result<(), ProgramError>, Vec<u8>, u64, u64, Events) {
    close_at::<N>(logs, ix, program, record, actor, slot, 0)
}

fn close_at<const N: usize>(
    logs: &Arc<Mutex<Events>>,
    ix: [u8; 8],
    program: &Pubkey,
    record: (&Key, &[u8], &Pubkey),
    actor: (&Key, bool),
    slot: u64,
    unix: i64,
) -> (Result<(), ProgramError>, Vec<u8>, u64, u64, Events) {
    logs.lock().unwrap().clear();
    let mut buf: Data<N> = data(record.1);
    let (mut rl, mut al, mut cl) = (2_000_000, 1_000_000, 1);
    let mut ad = [];
    let mut cd = clock_data(slot);
    cd[32..40].copy_from_slice(&unix.to_le_bytes());
    let (clock_owner, system) = (sysvar::ID, Pubkey::default());
    let record_owner = *record.2;
    let accounts = [
        AccountInfo::new(&record.0.key, false, true, &mut rl, &mut buf.bytes, &record_owner, false),
        AccountInfo::new(&actor.0.key, actor.1, true, &mut al, &mut ad, &system, false),
        AccountInfo::new(&sysvar::clock::ID, false, false, &mut cl, &mut cd, &clock_owner, false),
    ];
    let result = Processor::process(program, &accounts, &ix);
    let remaining = accounts[0].try_borrow_data().unwrap().to_vec();
    drop(accounts);
    let events = std::mem::take(&mut *logs.lock().unwrap());
    (result, remaining, rl, al, events)
}

fn expected(operation: &[u8], actor: &Pubkey, account: &Pubkey, old: &[u8]) -> Events {
    vec![vec![
        b"solana-confidential-compute:governance:v1".to_vec(),
        operation.to_vec(),
        actor.to_bytes().to_vec(),
        account.to_bytes().to_vec(),
        hashv(&[old]).to_bytes().to_vec(),
        hashv(&[&[]]).to_bytes().to_vec(),
    ]]
}

#[test]
fn close_operations_emit_governance_events_only_on_success() {
    let _lock = STUB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let logs = Arc::new(Mutex::new(Vec::new()));
    let _guard = Guard(Some(set_syscall_stubs(Box::new(Logs(logs.clone())))));
    close_stale_nonce_events(&logs);
    close_attested_signer_events(&logs);
}

fn close_stale_nonce_events(logs: &Arc<Mutex<Events>>) {
    const N: usize = UsedNonceAccount::SIZE;
    let program = Pubkey::new_unique();
    let refund = key(Pubkey::new_unique(), 0);
    let wrong = key(Pubkey::new_unique(), 0);
    let nonce = key(Pubkey::new_unique(), N);
    let tombstone = borsh::to_vec(&UsedNonceAccount::new(500, 0).with_refund(refund.key.to_bytes())).unwrap();
    let foreign = Pubkey::new_unique();
    // Too fresh, wrong refund account, foreign owner: no close, no event.
    for (actor, slot, owner, error) in [
        (&refund, 650, &program, VerifierError::UnauthorizedPolicy.into()),
        (&wrong, 651, &program, VerifierError::InvalidAccountAddress.into()),
        (&refund, 651, &foreign, ProgramError::IllegalOwner),
    ] {
        let (result, remaining, rl, al, events) = close::<N>(
            logs,
            CLOSE_STALE_NONCE_DISCRIMINATOR,
            &program,
            (&nonce, &tombstone, owner),
            (actor, false),
            slot,
        );
        assert_eq!(result, Err(error));
        assert_eq!(remaining, tombstone);
        assert_eq!((rl, al), (2_000_000, 1_000_000));
        assert!(events.is_empty());
    }

    let (result, remaining, rl, al, events) = close::<N>(
        logs,
        CLOSE_STALE_NONCE_DISCRIMINATOR,
        &program,
        (&nonce, &tombstone, &program),
        (&refund, false),
        651,
    );
    assert_eq!(result, Ok(()));
    assert!(remaining.is_empty());
    assert_eq!((rl, al), (0, 3_000_000));
    assert_eq!(events, expected(b"close_stale_nonce", &refund.key, &nonce.key, &tombstone));
}

fn close_attested_signer_events(logs: &Arc<Mutex<Events>>) {
    const N: usize = AttestedSignerAccount::SIZE;
    let program = Pubkey::new_unique();
    let signer = key(Pubkey::new_unique(), 0);
    let (record_key, bump) = Pubkey::find_program_address(&[b"attested_signer_v2", signer.key.as_ref()], &program);
    let record = key(record_key, N);
    let mut account = AttestedSignerAccount::new(
        AttestedSigner {
            signer_pubkey: signer.key.to_bytes(),
            enclave_type: EnclaveType::AmdSevSnp,
            measurement: MeasurementDigest([7; 48]),
            chip_id_hash: [0; 32],
            tcb_version: 0,
            registered_slot: 20,
            expires_slot: 500,
        },
        bump,
    );
    account.expires_unix_timestamp = i64::MAX;
    let value = borsh::to_vec(&account).unwrap();
    // Unsigned or unexpired: no close, no event.
    for (signed, slot, error) in
        [(false, 501, ProgramError::MissingRequiredSignature), (true, 500, VerifierError::UnauthorizedPolicy.into())]
    {
        let (result, remaining, rl, al, events) = close::<N>(
            logs,
            CLOSE_ATTESTED_SIGNER_DISCRIMINATOR,
            &program,
            (&record, &value, &program),
            (&signer, signed),
            slot,
        );
        assert_eq!(result, Err(error));
        assert_eq!(remaining, value);
        assert_eq!((rl, al), (2_000_000, 1_000_000));
        assert!(events.is_empty());
    }

    let mut revoked = AttestedSignerAccount::try_from_slice(&value).unwrap();
    revoked.record.expires_slot = 0;
    for platform in [EnclaveType::AmdSevSnp, EnclaveType::AwsNitro, EnclaveType::GcpConfidentialSpace] {
        revoked.record.enclave_type = platform;
        // Tombstones survive both slot and Unix expiry, including legacy
        // records with a nonzero deadline and new zero-deadline revocations.
        for (slot, unix, deadline) in [(501, 0, i64::MAX), (100, 100, 100), (100, 100, 0), (0, 0, 0)] {
            revoked.expires_unix_timestamp = deadline;
            let bytes = borsh::to_vec(&revoked).unwrap();
            let (result, remaining, rl, al, events) = close_at::<N>(
                logs,
                CLOSE_ATTESTED_SIGNER_DISCRIMINATOR,
                &program,
                (&record, &bytes, &program),
                (&signer, true),
                slot,
                unix,
            );
            assert_eq!(result, Err(VerifierError::UnauthorizedPolicy.into()));
            assert_eq!(remaining, bytes);
            assert_eq!((rl, al), (2_000_000, 1_000_000));
            assert!(events.is_empty());
        }
    }

    let (result, remaining, rl, al, events) = close::<N>(
        logs,
        CLOSE_ATTESTED_SIGNER_DISCRIMINATOR,
        &program,
        (&record, &value, &program),
        (&signer, true),
        501,
    );
    assert_eq!(result, Ok(()));
    assert!(remaining.is_empty());
    assert_eq!((rl, al), (0, 3_000_000));
    assert_eq!(events, expected(b"close_attested_signer", &signer.key, &record_key, &value));

    // Issue #288 / R1: a revoked signer (expires_slot = 0) can NEVER be closed.
    let mut revoked_account = account.clone();
    revoked_account.record.expires_slot = 0;
    let revoked_value = borsh::to_vec(&revoked_account).unwrap();
    let (result, remaining, rl, al, events) = close::<N>(
        logs,
        CLOSE_ATTESTED_SIGNER_DISCRIMINATOR,
        &program,
        (&record, &revoked_value, &program),
        (&signer, true),
        501,
    );
    assert_eq!(result, Err(VerifierError::UnauthorizedPolicy.into()));
    assert_eq!(remaining, revoked_value);
    assert_eq!((rl, al), (2_000_000, 1_000_000));
    assert!(events.is_empty());
}

#[test]
fn unix_expiry_cleanup_boundaries() {
    let _lock = STUB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let logs = Arc::new(Mutex::new(Vec::new()));
    let _guard = Guard(Some(set_syscall_stubs(Box::new(Logs(logs.clone())))));
    let program = Pubkey::new_unique();
    let signer = key(Pubkey::new_unique(), 0);
    let (address, bump) = Pubkey::find_program_address(&[b"attested_signer_v2", signer.key.as_ref()], &program);
    let record = key(address, AttestedSignerAccount::SIZE);
    let mut value = AttestedSignerAccount::new(
        AttestedSigner {
            signer_pubkey: signer.key.to_bytes(),
            enclave_type: EnclaveType::AwsNitro,
            measurement: MeasurementDigest([7; 48]),
            chip_id_hash: [0; 32],
            tcb_version: 0,
            registered_slot: 20,
            expires_slot: 500,
        },
        bump,
    );
    value.expires_unix_timestamp = 100;
    let bytes = borsh::to_vec(&value).unwrap();
    for (signed, slot, unix, expected) in [
        (true, 100, 99, Err(VerifierError::UnauthorizedPolicy.into())),
        (true, 100, 100, Ok(())),
        (true, 100, 101, Ok(())),
        (true, 501, 99, Ok(())),
        (false, 100, 100, Err(ProgramError::MissingRequiredSignature)),
        (true, 501, -1, Err(VerifierError::InvalidInstruction.into())),
    ] {
        let (result, remaining, rl, al, events) = close_at::<{ AttestedSignerAccount::SIZE }>(
            &logs,
            CLOSE_ATTESTED_SIGNER_DISCRIMINATOR,
            &program,
            (&record, &bytes, &program),
            (&signer, signed),
            slot,
            unix,
        );
        assert_eq!(result, expected, "slot={slot} unix={unix} signed={signed}");
        if expected.is_err() {
            assert_eq!(remaining, bytes);
            assert_eq!((rl, al), (2_000_000, 1_000_000));
            assert!(events.is_empty());
        } else {
            assert!(remaining.is_empty());
            assert_eq!((rl, al), (0, 3_000_000));
        }
    }
}
