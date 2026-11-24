//! On-chain AWS Nitro Enclaves attestation processor tests.
//!
//! @spec SCC-NITRO-006 SCC-NITRO-007 SCC-NITRO-008

#[path = "support/registration_events.rs"]
mod registration_events;

#[path = "../../../crates/solana-confidential-compute-crypto/tests/support/nitro_cert.rs"]
mod cert_fixture;
use borsh::{BorshDeserialize, BorshSerialize};
use cert_fixture::{standard_cert, standard_cert_until};
use p384::ecdsa::signature::hazmat::PrehashSigner;
use p384::ecdsa::SigningKey;
use sha2::{Digest, Sha384};
use solana_confidential_compute_core::types::{compute_action_commitment, EnclaveType};
use solana_confidential_compute_core::SignatureVerifier;
use solana_confidential_compute_verifier::error::VerifierError;
use solana_confidential_compute_verifier::payload::{
    VerifyNitroAttestationArgs, VERIFY_NITRO_ATTESTATION_DISCRIMINATOR, VERIFY_NITRO_MODE_A,
    VERIFY_NITRO_MODE_B,
};
use solana_program::entrypoint::ProgramResult;
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    program_stubs::{set_syscall_stubs, SyscallStubs},
    pubkey::Pubkey,
    sysvar::{clock, instructions, slot_hashes},
};
#[allow(deprecated)]
use solana_sdk_ids::system_program;
#[path = "common/legacy_nonce.rs"]
mod legacy_nonce_fixture;
use legacy_nonce_fixture::TestProcessor as Processor;
use solana_confidential_compute_verifier::state::{
    AttestedSignerAccount, PolicyRegistry, UsedNonceAccount, ATTESTED_SIGNER_DISCRIMINATOR,
    POLICY_REGISTRY_DISCRIMINATOR, USED_NONCE_DISCRIMINATOR,
};
use solana_confidential_compute_verifier::DirectCryptoVerifier;

/// Registry AMD root that must not authorize a Nitro document.
const UNRELATED_AMD_ARK: [u8; 96] = [0xAB; 96];

const NONCE_SLOT: u64 = 500;
const CURRENT_SLOT: u64 = 520;
const UNIX_NOW: i64 = 1_800_000_000;
const ATTESTATION_TTL_SLOTS: u64 = 216_000;
// A fresh simulated ledger hash per process; every document, fake SlotHashes
// entry, PDA and replay assertion below shares it. This is not an ECDSA nonce.
static SLOT_HASH: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
    use p384::elliptic_curve::rand_core::{OsRng, RngCore};
    let mut hash = [0; 32];
    OsRng.fill_bytes(&mut hash);
    hash
});
const PCR0: [u8; 48] = [0x42; 48];
const USER_DATA: [u8; 32] = [0x99; 32];

fn keypair(seed_lsb: u8) -> (SigningKey, [u8; 96]) {
    let mut seed = [0u8; 48];
    seed[47] = seed_lsb;
    let signing_key = SigningKey::from_slice(&seed).expect("valid scalar");
    let encoded = signing_key.verifying_key().to_encoded_point(false);
    let mut xy = [0u8; 96];
    xy[..48].copy_from_slice(encoded.x().unwrap().as_slice());
    xy[48..].copy_from_slice(encoded.y().unwrap().as_slice());
    (signing_key, xy)
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

fn cbor_uint(n: u64) -> Vec<u8> {
    if n <= 23 {
        vec![n as u8]
    } else if n <= 0xff {
        vec![0x18, n as u8]
    } else if n <= 0xffff {
        let b = (n as u16).to_be_bytes();
        vec![0x19, b[0], b[1]]
    } else if n <= 0xffff_ffff {
        let b = (n as u32).to_be_bytes();
        vec![0x1a, b[0], b[1], b[2], b[3]]
    } else {
        let b = n.to_be_bytes();
        let mut v = vec![0x1b];
        v.extend_from_slice(&b);
        v
    }
}

fn cbor_bstr(b: &[u8]) -> Vec<u8> {
    let mut out = cbor_header(2, b.len());
    out.extend_from_slice(b);
    out
}

fn cbor_tstr(s: &str) -> Vec<u8> {
    let mut out = cbor_header(3, s.len());
    out.extend_from_slice(s.as_bytes());
    out
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

struct NitroKeys {
    root_xy: [u8; 96],
    leaf_sk: SigningKey,
    root_cert: Vec<u8>,
    inter_cert: Vec<u8>,
    leaf_cert: Vec<u8>,
}

fn synthetic_nitro_keys() -> NitroKeys {
    let (root_sk, root_xy) = keypair(0x31);
    let (inter_sk, inter_xy) = keypair(0x32);
    let (leaf_sk, leaf_xy) = keypair(0x33);
    NitroKeys {
        root_xy,
        leaf_sk,
        root_cert: standard_cert(&root_xy, &root_sk, b"root", b"root", true),
        inter_cert: standard_cert(&inter_xy, &root_sk, b"root", b"inter", true),
        leaf_cert: standard_cert_until(
            &leaf_xy,
            &inter_sk,
            b"inter",
            b"leaf",
            false,
            b"270115080001Z",
        ),
    }
}

fn nitro_keys() -> NitroKeys {
    let (root_sk, _synthetic_root) = keypair(0x31);
    let (inter_sk, inter_xy) = keypair(0x32);
    let (leaf_sk, leaf_xy) = keypair(0x33);
    let aws_root = solana_confidential_compute_crypto::AWS_NITRO_ROOT_CA_PUBKEY_XY;
    NitroKeys {
        root_xy: aws_root,
        leaf_sk,
        root_cert: standard_cert(&aws_root, &root_sk, b"root", b"root", true),
        // The intermediate is not signed by the AWS root private key. Unit tests
        // accept that one link through `AwsRootTestVerifier`. Production
        // `DirectCryptoVerifier` still requires a real AWS signature.
        inter_cert: standard_cert(&inter_xy, &root_sk, b"root", b"inter", true),
        leaf_cert: standard_cert_until(
            &leaf_xy,
            &inter_sk,
            b"inter",
            b"leaf",
            false,
            b"270115080001Z",
        ),
    }
}

/// Accepts the pinned AWS root link so instruction tests can run without the
/// AWS Nitro Root CA private key. Every other key is checked with real P-384.
struct AwsRootTestVerifier;

impl SignatureVerifier for AwsRootTestVerifier {
    fn verify_p384(
        &self,
        public_key_xy: &[u8; 96],
        message_digest: &[u8; 48],
        signature_rs: &[u8; 96],
        instructions_sysvar: Option<&solana_program::account_info::AccountInfo>,
    ) -> ProgramResult {
        if public_key_xy == &solana_confidential_compute_crypto::AWS_NITRO_ROOT_CA_PUBKEY_XY {
            return Ok(());
        }
        SignatureVerifier::verify_p384(
            &DirectCryptoVerifier,
            public_key_xy,
            message_digest,
            signature_rs,
            instructions_sysvar,
        )
    }
}

fn process_nitro(
    program_id: &solana_program::pubkey::Pubkey,
    accounts: &[solana_program::account_info::AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    Processor::process_with(&AwsRootTestVerifier, program_id, accounts, instruction_data)
}

fn encode_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    cbor_array(&[
        cbor_tstr("Signature1"),
        cbor_bstr(protected),
        cbor_bstr(b""),
        cbor_bstr(payload),
    ])
}

fn nitro_document(
    keys: &NitroKeys,
    pcr0: [u8; 48],
    user_data: [u8; 32],
    nonce: [u8; 32],
) -> Vec<u8> {
    let pcrs = cbor_map_int(&[
        (0, cbor_bstr(&pcr0)),
        (1, cbor_bstr(&[1u8; 48])),
        (2, cbor_bstr(&[2u8; 48])),
        (8, cbor_bstr(&[8u8; 48])),
    ]);
    let cabundle = cbor_array(&[cbor_bstr(&keys.root_cert), cbor_bstr(&keys.inter_cert)]);
    let payload = cbor_map_text(&[
        ("module_id", cbor_tstr("i-teton-nitro-0")),
        ("timestamp", cbor_uint(UNIX_NOW as u64 * 1000)),
        ("digest", cbor_tstr("SHA384")),
        ("pcrs", pcrs),
        ("certificate", cbor_bstr(&keys.leaf_cert)),
        ("cabundle", cabundle),
        ("user_data", cbor_bstr(&user_data)),
        ("nonce", cbor_bstr(&nonce)),
    ]);
    let protected = vec![0xa1, 0x01, 0x38, 0x22];
    let encoded = encode_sig_structure(&protected, &payload);
    let mut hasher = Sha384::new();
    hasher.update(&encoded);
    let hash: [u8; 48] = hasher.finalize().into();
    let (signature, _) = keys.leaf_sk.sign_prehash(&hash).expect("sign");
    let mut sig = [0u8; 96];
    sig.copy_from_slice(signature.to_bytes().as_slice());
    let mut doc = vec![0xd2];
    doc.extend_from_slice(&cbor_array(&[
        cbor_bstr(&protected),
        vec![0xa0],
        cbor_bstr(&payload),
        cbor_bstr(&sig),
    ]));
    doc
}

fn verify_ix(mode: u8, nonce_slot: u64, action_hash: [u8; 32], document: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&VERIFY_NITRO_ATTESTATION_DISCRIMINATOR);
    VerifyNitroAttestationArgs {
        mode,
        nonce_slot,
        expected_action_hash: action_hash,
        document: document.to_vec(),
    }
    .serialize(&mut data)
    .unwrap();
    data
}

fn registry_bytes(authority: [u8; 32], ark: [u8; 96], bump: u8, pcr0: [u8; 48]) -> Vec<u8> {
    let mut measurements = [[0u8; 48]; 8];
    measurements[0] = pcr0;
    let registry = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority,
        ark_pubkey_xy: ark,
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 1,
        measurements,
        bump,
    };
    let mut data = vec![0u8; PolicyRegistry::SIZE];
    registry.serialize(&mut &mut data[..]).unwrap();
    data
}

fn clock_bytes(slot: u64, unix_timestamp: i64) -> Vec<u8> {
    let mut data = vec![0u8; 40];
    data[0..8].copy_from_slice(&slot.to_le_bytes());
    data[32..40].copy_from_slice(&unix_timestamp.to_le_bytes());
    data
}

fn slot_hashes_bytes(nonce_slot: u64, hash: &[u8; 32]) -> Vec<u8> {
    let mut data = vec![0u8; 8 + 40];
    data[0..8].copy_from_slice(&1u64.to_le_bytes());
    data[8..16].copy_from_slice(&nonce_slot.to_le_bytes());
    data[16..48].copy_from_slice(hash);
    data
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
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(program_id.as_ref());
        data.extend_from_slice(&(ix_data.len() as u16).to_le_bytes());
        data.extend_from_slice(ix_data);
    }
    data.extend_from_slice(&current_index.to_le_bytes());
    data
}

struct ClockSyscallStub {
    slot: u64,
    unix_timestamp: i64,
}

impl SyscallStubs for ClockSyscallStub {
    fn sol_log_data(&self, fields: &[&[u8]]) {
        registration_events::record(fields);
    }
    fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
        let clock = Clock {
            slot: self.slot,
            epoch_start_timestamp: 0,
            epoch: 0,
            leader_schedule_epoch: 0,
            unix_timestamp: self.unix_timestamp,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&clock as *const Clock).cast::<u8>(),
                var_addr,
                core::mem::size_of::<Clock>(),
            );
        }
        0
    }
}

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct SyscallGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prev: Option<Box<dyn SyscallStubs>>,
}

impl SyscallGuard {
    fn install(slot: u64, unix_timestamp: i64) -> Self {
        let lock = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        registration_events::clear();
        let prev = set_syscall_stubs(Box::new(ClockSyscallStub {
            slot,
            unix_timestamp,
        }));
        Self {
            _lock: lock,
            prev: Some(prev),
        }
    }
}

impl Drop for SyscallGuard {
    fn drop(&mut self) {
        if let Some(prev) = self.prev.take() {
            set_syscall_stubs(prev);
        }
    }
}

fn system_program_account<'a>(
    key: &'a Pubkey,
    lamports: &'a mut u64,
    data: &'a mut [u8],
) -> AccountInfo<'a> {
    AccountInfo::new(key, false, false, lamports, data, key, false)
}

#[test]
fn test_verify_nitro_mode_a_registers_aws_nitro_signer() {
    nitro_registration_case(false);
    nitro_registration_case(true);
}

fn nitro_registration_case(renewal: bool) {
    let _clock = SyscallGuard::install(CURRENT_SLOT, UNIX_NOW);
    let keys = nitro_keys();
    let doc = nitro_document(&keys, PCR0, USER_DATA, *SLOT_HASH);
    let pid = Pubkey::new_unique();
    let payer_key = Pubkey::new_unique();
    let authority_key = Pubkey::new_unique();
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (signer_pda, _) = Pubkey::find_program_address(&[b"attested_signer_v2", &USER_DATA], &pid);
    let (nonce_pda, _) =
        Pubkey::find_program_address(&[b"nonce", &[2], &USER_DATA, &*SLOT_HASH], &pid);

    let mut registry_data = registry_bytes(
        authority_key.to_bytes(),
        UNRELATED_AMD_ARK,
        registry_bump,
        PCR0,
    );
    let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
    let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
    let mut clock_data = clock_bytes(CURRENT_SLOT, UNIX_NOW);
    let mut sh_data = slot_hashes_bytes(NONCE_SLOT, &SLOT_HASH);
    let mut payer_lamports = 1000;
    let mut payer_data = vec![];
    let mut reg_lamports = 1000;
    let mut signer_lamports = 1000;
    let mut nonce_lamports = 1000;
    let mut clock_lamports = 1000;
    let mut sh_lamports = 1000;
    let sys_key = system_program::ID;
    let mut sys_lamports = 1;
    let mut sys_data = vec![];
    let clock_key = clock::ID;
    let sh_key = slot_hashes::ID;

    let payer_acc = AccountInfo::new(
        &payer_key,
        true,
        true,
        &mut payer_lamports,
        &mut payer_data,
        &pid,
        false,
    );
    let registry_acc = AccountInfo::new(
        &registry_pda,
        false,
        false,
        &mut reg_lamports,
        &mut registry_data,
        &pid,
        false,
    );
    let signer_acc = AccountInfo::new(
        &signer_pda,
        false,
        true,
        &mut signer_lamports,
        &mut signer_data,
        &pid,
        false,
    );
    let nonce_acc = AccountInfo::new(
        &nonce_pda,
        false,
        true,
        &mut nonce_lamports,
        &mut nonce_data,
        &pid,
        false,
    );
    let sh_acc = AccountInfo::new(
        &sh_key,
        false,
        false,
        &mut sh_lamports,
        &mut sh_data,
        &solana_program::sysvar::ID,
        false,
    );
    let clock_acc = AccountInfo::new(
        &clock_key,
        false,
        false,
        &mut clock_lamports,
        &mut clock_data,
        &solana_program::sysvar::ID,
        false,
    );
    let sys_acc = system_program_account(&sys_key, &mut sys_lamports, &mut sys_data);

    let ix = verify_ix(VERIFY_NITRO_MODE_A, NONCE_SLOT, [0u8; 32], &doc);
    let workload_key = Pubkey::new_from_array(USER_DATA);
    let mut workload_lamports = 1;
    let mut workload_data = [];
    let workload_acc = AccountInfo::new(
        &workload_key,
        true,
        false,
        &mut workload_lamports,
        &mut workload_data,
        &pid,
        false,
    );
    let mut accounts = vec![
        payer_acc,
        registry_acc,
        signer_acc,
        nonce_acc,
        sh_acc,
        clock_acc,
        sys_acc,
        workload_acc,
    ];
    if renewal {
        let existing = AttestedSignerAccount::new(
            solana_confidential_compute_core::types::AttestedSigner {
                signer_pubkey: USER_DATA,
                enclave_type: EnclaveType::AwsNitro,
                measurement: solana_confidential_compute_core::types::MeasurementDigest::new(PCR0),
                chip_id_hash: [0; 32],
                tcb_version: 0,
                registered_slot: CURRENT_SLOT - 1,
                expires_slot: CURRENT_SLOT + 1,
            },
            Pubkey::find_program_address(&[b"attested_signer_v2", &USER_DATA], &pid).1,
        );
        existing
            .serialize(&mut &mut accounts[2].try_borrow_mut_data().unwrap()[..])
            .unwrap();
    }
    let signer_before = accounts[2].try_borrow_data().unwrap().to_vec();
    let nonce_before = accounts[3].try_borrow_data().unwrap().to_vec();
    accounts[7].is_signer = false;
    assert_eq!(
        process_nitro(&pid, &accounts, &ix),
        Err(solana_program::program_error::ProgramError::MissingRequiredSignature)
    );
    let workload = accounts.pop().unwrap();
    assert_eq!(
        process_nitro(&pid, &accounts, &ix),
        Err(VerifierError::SignerMismatch.into())
    );
    assert_eq!(*accounts[2].try_borrow_data().unwrap(), signer_before);
    assert_eq!(*accounts[3].try_borrow_data().unwrap(), nonce_before);
    accounts.push(workload);
    accounts[7].is_signer = true;
    // The root edge is mocked explicitly; all descendant signatures are real.
    // Malformed signed paths must fail before signer/nonce writes.
    let (root_sk, _) = keypair(0x31);
    let (_, inter_xy) = keypair(0x32);
    for (label, extensions, issuer_name) in [
        ("extensionless", vec![], cert_fixture::name(b"root")),
        (
            "non-CA",
            cert_fixture::constraints(false, None, 128),
            cert_fixture::name(b"root"),
        ),
        (
            "no keyCertSign",
            cert_fixture::constraints(true, None, 128),
            cert_fixture::name(b"root"),
        ),
        (
            "issuer mismatch",
            cert_fixture::constraints(true, None, 4),
            cert_fixture::name(b"wrong"),
        ),
    ] {
        let mut malformed = nitro_keys();
        malformed.inter_cert = cert_fixture::encode_cert(
            &inter_xy,
            &root_sk,
            &issuer_name,
            &cert_fixture::name(b"inter"),
            &extensions,
        );
        let bad_doc = nitro_document(&malformed, PCR0, USER_DATA, *SLOT_HASH);
        let bad_ix = verify_ix(VERIFY_NITRO_MODE_A, NONCE_SLOT, [0; 32], &bad_doc);
        assert!(process_nitro(&pid, &accounts, &bad_ix).is_err(), "{label}");
        assert_eq!(
            *accounts[2].try_borrow_data().unwrap(),
            signer_before,
            "{label}"
        );
        assert_eq!(
            *accounts[3].try_borrow_data().unwrap(),
            nonce_before,
            "{label}"
        );
        registration_events::assert_empty();
    }
    let mut revoked = AttestedSignerAccount::new(
        solana_confidential_compute_core::types::AttestedSigner {
            signer_pubkey: USER_DATA,
            enclave_type: EnclaveType::AwsNitro,
            measurement: solana_confidential_compute_core::types::MeasurementDigest::new(PCR0),
            chip_id_hash: [0; 32],
            tcb_version: 0,
            registered_slot: 0,
            expires_slot: 0,
        },
        Pubkey::find_program_address(&[b"attested_signer_v2", &USER_DATA], &pid).1,
    );
    revoked.expires_unix_timestamp = 86_400;
    revoked
        .serialize(&mut &mut accounts[2].try_borrow_mut_data().unwrap()[..])
        .unwrap();
    assert_eq!(
        process_nitro(&pid, &accounts, &ix),
        Err(VerifierError::UnauthorizedPolicy.into())
    );
    assert_eq!(
        AttestedSignerAccount::try_from_slice(&accounts[2].try_borrow_data().unwrap()).unwrap(),
        revoked
    );
    // Native harness does not provide transaction rollback of nonce writes.
    accounts[3]
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&nonce_before);
    accounts[2]
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&signer_before);
    let res = process_nitro(&pid, &accounts, &ix);
    assert_eq!(res, Ok(()));
    registration_events::assert_event(b"register_signer", b"aws_nitro", &USER_DATA, &accounts[2]);

    let saved =
        AttestedSignerAccount::try_from_slice(&accounts[2].try_borrow_data().unwrap()).unwrap();
    assert_eq!(saved.discriminator, ATTESTED_SIGNER_DISCRIMINATOR);
    assert_eq!(saved.record.signer_pubkey, USER_DATA);
    assert_eq!(saved.record.enclave_type, EnclaveType::AwsNitro);
    assert_eq!(saved.record.measurement.0, PCR0);
    assert_eq!(saved.record.registered_slot, CURRENT_SLOT);
    assert_eq!(saved.expires_unix_timestamp, UNIX_NOW + 1);
    assert_eq!(
        saved.record.expires_slot,
        CURRENT_SLOT + ATTESTATION_TTL_SLOTS
    );

    let saved_nonce =
        UsedNonceAccount::try_from_slice(&accounts[3].try_borrow_data().unwrap()).unwrap();
    assert_eq!(saved_nonce.discriminator, USED_NONCE_DISCRIMINATOR);
    assert_eq!(saved_nonce.slot, CURRENT_SLOT);

    let replay = process_nitro(&pid, &accounts, &ix);
    assert_eq!(replay, Err(VerifierError::NonceAlreadyUsed.into()));
    registration_events::assert_empty();
}

#[test]
fn test_verify_nitro_rejects_unknown_pcr0() {
    let _clock = SyscallGuard::install(CURRENT_SLOT, UNIX_NOW);
    let keys = nitro_keys();
    let pid = Pubkey::new_unique();
    let payer_key = Pubkey::new_unique();
    let authority_key = Pubkey::new_unique();
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (signer_pda, _) = Pubkey::find_program_address(&[b"attested_signer_v2", &USER_DATA], &pid);
    let (nonce_pda, _) =
        Pubkey::find_program_address(&[b"nonce", &[2], &USER_DATA, &*SLOT_HASH], &pid);

    let mut registry_data = registry_bytes(
        authority_key.to_bytes(),
        UNRELATED_AMD_ARK,
        registry_bump,
        PCR0,
    );
    let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
    let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
    let mut clock_data = clock_bytes(CURRENT_SLOT, UNIX_NOW);
    let mut sh_data = slot_hashes_bytes(NONCE_SLOT, &SLOT_HASH);
    let mut payer_lamports = 1000;
    let mut payer_data = vec![];
    let mut reg_lamports = 1000;
    let mut signer_lamports = 1000;
    let mut nonce_lamports = 1000;
    let mut clock_lamports = 1000;
    let mut sh_lamports = 1000;
    let sys_key = system_program::ID;
    let mut sys_lamports = 1;
    let mut sys_data = vec![];
    let clock_key = clock::ID;
    let sh_key = slot_hashes::ID;

    // Unknown PCR0 (non-zero but not allowlisted).
    let unknown = nitro_document(&keys, [0x77u8; 48], USER_DATA, *SLOT_HASH);
    let payer_acc = AccountInfo::new(
        &payer_key,
        true,
        true,
        &mut payer_lamports,
        &mut payer_data,
        &pid,
        false,
    );
    let registry_acc = AccountInfo::new(
        &registry_pda,
        false,
        false,
        &mut reg_lamports,
        &mut registry_data,
        &pid,
        false,
    );
    let signer_acc = AccountInfo::new(
        &signer_pda,
        false,
        true,
        &mut signer_lamports,
        &mut signer_data,
        &pid,
        false,
    );
    let nonce_acc = AccountInfo::new(
        &nonce_pda,
        false,
        true,
        &mut nonce_lamports,
        &mut nonce_data,
        &pid,
        false,
    );
    let sh_acc = AccountInfo::new(
        &sh_key,
        false,
        false,
        &mut sh_lamports,
        &mut sh_data,
        &solana_program::sysvar::ID,
        false,
    );
    let clock_acc = AccountInfo::new(
        &clock_key,
        false,
        false,
        &mut clock_lamports,
        &mut clock_data,
        &solana_program::sysvar::ID,
        false,
    );
    let sys_acc = system_program_account(&sys_key, &mut sys_lamports, &mut sys_data);
    let ix = verify_ix(VERIFY_NITRO_MODE_A, NONCE_SLOT, [0u8; 32], &unknown);
    let res = process_nitro(
        &pid,
        &[
            payer_acc,
            registry_acc,
            signer_acc,
            nonce_acc,
            sh_acc,
            clock_acc,
            sys_acc,
        ],
        &ix,
    );
    assert_eq!(res, Err(VerifierError::DisallowedMeasurement.into()));
    registration_events::assert_empty();
}

#[test]
fn test_verify_nitro_rejects_stale_nonce() {
    let _clock = SyscallGuard::install(CURRENT_SLOT, UNIX_NOW);
    let keys = nitro_keys();
    let doc = nitro_document(&keys, PCR0, USER_DATA, *SLOT_HASH);
    let pid = Pubkey::new_unique();
    let payer_key = Pubkey::new_unique();
    let authority_key = Pubkey::new_unique();
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (signer_pda, _) = Pubkey::find_program_address(&[b"attested_signer_v2", &USER_DATA], &pid);
    let (nonce_pda, _) =
        Pubkey::find_program_address(&[b"nonce", &[2], &USER_DATA, &*SLOT_HASH], &pid);

    let mut registry_data = registry_bytes(
        authority_key.to_bytes(),
        UNRELATED_AMD_ARK,
        registry_bump,
        PCR0,
    );
    let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
    let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
    let mut clock_data = clock_bytes(CURRENT_SLOT, UNIX_NOW);
    let mut sh_data = slot_hashes_bytes(NONCE_SLOT, &SLOT_HASH);
    let mut payer_lamports = 1000;
    let mut payer_data = vec![];
    let mut reg_lamports = 1000;
    let mut signer_lamports = 1000;
    let mut nonce_lamports = 1000;
    let mut clock_lamports = 1000;
    let mut sh_lamports = 1000;
    let sys_key = system_program::ID;
    let mut sys_lamports = 1;
    let mut sys_data = vec![];
    let clock_key = clock::ID;
    let sh_key = slot_hashes::ID;

    let payer_acc = AccountInfo::new(
        &payer_key,
        true,
        true,
        &mut payer_lamports,
        &mut payer_data,
        &pid,
        false,
    );
    let registry_acc = AccountInfo::new(
        &registry_pda,
        false,
        false,
        &mut reg_lamports,
        &mut registry_data,
        &pid,
        false,
    );
    let signer_acc = AccountInfo::new(
        &signer_pda,
        false,
        true,
        &mut signer_lamports,
        &mut signer_data,
        &pid,
        false,
    );
    let nonce_acc = AccountInfo::new(
        &nonce_pda,
        false,
        true,
        &mut nonce_lamports,
        &mut nonce_data,
        &pid,
        false,
    );
    let sh_acc = AccountInfo::new(
        &sh_key,
        false,
        false,
        &mut sh_lamports,
        &mut sh_data,
        &solana_program::sysvar::ID,
        false,
    );
    let clock_acc = AccountInfo::new(
        &clock_key,
        false,
        false,
        &mut clock_lamports,
        &mut clock_data,
        &solana_program::sysvar::ID,
        false,
    );
    let sys_acc = system_program_account(&sys_key, &mut sys_lamports, &mut sys_data);

    let stale_slot = CURRENT_SLOT - 151;
    let ix = verify_ix(VERIFY_NITRO_MODE_A, stale_slot, [0u8; 32], &doc);
    let res = process_nitro(
        &pid,
        &[
            payer_acc,
            registry_acc,
            signer_acc,
            nonce_acc,
            sh_acc,
            clock_acc,
            sys_acc,
        ],
        &ix,
    );
    assert_eq!(res, Err(VerifierError::StaleNonce.into()));
    registration_events::assert_empty();
}

#[test]
fn test_verify_nitro_mode_b_commitment_and_replay() {
    let _clock = SyscallGuard::install(CURRENT_SLOT, UNIX_NOW);
    let keys = nitro_keys();
    let pid = Pubkey::new_unique();
    let payer_key = Pubkey::new_unique();
    let authority_key = Pubkey::new_unique();
    let consumer = Pubkey::new_unique();
    let action_hash = solana_confidential_compute_core::action::hash_action_parts(
        &[],
        0,
        core::iter::empty(),
        &[0u8; 8],
    );
    let commitment = compute_action_commitment(&SLOT_HASH, &action_hash, &consumer.to_bytes());
    let doc = nitro_document(&keys, PCR0, USER_DATA, commitment);

    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (signer_pda, _) = Pubkey::find_program_address(&[b"attested_signer_v2", &USER_DATA], &pid);
    let (nonce_pda, _) =
        Pubkey::find_program_address(&[b"nonce", &[2], &USER_DATA, &commitment], &pid);

    let mut registry_data = registry_bytes(
        authority_key.to_bytes(),
        UNRELATED_AMD_ARK,
        registry_bump,
        PCR0,
    );
    let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
    let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
    let mut clock_data = clock_bytes(CURRENT_SLOT, UNIX_NOW);
    let mut sh_data = slot_hashes_bytes(NONCE_SLOT, &SLOT_HASH);
    let ix = verify_ix(VERIFY_NITRO_MODE_B, NONCE_SLOT, action_hash, &doc);
    let mut ixs_data = serialize_instructions(&[(pid, ix.as_slice()), (consumer, &[0u8; 8])], 0);
    let mut payer_lamports = 1000;
    let mut payer_data = vec![];
    let mut reg_lamports = 1000;
    let mut signer_lamports = 1000;
    let mut nonce_lamports = 1000;
    let mut clock_lamports = 1000;
    let mut sh_lamports = 1000;
    let mut ix_lamports = 1000;
    let sys_key = system_program::ID;
    let mut sys_lamports = 1;
    let mut sys_data = vec![];
    let clock_key = clock::ID;
    let sh_key = slot_hashes::ID;
    let ix_key = instructions::ID;

    let payer_acc = AccountInfo::new(
        &payer_key,
        true,
        true,
        &mut payer_lamports,
        &mut payer_data,
        &pid,
        false,
    );
    let registry_acc = AccountInfo::new(
        &registry_pda,
        false,
        false,
        &mut reg_lamports,
        &mut registry_data,
        &pid,
        false,
    );
    let signer_acc = AccountInfo::new(
        &signer_pda,
        false,
        true,
        &mut signer_lamports,
        &mut signer_data,
        &pid,
        false,
    );
    let nonce_acc = AccountInfo::new(
        &nonce_pda,
        false,
        true,
        &mut nonce_lamports,
        &mut nonce_data,
        &pid,
        false,
    );
    let sh_acc = AccountInfo::new(
        &sh_key,
        false,
        false,
        &mut sh_lamports,
        &mut sh_data,
        &solana_program::sysvar::ID,
        false,
    );
    let clock_acc = AccountInfo::new(
        &clock_key,
        false,
        false,
        &mut clock_lamports,
        &mut clock_data,
        &solana_program::sysvar::ID,
        false,
    );
    let sys_acc = system_program_account(&sys_key, &mut sys_lamports, &mut sys_data);
    let ix_acc = AccountInfo::new(
        &ix_key,
        false,
        false,
        &mut ix_lamports,
        &mut ixs_data,
        &ix_key,
        false,
    );

    let accounts = vec![
        payer_acc,
        registry_acc,
        signer_acc,
        nonce_acc,
        sh_acc,
        clock_acc,
        sys_acc,
        ix_acc,
    ];
    // Same-program instruction substitution must fail before nonce writes.
    let sysvar = accounts
        .iter()
        .find(|a| a.key == &instructions::ID)
        .unwrap();
    let original_sysvar = sysvar.try_borrow_data().unwrap().to_vec();
    let mut substituted = [0u8; 8];
    substituted[0] ^= 1;
    let changed = serialize_instructions(&[(pid, &ix), (consumer, &substituted)], 0);
    sysvar
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&changed);
    assert_eq!(
        process_nitro(&pid, &accounts, &ix),
        Err(VerifierError::ActionHashMismatch.into())
    );
    assert!(accounts[3]
        .try_borrow_data()
        .unwrap()
        .iter()
        .all(|b| *b == 0));
    sysvar
        .try_borrow_mut_data()
        .unwrap()
        .copy_from_slice(&original_sysvar);

    let res = process_nitro(&pid, &accounts, &ix);
    assert_eq!(res, Ok(()));

    let saved_nonce =
        UsedNonceAccount::try_from_slice(&accounts[3].try_borrow_data().unwrap()).unwrap();
    assert_eq!(saved_nonce.discriminator, USED_NONCE_DISCRIMINATOR);

    let replay = process_nitro(&pid, &accounts, &ix);
    assert_eq!(replay, Err(VerifierError::NonceAlreadyUsed.into()));
}

#[test]
fn test_verify_nitro_mode_b_rejects_action_hash_mismatch() {
    let _clock = SyscallGuard::install(CURRENT_SLOT, UNIX_NOW);
    let keys = nitro_keys();
    let pid = Pubkey::new_unique();
    let payer_key = Pubkey::new_unique();
    let authority_key = Pubkey::new_unique();
    let consumer = Pubkey::new_unique();
    let action_hash = solana_confidential_compute_core::action::hash_action_parts(
        &[],
        0,
        core::iter::empty(),
        &[0u8; 8],
    );
    let commitment = compute_action_commitment(&SLOT_HASH, &action_hash, &consumer.to_bytes());
    let doc = nitro_document(&keys, PCR0, USER_DATA, commitment);

    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (signer_pda, _) = Pubkey::find_program_address(&[b"attested_signer_v2", &USER_DATA], &pid);
    let (nonce_pda, _) =
        Pubkey::find_program_address(&[b"nonce", &[2], &USER_DATA, &commitment], &pid);

    let mut registry_data = registry_bytes(
        authority_key.to_bytes(),
        UNRELATED_AMD_ARK,
        registry_bump,
        PCR0,
    );
    let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
    let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
    let mut clock_data = clock_bytes(CURRENT_SLOT, UNIX_NOW);
    let mut sh_data = slot_hashes_bytes(NONCE_SLOT, &SLOT_HASH);
    let bad_action = [0x33u8; 32];
    let ix = verify_ix(VERIFY_NITRO_MODE_B, NONCE_SLOT, bad_action, &doc);
    let mut ixs_data = serialize_instructions(&[(pid, ix.as_slice()), (consumer, &[0u8; 8])], 0);
    let mut payer_lamports = 1000;
    let mut payer_data = vec![];
    let mut reg_lamports = 1000;
    let mut signer_lamports = 1000;
    let mut nonce_lamports = 1000;
    let mut clock_lamports = 1000;
    let mut sh_lamports = 1000;
    let mut ix_lamports = 1000;
    let sys_key = system_program::ID;
    let mut sys_lamports = 1;
    let mut sys_data = vec![];
    let clock_key = clock::ID;
    let sh_key = slot_hashes::ID;
    let ix_key = instructions::ID;

    let accounts = vec![
        AccountInfo::new(
            &payer_key,
            true,
            true,
            &mut payer_lamports,
            &mut payer_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &registry_pda,
            false,
            false,
            &mut reg_lamports,
            &mut registry_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &signer_pda,
            false,
            true,
            &mut signer_lamports,
            &mut signer_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &nonce_pda,
            false,
            true,
            &mut nonce_lamports,
            &mut nonce_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &sh_key,
            false,
            false,
            &mut sh_lamports,
            &mut sh_data,
            &solana_program::sysvar::ID,
            false,
        ),
        AccountInfo::new(
            &clock_key,
            false,
            false,
            &mut clock_lamports,
            &mut clock_data,
            &solana_program::sysvar::ID,
            false,
        ),
        system_program_account(&sys_key, &mut sys_lamports, &mut sys_data),
        AccountInfo::new(
            &ix_key,
            false,
            false,
            &mut ix_lamports,
            &mut ixs_data,
            &ix_key,
            false,
        ),
    ];
    let res = process_nitro(&pid, &accounts, &ix);
    assert_eq!(res, Err(VerifierError::ActionHashMismatch.into()));
}

#[test]
fn test_verify_nitro_rejects_trailing_wire_bytes() {
    let _clock = SyscallGuard::install(CURRENT_SLOT, UNIX_NOW);
    let keys = nitro_keys();
    let doc = nitro_document(&keys, PCR0, USER_DATA, *SLOT_HASH);
    let pid = Pubkey::new_unique();
    let payer_key = Pubkey::new_unique();
    let authority_key = Pubkey::new_unique();
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (signer_pda, _) = Pubkey::find_program_address(&[b"attested_signer_v2", &USER_DATA], &pid);
    let (nonce_pda, _) =
        Pubkey::find_program_address(&[b"nonce", &[2], &USER_DATA, &*SLOT_HASH], &pid);

    let mut registry_data = registry_bytes(
        authority_key.to_bytes(),
        UNRELATED_AMD_ARK,
        registry_bump,
        PCR0,
    );
    let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
    let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
    let mut clock_data = clock_bytes(CURRENT_SLOT, UNIX_NOW);
    let mut sh_data = slot_hashes_bytes(NONCE_SLOT, &SLOT_HASH);
    let mut payer_lamports = 1000;
    let mut payer_data = vec![];
    let mut reg_lamports = 1000;
    let mut signer_lamports = 1000;
    let mut nonce_lamports = 1000;
    let mut clock_lamports = 1000;
    let mut sh_lamports = 1000;
    let sys_key = system_program::ID;
    let mut sys_lamports = 1;
    let mut sys_data = vec![];
    let clock_key = clock::ID;
    let sh_key = slot_hashes::ID;

    let accounts = vec![
        AccountInfo::new(
            &payer_key,
            true,
            true,
            &mut payer_lamports,
            &mut payer_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &registry_pda,
            false,
            false,
            &mut reg_lamports,
            &mut registry_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &signer_pda,
            false,
            true,
            &mut signer_lamports,
            &mut signer_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &nonce_pda,
            false,
            true,
            &mut nonce_lamports,
            &mut nonce_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &sh_key,
            false,
            false,
            &mut sh_lamports,
            &mut sh_data,
            &solana_program::sysvar::ID,
            false,
        ),
        AccountInfo::new(
            &clock_key,
            false,
            false,
            &mut clock_lamports,
            &mut clock_data,
            &solana_program::sysvar::ID,
            false,
        ),
        system_program_account(&sys_key, &mut sys_lamports, &mut sys_data),
    ];

    let mut ix = verify_ix(VERIFY_NITRO_MODE_A, NONCE_SLOT, [0u8; 32], &doc);
    ix.push(0xAA);
    let res = process_nitro(&pid, &accounts, &ix);
    assert_eq!(res, Err(VerifierError::InvalidInstruction.into()));
}

#[test]
fn test_verify_nitro_rejects_untrusted_root_ca() {
    let _clock = SyscallGuard::install(CURRENT_SLOT, UNIX_NOW);
    // cabundle[0] matches the registry AMD root. That substitution is rejected.
    // @spec SCC-NITRO-004 SCC-SEC-003
    let keys = synthetic_nitro_keys();
    let doc = nitro_document(&keys, PCR0, USER_DATA, *SLOT_HASH);
    let pid = Pubkey::new_unique();
    let payer_key = Pubkey::new_unique();
    let authority_key = Pubkey::new_unique();
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (signer_pda, _) = Pubkey::find_program_address(&[b"attested_signer_v2", &USER_DATA], &pid);
    let (nonce_pda, _) =
        Pubkey::find_program_address(&[b"nonce", &[2], &USER_DATA, &*SLOT_HASH], &pid);

    let mut registry_data =
        registry_bytes(authority_key.to_bytes(), keys.root_xy, registry_bump, PCR0);
    let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
    let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
    let mut clock_data = clock_bytes(CURRENT_SLOT, UNIX_NOW);
    let mut sh_data = slot_hashes_bytes(NONCE_SLOT, &SLOT_HASH);
    let mut payer_lamports = 1000;
    let mut payer_data = vec![];
    let mut reg_lamports = 1000;
    let mut signer_lamports = 1000;
    let mut nonce_lamports = 1000;
    let mut clock_lamports = 1000;
    let mut sh_lamports = 1000;
    let sys_key = system_program::ID;
    let mut sys_lamports = 1;
    let mut sys_data = vec![];
    let clock_key = clock::ID;
    let sh_key = slot_hashes::ID;

    let accounts = vec![
        AccountInfo::new(
            &payer_key,
            true,
            true,
            &mut payer_lamports,
            &mut payer_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &registry_pda,
            false,
            false,
            &mut reg_lamports,
            &mut registry_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &signer_pda,
            false,
            true,
            &mut signer_lamports,
            &mut signer_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &nonce_pda,
            false,
            true,
            &mut nonce_lamports,
            &mut nonce_data,
            &pid,
            false,
        ),
        AccountInfo::new(
            &sh_key,
            false,
            false,
            &mut sh_lamports,
            &mut sh_data,
            &solana_program::sysvar::ID,
            false,
        ),
        AccountInfo::new(
            &clock_key,
            false,
            false,
            &mut clock_lamports,
            &mut clock_data,
            &solana_program::sysvar::ID,
            false,
        ),
        system_program_account(&sys_key, &mut sys_lamports, &mut sys_data),
    ];

    let ix = verify_ix(VERIFY_NITRO_MODE_A, NONCE_SLOT, [0u8; 32], &doc);
    let res = Processor::process(&pid, &accounts, &ix);
    assert_eq!(res, Err(VerifierError::VerificationFailed.into()));
}
