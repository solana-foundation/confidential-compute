//! #163: a syntactically valid forged Nitro document must fail default dispatch.
//! Native controls only; this is not SBF, CU, or hardware evidence.
//!
//! @spec SCC-NITRO-006 SCC-NITRO-007 SCC-NITRO-008

#[path = "../../../crates/solana-confidential-compute-crypto/tests/support/nitro_cert.rs"]
mod cert_fixture;
use borsh::{BorshDeserialize, BorshSerialize};
use cert_fixture::standard_cert;
use p384::ecdsa::signature::hazmat::PrehashSigner;
use p384::ecdsa::SigningKey;
use sha2::{Digest, Sha384};
use solana_confidential_compute_core::types::EnclaveType;
use solana_confidential_compute_verifier::error::VerifierError;
use solana_confidential_compute_verifier::payload::{
    VerifyNitroAttestationArgs, VERIFY_NITRO_ATTESTATION_DISCRIMINATOR, VERIFY_NITRO_MODE_A,
};
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    program_stubs::{set_syscall_stubs, SyscallStubs},
    pubkey::Pubkey,
    sysvar::{clock, slot_hashes},
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
    leaf_sk: SigningKey,
    root_cert: Vec<u8>,
    inter_cert: Vec<u8>,
    leaf_cert: Vec<u8>,
}

fn nitro_keys() -> NitroKeys {
    let (root_sk, _synthetic_root) = keypair(0x31);
    let (inter_sk, inter_xy) = keypair(0x32);
    let (leaf_sk, leaf_xy) = keypair(0x33);
    let aws_root = solana_confidential_compute_crypto::AWS_NITRO_ROOT_CA_PUBKEY_XY;
    NitroKeys {
        leaf_sk,
        root_cert: standard_cert(&aws_root, &root_sk, b"root", b"root", true),
        // No AWS private key: embedding its public root cannot authorize this chain.
        inter_cert: standard_cert(&inter_xy, &root_sk, b"root", b"inter", true),
        leaf_cert: standard_cert(&leaf_xy, &inter_sk, b"inter", b"leaf", false),
    }
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
    // Make the COSE signature explicitly bogus as well as the synthetic chain.
    let signature_start = doc.len() - 96;
    doc[signature_start..].fill(0xEE);
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

struct ClockSyscallStub {
    slot: u64,
    unix_timestamp: i64,
}

impl SyscallStubs for ClockSyscallStub {
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
#[cfg_attr(
    feature = "mock-crypto",
    ignore = "requires the real default backend; CI uses --include-ignored for compatibility regression"
)]
fn forged_nitro_is_rejected_by_default_with_mock_acceptance_control() {
    let _clock = SyscallGuard::install(CURRENT_SLOT, UNIX_NOW);
    let keys = nitro_keys();
    // Runtime slot hash: the document nonce only has to match SlotHashes.
    let slot_hash = Pubkey::new_unique().to_bytes();
    let doc = nitro_document(&keys, PCR0, USER_DATA, slot_hash);
    let pid = Pubkey::new_unique();
    let payer_key = Pubkey::new_unique();
    let authority_key = Pubkey::new_unique();
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (signer_pda, _) = Pubkey::find_program_address(&[b"attested_signer_v2", &USER_DATA], &pid);
    let (nonce_pda, _) =
        Pubkey::find_program_address(&[b"nonce", &[2], &USER_DATA, &slot_hash], &pid);

    let mut registry_data = registry_bytes(
        authority_key.to_bytes(),
        UNRELATED_AMD_ARK,
        registry_bump,
        PCR0,
    );
    let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
    let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
    let mut clock_data = clock_bytes(CURRENT_SLOT, UNIX_NOW);
    let mut sh_data = slot_hashes_bytes(NONCE_SLOT, &slot_hash);
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
    // Preserve the workload-consent account contract from #204 when integrated.
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

    let ix = verify_ix(VERIFY_NITRO_MODE_A, NONCE_SLOT, [0u8; 32], &doc);
    let accounts = vec![
        payer_acc,
        registry_acc,
        signer_acc,
        nonce_acc,
        sh_acc,
        clock_acc,
        sys_acc,
        workload_acc,
    ];
    let control = Processor::process_with(&DirectCryptoVerifier, &pid, &accounts, &ix);
    assert!(
        control.is_err(),
        "real backend must reject synthetic AWS root signatures"
    );
    assert!(accounts[2]
        .try_borrow_data()
        .unwrap()
        .iter()
        .all(|b| *b == 0));
    let default_result = Processor::process(&pid, &accounts, &ix);
    assert_eq!(default_result, Err(VerifierError::InvalidSignature.into()));
    assert!(accounts[2]
        .try_borrow_data()
        .unwrap()
        .iter()
        .all(|b| *b == 0));
    assert!(accounts[3]
        .try_borrow_data()
        .unwrap()
        .iter()
        .all(|b| *b == 0));
    // Same bytes/accounts reach writes when signature checking is explicitly bypassed.
    let res = Processor::process_with(
        &solana_confidential_compute_verifier::MockVerifier::succeeding(),
        &pid,
        &accounts,
        &ix,
    );
    assert!(res.is_ok(), "mock-verified Nitro dispatch must succeed");

    let saved =
        AttestedSignerAccount::try_from_slice(&accounts[2].try_borrow_data().unwrap()).unwrap();
    assert_eq!(saved.discriminator, ATTESTED_SIGNER_DISCRIMINATOR);
    assert_eq!(saved.record.signer_pubkey, USER_DATA);
    assert_eq!(saved.record.enclave_type, EnclaveType::AwsNitro);
    assert_eq!(saved.record.measurement.0, PCR0);
    assert_eq!(saved.record.registered_slot, CURRENT_SLOT);
    assert_eq!(
        saved.record.expires_slot,
        CURRENT_SLOT + ATTESTATION_TTL_SLOTS
    );

    let saved_nonce =
        UsedNonceAccount::try_from_slice(&accounts[3].try_borrow_data().unwrap()).unwrap();
    assert_eq!(saved_nonce.discriminator, USED_NONCE_DISCRIMINATOR);
    assert_eq!(saved_nonce.slot, CURRENT_SLOT);

    let replay = Processor::process_with(
        &solana_confidential_compute_verifier::MockVerifier::succeeding(),
        &pid,
        &accounts,
        &ix,
    );
    assert_eq!(replay, Err(VerifierError::NonceAlreadyUsed.into()));
}
