// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Cache lookup seed contract for VCEK and VLEK report resolution.
//! Synthetic P384 AMD chains are rejected; cached keys below are native test fixtures,
//! not a claim that synthetic certificates can register or represent hardware.
//!
//! A leaf subject `CN=SEV-VLEK` with a non-zero `hwID` registers under
//! `sha256(public_key_xy)`. A report with `SIGNING_KEY == 1` and that same
//! chip id resolves the account. A `CN=SEV-VCEK` leaf keeps `sha256(chip_id)`.
//!
//! MIGRATION (solana 2.2 -> 4.x): this was one native test holding a
//! `set_syscall_stubs` clock. In 4.x `Clock::get()` resolves through
//! `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch is a hardcoded
//! `UNSUPPORTED_SYSVAR` that never consults `program_stubs`, so the stub was
//! dead code. Only `process_register_vcek` calls `Clock::get()`; the V2 cache
//! path reads the clock from the pinned clock *account*, which still works
//! natively. So the registration half moved to the real SBF artifact under
//! ProgramTest and the cache half stayed native -- deliberately, because native
//! keeps `DirectCryptoVerifier`, which really does verify the report's P-384
//! signature. The SBF build delegates P-384 to an unassigned sigverify
//! precompile via instruction introspection and would not verify it at all.
//!
//! @spec SCC-VERIFY-003 SCC-VERIFY-009

use borsh::{BorshDeserialize, BorshSerialize};
use p384::ecdsa::signature::hazmat::PrehashSigner;
use p384::ecdsa::SigningKey;
use sha2::{Digest, Sha384};
use solana_confidential_compute_core::SNP_REPORT_SIZE;
use solana_confidential_compute_verifier::error::VerifierError;
use solana_confidential_compute_verifier::payload::{
    RegisterVcekArgs, VerifyAndRegisterArgs, REGISTER_VCEK_DISCRIMINATOR, VERIFY_AND_REGISTER_DISCRIMINATOR,
};
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    hash::hashv,
    pubkey::Pubkey,
    sysvar::{clock, slot_hashes},
};
use solana_program_test::BanksClientError;
use solana_sdk::account::Account;
use solana_sdk::instruction::{AccountMeta, Instruction, InstructionError};
use solana_sdk::signature::Signer;
use solana_sdk::transaction::{Transaction, TransactionError};
#[allow(deprecated)]
use solana_sdk_ids::system_program;
#[path = "common/sbf.rs"]
mod sbf;

#[path = "common/legacy_nonce.rs"]
mod legacy_nonce_fixture;
use legacy_nonce_fixture::TestProcessor as Processor;
use solana_confidential_compute_verifier::state::{
    AttestedSignerAccount, PolicyRegistry, UsedNonceAccount, VcekAccount, POLICY_REGISTRY_DISCRIMINATOR,
    VCEK_ACCOUNT_DISCRIMINATOR,
};

const OID_TCB_VERSION: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x01];
const OID_HWID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x04];

const NOW_UNIX: i64 = 1_800_000_000;
const VALID_UNTIL_UNIX: u64 = 2_011_212_795;

fn instruction_error(err: BanksClientError) -> InstructionError {
    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(_, err)) => err,
        other => panic!("unexpected banks error: {other:?}"),
    }
}

fn keypair(seed_lsb: u8) -> (SigningKey, [u8; 96]) {
    let mut seed = [0u8; 48];
    seed[47] = seed_lsb;
    let signing_key = SigningKey::from_slice(&seed).expect("valid scalar");
    let encoded = signing_key.verifying_key().to_sec1_point(false);
    let mut xy = [0u8; 96];
    xy[..48].copy_from_slice(encoded.x().unwrap().as_slice());
    xy[48..].copy_from_slice(encoded.y().unwrap().as_slice());
    (signing_key, xy)
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(tag);
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else if value.len() < 0x100 {
        out.push(0x81);
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.push((value.len() >> 8) as u8);
        out.push(value.len() as u8);
    }
    out.extend_from_slice(value);
    out
}

fn encode_integer(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    let trimmed = &bytes[start..];
    if trimmed[0] & 0x80 != 0 {
        let mut prefixed = Vec::with_capacity(trimmed.len() + 1);
        prefixed.push(0x00);
        prefixed.extend_from_slice(trimmed);
        tlv(0x02, &prefixed)
    } else {
        tlv(0x02, trimmed)
    }
}

fn common_name(cn: &[u8]) -> Vec<u8> {
    let mut atv = Vec::new();
    atv.extend(tlv(0x06, &[0x55, 0x04, 0x03]));
    atv.extend(tlv(0x0C, cn));
    tlv(0x31, &tlv(0x30, &atv))
}

fn identity_extensions(chip_id: &[u8; 64], tcb_version: u64) -> Vec<u8> {
    let hwid_inner = tlv(0x04, chip_id);
    let mut tcb_be = tcb_version.to_be_bytes().to_vec();
    while tcb_be.len() > 1 && tcb_be[0] == 0 {
        tcb_be.remove(0);
    }
    if tcb_be[0] & 0x80 != 0 {
        tcb_be.insert(0, 0x00);
    }
    let tcb_int = tlv(0x02, &tcb_be);
    let mut extensions = Vec::new();
    for (oid, inner) in [(OID_HWID, hwid_inner.as_slice()), (OID_TCB_VERSION, tcb_int.as_slice())] {
        let mut body = Vec::new();
        body.extend(tlv(0x06, oid));
        body.extend(tlv(0x04, inner));
        extensions.extend(tlv(0x30, &body));
    }
    extensions
}

fn encode_cert(subject_xy: &[u8; 96], issuer: &SigningKey, subject_rdns: &[u8], extensions: &[u8]) -> Vec<u8> {
    let mut spki_alg = Vec::new();
    spki_alg.extend(tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]));
    spki_alg.extend(tlv(0x06, &[0x2B, 0x81, 0x04, 0x00, 0x22]));
    let mut key_bit = vec![0x00, 0x04];
    key_bit.extend_from_slice(subject_xy);
    let mut spki_body = Vec::new();
    spki_body.extend(tlv(0x30, &spki_alg));
    spki_body.extend(tlv(0x03, &key_bit));
    let spki = tlv(0x30, &spki_body);

    let sigalg = tlv(0x30, &tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]));
    let mut validity_body = Vec::new();
    validity_body.extend(tlv(0x17, b"250101000000Z"));
    validity_body.extend(tlv(0x17, b"350101000000Z"));

    let mut tbs_body = Vec::new();
    tbs_body.extend(tlv(0x02, &[0x01]));
    tbs_body.extend(&sigalg);
    tbs_body.extend(tlv(0x30, &[]));
    tbs_body.extend(tlv(0x30, &validity_body));
    tbs_body.extend(tlv(0x30, subject_rdns));
    tbs_body.extend(spki);
    if !extensions.is_empty() {
        tbs_body.extend(tlv(0xA3, &tlv(0x30, extensions)));
    }
    let tbs = tlv(0x30, &tbs_body);

    let mut hasher = Sha384::new();
    hasher.update(&tbs);
    let digest: [u8; 48] = hasher.finalize().into();
    let (signature, _) = issuer.sign_prehash(&digest).expect("sign TBS");
    let sig_bytes = signature.to_bytes();
    let mut sig_seq_body = Vec::new();
    sig_seq_body.extend(encode_integer(&sig_bytes[..48]));
    sig_seq_body.extend(encode_integer(&sig_bytes[48..]));
    let mut sig_bit = vec![0x00];
    sig_bit.extend(tlv(0x30, &sig_seq_body));

    let mut cert_body = Vec::new();
    cert_body.extend(tbs);
    cert_body.extend(sigalg);
    cert_body.extend(tlv(0x03, &sig_bit));
    tlv(0x30, &cert_body)
}

fn sign_report(report: &mut [u8; SNP_REPORT_SIZE], signing_key: &SigningKey) {
    let mut hasher = Sha384::new();
    hasher.update(&report[0..672]);
    let digest: [u8; 48] = hasher.finalize().into();
    let (signature, _) = signing_key.sign_prehash(&digest).expect("sign report");
    let sig_bytes = signature.to_bytes();
    let mut r_le = [0u8; 72];
    let mut s_le = [0u8; 72];
    for i in 0..48 {
        r_le[i] = sig_bytes[47 - i];
        s_le[i] = sig_bytes[95 - i];
    }
    report[0x2A0..0x2E8].copy_from_slice(&r_le);
    report[0x2E8..0x330].copy_from_slice(&s_le);
}

fn system_program_account<'a>(key: &'a Pubkey, lamports: &'a mut u64, data: &'a mut [u8]) -> AccountInfo<'a> {
    AccountInfo::new(key, false, false, lamports, data, key, false)
}

fn register_ix(chip_id: [u8; 64], tcb_version: u64, vcek_xy: [u8; 96], ask: &[u8], vcek: &[u8]) -> Vec<u8> {
    let mut ix = Vec::new();
    ix.extend_from_slice(&REGISTER_VCEK_DISCRIMINATOR);
    RegisterVcekArgs {
        chip_id,
        tcb_version,
        public_key_xy: vcek_xy,
        ask_cert_len: ask.len() as u16,
        vcek_cert_len: vcek.len() as u16,
    }
    .serialize(&mut ix)
    .unwrap();
    ix.extend_from_slice(ask);
    ix.extend_from_slice(vcek);
    ix
}

/// `register_vcek` against the real artifact: the synthetic chain must be
/// rejected and `candidate` must be left unallocated and unwritten.
async fn reject_synthetic_registration(
    pid: Pubkey,
    registry_pda: Pubkey,
    registry_data: &[u8],
    ix: &[u8],
    candidate: Pubkey,
) {
    let mut pt = sbf::verifier_program_test(pid);
    pt.add_account(
        registry_pda,
        Account { lamports: 10_000_000, data: registry_data.to_vec(), owner: pid, executable: false, rent_epoch: 0 },
    );
    pt.add_account(
        candidate,
        Account {
            lamports: 10_000_000,
            data: vec![0u8; VcekAccount::SIZE],
            owner: pid,
            executable: false,
            rent_epoch: 0,
        },
    );
    let ctx = pt.start_with_context().await;
    ctx.set_sysvar(&Clock { slot: 520, unix_timestamp: NOW_UNIX, ..Clock::default() });

    let instruction = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(ctx.payer.pubkey(), true),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new(candidate, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: ix.to_vec(),
    };
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(&[instruction], Some(&ctx.payer.pubkey()), &[&ctx.payer], blockhash);
    let err = ctx.banks_client.process_transaction(tx).await.expect_err("synthetic AMD chain must not register");
    assert_eq!(instruction_error(err), InstructionError::Custom(VerifierError::VerificationFailed as u32),);
    let after = ctx.banks_client.get_account(candidate).await.unwrap().expect("candidate cache account");
    assert!(after.data.iter().all(|b| *b == 0), "rejected registration wrote the cache account");
}

/// Reject unsupported registration and exercise V2 cache lookup separately.
///
/// `vlek` selects `CN=SEV-VLEK` plus `SIGNING_KEY == 1`. The chip id is
/// non-zero in both cases.
async fn reject_synthetic_registration_then_verify_cached_key(vlek: bool) {
    let current_slot = 520u64;
    let pid = Pubkey::new_unique();
    let payer_key = Pubkey::new_unique();
    let (ark_sk, ark_xy) = keypair(0x21);
    let (ask_sk, ask_xy) = keypair(0x22);
    let (vcek_sk, vcek_xy) = keypair(0x23);

    let chip_id = [0x55u8; 64];
    let measurement = [33u8; 48];
    let workload_pubkey = [0x77u8; 32];
    let slot_hash = [0x88u8; 32];
    let nonce_slot = 500u64;

    let mut report = [0u8; SNP_REPORT_SIZE];
    report[0..4].copy_from_slice(&1u32.to_le_bytes());
    report[8..16].copy_from_slice(&(1u64 << 17).to_le_bytes());
    report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    if vlek {
        report[0x48..0x4C].copy_from_slice(&4u32.to_le_bytes());
    }
    report[0x50..0x70].copy_from_slice(&workload_pubkey);
    report[0x70..0x90].copy_from_slice(&slot_hash);
    report[0x90..0xC0].copy_from_slice(&measurement);
    report[0x180] = 1;
    report[0x181] = 0;
    report[0x186] = 2;
    report[0x187] = 5;
    report[0x1A0..0x1E0].copy_from_slice(&chip_id);
    let tcb_version = u64::from_le_bytes(report[0x180..0x188].try_into().unwrap());
    sign_report(&mut report, &vcek_sk);

    let subject = if vlek { &b"SEV-VLEK"[..] } else { &b"SEV-VCEK"[..] };
    let ask_cert = encode_cert(&ask_xy, &ark_sk, &[], &[]);
    let vcek_cert = encode_cert(&vcek_xy, &ask_sk, &common_name(subject), &identity_extensions(&chip_id, tcb_version));
    let ix = register_ix(chip_id, tcb_version, vcek_xy, &ask_cert, &vcek_cert);

    let pubkey_hash = hashv(&[&vcek_xy]).to_bytes();
    let chip_hash = hashv(&[&chip_id]).to_bytes();
    let (right_hash, wrong_hash) = if vlek { (pubkey_hash, chip_hash) } else { (chip_hash, pubkey_hash) };
    let tcb_bytes = tcb_version.to_le_bytes();
    let (wrong_pda, _) = Pubkey::find_program_address(&[VcekAccount::SEED, &wrong_hash, &tcb_bytes], &pid);
    let (vcek_pda, vcek_bump) = Pubkey::find_program_address(&[VcekAccount::SEED, &right_hash, &tcb_bytes], &pid);
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);

    let mut registry_data = vec![0u8; PolicyRegistry::SIZE];
    PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: [0u8; 32],
        ark_pubkey_xy: ark_xy,
        min_tcb_boot_loader: 1,
        min_tcb_tee: 0,
        min_tcb_snp: 2,
        min_tcb_microcode: 5,
        measurement_count: 1,
        measurements: {
            let mut slots = [[0u8; 48]; 8];
            slots[0] = measurement;
            slots
        },
        bump: registry_bump,
    }
    .serialize(&mut &mut registry_data[..])
    .unwrap();

    // Neither candidate cache address may be created or written by a synthetic
    // chain. Runs as real SBF bytecode: `process_register_vcek` reads
    // `Clock::get()` before chain validation.
    reject_synthetic_registration(pid, registry_pda, &registry_data, &ix, wrong_pda).await;
    reject_synthetic_registration(pid, registry_pda, &registry_data, &ix, vcek_pda).await;

    let mut payer_lamports = 1_000u64;
    let mut payer_data = vec![];
    let mut reg_lamports = 1_000u64;
    let sys_key = system_program::ID;
    let mut sys_lamports = 1u64;
    let mut sys_data = vec![];
    let mut vcek_lamports = 1_000u64;
    let mut vcek_data = vec![0u8; VcekAccount::SIZE];
    // Seed an authenticated-key cache fixture only to exercise downstream PDA
    // resolution/report signatures, independently of vendor-chain validation.
    VcekAccount {
        discriminator: VCEK_ACCOUNT_DISCRIMINATOR,
        chip_id_hash: right_hash,
        tcb_version,
        public_key_xy: vcek_xy,
        registered_slot: current_slot,
        bump: vcek_bump,
        trust_profile: VcekAccount::MILAN_TRUST_PROFILE,
        valid_until_unix: VALID_UNTIL_UNIX,
        is_revoked: false,
    }
    .serialize(&mut &mut vcek_data[..])
    .unwrap();
    let saved = VcekAccount::try_from_slice(&vcek_data).unwrap();
    assert_eq!(saved.discriminator, VCEK_ACCOUNT_DISCRIMINATOR);
    assert_eq!(saved.chip_id_hash, right_hash);
    assert_eq!(saved.public_key_xy, vcek_xy);
    assert_ne!(saved.chip_id_hash, wrong_hash);
    assert_eq!(saved.trust_profile, VcekAccount::MILAN_TRUST_PROFILE);
    assert_eq!(saved.valid_until_unix, VALID_UNTIL_UNIX);
    assert!(!saved.is_revoked);

    let (signer_pda, signer_bump) = Pubkey::find_program_address(&[b"attested_signer_v2", &workload_pubkey], &pid);
    let (nonce_pda, nonce_bump) = Pubkey::find_program_address(&[b"nonce", &[1], &workload_pubkey, &slot_hash], &pid);

    let mut verify_ix = Vec::new();
    verify_ix.extend_from_slice(&VERIFY_AND_REGISTER_DISCRIMINATOR);
    VerifyAndRegisterArgs { nonce_slot, report }.serialize(&mut verify_ix).unwrap();
    verify_ix.push(nonce_bump);
    verify_ix.push(signer_bump);

    let slot_hashes_key = slot_hashes::ID;
    let mut slot_hashes_data = vec![0u8; 8 + 40];
    slot_hashes_data[0..8].copy_from_slice(&1u64.to_le_bytes());
    slot_hashes_data[8..16].copy_from_slice(&nonce_slot.to_le_bytes());
    slot_hashes_data[16..48].copy_from_slice(&slot_hash);

    let clock_key = clock::ID;
    let mut clock_data = vec![0u8; 40];
    clock_data[0..8].copy_from_slice(&current_slot.to_le_bytes());
    clock_data[32..40].copy_from_slice(&NOW_UNIX.to_le_bytes());

    let mut signer_lamports = 1_000u64;
    let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
    let mut nonce_lamports = 1_000u64;
    let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
    let mut sh_lamports = 1_000u64;
    let mut clock_lamports = 1_000u64;

    let workload_key = Pubkey::new_from_array(workload_pubkey);
    let mut workload_lamports = 1;
    let mut workload_data = [];
    let accounts = [
        AccountInfo::new(&payer_key, true, true, &mut payer_lamports, &mut payer_data, &pid, false),
        AccountInfo::new(&registry_pda, false, false, &mut reg_lamports, &mut registry_data, &pid, false),
        AccountInfo::new(&vcek_pda, false, false, &mut vcek_lamports, &mut vcek_data, &pid, false),
        AccountInfo::new(&signer_pda, false, true, &mut signer_lamports, &mut signer_data, &pid, false),
        AccountInfo::new(&nonce_pda, false, true, &mut nonce_lamports, &mut nonce_data, &pid, false),
        AccountInfo::new(
            &slot_hashes_key,
            false,
            false,
            &mut sh_lamports,
            &mut slot_hashes_data,
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
        AccountInfo::new(&workload_key, true, false, &mut workload_lamports, &mut workload_data, &pid, false),
    ];
    let trusted_cache = accounts[2].try_borrow_data().unwrap().to_vec();
    for invalid in ["expired", "revoked", "profile", "negative_clock"] {
        let mut cache = saved.clone();
        match invalid {
            "expired" => cache.valid_until_unix = NOW_UNIX as u64,
            "revoked" => cache.is_revoked = true,
            "profile" => cache.trust_profile[0] ^= 1,
            "negative_clock" => {
                accounts[6].try_borrow_mut_data().unwrap()[32..40].copy_from_slice(&(-1i64).to_le_bytes());
            }
            _ => unreachable!(),
        }
        cache.serialize(&mut &mut accounts[2].try_borrow_mut_data().unwrap()[..]).unwrap();
        let before: Vec<_> = accounts
            .iter()
            .map(|a| (**a.try_borrow_lamports().unwrap(), a.try_borrow_data().unwrap().to_vec()))
            .collect();
        assert_eq!(
            Processor::process(&pid, &accounts, &verify_ix),
            Err(VerifierError::UnauthorizedPolicy.into()),
            "{invalid}"
        );
        for (account, (lamports, data)) in accounts.iter().zip(before) {
            assert_eq!(**account.try_borrow_lamports().unwrap(), lamports, "{invalid}");
            assert_eq!(&account.try_borrow_data().unwrap()[..], data, "{invalid}");
        }
        accounts[6].try_borrow_mut_data().unwrap()[32..40].copy_from_slice(&NOW_UNIX.to_le_bytes());
    }
    accounts[2].try_borrow_mut_data().unwrap().copy_from_slice(&trusted_cache);
    let verified = Processor::process(&pid, &accounts, &verify_ix);
    assert_ne!(verified, Err(VerifierError::InvalidAccountAddress.into()));
    assert_eq!(verified, Ok(()), "VLEK={vlek} report should resolve the valid V2 cache fixture");
}

#[tokio::test]
async fn vlek_report_with_nonzero_chip_id_resolves_cached_pubkey_seed() {
    reject_synthetic_registration_then_verify_cached_key(true).await;
}

#[tokio::test]
async fn vcek_report_with_nonzero_chip_id_resolves_cached_chip_seed() {
    reject_synthetic_registration_then_verify_cached_key(false).await;
}
