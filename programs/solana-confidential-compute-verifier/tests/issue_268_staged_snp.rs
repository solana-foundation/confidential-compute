//! Bank proof with a real P-384 signature on a locally generated full-size
//! SNP report. Preloaded VCEK trust is a test fixture, not vendor/hardware proof.
//!
//! MIGRATION (solana 2.2 -> 4.x): the bank already drove this through
//! `ProgramTest`, but via `processor!(Processor::process)`. In 4.x `Clock::get()`
//! resolves through `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch
//! is a hardcoded `UNSUPPORTED_SYSVAR` that never consults `program_stubs`, so a
//! natively linked program can no longer read any sysvar. The staged transport
//! reads `Clock::get()` on every BEGIN/UPLOAD/SEAL/CONSUME, so the program must
//! execute as real SBF bytecode.
//!
//! Moving to SBF also moves `DefaultVerifier` from `DirectCryptoVerifier` to
//! `SolanaDefaultVerifier`: software P-384 returns `InvalidSignature` on
//! `target_os = "solana"`, so the report signature is now proved the way
//! production proves it -- by a preceding sigverify instruction at the pinned
//! `EXPECTED_SIGVERIFY_PROGRAM_ID`, bound byte-for-byte to the pubkey, digest
//! and `(r || s)` the verifier recomputed. That precompile is not deployed on
//! any cluster, so the bank gets a stand-in at the same address running the
//! same software P-384 check. The signature is still genuinely verified; what
//! changed is which program performs the scalar arithmetic.
#![allow(deprecated)]
use p384::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest, Sha384};
use solana_confidential_compute_verifier::{
    payload::VERIFY_AND_REGISTER_DISCRIMINATOR,
    processor::transport::*,
    state::{
        BackendPolicy, PolicyRegistry, UsedNonceAccount, VcekAccount, POLICY_REGISTRY_DISCRIMINATOR,
    },
};
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult};
use solana_program_test::processor;
use solana_sdk::{
    account::Account,
    clock::Clock,
    hash::hash,
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

#[path = "common/sbf.rs"]
mod sbf;

/// `solana_confidential_compute_verifier::processor::EXPECTED_SIGVERIFY_PROGRAM_ID`, which is only
/// compiled on `target_os = "solana"` and so cannot be imported here.
const SIGVERIFY_ID: Pubkey =
    Pubkey::new_from_array(*b"SECP384R1SIGVERIFY\0\0\0\0\0\0\0\0\0\0\0\0\0\0");

/// Stand-in for the undeployed precompile: same address, same P-384 check.
fn sigverify(_: &Pubkey, _: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (pubkey, rest) = data.split_at(96);
    let (digest, signature) = rest.split_at(48);
    match solana_confidential_compute_crypto::verify_p384_signature(
        pubkey.try_into().unwrap(),
        digest.try_into().unwrap(),
        signature.try_into().unwrap(),
    ) {
        Ok(true) => Ok(()),
        _ => Err(ProgramError::InvalidArgument),
    }
}

/// `pubkey (96) || digest (48) || r || s (96)`, the layout the verifier scans.
fn sigverify_ix(
    public_key_xy: &[u8; 96],
    digest: &[u8; 48],
    signature_rs: &[u8; 96],
) -> Instruction {
    let mut data = public_key_xy.to_vec();
    data.extend_from_slice(digest);
    data.extend_from_slice(signature_rs);
    Instruction {
        program_id: SIGVERIFY_ID,
        accounts: vec![],
        data,
    }
}

fn funded(owner: Pubkey, data: Vec<u8>) -> Account {
    Account {
        lamports: 100_000_000,
        owner,
        data,
        ..Account::default()
    }
}
#[tokio::test]
async fn full_snp_bank_staging_preserves_real_crypto_consent_and_nonce_one_shot() {
    let pid = solana_confidential_compute_verifier::id();
    let workload = Keypair::new();
    let payer = Keypair::new();
    let mut scalar = [0; 48];
    scalar[47] = 33;
    let signing = SigningKey::from_slice(&scalar).unwrap();
    let encoded = signing.verifying_key().to_encoded_point(false);
    let xy: [u8; 96] = encoded.as_bytes()[1..].try_into().unwrap();
    let chip_id = [0x51; 64];
    let chip_hash = hash(&chip_id).to_bytes();
    let identity_revocation = Pubkey::find_program_address(
        &[
            solana_confidential_compute_verifier::state::AmdIdentityRevocation::SEED,
            &chip_hash,
        ],
        &pid,
    )
    .0;
    let tcb = 0u64;
    let (registry, rb) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (vcek, vb) =
        Pubkey::find_program_address(&[VcekAccount::SEED, &chip_hash, &tcb.to_le_bytes()], &pid);
    let mut measurements = [[0; 48]; 8];
    measurements[0] = [0x42; 48];
    let policy = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: payer.pubkey().to_bytes(),
        ark_pubkey_xy: [0; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 1,
        measurements,
        bump: rb,
    };
    let cache = VcekAccount::new(chip_hash, tcb, xy, 1, vb).with_validity(i64::MAX as u64);
    let backend = Pubkey::find_program_address(&[b"backend_policy", &[1]], &pid);
    let mut pt = sbf::verifier_program_test(pid);
    pt.add_program("secp384r1_sigverify", SIGVERIFY_ID, processor!(sigverify));
    pt.add_account(
        payer.pubkey(),
        funded(solana_sdk_ids::system_program::ID, vec![]),
    );
    pt.add_account(
        workload.pubkey(),
        funded(solana_sdk_ids::system_program::ID, vec![]),
    );
    pt.add_account(registry, funded(pid, borsh::to_vec(&policy).unwrap()));
    pt.add_account(vcek, funded(pid, borsh::to_vec(&cache).unwrap()));
    pt.add_account(
        backend.0,
        funded(
            pid,
            borsh::to_vec(&BackendPolicy {
                discriminator: BackendPolicy::DISCRIMINATOR,
                source: 1,
                measurement_count: 1,
                measurements,
                bump: backend.1,
            })
            .unwrap(),
        ),
    );
    let mut ctx = pt.start_with_context().await;
    let clock: Clock = ctx.banks_client.get_sysvar().await.unwrap();
    let slots: solana_sdk::slot_hashes::SlotHashes = ctx.banks_client.get_sysvar().await.unwrap();
    let (nonce_slot, nonce_hash) = slots.first().unwrap();
    let nonce = nonce_hash.to_bytes();
    let mut report = [0; 1184];
    report[..4].copy_from_slice(&1u32.to_le_bytes());
    report[8..16].copy_from_slice(&(1u64 << 17).to_le_bytes());
    report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    report[0x50..0x70].copy_from_slice(workload.pubkey().as_ref());
    report[0x70..0x90].copy_from_slice(&nonce);
    report[0x90..0xc0].fill(0x42);
    report[0x1a0..0x1e0].copy_from_slice(&chip_id);
    let signature: Signature = signing
        .sign_prehash(&Sha384::digest(&report[..672]))
        .unwrap();
    let bytes = signature.to_bytes();
    for i in 0..48 {
        report[0x2a0 + i] = bytes[47 - i];
        report[0x2e8 + i] = bytes[95 - i];
    }
    let (signer, sb) =
        Pubkey::find_program_address(&[b"attested_signer_v2", workload.pubkey().as_ref()], &pid);
    let (used, nb) =
        Pubkey::find_program_address(&[b"nonce", &[1], workload.pubkey().as_ref(), &nonce], &pid);
    let legacy =
        Pubkey::find_program_address(&[b"nonce", workload.pubkey().as_ref(), &nonce], &pid).0;
    let mut payload = VERIFY_AND_REGISTER_DISCRIMINATOR.to_vec();
    payload.extend(nonce_slot.to_le_bytes());
    payload.extend(report);
    payload.extend([nb, sb]);
    let digest = hash(&payload);
    let stage = Pubkey::find_program_address(
        &[
            b"attestation_stage",
            payer.pubkey().as_ref(),
            digest.as_ref(),
        ],
        &pid,
    )
    .0;
    let pair = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(stage, false),
    ];
    let make = |tag: [u8; 8], rest: Vec<u8>, accounts: Vec<AccountMeta>| {
        let mut data = tag.to_vec();
        data.extend(rest);
        Instruction {
            program_id: pid,
            accounts,
            data,
        }
    };
    let mut begin = digest.to_bytes().to_vec();
    begin.extend((payload.len() as u32).to_le_bytes());
    begin.extend((clock.slot + 150).to_le_bytes());
    let mut begin_accounts = pair.clone();
    begin_accounts.push(AccountMeta::new_readonly(
        solana_sdk_ids::system_program::ID,
        false,
    ));
    let mut packets = vec![make(BEGIN, begin, begin_accounts)];
    for (index, chunk) in payload.chunks(MAX_CHUNK).enumerate() {
        let mut rest = ((index * MAX_CHUNK) as u32).to_le_bytes().to_vec();
        rest.extend(chunk);
        packets.push(make(UPLOAD, rest, pair.clone()));
    }
    packets.push(make(SEAL, vec![], pair.clone()));
    for ix in packets.clone() {
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            ctx.last_blockhash,
        );
        assert!(
            solana_packet::Packet::from_data(None, &tx)
                .unwrap()
                .meta()
                .size
                <= 1232
        );
        ctx.banks_client.process_transaction(tx).await.unwrap();
    }
    let mut accounts = pair.clone();
    accounts.extend([
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new_readonly(registry, false),
        AccountMeta::new_readonly(vcek, false),
        AccountMeta::new(signer, false),
        AccountMeta::new(used, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        AccountMeta::new_readonly(workload.pubkey(), true),
        AccountMeta::new_readonly(backend.0, false),
        AccountMeta::new_readonly(legacy, false),
        AccountMeta::new_readonly(identity_revocation, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
    ]);
    let consume = make(CONSUME, vec![], accounts);
    // The verifier recomputes both and compares them to the precompile's bytes.
    let precompile = sigverify_ix(
        &xy,
        &Sha384::digest(&report[..672]).into(),
        &bytes.as_slice().try_into().unwrap(),
    );
    // Missing workload consent fails and leaves both nonce and sealed stage intact.
    let mut missing = consume.clone();
    missing.accounts[10].is_signer = false;
    let tx = Transaction::new_signed_with_payer(
        &[precompile.clone(), missing],
        Some(&payer.pubkey()),
        &[&payer],
        ctx.last_blockhash,
    );
    assert_eq!(
        ctx.banks_client
            .process_transaction(tx)
            .await
            .unwrap_err()
            .unwrap(),
        solana_sdk::transaction::TransactionError::InstructionError(
            1,
            solana_sdk::instruction::InstructionError::MissingRequiredSignature
        )
    );
    assert!(ctx.banks_client.get_account(used).await.unwrap().is_none());
    assert_eq!(
        ctx.banks_client
            .get_account(stage)
            .await
            .unwrap()
            .unwrap()
            .data[88],
        1
    );
    let tx = Transaction::new_signed_with_payer(
        &[precompile.clone(), consume.clone()],
        Some(&payer.pubkey()),
        &[&payer, &workload],
        ctx.last_blockhash,
    );
    assert!(
        solana_packet::Packet::from_data(None, &tx)
            .unwrap()
            .meta()
            .size
            <= 1232
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    let saved = ctx.banks_client.get_account(used).await.unwrap().unwrap();
    assert_eq!(saved.data.len(), UsedNonceAccount::SIZE);
    assert!(ctx
        .banks_client
        .get_account(signer)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        ctx.banks_client
            .get_account(stage)
            .await
            .unwrap()
            .unwrap()
            .data[88],
        2
    );
    ctx.last_blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[precompile.clone(), consume.clone()],
        Some(&payer.pubkey()),
        &[&payer, &workload],
        ctx.last_blockhash,
    );
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());
    let tx = Transaction::new_signed_with_payer(
        &[make(CLOSE, vec![], pair.clone())],
        Some(&payer.pubkey()),
        &[&payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    assert!(ctx.banks_client.get_account(stage).await.unwrap().is_none());
    assert_eq!(
        ctx.banks_client
            .get_account(used)
            .await
            .unwrap()
            .unwrap()
            .data,
        saved.data
    );
    // A new upload of the same evidence after refund must still hit the nonce
    // tombstone; storage lifecycle is not replay authority.
    ctx.last_blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    for ix in packets {
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            ctx.last_blockhash,
        );
        ctx.banks_client.process_transaction(tx).await.unwrap();
    }
    let tx = Transaction::new_signed_with_payer(
        &[precompile, consume],
        Some(&payer.pubkey()),
        &[&payer, &workload],
        ctx.last_blockhash,
    );
    assert_eq!(
        ctx.banks_client
            .process_transaction(tx)
            .await
            .unwrap_err()
            .unwrap(),
        solana_sdk::transaction::TransactionError::InstructionError(
            1,
            solana_sdk::instruction::InstructionError::Custom(
                solana_confidential_compute_verifier::error::VerifierError::NonceAlreadyUsed as u32
            )
        )
    );
    assert_eq!(
        ctx.banks_client
            .get_account(stage)
            .await
            .unwrap()
            .unwrap()
            .data[88],
        1
    );
    assert_eq!(
        ctx.banks_client
            .get_account(used)
            .await
            .unwrap()
            .unwrap()
            .data,
        saved.data
    );
}
