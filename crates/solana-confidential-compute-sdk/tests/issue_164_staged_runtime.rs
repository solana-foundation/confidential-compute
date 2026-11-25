// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Real signed packets and bank CPI allocation through the staged transport.
//!
//! MIGRATION (solana 2.2 -> 4.x): this ran the chain twice, once natively via
//! `processor!(Processor::process)` and once as `#[ignore]`d SBF. In 4.x
//! `Clock::get()` resolves through `solana_get_sysvar::sol_get_sysvar`, whose
//! non-solana branch is a hardcoded `UNSUPPORTED_SYSVAR` that never consults
//! `program_stubs`, so a natively linked program can no longer read any sysvar.
//! Every staged BEGIN/UPLOAD/SEAL/CONSUME reads the clock, so the native half
//! can no longer run at all and the two paths collapse into one real-SBF run.
//!
//! The `#[ignore]`d half also asserted `e_flags == 0` (SBPFv0) on the artifact.
//! That assertion is dropped rather than updated, because the arch is no longer
//! fixed: a bare `cargo-build-sbf` still emits SBPFv0 into `target/deploy`,
//! which is what the ProgramTest suites run against, while the deployed release
//! is SBPFv3 from `scripts/build-sbpfv3.sh`. This test is arch-agnostic and
//! passes against either; pinning one would just break whenever the other is
//! the last thing to write `target/deploy/solana_confidential_compute_verifier.so`. Metered
//! `compute_units_consumed` already proves real bytecode executed. Every
//! account, instruction and assertion is otherwise unchanged.
use solana_confidential_compute_sdk::staged::*;
use solana_confidential_compute_verifier::{
    payload::REGISTER_VCEK_DISCRIMINATOR,
    state::{PolicyRegistry, VcekAccount, POLICY_REGISTRY_DISCRIMINATOR},
};
use solana_sdk::{
    account::Account,
    clock::Clock,
    hash::hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Signer,
    transaction::Transaction,
};

#[path = "support/sbf.rs"]
mod sbf;

#[tokio::test]
async fn sbf_real_chain_allocate_upload_seal_consume_close() {
    let pid = solana_confidential_compute_verifier::id();
    let (registry_key, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let registry = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: [9; 32],
        ark_pubkey_xy: [0; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 0,
        measurements: [[0; 48]; 8],
        bump,
    };
    let mut test = sbf::verifier_program_test(pid);
    test.add_account(
        registry_key,
        Account { lamports: 100000000, data: registry_bytes(&registry), owner: pid, executable: false, rent_epoch: 0 },
    );
    let mut ctx = test.start_with_context().await;
    let mut clock: Clock = ctx.banks_client.get_sysvar().await.unwrap();
    clock.unix_timestamp = 1790288000;
    ctx.set_sysvar(&clock);
    let ask = include_bytes!("../../solana-confidential-compute-crypto/tests/data/milan_ask.der");
    let leaf = include_bytes!("../../../fixtures/vcek_milan.der");
    // Extract the fixture SPKI BIT STRING; cryptographic validation stays in the handler.
    let key_at = leaf.windows(4).position(|b| b == [3, 98, 0, 4]).unwrap() + 4;
    let identity = solana_confidential_compute_crypto_identity(leaf);
    let chip_hash = hash(&identity.0);
    let tcb = identity.1.to_le_bytes();
    let (vcek, _) = Pubkey::find_program_address(&[VcekAccount::SEED, chip_hash.as_ref(), &tcb], &pid);
    let mut data = REGISTER_VCEK_DISCRIMINATOR.to_vec();
    data.extend(identity.0);
    data.extend(tcb);
    data.extend(&leaf[key_at..key_at + 96]);
    data.extend((ask.len() as u16).to_le_bytes());
    data.extend((leaf.len() as u16).to_le_bytes());
    data.extend(ask);
    data.extend(leaf);
    let payer = ctx.payer.pubkey();
    let source = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(registry_key, false),
            AccountMeta::new(vcek, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        ],
        data,
    };
    let plan = stage_vcek_registration(source.clone(), payer, clock.slot, clock.slot + 100).unwrap();
    for ix in std::iter::once(&plan.begin).chain(plan.uploads.iter()).chain([&plan.seal, &plan.consume]) {
        let mut tx = if ix.data == CONSUME {
            plan.consume_transaction(ctx.last_blockhash, 1_400_000).unwrap()
        } else {
            Transaction::new_unsigned(solana_sdk::message::Message::new_with_blockhash(
                std::slice::from_ref(ix),
                Some(&payer),
                &ctx.last_blockhash,
            ))
        };
        tx.sign(&[&ctx.payer], ctx.last_blockhash);
        assert!(bincode::serialize(&tx).unwrap().len() <= 1232);
        let result = ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap();
        assert!(result.result.is_ok(), "{:?}", result);
        let meta = result.metadata.expect("metered SBF metadata");
        assert!(meta.compute_units_consumed > 0);
        eprintln!("REAL_SBF transport tag={:?} CU={}", &ix.data[..8], meta.compute_units_consumed);
    }
    let account = ctx.banks_client.get_account(vcek).await.unwrap().unwrap();
    assert_eq!(
        &account.data[VcekAccount::PUBLIC_KEY_OFFSET..VcekAccount::PUBLIC_KEY_OFFSET + 96],
        &leaf[key_at..key_at + 96]
    );
    assert_eq!(ctx.banks_client.get_account(plan.address).await.unwrap().unwrap().data[88], 2);
    ctx.last_blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let replay = Transaction::new_signed_with_payer(
        std::slice::from_ref(&plan.consume),
        Some(&payer),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    assert!(ctx.banks_client.process_transaction(replay).await.is_err());
    let saved_vcek = ctx.banks_client.get_account(vcek).await.unwrap().unwrap();
    let mut bad_source = source;
    *bad_source.data.last_mut().unwrap() ^= 1;
    let bad = stage_vcek_registration(bad_source, payer, clock.slot, clock.slot + 100).unwrap();
    for ix in std::iter::once(&bad.begin).chain(bad.uploads.iter()).chain([&bad.seal]) {
        let tx = Transaction::new_signed_with_payer(
            std::slice::from_ref(ix),
            Some(&payer),
            &[&ctx.payer],
            ctx.last_blockhash,
        );
        assert!(bincode::serialize(&tx).unwrap().len() <= 1232);
        ctx.banks_client.process_transaction(tx).await.unwrap();
    }
    let mut invalid = bad.consume_transaction(ctx.last_blockhash, 1_400_000).unwrap();
    invalid.sign(&[&ctx.payer], ctx.last_blockhash);
    let invalid = ctx.banks_client.process_transaction_with_metadata(invalid).await.unwrap();
    assert!(
        matches!(
            invalid.result,
            // Index 1: `consume_transaction` prepends the compute budget request.
            Err(solana_sdk::transaction::TransactionError::InstructionError(
                1,
                solana_sdk::instruction::InstructionError::Custom(2)
            ))
        ),
        "{:?}",
        invalid
    );
    assert_eq!(ctx.banks_client.get_account(vcek).await.unwrap().unwrap(), saved_vcek);
    assert_eq!(ctx.banks_client.get_account(bad.address).await.unwrap().unwrap().data[88], 1);
    eprintln!("REAL_SBF invalid_signature CU={}", invalid.metadata.unwrap().compute_units_consumed);
    let close = Transaction::new_signed_with_payer(&[plan.close], Some(&payer), &[&ctx.payer], ctx.last_blockhash);
    ctx.banks_client.process_transaction(close).await.unwrap();
    assert!(ctx.banks_client.get_account(plan.address).await.unwrap().is_none());
}
// Fixture identity is independently encoded in its AMD OID extensions. Avoid a
// new production dependency in the SDK; this helper reads the known fixture via
// the report's chip/TCB fields which the on-chain certificate parser checks.
fn solana_confidential_compute_crypto_identity(_leaf: &[u8]) -> ([u8; 64], u64) {
    let report = include_bytes!("../../../fixtures/snp_hardware_report_milan.bin");
    let view = solana_confidential_compute_core::SnpReportView::try_from_slice(report).unwrap();
    (*view.chip_id(), view.reported_tcb())
}

fn registry_bytes(registry: &PolicyRegistry) -> Vec<u8> {
    let mut bytes = vec![0; PolicyRegistry::SIZE];
    bytes[..8].copy_from_slice(&registry.discriminator);
    bytes[8..40].copy_from_slice(&registry.authority);
    bytes[528] = registry.bump;
    bytes
}
