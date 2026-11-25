// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Compute Unit (CU) Benchmarking Suite for Solana Confidential Compute Verifier SBF Program.
//!
//! @spec SCC-PERF-001 SCC-PERF-002 SCC-PERF-003

use borsh::BorshSerialize;
use p384::ecdsa::signature::hazmat::PrehashSigner;
use p384::ecdsa::SigningKey;
use sha2::{Digest, Sha384};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_confidential_compute_core::types::{compute_action_commitment, VerifyAtomicHeader};
use solana_confidential_compute_core::SNP_REPORT_SIZE;
use solana_confidential_compute_verifier::payload::{
    InitPolicyRegistryArgs, VerifyAndRegisterArgs, INIT_POLICY_REGISTRY_DISCRIMINATOR,
    VERIFY_AND_REGISTER_DISCRIMINATOR, VERIFY_ATOMIC_DISCRIMINATOR, VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
};
use solana_confidential_compute_verifier::state::{BackendPolicy, VcekAccount, VCEK_ACCOUNT_DISCRIMINATOR};
use solana_program_test::*;
use solana_sdk::{
    account::Account,
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    sysvar::{clock, slot_hashes},
    transaction::Transaction,
};

fn test_keypair(seed_lsb: u8) -> (SigningKey, [u8; 96]) {
    let mut seed = [0u8; 48];
    seed[47] = seed_lsb;
    let signing_key = SigningKey::from_slice(&seed).expect("valid scalar");
    let encoded = signing_key.verifying_key().to_sec1_point(false);
    let mut xy = [0u8; 96];
    xy[..48].copy_from_slice(encoded.x().unwrap().as_slice());
    xy[48..].copy_from_slice(encoded.y().unwrap().as_slice());
    (signing_key, xy)
}

fn sign_snp_report(report: &mut [u8; SNP_REPORT_SIZE], signing_key: &SigningKey) {
    let mut hasher = Sha384::new();
    hasher.update(&report[0..672]);
    let digest: [u8; 48] = hasher.finalize().into();
    let (signature, _) = signing_key.sign_prehash(&digest).unwrap();
    let sig_bytes = signature.to_bytes();
    for i in 0..48 {
        report[0x2A0 + i] = sig_bytes[47 - i];
        report[0x2E8 + i] = sig_bytes[95 - i];
    }
}

fn create_mock_report(user_data: &[u8; 64], measurement: &[u8; 48], signing_key: &SigningKey) -> [u8; SNP_REPORT_SIZE] {
    let mut report = [0u8; SNP_REPORT_SIZE];
    report[0..4].copy_from_slice(&2u32.to_le_bytes());
    report[8..16].copy_from_slice(&(1u64 << 17).to_le_bytes()); // SMT enabled
    report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes()); // P-384 ECDSA
    report[0x50..0x90].copy_from_slice(user_data);
    report[0x90..0xC0].copy_from_slice(measurement);
    report[0x180] = 1; // boot_loader
    report[0x181] = 1; // tee
    report[0x186] = 1; // snp
    report[0x187] = 1; // microcode
    sign_snp_report(&mut report, signing_key);
    report
}

#[tokio::test]
#[ignore = "requires agave v4.3+ SBPFv3 runner"]
async fn test_cu_benchmarks_live_sbf() {
    let out_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy");
    let so_path = out_dir.join("solana_confidential_compute_verifier.so");
    if !so_path.exists() {
        eprintln!(
            "Skipping live SBF CU benchmark: {} not found. Build with scripts/build-sbpfv3.sh first.",
            so_path.display()
        );
        return;
    }
    if let Ok(bytes) = std::fs::read(&so_path) {
        if bytes.len() >= 52 && bytes[48] == 3 {
            eprintln!(
                "Skipping live SBF CU benchmark: {} is an SBPFv3 binary (e_flags=0x3) requiring Agave v4.3+ runtime (Devnet/Mainnet). Local solana-program-test 2.2 does not support SBPFv3 ELFs.",
                so_path.display()
            );
            return;
        }
    }
    std::env::set_var("SBF_OUT_DIR", &out_dir);

    let program_id = solana_confidential_compute_verifier::ID;
    let (signing_key, vcek_xy) = test_keypair(0x07);
    let chip_id_hash = hashv(&[&vcek_xy]).to_bytes();
    let tcb_version = u64::from_le_bytes([1, 1, 0, 0, 0, 0, 1, 1]);
    let measurement = [42u8; 48];
    let action_hash = [0x11u8; 32];
    let consumer_program = Pubkey::new_unique();

    let (registry_pda, _) = Pubkey::find_program_address(&[b"policy_registry"], &program_id);
    let (vcek_pda, vcek_bump) =
        Pubkey::find_program_address(&[b"vcek_v2", &chip_id_hash, &tcb_version.to_le_bytes()], &program_id);

    let mut program_test = ProgramTest::default();
    program_test.prefer_bpf(true);
    program_test.set_compute_max_units(1_400_000);
    program_test.add_program("solana_confidential_compute_verifier", program_id, None);

    // Seed VCEK account directly
    let mut vcek_data = vec![0u8; VcekAccount::SIZE];
    VcekAccount {
        discriminator: VCEK_ACCOUNT_DISCRIMINATOR,
        chip_id_hash,
        tcb_version,
        public_key_xy: vcek_xy,
        registered_slot: 100,
        bump: vcek_bump,

        trust_profile: VcekAccount::MILAN_TRUST_PROFILE,
        valid_until_unix: u64::MAX,
        is_revoked: false,
    }
    .serialize(&mut &mut vcek_data[..])
    .unwrap();
    program_test.add_account(
        vcek_pda,
        Account { lamports: 10_000_000, data: vcek_data, owner: program_id, executable: false, rent_epoch: 0 },
    );

    // #183: AMD (source 1) measurements are checked against the readonly backend policy.
    let (backend_policy_pda, backend_policy_bump) =
        Pubkey::find_program_address(&[BackendPolicy::SEED, &[1]], &program_id);
    let mut backend_measurements = [[0u8; 48]; 8];
    backend_measurements[0] = measurement;
    program_test.add_account(
        backend_policy_pda,
        Account {
            lamports: 10_000_000,
            data: borsh::to_vec(&BackendPolicy {
                discriminator: BackendPolicy::DISCRIMINATOR,
                source: 1,
                measurement_count: 1,
                measurements: backend_measurements,
                bump: backend_policy_bump,
            })
            .unwrap(),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let mut ctx = program_test.start_with_context().await;
    let loader = solana_sdk_ids::bpf_loader_upgradeable::id();
    let (program_data_pda, _) = Pubkey::find_program_address(&[program_id.as_ref()], &loader);
    let mut program_data = vec![0; 45];
    program_data[..4].copy_from_slice(&3u32.to_le_bytes());
    program_data[12] = 1;
    program_data[13..45].copy_from_slice(ctx.payer.pubkey().as_ref());
    ctx.set_account(
        &program_data_pda,
        &Account { lamports: 1_000_000, data: program_data, owner: loader, executable: false, rent_epoch: 0 }.into(),
    );
    let (banks_client, payer, recent_blockhash) = (ctx.banks_client, ctx.payer, ctx.last_blockhash);

    let slot_hashes_sysvar: solana_sdk::slot_hashes::SlotHashes = banks_client.get_sysvar().await.unwrap();
    let nonce_slot = 0u64;
    let slot_hash = slot_hashes_sysvar
        .iter()
        .find(|(slot, _)| *slot == nonce_slot)
        .map(|(_, h)| h.to_bytes())
        .expect("slot 0 in SlotHashes");

    // ------------------------------------------------------------------------
    // Benchmark 1: init_policy_registry
    // ------------------------------------------------------------------------
    let mut measurements = [[0u8; 48]; 8];
    measurements[0] = measurement;
    let mut init_ix_data = Vec::new();
    init_ix_data.extend_from_slice(&INIT_POLICY_REGISTRY_DISCRIMINATOR);
    InitPolicyRegistryArgs {
        authority: payer.pubkey().to_bytes(),
        ark_pubkey_xy: [0u8; 96],
        min_tcb_boot_loader: 1,
        min_tcb_tee: 0,
        min_tcb_snp: 1,
        min_tcb_microcode: 1,
        measurement_count: 1,
        measurements,
    }
    .serialize(&mut init_ix_data)
    .unwrap();

    let init_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(registry_pda, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(program_data_pda, false),
        ],
        data: init_ix_data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[ComputeBudgetInstruction::set_compute_unit_limit(100_000), init_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    let res = banks_client.process_transaction_with_metadata(tx).await.unwrap();
    assert!(res.result.is_ok(), "init_policy_registry failed");
    let init_cus = res.metadata.unwrap().compute_units_consumed;
    assert!(init_cus <= 15_000, "init_policy_registry exceeded 15,000 CUs: {}", init_cus);

    // ------------------------------------------------------------------------
    // Benchmark 2: Mode A (verify_and_register)
    // ------------------------------------------------------------------------
    let workload_keypair = Keypair::new_from_array([0x77u8; 32]);
    let mut mode_a_user_data = [0u8; 64];
    mode_a_user_data[0..32].copy_from_slice(&workload_keypair.pubkey().to_bytes());
    mode_a_user_data[32..64].copy_from_slice(&slot_hash);
    let mode_a_report = create_mock_report(&mode_a_user_data, &measurement, &signing_key);

    let (signer_pda, signer_bump) =
        Pubkey::find_program_address(&[b"attested_signer_v2", &workload_keypair.pubkey().to_bytes()], &program_id);
    let (used_nonce_pda_a, nonce_bump) =
        Pubkey::find_program_address(&[b"nonce", &[1], &workload_keypair.pubkey().to_bytes(), &slot_hash], &program_id);

    let mut mode_a_ix_data = Vec::new();
    mode_a_ix_data.extend_from_slice(&VERIFY_AND_REGISTER_DISCRIMINATOR);
    VerifyAndRegisterArgs { nonce_slot, report: mode_a_report }.serialize(&mut mode_a_ix_data).unwrap();
    mode_a_ix_data.push(nonce_bump);
    mode_a_ix_data.push(signer_bump);

    let mode_a_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new_readonly(vcek_pda, false),
            AccountMeta::new(signer_pda, false),
            AccountMeta::new(used_nonce_pda_a, false),
            AccountMeta::new_readonly(slot_hashes::ID, false),
            AccountMeta::new_readonly(clock::ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(backend_policy_pda, false),
        ],
        data: mode_a_ix_data,
    };

    let tx_a = Transaction::new_signed_with_payer(
        &[ComputeBudgetInstruction::set_compute_unit_limit(550_000), mode_a_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    let res_a = banks_client.process_transaction_with_metadata(tx_a).await.unwrap();
    assert!(res_a.result.is_ok(), "verify_and_register failed: {:?}", res_a.result);
    let mode_a_cus = res_a.metadata.unwrap().compute_units_consumed;
    assert!(
        mode_a_cus <= 550_000,
        "@spec SCC-PERF-001 violated: verify_and_register consumed {} CUs > 550,000",
        mode_a_cus
    );

    // ------------------------------------------------------------------------
    // Benchmark 3: Mode B Stateless (verify_atomic)
    // ------------------------------------------------------------------------
    let commitment = compute_action_commitment(&slot_hash, &action_hash, &consumer_program.to_bytes());
    let workload_signer = [0x88u8; 32];
    let mut mode_b_user_data = [0u8; 64];
    mode_b_user_data[0..32].copy_from_slice(&workload_signer);
    mode_b_user_data[32..64].copy_from_slice(&commitment);
    let mode_b_report = create_mock_report(&mode_b_user_data, &measurement, &signing_key);

    let header = VerifyAtomicHeader { nonce_slot, action_hash, consumer_program_id: consumer_program.to_bytes() };
    let mut mode_b_ix_data = Vec::new();
    mode_b_ix_data.extend_from_slice(&VERIFY_ATOMIC_DISCRIMINATOR);
    header.serialize(&mut mode_b_ix_data).unwrap();
    mode_b_ix_data.extend_from_slice(&mode_b_report);

    let mode_b_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new_readonly(vcek_pda, false),
            AccountMeta::new_readonly(slot_hashes::ID, false),
            AccountMeta::new_readonly(clock::ID, false),
            AccountMeta::new_readonly(backend_policy_pda, false),
        ],
        data: mode_b_ix_data,
    };

    let tx_b = Transaction::new_signed_with_payer(
        &[ComputeBudgetInstruction::set_compute_unit_limit(550_000), mode_b_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    let res_b =
        banks_client.process_transaction_with_metadata(tx_b).await.expect("verify_atomic transaction processed");
    assert!(res_b.result.is_err(), "verify_atomic must fail-closed without nonce: {:?}", res_b.result);
    let mode_b_cus = res_b.metadata.as_ref().map(|m| m.compute_units_consumed).unwrap_or(0);
    assert!(mode_b_cus <= 550_000, "@spec SCC-PERF-002 violated: verify_atomic consumed {} CUs > 550,000", mode_b_cus);

    // ------------------------------------------------------------------------
    // Benchmark 4: Mode B with Nonce (verify_atomic_with_nonce)
    // ------------------------------------------------------------------------
    let workload_signer = [0x88u8; 32];
    let (used_nonce_pda_b, nonce_bump_b) =
        Pubkey::find_program_address(&[b"nonce", &[1], &workload_signer, &commitment], &program_id);

    let mut mode_b_nonce_ix_data = Vec::new();
    mode_b_nonce_ix_data.extend_from_slice(&VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
    header.serialize(&mut mode_b_nonce_ix_data).unwrap();
    mode_b_nonce_ix_data.extend_from_slice(&mode_b_report);
    mode_b_nonce_ix_data.push(nonce_bump_b);

    let mode_b_nonce_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new_readonly(vcek_pda, false),
            AccountMeta::new(used_nonce_pda_b, false),
            AccountMeta::new_readonly(slot_hashes::ID, false),
            AccountMeta::new_readonly(clock::ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(backend_policy_pda, false),
        ],
        data: mode_b_nonce_ix_data,
    };

    let tx_b_nonce = Transaction::new_signed_with_payer(
        &[ComputeBudgetInstruction::set_compute_unit_limit(550_000), mode_b_nonce_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    let res_b_nonce = banks_client.process_transaction_with_metadata(tx_b_nonce).await.unwrap();
    assert!(res_b_nonce.result.is_ok(), "verify_atomic_with_nonce failed: {:?}", res_b_nonce.result);
    let mode_b_nonce_cus = res_b_nonce.metadata.unwrap().compute_units_consumed;
    assert!(mode_b_nonce_cus <= 550_000, "verify_atomic_with_nonce consumed {} CUs > 550,000", mode_b_nonce_cus);

    // ------------------------------------------------------------------------
    // Benchmark Summary Reporting (@spec SCC-PERF-003)
    // ------------------------------------------------------------------------
    // Mode B now allocates a UsedNonceAccount (H-01), so CUs are comparable to Mode A.
    // SCC-PERF-001 / SCC-PERF-002 require both paths stay at or below 550,000 CUs.
    assert!(
        mode_a_cus <= 550_000,
        "@spec SCC-PERF-001 violated: verify_and_register consumed {} CUs > 550,000",
        mode_a_cus
    );
    assert!(
        mode_b_nonce_cus <= 550_000,
        "@spec SCC-PERF-002 violated: verify_atomic_with_nonce consumed {} CUs > 550,000",
        mode_b_nonce_cus
    );

    println!("\n================================================================================");
    println!("SOLANA CONFIDENTIAL COMPUTE VERIFIER SBF COMPUTE UNIT BENCHMARK REPORT");
    println!("================================================================================");
    println!("{:<35} {:<15} {:<15} {:<15}", "Instruction", "Measured CUs", "Ceiling CUs", "Headroom");
    println!("--------------------------------------------------------------------------------");
    println!("{:<35} {:<15} {:<15} {:<15}", "init_policy_registry", init_cus, 15_000, 15_000i64 - init_cus as i64);
    println!(
        "{:<35} {:<15} {:<15} {:<15}",
        "verify_and_register (Mode A)",
        mode_a_cus,
        550_000,
        550_000i64 - mode_a_cus as i64
    );
    println!(
        "{:<35} {:<15} {:<15} {:<15}",
        "verify_atomic (Mode B)",
        mode_b_cus,
        550_000,
        550_000i64 - mode_b_cus as i64
    );
    println!(
        "{:<35} {:<15} {:<15} {:<15}",
        "verify_atomic_with_nonce (Mode B)",
        mode_b_nonce_cus,
        550_000,
        550_000i64 - mode_b_nonce_cus as i64
    );
    println!("--------------------------------------------------------------------------------");
    println!("Mode A and Mode B (with nonce) are both under the 550,000 CU ceiling (SCC-PERF-002).");
    println!("================================================================================\n");
}
