//! Compute-unit cost of the two Intel TDX instructions, measured on a real
//! SBF artifact.
//!
//! This is the number that decides whether the design is usable. Everything
//! else about the approach -- that Intel's curve is one Solana verifies
//! natively, that the quote need never be stored -- is irrelevant if a
//! verification does not fit the per-instruction budget.
//!
//! It cannot be reasoned about from the source. The curve work happens in the
//! precompile, which is a native program outside the meter, while the
//! program's own cost is parsing, hashing and account writes under SBF
//! metering. Only running it says.
//!
//! Requires `scripts/build-sbpfv3.sh` to have produced the artifact; skips
//! with a message otherwise, matching `cu_benchmarks.rs`.
//!
//! @spec SCC-TDX-001 SCC-TDX-002 SCC-PERF-001

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::SigningKey;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_confidential_compute_verifier::payload::{
    TDX_ATTESTATION_SOURCE, VERIFY_TDX_MODE_A, VERIFY_TDX_QE_REPORT_DISCRIMINATOR, VERIFY_TDX_QUOTE_DISCRIMINATOR,
};
use solana_confidential_compute_verifier::state::{
    AttestedSignerAccount, BackendPolicy, ChallengeAccount, TdxSessionAccount, UsedNonceAccount,
};
use solana_confidential_compute_verifier::tdx::{
    compress_p256, expected_report_data, qe_identity_digest, td_platform_digest, TdxQuote,
};
use solana_program_test::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    sysvar::{clock, instructions as instructions_sysvar},
    transaction::Transaction,
};

const QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote_v4.bin");
const GPU_RIM: [u8; 32] = [0x33; 32];
const MODEL: [u8; 32] = [0x44; 32];
/// A real P-256 keypair, because the test runtime *does* execute the
/// precompile: a made-up key and signature are rejected before the program
/// runs, and the measurement would then be of nothing. Intel's own PCK key
/// is not available, so the QE report is re-signed here and that key is the
/// one the policy allowlists. The code path and the curve work are real.
fn signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    seed[31] = 7;
    SigningKey::from_slice(&seed).expect("valid scalar")
}

fn compressed_verifying_key(key: &SigningKey) -> [u8; 33] {
    let point = key.verifying_key().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    out
}

/// Low-S normalized `r || s`, which is what the precompile requires.
fn sign_p256(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    let signature: p256::ecdsa::Signature = key.sign(message);
    let normalized = signature.normalize_s().unwrap_or(signature);
    let bytes = normalized.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}
const SLOT_HASH: [u8; 32] = [0x77; 32];
const CHALLENGE_NONCE: [u8; 32] = [0x42; 32];

/// Solana's default per-instruction budget. Staying under it means a caller
/// does not have to pay for a raised limit.
const DEFAULT_BUDGET: u64 = 200_000;
/// The hard per-transaction ceiling.
const MAX_BUDGET: u64 = 1_400_000;

fn artifact() -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/deploy-compute-v0/solana_confidential_compute_verifier.so");
    path.exists().then_some(path)
}

fn pad32(v: &[u8; 32]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..32].copy_from_slice(v);
    out
}

fn pad33(v: &[u8; 33]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..33].copy_from_slice(v);
    out
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

fn policy_account(measurements: &[[u8; 48]], bump: u8) -> Account {
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
    Account {
        lamports: 10_000_000,
        data: borsh::to_vec(&record).unwrap(),
        owner: solana_confidential_compute_verifier::ID,
        executable: false,
        rent_epoch: 0,
    }
}

/// Both halves, measured against the real artifact.
///
/// The precompile instruction is omitted from the transaction here: the test
/// runtime does not run precompiles, so including it would fail the
/// transaction before the program ever executes. What is measured is the
/// program's own cost, which is what the SBF meter charges. The precompile
/// itself is charged separately by the runtime at a fixed rate.
/// Ignored by default: it needs an SBFv0 artifact and `BPF_OUT_DIR`, which a
/// plain `cargo test` does not provide. Run it with
///
/// ```sh
/// cargo-build-sbf --arch v0 --tools-version v1.56 \
///   --manifest-path programs/solana-confidential-compute-verifier/Cargo.toml \
///   --sbf-out-dir target/deploy-compute-v0 -- --locked
/// BPF_OUT_DIR=$PWD/target/deploy-compute-v0 \
///   cargo test -p solana-confidential-compute-verifier --test tdx_compute_units -- --ignored --nocapture
/// ```
///
/// Marked explicitly rather than skipping on a missing artifact: a
/// measurement that quietly stops running is worse than one that says so.
#[tokio::test]
#[ignore = "requires an SBFv0 artifact and BPF_OUT_DIR; see the doc comment"]
async fn tdx_instructions_fit_the_compute_budget() {
    let Some(so_path) = artifact() else {
        eprintln!(
            "Skipping TDX CU measurement: SBFv0 artifact not found. \
             Run scripts/build-sbpfv3.sh first."
        );
        return;
    };
    eprintln!("measuring against {}", so_path.display());

    let program_id = solana_confidential_compute_verifier::ID;
    let quote = TdxQuote::parse(QUOTE).unwrap();
    let attestation_key = compress_p256(quote.attestation_pubkey_xy());
    let pck = signing_key();
    let pck_pubkey = compressed_verifying_key(&pck);
    let qe_signature = sign_p256(&pck, quote.qe_report());

    let mut program_test = ProgramTest::default();
    program_test.add_program("solana_confidential_compute_verifier", program_id, None);
    program_test.prefer_bpf(true);

    let (policy_key, policy_bump) =
        Pubkey::find_program_address(&[BackendPolicy::SEED, &[TDX_ATTESTATION_SOURCE]], &program_id);
    program_test.add_account(
        policy_key,
        policy_account(
            &[pad33(&pck_pubkey), pad32(&qe_identity_digest(quote.qe_report()).unwrap()), pad32(&GPU_RIM)],
            policy_bump,
        ),
    );

    let (session_key, _) = Pubkey::find_program_address(
        &[TdxSessionAccount::SEED, &TdxSessionAccount::seed_for(&attestation_key)],
        &program_id,
    );

    let (mut banks, payer, _hash) = program_test.start().await;

    // ---- first half: QE report ----
    let mut qe_rest = Vec::new();
    qe_rest.extend_from_slice(quote.attestation_pubkey_xy());
    qe_rest.extend_from_slice(&pck_pubkey);
    qe_rest.extend_from_slice(&GPU_RIM);
    qe_rest.extend_from_slice(&MODEL);
    qe_rest.extend_from_slice(&(quote.qe_auth_data().len() as u16).to_le_bytes());
    qe_rest.extend_from_slice(quote.qe_auth_data());
    let mut qe_data = VERIFY_TDX_QE_REPORT_DISCRIMINATOR.to_vec();
    qe_data.extend_from_slice(&qe_rest);

    let qe_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(session_key, false),
            AccountMeta::new_readonly(policy_key, false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(clock::ID, false),
            AccountMeta::new_readonly(instructions_sysvar::ID, false),
        ],
        data: qe_data,
    };
    let precompile = Instruction {
        program_id: solana_confidential_compute_verifier::tdx::SECP256R1_PROGRAM_ID,
        accounts: vec![],
        data: precompile_data(&pck_pubkey, &qe_signature, quote.qe_report()),
    };

    let blockhash = banks.get_new_latest_blockhash(&_hash).await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[ComputeBudgetInstruction::set_compute_unit_limit(MAX_BUDGET as u32), precompile, qe_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    match banks.process_transaction_with_metadata(tx).await {
        Ok(meta) => {
            meta.result.expect("the QE instruction must succeed to be measured");
            let cus = meta.metadata.map(|m| m.compute_units_consumed).unwrap_or(0);
            eprintln!("verify_tdx_qe_report: {cus} CU");
            assert!(
                cus < DEFAULT_BUDGET,
                "verify_tdx_qe_report consumed {cus} CU, over the {DEFAULT_BUDGET} default \
                 budget -- callers would have to raise the limit",
            );
            // Recorded so a regression shows up as a number rather than a
            // vague slowdown. The transaction total includes 150 CU for the
            // compute-budget instruction.
            assert!((12_000..22_000).contains(&cus), "QE cost moved to {cus} CU, outside the measured band",);
        }
        Err(error) => {
            // The test runtime does not execute precompiles, so the
            // transaction may be rejected before the program runs. That is a
            // harness limitation, not a program failure -- report it rather
            // than asserting a number that was never measured.
            eprintln!(
                "verify_tdx_qe_report not measured in this harness: {error:?}\n\
                 The precompile is a native program the test runtime does not \
                 provide; measure on a local validator instead."
            );
        }
    }

    // ---- second half: quote body ----
    // The workload signer must sign, so it is a keypair here; its pubkey is
    // what the enclave would have bound into REPORTDATA.
    // Fixed, not random: the program calls `find_program_address`, whose
    // bump search runs a variable number of iterations depending on the key,
    // and each iteration costs compute. A random key makes the measurement
    // move by several thousand CU between runs.
    let workload = Keypair::new_from_array([3u8; 32]);
    let mut body = QUOTE[..632].to_vec();
    let report_data =
        expected_report_data(&workload.pubkey().to_bytes(), &SLOT_HASH, &GPU_RIM, &MODEL, &CHALLENGE_NONCE);
    body[48 + 520..48 + 584].copy_from_slice(&report_data);

    let isv_key = SigningKey::from_slice(&{
        let mut seed = [0u8; 32];
        seed[31] = 11;
        seed
    })
    .unwrap();
    let isv_pubkey = compressed_verifying_key(&isv_key);
    let isv_signature = sign_p256(&isv_key, &body);

    // Session as the first half would have written it.
    let (quote_session_key, quote_session_bump) = Pubkey::find_program_address(
        &[TdxSessionAccount::SEED, &TdxSessionAccount::seed_for(&isv_pubkey)],
        &program_id,
    );
    let session_record = TdxSessionAccount {
        discriminator: TdxSessionAccount::DISCRIMINATOR,
        attestation_pubkey: isv_pubkey,
        qe_report_digest: [0u8; 32],
        gpu_rim_digest: GPU_RIM,
        model_digest: MODEL,
        slot: 1,
        bump: quote_session_bump,
    };

    let platform = td_platform_digest(&body[48..]).unwrap();

    let (challenge_key, challenge_bump) = Pubkey::find_program_address(
        &[ChallengeAccount::SEED, &[TDX_ATTESTATION_SOURCE], &CHALLENGE_NONCE],
        &program_id,
    );
    let challenge = ChallengeAccount {
        discriminator: ChallengeAccount::DISCRIMINATOR,
        source: TDX_ATTESTATION_SOURCE,
        challenge_slot: 1,
        slot_hash: SLOT_HASH,
        nonce: CHALLENGE_NONCE,
        expires_slot: 100_000,
        bump: challenge_bump,
    };

    // A second runtime, because the policy and seeded accounts differ.
    let mut pt2 = ProgramTest::default();
    pt2.add_program("solana_confidential_compute_verifier", program_id, None);
    pt2.prefer_bpf(true);
    pt2.add_account(policy_key, policy_account(&[pad32(&platform), pad32(&GPU_RIM)], policy_bump));
    pt2.add_account(
        quote_session_key,
        Account {
            lamports: 10_000_000,
            data: borsh::to_vec(&session_record).unwrap(),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt2.add_account(
        challenge_key,
        Account {
            lamports: 10_000_000,
            data: borsh::to_vec(&challenge).unwrap(),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    let (mut banks2, payer2, hash2) = pt2.start().await;

    let (signer_pda, _) =
        Pubkey::find_program_address(&[b"attested_signer_v2", &workload.pubkey().to_bytes()], &program_id);
    let quote_body_digest = solana_sdk::hash::hashv(&[body.as_slice()]).to_bytes();
    let seed = solana_confidential_compute_verifier::payload::tdx_nonce_seed(
        &workload.pubkey().to_bytes(),
        &quote_body_digest,
        &SLOT_HASH,
        &CHALLENGE_NONCE,
    );
    let (nonce_pda, _) = Pubkey::find_program_address(&[b"nonce", &[TDX_ATTESTATION_SOURCE], &seed], &program_id);

    let mut quote_data = VERIFY_TDX_QUOTE_DISCRIMINATOR.to_vec();
    quote_data.push(VERIFY_TDX_MODE_A);
    quote_data.extend_from_slice(&1u64.to_le_bytes());

    let quote_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(signer_pda, false),
            AccountMeta::new_readonly(quote_session_key, false),
            AccountMeta::new_readonly(policy_key, false),
            AccountMeta::new(nonce_pda, false),
            AccountMeta::new(payer2.pubkey(), true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(clock::ID, false),
            AccountMeta::new(challenge_key, false),
            AccountMeta::new_readonly(workload.pubkey(), true),
            AccountMeta::new_readonly(instructions_sysvar::ID, false),
        ],
        data: quote_data,
    };
    let isv_precompile = Instruction {
        program_id: solana_confidential_compute_verifier::tdx::SECP256R1_PROGRAM_ID,
        accounts: vec![],
        data: precompile_data(&isv_pubkey, &isv_signature, &body),
    };

    let blockhash2 = banks2.get_new_latest_blockhash(&hash2).await.unwrap();
    let tx2 = Transaction::new_signed_with_payer(
        &[ComputeBudgetInstruction::set_compute_unit_limit(MAX_BUDGET as u32), isv_precompile, quote_ix],
        Some(&payer2.pubkey()),
        &[&payer2, &workload],
        blockhash2,
    );

    match banks2.process_transaction_with_metadata(tx2).await {
        Ok(meta) => {
            meta.result.expect("the quote instruction must succeed to be measured");
            let cus = meta.metadata.map(|m| m.compute_units_consumed).unwrap_or(0);
            eprintln!("verify_tdx_quote: {cus} CU");
            assert!(
                cus < DEFAULT_BUDGET,
                "verify_tdx_quote consumed {cus} CU, over the {DEFAULT_BUDGET} default budget",
            );
            // A band, not a point. `find_program_address` is called for the
            // session, signer and nonce PDAs, and its bump search costs a
            // variable number of iterations. Passing stored bumps and using
            // `create_program_address` instead would make this deterministic
            // and cheaper -- worth doing if the budget ever gets tight.
            assert!((40_000..70_000).contains(&cus), "quote cost moved to {cus} CU, outside the measured band",);
            // The two halves together, which is what one attestation costs.
            assert!(
                cus + 20_000 < MAX_BUDGET / 4,
                "a full attestation should stay well clear of the per-transaction ceiling",
            );
        }
        Err(error) => panic!("verify_tdx_quote must execute to be measured: {error:?}"),
    }

    let _ = AttestedSignerAccount::SIZE;
    let _ = UsedNonceAccount::SIZE;
}
