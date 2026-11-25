//! Real SBF metering of the Google JWT path against the actual SBPFv0 artifact.
//!
//! MIGRATION (solana 2.2 -> 4.x): this ran twice -- once natively via
//! `processor!(Processor::process)` as a fixture/handler control, once against
//! an artifact named by `SOLANA_CC_SBF_ARTIFACT` (`#[ignore]`d by default). In 4.x
//! `Rent::get()` resolves through `solana_get_sysvar::sol_get_sysvar`, whose
//! non-solana branch is a hardcoded `UNSUPPORTED_SYSVAR` that never consults
//! `program_stubs`, so the natively linked program cannot allocate the registry
//! PDA and the control half is no longer runnable at all. The two halves
//! collapse into one real-SBF test. The compute assertions that used to sit
//! behind `#[ignore]` now always run, and the invalid-signature assertion that
//! used to be conditional is now unconditional. The artifact still comes from
//! the build output only -- `sbf::add_sbf_program` panics rather than silently
//! falling back to a native processor.
use borsh::BorshSerialize;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_confidential_compute_crypto::jwt::{compute_n0_and_r2, eat_nonce_tombstone_seed, kid_hash, RSA_EXPONENT};
use solana_confidential_compute_verifier::{payload::*, state::*};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_sdk::{
    account::Account,
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

#[path = "common/cu_tracker.rs"]
mod cu_tracker;
#[path = "common/sbf.rs"]
mod sbf;
const LIMIT: u32 = 1_400_000;
fn fixture() -> ([u8; 256], &'static str) {
    let mut lines = include_str!("../../../fixtures/jwt_compute_165.txt").lines();
    let hex = lines.next().unwrap();
    let jwt = lines.next().unwrap();
    let mut modulus = [0; 256];
    for (i, b) in modulus.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    (modulus, jwt)
}
fn owned(data: Vec<u8>, owner: Pubkey) -> Account {
    Account { lamports: 10_000_000, data, owner, executable: false, rent_epoch: 0 }
}
fn noop(_: &Pubkey, _: &[solana_sdk::account_info::AccountInfo], _: &[u8]) -> solana_sdk::entrypoint::ProgramResult {
    Ok(())
}
async fn send(
    ctx: &mut ProgramTestContext,
    ixs: &[Instruction],
    authority: Option<&Keypair>,
) -> (Result<(), TransactionError>, u64) {
    let mut instructions = vec![ComputeBudgetInstruction::set_compute_unit_limit(LIMIT)];
    instructions.extend_from_slice(ixs);
    let mut signers = vec![&ctx.payer];
    if let Some(key) = authority {
        signers.push(key);
    }
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(&instructions, Some(&ctx.payer.pubkey()), &signers, blockhash);
    let result = ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap();
    let metadata = result.metadata.expect("execution metadata required");
    eprintln!("result={:?} units={}", result.result, metadata.compute_units_consumed);
    (result.result, metadata.compute_units_consumed)
}
async fn run() {
    let pid = solana_confidential_compute_verifier::ID;
    let authority = Keypair::new();
    let consumer = Pubkey::new_from_array([0x33; 32]);
    let mut pt = ProgramTest::default();
    pt.set_compute_max_units(u64::from(LIMIT));
    // Provenance guard: metering is only meaningful against the real artifact.
    let path = sbf::so_path("solana_confidential_compute_verifier");
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.len() > 64 && &bytes[..4] == b"\x7fELF");
    assert_eq!(
        u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
        0,
        "program-test only supports SBPFv0; never claim v3 execution"
    );
    assert_eq!(path.file_name().unwrap(), "solana_confidential_compute_verifier.so");
    use sha2::{Digest, Sha256};
    eprintln!("actual SBPFv0 artifact sha256={:x} bytes={}", Sha256::digest(&bytes), bytes.len());
    sbf::add_sbf_program(&mut pt, "solana_confidential_compute_verifier", pid);
    // Only the inert consumer is native; it never touches a sysvar.
    //
    // `add_builtin_program`, not `add_program`: the latter resolves against
    // SBF_OUT_DIR when that variable is set, and then demands a
    // meter_consumer.so that does not exist and never will. It passes locally
    // only because the variable is usually unset there, so the same test fails
    // in the compute workflow, which exports it to point at the v0 artifact.
    pt.add_builtin_program(
        "meter_consumer",
        consumer,
        processor!(noop).expect("the processor macro always yields a registerer"),
    );
    pt.add_account(authority.pubkey(), owned(vec![], solana_sdk_ids::system_program::ID));
    let (registry, _) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    // Init authenticates the upgrade authority from canonical loader-owned ProgramData.
    let loader = solana_sdk_ids::bpf_loader_upgradeable::id();
    let (program_data, _) = Pubkey::find_program_address(&[pid.as_ref()], &loader);
    let mut program_data_bytes = vec![0; 45];
    program_data_bytes[..4].copy_from_slice(&3u32.to_le_bytes());
    program_data_bytes[12] = 1;
    program_data_bytes[13..45].copy_from_slice(authority.pubkey().as_ref());
    pt.add_account(program_data, owned(program_data_bytes, loader));
    let (modulus, jwt) = fixture();
    let hash = kid_hash(b"teton-test");
    let (jwks, jb) = Pubkey::find_program_address(&[b"jwks", &hash], &pid);
    let (n0, r2) = compute_n0_and_r2(&modulus).unwrap();
    pt.add_account(
        jwks,
        owned(
            borsh::to_vec(&JwksAccount {
                discriminator: JWKS_ACCOUNT_DISCRIMINATOR,
                kid_hash: hash,
                modulus,
                exponent: RSA_EXPONENT,
                n0,
                r2,
                registered_slot: 500,
                is_revoked: false,
                bump: jb,
            })
            .unwrap(),
            pid,
        ),
    );
    let registration_hash = kid_hash(b"meter-registration");
    let (registration, _) = Pubkey::find_program_address(&[b"jwks", &registration_hash], &pid);
    pt.add_account(registration, owned(vec![0; JwksAccount::SIZE], pid));
    // #183: JWT verification requires the canonical readonly GCP (source 3) backend policy.
    let (policy, policy_bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[3]], &pid);
    let mut policy_measurements = [[0; 48]; 8];
    policy_measurements[0][..32].fill(0xab);
    pt.add_account(
        policy,
        owned(
            borsh::to_vec(&BackendPolicy {
                discriminator: BackendPolicy::DISCRIMINATOR,
                source: 3,
                measurement_count: 1,
                measurements: policy_measurements,
                bump: policy_bump,
            })
            .unwrap(),
            pid,
        ),
    );
    let slot_hash = [0x11; 32];
    // Controlled V3 fixture shared with the native JWT processor regression.
    // Hash the actual complete consumer instruction, not an arbitrary digest.
    let consumer_ix = Instruction { program_id: consumer, accounts: vec![], data: vec![0x99; 11] };
    let action = solana_confidential_compute_core::action::hash_instruction(&consumer_ix);
    let commitment =
        solana_confidential_compute_core::types::compute_action_commitment(&slot_hash, &action, &consumer.to_bytes());
    // #205: GCP (source 3) tombstones live in the source-tagged namespace; the legacy
    // PDA is still passed (readonly, never created) so the migration guard can check it.
    let nonce_seed = eat_nonce_tombstone_seed(&commitment);
    let (nonce, _) = Pubkey::find_program_address(&[b"nonce", &[3], &nonce_seed], &pid);
    let (legacy_nonce, _) = Pubkey::find_program_address(&[b"nonce", &nonce_seed], &pid);
    pt.add_account(nonce, owned(vec![0; UsedNonceAccount::SIZE], pid));
    // Governed tenant scope for the fixture token's audience and subject (#199).
    let (tenant, tenant_bump) = Pubkey::find_program_address(&[GcpTenantPolicy::SEED], &pid);
    let tenant_policy = GcpTenantPolicy::new(
        b"teton-verifier",
        b"https://www.googleapis.com/compute/v1/projects/teton/zones/us/instances/vm",
        tenant_bump,
    )
    .unwrap();
    pt.add_account(tenant, owned(borsh::to_vec(&tenant_policy).unwrap(), pid));
    let mut ctx = pt.start_with_context().await;
    let clock = solana_sdk::clock::Clock { slot: 520, unix_timestamp: 1_700_000_100, ..Default::default() };
    ctx.set_sysvar(&clock);
    ctx.set_sysvar(&solana_sdk::slot_hashes::SlotHashes::new(&[(500, Hash::new_from_array(slot_hash))]));
    let mut measurements = [[0; 48]; 8];
    measurements[0][..32].fill(0xab);
    let mut data = INIT_POLICY_REGISTRY_DISCRIMINATOR.to_vec();
    InitPolicyRegistryArgs {
        authority: authority.pubkey().to_bytes(),
        ark_pubkey_xy: [0; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 1,
        measurements,
    }
    .serialize(&mut data)
    .unwrap();
    let init = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new(registry, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(program_data, false),
        ],
        data,
    };
    let (result, cu) = send(&mut ctx, &[init], Some(&authority)).await;
    assert!(result.is_ok(), "init sanity control");
    assert!(cu > 0 && cu < 100_000);
    let mut data = REGISTER_JWKS_KEY_DISCRIMINATOR.to_vec();
    RegisterJwksKeyArgs { kid: b"meter-registration".to_vec(), modulus, exponent: RSA_EXPONENT }
        .serialize(&mut data)
        .unwrap();
    let register = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new_readonly(authority.pubkey(), true),
            AccountMeta::new_readonly(registry, false),
            AccountMeta::new(registration, false),
            AccountMeta::new(ctx.payer.pubkey(), true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        ],
        data,
    };
    let (registered, reg_cu) = send(&mut ctx, &[register], Some(&authority)).await;
    eprintln!("REGISTER_JWKS_KEY cu={reg_cu} outcome={registered:?}");
    cu_tracker::record_cu("REGISTER_JWKS_KEY", reg_cu);
    let verify = |token: &str, payer: Pubkey| {
        let mut data = VERIFY_GOOGLE_JWT_DISCRIMINATOR.to_vec();
        VerifyGoogleJwtArgs {
            mode: VERIFY_GOOGLE_JWT_MODE_B,
            nonce_slot: 500,
            expected_action_hash: action,
            jwt: token.into(),
        }
        .serialize(&mut data)
        .unwrap();
        Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(Pubkey::new_unique(), false),
                AccountMeta::new_readonly(registry, false),
                AccountMeta::new_readonly(jwks, false),
                AccountMeta::new(nonce, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
                AccountMeta::new_readonly(tenant, false),
                AccountMeta::new_readonly(policy, false),
                AccountMeta::new_readonly(legacy_nonce, false),
            ],
            data,
        }
    };
    let good = verify(jwt, ctx.payer.pubkey());
    // Token-derived instruction data stays out of logs; Banks execution is not packet feasibility proof.
    let (verified, verify_cu) = send(&mut ctx, &[good, consumer_ix.clone()], None).await;
    eprintln!("VERIFY_GOOGLE_JWT cu={verify_cu} outcome={verified:?}");
    cu_tracker::record_cu("VERIFY_GOOGLE_JWT", verify_cu);
    // A fresh context would be needed for replay-independent valid-path repetition;
    // invalid signatures must reject before looking at the consumed nonce.
    let mut tampered = jwt.as_bytes().to_vec();
    let i = jwt.rfind('.').unwrap() + 1;
    tampered[i] = if tampered[i] == b'A' { b'B' } else { b'A' };
    let bad = verify(std::str::from_utf8(&tampered).unwrap(), ctx.payer.pubkey());
    let (invalid, invalid_cu) = send(&mut ctx, &[bad, consumer_ix], None).await;
    eprintln!("INVALID_SIGNATURE cu={invalid_cu} outcome={invalid:?}");
    cu_tracker::record_cu("INVALID_SIGNATURE", invalid_cu);
    assert!(invalid.is_err());
    assert_eq!(
        invalid,
        Err(TransactionError::InstructionError(
            1,
            solana_sdk::instruction::InstructionError::Custom(
                solana_confidential_compute_verifier::error::VerifierError::InvalidSignature as u32
            )
        ))
    );
    assert!(registered.is_ok(), "registration exceeds compute budget or fails: {registered:?}");
    assert!(verified.is_ok(), "verification exceeds compute budget or fails: {verified:?}");
    assert!(reg_cu <= 200_000, "registration exceeds default single-instruction budget");
    assert!(verify_cu <= 400_000, "JWT exceeds explicit sidecar budget request");
}
#[tokio::test]
async fn issue_165_actual_sbf_compute() {
    run().await;
}
