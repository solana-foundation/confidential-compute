//! Integration tests for the Solana Confidential Compute reference consumer.
//!
//! @spec SCC-CONSUMER-001 SCC-CONSUMER-002
//!
//! MIGRATION (solana 2.2 -> 4.x): the consumer was registered natively via
//! `processor!(process_instruction)`. In 4.x `Clock::get()` resolves through
//! `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch is a hardcoded
//! `UNSUPPORTED_SYSVAR` that never consults `program_stubs`, so a natively
//! linked program can no longer read any sysvar. Mode A expiry runs through
//! `solana_confidential_compute_cpi`'s `Clock::get()`, so the consumer must execute as real SBF
//! bytecode; the no-op verifier fixture stays native because it reads nothing.
//! Every account, instruction and assertion is unchanged, but the CU ceilings
//! are now measured against real bytecode rather than a builtin call frame.

use solana_confidential_compute_consumer_reference::{
    hash_action, AttestedSignerAccount, CpiError, EXPECTED_MEASUREMENT, IX_EXECUTE_ATOMIC_ACTION,
    IX_EXECUTE_SESSION_ACTION, MODE_A_CU_CEILING, MODE_B_CU_CEILING, VERIFIER_PROGRAM_ID, VERIFY_ATOMIC_DISCRIMINATOR,
    VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
};
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    signature::{Keypair, Signer},
    sysvar::instructions,
    transaction::{Transaction, TransactionError},
};

#[path = "common/sbf.rs"]
mod sbf;

const SNP_REPORT_SIZE: usize = 1184;
const HAPPY_EXPIRES_SLOT: u64 = 1_000_000;
const ACTION_PAYLOAD: [u8; 2] = [0xAB, 0xCD];
const WORKLOAD_SIGNER: [u8; 32] = [0x33; 32];

fn noop_confidential_compute(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    Ok(())
}

fn program_test() -> ProgramTest {
    let mut pt = sbf::consumer_program_test(solana_confidential_compute_consumer_reference::id());
    pt.add_program("solana_confidential_compute_verifier", VERIFIER_PROGRAM_ID, processor!(noop_confidential_compute));
    pt
}

fn pack_attested_signer(signer_pubkey: [u8; 32], measurement: [u8; 48], expires_slot: u64) -> Vec<u8> {
    AttestedSignerAccount {
        discriminator: AttestedSignerAccount::DISCRIMINATOR,
        signer_pubkey,
        enclave_type: 1,
        measurement,
        chip_id_hash: [0u8; 32],
        tcb_version: [0u8; 8],
        registered_slot: [0u8; 8],
        expires_slot: expires_slot.to_le_bytes(),
        bump: 255,
        expires_unix_timestamp: i64::MAX.to_le_bytes(),
    }
    .as_bytes()
    .to_vec()
}

fn add_attested_signer(
    pt: &mut ProgramTest,
    signer_pubkey: [u8; 32],
    measurement: [u8; 48],
    expires_slot: u64,
    owner: Pubkey,
) -> Pubkey {
    let key = Pubkey::new_unique();
    pt.add_account(
        key,
        Account {
            lamports: 1_000_000,
            data: pack_attested_signer(signer_pubkey, measurement, expires_slot),
            owner,
            executable: false,
            rent_epoch: 0,
        },
    );
    key
}

fn session_ix(attested_signer: Pubkey, workload_signer: Pubkey) -> Instruction {
    Instruction {
        program_id: solana_confidential_compute_consumer_reference::id(),
        accounts: vec![
            AccountMeta::new_readonly(attested_signer, false),
            AccountMeta::new_readonly(workload_signer, true),
        ],
        data: vec![IX_EXECUTE_SESSION_ACTION],
    }
}

fn atomic_confidential_compute_ix(require_nonce: bool, action_hash: [u8; 32], measurement: [u8; 48]) -> Instruction {
    let disc = if require_nonce { VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR } else { VERIFY_ATOMIC_DISCRIMINATOR };
    let mut data = Vec::with_capacity(80 + SNP_REPORT_SIZE);
    data.extend_from_slice(&disc);
    data.extend_from_slice(&500u64.to_le_bytes());
    data.extend_from_slice(&action_hash);
    data.extend_from_slice(solana_confidential_compute_consumer_reference::id().as_ref());
    let mut report = vec![0u8; SNP_REPORT_SIZE];
    report[0x50..0x70].copy_from_slice(&WORKLOAD_SIGNER);
    report[0x90..0xC0].copy_from_slice(&measurement);
    data.extend_from_slice(&report);
    Instruction { program_id: VERIFIER_PROGRAM_ID, accounts: vec![], data }
}

fn atomic_consumer_ix(payload: &[u8]) -> Instruction {
    let mut data = Vec::with_capacity(1 + payload.len());
    data.push(IX_EXECUTE_ATOMIC_ACTION);
    data.extend_from_slice(payload);
    Instruction {
        program_id: solana_confidential_compute_consumer_reference::id(),
        accounts: vec![AccountMeta::new_readonly(instructions::ID, false)],
        data,
    }
}

/// Same digest `execute_atomic_action` computes for the instructions-sysvar account.
fn attested_action_hash(payload: &[u8]) -> [u8; 32] {
    let sysvar = instructions::ID;
    hash_action(
        &[IX_EXECUTE_ATOMIC_ACTION],
        &[solana_program::instruction::AccountMeta::new_readonly(sysvar, false)],
        payload,
    )
}

fn custom_err(code: CpiError) -> InstructionError {
    InstructionError::Custom(code as u32)
}

#[tokio::test]
async fn mode_a_happy_path_and_cu_budget() {
    let workload_signer = Keypair::new();
    let mut pt = program_test();
    let attested = add_attested_signer(
        &mut pt,
        workload_signer.pubkey().to_bytes(),
        EXPECTED_MEASUREMENT,
        HAPPY_EXPIRES_SLOT,
        VERIFIER_PROGRAM_ID,
    );
    let context = pt.start_with_context().await;
    let ix = session_ix(attested, workload_signer.pubkey());
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&context.payer.pubkey()),
        &[&context.payer, &workload_signer],
        context.last_blockhash,
    );
    let res = context.banks_client.process_transaction_with_metadata(tx).await.expect("mode A transaction processed");
    assert!(res.result.is_ok(), "mode A happy path failed: {:?}", res.result);
    let cus = res.metadata.unwrap().compute_units_consumed;
    eprintln!("Mode A consumer CUs: {cus} (ceiling {MODE_A_CU_CEILING})");
    assert!(
        cus <= MODE_A_CU_CEILING,
        "@spec SCC-CONSUMER-001 violated: Mode A consumed {cus} CUs > {MODE_A_CU_CEILING}"
    );
}

#[tokio::test]
async fn mode_a_rejects_expired_slot() {
    let workload_signer = Keypair::new();
    let mut pt = program_test();
    let attested =
        add_attested_signer(&mut pt, workload_signer.pubkey().to_bytes(), EXPECTED_MEASUREMENT, 0, VERIFIER_PROGRAM_ID);
    let context = pt.start_with_context().await;
    let tx = Transaction::new_signed_with_payer(
        &[session_ix(attested, workload_signer.pubkey())],
        Some(&context.payer.pubkey()),
        &[&context.payer, &workload_signer],
        context.last_blockhash,
    );
    let res = context.banks_client.process_transaction_with_metadata(tx).await.expect("expired transaction processed");
    assert_eq!(
        res.result.unwrap_err(),
        TransactionError::InstructionError(0, custom_err(CpiError::AttestationExpired))
    );
}

#[tokio::test]
async fn mode_a_rejects_wrong_measurement() {
    let workload_signer = Keypair::new();
    let mut pt = program_test();
    let attested = add_attested_signer(
        &mut pt,
        workload_signer.pubkey().to_bytes(),
        [0x99; 48],
        HAPPY_EXPIRES_SLOT,
        VERIFIER_PROGRAM_ID,
    );
    let context = pt.start_with_context().await;
    let tx = Transaction::new_signed_with_payer(
        &[session_ix(attested, workload_signer.pubkey())],
        Some(&context.payer.pubkey()),
        &[&context.payer, &workload_signer],
        context.last_blockhash,
    );
    let res = context
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .expect("wrong-measurement transaction processed");
    assert_eq!(
        res.result.unwrap_err(),
        TransactionError::InstructionError(0, custom_err(CpiError::DisallowedMeasurement))
    );
}

#[tokio::test]
async fn mode_a_rejects_missing_signature() {
    let workload_signer = Keypair::new();
    let mut pt = program_test();
    let attested = add_attested_signer(
        &mut pt,
        workload_signer.pubkey().to_bytes(),
        EXPECTED_MEASUREMENT,
        HAPPY_EXPIRES_SLOT,
        VERIFIER_PROGRAM_ID,
    );
    let context = pt.start_with_context().await;
    let ix = Instruction {
        program_id: solana_confidential_compute_consumer_reference::id(),
        accounts: vec![
            AccountMeta::new_readonly(attested, false),
            AccountMeta::new_readonly(workload_signer.pubkey(), false),
        ],
        data: vec![IX_EXECUTE_SESSION_ACTION],
    };
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let res = context
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .expect("missing-signature transaction processed");
    assert_eq!(
        res.result.unwrap_err(),
        TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature)
    );
}

#[tokio::test]
async fn mode_a_rejects_signer_mismatch() {
    let workload_signer = Keypair::new();
    let packed_signer = Keypair::new();
    let mut pt = program_test();
    let attested = add_attested_signer(
        &mut pt,
        packed_signer.pubkey().to_bytes(),
        EXPECTED_MEASUREMENT,
        HAPPY_EXPIRES_SLOT,
        VERIFIER_PROGRAM_ID,
    );
    let context = pt.start_with_context().await;
    let tx = Transaction::new_signed_with_payer(
        &[session_ix(attested, workload_signer.pubkey())],
        Some(&context.payer.pubkey()),
        &[&context.payer, &workload_signer],
        context.last_blockhash,
    );
    let res = context
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .expect("signer-mismatch transaction processed");
    assert_eq!(res.result.unwrap_err(), TransactionError::InstructionError(0, custom_err(CpiError::SignerMismatch)));
}

#[tokio::test]
async fn mode_a_rejects_wrong_owner() {
    let workload_signer = Keypair::new();
    let mut pt = program_test();
    let attested = add_attested_signer(
        &mut pt,
        workload_signer.pubkey().to_bytes(),
        EXPECTED_MEASUREMENT,
        HAPPY_EXPIRES_SLOT,
        Pubkey::new_unique(),
    );
    let context = pt.start_with_context().await;
    let tx = Transaction::new_signed_with_payer(
        &[session_ix(attested, workload_signer.pubkey())],
        Some(&context.payer.pubkey()),
        &[&context.payer, &workload_signer],
        context.last_blockhash,
    );
    let res =
        context.banks_client.process_transaction_with_metadata(tx).await.expect("wrong-owner transaction processed");
    assert_eq!(res.result.unwrap_err(), TransactionError::InstructionError(0, InstructionError::IncorrectProgramId));
}

#[tokio::test]
async fn mode_b_happy_path_and_cu_budget() {
    let context = program_test().start_with_context().await;
    let action_hash = attested_action_hash(&ACTION_PAYLOAD);
    let tx = Transaction::new_signed_with_payer(
        &[atomic_confidential_compute_ix(true, action_hash, EXPECTED_MEASUREMENT), atomic_consumer_ix(&ACTION_PAYLOAD)],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let res = context.banks_client.process_transaction_with_metadata(tx).await.expect("mode B transaction processed");
    assert!(res.result.is_ok(), "mode B happy path failed: {:?}", res.result);
    let cus = res.metadata.unwrap().compute_units_consumed;
    eprintln!("Mode B consumer CUs: {cus} (ceiling {MODE_B_CU_CEILING})");
    assert!(
        cus <= MODE_B_CU_CEILING,
        "@spec SCC-CONSUMER-002 violated: Mode B consumed {cus} CUs > {MODE_B_CU_CEILING}"
    );
}

#[tokio::test]
async fn mode_b_rejects_missing_nonce() {
    let context = program_test().start_with_context().await;
    let action_hash = attested_action_hash(&ACTION_PAYLOAD);
    let tx = Transaction::new_signed_with_payer(
        &[
            atomic_confidential_compute_ix(false, action_hash, EXPECTED_MEASUREMENT),
            atomic_consumer_ix(&ACTION_PAYLOAD),
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let res =
        context.banks_client.process_transaction_with_metadata(tx).await.expect("missing-nonce transaction processed");
    assert_eq!(
        res.result.unwrap_err(),
        TransactionError::InstructionError(1, custom_err(CpiError::UnsupportedAttestationInstruction))
    );
}

#[tokio::test]
async fn mode_b_rejects_tampered_action_hash() {
    let context = program_test().start_with_context().await;
    let action_hash = attested_action_hash(&ACTION_PAYLOAD);
    let tx = Transaction::new_signed_with_payer(
        &[atomic_confidential_compute_ix(true, action_hash, EXPECTED_MEASUREMENT), atomic_consumer_ix(&[0xAB, 0xCE])],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let res =
        context.banks_client.process_transaction_with_metadata(tx).await.expect("tampered-hash transaction processed");
    assert_eq!(
        res.result.unwrap_err(),
        TransactionError::InstructionError(1, custom_err(CpiError::ActionHashMismatch))
    );
}

#[tokio::test]
async fn mode_a_rejects_other_platform_with_same_measurement() {
    let workload = Keypair::new();
    let mut pt = program_test();
    let key = Pubkey::new_unique();
    let mut data = pack_attested_signer(workload.pubkey().to_bytes(), EXPECTED_MEASUREMENT, HAPPY_EXPIRES_SLOT);
    data[40] = 3; // GCP; this consumer explicitly pins AMD.
    pt.add_account(
        key,
        Account { lamports: 1_000_000, data, owner: VERIFIER_PROGRAM_ID, executable: false, rent_epoch: 0 },
    );
    let context = pt.start_with_context().await;
    let tx = Transaction::new_signed_with_payer(
        &[session_ix(key, workload.pubkey())],
        Some(&context.payer.pubkey()),
        &[&context.payer, &workload],
        context.last_blockhash,
    );
    let result = context.banks_client.process_transaction_with_metadata(tx).await.unwrap();
    assert_eq!(result.result, Err(TransactionError::InstructionError(0, custom_err(CpiError::PlatformMismatch))));
}

#[tokio::test]
async fn mode_a_rejects_v2_unix_expiry_from_trusted_clock() {
    let workload = Keypair::new();
    let mut pt = program_test();
    let key = Pubkey::new_unique();
    let mut data = pack_attested_signer(workload.pubkey().to_bytes(), EXPECTED_MEASUREMENT, HAPPY_EXPIRES_SLOT);
    data[146..154].copy_from_slice(&1000i64.to_le_bytes());
    pt.add_account(
        key,
        Account { lamports: 1_000_000, data, owner: VERIFIER_PROGRAM_ID, executable: false, rent_epoch: 0 },
    );
    let context = pt.start_with_context().await;
    context.set_sysvar(&solana_sdk::clock::Clock { slot: 1, unix_timestamp: 1000, ..Default::default() });
    let tx = Transaction::new_signed_with_payer(
        &[session_ix(key, workload.pubkey())],
        Some(&context.payer.pubkey()),
        &[&context.payer, &workload],
        context.last_blockhash,
    );
    let result = context.banks_client.process_transaction_with_metadata(tx).await.unwrap();
    assert_eq!(result.result, Err(TransactionError::InstructionError(0, custom_err(CpiError::AttestationExpired))));
}
