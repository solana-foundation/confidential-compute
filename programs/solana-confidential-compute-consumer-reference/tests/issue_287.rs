//! Controlled consumer runtime test; the verifier is intentionally a no-op.
//! This isolates helper call-frame binding, not attestation cryptography.
use solana_confidential_compute_cpi::{
    assert_attestation_atomic, AtomicAttestationExpectation, VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    pubkey::Pubkey,
    sysvar::instructions,
};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    signature::Signer,
    transaction::{Transaction, TransactionError},
};

const CONSUMER: Pubkey = Pubkey::new_from_array([71; 32]);
const MEASUREMENT: [u8; 48] = [42; 48];

fn verifier(_: &Pubkey, _: &[AccountInfo], _: &[u8]) -> ProgramResult {
    Ok(())
}

fn consumer(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data == [1] {
        // Invoke the same program twice. Each inner frame sees the same previous
        // top-level verifier and the same Instructions-sysvar current index.
        let ix = Instruction {
            program_id: *program_id,
            accounts: vec![AccountMeta::new_readonly(instructions::ID, false)],
            data: vec![0],
        };
        invoke(&ix, accounts)?;
        invoke(&ix, accounts)?;
        return Ok(());
    }
    assert_attestation_atomic(
        &accounts[0],
        &AtomicAttestationExpectation {
            expected_measurement: MEASUREMENT,
            action_hash: [9; 32],
            ..Default::default()
        },
        program_id,
    )?;
    Ok(())
}

async fn run(nested: bool) -> Result<(), TransactionError> {
    let mut pt = ProgramTest::new("controlled_consumer", CONSUMER, processor!(consumer));
    pt.add_program(
        "noop_verifier",
        solana_confidential_compute_cpi::ID,
        processor!(verifier),
    );
    let ctx = pt.start_with_context().await;
    let mut data = VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&10u64.to_le_bytes());
    data.extend_from_slice(&[9; 32]);
    data.extend_from_slice(CONSUMER.as_ref());
    let mut report = vec![0; 1184];
    report[0x90..0xc0].copy_from_slice(&MEASUREMENT);
    data.extend_from_slice(&report);
    let mut accounts = vec![AccountMeta::new_readonly(instructions::ID, false)];
    if nested {
        accounts.push(AccountMeta::new_readonly(CONSUMER, false));
    }
    let tx = Transaction::new_signed_with_payer(
        &[
            Instruction {
                program_id: solana_confidential_compute_cpi::ID,
                accounts: vec![],
                data,
            },
            Instruction {
                program_id: CONSUMER,
                accounts,
                data: vec![u8::from(nested)],
            },
        ],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client
        .process_transaction(tx)
        .await
        .map_err(|e| e.unwrap())
}

#[tokio::test]
async fn issue_287_direct_consumer_still_passes() {
    run(false).await.unwrap();
}

#[tokio::test]
async fn issue_287_self_cpi_cannot_reuse_top_level_attestation() {
    // Keep the expected code numeric so the regression compiles on baseline.
    assert_eq!(
        run(true).await.unwrap_err(),
        TransactionError::InstructionError(
            1,
            solana_sdk::instruction::InstructionError::Custom(1018)
        )
    );
}
