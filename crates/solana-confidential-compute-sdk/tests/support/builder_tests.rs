//! Transaction packing, discriminator, index, and error tests for solana-confidential-compute-sdk builders.
//!
//! @spec SCC-SDK-001 SCC-SEC-005

use solana_confidential_compute_sdk::internal::{
    build_atomic_attestation_tx_for_program_oversized,
    build_register_signer_ix_for_program_oversized, build_register_signer_ix_oversized,
};
use solana_confidential_compute_sdk::{
    build_atomic_attestation_tx, build_register_signer_ix, build_session_action_tx,
    compute_commitment, hash_action, ConfidentialComputeClient, SdkError, ATTESTATION_TTL_SLOTS,
    ID as SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID, MODE_B_REQUIRE_NONCE_DEFAULT, PACKET_DATA_SIZE,
    SNP_REPORT_SIZE, VERIFY_AND_REGISTER_DISCRIMINATOR, VERIFY_AND_REGISTER_IX_LEN,
    VERIFY_ATOMIC_DISCRIMINATOR, VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
    VERIFY_ATOMIC_WITH_NONCE_IX_LEN,
};
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    transaction::Transaction,
};

const MEASUREMENT: [u8; 48] = [0x42; 48];
const ACTION_HASH: [u8; 32] = [0x11; 32];
// Runtime nonce, fixed for the process so report and PDA expectations agree.
static NONCE: std::sync::LazyLock<[u8; 32]> =
    std::sync::LazyLock::new(|| solana_sdk::hash::Hash::new_unique().to_bytes());

fn sample_report(signer: [u8; 32], measurement: [u8; 48]) -> [u8; SNP_REPORT_SIZE] {
    let mut report = [0u8; SNP_REPORT_SIZE];
    report[0x1a0..0x1e0].fill(9);
    report[0x50..0x70].copy_from_slice(&signer);
    report[0x70..0x90].copy_from_slice(&*NONCE);
    report[0x90..0xC0].copy_from_slice(&measurement);
    report
}

fn dummy_consumer_ix(program_id: Pubkey, payer: Pubkey) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![AccountMeta::new(payer, true)],
        data: vec![0xAB, 0xCD],
    }
}

fn compiled_program_id(tx: &Transaction, ix_index: usize) -> Pubkey {
    let ix = &tx.message.instructions[ix_index];
    tx.message.account_keys[ix.program_id_index as usize]
}

#[test]
fn register_signer_ix_packs_verify_and_register() {
    let payer = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let report = sample_report(signer.to_bytes(), MEASUREMENT);
    let expires = 500 + ATTESTATION_TTL_SLOTS;

    let ix =
        build_register_signer_ix_oversized(&payer, &signer, &report, expires).expect("register ix");
    assert!(matches!(
        build_register_signer_ix(&payer, &signer, &report, expires),
        Err(SdkError::PacketTooLarge { len }) if len > PACKET_DATA_SIZE
    ));
    assert_eq!(ix.program_id, SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID);
    assert_eq!(&ix.data[..8], &VERIFY_AND_REGISTER_DISCRIMINATOR);
    assert_eq!(&ix.data[8..16], &0u64.to_le_bytes());
    assert_eq!(&ix.data[16..16 + SNP_REPORT_SIZE], report.as_slice());
    assert_eq!(ix.data.len(), VERIFY_AND_REGISTER_IX_LEN);
    assert_eq!(VERIFY_AND_REGISTER_IX_LEN, 1202);
    assert_eq!(ix.accounts.len(), 12);
    assert_eq!(ix.accounts[8], AccountMeta::new_readonly(signer, true));
    assert_eq!(
        ix.accounts[9],
        AccountMeta::new_readonly(
            solana_confidential_compute_sdk::derive_backend_policy_pda(
                &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
                1
            )
            .unwrap()
            .0,
            false
        )
    );
    assert_eq!(ix.accounts[0].pubkey, payer);
    assert!(ix.accounts[0].is_signer);
    let (signer_pda, signer_bump) = Pubkey::find_program_address(
        &[b"attested_signer_v2", signer.as_ref()],
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    );
    let (nonce_pda, nonce_bump) = Pubkey::find_program_address(
        &[b"nonce", &[1], signer.as_ref(), &*NONCE],
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    );
    assert_eq!(ix.accounts[3].pubkey, signer_pda);
    assert_eq!(ix.accounts[4].pubkey, nonce_pda);
    assert_eq!(ix.data[16 + SNP_REPORT_SIZE], nonce_bump);
    assert_eq!(ix.data[16 + SNP_REPORT_SIZE + 1], signer_bump);
}

#[test]
fn register_signer_ix_at_slot_packs_nonce_slot() {
    let payer = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let report = sample_report(signer.to_bytes(), MEASUREMENT);
    let program_id = Pubkey::new_unique();
    let ix = build_register_signer_ix_for_program_oversized(
        &program_id,
        &payer,
        &signer,
        &report,
        ATTESTATION_TTL_SLOTS,
        777,
    )
    .expect("register at slot");
    assert_eq!(ix.program_id, program_id);
    assert_eq!(&ix.data[8..16], &777u64.to_le_bytes());
}

#[test]
fn register_signer_ix_rejects_short_report_and_signer_mismatch() {
    let payer = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    assert_eq!(
        build_register_signer_ix(&payer, &signer, &[0u8; 16], 1).unwrap_err(),
        SdkError::InvalidReportSize
    );
    let report = sample_report(Pubkey::new_unique().to_bytes(), MEASUREMENT);
    assert_eq!(
        build_register_signer_ix(&payer, &signer, &report, 1).unwrap_err(),
        SdkError::SignerMismatch
    );
}

#[test]
fn session_action_tx_contains_consumer_ix_and_workload_signature() {
    let signer = Keypair::new();
    let consumer = Pubkey::new_unique();
    let blockhash = Hash::new_unique();
    let consumer_ix = dummy_consumer_ix(consumer, signer.pubkey());
    let tx = build_session_action_tx(&signer.pubkey(), &signer, consumer_ix.clone(), blockhash)
        .expect("session tx");
    assert_eq!(tx.message.instructions.len(), 1);
    assert_eq!(compiled_program_id(&tx, 0), consumer);
    assert_eq!(tx.message.instructions[0].data, consumer_ix.data);
    assert_eq!(tx.message.recent_blockhash, blockhash);
    assert_eq!(tx.signatures.len(), 1);
    assert_ne!(
        tx.signatures[0],
        solana_sdk::signature::Signature::default()
    );
}

#[test]
fn session_action_tx_promotes_existing_workload_account_to_signer() {
    let payer = Pubkey::new_unique();
    let signer = Keypair::new();
    let consumer = Pubkey::new_unique();
    let blockhash = Hash::new_unique();
    let consumer_ix = Instruction {
        program_id: consumer,
        accounts: vec![AccountMeta::new(signer.pubkey(), false)],
        data: vec![0x11],
    };
    let tx = build_session_action_tx(&payer, &signer, consumer_ix, blockhash)
        .expect("existing account becomes a signer");
    let signer_index = tx
        .message
        .account_keys
        .iter()
        .position(|key| key == &signer.pubkey())
        .expect("workload key is on the message");
    assert!(signer_index < usize::from(tx.message.header.num_required_signatures));
    assert_ne!(
        tx.signatures[signer_index],
        solana_sdk::signature::Signature::default()
    );
}

#[test]
fn atomic_attestation_tx_packs_nonce_bound_confidential_compute_then_consumer() {
    let payer = Pubkey::new_unique();
    let consumer = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let report = sample_report(signer.to_bytes(), MEASUREMENT);
    let blockhash = Hash::new_unique();
    let consumer_ix = dummy_consumer_ix(consumer, payer);

    let tx = build_atomic_attestation_tx_for_program_oversized(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        &payer,
        &consumer,
        ACTION_HASH,
        MEASUREMENT,
        &report,
        consumer_ix.clone(),
        blockhash,
        0,
    )
    .expect("atomic tx");
    assert!(matches!(
        build_atomic_attestation_tx(
            &payer,
            &consumer,
            ACTION_HASH,
            MEASUREMENT,
            &report,
            consumer_ix.clone(),
            blockhash,
        ),
        Err(SdkError::PacketTooLarge { len }) if len > PACKET_DATA_SIZE
    ));

    assert_eq!(tx.message.instructions.len(), 2);
    assert_eq!(
        compiled_program_id(&tx, 0),
        SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID
    );
    assert_eq!(compiled_program_id(&tx, 1), consumer);

    let confidential_compute_data = &tx.message.instructions[0].data;
    assert_eq!(
        &confidential_compute_data[..8],
        &VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR
    );
    assert_ne!(
        &confidential_compute_data[..8],
        &VERIFY_ATOMIC_DISCRIMINATOR
    );
    assert_eq!(&confidential_compute_data[8..16], &0u64.to_le_bytes());
    assert_eq!(&confidential_compute_data[0x10..0x30], &ACTION_HASH);
    assert_eq!(&confidential_compute_data[0x30..0x50], consumer.as_ref());
    assert_eq!(
        &confidential_compute_data[80..80 + SNP_REPORT_SIZE],
        report.as_slice()
    );
    assert_eq!(
        confidential_compute_data.len(),
        VERIFY_ATOMIC_WITH_NONCE_IX_LEN
    );
    assert_eq!(VERIFY_ATOMIC_WITH_NONCE_IX_LEN, 1265);
    let (_, nonce_bump) = Pubkey::find_program_address(
        &[b"nonce", &[1], signer.as_ref(), &*NONCE],
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    );
    assert_eq!(confidential_compute_data[80 + SNP_REPORT_SIZE], nonce_bump);
    assert_eq!(tx.message.instructions[1].data, consumer_ix.data);
    assert_eq!(tx.message.recent_blockhash, blockhash);
    const { assert!(MODE_B_REQUIRE_NONCE_DEFAULT) };
}

#[test]
fn atomic_attestation_tx_rejects_invalid_report_and_measurement() {
    let payer = Pubkey::new_unique();
    let consumer = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let consumer_ix = dummy_consumer_ix(consumer, payer);
    let blockhash = Hash::default();

    assert_eq!(
        build_atomic_attestation_tx(
            &payer,
            &consumer,
            ACTION_HASH,
            MEASUREMENT,
            &[0u8; 8],
            consumer_ix.clone(),
            blockhash,
        )
        .unwrap_err(),
        SdkError::InvalidReportSize
    );

    let report = sample_report(signer.to_bytes(), MEASUREMENT);
    assert_eq!(
        build_atomic_attestation_tx(
            &payer,
            &consumer,
            ACTION_HASH,
            [0x99; 48],
            &report,
            consumer_ix,
            blockhash,
        )
        .unwrap_err(),
        SdkError::MeasurementMismatch
    );
}

#[test]
fn client_builders_target_custom_program_id() {
    let program_id = Pubkey::new_unique();
    let client = ConfidentialComputeClient::new(program_id);
    let payer = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let report = sample_report(signer.to_bytes(), MEASUREMENT);
    assert!(matches!(
        client.build_register_signer_ix(&payer, &signer, &report, 1),
        Err(SdkError::PacketTooLarge { len }) if len > PACKET_DATA_SIZE
    ));
    let ix =
        build_register_signer_ix_for_program_oversized(&program_id, &payer, &signer, &report, 1, 0)
            .expect("oversized register");
    assert_eq!(ix.program_id, program_id);

    let consumer = Pubkey::new_unique();
    let consumer_ix = dummy_consumer_ix(consumer, payer);
    let blockhash = Hash::new_unique();
    assert!(matches!(
        client.build_atomic_attestation_tx(
            &payer,
            &consumer,
            ACTION_HASH,
            MEASUREMENT,
            &report,
            consumer_ix.clone(),
            blockhash,
        ),
        Err(SdkError::PacketTooLarge { .. })
    ));
    let tx = build_atomic_attestation_tx_for_program_oversized(
        &program_id,
        &payer,
        &consumer,
        ACTION_HASH,
        MEASUREMENT,
        &report,
        consumer_ix,
        blockhash,
        0,
    )
    .expect("oversized atomic");
    assert_eq!(compiled_program_id(&tx, 0), program_id);
}

#[test]
fn compute_commitment_matches_core_and_hash_action_is_exported() {
    let slot_hash = [0x11u8; 32];
    let consumer = Pubkey::new_unique();
    let commitment = compute_commitment(&slot_hash, &ACTION_HASH, &consumer);
    assert_eq!(
        commitment,
        solana_confidential_compute_core::compute_action_commitment(
            &slot_hash,
            &ACTION_HASH,
            &consumer.to_bytes()
        )
    );
    let hashed = hash_action(
        &[7u8; 8],
        &[solana_sdk::instruction::AccountMeta::new_readonly(
            consumer, false,
        )],
        &[1, 2, 3],
    );
    assert_eq!(hashed.len(), 32);
}

/// Shared cross-language test vector for action-hash derivation and commitment calculation.
///
/// Verified identically against TypeScript SDK in `sdks/typescript/test/packet.test.cjs`.
/// @spec SCC-PERF-001 SCC-CONSUMER-001 SCC-CONSUMER-002 SCC-ANCHOR-001
#[test]
fn shared_wire_test_vector_action_hash_and_commitment() {
    let disc = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let acc1 = Pubkey::new_from_array([10u8; 32]);
    let acc2 = Pubkey::new_from_array([20u8; 32]);
    let data = [0xaau8, 0xbb, 0xcc, 0xdd];
    let action_hash = hash_action(
        &disc,
        &[
            solana_sdk::instruction::AccountMeta::new_readonly(acc1, false),
            solana_sdk::instruction::AccountMeta::new_readonly(acc2, false),
        ],
        &data,
    );

    let expected_action_hash: [u8; 32] = [
        235, 83, 105, 10, 187, 214, 226, 188, 61, 43, 63, 19, 184, 121, 255, 58, 52, 126, 160, 114,
        12, 209, 122, 216, 71, 203, 76, 236, 70, 186, 77, 72,
    ];
    assert_eq!(action_hash, expected_action_hash);

    let slot_hash = [0x42u8; 32];
    let consumer = Pubkey::new_from_array([30u8; 32]);
    let commitment = compute_commitment(&slot_hash, &action_hash, &consumer);

    let expected_commitment: [u8; 32] = [
        14, 199, 119, 170, 190, 142, 1, 96, 135, 78, 206, 131, 174, 75, 39, 221, 193, 93, 1, 176,
        24, 11, 0, 50, 19, 98, 109, 138, 103, 222, 225, 29,
    ];
    assert_eq!(commitment, expected_commitment);
    assert_eq!(
        commitment,
        solana_confidential_compute_core::compute_action_commitment(
            &slot_hash,
            &action_hash,
            &consumer.to_bytes()
        )
    );
}

fn noop(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    Ok(())
}

#[tokio::test]
async fn atomic_attestation_tx_executes_packed_indices_against_noop_programs() {
    let consumer_id = Pubkey::new_unique();
    let mut pt = ProgramTest::new(
        "solana_confidential_compute_verifier",
        SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        processor!(noop),
    );
    pt.add_program(
        "confidential_compute_consumer",
        consumer_id,
        processor!(noop),
    );
    let context = pt.start_with_context().await;

    let signer = Pubkey::new_unique();
    let report = sample_report(signer.to_bytes(), MEASUREMENT);
    let consumer_ix = dummy_consumer_ix(consumer_id, context.payer.pubkey());
    let mut tx = build_atomic_attestation_tx_for_program_oversized(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        &context.payer.pubkey(),
        &consumer_id,
        ACTION_HASH,
        MEASUREMENT,
        &report,
        consumer_ix,
        context.last_blockhash,
        500,
    )
    .expect("pack atomic");
    assert_eq!(
        compiled_program_id(&tx, 0),
        SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID
    );
    assert_eq!(compiled_program_id(&tx, 1), consumer_id);
    assert_eq!(
        &tx.message.instructions[0].data[..8],
        &VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR
    );

    tx.sign(&[&context.payer], context.last_blockhash);
    context
        .banks_client
        .process_transaction(tx)
        .await
        .expect("packed Mode B transaction processes");
}

fn invoke_builder_ix(ix: &Instruction) -> solana_program::program_error::ProgramError {
    let keys: Vec<_> = ix.accounts.iter().map(|m| m.pubkey).collect();
    let owners: Vec<_> = keys
        .iter()
        .map(|k| {
            if *k == solana_program::sysvar::clock::ID {
                solana_program::sysvar::ID
            } else {
                Pubkey::default()
            }
        })
        .collect();
    let mut lamports = vec![1_000_000u64; keys.len()];
    let mut data: Vec<Vec<u8>> = keys
        .iter()
        .map(|k| {
            if *k == solana_program::sysvar::clock::ID {
                vec![0; 40]
            } else if *k == solana_program::sysvar::instructions::ID {
                // Empty instruction list with a valid current-index trailer;
                // this length-only fixture must fail without panicking.
                vec![0; 4]
            } else {
                vec![]
            }
        })
        .collect();
    let accounts: Vec<_> = ix
        .accounts
        .iter()
        .zip(keys.iter())
        .zip(owners.iter())
        .zip(lamports.iter_mut())
        .zip(data.iter_mut())
        .map(|((((m, key), owner), balance), bytes)| {
            AccountInfo::new(
                key,
                m.is_signer,
                m.is_writable,
                balance,
                bytes,
                owner,
                false,
            )
        })
        .collect();
    solana_confidential_compute_verifier::process_instruction(&ix.program_id, &accounts, &ix.data)
        .expect_err("a synthetic report is not a complete attestation")
}

/// Builder bytes must pass the verifier's exact-length gate.
///
/// A missing canonical bump returns `InvalidInstruction` before signature checks.
/// @spec SCC-SEC-008 SCC-ARCH-001 SCC-SDK-001
#[test]
fn builder_instructions_pass_verifier_length_gate() {
    use solana_confidential_compute_sdk::internal::build_verify_atomic_with_nonce_ix_oversized;
    use solana_confidential_compute_verifier::error::VerifierError;
    use solana_program::program_error::ProgramError;

    let invalid = ProgramError::from(VerifierError::InvalidInstruction);
    let payer = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let report = sample_report(signer.to_bytes(), MEASUREMENT);
    let register = build_register_signer_ix_for_program_oversized(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        &payer,
        &signer,
        &report,
        ATTESTATION_TTL_SLOTS,
        7,
    )
    .expect("register ix");
    assert_eq!(register.data.len(), 1202);
    assert_ne!(invoke_builder_ix(&register), invalid);

    let consumer = Pubkey::new_unique();
    let atomic = build_verify_atomic_with_nonce_ix_oversized(
        &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        &payer,
        &consumer,
        ACTION_HASH,
        MEASUREMENT,
        &report,
        7,
    )
    .expect("atomic ix");
    assert_eq!(atomic.data.len(), 1265);
    assert_ne!(invoke_builder_ix(&atomic), invalid);
}

#[test]
fn mode_a_enrollment_requires_and_can_collect_workload_consent() {
    let payer = Keypair::new();
    let workload = Keypair::new();
    let report = sample_report(workload.pubkey().to_bytes(), MEASUREMENT);
    let snp = build_register_signer_ix_oversized(&payer.pubkey(), &workload.pubkey(), &report, 1)
        .unwrap();
    let nonce = Hash::new_unique().to_bytes();
    let nitro =
        solana_confidential_compute_sdk::nitro::build_verify_nitro_attestation_ix_oversized(
            &payer.pubkey(),
            &workload.pubkey(),
            0,
            1,
            [0; 32],
            &[1],
            &nonce,
        )
        .unwrap();
    for (ix, source, legacy_nonce) in [(snp, 1, *NONCE), (nitro, 2, nonce)] {
        assert_eq!(
            ix.accounts[ix.accounts.len() - if source == 1 { 4 } else { 3 }],
            AccountMeta::new_readonly(workload.pubkey(), true)
        );
        assert_eq!(
            ix.accounts
                .get(ix.accounts.len() - if source == 1 { 3 } else { 2 }),
            Some(&AccountMeta::new_readonly(
                solana_confidential_compute_sdk::derive_backend_policy_pda(&ix.program_id, source)
                    .unwrap()
                    .0,
                false
            ))
        );
        assert_eq!(
            ix.accounts
                .get(ix.accounts.len() - if source == 1 { 2 } else { 1 }),
            Some(&AccountMeta::new_readonly(
                solana_confidential_compute_sdk::derive_legacy_used_nonce_pda(
                    &ix.program_id,
                    &workload.pubkey().to_bytes(),
                    &legacy_nonce
                )
                .0,
                false
            ))
        );
        let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
        let blockhash = Hash::new_unique();
        tx.try_partial_sign(&[&payer], blockhash).unwrap();
        assert!(tx.verify().is_err());
        tx.try_partial_sign(&[&workload], blockhash).unwrap();
        assert!(tx.verify().is_ok());
    }
}
