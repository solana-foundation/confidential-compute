//! AWS Nitro builder layout, account-lock, and packet-ceiling tests.
//!
//! @spec SCC-NITRO-008 SCC-SDK-001 SCC-PERF-002

use solana_confidential_compute_core::MAX_NITRO_DOCUMENT_LEN;
use solana_confidential_compute_sdk::nitro::{
    build_verify_nitro_attestation_ix_oversized, build_verify_nitro_attestation_tx_oversized,
};
use solana_confidential_compute_sdk::{
    build_verify_nitro_attestation_ix, build_verify_nitro_attestation_ix_for_program,
    build_verify_nitro_attestation_tx, ConfidentialComputeClient, SdkError,
    ID as SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID, NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER, PACKET_DATA_SIZE,
    VERIFY_NITRO_ATTESTATION_DISCRIMINATOR, VERIFY_NITRO_ATTESTATION_HEADER_LEN, VERIFY_NITRO_MODE_A,
    VERIFY_NITRO_MODE_B,
};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    sysvar::{self, clock, slot_hashes},
};

const ACTION_HASH: [u8; 32] = [0x11; 32];
// Runtime nonce, fixed for the process so report and PDA expectations agree.
static NONCE: std::sync::LazyLock<[u8; 32]> =
    std::sync::LazyLock::new(|| solana_sdk::hash::Hash::new_unique().to_bytes());

fn sample_document(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i & 0xff) as u8).collect()
}

fn consumer_ix(payer: Pubkey) -> Instruction {
    Instruction { program_id: Pubkey::new_unique(), accounts: vec![AccountMeta::new(payer, true)], data: vec![1, 2, 3] }
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().expect("u32"))
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().expect("u64"))
}

#[test]
fn mode_a_instruction_packs_header_and_writable_signer_pda() {
    let payer = Pubkey::new_unique();
    let workload = Pubkey::new_unique();
    let document = sample_document(64);
    let ix = build_verify_nitro_attestation_ix_oversized(
        &payer,
        &workload,
        VERIFY_NITRO_MODE_A,
        95,
        ACTION_HASH,
        &document,
        &NONCE,
    )
    .expect("mode a ix");

    assert_eq!(ix.program_id, SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID);
    assert_eq!(ix.data.len(), VERIFY_NITRO_ATTESTATION_HEADER_LEN + document.len());
    assert_eq!(&ix.data[..8], &VERIFY_NITRO_ATTESTATION_DISCRIMINATOR);
    assert_eq!(ix.data[8], VERIFY_NITRO_MODE_A);
    assert_eq!(read_u64_le(&ix.data, 9), 95);
    assert_eq!(&ix.data[17..49], &ACTION_HASH);
    assert_eq!(read_u32_le(&ix.data, 49), document.len() as u32);
    assert_eq!(&ix.data[53..], document.as_slice());

    let client = ConfidentialComputeClient::new(SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID);
    let (policy_registry, _) = client.derive_policy_registry_pda();
    let (attested_signer, _) = client.derive_signer_pda(&workload.to_bytes());
    let (used_nonce, _) = client.derive_used_nonce_pda_for_source(2, &workload.to_bytes(), &NONCE).unwrap();
    assert_eq!(ix.accounts.len(), 10);
    assert_eq!(ix.accounts[7], solana_sdk::instruction::AccountMeta::new_readonly(workload, true));
    assert_eq!(
        ix.accounts[8],
        solana_sdk::instruction::AccountMeta::new_readonly(
            solana_confidential_compute_sdk::derive_backend_policy_pda(&SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID, 2)
                .unwrap()
                .0,
            false
        )
    );
    assert_eq!(
        ix.accounts[9],
        solana_sdk::instruction::AccountMeta::new_readonly(
            solana_confidential_compute_sdk::derive_legacy_used_nonce_pda(
                &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
                &workload.to_bytes(),
                &NONCE
            )
            .0,
            false
        )
    );
    assert_eq!(ix.accounts[0].pubkey, payer);
    assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
    assert_eq!(ix.accounts[1].pubkey, policy_registry);
    assert!(!ix.accounts[1].is_writable);
    assert_eq!(ix.accounts[2].pubkey, attested_signer);
    assert!(ix.accounts[2].is_writable);
    assert_eq!(ix.accounts[3].pubkey, used_nonce);
    assert!(ix.accounts[3].is_writable);
    assert_eq!(ix.accounts[4].pubkey, slot_hashes::ID);
    assert_eq!(ix.accounts[5].pubkey, clock::ID);
    assert_eq!(ix.accounts[6].pubkey, solana_sdk_ids::system_program::ID);
    let (backend, _) =
        Pubkey::find_program_address(&[b"backend_policy", &[2]], &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID);
    assert_eq!(
        ix.accounts,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(policy_registry, false),
            AccountMeta::new(attested_signer, false),
            AccountMeta::new(used_nonce, false),
            AccountMeta::new_readonly(slot_hashes::ID, false),
            AccountMeta::new_readonly(clock::ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(workload, true),
            AccountMeta::new_readonly(backend, false),
            AccountMeta::new_readonly(
                solana_confidential_compute_sdk::derive_legacy_used_nonce_pda(
                    &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
                    &workload.to_bytes(),
                    &NONCE
                )
                .0,
                false,
            ),
        ]
    );
}

#[test]
fn mode_b_placeholder_is_read_only_and_adds_instructions_sysvar() {
    let payer = Pubkey::new_unique();
    let workload = Pubkey::new_unique();
    let ix = build_verify_nitro_attestation_ix(
        &payer,
        &workload,
        VERIFY_NITRO_MODE_B,
        120,
        ACTION_HASH,
        &sample_document(8),
        &NONCE,
    )
    .expect("mode b ix");

    assert_eq!(ix.data[8], VERIFY_NITRO_MODE_B);
    assert_eq!(ix.accounts.len(), 10);
    assert_eq!(ix.accounts[2].pubkey, NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER);
    assert!(!ix.accounts[2].is_writable);
    assert!(!ix.accounts[2].is_signer);
    assert_eq!(NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER.to_bytes(), [0xff; 32]);
    assert_eq!(ix.accounts[7].pubkey, sysvar::instructions::ID);
    assert!(!ix.accounts[7].is_writable);
    let client = ConfidentialComputeClient::new(SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID);
    let (used_nonce, _) = client.derive_used_nonce_pda_for_source(2, &workload.to_bytes(), &NONCE).unwrap();
    assert_eq!(ix.accounts[3].pubkey, used_nonce);
    let (policy_registry, _) = client.derive_policy_registry_pda();
    let (backend, _) =
        Pubkey::find_program_address(&[b"backend_policy", &[2]], &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID);
    assert_eq!(
        ix.accounts,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(policy_registry, false),
            AccountMeta::new_readonly(NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER, false),
            AccountMeta::new(used_nonce, false),
            AccountMeta::new_readonly(slot_hashes::ID, false),
            AccountMeta::new_readonly(clock::ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
            AccountMeta::new_readonly(backend, false),
            AccountMeta::new_readonly(
                solana_confidential_compute_sdk::derive_legacy_used_nonce_pda(
                    &SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
                    &workload.to_bytes(),
                    &NONCE
                )
                .0,
                false,
            ),
        ]
    );
}

#[test]
fn mode_a_transaction_appends_consumer_when_provided() {
    let payer = Pubkey::new_unique();
    let workload = Pubkey::new_unique();
    let consumer = consumer_ix(payer);
    let blockhash = Hash::new_unique();
    let alone = build_verify_nitro_attestation_tx(
        &payer,
        &workload,
        VERIFY_NITRO_MODE_A,
        1,
        ACTION_HASH,
        &sample_document(8),
        &NONCE,
        blockhash,
        None,
    )
    .expect("mode a alone");
    assert_eq!(alone.message.instructions.len(), 1);
    assert_eq!(
        alone.message.account_keys[alone.message.instructions[0].program_id_index as usize],
        SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID
    );

    let with_consumer = build_verify_nitro_attestation_tx(
        &payer,
        &workload,
        VERIFY_NITRO_MODE_A,
        1,
        ACTION_HASH,
        &sample_document(8),
        &NONCE,
        blockhash,
        Some(consumer.clone()),
    )
    .expect("mode a with consumer");
    assert_eq!(with_consumer.message.instructions.len(), 2);
    let consumer_ix = &with_consumer.message.instructions[1];
    assert_eq!(with_consumer.message.account_keys[consumer_ix.program_id_index as usize], consumer.program_id);
    assert_eq!(consumer_ix.data, consumer.data);
}

#[test]
fn mode_b_transaction_places_consumer_at_index_1() {
    let payer = Pubkey::new_unique();
    let workload = Pubkey::new_unique();
    let consumer = consumer_ix(payer);
    let tx = build_verify_nitro_attestation_tx_oversized(
        &payer,
        &workload,
        VERIFY_NITRO_MODE_B,
        10,
        ACTION_HASH,
        &sample_document(32),
        &NONCE,
        Hash::new_unique(),
        Some(consumer.clone()),
    )
    .expect("mode b tx");
    assert_eq!(tx.message.instructions.len(), 2);
    assert_eq!(
        tx.message.account_keys[tx.message.instructions[0].program_id_index as usize],
        SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID
    );
    assert_eq!(tx.message.instructions[0].data[8], VERIFY_NITRO_MODE_B);
    assert_eq!(tx.message.account_keys[tx.message.instructions[1].program_id_index as usize], consumer.program_id);
}

#[test]
fn builders_reject_bad_mode_empty_document_and_missing_mode_b_consumer() {
    let payer = Pubkey::new_unique();
    let workload = Pubkey::new_unique();
    assert_eq!(
        build_verify_nitro_attestation_ix(&payer, &workload, 2, 1, ACTION_HASH, &sample_document(8), &NONCE,),
        Err(SdkError::InvalidNitroMode)
    );
    assert_eq!(
        build_verify_nitro_attestation_ix_oversized(
            &payer,
            &workload,
            VERIFY_NITRO_MODE_A,
            1,
            ACTION_HASH,
            &[],
            &NONCE,
        ),
        Err(SdkError::InvalidNitroDocument)
    );
    assert_eq!(
        build_verify_nitro_attestation_ix_oversized(
            &payer,
            &workload,
            VERIFY_NITRO_MODE_A,
            1,
            ACTION_HASH,
            &sample_document(MAX_NITRO_DOCUMENT_LEN + 1),
            &NONCE,
        ),
        Err(SdkError::InvalidNitroDocument)
    );
    assert_eq!(
        build_verify_nitro_attestation_tx(
            &payer,
            &workload,
            VERIFY_NITRO_MODE_B,
            1,
            ACTION_HASH,
            &sample_document(8),
            &NONCE,
            Hash::new_unique(),
            None,
        ),
        Err(SdkError::MissingConsumerInstruction)
    );
}

#[test]
fn max_document_fails_closed_above_packet_data_size() {
    let payer = Pubkey::new_unique();
    let workload = Pubkey::new_unique();
    let document = sample_document(MAX_NITRO_DOCUMENT_LEN);
    let err =
        build_verify_nitro_attestation_ix(&payer, &workload, VERIFY_NITRO_MODE_A, 1, ACTION_HASH, &document, &NONCE);
    assert!(matches!(err, Err(SdkError::PacketTooLarge { len }) if len > PACKET_DATA_SIZE));

    let oversized = build_verify_nitro_attestation_ix_oversized(
        &payer,
        &workload,
        VERIFY_NITRO_MODE_A,
        1,
        ACTION_HASH,
        &document,
        &NONCE,
    )
    .expect("oversized");
    assert_eq!(oversized.data.len(), VERIFY_NITRO_ATTESTATION_HEADER_LEN + MAX_NITRO_DOCUMENT_LEN);

    let program_id = Pubkey::new_unique();
    let for_program = build_verify_nitro_attestation_ix_for_program(
        &program_id,
        &payer,
        &workload,
        VERIFY_NITRO_MODE_A,
        7,
        ACTION_HASH,
        &sample_document(4),
        &NONCE,
    )
    .expect("custom program");
    assert_eq!(for_program.program_id, program_id);
    assert_eq!(read_u64_le(&for_program.data, 9), 7);
}
