use solana_confidential_compute_sdk::{
    hash_compiled_action, validate_compiled_action, ActionCommitmentError,
};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{Message, VersionedMessage},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

fn ix(program: u8, keys: Vec<AccountMeta>) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array([program; 32]),
        accounts: keys,
        data: vec![7, 8, 9],
    }
}
fn compiled(ixs: &[Instruction], payer: &Pubkey) -> VersionedMessage {
    VersionedMessage::Legacy(Message::new(ixs, Some(payer)))
}
#[test]
fn complete_message_elevates_other_instruction_flags_and_payer() {
    let payer = Pubkey::new_from_array([1; 32]);
    let key = Pubkey::new_from_array([3; 32]);
    let action = ix(
        2,
        vec![
            AccountMeta::new_readonly(payer, false),
            AccountMeta::new_readonly(key, false),
            AccountMeta::new_readonly(key, false),
        ],
    );
    let base = compiled(std::slice::from_ref(&action), &payer);
    let h = hash_compiled_action(&base, 0, 0).unwrap();
    let other = ix(4, vec![AccountMeta::new(key, false)]);
    let elevated = compiled(&[action.clone(), other], &payer);
    let writable = hash_compiled_action(&elevated, 0, 0).unwrap();
    assert_ne!(h, writable);
    assert_eq!(
        writable,
        hex32("6777901e314a11c4c8bad75331b061ab7c90c832603f5970937033ff21fd51cc")
    );
    let signer = compiled(
        &[
            action.clone(),
            ix(4, vec![AccountMeta::new_readonly(key, true)]),
        ],
        &payer,
    );
    assert_ne!(h, hash_compiled_action(&signer, 0, 0).unwrap());
    // Same consumer program, ordered pubkeys, and bytes in every message.
    for m in [&base, &elevated, &signer] {
        let c = &m.instructions()[0];
        assert_eq!(c.data, action.data);
        assert_eq!(
            m.static_account_keys()[c.program_id_index as usize],
            action.program_id
        );
        assert_eq!(
            c.accounts
                .iter()
                .map(|i| m.static_account_keys()[*i as usize])
                .collect::<Vec<_>>(),
            action.accounts.iter().map(|a| a.pubkey).collect::<Vec<_>>()
        );
    }
    let other_payer = Pubkey::new_from_array([5; 32]);
    assert_ne!(
        h,
        hash_compiled_action(&compiled(&[action], &other_payer), 0, 0).unwrap()
    );
    assert_eq!(
        validate_compiled_action(&elevated, 0, &h),
        Err(ActionCommitmentError::Mismatch)
    );
}
fn hex32(s: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
}
#[test]
fn sdk_program_demotion_and_reserved_write_rejection() {
    let payer = Pubkey::new_unique();
    let program = Pubkey::new_unique();
    let action = Instruction {
        program_id: program,
        accounts: vec![AccountMeta::new(program, false)],
        data: vec![7],
    };
    let m = compiled(&[action], &payer);
    assert_eq!(
        hash_compiled_action(&m, 0, 0).unwrap(),
        solana_confidential_compute_sdk::hash_action(
            &[7],
            &[AccountMeta::new_readonly(program, false)],
            &[]
        )
    );
    let bad = ix(
        2,
        vec![AccountMeta::new(solana_sdk::sysvar::clock::ID, false)],
    );
    assert_eq!(
        hash_compiled_action(&compiled(&[bad], &payer), 0, 0),
        Err(ActionCommitmentError::ReservedWritable)
    );
}
#[test]
fn normal_nitro_builder_accepts_template_then_rejects_legacy_digest() {
    let payer = Pubkey::new_unique();
    let workload = Pubkey::new_unique();
    let nonce = Keypair::new().pubkey().to_bytes();
    let consumer = ix(2, vec![AccountMeta::new_readonly(payer, false)]);
    let verifier = solana_confidential_compute_sdk::build_verify_nitro_attestation_ix(
        &payer,
        &workload,
        1,
        1,
        [0; 32],
        &[0x80],
        &nonce,
    )
    .unwrap();
    // Instruction data other than consumer bytes is irrelevant to privileges.
    let mut metadata = verifier.clone();
    metadata.data.clear();
    let template = compiled(&[metadata, consumer.clone()], &payer);
    let expected = hash_compiled_action(&template, 1, 0).unwrap();
    let build = |hash| {
        solana_confidential_compute_sdk::build_verify_nitro_attestation_tx(
            &payer,
            &workload,
            1,
            1,
            hash,
            &[0x80],
            &nonce,
            Hash::new_unique(),
            Some(consumer.clone()),
        )
    };
    let tx = build(expected).unwrap();
    assert_eq!(
        hash_compiled_action(&VersionedMessage::Legacy(tx.message), 1, 0).unwrap(),
        expected
    );
    assert_eq!(
        build([0; 32]).unwrap_err(),
        solana_confidential_compute_sdk::SdkError::DisallowedInstruction
    );
}

#[test]
fn full_wire_handles_empty_short_and_long_data_without_a_schema_guess() {
    let payer = Pubkey::new_unique();
    for bytes in [vec![], vec![7], vec![7, 8], (0..19).collect()] {
        let mut action = ix(2, vec![AccountMeta::new_readonly(payer, false)]);
        action.data = bytes.clone();
        let message = compiled(&[action], &payer);
        let expected = solana_confidential_compute_core::action::hash_action_parts(
            &[],
            1,
            std::iter::once((&payer, true, true)),
            &bytes,
        );
        for split in 0..=bytes.len() {
            assert_eq!(hash_compiled_action(&message, 0, split).unwrap(), expected);
        }
        validate_compiled_action(&message, 0, &expected).unwrap();
    }
}
