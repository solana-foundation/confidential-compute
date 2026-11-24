//! Actual bank/runtime differential, with a no-op verifier fixture to isolate
//! consumer binding. This is not evidence of hardware/cryptographic verification.
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    hash::Hasher,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    transaction::Transaction,
};

fn noop(_: &Pubkey, _: &[AccountInfo], _: &[u8]) -> ProgramResult {
    Ok(())
}
// Reproduces baseline V1 serialization, deliberately only in this test fixture.
fn legacy_hash(keys: &[Pubkey], payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::default();
    h.hash(&1u32.to_le_bytes());
    h.hash(&[1]);
    h.hash(&(keys.len() as u32).to_le_bytes());
    for key in keys {
        h.hash(key.as_ref());
    }
    h.hash(&(payload.len() as u32).to_le_bytes());
    h.hash(payload);
    h.result().to_bytes()
}
fn legacy_consumer(_: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let index = load_current_index_checked(&accounts[0])?;
    let previous = load_instruction_at_checked(index as usize - 1, &accounts[0])?;
    let keys = accounts.iter().map(|a| *a.key).collect::<Vec<_>>();
    if legacy_hash(&keys, &data[1..]) != previous.data[16..48] {
        return Err(ProgramError::InvalidInstructionData);
    }
    // Concrete downstream effect depends on runtime privilege, beyond hash output.
    if accounts[1].is_writable {
        accounts[1].try_borrow_mut_data()?[0] += 1;
    }
    if accounts[1].is_signer {
        return Err(ProgramError::Custom(7273));
    }
    Ok(())
}
fn proof(hash: [u8; 32], consumer: Pubkey) -> Instruction {
    let mut data =
        Vec::from(solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
    data.extend_from_slice(&500u64.to_le_bytes());
    data.extend_from_slice(&hash);
    data.extend_from_slice(consumer.as_ref());
    let mut report = vec![0; 1184];
    report[0x50..0x70].copy_from_slice(&[0x33; 32]);
    report[0x90..0xc0]
        .copy_from_slice(&solana_confidential_compute_consumer_reference::EXPECTED_MEASUREMENT);
    data.extend(report);
    Instruction {
        program_id: solana_confidential_compute_cpi::ID,
        accounts: vec![],
        data,
    }
}
#[tokio::test]
async fn baseline_privilege_substitution_changes_downstream_effect_and_v2_rejects_it() {
    let legacy = Pubkey::new_unique();
    let elevator = Pubkey::new_unique();
    let state = Keypair::new();
    let alternate_payer = Keypair::new();
    let mut pt = ProgramTest::new(
        "consumer_reference",
        solana_confidential_compute_consumer_reference::ID,
        processor!(solana_confidential_compute_consumer_reference::process_instruction),
    );
    pt.add_program(
        "legacy_privilege_fixture",
        legacy,
        processor!(legacy_consumer),
    );
    pt.add_program(
        "verifier_fixture",
        solana_confidential_compute_cpi::ID,
        processor!(noop),
    );
    pt.add_program("elevator_fixture", elevator, processor!(noop));
    pt.add_account(
        state.pubkey(),
        Account {
            lamports: 1_000_000,
            data: vec![0],
            owner: legacy,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        alternate_payer.pubkey(),
        Account {
            lamports: 10_000_000,
            data: vec![],
            owner: solana_sdk_ids::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let ctx = pt.start_with_context().await;
    let keys = vec![solana_sdk::sysvar::instructions::ID, state.pubkey()];
    let action = Instruction {
        program_id: legacy,
        accounts: keys
            .iter()
            .map(|k| AccountMeta::new_readonly(*k, false))
            .collect(),
        data: vec![1, 8, 9],
    };
    let old = legacy_hash(&keys, &action.data[1..]);
    let old_proof = proof(old, legacy);
    let tx = Transaction::new_signed_with_payer(
        &[old_proof.clone(), action.clone()],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    assert_eq!(
        ctx.banks_client
            .get_account(state.pubkey())
            .await
            .unwrap()
            .unwrap()
            .data,
        [0]
    );
    let elevate = Instruction {
        program_id: elevator,
        accounts: vec![AccountMeta::new(state.pubkey(), false)],
        data: vec![],
    };
    // Consumer bytes and ordered keys are IDENTICAL, but compiler globally upgrades writable.
    let tx = Transaction::new_signed_with_payer(
        &[elevate.clone(), old_proof, action.clone()],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    assert_eq!(
        ctx.banks_client
            .get_account(state.pubkey())
            .await
            .unwrap()
            .unwrap()
            .data,
        [1]
    );
    // Signer elevation also reaches AccountInfo although the consumer meta is unchanged.
    let sign = Instruction {
        program_id: elevator,
        accounts: vec![AccountMeta::new_readonly(state.pubkey(), true)],
        data: vec![],
    };
    let tx = Transaction::new_signed_with_payer(
        &[sign, proof(old, legacy), action.clone()],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer, &state],
        ctx.last_blockhash,
    );
    assert!(format!(
        "{:?}",
        ctx.banks_client.process_transaction(tx).await.unwrap_err()
    )
    .contains("7273"));
    // The actual reference consumer recomputes V3 from received AccountInfos.
    let mut current = action.clone();
    current.program_id = solana_confidential_compute_consumer_reference::ID;
    let digest =
        solana_confidential_compute_cpi::hash_action(&[1], &current.accounts, &current.data[1..]);
    let tx = Transaction::new_signed_with_payer(
        &[proof(digest, current.program_id), current.clone()],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[
            elevate.clone(),
            proof(digest, current.program_id),
            current.clone(),
        ],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());
    // Fresh attestation to the FINAL privilege shape succeeds.
    let mut effective = current.accounts.clone();
    effective[1].is_writable = true;
    let digest = solana_confidential_compute_cpi::hash_action(&[1], &effective, &current.data[1..]);
    let tx = Transaction::new_signed_with_payer(
        &[elevate, proof(digest, current.program_id), current.clone()],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    // Another instruction can elevate signer status without writable elevation.
    let sign = Instruction {
        program_id: elevator,
        accounts: vec![AccountMeta::new_readonly(state.pubkey(), true)],
        data: vec![],
    };
    let readonly_digest =
        solana_confidential_compute_cpi::hash_action(&[1], &current.accounts, &current.data[1..]);
    let tx = Transaction::new_signed_with_payer(
        &[
            sign.clone(),
            proof(readonly_digest, current.program_id),
            current.clone(),
        ],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer, &state],
        ctx.last_blockhash,
    );
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());
    let mut signed_metas = current.accounts.clone();
    signed_metas[1].is_signer = true;
    let signed_digest =
        solana_confidential_compute_cpi::hash_action(&[1], &signed_metas, &current.data[1..]);
    let tx = Transaction::new_signed_with_payer(
        &[
            sign,
            proof(signed_digest, current.program_id),
            current.clone(),
        ],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer, &state],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    // Changing only the fee payer elevates a declared readonly non-signer account.
    let mut payer_action = current.clone();
    payer_action
        .accounts
        .push(AccountMeta::new_readonly(alternate_payer.pubkey(), false));
    let readonly = solana_confidential_compute_cpi::hash_action(
        &[1],
        &payer_action.accounts,
        &payer_action.data[1..],
    );
    let tx = Transaction::new_signed_with_payer(
        &[
            proof(readonly, payer_action.program_id),
            payer_action.clone(),
        ],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[
            proof(readonly, payer_action.program_id),
            payer_action.clone(),
        ],
        Some(&alternate_payer.pubkey()),
        &[&alternate_payer],
        ctx.last_blockhash,
    );
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());
    let mut final_metas = payer_action.accounts.clone();
    final_metas[2].is_signer = true;
    final_metas[2].is_writable = true;
    let final_digest =
        solana_confidential_compute_cpi::hash_action(&[1], &final_metas, &payer_action.data[1..]);
    let tx = Transaction::new_signed_with_payer(
        &[proof(final_digest, payer_action.program_id), payer_action],
        Some(&alternate_payer.pubkey()),
        &[&alternate_payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    // V1 digest has no accepted migration fallback.
    let tx = Transaction::new_signed_with_payer(
        &[proof(old, current.program_id), current],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());
}
