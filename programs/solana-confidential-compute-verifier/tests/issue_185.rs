use solana_confidential_compute_verifier::payload::{
    CLOSE_ATTESTED_SIGNER_DISCRIMINATOR, CLOSE_STALE_NONCE_DISCRIMINATOR,
};
use solana_program::{
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    sysvar,
};
use solana_sdk::{
    account::Account,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
#[path = "common/legacy_nonce.rs"]
mod legacy_nonce_fixture;
use legacy_nonce_fixture::TestProcessor as Processor;
use solana_confidential_compute_verifier::state::{LEGACY_USED_NONCE_DISCRIMINATOR, USED_NONCE_DISCRIMINATOR};

#[path = "common/sbf.rs"]
mod sbf;
fn tombstone(slot: u64, refund: Pubkey) -> Vec<u8> {
    let mut bytes = USED_NONCE_DISCRIMINATOR.to_vec();
    bytes.extend_from_slice(&slot.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(refund.as_ref());
    bytes
}
#[tokio::test]
async fn stale_nonce_closes_only_after_replay_window_and_refunds_recorded_payer() {
    let pid = Pubkey::new_unique();
    let refund = Pubkey::new_unique();
    let wrong = Pubkey::new_unique();
    let fresh = Pubkey::new_unique();
    let stale = Pubkey::new_unique();
    let future = Pubkey::new_unique();
    let legacy = Pubkey::new_unique();
    let workload = Keypair::new();
    let workload_key = workload.pubkey();
    let (record_key, bump) = Pubkey::find_program_address(&[b"attested_signer_v2", workload_key.as_ref()], &pid);
    let mut pt = sbf::verifier_program_test(pid);
    for (key, slot) in [(fresh, 501), (stale, 500), (future, 652)] {
        pt.add_account(
            key,
            Account {
                lamports: 2_000_000,
                data: tombstone(slot, refund),
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        );
    }
    let mut old = LEGACY_USED_NONCE_DISCRIMINATOR.to_vec();
    old.extend_from_slice(&500u64.to_le_bytes());
    old.push(0);
    pt.add_account(legacy, Account { lamports: 2_000_000, data: old, owner: pid, executable: false, rent_epoch: 0 });
    for key in [refund, wrong] {
        pt.add_account(
            key,
            Account {
                lamports: 1_000_000,
                data: vec![],
                owner: solana_sdk_ids::system_program::ID,
                executable: false,
                rent_epoch: 0,
            },
        );
    }
    let record = solana_confidential_compute_verifier::state::AttestedSignerAccount::new(
        solana_confidential_compute_core::types::AttestedSigner {
            signer_pubkey: workload_key.to_bytes(),
            enclave_type: solana_confidential_compute_core::types::EnclaveType::AmdSevSnp,
            measurement: solana_confidential_compute_core::types::MeasurementDigest([7; 48]),
            chip_id_hash: [0; 32],
            tcb_version: 0,
            registered_slot: 20,
            expires_slot: 500,
        },
        bump,
    );
    pt.add_account(
        record_key,
        Account {
            lamports: 2_000_000,
            data: borsh::to_vec(&record).unwrap(),
            owner: pid,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        workload_key,
        Account {
            lamports: 1_000_000,
            data: vec![],
            owner: solana_sdk_ids::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let ctx = pt.start_with_context().await;
    ctx.set_sysvar(&Clock { slot: 651, ..Clock::default() });
    for (nonce, destination, success) in [
        (fresh, refund, false),
        (future, refund, false),
        (legacy, refund, false),
        (stale, wrong, false),
        (stale, refund, true),
    ] {
        let before = ctx.banks_client.get_balance(destination).await.unwrap();
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(nonce, false),
                AccountMeta::new(destination, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
            ],
            data: CLOSE_STALE_NONCE_DISCRIMINATOR.to_vec(),
        };
        let tx =
            Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer], ctx.last_blockhash);
        let result = ctx.banks_client.process_transaction(tx).await;
        assert_eq!(result.is_ok(), success, "{nonce}: {result:?}");
        let remaining = ctx.banks_client.get_account(nonce).await.unwrap();
        let after = ctx.banks_client.get_balance(destination).await.unwrap();
        if success {
            assert!(remaining.is_none());
            assert_eq!(after, before + 2_000_000);
        } else {
            assert!(remaining.is_some());
            assert_eq!(after, before);
        }
    }
    for signed in [false, true] {
        let before = ctx.banks_client.get_balance(workload_key).await.unwrap();
        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(record_key, false),
                AccountMeta::new(workload_key, signed),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
            ],
            data: CLOSE_ATTESTED_SIGNER_DISCRIMINATOR.to_vec(),
        };
        let tx = if signed {
            Transaction::new_signed_with_payer(
                &[ix],
                Some(&ctx.payer.pubkey()),
                &[&ctx.payer, &workload],
                ctx.last_blockhash,
            )
        } else {
            Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer], ctx.last_blockhash)
        };
        assert_eq!(ctx.banks_client.process_transaction(tx).await.is_ok(), signed);
        assert_eq!(ctx.banks_client.get_account(record_key).await.unwrap().is_none(), signed);
        assert_eq!(
            ctx.banks_client.get_balance(workload_key).await.unwrap(),
            before + if signed { 2_000_000 } else { 0 }
        );
    }
    // Recreating a removed tombstone cannot make the old signed hash fresh.
    let sh = solana_program::sysvar::slot_hashes::ID;
    let owner = sysvar::ID;
    let mut lamports = 1;
    let mut bytes = 1u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(&500u64.to_le_bytes());
    bytes.extend_from_slice(&[8; 32]);
    let acc =
        solana_program::account_info::AccountInfo::new(&sh, false, false, &mut lamports, &mut bytes, &owner, false);
    assert!(Processor::verify_recent_slot_hash(&acc, 651, 500, &[8; 32]).is_err());
    assert!(Processor::verify_recent_slot_hash(&acc, 650, 500, &[8; 32]).is_ok());
}
