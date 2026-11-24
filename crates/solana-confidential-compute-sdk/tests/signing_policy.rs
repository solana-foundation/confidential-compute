use solana_confidential_compute_sdk::{build_session_action_tx, ConfidentialComputeClient};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
#[allow(deprecated)]
use solana_system_interface::instruction as system_instruction;

#[test]
fn rejects_system_transfers_before_signing_in_both_entrypoints() {
    let signer = Keypair::new();
    let ix = system_instruction::transfer(&signer.pubkey(), &Pubkey::new_unique(), 1_000_000_000);
    assert!(build_session_action_tx(&signer.pubkey(), &signer, ix.clone(), Hash::new_unique()).is_err());
    assert!(ConfidentialComputeClient::new(solana_confidential_compute_sdk::ID)
        .build_session_action_tx(&signer.pubkey(), &signer, ix, Hash::new_unique())
        .is_err());
}

#[test]
fn signs_custom_consumer_and_verifies_workload_signature() {
    let signer = Keypair::new();
    let consumer = Pubkey::new_unique();
    let ix = Instruction {
        program_id: consumer,
        accounts: vec![AccountMeta::new(signer.pubkey(), false)],
        data: vec![0xff; 512],
    };
    let tx = build_session_action_tx(&signer.pubkey(), &signer, ix, Hash::new_unique()).unwrap();
    assert!(tx.signatures[0].verify(signer.pubkey().as_ref(), &tx.message_data()));
    assert_eq!(tx.message.account_keys[tx.message.instructions[0].program_id_index as usize], consumer);
}
