use solana_confidential_compute_sidecar::keys::EphemeralKeyManager;
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{v0, Message, VersionedMessage},
    pubkey::Pubkey,
    signature::Signature,
    transaction::{Transaction, VersionedTransaction},
};

fn instruction(workload: Pubkey) -> Instruction {
    Instruction {
        program_id: solana_confidential_compute_cpi::ID,
        accounts: vec![AccountMeta::new_readonly(workload, true)],
        data: solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec(),
    }
}

#[test]
fn workload_payer_rejected_before_any_signature_mutation() {
    let keys = EphemeralKeyManager::new();
    let payer = keys.pubkey();
    let ix = instruction(payer);
    for message in [
        VersionedMessage::Legacy(Message::new(std::slice::from_ref(&ix), Some(&payer))),
        VersionedMessage::V0(v0::Message::try_compile(&payer, &[ix], &[], Hash::default()).unwrap()),
    ] {
        let mut tx = VersionedTransaction { signatures: vec![], message };
        let before = tx.clone();
        let err = keys.sign_transaction(&mut tx).expect_err("workload must never fund caller fees");
        assert!(err.to_string().contains("fee payer"), "{err}");
        assert_eq!(tx, before, "rejection must precede signature vector resizing or release");
    }
}

#[test]
fn distinct_external_payer_preserved_and_workload_signature_verifies() {
    let keys = EphemeralKeyManager::new();
    let payer = Pubkey::new_unique();
    let message = VersionedMessage::V0(
        v0::Message::try_compile(&payer, &[instruction(keys.pubkey())], &[], Hash::default()).unwrap(),
    );
    let payer_signature = Signature::from([0x55; 64]);
    let mut tx = VersionedTransaction { signatures: vec![payer_signature, Signature::default()], message };
    let signature = keys.sign_transaction(&mut tx).unwrap();
    assert_eq!(tx.signatures[0], payer_signature);
    assert_eq!(tx.signatures[1], signature);
    assert!(signature.verify(keys.pubkey().as_ref(), &tx.message.serialize()));
}

#[test]
fn legacy_partial_sign_also_rejects_workload_payer() {
    let keys = EphemeralKeyManager::new();
    let mut tx = Transaction::new_with_payer(&[instruction(keys.pubkey())], Some(&keys.pubkey()));
    let before = tx.clone();
    assert!(keys.partial_sign(&mut tx, Hash::default()).is_err());
    assert_eq!(tx, before);
}
