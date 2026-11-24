use solana_confidential_compute_sidecar::{
    AttestationReport, EphemeralKeyManager, MockCluster, OnchainAttestor,
};
use solana_sdk::{
    hash::hash,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
#[tokio::test]
async fn snp_enrollment_inherits_readonly_amd_backend_policy() {
    let pid = Pubkey::new_unique();
    let keys = EphemeralKeyManager::new();
    // Runtime nonce material from a fresh random keypair, not a fixed value.
    let nonce = Keypair::new().pubkey().to_bytes();
    let cluster = MockCluster::new(100, vec![(95, nonce)]);
    let attestor = OnchainAttestor::mock(cluster.clone(), Some(pid), Some(Keypair::new()));
    let chip_id = [9; 64];
    let mut report = vec![0; 1184];
    report[0x1A0..0x1E0].copy_from_slice(&chip_id);
    report[0x50..0x70].copy_from_slice(keys.pubkey().as_ref());
    report[0x70..0x90].copy_from_slice(&nonce);
    attestor
        .submit_attestation(
            &keys,
            95,
            &AttestationReport::SevSnp {
                report,
                vcek_cert: None,
            },
        )
        .await
        .unwrap();
    let txs = cluster.submitted();
    let tx = &txs[0];
    let ix = &tx.message.instructions[0];
    // The source policy and legacy replay guard retain their order; the new
    // identity revocation guard is appended after them. This is account-plumbing
    // evidence from a controlled report, not cryptographic or hardware admission.
    let expected_suffix = [
        solana_confidential_compute_sdk::derive_backend_policy_pda(&pid, 1)
            .unwrap()
            .0,
        solana_confidential_compute_sdk::nonce::derive_legacy_used_nonce_pda(
            &pid,
            &keys.pubkey().to_bytes(),
            &nonce,
        )
        .0,
        solana_confidential_compute_sdk::derive_amd_revocation_pda(
            &pid,
            &hash(&chip_id).to_bytes(),
        )
        .0,
    ];
    let suffix = &ix.accounts[ix.accounts.len() - expected_suffix.len()..];
    for (&account_index, expected_key) in suffix.iter().zip(expected_suffix) {
        let index = usize::from(account_index);
        assert_eq!(tx.message.account_keys[index], expected_key);
        assert!(!tx.message.is_signer(index));
        #[allow(deprecated)]
        {
            assert!(!tx.message.is_maybe_writable(index, None));
        }
    }
}
