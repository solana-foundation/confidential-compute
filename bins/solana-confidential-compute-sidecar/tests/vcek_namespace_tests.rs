use solana_confidential_compute_sidecar::{
    AttestationReport, EphemeralKeyManager, MockCluster, OnchainAttestor,
};
use solana_sdk::{hash::hash, pubkey::Pubkey, signature::Keypair};
#[tokio::test]
async fn dry_run_snp_enrollment_consumes_sdk_v2_cache_derivation() {
    let workload = EphemeralKeyManager::new();
    let payer = Keypair::new();
    let pid = Pubkey::new_unique();
    let cluster = MockCluster::new(100, vec![(95, [7; 32])]);
    let mut report = vec![0; 1184];
    report[0x50..0x70].copy_from_slice(workload.pubkey().as_ref());
    report[0x70..0x90].copy_from_slice(&[7; 32]);
    report[0x1a0..0x1e0].fill(9);
    let chip = hash(&report[0x1a0..0x1e0]).to_bytes();
    let expected = Pubkey::find_program_address(
        &[
            solana_confidential_compute_sdk::VCEK_SEED,
            &chip,
            &0u64.to_le_bytes(),
        ],
        &pid,
    )
    .0;
    let attestor = OnchainAttestor::mock(cluster.clone(), Some(pid), Some(payer));
    attestor
        .submit_attestation(
            &workload,
            95,
            &AttestationReport::SevSnp {
                report,
                vcek_cert: None,
            },
        )
        .await
        .unwrap();
    let txs = cluster.submitted();
    let ix = &txs[0].message.instructions[0];
    assert_eq!(
        txs[0].message.account_keys[ix.accounts[2] as usize],
        expected
    );
    assert_ne!(
        expected,
        Pubkey::find_program_address(&[b"vcek", &chip, &0u64.to_le_bytes()], &pid).0
    );
    assert!(txs[0].signatures[0].verify(
        txs[0].message.account_keys[0].as_ref(),
        &txs[0].message_data()
    ));
}
