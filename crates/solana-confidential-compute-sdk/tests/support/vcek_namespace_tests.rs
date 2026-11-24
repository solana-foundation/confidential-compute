//! V2 VCEK cache namespace tests for the client and both raw AMD builders.
//!
//! Registered as a unit-test module (like `builder_tests`) so the default-feature
//! `cargo test -p solana-confidential-compute-sdk` lane can reach the crate-private `internal` packers.

use solana_confidential_compute_sdk::{
    internal::{
        build_register_signer_ix_for_program_oversized, build_verify_atomic_with_nonce_ix_oversized,
    },
    ConfidentialComputeClient,
};
use solana_confidential_compute_verifier::state::VcekAccount;
use solana_sdk::{hash::hash, pubkey::Pubkey};
#[test]
fn client_and_both_amd_builders_use_verifier_cache_namespace() {
    assert_eq!(
        solana_confidential_compute_sdk::VCEK_SEED,
        VcekAccount::SEED
    );
    let pid = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    let mut report = [0u8; 1184];
    report[0x50..0x70].copy_from_slice(signer.as_ref());
    report[0x180..0x188].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
    report[0x1a0..0x1e0].fill(7);
    let chip = hash(&report[0x1a0..0x1e0]).to_bytes();
    let tcb = 0x0102030405060708u64;
    let expected =
        Pubkey::find_program_address(&[VcekAccount::SEED, &chip, &tcb.to_le_bytes()], &pid);
    let legacy = Pubkey::find_program_address(&[b"vcek", &chip, &tcb.to_le_bytes()], &pid);
    assert_ne!(expected.0, legacy.0);
    assert_eq!(
        ConfidentialComputeClient::new(pid).derive_vcek_pda(&chip, tcb),
        expected
    );
    let a = build_register_signer_ix_for_program_oversized(&pid, &payer, &signer, &report, 0, 1)
        .unwrap();
    let b = build_verify_atomic_with_nonce_ix_oversized(
        &pid,
        &payer,
        &Pubkey::new_unique(),
        [0; 32],
        [0; 48],
        &report,
        1,
    )
    .unwrap();
    for ix in [a, b] {
        assert_eq!(ix.accounts[2].pubkey, expected.0);
        assert!(!ix.accounts[2].is_signer && !ix.accounts[2].is_writable);
    }
}
