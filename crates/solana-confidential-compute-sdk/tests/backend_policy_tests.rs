use solana_confidential_compute_sdk::{
    internal::{build_register_signer_ix_for_program_oversized, build_verify_atomic_with_nonce_ix_oversized},
    nitro::build_verify_nitro_attestation_ix_for_program_oversized,
};
use solana_confidential_compute_verifier::state::BackendPolicy;
use solana_sdk::{instruction::AccountMeta, pubkey::Pubkey};
fn expected(pid: &Pubkey, source: u8) -> AccountMeta {
    AccountMeta::new_readonly(Pubkey::find_program_address(&[BackendPolicy::SEED, &[source]], pid).0, false)
}
#[test]
fn every_sdk_verification_builder_appends_canonical_source_policy() {
    let pid = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    // Runtime nonce: account layout does not depend on its value.
    let nonce = Pubkey::new_unique().to_bytes();
    let mut report = [0; 1184];
    report[0x1a0..0x1e0].fill(9);
    report[0x50..0x70].copy_from_slice(signer.as_ref());
    let a = build_register_signer_ix_for_program_oversized(&pid, &payer, &signer, &report, 0, 95).unwrap();
    let b = build_verify_atomic_with_nonce_ix_oversized(&pid, &payer, &signer, [0; 32], [0; 48], &report, 95).unwrap();
    let n0 =
        build_verify_nitro_attestation_ix_for_program_oversized(&pid, &payer, &signer, 0, 95, [0; 32], &[1], &nonce)
            .unwrap();
    let n1 =
        build_verify_nitro_attestation_ix_for_program_oversized(&pid, &payer, &signer, 1, 95, [0; 32], &[1], &nonce)
            .unwrap();
    for (ix, source) in [(a, 1), (b, 1), (n0, 2), (n1, 2)] {
        assert_eq!(ix.accounts.get(ix.accounts.len() - if source == 1 { 3 } else { 2 }), Some(&expected(&pid, source)));
        assert!(!ix.accounts.contains(&expected(&pid, if source == 1 { 2 } else { 1 })));
    }
    let checked = solana_confidential_compute_sdk::build_verify_nitro_attestation_ix_for_program(
        &pid,
        &payer,
        &signer,
        0,
        95,
        [0; 32],
        &[1],
        &nonce,
    )
    .unwrap();
    assert_eq!(checked.accounts.get(checked.accounts.len() - 2), Some(&expected(&pid, 2)));
}
#[test]
fn governed_setter_has_exact_borsh_bytes_metas_and_bounds() {
    use solana_confidential_compute_sdk::backend_policy::{
        build_set_backend_policy_ix, derive_backend_policy_pda, BackendPolicyError, SET_BACKEND_POLICY_DISCRIMINATOR,
    };
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    assert_eq!(
        SET_BACKEND_POLICY_DISCRIMINATOR,
        solana_confidential_compute_verifier::payload::SET_BACKEND_POLICY_DISCRIMINATOR
    );
    assert_eq!(solana_confidential_compute_sdk::backend_policy::BACKEND_POLICY_SEED, BackendPolicy::SEED);
    assert_eq!(BackendPolicy::SIZE, 398);
    // 5 is Intel TDX. The builder mirrors the program, which accepts 1..=5.
    for source in [1, 2, 3, 4, 5] {
        let backend = derive_backend_policy_pda(&pid, source).unwrap().0;
        let ix = build_set_backend_policy_ix(&pid, &authority, &payer, source, &[[7; 48]]).unwrap();
        let mut bytes = SET_BACKEND_POLICY_DISCRIMINATOR.to_vec();
        bytes.push(source);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[7; 48]);
        bytes.resize(397, 0);
        assert_eq!(ix.data, bytes);
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(Pubkey::find_program_address(&[b"policy_registry"], &pid).0, false),
                AccountMeta::new(backend, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false)
            ]
        );
        let halt = build_set_backend_policy_ix(&pid, &authority, &payer, source, &[]).unwrap();
        assert_eq!(&halt.data[9..], &[0; 388]);
        assert!(build_set_backend_policy_ix(&pid, &authority, &payer, source, &[[8; 48]; 8]).is_ok());
        assert_eq!(
            build_set_backend_policy_ix(&pid, &authority, &payer, source, &[[8; 48]; 9]).unwrap_err(),
            BackendPolicyError::InvalidMeasurements
        );
    }
    for source in [0, 6, 255] {
        assert_eq!(derive_backend_policy_pda(&pid, source).unwrap_err(), BackendPolicyError::InvalidSource);
        assert_eq!(
            build_set_backend_policy_ix(&pid, &authority, &payer, source, &[]).unwrap_err(),
            BackendPolicyError::InvalidSource
        );
    }
    assert_ne!(derive_backend_policy_pda(&pid, 1).unwrap().0, derive_backend_policy_pda(&pid, 2).unwrap().0);
}
