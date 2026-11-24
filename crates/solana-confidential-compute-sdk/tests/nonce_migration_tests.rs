use solana_confidential_compute_sdk::internal::{
    build_register_signer_ix_for_program_oversized, build_verify_atomic_with_nonce_ix_oversized,
};
use solana_confidential_compute_sdk::nitro::build_verify_nitro_attestation_ix_for_program_oversized;
use solana_sdk::{instruction::AccountMeta, pubkey::Pubkey};
#[test]
fn builders_use_source_tagged_nonce_and_keep_legacy_readonly_last() {
    let pid = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let nonce = Pubkey::new_unique().to_bytes();
    let mut report = [0u8; 1184];
    report[0x1a0..0x1e0].fill(9);
    report[0x50..0x70].copy_from_slice(signer.as_ref());
    report[0x70..0x90].copy_from_slice(&nonce);
    let a = build_register_signer_ix_for_program_oversized(&pid, &payer, &signer, &report, 0, 95)
        .unwrap();
    let b = build_verify_atomic_with_nonce_ix_oversized(
        &pid, &payer, &signer, [0; 32], [0; 48], &report, 95,
    )
    .unwrap();
    let n0 = build_verify_nitro_attestation_ix_for_program_oversized(
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
    let n1 = build_verify_nitro_attestation_ix_for_program_oversized(
        &pid,
        &payer,
        &signer,
        1,
        95,
        [0; 32],
        &[1],
        &nonce,
    )
    .unwrap();
    for (ix, tag, binding, index, bump_at) in [
        (a, 1, nonce, 4, Some(1200)),
        (b, 1, nonce, 3, Some(1264)),
        (n0, 2, nonce, 3, None),
        (n1, 2, nonce, 3, None),
    ] {
        let expected =
            Pubkey::find_program_address(&[b"nonce", &[tag], signer.as_ref(), &binding], &pid);
        let legacy = Pubkey::find_program_address(&[b"nonce", signer.as_ref(), &binding], &pid).0;
        assert_eq!(ix.accounts[index].pubkey, expected.0);
        assert_eq!(
            ix.accounts
                .get(ix.accounts.len() - if tag == 1 { 2 } else { 1 }),
            Some(&AccountMeta::new_readonly(legacy, false))
        );
        assert_ne!(expected.0, legacy);
        if let Some(at) = bump_at {
            assert_eq!(ix.data[at], expected.1);
        }
    }
}

#[test]
fn explicit_nonce_domains_match_producer_tuples_and_reject_unknown_sources() {
    use solana_confidential_compute_sdk::{
        derive_google_used_nonce_pda, derive_legacy_google_used_nonce_pda,
        derive_legacy_used_nonce_pda, derive_used_nonce_pda_for_source, NonceError,
    };
    let pid = Pubkey::new_unique();
    let signer = Pubkey::new_unique().to_bytes();
    let nonce = Pubkey::new_unique().to_bytes();
    let amd = derive_used_nonce_pda_for_source(&pid, 1, &signer, &nonce).unwrap();
    let nitro = derive_used_nonce_pda_for_source(&pid, 2, &signer, &nonce).unwrap();
    assert_ne!(amd.0, nitro.0);
    let legacy = derive_legacy_used_nonce_pda(&pid, &signer, &nonce);
    assert_eq!(
        legacy,
        Pubkey::find_program_address(&[b"nonce", &signer, &nonce], &pid)
    );
    assert_ne!(amd.0, legacy.0);
    for source in [0, 3, 4, 255] {
        assert_eq!(
            derive_used_nonce_pda_for_source(&pid, source, &signer, &nonce),
            Err(NonceError::InvalidSource)
        );
    }
    for binding in [vec![8; 32], [signer, nonce].concat()] {
        let hash = solana_sdk::hash::hash(&binding).to_bytes();
        let active = derive_google_used_nonce_pda(&pid, &binding).unwrap();
        assert_eq!(
            active,
            Pubkey::find_program_address(&[b"nonce", &[3], &hash], &pid)
        );
        assert_eq!(
            derive_legacy_google_used_nonce_pda(&pid, &binding).unwrap(),
            Pubkey::find_program_address(&[b"nonce", &hash], &pid)
        );
        let double_hash = solana_sdk::hash::hash(&hash).to_bytes();
        assert_ne!(
            active.0,
            Pubkey::find_program_address(&[b"nonce", &[3], &double_hash], &pid).0
        );
    }
    for size in [0, 31, 33, 43, 63, 65, 86] {
        assert_eq!(
            derive_google_used_nonce_pda(&pid, &vec![b'A'; size]),
            Err(NonceError::InvalidGoogleBinding)
        );
        assert_eq!(
            derive_legacy_google_used_nonce_pda(&pid, &vec![b'A'; size]),
            Err(NonceError::InvalidGoogleBinding)
        );
    }
}
