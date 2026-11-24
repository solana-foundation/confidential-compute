use solana_confidential_compute_sdk::governance::*;
use solana_confidential_compute_verifier::payload as wire;
use solana_sdk::{hash::hash, instruction::AccountMeta, pubkey::Pubkey};

#[test]
fn existing_discriminators_match_program_and_new_operations_match_anchor() {
    assert_eq!(UPDATE_POLICY_DISCRIMINATOR, wire::UPDATE_POLICY_DISCRIMINATOR);
    assert_eq!(ROTATE_ROOT_CERT_DISCRIMINATOR, wire::ROTATE_ROOT_CERT_DISCRIMINATOR);
    assert_eq!(REGISTER_JWKS_KEY_DISCRIMINATOR, wire::REGISTER_JWKS_KEY_DISCRIMINATOR);
    assert_eq!(REVOKE_JWKS_KEY_DISCRIMINATOR, wire::REVOKE_JWKS_KEY_DISCRIMINATOR);
    assert_eq!(
        ROTATE_AUTHORITY_DISCRIMINATOR,
        solana_confidential_compute_verifier::processor::ROTATE_AUTHORITY_DISCRIMINATOR
    );
    for (name, bytes) in [
        ("rotate_authority", ROTATE_AUTHORITY_DISCRIMINATOR),
        ("revoke_attested_signer", REVOKE_ATTESTED_SIGNER_DISCRIMINATOR),
    ] {
        assert_eq!(bytes.as_slice(), &hash(format!("global:{name}").as_bytes()).to_bytes()[..8]);
    }
}
#[test]
fn policy_bytes_and_metas_match_borsh_contract() {
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let registry = Pubkey::find_program_address(&[b"policy_registry"], &pid).0;
    let policy = PolicyUpdate { min_tcb: [1, 2, 3, 4], measurements: vec![[7; 48]] };
    let ix = build_update_policy_ix(&pid, &authority, &policy).unwrap();
    assert_eq!(ix.program_id, pid);
    assert_eq!(ix.accounts, vec![AccountMeta::new_readonly(authority, true), AccountMeta::new(registry, false)]);
    let mut expected = UPDATE_POLICY_DISCRIMINATOR.to_vec();
    expected.extend_from_slice(&[1, 2, 3, 4]);
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&[7; 48]);
    expected.resize(400, 0);
    assert_eq!(ix.data, expected);
    let halt =
        build_update_policy_ix(&pid, &authority, &PolicyUpdate { min_tcb: [0; 4], measurements: vec![] }).unwrap();
    assert_eq!(&halt.data[12..], &[0; 388]);
    assert_eq!(
        build_update_policy_ix(&pid, &authority, &PolicyUpdate { min_tcb: [0; 4], measurements: vec![[0; 48]; 9] })
            .unwrap_err(),
        GovernanceError::InvalidMeasurements
    );
    assert!(build_update_policy_ix(
        &pid,
        &authority,
        &PolicyUpdate { min_tcb: [255; 4], measurements: vec![[0; 48]; 8] }
    )
    .is_ok());
    let root = build_rotate_root_cert_ix(&pid, &authority, &[9; 96]);
    assert_eq!(root.accounts, ix.accounts);
    assert_eq!(&root.data[8..], &[9; 96]);
    assert_eq!(root.data.len(), 104);
}
#[test]
fn jwks_borsh_bytes_pda_and_account_privileges() {
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    let kid = b"kid-1";
    let n = [0xff; 256];
    let ix = build_register_jwks_key_ix(&pid, &authority, &payer, kid, &n, 65537).unwrap();
    let hash = hash(kid).to_bytes();
    let jwks = Pubkey::find_program_address(&[b"jwks", &hash], &pid).0;
    let registry = Pubkey::find_program_address(&[b"policy_registry"], &pid).0;
    assert_eq!(
        ix.accounts,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(registry, false),
            AccountMeta::new(jwks, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false)
        ]
    );
    let mut expected = REGISTER_JWKS_KEY_DISCRIMINATOR.to_vec();
    expected.extend_from_slice(&5u32.to_le_bytes());
    expected.extend_from_slice(kid);
    expected.extend_from_slice(&n);
    expected.extend_from_slice(&65537u32.to_le_bytes());
    assert_eq!(ix.data, expected);
    let revoke = build_revoke_jwks_key_ix(&pid, &authority, hash);
    assert_eq!(revoke.accounts, ix.accounts[..3]);
    assert_eq!(&revoke.data[8..], &hash);
    for kid in [&b""[..], &b"a\0b"[..], &[1; 65][..]] {
        assert_eq!(
            build_register_jwks_key_ix(&pid, &authority, &payer, kid, &n, 65537).unwrap_err(),
            GovernanceError::InvalidKid
        );
    }
    assert!(build_register_jwks_key_ix(&pid, &authority, &payer, &[1; 64], &n, 65537).is_ok());
    assert_eq!(
        build_register_jwks_key_ix(&pid, &authority, &payer, kid, &n, 3).unwrap_err(),
        GovernanceError::InvalidRsaKey
    );
    assert!(build_register_jwks_key_ix(&pid, &authority, &payer, kid, &[0; 256], 65537).is_err());
}
#[test]
fn atomic_rotation_and_targeted_revocation_match_agreed_contract() {
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let receiver = Pubkey::new_unique();
    let ix = build_rotate_authority_ix(&pid, &authority, &receiver).unwrap();
    assert_eq!(ix.data, ROTATE_AUTHORITY_DISCRIMINATOR);
    assert_eq!(
        ix.accounts,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(Pubkey::find_program_address(&[b"policy_registry"], &pid).0, false),
            AccountMeta::new_readonly(receiver, true)
        ]
    );
    for bad in [authority, Pubkey::default()] {
        assert_eq!(build_rotate_authority_ix(&pid, &authority, &bad).unwrap_err(), GovernanceError::InvalidAuthority);
    }
    let revoke = build_revoke_attested_signer_ix(&pid, &authority, &receiver);
    assert!(!revoke.accounts[1].is_writable);
    assert_eq!(
        revoke.accounts[2],
        AccountMeta::new(
            Pubkey::find_program_address(
                &[solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED, receiver.as_ref()],
                &pid
            )
            .0,
            false
        )
    );
    assert_eq!(&revoke.data[8..], receiver.as_ref());
}

#[test]
fn vcek_revocation_matches_program_wire_and_v2_cache() {
    assert_eq!(REVOKE_VCEK_DISCRIMINATOR, wire::REVOKE_VCEK_DISCRIMINATOR);
    assert_eq!(REVOKE_VCEK_DISCRIMINATOR.as_slice(), &hash(b"global:revoke_vcek").to_bytes()[..8]);
    let (pid, authority) = (Pubkey::new_unique(), Pubkey::new_unique());
    let chip_id_hash = [6u8; 32];
    let ix = build_revoke_vcek_ix(&pid, &authority, &authority, &chip_id_hash, 77);
    assert!(!ix.accounts[1].is_writable);
    assert_eq!(
        ix.accounts[2],
        AccountMeta::new(
            Pubkey::find_program_address(
                &[solana_confidential_compute_sdk::VCEK_SEED, &chip_id_hash, &77u64.to_le_bytes()],
                &pid
            )
            .0,
            false
        )
    );
    assert_eq!(
        ix.accounts[3],
        AccountMeta::new(solana_confidential_compute_sdk::derive_amd_revocation_pda(&pid, &chip_id_hash).0, false)
    );
    assert_eq!(ix.accounts[4], AccountMeta::new(authority, true));
    assert_eq!(ix.accounts[5], AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false));
    assert_eq!(&ix.data[8..40], &chip_id_hash);
    assert_eq!(&ix.data[40..], &77u64.to_le_bytes());
}
