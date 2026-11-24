use solana_confidential_compute_sdk::{
    build_set_gcp_tenant_policy_ix, gcp_policy::SET_GCP_TENANT_POLICY_DISCRIMINATOR,
};
use solana_sdk::{instruction::AccountMeta, pubkey::Pubkey};
#[test]
fn governed_tenant_setter_matches_program_bytes_and_accounts() {
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    assert_eq!(
        SET_GCP_TENANT_POLICY_DISCRIMINATOR,
        solana_confidential_compute_verifier::payload::SET_GCP_TENANT_POLICY_DISCRIMINATOR
    );
    let ix = build_set_gcp_tenant_policy_ix(&pid, &authority, &payer, "aud", "sub").unwrap();
    let mut expected = SET_GCP_TENANT_POLICY_DISCRIMINATOR.to_vec();
    expected.extend_from_slice(&[3, 0, 0, 0, b'a', b'u', b'd', 3, 0, 0, 0, b's', b'u', b'b']);
    assert_eq!(ix.data, expected);
    assert_eq!(
        ix.accounts,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(Pubkey::find_program_address(&[b"policy_registry"], &pid).0, false),
            AccountMeta::new(Pubkey::find_program_address(&[b"gcp_tenant_policy"], &pid).0, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false)
        ]
    );
    for (a, s) in [("", "s"), ("a", ""), ("a\0b", "s")] {
        assert!(build_set_gcp_tenant_policy_ix(&pid, &authority, &payer, a, s).is_err());
    }
    assert!(build_set_gcp_tenant_policy_ix(&pid, &authority, &payer, &"é".repeat(65), "s").is_err());
    assert!(build_set_gcp_tenant_policy_ix(&pid, &authority, &payer, &"a".repeat(128), &"s".repeat(160)).is_ok());
}
