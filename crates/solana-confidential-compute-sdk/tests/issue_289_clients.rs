//! Producer account contract only; cryptographic admission remains the verifier's job.
use solana_confidential_compute_sdk::{
    derive_amd_revocation_pda,
    staged::{stage_vcek_registration, StageError},
};
use solana_sdk::{
    hash::hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
#[test]
fn staged_registration_preserves_suffix_and_selects_canonical_vcek_or_vlek_identity() {
    let pid = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    let marker = Pubkey::new_unique();
    for (identity_bytes, tcb) in [(&[7u8; 64][..], 17u64), (&[9u8; 96][..], 33)] {
        let identity = hash(identity_bytes).to_bytes();
        let cache =
            Pubkey::find_program_address(&[b"vcek_v2", &identity, &tcb.to_le_bytes()], &pid).0;
        let mut data = vec![228, 65, 209, 71, 242, 135, 131, 17];
        data.extend([7; 64]);
        data.extend(tcb.to_le_bytes());
        data.extend([9; 96]);
        let source = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(Pubkey::new_unique(), false),
                AccountMeta::new(cache, false),
                AccountMeta::new_readonly(marker, false),
            ],
            data,
        };
        let plan = stage_vcek_registration(source.clone(), payer, 100, 150).unwrap();
        assert_eq!(&plan.consume.accounts[2..6], source.accounts.as_slice());
        assert_eq!(
            plan.consume.accounts.last(),
            Some(&AccountMeta::new_readonly(
                derive_amd_revocation_pda(&pid, &identity).0,
                false
            ))
        );
        let mut wrong = source.clone();
        wrong.accounts[2].pubkey = Pubkey::new_unique();
        assert!(matches!(
            stage_vcek_registration(wrong, payer, 100, 150),
            Err(StageError::InvalidAuthority)
        ));
        let mut elevated = source;
        elevated.accounts.push(AccountMeta::new(
            derive_amd_revocation_pda(&pid, &identity).0,
            false,
        ));
        assert!(matches!(
            stage_vcek_registration(elevated, payer, 100, 150),
            Err(StageError::InvalidAuthority)
        ));
    }
}
