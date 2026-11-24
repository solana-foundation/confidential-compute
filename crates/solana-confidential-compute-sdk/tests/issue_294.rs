//! Address derivation component regression, not authentic VLEK admission proof.
#![cfg(feature = "test-utils")]
use solana_confidential_compute_sdk::{
    internal::{
        build_register_signer_ix_for_program_oversized,
        build_register_signer_ix_for_program_oversized_with_endorsement,
        build_verify_atomic_with_nonce_ix_oversized_with_endorsement,
    },
    SdkError,
};
use solana_sdk::{hash::hash, instruction::AccountMeta, pubkey::Pubkey};
#[test]
fn explicit_xy_selects_vlek_address_and_missing_key_fails_closed() {
    let pid = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let xy = [17; 96];
    for (flags, chip) in [(4u32, 9u8), (0, 0), (1, 9)] {
        let mut report = [0; 1184];
        report[0x48..0x4c].copy_from_slice(&flags.to_le_bytes());
        report[0x50..0x70].copy_from_slice(signer.as_ref());
        report[0x1a0..0x1e0].fill(chip);
        let is_vlek = flags == 4 || chip == 0;
        let identity = if is_vlek {
            hash(&xy)
        } else {
            hash(&[chip; 64])
        };
        let expected = Pubkey::find_program_address(
            &[b"vcek_v2", identity.as_ref(), &0u64.to_le_bytes()],
            &pid,
        )
        .0;
        let a = build_register_signer_ix_for_program_oversized_with_endorsement(
            &pid,
            &payer,
            &signer,
            &report,
            0,
            0,
            Some(&xy),
        )
        .unwrap();
        let b = build_verify_atomic_with_nonce_ix_oversized_with_endorsement(
            &pid,
            &payer,
            &signer,
            [0; 32],
            [0; 48],
            &report,
            0,
            Some(&xy),
        )
        .unwrap();
        assert_eq!(a.accounts[2].pubkey, expected);
        assert_eq!(b.accounts[2].pubkey, expected);
        let revocation = AccountMeta::new_readonly(
            Pubkey::find_program_address(&[b"amd_revocation", identity.as_ref()], &pid).0,
            false,
        );
        assert_eq!(a.accounts.last(), Some(&revocation));
        assert_eq!(b.accounts.last(), Some(&revocation));
        if is_vlek {
            assert_eq!(
                build_register_signer_ix_for_program_oversized(
                    &pid, &payer, &signer, &report, 0, 0
                ),
                Err(SdkError::MissingEndorsementKey)
            );
            assert!(matches!(
                solana_confidential_compute_sdk::build_register_signer_ix_for_program_with_endorsement(
                    &pid, &payer, &signer, &report, 0, 0, &xy
                ),
                Err(SdkError::PacketTooLarge { .. })
            ));
        }
    }
}
