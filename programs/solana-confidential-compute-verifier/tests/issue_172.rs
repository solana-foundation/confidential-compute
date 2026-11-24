use borsh::BorshSerialize;
use solana_confidential_compute_verifier::{
    error::VerifierError, payload::*, processor::Processor, state::*,
};
use solana_program::{account_info::AccountInfo, pubkey::Pubkey};
#[test]
fn mutable_p384_root_rotation_is_unsupported_and_preserves_policy() {
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (registry, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let original = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: authority.to_bytes(),
        ark_pubkey_xy: [9; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 0,
        measurements: [[0; 48]; 8],
        bump,
    };
    for proposed in [[0; 96], [255; 96], [1; 96]] {
        let mut bytes = borsh::to_vec(&original).unwrap();
        let before = bytes.clone();
        let mut ad = [];
        let mut a = 1;
        let mut b = 1;
        let accounts = [
            AccountInfo::new(&authority, true, false, &mut a, &mut ad, &pid, false),
            AccountInfo::new(&registry, false, true, &mut b, &mut bytes, &pid, false),
        ];
        let mut ix = ROTATE_ROOT_CERT_DISCRIMINATOR.to_vec();
        RotateRootCertArgs {
            new_ark_pubkey_xy: proposed,
        }
        .serialize(&mut ix)
        .unwrap();
        assert_eq!(
            Processor::process(&pid, &accounts, &ix),
            Err(VerifierError::InvalidInstruction.into())
        );
        assert_eq!(&**accounts[1].try_borrow_data().unwrap(), before.as_slice());
    }
}
