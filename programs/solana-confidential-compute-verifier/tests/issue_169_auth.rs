// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use borsh::{BorshDeserialize, BorshSerialize};
use solana_confidential_compute_verifier::{
    error::VerifierError,
    payload::*,
    processor::Processor,
    state::{PolicyRegistry, POLICY_REGISTRY_DISCRIMINATOR},
};
use solana_program::{account_info::AccountInfo, pubkey::Pubkey};

fn account(key: Pubkey, owner: Pubkey, signer: bool, writable: bool, data: Vec<u8>) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        signer,
        writable,
        Box::leak(Box::new(1000)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
    )
}
fn registry(pid: Pubkey, authority: Pubkey) -> AccountInfo<'static> {
    let (key, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    account(
        key,
        pid,
        false,
        true,
        borsh::to_vec(&PolicyRegistry {
            discriminator: POLICY_REGISTRY_DISCRIMINATOR,
            authority: authority.to_bytes(),
            ark_pubkey_xy: [3; 96],
            min_tcb_boot_loader: 10,
            min_tcb_tee: 20,
            min_tcb_snp: 30,
            min_tcb_microcode: 40,
            measurement_count: 1,
            measurements: [[42; 48]; 8],
            bump,
        })
        .unwrap(),
    )
}
fn instruction<T: BorshSerialize>(disc: [u8; 8], args: &T) -> Vec<u8> {
    let mut data = disc.to_vec();
    args.serialize(&mut data).unwrap();
    data
}
fn update(floors: [u8; 4], count: u32) -> Vec<u8> {
    instruction(
        UPDATE_POLICY_DISCRIMINATOR,
        &UpdatePolicyArgs {
            min_tcb_boot_loader: floors[0],
            min_tcb_tee: floors[1],
            min_tcb_snp: floors[2],
            min_tcb_microcode: floors[3],
            measurement_count: count,
            measurements: [[77; 48]; 8],
        },
    )
}
fn saved(a: &AccountInfo) -> PolicyRegistry {
    PolicyRegistry::try_from_slice(&a.try_borrow_data().unwrap()).unwrap()
}
#[test]
fn ordinary_updates_cannot_lower_any_tcb_floor() {
    let pid = Pubkey::new_unique();
    let auth = Pubkey::new_unique();
    for component in 0..4 {
        let a = vec![account(auth, pid, true, false, vec![]), registry(pid, auth)];
        let before = a[1].data.borrow().to_vec();
        let mut floors = [10, 20, 30, 40];
        floors[component] -= 1;
        assert_eq!(Processor::process(&pid, &a, &update(floors, 1)), Err(VerifierError::UnauthorizedPolicy.into()));
        assert_eq!(*a[1].data.borrow(), before.as_slice());
    }
    let a = vec![account(auth, pid, true, false, vec![]), registry(pid, auth)];
    assert_eq!(Processor::process(&pid, &a, &update([10, 20, 30, 40], 1)), Ok(()));
    assert!(saved(&a[1]).is_measurement_allowed(&[77; 48]));
    assert_eq!(Processor::process(&pid, &a, &update([11, 21, 31, 41], 1)), Ok(()));
    assert_eq!(saved(&a[1]).min_tcb_boot_loader, 11);
    let before = a[1].data.borrow().to_vec();
    assert_eq!(
        Processor::process(&pid, &a, &update([10, 20, 30, 40], 1)),
        Err(VerifierError::UnauthorizedPolicy.into())
    );
    assert_eq!(*a[1].data.borrow(), before.as_slice());
}
