use borsh::{BorshDeserialize, BorshSerialize};
use solana_confidential_compute_verifier::{
    error::VerifierError,
    payload::*,
    processor::Processor,
    state::{PolicyRegistry, POLICY_REGISTRY_DISCRIMINATOR},
};
use solana_program::{account_info::AccountInfo, pubkey::Pubkey};

fn account(
    key: Pubkey,
    owner: Pubkey,
    signer: bool,
    writable: bool,
    data: Vec<u8>,
) -> AccountInfo<'static> {
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
fn init_accounts(pid: Pubkey, authority: Pubkey) -> Vec<AccountInfo<'static>> {
    let loader = solana_sdk_ids::bpf_loader_upgradeable::id();
    let (pd, _) = Pubkey::find_program_address(&[pid.as_ref()], &loader);
    let (reg, _) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let mut data = vec![0; 45];
    data[..4].copy_from_slice(&3u32.to_le_bytes());
    data[12] = 1;
    data[13..].copy_from_slice(authority.as_ref());
    vec![
        account(authority, pid, true, true, vec![]),
        account(reg, pid, false, true, vec![0; PolicyRegistry::SIZE]),
        account(
            solana_sdk_ids::system_program::id(),
            pid,
            false,
            false,
            vec![],
        ),
        account(pd, loader, false, false, data),
    ]
}
fn init(authority: Pubkey, count: u32) -> Vec<u8> {
    instruction(
        INIT_POLICY_REGISTRY_DISCRIMINATOR,
        &InitPolicyRegistryArgs {
            authority: authority.to_bytes(),
            ark_pubkey_xy: [3; 96],
            min_tcb_boot_loader: 10,
            min_tcb_tee: 20,
            min_tcb_snp: 30,
            min_tcb_microcode: 40,
            measurement_count: count,
            measurements: [[42; 48]; 8],
        },
    )
}

#[test]
fn measurement_count_is_bounded_on_init_and_update() {
    let pid = Pubkey::new_unique();
    let auth = Pubkey::new_unique();
    for count in [0, 1, 8, 9, u32::MAX] {
        let a = init_accounts(pid, auth);
        let before = a[1].data.borrow().to_vec();
        let res = Processor::process(&pid, &a, &init(auth, count));
        if count <= 8 {
            assert_eq!(res, Ok(()));
            assert_eq!(saved(&a[1]).measurement_count, count);
        } else {
            assert_eq!(res, Err(VerifierError::InvalidInstruction.into()));
            assert_eq!(*a[1].data.borrow(), before.as_slice());
        }
        let a = vec![account(auth, pid, true, false, vec![]), registry(pid, auth)];
        let before = a[1].data.borrow().to_vec();
        let res = Processor::process(&pid, &a, &update([10, 20, 30, 40], count));
        if count <= 8 {
            assert_eq!(res, Ok(()));
            assert_eq!(saved(&a[1]).measurement_count, count);
        } else {
            assert_eq!(res, Err(VerifierError::InvalidInstruction.into()));
            assert_eq!(*a[1].data.borrow(), before.as_slice());
        }
    }
}
#[test]
fn empty_policy_is_recoverable_and_full_tcb_byte_range_remains_supported() {
    let pid = Pubkey::new_unique();
    let auth = Pubkey::new_unique();
    let a = vec![account(auth, pid, true, false, vec![]), registry(pid, auth)];
    assert_eq!(Processor::process(&pid, &a, &update([255; 4], 0)), Ok(()));
    assert!(!saved(&a[1]).is_measurement_allowed(&[77; 48]));
    assert_eq!(Processor::process(&pid, &a, &update([255; 4], 1)), Ok(()));
    assert!(saved(&a[1]).is_measurement_allowed(&[77; 48]));
}
