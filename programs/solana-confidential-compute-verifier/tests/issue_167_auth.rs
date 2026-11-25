// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unreachable)]
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
fn rotate() -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(b"global:rotate_authority")[..8].to_vec()
}
#[test]
fn authority_handover_requires_both_signatures_and_moves_governance() {
    let pid = Pubkey::new_unique();
    let old = Pubkey::new_unique();
    let new = Pubkey::new_unique();
    let a = vec![account(old, pid, true, false, vec![]), registry(pid, old), account(new, pid, true, false, vec![])];
    let mut expected = saved(&a[1]);
    expected.authority = new.to_bytes();
    assert_eq!(Processor::process(&pid, &a, &rotate()), Ok(()));
    assert_eq!(saved(&a[1]), expected); // all policy and trust-root bytes preserved
    assert!(Processor::process(&pid, &a, &update([10, 20, 30, 40], 1)).is_err());
    let next = vec![a[2].clone(), a[1].clone()];
    assert_eq!(Processor::process(&pid, &next, &update([10, 20, 30, 40], 1)), Ok(()));
    let root_ix = instruction(ROTATE_ROOT_CERT_DISCRIMINATOR, &RotateRootCertArgs { new_ark_pubkey_xy: [5; 96] });
    assert!(Processor::process(&pid, &a, &root_ix).is_err());
    // Issue #172: even the new authority's root rotation is refused, registry unchanged.
    let before = a[1].data.borrow().to_vec();
    assert_eq!(Processor::process(&pid, &next, &root_ix), Err(VerifierError::InvalidInstruction.into()));
    assert_eq!(*a[1].data.borrow(), before.as_slice());
}
#[test]
fn invalid_handover_preserves_every_registry_byte() {
    let pid = Pubkey::new_unique();
    let old = Pubkey::new_unique();
    let new = Pubkey::new_unique();
    for case in 0..10 {
        let mut a =
            vec![account(old, pid, true, false, vec![]), registry(pid, old), account(new, pid, true, false, vec![])];
        let mut ix = rotate();
        match case {
            0 => a[0].is_signer = false,
            1 => a[2].is_signer = false,
            2 => a[0] = account(Pubkey::new_unique(), pid, true, false, vec![]),
            3 => a[2] = account(Pubkey::default(), pid, true, false, vec![]),
            4 => a[2] = a[0].clone(),
            5 => ix.push(1),
            6 => a[1].is_writable = false,
            7 => {
                let data = a[1].data.borrow().to_vec();
                a[1] = account(*a[1].key, Pubkey::new_unique(), false, true, data);
            }
            8 => {
                let data = a[1].data.borrow().to_vec();
                a[1] = account(Pubkey::new_unique(), pid, false, true, data);
            }
            9 => a[1].try_borrow_mut_data().unwrap()[0] ^= 1,
            _ => unreachable!(),
        }
        let before = a[1].data.borrow().to_vec();
        assert!(Processor::process(&pid, &a, &ix).is_err(), "case {case}");
        assert_eq!(*a[1].data.borrow(), before.as_slice(), "case {case}");
    }
}
