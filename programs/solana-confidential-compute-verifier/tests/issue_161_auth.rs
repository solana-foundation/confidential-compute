// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unreachable)]
use borsh::{BorshDeserialize, BorshSerialize};
use solana_confidential_compute_verifier::{payload::*, processor::Processor, state::PolicyRegistry};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

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
fn instruction<T: BorshSerialize>(disc: [u8; 8], args: &T) -> Vec<u8> {
    let mut data = disc.to_vec();
    args.serialize(&mut data).unwrap();
    data
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
        account(solana_sdk_ids::system_program::id(), pid, false, false, vec![]),
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
fn init_requires_authenticated_program_data_and_preserves_state_on_failure() {
    let pid = Pubkey::new_unique();
    let auth = Pubkey::new_unique();
    let ix = init(auth, 1);
    // Positive control: authentic upgrade authority initializes all trust roots.
    let accounts = init_accounts(pid, auth);
    assert_eq!(Processor::process(&pid, &accounts, &ix), Ok(()));
    assert_eq!(saved(&accounts[1]).authority, auth.to_bytes());
    assert_eq!(Processor::process(&pid, &accounts, &ix), Err(ProgramError::AccountAlreadyInitialized));
    for case in 0..9 {
        let mut a = init_accounts(pid, auth);
        match case {
            0 => {
                a.truncate(3);
            }
            1 => {
                a[3].try_borrow_mut_data().unwrap()[12] = 0;
            } // finalized
            2 => {
                a[3] = account(*a[3].key, *a[3].owner, false, false, vec![0; 12]);
            }
            3 => {
                a[3].try_borrow_mut_data().unwrap()[0] = 2;
            } // wrong loader variant
            4 => {
                a[3].try_borrow_mut_data().unwrap()[12] = 2;
            } // invalid Option tag
            5 => {
                a[3].try_borrow_mut_data().unwrap()[13..45].copy_from_slice(Pubkey::new_unique().as_ref());
            }
            6 => {
                let data = a[3].data.borrow().to_vec();
                a[3] = account(Pubkey::new_unique(), *a[3].owner, false, false, data);
            }
            7 => {
                let data = a[3].data.borrow().to_vec();
                a[3] = account(*a[3].key, Pubkey::new_unique(), false, false, data);
            }
            8 => {
                a[0].is_signer = false;
            }
            _ => unreachable!(),
        }
        let before = a[1].data.borrow().to_vec();
        assert!(Processor::process(&pid, &a, &ix).is_err(), "invalid ProgramData case {case} accepted");
        assert_eq!(*a[1].data.borrow(), before.as_slice(), "case {case} mutated registry");
    }
}
