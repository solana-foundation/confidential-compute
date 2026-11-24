//! Regression for #214: initialization authorization prevents policy-denial takeover.
//! Legacy global list storage remains recoverable; runtime admission uses BackendPolicy.
#![allow(deprecated)]
use borsh::{BorshDeserialize, BorshSerialize};
use solana_confidential_compute_verifier::{
    payload::{
        InitPolicyRegistryArgs, UpdatePolicyArgs, INIT_POLICY_REGISTRY_DISCRIMINATOR, UPDATE_POLICY_DISCRIMINATOR,
    },
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
fn write_policy<'a>(
    pid: &Pubkey,
    authority: &AccountInfo<'a>,
    registry: &AccountInfo<'a>,
    count: u32,
) -> solana_program::entrypoint::ProgramResult {
    let mut ix = UPDATE_POLICY_DISCRIMINATOR.to_vec();
    UpdatePolicyArgs {
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: count,
        measurements: [[0x42; 48]; 8],
    }
    .serialize(&mut ix)
    .unwrap();
    Processor::process(pid, &[authority.clone(), registry.clone()], &ix)
}
#[test]
fn initialization_proof_blocks_takeover_and_legacy_list_remains_replaceable() {
    let pid = Pubkey::new_unique();
    let (pda, _) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let attacker = account(Pubkey::new_unique(), solana_sdk_ids::system_program::ID, true, true, vec![]);
    let registry = account(pda, pid, false, true, vec![0; PolicyRegistry::SIZE]);
    let system = account(solana_sdk_ids::system_program::ID, solana_sdk_ids::system_program::ID, false, false, vec![]);
    let mut ix = INIT_POLICY_REGISTRY_DISCRIMINATOR.to_vec();
    InitPolicyRegistryArgs {
        authority: attacker.key.to_bytes(),
        ark_pubkey_xy: [1; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 1,
        measurements: [[0x42; 48]; 8],
    }
    .serialize(&mut ix)
    .unwrap();
    let before_init = registry.try_borrow_data().unwrap().to_vec();
    assert!(Processor::process(&pid, &[attacker.clone(), registry.clone(), system.clone()], &ix).is_err());
    assert_eq!(registry.try_borrow_data().unwrap().to_vec(), before_init);
    let loader = solana_sdk_ids::bpf_loader_upgradeable::ID;
    let (programdata_key, _) = Pubkey::find_program_address(&[pid.as_ref()], &loader);
    let mut programdata_bytes = vec![0; 45];
    programdata_bytes[..4].copy_from_slice(&3u32.to_le_bytes());
    programdata_bytes[12] = 1;
    programdata_bytes[13..45].copy_from_slice(Pubkey::new_unique().as_ref());
    let programdata = account(programdata_key, loader, false, false, programdata_bytes);
    assert!(Processor::process(&pid, &[attacker.clone(), registry.clone(), system.clone(), programdata.clone()], &ix)
        .is_err());
    assert_eq!(registry.try_borrow_data().unwrap().to_vec(), before_init);
    // Controlled upgrade-authority fixture, with all fields and positions valid.
    programdata.try_borrow_mut_data().unwrap()[13..45].copy_from_slice(attacker.key.as_ref());
    assert_eq!(Processor::process(&pid, &[attacker.clone(), registry.clone(), system, programdata], &ix), Ok(()));
    let initial = PolicyRegistry::try_from_slice(&registry.try_borrow_data().unwrap()).unwrap();
    assert_eq!(initial.discriminator, POLICY_REGISTRY_DISCRIMINATOR);
    assert_eq!(initial.authority, attacker.key.to_bytes());
    assert!(initial.is_measurement_allowed(&[0x42; 48]));
    let stranger = account(Pubkey::new_unique(), solana_sdk_ids::system_program::ID, true, false, vec![]);
    let before = registry.try_borrow_data().unwrap().to_vec();
    assert!(write_policy(&pid, &stranger, &registry, 0).is_err());
    assert_eq!(registry.try_borrow_data().unwrap().to_vec(), before);
    assert_eq!(write_policy(&pid, &attacker, &registry, 0), Ok(()));
    assert!(!PolicyRegistry::try_from_slice(&registry.try_borrow_data().unwrap())
        .unwrap()
        .is_measurement_allowed(&[0x42; 48]));
    assert_eq!(write_policy(&pid, &attacker, &registry, 1), Ok(()));
    assert!(PolicyRegistry::try_from_slice(&registry.try_borrow_data().unwrap())
        .unwrap()
        .is_measurement_allowed(&[0x42; 48]));
}
