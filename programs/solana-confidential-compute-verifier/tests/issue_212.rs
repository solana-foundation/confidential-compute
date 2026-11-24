//! Regression for #212: reject out-of-capacity policy writes while preserving
//! legacy global list replacement and the full supported u8 TCB range.
use borsh::{BorshDeserialize, BorshSerialize};
use solana_confidential_compute_verifier::{
    payload::{UpdatePolicyArgs, UPDATE_POLICY_DISCRIMINATOR},
    processor::Processor,
    state::{PolicyRegistry, POLICY_REGISTRY_DISCRIMINATOR},
};
use solana_program::{account_info::AccountInfo, pubkey::Pubkey};

fn args(count: u32, floor: u8) -> UpdatePolicyArgs {
    UpdatePolicyArgs {
        min_tcb_boot_loader: floor,
        min_tcb_tee: floor,
        min_tcb_snp: floor,
        min_tcb_microcode: floor,
        measurement_count: count,
        measurements: [[0x42; 48]; 8],
    }
}
fn update(
    count: u32,
    floor: u8,
    signer: bool,
    foreign: bool,
    bytes: &mut [u8],
    pid: Pubkey,
    authority: Pubkey,
) -> solana_program::entrypoint::ProgramResult {
    let (pda, _) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let key = if foreign {
        Pubkey::new_unique()
    } else {
        authority
    };
    let mut lamports = 1;
    let mut registry_lamports = 1;
    let mut empty = [];
    let accounts = [
        AccountInfo::new(&key, signer, false, &mut lamports, &mut empty, &pid, false),
        AccountInfo::new(
            &pda,
            false,
            true,
            &mut registry_lamports,
            bytes,
            &pid,
            false,
        ),
    ];
    let mut ix = UPDATE_POLICY_DISCRIMINATOR.to_vec();
    args(count, floor).serialize(&mut ix).unwrap();
    Processor::process(&pid, &accounts, &ix)
}
fn setup() -> (Pubkey, Pubkey, Vec<u8>) {
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (_, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let registry = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: authority.to_bytes(),
        ark_pubkey_xy: [1; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 1,
        measurements: [[0x42; 48]; 8],
        bump,
    };
    (pid, authority, borsh::to_vec(&registry).unwrap())
}
#[test]
fn empty_policy_is_recoverable_and_authorization_preserves_state() {
    let (pid, authority, mut bytes) = setup();
    assert!(PolicyRegistry::try_from_slice(&bytes)
        .unwrap()
        .is_measurement_allowed(&[0x42; 48]));
    assert_eq!(
        update(0, 0, true, false, &mut bytes, pid, authority),
        Ok(())
    );
    assert!(!PolicyRegistry::try_from_slice(&bytes)
        .unwrap()
        .is_measurement_allowed(&[0x42; 48]));
    let halted = bytes.clone();
    assert!(update(1, 0, false, false, &mut bytes, pid, authority).is_err());
    assert_eq!(bytes, halted);
    assert!(update(1, 0, true, true, &mut bytes, pid, authority).is_err());
    assert_eq!(bytes, halted);
    assert_eq!(
        update(1, 0, true, false, &mut bytes, pid, authority),
        Ok(())
    );
    assert!(PolicyRegistry::try_from_slice(&bytes)
        .unwrap()
        .is_measurement_allowed(&[0x42; 48]));
}
#[test]
fn full_u8_tcb_floor_is_representable() {
    let (pid, authority, mut bytes) = setup();
    assert_eq!(
        update(1, 255, true, false, &mut bytes, pid, authority),
        Ok(())
    );
    assert_eq!(
        PolicyRegistry::try_from_slice(&bytes)
            .unwrap()
            .min_tcb_microcode,
        255
    );
}
#[test]
fn out_of_capacity_count_is_rejected_without_mutation() {
    let (pid, authority, mut bytes) = setup();
    let before = bytes.clone();
    assert!(update(9, 0, true, false, &mut bytes, pid, authority).is_err());
    assert_eq!(bytes, before);
}
