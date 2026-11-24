use borsh::{BorshDeserialize, BorshSerialize};
use solana_confidential_compute_verifier::{payload::*, processor::Processor, state::*};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
#[test]
fn tenant_policy_configuration_is_governed_exact_and_bounded() {
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let system = solana_sdk_ids::system_program::ID;
    let (registry, rb) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (policy, pb) = Pubkey::find_program_address(&[b"gcp_tenant_policy"], &pid);
    for (signed, aud, sub, success) in [
        (false, "aud", "tenant", false),
        (true, "", "tenant", false),
        (true, "aud", "", false),
        (true, "aud", "tenant", true),
    ] {
        let mut rd = borsh::to_vec(&PolicyRegistry {
            discriminator: POLICY_REGISTRY_DISCRIMINATOR,
            authority: authority.to_bytes(),
            ark_pubkey_xy: [0; 96],
            min_tcb_boot_loader: 0,
            min_tcb_tee: 0,
            min_tcb_snp: 0,
            min_tcb_microcode: 0,
            measurement_count: 0,
            measurements: [[0; 48]; 8],
            bump: rb,
        })
        .unwrap();
        let mut pd = vec![0; GcpTenantPolicy::SIZE];
        let mut ad = [];
        let mut sd = [];
        let mut balances = [1u64; 4];
        let [a, b, c, d] = &mut balances;
        let accounts = [
            AccountInfo::new(&authority, signed, true, a, &mut ad, &pid, false),
            AccountInfo::new(&registry, false, false, b, &mut rd, &pid, false),
            AccountInfo::new(&policy, false, true, c, &mut pd, &pid, false),
            AccountInfo::new(&system, false, false, d, &mut sd, &system, true),
        ];
        let call = [
            accounts[0].clone(),
            accounts[1].clone(),
            accounts[2].clone(),
            accounts[0].clone(),
            accounts[3].clone(),
        ];
        let mut ix = SET_GCP_TENANT_POLICY_DISCRIMINATOR.to_vec();
        SetGcpTenantPolicyArgs {
            expected_audience: aud.into(),
            expected_subject: sub.into(),
        }
        .serialize(&mut ix)
        .unwrap();
        let result = Processor::process(&pid, &call, &ix);
        if success {
            assert_eq!(result, Ok(()));
            let saved =
                GcpTenantPolicy::try_from_slice(&call[2].try_borrow_data().unwrap()).unwrap();
            assert_eq!(saved.expected().unwrap(), (aud.as_bytes(), sub.as_bytes()));
            assert_eq!(saved.bump, pb);
        } else {
            assert!(result.is_err());
            assert!(call[2].try_borrow_data().unwrap().iter().all(|v| *v == 0));
            if !signed {
                assert_eq!(result, Err(ProgramError::MissingRequiredSignature));
            }
        }
    }
    assert!(GcpTenantPolicy::new(&[b'a'; 129], b"tenant", pb).is_err());
    assert!(GcpTenantPolicy::new(b"aud", &[b's'; 161], pb).is_err());
}
