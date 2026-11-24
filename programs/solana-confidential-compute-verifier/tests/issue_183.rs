use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::program_stubs::{set_syscall_stubs, SyscallStubs};
use solana_program::{account_info::AccountInfo, pubkey::Pubkey};
use std::sync::{Arc, Mutex};
type Events = Vec<Vec<Vec<u8>>>;
struct Logs(Arc<Mutex<Events>>);
impl SyscallStubs for Logs {
    fn sol_log_data(&self, fields: &[&[u8]]) {
        self.0.lock().unwrap().push(fields.iter().map(|x| x.to_vec()).collect());
    }
}
struct Guard(Option<Box<dyn SyscallStubs>>);
impl Drop for Guard {
    fn drop(&mut self) {
        set_syscall_stubs(self.0.take().unwrap());
    }
}
use solana_confidential_compute_verifier::{payload::*, processor::Processor, state::*};
#[test]
fn backend_policy_configuration_is_governed_bounded_and_source_specific() {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let _guard = Guard(Some(set_syscall_stubs(Box::new(Logs(logs.clone())))));
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let system = solana_sdk_ids::system_program::ID;
    let (registry, rb) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    for (source, count, signed, success) in [
        (1, 8, true, true),
        (2, 0, true, true),
        (3, 1, true, true),
        (4, 1, true, true),
        // Intel TDX. Source 5 became valid when the TDX verifier landed;
        // the upper bound moved rather than disappeared.
        (5, 1, true, true),
        (3, 9, true, false),
        (0, 1, true, false),
        (6, 1, true, false),
        (3, 1, false, false),
    ] {
        let (policy, _) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[source]], &pid);
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
        let mut pd = vec![0; BackendPolicy::SIZE];
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
        let call =
            [accounts[0].clone(), accounts[1].clone(), accounts[2].clone(), accounts[0].clone(), accounts[3].clone()];
        let mut ix = SET_BACKEND_POLICY_DISCRIMINATOR.to_vec();
        SetBackendPolicyArgs { source, measurement_count: count, measurements: [[7; 48]; 8] }
            .serialize(&mut ix)
            .unwrap();
        logs.lock().unwrap().clear();
        let before = solana_program::hash::hashv(&[&call[2].try_borrow_data().unwrap()]);
        assert_eq!(Processor::process(&pid, &call, &ix).is_ok(), success);
        let events = std::mem::take(&mut *logs.lock().unwrap());
        if success {
            let saved = BackendPolicy::try_from_slice(&call[2].try_borrow_data().unwrap()).unwrap();
            assert_eq!(saved.is_measurement_allowed(source, &[7; 48]), count > 0);
            assert!(!saved.is_measurement_allowed(if source == 3 { 1 } else { 3 }, &[7; 48]));
            // Governed writes emit the #227 governance event over old/new bytes.
            let after = solana_program::hash::hashv(&[&call[2].try_borrow_data().unwrap()]);
            assert_eq!(
                events,
                vec![vec![
                    b"solana-confidential-compute:governance:v1".to_vec(),
                    b"set_backend_policy".to_vec(),
                    authority.to_bytes().to_vec(),
                    policy.to_bytes().to_vec(),
                    before.to_bytes().to_vec(),
                    after.to_bytes().to_vec(),
                ]]
            );
            // Re-setting the identical policy is a no-op: no write and no event.
            assert!(Processor::process(&pid, &call, &ix).is_ok());
            assert!(logs.lock().unwrap().is_empty());
        } else {
            assert!(call[2].try_borrow_data().unwrap().iter().all(|b| *b == 0));
            assert!(events.is_empty());
        }
    }
}
