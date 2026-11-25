// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Native production-processor regression for authoritative backend admission.
//! Uses a signed JWT fixture; no automatic global-to-backend policy fixture.
use borsh::BorshDeserialize;
use solana_confidential_compute_verifier::{error::VerifierError, payload::*, processor::Processor, state::*};
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    program_stubs::{set_syscall_stubs, SyscallStubs},
    pubkey::Pubkey,
    sysvar,
};
const MODULUS_HEX: &str = "a583d1867001a794bcb2bdd2780451830f702f68c06866249499804f9ba437ad469ac221eea5fb6c3381bcaba74ea30230185b5582bb3c45278477df8dfe4818e673a7a3d763ca71c58c99d827e6b673eda72fc8ad4de529674726d187b1b7a50c6b87a5b7b042d07c07b66714bf4ee6527df0def652654b2d92c26e40dca7a237d20a17bd864093901184a303e1f002ced9e8dd5d41daced40d2372438bb692d53b94ce408f8381b790a43df7bd491bf852fcc5967d45372672ec37fdd1668edd0cf0fdcf0cc70f154d0a96a663a0fcd3f98691ebac12f5f9e1b9c12305cb895ab8663da3d48fbd7e0e0d5ab39e5651b32ee2afe953514462816ba4bda9221b";
const VALID_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXRvbi12ZXJpZmllciIsImRiZ3N0YXQiOiJkaXNhYmxlZC1zaW5jZS1ib290IiwiZWF0X25vbmNlIjpbImJtNXVibTV1Ym01dWJtNXVibTV1Ym01dWJtNXVibTV1Ym01dWJtNXVibTQiLCJibTV1Ym01dWJtNXVibTV1Ym01dWJtNXVibTV1Ym01dWJtNXVibTV1Ym00Il0sImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2NvbmZpZGVudGlhbGNvbXB1dGluZy5nb29nbGVhcGlzLmNvbSIsInNlY2Jvb3QiOnRydWUsInN1YiI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2NvbXB1dGUvdjEvcHJvamVjdHMvdGV0b24vem9uZXMvdXMvaW5zdGFuY2VzL3ZtIiwic3VibW9kcyI6eyJjb250YWluZXIiOnsiaW1hZ2VfZGlnZXN0Ijoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifX19.lcgG76LbpMlUyft0pAQS9mv1EXuOOZmxkFlu0BHnQuwZc3CgIDYqoXW_9jf_IRkNWwXz4kdIS3g_bqkaT69B2lPgSHOY6K96ce6f792ze7T3LUMIQOQVScdh1GwHwrOHvF8im1nfMIi_XCPG5xhsbU8SgswDGnszqLZPO0M31hH4YaZq491hU7ciBnWfuXl9Gd8Wd0zGZQM98ubHssnqMEClhmV0-2LQDz48OiyvPYKUCifpsqf-r1ILLLC3efg7eWmNvXcDRYKP1rTuOylNGdKYwMy25kAwZOEf8n54MO29OhFMOk4EvkmdJ8kGrBiMogGH-WkRUgtNJHXdyxC8DQ";
const MODE_B_MODULUS_HEX: &str = "873249253d49eee96b81c9d585cce94648004a1d4b2d185842f1ebed675b76edc0e8b92d23e8edb4db31f9f09f06435ddf0bee84f4336b92791e5ae1b16d24d4a54902c369cd2e7ace2a158455c075d67837a7ef2002307159d371db7d3f8f8b59104438614c20a53c1dc451651401f81b26b132002374b7a659bf7f62ae5fd4a2fa191f8c9843991ca7b5599542c3d318ec495874e0ad8a64707c9c30f89f4bc02f661dcf3b8655fee0adc660273aa856ec547061ef52f23c6685265c9c29128fc08ad66242d29807f7d500811d15e8e33c4bace57dec95dfe19acce1e764f4e71a2d96a853cdfeb60c631cd6f54e47f53f48dbcfc67679818aac99ba7ae3a3";
const MODE_B_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXRvbi12ZXJpZmllciIsImRiZ3N0YXQiOiJkaXNhYmxlZC1zaW5jZS1ib290IiwiZWF0X25vbmNlIjoic05TZXAxbjlPQU5qREF5MTZUdGtXdDctLUxFMmpHMjM1Z1hKejZXSng0ayIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2NvbmZpZGVudGlhbGNvbXB1dGluZy5nb29nbGVhcGlzLmNvbSIsInNlY2Jvb3QiOnRydWUsInN1YiI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2NvbXB1dGUvdjEvcHJvamVjdHMvdGV0b24vem9uZXMvdXMvaW5zdGFuY2VzL3ZtIiwic3VibW9kcyI6eyJjb250YWluZXIiOnsiaW1hZ2VfZGlnZXN0Ijoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifX19.LFeExAEgTQoFYbgUJXFeiEhoBoxBhTi4BIR3kt7c0ybWkFZOz3l6DikD7mxxocbZswyTCJNKMdsxRZXtvTnm8NeKC73nLqaYYIXT79xSAB1Z8phsPCxU4oreoQz69mKBoaMxNCXuGWzthfvChXu8TB6cGQ8n-kRujisEw7KcRsp3VwcHPzmd33dov06-fqBR-XWAmVzWU_U8pps6SOuetVYjYPtUTq6siu_nv6Za9TOJEjYUGR0VkYjkGn6ohxQg18h-qDWYrpPT9WFeKU6wq2gOxNbZHjRVnezbErNw4CXO-ZLyyBXKS5FXDeWyn1hD5zgIkJoOD3ax_I7o1uZkUQ";
struct ClockStub;
impl SyscallStubs for ClockStub {
    fn sol_get_clock_sysvar(&self, dst: *mut u8) -> u64 {
        let clock = Clock { slot: 520, unix_timestamp: 1_700_000_100, ..Clock::default() };
        unsafe {
            std::ptr::copy_nonoverlapping((&clock as *const Clock).cast::<u8>(), dst, std::mem::size_of::<Clock>());
        }
        0
    }
}
struct Guard(Option<Box<dyn SyscallStubs>>);
impl Drop for Guard {
    fn drop(&mut self) {
        set_syscall_stubs(self.0.take().unwrap());
    }
}
fn account(key: Pubkey, owner: Pubkey, data: Vec<u8>, signer: bool, writable: bool) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        signer,
        writable,
        Box::leak(Box::new(1_000_000)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
    )
}
fn ix<T: borsh::BorshSerialize>(disc: [u8; 8], args: &T) -> Vec<u8> {
    [disc.to_vec(), borsh::to_vec(args).unwrap()].concat()
}
#[test]
fn issue_296_authorized_backend_halt_blocks_runtime_and_resume_restores_admission() {
    let _guard = Guard(Some(set_syscall_stubs(Box::new(ClockStub))));
    for mode in [VERIFY_GOOGLE_JWT_MODE_A, VERIFY_GOOGLE_JWT_MODE_B] {
        halt_resume_case(mode);
    }
}
fn halt_resume_case(mode: u8) {
    let mode_a = mode == VERIFY_GOOGLE_JWT_MODE_A;
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let workload = Pubkey::new_from_array([b'n'; 32]);
    let (registry, rb) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (backend, bb) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[3]], &pid);
    let (tenant, tb) = Pubkey::find_program_address(&[GcpTenantPolicy::SEED], &pid);
    let kh = solana_confidential_compute_crypto::jwt::kid_hash(b"teton-test");
    let (jwks, jb) = Pubkey::find_program_address(&[b"jwks", &kh], &pid);
    let (signer, _) = Pubkey::find_program_address(&[b"attested_signer_v2", workload.as_ref()], &pid);
    // Match the signed V3 JWT fixture to the complete consumer instruction.
    let consumer_data = [0x99; 11];
    let action =
        solana_confidential_compute_core::action::hash_action_parts(&[], 0, core::iter::empty(), &consumer_data);
    let consumer = Pubkey::new_from_array([0x33; 32]);
    let slot_hash = if mode_a { [b'n'; 32] } else { [0x11; 32] };
    let commitment =
        solana_confidential_compute_core::types::compute_action_commitment(&slot_hash, &action, &consumer.to_bytes());
    let nonce_seed = solana_confidential_compute_crypto::jwt::eat_nonce_tombstone_seed(if mode_a {
        &[b'n'; 64]
    } else {
        &commitment
    });
    let (nonce, _) = Pubkey::find_program_address(&[b"nonce", &[3], &nonce_seed], &pid);
    let mut measurement = [0; 48];
    measurement[..32].fill(0xab);
    let global = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: authority.to_bytes(),
        ark_pubkey_xy: [0; 96],
        min_tcb_boot_loader: 1,
        min_tcb_tee: 2,
        min_tcb_snp: 3,
        min_tcb_microcode: 4,
        measurement_count: 1,
        measurements: [measurement; 8],
        bump: rb,
    };
    let global_acc = account(registry, pid, borsh::to_vec(&global).unwrap(), false, true);
    let auth = account(authority, pid, vec![], true, true);
    let system = account(solana_sdk_ids::system_program::ID, solana_sdk_ids::system_program::ID, vec![], false, false);
    let backend_acc = account(backend, pid, vec![0; BackendPolicy::SIZE], false, true);
    let governance = [auth.clone(), global_acc.clone(), backend_acc.clone(), auth.clone(), system.clone()];
    let set_backend = |count| {
        ix(
            SET_BACKEND_POLICY_DISCRIMINATOR,
            &SetBackendPolicyArgs { source: 3, measurement_count: count, measurements: [measurement; 8] },
        )
    };
    assert_eq!(Processor::process(&pid, &governance, &set_backend(1)), Ok(()));
    let saved = BackendPolicy::try_from_slice(&backend_acc.try_borrow_data().unwrap()).unwrap();
    assert_eq!(saved.bump, bb);
    let clear_global = ix(
        UPDATE_POLICY_DISCRIMINATOR,
        &UpdatePolicyArgs {
            min_tcb_boot_loader: 1,
            min_tcb_tee: 2,
            min_tcb_snp: 3,
            min_tcb_microcode: 4,
            measurement_count: 0,
            measurements: [[0; 48]; 8],
        },
    );
    assert_eq!(Processor::process(&pid, &governance[..2], &clear_global), Ok(()));
    assert_eq!(global_acc.data_len(), 529); // Account ABI is unchanged.
    let cleared = PolicyRegistry::try_from_slice(&global_acc.try_borrow_data().unwrap()).unwrap();
    assert_eq!(cleared.measurement_count, 0);
    assert_eq!(
        [cleared.min_tcb_boot_loader, cleared.min_tcb_tee, cleared.min_tcb_snp, cleared.min_tcb_microcode],
        [1, 2, 3, 4]
    );
    assert_eq!(BackendPolicy::try_from_slice(&backend_acc.try_borrow_data().unwrap()).unwrap(), saved);
    let modulus_hex = if mode_a { MODULUS_HEX } else { MODE_B_MODULUS_HEX };
    let modulus: [u8; 256] = std::array::from_fn(|i| u8::from_str_radix(&modulus_hex[i * 2..i * 2 + 2], 16).unwrap());
    let (n0, r2) = solana_confidential_compute_crypto::jwt::compute_n0_and_r2(&modulus).unwrap();
    let jwks_acc = account(
        jwks,
        pid,
        borsh::to_vec(&JwksAccount::new(kh, modulus, 65537, n0, r2, 520, jb)).unwrap(),
        false,
        false,
    );
    let tenant_acc = account(
        tenant,
        pid,
        borsh::to_vec(
            &GcpTenantPolicy::new(
                b"teton-verifier",
                b"https://www.googleapis.com/compute/v1/projects/teton/zones/us/instances/vm",
                tb,
            )
            .unwrap(),
        )
        .unwrap(),
        false,
        false,
    );
    let clock_acc = account(
        sysvar::clock::ID,
        sysvar::ID,
        [
            520u64.to_le_bytes(),
            0u64.to_le_bytes(),
            0u64.to_le_bytes(),
            0u64.to_le_bytes(),
            1_700_000_100i64.to_le_bytes(),
        ]
        .concat(),
        false,
        false,
    );
    // SlotHashes bincode sequence: one slot/hash entry.
    let hashes = [1u64.to_le_bytes().as_slice(), 500u64.to_le_bytes().as_slice(), slot_hash.as_slice()].concat();
    let sh_acc = account(sysvar::slot_hashes::ID, sysvar::ID, hashes, false, false);
    // Explicit empty legacy tombstone proves this nonce was not consumed before
    // backend-scoped nonce namespaces; no fixture injects admission policy.
    let legacy_nonce = Pubkey::find_program_address(&[b"nonce", &nonce_seed], &pid).0;
    let legacy_acc = account(legacy_nonce, solana_sdk_ids::system_program::ID, vec![], false, false);
    let verify = ix(
        VERIFY_GOOGLE_JWT_DISCRIMINATOR,
        &VerifyGoogleJwtArgs {
            mode,
            nonce_slot: 500,
            expected_action_hash: action,
            jwt: if mode_a { VALID_JWT } else { MODE_B_JWT }.into(),
        },
    );
    let signer_acc = account(signer, pid, vec![0; AttestedSignerAccount::SIZE], false, true);
    let nonce_acc = account(nonce, pid, vec![0; UsedNonceAccount::SIZE], false, true);
    let mut accounts = vec![
        signer_acc.clone(),
        global_acc.clone(),
        jwks_acc.clone(),
        nonce_acc.clone(),
        auth.clone(),
        system.clone(),
        clock_acc.clone(),
        sh_acc.clone(),
        account(workload, pid, vec![], true, false),
        backend_acc.clone(),
        tenant_acc.clone(),
        legacy_acc.clone(),
    ];
    if !mode_a {
        let consumer_ix = solana_program::sysvar::instructions::BorrowedInstruction {
            program_id: &consumer,
            accounts: vec![],
            data: &consumer_data,
        };
        let verifier_ix = solana_program::sysvar::instructions::BorrowedInstruction {
            program_id: &pid,
            accounts: vec![],
            data: &verify,
        };
        let data =
            solana_program::sysvar::instructions::construct_instructions_data(&[verifier_ix, consumer_ix]).unwrap();
        accounts.push(account(sysvar::instructions::ID, sysvar::ID, data, false, false));
    }
    // The same untouched signer/nonce accounts are used for halt and resume.
    for allow in [false, true] {
        let policy_before = backend_acc.try_borrow_data().unwrap().to_vec();
        let mut unsigned = governance.clone();
        unsigned[0].is_signer = false;
        unsigned[3].is_signer = false;
        assert_eq!(
            Processor::process(&pid, &unsigned, &set_backend(u32::from(allow))),
            Err(solana_program::program_error::ProgramError::MissingRequiredSignature)
        );
        assert_eq!(*backend_acc.try_borrow_data().unwrap(), policy_before);
        assert_eq!(Processor::process(&pid, &governance, &set_backend(u32::from(allow))), Ok(()));
        let result = Processor::process(&pid, &accounts, &verify);
        if allow {
            assert_eq!(
                result,
                Ok(()),
                "restoring the backend policy must resume admission even with an empty global list"
            );
            if mode_a {
                let saved = AttestedSignerAccount::try_from_slice(&signer_acc.try_borrow_data().unwrap()).unwrap();
                assert_eq!(saved.record.signer_pubkey, workload.to_bytes());
                assert_eq!(saved.record.measurement.0, measurement);
            } else {
                assert!(signer_acc.try_borrow_data().unwrap().iter().all(|b| *b == 0));
            }
            let consumed = UsedNonceAccount::try_from_slice(&nonce_acc.try_borrow_data().unwrap()).unwrap();
            assert_eq!(consumed.discriminator, USED_NONCE_DISCRIMINATOR);
            assert_eq!(consumed.slot, 520);
        } else {
            assert_eq!(result, Err(VerifierError::DisallowedMeasurement.into()));
            assert!(signer_acc.try_borrow_data().unwrap().iter().all(|b| *b == 0));
            assert!(nonce_acc.try_borrow_data().unwrap().iter().all(|b| *b == 0));
        }
    }
}
