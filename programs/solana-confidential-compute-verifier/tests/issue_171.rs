use borsh::BorshDeserialize;
use solana_confidential_compute_core::types::{AttestedSigner, EnclaveType, MeasurementDigest};
use solana_confidential_compute_verifier::{processor::Processor, state::*};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
#[test]
fn governance_can_expire_a_live_signer_and_unauthorized_calls_preserve_it() {
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let signer = [7u8; 32];
    let (registry, rb) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (pda, bump) = Pubkey::find_program_address(&[b"attested_signer_v2", &signer], &pid);
    let policy = PolicyRegistry {
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
    };
    let original = AttestedSignerAccount::new(
        AttestedSigner {
            signer_pubkey: signer,
            enclave_type: EnclaveType::GcpConfidentialSpace,
            measurement: MeasurementDigest([3; 48]),
            chip_id_hash: [0; 32],
            tcb_version: 0,
            registered_slot: 20,
            expires_slot: 216020,
        },
        bump,
    );
    assert!(!original.record.is_expired(21));
    for authorized in [false, true] {
        let mut a = 1;
        let mut b = 1;
        let mut c = 1;
        let mut ad = [];
        let mut rd = borsh::to_vec(&policy).unwrap();
        let mut sd = borsh::to_vec(&original).unwrap();
        let accounts = [
            AccountInfo::new(&authority, authorized, false, &mut a, &mut ad, &pid, false),
            AccountInfo::new(&registry, false, false, &mut b, &mut rd, &pid, false),
            AccountInfo::new(&pda, false, true, &mut c, &mut sd, &pid, false),
        ];
        let mut ix = vec![174, 9, 66, 138, 2, 191, 81, 61];
        ix.extend_from_slice(&signer);
        let result = Processor::process(&pid, &accounts, &ix);
        if authorized {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(ProgramError::MissingRequiredSignature));
        }
        let saved =
            AttestedSignerAccount::try_from_slice(&accounts[2].try_borrow_data().unwrap()).unwrap();
        assert_eq!(saved.record.is_expired(21), authorized);
        if !authorized {
            assert_eq!(saved, original);
        } else {
            assert_eq!(saved.record.signer_pubkey, signer);
            assert_eq!(saved.record.expires_slot, 0);
        }
    }
}
