use borsh::{BorshDeserialize, BorshSerialize};
use solana_confidential_compute_verifier::{payload::*, processor::Processor, state::*};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
#[test]
fn cached_key_is_bound_to_profile_time_and_governed_revocation() {
    let pid = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    let system = solana_sdk_ids::system_program::ID;
    let hash = [6; 32];
    let tcb = 77u64;
    let (registry, rb) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (cache, bump) = Pubkey::find_program_address(&[VcekAccount::SEED, &hash, &tcb.to_le_bytes()], &pid);
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
    let original = VcekAccount::new(hash, tcb, [1; 96], 500, bump).with_validity(1000);
    let bytes = borsh::to_vec(&original).unwrap();
    let view = VcekAccountView::try_from_slice(&bytes).unwrap();
    assert!(view.is_trusted_at_unix(999));
    assert!(!view.is_trusted_at_unix(1000));
    assert!(!view.is_trusted_at_unix(-1));
    assert!(VcekAccountView::try_from_slice(&bytes[..153]).is_err());
    let (identity, identity_bump) = Pubkey::find_program_address(&[AmdIdentityRevocation::SEED, &hash], &pid);
    // Isolate the existing-cache governance transition with a valid pre-existing
    // identity tombstone. issue_289's native-runtime test covers first creation,
    // System CPI and rent; this native AccountInfo harness cannot allocate it.
    let tombstone = borsh::to_vec(&AmdIdentityRevocation {
        discriminator: AmdIdentityRevocation::DISCRIMINATOR,
        identity: hash,
        bump: identity_bump,
    })
    .unwrap();
    for (authority_signed, payer_signed) in [(false, true), (true, false), (true, true)] {
        let authorized = authority_signed && payer_signed;
        let mut a = 1;
        let mut b = 1;
        let mut c = 1;
        let mut identity_lamports = 1;
        let mut payer_lamports = 1;
        let mut system_lamports = 1;
        let mut identity_data = tombstone.clone();
        let mut payer_data = [];
        let mut system_data = [];
        let mut ad = [];
        let mut rd = borsh::to_vec(&policy).unwrap();
        let mut cd = bytes.clone();
        let accounts = [
            AccountInfo::new(&authority, authority_signed, false, &mut a, &mut ad, &pid, false),
            AccountInfo::new(&registry, false, false, &mut b, &mut rd, &pid, false),
            AccountInfo::new(&cache, false, true, &mut c, &mut cd, &pid, false),
            AccountInfo::new(&identity, false, true, &mut identity_lamports, &mut identity_data, &pid, false),
            AccountInfo::new(&payer, payer_signed, true, &mut payer_lamports, &mut payer_data, &system, false),
            AccountInfo::new(&system, false, false, &mut system_lamports, &mut system_data, &system, true),
        ];
        let mut ix = REVOKE_VCEK_DISCRIMINATOR.to_vec();
        RevokeVcekArgs { chip_id_hash: hash, tcb_version: tcb }.serialize(&mut ix).unwrap();
        let result = Processor::process(&pid, &accounts, &ix);
        if authorized {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(ProgramError::MissingRequiredSignature));
        }
        let data = accounts[2].try_borrow_data().unwrap();
        let saved = VcekAccount::try_from_slice(&data).unwrap();
        assert_eq!(saved.is_revoked, authorized);
        assert_eq!(saved.public_key_xy, original.public_key_xy);
        let mut expected = original.clone();
        expected.is_revoked = authorized;
        // Identity, TCB, key, pinned profile, certificate deadline, slot and bump
        // stay byte-for-byte bound to the original cache; only revocation changes.
        assert_eq!(saved, expected);
        if !authorized {
            assert_eq!(&data[..], bytes.as_slice());
        }
        assert_eq!(&accounts[3].try_borrow_data().unwrap()[..], tombstone.as_slice());
        assert_eq!(VcekAccountView::try_from_slice(&data).unwrap().is_trusted_at_unix(999), !authorized);
    }
}
