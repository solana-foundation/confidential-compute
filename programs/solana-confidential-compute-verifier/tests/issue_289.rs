//! Controlled native-runtime governance lifecycle; no vendor/hardware admission claim.
use borsh::BorshDeserialize;
use solana_confidential_compute_verifier::{payload::*, processor::Processor, state::*};
use solana_program::pubkey::Pubkey;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    transaction::Transaction,
};

#[path = "common/sbf.rs"]
mod sbf;

#[tokio::test]
async fn identity_revoke_is_proactive_rent_funded_and_validates_all_metas() {
    let pid = Pubkey::new_unique();
    let authority = Keypair::new();
    let identity = [9; 32];
    let tcb = 7u64;
    let (registry, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (cache, _) = Pubkey::find_program_address(&[VcekAccount::SEED, &identity, &tcb.to_le_bytes()], &pid);
    let (deny, db) = Pubkey::find_program_address(&[AmdIdentityRevocation::SEED, &identity], &pid);
    let mut test = sbf::verifier_program_test(pid);
    let reg = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: authority.pubkey().to_bytes(),
        ark_pubkey_xy: [0; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 0,
        measurements: [[0; 48]; 8],
        bump,
    };
    test.add_account(
        registry,
        Account { lamports: 10_000_000, data: borsh::to_vec(&reg).unwrap(), owner: pid, ..Account::default() },
    );
    test.add_account(authority.pubkey(), Account { lamports: 10_000_000, ..Account::default() });
    // A prefunded system-owned PDA must still be allocated, assigned and topped up.
    test.add_account(deny, Account { lamports: 1, ..Account::default() });
    let ctx = test.start_with_context().await;
    let mut data = REVOKE_VCEK_DISCRIMINATOR.to_vec();
    data.extend(identity);
    data.extend(tcb.to_le_bytes());
    let ix = Instruction {
        program_id: pid,
        data,
        accounts: vec![
            AccountMeta::new_readonly(authority.pubkey(), true),
            AccountMeta::new_readonly(registry, false),
            AccountMeta::new(cache, false),
            AccountMeta::new(deny, false),
            AccountMeta::new(ctx.payer.pubkey(), true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        ],
    };
    for case in 0..5 {
        let mut bad = ix.clone();
        match case {
            0 => {
                bad.accounts[0].is_signer = false;
            }
            1 => {
                bad.accounts[3].is_writable = false;
            }
            2 => {
                bad.accounts[3].pubkey = Pubkey::new_unique();
            }
            3 => {
                bad.accounts[5].pubkey = Pubkey::new_unique();
            }
            _ => {
                bad.accounts.truncate(3);
            }
        }
        let signers: Vec<&dyn Signer> = if case == 0 { vec![&ctx.payer] } else { vec![&ctx.payer, &authority] };
        let tx = Transaction::new_signed_with_payer(&[bad], Some(&ctx.payer.pubkey()), &signers, ctx.last_blockhash);
        assert!(ctx.banks_client.process_transaction(tx).await.is_err(), "case {case}");
        let state = ctx.banks_client.get_account(deny).await.unwrap().unwrap();
        assert_eq!(state.owner, solana_sdk_ids::system_program::ID);
        assert!(state.data.is_empty());
        assert_eq!(state.lamports, 1);
    }
    let tx = Transaction::new_signed_with_payer(
        std::slice::from_ref(&ix),
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer, &authority],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    let state = ctx.banks_client.get_account(deny).await.unwrap().unwrap();
    assert_eq!(state.owner, pid);
    assert_eq!(state.data.len(), AmdIdentityRevocation::SIZE);
    assert!(state.lamports >= ctx.banks_client.get_rent().await.unwrap().minimum_balance(state.data.len()));
    assert_eq!(
        AmdIdentityRevocation::try_from_slice(&state.data).unwrap(),
        AmdIdentityRevocation { discriminator: AmdIdentityRevocation::DISCRIMINATOR, identity, bump: db }
    );
    assert!(ctx.banks_client.get_account(cache).await.unwrap().is_none());
    // Idempotent repeat targets a different, never registered TCB with the same identity.
    let mut second = ix;
    second.data[40..48].copy_from_slice(&99u64.to_le_bytes());
    second.accounts[2].pubkey =
        Pubkey::find_program_address(&[VcekAccount::SEED, &identity, &99u64.to_le_bytes()], &pid).0;
    let tx = Transaction::new_signed_with_payer(
        &[second],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer, &authority],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    assert_eq!(ctx.banks_client.get_account(deny).await.unwrap().unwrap().data, state.data);
}

#[test]
fn existing_cache_revoke_checks_identity_owner_payer_signature_and_writability() {
    use solana_program::{account_info::AccountInfo, program_error::ProgramError};
    let pid = Pubkey::new_unique();
    let auth = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    let foreign = Pubkey::new_unique();
    let system = solana_sdk_ids::system_program::ID;
    let identity = [8; 32];
    let tcb = 7u64;
    let (rk, rb) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (ck, cb) = Pubkey::find_program_address(&[VcekAccount::SEED, &identity, &tcb.to_le_bytes()], &pid);
    let (dk, db) = Pubkey::find_program_address(&[AmdIdentityRevocation::SEED, &identity], &pid);
    let mut ix = REVOKE_VCEK_DISCRIMINATOR.to_vec();
    ix.extend(identity);
    ix.extend(tcb.to_le_bytes());
    for case in 0..9 {
        let mut ad = [];
        let mut pd = [];
        let mut sysd = [];
        let mut rd = borsh::to_vec(&PolicyRegistry {
            discriminator: POLICY_REGISTRY_DISCRIMINATOR,
            authority: auth.to_bytes(),
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
        let mut cd = borsh::to_vec(&VcekAccount::new(identity, tcb, [2; 96], 0, cb).with_validity(100)).unwrap();
        let mut dd = borsh::to_vec(&AmdIdentityRevocation {
            discriminator: AmdIdentityRevocation::DISCRIMINATOR,
            identity,
            bump: db,
        })
        .unwrap();
        if case == 7 {
            dd[0] ^= 1;
        }
        let before_cache = cd.clone();
        let before_deny = dd.clone();
        let [a, b, c, d, p, s] = &mut [1u64; 6];
        let mut accounts = [
            AccountInfo::new(&auth, true, false, a, &mut ad, &system, false),
            AccountInfo::new(&rk, false, false, b, &mut rd, &pid, false),
            AccountInfo::new(&ck, false, true, c, &mut cd, &pid, false),
            AccountInfo::new(&dk, false, true, d, &mut dd, &pid, false),
            AccountInfo::new(&payer, true, true, p, &mut pd, &system, false),
            AccountInfo::new(&system, false, false, s, &mut sysd, &system, true),
        ];
        match case {
            0 => accounts[4].is_signer = false,
            1 => accounts[4].is_writable = false,
            2 => accounts[3].owner = &foreign,
            3 => accounts[2].owner = &foreign,
            4 => accounts[3].key = &foreign,
            5 => accounts[5].executable = false,
            6 => accounts[2].is_writable = false,
            _ => {}
        }
        let result = Processor::process(&pid, &accounts, &ix);
        if case == 8 {
            assert_eq!(result, Ok(()));
            assert!(VcekAccount::try_from_slice(&accounts[2].try_borrow_data().unwrap()).unwrap().is_revoked);
        } else {
            assert!(result.is_err(), "case {case}");
            if case == 0 {
                assert_eq!(result, Err(ProgramError::MissingRequiredSignature));
            }
            assert_eq!(*accounts[2].try_borrow_data().unwrap(), before_cache);
        }
        assert_eq!(*accounts[3].try_borrow_data().unwrap(), before_deny);
    }
}
