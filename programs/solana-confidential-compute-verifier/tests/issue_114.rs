// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Mode B consumer binding and pre-funded PDA allocation.
//!
//! MIGRATION (solana 2.2 -> 4.x): the Mode B tests ran the verifier natively via
//! `processor!(Processor::process)`. In 4.x `Rent::get()` resolves through
//! `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch is a hardcoded
//! `UNSUPPORTED_SYSVAR` that never consults `program_stubs` -- so a natively
//! linked program cannot read a sysvar at all. `create_pda_if_needed` needs
//! `Rent::get()` to allocate the nonce PDA, so Mode B now runs the real SBF
//! artifact under ProgramTest. The native `Processor` wrapper used to inject the
//! denylist, backend policy and legacy nonce accounts behind the test's back;
//! real bytecode cannot, so those are now explicit account metas.
//!
//! @spec SCC-VERIFY-010 SCC-VERIFY-011 SCC-VERIFY-013 SCC-SEC-005 SCC-ARCH-001

use borsh::BorshSerialize;
use p384::ecdsa::signature::hazmat::PrehashSigner;
use p384::ecdsa::SigningKey;
use sha2::{Digest, Sha384};
use solana_confidential_compute_core::types::{compute_action_commitment, VerifyAtomicHeader};
use solana_confidential_compute_core::SNP_REPORT_SIZE;
use solana_confidential_compute_verifier::error::VerifierError;
use solana_confidential_compute_verifier::payload::{
    InitPolicyRegistryArgs, INIT_POLICY_REGISTRY_DISCRIMINATOR, VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
};
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::hash::hashv;
use solana_program::pubkey::Pubkey;
use solana_program_test::{processor, BanksClientError};
use solana_sdk::account::Account;
use solana_sdk::instruction::{AccountMeta, Instruction, InstructionError};
use solana_sdk::rent::Rent;
use solana_sdk::signature::Signer;
use solana_sdk::sysvar::{self, clock, slot_hashes};
use solana_sdk::transaction::{Transaction, TransactionError};
#[allow(deprecated)]
use solana_system_interface::instruction as system_instruction;
#[path = "common/sbf.rs"]
mod sbf;

use solana_confidential_compute_verifier::state::{
    AmdIdentityRevocation, BackendPolicy, PolicyRegistry, VcekAccount, POLICY_REGISTRY_DISCRIMINATOR,
    USED_NONCE_DISCRIMINATOR, VCEK_ACCOUNT_DISCRIMINATOR,
};

fn tx_error(err: BanksClientError) -> TransactionError {
    match err {
        BanksClientError::TransactionError(err) => err,
        other => panic!("unexpected banks error: {other:?}"),
    }
}

fn instruction_error(err: BanksClientError) -> InstructionError {
    match tx_error(err) {
        TransactionError::InstructionError(_, err) => err,
        other => panic!("unexpected transaction error: {other:?}"),
    }
}

fn noop(_program_id: &Pubkey, _accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    Ok(())
}

/// `processor::EXPECTED_SIGVERIFY_PROGRAM_ID`, which is `cfg(target_os = "solana")`
/// and so not nameable from a host test. ASCII `SECP384R1SIGVERIFY`, zero padded.
const SIGVERIFY_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x53, 0x45, 0x43, 0x50, 0x33, 0x38, 0x34, 0x52, 0x31, 0x53, 0x49, 0x47, 0x56, 0x45, 0x52, 0x49, 0x46, 0x59, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

/// `pubkey (96) || SHA-384(signed body) (48) || r_be || s_be (96)`.
///
/// The SBF build never runs P-384 in-program -- software P-384 exceeds the CU
/// ceiling -- so `SolanaDefaultVerifier` scans back through `sysvar::instructions`
/// for an instruction to the pinned sigverify program whose data byte-matches
/// this payload. The signature bytes are carried verbatim from the report, so a
/// tampered report body or signature no longer matches and is rejected.
fn sigverify_ix(report: &[u8; SNP_REPORT_SIZE], public_key_xy: &[u8; 96]) -> Instruction {
    let mut data = Vec::with_capacity(240);
    data.extend_from_slice(public_key_xy);
    data.extend_from_slice(&Sha384::digest(&report[..672]));
    for base in [0x2A0, 0x2E8] {
        let mut be = report[base..base + 48].to_vec();
        be.reverse();
        data.extend_from_slice(&be);
    }
    Instruction { program_id: SIGVERIFY_PROGRAM_ID, accounts: vec![], data }
}

fn init_ix(program_id: &Pubkey, payer: &Pubkey, registry: &Pubkey) -> Instruction {
    let mut data = Vec::new();
    data.extend_from_slice(&INIT_POLICY_REGISTRY_DISCRIMINATOR);
    InitPolicyRegistryArgs {
        authority: payer.to_bytes(),
        ark_pubkey_xy: [0u8; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 0,
        measurements: [[0u8; 48]; 8],
    }
    .serialize(&mut data)
    .unwrap();
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*registry, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(
                Pubkey::find_program_address(&[program_id.as_ref()], &solana_sdk_ids::bpf_loader_upgradeable::id()).0,
                false,
            ),
        ],
        data,
    }
}

// ProgramTest's native program has no loader metadata. Supply authentic-shaped
// ProgramData in the bank for initialization without changing allocation assertions.
fn set_upgrade_authority(ctx: &mut solana_program_test::ProgramTestContext, program_id: &Pubkey) {
    let loader = solana_sdk_ids::bpf_loader_upgradeable::id();
    let (key, _) = Pubkey::find_program_address(&[program_id.as_ref()], &loader);
    let mut data = vec![0; 45];
    data[..4].copy_from_slice(&3u32.to_le_bytes());
    data[12] = 1;
    data[13..45].copy_from_slice(ctx.payer.pubkey().as_ref());
    ctx.set_account(
        &key,
        &Account { lamports: 1_000_000, data, owner: loader, executable: false, rent_epoch: 0 }.into(),
    );
}

async fn send(ctx: &mut solana_program_test::ProgramTestContext, ix: Instruction) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer], blockhash);
    ctx.banks_client.process_transaction(tx).await
}

#[tokio::test]
async fn unfunded_policy_registry_initializes() {
    let program_id = Pubkey::new_unique();
    let pt = sbf::verifier_program_test(program_id);
    let (registry, _) = Pubkey::find_program_address(&[b"policy_registry"], &program_id);
    let mut ctx = pt.start_with_context().await;
    set_upgrade_authority(&mut ctx, &program_id);
    let payer = ctx.payer.pubkey();
    send(&mut ctx, init_ix(&program_id, &payer, &registry)).await.expect("unfunded create_account");
    let account = ctx.banks_client.get_account(registry).await.unwrap().expect("registry");
    assert_eq!(account.owner, program_id);
    assert_eq!(account.data.len(), PolicyRegistry::SIZE);
    assert_eq!(&account.data[..8], &POLICY_REGISTRY_DISCRIMINATOR);
}

#[tokio::test]
async fn prefunded_policy_registry_initializes() {
    let program_id = Pubkey::new_unique();
    let mut pt = sbf::verifier_program_test(program_id);
    let (registry, _) = Pubkey::find_program_address(&[b"policy_registry"], &program_id);
    pt.add_account(
        registry,
        Account {
            lamports: 1,
            data: vec![],
            owner: solana_sdk_ids::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let mut ctx = pt.start_with_context().await;
    set_upgrade_authority(&mut ctx, &program_id);
    let payer = ctx.payer.pubkey();
    send(&mut ctx, init_ix(&program_id, &payer, &registry)).await.expect("prefunded allocate+assign");
    let account = ctx.banks_client.get_account(registry).await.unwrap().expect("registry");
    assert_eq!(account.owner, program_id);
    assert_eq!(account.data.len(), PolicyRegistry::SIZE);
    assert_eq!(&account.data[..8], &POLICY_REGISTRY_DISCRIMINATOR);
    assert!(account.lamports > 1);
}

fn sign_report(workload: [u8; 32], nonce: [u8; 32], measurement: [u8; 48]) -> ([u8; SNP_REPORT_SIZE], [u8; 96]) {
    let mut seed = [0u8; 48];
    seed[47] = 0x21;
    let signing_key = SigningKey::from_slice(&seed).expect("scalar");
    let encoded = signing_key.verifying_key().to_sec1_point(false);
    let mut xy = [0u8; 96];
    xy[..48].copy_from_slice(encoded.x().unwrap());
    xy[48..].copy_from_slice(encoded.y().unwrap());

    let mut report = [0u8; SNP_REPORT_SIZE];
    report[0..4].copy_from_slice(&1u32.to_le_bytes());
    report[8..16].copy_from_slice(&(1u64 << 17).to_le_bytes());
    report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    report[0x50..0x70].copy_from_slice(&workload);
    report[0x70..0x90].copy_from_slice(&nonce);
    report[0x90..0xC0].copy_from_slice(&measurement);

    let mut hasher = Sha384::new();
    hasher.update(&report[0..672]);
    let digest: [u8; 48] = hasher.finalize().into();
    let (signature, _) = signing_key.sign_prehash(&digest).expect("sign");
    let sig_bytes = signature.to_bytes();
    for i in 0..48 {
        report[0x2A0 + i] = sig_bytes[47 - i];
        report[0x2E8 + i] = sig_bytes[95 - i];
    }
    (report, xy)
}

struct ModeBBoot {
    ctx: solana_program_test::ProgramTestContext,
    program_id: Pubkey,
    consumer: Pubkey,
    other: Pubkey,
    registry_pda: Pubkey,
    vcek_pda: Pubkey,
    policy_pda: Pubkey,
    denylist_pda: Pubkey,
    vcek_xy: [u8; 96],
    workload: [u8; 32],
    nonce_slot: u64,
    commitment: [u8; 32],
    report: [u8; SNP_REPORT_SIZE],
}

impl ModeBBoot {
    /// `[payer, registry, vcek, used_nonce, slot_hashes, clock, system, instructions]`
    /// plus the three accounts the program resolves by address: the AMD denylist,
    /// the source-1 backend policy, and the pre-namespace legacy nonce.
    fn verify_accounts(&self, nonce_pda: Pubkey, commitment: &[u8; 32]) -> Vec<AccountMeta> {
        let (legacy_nonce, _) = Pubkey::find_program_address(&[b"nonce", &self.workload, commitment], &self.program_id);
        vec![
            AccountMeta::new(self.ctx.payer.pubkey(), true),
            AccountMeta::new_readonly(self.registry_pda, false),
            AccountMeta::new_readonly(self.vcek_pda, false),
            AccountMeta::new(nonce_pda, false),
            AccountMeta::new_readonly(slot_hashes::ID, false),
            AccountMeta::new_readonly(clock::ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
            AccountMeta::new_readonly(self.denylist_pda, false),
            AccountMeta::new_readonly(self.policy_pda, false),
            AccountMeta::new_readonly(legacy_nonce, false),
        ]
    }
}

fn canonical_consumer_hash() -> [u8; 32] {
    solana_confidential_compute_core::action::hash_action_parts(&[], 0, core::iter::empty(), &[1])
}

async fn boot_mode_b() -> ModeBBoot {
    let program_id = Pubkey::new_unique();
    let consumer = Pubkey::new_unique();
    let other = Pubkey::new_unique();
    let mut pt = sbf::verifier_program_test(program_id);
    pt.add_program("consumer_a", consumer, processor!(noop));
    pt.add_program("consumer_b", other, processor!(noop));
    // Stands in for the unassigned secp384r1 precompile the SBF build introspects.
    pt.add_program("sigverify", SIGVERIFY_PROGRAM_ID, processor!(noop));

    let measurement = [0x42u8; 48];
    let workload = [0x99u8; 32];
    let mut seed = [0u8; 48];
    seed[47] = 0x21;
    let signing_key = SigningKey::from_slice(&seed).expect("scalar");
    let encoded = signing_key.verifying_key().to_sec1_point(false);
    let mut vcek_xy = [0u8; 96];
    vcek_xy[..48].copy_from_slice(encoded.x().unwrap());
    vcek_xy[48..].copy_from_slice(encoded.y().unwrap());
    let chip_id_hash = hashv(&[&vcek_xy]).to_bytes();
    let tcb_version = 0u64;
    let (vcek_pda, vcek_bump) =
        Pubkey::find_program_address(&[b"vcek_v2", &chip_id_hash, &tcb_version.to_le_bytes()], &program_id);
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &program_id);

    let mut measurements = [[0u8; 48]; 8];
    measurements[0] = measurement;
    let mut registry_data = vec![0u8; PolicyRegistry::SIZE];
    PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: [0u8; 32],
        ark_pubkey_xy: [0u8; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 1,
        measurements,
        bump: registry_bump,
    }
    .serialize(&mut &mut registry_data[..])
    .unwrap();
    let mut vcek_data = vec![0u8; VcekAccount::SIZE];
    VcekAccount {
        discriminator: VCEK_ACCOUNT_DISCRIMINATOR,
        chip_id_hash,
        tcb_version,
        public_key_xy: vcek_xy,
        registered_slot: 1,
        bump: vcek_bump,

        trust_profile: VcekAccount::MILAN_TRUST_PROFILE,
        valid_until_unix: u64::MAX,
        is_revoked: false,
    }
    .serialize(&mut &mut vcek_data[..])
    .unwrap();
    pt.add_account(
        registry_pda,
        Account { lamports: 10_000_000, data: registry_data, owner: program_id, executable: false, rent_epoch: 0 },
    );
    pt.add_account(
        vcek_pda,
        Account { lamports: 10_000_000, data: vcek_data, owner: program_id, executable: false, rent_epoch: 0 },
    );
    // AMD SNP admission reads the source-1 backend policy by address.
    let (policy_pda, policy_bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[1]], &program_id);
    pt.add_account(
        policy_pda,
        Account {
            lamports: 10_000_000,
            data: borsh::to_vec(&BackendPolicy {
                discriminator: BackendPolicy::DISCRIMINATOR,
                source: 1,
                measurement_count: 1,
                measurements,
                bump: policy_bump,
            })
            .unwrap(),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    // Left uncreated: an absent, system-owned denylist entry is "not revoked".
    let (denylist_pda, _) = Pubkey::find_program_address(&[AmdIdentityRevocation::SEED, &chip_id_hash], &program_id);

    let ctx = pt.start_with_context().await;
    let slot_hashes_sysvar: solana_sdk::slot_hashes::SlotHashes = ctx.banks_client.get_sysvar().await.unwrap();
    let (nonce_slot, slot_hash) =
        slot_hashes_sysvar.iter().next().map(|(slot, hash)| (*slot, hash.to_bytes())).expect("slot hash");
    let action_hash = canonical_consumer_hash();
    let commitment = compute_action_commitment(&slot_hash, &action_hash, &consumer.to_bytes());
    let (report, _) = sign_report(workload, commitment, measurement);
    ModeBBoot {
        ctx,
        program_id,
        consumer,
        other,
        registry_pda,
        vcek_pda,
        policy_pda,
        denylist_pda,
        vcek_xy,
        workload,
        nonce_slot,
        commitment,
        report,
    }
}

/// A bump accepted by `create_program_address` that is not the canonical bump.
fn alternate_off_curve_nonce(
    workload: &[u8; 32],
    commitment: &[u8; 32],
    program_id: &Pubkey,
    canonical: u8,
) -> (u8, Pubkey) {
    for bump in (0..=255u8).rev() {
        if bump == canonical {
            continue;
        }
        let bump_seed = [bump];
        if let Ok(pda) = Pubkey::create_program_address(&[b"nonce", &[1], workload, commitment, &bump_seed], program_id)
        {
            return (bump, pda);
        }
    }
    panic!("no alternate off-curve nonce bump");
}

#[tokio::test]
async fn mode_b_binds_next_consumer_and_accepts_prefunded_nonce() {
    let boot = boot_mode_b().await;
    let ModeBBoot { ref ctx, program_id, consumer, other, workload, nonce_slot, commitment, ref report, .. } = boot;
    let action_hash = canonical_consumer_hash();
    let (nonce_pda, nonce_bump) = Pubkey::find_program_address(&[b"nonce", &[1], &workload, &commitment], &program_id);

    let mut ix_data = Vec::from(VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
    VerifyAtomicHeader { nonce_slot, action_hash, consumer_program_id: consumer.to_bytes() }
        .serialize(&mut ix_data)
        .unwrap();
    ix_data.extend_from_slice(report);
    ix_data.push(nonce_bump);

    let verify_ix = Instruction { program_id, accounts: boot.verify_accounts(nonce_pda, &commitment), data: ix_data };
    let consumer_ix = Instruction { program_id: consumer, accounts: vec![], data: vec![1] };
    let other_ix = Instruction { program_id: other, accounts: vec![], data: vec![1] };
    let sigverify = sigverify_ix(report, &boot.vcek_xy);

    let rent: Rent = ctx.banks_client.get_sysvar().await.unwrap();
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let fund = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&ctx.payer.pubkey(), &nonce_pda, rent.minimum_balance(0))],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        blockhash,
    );
    ctx.banks_client.process_transaction(fund).await.expect("prefund");

    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let grief = Transaction::new_signed_with_payer(
        &[sigverify.clone(), verify_ix.clone()],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        blockhash,
    );
    let grief_err = ctx.banks_client.process_transaction(grief).await.unwrap_err();
    assert_eq!(instruction_error(grief_err), InstructionError::InvalidArgument);

    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let mismatch = Transaction::new_signed_with_payer(
        &[sigverify.clone(), verify_ix.clone(), other_ix],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        blockhash,
    );
    let mismatch_err = ctx.banks_client.process_transaction(mismatch).await.unwrap_err();
    assert_eq!(instruction_error(mismatch_err), InstructionError::Custom(12));

    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let ok = Transaction::new_signed_with_payer(
        &[sigverify.clone(), verify_ix.clone(), consumer_ix],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        blockhash,
    );
    ctx.banks_client.process_transaction(ok).await.expect("mode b with prefunded nonce");
    let nonce = ctx.banks_client.get_account(nonce_pda).await.unwrap().expect("nonce");
    assert_eq!(nonce.owner, program_id);
    assert_eq!(&nonce.data[..8], &USED_NONCE_DISCRIMINATOR);
    assert!(nonce.lamports > 1);

    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let replay = Transaction::new_signed_with_payer(
        &[sigverify, verify_ix, consumer_ix_again(&consumer)],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        blockhash,
    );
    let replay_err = ctx.banks_client.process_transaction(replay).await.unwrap_err();
    assert_eq!(instruction_error(replay_err), InstructionError::Custom(5));
}

fn consumer_ix_again(consumer: &Pubkey) -> Instruction {
    Instruction { program_id: *consumer, accounts: vec![], data: vec![1] }
}

/// Alternate off-curve bumps derive a second UsedNonceAccount for the same report.
/// That address must be rejected so the attestation cannot be replayed.
/// @spec SCC-SEC-005 SCC-VERIFY-006 SCC-VERIFY-011
#[tokio::test]
async fn verify_atomic_with_nonce_rejects_alternate_off_curve_bump() {
    let boot = boot_mode_b().await;
    let (canonical_pda, canonical_bump) =
        Pubkey::find_program_address(&[b"nonce", &[1], &boot.workload, &boot.commitment], &boot.program_id);
    let (alt_bump, alt_pda) =
        alternate_off_curve_nonce(&boot.workload, &boot.commitment, &boot.program_id, canonical_bump);
    assert_ne!(alt_bump, canonical_bump);
    assert_ne!(alt_pda, canonical_pda);

    let mut ix_data = Vec::from(VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
    VerifyAtomicHeader {
        nonce_slot: boot.nonce_slot,
        action_hash: canonical_consumer_hash(),
        consumer_program_id: boot.consumer.to_bytes(),
    }
    .serialize(&mut ix_data)
    .unwrap();
    ix_data.extend_from_slice(&boot.report);
    ix_data.push(alt_bump);

    let verify_ix = Instruction {
        program_id: boot.program_id,
        accounts: boot.verify_accounts(alt_pda, &boot.commitment),
        data: ix_data,
    };
    let consumer_ix = Instruction { program_id: boot.consumer, accounts: vec![], data: vec![1] };
    let blockhash = boot.ctx.banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[sigverify_ix(&boot.report, &boot.vcek_xy), verify_ix, consumer_ix],
        Some(&boot.ctx.payer.pubkey()),
        &[&boot.ctx.payer],
        blockhash,
    );
    let err = boot.ctx.banks_client.process_transaction(tx).await.expect_err("alternate bump must be rejected");
    assert_eq!(instruction_error(err), InstructionError::Custom(VerifierError::InvalidAccountAddress as u32),);
}

/// Controlled signed SNP report + native production processor. The preloaded
/// VCEK models trust establishment; this is not vendor/hardware admission proof.
#[tokio::test]
async fn issue_300_copied_verifier_cannot_burn_nonce_with_other_consumer_action() {
    let boot = boot_mode_b().await;
    // Independent encoder for action hash
    let action_hash =
        hashv(&[b"solana-confidential-compute:action:v1\0", &0u32.to_le_bytes(), &1u32.to_le_bytes(), &[1]]).to_bytes();
    let hashes: solana_sdk::slot_hashes::SlotHashes = boot.ctx.banks_client.get_sysvar().await.unwrap();
    let slot_hash = hashes.get(&boot.nonce_slot).unwrap().to_bytes();
    let commitment = compute_action_commitment(&slot_hash, &action_hash, &boot.consumer.to_bytes());
    let (report, _) = sign_report(boot.workload, commitment, [0x42; 48]);
    let (nonce, bump) = Pubkey::find_program_address(&[b"nonce", &[1], &boot.workload, &commitment], &boot.program_id);
    let mut data = VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec();
    VerifyAtomicHeader { nonce_slot: boot.nonce_slot, action_hash, consumer_program_id: boot.consumer.to_bytes() }
        .serialize(&mut data)
        .unwrap();
    data.extend_from_slice(&report);
    data.push(bump);
    let verify = Instruction { program_id: boot.program_id, accounts: boot.verify_accounts(nonce, &commitment), data };
    for changed_data in [vec![2], vec![], vec![1, 0]] {
        let tx = Transaction::new_signed_with_payer(
            &[
                sigverify_ix(&report, &boot.vcek_xy),
                verify.clone(),
                Instruction { program_id: boot.consumer, accounts: vec![], data: changed_data },
            ],
            Some(&boot.ctx.payer.pubkey()),
            &[&boot.ctx.payer],
            boot.ctx.last_blockhash,
        );
        let result = boot.ctx.banks_client.process_transaction(tx).await;
        assert!(result.is_err(), "copied verifier burned nonce with substitute action");
        assert_eq!(
            instruction_error(result.unwrap_err()),
            InstructionError::Custom(VerifierError::ActionHashMismatch as u32)
        );
        assert!(boot.ctx.banks_client.get_account(nonce).await.unwrap().is_none());
    }
    let tx = Transaction::new_signed_with_payer(
        &[
            sigverify_ix(&report, &boot.vcek_xy),
            verify,
            Instruction { program_id: boot.consumer, accounts: vec![], data: vec![1] },
        ],
        Some(&boot.ctx.payer.pubkey()),
        &[&boot.ctx.payer],
        boot.ctx.last_blockhash,
    );
    boot.ctx.banks_client.process_transaction(tx).await.unwrap();
    assert!(boot.ctx.banks_client.get_account(nonce).await.unwrap().is_some());
}
