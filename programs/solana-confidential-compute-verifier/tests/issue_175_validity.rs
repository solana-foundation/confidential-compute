//! The real Milan chain is admitted only inside its certificate validity window.
//!
//! MIGRATION (solana 2.2 -> 4.x): this was a native unit test that drove
//! `Processor::process` over hand-built `AccountInfo`s and moved the clock with
//! `set_syscall_stubs`. In 4.x `Clock::get()` resolves through
//! `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch is a hardcoded
//! `UNSUPPORTED_SYSVAR` that never consults `program_stubs` -- so a natively
//! linked program can no longer read any sysvar and the stub is dead code.
//! `process_register_vcek` reads `Clock::get()` to time-bound the chain, so the
//! only way to exercise it is the real SBF artifact under `ProgramTest`, with
//! the clock moved by `ProgramTestContext::set_sysvar`.
//!
//! The file header used to read "the real chain exceeds packet size", which is
//! why it never ran on a bank. It still does (3208 bytes of instruction data),
//! so registration goes through the staged transport -- `REGISTER_VCEK` is one
//! of the three payloads `transport::allowed` accepts, and CONSUME dispatches
//! straight into the same handler. Both RSA-4096 PSS verifications are real;
//! on SBF `solana_confidential_compute_core::big_mod_exp` lowers to the `sol_big_mod_exp` syscall.
#![allow(deprecated)]
use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_confidential_compute_verifier::{error::VerifierError, payload::*, processor::transport::*, state::*},
    solana_program_test::ProgramTestContext,
    solana_sdk::{
        account::Account,
        clock::Clock,
        hash::{hash, hashv},
        instruction::{AccountMeta, Instruction, InstructionError},
        pubkey::Pubkey,
        signature::Signer,
        transaction::{Transaction, TransactionError},
    },
};

#[path = "common/sbf.rs"]
mod sbf;

const ASK: &[u8] = include_bytes!("../../../crates/solana-confidential-compute-crypto/tests/data/milan_ask.der");
const LEAF: &[u8] = include_bytes!("../../../fixtures/vcek_milan.der");

/// Subject public key as it sits in the leaf's `SubjectPublicKeyInfo`.
fn leaf_public_key_xy() -> [u8; 96] {
    let offset = LEAF.windows(4).position(|w| w == [3, 0x62, 0, 4]).unwrap() + 4;
    LEAF[offset..offset + 96].try_into().unwrap()
}

fn register_vcek_payload(public_key_xy: [u8; 96]) -> Vec<u8> {
    let identity = solana_confidential_compute_crypto::parse_vcek_identity(LEAF).unwrap();
    let mut payload = REGISTER_VCEK_DISCRIMINATOR.to_vec();
    RegisterVcekArgs {
        chip_id: identity.chip_id,
        tcb_version: identity.tcb_version,
        public_key_xy,
        ask_cert_len: ASK.len() as u16,
        vcek_cert_len: LEAF.len() as u16,
    }
    .serialize(&mut payload)
    .unwrap();
    payload.extend_from_slice(ASK);
    payload.extend_from_slice(LEAF);
    payload
}

fn instruction_error(err: solana_program_test::BanksClientError) -> InstructionError {
    match err.unwrap() {
        TransactionError::InstructionError(_, e) => e,
        other => panic!("unexpected transaction error: {other:?}"),
    }
}

async fn boot(pid: Pubkey, now: i64) -> ProgramTestContext {
    let mut pt = sbf::verifier_program_test(pid);
    let (registry, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let policy = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        // `ark_pubkey_xy` is legacy and ignored; the Milan ARK modulus is pinned
        // in `solana_confidential_compute_crypto`, so a zero root cannot admit a synthetic chain.
        authority: Pubkey::new_unique().to_bytes(),
        ark_pubkey_xy: [0; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 0,
        measurements: [[0; 48]; 8],
        bump,
    };
    pt.add_account(
        registry,
        Account { lamports: 10_000_000, data: borsh::to_vec(&policy).unwrap(), owner: pid, ..Account::default() },
    );
    let ctx = pt.start_with_context().await;
    let mut clock: Clock = ctx.banks_client.get_sysvar().await.unwrap();
    clock.unix_timestamp = now;
    ctx.set_sysvar(&clock);
    ctx
}

fn transport_ix(pid: Pubkey, tag: [u8; 8], rest: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = tag.to_vec();
    data.extend(rest);
    Instruction { program_id: pid, accounts, data }
}

/// Uploads and seals `payload`, returning the stage PDA. Sealing authenticates
/// bytes only; every trust decision still happens in CONSUME.
async fn seal(ctx: &mut ProgramTestContext, pid: Pubkey, payload: &[u8]) -> Pubkey {
    let authority = ctx.payer.pubkey();
    let digest = hash(payload);
    let stage = Pubkey::find_program_address(&[b"attestation_stage", authority.as_ref(), digest.as_ref()], &pid).0;
    let pair = vec![AccountMeta::new(authority, true), AccountMeta::new(stage, false)];
    let slot = ctx.banks_client.get_sysvar::<Clock>().await.unwrap().slot;

    let mut begin = digest.to_bytes().to_vec();
    begin.extend((payload.len() as u32).to_le_bytes());
    begin.extend((slot + MAX_LIFETIME_SLOTS).to_le_bytes());
    let mut begin_accounts = pair.clone();
    begin_accounts.push(AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false));

    let mut packets = vec![transport_ix(pid, BEGIN, begin, begin_accounts)];
    for (index, chunk) in payload.chunks(MAX_CHUNK).enumerate() {
        let mut rest = ((index * MAX_CHUNK) as u32).to_le_bytes().to_vec();
        rest.extend(chunk);
        packets.push(transport_ix(pid, UPLOAD, rest, pair.clone()));
    }
    packets.push(transport_ix(pid, SEAL, vec![], pair.clone()));

    for ix in packets {
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&authority), &[&ctx.payer], ctx.last_blockhash);
        assert!(solana_packet::Packet::from_data(None, &tx).unwrap().meta().size <= 1232);
        ctx.banks_client.process_transaction(tx).await.unwrap();
    }
    stage
}

/// `[authority, stage]` for the transport, then the handler's own metas. The
/// handler payer must be the staging authority, so it appears twice.
fn consume(
    pid: Pubkey,
    authority: Pubkey,
    stage: Pubkey,
    registry: Pubkey,
    vcek: Pubkey,
    revocation: Option<Pubkey>,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new(stage, false),
        AccountMeta::new(authority, true),
        AccountMeta::new_readonly(registry, false),
        AccountMeta::new(vcek, false),
        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
    ];
    accounts.extend(revocation.map(|key| AccountMeta::new_readonly(key, false)));
    transport_ix(pid, CONSUME, vec![], accounts)
}

/// Chain validation is two RSA-4096 PSS verifications; the default 200k CU
/// ceiling is not enough. Consumes repeat verbatim across the denylist cases,
/// so each gets a fresh blockhash -- an identical signature would be answered
/// from the status cache instead of being executed.
async fn send(ctx: &mut ProgramTestContext, ix: Instruction) -> Result<(), solana_program_test::BanksClientError> {
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000), ix],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        blockhash,
    );
    ctx.banks_client.process_transaction(tx).await
}

#[tokio::test]
async fn real_chain_registration_rejects_out_of_window_clock_without_writes() {
    let xy = leaf_public_key_xy();
    let identity = solana_confidential_compute_crypto::parse_vcek_identity(LEAF).unwrap();
    let chip_id_hash = hashv(&[&identity.chip_id]).to_bytes();
    let payload = register_vcek_payload(xy);

    for (now, accept) in
        [(1_790_287_994, false), (1_790_287_995, true), (2_011_212_795, false), (2_208_988_800, false), (-1, false)]
    {
        let pid = Pubkey::new_unique();
        let mut ctx = boot(pid, now).await;
        let authority = ctx.payer.pubkey();
        let (registry, _) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
        let (vcek, _) = Pubkey::find_program_address(
            &[VcekAccount::SEED, &chip_id_hash, &identity.tcb_version.to_le_bytes()],
            &pid,
        );
        let (revocation, _) = Pubkey::find_program_address(&[AmdIdentityRevocation::SEED, &chip_id_hash], &pid);
        let stage = seal(&mut ctx, pid, &payload).await;

        if accept {
            // A valid authentic certificate cannot bypass the source identity
            // denylist: any program-owned record fails closed.
            ctx.set_account(
                &revocation,
                &Account { lamports: 10_000_000, data: vec![0; 1], owner: pid, ..Account::default() }.into(),
            );
            let err =
                send(&mut ctx, consume(pid, authority, stage, registry, vcek, Some(revocation))).await.unwrap_err();
            assert_eq!(instruction_error(err), InstructionError::Custom(VerifierError::UnauthorizedPolicy as u32));
            assert!(ctx.banks_client.get_account(vcek).await.unwrap().is_none());
            ctx.set_account(
                &revocation,
                &Account { lamports: 1, owner: solana_sdk_ids::system_program::ID, ..Account::default() }.into(),
            );

            // Omitting the denylist account is not a way to skip the check.
            let err = send(&mut ctx, consume(pid, authority, stage, registry, vcek, None)).await.unwrap_err();
            assert_eq!(instruction_error(err), InstructionError::NotEnoughAccountKeys);
            assert!(ctx.banks_client.get_account(vcek).await.unwrap().is_none());
        }

        let result = send(&mut ctx, consume(pid, authority, stage, registry, vcek, Some(revocation))).await;

        if accept {
            result.expect("in-window real chain");
            let saved =
                VcekAccount::try_from_slice(&ctx.banks_client.get_account(vcek).await.unwrap().unwrap().data).unwrap();
            assert_eq!(saved.public_key_xy, xy);
            assert_eq!(saved.valid_until_unix, 2_011_212_795);
            assert_eq!(saved.trust_profile, VcekAccount::MILAN_TRUST_PROFILE);
            assert!(!saved.is_revoked);
            // Only a successful handler marks the stage consumed.
            assert_eq!(ctx.banks_client.get_account(stage).await.unwrap().unwrap().data[88], 2);
        } else {
            assert_eq!(
                instruction_error(result.unwrap_err()),
                InstructionError::Custom(if now < 0 {
                    // `u64::try_from(clock.unix_timestamp)` fails before any DER is read.
                    VerifierError::InvalidInstruction as u32
                } else {
                    VerifierError::VerificationFailed as u32
                }),
                "accepted clock {now}"
            );
            assert!(ctx.banks_client.get_account(vcek).await.unwrap().is_none());
            // A rejected consume leaves the stage sealed, never consumed.
            assert_eq!(ctx.banks_client.get_account(stage).await.unwrap().unwrap().data[88], 1);
        }
    }
}
