// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Versioned governance events describe successful writes; consumers must also
//! require transaction success because a later instruction can roll a write back.
//!
//! MIGRATION (solana 2.2 -> 4.x): every case here drove `Processor::process`
//! natively over hand-built `AccountInfo`s and read events out of a
//! `sol_log_data` `SyscallStubs` impl, with a second stub feeding `Clock::get()`.
//! In 4.x `Sysvar::get()` resolves through `solana_get_sysvar::sol_get_sysvar`,
//! whose non-solana branch is a hardcoded `UNSUPPORTED_SYSVAR` that never
//! consults `program_stubs`: the stub machinery is dead code and
//! `register_jwks_key` cannot read the clock natively. The program now runs as
//! real SBF bytecode under `ProgramTest`, so events are decoded from the
//! transaction's base64 `Program data:` log lines and "no write on failure" is
//! read back through `BanksClient` instead of from a still-borrowed buffer.
//! Real bytecode also allocates its own PDAs rather than inheriting
//! preallocated mocks, so `init_policy_registry` needs a planted ProgramData
//! account and created PDAs hash their `before` over zeroed bytes of the exact
//! size. The foreign-owner rejection, dead in the native file because no caller
//! ever passed `foreign = true`, is now exercised against a real PDA owned by
//! another program.
use {
    base64::{engine::general_purpose::STANDARD, Engine},
    borsh::BorshSerialize,
    solana_confidential_compute_core::types::{AttestedSigner, EnclaveType, MeasurementDigest},
    solana_confidential_compute_crypto::jwt::{kid_hash, JWKS_SEED, RSA_EXPONENT},
    solana_confidential_compute_verifier::{
        error::VerifierError, payload::*, processor::ROTATE_AUTHORITY_DISCRIMINATOR, state::*,
    },
    solana_program::hash::hashv,
    solana_program_test::ProgramTestContext,
    solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction, InstructionError},
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        transaction::{Transaction, TransactionError},
    },
};

#[path = "common/sbf.rs"]
mod sbf;

const SYSTEM: Pubkey = solana_sdk_ids::system_program::ID;

type Events = Vec<Vec<Vec<u8>>>;

/// `sol_log_data` reaches the host as one space-separated base64 field list.
fn decode(logs: &[String]) -> Events {
    logs.iter()
        .filter_map(|line| line.strip_prefix("Program data: "))
        .map(|fields| fields.split_whitespace().map(|field| STANDARD.decode(field).unwrap()).collect())
        .collect()
}

fn custom(err: VerifierError) -> TransactionError {
    TransactionError::InstructionError(0, InstructionError::Custom(err as u32))
}

fn ix_err(err: InstructionError) -> TransactionError {
    TransactionError::InstructionError(0, err)
}

fn funded() -> Account {
    Account { lamports: 10_000_000, ..Account::default() }
}

fn owned(program_id: Pubkey, data: Vec<u8>) -> Account {
    Account { lamports: 10_000_000, data, owner: program_id, ..Account::default() }
}

fn registry_account(program_id: Pubkey, authority: &Pubkey, bump: u8) -> Account {
    owned(
        program_id,
        borsh::to_vec(&PolicyRegistry {
            discriminator: POLICY_REGISTRY_DISCRIMINATOR,
            authority: authority.to_bytes(),
            ark_pubkey_xy: [1; 96],
            min_tcb_boot_loader: 0,
            min_tcb_tee: 0,
            min_tcb_snp: 0,
            min_tcb_microcode: 0,
            measurement_count: 0,
            measurements: [[0; 48]; 8],
            bump,
        })
        .unwrap(),
    )
}

/// The bank's program account is a loader-v2 executable with no ProgramData.
/// Initialization authenticates the upgrade authority, so plant one.
fn set_upgrade_authority(ctx: &mut ProgramTestContext, program_id: &Pubkey, authority: &Pubkey) {
    let loader = solana_sdk_ids::bpf_loader_upgradeable::id();
    let (key, _) = Pubkey::find_program_address(&[program_id.as_ref()], &loader);
    let mut data = vec![0; 45];
    data[..4].copy_from_slice(&3u32.to_le_bytes());
    data[12] = 1;
    data[13..45].copy_from_slice(authority.as_ref());
    ctx.set_account(
        &key,
        &Account { lamports: 1_000_000, data, owner: loader, executable: false, rent_epoch: 0 }.into(),
    );
}

async fn send(
    ctx: &mut ProgramTestContext,
    ix: Instruction,
    extra: &[&Keypair],
) -> (Result<(), TransactionError>, Events) {
    let mut signers: Vec<&Keypair> = vec![&ctx.payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &signers, ctx.last_blockhash);
    drop(signers);
    let out = ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap();
    let logs = out.metadata.expect("transaction metadata").log_messages;
    (out.result, decode(&logs))
}

async fn state(ctx: &mut ProgramTestContext, key: Pubkey) -> Option<Vec<u8>> {
    ctx.banks_client.get_account(key).await.unwrap().map(|account| account.data)
}

/// Exactly one version 1 governance event, bound to the account's real bytes.
fn assert_event(events: &Events, operation: &[u8], actor: &Pubkey, account: &Pubkey, before: &[u8], after: &[u8]) {
    let label = String::from_utf8_lossy(operation).into_owned();
    assert_ne!(before, after, "{label}: no write");
    assert_eq!(events.len(), 1, "{label}");
    assert_eq!(
        events[0],
        vec![
            b"solana-confidential-compute:governance:v1".to_vec(),
            operation.to_vec(),
            actor.to_bytes().to_vec(),
            account.to_bytes().to_vec(),
            hashv(&[before]).to_bytes().to_vec(),
            hashv(&[after]).to_bytes().to_vec(),
        ],
        "{label}"
    );
}

/// The three controls shared by every governed write: an unsigned actor and a
/// signed impostor are refused without touching `account` or logging anything,
/// and the authority's write emits exactly one event. `logged_before` is what
/// the program hashes as the prior state -- zeroed bytes for a PDA this call
/// allocates, the stored bytes otherwise.
async fn governed_write(
    ctx: &mut ProgramTestContext,
    base: &Instruction,
    authority: &Keypair,
    stranger: &Keypair,
    account: Pubkey,
    operation: &[u8],
    logged_before: &[u8],
) {
    let label = String::from_utf8_lossy(operation).into_owned();
    let pre = state(ctx, account).await;

    let mut unsigned = base.clone();
    unsigned.accounts[0].is_signer = false;
    let (result, events) = send(ctx, unsigned, &[]).await;
    assert_eq!(result, Err(ix_err(InstructionError::MissingRequiredSignature)), "{label}: unsigned");
    assert!(events.is_empty(), "{label}: unsigned");
    assert_eq!(state(ctx, account).await, pre, "{label}: unsigned");

    let mut impostor = base.clone();
    impostor.accounts[0].pubkey = stranger.pubkey();
    let (result, events) = send(ctx, impostor, &[stranger]).await;
    assert_eq!(result, Err(custom(VerifierError::InvalidAuthority)), "{label}: impostor");
    assert!(events.is_empty(), "{label}: impostor");
    assert_eq!(state(ctx, account).await, pre, "{label}: impostor");

    let (result, events) = send(ctx, base.clone(), &[authority]).await;
    assert_eq!(result, Ok(()), "{label}");
    let after = state(ctx, account).await.expect(&label);
    assert_event(&events, operation, &authority.pubkey(), &account, logged_before, &after);
}

fn init_ix(program_id: &Pubkey, registry: &Pubkey, authority: &Pubkey) -> Instruction {
    let mut data = INIT_POLICY_REGISTRY_DISCRIMINATOR.to_vec();
    InitPolicyRegistryArgs {
        authority: authority.to_bytes(),
        ark_pubkey_xy: [1; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 0,
        measurements: [[0; 48]; 8],
    }
    .serialize(&mut data)
    .unwrap();
    Instruction {
        program_id: *program_id,
        data,
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(*registry, false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(
                Pubkey::find_program_address(&[program_id.as_ref()], &solana_sdk_ids::bpf_loader_upgradeable::id()).0,
                false,
            ),
        ],
    }
}

#[tokio::test]
async fn init_policy_registry_emits_one_event_and_authenticates_the_upgrade_authority() {
    let pid = Pubkey::new_unique();
    let authority = Keypair::new();
    let stranger = Keypair::new();
    let (registry, _) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let mut pt = sbf::verifier_program_test(pid);
    pt.add_account(authority.pubkey(), funded());
    pt.add_account(stranger.pubkey(), funded());
    let mut ctx = pt.start_with_context().await;
    set_upgrade_authority(&mut ctx, &pid, &authority.pubkey());

    // A signed impostor naming itself in the args still fails the ProgramData
    // check: no allocation, no event.
    let ix = init_ix(&pid, &registry, &stranger.pubkey());
    let (result, events) = send(&mut ctx, ix, &[&stranger]).await;
    assert_eq!(result, Err(custom(VerifierError::InvalidAuthority)));
    assert!(events.is_empty());
    assert!(state(&mut ctx, registry).await.is_none());

    governed_write(
        &mut ctx,
        &init_ix(&pid, &registry, &authority.pubkey()),
        &authority,
        &stranger,
        registry,
        b"init_policy_registry",
        &vec![0; PolicyRegistry::SIZE],
    )
    .await;
}

fn register_jwks_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    registry: &Pubkey,
    jwks: &Pubkey,
    payer: &Pubkey,
    kid: &[u8],
) -> Instruction {
    let mut data = REGISTER_JWKS_KEY_DISCRIMINATOR.to_vec();
    RegisterJwksKeyArgs { kid: kid.to_vec(), modulus: [0xff; 256], exponent: RSA_EXPONENT }
        .serialize(&mut data)
        .unwrap();
    Instruction {
        program_id: *program_id,
        data,
        accounts: vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(*registry, false),
            AccountMeta::new(*jwks, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    }
}

fn revoke_jwks_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    registry: &Pubkey,
    jwks: &Pubkey,
    hash: [u8; 32],
) -> Instruction {
    let mut data = REVOKE_JWKS_KEY_DISCRIMINATOR.to_vec();
    RevokeJwksKeyArgs { kid_hash: hash }.serialize(&mut data).unwrap();
    Instruction {
        program_id: *program_id,
        data,
        accounts: vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(*registry, false),
            AccountMeta::new(*jwks, false),
        ],
    }
}

#[tokio::test]
async fn jwks_and_policy_writes_emit_one_event_each_and_refuse_foreign_accounts() {
    let pid = Pubkey::new_unique();
    let authority = Keypair::new();
    let stranger = Keypair::new();
    let kid = b"event-test";
    let hash = kid_hash(kid);
    let (jwks, _) = Pubkey::find_program_address(&[JWKS_SEED, &hash], &pid);
    let alien_kid = b"foreign-test";
    let alien_hash = kid_hash(alien_kid);
    let (alien, _) = Pubkey::find_program_address(&[JWKS_SEED, &alien_hash], &pid);
    let (registry, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);

    let mut pt = sbf::verifier_program_test(pid);
    pt.add_account(registry, registry_account(pid, &authority.pubkey(), bump));
    pt.add_account(authority.pubkey(), funded());
    pt.add_account(stranger.pubkey(), funded());
    // Canonical JWKS address, foreign owner: never this program's key material.
    pt.add_account(alien, owned(Pubkey::new_unique(), vec![0; JwksAccount::SIZE]));
    let mut ctx = pt.start_with_context().await;
    let payer = ctx.payer.pubkey();

    governed_write(
        &mut ctx,
        &register_jwks_ix(&pid, &authority.pubkey(), &registry, &jwks, &payer, kid),
        &authority,
        &stranger,
        jwks,
        b"register_jwks_key",
        &vec![0; JwksAccount::SIZE],
    )
    .await;

    let before = state(&mut ctx, alien).await.unwrap();
    let ix = register_jwks_ix(&pid, &authority.pubkey(), &registry, &alien, &payer, alien_kid);
    let (result, events) = send(&mut ctx, ix, &[&authority]).await;
    assert_eq!(result, Err(ix_err(InstructionError::IllegalOwner)));
    assert!(events.is_empty());
    assert_eq!(state(&mut ctx, alien).await.unwrap(), before);

    let mut data = UPDATE_POLICY_DISCRIMINATOR.to_vec();
    UpdatePolicyArgs {
        min_tcb_boot_loader: 1,
        min_tcb_tee: 1,
        min_tcb_snp: 1,
        min_tcb_microcode: 1,
        measurement_count: 0,
        measurements: [[0; 48]; 8],
    }
    .serialize(&mut data)
    .unwrap();
    let update = Instruction {
        program_id: pid,
        data,
        accounts: vec![AccountMeta::new_readonly(authority.pubkey(), true), AccountMeta::new(registry, false)],
    };
    let before = state(&mut ctx, registry).await.unwrap();
    governed_write(&mut ctx, &update, &authority, &stranger, registry, b"update_policy", &before).await;

    let before = state(&mut ctx, jwks).await.unwrap();
    governed_write(
        &mut ctx,
        &revoke_jwks_ix(&pid, &authority.pubkey(), &registry, &jwks, hash),
        &authority,
        &stranger,
        jwks,
        b"revoke_jwks_key",
        &before,
    )
    .await;

    let before = state(&mut ctx, alien).await.unwrap();
    let ix = revoke_jwks_ix(&pid, &authority.pubkey(), &registry, &alien, alien_hash);
    let (result, events) = send(&mut ctx, ix, &[&authority]).await;
    assert_eq!(result, Err(custom(VerifierError::InvalidAccountAddress)));
    assert!(events.is_empty());
    assert_eq!(state(&mut ctx, alien).await.unwrap(), before);

    // Root rotation is refused even for the authority: no write, so no event.
    let mut data = ROTATE_ROOT_CERT_DISCRIMINATOR.to_vec();
    RotateRootCertArgs { new_ark_pubkey_xy: [2; 96] }.serialize(&mut data).unwrap();
    let before = state(&mut ctx, registry).await.unwrap();
    let ix = Instruction {
        program_id: pid,
        data,
        accounts: vec![AccountMeta::new_readonly(authority.pubkey(), true), AccountMeta::new(registry, false)],
    };
    let (result, events) = send(&mut ctx, ix, &[&authority]).await;
    assert_eq!(result, Err(custom(VerifierError::InvalidInstruction)));
    assert!(events.is_empty());
    assert_eq!(state(&mut ctx, registry).await.unwrap(), before);
}

#[tokio::test]
async fn authority_handover_needs_both_signatures_and_emits_one_event() {
    let pid = Pubkey::new_unique();
    let authority = Keypair::new();
    let stranger = Keypair::new();
    let new_authority = Keypair::new();
    let (registry, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let mut pt = sbf::verifier_program_test(pid);
    pt.add_account(registry, registry_account(pid, &authority.pubkey(), bump));
    for key in [&authority, &stranger, &new_authority] {
        pt.add_account(key.pubkey(), funded());
    }
    let mut ctx = pt.start_with_context().await;
    let base = Instruction {
        program_id: pid,
        data: ROTATE_AUTHORITY_DISCRIMINATOR.to_vec(),
        accounts: vec![
            AccountMeta::new_readonly(authority.pubkey(), true),
            AccountMeta::new(registry, false),
            AccountMeta::new_readonly(new_authority.pubkey(), true),
        ],
    };
    let before = state(&mut ctx, registry).await.unwrap();

    // Unsigned current authority, a signed impostor, then an unsigned recipient.
    for case in 0..3 {
        let mut ix = base.clone();
        let mut signers: Vec<&Keypair> = vec![&new_authority];
        let expected = match case {
            0 => {
                ix.accounts[0].is_signer = false;
                ix_err(InstructionError::MissingRequiredSignature)
            }
            1 => {
                ix.accounts[0].pubkey = stranger.pubkey();
                signers.push(&stranger);
                custom(VerifierError::InvalidAuthority)
            }
            _ => {
                ix.accounts[2].is_signer = false;
                signers = vec![&authority];
                ix_err(InstructionError::MissingRequiredSignature)
            }
        };
        let (result, events) = send(&mut ctx, ix, &signers).await;
        assert_eq!(result, Err(expected), "case {case}");
        assert!(events.is_empty(), "case {case}");
        assert_eq!(state(&mut ctx, registry).await.unwrap(), before, "case {case}");
    }

    let (result, events) = send(&mut ctx, base, &[&authority, &new_authority]).await;
    assert_eq!(result, Ok(()));
    let after = state(&mut ctx, registry).await.unwrap();
    assert_event(&events, b"rotate_authority", &authority.pubkey(), &registry, &before, &after);
}

#[tokio::test]
async fn revoke_attested_signer_requires_the_authority_and_emits_one_event() {
    let pid = Pubkey::new_unique();
    let authority = Keypair::new();
    let stranger = Keypair::new();
    let signer_pubkey = [7u8; 32];
    let (registry, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (signer, signer_bump) = Pubkey::find_program_address(&[b"attested_signer_v2", &signer_pubkey], &pid);
    let live = AttestedSignerAccount::new(
        AttestedSigner {
            signer_pubkey,
            enclave_type: EnclaveType::GcpConfidentialSpace,
            measurement: MeasurementDigest([3; 48]),
            chip_id_hash: [0; 32],
            tcb_version: 0,
            registered_slot: 20,
            expires_slot: 216020,
        },
        signer_bump,
    );
    let mut pt = sbf::verifier_program_test(pid);
    pt.add_account(registry, registry_account(pid, &authority.pubkey(), bump));
    pt.add_account(signer, owned(pid, borsh::to_vec(&live).unwrap()));
    pt.add_account(authority.pubkey(), funded());
    pt.add_account(stranger.pubkey(), funded());
    let mut ctx = pt.start_with_context().await;

    let mut data = REVOKE_ATTESTED_SIGNER_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&signer_pubkey);
    let ix = Instruction {
        program_id: pid,
        data,
        accounts: vec![
            AccountMeta::new_readonly(authority.pubkey(), true),
            AccountMeta::new_readonly(registry, false),
            AccountMeta::new(signer, false),
        ],
    };
    let before = state(&mut ctx, signer).await.unwrap();
    governed_write(&mut ctx, &ix, &authority, &stranger, signer, b"revoke_attested_signer", &before).await;
}

fn gcp_ix(
    program_id: &Pubkey,
    actor: &Pubkey,
    registry: &Pubkey,
    policy: &Pubkey,
    payer: &Pubkey,
    audience: &str,
) -> Instruction {
    let mut data = SET_GCP_TENANT_POLICY_DISCRIMINATOR.to_vec();
    SetGcpTenantPolicyArgs { expected_audience: audience.into(), expected_subject: "tenant".into() }
        .serialize(&mut data)
        .unwrap();
    Instruction {
        program_id: *program_id,
        data,
        accounts: vec![
            AccountMeta::new_readonly(*actor, true),
            AccountMeta::new_readonly(*registry, false),
            AccountMeta::new(*policy, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    }
}

#[tokio::test]
async fn gcp_tenant_policy_emits_one_event_per_change_and_nothing_for_a_no_op() {
    let pid = Pubkey::new_unique();
    let authority = Keypair::new();
    let stranger = Keypair::new();
    let (registry, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (policy, _) = Pubkey::find_program_address(&[GcpTenantPolicy::SEED], &pid);
    let mut pt = sbf::verifier_program_test(pid);
    pt.add_account(registry, registry_account(pid, &authority.pubkey(), bump));
    pt.add_account(authority.pubkey(), funded());
    pt.add_account(stranger.pubkey(), funded());
    let mut ctx = pt.start_with_context().await;
    let payer = ctx.payer.pubkey();

    // Unsigned authority, wrong authority and a rejected (empty) audience fail
    // before allocation, so the policy PDA is never created and nothing logs.
    for case in 0..3 {
        let (actor, audience) = match case {
            1 => (stranger.pubkey(), "aud"),
            _ => (authority.pubkey(), if case == 0 { "aud" } else { "" }),
        };
        let mut ix = gcp_ix(&pid, &actor, &registry, &policy, &payer, audience);
        let signers: Vec<&Keypair> = match case {
            0 => {
                ix.accounts[0].is_signer = false;
                vec![]
            }
            1 => vec![&stranger],
            _ => vec![&authority],
        };
        let expected = match case {
            0 => ix_err(InstructionError::MissingRequiredSignature),
            1 => custom(VerifierError::InvalidAuthority),
            _ => ix_err(InstructionError::InvalidInstructionData),
        };
        let (result, events) = send(&mut ctx, ix, &signers).await;
        assert_eq!(result, Err(expected), "case {case}");
        assert!(events.is_empty(), "case {case}");
        assert!(state(&mut ctx, policy).await.is_none(), "case {case}");
    }

    // The governed write emits exactly one event over the freshly zeroed PDA.
    let ix = gcp_ix(&pid, &authority.pubkey(), &registry, &policy, &payer, "aud");
    let (result, events) = send(&mut ctx, ix.clone(), &[&authority]).await;
    assert_eq!(result, Ok(()));
    let seated = state(&mut ctx, policy).await.unwrap();
    assert_event(
        &events,
        b"set_gcp_tenant_policy",
        &authority.pubkey(),
        &policy,
        &vec![0; GcpTenantPolicy::SIZE],
        &seated,
    );

    // Re-setting the identical policy succeeds as a no-op: no write, no event.
    // A fresh blockhash only distinguishes the otherwise identical signature.
    ctx.last_blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let (result, events) = send(&mut ctx, ix, &[&authority]).await;
    assert_eq!(result, Ok(()));
    assert!(events.is_empty());
    assert_eq!(state(&mut ctx, policy).await.unwrap(), seated);

    // A changed policy emits exactly one event over the previous bytes.
    let ix = gcp_ix(&pid, &authority.pubkey(), &registry, &policy, &payer, "aud2");
    let (result, events) = send(&mut ctx, ix, &[&authority]).await;
    assert_eq!(result, Ok(()));
    let after = state(&mut ctx, policy).await.unwrap();
    assert_event(&events, b"set_gcp_tenant_policy", &authority.pubkey(), &policy, &seated, &after);
}
