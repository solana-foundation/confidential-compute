//! #211: actual JWT issuance must produce bytes whose credential deadline
//! and governed revocation are enforced by the actual Mode A consumer.
//! The locally signed JWT proves protocol logic, not Google provenance.
//!
//! MIGRATION (solana 2.2 -> 4.x): this called `Processor::process` directly on
//! hand-built `AccountInfo`s and stubbed the clock via `set_syscall_stubs`. In
//! 4.x `Clock::get()` resolves through `solana_get_sysvar::sol_get_sysvar`,
//! whose non-solana branch is a hardcoded `UNSUPPORTED_SYSVAR` that never
//! consults `program_stubs`, so a natively linked program can no longer read
//! any sysvar -- `register_jwks_key` dies on `Clock::get()` before the test
//! gets started. Issuance therefore has to run as real SBF bytecode under
//! `ProgramTest`.
//!
//! That forces two changes, both of which make the test stricter, not looser:
//!
//! 1. The shared `teton-test` JWT fixture is unusable here. Its Mode A binding
//!    commits to workload key `[b'n'; 32]`, and `process_verify_google_jwt`
//!    requires that key to be a transaction signer. No private key exists for
//!    it, and a real runtime verifies signatures, so the fixture can never be
//!    consumed on-chain. This test now mints its own RS256 token over a
//!    freshly generated RSA key and binds it to a real `Keypair`, so the
//!    workload signature is genuine rather than a fabricated `is_signer` flag.
//!    The fixture constant is left alone for the tests that still parse it.
//!
//! 2. The consumer half changes its observation point. `assert_attestation_
//!    signer` reads `Clock::get()`, which only resolves inside a program, and
//!    the verifier `.so` does not expose the Mode A consumer helper. The
//!    deadline and revocation assertions therefore call
//!    `assert_attestation_signer_at_slot` (solana-confidential-compute-cpi's own `test-bpf` seam)
//!    over an `AccountInfo` rebuilt from the bytes the bank actually wrote.
//!    The whole of `assert_attestation_signer_inner` -- platform, PDA, signer,
//!    measurement, expiry -- still runs; only the clock source is injected
//!    instead of read. The record bytes are still passed through verbatim.
#![cfg(feature = "test-bpf")]
use rsa::{
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer as _},
    traits::PublicKeyParts,
    PrivateKey,
};
use sha2::Sha256;
use solana_confidential_compute_cpi::AttestationPlatform;
use solana_confidential_compute_verifier::{
    payload::{
        REGISTER_JWKS_KEY_DISCRIMINATOR, REVOKE_ATTESTED_SIGNER_DISCRIMINATOR, REVOKE_JWKS_KEY_DISCRIMINATOR,
        VERIFY_GOOGLE_JWT_DISCRIMINATOR,
    },
    state::{BackendPolicy, GcpTenantPolicy, PolicyRegistry, UsedNonceAccount, POLICY_REGISTRY_DISCRIMINATOR},
};
use solana_program::account_info::AccountInfo;
use solana_sdk::{
    account::Account,
    clock::Clock,
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    slot_hashes::SlotHashes,
    transaction::Transaction,
};

#[path = "support/sbf.rs"]
mod sbf;

const KID: &[u8] = b"solana-cc-test";
const AUDIENCE: &[u8] = b"solana-confidential-compute-verifier";
const SUBJECT: &[u8] =
    b"https://www.googleapis.com/compute/v1/projects/solana-confidential-compute/zones/us/instances/vm";
const SLOT: u64 = 520;
const NONCE_SLOT: u64 = 500;
const TOKEN_EXP: i64 = 4_102_444_800;
const SLOT_EXP: u64 = SLOT + 216_000;

fn b64url(bytes: &[u8]) -> String {
    const SET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..chunk.len() + 1 {
            out.push(SET[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
        }
    }
    out
}

/// Mints the token the Google Confidential Space issuer would have produced,
/// with the Mode A binding pointed at a workload key this test can sign for.
fn mint_jwt(key: &PrivateKey, workload: &Pubkey, slot_hash: &[u8; 32], iat: i64) -> String {
    let header = br#"{"alg":"RS256","kid":"solana-cc-test","typ":"JWT"}"#;
    let claims = format!(
        concat!(
            r#"{{"aud":"solana-confidential-compute-verifier","dbgstat":"disabled-since-boot","#,
            r#""eat_nonce":["{}","{}"],"exp":{},"iat":{},"#,
            r#""iss":"https://confidentialcomputing.googleapis.com","secboot":true,"#,
            r#""sub":"{}","submods":{{"container":{{"image_digest":"sha256:{}"}}}}}}"#,
        ),
        b64url(workload.as_ref()),
        b64url(slot_hash),
        TOKEN_EXP,
        iat,
        core::str::from_utf8(SUBJECT).unwrap(),
        "ab".repeat(32),
    );
    let signing_input = format!("{}.{}", b64url(header), b64url(claims.as_bytes()));
    let signature = SigningKey::<Sha256>::new(key.clone()).sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(&signature.to_bytes()))
}

fn funded(owner: Pubkey, data: Vec<u8>) -> Account {
    Account { lamports: 100_000_000, data, owner, executable: false, rent_epoch: 0 }
}

/// An `AccountInfo` over the exact bytes the bank holds for `key`.
fn as_account_info(key: Pubkey, owner: Pubkey, signer: bool, data: Vec<u8>) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        signer,
        false,
        Box::leak(Box::new(100_000_000)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
    )
}

#[tokio::test]
async fn issued_session_stops_at_credential_expiry_and_governed_revocation() {
    let pid = solana_confidential_compute_verifier::id();
    let authority = Keypair::new();
    let workload = Keypair::new();
    // A distinct fee payer: the runtime always marks the fee payer a signer, so
    // the authority must not be it if the unsigned-authority path is to exist.
    let fee_payer = Keypair::new();
    let slot_hash = [0x5a; 32];
    let mut measurement = [0; 48];
    measurement[..32].fill(0xab);

    let key = PrivateKey::new(&mut rand::rng(), 2048).unwrap();
    let mut modulus = [0u8; 256];
    modulus.copy_from_slice(&key.n_bytes());

    let (registry, rb) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let kid_hash = solana_confidential_compute_crypto_kid_hash(KID);
    let (jwks, _) = Pubkey::find_program_address(&[b"jwks", &kid_hash], &pid);
    let (record, _) = Pubkey::find_program_address(&[b"attested_signer_v2", workload.pubkey().as_ref()], &pid);

    let mut policy = vec![0; PolicyRegistry::SIZE];
    policy[..8].copy_from_slice(&POLICY_REGISTRY_DISCRIMINATOR);
    policy[8..40].copy_from_slice(authority.pubkey().as_ref());
    policy[140..144].copy_from_slice(&1u32.to_le_bytes());
    policy[144..192].copy_from_slice(&measurement);
    *policy.last_mut().unwrap() = rb;

    // Governed tenant binding (#247): the minted token's exact audience and subject.
    let (tenant, tenant_bump) = Pubkey::find_program_address(&[GcpTenantPolicy::SEED], &pid);
    let mut tenant_policy = GcpTenantPolicy::DISCRIMINATOR.to_vec();
    tenant_policy.push(AUDIENCE.len() as u8);
    tenant_policy.extend_from_slice(AUDIENCE);
    tenant_policy.resize(8 + 1 + 128, 0);
    tenant_policy.push(SUBJECT.len() as u8);
    tenant_policy.extend_from_slice(SUBJECT);
    tenant_policy.resize(GcpTenantPolicy::SIZE - 1, 0);
    tenant_policy.push(tenant_bump);

    // #183: JWT verification requires the governed GCP (source 3) backend policy.
    let (backend, backend_bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[3]], &pid);
    let mut backend_policy = BackendPolicy::DISCRIMINATOR.to_vec();
    backend_policy.push(3);
    backend_policy.extend_from_slice(&1u32.to_le_bytes());
    backend_policy.extend_from_slice(&measurement);
    backend_policy.resize(BackendPolicy::SIZE - 1, 0);
    backend_policy.push(backend_bump);

    let mut pt = sbf::verifier_program_test(pid);
    pt.add_account(authority.pubkey(), funded(solana_sdk_ids::system_program::ID, vec![]));
    pt.add_account(workload.pubkey(), funded(solana_sdk_ids::system_program::ID, vec![]));
    pt.add_account(fee_payer.pubkey(), funded(solana_sdk_ids::system_program::ID, vec![]));
    pt.add_account(registry, funded(pid, policy));
    pt.add_account(tenant, funded(pid, tenant_policy));
    pt.add_account(backend, funded(pid, backend_policy));
    let mut ctx = pt.start_with_context().await;
    // Pin the clock one second before the credential deadline, so the token's
    // own `exp` -- not the rolling session TTL -- is what bounds the session.
    ctx.set_sysvar(&Clock { slot: SLOT, unix_timestamp: TOKEN_EXP - 1, ..Clock::default() });
    ctx.set_sysvar(&SlotHashes::new(&[(NONCE_SLOT, Hash::new_from_array(slot_hash))]));

    // Register the generated RSA key through the actual governance handler,
    // including its Montgomery precomputation, instead of inventing a
    // serialized key cache.
    let mut register_ix = REGISTER_JWKS_KEY_DISCRIMINATOR.to_vec();
    register_ix.extend_from_slice(&(KID.len() as u32).to_le_bytes());
    register_ix.extend_from_slice(KID);
    register_ix.extend_from_slice(&modulus);
    register_ix.extend_from_slice(&65537u32.to_le_bytes());
    send(
        &mut ctx,
        &fee_payer,
        Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(registry, false),
                AccountMeta::new(jwks, false),
                AccountMeta::new(fee_payer.pubkey(), true),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data: register_ix,
        },
        &[&fee_payer, &authority],
    )
    .await
    .unwrap();

    let jwt = mint_jwt(&key, &workload.pubkey(), &slot_hash, TOKEN_EXP - 1_000);
    let mut raw = workload.pubkey().to_bytes().to_vec();
    raw.extend_from_slice(&slot_hash);
    let nonce_seed = solana_confidential_compute_crypto_kid_hash(&raw);
    // #205: GCP tombstones are source-tagged; the empty legacy address is the readonly guard.
    let (nonce, _) = Pubkey::find_program_address(&[b"nonce", &[3], &nonce_seed], &pid);
    let (legacy_nonce, _) = Pubkey::find_program_address(&[b"nonce", &nonce_seed], &pid);

    let mut verify_ix = VERIFY_GOOGLE_JWT_DISCRIMINATOR.to_vec();
    verify_ix.push(0);
    verify_ix.extend_from_slice(&NONCE_SLOT.to_le_bytes());
    verify_ix.extend_from_slice(&[0; 32]);
    verify_ix.extend_from_slice(&(jwt.len() as u32).to_le_bytes());
    verify_ix.extend_from_slice(jwt.as_bytes());
    send(
        &mut ctx,
        &fee_payer,
        Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new(record, false),
                AccountMeta::new_readonly(registry, false),
                AccountMeta::new(jwks, false),
                AccountMeta::new(nonce, false),
                AccountMeta::new(fee_payer.pubkey(), true),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
                AccountMeta::new_readonly(workload.pubkey(), true),
                AccountMeta::new_readonly(tenant, false),
                AccountMeta::new_readonly(backend, false),
                AccountMeta::new_readonly(legacy_nonce, false),
            ],
            data: verify_ix,
        },
        &[&fee_payer, &workload],
    )
    .await
    .unwrap();

    // Pass the exact bytes written by issuance to the consumer; no edits can
    // hide a producer/consumer mismatch.
    let issued = ctx.banks_client.get_account(record).await.unwrap().unwrap();
    assert_eq!(issued.owner, pid);
    assert_eq!(issued.data.len(), 154);
    let deadline = i64::from_le_bytes(issued.data[146..154].try_into().unwrap());
    assert_eq!(deadline, TOKEN_EXP);
    assert_eq!(u64::from_le_bytes(issued.data[137..145].try_into().unwrap()), SLOT_EXP);
    let used = ctx.banks_client.get_account(nonce).await.unwrap().unwrap();
    assert_eq!(used.data.len(), UsedNonceAccount::SIZE);

    let consume = |data: Vec<u8>, unix: i64| {
        let record_acc = as_account_info(record, pid, false, data);
        let workload_acc = as_account_info(workload.pubkey(), solana_sdk_ids::system_program::ID, true, vec![]);
        solana_confidential_compute_cpi::assert_attestation_signer_at_slot(
            &record_acc,
            &workload_acc,
            SLOT,
            &measurement,
            AttestationPlatform::GcpConfidentialSpace,
            unix,
        )
    };
    assert_eq!(consume(issued.data.clone(), TOKEN_EXP - 1), Ok(SLOT_EXP));
    // Same slot and still-signed key: the credential deadline alone stops use.
    assert_eq!(
        consume(issued.data.clone(), TOKEN_EXP),
        Err(solana_confidential_compute_cpi::CpiError::AttestationExpired.into())
    );
    assert_eq!(
        consume(issued.data.clone(), -1),
        Err(solana_confidential_compute_cpi::CpiError::AttestationExpired.into())
    );

    // Issuer revocation alone does not invalidate an already issued session.
    let mut revoke_issuer = REVOKE_JWKS_KEY_DISCRIMINATOR.to_vec();
    revoke_issuer.extend_from_slice(&kid_hash);
    send(
        &mut ctx,
        &fee_payer,
        Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(registry, false),
                AccountMeta::new(jwks, false),
            ],
            data: revoke_issuer,
        },
        &[&fee_payer, &authority],
    )
    .await
    .unwrap();
    let after_issuer = ctx.banks_client.get_account(record).await.unwrap().unwrap();
    assert_eq!(after_issuer.data, issued.data);
    assert_eq!(consume(after_issuer.data.clone(), TOKEN_EXP - 1), Ok(SLOT_EXP));

    let mut revoke = REVOKE_ATTESTED_SIGNER_DISCRIMINATOR.to_vec();
    revoke.extend_from_slice(workload.pubkey().as_ref());
    let revoke_ix = |signer: Pubkey, is_signer: bool| Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new_readonly(signer, is_signer),
            AccountMeta::new_readonly(registry, false),
            AccountMeta::new(record, false),
        ],
        data: revoke.clone(),
    };

    // A stranger cannot revoke, and the record is untouched.
    let stranger = Keypair::new();
    assert!(send(&mut ctx, &fee_payer, revoke_ix(stranger.pubkey(), true), &[&fee_payer, &stranger]).await.is_err());
    assert_eq!(ctx.banks_client.get_account(record).await.unwrap().unwrap().data, issued.data);

    // Nor can an unsigned authority.
    assert!(send(&mut ctx, &fee_payer, revoke_ix(authority.pubkey(), false), &[&fee_payer]).await.is_err());
    let still = ctx.banks_client.get_account(record).await.unwrap().unwrap();
    assert_eq!(still.data, issued.data);
    assert_eq!(consume(still.data, TOKEN_EXP - 1), Ok(SLOT_EXP));

    send(&mut ctx, &fee_payer, revoke_ix(authority.pubkey(), true), &[&fee_payer, &authority]).await.unwrap();
    let revoked = ctx.banks_client.get_account(record).await.unwrap().unwrap();
    assert_eq!(
        consume(revoked.data.clone(), TOKEN_EXP - 1),
        Err(solana_confidential_compute_cpi::CpiError::AttestationExpired.into())
    );
    assert_eq!(&revoked.data[137..145], &0u64.to_le_bytes());
    assert_eq!(&revoked.data[..137], &issued.data[..137]);
}

fn solana_confidential_compute_crypto_kid_hash(bytes: &[u8]) -> [u8; 32] {
    solana_sdk::hash::hash(bytes).to_bytes()
}

async fn send(
    ctx: &mut solana_program_test::ProgramTestContext,
    payer: &Keypair,
    ix: Instruction,
    signers: &[&Keypair],
) -> Result<(), solana_program_test::BanksClientError> {
    ctx.last_blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    // RS256 with on-chain Montgomery reduction does not fit the 200k default.
    let tx = Transaction::new_signed_with_payer(
        &[solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000), ix],
        Some(&payer.pubkey()),
        signers,
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await
}
