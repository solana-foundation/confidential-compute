//! On-chain Google Cloud OIDC / JWT processor tests.
//!
//! @spec SCC-JWT-001 SCC-JWT-002 SCC-JWT-003 SCC-JWT-005 SCC-JWT-006
//!
//! MIGRATION (solana 2.2 -> 4.x): every test here drove `Processor::process`
//! directly over hand-built `AccountInfo`s and stubbed the clock through
//! `set_syscall_stubs`. In 4.x `Clock::get()` / `Rent::get()` resolve through
//! `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch is a hardcoded
//! `UNSUPPORTED_SYSVAR` that never consults `program_stubs`, so a natively
//! linked program can no longer read any sysvar. `process_register_jwks_key`
//! and `process_verify_google_jwt` both read the clock, so the program must
//! execute as real SBF bytecode under `ProgramTest`.
//!
//! The fixtures are fixed RSA-signed strings whose `eat_nonce` commits to slot
//! 500 with a specific slot hash, and they cannot be regenerated (no private
//! key in tree). `ProgramTestContext::set_sysvar` pins `Clock` and `SlotHashes`
//! on the working bank so both `Clock::get()` and the clock / slot-hashes
//! sysvar *accounts* the program reads return exactly what the tokens commit
//! to. The bank is never warped: `set_sysvar` survives for the life of the
//! working bank, and is re-applied before each transaction regardless.
//!
//! Three shims disappear and become explicit transaction state:
//!   * `common/source_policy.rs` injected the source-3 `BackendPolicy` PDA;
//!     it is now a preloaded account and an explicit `AccountMeta`.
//!   * `common/legacy_nonce.rs` injected the legacy nonce PDA; it is now an
//!     explicit (uncreated, system-owned) `AccountMeta`.
//!   * `process_with_tenant` fabricated a `GcpTenantPolicy` `AccountInfo`; it
//!     is now a real preloaded account, and "tenant absent" is the absence of
//!     that `AccountMeta`.
//!
//! `registration_events` captured `sol_log_data` through a syscall stub. Under
//! SBF those are `Program data:` log lines, read back from transaction
//! metadata and decoded here.
//!
//! The attested workload key is a fixture constant (`[b'n'; 32]`, and the
//! high-bit vector) with no secret, so its signature slot stays
//! `Signature::default()`. `solana-program-test` does not sigverify, so the
//! program observes `is_signer` from the message header exactly as it observed
//! the native harness's hand-built `AccountInfo { is_signer: true }`.

use base64::{engine::general_purpose::STANDARD, Engine};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_confidential_compute_core::types::EnclaveType;
use solana_confidential_compute_crypto::jwt::{eat_nonce_tombstone_seed, kid_hash, RSA_EXPONENT};
use solana_confidential_compute_verifier::error::VerifierError;
use solana_confidential_compute_verifier::payload::{
    RegisterJwksKeyArgs, RevokeJwksKeyArgs, VerifyGoogleJwtArgs, REGISTER_JWKS_KEY_DISCRIMINATOR,
    REVOKE_JWKS_KEY_DISCRIMINATOR, VERIFY_GOOGLE_JWT_DISCRIMINATOR, VERIFY_GOOGLE_JWT_MODE_A,
    VERIFY_GOOGLE_JWT_MODE_B,
};
use solana_confidential_compute_verifier::state::{
    AttestedSignerAccount, BackendPolicy, GcpTenantPolicy, JwksAccount, PolicyRegistry,
    UsedNonceAccount, ATTESTED_SIGNER_DISCRIMINATOR, JWKS_ACCOUNT_DISCRIMINATOR,
    POLICY_REGISTRY_DISCRIMINATOR, USED_NONCE_DISCRIMINATOR,
};
use solana_program_test::ProgramTestContext;
use solana_sdk::{
    account::Account,
    clock::Clock,
    hash::{hashv, Hash},
    instruction::{AccountMeta, Instruction, InstructionError},
    message::Message,
    program_error::ProgramError,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    slot_hashes::SlotHashes,
    sysvar::{clock, instructions, slot_hashes},
    transaction::{Transaction, TransactionError},
};
#[allow(deprecated)]
use solana_sdk_ids::system_program;

#[path = "common/sbf.rs"]
mod sbf;

const MODULUS_HEX: &str = "a583d1867001a794bcb2bdd2780451830f702f68c06866249499804f9ba437ad469ac221eea5fb6c3381bcaba74ea30230185b5582bb3c45278477df8dfe4818e673a7a3d763ca71c58c99d827e6b673eda72fc8ad4de529674726d187b1b7a50c6b87a5b7b042d07c07b66714bf4ee6527df0def652654b2d92c26e40dca7a237d20a17bd864093901184a303e1f002ced9e8dd5d41daced40d2372438bb692d53b94ce408f8381b790a43df7bd491bf852fcc5967d45372672ec37fdd1668edd0cf0fdcf0cc70f154d0a96a663a0fcd3f98691ebac12f5f9e1b9c12305cb895ab8663da3d48fbd7e0e0d5ab39e5651b32ee2afe953514462816ba4bda9221b";

/// Mode A token. `eat_nonce` is two unpadded base64url strings of `[b'n'; 32]`.
const VALID_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXRvbi12ZXJpZmllciIsImRiZ3N0YXQiOiJkaXNhYmxlZC1zaW5jZS1ib290IiwiZWF0X25vbmNlIjpbImJtNXVibTV1Ym01dWJtNXVibTV1Ym01dWJtNXVibTV1Ym01dWJtNXVibTQiLCJibTV1Ym01dWJtNXVibTV1Ym01dWJtNXVibTV1Ym01dWJtNXVibTV1Ym00Il0sImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2NvbmZpZGVudGlhbGNvbXB1dGluZy5nb29nbGVhcGlzLmNvbSIsInNlY2Jvb3QiOnRydWUsInN1YiI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2NvbXB1dGUvdjEvcHJvamVjdHMvdGV0b24vem9uZXMvdXMvaW5zdGFuY2VzL3ZtIiwic3VibW9kcyI6eyJjb250YWluZXIiOnsiaW1hZ2VfZGlnZXN0Ijoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifX19.lcgG76LbpMlUyft0pAQS9mv1EXuOOZmxkFlu0BHnQuwZc3CgIDYqoXW_9jf_IRkNWwXz4kdIS3g_bqkaT69B2lPgSHOY6K96ce6f792ze7T3LUMIQOQVScdh1GwHwrOHvF8im1nfMIi_XCPG5xhsbU8SgswDGnszqLZPO0M31hH4YaZq491hU7ciBnWfuXl9Gd8Wd0zGZQM98ubHssnqMEClhmV0-2LQDz48OiyvPYKUCifpsqf-r1ILLLC3efg7eWmNvXcDRYKP1rTuOylNGdKYwMy25kAwZOEf8n54MO29OhFMOk4EvkmdJ8kGrBiMogGH-WkRUgtNJHXdyxC8DQ";

/// Workload pubkey `80 01 02 … 1f` (high bit set) and slot hash `[0x5a; 32]`.
const HIGH_BIT_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXRvbi12ZXJpZmllciIsImRiZ3N0YXQiOiJkaXNhYmxlZC1zaW5jZS1ib290IiwiZWF0X25vbmNlIjpbImdBRUNBd1FGQmdjSUNRb0xEQTBPRHhBUkVoTVVGUllYR0JrYUd4d2RIaDgiLCJXbHBhV2xwYVdscGFXbHBhV2xwYVdscGFXbHBhV2xwYVdscGFXbHBhV2xvIl0sImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2NvbmZpZGVudGlhbGNvbXB1dGluZy5nb29nbGVhcGlzLmNvbSIsInNlY2Jvb3QiOnRydWUsInN1YiI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2NvbXB1dGUvdjEvcHJvamVjdHMvdGV0b24vem9uZXMvdXMvaW5zdGFuY2VzL3ZtIiwic3VibW9kcyI6eyJjb250YWluZXIiOnsiaW1hZ2VfZGlnZXN0Ijoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifX19.QuqstIIdyV6zZLRiHrb7BjBZSXpVGOJsi6W7Mnv4veX3l4TxQjzFvUAYVrgWxQ214RI7rKEz_KnoTwju064lZGKH4VqOSGPLxC3Wv6eaVCs3kYJ924T6mQShs83tW5ag9LwVGyXlIfBf850gg8UI-IVjt0GSeOt-e_c6Oh2TYWIbLGwZNULGCJDDwhIQsYZI8c38sD2TWAwAEs2Nbip1ivfzccD5-p0PDm15Yjb1S3C9ieYJn_AP7eYMXpNjMxtNpOXn_iZfprgO0zB0iUwytyW7CxvJnj8y7inO3z7dyGhNW5aFVYlgN2fYuRbTB3eBu3Nu8g8XHFSE3xcYPwRSUw";

const MODE_B_MODULUS_HEX: &str = "873249253d49eee96b81c9d585cce94648004a1d4b2d185842f1ebed675b76edc0e8b92d23e8edb4db31f9f09f06435ddf0bee84f4336b92791e5ae1b16d24d4a54902c369cd2e7ace2a158455c075d67837a7ef2002307159d371db7d3f8f8b59104438614c20a53c1dc451651401f81b26b132002374b7a659bf7f62ae5fd4a2fa191f8c9843991ca7b5599542c3d318ec495874e0ad8a64707c9c30f89f4bc02f661dcf3b8655fee0adc660273aa856ec547061ef52f23c6685265c9c29128fc08ad66242d29807f7d500811d15e8e33c4bace57dec95dfe19acce1e764f4e71a2d96a853cdfeb60c631cd6f54e47f53f48dbcfc67679818aac99ba7ae3a3";

/// Mode B token. `eat_nonce` is the unpadded base64url of SHA-256(slot || action || consumer).
/// Controlled V3 fixture; its decoded commitment has the high bit set.
const MODE_B_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXRvbi12ZXJpZmllciIsImRiZ3N0YXQiOiJkaXNhYmxlZC1zaW5jZS1ib290IiwiZWF0X25vbmNlIjoic05TZXAxbjlPQU5qREF5MTZUdGtXdDctLUxFMmpHMjM1Z1hKejZXSng0ayIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2NvbmZpZGVudGlhbGNvbXB1dGluZy5nb29nbGVhcGlzLmNvbSIsInNlY2Jvb3QiOnRydWUsInN1YiI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2NvbXB1dGUvdjEvcHJvamVjdHMvdGV0b24vem9uZXMvdXMvaW5zdGFuY2VzL3ZtIiwic3VibW9kcyI6eyJjb250YWluZXIiOnsiaW1hZ2VfZGlnZXN0Ijoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifX19.LFeExAEgTQoFYbgUJXFeiEhoBoxBhTi4BIR3kt7c0ybWkFZOz3l6DikD7mxxocbZswyTCJNKMdsxRZXtvTnm8NeKC73nLqaYYIXT79xSAB1Z8phsPCxU4oreoQz69mKBoaMxNCXuGWzthfvChXu8TB6cGQ8n-kRujisEw7KcRsp3VwcHPzmd33dov06-fqBR-XWAmVzWU_U8pps6SOuetVYjYPtUTq6siu_nv6Za9TOJEjYUGR0VkYjkGn6ohxQg18h-qDWYrpPT9WFeKU6wq2gOxNbZHjRVnezbErNw4CXO-ZLyyBXKS5FXDeWyn1hD5zgIkJoOD3ax_I7o1uZkUQ";

const KID: &[u8] = b"teton-test";
const EAT_NONCE: &[u8] = b"nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
const NONCE_SLOT: u64 = 500;
const CURRENT_SLOT: u64 = 520;
const UNIX_NOW: i64 = 1_700_000_100;
const ATTESTATION_TTL_SLOTS: u64 = 216_000;
const MODE_A_SLOT_HASH: [u8; 32] = [b'n'; 32];
const EXPECTED_AUDIENCE: &[u8] = b"teton-verifier";
const EXPECTED_SUBJECT: &[u8] =
    b"https://www.googleapis.com/compute/v1/projects/teton/zones/us/instances/vm";
/// The verifier recomputes the mode B commitment over this consumer program id.
const CONSUMER_ID: Pubkey = Pubkey::new_from_array([0x33; 32]);
/// RSA verification plus PDA creation does not fit the 200k default.
const CU_LIMIT: u32 = 1_400_000;

fn modulus_from_hex(s: &str) -> [u8; 256] {
    let mut out = [0u8; 256];
    for i in 0..256 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn modulus() -> [u8; 256] {
    modulus_from_hex(MODULUS_HEX)
}

fn measurement() -> [u8; 48] {
    let mut m = [0u8; 48];
    m[..32].fill(0xab);
    m
}

fn funded(owner: Pubkey, data: Vec<u8>) -> Account {
    Account {
        lamports: 100_000_000,
        owner,
        data,
        ..Account::default()
    }
}

fn registry_bytes(authority: [u8; 32], bump: u8) -> Vec<u8> {
    let mut measurements = [[0u8; 48]; 8];
    measurements[0] = measurement();
    let registry = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority,
        ark_pubkey_xy: [0u8; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 1,
        measurements,
        bump,
    };
    let mut data = vec![0u8; PolicyRegistry::SIZE];
    registry.serialize(&mut &mut data[..]).unwrap();
    data
}

fn register_data(kid: &[u8], modulus: [u8; 256]) -> Vec<u8> {
    let mut data = REGISTER_JWKS_KEY_DISCRIMINATOR.to_vec();
    RegisterJwksKeyArgs {
        kid: kid.to_vec(),
        modulus,
        exponent: RSA_EXPONENT,
    }
    .serialize(&mut data)
    .unwrap();
    data
}

fn verify_data(mode: u8, jwt: &str, nonce_slot: u64, expected_action_hash: [u8; 32]) -> Vec<u8> {
    let mut data = VERIFY_GOOGLE_JWT_DISCRIMINATOR.to_vec();
    VerifyGoogleJwtArgs {
        mode,
        nonce_slot,
        expected_action_hash,
        jwt: jwt.to_string(),
    }
    .serialize(&mut data)
    .unwrap();
    data
}

/// Mode A binding: SHA-256(workload pubkey || slot hash).
fn mode_a_seed(pubkey: &[u8; 32], slot_hash: &[u8; 32]) -> [u8; 32] {
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(pubkey);
    raw[32..].copy_from_slice(slot_hash);
    eat_nonce_tombstone_seed(&raw)
}

/// A started bank with the real verifier bytecode, a populated policy registry,
/// a source-3 backend policy, and `Clock` / `SlotHashes` pinned to what the
/// token fixtures commit to.
struct Env {
    ctx: ProgramTestContext,
    pid: Pubkey,
    authority: Keypair,
    registry: Pubkey,
    jwks: Pubkey,
    clock: Clock,
    slots: SlotHashes,
}

/// `tenant` absent means no `GcpTenantPolicy` account exists, which the caller
/// pairs with dropping its `AccountMeta`.
async fn boot(pid: Pubkey, tenant: Option<(&[u8], &[u8])>, preload: Vec<(Pubkey, Account)>) -> Env {
    let authority = Keypair::new();
    let (registry, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (jwks, _) = Pubkey::find_program_address(
        &[
            solana_confidential_compute_crypto::jwt::JWKS_SEED,
            &kid_hash(KID),
        ],
        &pid,
    );
    let (backend, backend_bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[3]], &pid);
    let (tenant_key, tenant_bump) = Pubkey::find_program_address(&[GcpTenantPolicy::SEED], &pid);

    let mut pt = sbf::verifier_program_test(pid);
    pt.add_program(
        "confidential_compute_jwt_consumer",
        CONSUMER_ID,
        solana_program_test::processor!(consumer),
    );
    pt.add_account(authority.pubkey(), funded(system_program::ID, vec![]));
    pt.add_account(
        registry,
        funded(
            pid,
            registry_bytes(authority.pubkey().to_bytes(), registry_bump),
        ),
    );
    let mut measurements = [[0u8; 48]; 8];
    measurements[0] = measurement();
    pt.add_account(
        backend,
        funded(
            pid,
            borsh::to_vec(&BackendPolicy {
                discriminator: BackendPolicy::DISCRIMINATOR,
                source: 3,
                measurement_count: 1,
                measurements,
                bump: backend_bump,
            })
            .unwrap(),
        ),
    );
    if let Some((aud, sub)) = tenant {
        pt.add_account(
            tenant_key,
            funded(
                pid,
                borsh::to_vec(&GcpTenantPolicy::new(aud, sub, tenant_bump).unwrap()).unwrap(),
            ),
        );
    }
    for (key, account) in preload {
        pt.add_account(key, account);
    }

    let mut env = Env {
        ctx: pt.start_with_context().await,
        pid,
        authority,
        registry,
        jwks,
        clock: Clock::default(),
        slots: SlotHashes::default(),
    };
    env.pin(CURRENT_SLOT, UNIX_NOW, NONCE_SLOT, MODE_A_SLOT_HASH);
    env
}

/// No-op stand-in for the mode B consumer program the commitment binds to.
/// It never reads a sysvar, so it stays on the native `processor!` path.
fn consumer(
    _: &Pubkey,
    _: &[solana_program::account_info::AccountInfo],
    _: &[u8],
) -> solana_program::entrypoint::ProgramResult {
    Ok(())
}

struct Outcome {
    result: Result<(), TransactionError>,
    logs: Vec<String>,
}

impl Outcome {
    fn ok(&self) {
        assert_eq!(self.result, Ok(()), "{:#?}", self.logs);
    }
    /// Every verify/register instruction in this file sits at index 1, behind
    /// the compute budget request.
    fn err(&self, e: ProgramError) {
        let expected = match e {
            ProgramError::Custom(c) => InstructionError::Custom(c),
            other => InstructionError::from(u64::from(other)),
        };
        assert_eq!(
            self.result,
            Err(TransactionError::InstructionError(1, expected)),
            "{:#?}",
            self.logs
        );
    }
    /// `sol_log_data` fields become one space-separated base64 token each.
    fn registrations(&self) -> Vec<Vec<Vec<u8>>> {
        self.logs
            .iter()
            .filter_map(|line| line.strip_prefix("Program data: "))
            .map(|rest| {
                rest.split_whitespace()
                    .map(|token| STANDARD.decode(token).expect("base64"))
                    .collect::<Vec<Vec<u8>>>()
            })
            .filter(|fields| {
                fields.first().map(Vec::as_slice)
                    == Some(b"solana-confidential-compute:registration:v1".as_slice())
            })
            .collect()
    }
    fn assert_no_registration(&self) {
        assert!(
            self.registrations().is_empty(),
            "failed call emitted a registration event"
        );
    }
}

impl Env {
    fn pin(&mut self, slot: u64, unix_timestamp: i64, nonce_slot: u64, hash: [u8; 32]) {
        self.clock = Clock {
            slot,
            epoch_start_timestamp: 0,
            epoch: 0,
            leader_schedule_epoch: 0,
            unix_timestamp,
        };
        self.slots = SlotHashes::new(&[(nonce_slot, Hash::new_from_array(hash))]);
        self.apply();
    }

    fn apply(&self) {
        self.ctx.set_sysvar(&self.clock);
        self.ctx.set_sysvar(&self.slots);
    }

    /// Advancing the blockhash keeps otherwise-identical replays distinct. It
    /// registers a hash on the same working bank rather than building a new
    /// one, but the pinned sysvars are re-applied anyway.
    async fn send(&mut self, ix: Instruction) -> Outcome {
        self.submit(&[ix], None, false).await
    }

    async fn send_authority(&mut self, ix: Instruction) -> Outcome {
        self.submit(&[ix], None, true).await
    }

    async fn send_signed(&mut self, ix: Instruction, extra: &Keypair) -> Outcome {
        self.submit(&[ix], Some(extra), false).await
    }

    async fn send_all(&mut self, ixs: &[Instruction]) -> Outcome {
        self.submit(ixs, None, false).await
    }

    async fn submit(
        &mut self,
        ixs: &[Instruction],
        extra: Option<&Keypair>,
        authority: bool,
    ) -> Outcome {
        self.ctx.last_blockhash = self.ctx.get_new_latest_blockhash().await.unwrap();
        self.apply();
        let mut all = vec![ComputeBudgetInstruction::set_compute_unit_limit(CU_LIMIT)];
        all.extend_from_slice(ixs);
        let mut tx = Transaction::new_unsigned(Message::new(&all, Some(&self.ctx.payer.pubkey())));
        let mut signers: Vec<&Keypair> = vec![&self.ctx.payer];
        if authority {
            signers.push(&self.authority);
        }
        signers.extend(extra);
        tx.partial_sign(&signers, self.ctx.last_blockhash);
        let done = self
            .ctx
            .banks_client
            .process_transaction_with_metadata(tx)
            .await
            .unwrap();
        Outcome {
            result: done.result,
            logs: done.metadata.map(|m| m.log_messages).unwrap_or_default(),
        }
    }

    async fn account(&self, key: Pubkey) -> Option<Account> {
        self.ctx.banks_client.get_account(key).await.unwrap()
    }

    async fn data(&self, key: Pubkey) -> Vec<u8> {
        self.account(key).await.expect("account").data
    }

    fn register_ix(&self, kid: &[u8], modulus: [u8; 256]) -> Instruction {
        self.register_ix_as(&self.authority.pubkey(), kid, modulus)
    }

    fn register_ix_as(&self, authority: &Pubkey, kid: &[u8], modulus: [u8; 256]) -> Instruction {
        let (jwks, _) = Pubkey::find_program_address(
            &[
                solana_confidential_compute_crypto::jwt::JWKS_SEED,
                &kid_hash(kid),
            ],
            &self.pid,
        );
        Instruction {
            program_id: self.pid,
            accounts: vec![
                AccountMeta::new_readonly(*authority, true),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(jwks, false),
                AccountMeta::new(self.ctx.payer.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: register_data(kid, modulus),
        }
    }

    fn revoke_ix(&self, jwks: Pubkey, kid_hash: [u8; 32]) -> Instruction {
        let mut data = REVOKE_JWKS_KEY_DISCRIMINATOR.to_vec();
        RevokeJwksKeyArgs { kid_hash }.serialize(&mut data).unwrap();
        Instruction {
            program_id: self.pid,
            accounts: vec![
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(jwks, false),
            ],
            data,
        }
    }

    /// `[attested_signer, registry, jwks, used_nonce, payer, system, clock,
    /// slot_hashes, workload|instructions, tenant, backend(3), legacy_nonce]`.
    /// The last three replace what `source_policy.rs` / `legacy_nonce.rs` /
    /// `process_with_tenant` used to inject behind the test's back.
    fn verify_metas(
        &self,
        signer: Pubkey,
        seed: &[u8; 32],
        ninth: AccountMeta,
    ) -> Vec<AccountMeta> {
        let (used, _) = Pubkey::find_program_address(&[b"nonce", &[3], seed], &self.pid);
        let legacy = Pubkey::find_program_address(&[b"nonce", seed], &self.pid).0;
        vec![
            AccountMeta::new(signer, false),
            AccountMeta::new_readonly(self.registry, false),
            AccountMeta::new_readonly(self.jwks, false),
            AccountMeta::new(used, false),
            AccountMeta::new(self.ctx.payer.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(clock::ID, false),
            AccountMeta::new_readonly(slot_hashes::ID, false),
            ninth,
            AccountMeta::new_readonly(
                Pubkey::find_program_address(&[GcpTenantPolicy::SEED], &self.pid).0,
                false,
            ),
            AccountMeta::new_readonly(
                Pubkey::find_program_address(&[BackendPolicy::SEED, &[3]], &self.pid).0,
                false,
            ),
            AccountMeta::new_readonly(legacy, false),
        ]
    }

    /// Mode A verify against a workload key the test cannot sign for.
    fn mode_a_ix(
        &self,
        jwt: &str,
        nonce_slot: u64,
        workload: Pubkey,
        seed: &[u8; 32],
    ) -> Instruction {
        let (signer, _) =
            Pubkey::find_program_address(&[b"attested_signer_v2", workload.as_ref()], &self.pid);
        Instruction {
            program_id: self.pid,
            accounts: self.verify_metas(signer, seed, AccountMeta::new_readonly(workload, true)),
            data: verify_data(VERIFY_GOOGLE_JWT_MODE_A, jwt, nonce_slot, [0u8; 32]),
        }
    }

    fn mode_b_ix(&self, nonce_slot: u64, action: [u8; 32], seed: &[u8; 32]) -> Instruction {
        Instruction {
            program_id: self.pid,
            accounts: self.verify_metas(
                Pubkey::new_unique(),
                seed,
                AccountMeta::new_readonly(instructions::ID, false),
            ),
            data: verify_data(VERIFY_GOOGLE_JWT_MODE_B, MODE_B_JWT, nonce_slot, action),
        }
    }

    fn used_nonce(&self, seed: &[u8; 32]) -> Pubkey {
        Pubkey::find_program_address(&[b"nonce", &[3], seed], &self.pid).0
    }

    fn signer_pda(&self, workload: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[b"attested_signer_v2", workload.as_ref()], &self.pid).0
    }
}

fn assert_registration(out: &Outcome, subject: &[u8], account: Pubkey, data: &[u8]) {
    let observed = out.registrations();
    assert_eq!(observed.len(), 1, "one success event per registration");
    assert_eq!(
        observed[0],
        vec![
            b"solana-confidential-compute:registration:v1".to_vec(),
            b"register_signer".to_vec(),
            b"gcp_confidential_space".to_vec(),
            subject.to_vec(),
            account.to_bytes().to_vec(),
            hashv(&[data]).to_bytes().to_vec(),
        ]
    );
}

#[test]
fn test_jwks_account_size() {
    let account = JwksAccount::new([1u8; 32], [2u8; 256], RSA_EXPONENT, 3, [4u8; 256], 5, 6);
    let mut buf = Vec::new();
    account.serialize(&mut buf).unwrap();
    assert_eq!(buf.len(), JwksAccount::SIZE);
    assert_eq!(JwksAccount::SIZE, 574);
}

#[tokio::test]
async fn test_register_jwks_and_verify_mode_a() {
    mode_a_tenant_case(EXPECTED_AUDIENCE, EXPECTED_SUBJECT, true, true).await;
}

#[tokio::test]
async fn rejects_signed_token_for_wrong_or_missing_tenant_before_writes() {
    mode_a_tenant_case(b"foreign-audience", EXPECTED_SUBJECT, true, false).await;
    mode_a_tenant_case(EXPECTED_AUDIENCE, b"foreign-subject", true, false).await;
    mode_a_tenant_case(EXPECTED_AUDIENCE, EXPECTED_SUBJECT, false, false).await;
}

async fn mode_a_tenant_case(aud: &[u8], sub: &[u8], present: bool, accepted: bool) {
    let pid = Pubkey::new_unique();
    let workload = Pubkey::new_from_array(MODE_A_SLOT_HASH);
    let mut env = boot(pid, present.then_some((aud, sub)), vec![]).await;

    env.send_authority(env.register_ix(KID, modulus()))
        .await
        .ok();
    let saved_jwks = JwksAccount::try_from_slice(&env.data(env.jwks).await).unwrap();
    assert_eq!(saved_jwks.discriminator, JWKS_ACCOUNT_DISCRIMINATOR);
    assert_eq!(saved_jwks.kid_hash, kid_hash(KID));
    assert_eq!(saved_jwks.exponent, RSA_EXPONENT);
    assert!(!saved_jwks.is_revoked);
    assert_eq!(saved_jwks.registered_slot, CURRENT_SLOT);

    let seed = eat_nonce_tombstone_seed(EAT_NONCE);
    let mut ix = env.mode_a_ix(VALID_JWT, NONCE_SLOT, workload, &seed);
    if !present {
        // No tenant account exists, so the policy meta is absent as well.
        ix.accounts.remove(9);
    }
    let signer = env.signer_pda(&workload);
    let nonce = env.used_nonce(&seed);
    let out = env.send(ix.clone()).await;
    if !accepted {
        assert!(
            out.result.is_err(),
            "wrong/missing configured tenant accepted"
        );
        out.assert_no_registration();
        assert!(env.account(signer).await.is_none());
        assert!(env.account(nonce).await.is_none());
        return;
    }
    out.ok();

    let signer_data = env.data(signer).await;
    assert_registration(&out, workload.as_ref(), signer, &signer_data);
    let saved_signer = AttestedSignerAccount::try_from_slice(&signer_data).unwrap();
    assert_eq!(saved_signer.discriminator, ATTESTED_SIGNER_DISCRIMINATOR);
    assert_eq!(saved_signer.record.signer_pubkey, workload.to_bytes());
    assert_eq!(
        saved_signer.record.enclave_type,
        EnclaveType::GcpConfidentialSpace
    );
    assert_eq!(saved_signer.record.measurement.0, measurement());
    assert_eq!(saved_signer.record.registered_slot, CURRENT_SLOT);
    assert_eq!(
        saved_signer.record.expires_slot,
        CURRENT_SLOT + ATTESTATION_TTL_SLOTS
    );

    let saved_nonce = UsedNonceAccount::try_from_slice(&env.data(nonce).await).unwrap();
    assert_eq!(saved_nonce.discriminator, USED_NONCE_DISCRIMINATOR);
    assert_eq!(saved_nonce.slot, CURRENT_SLOT);

    let replay = env.send(ix).await;
    replay.err(VerifierError::NonceAlreadyUsed.into());
    replay.assert_no_registration();
}

#[tokio::test]
async fn test_rejects_non_authority_registering_jwks() {
    let pid = Pubkey::new_unique();
    let attacker = Keypair::new();
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
    let ix = env.register_ix_as(&attacker.pubkey(), KID, modulus());
    env.send_signed(ix, &attacker)
        .await
        .err(VerifierError::InvalidAuthority.into());
    assert!(env.account(env.jwks).await.is_none());
}

/// A revoked key is rejected even with the slot hash the token binds to, so
/// revocation is the only thing standing between the token and admission.
#[tokio::test]
async fn test_rejects_revoked_jwks_key() {
    let pid = Pubkey::new_unique();
    let workload = Pubkey::new_from_array(MODE_A_SLOT_HASH);
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
    env.send_authority(env.register_ix(KID, modulus()))
        .await
        .ok();

    let jwks = env.jwks;
    env.send_authority(env.revoke_ix(jwks, kid_hash(KID)))
        .await
        .ok();
    assert!(
        JwksAccount::try_from_slice(&env.data(jwks).await)
            .unwrap()
            .is_revoked
    );

    let seed = eat_nonce_tombstone_seed(EAT_NONCE);
    let ix = env.mode_a_ix(VALID_JWT, NONCE_SLOT, workload, &seed);
    env.send(ix)
        .await
        .err(VerifierError::UnauthorizedPolicy.into());
}

/// Both halves run against the slot hash the token binds to, so the tampered
/// signature and the out-of-window nonce slot are each the sole cause.
#[tokio::test]
async fn test_rejects_tampered_jwt_and_stale_slot_hash() {
    let pid = Pubkey::new_unique();
    let workload = Pubkey::new_from_array(MODE_A_SLOT_HASH);
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
    env.send_authority(env.register_ix(KID, modulus()))
        .await
        .ok();

    let mut tampered = VALID_JWT.as_bytes().to_vec();
    let view = solana_confidential_compute_crypto::jwt::JwtView::parse(VALID_JWT).expect("parse");
    tampered[view.signing_input.len() + 1] ^= 0x01;
    let tampered_jwt = std::str::from_utf8(&tampered).expect("ascii");

    let seed = eat_nonce_tombstone_seed(EAT_NONCE);
    let out = env
        .send(env.mode_a_ix(tampered_jwt, NONCE_SLOT, workload, &seed))
        .await;
    out.err(VerifierError::InvalidSignature.into());
    out.assert_no_registration();

    let stale = env
        .send(env.mode_a_ix(VALID_JWT, CURRENT_SLOT.saturating_sub(151), workload, &seed))
        .await;
    stale.err(VerifierError::StaleNonce.into());
    stale.assert_no_registration();
    assert!(env.account(env.used_nonce(&seed)).await.is_none());
}

#[tokio::test]
async fn test_rejects_slot_hash_mismatch_in_mode_a() {
    let pid = Pubkey::new_unique();
    let workload = Pubkey::new_from_array(MODE_A_SLOT_HASH);
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
    env.send_authority(env.register_ix(KID, modulus()))
        .await
        .ok();

    // The pinned hash does not match nonce 1, which decodes to [b'n'; 32].
    env.pin(CURRENT_SLOT, UNIX_NOW, NONCE_SLOT, [0x55; 32]);
    let seed = eat_nonce_tombstone_seed(EAT_NONCE);
    env.send(env.mode_a_ix(VALID_JWT, NONCE_SLOT, workload, &seed))
        .await
        .err(VerifierError::SignerMismatch.into());
}

#[tokio::test]
async fn test_rejects_non_owner_revoke_jwks() {
    let pid = Pubkey::new_unique();
    let wrong_owner = Pubkey::new_unique();
    let (jwks, bump) = Pubkey::find_program_address(
        &[
            solana_confidential_compute_crypto::jwt::JWKS_SEED,
            &kid_hash(KID),
        ],
        &pid,
    );
    let (n0, r2) = solana_confidential_compute_crypto::jwt::compute_n0_and_r2(&modulus()).unwrap();
    let live = JwksAccount::new(
        kid_hash(KID),
        modulus(),
        RSA_EXPONENT,
        n0,
        r2,
        CURRENT_SLOT,
        bump,
    );
    let mut env = boot(
        pid,
        Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)),
        vec![(jwks, funded(wrong_owner, borsh::to_vec(&live).unwrap()))],
    )
    .await;

    env.send_authority(env.revoke_ix(jwks, kid_hash(KID)))
        .await
        .err(VerifierError::InvalidAccountAddress.into());
    assert_eq!(
        JwksAccount::try_from_slice(&env.data(jwks).await).unwrap(),
        live
    );
}

/// A live SEV-SNP session cannot be re-typed by a JWT, and a governance
/// tombstone stays closed. Unlike the native harness, the bank rolls back the
/// nonce write from the rejected first attempt, so the second attempt no
/// longer needs the test to zero the nonce account by hand.
#[tokio::test]
async fn test_rejects_session_enclave_type_overwrite() {
    let pid = Pubkey::new_unique();
    let workload = Pubkey::new_from_array(MODE_A_SLOT_HASH);
    let (signer, signer_bump) =
        Pubkey::find_program_address(&[b"attested_signer_v2", workload.as_ref()], &pid);
    let existing = AttestedSignerAccount::new(
        solana_confidential_compute_core::types::AttestedSigner {
            signer_pubkey: MODE_A_SLOT_HASH,
            enclave_type: EnclaveType::AmdSevSnp,
            measurement: solana_confidential_compute_core::types::MeasurementDigest(measurement()),
            chip_id_hash: [0u8; 32],
            tcb_version: 0,
            registered_slot: CURRENT_SLOT,
            expires_slot: CURRENT_SLOT + 1000,
        },
        signer_bump,
    );
    let mut env = boot(
        pid,
        Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)),
        vec![(signer, funded(pid, borsh::to_vec(&existing).unwrap()))],
    )
    .await;
    env.send_authority(env.register_ix(KID, modulus()))
        .await
        .ok();

    let seed = eat_nonce_tombstone_seed(EAT_NONCE);
    let ix = env.mode_a_ix(VALID_JWT, NONCE_SLOT, workload, &seed);
    env.send(ix.clone())
        .await
        .err(ProgramError::AccountAlreadyInitialized);
    assert!(env.account(env.used_nonce(&seed)).await.is_none());

    let mut revoked = existing;
    revoked.record.enclave_type = EnclaveType::GcpConfidentialSpace;
    revoked.record.expires_slot = 0;
    revoked.expires_unix_timestamp = 86_400;
    env.ctx.set_account(
        &signer,
        &solana_sdk::account::AccountSharedData::from(funded(
            pid,
            borsh::to_vec(&revoked).unwrap(),
        )),
    );
    env.send(ix)
        .await
        .err(VerifierError::UnauthorizedPolicy.into());
    assert_eq!(
        AttestedSignerAccount::try_from_slice(&env.data(signer).await).unwrap(),
        revoked
    );
}

#[tokio::test]
async fn test_verify_google_jwt_mode_b_success_and_mismatch() {
    let pid = Pubkey::new_unique();
    let slot_hash = [0x11u8; 32];
    let consumer_data = [0x99u8; 11];
    // Full-wire V3 action chosen to retain the high-bit raw commitment control.
    let action = solana_confidential_compute_core::action::hash_action_parts(
        &[],
        0,
        core::iter::empty(),
        &consumer_data,
    );
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
    env.pin(CURRENT_SLOT, UNIX_NOW, NONCE_SLOT, slot_hash);
    env.send_authority(env.register_ix(KID, modulus_from_hex(MODE_B_MODULUS_HEX)))
        .await
        .ok();

    let view =
        solana_confidential_compute_crypto::jwt::JwtView::parse(MODE_B_JWT).expect("parse view");
    let claims = solana_confidential_compute_crypto::jwt::parse_google_claims_b64(view.payload_b64)
        .expect("claims");
    let raw = claims.decode_mode_b_commitment().expect("mode b nonce");
    assert_eq!(claims.eat_nonce().len(), 43);
    assert_ne!(raw[0] & 0x80, 0);
    assert_ne!(&claims.eat_nonce()[..32], &raw[..]);
    assert_eq!(
        raw,
        solana_confidential_compute_core::types::compute_action_commitment(
            &slot_hash,
            &action,
            &CONSUMER_ID.to_bytes()
        )
    );
    let seed = eat_nonce_tombstone_seed(&raw);
    let nonce = env.used_nonce(&seed);

    let verify = env.mode_b_ix(NONCE_SLOT, action, &seed);
    let consume = |data: Vec<u8>| Instruction {
        program_id: CONSUMER_ID,
        accounts: vec![],
        data,
    };

    // A substituted consumer instruction must fail before nonce writes.
    let mut substituted = consumer_data;
    substituted[0] ^= 1;
    env.send_all(&[verify.clone(), consume(substituted.to_vec())])
        .await
        .err(VerifierError::ActionHashMismatch.into());
    assert!(env.account(nonce).await.is_none());

    env.send_all(&[verify.clone(), consume(consumer_data.to_vec())])
        .await
        .ok();
    let saved = UsedNonceAccount::try_from_slice(&env.data(nonce).await).unwrap();
    assert_eq!(saved.discriminator, USED_NONCE_DISCRIMINATOR);
    assert_eq!(saved.slot, CURRENT_SLOT);

    env.send_all(&[verify, consume(consumer_data.to_vec())])
        .await
        .err(VerifierError::NonceAlreadyUsed.into());

    let mismatch = env.mode_b_ix(NONCE_SLOT, [0xfe; 32], &seed);
    env.send_all(&[mismatch, consume(consumer_data.to_vec())])
        .await
        .err(VerifierError::ActionHashMismatch.into());
}

#[tokio::test]
async fn test_verify_google_jwt_rejects_foreign_jwks_owner() {
    let pid = Pubkey::new_unique();
    let wrong_owner = Pubkey::new_unique();
    let foreign = Pubkey::new_unique();
    let mut env = boot(
        pid,
        Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)),
        vec![(foreign, funded(wrong_owner, vec![0u8; JwksAccount::SIZE]))],
    )
    .await;
    let seed = eat_nonce_tombstone_seed(EAT_NONCE);
    let mut ix = env.mode_a_ix("", NONCE_SLOT, Pubkey::new_unique(), &seed);
    ix.accounts[2] = AccountMeta::new_readonly(foreign, false);
    env.send(ix).await.err(ProgramError::IllegalOwner);
}

#[tokio::test]
async fn test_mode_a_accepts_high_bit_pubkey_base64url_nonces() {
    let pid = Pubkey::new_unique();
    let workload_bytes = [
        0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    assert_ne!(workload_bytes[0] & 0x80, 0);
    let workload = Pubkey::new_from_array(workload_bytes);
    let slot_hash = [0x5au8; 32];
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
    env.send_authority(env.register_ix(KID, modulus()))
        .await
        .ok();
    env.pin(CURRENT_SLOT, UNIX_NOW, NONCE_SLOT, slot_hash);

    let seed = mode_a_seed(&workload_bytes, &slot_hash);
    env.send(env.mode_a_ix(HIGH_BIT_JWT, NONCE_SLOT, workload, &seed))
        .await
        .ok();
    let saved =
        AttestedSignerAccount::try_from_slice(&env.data(env.signer_pda(&workload)).await).unwrap();
    assert_eq!(saved.record.signer_pubkey, workload_bytes);
    assert_ne!(saved.record.signer_pubkey[0] & 0x80, 0);
    assert_eq!(saved.record.enclave_type, EnclaveType::GcpConfidentialSpace);
}

#[tokio::test]
async fn test_rejects_nul_kid_registration_before_writes() {
    let pid = Pubkey::new_unique();
    let kid = b"teton-test\0suffix".to_vec();
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
    let ix = env.register_ix(&kid, modulus());
    let jwks = ix.accounts[2].pubkey;
    env.send_authority(ix)
        .await
        .err(VerifierError::InvalidInstruction.into());
    assert!(env.account(jwks).await.is_none());
}

#[tokio::test]
async fn issue_170_jwks_freshness_boundary() {
    for age in [216_000u64, 216_001] {
        let pid = Pubkey::new_unique();
        let workload = Pubkey::new_from_array(MODE_A_SLOT_HASH);
        let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
        env.send_authority(env.register_ix(KID, modulus()))
            .await
            .ok();
        let saved_jwks = JwksAccount::try_from_slice(&env.data(env.jwks).await).unwrap();
        assert_eq!(saved_jwks.discriminator, JWKS_ACCOUNT_DISCRIMINATOR);
        assert_eq!(saved_jwks.kid_hash, kid_hash(KID));
        assert_eq!(saved_jwks.exponent, RSA_EXPONENT);
        assert!(!saved_jwks.is_revoked);
        assert_eq!(saved_jwks.registered_slot, CURRENT_SLOT);

        env.pin(
            CURRENT_SLOT + age,
            UNIX_NOW,
            NONCE_SLOT + age,
            MODE_A_SLOT_HASH,
        );
        let seed = eat_nonce_tombstone_seed(EAT_NONCE);
        let out = env
            .send(env.mode_a_ix(VALID_JWT, NONCE_SLOT + age, workload, &seed))
            .await;
        if age <= JwksAccount::MAX_AGE_SLOTS {
            out.ok();
        } else {
            out.err(VerifierError::UnauthorizedPolicy.into());
        }
    }
}

/// Seats `existing` at the JWKS PDA, then replays the governance refresh.
async fn issue_170_refresh_attempt(
    env: &mut Env,
    modulus: [u8; 256],
    existing: &JwksAccount,
    expected: Result<(), ProgramError>,
) -> JwksAccount {
    let jwks = env.jwks;
    env.ctx.set_account(
        &jwks,
        &solana_sdk::account::AccountSharedData::from(funded(
            env.pid,
            borsh::to_vec(existing).unwrap(),
        )),
    );
    let out = env.send_authority(env.register_ix(KID, modulus)).await;
    match expected {
        Ok(()) => out.ok(),
        Err(e) => out.err(e),
    }
    JwksAccount::try_from_slice(&env.data(jwks).await).unwrap()
}

#[tokio::test]
async fn issue_170_governance_refresh_preserves_revocation_and_live_keys() {
    let pid = Pubkey::new_unique();
    let (_, bump) = Pubkey::find_program_address(&[b"jwks", &kid_hash(KID)], &pid);
    let (n0, r2) = solana_confidential_compute_crypto::jwt::compute_n0_and_r2(&modulus()).unwrap();
    let expired = JwksAccount::new(kid_hash(KID), modulus(), RSA_EXPONENT, n0, r2, 500, bump);
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
    env.pin(216_501, UNIX_NOW, NONCE_SLOT, MODE_A_SLOT_HASH);

    let refreshed = issue_170_refresh_attempt(&mut env, modulus(), &expired, Ok(())).await;
    assert_eq!(refreshed.registered_slot, 216_501);
    for kind in 0..4 {
        let mut old = expired.clone();
        if kind == 0 {
            old.registered_slot = 216_501;
        }
        if kind == 1 {
            old.is_revoked = true;
        }
        if kind == 2 {
            old.registered_slot = u64::MAX;
        }
        let mut replacement = modulus();
        if kind == 3 {
            replacement[1] ^= 1;
        }
        let after = issue_170_refresh_attempt(
            &mut env,
            replacement,
            &old,
            Err(ProgramError::AccountAlreadyInitialized),
        )
        .await;
        assert_eq!(after, old, "kind {kind}");
    }
}

#[tokio::test]
async fn issue_194_revoked_kid_accepts_different_replacement_not_compromised_key() {
    let pid = Pubkey::new_unique();
    let (_, bump) = Pubkey::find_program_address(&[b"jwks", &kid_hash(KID)], &pid);
    let (n0, r2) = solana_confidential_compute_crypto::jwt::compute_n0_and_r2(&modulus()).unwrap();
    let mut revoked = JwksAccount::new(kid_hash(KID), modulus(), RSA_EXPONENT, n0, r2, 500, bump);
    revoked.is_revoked = true;
    let replacement = modulus_from_hex(MODE_B_MODULUS_HEX);
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;

    let saved = issue_170_refresh_attempt(&mut env, replacement, &revoked, Ok(())).await;
    assert!(!saved.is_revoked);
    assert_eq!(saved.modulus, replacement);
    assert_eq!(saved.registered_slot, CURRENT_SLOT);

    let after = issue_170_refresh_attempt(
        &mut env,
        modulus(),
        &revoked,
        Err(ProgramError::AccountAlreadyInitialized),
    )
    .await;
    assert_eq!(after, revoked);
}

/// The global registry allowlist is not a substitute for the source-3 backend
/// policy; without that account the token is refused.
#[tokio::test]
async fn issue_183_requires_source_scoped_policy() {
    let pid = Pubkey::new_unique();
    let workload = Pubkey::new_from_array(MODE_A_SLOT_HASH);
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
    env.send_authority(env.register_ix(KID, modulus()))
        .await
        .ok();

    let seed = eat_nonce_tombstone_seed(EAT_NONCE);
    let mut ix = env.mode_a_ix(VALID_JWT, NONCE_SLOT, workload, &seed);
    ix.accounts.remove(10); // source-3 backend policy
    env.send(ix)
        .await
        .err(VerifierError::UnauthorizedPolicy.into());
    assert!(env.account(env.signer_pda(&workload)).await.is_none());
}

#[tokio::test]
async fn issue_182_session_cannot_outlive_jwt_in_unix_time() {
    let pid = Pubkey::new_unique();
    let workload = Pubkey::new_from_array(MODE_A_SLOT_HASH);
    let mut env = boot(pid, Some((EXPECTED_AUDIENCE, EXPECTED_SUBJECT)), vec![]).await;
    env.send_authority(env.register_ix(KID, modulus()))
        .await
        .ok();
    env.pin(CURRENT_SLOT, 4_102_444_799, NONCE_SLOT, MODE_A_SLOT_HASH);

    let seed = eat_nonce_tombstone_seed(EAT_NONCE);
    env.send(env.mode_a_ix(VALID_JWT, NONCE_SLOT, workload, &seed))
        .await
        .ok();
    let bytes = env.data(env.signer_pda(&workload)).await;
    let deadline = bytes
        .get(146..154)
        .map(|s| i64::from_le_bytes(s.try_into().unwrap()));
    assert_eq!(deadline, Some(4_102_444_800)); // JWT has one second remaining
}
