//! Every TDX enrolment PDA is really allocated, from a genuinely empty
//! account, by real SBF bytecode.
//!
//! WHAT THIS PROVES, AND WHY NOTHING ELSE DID.
//!
//! `Processor::create_pda_if_needed` has two arms. If the account already has
//! `data_len == space` it returns early and never touches a sysvar. Only if
//! `data_len == 0` does it call `Rent::get()` and CPI into the system program
//! to allocate. Live enrolment always takes the second arm: on chain the
//! challenge, session, used-nonce and attested-signer PDAs start as nothing
//! at all.
//!
//! Every existing TDX test takes the first arm. `tdx_handler_tests.rs` builds
//! each PDA as `account(key, pid, false, true, vec![0; T::SIZE])` -- allocated
//! to the exact size and already owned by the program -- and
//! `tdx_compute_units.rs` (itself `#[ignore]`d) pre-seeds its session and
//! challenge accounts the same way. Both therefore return at the early arm and
//! never reach `Rent::get()`.
//!
//! That matters under solana 4.x specifically. `Sysvar::get()` now resolves
//! through `solana_get_sysvar::sol_get_sysvar`, whose `not(target_os =
//! "solana")` branch is a hardcoded `UNSUPPORTED_SYSVAR` with no
//! `program_stubs` hook -- so a natively linked program cannot read Rent at
//! all, and the allocating arm cannot even execute off chain. The whole TDX
//! enrolment path had therefore never been shown to allocate anything.
//!
//! This test starts from accounts that do not exist -- not pre-allocated, not
//! pre-funded, not program-owned -- drives `issue_tdx_challenge` and then the
//! full `verify_tdx_qe_report` + `verify_tdx_quote` enrolment through the
//! compiled `.so`, and asserts afterwards that each PDA exists with the right
//! owner, the right length, and a balance the bank's own `Rent` calls exempt.
//!
//! The instructions are built with the client SDK (`solana_confidential_compute_sdk::tdx`) rather
//! than hand-packed, so the account order and PDA derivations a real caller
//! uses are exercised too.
//!
//! The cryptography is genuine but not Intel's. The quote fixture supplies the
//! QE report, the TD body and the measurements; the two signatures are
//! re-made with locally generated P-256 keys, because the secp256r1 precompile
//! really runs here and Intel's private keys are not available. The QE
//! report's REPORTDATA is re-bound to the local attestation key for the same
//! reason. Allowlisting those keys is what governance does for a real
//! platform, and none of it touches the allocation arm under test.
//!
//! The negative control is
//! [`native_linkage_cannot_allocate_but_a_preallocated_pda_hides_it`]: the same
//! instruction, from the same empty account, against the *natively linked*
//! processor, must fail inside `Rent::get()` -- and then succeed as soon as the
//! PDA is pre-allocated the way the existing tests do it. If the SBF harness
//! here were silently taking the early-return arm, that control would pass on
//! the first case too.
//!
//! @spec SCC-TDX-001 SCC-TDX-002 SCC-TDX-005 SCC-ARCH-001

use {
    borsh::BorshDeserialize,
    p256::ecdsa::{signature::Signer as _, SigningKey},
    solana_confidential_compute_sdk::tdx as sdk,
    solana_confidential_compute_verifier::{
        error::VerifierError,
        payload::TDX_ATTESTATION_SOURCE,
        processor::Processor,
        state::{
            AttestedSignerAccount, BackendPolicy, ChallengeAccount, TdxSessionAccount, UsedNonceAccount,
            ATTESTED_SIGNER_DISCRIMINATOR, USED_NONCE_DISCRIMINATOR,
        },
        tdx::{
            expected_report_data, qe_identity_digest, td_platform_digest, TdxQuote, QE_REPORT_DATA_OFFSET,
            QUOTE_HEADER_LEN,
        },
    },
    solana_program::hash::hashv,
    solana_program_test::{processor, ProgramTest, ProgramTestContext},
    solana_sdk::{
        account::Account,
        instruction::InstructionError,
        pubkey::Pubkey,
        rent::Rent,
        signature::{Keypair, Signer},
        sysvar::slot_hashes,
        transaction::{Transaction, TransactionError, VersionedTransaction},
    },
};

#[path = "common/sbf.rs"]
mod sbf;

const QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote_v4.bin");
const GPU_RIM: [u8; 32] = [0x33; 32];
const MODEL: [u8; 32] = [0x44; 32];
const CHALLENGE_NONCE: [u8; 32] = [0x42; 32];
/// `verify_tdx_qe_report` plus `verify_tdx_quote` measure at roughly 20k and
/// 60k CU; v1 carries the limit as a message field, and `None` means zero.
const COMPUTE_UNIT_LIMIT: u32 = 400_000;
/// Also a v1 message field, and also zero when unset -- an enrolment that
/// leaves it out is rejected with `MaxLoadedAccountsDataSizeExceeded` before
/// the program runs. The verifier's own `.so` is ~630 KiB of that budget.
const LOADED_ACCOUNTS_DATA_SIZE_LIMIT: u32 = 2 * 1024 * 1024;
/// Offset of REPORTDATA inside the TD report body, relative to the quote.
const TD_REPORT_DATA: usize = QUOTE_HEADER_LEN + 520;

// ---------------------------------------------------------------------------
// P-256 helpers
// ---------------------------------------------------------------------------

/// A deterministic P-256 key. Fixed seeds keep PDA derivation -- and therefore
/// the bump search -- identical between runs.
fn key(seed_byte: u8) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[31] = seed_byte;
    SigningKey::from_slice(&seed).expect("a valid P-256 scalar")
}

fn compressed(key: &SigningKey) -> [u8; 33] {
    let point = key.verifying_key().to_sec1_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    out
}

/// Uncompressed `X || Y`, the shape a quote carries an attestation key in.
fn uncompressed_xy(key: &SigningKey) -> [u8; 64] {
    let point = key.verifying_key().to_sec1_point(false);
    let mut out = [0u8; 64];
    out.copy_from_slice(&point.as_bytes()[1..]);
    out
}

/// Low-S normalized `r || s`; the precompile rejects the other form.
fn sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    let signature: p256::ecdsa::Signature = key.sign(message);
    let normalized = signature.normalize_s();
    let mut out = [0u8; 64];
    out.copy_from_slice(&normalized.to_bytes());
    out
}

// ---------------------------------------------------------------------------
// Account fixtures and assertions
// ---------------------------------------------------------------------------

fn pad32(v: &[u8; 32]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..32].copy_from_slice(v);
    out
}

fn pad33(v: &[u8; 33]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..33].copy_from_slice(v);
    out
}

/// The source-5 allowlist, as governance would have seated it.
///
/// This is the one account the test injects. It is deliberately not a PDA the
/// enrolment path allocates -- `set_backend_policy` creates it, and seating it
/// here does not touch any arm of `create_pda_if_needed`.
fn policy_account(program_id: &Pubkey, measurements: &[[u8; 48]], bump: u8) -> Account {
    let mut slots = [[0u8; 48]; 8];
    for (slot, m) in slots.iter_mut().zip(measurements) {
        *slot = *m;
    }
    let record = BackendPolicy {
        discriminator: BackendPolicy::DISCRIMINATOR,
        source: TDX_ATTESTATION_SOURCE,
        measurement_count: measurements.len().min(8) as u32,
        measurements: slots,
        bump,
    };
    Account {
        lamports: 10_000_000,
        data: borsh::to_vec(&record).unwrap(),
        owner: *program_id,
        executable: false,
        rent_epoch: 0,
    }
}

/// Assert the account does not exist at all: no lamports, no data, no owner.
///
/// This is what makes the test non-vacuous. If any of these were already
/// allocated, `create_pda_if_needed` would return at its early arm and the
/// allocation this test exists to prove would never be attempted.
async fn assert_absent(ctx: &mut ProgramTestContext, key: Pubkey, label: &str) {
    assert!(
        ctx.banks_client.get_account(key).await.unwrap().is_none(),
        "{label} must start as a genuinely empty system account",
    );
}

/// Assert the PDA was allocated by the program and is rent exempt.
async fn assert_allocated(
    ctx: &mut ProgramTestContext,
    key: Pubkey,
    program_id: &Pubkey,
    space: usize,
    label: &str,
) -> Vec<u8> {
    let rent: Rent = ctx.banks_client.get_sysvar().await.unwrap();
    let account =
        ctx.banks_client.get_account(key).await.unwrap().unwrap_or_else(|| panic!("{label} was never allocated"));
    assert_eq!(&account.owner, program_id, "{label} has the wrong owner");
    assert_eq!(account.data.len(), space, "{label} has the wrong length");
    assert!(
        rent.is_exempt(account.lamports, account.data.len()),
        "{label} holds {} lamports, below the {} the bank's rent requires for {} bytes",
        account.lamports,
        rent.minimum_balance(account.data.len()),
        account.data.len(),
    );
    assert_eq!(
        account.lamports,
        rent.minimum_balance(space),
        "{label} was not funded from the bank's own Rent -- a stale or hardcoded \
         minimum balance would show up here",
    );
    account.data
}

/// The most recent slot in the SlotHashes sysvar, which is the only slot
/// `issue_tdx_challenge` will accept a hash for. Parsed the way the program
/// parses it: a `u64` count followed by 40-byte `(slot, hash)` entries,
/// newest first.
async fn newest_slot_hash_slot(ctx: &mut ProgramTestContext) -> u64 {
    let data =
        ctx.banks_client.get_account(slot_hashes::ID).await.unwrap().expect("the SlotHashes sysvar always exists").data;
    let count = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert!(count > 0, "SlotHashes is empty, so no challenge can be issued");
    u64::from_le_bytes(data[8..16].try_into().unwrap())
}

fn instruction_error(err: solana_program_test::BanksClientError) -> InstructionError {
    match err.unwrap() {
        TransactionError::InstructionError(_, e) => e,
        other => panic!("unexpected transaction error: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tdx_enrolment_allocates_every_pda_from_empty_accounts_under_sbf() {
    let program_id = Pubkey::new_unique();
    let workload = Keypair::new_from_array([3u8; 32]);

    // ---- quote material -------------------------------------------------
    //
    // The fixture supplies the QE report, the TD body and the measurements.
    // The signatures are re-made locally: the precompile really executes in
    // this harness, so a made-up signature would be rejected before the
    // program ran and nothing would be measured.
    let quote = TdxQuote::parse(QUOTE).expect("the fixture is a well-formed v4 quote");
    let pck = key(7);
    let attestation = key(11);
    let attestation_xy = uncompressed_xy(&attestation);
    let pck_pubkey = compressed(&pck);

    // Intel binds the QE report to the attestation key through REPORTDATA =
    // SHA-256(attestation_key || qe_auth_data) || 32 zero bytes. The local
    // attestation key needs the same binding or `verify_tdx_qe_report`
    // rejects it. The identity digest the policy allowlists covers
    // ATTRIBUTES, MRSIGNER, ISVPRODID and ISVSVN -- none of which move.
    let qe_auth_data = quote.qe_auth_data().to_vec();
    let mut qe_report = quote.qe_report().to_vec();
    let commitment = hashv(&[&attestation_xy, qe_auth_data.as_slice()]).to_bytes();
    qe_report[QE_REPORT_DATA_OFFSET..QE_REPORT_DATA_OFFSET + 32].copy_from_slice(&commitment);
    qe_report[QE_REPORT_DATA_OFFSET + 32..QE_REPORT_DATA_OFFSET + 64].fill(0);
    let qe_signature = sign(&pck, &qe_report);

    // The platform digest is taken from the pristine body: it covers
    // TEE_TCB_SVN, MRSEAM, TD_ATTRIBUTES, XFAM, MRTD, MRCONFIGID and
    // RTMR0..2, and REPORTDATA -- the only field this test rewrites -- is not
    // among them.
    let platform_digest =
        td_platform_digest(&quote.isv_signed_region()[QUOTE_HEADER_LEN..]).expect("the fixture body parses");

    // ---- runtime --------------------------------------------------------
    let mut pt = sbf::verifier_program_test(program_id);
    let (policy_key, policy_bump) =
        Pubkey::find_program_address(&[BackendPolicy::SEED, &[TDX_ATTESTATION_SOURCE]], &program_id);
    assert_eq!(
        policy_key,
        sdk::derive_tdx_backend_policy_pda(&program_id),
        "the SDK and the program must agree on the source-5 policy address",
    );
    pt.add_account(
        policy_key,
        policy_account(
            &program_id,
            &[
                pad33(&pck_pubkey),
                pad32(&qe_identity_digest(&qe_report).unwrap()),
                pad32(&platform_digest),
                pad32(&GPU_RIM),
            ],
            policy_bump,
        ),
    );
    let mut ctx = pt.start_with_context().await;

    // ---- step 1: issue_tdx_challenge ------------------------------------
    let nonce_slot = newest_slot_hash_slot(&mut ctx).await;
    let (challenge_pda, _) = sdk::derive_tdx_challenge_pda(&program_id, &CHALLENGE_NONCE);
    assert_absent(&mut ctx, challenge_pda, "the challenge PDA").await;

    let issue_ix =
        sdk::build_issue_tdx_challenge_ix_for_program(&program_id, &ctx.payer.pubkey(), &CHALLENGE_NONCE, nonce_slot);
    let tx =
        Transaction::new_signed_with_payer(&[issue_ix], Some(&ctx.payer.pubkey()), &[&ctx.payer], ctx.last_blockhash);
    ctx.banks_client
        .process_transaction(tx)
        .await
        .expect("issue_tdx_challenge must allocate its PDA from an empty account");

    let challenge_data =
        assert_allocated(&mut ctx, challenge_pda, &program_id, ChallengeAccount::SIZE, "the challenge PDA").await;
    let challenge = ChallengeAccount::try_from_slice(&challenge_data).expect("challenge decodes");
    assert_eq!(challenge.discriminator, ChallengeAccount::DISCRIMINATOR);
    assert_eq!(challenge.source, TDX_ATTESTATION_SOURCE);
    assert_eq!(challenge.nonce, CHALLENGE_NONCE);
    assert_eq!(challenge.challenge_slot, nonce_slot);
    assert_ne!(
        challenge.slot_hash, [0u8; 32],
        "the slot hash must come from the SlotHashes sysvar, not from the caller",
    );

    // ---- the enclave answers the challenge ------------------------------
    //
    // Exactly the live ordering: the slot hash is read back out of the
    // account the first transaction wrote, and only then can a quote be bound
    // to it.
    let mut isv_signed = quote.isv_signed_region().to_vec();
    let report_data =
        expected_report_data(&workload.pubkey().to_bytes(), &challenge.slot_hash, &GPU_RIM, &MODEL, &CHALLENGE_NONCE);
    isv_signed[TD_REPORT_DATA..TD_REPORT_DATA + 64].copy_from_slice(&report_data);
    let isv_signature = sign(&attestation, &isv_signed);

    // ---- step 2+3: the enrolment packet ---------------------------------
    let (session_pda, _) = sdk::derive_tdx_session_pda_from_xy(&program_id, &attestation_xy);
    let (nonce_pda, _) = sdk::derive_tdx_quote_nonce_pda(
        &program_id,
        &workload.pubkey(),
        &isv_signed,
        &challenge.slot_hash,
        &CHALLENGE_NONCE,
    )
    .expect("the signed region is the right length");
    let (signer_pda, _) = sdk::derive_attested_signer_pda(&program_id, &workload.pubkey());

    assert_absent(&mut ctx, session_pda, "the session PDA").await;
    assert_absent(&mut ctx, nonce_pda, "the used-nonce PDA").await;
    assert_absent(&mut ctx, signer_pda, "the attested-signer PDA").await;

    let enrolment = sdk::TdxEnrolment {
        payer: ctx.payer.pubkey(),
        workload_signer: workload.pubkey(),
        attestation_pubkey_xy: &attestation_xy,
        pck_pubkey: &pck_pubkey,
        gpu_rim_digest: &GPU_RIM,
        model_digest: &MODEL,
        qe_auth_data: &qe_auth_data,
        qe_report: &qe_report,
        qe_report_signature: &qe_signature,
        isv_signed: &isv_signed,
        isv_signature: &isv_signature,
        slot_hash: &challenge.slot_hash,
        challenge_nonce: &CHALLENGE_NONCE,
        nonce_slot,
    };
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let unsigned = sdk::build_tdx_enrolment_tx_for_program(
        &program_id,
        &enrolment,
        blockhash,
        solana_message::v1::TransactionConfig::empty()
            .with_compute_unit_limit(COMPUTE_UNIT_LIMIT)
            .with_loaded_accounts_data_size_limit(LOADED_ACCOUNTS_DATA_SIZE_LIMIT),
    )
    .expect("the enrolment fits one v1 transaction");
    let tx =
        VersionedTransaction::try_new(unsigned.message, &[&ctx.payer, &workload]).expect("payer and workload signer");
    ctx.banks_client.process_transaction(tx).await.expect("the enrolment must allocate its PDAs from empty accounts");

    // ---- every PDA the enrolment touches --------------------------------
    let session_data =
        assert_allocated(&mut ctx, session_pda, &program_id, TdxSessionAccount::SIZE, "the session PDA").await;
    let session = TdxSessionAccount::try_from_slice(&session_data).unwrap();
    assert_eq!(session.discriminator, TdxSessionAccount::DISCRIMINATOR);
    assert_eq!(session.attestation_pubkey, sdk::compress_p256(&attestation_xy));
    assert_eq!(session.gpu_rim_digest, GPU_RIM);
    assert_eq!(session.model_digest, MODEL);

    let nonce_data =
        assert_allocated(&mut ctx, nonce_pda, &program_id, UsedNonceAccount::SIZE, "the used-nonce PDA").await;
    assert_eq!(nonce_data[..8], USED_NONCE_DISCRIMINATOR, "the used-nonce PDA was allocated but not initialized",);

    let signer_data =
        assert_allocated(&mut ctx, signer_pda, &program_id, AttestedSignerAccount::SIZE, "the attested-signer PDA")
            .await;
    let record = AttestedSignerAccount::try_from_slice(&signer_data).unwrap();
    assert_eq!(record.discriminator, ATTESTED_SIGNER_DISCRIMINATOR);
    assert_eq!(record.record.signer_pubkey, workload.pubkey().to_bytes());
    assert_eq!(record.record.enclave_type, solana_confidential_compute_core::types::EnclaveType::IntelTdx,);

    // The challenge is retired in place rather than reallocated, so it stays
    // the same size and stays rent exempt.
    let retired = ChallengeAccount::try_from_slice(
        &assert_allocated(&mut ctx, challenge_pda, &program_id, ChallengeAccount::SIZE, "the retired challenge PDA")
            .await,
    )
    .unwrap();
    assert!(retired.is_consumed(), "an accepted quote must tombstone the challenge it answered",);
}

// ---------------------------------------------------------------------------
// Negative control
// ---------------------------------------------------------------------------

/// The control that proves the test above is not vacuous.
///
/// Case 1 runs `issue_tdx_challenge` from the same empty account against the
/// *natively linked* processor. `Rent::get()` is `UNSUPPORTED_SYSVAR` off
/// chain under solana 4.x, so the allocating arm must fail -- which is only
/// possible if that arm is the one being reached. If the SBF test above were
/// quietly taking the early-return arm, this case would succeed instead.
///
/// Case 2 pre-allocates the PDA exactly the way `tdx_handler_tests.rs` does --
/// zeroed, program-owned, `ChallengeAccount::SIZE` bytes -- and the same
/// natively linked program then succeeds. That is the bypass: a test written
/// this way passes without ever allocating anything, which is why it cannot
/// stand in for the proof above.
#[tokio::test]
async fn native_linkage_cannot_allocate_but_a_preallocated_pda_hides_it() {
    for preallocated in [false, true] {
        let program_id = Pubkey::new_unique();
        let (challenge_pda, _) = sdk::derive_tdx_challenge_pda(&program_id, &CHALLENGE_NONCE);

        let mut pt = ProgramTest::default();
        // Explicit: `ProgramTest::default()` turns `prefer_bpf` on whenever
        // `SBF_OUT_DIR`/`BPF_OUT_DIR` is set, which would load the real `.so`
        // and destroy the control.
        pt.prefer_bpf(false);
        pt.add_builtin_program(
            "solana_confidential_compute_verifier",
            program_id,
            processor!(Processor::process).expect("the processor macro always yields a registerer"),
        );
        if preallocated {
            pt.add_account(
                challenge_pda,
                Account {
                    lamports: 10_000_000,
                    data: vec![0; ChallengeAccount::SIZE],
                    owner: program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            );
        }
        let mut ctx = pt.start_with_context().await;

        let nonce_slot = newest_slot_hash_slot(&mut ctx).await;
        let ix = sdk::build_issue_tdx_challenge_ix_for_program(
            &program_id,
            &ctx.payer.pubkey(),
            &CHALLENGE_NONCE,
            nonce_slot,
        );
        let tx =
            Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer], ctx.last_blockhash);
        let outcome = ctx.banks_client.process_transaction(tx).await;

        if preallocated {
            outcome.expect(
                "a pre-allocated PDA takes the early-return arm, so the native build succeeds \
                 without ever allocating anything -- this is exactly what the existing tests do",
            );
            let data = ctx.banks_client.get_account(challenge_pda).await.unwrap().unwrap().data;
            let challenge = ChallengeAccount::try_from_slice(&data).unwrap();
            assert_eq!(challenge.nonce, CHALLENGE_NONCE);
        } else {
            assert_eq!(
                instruction_error(outcome.expect_err(
                    "an empty PDA must reach Rent::get(), which a natively linked program \
                     cannot read under solana 4.x",
                )),
                InstructionError::Custom(VerifierError::InvalidAccountAddress as u32),
                "the failure must be the mapped Rent::get() error, not something earlier",
            );
            assert!(
                ctx.banks_client.get_account(challenge_pda).await.unwrap().is_none(),
                "nothing may be allocated when Rent::get() fails",
            );
        }
    }
}
