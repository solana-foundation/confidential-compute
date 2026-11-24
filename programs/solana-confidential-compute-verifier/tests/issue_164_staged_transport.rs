//! Bank transport state-machine and authentic Milan verification regression.
//!
//! MIGRATION (solana 2.2 -> 4.x): this drove `Processor::process` natively and
//! stubbed the clock via `set_syscall_stubs`. In 4.x `Clock::get()` resolves
//! through `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch is a
//! hardcoded `UNSUPPORTED_SYSVAR` that never consults `program_stubs` -- so a
//! natively linked program can no longer read any sysvar and the stub is dead
//! code. The transport reads `Clock::get()` on every BEGIN/UPLOAD/SEAL/CONSUME,
//! so it must execute as real SBF bytecode under `ProgramTest`; the clock is now
//! driven by `set_sysvar`, which also moves backwards.
//!
//! Two consequences of the bank, both widening what is asserted:
//! * `BEGIN` now allocates the stage PDA through the system program instead of
//!   receiving it preallocated, so the CPI path is covered too.
//! * Failed instructions roll back, so the "no partial write" assertions now
//!   confirm bank atomicity rather than in-place handler discipline. Each one is
//!   therefore pinned to the exact `InstructionError` the handler returns, which
//!   also rules out a vacuous pass from a replayed signature.
use borsh::BorshDeserialize;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_confidential_compute_verifier::{
    error::VerifierError,
    payload::REGISTER_VCEK_DISCRIMINATOR,
    processor::transport::*,
    state::{AmdIdentityRevocation, PolicyRegistry, VcekAccount, POLICY_REGISTRY_DISCRIMINATOR},
};
use solana_program_test::{BanksClientError, ProgramTestContext};
use solana_sdk::{
    account::{Account, AccountSharedData},
    clock::Clock,
    hash::hash,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

#[path = "common/sbf.rs"]
mod sbf;

/// The stub pinned the wall clock; `validate_vcek_chain_at` reads it, so the
/// fixture's validity window must not drift with the host date.
const PINNED_UNIX: i64 = 1_790_288_000;
/// Registration runs a full P-384 chain validation; production sizes the same.
const CONSUME_BUDGET: u32 = 1_400_000;

fn funded(owner: Pubkey, data: Vec<u8>) -> Account {
    Account {
        lamports: 100_000_000,
        owner,
        data,
        ..Account::default()
    }
}

fn at_slot(slot: u64) -> Clock {
    Clock {
        slot,
        unix_timestamp: PINNED_UNIX,
        ..Clock::default()
    }
}

fn instruction_error(err: BanksClientError) -> InstructionError {
    match err.unwrap() {
        TransactionError::InstructionError(_, e) => e,
        other => panic!("unexpected transaction error: {other:?}"),
    }
}

fn invalid() -> InstructionError {
    InstructionError::InvalidInstructionData
}

/// Every send takes a fresh blockhash: an identical retry must reach the program
/// instead of returning the cached status of the first attempt.
async fn send(
    ctx: &mut ProgramTestContext,
    signer: Option<&Keypair>,
    instructions: &[Instruction],
) -> Result<(), BanksClientError> {
    ctx.last_blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let mut signers: Vec<&Keypair> = vec![&ctx.payer];
    signers.extend(signer);
    let tx = Transaction::new_signed_with_payer(
        instructions,
        Some(&ctx.payer.pubkey()),
        &signers,
        ctx.last_blockhash,
    );
    assert!(
        solana_packet::Packet::from_data(None, &tx)
            .unwrap()
            .meta()
            .size
            <= 1232
    );
    ctx.banks_client.process_transaction(tx).await
}

async fn data_of(ctx: &mut ProgramTestContext, key: Pubkey) -> Vec<u8> {
    ctx.banks_client
        .get_account(key)
        .await
        .unwrap()
        .unwrap()
        .data
}

fn real_payload() -> Vec<u8> {
    let ask = include_bytes!(
        "../../../crates/solana-confidential-compute-crypto/tests/data/milan_ask.der"
    );
    let leaf = include_bytes!("../../../fixtures/vcek_milan.der");
    let identity = solana_confidential_compute_crypto::parse_vcek_identity(leaf).unwrap();
    let key_at = leaf.windows(4).position(|b| b == [3, 98, 0, 4]).unwrap() + 4;
    let mut payload = REGISTER_VCEK_DISCRIMINATOR.to_vec();
    payload.extend(identity.chip_id);
    payload.extend(identity.tcb_version.to_le_bytes());
    payload.extend(&leaf[key_at..key_at + 96]);
    payload.extend((ask.len() as u16).to_le_bytes());
    payload.extend((leaf.len() as u16).to_le_bytes());
    payload.extend(ask);
    payload.extend(leaf);
    payload
}

fn stage_address(pid: &Pubkey, authority: &Pubkey, payload: &[u8]) -> Pubkey {
    Pubkey::find_program_address(
        &[
            b"attestation_stage",
            authority.as_ref(),
            hash(payload).as_ref(),
        ],
        pid,
    )
    .0
}

#[tokio::test]
async fn authentic_milan_transport_and_adversarial_lifecycle() {
    let pid = solana_confidential_compute_verifier::id();
    let authority = Keypair::new();
    let foreign = Keypair::new();
    let payload = real_payload();
    let mut tampered = payload.clone();
    *tampered.last_mut().unwrap() ^= 1;

    let stage = stage_address(&pid, &authority.pubkey(), &payload);
    let bad = stage_address(&pid, &authority.pubkey(), &tampered);
    let chip_hash = hash(&payload[8..72]);
    let tcb = &payload[72..80];
    let (registry_key, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let (vcek_key, _) =
        Pubkey::find_program_address(&[VcekAccount::SEED, chip_hash.as_ref(), tcb], &pid);
    let deny =
        Pubkey::find_program_address(&[AmdIdentityRevocation::SEED, chip_hash.as_ref()], &pid).0;

    let mut pt = sbf::verifier_program_test(pid);
    pt.add_account(
        authority.pubkey(),
        funded(solana_sdk_ids::system_program::ID, vec![]),
    );
    pt.add_account(
        foreign.pubkey(),
        funded(solana_sdk_ids::system_program::ID, vec![]),
    );
    pt.add_account(
        registry_key,
        funded(
            pid,
            borsh::to_vec(&PolicyRegistry {
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
            })
            .unwrap(),
        ),
    );
    pt.add_account(vcek_key, funded(pid, vec![0; VcekAccount::SIZE]));
    let mut ctx = pt.start_with_context().await;
    ctx.set_sysvar(&at_slot(100));

    let pair = |stage: Pubkey| {
        vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new(stage, false),
        ]
    };
    let make = |tag: [u8; 8], rest: Vec<u8>, accounts: Vec<AccountMeta>| {
        let mut data = tag.to_vec();
        data.extend(rest);
        Instruction {
            program_id: pid,
            accounts,
            data,
        }
    };
    let begin = |stage: Pubkey, payload: &[u8], expiry: u64| {
        let mut rest = hash(payload).to_bytes().to_vec();
        rest.extend((payload.len() as u32).to_le_bytes());
        rest.extend(expiry.to_le_bytes());
        let mut accounts = pair(stage);
        accounts.push(AccountMeta::new_readonly(
            solana_sdk_ids::system_program::ID,
            false,
        ));
        make(BEGIN, rest, accounts)
    };
    let chunks = |stage: Pubkey, payload: &[u8]| {
        payload
            .chunks(MAX_CHUNK)
            .enumerate()
            .map(|(index, chunk)| {
                let mut rest = ((index * MAX_CHUNK) as u32).to_le_bytes().to_vec();
                rest.extend(chunk);
                make(UPLOAD, rest, pair(stage))
            })
            .collect::<Vec<_>>()
    };

    send(&mut ctx, Some(&authority), &[begin(stage, &payload, 150)])
        .await
        .unwrap();
    let empty = data_of(&mut ctx, stage).await;

    // Nothing but an in-order UPLOAD advances a freshly begun stage.
    for (tag, rest, expected) in [
        (SEAL, vec![], invalid()),
        (CONSUME, vec![], invalid()),
        (UPLOAD, vec![1, 0, 0, 0, 7], invalid()),
        (UPLOAD, vec![0; MAX_CHUNK + 5], invalid()),
    ] {
        let err = send(&mut ctx, Some(&authority), &[make(tag, rest, pair(stage))])
            .await
            .unwrap_err();
        assert_eq!(instruction_error(err), expected, "{tag:?}");
        assert_eq!(data_of(&mut ctx, stage).await, empty);
    }

    let mut unsigned = make(UPLOAD, vec![0, 0, 0, 0, 7], pair(stage));
    unsigned.accounts[0].is_signer = false;
    let err = send(&mut ctx, None, &[unsigned]).await.unwrap_err();
    assert_eq!(
        instruction_error(err),
        InstructionError::MissingRequiredSignature
    );

    // Any signer may ask, but only the recorded authority owns the stage.
    let mut intruder = make(CLOSE, vec![], pair(stage));
    intruder.accounts[0].pubkey = foreign.pubkey();
    let err = send(&mut ctx, Some(&foreign), &[intruder])
        .await
        .unwrap_err();
    assert_eq!(instruction_error(err), InstructionError::InvalidAccountData);

    for ix in chunks(stage, &payload) {
        send(&mut ctx, Some(&authority), &[ix]).await.unwrap();
    }
    let complete = data_of(&mut ctx, stage).await;

    let err = send(
        &mut ctx,
        Some(&authority),
        &[make(UPLOAD, vec![0, 0, 0, 0, 9], pair(stage))],
    )
    .await
    .unwrap_err();
    assert_eq!(instruction_error(err), invalid());

    // Sealing authenticates the bytes against the digest committed at BEGIN.
    let mut corrupt = complete.clone();
    corrupt[HEADER + 500] ^= 1;
    ctx.set_account(
        &stage,
        &AccountSharedData::from(funded(pid, corrupt.clone())),
    );
    let err = send(
        &mut ctx,
        Some(&authority),
        &[make(SEAL, vec![], pair(stage))],
    )
    .await
    .unwrap_err();
    assert_eq!(instruction_error(err), invalid());

    ctx.set_account(
        &stage,
        &AccountSharedData::from(funded(pid, complete.clone())),
    );
    send(
        &mut ctx,
        Some(&authority),
        &[make(SEAL, vec![], pair(stage))],
    )
    .await
    .unwrap();

    // A sealed stage is frozen: no further bytes, no second seal.
    for (tag, rest) in [(UPLOAD, vec![0, 0, 0, 0, 9]), (SEAL, vec![])] {
        let err = send(&mut ctx, Some(&authority), &[make(tag, rest, pair(stage))])
            .await
            .unwrap_err();
        assert_eq!(instruction_error(err), invalid(), "{tag:?}");
    }

    // Handler error leaves the stage sealed, not consumed.
    let err = send(
        &mut ctx,
        Some(&authority),
        &[make(CONSUME, vec![], pair(stage))],
    )
    .await
    .unwrap_err();
    assert_eq!(instruction_error(err), invalid());
    assert_eq!(data_of(&mut ctx, stage).await[88], 1);

    let handler = |stage: Pubkey| {
        let mut accounts = pair(stage);
        accounts.extend([
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(registry_key, false),
            AccountMeta::new(vcek_key, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(deny, false),
        ]);
        vec![
            ComputeBudgetInstruction::set_compute_unit_limit(CONSUME_BUDGET),
            make(CONSUME, vec![], accounts),
        ]
    };

    ctx.set_sysvar(&at_slot(150));
    let err = send(&mut ctx, Some(&authority), &handler(stage))
        .await
        .unwrap_err();
    assert_eq!(instruction_error(err), invalid());
    assert!(data_of(&mut ctx, vcek_key).await.iter().all(|b| *b == 0));

    ctx.set_sysvar(&at_slot(149));
    send(&mut ctx, Some(&authority), &handler(stage))
        .await
        .unwrap();
    let saved = VcekAccount::try_from_slice(&data_of(&mut ctx, vcek_key).await).unwrap();
    assert_eq!(saved.public_key_xy.as_slice(), &payload[80..176]);
    assert_eq!(data_of(&mut ctx, stage).await[88], 2);

    let err = send(&mut ctx, Some(&authority), &handler(stage))
        .await
        .unwrap_err();
    assert_eq!(instruction_error(err), invalid());

    // A sealed upload with a corrupted vendor signature is storage-authentic,
    // but still fails real on-chain cryptographic verification.
    send(&mut ctx, Some(&authority), &[begin(bad, &tampered, 150)])
        .await
        .unwrap();
    for ix in chunks(bad, &tampered) {
        send(&mut ctx, Some(&authority), &[ix]).await.unwrap();
    }
    send(&mut ctx, Some(&authority), &[make(SEAL, vec![], pair(bad))])
        .await
        .unwrap();
    let err = send(&mut ctx, Some(&authority), &handler(bad))
        .await
        .unwrap_err();
    assert_eq!(
        instruction_error(err),
        InstructionError::Custom(VerifierError::VerificationFailed as u32)
    );
    let sealed = data_of(&mut ctx, bad).await;
    assert_eq!(sealed[88], 1);

    // Owner, address and length are each sufficient on their own to reject.
    ctx.set_account(
        &bad,
        &AccountSharedData::from(funded(Pubkey::new_unique(), sealed.clone())),
    );
    let err = send(&mut ctx, Some(&authority), &[make(SEAL, vec![], pair(bad))])
        .await
        .unwrap_err();
    assert_eq!(instruction_error(err), InstructionError::IllegalOwner);
    ctx.set_account(&bad, &AccountSharedData::from(funded(pid, sealed.clone())));

    let squatter = Pubkey::new_unique();
    ctx.set_account(&squatter, &AccountSharedData::from(funded(pid, sealed)));
    let err = send(
        &mut ctx,
        Some(&authority),
        &[make(SEAL, vec![], pair(squatter))],
    )
    .await
    .unwrap_err();
    assert_eq!(instruction_error(err), InstructionError::InvalidSeeds);

    let truncated = Pubkey::new_unique();
    ctx.set_account(
        &truncated,
        &AccountSharedData::from(funded(pid, vec![0; HEADER - 1])),
    );
    let err = send(
        &mut ctx,
        Some(&authority),
        &[make(CONSUME, vec![], pair(truncated))],
    )
    .await
    .unwrap_err();
    assert_eq!(instruction_error(err), InstructionError::InvalidAccountData);

    // Oversized/zero allocations and deadlines fail before CPI/allocation.
    for (length, expiry) in [
        (0u32, 150u64),
        ((MAX_PAYLOAD + 1) as u32, 150),
        (8, 149),
        (8, 300),
    ] {
        let mut rest = [1; 32].to_vec();
        rest.extend(length.to_le_bytes());
        rest.extend(expiry.to_le_bytes());
        let err = send(
            &mut ctx,
            Some(&authority),
            &[make(BEGIN, rest, pair(stage))],
        )
        .await
        .unwrap_err();
        assert_eq!(instruction_error(err), invalid(), "{length}/{expiry}");
    }

    // Expiry blocks verification but never strands the uploader's rent.
    ctx.set_sysvar(&at_slot(150));
    send(
        &mut ctx,
        Some(&authority),
        &[make(CLOSE, vec![], pair(bad))],
    )
    .await
    .unwrap();
    assert!(ctx.banks_client.get_account(bad).await.unwrap().is_none());

    let prior = ctx
        .banks_client
        .get_balance(authority.pubkey())
        .await
        .unwrap();
    let rent = ctx.banks_client.get_balance(stage).await.unwrap();
    send(
        &mut ctx,
        Some(&authority),
        &[make(CLOSE, vec![], pair(stage))],
    )
    .await
    .unwrap();
    assert_eq!(
        ctx.banks_client
            .get_balance(authority.pubkey())
            .await
            .unwrap(),
        prior + rent
    );
    assert!(ctx.banks_client.get_account(stage).await.unwrap().is_none());

    let err = send(&mut ctx, Some(&authority), &handler(stage))
        .await
        .unwrap_err();
    assert_eq!(instruction_error(err), InstructionError::IllegalOwner);
}
