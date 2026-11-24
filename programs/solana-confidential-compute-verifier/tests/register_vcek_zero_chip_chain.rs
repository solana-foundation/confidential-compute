//! A synthetic P-384 chain is not an AMD Milan endorsement, even with matching
//! identity extensions and a correct PDA seed.
//!
//! MIGRATION (solana 2.2 -> 4.x): this was the unit test
//! `processor::tests::test_register_vcek_rejects_synthetic_zero_chip_chain`,
//! which pinned the clock with `set_syscall_stubs`. `process_register_vcek` is
//! the only handler that reads the clock via `Clock::get()` rather than taking
//! a clock account, and in 4.x `Clock::get()` resolves through
//! `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch is a hardcoded
//! `UNSUPPORTED_SYSVAR` that never consults `program_stubs`. Natively the
//! handler therefore failed at the clock read with `InvalidAccountAddress`
//! before reaching any chain validation, and the stub was dead code. Restoring
//! the assertions requires the real SBF artifact under `ProgramTest`, which a
//! crate-internal unit test cannot drive -- hence the move out of `src/`.
//!
//! `registration_events` was fed by the `sol_log_data` stub, which the native
//! harness no longer reaches. Under the bank the same emission appears as a
//! `Program data:` log line, so the "failed call emitted no registration
//! event" assertion reads the transaction logs instead. `log_registration` and
//! `write_governance_data` are the program's only `sol_log_data` callers and
//! neither is reachable from a failing `register_vcek`, so the check is
//! equivalent.
use borsh::BorshSerialize;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_confidential_compute_verifier::{
    error::VerifierError,
    payload::{RegisterVcekArgs, REGISTER_VCEK_DISCRIMINATOR},
    state::{PolicyRegistry, VcekAccount, POLICY_REGISTRY_DISCRIMINATOR},
};
use solana_program::hash::hashv;
use solana_program_test::ProgramTestContext;
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signature::Signer,
    transaction::{Transaction, TransactionError},
};

#[path = "support/p384_certs.rs"]
mod p384_certs;
#[path = "common/sbf.rs"]
mod sbf;

use p384_certs::{encode_minimal_p384_cert, encode_vcek_with_identity, test_keypair};

/// Matches the slot and wall clock the retired `ClockSyscallStub` installed;
/// the synthetic certs are valid 2025-01-01..2035-01-01.
const SLOT: u64 = 100;
const UNIX: i64 = 1_800_000_000;
/// Chain validation is real P-384; production sizes registration the same.
const BUDGET: u32 = 1_400_000;

#[tokio::test]
async fn register_vcek_rejects_synthetic_zero_chip_chain() {
    let pid = Pubkey::new_unique();
    let zero_chip_id = [0u8; 64];
    let tcb_version = 42u64;

    let (ark_sk, ark_xy) = test_keypair(0x10);
    let (ask_sk, ask_xy) = test_keypair(0x11);
    let (_vcek_sk, vcek_xy) = test_keypair(0x12);
    let ask_cert = encode_minimal_p384_cert(&ask_xy, &ark_sk);
    let vcek_cert_bare = encode_minimal_p384_cert(&vcek_xy, &ask_sk);
    let vcek_cert = encode_vcek_with_identity(&vcek_xy, &ask_sk, &zero_chip_id, tcb_version);

    let chip_id_hash = hashv(&[&vcek_xy]).to_bytes();
    let (vcek_pda, _bump) = Pubkey::find_program_address(
        &[b"vcek_v2", &chip_id_hash, &tcb_version.to_le_bytes()],
        &pid,
    );
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);

    let registry = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: [0u8; 32],
        ark_pubkey_xy: ark_xy,
        min_tcb_boot_loader: 1,
        min_tcb_tee: 0,
        min_tcb_snp: 2,
        min_tcb_microcode: 5,
        measurement_count: 0,
        measurements: [[0u8; 48]; 8],
        bump: registry_bump,
    };
    let mut registry_data = vec![0u8; PolicyRegistry::SIZE];
    registry.serialize(&mut &mut registry_data[..]).unwrap();

    let funded = |owner: Pubkey, data: Vec<u8>| Account {
        lamports: 100_000_000,
        owner,
        data,
        ..Account::default()
    };
    let mut pt = sbf::verifier_program_test(pid);
    pt.add_account(registry_pda, funded(pid, registry_data));
    pt.add_account(vcek_pda, funded(pid, vec![0u8; VcekAccount::SIZE]));
    let mut ctx = pt.start_with_context().await;
    ctx.set_sysvar(&Clock {
        slot: SLOT,
        unix_timestamp: UNIX,
        ..Clock::default()
    });

    let pack = |chip_id: [u8; 64], tcb: u64, vcek: &[u8]| -> Vec<u8> {
        let mut ix_data = Vec::new();
        ix_data.extend_from_slice(&REGISTER_VCEK_DISCRIMINATOR);
        RegisterVcekArgs {
            chip_id,
            tcb_version: tcb,
            public_key_xy: vcek_xy,
            ask_cert_len: ask_cert.len() as u16,
            vcek_cert_len: vcek.len() as u16,
        }
        .serialize(&mut ix_data)
        .unwrap();
        ix_data.extend_from_slice(&ask_cert);
        ix_data.extend_from_slice(vcek);
        ix_data
    };
    let payer = ctx.payer.pubkey();
    let accounts = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(registry_pda, false),
        AccountMeta::new(vcek_pda, false),
        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
    ];

    for (label, data) in [
        // Leaf without the AMD identity extensions.
        (
            "missing identity",
            pack(zero_chip_id, tcb_version, &vcek_cert_bare),
        ),
        ("tcb mismatch", pack(zero_chip_id, 99, &vcek_cert)),
        ("chip mismatch", pack([0xABu8; 64], tcb_version, &vcek_cert)),
        // The namesake: identity extensions and PDA seed both agree.
        (
            "synthetic zero-chip chain",
            pack(zero_chip_id, tcb_version, &vcek_cert),
        ),
    ] {
        let err = send(&mut ctx, pid, accounts.clone(), data).await;
        assert_eq!(
            err,
            InstructionError::Custom(VerifierError::VerificationFailed as u32),
            "{label}"
        );
    }

    // No partial write to the preallocated cache.
    assert!(ctx
        .banks_client
        .get_account(vcek_pda)
        .await
        .unwrap()
        .unwrap()
        .data
        .iter()
        .all(|b| *b == 0));
}

/// Sends one registration and returns its `InstructionError`, asserting the
/// call emitted no registration event.
async fn send(
    ctx: &mut ProgramTestContext,
    pid: Pubkey,
    accounts: Vec<AccountMeta>,
    data: Vec<u8>,
) -> InstructionError {
    ctx.last_blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(BUDGET),
            Instruction {
                program_id: pid,
                accounts,
                data,
            },
        ],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    let size = solana_packet::Packet::from_data(None, &tx)
        .expect("transaction exceeds the 1232-byte packet limit")
        .meta()
        .size;
    assert!(size <= 1232, "transaction is {size} bytes");
    let result = ctx
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .unwrap();
    let logs = result.metadata.map(|m| m.log_messages).unwrap_or_default();
    assert!(
        !logs.iter().any(|l| l.starts_with("Program data:")),
        "failed call emitted a registration event: {logs:?}"
    );
    match result.result.unwrap_err() {
        TransactionError::InstructionError(_, e) => e,
        other => panic!("unexpected transaction error: {other:?}"),
    }
}
