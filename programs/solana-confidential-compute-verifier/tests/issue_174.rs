//! Registration reads the trusted Clock before chain validation (#175).
//!
//! MIGRATION (solana 2.2 -> 4.x): this was a native unit test that stubbed the
//! clock via `set_syscall_stubs`. In 4.x `Clock::get()` resolves through
//! `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch is a hardcoded
//! `UNSUPPORTED_SYSVAR` that never consults `program_stubs` -- so a natively
//! linked program can no longer read any sysvar and the stub is dead code.
//! `process_register_vcek` calls `Clock::get()` before chain validation, so the
//! only way to exercise it is to run the real SBF artifact under ProgramTest.
use {
    borsh::BorshSerialize,
    solana_confidential_compute_verifier::{error::VerifierError, payload::*, state::*},
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

fn malformed_register_vcek_data() -> Vec<u8> {
    let mut instruction = REGISTER_VCEK_DISCRIMINATOR.to_vec();
    RegisterVcekArgs { chip_id: [0; 64], tcb_version: 0, public_key_xy: [0; 96], ask_cert_len: 1, vcek_cert_len: 1 }
        .serialize(&mut instruction)
        .unwrap();
    instruction.extend_from_slice(&[0xff, 0xff]); // deliberately malformed DER
    instruction
}

fn instruction_error(err: solana_program_test::BanksClientError) -> InstructionError {
    match err.unwrap() {
        TransactionError::InstructionError(_, e) => e,
        other => panic!("unexpected transaction error: {other:?}"),
    }
}

async fn boot(pid: Pubkey, authority: &Pubkey) -> (ProgramTestContext, Pubkey) {
    let mut pt = sbf::verifier_program_test(pid);
    let (registry, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
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
        bump,
    };
    pt.add_account(
        registry,
        Account {
            lamports: 10_000_000,
            data: borsh::to_vec(&policy).unwrap(),
            owner: pid,
            executable: false,
            rent_epoch: 0,
        },
    );
    (pt.start_with_context().await, registry)
}

/// An unsigned payer is rejected before anything is read; a signed one gets as
/// far as chain validation and dies on the malformed DER. Neither writes.
#[tokio::test]
async fn unsigned_vcek_registration_stops_before_der_parsing() {
    for signed in [false, true] {
        let pid = Pubkey::new_unique();
        let authority = Keypair::new();
        let (ctx, registry) = boot(pid, &authority.pubkey()).await;
        let before = ctx.banks_client.get_account(registry).await.unwrap().unwrap().data;
        let vcek = Pubkey::new_unique();

        let ix = Instruction {
            program_id: pid,
            accounts: vec![
                AccountMeta { pubkey: authority.pubkey(), is_signer: signed, is_writable: true },
                AccountMeta::new_readonly(registry, false),
                AccountMeta::new(vcek, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            ],
            data: malformed_register_vcek_data(),
        };

        let mut signers: Vec<&Keypair> = vec![&ctx.payer];
        if signed {
            signers.push(&authority);
        }
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &signers, ctx.last_blockhash);
        let err = instruction_error(ctx.banks_client.process_transaction(tx).await.unwrap_err());
        assert_eq!(
            err,
            if signed {
                InstructionError::Custom(VerifierError::VerificationFailed as u32)
            } else {
                InstructionError::MissingRequiredSignature
            },
            "signed={signed}"
        );

        // No partial writes on either path.
        let after = ctx.banks_client.get_account(registry).await.unwrap().unwrap().data;
        assert_eq!(after, before, "registry was mutated (signed={signed})");
        assert!(
            ctx.banks_client.get_account(vcek).await.unwrap().is_none(),
            "vcek account was allocated (signed={signed})"
        );
    }
}
