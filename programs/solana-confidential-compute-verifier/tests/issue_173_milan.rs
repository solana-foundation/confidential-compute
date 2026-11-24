//! Authentic Milan VCEK registration keeps the supported vendor trust profile.
//!
//! MIGRATION (solana 2.2 -> 4.x): this was a native test that stubbed both the
//! clock and `sol_log_data` via `set_syscall_stubs`. In 4.x `Clock::get()`
//! resolves through `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch
//! is a hardcoded `UNSUPPORTED_SYSVAR` that never consults `program_stubs`, so a
//! natively linked program cannot read a sysvar and both stubs are dead code.
//! `process_register_vcek` reads `Clock::get()` before chain validation, so the
//! only way to exercise it is the real SBF artifact under ProgramTest. Two
//! consequences: the registration event is now read back from the transaction's
//! `Program data:` log instead of a `sol_log_data` stub, and the real ASK+VCEK
//! chain is ~3KB of instruction data -- larger than a 1232-byte cluster packet,
//! so this remains a Banks-only correctness test and is not a claim that the
//! chain fits in one on-chain transaction.
use borsh::{BorshDeserialize, BorshSerialize};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_confidential_compute_verifier::{
    payload::{RegisterVcekArgs, REGISTER_VCEK_DISCRIMINATOR},
    state::{AmdIdentityRevocation, PolicyRegistry, VcekAccount, POLICY_REGISTRY_DISCRIMINATOR},
};
use solana_program::{clock::Clock, hash::hashv, pubkey::Pubkey};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    signature::Signer,
    transaction::Transaction,
};

#[path = "common/sbf.rs"]
mod sbf;

const NOW_UNIX: i64 = 1_800_000_000;
const CU_LIMIT: u32 = 1_400_000;

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i)) as usize & 0x3F] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `sol_log_data` renders as `Program data: <b64 field> <b64 field> ...`.
fn assert_event(logs: &[String], fields: &[&[u8]]) {
    let expected = format!("Program data: {}", fields.iter().map(|f| base64(f)).collect::<Vec<_>>().join(" "));
    let observed: Vec<_> = logs.iter().filter(|l| l.starts_with("Program data: ")).collect();
    assert_eq!(observed.len(), 1, "one success event per registration");
    assert_eq!(*observed[0], expected);
}

#[tokio::test]
async fn authentic_milan_registration_preserves_supported_vendor_profile() {
    let ask = include_bytes!("../../../crates/solana-confidential-compute-crypto/tests/data/milan_ask.der");
    let leaf = include_bytes!("../../../fixtures/vcek_milan.der");
    let offset = leaf.windows(4).position(|w| w == [3, 0x62, 0, 4]).unwrap() + 4;
    let xy: [u8; 96] = leaf[offset..offset + 96].try_into().unwrap();
    let identity = solana_confidential_compute_crypto::parse_vcek_identity(leaf).unwrap();

    let pid = Pubkey::new_unique();
    let (registry, rb) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let hash = hashv(&[&identity.chip_id]).to_bytes();
    let tcb = identity.tcb_version.to_le_bytes();
    let (vcek, _) = Pubkey::find_program_address(&[VcekAccount::SEED, &hash, &tcb], &pid);
    let (deny, _) = Pubkey::find_program_address(&[AmdIdentityRevocation::SEED, &hash], &pid);

    let mut pt = sbf::verifier_program_test(pid);
    pt.set_compute_max_units(u64::from(CU_LIMIT));
    let mut ctx = pt.start_with_context().await;
    ctx.set_account(
        &registry,
        &Account {
            lamports: 10_000_000,
            data: borsh::to_vec(&PolicyRegistry {
                discriminator: POLICY_REGISTRY_DISCRIMINATOR,
                authority: ctx.payer.pubkey().to_bytes(),
                ark_pubkey_xy: [0; 96],
                min_tcb_boot_loader: 0,
                min_tcb_tee: 0,
                min_tcb_snp: 0,
                min_tcb_microcode: 0,
                measurement_count: 0,
                measurements: [[0; 48]; 8],
                bump: rb,
            })
            .unwrap(),
            owner: pid,
            executable: false,
            rent_epoch: 0,
        }
        .into(),
    );
    ctx.set_sysvar(&Clock { slot: 500, unix_timestamp: NOW_UNIX, ..Clock::default() });

    let mut data = REGISTER_VCEK_DISCRIMINATOR.to_vec();
    RegisterVcekArgs {
        chip_id: identity.chip_id,
        tcb_version: identity.tcb_version,
        public_key_xy: xy,
        ask_cert_len: ask.len() as u16,
        vcek_cert_len: leaf.len() as u16,
    }
    .serialize(&mut data)
    .unwrap();
    data.extend(ask);
    data.extend(leaf);

    let register = Instruction {
        program_id: pid,
        accounts: vec![
            AccountMeta::new(ctx.payer.pubkey(), true),
            AccountMeta::new_readonly(registry, false),
            AccountMeta::new(vcek, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(deny, false),
        ],
        data,
    };
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[ComputeBudgetInstruction::set_compute_unit_limit(CU_LIMIT), register],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        blockhash,
    );
    let outcome = ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap();
    let metadata = outcome.metadata.expect("execution metadata required");
    assert_eq!(outcome.result, Ok(()));

    let account = ctx.banks_client.get_account(vcek).await.unwrap().expect("vcek cache");
    assert_eq!(account.owner, pid);
    assert_event(
        &metadata.log_messages,
        &[
            b"solana-confidential-compute:registration:v1",
            b"register_vcek",
            b"amd_sev_snp",
            &xy,
            vcek.as_ref(),
            hashv(&[&account.data]).as_ref(),
        ],
    );

    let saved = VcekAccount::try_from_slice(&account.data).unwrap();
    assert_eq!(saved.public_key_xy, xy);
    // The authenticated chain deadline is persisted, not discarded.
    assert_eq!(saved.trust_profile, VcekAccount::MILAN_TRUST_PROFILE);
    assert!(saved.valid_until_unix > u64::try_from(NOW_UNIX).unwrap());
    assert_ne!(saved.valid_until_unix, u64::MAX);
    assert!(!saved.is_revoked);
}
