//! MIGRATION HELPER (solana 2.2 -> 4.x).
//!
//! In solana 4.x, `Sysvar::get()` (Clock, Rent, ...) is implemented via
//! `impl_get_sysvar!(ID)` -> `solana_get_sysvar::sol_get_sysvar`, which on
//! `not(target_os = "solana")` is a hardcoded `UNSUPPORTED_SYSVAR` with NO
//! `program_stubs` hook, and `solana-program-test` 4.3 no longer installs stubs.
//!
//! Net effect: a program registered natively via `processor!` can no longer read
//! any sysvar. `solana_confidential_compute_cpi::assert_attested_signer` calls `Clock::get()` on every
//! Mode A check, so this consumer MUST execute as real SBF bytecode.
//!
//! `ProgramTest::prefer_bpf` (set by `SBF_OUT_DIR`) is all-or-nothing and panics
//! for any registered program lacking a `.so`, which would force a shared object
//! for the inline no-op verifier fixture too. Instead we install the consumer's
//! `.so` directly as a loader-v2 executable account, leaving inline `processor!`
//! fixtures on the native path where they never touch a sysvar. This mirrors
//! `programs/solana-confidential-compute-verifier/tests/common/sbf.rs`.
#![allow(dead_code)]

use {
    solana_program_test::ProgramTest,
    solana_sdk::{account::Account, pubkey::Pubkey, rent::Rent},
};

/// Path to the SBF shared object, honouring `SBF_OUT_DIR`/`BPF_OUT_DIR`.
fn so_path(program_name: &str) -> std::path::PathBuf {
    let dir = std::env::var("SBF_OUT_DIR")
        .or_else(|_| std::env::var("BPF_OUT_DIR"))
        .unwrap_or_else(|_| {
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").to_string()
        });
    std::path::Path::new(&dir).join(format!("{program_name}.so"))
}

/// Install a compiled SBF program as an executable account.
pub fn add_sbf_program(pt: &mut ProgramTest, program_name: &str, program_id: Pubkey) {
    let path = so_path(program_name);
    let data = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}\nRun `cargo-build-sbf --manifest-path \
             programs/solana-confidential-compute-consumer-reference/Cargo.toml` first, or set SBF_OUT_DIR.",
            path.display()
        )
    });
    pt.add_account(
        program_id,
        Account {
            lamports: Rent::default().minimum_balance(data.len()).max(1),
            data,
            owner: solana_sdk_ids::bpf_loader::id(),
            executable: true,
            rent_epoch: 0,
        },
    );
}

/// `ProgramTest` with the real consumer bytecode loaded at `program_id`.
pub fn consumer_program_test(program_id: Pubkey) -> ProgramTest {
    let mut pt = ProgramTest::default();
    add_sbf_program(
        &mut pt,
        "solana_confidential_compute_consumer_reference",
        program_id,
    );
    pt
}
