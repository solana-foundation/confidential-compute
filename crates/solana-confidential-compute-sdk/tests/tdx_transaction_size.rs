//! Packet budget for the two Intel TDX transactions.
//!
//! The secp256r1 precompile reads its message from instruction data, so the
//! quote bytes ride in the transaction rather than in an account. That makes
//! the 1,232-byte packet the binding constraint on the whole design, and it
//! is not a constraint a compiler or a unit test would otherwise notice: a
//! transaction one byte too large is built fine, signed fine, and rejected by
//! the cluster at submit time.
//!
//! These numbers were measured, not derived. Adding one account or twenty
//! bytes of instruction data to the second transaction breaks it.
//!
//! @spec SCC-TDX-001 SCC-TDX-002

use solana_message::AddressLookupTableAccount;
use solana_packet::PACKET_DATA_SIZE;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::{v0, VersionedMessage};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::{Transaction, VersionedTransaction};

/// `num_signatures (1) + padding (1) + offsets (14) + pubkey (33) + signature (64)`.
const PRECOMPILE_OVERHEAD: usize = 16 + 33 + 64;
/// `EnclaveReportBody`.
const QE_REPORT_LEN: usize = 384;
/// TDX v4 `header || td_report_body`.
const ISV_SIGNED_LEN: usize = 632;

/// `discriminator || attestation_pubkey_xy || pck_pubkey || gpu_rim ||
/// model_digest || auth_len || auth_data`, with Intel's 32-byte auth data.
const QE_IX_DATA_LEN: usize = 8 + 64 + 33 + 32 + 32 + 2 + 32;
/// `discriminator || mode || nonce_slot`.
const QUOTE_IX_DATA_LEN: usize = 8 + 1 + 8;

fn legacy_size(ixs: &[Instruction], payer: &Pubkey) -> usize {
    let tx = Transaction::new_with_payer(ixs, Some(payer));
    bincode::serialized_size(&tx).expect("serializable") as usize
}

fn precompile_ix(program: Pubkey, message_len: usize) -> Instruction {
    Instruction {
        program_id: program,
        accounts: vec![],
        data: vec![0u8; PRECOMPILE_OVERHEAD + message_len],
    }
}

fn writable(n: usize) -> Vec<Pubkey> {
    (0..n).map(|_| Pubkey::new_unique()).collect()
}

/// The QE step fits a plain legacy transaction, which keeps the first half of
/// enrolment simple for any client.
#[test]
fn the_qe_report_transaction_fits_a_legacy_packet() {
    let payer = Keypair::new().pubkey();
    let secp = Pubkey::new_unique();
    let program = Pubkey::new_unique();

    // session, policy, payer, system, clock, instructions.
    let accounts: Vec<AccountMeta> = writable(6)
        .into_iter()
        .map(|k| AccountMeta::new(k, false))
        .collect();

    let size = legacy_size(
        &[
            precompile_ix(secp, QE_REPORT_LEN),
            Instruction {
                program_id: program,
                accounts,
                data: vec![0u8; QE_IX_DATA_LEN],
            },
        ],
        &payer,
    );

    assert!(
        size <= PACKET_DATA_SIZE,
        "QE transaction is {size} bytes, over the {PACKET_DATA_SIZE}-byte packet",
    );
    // Recorded so a regression is visible as a number, not just a pass/fail.
    assert_eq!(size, 1104, "QE transaction size changed");
}

/// The quote step does **not** fit a legacy transaction. This is not a bug to
/// fix later -- it is why the client must send a versioned transaction.
#[test]
fn the_quote_transaction_requires_a_versioned_message() {
    let payer = Keypair::new().pubkey();
    let secp = Pubkey::new_unique();
    let program = Pubkey::new_unique();

    let accounts: Vec<AccountMeta> = writable(10)
        .into_iter()
        .map(|k| AccountMeta::new(k, false))
        .collect();

    let size = legacy_size(
        &[
            precompile_ix(secp, ISV_SIGNED_LEN),
            Instruction {
                program_id: program,
                accounts,
                data: vec![0u8; QUOTE_IX_DATA_LEN],
            },
        ],
        &payer,
    );

    assert!(
        size > PACKET_DATA_SIZE,
        "a legacy quote transaction now fits at {size} bytes -- if the account \
         list shrank, the versioned-transaction requirement can be revisited",
    );
    assert_eq!(size, 1297, "legacy quote transaction size changed");
}

/// With the six fixed accounts in a lookup table it fits, with room to spare.
#[test]
fn the_quote_transaction_fits_with_a_lookup_table() {
    let payer = Keypair::new().pubkey();
    let secp = Pubkey::new_unique();
    let program = Pubkey::new_unique();

    // Per-request: attested signer, session, nonce, challenge.
    let dynamic = writable(4);
    // Fixed for a deployment: policy, system program, clock, instructions
    // sysvar, workload signer, and one spare.
    let fixed = writable(6);

    let mut accounts: Vec<AccountMeta> = dynamic
        .iter()
        .map(|k| AccountMeta::new(*k, false))
        .collect();
    accounts.extend(fixed.iter().map(|k| AccountMeta::new_readonly(*k, false)));

    let ixs = vec![
        precompile_ix(secp, ISV_SIGNED_LEN),
        Instruction {
            program_id: program,
            accounts,
            data: vec![0u8; QUOTE_IX_DATA_LEN],
        },
    ];

    let table = AddressLookupTableAccount {
        key: Pubkey::new_unique(),
        addresses: fixed,
    };
    let message = v0::Message::try_compile(&payer, &ixs, &[table], Hash::default())
        .expect("the lookup table resolves every fixed account");
    let tx = VersionedTransaction {
        signatures: vec![Default::default()],
        message: VersionedMessage::V0(message),
    };
    let size = bincode::serialized_size(&tx).expect("serializable") as usize;

    assert!(
        size <= PACKET_DATA_SIZE,
        "quote transaction is {size} bytes even with a lookup table",
    );
    assert_eq!(size, 1147, "versioned quote transaction size changed");

    // Headroom worth naming: one more 32-byte account outside the table
    // would eat a third of it.
    assert!(
        PACKET_DATA_SIZE - size >= 64,
        "only {} bytes of headroom left",
        PACKET_DATA_SIZE - size
    );
}

/// Why the two signatures cannot share a transaction, in one assertion.
#[test]
fn both_precompile_messages_cannot_share_one_transaction() {
    let qe = PRECOMPILE_OVERHEAD + QE_REPORT_LEN;
    let isv = PRECOMPILE_OVERHEAD + ISV_SIGNED_LEN;
    assert_eq!(qe, 497);
    assert_eq!(isv, 745);
    assert!(
        qe + isv > PACKET_DATA_SIZE,
        "if these ever fit together the two instructions could be merged",
    );
}

/// The same transaction with a sponsor paying the fee.
///
/// The earlier figure assumed one signature because the fixture made the fee
/// payer and the workload signer the same key. The handler requires both to
/// sign, and a gas relay makes them different: a second 64-byte signature
/// plus the extra account. Measured here rather than asserted, because the
/// answer decides whether sponsored enrolment is possible at all.
#[test]
fn a_sponsored_quote_transaction_is_measured_not_assumed() {
    let payer = Keypair::new().pubkey();
    let workload = Keypair::new().pubkey();
    let secp = Pubkey::new_unique();
    let program = Pubkey::new_unique();

    let dynamic = writable(4);
    let fixed = writable(6);

    let mut accounts: Vec<AccountMeta> = dynamic
        .iter()
        .map(|k| AccountMeta::new(*k, false))
        .collect();
    accounts.extend(fixed.iter().map(|k| AccountMeta::new_readonly(*k, false)));
    // The workload signer signs and is not in the table: a signer cannot be
    // looked up, so it always costs a full 32 bytes plus a signature.
    accounts.push(AccountMeta::new_readonly(workload, true));

    let ixs = vec![
        precompile_ix(secp, ISV_SIGNED_LEN),
        Instruction {
            program_id: program,
            accounts,
            data: vec![0u8; QUOTE_IX_DATA_LEN],
        },
    ];
    let table = AddressLookupTableAccount {
        key: Pubkey::new_unique(),
        addresses: fixed,
    };
    let message = v0::Message::try_compile(&payer, &ixs, &[table], Hash::default())
        .expect("the lookup table resolves every fixed account");
    let tx = VersionedTransaction {
        // Two signatures: the sponsor and the workload key.
        signatures: vec![Default::default(), Default::default()],
        message: VersionedMessage::V0(message),
    };
    let size = bincode::serialized_size(&tx).expect("serializable") as usize;

    eprintln!("sponsored quote transaction: {size} bytes (limit {PACKET_DATA_SIZE})");
    assert!(
        size > PACKET_DATA_SIZE,
        "a sponsored quote transaction now fits at {size} bytes; if the account list \
         shrank, the self-paying requirement can be relaxed",
    );
}

/// With the workload key paying its own fee there is one signature and it fits.
#[test]
fn a_self_paying_quote_transaction_fits() {
    let workload = Keypair::new().pubkey();
    let secp = Pubkey::new_unique();
    let program = Pubkey::new_unique();

    let dynamic = writable(4);
    let fixed = writable(6);

    let mut accounts: Vec<AccountMeta> = dynamic
        .iter()
        .map(|k| AccountMeta::new(*k, false))
        .collect();
    accounts.extend(fixed.iter().map(|k| AccountMeta::new_readonly(*k, false)));
    accounts.push(AccountMeta::new(workload, true));

    let ixs = vec![
        precompile_ix(secp, ISV_SIGNED_LEN),
        Instruction {
            program_id: program,
            accounts,
            data: vec![0u8; QUOTE_IX_DATA_LEN],
        },
    ];
    let table = AddressLookupTableAccount {
        key: Pubkey::new_unique(),
        addresses: fixed,
    };
    let message =
        v0::Message::try_compile(&workload, &ixs, &[table], Hash::default()).expect("compiles");
    let tx = VersionedTransaction {
        signatures: vec![Default::default()],
        message: VersionedMessage::V0(message),
    };
    let size = bincode::serialized_size(&tx).expect("serializable") as usize;
    eprintln!("self-paying quote transaction: {size} bytes (limit {PACKET_DATA_SIZE})");
    assert!(
        size <= PACKET_DATA_SIZE,
        "self-paying transaction is {size} bytes"
    );
}

/// Sponsoring fits once the per-enclave accounts join the lookup table.
///
/// The session and attested-signer PDAs are derived from the attestation key
/// and the workload key, so they are stable for a given enclave even though
/// they are not stable for the deployment. A table seeded per enclave can
/// carry them, which buys back the 32 bytes each that a sponsor's second
/// signature costs. Only the challenge and nonce PDAs genuinely change per
/// request and have to stay inline.
#[test]
fn sponsoring_fits_when_the_per_enclave_pdas_are_in_the_table() {
    let payer = Keypair::new().pubkey();
    let workload = Keypair::new().pubkey();
    let secp = Pubkey::new_unique();
    let program = Pubkey::new_unique();

    // Genuinely per-request: challenge and nonce.
    let per_request = writable(2);
    // Stable for this enclave: attested signer and session.
    let per_enclave = writable(2);
    // Stable for the deployment.
    let fixed = writable(6);

    let mut accounts: Vec<AccountMeta> = per_request
        .iter()
        .map(|k| AccountMeta::new(*k, false))
        .collect();
    accounts.extend(per_enclave.iter().map(|k| AccountMeta::new(*k, false)));
    accounts.extend(fixed.iter().map(|k| AccountMeta::new_readonly(*k, false)));
    accounts.push(AccountMeta::new_readonly(workload, true));

    let ixs = vec![
        precompile_ix(secp, ISV_SIGNED_LEN),
        Instruction {
            program_id: program,
            accounts,
            data: vec![0u8; QUOTE_IX_DATA_LEN],
        },
    ];
    let mut addresses = fixed;
    addresses.extend(per_enclave);
    let table = AddressLookupTableAccount {
        key: Pubkey::new_unique(),
        addresses,
    };
    let message =
        v0::Message::try_compile(&payer, &ixs, &[table], Hash::default()).expect("compiles");
    let tx = VersionedTransaction {
        signatures: vec![Default::default(), Default::default()],
        message: VersionedMessage::V0(message),
    };
    let size = bincode::serialized_size(&tx).expect("serializable") as usize;
    eprintln!("sponsored with per-enclave table: {size} bytes (limit {PACKET_DATA_SIZE})");
    assert!(
        size <= PACKET_DATA_SIZE,
        "sponsoring still does not fit at {size} bytes",
    );
}
