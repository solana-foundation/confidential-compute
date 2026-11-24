---
title: 15-Minute Integrator Quickstart
description: Step-by-step walkthrough for integrating Solana Confidential Compute hardware attestation into your Solana program.
---

This guide walks through integrating Solana Confidential Compute into a Solana program in 15 minutes.

---

## Step 1: Choose Your Integration Mode

Solana Confidential Compute supports two operational modes. Select the mode matching your throughput requirements:

| Decision Factor | Mode A (Stateful Session) | Mode B (Stateless Atomic) |
| :--- | :--- | :--- |
| **Primary Use Case** | Streaming oracles, market-maker quotes, frequent heartbeats | NAV marks, governance proposals, treasury rebalances, large liquidations |
| **Execution Frequency** | High-frequency (sub-second to seconds) | Discrete / low-frequency (minutes to hours) |
| **Transaction Structure** | Enclave attests once per 24h; downstream transactions send standard Ed25519 signatures | Attestation instruction and consumer instruction execute in the same transaction |
| **Consumer Compute Cost** | **~355 CUs** (validating `AttestedSignerAccount` PDA) | **~2,500 CUs** (validating preceding instruction via introspection) |
| **State Footprint** | One 154-byte `AttestedSignerAccount` PDA per active enclave | One 49-byte `UsedNonceAccount` PDA per transaction (rent refundable to the payer via `close_stale_nonce` after 150 slots) |

---

## Step 2: Add `solana-confidential-compute-cpi` Dependency

Add the CPI crate to your Solana program's `Cargo.toml`:

```toml
[dependencies]
solana-confidential-compute-cpi = { version = "0.1.0" }
solana-program = ">=1.18, <=4.1"
```

For Anchor projects:
```toml
[dependencies]
solana-confidential-compute-cpi = { version = "0.1.0", features = ["anchor"] }
```

---

## Step 3: Verify Signatures in Your Program

### Path A: Mode A (Session Signer Verification)

Verify that the caller's Ed25519 signer is backed by an active, unexpired `AttestedSignerAccount` matching your pinned measurement:

```rust
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};
use solana_confidential_compute_cpi::assert_attestation_signer;

// Pinned SHA-384 measurement of your authorized enclave binary
pub const EXPECTED_MEASUREMENT: [u8; 48] = [
    0x96, 0x1d, 0x86, 0x6e, 0x60, 0x98, 0x07, 0xee, 0x6e, 0x06, 0xeb, 0x48,
    0x2c, 0xa1, 0x01, 0x93, 0x51, 0x0f, 0xc1, 0xd4, 0xb9, 0xb4, 0x6f, 0xee,
    0x53, 0x00, 0xc6, 0x5b, 0xbe, 0x99, 0x36, 0x76, 0x5c, 0x3e, 0x70, 0x22,
    0x9c, 0x11, 0x8a, 0x37, 0x97, 0xb1, 0x4e, 0x94, 0xb8, 0x8e, 0xd0, 0x85,
];

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let workload_signer = next_account_info(account_info_iter)?;
    let attested_info = next_account_info(account_info_iter)?;

    // 1. Enforce that the workload key signed this transaction
    if !workload_signer.is_signer {
        return Err(solana_program::program_error::ProgramError::MissingRequiredSignature);
    }

    // 2. Validate attestation PDA (ownership, TTL freshness, and pinned measurement)
    assert_attestation_signer(
        attested_info,
        workload_signer,
        &EXPECTED_MEASUREMENT,
        solana_confidential_compute_cpi::AttestationPlatform::AmdSevSnp,
    )?;

    // 3. Process business logic (guaranteed to be signed by verified enclave)
    Ok(())
}
```

### Path B: Mode B (Atomic Preceding Instruction Introspection)

Verify that instruction 0 in the transaction executed `verify_atomic_with_nonce` and committed to your instruction arguments:

```rust
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};
use solana_confidential_compute_cpi::{assert_attestation_atomic, hash_action_account_infos, AtomicAttestationExpectation, AttestationPlatform};

pub const EXPECTED_MEASUREMENT: [u8; 48] = [ /* 48-byte measurement */ 0x96; 48 ];
pub const IX_EXECUTE_ATOMIC_ACTION: u8 = 1;

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let sysvar_instructions = next_account_info(account_info_iter)?;
    let account_a = next_account_info(account_info_iter)?;
    let account_b = next_account_info(account_info_iter)?;

    // 1. Compute the V2 digest from top-level effective account privileges
    let action_hash = hash_action_account_infos(
        &[IX_EXECUTE_ATOMIC_ACTION],
        accounts, // all ordered runtime accounts, including the Instructions sysvar
        instruction_data.get(1..).ok_or(
            solana_program::program_error::ProgramError::InvalidInstructionData,
        )?,
    );

    // 2. Introspect instruction 0 to verify attestation header and measurement
    let expectation = AtomicAttestationExpectation {
        expected_platform: AttestationPlatform::AmdSevSnp,
        action_hash,
        expected_measurement: EXPECTED_MEASUREMENT,
        expected_signer: None,
        require_nonce: true,
        verifier_ix_index: None,
    };
    assert_attestation_atomic(
        sysvar_instructions,
        &expectation,
        program_id,
    )?;

    // 3. Process atomic business logic
    Ok(())
}
```

---

## Step 4: Pin Your Enclave Measurement

Where does `EXPECTED_MEASUREMENT` come from?

1. **Build Your Enclave:** Compile your workload binary inside Docker / AWS Nitro CLI or GCP Confidential VM tools.
2. **Retrieve the SHA-384 Measurement:**
   - **AWS Nitro Enclaves:** Run `nitro-cli describe-eif --eif-path <image.eif>`. Read the `PCR0` field.
   - **AMD SEV-SNP:** Run `sev-guest-get-report` or inspect build logs for the 48-byte launch digest.
3. **Embed the Constant:** Paste the 48-byte array into your consumer program or register it in an on-chain `PolicyRegistry` account.

---

## Step 5: Test on Solana Devnet

The official Solana Confidential Compute verifier and reference consumer are deployed on Solana Devnet:

| Program | Cluster | Address |
| :--- | :--- | :--- |
| **`solana-confidential-compute-verifier`** | Devnet | `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh` |
| **`solana-confidential-compute-consumer-reference`** | Devnet | `A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ` |

To run the complete reference test suite against the local SBF harness:

```bash
cargo test -p solana-confidential-compute-consumer-reference
cargo test -p solana-confidential-compute-cpi
```

For the compilable reference implementation, inspect [`programs/solana-confidential-compute-consumer-reference/src/lib.rs`](../../../../../programs/solana-confidential-compute-consumer-reference/src/lib.rs).

Mode A source contract: [CPI API and V2 layout](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/README.md#2-mode-a-account), [production helper](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/src/lib.rs), and [zero-copy validation](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/src/anchor.rs). The examples pin AMD; choose the expected platform for your own workload. Both slot and exclusive Unix deadlines apply.

Mode B V2 requires fresh attestations and coordinated consumer/helper/SDK/sidecar migration, without legacy fallback. Use the [V2 wire/API and complete metadata construction contract](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/README.md#4-hash_action) before obtaining evidence and validate the final compiled message before signing. The full SNP packet limitation and lack of staged atomic adapter still apply.
