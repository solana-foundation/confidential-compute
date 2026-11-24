---
title: Rust CPI / Anchor
description: Three-line assert_attestation_atomic helper and Anchor adapters for Solana Confidential Compute consumer programs.
---

Consumer programs depend on `solana-confidential-compute-cpi`. The crate uses `solana-program`, `solana-confidential-compute-core`, `thiserror`, and `bytemuck`. It does not depend on `solana-sdk` or `anchor-lang`.

```toml
solana-confidential-compute-cpi = { version = "0.1.0" }
```

Program id matches the live verifier: `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`.

## Mode B — three-line helper

`assert_attestation_atomic` introspects the preceding verifier instruction. Pass the Instructions sysvar, the expectation, and `program_id`.

```rust
let claims = solana_confidential_compute_cpi::assert_attestation_atomic(
    instructions_sysvar,
    &expectation,
    program_id,
)?;
```

Compute the action digest at the top-level consumer before any CPI from **all** ordered runtime `AccountInfo`s, including sysvars and duplicates. Do not accept a caller-supplied hash. The [source-linked wire/API contract](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/README.md#4-hash_action) specifies the domain, flags, metadata construction and migration.

```rust
use solana_confidential_compute_cpi::{assert_attestation_atomic, hash_action_account_infos, AtomicAttestationExpectation, AttestationPlatform};

const IX_EXECUTE_ATOMIC_ACTION: u8 = 1;
// PLACEHOLDER — replace before deploying. `[0x42; 48]` is not a real enclave
// measurement; no genuine hardware produces it. This constant decides which
// enclave image your program trusts, so substitute your own image's SHA-384
// measurement and keep it in sync with the verifier's BackendPolicy.
const EXPECTED_MEASUREMENT: [u8; 48] = [0x42; 48];

let action_hash = hash_action_account_infos(
    &[IX_EXECUTE_ATOMIC_ACTION],
    accounts, // all ordered runtime accounts, including sysvars and duplicates
    payload,
);
let expectation = AtomicAttestationExpectation {
    expected_platform: AttestationPlatform::AmdSevSnp,
    action_hash,
    expected_measurement: EXPECTED_MEASUREMENT,
    expected_signer: None,
    require_nonce: true,
    verifier_ix_index: None, // preceding instruction
};
let claims = assert_attestation_atomic(instructions_sysvar, &expectation, program_id)?;
```

For Anchor, `solana_confidential_compute_cpi::anchor::assert_attestation_atomic_action_ctx(instructions_sysvar, expectation, current_program_id, discriminator, accounts, payload)` recomputes the digest from all ordered runtime accounts and calls the existing guard. Pass the full account list, not only the business accounts. Lower-level expectation-taking helpers below require the same runtime-derived digest.

`require_nonce` must stay `true`. `false` returns `CpiError::NonceRequired`. SNP Mode B requires `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR`. Nitro Mode B requires `verify_nitro_attestation` with `mode == 1`.

`verifier_ix_index: None` selects `current_index - 1`. An explicit index may name any earlier verifier instruction.

## Anchor adapters

The two-arg macro reads `ctx.accounts.instructions` and `ctx.program_id`:

```rust
solana_confidential_compute_cpi::assert_attestation_atomic_ctx!(ctx, &expectation)?;
```

Function form:

```rust
solana_confidential_compute_cpi::anchor::assert_attestation_atomic_ctx(
    &ctx.accounts.instructions.to_account_info(),
    &expectation,
    ctx.program_id,
)?;
```

Declare the sysvar as an unchecked account. Pin it to `sysvar::instructions::ID` in your own constraint if you want an extra check. The helper already asserts `instructions_sysvar.key == instructions::ID`.

## Mode A — session signer

```rust
use solana_confidential_compute_cpi::AttestedSignerAccount;

let attested = AttestedSignerAccount::try_from_account_info(attested_info)?;
attested.validate_session_signer(
    workload_signer, &EXPECTED_MEASUREMENT, solana_confidential_compute_cpi::AttestationPlatform::AmdSevSnp,
)?;
```

`try_from_account_info` asserts owner `== solana_confidential_compute_cpi::ID` and the 8-byte discriminator. `validate_session_signer` requires `workload_signer.is_signer`, pubkey equality, measurement match, and `Clock::get()?.slot <= expires_slot` and `0 <= Clock::get()?.unix_timestamp < expires_unix_timestamp`.

The lower-level helper also re-derives the PDA:

```rust
solana_confidential_compute_cpi::assert_attestation_signer(
    attested_info,
    workload_signer,
    &EXPECTED_MEASUREMENT,
    solana_confidential_compute_cpi::AttestationPlatform::AmdSevSnp,
)?;
```

## `hash_action`

Domain separation hashes `b"solana-confidential-compute:action:v1\0"`, ordered account count/keys/effective signer-writable flags, and length-prefixed complete instruction bytes. The discriminator/payload split does not affect the digest. On-chain consumers use their top-level `AccountInfo` flags; off-chain callers use the SDK compiled-message helper with the final payer and revalidate the assembled message.

```rust
pub fn hash_action(discriminator: &[u8], accounts: &[AccountMeta], data: &[u8]) -> [u8; 32]
```

```rust
let digest = solana_confidential_compute_cpi::hash_action_account_infos(discriminator, accounts, payload);
```

Keep digest-derived nonce/upload keys out of consumer accounts. Unresolved LUTs and requested-writable reserved consumer keys are conservatively rejected. See the [wire/API and construction contract](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/README.md#4-hash_action).

## `CpiError`

Codes align with `VerifierError`:

| Variant | Code | When |
| :--- | ---: | :--- |
| `DisallowedMeasurement` | 3 | Measurement mismatch |
| `AttestationExpired` | 8 | `clock.slot > expires_slot` or Unix timestamp negative / at or beyond the exclusive deadline |
| `ActionHashMismatch` | 12 | Header `action_hash` mismatch |
| `SignerMismatch` | 13 | Workload pubkey mismatch |
| `NonceRequired` | 16 | `require_nonce == false` or `verify_atomic` discriminator |
| `ConsumerProgramMismatch` | 17 | Consumer program id mismatch |

See the [instruction matrix](/reference/instruction-matrix/) for the full `VerifierError` table.

## Reference consumer

`programs/solana-confidential-compute-consumer-reference` shows both paths. Mode A: `execute_session_action`. Mode B: `execute_atomic_action` with `assert_attestation_atomic_ctx`.

:::note
The complete, compilable reference consumer is [`programs/solana-confidential-compute-consumer-reference/src/lib.rs`](../../../../../programs/solana-confidential-compute-consumer-reference/src/lib.rs).
:::

Mode A source contract: [CPI API and V2 layout](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/README.md#2-mode-a-account), [production helper](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/src/lib.rs), and [zero-copy validation](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/src/anchor.rs). The examples pin AMD; choose the expected platform for your own workload. Both slot and exclusive Unix deadlines apply.
