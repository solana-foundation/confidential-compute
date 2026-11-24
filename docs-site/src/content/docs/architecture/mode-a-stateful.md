---
title: Mode A — Stateful Session Caching
description: verify_and_register writes an AttestedSignerAccount PDA. TTL is 216,000 slots. Later transactions skip P-384.
---

<!-- @spec SCC-DOCS-001 SCC-ARCH-001 SCC-VERIFY-004 SCC-VERIFY-008 SCC-VERIFY-015 SCC-ANCHOR-001 -->

Mode A registers a hardware-attested Ed25519 key once. Later consumer transactions treat that key as a session signer.

:::tip[When to choose Mode A]
**Choose Mode A if:** You execute high-frequency, repeated operations from the same key (e.g. streaming oracle prices, market-maker quotes, frequent worker heartbeats). Hardware attestation runs once per ~24-hour session (`ATTESTATION_TTL_SLOTS = 216_000`), while subsequent consumer transactions only pay a lightweight **~355 CU** check against the `AttestedSignerAccount` PDA.
:::

## Flow

1. The enclave generates an ephemeral Ed25519 key in encrypted RAM.
2. Hardware signs a report with `REPORT_DATA[0..32] = pubkey` and `REPORT_DATA[32..64] = slot_hash`.
3. The client submits `verify_and_register`.
4. The verifier checks VCEK (or Nitro COSE), measurement, TCB, SlotHashes age ≤ 150, and burns a `UsedNonceAccount`.
5. The verifier writes the V2 `AttestedSignerAccount` with `expires_slot = clock.slot + 216_000` and an independent exclusive Unix deadline (GCP is also capped by JWT expiry).
6. The consumer calls `assert_attestation_signer` (or `AttestedSignerAccount::validate_session_signer`). Subsequent transactions use native Ed25519 and skip P-384.

Stage 2 stays under 550,000 CUs (`@spec SCC-PERF-001`). Mock-crypto SBF harness: `verify_and_register` ≈ 62,734 CUs. The consumer PDA check is bounded at **1,500 CUs** (`@spec SCC-CONSUMER-001`).

## TTL

`ATTESTATION_TTL_SLOTS = 216_000` (~24 hours at 400 ms slots). The verifier writes expiry from `Clock`. Clients pass `expiresSlot` only as bookkeeping.

Re-attestation of a live PDA is allowed when `current_slot > expires_slot`, or when the stored pubkey matches and a fresh unused nonce verifies (`@spec SCC-VERIFY-004`).

## Wire layout (`verify_and_register`)

Discriminator `sha256("global:verify_and_register")[..8]`:

`[246, 249, 100, 14, 102, 116, 92, 145]`

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | Discriminator |
| 8 | 8 | `nonce_slot` (u64 LE) |
| 16 | 1184 | SNP report (zero-copy borrow, `@spec SCC-ARCH-002`) |

Total instruction data: **1,200 bytes**.

Accounts: `payer`, `policy_registry`, `vcek`, `attested_signer`, `used_nonce`, `SlotHashes`, `Clock`, `system_program`.

Nitro Mode A uses `verify_nitro_attestation` with `mode = 0`. See the [instruction matrix](/reference/instruction-matrix/).

## `AttestedSignerAccount`

PDA seeds: `[b"attested_signer_v2", signer_pubkey]`. Size **154 bytes**. Discriminator `[43, 255, 114, 40, 233, 28, 127, 238]`.

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | Discriminator |
| 8 | 32 | `signer_pubkey` |
| 40 | 1 | `enclave_type` |
| 41 | 48 | `measurement` |
| 89 | 32 | `chip_id_hash` |
| 121 | 8 | `tcb_version` LE |
| 129 | 8 | `registered_slot` LE |
| 137 | 8 | `expires_slot` LE |
| 145 | 1 | `bump` |
| 146 | 8 | `expires_unix_timestamp` signed i64 LE |

`tcb_version` and slot fields sit at unaligned offsets, so the CPI type stores them as `[u8; 8]` (`bytemuck::Pod`, align 1).

## Consumer check

```rust
let attested = solana_confidential_compute_cpi::AttestedSignerAccount::try_from_account_info(attested_info)?;
attested.validate_session_signer(
    workload_signer, &EXPECTED_MEASUREMENT, solana_confidential_compute_cpi::AttestationPlatform::AmdSevSnp,
)?;
```

`validate_session_signer` requires `workload_signer.is_signer`, pubkey equality, measurement match, and `Clock::get()?.slot <= expires_slot` and `0 <= Clock::get()?.unix_timestamp < expires_unix_timestamp` (`@spec SCC-SEC-004`). Owner plus discriminator authenticate the record. PDA re-derivation is optional defense-in-depth and costs 1,500 CUs.

The helper `solana_confidential_compute_cpi::assert_attestation_signer` also re-derives the PDA.

## PDA lifecycle (`@spec SCC-ARCH-001`)

New PDAs allocate through System Program `create_account`, funded by `payer`. The program asserts `owner == program_id` and `is_writable` on writable accounts. Stage 2 prefers client-supplied bumps and `create_program_address` over `find_program_address`.

## Related

- [Mode B](/architecture/mode-b-atomic/)
- [Rust CPI](/integration/rust-cpi/)
- [TypeScript SDK](/integration/typescript-sdk/)


Mode A source contract: [CPI API and V2 layout](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/README.md#2-mode-a-account), [production helper](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/src/lib.rs), and [zero-copy validation](https://github.com/solana-foundation/confidential-compute/blob/main/crates/solana-confidential-compute-cpi/src/anchor.rs). The examples pin AMD; choose the expected platform for your own workload. Both slot and exclusive Unix deadlines apply.
