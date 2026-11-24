---
title: Mode B — Stateless Atomic Attestation
description: One-transaction attestation with an 80-byte header, SlotHashes freshness, and UsedNonceAccount replay defense.
---

<!-- @spec SCC-DOCS-001 SCC-ARCH-001 SCC-ARCH-002 SCC-VERIFY-010 SCC-VERIFY-011 SCC-VERIFY-012 SCC-SEC-005 -->

Mode B attests and executes in **one transaction**. Instruction 0 is the verifier. Instruction 1 is the consumer. The pair succeeds or fails together.

:::tip[When to choose Mode B]
**Choose Mode B if:** You execute discrete, high-value settlement operations where each action must carry fresh, unreplayable hardware attestation proof directly in the transaction (e.g. NAV marks, governance actions, treasury rebalances, large liquidations). Each transaction costs **~2,500 CUs** on the consumer to introspect instruction 0 and verify the cryptographic action commitment.
:::

The canonical instruction is `verify_atomic_with_nonce`. `verify_atomic` returns `VerifierError::NonceRequired` and writes no state (`@spec SCC-SEC-005`).

## Flow

1. The enclave binds `REPORT_DATA[32..64] = SHA-256(slot_hash ‖ action_hash ‖ consumer_program_id)`.
2. The client packs the verifier at index 0 and the consumer at index 1.
3. The verifier loads `slot_hash` from `SlotHashes` at `nonce_slot` (age ≤ 150).
4. The verifier checks VCEK / Nitro signature, measurement, TCB, and the action commitment (`@spec SCC-VERIFY-012`).
5. The verifier allocates a 49-byte `UsedNonceAccount` PDA seeded `[b"nonce", signer_pubkey, commitment]`.
6. The consumer calls `assert_attestation_atomic` and reads the preceding verifier instruction through `sysvar::instructions`.

Stage 2 stays under 550,000 CUs (`@spec SCC-PERF-002`). Mock-crypto SBF harness: `verify_atomic_with_nonce` ≈ 59,638 CUs. The consumer introspection check is bounded at **2,500 CUs** (`@spec SCC-CONSUMER-002`).

## 80-byte header

On the wire, Mode B SNP data is:

`discriminator (8) ‖ VerifyAtomicHeader (72) ‖ SNP report (1,184)` = **1,264 bytes**.

The 80-byte prefix at `0x00..0x50` is the discriminator plus header:

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR` `[209, 4, 10, 239, 3, 142, 223, 250]` |
| 8 | 8 | `nonce_slot` (u64 LE) |
| 16 | 32 | `action_hash` |
| 48 | 32 | `consumer_program_id` |
| 80 | 1184 | SNP report (zero-copy, `@spec SCC-ARCH-002`) |

`solana_confidential_compute_core::VerifyAtomicHeader` is the 72-byte body after the discriminator (`nonce_slot`, `action_hash`, `consumer_program_id`).

## SlotHashes freshness

The verifier pins `slot_hashes_account.key == sysvar::slot_hashes::ID` and loads the 32-byte hash at `nonce_slot`. Age above 150 slots is `VerifierError::StaleNonce`.

The commitment is native `hashv`:

```text
expected = SHA-256(slot_hash ‖ header.action_hash ‖ header.consumer_program_id)
REPORT_DATA[32..64] == expected
```

A mismatch is `VerifierError::ActionHashMismatch`.

## `UsedNonceAccount` replay defense

| Item | Value |
| :--- | :--- |
| Size | 49 bytes (disc 8 + slot 8 + bump 1 + `refund_pubkey` 32) |
| Discriminator | `[138, 99, 69, 17, 9, 177, 205, 94]` (`sha256("account:UsedNonceAccountV2")[..8]`) |
| Legacy record | 17 bytes, discriminator `[157, 75, 223, 206, 73, 132, 216, 154]`, no refund field; still blocks replay; cannot be closed |
| Seeds | `[b"nonce", signer_pubkey, commitment]` |
| Allocate | System Program `create_account`, funded by `payer` (`@spec SCC-ARCH-001`) |
| Replay | `VerifierError::NonceAlreadyUsed` (either discriminator) |
| Cleanup | `close_stale_nonce` (accounts: nonce writable, recorded payer writable, Clock; no payload). Allowed only when `clock.slot - slot > 150`; all lamports go to `refund_pubkey`. The nonce is then outside the `SlotHashes` window and fails with `StaleNonce`. |

`solana_confidential_compute_cpi::assert_attestation_atomic` rejects `require_nonce == false` and rejects the `verify_atomic` discriminator (`@spec SCC-VERIFY-013`).

## Accounts

`payer`, `policy_registry`, `vcek`, `used_nonce`, `SlotHashes`, `Clock`, `system_program`.

Nitro Mode B uses `verify_nitro_attestation` with `mode = 1` and appends the Instructions sysvar. The consumer program id is the next instruction's program id.

## Packet size

A 1,264-byte SNP payload exceeds the **1,232-byte** legacy UDP MTU. Use Solana v1 transactions (4,096-byte MTU, SIMD-0296). The TypeScript SDK throws `PacketTooLargeError` on the legacy path. See the [TypeScript SDK](/integration/typescript-sdk/).

## Related

- [Mode A](/architecture/mode-a-stateful/)
- [Rust CPI](/integration/rust-cpi/)
- [Instruction matrix](/reference/instruction-matrix/)
