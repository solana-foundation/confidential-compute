---
title: TypeScript SDK
description: "@solana/confidential-compute builders for Mode A and Mode B. Packet MTU ceiling is 1,232 bytes."
---

The TypeScript client lives in `sdks/typescript/` and publishes as `@solana/confidential-compute`. Layouts match the Rust builders byte for byte. Slot and lamport values use `bigint`.

```bash
cd sdks/typescript
bun install
bun run build
```

```ts
import {
  SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
  PACKET_DATA_SIZE,
  PacketTooLargeError,
  buildRegisterSignerIx,
  buildSessionActionTx,
  buildAtomicAttestationTx,
  buildVerifyNitroAttestationTx,
  deriveSignerPda,
} from "@solana/confidential-compute";
```

`SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID` is `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`.

## Packet MTU ceiling

Legacy cluster UDP caps a serialized transaction at **1,232 bytes** (`PACKET_DATA_SIZE`). A raw 1,184-byte SNP report does not fit that envelope once signatures and keys are included.

Standard builders call `assertPacketFits` / `probePacket` and throw `PacketTooLargeError`. The authentic Milan registration instruction is 3,208 bytes (minimal serialized transaction 3,379); the authentic 4,526-byte Nitro document produces a 4,579-byte instruction. Neither fits the 1,232-byte packet limit. Current source provides bounded staged VCEK registration and Nitro Mode A transport in the Rust SDK (`crates/solana-confidential-compute-sdk/src/staged.rs`); this does not make these TypeScript inline builders a staged path. Staged Mode B is rejected, and these checks establish no extended-MTU deployment or real SBF/hardware enrollment. Test harness packers are for layout inspection; bypassing the guard is not a supported submission path.

```ts
try {
  const ix = buildRegisterSignerIx(payer, signer, report, expiresSlot, nonceSlot);
} catch (err) {
  if (err instanceof PacketTooLargeError) {
    // Handle the unsupported inline payload; do not bypass the packet guard.
  }
  throw err;
}
```

## Local signing and caller policy

The local session builder receives a workload `Keypair` and signs locally. Keep that key inside the enclave; the production signing path is the sidecar `POST /v1/sign`, which this SDK does not call automatically. Rejects every System Program instruction before workload-key signing in both SDKs. Custom consumer programs, accounts, and data still require caller policy; the SDK does not provide the sidecar's transaction-screening guarantees.

## Mode A

`buildRegisterSignerIx` packs `verify_and_register`: discriminator + `nonce_slot` (u64 LE) + 1,184-byte report.

`expiresSlot` is caller bookkeeping. On-chain TTL is `clock.slot + 216_000n` (`ATTESTATION_TTL_SLOTS`).

```ts
const ix = buildRegisterSignerIx(
  payer,
  workloadSigner,
  snpReport,      // Uint8Array length 1184
  0n,             // expiresSlot bookkeeping
  nonceSlot,      // bigint
);

// Local example: workloadKeypair must remain inside the enclave.
// Production callers request sidecar POST /v1/sign instead.
const tx = buildSessionActionTx(
  payer,
  workloadKeypair,
  consumerIx,
  recentBlockhash,
);
```

The caller supplies `nonceSlot`. It is the slot whose hash the enclave wrote into the report. This package does not read `SlotHashes`.

PDA helpers: `deriveSignerPda`, `deriveUsedNoncePdaForSource`, `deriveLegacyUsedNoncePda`, `derivePolicyRegistryPda`, `deriveVcekPda`. All use `PublicKey.findProgramAddressSync`.

## Mode B

`buildAtomicAttestationTx` always packs `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR` at index 0 and the consumer at index 1 (`@spec SCC-SEC-005`). `requireNonce` is `true`.

The caller supplies `nonceSlot`, `actionHash`, and `measurement`. `nonceSlot` is the SlotHashes slot bound into the report. `actionHash` is the 32-byte consumer-instruction digest. `measurement` is the 48-byte enclave image digest. This package does not derive those values. The `hashAction` and `computeCommitment` code example is in [sdks/typescript/README.md](../../../../../sdks/typescript/README.md#4-quickstart).

```ts
const tx = buildAtomicAttestationTx(
  payer,
  consumerProgramId,
  actionHash,       // 32 bytes
  measurement,      // 48 bytes
  snpReport,        // 1184 bytes
  consumerIx,
  recentBlockhash,
  nonceSlot,
);
```

Expectation type:

```ts
interface AtomicAttestationExpectation {
  actionHash: Uint8Array;
  expectedMeasurement: Uint8Array;
  expectedSigner: Uint8Array | null;
  requireNonce: boolean;     // default true
  verifierIxIndex: number | null;
}
```

## Nitro (Mode A and Mode B)

`buildVerifyNitroAttestationTx` packs `verify_nitro_attestation`.

| Field | Layout |
| :--- | :--- |
| Discriminator | `[107, 76, 178, 169, 215, 146, 23, 95]` |
| `mode` | `0` Mode A, `1` Mode B |
| `nonce_slot` | u64 LE |
| `expected_action_hash` | 32 bytes |
| `doc_len` | u32 LE |
| document | COSE Sign1, `doc_len ≤ 8192` (`MAX_NITRO_DOCUMENT_LEN`) |

Mode A uses attested-signer PDA `["attested_signer_v2", workload_signer]`. Mode B uses a dummy attested-signer and a nonce PDA seeded with the action commitment `SHA-256(slotHash ‖ actionHash ‖ consumerProgramId)`. Mode B requires a consumer instruction at index 1. The caller supplies `nonceSlot` and `actionHash`, as in the Mode B builder above.

```ts
const tx = buildVerifyNitroAttestationTx(
  payer,
  workloadSigner,
  1,                 // Mode B
  nonceSlot,
  actionHash,
  coseDocument,
  nonce,             // 32-byte commitment
  recentBlockhash,
  consumerIx,
);
```

CU telemetry ceiling for these paths is 550,000.

## Related

- [Mode A](/architecture/mode-a-stateful/)
- [Mode B](/architecture/mode-b-atomic/)
- [Instruction matrix](/reference/instruction-matrix/)
