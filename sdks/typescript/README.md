# @solana/confidential-compute

TypeScript client for Solana Confidential Compute. The package name is `@solana/confidential-compute`. The version in this tree is `0.1.0`. The source file is `sdks/typescript/src/index.ts`. `tsc` writes `dist/index.js` and `dist/index.d.ts`.

The client packs the same bytes as `solana-confidential-compute-sdk`. It does not send a transaction. It does not open a hardware device.

`@spec SCC-SDK-002` `@spec SCC-ARCH-001` `@spec SCC-VERIFY-001` `@spec SCC-SEC-001`

Run the tests from this directory. A `npm test` started in a parent repository can select a different `package.json`.

```bash
cd sdks/typescript
bun test
```

`bun test` runs `tsc`, then executes `test/packet.test.cjs` and `test/nitro.test.cjs`.

CI runs the SDK tests on Node.js **24.22.1**, which includes the
[October 2026 security fixes](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).
Use that version or a newer patched release in a supported Node.js line locally.
Bun remains the dependency installer and build-script runner.

Node, from this same directory:

```bash
cd sdks/typescript
bun run test
```

A passing run reports **17 passed**: 7 in `test/packet.test.cjs` and 10 in `test/nitro.test.cjs`.

---

## 1. Constants

| Export                                   | Value                                         |
| :--------------------------------------- | :-------------------------------------------- |
| `SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID` | `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh` |
| `SNP_REPORT_SIZE`                        | 1184                                          |
| `ATTESTED_SIGNER_ACCOUNT_SIZE`           | **154**                                       |
| `MAX_NITRO_DOCUMENT_LEN`                 | **8192**                                      |
| `PACKET_DATA_SIZE`                       | 1232                                          |
| `ATTESTATION_TTL_SLOTS`                  | `216000n`                                     |
| `VERIFY_AND_REGISTER_IX_LEN`             | 1202 (8 + 8 + 1184 + 2 bumps)                 |
| `VERIFY_ATOMIC_WITH_NONCE_IX_LEN`        | 1265 (8 + 72 + 1184 + 1 bump)                 |
| `VERIFY_NITRO_ATTESTATION_HEADER_LEN`    | 53 (8 + 1 + 8 + 32 + 4)                       |
| `VERIFY_NITRO_MODE_A`                    | 0                                             |
| `VERIFY_NITRO_MODE_B`                    | 1                                             |
| `MODE_B_REQUIRE_NONCE_DEFAULT`           | `true`                                        |

The consumer reference program id, used as `--consumer-program` in the CLI, is `A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ`. This package pins the verifier id. Pass the consumer id into `computeCommitment` and into the Mode B builders.

---

## 2. Packet picture

```
 legacy UDP packet                         1232 bytes max
 +------------------------------------------------------------------+
 | signatures | message header | account keys | recent blockhash    |
 |            | instructions (this is where Solana Confidential Compute bytes go)         |
 +------------------------------------------------------------------+

 Mode A instruction body                   1202 bytes
 +----------+----------------+---------------------------+--------+
 | disc 8   | nonce_slot 8   | SNP report 1184           | bumps 2|
 +----------+----------------+---------------------------+--------+

 Nitro header                              53 bytes
 +------+------+----------+------------+---------+
 | disc | mode | slot     | action hash| doc_len |
 |  8   |  1   |  8       |  32        |  4      |
 +------+------+----------+------------+---------+
 document bytes follow, length 1..=8192
```

`buildRegisterSignerIx`, `buildAtomicAttestationTx`, `buildVerifyAtomicWithNonceIx`, `buildVerifyNitroAttestationIx`, and `buildVerifyNitroAttestationTx` measure the serialized transaction. A length above 1232 throws `PacketTooLargeError`. The `len` field is the measured size.

A 4,526-byte hardware COSE document plus the 53-byte header is 4,579 bytes before signatures. That document fits the 8,192 parser limit. It does not fit the packet. The test rejects it.

Oversized packers live in `src/internal/oversized.ts`. The package entry does not re-export them. Use them to inspect layout in a test. Do not submit them to a cluster.

This client does not prepend a compute-budget instruction. Add `ComputeBudgetProgram.setComputeUnitLimit` in your own transaction when you broadcast. The verifier ceiling is 550,000 CU. The CLI dry-run uses 700,000. This package does not retry an RPC send.

---

## 3. Anchor discriminators and types

There is no `idl.json` in this directory. There is no Anchor codegen step. The 8-byte values are the Anchor discriminators, copied to match the Rust constants (`sha256("global:<instruction>")[..8]` and `sha256("account:<Account>")[..8]`).

`tsc` emits the TypeScript declarations in `dist/index.d.ts`. That file is the type surface.

| Export                                   | Bytes                                    |
| :--------------------------------------- | :--------------------------------------- |
| `INIT_POLICY_REGISTRY_DISCRIMINATOR`     | `[90, 53, 0, 89, 164, 70, 107, 186]`     |
| `VERIFY_AND_REGISTER_DISCRIMINATOR`      | `[246, 249, 100, 14, 102, 116, 92, 145]` |
| `VERIFY_ATOMIC_DISCRIMINATOR`            | `[65, 19, 195, 149, 67, 219, 25, 75]`    |
| `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR` | `[209, 4, 10, 239, 3, 142, 223, 250]`    |
| `VERIFY_NITRO_ATTESTATION_DISCRIMINATOR` | `[107, 76, 178, 169, 215, 146, 23, 95]`  |
| `ATTESTED_SIGNER_DISCRIMINATOR`          | `[43, 255, 114, 40, 233, 28, 127, 238]`  |

`parseAttestedSignerAccount` reads a 154-byte account:

```
 0    discriminator        8
 8    signerPubkey        32
40    enclaveType          1
41    measurement         48
89    chipIdHash          32
121   tcbVersion           8    bigint, little-endian
129   registeredSlot       8    bigint
137   expiresSlot          8    bigint
145   bump                 1
146   expiresUnixTimestamp  8    signed i64 LE, bigint
```

`parseAttestedSignerAccount` decodes fields; it does not validate ownership, PDA, caller signature, platform, measurement, or expiry. Consumers must enforce both slot and Unix deadlines using a trusted Clock. Slots, Unix timestamps, and the TTL use `bigint`. Do not put a slot in a JavaScript `number` past `2^53`.

`hashAction(discriminator, accounts: AccountMeta[], data)` matches the [V3 CPI wire contract](../../crates/solana-confidential-compute-cpi/README.md#4-hash_action):

```text
 ASCII("solana-confidential-compute:action:v1") || 0x00
 || u32le(account_count)
 || each ordered pubkey32 || isSigner:u8 || isWritable:u8
 || u32le(complete_wire_data_len) || discriminator || data
```

Flags are 0/1; retain duplicates and all consumer accounts. The discriminator/payload split does not affect the digest. Legacy pubkey-only input throws. `hashCompiledAction(message, consumerIndex, splitHint?)` computes effective global privileges from `Message | MessageV0`; the optional split hint has no effect. `validateCompiledAction(message, consumerIndex, expectedHash)` checks all consumer instruction bytes, including empty data. Unresolved LUTs and requested-writable reserved consumer keys are conservatively rejected. Source: [`src/index.ts`](src/index.ts).

`computeCommitment(slotHash, actionHash, consumerProgramId)` is SHA-256 of the three 32-byte fields in that order. `@spec SCC-VERIFY-001` is the on-chain rule that the slot hash inside the report is at most 150 slots old. This function only hashes. It does not read `SlotHashes`.

PDA helpers:

| Function                      | Seeds                                                 |
| :---------------------------- | :---------------------------------------------------- |
| `deriveSignerPda`             | `["attested_signer_v2", signer]`                      |
| `deriveVcekPda`               | `["vcek_v2", chipIdHash, tcb_le]`                     |
| `derivePolicyRegistryPda`     | `["policy_registry"]`                                 |
| `deriveUsedNoncePdaForSource` | `["nonce", [source], signer, nonce]` (AMD=1, Nitro=2) |
| `deriveLegacyUsedNoncePda`    | `["nonce", signer, nonce]` (readonly migration guard) |

`@spec SCC-ARCH-001` is the on-chain create path. These helpers call `PublicKey.findProgramAddressSync`.

`defaultAtomicAttestationExpectation` sets `requireNonce: true`. Builders pack `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR`. `@spec SCC-SEC-001` is the guest-policy rule inside the verifier. This client does not re-check policy bits.

---

## 4. Quickstart

Install from this directory after a clone:

```bash
cd sdks/typescript
npm install
npm run build
```

Derive the Mode A account for a workload key:

```javascript
const { PublicKey } = require('@solana/web3.js');
const { deriveSignerPda, SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID } = require('./dist/index.js');

const workload = new PublicKey('<WORKLOAD_ED25519_PUBKEY>');
const [pda, bump] = deriveSignerPda(workload, SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID);
console.log(pda.toBase58(), bump);
```

V3 hashes the complete consumer bytes and ordered effective account privileges, retaining duplicates. Compile the complete message with the final payer before obtaining evidence; `hashCompiledAction(message, consumerIndex)` resolves effective privileges. After filling evidence and transport addresses, call `validateCompiledAction` on the final message. Unresolved lookup tables and requested writable reserved accounts reject. Keep digest-derived nonce/upload accounts out of consumer accounts. Upgrade verifier, consumer helpers, SDKs and sidecar together and obtain fresh V3 evidence; there is no V1/V2 fallback. The low-level equivalent below requires already resolved effective metadata:

```javascript
const { PublicKey } = require('@solana/web3.js');
const { hashAction, computeCommitment } = require('./dist/index.js');

const consumer = new PublicKey('A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ');
const actionHash = hashAction(
    Uint8Array.of(1),
    [/* {pubkey, isSigner, isWritable}, effective compiled flags in order */],
    new Uint8Array(),
);
const commitment = computeCommitment(
    new Uint8Array(32), // slot hash from SlotHashes
    actionHash,
    consumer,
);
```

Blockhash/signatures/other instructions' data are not hashed. Changes to payer, keys or instruction metadata require final validation. V3 requires fresh attestations and coordinated verifier/consumer/helper/SDK/sidecar migration, with no accepted V1/V2 fallback. The supported Nitro Mode B transaction builder validates its final digest after checking packet size. Oversized packers remain test harnesses; a full SNP report still exceeds live packet size and no staged atomic adapter is introduced.

The local session builder receives a workload `Keypair` and signs locally. Keep that key inside the enclave; the production signing path is the sidecar `POST /v1/sign`, which this SDK does not call automatically. The coordinated upstream issue #186 fix rejects every System Program instruction before workload-key signing in both SDKs. Custom consumer programs, accounts, and data still require caller policy; the SDK does not provide the sidecar's transaction-screening guarantees. Require the #186 implementation in the selected release before relying on its System Program guard.

---

## 5. What the tests lock

`test/packet.test.cjs` locks the 1,232-byte rejection for a raw SNP report. `test/nitro.test.cjs` locks `MAX_NITRO_DOCUMENT_LEN` at 8192, the Nitro header length, and the packet rejection for a document that fits the parser and misses the packet.

`@spec SCC-SEC-001` is not re-implemented here. A debug-policy report is rejected by `solana-confidential-compute-core` and by `solana-confidential-compute-verifier`.

### Current Mode A V2 contract

The current account uses seed `[b"attested_signer_v2", signer_pubkey]`, discriminator `sha256("account:AttestedSignerAccountV2")[..8]` = `[43, 255, 114, 40, 233, 28, 127, 238]`, and a 154-byte serialized layout. The bump remains at byte 145; bytes 146..154 contain `expires_unix_timestamp` as signed little-endian i64. V1 (`attested_signer`, 146 bytes, V1 discriminator) is historical and is rejected by the current V2 consumer contract; do not pad or reinterpret it as V2.

A valid session requires both `clock.slot <= expires_slot` and `0 <= clock.unix_timestamp < expires_unix_timestamp`. Slot equality is valid; Unix deadline equality is expired. Both values come from the trusted Clock, not from caller arguments. A decoder alone does not perform session validation. Consumer helpers also check owner/discriminator, workload signature and stored pubkey, caller-pinned measurement and platform; the low-level helper additionally re-derives the PDA. Registration derives the Unix deadline independently of slot duration (and caps GCP sessions at JWT expiry).

Sources: [verifier state](../../programs/solana-confidential-compute-verifier/src/state.rs), [deadline construction](../../programs/solana-confidential-compute-verifier/src/processor.rs) (`session_unix_deadline`), [CPI validation](../../crates/solana-confidential-compute-cpi/src/lib.rs) (`assert_attestation_signer`), [zero-copy adapter](../../crates/solana-confidential-compute-cpi/src/anchor.rs), and [TypeScript decoder](../../sdks/typescript/src/index.ts). These source contracts do not establish deployment or fresh hardware/SBF evidence.

### Backend measurement governance

`BackendPolicy` is authoritative for measurement admission: source 1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space. Each canonical PDA uses `[b"backend_policy", &[source]]` and holds up to eight measurements. Missing, empty, or mismatched backend policy fails closed. The global `PolicyRegistry.measurement_count` / `measurements` fields and `update_policy` measurement payload are deprecated as runtime controls and retained for state/wire compatibility; clearing that global list does not halt admission. There is no implicit global/backend allowlist AND. Registry authority checks and monotonic AMD TCB floors remain active.

To halt new admission, the registry authority uses `set_backend_policy` with an empty list (`[]`) for each relevant backend; update all three policies to halt all backends. Rust exposes `build_set_backend_policy_ix`, TypeScript `buildSetBackendPolicyIx`. This does not revoke existing Mode A sessions: use `revoke_attested_signer` separately for targeted containment. These are source contracts, not evidence of deployment or hardware/SBF validation.
