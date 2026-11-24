# solana-confidential-compute-cpi

`solana-confidential-compute-cpi` is the on-chain helper a consumer program calls. It depends on `solana-program` 2.2, `solana-confidential-compute-core`, and `bytemuck`. It does not depend on `solana-sdk`.

The crate declares the same program id as `solana-confidential-compute-verifier`:

```
EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh
```

A consumer cannot pass a different verifier id. Mode A compares `account.owner` with `crate::ID`. Mode B compares `instruction.program_id` with `crate::ID`.

`@spec SCC-ARCH-001` `@spec SCC-VERIFY-001` `@spec SCC-SEC-001`

---

## 1. Two checks

```
 Mode A  (session)                         Mode B  (one transaction)

 consumer instruction                      instruction N-1: verifier
 +----------------------------+            instruction N  : consumer
 | attested PDA  (154 bytes)  |            +---------------------------+
 | workload signer (signer)   |            | Instructions sysvar       |
 +----------------------------+            | hash of THIS instruction  |
            |                              +---------------------------+
            v                                           |
 assert_attestation_signer                                 v
                                            assert_attestation_atomic
```

| Helper | When the consumer calls it | Ceiling in the reference program |
| :--- | :--- | ---: |
| `assert_attestation_signer` | After Mode A registration, including `verify_tdx_quote`. The hot path is an Ed25519 signature plus this PDA read. | at or under 1,500 CU (`@spec SCC-CONSUMER-001`) |
| `assert_attestation_atomic` | In the same transaction as `verify_atomic_with_nonce` or Nitro Mode B. TDX has no atomic packet. | at or under 2,500 CU (`@spec SCC-CONSUMER-002`) |

`programs/solana-confidential-compute-consumer-reference/tests/consumer_tests.rs` asserts both ceilings. The Gate 3 Devnet sample of a rejected Mode A call consumed 355 CU.

Call `assert_attestation_atomic` once in the top-level consumer handler before executing its committed operation and before any inner `invoke`. Every platform rejects a CPI frame, including self-CPI, with `InvalidConsumerStackHeight` (1018). The helper is read-only: repeated calls within the same handler do not consume another marker or enforce the number of business operations. Consumers must execute exactly the operation they hashed; a loop that executes a withdrawal multiple times after one check is a consumer authorization bug. The Instructions sysvar lists top-level instructions only. A Solana Confidential Compute call made after this program has already called out is not visible.

```bash
cargo test -p solana-confidential-compute-cpi
```

---

## 2. Mode A account

`ATTESTED_SIGNER_ACCOUNT_SIZE` is **154**. The discriminator is `sha256("account:AttestedSignerAccountV2")[..8]`:

```
[43, 255, 114, 40, 233, 28, 127, 238]
```

The seed is `ATTESTED_SIGNER_SEED` = `b"attested_signer_v2"`.

```
 byte
  0    discriminator          8
  8    signer_pubkey         32     SIGNER_PUBKEY_OFFSET
 40    enclave_type           1
 41    measurement           48     MEASUREMENT_OFFSET
 89    chip_id_hash          32
121    tcb_version            8
129    registered_slot        8
137    expires_slot           8     EXPIRES_SLOT_OFFSET
145    bump                   1     BUMP_OFFSET
146    expires_unix_timestamp 8     signed i64, little-endian
```

`assert_attestation_signer` does this, in order:

1. Read `Clock::get()`. The caller cannot supply the slot or Unix timestamp.
2. Require `workload_signer.is_signer`.
3. Require `attested_record.owner == ID`.
4. Require length at least 154 and the V2 discriminator above; check the caller-pinned `expected_platform` (AMD=1, Nitro=2, GCP=3, Intel TDX=5). Tag 4 (NVIDIA) is rejected.
5. Require the stored pubkey to equal `workload_signer.key`.
6. Rebuild the PDA with `create_program_address` and the stored bump. `@spec SCC-ARCH-001` uses that bump. This helper does not call `find_program_address`.
7. Require the measurement to equal `expected_measurement`.
8. Require `current_slot <= expires_slot` and `0 <= clock.unix_timestamp < expires_unix_timestamp`.

The function returns `expires_slot` on success.

`anchor::AttestedSignerAccount` is a `Pod` of 154 bytes with alignment 1. `u64` fields are raw little-endian bytes because offsets 121, 129, 137, and 146 are not 8-byte aligned. `try_from_account_info` checks the owner, the discriminator, and the length.

`assert_attestation_signer_at_slot` takes both simulated slot and Unix timestamp and exists under `test` and `test-bpf`. Production code uses `assert_attestation_signer`.

---

## 3. Mode B introspection

`MODE_B_REQUIRE_NONCE_DEFAULT` is **true**. `AtomicAttestationExpectation::default` sets `require_nonce: true`. A value of `false` returns `CpiError::NonceRequired` (custom error 16) before the body is parsed. `@spec SCC-SEC-005` closes the stateless path. `verify_atomic` without a nonce aborts in the verifier with the same code.

```
 Instructions sysvar
        |
        |  load_current_index_checked
        v
 current_index
        |
        |  verifier_ix_index = current_index - 1
        |  (unless the caller set an earlier index)
        v
 load_instruction_at_checked
        |
        +-- program_id == EKfHCT... ----+
                                        |
                    +-------------------+-------------------+
                    |                                       |
                    v                                       v
     VERIFY_ATOMIC_WITH_NONCE                 VERIFY_NITRO_ATTESTATION
     disc ends in ... 223, 250                disc ends in ... 146, 23, 95
                    |                                       |
                    v                                       v
            SNP report at offset 80              mode byte must be 1
```

`verifier_ix_index` must be strictly less than `current_index`. The instructions account key must equal `sysvar::instructions::ID`.

### 3.1 SNP body

The SNP instruction is 80 bytes of header plus 1,184 bytes of report.

| Range | Field | Check |
| :--- | :--- | :--- |
| `0x10..0x30` | `action_hash` | Equals `expectation.action_hash`. |
| `0x30..0x50` | `consumer_program_id` | Equals the consumer program id. |
| `80..1264` | report | Measurement and optional signer. |

`@spec SCC-VERIFY-001` freshness is enforced inside the verifier instruction, which already ran. This helper reads the report bytes that instruction carried. It does not scan `SlotHashes` again.

### 3.2 Nitro body

Nitro wire offsets inside the full instruction:

| Offset | Field | Length |
| :--- | :--- | ---: |
| 0 | discriminator | 8 |
| 8 | `mode` | 1 |
| 9 | `nonce_slot` | 8 |
| 17 | `action_hash` | 32 |
| 49 | `doc_len` | 4 |
| 53 | COSE document | `doc_len` |

Mode B requires `mode == VERIFY_NITRO_MODE_B` (`1`). `doc_len` must be in `1..=8192` (`MAX_NITRO_DOCUMENT_LEN`). The helper also checks that the next top-level instruction is this consumer, and that `user_data` matches `expected_signer` when that field is set.

### 3.3 CBOR in this crate

`parse_nitro_payload` accepts a definite map and an indefinite map (`0xbf` … break `0xff`). The hardware COSE document in `fixtures/nitro_hardware_document.cose` uses the indefinite form. `user_data` in that document is 32 bytes of `0x55`. PCR0 is the 48-byte digest from the Nitro hardware run.

`skip_cbor_value_depth` accepts major type 7 simple values whose additional info is 0 through 23. That includes `false` (`0xf4`), `true` (`0xf5`), and `null` (`0xf6`). The hardware document stores `public_key` as `null`. Additional info 24 through 30, including floats, returns `InvalidInstructionData`. Additional info 31 on major type 7 is the break stop (`0xff`).

Indefinite arrays (`0x9f`) and indefinite maps (`0xbf`) are skipped until that break. A break where a map value is required returns `InvalidInstructionData` and leaves the break unread. `MAX_CBOR_SKIP_DEPTH` is **8**, matching `solana-confidential-compute-crypto`. The skipper and the payload parser borrow the instruction bytes. They do not allocate.

The helper reads `user_data` and PCR0. Certificate chain and COSE signature checks stay in `verify_nitro_attestation`.

### 3.4 Intel TDX

`AttestationPlatform::IntelTdx` is `5`, the same value as `EnclaveType::IntelTdx`. `verify_tdx_quote` writes that tag. Pass `AttestationPlatform::IntelTdx` as `expected_platform` to `assert_attestation_signer` (and to the Anchor adapter) after the quote instruction has registered the signer.

`assert_attestation_atomic` parses SNP `verify_atomic_with_nonce` and Nitro Mode B. It does not parse `verify_tdx_quote`. TDX enrollment is Mode A. The quote instruction itself rejects every mode other than `0`.

`build_set_backend_policy_ix` in `solana-confidential-compute-sdk` is the governance builder for source 5. The quote and QE-report instruction layouts are documented on [solana-confidential-compute-verifier](../../programs/solana-confidential-compute-verifier/README.md). This crate checks the resulting signer record. It does not rebuild those instructions.

---

## 4. `hash_action`

`@spec SCC-VERIFY-014`. V3 streams the canonical full instruction into SHA-256 without allocating:

```
 b"solana-confidential-compute:action:v1\0"
 le_u32(account_count) || (pubkey32 || signer:u8 || writable:u8)*
 le_u32(complete_instruction_data_len) || complete_instruction_data
```

Preserve account order and duplicates. `hash_action(discriminator, accounts, payload)` accepts effective `AccountMeta` flags and concatenates the two byte slices; their split does not change the digest. On-chain consumers use `hash_action_account_infos` with their top-level accounts. Off-chain callers use the Rust/TypeScript SDK compiled-message helper with the final payer and complete transaction account metadata, then validate the final assembled message again. Isolated declared metas can omit privilege elevation. Unresolved address tables and requested writable reserved accounts reject.

Every Mode B verifier path hashes the actual next instruction before writing a nonce. Upgrade verifier, consumers, SDKs and sidecar screen together and obtain fresh V3 evidence. V1/V2 digests have no fallback. Keep digest-derived nonce/upload addresses out of consumer accounts. The reference consumer hashes its own complete bytes and effective account flags; it does not accept a caller-supplied digest.

Source APIs in [lib.rs](src/lib.rs): `hash_action(discriminator: &[u8], accounts: &[AccountMeta], data: &[u8]) -> [u8; 32]` replaces the pubkey-only signature. Supply effective flags, or use `hash_action_account_infos(discriminator: &[u8], accounts: &[AccountInfo], data: &[u8]) -> [u8; 32]` at the top-level consumer before CPI. Both stream the V3 hash. Program-id demotion follows the pinned Solana SDK, including its upgradeable-loader exception. Inner CPI or `invoke_signed` privileges describe a different action and must not be substituted. The [Anchor adapter](src/anchor.rs) `assert_attestation_atomic_action_ctx(instructions_sysvar, expectation, current_program_id, discriminator, accounts, payload)` recomputes `expectation.action_hash` from all ordered runtime `AccountInfo`s before invoking the existing guard. The older expectation-taking helpers require the caller to compute this binding; a supplied digest alone does not authenticate the action.

Off chain, [Rust `solana_confidential_compute_sdk::action`](../solana-confidential-compute-sdk/src/action.rs) exposes `hash_compiled_action(&VersionedMessage, consumer_index, split_hint)` and `validate_compiled_action(&VersionedMessage, consumer_index, &expected_hash)`, returning `Result` with `ActionCommitmentError`. The split hint is retained for source compatibility and does not affect the digest; validation hashes complete instruction bytes, including empty and non-Anchor data. [TypeScript](../../sdks/typescript/src/index.ts) provides `hashAction(discriminator, AccountMeta[], data)`, `hashCompiledAction(message, consumerIndex, splitHint?)` and `validateCompiledAction(message, consumerIndex, expectedHash)` for `Message | MessageV0`; legacy pubkey-only JS input throws. Compiled helpers reject unresolved address lookup tables and conservatively reject requested-writable reserved consumer keys across the pinned SDK's active and pending reserved sets, instead of guessing runtime feature activation.

### Construct before attesting, validate before signing

1. Compile a metadata template containing the **final payer, program IDs and every instruction's account metadata**. Consumer discriminator and payload must be final. Other instructions' data may be empty: those bytes do not determine compiled privileges.
2. Derive the V3 digest from that compiled template. Keep digest-derived nonce/upload addresses out of consumer account keys to avoid hash/data circularity; this procedure does not solve a fixed-point construction.
3. Obtain fresh attestation evidence binding that digest through the unchanged outer `SHA-256(slot_hash || action_hash || consumer_program_id)` commitment.
4. Fill evidence and derived transport keys, compile the final transaction, and validate the expected digest again before signing. Reject changed digest, key aliasing or privilege elevation that changes it. Blockhashes, signatures and other instructions' data are not hashed, but changing payer, keys or instruction metadata can change privileges and requires revalidation.

### Coordinated migration and limits

V3 has **no accepted V1/V2 fallback**. Migrate consumers, CPI/Anchor helpers, Rust/TypeScript SDKs and sidecar screening together and obtain fresh V3 attestations; old V1 pubkey-only and V2 split-data action digests cannot be reused with V3 consumers. Select a release containing the coordinated #300 implementation. This account-privilege commitment version is separate from the Mode A account-layout version.

The supported Nitro Mode B transaction builder validates the final compiled digest after its packet check. Quarantined oversized packers remain byte-layout harnesses; they are not a legacy consumer fallback. A full SNP report still exceeds the live packet limit; V3 introduces no staged atomic adapter. Source, native tests and serialized packets do not prove deployment, successful real SBF cryptographic enrollment or new hardware evidence.

---

## 5. Error codes

Codes that match `VerifierError` keep the same number. `ConsumerProgramMismatch` is CPI-only.

| Code | Variant |
| ---: | :--- |
| 3 | `DisallowedMeasurement` |
| 7 | `UnauthorizedPolicy` |
| 8 | `AttestationExpired` |
| 12 | `ActionHashMismatch` |
| 13 | `SignerMismatch` |
| 16 | `NonceRequired` |
| 1018 | `InvalidConsumerStackHeight` |
| 17 | `ConsumerProgramMismatch` |

Custom code 7 is policy. Custom code 17 is a consumer-id mismatch. Do not treat them as the same error.

---

## 6. Discriminators

| Name | Bytes |
| :--- | :--- |
| `VERIFY_ATOMIC_DISCRIMINATOR` | `[65, 19, 195, 149, 67, 219, 25, 75]` |
| `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR` | `[209, 4, 10, 239, 3, 142, 223, 250]` |
| `VERIFY_NITRO_ATTESTATION_DISCRIMINATOR` | `[107, 76, 178, 169, 215, 146, 23, 95]` |
| `VERIFY_TDX_QE_REPORT_DISCRIMINATOR` | `[210, 155, 95, 37, 125, 174, 77, 73]` (verifier crate) |
| `VERIFY_TDX_QUOTE_DISCRIMINATOR` | `[173, 239, 124, 214, 245, 185, 23, 137]` (verifier crate) |
| `ATTESTED_SIGNER_DISCRIMINATOR` | `[43, 255, 114, 40, 233, 28, 127, 238]` |

The live Mode B SNP path uses `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR` only.


### Current Mode A V2 contract

The current account uses seed `[b"attested_signer_v2", signer_pubkey]`, discriminator `sha256("account:AttestedSignerAccountV2")[..8]` = `[43, 255, 114, 40, 233, 28, 127, 238]`, and a 154-byte serialized layout. The bump remains at byte 145; bytes 146..154 contain `expires_unix_timestamp` as signed little-endian i64. V1 (`attested_signer`, 146 bytes, V1 discriminator) is historical and is rejected by the current V2 consumer contract; do not pad or reinterpret it as V2.

A valid session requires both `clock.slot <= expires_slot` and `0 <= clock.unix_timestamp < expires_unix_timestamp`. Slot equality is valid; Unix deadline equality is expired. Both values come from the trusted Clock, not from caller arguments. A decoder alone does not perform session validation. Consumer helpers also check owner/discriminator, workload signature and stored pubkey, caller-pinned measurement and platform; the low-level helper additionally re-derives the PDA. Registration derives the Unix deadline independently of slot duration (and caps GCP sessions at JWT expiry).

Sources: [verifier state](../../programs/solana-confidential-compute-verifier/src/state.rs), [deadline construction](../../programs/solana-confidential-compute-verifier/src/processor.rs) (`session_unix_deadline`), [CPI validation](../../crates/solana-confidential-compute-cpi/src/lib.rs) (`assert_attestation_signer`), [zero-copy adapter](../../crates/solana-confidential-compute-cpi/src/anchor.rs), and [TypeScript decoder](../../sdks/typescript/src/index.ts). These source contracts do not establish deployment or fresh hardware/SBF evidence.

Existing contract coverage: [TypeScript constants/decoding](../../sdks/typescript/test/contracts.test.cjs), [V2 lifecycle/legacy rejection](../../sdks/typescript/test/lifecycle.test.cjs), and the expiry cases in [the CPI implementation tests](src/lib.rs) and [adapter tests](src/anchor.rs). Native tests and historical CU reports do not establish current real SBF or hardware execution.
