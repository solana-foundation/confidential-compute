# solana-confidential-compute-consumer-reference

This program shows a DeFi, oracle, or real-world-asset program how to accept a Solana Confidential Compute workload key. It performs no custody math. It performs the attestation check, then returns success.

Program id:

```
A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ
```

Devnet explorer:

```
https://explorer.solana.com/address/A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ?cluster=devnet
```

The verifier id it trusts is `solana_confidential_compute_cpi::ID`:

```
EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh
```

Devnet program-data account: `8o22e8hzYPkWAn48wE91CaL4WJQawhUP4YiqdozkE6ym`. Slot **505,980,264**. ELF length **127,744** bytes. Header: `e_machine = 0x107` (`EM_SBF`), `e_flags = 0x0`. Upgrade transaction [`5a92Bwn8p9371LRQhtUJNrbKtCAoe67Wzjd6L9gbCsyGJ5szzoFuLBz5uwAGkrdWnmMRorfeQVXFnKs7VNcTrdMC`](https://explorer.solana.com/tx/5a92Bwn8p9371LRQhtUJNrbKtCAoe67Wzjd6L9gbCsyGJ5szzoFuLBz5uwAGkrdWnmMRorfeQVXFnKs7VNcTrdMC?cluster=devnet). `scripts/build-sbpfv3.sh` does not build this program. The live ELF is not SBPFv3.

`execute_session_action` stays at or under **1,500 CU** (`MODE_A_CU_CEILING`, `@spec SCC-CONSUMER-001`). `execute_atomic_action` stays at or under **2,500 CU** (`MODE_B_CU_CEILING`, `@spec SCC-CONSUMER-002`). [`tests/consumer_tests.rs`](tests/consumer_tests.rs) asserts both ceilings. The Gate 3 Devnet sample of a rejected Mode A call consumed **355 CU**.

`@spec SCC-ARCH-001` `@spec SCC-VERIFY-001` `@spec SCC-SEC-001`

```bash
cargo test -p solana-confidential-compute-consumer-reference
```

---

## 1. Two instructions

The first byte of `instruction_data` selects the path.

| Byte | Constant | Function | CU ceiling |
| ---: | :--- | :--- | ---: |
| 0 | `IX_EXECUTE_SESSION_ACTION` | `execute_session_action` | 1,500 |
| 1 | `IX_EXECUTE_ATOMIC_ACTION` | `execute_atomic_action` | 2,500 |

Any other first byte returns `ConsumerError::InvalidInstruction` (custom 0).

`EXPECTED_MEASUREMENT` is 48 bytes of `0x42`. A production fork replaces that constant with the measurement of its own enclave image.

```
                    your protocol program
                    A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ
                                      |
              +-----------------------+-----------------------+
              |                                               |
              v                                               v
        byte 0: Mode A                                  byte 1: Mode B
        read 146-byte PDA                           hash this instruction
        signer must sign                           read previous instruction
```

---

## 2. Mode A

Accounts:

```
 0  AttestedSignerAccount     owned by the verifier
 1  workload signer           must be a signer
```

```
 workload transaction                         verifier already ran earlier
 +------------------------------------+       +---------------------------+
 | Ed25519 signature                  |       | AttestedSignerAccount     |
 | execute_session_action (byte 0)    |       | 146 bytes                 |
 +------------------------------------+       +---------------------------+
                    \______________________________/
                                 |
                                 v
                    AttestedSignerAccount::try_from_account_info
                    signer_pubkey == workload_signer.key
                    measurement == [0x42; 48]
                    current slot <= expires_slot
```

The account check uses the Anchor `Pod` in `solana_confidential_compute_cpi::anchor`. Owner, discriminator, and length come from that adapter. The reference program then compares the pubkey and calls `validate`. `@spec SCC-CONSUMER-001`.

This path does not run P-384. The P-384 check happened in `verify_and_register`.

---

## 3. Mode B and `assert_attestation_atomic`

Accounts:

```
 0  Instructions sysvar
 1..  every account that must be bound into the action hash
```

`execute_atomic_action` hashes its own identity. It does not read an action hash from the caller.

```
 bound_action_hash
   discriminator = [1]                  IX_EXECUTE_ATOMIC_ACTION
   accounts      = every account key and effective signer/writable flags, at most 64
   data          = instruction_data[1..]
        |
        v
 AtomicAttestationExpectation
   action_hash          = that digest
   expected_measurement = [0x42; 48]
   expected_signer      = None
   require_nonce        = true
   verifier_ix_index       = None          previous instruction
        |
        v
 assert_attestation_atomic_ctx
```

`MAX_BOUND_ACCOUNTS` is 64. That matches the legacy transaction account limit. The hash is computed on the stack. The function does not allocate.

`require_nonce: true` selects `verify_atomic_with_nonce`. The verifier instruction must be the previous top-level instruction. Its program id must be `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`. Its `consumer_program_id` must be this program. Its `action_hash` must equal the digest above.

```
 one transaction
 +----------------------------------+-------------------------------+
 | ix 0  solana-confidential-compute-verifier             | ix 1  this program            |
 | verify_atomic_with_nonce         | execute_atomic_action (0x01) |
 | REPORT_DATA[32..64] = commitment | assert_attestation_atomic     |
 +----------------------------------+-------------------------------+
        |                                      |
        |  commitment binds slot hash,         |  reads ix 0 through
        |  action hash, and this program id    |  the Instructions sysvar
        v                                      v
   UsedNonceAccount (49 bytes)            success or a CPI error
```

`@spec SCC-VERIFY-001` still applies inside instruction 0. The nonce slot must be at most 150 slots old. This program does not scan `SlotHashes` itself.

`@spec SCC-SEC-001` still applies inside instruction 0 for an SNP report. A debug guest never reaches instruction 1 with a successful verifier result.

Nitro Mode B uses the same helper when instruction 0 is `verify_nitro_attestation` with `mode == 1`. `parse_nitro_payload` accepts a definite map and an indefinite map (`0xbf` … break `0xff`). `skip_cbor_value_depth` accepts major type 7 simple values, including `null` (`0xf6`). Read the [`solana-confidential-compute-cpi` README](../../crates/solana-confidential-compute-cpi/README.md) before you pass a hardware COSE document into this check.

---

V3 requires a coordinated verifier/consumer/SDK/sidecar upgrade and fresh evidence. V1/V2 action digests have no fallback. Keep digest-derived nonce/upload addresses out of consumer accounts to avoid a hash fixed point.

## 4. What to copy

1. Keep `require_nonce` true.
2. Use `solana_confidential_compute_cpi::hash_action_account_infos` to hash complete instruction bytes and ordered effective account flags, including duplicates. The discriminator/payload split is local and does not affect the V3 digest. Prepare evidence with the SDK compiled-message helper using the final payer and transaction metadata, then validate the assembled message again.
3. Pass `verifier_ix_index: None` so the helper loads the current index from the sysvar.
4. Check once before executing exactly the committed operation and before any CPI. The separate #287 guard rejects nested use; the read-only helper does not count business operations within a handler.
5. Replace `EXPECTED_MEASUREMENT` with your image digest.
6. Set `expected_signer` when the protocol must name one workload key. This sample leaves it unset.

`@spec SCC-CONSUMER-002` is the 2,500 CU ceiling for `execute_atomic_action`. `@spec SCC-CONSUMER-001` is the 1,500 CU ceiling for `execute_session_action`.

### V3 commitment construction and migration

V3 hashes `"solana-confidential-compute:action:v1\0" || u32LE(account count) ||
(pubkey[32] || signer[1] || writable[1])* ||
u32LE(complete instruction length) || discriminator || payload` with SHA-256.
Flag bytes are 0 or 1; the discriminator/payload split does not affect the digest.
The outer slot/action/program commitment is unchanged. The reference discriminator
is one byte; Anchor applications use their complete eight-byte discriminator.

Offchain, use `solana_confidential_compute_sdk::hash_compiled_action` or TypeScript `hashCompiledAction`
with the **complete compiled message**, not an isolated instruction's declared
metas. A fee payer or another instruction can elevate a consumer account's flags.
Before obtaining evidence, compile final payer/program/account metadata for every
instruction, leaving other instruction data empty if necessary. Consumer data must
already be final. Keep digest-derived nonce/upload accounts out of consumer keys
to avoid requiring a hash fixed point. Fill in evidence and transport addresses,
then validate the final compiled message before signing. Changed aliases or
privileges must cause rejection and new evidence. Unresolved LUTs and requested
writes to reserved consumer accounts fail closed; no runtime feature guess is made.

Upgrade verifier, consumer/CPI helpers, SDKs and sidecar screen together, then obtain
fresh V3 attestations. V1/V2 digests are rejected; there is no legacy fallback.
This source migration does not deploy a program or add staged atomic support.

`tests/privilege_runtime.rs` reproduces a V1 downstream mutation caused by another
instruction's writable elevation, plus a signer-dependent runtime differential.
It checks the actual reference consumer rejects stale V3 and V1 digests and
accepts a fresh V3 digest for the final privileges. Its no-op verifier fixture
isolates consumer binding and does not prove cryptographic or hardware verification.
