# solana-confidential-compute-verifier

`solana-confidential-compute-verifier` is the on-chain program. It checks a hardware report, checks the measurement allowlist, and records the result. It is an SBPFv3 program. `e_flags = 0x3` (`@spec SCC-DEPLOY-001`).

The program id comes from the deployer keypair at deploy time. A buyer deploys a separate copy and receives a new program id.

Grantee Devnet deployment:

```
EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh
```

Devnet explorer:

```
https://explorer.solana.com/address/EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh?cluster=devnet
```

`@spec SCC-VERIFY-001` `@spec SCC-SEC-001` `@spec SCC-ARCH-001`

```bash
cargo test -p solana-confidential-compute-verifier
bash scripts/build-sbpfv3.sh --self-test
```

`scripts/build-sbpfv3.sh` compiles this program only. A passing build prints `e_flags=0x3` for `target/deploy/solana_confidential_compute_verifier.so` and checks static Murmur3-32 syscalls. It rejects `SHT_DYNSYM`, `SHT_REL`, and `SHT_RELA`. `e_machine` for that artifact is `EM_BPF` (`0xf7`). Platform-tools pin is v1.56. Do not pass `--arch v3` to platform-tools older than v1.53. Do not pass `--features test-bpf` on a release build.

The CU harness is [`programs/solana-confidential-compute-verifier/tests/cu_benchmarks.rs`](tests/cu_benchmarks.rs). `test_cu_benchmarks_live_sbf` is `#[ignore]`. A manual run returns without measuring when `target/deploy/solana_confidential_compute_verifier.so` is absent. It also returns when ELF byte 48 is `0x3`. The log then states that `solana-program-test` 2.2 cannot load that ELF. The file does not pin a measured integer. Measured figures are in the [root README](../../README.md), section 6.2.

Devnet program-data account `EWShgrBQhkQiTmGTrYm9DuWvUPKRcsbECqXJuGa1BFcX`, slot **505,980,419**, holds a **673,784-byte** ELF. Header words: `e_machine = 0xf7`, `e_flags = 0x3`. Upgrade transaction [`KHUQUyx8xQB5VD4KFBsE3hQ4RrtUD8iQ72ZbMEeSiYomU1u1y48oZF73eqTkvQ93Dp8PXUjJdZb2jE5P5JjG2QM`](https://explorer.solana.com/tx/KHUQUyx8xQB5VD4KFBsE3hQ4RrtUD8iQ72ZbMEeSiYomU1u1y48oZF73eqTkvQ93Dp8PXUjJdZb2jE5P5JjG2QM?cluster=devnet). The Gate 4 ELF was 618,288 bytes at slot 503,550,668. That artifact is not the account contents now.

Devnet upgrade authority: `BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG`. Production custody is intended to use Foundation governance (Squads multisig); this repository does not establish a production vault address or executed handoff. The loader upgrade authority and `PolicyRegistry.authority` are separate controls. The registry signer cannot change any trust root: since upstream PR #255, `rotate_root_cert` returns `VerifierError::InvalidInstruction` even when the registry authority signs, and leaves the legacy AMD P-384 `ark_pubkey_xy` field unchanged. Pinned Nitro and Milan RSA roots require a code change. The coordinated upstream #173 fix / PR #226 restricts production AMD to pinned Milan RSA, so that legacy field has no supported vendor-root meaning. A registry signer may be a keypair or a governance PDA signing via CPI; Solana Confidential Compute enforces no threshold or timelock itself. See the [authority and trust-root model](../../SECURITY.md#administrative-authorities-and-trust-roots). Build with `scripts/build-sbpfv3.sh`. The authority key signs the upgrade. See [`scripts/README.md`](../../scripts/README.md).

The Gate 3 Devnet sample of a rejected `execute_session_action` call consumed **355** compute units (`@spec SCC-CONSUMER-001`). The Gate 3 program-test note for `execute_atomic_action` is about **1,950** compute units (`@spec SCC-CONSUMER-002`). `programs/solana-confidential-compute-consumer-reference/tests/consumer_tests.rs` checks both instructions. It does not encode 1,950.

The release profile sets `overflow-checks = true` and `panic = "abort"`.

---

## 1. Dispatch

`Processor::process_with` reads 8 bytes. A shorter buffer returns `VerifierError::InvalidInstruction` (custom 0). An unknown discriminator returns `InvalidDiscriminator` (custom 1).

```
 instruction_data
 +------------------+------------------------------+
 | discriminator 8  | rest                         |
 +------------------+------------------------------+
          |
          +-- init_policy_registry
          +-- update_policy
          +-- rotate_root_cert
          +-- register_vcek
          +-- verify_and_register            Mode A SNP
          +-- verify_atomic                  abort: NonceRequired
          +-- verify_atomic_with_nonce       Mode B SNP
          +-- register_jwks_key
          +-- revoke_jwks_key
          +-- verify_google_jwt
          +-- verify_nitro_attestation       Mode A or Mode B Nitro
          +-- issue_tdx_challenge            Intel TDX freshness (handler 19)
          +-- verify_tdx_qe_report           Intel TDX step 1 (handler 20)
          +-- verify_tdx_quote               Intel TDX step 2 (handler 21)
          +-- verify_nvidia_attestation      Reserved; both modes fail closed
```

| Instruction | Discriminator |
| :--- | :--- |
| `init_policy_registry` | `[90, 53, 0, 89, 164, 70, 107, 186]` |
| `update_policy` | `[227, 150, 114, 217, 142, 172, 100, 228]` |
| `register_vcek` | `[228, 65, 209, 71, 242, 135, 131, 17]` |
| `verify_and_register` | `[246, 249, 100, 14, 102, 116, 92, 145]` |
| `verify_atomic` | `[65, 19, 195, 149, 67, 219, 25, 75]` |
| `verify_atomic_with_nonce` | `[209, 4, 10, 239, 3, 142, 223, 250]` |
| `rotate_root_cert` | `[137, 212, 96, 71, 222, 5, 133, 104]` (refused: `InvalidInstruction`, #255) |
| `register_jwks_key` | `[122, 195, 232, 116, 203, 137, 219, 14]` |
| `revoke_jwks_key` | `[184, 102, 12, 45, 99, 128, 41, 16]` |
| `verify_google_jwt` | `[104, 38, 12, 199, 131, 240, 78, 165]` |
| `verify_nitro_attestation` | `[107, 76, 178, 169, 215, 146, 23, 95]` |
| `issue_tdx_challenge` | `[70, 183, 171, 140, 168, 137, 54, 149]` |
| `verify_tdx_qe_report` | `[210, 155, 95, 37, 125, 174, 77, 73]` |
| `verify_tdx_quote` | `[173, 239, 124, 214, 245, 185, 23, 137]` |
| `verify_nvidia_attestation` | `[31, 2, 40, 104, 69, 155, 234, 120]` |

`verify_atomic` returns `VerifierError::NonceRequired` (custom 16). It does not verify the report. The live Mode B path is `verify_atomic_with_nonce`.

Nitro and NVIDIA `mode` 0 is Mode A. `mode` 1 is Mode B. Google JWT uses the same mode numbers.

`set_backend_policy` configures `BackendPolicy` for `source` in `1..=5`:
- `1`: AMD SEV-SNP (`AttestationPlatform::AmdSevSnp`)
- `2`: AWS Nitro Enclaves (`AttestationPlatform::AwsNitro`)
- `3`: Google Cloud Confidential Space (`AttestationPlatform::GcpConfidentialSpace`)
- `4`: NVIDIA Confidential GPU (`AttestationPlatform::NvidiaH100`), reserved and unable to enroll
- `5`: Intel TDX (`AttestationPlatform::IntelTdx` and `EnclaveType::IntelTdx`)

---

## 2. Mode A accounts and bytes

`verify_and_register` accounts, in order:

```
 0  payer                  signer, writable
 1  PolicyRegistry         PDA
 2  VcekAccount            PDA
 3  AttestedSignerAccount  PDA, writable
 4  UsedNonceAccount       PDA, writable
 5  sysvar::slot_hashes    key must be the SlotHashes id
 6  sysvar::clock          key must be the Clock id
 7  system program
```

Instruction rest:

```
 rest[0..8]              nonce_slot, little-endian u64
 rest[8..8+1184]         AMD report, borrowed, not copied
```

`@spec SCC-ARCH-002` borrows the report from instruction data. `PolicyRegistry` and `VcekAccount` are read from account bytes. The hot path does not Borsh-deserialize those two accounts onto the stack.

`@spec SCC-SEC-001` runs inside report policy checks: version `1..=5`, `signature_algo == 1`, VMPL 0, debug bit clear, migration bit clear, reserved bit set.

`@spec SCC-VERIFY-001` then runs `verify_recent_slot_hash`. The nonce is report bytes `0x070..0x090`. The age limit is 150 slots.

On success the program writes:

- `AttestedSignerAccount` V2 (154 bytes). `expires_slot = clock.slot + 216000`; consumers also enforce its exclusive Unix deadline (see the source-linked V2 contract below).
- `UsedNonceAccount` (49 bytes, with the signing payer as `refund_pubkey`) at source-tagged seed `[b"nonce", &[source], signer_pubkey, nonce]` (AMD=1, Nitro=2) or `[b"nonce", &[3], sha256(binding)]` (GCP).
- The untagged pre-upgrade address (`[b"nonce", signer_pubkey, nonce]`, GCP `[b"nonce", sha256(binding)]`) must be passed as a readonly account. A tombstone there blocks the nonce through 150 slots after its consumption slot inclusive; a future consumption slot fails closed, and a missing account returns `InvalidAccountAddress`.

A second use of the same nonce finds the discriminator and returns `NonceAlreadyUsed` (custom 5). Legacy 17-byte records written before #258 also return `NonceAlreadyUsed`.

`close_stale_nonce` closes a 49-byte record more than 150 slots after its consumption slot and refunds all lamports to `refund_pubkey`; legacy 17-byte records cannot be closed. `close_attested_signer` closes an expired `[b"attested_signer_v2", signer]` record (`clock.slot > expires_slot`) only when the workload signer signs, and refunds the rent to that signer. After a successful close each emits one `solana-confidential-compute:governance:v1` event: operation `close_stale_nonce` or `close_attested_signer`, actor (the refund account or the workload signer), closed account, SHA-256(old account bytes), SHA-256(empty data). Failed closes emit nothing; indexers must still require transaction success.

---

## 3. SlotHashes pin

`load_slot_hash` rejects any account whose key is not `sysvar::slot_hashes::ID`. The error is `InvalidAccountAddress` (custom 9).

```
 SlotHashes account data
 +------------------+----------------------------------------------+
 | num_entries  u64 | entry 0          entry 1         ...         |
 | 8 bytes LE       | 8 byte slot + 32 byte hash   (40 each)       |
 +------------------+----------------------------------------------+

 scan: i in 0 .. min(num_entries, 150)
 start = 8 + i * 40
 match when slot == nonce_slot
 age:  clock.slot - nonce_slot <= 150
```

A missing entry, a short account, or an age above 150 returns `StaleNonce` (custom 4). The scan stops at 150 entries. A longer sysvar cannot force an unbounded loop.

Mode B uses the same function. It loads `slot_hash` from the sysvar. It does not treat `view.nonce()` as the slot hash. The commitment check is:

```
 REPORT_DATA[32..64] == SHA-256(slot_hash || action_hash || consumer_program_id)
```

A mismatch returns `ActionHashMismatch` (custom 12).

---

## 4. State accounts

Sizes are `SIZE` on the Rust type. The 8-byte discriminator is `sha256("account:<Name>")[..8]`.

| Account | Size | Seed | Discriminator (first bytes) |
| :--- | ---: | :--- | :--- |
| `AttestedSignerAccount` | **154** | `[b"attested_signer_v2", signer]` | `[43, 255, 114, 40, 233, 28, 127, 238]` |
| `VcekAccount` | 194 | `[b"vcek_v2", chip_id_hash, tcb_le]` | `[180, 227, 118, 227, ...]` |
| `PolicyRegistry` | 529 | `[b"policy_registry"]` | `[175, 179, 180, 44, ...]` |
| `UsedNonceAccount` | 49 | `[b"nonce", &[source], signer, nonce]` | `[138, 99, 69, 17, ...]` |
| `UsedNonceAccount` (pre-upgrade, readonly guard) | 17 or 49 | `[b"nonce", signer, nonce]` | `[157, 75, 223, 206, ...]` or `[138, 99, 69, 17, ...]` |
| `BackendPolicy` | 398 | `[b"backend_policy", &[source]]` | `[99, 240, 210, 185, 15, 133, 69, 24]` |
| `JwksAccount` | 574 | `[b"jwks", sha256(kid)]` | `[114, 88, 154, 233, ...]` |

```
 VcekAccount (194)
 disc 8 | chip_id_hash 32 | tcb 8 | pubkey X||Y 96 | registered_slot 8 | bump 1
 | trust_profile 32 | valid_until_unix 8 | is_revoked 1
 public key starts at PUBLIC_KEY_OFFSET 0x30
 bump is at BUMP_OFFSET 0x98

 PolicyRegistry (529)
 disc 8 | authority 32 | ARK X||Y 96 | min TCB 4 | count 4 | 8 x measurement 48 | bump 1
 min TCB at 0x88
 measurement count at 0x8C
 measurements at 0x90
 bump at 0x210

 UsedNonceAccount (17)
 disc 8 | slot 8 | bump 1

 JwksAccount (574)
 disc 8 | kid_hash 32 | modulus 256 | exponent 4 | n0 8 | R^2 256
        | registered_slot 8 | is_revoked 1 | bump 1
```

`PolicyRegistry` retains eight legacy measurement slots for compatibility. Admission reads the source-specific `BackendPolicy`, which rejects all-zero measurements and bounds its active count to eight.

`register_vcek` checks the ARK to ASK to VCEK signatures, then `parse_vcek_identity`. The certificate `hwID` and TCB must equal the instruction arguments. A mismatch returns `VerificationFailed` (custom 2) before the PDA is created. A zero `chip_id` derives the seed from `sha256(public_key_xy)` (`@spec SCC-VERIFY-009`). The account is first-writer. A second create returns `AccountAlreadyInitialized`.

Devnet `PolicyRegistry` PDA: `2FX8HZqEXr7x8kHzkhy4KPUuViVt9M6xqhFTB12jaDUf`.

`@spec SCC-ARCH-001` creates a PDA with `system_instruction::create_account` and `invoke_signed` when the account is empty. An account that already has the exact size and the program owner skips the CPI. Any other length is `InvalidAccountData`.

---

## 5. Nitro instruction

`verify_nitro_attestation` rest layout:

```
 mode          1 byte     0 = Mode A, 1 = Mode B
 nonce_slot    8 bytes
 action_hash  32 bytes
 doc_len       4 bytes    little-endian
 document      doc_len    must be <= 8192
```

The processor requires `rest.len() == header + doc_len`. `MAX_NITRO_DOCUMENT_LEN` is **8192**. The on-chain chain accepts `cabundle[0]` only when its key equals `AWS_NITRO_ROOT_CA_PUBKEY_XY`. `PolicyRegistry.ark_pubkey_xy` is not a Nitro trust anchor. PCR0 must be non-zero and present in the Nitro `BackendPolicy` (source 2).

A 4,526-byte hardware document plus the header does not fit in a 1,232-byte packet. The v1.0.0 Devnet smoke transaction [`2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH`](https://explorer.solana.com/tx/2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH?cluster=devnet) landed at slot 505,980,579. The parsing path consumed 8,122 compute units. The verifier then returned `custom program error: 0x2` (`VerificationFailed`). Transaction meta `computeUnitsConsumed` is 8,272. The Phase 7.3 sample was a 522-byte document. That instruction consumed 7,829 compute units and returned the same custom error.

---

## 6. NVIDIA instruction safety gate

`verify_nvidia_attestation` (discriminator `[31, 2, 40, 104, 69, 155, 234, 120]`)
is reserved. The legacy 81-byte packet has no authenticated NVIDIA evidence,
CPU quote, proof or authorized appraiser signature. Both modes return
`VerifierError::NvidiaAttestationUnavailable` (custom 18) before account reads,
allocations, nonce consumption or signer creation/renewal. Invalid mode/length
returns `InvalidInstruction`. The signature-verifier backend is passed through
dispatch; no backend can bypass the gate.

Legacy data layout after the 8-byte discriminator (73 bytes):

```
 mode                  1 byte     0 = reserved Mode A, 1 = reserved Mode B
 nonce_slot            8 bytes    little-endian u64
 expected_action_hash 32 bytes
 gpu_measurement      32 bytes
```

Source-4 `BackendPolicy` management remains governance-controlled. Entries are
public reference values and grant no NVIDIA authority. SDK packet/PDA builders
remain available for fixtures, but cannot enroll a session or authorize an action.

`solana-confidential-compute-cpi` rejects NVIDIA V2 signer records and atomic packets with
`UnsupportedPlatform`, including previously minted unauthenticated records.
Deployed consumers need a rebuild/upgrade to adopt this check; no deployment is
performed by this fix. Old records must not be migrated as genuine evidence.

upstream #320 v3
requires a separate proof-backed adapter and versioned record with complete
DCAP/NRAS authentication, key/evidence/runtime binding, policy/domain/freshness,
expiry/revocation and one-use challenges. No implicit appraiser key is introduced.
See [remaining NVIDIA gates](../../docs/intent/confidential-compute-nvidia-specs.md).

---

## 6.1 Intel TDX

Devnet program id, shared with the rest of this program:

```
EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh
```

A DCAP quote is signed with ECDSA P-256. Solana checks P-256 with the native `secp256r1` precompile (`Secp256r1SigVerify1111111111111111111111111`). The precompile reads its message from instruction data. The QE message is 384 bytes (precompile instruction about 497 bytes). The Trust Domain header and body are 632 bytes (precompile instruction about 745 bytes). Together those instructions exceed a 1,232-byte packet, so verification is split.

`Processor::process_with` numbers the handlers after the staged-transport gate. `issue_tdx_challenge` is handler 19. `verify_tdx_qe_report` is handler 20. `verify_tdx_quote` is handler 21. Quote mode must be `0` (Mode A). Any other mode returns `InvalidInstruction`.

| Instruction | Handler | Harness band | What it checks |
| :--- | ---: | :--- | :--- |
| `verify_tdx_qe_report` | 20 | 12,000–22,000 CU | PCK signature over the QE report, QE identity, debug bit clear. Writes `TdxSessionAccount`. |
| `verify_tdx_quote` | 21 | 40,000–70,000 CU | Attestation-key signature over the TD body, platform digest, `REPORTDATA`, challenge. Writes the Mode A signer. |
| Both steps | 20 then 21 | about 75,000 CU | Sum of the bands is 52,000–92,000 CU. Under the 200,000 default limit. |

The bands are the assertions in [`tests/tdx_compute_units.rs`](tests/tdx_compute_units.rs) on the transaction's `compute_units_consumed`. That test is `#[ignore]` until an SBF artifact is supplied. They are not a Devnet sample. The deployed `v1.0.0` ELF at the Devnet address predates these handlers. Deploy this source before calling them.

Order of work:

1. `issue_tdx_challenge`. Accounts: challenge PDA writable, payer signer, system program, clock, slot hashes. Payload: 32-byte nonce, then `nonce_slot` as a little-endian `u64`. The program copies the slot hash from `SlotHashes`. The PDA is `[b"challenge", &[5], nonce]`. Lifetime is 1,500 slots. Reissue of a live or consumed challenge returns `StaleNonce`.
2. `secp256r1` over the 384-byte QE report, then `verify_tdx_qe_report`. Accounts: session PDA writable, source-5 policy, payer signer, system program, clock, instructions sysvar. The session PDA is `[b"tdx_session", sha256(compressed attestation key)]`. It stays live for 150 slots.
3. `secp256r1` over the 632-byte header and body, then `verify_tdx_quote`. Accounts: attested-signer PDA writable, session PDA, source-5 policy, nonce PDA writable, payer signer (signer, writable), system program, clock, challenge PDA (writable), workload signer (signer), instructions sysvar. Payload is one mode byte (`0`) and `nonce_slot`.

Success writes `AttestedSignerAccount` with `enclave_type = EnclaveType::IntelTdx` (5). `chip_id_hash` is `SHA-256(MR_TD)`. The measurement is the journal hash in the first 32 bytes and 16 zero bytes. The journal hash is `SHA-256(MR_TD || MRCONFIGID || SHA-256(RTMR[0..3]))`.

Source 5 must allowlist four 48-byte values: the PCK key padded with 15 zero bytes, the QE identity digest padded with 16 zero bytes, the platform digest padded with 16 zero bytes, and the GPU RIM digest padded with 16 zero bytes. A zero measurement is rejected. Trust assumptions are in [SECURITY.md](../../SECURITY.md#intel-tdx-trust-assumptions).

---

## 7. Error codes

| Code | Name |
| ---: | :--- |
| 0 | `InvalidInstruction` |
| 1 | `InvalidDiscriminator` |
| 2 | `VerificationFailed` |
| 3 | `DisallowedMeasurement` |
| 4 | `StaleNonce` |
| 5 | `NonceAlreadyUsed` |
| 6 | `TcbBelowMinimum` |
| 7 | `UnauthorizedPolicy` |
| 8 | `AttestationExpired` |
| 9 | `InvalidAccountAddress` |
| 10 | retired (`SignerAlreadyAttested` is not reused) |
| 11 | `InvalidSignature` |
| 12 | `ActionHashMismatch` |
| 13 | `SignerMismatch` |
| 14 | `InvalidProof` |
| 15 | `InvalidAuthority` |
| 16 | `NonceRequired` |
| 18 | `NvidiaAttestationUnavailable` |

`Groth16SyscallVerifier` is not `DefaultVerifier`. Its error returns use `InvalidProof` (custom 14). A successful pairing returns `Ok(())`.

`DefaultVerifier` depends on the build:

| Build | `DefaultVerifier` |
| :--- | :--- |
| `mock-crypto` | `MockVerifier`. Forbidden on `target_os = "solana"` unless `test-bpf` is set. |
| Host, no `mock-crypto` | `DirectCryptoVerifier`. Calls `solana_confidential_compute_crypto::verify_p384_signature`. |
| `target_os = "solana"`, no `mock-crypto` | `SolanaDefaultVerifier`. Introspects a preceding sigverify instruction. |

`EXPECTED_SIGVERIFY_PROGRAM_ID` is the pinned sigverify program. No mainnet secp384r1 precompile id is assigned. Introspection fails closed until that program is deployed. On Solana, `DirectCryptoVerifier::verify_p384` returns `InvalidSignature` and does not run the host P-384 code. `scripts/build-sbpfv3.sh` does not pass `--features mock-crypto`. The Devnet ELF uses `SolanaDefaultVerifier`.

Measured compute units are in the [root README](../../README.md), section 6.2, including the Intel TDX bands from section 6.1. The Devnet parsing path consumed 8,122 compute units. Policy init consumed 7,435 compute units. `@spec SCC-PERF-001`.

---

## 8. Source files

| File | Role |
| :--- | :--- |
| `lib.rs` | `declare_id!` and module exports. |
| `entrypoint.rs` | Solana entrypoint. |
| `processor.rs` | Dispatch and account rules. |
| `payload.rs` | Discriminators and argument structs. |
| `state.rs` | Account layouts. |
| `error.rs` | Custom error numbers. |
| `introspection.rs` | Instruction-introspection backend. |
| `groth16.rs` | Experimental P-384 Groth16 backend (`alt_bn128_pairing`). Unwired as the default. |
| `tdx.rs` | Intel TDX DCAP quote view and `secp256r1` introspection. |


### Current Mode A V2 contract

The current account uses seed `[b"attested_signer_v2", signer_pubkey]`, discriminator `sha256("account:AttestedSignerAccountV2")[..8]` = `[43, 255, 114, 40, 233, 28, 127, 238]`, and a 154-byte serialized layout. The bump remains at byte 145; bytes 146..154 contain `expires_unix_timestamp` as signed little-endian i64. V1 (`attested_signer`, 146 bytes, V1 discriminator) is historical and is rejected by the current V2 consumer contract; do not pad or reinterpret it as V2.

A valid session requires both `clock.slot <= expires_slot` and `0 <= clock.unix_timestamp < expires_unix_timestamp`. Slot equality is valid; Unix deadline equality is expired. Both values come from the trusted Clock, not from caller arguments. A decoder alone does not perform session validation. Consumer helpers also check owner/discriminator, workload signature and stored pubkey, caller-pinned measurement and platform; the low-level helper additionally re-derives the PDA. Registration derives the Unix deadline independently of slot duration and caps new sessions at the authenticated source credential expiry (AMD ASK/VCEK chain, Nitro chain, or GCP JWT).

Sources: [verifier state](../../programs/solana-confidential-compute-verifier/src/state.rs), [deadline construction](../../programs/solana-confidential-compute-verifier/src/processor.rs) (`session_unix_deadline`), [CPI validation](../../crates/solana-confidential-compute-cpi/src/lib.rs) (`assert_attestation_signer`), [zero-copy adapter](../../crates/solana-confidential-compute-cpi/src/anchor.rs), and [TypeScript decoder](../../sdks/typescript/src/index.ts). These source contracts do not establish deployment or fresh hardware/SBF evidence.

### Backend measurement governance

`BackendPolicy` is authoritative for measurement admission: source 1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space, 4 = NVIDIA (reserved, does not enroll), 5 = Intel TDX. Each canonical PDA uses `[b"backend_policy", &[source]]` and holds up to eight measurements. Missing, empty, or mismatched backend policy fails closed. The global `PolicyRegistry.measurement_count` / `measurements` fields and `update_policy` measurement payload are deprecated as runtime controls and retained for state/wire compatibility; clearing that global list does not halt admission. There is no implicit global/backend allowlist AND. Registry authority checks and monotonic AMD TCB floors remain active.

To halt new admission, the registry authority uses `set_backend_policy` with an empty list (`[]`) for each relevant backend. Empty sources 1, 2, 3, and 5 to halt every backend that can enroll. Rust exposes `build_set_backend_policy_ix`, which accepts source `1..=5`. TypeScript exposes `buildSetBackendPolicyIx`. This does not revoke existing Mode A sessions: use `revoke_attested_signer` separately for targeted containment. These are source contracts, not evidence of deployment or hardware/SBF validation.
### Permanent targeted signer revocation

`revoke_attested_signer` retains the canonical V2 signer PDA as a permanent
public-key tombstone: `expires_slot == 0`. Ordinary admission always adds a
positive 216,000-slot TTL, so natural expiry never has this value. New revocations
also set the exclusive Unix deadline to zero. Existing zero-slot revocations
remain tombstones even when their old Unix deadline is nonzero.

AMD, GCP and Nitro Mode A refuse to overwrite these records, including after
natural expiry or when changing attestation source. `close_attested_signer`
refuses their deletion. CPI and Anchor consumers reject zero-slot tombstones,
including at slot zero. Other naturally expired records remain renewable and
closable. There is no un-revoke instruction: governance must retain the account
and its rent; recovery uses a different workload public key and fresh evidence.
This blocks this key, not every key a compromised workload could generate.

### Mode A admission lifetime and policy changes

The V2 record is an admission snapshot. Its exclusive Unix expiry is the minimum
of admission time plus 86,400 seconds and the authenticated source credential
expiry: cached ASK/VCEK chain expiry for AMD, minimum checked Nitro-chain
`notAfter`, or JWT `exp` for GCP. Consumers also enforce the independent
216,000-slot limit. This source does not shorten records already issued before
this change.

Measurement allowlists, TCB floors, tenant policy and issuer revocations are
checked at admission. They do not propagate automatically to live Mode A records.
Use governed `revoke_attested_signer` on affected keys for immediate session
containment. See [the security contract](../../SECURITY.md)
for the precise consumer boundary and operational enumeration requirement.

### AMD identity revocation across TCB caches

`revoke_vcek` keeps its discriminator and 40-byte identity/TCB payload. Its
accounts are now `[authority signer, registry readonly, tuple cache writable,
identity revocation writable, payer signer writable, System program]`.
The revocation PDA is `[b"amd_revocation", chip_id_hash]`, with no TCB seed.
Its permanent 41-byte record is discriminator
`[141,22,195,50,29,169,176,109]`, identity hash32 and canonical bump1.
Governance funds rent through the explicit payer. It may revoke an identity
before any tuple cache exists; the supplied tuple address must still be canonical
and either a valid existing cache or an empty System-owned account. Existing
caches are also marked revoked. Repeating revocation is idempotent. There is no
close or un-revoke instruction for the identity tombstone. Revocations made by
older program versions remain tuple-scoped until governance reissues
`revoke_vcek` with the new accounts to create the identity tombstone; this source
cannot enumerate or backfill historical caches automatically.

All AMD VCEK registration and SNP Mode A/B admission paths require the canonical
identity PDA as a readonly suffix account, even when it does not yet exist.
Only an empty, nonexecutable System-owned canonical account means no revocation;
omission, foreign owner or program-owned tombstone fails closed. Existing fixed
account positions and other suffix accounts retain their order. Integrators must
update instruction builders together with the verifier; old builders fail closed.

The identity is authenticated by the endorsement certificate and report/cache
binding: SHA-256(chip ID) for VCEK, SHA-256(endorsement public key XY) for VLEK.
Thus VCEK revocation applies to the same identified chip across TCB versions;
VLEK revocation applies to that endorsement key across TCB versions. VLEK does
not expose a stable physical-chip identity here: a different certified VLEK key
is a different identity and is not covered by this denylist. Do not advertise
this as physical-chip containment across distinct VLEK keys. Live Mode A records
remain admission snapshots; target their signer records separately for immediate
containment. No deployed-state migration or authentic hardware proof is claimed.
