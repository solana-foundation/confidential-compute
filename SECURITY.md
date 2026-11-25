# SECURITY.md: Security Model & Invariant Specifications

This document defines the security architecture, threat model, trust boundaries, and formal invariant specifications (`@spec SCC-SEC-*`) for **Solana Confidential Compute** (Verifiable Compute Layer for Solana).

This specification is prepared for independent third-party security audits, grant evaluators, and protocol integrators.

---

## 1. System Architecture

```
 +------------------+     +------------------+     +----------------------+     +------------------+
 | Hardware Root    |     | Guest Enclave    |     | Solana BPF Verifier  |     | Consumer Program |
 | AMD PSP          | --> | Linux Kernel     | --> | solana-confidential-compute-verifier       | --> | Your Protocol    |
 | Nitro Hypervisor |     | /dev/sev-guest   |     | SBPFv3 e_flags = 0x3 |     | solana-confidential-compute-cpi Helper |
 | Intel TDX / PCK  |     | dstack.sock      |     | secp256r1 for TDX    |     |                  |
 +------------------+     +------------------+     +----------------------+     +------------------+
   Signs attestation        Copies signed bytes      Verifies signature,          Consumes verified
   with vendor key          to user process          cert chain, measurement,     workload key
                                                     and fresh slot hash
```

### On-Chain Program Identifiers

| Program | Program ID | Environment |
| :--- | :--- | :--- |
| `solana-confidential-compute-verifier` | `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh` | Solana Devnet |
| `solana-confidential-compute-consumer-reference` | `A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ` | Solana Devnet |

Release `v1.0.0` is git tag `v1.0.0`.

| Program | ELF | Deployment slot | Size |
| :--- | :--- | ---: | ---: |
| `solana-confidential-compute-verifier` | SBPFv3, `e_flags = 0x3` | 505,980,419 | 673,784 bytes |
| `solana-confidential-compute-consumer-reference` | `e_machine = 0x107`, `e_flags = 0x0` | 505,980,264 | 127,744 bytes |

The consumer record matches [`programs/solana-confidential-compute-consumer-reference/README.md`](programs/solana-confidential-compute-consumer-reference/README.md). Slot 505,980,264 holds a 127,744-byte ELF with `e_machine = 0x107` (`EM_SBF`) and `e_flags = 0x0`. That header is not SBPFv3. A buyer who redeploys a consumer program compiles it with `cargo-build-sbf --arch v3`.

Upgrade authority: `BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG`. `PolicyRegistry` PDA: `2FX8HZqEXr7x8kHzkhy4KPUuViVt9M6xqhFTB12jaDUf`.

Live smoke transaction [`2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH`](https://explorer.solana.com/tx/2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH?cluster=devnet) consumed 8,122 of 549,850 compute units. The transaction tests fail-closed rejection. The program returned `Custom(2)` (`VerifierError::VerificationFailed`) on a 522-byte synthetic COSE document.

---

## 2. Threat Model & Trust Boundaries

The host operator environment is untrusted. Workload private keys must remain strictly within enclave memory. Compromise of host privileges must not compromise enclave signing keys or forge valid on-chain attestations.

```
 Trust expands rightward only after cryptographic verification:

 [ Hardware Root ]           [ Host / Guest ]          [ On-Chain Verifier ]       [ Downstream Consumer ]
 AMD / Nitro Root      -->   Untrusted Operator  -->   Rejects invalid sigs  -->   Asserts PDA / mode
 Hardware Signature          May replay / drop         Enforces SlotHashes         Guards business logic
                             May tamper memory         Enforces used nonces        Ceiling <= 2,500 CU
```

### Administrative authorities and trust roots

The authority/root distinction is grounded in source baseline `19438166d46c3d95c33016e42bbe9f52918dd7fd`. The initialization and handoff procedure below describes the coordinated fixes in upstream PR #219 (#161) and upstream PR #229 (#167); require those changes in the target program before using that procedure. This does not assert a merge, deployment, or recovery of an existing registry.

Solana Confidential Compute has two separate administrative authorities. A deployment may assign both to the same governance system, but the verifier does not require this.

| Authority or root | Enforced control in this source | Security consequence |
| :--- | :--- | :--- |
| Loader upgrade authority | Authority recorded by Solana's upgradeable loader in ProgramData | Can replace the verifier code, including pinned roots and authorization checks. This power can also supersede registry governance. |
| `PolicyRegistry.authority` | Matching account pubkey with `is_signer` for registry governance instructions | Can update measurement/TCB policy and register/revoke Google JWKS keys without a program upgrade. It cannot rotate `ark_pubkey_xy`: `rotate_root_cert` is refused (upstream PR #255). |
| AMD P-384 `PolicyRegistry.ark_pubkey_xy` | Set by `init_policy_registry`. `rotate_root_cert` checks the registry PDA and authority signature, then returns `VerifierError::InvalidInstruction` (custom 0) without writing (upstream PR #255). | Legacy field from the synthetic P-384 ASK path; it cannot be rotated on-chain. upstream PR #226 (#173) restricts production AMD chains to pinned Milan RSA; the 96-byte field has no supported vendor-root meaning in that path. |
| AMD RSA Milan `MILAN_ARK_MODULUS` | Compiled into `solana-confidential-compute-crypto` | Changing the pinned anchor requires changing the deployed program code. `rotate_root_cert` does not change it. |
| AWS Nitro `AWS_NITRO_ROOT_CA_PUBKEY_XY` | Compiled into `solana-confidential-compute-crypto` | Changing the pinned anchor requires changing the deployed program code. Nitro `BackendPolicy` (source 2) controls accepted measurements. |

A registry authority can be an ordinary Ed25519 keypair or a PDA that a governance program, such as Squads, signs for through CPI. Solana Confidential Compute checks the resulting signer privilege and pubkey; it does not validate Squads membership, an m-of-n threshold, or a timelock. With a keypair authority, that one key can authorize registry writes. With a governance PDA, the governing program's configuration and execution rules supply those protections. A pubkey equality check alone establishes neither single-person custody nor multisig custody.

The production Squads references in the milestone documents describe intended operational custody. This repository does not record a production vault address, threshold, members, timelock, or proof of an executed handoff. Devnet addresses and historical transaction records do not establish current production custody. Integrators must inspect the target deployment's ProgramData upgrade authority, deserialize its canonical `PolicyRegistry.authority`, and verify each authority's custody and governance configuration separately. No live authority inspection is claimed here.

Transferring the loader upgrade authority does **not** modify `PolicyRegistry.authority`. A registry initialized with a deployer or smoke-test payer remains under that authority after a loader transfer. With the coordinated fixes:

1. Initialization requires the canonical, loader-owned ProgramData account as the fourth account and the current upgrade authority as the signing initializer. `args.authority` must match that signer. Initialize before finalizing the program; a finalized program has no upgrade authority to authorize initialization. This prevents new unauthorized initialization, but does not recover previously captured registries.
2. Registry custody transfers separately through `rotate_authority`: accounts are `[current authority signer, registry writable, receiving authority signer]`, with no payload. Both authorities must sign in the same transaction, including governance PDA signatures through CPI when applicable. There is no pending-authority state. An address in instruction data alone cannot authorize a transfer. This supports normal custody handoff, not recovery after losing the current key.
3. Verify the stored registry authority after its transfer, then transfer and verify loader authority separately. Either authority may use a governance PDA, but neither handoff proves that the external governance threshold/timelock is configured correctly.

Policy guardrails in upstream PR #230 (#168) bound measurement count to eight for the legacy payload; an empty global list is not a runtime halt. upstream PR #231 (#169) prevents ordinary updates from decreasing any TCB component. Governance remains trusted for root/key provenance and measurement choices; these checks do not authenticate the provenance of a newly authorized root or key. An empty allowlist can be replaced later, subject to the TCB floors. These coordinated changes must be integrated before relying on their guardrails.

These are authorization boundaries, not claims that native tests establish deployable SBF feasibility, hardware verification, or automatic invalidation of cached signer/VCEK records after root changes. The baseline initializer's optional ProgramData check is the separate authorization gap fixed by PR #219; this documentation PR does not change the processor.

Source references: [registry handlers](programs/solana-confidential-compute-verifier/src/processor.rs), [registry layout](programs/solana-confidential-compute-verifier/src/state.rs), [AMD chain selection](crates/solana-confidential-compute-crypto/src/vcek.rs), and [Nitro anchor](crates/solana-confidential-compute-crypto/src/nitro.rs).

### Trust Boundary Analysis

| Boundary | Trusted For | Untrusted For |
| :--- | :--- | :--- |
| **Hardware Root** (AMD PSP / AWS Nitro / Intel TDX) | Signing attestation reports, COSE documents, or a DCAP quote under manufacturer keys. For TDX the on-chain anchor is an allowlisted PCK leaf, not a parsed certificate chain. | Transaction generation. The workload supplies `REPORT_DATA` / `user_data` and the challenge or slot nonce. |
| **Guest Kernel / Hypervisor** | Passing ioctl bytes between hardware device nodes (`/dev/sev-guest`, `/dev/nsm`, `/dev/tdx-guest`) or the dstack socket and the sidecar. | Attestation integrity. The on-chain verifier independently validates the signature and the allowlist. |
| **On-Chain Verifier** (`solana-confidential-compute-verifier`) | Signature validation, certificate chain path, measurement allowlist, TCB floor, debug bit check, slot freshness, single-use nonces. | Downstream consumer business rules and asset transfers. |
| **Consumer Program** | Binding protocol instructions to verified enclave keys. | Cryptographic verification. Mode A checks `AttestedSignerAccount` PDA. Mode B checks preceding instruction. TDX enrollment is Mode A. |

<a id="intel-tdx-trust-assumptions"></a>

### Intel TDX trust assumptions

Intel TDX quotes are ECDSA P-256. `verify_tdx_qe_report` and `verify_tdx_quote` accept a signature only when an earlier instruction in the same transaction is the native `secp256r1` precompile (`Secp256r1SigVerify1111111111111111111111111`) over the matching message. The program does not run a zkVM for this path.

Four assumptions bound that check. Spec anchors are `SCC-TDX-001`, `SCC-TDX-002`, and `SCC-TDX-005`.

**Intel PCK certificate authority.** The program does not walk Intel's PCK certificate chain. Governance places the compressed PCK leaf public key on the source-5 `BackendPolicy` allowlist. That leaf is the key Intel's Provisioning Certification Key CA certifies for one platform. A signature under any other key fails the allowlist. The PCK key signs every enclave on that platform, so the leaf alone is not enough. The on-chain program does not query Intel Collateral Caching Service (PCS), evaluate TCB status, or check certificate revocation lists (CRLs). Governance bears sole responsibility for authenticating PCK certificates offline and updating or revoking source-5 allowlist pins upon Intel advisory or certificate expiry.

**Quoting Enclave identity.** `verify_tdx_qe_report` also allowlists `SHA-256(MRSIGNER || ISVPRODID || ISVSVN)` from the QE report. That digest is what selects Intel's TDX Quoting Enclave at an approved revision. A different enclave on the same platform cannot certify an attestation key.

**Debug rejection.** A debug QE has SGX `ATTRIBUTES.FLAGS` bit 1 set. A debug Trust Domain has `TD_ATTRIBUTES` bit 0 (`TUD.DEBUG`) set. Both are rejected with `DisallowedMeasurement` (custom 3). A debug guest can be inspected by the host, including a guest that carries an approved measurement.

**Challenge nonce replay.** `issue_tdx_challenge` stores a caller-chosen nonce and a slot hash read from `SlotHashes`. The nonce selects the PDA `[b"challenge", &[5], nonce]`. The slot hash is what the guest must answer, so a quote cannot be prepared for a challenge that has not been issued. A live challenge and a consumed challenge both refuse reissue. `verify_tdx_quote` accepts the quote only when `REPORTDATA` binds the workload key, that slot hash, the challenge nonce, and the GPU and model digests recorded by the QE step. Success sets `expires_slot` to 0 on the challenge. That tombstone is permanent. The used-nonce PDA is `[b"nonce", &[5], SHA-256(subject || quote_body_digest || slot_hash || challenge_nonce)]`. A second spend returns `NonceAlreadyUsed`. The challenge lives 1,500 slots. The QE session lives 150 slots. Consuming the challenge closes the window in which a reclaimed nonce account could otherwise accept the same quote again.

Source-5 policy also pins a platform digest over `TEE_TCB_SVN`, `MRSEAM`, `TD_ATTRIBUTES`, `XFAM`, `MRTD`, `MRCONFIGID`, and `RTMR0` through `RTMR2`. `RTMR3` is omitted because a dstack guest extends it on every boot.

---

## 3. Formal Security Invariant Specifications

The codebase enforces ten foundational security invariants. Each identifier below has the same meaning in [docs/intent/confidential-compute-verifier-specs.md](docs/intent/confidential-compute-verifier-specs.md).

<a id="spec-scc-sec-001"></a>

### `@spec SCC-SEC-001`: Debug and Migration Policy Rejection
- Hardware attestation reports with debug flags enabled (`policy bit 19 == 1`) or migration flags enabled (`policy bit 18 == 1`) are unconditionally rejected.
- VMPL level must be 0 (most privileged guest execution level).
- Report `version` is within `1..=5`. Policy bit 17 (`RESERVED_MUST_BE_ONE`) is set. `signature_algo` is 1 (P-384 ECDSA).

<a id="spec-scc-sec-002"></a>

### `@spec SCC-SEC-002`: Measurement Floor & Allowlist Enforcement
- All-zero measurements or uninitialized PCR0 buffers are rejected on-chain.
- The signed launch measurement must exist in the source-specific `BackendPolicy` allowlist.

<a id="spec-scc-sec-003"></a>

### `@spec SCC-SEC-003`: Pinned Root CA & Cryptographic Chain Validation
- The baseline accepts both registry P-384 and pinned Milan RSA chain paths. The coordinated #173 fix (PR #226) restricts production AMD to pinned Milan RSA; the mutable P-384 field has no supported vendor-root meaning. Require that fix in the target program; see [administrative authorities and trust roots](#administrative-authorities-and-trust-roots).
- AWS Nitro documents validate against pinned AWS Nitro Root CA G1 (`AWS_NITRO_ROOT_CA_PUBKEY_XY`).
- P-384 ECDSA signatures and SHA-384 digests are strictly verified.

<a id="spec-scc-sec-004"></a>

### `@spec SCC-SEC-004`: Zero-Trust Timestamps & Slot Freshness
- Attestation freshness is validated against the Solana `sysvar::slot_hashes::ID` sysvar.
- Maximum allowable attestation age is 150 slots (~60 seconds).
- Downstream consumer helpers load the current slot exclusively via `Clock::get()?.slot`. Caller-supplied timestamps are rejected.
- `programs/solana-confidential-compute-verifier` loads `Clock::get()` without `unwrap_or_default`. A missing Clock sysvar aborts with `VerifierError::InvalidAccountAddress`.

<a id="spec-scc-sec-005"></a>

### `@spec SCC-SEC-005`: Replay Defense & Nonce Single-Use
- Mode B atomic attestations require single-use nonces via `verify_atomic_with_nonce`.
- Nonce consumption is recorded on-chain in a `UsedNonceAccount` PDA (`seeds = [b"nonce", signer_pubkey, commitment]`). New records are 49 bytes (discriminator `sha256("account:UsedNonceAccountV2")[..8]`, consumption slot, bump, and the 32-byte signing `payer` as `refund_pubkey`). Legacy 17-byte records (discriminator `sha256("account:UsedNonceAccount")[..8]`, no refund field) written before upstream PR #258 still count as used.
- Every nonce-consuming path (Mode A and Mode B, SNP, Nitro and Google JWT) rejects either discriminator with `NonceAlreadyUsed`.
- `close_stale_nonce` closes a 49-byte record only when the current slot is more than 150 slots after the recorded consumption slot, and only to the recorded `refund_pubkey`. By then the `SlotHashes` freshness check (age ≤ 150) already rejects the same nonce, so closing does not reopen replay. Legacy 17-byte records cannot be closed and stay permanent.
- Duplicate submissions of the same nonce fail closed with custom error 5 (`VerifierError::NonceAlreadyUsed`).
- Consumer Mode B introspection accepts only a top-level call frame on every platform; self-CPI and other nested calls reject with `CpiError::InvalidConsumerStackHeight` (1018). The helper validates a transaction instruction and is read-only. It does not consume a per-handler marker or count business operations. Consumers must check once before executing exactly the committed operation; repeating withdrawals within one handler is not a globally enforced single-use guarantee.

<a id="spec-scc-sec-006"></a>

### `@spec SCC-SEC-006`: Action Commitment Binding
- Mode B binds the attestation directly to the downstream transaction:
  ```
  REPORT_DATA[32..64] = SHA-256(slot_hash || action_hash || consumer_program_id)
  ```
- V3 `action_hash` is SHA-256 of `b"solana-confidential-compute:action:v1\0" || account_count:u32LE || (pubkey32 || signer:u8 || writable:u8)* || wire_data_length:u32LE || complete_instruction_data`. Preserve ordered duplicate accounts. Flags are the final compiled message's effective privileges, including fee-payer/other-instruction elevation and Solana program demotion.
- AMD, Nitro and GCP Mode B recompute that hash from the immediately following Instructions-sysvar instruction before writing the nonce. Copying a verifier and substituting a different attestation-free instruction of the same program rejects without burning the nonce.
- The discriminator is part of the complete instruction bytes; its length is not guessed or separately committed. Empty data and non-Anchor instruction formats follow the same encoding. The outer slot/action/program commitment is unchanged.
- V1 pubkey-only and V2 split discriminator/payload digests have no acceptance fallback. Upgrade verifier, consumer/CPI helpers, SDKs and sidecar final-message screen together, then obtain fresh V3 evidence. Compile the complete message with the final payer before obtaining evidence; resolve all account keys/privileges and validate the final assembled transaction again. Keep digest-derived nonce/upload addresses out of the consumer accounts to avoid a hash fixed point.
- This prevents instruction substitution, not fee-payer ownership of evidence: copying the exact authorized consumer action may still submit that authorized action. Consumers remain responsible for their own business rules and operation cardinality.
- On chain use `hash_action_account_infos` before any CPI; off chain hash the complete compiled metadata template and validate the final message before signing. See the [exact V3 wire/API, construction and migration contract](crates/solana-confidential-compute-cpi/README.md#4-hash_action). LUTs and requested-writable reserved consumer keys are conservatively rejected by compiled helpers. This does not add staged Mode B, establish real SBF/hardware proof, or authorize deployment.

<a id="spec-scc-sec-007"></a>

### `@spec SCC-SEC-007`: Enclave Memory Hygiene & Key Zeroization
- Enclave signing keys in `bins/solana-confidential-compute-sidecar` implement `Drop` with `zeroize::Zeroize`.
- Ephemeral private keys are cleared from RAM upon rotation or process termination.
- Loopback binding defaults to `127.0.0.1:8080`.

<a id="spec-scc-sec-008"></a>

### `@spec SCC-SEC-008`: Memory Alignment & Bounded Parser Safety
- Introspection accounts utilize 1-byte aligned Pod representations (`bytemuck::Pod`) to prevent unaligned memory faults under SBF.
- CBOR and DER parsers enforce bounded depth limits (`MAX_CBOR_SKIP_DEPTH = 8`) and maximum buffer caps (`MAX_NITRO_DOCUMENT_LEN = 8192`).
- All deserialization routines return `Result` and avoid panicking operations.

<a id="spec-scc-sec-009"></a>

### `@spec SCC-SEC-009`: AMD Signature Format & Scalar Bounds
- The 512-byte signature block starts at offset `0x2A0`.
- `r` is the 72-byte little-endian field at `0x2A0..0x2E8`. `s` is the 72-byte little-endian field at `0x2E8..0x330`.
- Bytes 48..72 of each field are zero. The first 48 bytes are the big-endian P-384 scalar.
- `signature_algo` at offset `0x034` is 1. A padding or algorithm failure aborts with `VerifierError::InvalidSignature`.

<a id="spec-scc-sec-010"></a>

### `@spec SCC-SEC-010`: AMD PSP P-384 Signature Specification & Observability
- AMD SEV-SNP signatures follow FIPS 186-4 (AMD Publication #56860). The verifier accepts scalar `s` in `1..n`. Low-S form (`s <= floor(n/2)`) is not required.
- `solana-confidential-compute-cli` logs a high-S scalar (`s > floor(n/2)`) and keeps the original bytes on the wire. The log text is `HIGH_S_WARN`.

---

## 4. Defense-in-Depth Control Matrix

| Control | Implementation Location | Attack Mitigated |
| :--- | :--- | :--- |
| **Bounded CBOR Depth** | `crates/solana-confidential-compute-crypto`, `crates/solana-confidential-compute-cpi` | Stack exhaustion from deeply nested CBOR maps/arrays (`MAX_CBOR_SKIP_DEPTH = 8`). |
| **Indefinite Map Termination** | `crates/solana-confidential-compute-crypto` | Denial-of-service from indefinite CBOR map loops without break bytes (`0xff`). |
| **Buffer Length Bounds** | `crates/solana-confidential-compute-core`, `crates/solana-confidential-compute-crypto` | Out-of-memory or compute exhaustion (`MAX_NITRO_DOCUMENT_LEN = 8192`, `MAX_CERT_DER_LEN = 4096`). |
| **Safe Struct Alignment** | `crates/solana-confidential-compute-cpi/src/lib.rs` | SBF unaligned memory trap on unaligned integer offsets. |
| **Fixed Report Slicing** | `crates/solana-confidential-compute-core/src/report.rs` | Buffer over-read on short AMD SEV-SNP reports (`SnpReportView::try_from_slice` requires 1,184 bytes). |
| **Slot Hash Pinning** | `programs/solana-confidential-compute-verifier/src/processor.rs` | Spoofing recent slots with fake sysvar accounts. |
| **Fail-Closed Gate** | `programs/solana-confidential-compute-verifier/src/processor.rs` | Un-nonce Mode B attempts fail closed (`NonceRequired`). |
| **Owner & Signer Asserts** | `crates/solana-confidential-compute-cpi/src/lib.rs` | Foreign account injection or forged PDA ownership. |

---

## 5. Verification Suite & Reproducibility

External auditors and evaluators can verify the entire test suite locally:

### 5.1 Full Workspace Test Suite

```bash
cargo test --workspace
```
*Expected result:* 279 passed, 0 failed, 1 ignored (`test_cu_benchmarks_live_sbf` requires local Agave SBPFv3 runner).

### 5.2 Clippy & Linter Hygiene

```bash
cargo clippy --workspace --all-targets -- -D warnings
```
*Expected result:* 0 warnings, clean compilation.

The workspace denies `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::panic_in_result_fn`, `clippy::unreachable`, `clippy::todo` and `clippy::unimplemented` (SDLC 3.2.8). `clippy.toml` allows the first three in `#[cfg(test)]` code, and integration test files allow them at file level. An `expect` is allowed only when a compile-time `const` assertion proves it cannot fail. Mark it with `#[allow(clippy::expect_used)]` and a comment that names the proof. The crates on the onchain path (the verifier, the consumer reference, core, crypto and cpi) also deny `clippy::arithmetic_side_effects` at the crate root (SDLC 3.2.1). A unit test module that builds fixtures with unchecked arithmetic allows it.

### 5.3 TypeScript Client SDK Suite

```bash
cd sdks/typescript && npm test
```
*Expected result:* 17 passed, 0 failed (7 in `test/packet.test.cjs`, 10 in `test/nitro.test.cjs`).

### 5.4 SBPFv3 Compile & Verification

```bash
bash scripts/build-sbpfv3.sh --self-test
```
*Expected result:* Program builds cleanly with SIMD-0500 `e_flags = 0x3`.

### 5.5 Hardware Fixture Cryptographic Validation

Offline cryptographic verification of genuine AMD and AWS Nitro hardware attestation reports:

```bash
# Validates AMD SEV-SNP report against AMD KDS Milan certificate chain
cargo test -p solana-confidential-compute-crypto --test milan_kds

# Validates AWS Nitro Enclaves attestation document against AWS Root CA G1
cargo test -p solana-confidential-compute-crypto --lib verify_hardware_nitro_attestation_document
```

---

## 6. Workspace Module Navigation for Auditors

| Module | README Link | Primary Auditor Focus |
| :--- | :--- | :--- |
| `crates/solana-confidential-compute-core` | [`crates/solana-confidential-compute-core/README.md`](crates/solana-confidential-compute-core/README.md) | AMD SEV-SNP 1,184-byte view, Nitro length constants, zero-copy safety. |
| `crates/solana-confidential-compute-crypto` | [`crates/solana-confidential-compute-crypto/README.md`](crates/solana-confidential-compute-crypto/README.md) | NIST P-384 ECDSA, X.509 DER parser, CBOR decoder, AWS Root CA G1 pin. |
| `crates/solana-confidential-compute-cpi` | [`crates/solana-confidential-compute-cpi/README.md`](crates/solana-confidential-compute-cpi/README.md) | On-chain introspection helpers (`assert_attestation_signer`, `assert_attestation_atomic`). |
| `crates/solana-confidential-compute-sdk` | [`crates/solana-confidential-compute-sdk/README.md`](crates/solana-confidential-compute-sdk/README.md) | Off-chain transaction packing, 1,232-byte MTU enforcement, Mode A / Mode B builders. |
| `programs/solana-confidential-compute-verifier` | [`programs/solana-confidential-compute-verifier/README.md`](programs/solana-confidential-compute-verifier/README.md) | SBPFv3 attestation program, instruction dispatch, `SlotHashes` sysvar verification. |
| `programs/solana-confidential-compute-consumer-reference` | [`programs/solana-confidential-compute-consumer-reference/README.md`](programs/solana-confidential-compute-consumer-reference/README.md) | Consumer CPI integration, compute unit consumption, measurement guard. |
| `bins/solana-confidential-compute-cli` | [`bins/solana-confidential-compute-cli/README.md`](bins/solana-confidential-compute-cli/README.md) | CLI attestation client, `/dev/sev-guest` ioctl ABI, 32-byte PSP prefix handling. |
| `bins/solana-confidential-compute-sidecar` | [`bins/solana-confidential-compute-sidecar/README.md`](bins/solana-confidential-compute-sidecar/README.md) | Enclave signing daemon, key zeroization on drop, loopback server. |
| `sdks/typescript` | [`sdks/typescript/README.md`](sdks/typescript/README.md) | TypeScript client SDK, packet serialization, browser/Node compatibility. |

---

## 7. Hardware Evidence & Runbooks

Genuine hardware attestation captures and reproducible runbooks:

- **AMD SEV-SNP (GCP Confidential VM):** [`docs/verification/hardware-verification-gcp-sev-snp.md`](docs/verification/hardware-verification-gcp-sev-snp.md)
- **AWS Nitro Enclaves (AWS c6i.xlarge):** [`docs/verification/hardware-verification-aws-nitro.md`](docs/verification/hardware-verification-aws-nitro.md)
- **Grant Handoff & Evaluator Guide:** [`docs/handoff/grant-handoff-guide.md`](docs/handoff/grant-handoff-guide.md)

---

## 8. Auditor Scope & Runtime Limitations

This section separates the recorded `v1.0.0` deployment evidence from controls present in current source. Source and native tests do not establish that these controls were deployed or validated on real SBF or hardware.

### 8.1 On-chain signature backend

On `target_os = "solana"` without `mock-crypto`, `DefaultVerifier` is `SolanaDefaultVerifier`. `Processor::process` passes `DefaultVerifier::default()` into `process_with`. `SolanaDefaultVerifier::verify_p384` does not call `solana_confidential_compute_crypto::verify_p384_signature`. It delegates to `InstructionIntrospectionVerifier` and accepts a signature only when a preceding instruction has program id `EXPECTED_SIGVERIFY_PROGRAM_ID` (`programs/solana-confidential-compute-verifier/src/processor.rs`). No mainnet secp384r1 precompile id is assigned to that constant. A missing or mismatched instruction returns `VerifierError::InvalidSignature`. The check fails closed.

`scripts/build-sbpfv3.sh` does not pass `--features mock-crypto`. The Devnet ELF uses this introspection backend. `DirectCryptoVerifier` is the host default. On Solana, `DirectCryptoVerifier::verify_p384` returns `InvalidSignature` and does not run the host P-384 code. `Groth16SyscallVerifier` is not `DefaultVerifier`.

### 8.2 Software P-384 compute (`@spec SCC-SEC-003`)

`@spec SCC-SEC-003` still requires pinned AMD ARK/ASK and AWS Nitro Root CA G1 chain checks, and a P-384 ECDSA check over a SHA-384 digest. Host builds and `solana-confidential-compute-cli` perform that P-384 check in `solana-confidential-compute-crypto`. The Solana program does not.

Actual SBF compute and stack requirements have not been established by the current issue validation: SBF tools and a corresponding artifact were unavailable. Historical estimates and native timings do not establish those measurements. The baseline introspection path in §8.1 remains fail closed; mock-crypto rows measure policy/parsing, not on-chain signature verification. Bounded staged account transport is implemented as described below. Use of the existing `sol_big_mod_exp` syscall as a production cryptographic path requires separate validation; transport alone establishes no signature-verification feasibility.

Native serialization reproduced these transport bounds with authentic fixtures:

| Input | Serialized size | Established limitation |
| :--- | :--- | :--- |
| Milan ASK 1,677 bytes + VCEK 1,351 bytes (#164) | Inline registration instruction 3,208 bytes; even a minimal transaction 3,379 bytes | Exceeds the 1,232-byte packet limit before the full real account set. |
| Nitro COSE document 4,526 bytes (#197) | Instruction 4,579 bytes | Exceeds the packet limit; the checked SDK already rejects oversized serialization. |

These measurements establish failure of these inline payloads under the packet guard. Current source implements staged transport in [`transport.rs`](programs/solana-confidential-compute-verifier/src/transport.rs) and Rust SDK [`staged.rs`](crates/solana-confidential-compute-sdk/src/staged.rs): begin → sequential upload → seal → consume → close. Limits are 9,000 payload bytes, 700 bytes per chunk, and a lifetime of at most 150 slots. The stage PDA binds the uploading authority and payload digest; seal checks completeness, digest, and the allowed instruction. Consume requires that authority to sign and to match the handler payer, rejects account aliasing, runs the existing handler checks, and marks the stage consumed only on success. Close refunds only the authenticated authority, including cancellation and expired-stage cleanup.

The allowlist is deliberately narrow: `register_vcek` and Nitro Mode A only. Mode B is rejected at seal and consume: there is no staged atomic consumer adapter. Sealing authenticates bytes, not hardware evidence; signature, root, identity, freshness, policy and replay checks remain the handler's responsibility. Native tests [`issue_164_staged_transport.rs`](programs/solana-confidential-compute-verifier/tests/issue_164_staged_transport.rs), [`issue_164_staged_runtime.rs`](crates/solana-confidential-compute-sdk/tests/issue_164_staged_runtime.rs), and [`issue_197_staged_cpi.rs`](crates/solana-confidential-compute-sdk/tests/issue_197_staged_cpi.rs) record transport behavior; consult their verifier configuration before treating a successful test as cryptographic evidence. These controls do not prove real SBF execution, hardware enrollment, provider availability, or deployment. No hardware probe or new Devnet transaction was run for this documentation correction.

### 8.3 Consumer reference ELF

The Devnet `solana-confidential-compute-consumer-reference` account at slot **505,980,264** holds a **127,744**-byte ELF. Header words: `e_machine = 0x107` (`EM_SBF`), `e_flags = 0x0`. `solana-confidential-compute-verifier` at slot 505,980,419 is the SBPFv3 artifact (`e_flags = 0x3`, 673,784 bytes). Buyer redeployments of consumer programs pass `--arch v3`.

### 8.4 Residual risks

This subsection describes the `v1.0.0` handoff. At that tag Mode B wrote a 17-byte `UsedNonceAccount` PDA (`@spec SCC-SEC-005`) with no close instruction, so the account is a permanent tombstone. Those legacy records stay permanent on current `main`: `close_stale_nonce` refuses them because they carry no refund provenance. A second submission of the same nonce returns `VerifierError::NonceAlreadyUsed` (custom error 5) while the account exists.

Since upstream PR #258, new nonce records are 49 bytes and store the signing payer. Anyone may call `close_stale_nonce` (accounts: nonce writable, recorded payer writable, Clock sysvar; no payload, no signer). It closes the record and moves all of its lamports to the recorded payer once `clock.slot - record.slot > 150`. Earlier calls fail with `VerifierError::UnauthorizedPolicy`; a legacy record or a different refund account fails with `VerifierError::InvalidAccountAddress`. After closure, the same nonce is older than the 150-slot `SlotHashes` window and fails with `VerifierError::StaleNonce` instead of `NonceAlreadyUsed`. Both `close_stale_nonce` and `close_attested_signer` call `close_governance_account` and emit `solana-confidential-compute:governance:v1` after successful closure. The fields are domain, operation, actor, closed account, SHA-256(old account bytes), SHA-256(empty data). The actor is the recorded refund account for permissionless nonce cleanup, or the signing workload key for signer cleanup. Failed closes emit no close event. Indexers must require **transaction success**: later instructions can roll back an earlier close while execution logs remain. See [`processor.rs`](programs/solana-confidential-compute-verifier/src/processor.rs) and native log assertions in [`close_governance_events.rs`](programs/solana-confidential-compute-verifier/tests/close_governance_events.rs).

Mode A writes a V2 `AttestedSignerAccount` admission snapshot. Consumers enforce the canonical PDA, owner, discriminator, workload signature, caller-pinned platform and measurement, and both stored deadlines: `current_slot <= expires_slot` and `0 <= Clock.unix_timestamp < expires_unix_timestamp`. The independent slot cap is 216,000; the Unix cap is 86,400 seconds. New AMD records are additionally capped at the cached authenticated ASK/VCEK chain deadline; Nitro records at the minimum authenticated certificate `notAfter` across the checked chain; GCP records at JWT `exp`. Equality at the Unix deadline is expired. Existing records are not rewritten by this source change and retain their already issued deadlines until expiry or targeted governance action.

This is bounded admission trust, not continuous policy evaluation. `BackendPolicy` measurement removal, registry TCB-floor increases, GCP tenant-policy changes, JWKS revocation and AMD credential/identity revocation gate subsequent admissions. The ordinary Mode A helpers do not read those accounts on every action, so these changes do **not** invalidate previously issued records automatically. A caller-pinned measurement/platform remains binding, but is not a live registry lookup. Governance must explicitly call `revoke_attested_signer` for affected live workload keys to stop their sessions immediately, or wait for their stored expiry; enumeration/indexing is an operational requirement. Consumers needing policy changes to affect every action must implement and authenticate the additional live policy checks themselves; the ordinary helpers do not provide that guarantee.

Contract basis: at baseline `eb133d03bdbcf5852c36ad425d3621eb275459e7`, [SCC-VERIFY-008/015 and SCC-ANCHOR-001](docs/intent/confidential-compute-verifier-specs.md) specify stored measurement and expiry consumer guards, without retroactive policy propagation. upstream PR #251 introduced the V2 dual deadline, explicitly clamping GCP JWT expiry. Those clauses' older V1 layout references are historical; current V2 layout and checks are in [CPI](crates/solana-confidential-compute-cpi/src/lib.rs) and [Anchor](crates/solana-confidential-compute-cpi/src/anchor.rs). The former text here claiming no targeted signer-revocation instruction was stale and is not the policy authority.

Targeted containment uses `revoke_attested_signer`: the registry authority signs, the handler validates the canonical registry and signer record, and writes both deadlines to zero. The V2 record remains a permanent public-key tombstone: admission cannot overwrite it, cleanup cannot delete it, and CPI/Anchor consumers reject it even at slot zero. This blocks the recorded key; a workload can still generate a different key. The Rust SDK exposes `build_revoke_attested_signer_ix` (authority signer, registry readonly, signer record writable; payload: signer public key). Successful revocation emits `solana-confidential-compute:governance:v1` and `solana-confidential-compute:revoke_attested_signer:v1`.

Disable the compromised issuer or backend admission before revoking affected sessions. Targeted revocation does not disable the issuer. `close_attested_signer` is rent cleanup for naturally expired, nonrevoked records: it requires the workload signature and `clock.slot > expires_slot` and refunds that signer; Unix expiry alone does not satisfy its guard. These are source contracts, not deployment or hardware proof.

### Dependency advisories

`rustls` is patched to `0.23.46` in `Cargo.lock`, closing GHSA-c8m5-c952-6cm4 (session `Debug` formatting exposes TLS master secrets), GHSA-vp88-798v-h67f, GHSA-w44r-93j7-qv28 and GHSA-h2v8-394m-p7vv. `rustls` is a host-side transport dependency; it is not reachable from the on-chain program.

Three advisories remain open and cannot be resolved from this workspace: `ed25519-dalek` 1.0.1 (CVE-2022-50237, double public key signing oracle), `curve25519-dalek` 3.2.0 (CVE-2024-58262, timing variability) and `rand` 0.7.3 (GHSA-cq8v-f236-94qc). All three arrive through a single parent, `agave-precompiles`, which pins `ed25519-dalek = "=1.0.1"` as a normal dependency; that pin in turn fixes the other two:

```
agave-precompiles v4.3.2 -> ed25519-dalek v1.0.1 -> curve25519-dalek v3.2.0
                                                 -> rand v0.7.3
```

That parent is reached only as a development dependency, through `solana-program-test` -> `solana-runtime` -> `agave-precompiles`. Verify with version-qualified queries, because an unqualified crate name also matches the production copies `ed25519-dalek@2.2.0` and `curve25519-dalek@4.1.3`:

```bash
cargo tree --locked --workspace -i ed25519-dalek@1.0.1    --edges normal,build --target all
cargo tree --locked --workspace -i curve25519-dalek@3.2.0 --edges normal,build --target all
cargo tree --locked --workspace -i rand@0.7.3             --edges normal,build --target all
```

Each returns nothing; the vulnerable copies appear only with `--edges all`, under `solana-program-test`. They are therefore absent from every deployed artifact, including the SBF program, the sidecar and the CLI. The on-chain program verifies Ed25519 signatures through Solana syscalls and P-384 through `solana-bn254` and the pinned software path (`@spec SCC-SEC-003`, `@spec SCC-SEC-010`), not through these crates. Exposure is limited to compiling and running the test suite.

`rand` 0.7.3 resolves in this tree with `alloc,getrandom,getrandom_package,libc,std` and no `log` feature; `log` is absent from its locked dependency set. GHSA-cq8v-f236-94qc requires a custom logger observing `rand::rng()`, so the published path is not reachable here even in test builds.

No patched release can be selected on the current line. `agave-precompiles` 4.4.0 and 4.4.1 are newer than the locked 4.3.2 and still pin `ed25519-dalek = "=1.0.1"` as a normal dependency. Only 4.5.0-beta.0 and 5.0.0-alpha.1 demote it to a dev-dependency, so resolution requires an Agave release on the 4.5 or 5.0 line. Until such a release is adopted, these three Dependabot alerts stay open by decision: dismissing them would also suppress a future advisory on the same crates reaching a shipped path.

### Backend measurement governance

`BackendPolicy` is authoritative for measurement admission: source 1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space, 4 = NVIDIA (reserved, does not enroll), 5 = Intel TDX. Each canonical PDA uses `[b"backend_policy", &[source]]` and holds up to eight measurements. Missing, empty, or mismatched backend policy fails closed. The global `PolicyRegistry.measurement_count` / `measurements` fields and `update_policy` measurement payload are deprecated as runtime controls and retained for state/wire compatibility; clearing that global list does not halt admission. There is no implicit global/backend allowlist AND. Registry authority checks and monotonic AMD TCB floors remain active.

To halt new admission, the registry authority uses `set_backend_policy` with an empty list (`[]`) for each relevant backend. Empty sources 1, 2, 3, and 5 to halt every backend that can enroll. Rust exposes `build_set_backend_policy_ix`, which accepts source `1..=5`. TypeScript exposes `buildSetBackendPolicyIx`. This does not revoke existing Mode A sessions: use `revoke_attested_signer` separately for targeted containment. These are source contracts, not evidence of deployment or hardware/SBF validation.

### Emergency admission controls

The registry authority can halt new admission and Mode B verification by setting the relevant `BackendPolicy` to an empty list. `solana-confidential-compute governance --authority PUBKEY emergency-halt --source 1|2|3|5` exports this existing on-chain setter; it does not broadcast. Source 5 is Intel TDX. Each source requires its own transaction. Missing or empty backend policy fails closed, and restoring an explicit reviewed allowlist resumes that backend subject to the remaining trust, freshness, replay and AMD TCB checks. The legacy `update_policy` measurement payload and registry fields remain ABI-compatible but do not govern runtime admission; there is no global/backend allowlist AND.

Backend halt does not invalidate existing Mode A sessions: use `revoke-attested-signer` separately, after containing admission. `revoke-vcek` irreversibly revokes the effective AMD identity across all TCB versions and marks the selected V2 cache (identity hash plus packed TCB) revoked if present; the fee payer funds the identity tombstone. Restoring a backend measurement does not un-revoke that identity or any signer/JWKS key. `set-gcp-tenant-policy` changes the required audience/subject, not the backend measurement policy. Follow the [operator procedure](docs-site/src/content/docs/reference/governance.md#emergency-halt-and-resume), including signed submission and on-chain verification.
