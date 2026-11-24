# Solana Confidential Compute — Milestone Gate 1 Verification Report

Architecture map: [docs/high-level-design.md](../high-level-design.md).

**Milestone:** Gate 1 (End of Month 1)  
**Deliverable:** Component 6 — One-Command Proof-of-Enclave CLI (`bins/solana-confidential-compute-cli`)  
**Status:** **SATISFIED**  
**Pull Request:** PR #348  
**Commit:** `f27fa3c`  

---

## 0. Tag `v1.0.0`

The sections below are the Gate 1 record. These facts match the tag:

- Subcommands are `prove` and `verify`. `prove` prints a dry-run transaction. It does not submit. `--dry-run false` returns an error.
- `SNP_GET_REPORT` is `0xC0205300` (`_IOWR('S', 0x00, 32)`). The ioctl argument is 32 bytes. `SnpReportReq` is 96 bytes. The value `0xC0485301` is not this ioctl.
- `SnpReportView` is `crates/solana-confidential-compute-core/src/report.rs`. `verify_report_locally` calls `SnpReportView::validate_security_invariants` before the P-384 check.
- The test log in §5.1 is the Gate 1 capture. It is not a transcript of `cargo test -p solana-confidential-compute-cli` on this tag.

---

## 1. Executive Summary

Milestone Gate 1 of the Solana Foundation Grant is **SATISFIED**.

`solana-confidential-compute-cli` reads an AMD SEV-SNP report, binds a Solana public key or a Mode B commitment into `REPORT_DATA`, checks the report locally, and prints a dry-run transaction. The binary does not broadcast that transaction.

### Key Terminology
- **AMD SEV-SNP:** AMD Secure Encrypted Virtualization-Secure Nested Paging. This hardware feature encrypts CPU memory and protects virtual machines from untrusted cloud hypervisors.
- **VCEK:** Versioned Chip Endorsement Key. This is a certificate signed by AMD that proves a report came from a genuine AMD processor.
- **NIST P-384:** The elliptic curve standard that AMD hardware uses to sign attestation reports.
- **Mode A (Stateful):** Attests an enclave once and registers an on-chain account for repeated signing sessions.
- **Mode B (Atomic):** Attests a single action in the same transaction bundle with zero on-chain account storage.

| Gate | Target Milestone | Acceptance Criteria | Status |
| :--- | :--- | :--- | :--- |
| **Gate 1** | End of Month 1 | Local CLI extracts AMD SEV-SNP report on Linux (`/dev/sev-guest` or mock), encodes `REPORT_DATA`, and verifies signature locally. | **SATISFIED** |

---

## 2. Deliverable Scope & CLI Capabilities

`solana-confidential-compute-cli` implements two primary subcommands:

### 2.1 `solana-confidential-compute-cli prove`
The `prove` command collects evidence from hardware and builds transactions:
1. **Detects Environment:** Queries the Linux `/dev/sev-guest` kernel character device. If the hardware device is not present, it requires the `--mock` flag for local development and CI testing.
2. **Encodes User Data (`REPORT_DATA`):** Injects a 64-byte payload into the AMD report:
   - **Mode A (Stateful):** Bytes `0..32` contain the workload Ed25519 public key. Bytes `32..64` contain the slot hash nonce.
   - **Mode B (Atomic):** Bytes `0..32` contain zero padding. Bytes `32..64` contain an action commitment hash:
     $$\text{commitment} = \text{SHA-256}(\text{slot\_hash} \parallel \text{action\_hash} \parallel \text{consumer\_program\_id})$$
3. **Retrieves Hardware Report:** Sends the `SNP_GET_REPORT` ioctl to retrieve the report from the AMD Secure Processor. The guest response is accepted only when `report_size` equals 1,184 (`SNP_REPORT_SIZE`). `report_size == 0` and every other size are rejected.
4. **Checks `REPORT_DATA` echo:** Bytes `data[0x50..0x90]` must equal the 64-byte `user_data` written into the guest request. A report that does not echo that payload is rejected before signature verification.
5. **Validates Report Locally:** Checks the 1,184-byte length, the `REPORT_DATA` echo, `SnpReportView::validate_security_invariants`, and the P-384 signature under the selected VCEK key. `--vcek-pubkey` supplies that 96-byte X||Y key. `mock_vcek_public_key_xy()` is used only when `--mock` is set and `--vcek-pubkey` is omitted. This step does not submit a transaction.
6. **Assembles Transaction:** Prints the Solana transaction in base64 and hex. `--dry-run false` returns an error.

### 2.2 `solana-confidential-compute-cli verify`
The `verify` command inspects registration status. Given an Ed25519 public key and the Solana Confidential Compute verifier program ID, it derives and prints the on-chain `AttestedSigner` Program-Derived Address (PDA).

---

## 3. Key Engineering Decisions & Architectural Details

### 3.1 Direct Linux kernel ioctl

On Linux, `solana-confidential-compute-cli` opens `/dev/sev-guest` and issues `SNP_GET_REPORT` (`0xC0205300`). That constant is `_IOWR('S', 0x00, 32)`.

| Object | Length |
| :--- | ---: |
| `SnpGuestRequestIoctl` | 32 |
| `SnpReportReq` (`user_data`, `vmpl`, `key_sel`, 27 reserved bytes) | 96 |
| Guest response object | 4032 |
| Bytes the kernel writes into `data` | 4000 |

`key_sel` is 0. `copy_guest_report_prefix` in `bins/solana-confidential-compute-cli/src/lib.rs` applies the 32-byte PSP prefix rule. The report view is `SnpReportView` in `crates/solana-confidential-compute-core/src/report.rs`. The CLI does not link a third-party SEV library.

`0xC0485301` is not `SNP_GET_REPORT`.

### 3.2 Cross-Platform Mock Engine (`--mock`)
Developer machines and CI hosts do not provide `/dev/sev-guest`. The `--mock` flag synthesizes a valid 1,184-byte report strictly conforming to AMD Publication #56860 (Table 141), signed with a deterministic NIST P-384 key pair.

### 3.3 Local Pre-Flight Verification
Submitting invalid attestation reports to Solana wastes network transaction fees. `solana-confidential-compute-cli` verifies the 1,184-byte report locally before building transactions. It checks the signature against the selected VCEK key, validates TCB levels, and rejects reports with debug mode enabled.

VCEK selection is fail-closed:

- `--vcek-pubkey` is a 96-byte uncompressed X||Y hex string. When it is set, that key is the verification key, including in `--mock` mode.
- `mock_vcek_public_key_xy()` runs only when `--mock` is set and `--vcek-pubkey` is omitted.
- A hardware prove that omits both `--mock` and `--vcek-pubkey` aborts with `InvalidArgument` before the CLI opens `/dev/sev-guest`.

### 3.4 Hardware High-S Signature Detection
An ECDSA signature is high-S when the scalar $s$ exceeds half the curve order ($s > n/2$). AMD hardware microcode can emit high-S signatures. `solana-confidential-compute-cli` detects and logs high-S signatures while preserving the original hardware signature on the wire so it remains cryptographically valid against the AMD VCEK certificate.

### 3.5 Dual-Modality Transaction Assembly
The CLI constructs transactions for both verification paths:
- **Mode A (`--mode stateful`):** Builds a `verify_and_register` instruction targeting the `AttestedSigner` and `UsedNonce` PDAs for high-frequency signing sessions.
- **Mode B (`--mode atomic`):** Builds a `verify_atomic_with_nonce` instruction, creating a single-use `UsedNonceAccount` PDA.

### 3.6 Mode B Replay Gate (H-01) — CLOSED
Stateless `verify_atomic` verifies a report inside the 150-slot `SlotHashes` window and writes no nonce account, so the same signed report can be replayed. That path is disabled.

- `solana-confidential-compute prove --stateless-idempotent` returns `InvalidArgument` and builds no transaction. The error states that stateless Mode B is disabled to prevent replay (finding H-01) and that every Mode B transaction requires nonce consumption.
- The default atomic prove path emits `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR`.
- Status: **CLOSED** for the CLI. Mode B prove cannot package a replayable `verify_atomic` instruction.

---

## 4. Internal Research Citations

All design decisions cite internal research documents within the `confidential-compute/` repository:

- **[AMD SEV-SNP Architecture & ABI Specification](../research/amd-sev-snp.md):**  
  Documents Table 141 report structures, guest request ioctl interfaces, and the VCEK certificate hierarchy.
- **[Confidential Computing & TEE Threat Model](../research/tee-confidential-compute.md):**  
  Documents untrusted hypervisor threats, memory isolation boundaries, and clock freshness requirements.
- **[Solana Confidential Compute CLI Low-Level Design](../intent/confidential-compute-cli-lld.md):**  
  Defines CLI subcommands, argument parsers, error types, and transaction construction.
- **[Solana Confidential Compute CLI Intent Specifications](../intent/confidential-compute-cli-specs.md):**  
  Formal specifications (`@spec SCC-CLI-001` through `SCC-CLI-005`) covering report extraction, pre-flight validation, commitment construction, and transaction building.

---

## 5. Evidence of Completion & Test Suite

### 5.1 Automated Test Execution

The log below is the Gate 1 capture. Tag `v1.0.0` keeps these checks and adds more tests in the same package. Re-run `cargo test -p solana-confidential-compute-cli` on that tag. Do not treat the counts in the paste as the current total.

```
$ cargo test -p teton-cli

library src/lib.rs — report size, REPORT_DATA echo, VCEK selection, signature verify
test tests::test_report_size_rejects_zero ... ok
test tests::test_report_size_rejects_noncanonical ... ok
test tests::test_report_size_accepts_exact_when_report_data_echoes ... ok
test tests::test_report_data_echo_rejects_mismatch ... ok
test tests::test_report_data_ignores_bytes_outside_echo_window ... ok
test tests::test_mock_vcek_is_used_only_when_mock_and_no_target ... ok
test tests::test_explicit_vcek_pubkey_is_the_preflight_key ... ok
test tests::test_missing_vcek_pubkey_without_mock_does_not_call_mock_key ... ok
test tests::test_vcek_hex_rejects_wrong_length ... ok
test tests::test_selected_vcek_verifies_matching_signature_and_rejects_other ... ok
test result: ok. 10 passed

binary src/main.rs — ioctl mapping, prove preflight, Mode B replay rejection
test hardware::tests::test_accept_hardware_report_rejects_zero_size_and_bad_echo ... ok
test tests::test_run_prove_requires_vcek_pubkey_without_mock ... ok
test tests::test_run_prove_rejects_mismatched_vcek_pubkey ... ok
test tests::test_run_prove_accepts_explicit_mock_vcek_pubkey ... ok
test tests::test_run_prove_atomic_stateless_idempotent ... ok
test result: ok. 23 passed (includes the checks above plus parsing, mock reports, and dry-run assembly)
```

### 5.2 Command Execution Output
Running `solana-confidential-compute-cli prove` in mock dry-run mode extracts a report, performs local pre-flight checks, reports signature status, and emits serialized transaction payloads:

```
$ cargo run -p teton-cli -- prove --mock --pubkey 11111111111111111111111111111111 --dry-run
[WARN] High-S signature detected (s > n/2). Hardware vendor: AMD PSP. Valid under FIPS 186-4; non-canonical under BIP-62.
transaction_base64=AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAYJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKKL+DM3Yqn5UnGo5hqqWopHKSdEeBPUSZZIxz5LR9se0SQIfc5xhgnqP/IL4zTr5c6/qlN+lsuFyKpBsvCGSnAwZGb+UhFzL/7K26csOb57yM5bvF9xJrLEObOkAAAAAGp9UXGMd0yShWY5hpHV62i164o5tLbVxzVVshAAAAAAan1RcZLwqvxvJl4/t3zHragsUp0L47E24tAFUgAAAABtPyZ4Fbb+m9MfSDbrKQmpLT2HLeMTIYTwpDQAAAAADwgHedEm7MqPYn3z9IUyZRGqiVt3/BVIoLD533iP7Pwv/0nEJSLCOrNuWJiZ7k/aDBb/Ehp7ZVAFXj5l5O7E6l...
transaction_hex=0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100060900000000000000000000000000000000000000000000000000000000000000000a28bf8333762a9f95271a8e61aaa5a8a472927447813d4499648c73e4b47db1ed124087dce718609ea3ff20be334ebe5cebfaa537e96cb85c8aa41b2f0864a70306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a4000000006a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b210000000006a7d517192f0aafc6f265e3fb77cc7ada82c529d0be3b136e2d005520...
```

Running `solana-confidential-compute-cli verify` derives the deterministic `AttestedSigner` PDA:

```
$ cargo run -p teton-cli -- verify --pubkey 11111111111111111111111111111111
Derived AttestedSigner PDA: GxRmTpxiukVcCGwSFggpvCYVrk5jBSTd25BJ2JcU6wNv (bump: 255) for 11111111111111111111111111111111
```

---

## 6. Traceability Matrix

| Requirement | Implementation File | Spec Tag |
| :--- | :--- | :--- |
| Linux `/dev/sev-guest` ioctl interface | `../../bins/solana-confidential-compute-cli/src/hardware.rs` | `@spec SCC-CLI-001` |
| Exact `report_size` and `REPORT_DATA` echo (`data[0x50..0x90]`) | `../../bins/solana-confidential-compute-cli/src/lib.rs` `validate_hardware_report`; applied from `hardware.rs` `accept_hardware_report` | `@spec SCC-CLI-001` |
| Mock report generator conforming to Table 141 | `../../bins/solana-confidential-compute-cli/src/mock.rs` | `@spec SCC-CLI-001` |
| Mode A report encoding & transaction builder | `../../bins/solana-confidential-compute-cli/src/main.rs` `run_prove` stateful arm | `@spec SCC-CLI-002` |
| Mode B commitment and nonce-bound transaction; `--stateless-idempotent` rejected (H-01) | `../../bins/solana-confidential-compute-cli/src/main.rs` `run_prove` | `@spec SCC-CLI-003` |
| Compute budget injection & dry-run output | `../../bins/solana-confidential-compute-cli/src/tx.rs` | `@spec SCC-CLI-004` |
| VCEK selection (`--vcek-pubkey`, mock key only under `--mock`) and local P-384 preflight | `../../bins/solana-confidential-compute-cli/src/lib.rs` `resolve_vcek_public_key`; `../../bins/solana-confidential-compute-cli/src/tx.rs` `verify_report_locally` | `@spec SCC-CLI-005` |
