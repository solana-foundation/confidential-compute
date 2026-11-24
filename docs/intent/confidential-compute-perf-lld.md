# Low-Level Design: SBF Compute Unit Benchmarking Harness (`cu_benchmarks`)

This document defines the architecture, test harness, execution environment, and performance invariants for the automated on-chain SBF Compute Unit (CU) benchmark suite for `solana-confidential-compute-verifier` (Milestone Gate 2, Component 1).

---

## 1. Objectives & Boundaries

- **Objective:** Establish an automated integration test harness that compiles the `solana-confidential-compute-verifier` SBF program and executes instructions under the Solana BPF runtime to meter exact compute unit consumption.
- **Verification Targets:**
  - `@spec SCC-PERF-001`: Stage 2 `verify_and_register` consumes $\le 550,000$ CUs.
  - `@spec SCC-PERF-002`: Mode B `verify_atomic` consumes $\le 550,000$ CUs and demonstrates measurable CU savings relative to Mode A due to zero account writes.
  - `@spec SCC-PERF-003`: Automated regression suite asserts compliance across all instruction discriminators.
  - `@spec SCC-DEPLOY-001`: SBPFv3 ELF (`e_flags = 0x3`) with 0 CU runtime delta versus SBPFv0 and a 5–15% smaller binary.
- **Engineering Performance Target:** Directly satisfies the internal compute unit target for Milestone Gate 2:
  > *Solana testnet deployment successfully validates AMD VCEK certificate chain and executes both Mode A `verify_and_register` and Mode B `verify_atomic` consuming $\le 550,000$ CUs, ensuring ample headroom under Solana's 1,400,000 CU limit for downstream consumer logic.*

---

## 2. Test Harness Architecture

```
confidential-compute/programs/solana-confidential-compute-verifier/
├── Cargo.toml (dev-dependencies: solana-program-test or mollusk-svm, solana-confidential-compute-core, solana-confidential-compute-crypto)
└── tests/
    └── cu_benchmarks.rs (Integration test harness)
```

### 2.1 Runtime Harness Selection
The harness executes either:
1. **`solana-program-test` (BanksClient):** In-process Solana validator engine loading `target/deploy/solana_confidential_compute_verifier.so`. Extracts CU consumption from `BanksClient::process_transaction_with_metadata` or transaction logs (`consumed X of Y compute units`).
2. **`mollusk-svm`:** Lightweight Solana SVM harness executing instruction vectors directly against the loaded ELF binary, providing exact scalar `result.compute_units_consumed`.

---

## 3. Instruction Test Vectors & Setup Fixtures

For each benchmark pass, the harness configures valid on-chain account state:

1. **`init_policy_registry`:**
   - PDA `[b"policy_registry"]`.
   - Populated with valid `ARK` public key, measurement allowlist holding `MOCK_MEASUREMENT`, and minimum TCB thresholds.
2. **`register_vcek` (or seeded `VcekAccount`):**
   - PDA `[b"vcek_v2", &chip_id_hash, &tcb_version.to_le_bytes()]` (`VcekAccount::SEED`, #253).
   - Populated with `MOCK_VCEK_PUBLIC_KEY_XY`.
3. **`SlotHashes` & `Clock` Sysvars:**
   - `SlotHashes` seeded with entry `(nonce_slot = 500, slot_hash = 0x55..55)`.
   - `Clock` seeded with `slot = 520` (age = 20 slots $\le 150$).
4. **Attestation Report:**
   - 1,184-byte report synthesized conforming to AMD #56860 Table 141.
   - Signed with deterministic P-384 key matching seeded `VcekAccount`.

---

## 4. Benchmark Invariants & Assertion Matrix

| Instruction | Max CU Ceiling | Metric Verified |
| :--- | :--- | :--- |
| `init_policy_registry` | $\le 15,000$ CUs | Registry initialization & PDA allocation |
| `register_vcek` | $\le 35,000$ CUs | VCEK cache lookup / allocation |
| `verify_and_register` (Mode A) | $\le 550,000$ CUs | P-384 ECDSA verification + `AttestedSignerAccount` allocation + `UsedNonceAccount` allocation |
| `verify_atomic` (Mode B) | $\le 550,000$ CUs | Stateless P-384 ECDSA verification + commitment matching ($\text{CUs} < \text{Mode A}$) |
| `verify_atomic_with_nonce` (Mode B) | $\le 550,000$ CUs | Nonce-variant P-384 ECDSA verification + single `UsedNonceAccount` allocation |

---

## 5. Output Telemetry

Upon completion, the harness outputs a structured scalar summary table:
```
================================================================================
SOLANA CONFIDENTIAL COMPUTE VERIFIER SBF COMPUTE UNIT BENCHMARK REPORT
================================================================================
Instruction                        Measured CUs    Ceiling CUs    Headroom
--------------------------------------------------------------------------------
init_policy_registry               ...             15,000         ...
register_vcek                      ...             35,000         ...
verify_and_register (Mode A)       ...             550,000        ...
verify_atomic (Mode B)             ...             550,000        ...
verify_atomic_with_nonce (Mode B)  ...             550,000        ...
--------------------------------------------------------------------------------
Mode B Stateless CU Savings: ... CUs (...%)
================================================================================
```

---

## 6. SBPFv3 Compute and Binary Size Invariants (`@spec SCC-DEPLOY-001`)

SBPFv3 (Agave v4.4 / SIMD-0500) is a bytecode and ELF-layout change. It does not alter Solana Confidential Compute instruction semantics, account layouts, or the CU ceilings in §4.

| Metric | Invariant |
| :--- | :--- |
| Runtime CU delta versus SBPFv0 | **0 CUs** for the same instruction path, account set, and verifier backend |
| Binary size | **5–15% smaller** than the SBPFv0 artifact (dynamic symbol table and load-time relocation records omitted) |
| CU ceilings | `@spec SCC-PERF-001` / `002` / `003` remain $\le 550,000$ CUs (and the per-instruction table in §4) |
| ELF conformance | `target/deploy/solana_confidential_compute_verifier.so` MUST report `Flags: 0x3` (`e_flags = 0x3`); syscalls MUST be static Murmur3-32 hashes |

The `cu_benchmarks` harness MUST continue to pass against an SBPFv3 `solana_confidential_compute_verifier.so`. A CU regression is a change in measured CUs relative to the SBPFv0 baseline for the same `--features` artifact, not a change in ELF `e_flags`. Build and assert the v3 artifact with `scripts/build-sbpfv3.sh`.
