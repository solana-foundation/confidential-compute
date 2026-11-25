# Solana Confidential Compute — Milestone Gate 4 Verification Report

Architecture map: [docs/high-level-design.md](../high-level-design.md).

**Milestone:** Gate 4 (End of Month 4) — Phase 7.3  
**Deliverable:** SBPFv3 compilation, Devnet program upgrade, and live AWS Nitro Mode A smoke test  
**Status:** **SATISFIED** for the on-chain Nitro dispatch and SBPFv3 deploy gate  
**Pull Request:** upstream #47  

---

## 0. Grant closeout deployment

Phase 7.3 telemetry in §3 is the slot 503,550,668 deploy (618,288 bytes) and transaction `S3GWXy9…` (7,829 CUs). That ELF is not the program-data account now.

| Program | Program-data account | Slot | ELF bytes | Header | Upgrade transaction |
| :--- | :--- | ---: | ---: | :--- | :--- |
| `solana-confidential-compute-verifier` | `EWShgrBQhkQiTmGTrYm9DuWvUPKRcsbECqXJuGa1BFcX` | 505,980,419 | 673,784 | `e_machine = 0xf7`, `e_flags = 0x3` | [`KHUQUyx8…`](https://explorer.solana.com/tx/KHUQUyx8xQB5VD4KFBsE3hQ4RrtUD8iQ72ZbMEeSiYomU1u1y48oZF73eqTkvQ93Dp8PXUjJdZb2jE5P5JjG2QM?cluster=devnet) |
| `solana-confidential-compute-consumer-reference` | `8o22e8hzYPkWAn48wE91CaL4WJQawhUP4YiqdozkE6ym` | 505,980,264 | 127,744 | `e_machine = 0x107`, `e_flags = 0x0` | [`5a92Bwn8…`](https://explorer.solana.com/tx/5a92Bwn8p9371LRQhtUJNrbKtCAoe67Wzjd6L9gbCsyGJ5szzoFuLBz5uwAGkrdWnmMRorfeQVXFnKs7VNcTrdMC?cluster=devnet) |

`scripts/build-sbpfv3.sh` builds the verifier only. The consumer header is not SBPFv3.

Grant closeout deployment smoke transaction: [`2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH`](https://explorer.solana.com/tx/2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH?cluster=devnet). Slot 505,980,579. The parsing path consumed 8,122 compute units. The verifier then returned `custom program error: 0x2` (`VerificationFailed`). Transaction meta `computeUnitsConsumed` is 8,272.

TypeScript package at the grant closeout deployment: **17 passed** tests. 7 in `sdks/typescript/test/packet.test.cjs`. 10 in `sdks/typescript/test/nitro.test.cjs`. The “13/13” line in §6.2 is the Gate 4 capture.

On Solana, without `mock-crypto`, `DefaultVerifier` is `SolanaDefaultVerifier`. `scripts/build-sbpfv3.sh` does not enable `mock-crypto`. `DirectCryptoVerifier` is the host default. `Groth16SyscallVerifier` is not the default.

Devnet upgrade authority: `BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG`. Production custody is intended to use Foundation governance (Squads multisig); this repository does not establish a production vault address or executed handoff. The loader upgrade authority and `PolicyRegistry.authority` are separate controls. The registry signer cannot change any trust root: since upstream PR #255, `rotate_root_cert` returns `VerifierError::InvalidInstruction` even when the registry authority signs, and leaves the legacy AMD P-384 `ark_pubkey_xy` field unchanged. Pinned Nitro and Milan RSA roots require a code change. The coordinated upstream #173 fix / PR #226 restricts production AMD to pinned Milan RSA, so that legacy field has no supported vendor-root meaning. A registry signer may be a keypair or a governance PDA signing via CPI; Solana Confidential Compute enforces no threshold or timelock itself. See the [authority and trust-root model](../../SECURITY.md#administrative-authorities-and-trust-roots). Commands are in [`scripts/README.md`](../../scripts/README.md).

The Mode A consumer check consumed 355 compute units on Devnet (`@spec SCC-CONSUMER-001`). The Mode B consumer check consumed about 1,950 compute units (`@spec SCC-CONSUMER-002`). Policy init consumed 7,435 compute units.

---

## 1. Executive Summary

Phase 7.3 of Gate 4 is **SATISFIED** for the capture in §3.

`solana-confidential-compute-verifier` compiles as an SBPFv3 ELF (`e_flags = 0x3`, SIMD-0500) through `scripts/build-sbpfv3.sh`. The program id on Devnet is `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`. The bytes in the program-data account at the grant closeout deployment are in §0. `scripts/smoke_test_devnet.ts` packs `verify_nitro_attestation` Mode A, rejects an oversized document against the 1,232-byte packet cap, and submits a synthetic COSE Sign1 document.

The Phase 7.3 instruction aborted with `VerifierError::VerificationFailed` (`Custom(2)`). That instruction consumed 7,829 compute units. The later smoke transaction in §0 failed closed with the same custom error. That parsing path consumed 8,122 compute units. `@spec SCC-PERF-001`.

---

## 2. On-Chain Deployments & Verified Addresses (Solana Devnet)

| Component | Program ID / PDA | Network | Status | Explorer Link |
| :--- | :--- | :--- | :--- | :--- |
| **`solana-confidential-compute-verifier`** | `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh` | Devnet | **673,784 bytes, `e_flags = 0x3`, slot 505,980,419** | [Explorer](https://explorer.solana.com/address/EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh?cluster=devnet) |
| **`solana-confidential-compute-consumer-reference`** | `A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ` | Devnet | **127,744 bytes, `e_flags = 0x0`, slot 505,980,264** | [Explorer](https://explorer.solana.com/address/A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ?cluster=devnet) |
| **`PolicyRegistry` Singleton** | `2FX8HZqEXr7x8kHzkhy4KPUuViVt9M6xqhFTB12jaDUf` | Devnet | **Initialized** | [Explorer](https://explorer.solana.com/address/2FX8HZqEXr7x8kHzkhy4KPUuViVt9M6xqhFTB12jaDUf?cluster=devnet) |
| **Upgrade authority** | `BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG` | Devnet | **Active** | [Explorer](https://explorer.solana.com/address/BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG?cluster=devnet) |

Verifier program-data account: `EWShgrBQhkQiTmGTrYm9DuWvUPKRcsbECqXJuGa1BFcX`. The Phase 7.3 upgrade in §3.1 used slot **503,550,668** and a 618,288-byte ELF. The account slot is now **505,980,419** (673,784 bytes). See §0.

Consumer program-data account: `8o22e8hzYPkWAn48wE91CaL4WJQawhUP4YiqdozkE6ym`. Slot **505,980,264**. ELF **127,744** bytes. `e_flags = 0x0`.

---

## 3. Live Devnet Transaction Telemetry

### 3.1 Phase 7.3 SBPFv3 program upgrade

This subsection is the slot 503,550,668 capture. It is not the current program-data slot.

- **Transaction Signature:** [`29h4C33wGxiFTSyvfay3pwUBc1MDCU3AcvYzZJwuCcZFtDR6hzk7Lg57LAr18Bem5Fd9okxmP3pCPRZxGPm5tDf7`](https://explorer.solana.com/tx/29h4C33wGxiFTSyvfay3pwUBc1MDCU3AcvYzZJwuCcZFtDR6hzk7Lg57LAr18Bem5Fd9okxmP3pCPRZxGPm5tDf7?cluster=devnet)
- **Slot:** 503,550,668
- **Status:** Finalized
- **ELF:** `target/deploy/solana_confidential_compute_verifier.so` — 618,288 bytes, `e_machine = EM_BPF (0xf7)`, `e_flags = 0x3`
- **Log Telemetry:**
  ```
  Program BPFLoaderUpgradeab1e11111111111111111111111 invoke [1]
  Upgraded program EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh
  Program BPFLoaderUpgradeab1e11111111111111111111111 success
  ```

### 3.2 Phase 7.3 Nitro Mode A fail-closed gate

This subsection is transaction `S3GWXy9…` at slot 503,550,778. The grant closeout smoke transaction is in §0.

- **Transaction Signature:** [`S3GWXy9PMFSpxX5LHVWBYZFY4oqokL3Kg5HZvWwXkqxucBn3JKLjw5JowZPwCbeWaXNeDm7a6UVCsR97LGWzkr9`](https://explorer.solana.com/tx/S3GWXy9PMFSpxX5LHVWBYZFY4oqokL3Kg5HZvWwXkqxucBn3JKLjw5JowZPwCbeWaXNeDm7a6UVCsR97LGWzkr9?cluster=devnet)
- **Slot:** 503,550,778
- **Instruction:** `verify_nitro_attestation` Mode A (`discriminator [107, 76, 178, 169, 215, 146, 23, 95]`, `mode = 0`)
- **Document:** 522-byte tagged COSE Sign1 with placeholder leaf and root certificates
- **On-chain result:** `Custom(2)` = `VerifierError::VerificationFailed` (certificate chain rejected)
- **Solana Confidential Compute instruction compute:** **7,829 CUs**
- **Transaction compute:** **7,979 CUs**
- **Log Telemetry:**
  ```
  Program ComputeBudget111111111111111111111111111111 invoke [1]
  Program ComputeBudget111111111111111111111111111111 success
  Program EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh invoke [1]
  Program EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh consumed 7829 of 549850 compute units
  Program EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh failed: custom program error: 0x2
  ```
- **Evaluation:** The upgraded SBPFv3 binary dispatches `verify_nitro_attestation`. A synthetic document that is not an AWS-signed chain aborts before signer registration. The instruction consumed 7,829 compute units. `@spec SCC-PERF-001`.

### 3.3 Packet Ceiling (Local, Pre-RPC)

The Phase 7.3 capture recorded a 4,096-byte Nitro document at 4,518 bytes and a raw Mode B report at 1,704 bytes. Both threw `PacketTooLargeError` and were not submitted.

The grant closeout deployment harness `scripts/smoke_test_devnet.ts` rejects a document of `MAX_NITRO_DOCUMENT_LEN` (8,192 bytes) and a raw 1,184-byte Mode B report with `PacketTooLargeError`. It does not submit either one. It does not pin the 4,518 or 1,704 integers.

---

## 4. Priority Alignment & Invariant Matrix

| Priority | Invariant / Specification | Verification Method | Result |
| :--- | :--- | :--- | :--- |
| **1. Security (Zero Compromise)** | **SBPFv3 Conformance (`@spec SCC-DEPLOY-001`):** Compile with `cargo-build-sbf --arch v3` and static Murmur3-32 syscall hashes (SIMD-0178 / SIMD-0500). | `scripts/build-sbpfv3.sh --self-test` and `--verify`. ELF `Flags: 0x3`. | **VERIFIED** |
| | **Nitro instruction dispatch (`@spec SCC-NITRO-008`):** Mode A `verify_nitro_attestation` registers only after COSE parse, PCR0 allowlist, nonce freshness, and chain verification. | Live Devnet tx `S3GWXy9…` aborted at chain verification (`Custom(2)`) with Mode A account order. | **VERIFIED** (fail-closed) |
| | **Legacy packet cap:** Standard builders reject payloads above 1,232 bytes. Oversized packers stay off the live cluster. | Phase 7.3 capture: 4,096-byte document → `PacketTooLargeError` (4,518 bytes). The grant closeout deployment harness rejects 8,192 bytes and a raw Mode B report. | **VERIFIED** |
| **2. Ease of Use** | **TypeScript builders:** `buildVerifyNitroAttestationIx` / `Tx` and quarantined `*Oversized` packers. | Gate 4 capture was 13 tests. The grant closeout deployment has 17 tests (7 packet, 10 nitro). | **VERIFIED** |
| **3. Compute Units (CUs)** | **Nitro Mode A parsing path (`@spec SCC-PERF-001`):** | Phase 7.3: **7,829** instruction CUs and **7,979** transaction CUs. Grant closeout smoke: **8,122** CUs. Transaction meta 8,272. | **VERIFIED** |

---

## 5. SBPFv3 Build Gate (`@spec SCC-DEPLOY-001`)

```
$ bash scripts/build-sbpfv3.sh --self-test
==> self-test ok (SCC-DEPLOY-001 parser gate)

$ bash scripts/build-sbpfv3.sh
==> SBPFv3 build (SCC-DEPLOY-001)
    toolchain: cargo-build-sbf
    arch:      v3
    tools:     v1.56
==> ok: target/deploy/teton_verifier.so (618288 bytes) e_flags=0x3
```

The log above is the Phase 7.3 capture (618,288 bytes). A later Devnet upgrade wrote 673,784 bytes at slot 505,980,419. Both headers that this script accepts for the verifier have `e_flags = 0x3`. The parser gate rejects `e_flags = 0x2`, big-endian ELF, a non-BPF `e_machine`, and non-ELF files. The script also rejects dynamic syscall sections. Size is not pinned.

---

## 6. Automated Verification Suites

### 6.1 Rust Workspace Test Suite

```
$ cargo test --workspace
```

The Gate 4 host run recorded `nitro_tests` (7/7), JWT processor tests (11/11), sidecar (21 library + 6 integration), and Rust SDK builder tests noted then as 9/9. Those integers are the capture. They are not the grant closeout deployment totals. `test_cu_benchmarks_live_sbf` in `programs/solana-confidential-compute-verifier/tests/cu_benchmarks.rs` is `#[ignore]`. A manual run returns when `target/deploy/solana_confidential_compute_verifier.so` is absent, and when ELF byte 48 is `0x3`.

### 6.2 TypeScript SDK

```
$ cd sdks/typescript && npm test
```

The Gate 4 capture reported 13 tests. The grant closeout deployment has 17 tests in `sdks/typescript/test/packet.test.cjs` (7) and `sdks/typescript/test/nitro.test.cjs` (10). `npm test` runs `tsc` and then `node --test` on those files. `scripts/tsconfig.json` typechecks `scripts/smoke_test_devnet.ts`.

### 6.3 Devnet Smoke Harness

```
$ NODE_PATH=sdks/typescript/node_modules bun scripts/smoke_test_devnet.ts
```

Completed successfully. Live signature and CU telemetry are in §3.2.

---

## 7. Deliverable Artifacts

| Component | Repository Path |
| :--- | :--- |
| **SBPFv3 Build Tooling** | `scripts/build-sbpfv3.sh` |
| **Devnet Smoke Test Harness** | `scripts/smoke_test_devnet.ts` |
| **Nitro TypeScript Builders** | `sdks/typescript/src/index.ts` |
| **On-Chain Nitro Processor** | `programs/solana-confidential-compute-verifier/src/processor.rs` |
| **Nitro Intent Specifications** | `docs/intent/confidential-compute-nitro-specs.md` |

---

## 8. Remaining Gate 4 Items

This report satisfies the Phase 7.3 deploy gate: SBPFv3 ELF, Devnet upgrade, and live Nitro instruction telemetry.

The broader Gate 4 milestone still includes:

1. **Production AWS-signed document.** The live transaction used a synthetic COSE Sign1. Placeholder certificates fail closed at chain verification. A hardware NSM document with the AWS Nitro Root CA G1 chain is the remaining happy-path proof.
2. **Production P-384 compute.** The Solana build without `mock-crypto` sets `DefaultVerifier` to `SolanaDefaultVerifier`. `DirectCryptoVerifier` is the host default. On Solana its `verify_p384` returns `InvalidSignature` and does not run host P-384. `Groth16SyscallVerifier` is not the default. `EXPECTED_SIGVERIFY_PROGRAM_ID` has no mainnet secp384r1 program id. Introspection fails closed until that program is deployed.
3. **Documentation portal** and **clean repository extraction**, as listed in the project delivery schedule.

---

## 9. Final Sign-Off

Phase 7.3 of Gate 4 is complete. `solana-confidential-compute-verifier` is an SBPFv3 program on Solana Devnet. `verify_nitro_attestation` Mode A is live and fail-closed. The Phase 7.3 instruction consumed 7,829 compute units. The grant closeout deployment parsing path consumed 8,122 compute units.
