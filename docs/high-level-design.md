# Solana Confidential Compute: High-Level Design (HLD)

## 1. Vision & Intent

Solana Confidential Compute delivers a Verifiable Compute layer for Solana. It anchors workload signing authority into hardware-protected Trusted Execution Environments (TEEs: AMD SEV-SNP and AWS Nitro Enclaves). Administrative key custody remains part of the [trust model](../SECURITY.md#administrative-authorities-and-trust-roots).

---

## 2. System Architecture

The architecture consists of four distinct tiers:

```
[ Tier 1: Hardware Runtime (Off-Chain) ]
GCE SEV-SNP Confidential VM / AWS Nitro Enclave
  - Workload execution inside encrypted CPU memory
  - Ephemeral Ed25519 keypair generation
  - Hardware attestation report query via PSP / Nitro hypervisor

[ Tier 2: Attestation Sidecar & CLI (Tooling) ]
solana-confidential-compute-sidecar / solana-confidential-compute-cli
  - Fetches AMD VCEK cert chain & Google Cloud OIDC JWT
  - Encodes workload public key and fresh slot blockhash into REPORT_DATA (bytes 0x050..0x090)
  - Builds transactions subject to the 1,232-byte packet guard; authentic inline certificate/document payloads exceed it

[ Tier 3: On-Chain Verifier (Smart Contract) ]
solana-confidential-compute-verifier (Native Solana BPF with Anchor Interop ABI)
  - 2-Stage Verification Pipeline (Cached VCEK PDA + Workload Attestation)
  - Validates P-384 ECDSA signatures on AMD VCEK / ASK / ARK certificates (AMD #56860 Table 141, FIPS 186-4)
  - Parses measurement, REPORT_DATA, chip_id, and TCB directly from signed 1,184-byte report
  - Inspects SlotHashes sysvar via O(1) byte offset lookup (age <= 150 slots)
  - Dual-Modality Dispatch:
    - Mode A (`verify_and_register`): Stateful session caching. Initializes `AttestedSignerAccount` and `UsedNonceAccount` PDAs.
    - Mode B (`verify_atomic` / `verify_atomic_with_nonce`): Stateless/ephemeral atomic attestation via `VerifyAtomicHeader` (80 bytes) and 32-byte action commitment.
  - Asserts binary measurement against governance allowlist
  - Enforces minimum TCB version policy

[ Tier 4: On-Chain Consumers (Ecosystem) ]
DeFi Protocols, RWA Issuers, Oracles, DePIN
  - Mode A: Reads or CPIs into `AttestedSignerAccount` PDA (measured Mode A check: 355 compute units; [README.md](../README.md#62-compute-units) §6.2).
  - Mode B: Introspects preceding Solana Confidential Compute instruction via `solana_confidential_compute_cpi::assert_attestation_atomic` (zero PDA rent).
  - Guarantees incoming signatures originate strictly from attested enclaves.
```

---

## 3. Subsystem Breakdown

1. **`solana-confidential-compute-core`:** Core domain models, zero-copy byte slicers over 1,184-byte SNP reports, and `REPORT_DATA` binary formats (`no_std` zero-heap compatible).
2. **`solana-confidential-compute-crypto`:** Montgomery P-384 ECDSA field arithmetic, ASN.1/DER X.509 certificate parsers, and JWT verification routines.
3. **`solana-confidential-compute-verifier`:** Native Solana BPF program exposing Anchor-compatible 8-byte instruction and account discriminators for both Mode A and Mode B.
4. **`solana-confidential-compute-cpi`:** On-chain consumer helpers (`assert_attestation_atomic`, `assert_attestation_signer`, `hash_action`). Depends on `solana-program` only. Does not depend on `solana-sdk`.
5. **`solana-confidential-compute-sdk`:** Off-chain Rust and TypeScript client libraries for publishers. Re-exports `solana-confidential-compute-cpi` types for host-side callers.
6. **`solana-confidential-compute-cli`:** Operational tool to generate and verify enclave proofs in a single command, including hardware low-S telemetry. Mode B defaults to `verify_atomic_with_nonce`.
7. **`solana-confidential-compute-sidecar`:** Daemon running inside the enclave container to handle key generation, attestation refresh, and on-chain heartbeats.

---

## 4. Key Architectural Invariants & Solutions

### 4.1 Solana Packet MTU (1,184-Byte SNP Report)
- **Problem:** An AMD SEV-SNP report body is 1,184 bytes. In legacy Solana v0 transactions (1,232-byte MTU), the report exceeds packet boundaries once signatures and account keys are included. Mode B adds an 80-byte `VerifyAtomicHeader` (1,264 bytes total).
- **Current limitation:** Public builders reject oversized packets. No staged account transport is implemented; an extended-MTU deployment is not established by native tests. See [measured transport limits](../SECURITY.md#82-software-p-384-compute-spec-scc-sec-003) before choosing a submission path.

### 4.2 2-Stage Verification Pipeline (CU Ceiling Management)

> The grant closeout deployment does not evaluate P-384 in software inside the Solana program. `SolanaDefaultVerifier` delegates to `InstructionIntrospectionVerifier` and accepts a signature only when a preceding instruction has program id `EXPECTED_SIGVERIFY_PROGRAM_ID`. No mainnet secp384r1 precompile id is assigned, so on-chain verification fails closed. A pure-software NIST P-384 scalar multiplication on SBF costs ~46,000,000 CUs against a 1,400,000 CU transaction limit. Host crates (`solana-confidential-compute-crypto`, `solana-confidential-compute-cli`) verify P-384 on host/off-chain targets. Section 4.2 below describes the future target architecture pending a native SVM secp384r1 precompile or syscall. For Milan KDS chains, ARK and ASK certificates are RSA-4096 RSASSA-PSS SHA-384; the VCEK leaf is P-384. See [SECURITY.md](../SECURITY.md#8-auditor-scope--runtime-limitations) §8.

The measured Mode A consumer check is 355 compute units. See [README.md](../README.md#62-compute-units) §6.2.

- **Problem:** Verifying a full 3-cert X.509 chain (ARK -> ASK -> VCEK) plus the attestation report signature in a single transaction requires 4 P-384 verifications (~1.6M-1.8M CUs), exceeding Solana's 1.4M CU limit.
- **Solution:**
  - **Stage 1 (`RegisterVcek`):** Executed once per physical host machine. Cryptographically verifies the AMD certificate chain from the trusted AMD Root Key (ARK) down to the Versioned Chip Endorsement Key (VCEK):
    1. Reads `ark_pubkey_xy` from the singleton `PolicyRegistry` PDA.
    2. Verifies AMD Signing Key (ASK) certificate signature against `ark_pubkey_xy` (P-384 ECDSA over SHA-384).
    3. Verifies Versioned Chip Endorsement Key (VCEK) certificate signature against ASK public key.
    4. Extracts hardware `chip_id`, TCB version, and VCEK SPKI public key from X.509 extensions and subject info.
    5. Initializes and caches a `VcekAccount` PDA derived from `[b"vcek_v2", chip_id_hash, tcb_bytes]` via System Program CPI `create_account`.
  - **Stage 2 Verification Modalities:**
    - **Mode A (`VerifyAndRegister` - Session Caching):**
      1. Reads cached `VcekAccount` PDA.
      2. Zero-copy borrows the 1,184-byte report.
      3. Verifies single P-384 signature over the 672-byte report body (~380k CUs).
      4. Inspects `SlotHashes` sysvar (age <= 150 slots).
      5. Initializes `UsedNonceAccount` PDA.
      6. Checks binary measurement and TCB floor.
      7. Initializes or refreshes `AttestedSignerAccount` PDA. Total CU: <= 550,000 CUs.
    - **Mode B (`VerifyAtomic` - Stateless Introspection):**
      1. Reads cached `VcekAccount` PDA and `SlotHashes` sysvar.
      2. Loads `slot_hash` via `load_slot_hash(nonce_slot)`.
      3. Verifies commitment: $\text{REPORT\_DATA}[32..64] == \text{SHA-256}(\text{slot\_hash} \parallel \text{header.action\_hash} \parallel \text{header.consumer\_program\_id})$.
      4. Verifies P-384 signature and hardware policy.
      5. Zero PDA writes (`verify_atomic`) or writes `UsedNonceAccount` PDA (`verify_atomic_with_nonce`).
      6. Downstream instruction introspects Solana Confidential Compute execution via `sysvar::instructions`.

### 4.3 Anti-Replay & Freshness Engine
- **SlotHashes Bounded Scan:** In Mode A, verifier asserts `slot_hash == view.nonce()`. In Mode B, verifier loads `slot_hash` directly from `SlotHashes` sysvar and verifies the commitment hash.
- **Nonce Age Bound:** Enforces `clock.slot - nonce_slot <= 150` slots (~60 seconds).
- **Multi-Tenant Anti-Replay:**
  - Mode A: Initializes `UsedNonceAccount` PDA derived from `[b"nonce", signer_pubkey, nonce]`.
  - Mode B Nonce Variant: Initializes `UsedNonceAccount` PDA derived from `[b"nonce", signer_pubkey, commitment]`. Identical signer/commitment replay within 150 slots fails closed.

### 4.4 Account Lifecycle & Cross-Program Invocation (CPI)
- **On-Chain PDA Allocation:** When any PDA (`PolicyRegistry`, `VcekAccount`, `AttestedSignerAccount`, `UsedNonceAccount`) is created, the program executes `invoke_signed` against `system_instruction::create_account`, funded by the transaction `payer`.
- **Strict Ownership & Writable Assertions:** The verifier asserts `account.owner == program_id`, `account.is_writable == true`, and verifies expected PDA addresses using client-provided bumps via `Pubkey::create_program_address` to eliminate on-chain bump hunting.
- **Re-Initialization Guards:** 
  - `PolicyRegistry` rejects re-initialization with `ProgramError::AccountAlreadyInitialized`. Its stored authority can still update policy; `rotate_root_cert` is refused with `InvalidInstruction` (#255), so it cannot rotate the AMD P-384 root; see the [authority model](../SECURITY.md#administrative-authorities-and-trust-roots).
  - `VcekAccount` is immutable once registered for a specific chip ID and TCB version vector.
  - `AttestedSignerAccount` permits re-attestation only when expired (`current_slot > expires_slot`) or when authenticated with a fresh slot blockhash nonce.

### 4.5 Silicon Integrity & Signed Byte Parsing
- **Zero Struct Substitution:** The on-chain verifier does not trust any user-supplied struct fields for measurement or pubkey. The verifier parses measurement (`0x090..0x0C0`), `REPORT_DATA` (`0x050..0x090`), `chip_id` (`0x1A0..0x1E0`), and `reported_tcb` (`0x180..0x188`) directly from the signed 1,184-byte report payload.
- **Hardware Security Policy Gates:**
  - Policy bit 19 (`DEBUG`) must be 0 (`@spec SCC-SEC-001`).
  - Policy bit 18 (`MIGRATE_MA`) must be 0.
  - Policy bit 17 (`RESERVED_MUST_BE_ONE`) must be 1.
  - Policy bit 16 (`SMT`) is allowed and is not required.
  - `vmpl` must be 0.
  - Report `version` must be within `1..=5`.
- **Minimum TCB Policy:** The `PolicyRegistry` enforces an on-chain minimum TCB version (`min_tcb`). Reports from outdated or vulnerable hardware microcode are rejected even if the signature is valid.



Current Mode A records use V2 (`attested_signer_v2`, 154 bytes, V2 discriminator) and require slot plus exclusive Unix expiry checks. See the [source-linked V2 contract](intent/confidential-compute-verifier-specs.md#current-mode-a-v2-contract); historical gate results do not establish V2 runtime performance.
