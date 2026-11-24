# Low-Level Design: Solana Confidential Compute Developer CLI (`solana-confidential-compute-cli`)

This document defines the architecture, Linux AMD SEV-SNP ioctl interface, mock report generator, transaction assembly pipeline, and telemetry logging for `solana-confidential-compute-cli` (Component 6, Milestone Gate 1).

---

## 1. Objectives & Boundaries

- **Objective:** Provide a single-binary developer CLI to query AMD SEV-SNP hardware reports (or generate mock reports), bind Ed25519 workload identities, verify reports locally, and package Solana on-chain attestation transactions.
- **Hardware Abstraction:**
  - On Linux with `/dev/sev-guest`: execute ioctl `SNP_GET_REPORT` to obtain 1,184-byte attestation report from AMD PSP.
  - On macOS or non-SNP hosts: execute in mock mode (`--mock`) using cryptographic test vectors and simulated P-384 signatures.
- **Milestone Gate 1 Compliance:** Satisfy Gate 1 criteria:
  > *Local CLI extracts AMD SEV-SNP report on Linux (`/dev/sev-guest` or mock), encodes `REPORT_DATA`, and verifies signature locally.*
- **ASD-STE100 Compliance:** Concise design, explicit types, zero undefined states.

---

## 2. Command Architecture & Subcommands

```
solana-confidential-compute
├── prove
│   ├── --mode <stateful|atomic>       Attestation modality (Mode A vs Mode B)
│   ├── --keypair <PATH>               Path to workload Ed25519 keypair
│   ├── --mock                         Emulate AMD SEV-SNP report locally
│   ├── --device <PATH>                SEV-guest device path (default: /dev/sev-guest)
│   ├── --rpc <URL>                    Solana RPC URL
│   ├── --payer <PATH>                 Transaction fee payer keypair
│   ├── --program-id <PUBKEY>          Solana Confidential Compute verifier program ID
│   ├── --action-hash <HEX>            Mode B action hash (32 bytes hex)
│   ├── --consumer-program <PUBKEY>    Mode B consumer program ID
│   ├── --stateless-idempotent         Mode B: use verify_atomic (idempotent actions only)
│   └── --dry-run                      Print base64/hex transaction without submitting
└── verify
    ├── --pubkey <PUBKEY>              Workload Ed25519 pubkey to check
    ├── --program-id <PUBKEY>          Solana Confidential Compute verifier program ID
    └── --rpc <URL>                    Solana RPC URL
```

---

## 3. Linux SEV-SNP Hardware Interface (`/dev/sev-guest`)

### 3.1 Kernel ioctl Layout
Linux kernel ABI for `/dev/sev-guest` uses `SNP_GET_REPORT` ioctl `0xC0205300`. That value is `_IOWR('S', 0x00, 32)`. The argument is the 32-byte `snp_guest_request_ioctl`. `0xC0485301` is not this ioctl. The layout matches `bins/solana-confidential-compute-cli/src/hardware.rs`.
```rust
pub const SNP_GET_REPORT: u64 = 0xC0205300; // _IOWR('S', 0x00, 32)

#[repr(C)]
pub struct SnpGuestRequestIoctl {
    pub msg_version: u8,
    pub _pad: [u8; 7],
    pub req_data: u64,
    pub resp_data: u64,
    pub exitinfo2: u64,
}

#[repr(C)]
pub struct SnpReportReq {
    pub user_data: [u8; 64], // Injected into REPORT_DATA
    pub vmpl: u32,           // VMPL level (0)
    pub key_sel: u8,         // Sent as 0
    pub reserved: [u8; 27],
}

/// `data` is 4,000 bytes at offset 0. The 32-byte tail is not written by the driver.
#[repr(C)]
pub struct SnpReportResp {
    pub data: [u8; 4000],
    pub reserved: [u8; 32],
}
```

### 3.2 Mock Generator (`--mock`)
When `--mock` is specified:
1. Synthesizes a valid 1,184-byte report conforming to AMD Publication #56860 Table 141.
2. Injects requested `REPORT_DATA[0..64]`.
3. Signs `report[0..672]` with a deterministic P-384 testing key.
4. Populates $r$ and $s$ in little-endian format at offsets `0x2A0` and `0x2E8`.

---

## 4. Transaction Assembly & Compute Budget

Attestation transactions require elevated compute budgets:
1. **Compute Limit:** `ComputeBudgetProgram::set_compute_unit_limit(700_000)` (provides 150k CU buffer above 550k ceiling).
2. **Priority Fee:** `ComputeBudgetProgram::set_compute_unit_price(micro_lamports)`.
3. **Instruction Composition:**
   - **Mode A (`verify_and_register`):**
     - Accounts: `[payer, policy_registry, vcek_account, attested_signer, slot_hashes_sysvar, clock_sysvar, system_program]`.
     - Data: `[VERIFY_AND_REGISTER_DISCRIMINATOR || report_bytes]`.
   - **Mode B (`verify_atomic_with_nonce`, default):**
     - Accounts: `[payer, policy_registry, vcek_account, used_nonce, slot_hashes_sysvar, clock_sysvar, system_program]`.
     - Data: `[VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR || VerifyAtomicHeader (72 bytes) || report_bytes (1184 bytes)]`.
   - **Mode B (`verify_atomic`, `--stateless-idempotent` only):**
     - Accounts: `[policy_registry, vcek_account, slot_hashes_sysvar, clock_sysvar]`.
     - Data: `[VERIFY_ATOMIC_DISCRIMINATOR || VerifyAtomicHeader (72 bytes) || report_bytes (1184 bytes)]`.
     - Reserved for idempotent actions. Value-moving operations MUST use the nonce-bound default.

---

## 5. Low-S Telemetry & Verification (@spec SCC-SEC-010)

Before submitting or outputting any report, `solana-confidential-compute-cli`:
1. Checks if scalar $s > \lfloor n / 2 \rfloor$.
2. Logs high-S telemetry: `[WARN] High-S signature detected (s > n/2). Hardware vendor: AMD PSP. Valid under FIPS 186-4; non-canonical under BIP-62.`
3. Verifies ECDSA P-384 signature locally using `solana_confidential_compute_crypto::verify_p384_signature`.
