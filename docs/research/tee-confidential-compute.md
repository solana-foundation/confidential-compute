# Confidential Computing & Trusted Execution Environments (TEEs)

Category: Architecture
Last reviewed: 2026-09-17
Status: VERIFIED
Verified against: [Confidential Computing Consortium](https://confidentialcomputing.io), AMD Publication #56860 (Rev 3.00), AWS Nitro Enclaves User Guide (v2026), Google Cloud Confidential Space Docs
Sources: [AMD SEV-SNP Architecture](https://www.amd.com/en/developer/sev.html), [AWS Nitro Enclaves User Guide](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html), [Google Cloud Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs)

---

## 1. Executive Summary

Confidential Computing protects data in use by performing computation inside hardware-isolated **Trusted Execution Environments (TEEs)**. In traditional cloud architectures, anyone with root or physical host access (hypervisor administrators, cloud technicians, kernel exploits) can dump memory to extract cryptographic private keys. TEEs eliminate this attack surface through CPU-level memory encryption (AMD SEV-SNP), hardware ASIC core/memory isolation (AWS Nitro), and cryptographic attestation.

Solana Confidential Compute anchors Solana Ed25519 signing keys inside TEEs to eliminate operator private key risk, rogue admin compromises (e.g. Drift $285M loss), and unverified RWA fund redemptions.

---

## 2. Threat Model & Security Guarantees

```
+-------------------------------------------------------------------------+
|                              Untrusted World                            |
|  - Host Operating System / Hypervisor (KVM, QEMU, Xen)                  |
|  - Cloud Provider Engineers & Data Center Personnel                     |
|  - Neighboring Multi-Tenant Virtual Machines                            |
|  - Untrusted Host I/O, Storage, and Host Network Stack                  |
+-------------------------------------------------------------------------+
                                    |
                    Hard Hardware Boundary (CPU / ASIC)
                                    v
+-------------------------------------------------------------------------+
|                      Trusted Execution Environment                      |
|                                                                         |
|  1. Data Isolation:                                                     |
|     - AMD SEV-SNP: AES memory encryption + Reverse Map Table (RMP).     |
|     - AWS Nitro: Hardware core partitioning & memory carving via ASIC.  |
|                                                                         |
|  2. Launch Integrity: Hardware cryptographically signs a SHA-384 digest |
|     of the workload initial image, proving exact code execution.        |
|                                                                         |
|  3. Ephemeral Cryptographic Authority: Private keys generated inside RAM|
|     cannot be extracted by host administrators or hypervisors.          |
+-------------------------------------------------------------------------+
```

### What TEEs Protect Against
1. **Host Memory Dumps:** Hypervisor cannot read guest memory. On AMD SEV-SNP, memory is CPU-encrypted. On AWS Nitro, memory is physically partitioned and unmapped from the parent instance.
2. **Operator Phishing & Social Engineering:** Developers and infrastructure administrators do not hold or possess the private keys.
3. **Launch Image Subversion:** Malicious hypervisors cannot modify guest binaries without altering the hardware measurement.

### What TEEs Do NOT Protect Against (Critical Engineering Constraints)
1. **Side-Channel Timing & Speculative Execution:** CPU attacks (Spectre, Inception, CacheWarp) require microcode patches and on-chain minimum TCB gating.
2. **Untrusted I/O & Network MITM:** Network and storage traffic routed through the host can be dropped, delayed, or reordered. All transaction payloads must be self-contained, authenticated, and signed inside the enclave before transmission across vsock or network interfaces.
3. **Clock Deception:** Host hypervisors can manipulate guest system time. TEE workloads cannot rely on local host clocks for blockchain consensus; freshness must bind to on-chain Solana slot blockhashes (`REPORT_DATA`).

---

## 3. Platform Comparison: AMD SEV-SNP vs. AWS Nitro Enclaves

| Architecture Dimension | AMD SEV-SNP (GCE Confidential VM) | AWS Nitro Enclaves |
| :--- | :--- | :--- |
| **Isolation Mechanism** | Reverse Map Table (RMP) + AES memory encryption on AMD EPYC CPUs. | CPU core partitioning + memory isolation enforced by custom AWS Nitro PCIe ASIC. |
| **Attestation Format** | Binary 1,184-byte hardware report signed with **ECDSA P-384** (SHA-384). | **COSE Sign1** (CBOR Object Signing and Encryption) signed with **ECDSA P-384**. |
| **Device Interface** | `/dev/sev-guest` (ioctl `SNP_GET_REPORT`). | `/dev/nsm` (Nitro Security Module ioctl). |
| **Root of Trust** | AMD Root Key (ARK) $\to$ AMD Signing Key (ASK) $\to$ Chip VCEK/VLEK. | AWS Nitro Root CA $\to$ Intermediate CA $\to$ Enclave leaf certificate. |
| **Measurement Anchor** | 48-byte SHA-384 launch digest (`measurement` / MRENCLAVE). | `PCR0` (EIF image), `PCR1` (kernel/bootstrap), `PCR2` (app), `PCR8` (EIF signer). |
| **User Data Binding** | 64-byte `REPORT_DATA` field embedded in hardware-signed report. | `user_data` (up to 1,024 B) and `nonce` embedded in signed CBOR document. |
| **Network Architecture** | Full VM with encrypted memory; standard Linux networking. | Striped micro-VM with **no persistent storage and no external network** (vsock only). |
| **Verification Path on Solana** | Stage 1 (Cached `VcekAccount` PDA) + Stage 2 (`verify_and_register`). | Stage 1 (Cached AWS Intermediate PDA) + Stage 2 (`verify_nitro`). |

---

## 4. Hardware Attacks & Mitigation Matrix

| Attack Vector | Target Platform | Mitigation in Solana Confidential Compute |
| :--- | :--- | :--- |
| **CacheWarp** | AMD SEV-SNP (Milan) | Enforce component-wise `min_tcb` on microcode. |
| **INCEPTION / SRSO** | AMD SEV-SNP | Enforce `min_tcb` microcode and launch mitigation vectors. |
| **Enclave Debug Mode** | AMD SEV-SNP | Enforce `@spec SCC-SEC-001`: reject report if `policy & (1 << 19) != 0`. |
| **Nitro Debug Mode** | AWS Nitro Enclaves | Enforce non-zero `PCR0`, `PCR1`, and `PCR2` (debug enclaves have all-zero PCRs). |
| **Vsock Proxy MITM** | AWS Nitro Enclaves | Ephemeral Ed25519 key signs complete transaction wire bytes in enclave memory. |
| **Untrusted Clock Skew** | Both | Nonce freshness validated against Solana `SlotHashes` sysvar ($\le 150$ slots). |
| **In-Window Replay** | Both | `UsedNonceAccount` PDA prevents duplicate report submission. |

---

## 5. Security Invariants for Solana Confidential Compute

1. **Deterministic Key Ownership:** The on-chain program only registers an Ed25519 public key if that key matches bytes `0..32` of `REPORT_DATA` (or `user_data`) extracted directly from a valid hardware-signed attestation.
2. **Binary Allowlisting:** The measurement digest (`measurement` or `PCR0`) extracted from the hardware report must match an active entry in the source-specific `BackendPolicy.measurements` (AMD=1, Nitro=2, GCP=3). `PolicyRegistry` retains authority and AMD component-wise TCB floors; its legacy measurement storage is not an admission control. See the [current governance contract](../intent/confidential-compute-verifier-specs.md#backend-measurement-governance).
3. **Silicon Revocation:** Physical CPUs with vulnerable microcode levels are rejected via on-chain component-wise `min_tcb` checks.
