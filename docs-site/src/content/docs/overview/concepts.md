---
title: Concepts & Glossary
description: Core concepts of hardware-attested verifiable compute on Solana, including Intel TDX quotes, with plain-English definitions.
---

Solana Confidential Compute bridges hardware confidential computing and the Solana Virtual Machine (SVM). This page explains how Trusted Execution Environments (TEEs) eliminate hot-key risk for smart contracts and defines essential terminology.

For the full reference document, see [GLOSSARY.md](../../../../../GLOSSARY.md).

---

## TEE in 5 Minutes for Solana Developers

### 1. The Problem: Hot Keys are Vulnerable
DeFi protocols, automated market makers, cross-chain bridges, and oracle networks run automated backend processes. These processes hold **hot Ed25519 private keys** in memory on cloud virtual machines.

If a server is compromised, an attacker dumps the RAM and steals the private key. With the private key, the attacker can drain vaults, alter oracle prices, or execute rogue governance proposals.

### 2. The Solution: Hardware-Isolated Keys
Instead of storing keys in standard server memory, Solana Confidential Compute runs workload binaries inside a **Trusted Execution Environment (TEE)**:
- **Encrypted Memory:** Memory pages are hardware-encrypted by the CPU with ephemeral keys unknown to the host operating system or hypervisor.
- **Enclave Isolation:** Neither cloud provider administrators nor malicious root processes can inspect CPU registers or memory contents.
- **In-Enclave Key Generation:** The Ed25519 workload key is generated directly inside enclave RAM. The private key never leaves the enclave.

```
+-------------------------------------------------------+
| Cloud Host (Untrusted)                                |
|   Hypervisor, OS, Root Admin                          |
|                                                       |
|   +-----------------------------------------------+   |
|   | Enclave (Hardware Encrypted & Measured)       |   |
|   |                                               |   |
|   |   1. Generate Ed25519 Private Key in RAM      |   |
|   |   2. Compute Code Measurement (SHA-384)       |   |
|   |   3. Ask SNP, Nitro, or Intel TDX for a quote |   |
|   |                                               |   |
|   |   Output: Attestation Report                  |   |
|   +-----------------------------------------------+   |
+-------------------------------------------------------+
                           |
                           v
        Solana Cluster: solana-confidential-compute-verifier checks report
```

### 3. How Solana Verifies Silicon: Attestation
How does a Solana program know a transaction came from an uncompromised enclave?

1. **Hardware Measurement:** When an enclave boots, the hardware security processor hashes its initial code and memory state (`SHA-384`). This hash is the **measurement**.
2. **Attestation Report:** The enclave requests a signed hardware report from the processor:
   - On **AMD SEV-SNP**, the Platform Security Processor (PSP) signs the report using the Versioned Chip Endorsement Key (VCEK).
   - On **AWS Nitro Enclaves**, the Nitro Security Module (`/dev/nsm`) generates a COSE Sign1 document signed by the AWS Nitro Root CA.
   - On **Intel TDX**, the quoting stack returns a DCAP quote. The quote is a certificate from the chip. It names the code in the vault and carries 64 bytes the guest chose.
3. **Cryptographic Binding:** The report includes a user-programmable field (`REPORT_DATA` or `user_data`). Solana Confidential Compute places the **Ed25519 public key** and a fresh **Solana slot hash** inside this field. Intel TDX hashes those values into `REPORTDATA` with a fixed domain string. The [Intel TDX](/backends/intel-tdx/) page shows the formula.
4. **On-Chain Verification:** The Solana program `solana-confidential-compute-verifier` checks:
   - Hardware signature and certificate chain. For Intel TDX this is two ECDSA P-256 signatures, checked by Solana's native `secp256r1` program. The two instructions cost about 75,000 compute units. The path uses no zero-knowledge proof and no zkVM.
   - Enclave measurement against the source-specific on-chain `BackendPolicy`.
   - Nonce slot freshness against Solana's `SlotHashes` sysvar (≤ 150 slots).
5. **Consumer CPI:** A consumer program (your smart contract) calls `solana-confidential-compute-cpi` to verify that the signer is attested before processing state updates.

---

## Core Concepts Glossary

### Trusted Execution Environment (TEE)
An isolated CPU execution environment that provides memory encryption and hardware-level isolation from host administrators and hypervisors.

### Enclave
An isolated virtual partition running inside a TEE. Supported roots in Solana Confidential Compute include AMD SEV-SNP confidential VMs, AWS Nitro Enclaves, and Intel TDX Trust Domains. A Trust Domain is the Intel name for the same idea: a vault whose memory the host cannot read.

### Measurement
A SHA-384 digest representing the exact initial code, kernel, and filesystem loaded into the enclave. If a single byte of code changes, the measurement changes. Intel TDX splits the idea into two fields. `MR_TD` (Measurement of the Trust Domain) is the build-time hash of the image at launch. An `RTMR` (Runtime Measurement Register) is a boot log the guest extends while it starts. Details: [Intel TDX](/backends/intel-tdx/).

### Attestation
The process whereby hardware creates a cryptographically signed statement proving that a specific workload runs inside authentic, unmodified silicon.

### REPORT_DATA / user_data
A programmable byte array inside the hardware report. Used to bind an ephemeral Ed25519 public key and fresh slot nonce to the attestation proof.

### Policy Registry
`BackendPolicy` specifies authorized measurements per backend. `PolicyRegistry` retains governance authority and AMD minimum firmware security versions; its legacy measurement list is compatibility-only.

### Nonce Freshness
Verification that an attestation was generated within the last 150 Solana slots (~60 seconds), blocking replay attacks.

### Mode A (Stateful Session)
Registers an attested Ed25519 key on-chain for 216,000 slots (~24 hours). Subsequent transactions sign with native Ed25519 and bypass hardware verification costs. Ideal for high-frequency oracles and quotes.

### Mode B (Stateless Atomic)
Single-transaction attestation. The verification instruction and the consumer execution instruction execute together. Binds an exact action hash and consumer program ID. Ideal for discrete, one-shot settlement actions (NAV marks, rebalances, liquidations).

### Instruction Introspection
The mechanism whereby a consumer program reads preceding instructions inside the current transaction via `sysvar::instructions` to confirm successful attestation verification.
