# AWS Nitro Enclaves: Architecture, Attestation, and Cryptographic Format

Category: Architecture
Last reviewed: 2026-09-17
Status: VERIFIED
Verified against: AWS Nitro Enclaves User Guide, AWS Cryptographic Specifications, RFC 8152 / RFC 9052 (COSE)
Sources: [AWS Nitro Enclaves Docs](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html), [AWS Nitro Attestation Document Spec](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)

---

## 1. Executive Summary

AWS Nitro Enclaves provide isolated, hardened, and highly constrained virtualized compute environments on Amazon EC2. Unlike AMD SEV-SNP (which encrypts full VMs with network access), a Nitro Enclave has **no persistent storage, no external network interface, and no interactive operator access**. All communication with the external world occurs strictly through a virtual socket (`vsock`) connected to the parent EC2 instance. Attestations are emitted as CBOR-encoded **COSE Sign1** documents cryptographically signed by the AWS Nitro Root CA using ECDSA P-384.

---

## 2. Silicon & Hypervisor Architecture

```
+-------------------------------------------------------------------------+
|                           Physical EC2 Server                           |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                     AWS Nitro PCIe System Controller               |  |
|  |  - Dedicated hardware ASIC managing virtualization & security.    |  |
|  |  - Carves off dedicated CPU cores and RAM from parent instance.   |  |
|  |  - Generates and cryptographically signs attestation documents.   |  |
|  +-------------------------------------------------------------------+  |
|                                                                         |
|  +-----------------------------+     +-------------------------------+  |
|  |     Parent EC2 Instance     |     |      AWS Nitro Enclave        |  |
|  | - Standard Linux OS / IP Net |     | - No persistent disk          |  |
|  | - User SSH / Admin access   |     | - No Ethernet / No IP stack   |  |
|  | - Untrusted environment     |     | - Workload code in RAM only   |  |
|  |                             |     | - Holds Ed25519 signing key   |  |
|  +--------------+--------------+     +---------------+---------------+  |
|                 |                                    |                  |
|                 +=========== Local Vsock ============+                  |
|                           (AF_VSOCK Channel)                            |
+-------------------------------------------------------------------------+
```

### Key Differences from AMD SEV-SNP:
1. **Network Isolation:** Nitro Enclaves have zero external IP access. An in-enclave trading engine cannot call Solana RPC directly; it must route transactions through an untrusted vsock proxy running on the parent EC2 instance.
2. **Ephemeral Memory:** Enclave memory is carved out of the parent instance. If the parent EC2 instance reboots or terminates, the enclave memory vanishes instantly.
3. **No Interactive Admin:** Neither root users on the parent instance nor AWS engineers can attach debuggers, SSH, or inspect memory inside the enclave.
4. **No On-Die Memory Encryption:** Unlike AMD SEV-SNP (which uses dedicated hardware AES-128/256 engines on the memory controller), Nitro does NOT encrypt enclave memory in DRAM. Nitro relies on PCIe ASIC core/RAM partitioning. Physical DRAM bus tapping or cold-boot attacks against physical motherboards are out-of-scope for Nitro's threat model.

---

## 3. Platform Configuration Registers (PCRs)

Nitro Enclaves measure system integrity using sequential Platform Configuration Registers (PCRs) hashed with SHA-384:

| PCR Index | Measured Artifact | Purpose & Validation Rule |
| :--- | :--- | :--- |
| **`PCR0`** | Enclave Image Format (EIF) measurement (kernel + ramdisk + app). | Primary measurement anchor. Verifies the exact software binary. Must match allowlist. Cannot be all zeros. |
| **`PCR1`** | Linux kernel bootstrap and command line. | Ensures boot parameters and kernel image have not been modified. |
| **`PCR2`** | Enclave application user data and dependencies. | Application-specific runtime measurement. |
| **`PCR3`** | Parent EC2 instance IAM role ARN. | Proves which AWS cloud IAM role spawned the enclave. |
| **`PCR4`** | Parent EC2 instance ID (`i-0123456789abcdef0`). | Validates physical/virtual parent instance identity. |
| **`PCR8`** | Hash of EIF signing certificate (or all zeros if unsigned). | Enforces that only EIFs signed by an authorized engineering keypair execute. |

---

## 4. Attestation Document: COSE Sign1 (CBOR)

When an enclave queries the Nitro Security Module character device (`/dev/nsm`) via `ioctl` for an attestation, the Nitro hypervisor returns a **COSE Sign1** document (RFC 8152 / RFC 9052):

```
COSE_Sign1 = [
    protected_headers: {
        1 (alg): -35 (ES384 / ECDSA P-384 with SHA-384)
    },
    unprotected_headers: {},
    payload: AttestationDocument (CBOR-encoded map),
    signature: bstr (96-byte P-384 signature [r || s])
]
```

### 4.1 Attestation Payload Map Layout
The payload is a CBOR map containing:
- `module_id`: String identifying the Nitro enclave module.
- `timestamp`: UTC millisecond timestamp of document creation.
- `digest`: String indicating hash algorithm (`"SHA384"`).
- `pcrs`: Map of `u8 -> bstr` containing `PCR0`, `PCR1`, `PCR2`, `PCR8` (each 48 bytes).
- `certificate`: DER-encoded X.509 leaf certificate issued by AWS Nitro CA.
- `cabundle`: Array of DER-encoded intermediate certificates chaining to the AWS Nitro Root CA.
- `user_data`: Arbitrary user-supplied byte slice (up to 1,024 bytes). **Solana Confidential Compute embeds the workload Ed25519 public key here.**
- `nonce`: Arbitrary user-supplied byte slice (up to 1,024 bytes). **Solana Confidential Compute embeds the fresh Solana slot blockhash here.**

---

## 5. Verification Path on Solana

To verify a Nitro attestation inside a Solana smart contract:

```
[ Nitro Attestation COSE Payload ]
                |
                v
1. Parse COSE Sign1 structure (zero-copy CBOR decoder)
                |
2. Verify AWS Certificate Chain (Leaf -> Intermediate -> Trusted AWS Root CA)
                |
3. Verify COSE Signature using Leaf Certificate Public Key (P-384 ECDSA)
                |
4. Validate `nonce` against Solana `SlotHashes` sysvar (age <= 150 slots)
                |
5. Assert `PCR0` matches the Nitro `BackendPolicy` allowlist (source 2)
                |
6. Register `user_data` (Ed25519 Pubkey) into `AttestedSignerAccount` PDA
```

Measurement admission uses the backend policy, not the legacy global measurement list. `PolicyRegistry` supplies governance authority and AMD TCB floors; those AMD floors are not Nitro PCR policy. See the [current governance contract](../intent/confidential-compute-verifier-specs.md#backend-measurement-governance).

### Compute Budget Considerations:
- Like AMD SEV-SNP, the AWS certificate chain contains 3 X.509 certificates and 1 COSE document signature.
- Verifying the entire chain in one transaction exceeds 1.4M CUs.
- **Solution:** Apply the same 2-stage cached architecture:
  - **Stage 1:** Verify AWS Intermediate CA once and cache on-chain.
  - **Stage 2:** Verify leaf certificate, COSE signature, and register the workload public key.

---

## 6. Critical Security Boundaries & Corner Cases

1. **Vsock Proxy Tampering (Man-in-the-Middle):**
   - The vsock proxy running on the parent EC2 instance is untrusted.
   - The parent OS can attempt to modify Solana transactions emitted by the enclave.
   - *Mitigation:* The enclave generates its own Solana keypair, builds the entire transaction payload internally, signs it with its Ed25519 key, and passes the finalized wire transaction across vsock. The parent proxy can only broadcast the signed bytes; it cannot alter the instruction data without invalidating the signature.
2. **Deterministic Build Reproducibility:**
   - `PCR0` changes if a single byte in the Docker image changes (e.g. timestamp differences in build tools).
   - *Mitigation:* Docker builds must use deterministic timestamps (`SOURCE_DATE_EPOCH`) to ensure reproducible PCR0 hashes.
3. **No Internal Clock Synchronization:**
   - The enclave does not possess a trusted hardware RTC. It receives time from the parent hypervisor.
   - *Mitigation:* Never trust the `timestamp` field in the attestation document for blockchain expiry; rely exclusively on the embedded Solana slot blockhash (`nonce`).
