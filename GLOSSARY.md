# Solana Confidential Compute Glossary

Key terms and definitions for hardware-attested verifiable compute on Solana.

---

## Hardware and Confidential Computing

### Trusted Execution Environment (TEE)
An isolated hardware compute environment. CPU hardware encrypts memory and registers. The host operating system, hypervisor, and hardware administrators cannot inspect or alter enclave memory.

### Enclave
An isolated virtual machine or partition running inside a TEE. Memory encryption keys are held in CPU hardware and are never exposed to the host system.

### AMD SEV-SNP
Secure Encrypted Virtualization with Secure Nested Paging. AMD EPYC processor technology protecting guest VMs from hypervisor tampering, memory alteration, and replay attacks. Enclave communication passes through `/dev/sev-guest`.

### AWS Nitro Enclaves
Isolated compute environments running alongside AWS EC2 instances. Enclaves have no persistent storage, no interactive access, and no external networking. Communication occurs exclusively over local virtual sockets (`AF_VSOCK`, `/dev/nsm`).

### Intel TDX
Intel Trust Domain Extensions. CPU support for hardware-isolated virtual machines called Trust Domains. Guest memory is encrypted with keys that stay inside the processor. The host operating system and the hypervisor cannot read that memory.

### Trust Domain (TD)
The Intel TDX guest. It is a virtual machine whose memory and registers the CPU isolates from the host. Solana Confidential Compute treats one Trust Domain as one enclave. Backend policy source 5 admits its measurements.

### DCAP Quote
A Data Center Attestation Primitives quote. This is the remotely checkable form of a Trust Domain report. Intel's Quoting Enclave signs it with an attestation key. The platform PCK key certifies that attestation key. Solana Confidential Compute accepts a version-4 quote whose attestation key type is ECDSA P-256. Solana checks both signatures with the native `secp256r1` precompile. A local TDREPORT from `/dev/tdx-guest` is not a DCAP quote and cannot be checked remotely.

### Quoting Enclave (QE)
Intel's enclave that turns a local Trust Domain report into a DCAP quote. Its own report is signed by the platform Provisioning Certification Key (PCK). Solana Confidential Compute allowlists the PCK public key and a digest of the QE identity (`MRSIGNER`, product id, and security version). A debug QE is rejected.

### MR_TD
The 48-byte measurement of the Trust Domain's initial contents. It is the TDX field `MRTD`. It names the firmware and the image that were loaded at boot. Governance pins it inside the source-5 platform digest, together with the launch configuration (`MRCONFIGID`).

### RTMR[0..3]
Four 48-byte runtime measurement registers in the Trust Domain. Each register extends as the guest boots and runs. `RTMR0`, `RTMR1`, and `RTMR2` are part of the allowlisted platform digest. `RTMR3` changes on every boot (instance id and fresh GPU-attestation events on a dstack guest), so it is left out of that digest. The signer record still stores a hash of all four registers for off-chain inspection.

### Platform Security Processor (PSP) / AMD Secure Processor (ASP)
Dedicated ARM core embedded in AMD EPYC processors. Executes security firmware, manages memory encryption keys, and signs SEV-SNP attestation reports.

### Nitro Security Module (NSM)
Virtual cryptographic hardware device inside AWS Nitro Enclaves (`/dev/nsm`). Generates CBOR/COSE signed attestation documents backed by AWS Nitro Root CA G1.

### Trusted Computing Base (TCB)
The minimal set of hardware, firmware, and boot software required to enforce security guarantees. Any vulnerability within the TCB breaks the security of the enclave.

---

## Cryptography and Attestation

### Attestation
A cryptographic process where hardware generates a signed report proving that a specific workload runs inside genuine, uncompromised silicon.

### Attestation Report / Document
A structured payload signed by the hardware security processor:
- **AMD SEV-SNP:** 1,184-byte report signed with ECDSA P-384 by the VCEK.
- **AWS Nitro Enclaves:** COSE Sign1 document containing CBOR payload signed with ECDSA P-384 by AWS Nitro Root CA G1.

### Measurement
A SHA-384 cryptographic digest of the initial code, kernel, and memory state loaded into the enclave at boot:
- **AMD SEV-SNP:** 48-byte `measurement` field in the report.
- **AWS Nitro Enclaves:** `PCR0` register in the attestation document.

### Versioned Chip Endorsement Key (VCEK)
An ECDSA P-384 private key unique to an individual AMD EPYC processor and its current firmware TCB level. Endorsed by AMD's certificate authority.

### AMD Root Key (ARK) and AMD SEV Signing Key (ASK)
The AMD certificate authority chain for SEV-SNP:
- **ARK:** Root public key self-signed with RSA-4096 RSASSA-PSS SHA-384.
- **ASK:** Intermediate certificate signed by ARK with RSA-4096 RSASSA-PSS SHA-384.
- **VCEK:** Leaf certificate signed by ASK, containing the processor's P-384 public key.

### Platform Configuration Registers (PCR)
Cryptographic registers inside AWS Nitro Enclaves recording sha384 digests:
- **PCR0:** Enclave image file (EIF).
- **PCR1:** Kernel and RAM disk.
- **PCR2:** Application software.
- **PCR8:** Enclave image file signing certificate.

### REPORT_DATA / user_data
A user-controllable byte field in the attestation payload (64 bytes in AMD SEV-SNP; up to 1,024 bytes in Nitro):
- In Solana Confidential Compute, this field binds the enclave's generated Ed25519 workload public key and fresh Solana slot hash or action commitment.

### COSE Sign1
CBOR Object Signing and Encryption standard (RFC 8152). Format used by AWS Nitro Enclaves to sign attestation documents.

---

## Solana and Confidential Compute Architecture

### Policy Registry
An on-chain account (`PolicyRegistry`) holding the registry authority, monotonic AMD minimum TCB floors, and legacy global measurement fields retained only for state/wire compatibility. Source-specific `BackendPolicy` accounts control measurement admission (AMD=1, Nitro=2, GCP=3, NVIDIA=4 reserved, Intel TDX=5); clearing the global measurement list does not halt admission. The legacy AMD P-384 root field has no supported vendor-root meaning in the pinned Milan RSA production path, and `rotate_root_cert` is refused. See the [current backend governance contract](docs/intent/confidential-compute-verifier-specs.md#backend-measurement-governance) and [trust model](SECURITY.md#administrative-authorities-and-trust-roots).

### Registry Authority
The pubkey in `PolicyRegistry.authority`. Governance writes require this account to be a signer. It may be a keypair or a governance PDA signing through CPI; Solana Confidential Compute itself enforces no multisig threshold or timelock.

### Upgrade Authority
The authority recorded in the Solana upgradeable loader's ProgramData account. It can replace verifier code, including pinned Nitro/Milan roots and registry authorization rules. Transferring it does not transfer registry authority. See the [trust model](SECURITY.md#administrative-authorities-and-trust-roots).

### Nonce Freshness
Verification that an attestation was generated recently. Solana Confidential Compute validates that `nonce_slot` matches an entry in Solana's `sysvar::slot_hashes` table within 150 slots (~60 seconds).

### Used Nonce Account
A `UsedNonceAccount` PDA initialized during attestation. Prevents replay attacks by marking a nonce slot or action hash as spent. New records are 49 bytes and store the signing payer as `refund_pubkey`; after more than 150 slots, `close_stale_nonce` may close one and refund its rent to that payer. Legacy 17-byte records have no refund field and stay permanent. Both formats return `NonceAlreadyUsed` on replay.

### Mode A (Stateful Session Caching)
High-frequency operational mode. The enclave attests once and records an `AttestedSignerAccount` PDA with a 24-hour TTL (216,000 slots). Subsequent transactions use standard Ed25519 signatures and skip hardware report parsing on-chain.

### Mode B (Stateless Atomic Attestation)
One-shot operational mode. The attestation verification instruction and the consumer execution instruction execute inside the same transaction. The attestation binds an exact action hash and consumer program ID.

### Instruction Introspection
Solana verification pattern using `sysvar::instructions`. A consumer program reads preceding instructions in the transaction to guarantee that `solana-confidential-compute-verifier` executed and succeeded.

### Consumer Program
A downstream Solana program (e.g. DeFi exchange, oracle, or tokenized vault) that calls `solana-confidential-compute-cpi` to verify that an incoming instruction or session key originated from an attested enclave.
