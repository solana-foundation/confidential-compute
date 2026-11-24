# AMD SEV-SNP: Architecture, Attestation, and Certificate Hierarchy

Category: Architecture
Last reviewed: 2026-09-19
Status: VERIFIED
Verified against: AMD Publication #56860 (Rev 3.00), AMD SEV-SNP Firmware ABI Specification, Google Cloud Confidential VM Docs
Sources: [AMD SEV-SNP ABI Spec (Pub 56860)](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/56860.pdf), [AMD KDS Specification](https://www.amd.com/en/developer/sev.html), [Google Confidential VM](https://cloud.google.com/confidential-computing)

---

## 1. Executive Summary

AMD Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP) provides hardware memory encryption and memory integrity protection for virtual machines running on AMD EPYC processors (Zen 3 Milan, Zen 4 Genoa, Zen 5 Turin). SEV-SNP protects guest memory against hypervisor attacks, memory aliasing, and memory replaying. The AMD Platform Security Processor (PSP) generates an immutable, 1,184-byte attestation report signed with ECDSA P-384 that cryptographically binds an ephemeral workload public key to an exact code measurement.

---

## 2. Core Silicon Architecture & RMP

```
+------------------------------------------------------------------------+
|                             AMD EPYC CPU Die                           |
|                                                                        |
|  +-----------------------------------+   +--------------------------+  |
|  |       AMD Secure Processor        |   |   Memory Encryption      |  |
|  |            (ASP / PSP)            |   |         Engine           |  |
|  | - Dedicated 32-bit ARM Cortex-A5  |   | - AES-128 / AES-256      |  |
|  | - Holds Chip Endorsement Keys     |   | - Unique AES key per VM  |  |
|  | - Generates Attestation Reports   |   +--------------------------+  |
|  +-----------------------------------+                                  |
|                                                                        |
|  +------------------------------------------------------------------+  |
|  |                Reverse Map Table (RMP) Hardware Engine           |  |
|  | - Hardware-enforced page ownership table.                        |  |
|  | - Enforces strict 1:1 Guest Physical Address to Host mapping.   |  |
|  | - Prevents hypervisor memory aliasing, remapping, and injection.  |  |
|  +------------------------------------------------------------------+  |
+------------------------------------------------------------------------+
```

### Protection Generations:
1. **SEV (Gen 1):** Memory encryption only. Hypervisor could alter ciphertext or read CPU registers during VM exits.
2. **SEV-ES (Gen 2):** Encrypted State. Encrypts all CPU registers during VM exits. Hypervisor could still alter memory mapping.
3. **SEV-SNP (Gen 3):** Secure Nested Paging. Introduces the **Reverse Map Table (RMP)**. Hardware enforces that each system physical page is owned by exactly one guest context. Hypervisor memory replay or remap attacks immediately trigger a hardware exception.

---

## 3. AMD Certificate Hierarchy & Attestation Chain

AMD establishes silicon trust through an on-die cryptographic hierarchy:

```
[ AMD Root Key (ARK) ]  (Self-signed root CA for product line: Milan/Genoa/Turin)
          |
          | Signs with ECDSA P-384 (SHA-384)
          v
[ AMD SEV-SNP Signing Key (ASK) ]  (Intermediate CA certificate)
          |
          | Signs with ECDSA P-384 (SHA-384)
          v
[ Versioned Chip Endorsement Key (VCEK) ]  (Leaf cert unique to physical silicon)
          |
          | Signs with ECDSA P-384 (SHA-384)
          v
[ SEV-SNP Attestation Report ]  (1,184-byte hardware payload with REPORT_DATA)
```

### 3.1 AMD Key Distribution Service (KDS)
- Host administrators and cloud operators fetch VCEK certificates via AMD KDS:
  `https://kdsintf.amd.com/vcek/v1/{product}/{chip_id}?blSPL={bootloader}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={microcode}`
- The VCEK certificate embeds:
  - Custom X.509 v3 extensions for `chip_id` (64 bytes).
  - TCB version parameters matching the physical processor's firmware patch level.

### 3.2 VCEK vs. VLEK (Hyperscaler / Google Cloud Deployments)
- **VCEK:** Direct chip certificate fetched from AMD KDS. Contains the true physical `chip_id`.
- **VLEK (Versioned Loaded Endorsement Key):** Alternative endorsement model used by hyperscalers (including Google Cloud GCE). Google operates an internal VLEK service to issue endorsement certificates without querying external AMD servers for every instance.
- **Critical Corner Case (Multi-Tenant Isolation):**
  - In GCE Confidential VMs, `chip_id` may be all zeros to prevent cross-tenant hardware tracking.
  - *PDA Collision Hole:* Deriving `[b"vcek_v2", sha256(chip_id), tcb]` would map all cloud instances on all servers to the same PDA!
  - *Solana Confidential Compute Solution:* When `chip_id` is all zeros, the `VcekAccount` PDA is derived using `sha256(vcek_cert_public_key)`:
    `[b"vcek_v2", &sha256(vcek_public_key_xy)[..], &tcb.to_le_bytes()]` (versioned seed since #253)..
    Because every host VLEK certificate has a distinct P-384 public key, this guarantees 100% collision-free derivation across all cloud tenants.

---

## 4. Canonical 1,184-Byte Report Layout (AMD Publication #56860)

The AMD SEV-SNP attestation report is an exact 1,184-byte binary structure:

| Byte Offset | Size | Field Name | Description & Protocol Significance |
| :--- | :--- | :--- | :--- |
| `0x000..0x004` | 4 B | `version` | Structure version. Must be in range `2..=5` (version 1 is rejected). |
| `0x004..0x008` | 4 B | `guest_svn` | Guest Security Version Number. |
| `0x008..0x010` | 8 B | `policy` | Guest policy bitmask: **Bit 19 (DEBUG) must be 0**; **Bit 18 (MIGRATE_MA) must be 0**; **Bit 17 (`RESERVED_MUST_BE_ONE`) must be 1**; **Bit 16 (SMT) is allowed**. |
| `0x010..0x020` | 16 B | `family_id` | Workload family identifier. |
| `0x020..0x030` | 16 B | `image_id` | Workload image identifier. |
| `0x030..0x034` | 4 B | `vmpl` | Virtual Machine Privilege Level (0 = highest privilege). |
| `0x034..0x038` | 4 B | `signature_algo` | Signature algorithm: `1` = ECDSA P-384 with SHA-384. |
| `0x038..0x040` | 8 B | `current_tcb` | Current microcode / PSP firmware version vector. |
| `0x040..0x048` | 8 B | `platform_info` | SMT enabled, TSME enabled, etc. |
| `0x048..0x04C` | 4 B | `flags` | Author key enabled, masking flags. |
| `0x04C..0x050` | 4 B | `reserved0` | Zero padding. |
| `0x050..0x090` | 64 B | `report_data` | **User Data Scratchpad:** `[0..32]` = Ed25519 Pubkey, `[32..64]` = Solana Blockhash Nonce. |
| `0x090..0x0C0` | 48 B | `measurement` | **SHA-384 Launch Digest:** Cryptographic measurement of the guest initial memory image. |
| `0x0C0..0x0E0` | 32 B | `host_data` | Optional data provided by the untrusted hypervisor (ignored for authorization). |
| `0x0E0..0x110` | 48 B | `id_key_digest` | SHA-384 digest of the ID key (if used). |
| `0x110..0x140` | 48 B | `author_key_digest` | SHA-384 digest of author key (if used). |
| `0x140..0x160` | 32 B | `report_id` | Unique hardware-generated report identifier. |
| `0x160..0x180` | 32 B | `report_id_ma` | Migration agent report identifier. |
| `0x180..0x188` | 8 B | `reported_tcb` | TCB level at which this attestation was generated (`[0]=boot_loader, [1]=tee, [6]=snp, [7]=microcode`). |
| `0x188..0x1A0` | 24 B | `reserved1` | Zero padding. |
| `0x1A0..0x1E0` | 64 B | `chip_id` | 64-byte silicon identifier of the AMD CPU (all zeros in hyperscaler VLEK mode). |
| `0x1E0..0x1E8` | 8 B | `committed_tcb` | Committed TCB level. |
| `0x1E8..0x1EB` | 3 B | `build/minor/major` | Build numbers for PSP firmware. |
| `0x1EB..0x2A0` | 181 B | `reserved2` | Zero padding up to signature block. |
| **0x000..0x2A0** | **672 B** | **Signed Body** | **Exact byte slice hashed via SHA-384 for signature.** |
| `0x2A0..0x2E8` | 72 B | `signature_r` | **ECDSA $r$ component (Little-Endian):** bytes `0..48` is scalar $r$; bytes `48..72` must be zero. |
| `0x2E8..0x330` | 72 B | `signature_s` | **ECDSA $s$ component (Little-Endian):** bytes `0..48` is scalar $s$; bytes `48..72` must be zero. |
| `0x330..0x4A0` | 368 B | `reserved_sig` | Reserved signature block padding (total report = 1,184 B). |

---

## 5. Google Cloud Confidential Space Architecture

Google Cloud Confidential Space deploys AMD SEV-SNP inside hardened Container-Optimized OS (COS) instances:

1. **Attestation Flow:**
   - The workload container executes inside the GCE Confidential VM.
   - The workload sends an OIDC token request with audience and nonces to `http://localhost/v1/token` over the launcher Unix socket `/run/container_launcher/teeserver.sock`.
   - The launcher collects evidence and obtains a signed attestation JWT from Google Cloud Attestation, as specified by the [launcher API](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources). GCE metadata instance identity tokens are a different product and do not implement this custom-nonce contract.
2. **JWT Claims:**
   - `sub`: Service account / workload identity.
   - `aud`: Audience (set to Solana Confidential Compute program / operator public key).
   - `swname`, `swversion`: Hash of container image.
   - `secboot`: Boolean verifying UEFI Secure Boot status.
   - `eat_profile`: Attestation profile.
3. **Dual Verification Option:**
   - Direct AMD hardware verification (P-384 VCEK chain on-chain).
   - Google OIDC JWT verification using Google's public JWKS.

---

## 6. Critical Hardware Corner Cases & Vulnerabilities

1. **The Enclave Debug Hole (Policy Bit 19):**
   - If a host boots an SEV-SNP guest with `policy` bit 19 set, the hypervisor can inject commands or inspect CPU registers for debugging.
   - *Requirement:* Enforce `@spec SCC-SEC-001`: assert `(policy & (1 << 19)) == 0`, `(policy & (1 << 18)) == 0`, `(policy & (1 << 17)) != 0`, and `vmpl == 0`. Bit 16 (SMT) is allowed.
2. **TCB Rollback Attacks:**
   - Attackers might run workloads on unpatched hardware vulnerable to microcode exploits (e.g. CacheWarp).
   - *Requirement:* Component-wise enforcement of `reported_tcb >= min_tcb_version` on-chain.
3. **Hypervisor Packet Dropping & Time Skew:**
   - The hypervisor can artificially delay outgoing transactions to force slot blockhashes past the 150-slot TTL.
   - *Mitigation:* The in-enclave sidecar must fetch fresh blockhashes directly before report generation and pipeline submission via private RPCs.
