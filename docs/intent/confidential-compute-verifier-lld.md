# Solana Confidential Compute Verifier: Low-Level Design (LLD)

## 1. On-Chain State Model & Anchor-Compatible Discriminators

All state accounts prepend standard 8-byte Anchor discriminators: `sha256("account:<StructName>")[..8]`.

### 1.1 `AttestedSignerAccount` PDA
- **Seeds:** `[b"attested_signer_v2", signer_pubkey.as_ref()]`
- **Owner:** `solana_confidential_compute_verifier::ID`
- **Discriminator:** `[43, 255, 114, 40, 233, 28, 127, 238]` (`sha256("account:AttestedSignerAccountV2")[..8]`)
- **Serialized field order** (Borsh; descriptive layout, not a native Rust ABI; source: `programs/solana-confidential-compute-verifier/src/state.rs` and `crates/solana-confidential-compute-cpi/src/anchor.rs`):
  ```rust
  pub struct AttestedSignerAccount {
      pub discriminator: [u8; 8],     // Offset 0x00..0x08
      pub signer_pubkey: [u8; 32],     // Offset 0x08..0x28 (Ed25519)
      pub enclave_type: u8,            // Offset 0x28..0x29 (1 = AMD SEV-SNP, 2 = AWS Nitro)
      pub measurement: [u8; 48],       // Offset 0x29..0x59 (SHA-384 launch digest)
      pub chip_id_hash: [u8; 32],      // Offset 0x59..0x79 (SHA-256 of 64-byte AMD Chip ID)
      pub tcb_version: u64,            // Offset 0x79..0x81 (Reported TCB)
      pub registered_slot: u64,        // Offset 0x81..0x89
      pub expires_slot: u64,           // Offset 0x89..0x91 (registered_slot + TTL)
      pub bump: u8,                    // Offset 0x91..0x92
      pub expires_unix_timestamp: i64, // Offset 0x92..0x9A (exclusive deadline)
  }
  ```
- **Total Size:** 154 bytes.
- **Account Lifecycle & Re-Attestation Guard:**
  - Initial creation MUST allocate space via `system_instruction::create_account` funded by `payer`.
  - Re-attestation over an existing account is permitted ONLY when `current_slot > expires_slot` (expired session renewal) OR when the existing `signer_pubkey` matches and a fresh, unused slot blockhash nonce is verified.
  - Overwriting an active unexpired signer with a different pubkey is rejected with `ProgramError::AccountAlreadyInitialized`.

### 1.2 `VcekAccount` PDA (Cached Physical Chip Key)
- **Seeds:** `[b"vcek_v2", sha256(chip_id).as_ref(), tcb_version.to_le_bytes().as_ref()]` (`VcekAccount::SEED`; versioned in #253, legacy `b"vcek"` caches are not read)
  - *Seed Length Constraint:* AMD `chip_id` is 64 bytes. Solana runtime enforces `MAX_SEED_LEN = 32`. Seeds MUST use the 32-byte SHA-256 hash of `chip_id`.
  - *VLEK Derivation Fallback:* If `key_sel == 1` or `chip_id` is all zeros (`[0u8; 64]`), seeds use `sha256(vcek_public_key)`.
- **Owner:** `solana_confidential_compute_verifier::ID`
- **Discriminator:** `[180, 227, 118, 227, 197, 175, 220, 193]` (`sha256("account:VcekAccountV2")[..8]`)
- **Memory Layout:**
  ```rust
  pub struct VcekAccount {
      pub discriminator: [u8; 8],     // Offset 0x00..0x08
      pub chip_id_hash: [u8; 32],      // Offset 0x08..0x28 (SHA-256 of 64-byte chip ID or pubkey)
      pub tcb_version: u64,            // Offset 0x28..0x30
      pub public_key_xy: [u8; 96],     // Offset 0x30..0x90 (P-384 uncompressed public key)
      pub registered_slot: u64,        // Offset 0x90..0x98
      pub bump: u8,                    // Offset 0x98..0x99
      pub trust_profile: [u8; 32],     // Offset 0x99..0xB9 (SHA-256 of pinned Milan RSA ARK modulus)
      pub valid_until_unix: u64,       // Offset 0xB9..0xC1 (exclusive certificate deadline)
      pub is_revoked: bool,            // Offset 0xC1..0xC2
  }
  ```
- **Total Size:** 194 bytes.
- **Immutability and revocation:** Key material remains immutable within each authenticated identity/TCB cache. Only expired, nonrevoked caches can be revalidated. Governed `revoke_vcek` also retains a permanent `[b"amd_revocation", identity_hash]` PDA without a TCB seed, checked by registration and report admission. The readonly canonical identity account is mandatory even when absent; omission fails closed. See the [current account contract](../../programs/solana-confidential-compute-verifier/README.md#amd-identity-revocation-across-tcb-caches). VCEK identity is SHA-256(chip ID); VLEK identity is SHA-256(endorsement XY), not a stable physical-chip identity across different VLEK keys.

### 1.3 `PolicyRegistry` PDA (Governance Allowlist & Roots)

Registry writes check a matching signer account; multisig thresholds and timelocks, if used, are enforced by an external governance program. The loader upgrade authority controls code and pinned roots separately. See the [trust model](../../SECURITY.md#administrative-authorities-and-trust-roots).

- **Seeds:** `[b"policy_registry"]`
- **Owner:** `solana_confidential_compute_verifier::ID`
- **Discriminator:** `[175, 179, 180, 44, 5, 161, 62, 240]` (`sha256("account:PolicyRegistry")[..8]`)
- **Memory Layout:**
  ```rust
  pub struct PolicyRegistry {
      pub discriminator: [u8; 8],      // Offset 0x000..0x008
      pub authority: [u8; 32],          // Offset 0x008..0x028 (Authorized signer pubkey: keypair or governance PDA)
      pub ark_pubkey_xy: [u8; 96],      // Offset 0x028..0x088 (Trusted AMD Root Key P-384)
      pub min_tcb_boot_loader: u8,      // Offset 0x088..0x089
      pub min_tcb_tee: u8,              // Offset 0x089..0x08A
      pub min_tcb_snp: u8,              // Offset 0x08A..0x08B
      pub min_tcb_microcode: u8,        // Offset 0x08B..0x08C
      pub measurement_count: u32,       // Offset 0x08C..0x090
      pub measurements: [[u8; 48]; 8],  // Offset 0x090..0x210 (Allowlisted SHA-384 digests, 384 B)
      pub bump: u8,                     // Offset 0x210..0x211
  }
  ```
- **Total Size:** 529 bytes (`8 + 32 + 96 + 4 + 4 + 384 + 1 = 529`).
- **Initialization Guard:** Calling `init_policy_registry` when discriminator matches or data is non-empty MUST return `ProgramError::AccountAlreadyInitialized`.

### 1.4 `UsedNonceAccount` PDA (Anti-Replay Record)
- **Seeds:** `[b"nonce", signer_pubkey.as_ref(), nonce_blockhash.as_ref()]`
  - *Multi-Tenant Isolation:* Deriving with `signer_pubkey` prevents multi-tenant collisions when distinct enclaves register on the same blockhash.
- **Owner:** `solana_confidential_compute_verifier::ID`
- **Discriminator:** `[138, 99, 69, 17, 9, 177, 205, 94]` (`sha256("account:UsedNonceAccountV2")[..8]`). Legacy records use `[157, 75, 223, 206, 73, 132, 216, 154]` (`sha256("account:UsedNonceAccount")[..8]`).
- **Memory Layout:**
  ```rust
  pub struct UsedNonceAccount {
      pub discriminator: [u8; 8],     // Offset 0x00..0x08
      pub slot: u64,                   // Offset 0x08..0x10
      pub bump: u8,                    // Offset 0x10..0x11
      pub refund_pubkey: [u8; 32],     // Offset 0x11..0x31 (signing payer)
  }
  ```
- **Total Size:** 49 bytes. Legacy records are 17 bytes (no `refund_pubkey`).
- **Replay:** Every nonce-consuming path returns `VerifierError::NonceAlreadyUsed` when the PDA carries either discriminator.
- **Cleanup:** `close_stale_nonce` (accounts: nonce writable, refund writable, Clock sysvar; no payload, no signer) closes a 49-byte record when `clock.slot - slot > 150` and moves all lamports to `refund_pubkey`. A legacy record or a refund account other than `refund_pubkey` fails with `InvalidAccountAddress`; an earlier slot fails with `UnauthorizedPolicy`. After closure the nonce is outside the `SlotHashes` window (`StaleNonce`). Legacy records cannot be closed. A successful close emits `solana-confidential-compute:governance:v1` with operation `close_stale_nonce`, the refund account as actor, the nonce account, SHA-256(old record bytes) and SHA-256 of the empty closed data; `close_attested_signer` emits the same shape with the workload signer as actor.
- **Creation Guard:** Allocated via `system_instruction::create_account`. If account already exists or data is non-empty, transaction fails with `VerifierError::NonceAlreadyUsed`.

### 1.5 `AttestationBuffer` Account (Legacy Transport Fallback)
- Used when Solana v1 (SIMD-0296) is unavailable on older RPCs.
- Created with space 1,184 bytes.
- Instruction `write_buffer_chunk(offset, chunk)` appends data across 2 transactions.
- Instruction `verify_and_register_buffered` processes the completed buffer.

---

## 2. Anchor-Compatible Instruction Dispatch & Payload Layouts

All instructions route by matching the first 8 bytes against Anchor's global instruction discriminators: `sha256("global:<instruction_name>")[..8]`.

| Instruction | Discriminator (Bytes) | Discriminator (Hex) | Purpose |
| :--- | :--- | :--- | :--- |
| `init_policy_registry` | `[90, 53, 0, 89, 164, 70, 107, 186]` | `5a350059a4466bba` | Initialize policy registry, trusted ARK, and governance authority. |
| `update_policy` | `[227, 150, 114, 217, 142, 172, 100, 228]` | `e39672d98eac64e4` | Registry-authorized monotonic `min_tcb` updates; measurement payload is compatibility-only. |
| `register_vcek` | `[228, 65, 209, 71, 242, 135, 131, 17]` | `e441d147f2878311` | Cryptographically verify ARK -> ASK -> VCEK cert chain and cache `VcekAccount`. |
| `verify_and_register` | `[246, 249, 100, 14, 102, 116, 92, 145]` | `f6f9640e66745c91` | Mode A: Verify signed 1,184-byte report, check nonce, register `AttestedSignerAccount` PDA. |
| `verify_atomic` | `[65, 19, 195, 149, 67, 219, 25, 75]` | `4113c39543db194b` | Mode B: Stateless atomic attestation verification for idempotent actions (zero PDA writes). |
| `verify_atomic_with_nonce` | `[209, 4, 10, 239, 3, 142, 223, 250]` | `d1040aef038edffa` | Mode B: Ephemeral atomic attestation allocating `UsedNonceAccount` for non-idempotent actions. |
| `rotate_root_cert` | `[137, 212, 96, 71, 222, 5, 133, 104]` | `89d46047de058568` | Refused since #255: checks the registry PDA and authority signature, then returns `InvalidInstruction` without writing. |

### 2.1 Stage 1 Payload (`register_vcek`)
The instruction verifies AMD certificate signatures and extracts chip identities.
Header (`RegisterVcekArgs`, 172 bytes) followed by ASK DER then VCEK DER:
```rust
pub struct RegisterVcekArgs {
    pub chip_id: [u8; 64],
    pub tcb_version: u64,
    pub public_key_xy: [u8; 96],
    pub ask_cert_len: u16,
    pub vcek_cert_len: u16,
}
```
Validation Sequence:
1. Load `ark_pubkey_xy` from `PolicyRegistry`.
2. Verify `ask_cert_der` signature using `ark_pubkey_xy` (P-384 ECDSA over SHA-384).
3. Extract ASK public key from `ask_cert_der`.
4. Verify `vcek_cert_der` signature using ASK public key.
5. Extract VCEK uncompressed public key `[u8; 96]`, `chip_id`, and TCB from `vcek_cert_der`.
6. Allocate `VcekAccount` PDA via CPI `system_instruction::create_account` and persist verified key.

### 2.2 Stage 2 Payload (`verify_and_register`) Zero-Copy Instruction
To respect the 4 KiB SBF stack ceiling, the 1,184-byte report is NEVER deserialized with Borsh into a stack variable.
Instruction Data Layout:
- `0x00..0x08`: 8-byte discriminator (`[246, 249, 100, 14, 102, 116, 92, 145]`)
- `0x08..0x10`: `nonce_slot: u64` (Little-Endian) (`rest[0..8]`)
- `0x10..0x4B0`: Raw 1,184-byte AMD SEV-SNP Report (`rest[8..8+1184]`)
- `0x4B0`: `nonce_bump: u8` (client-provided `UsedNonceAccount` bump)
- `0x4B1`: `signer_bump: u8` (client-provided `AttestedSignerAccount` bump)

Accounts (in order): `[payer, policy_registry, vcek_pda, attested_signer_pda, used_nonce_pda, slot_hashes_sysvar, clock_sysvar, system_program]`.

Validation Sequence:
1. Zero-copy borrow `report_bytes = &rest[8..8+1184]`.
2. Construct `SnpReportView::try_from_slice(report_bytes)` with zero stack allocations.
3. Validate hardware security policy via `SnpReportView::validate_security_invariants`:
   - `(policy & GUEST_POLICY_DEBUG) == 0` (bit 19; reject DEBUG).
   - `(policy & GUEST_POLICY_MIGRATE_MA) == 0` (bit 18; reject MIGRATE_MA).
   - `(policy & GUEST_POLICY_RESERVED_MUST_BE_ONE) != 0` (bit 17; AMD reserved must be 1).
   - Bit 16 (`GUEST_POLICY_SMT`) is allowed and is not required.
   - `vmpl == 0`.
   - `version >= 1 && version <= 5`.
   - `signature_algo == 1`.
4. Resolve cached `VcekAccount` PDA using `chip_id_hash`, `reported_tcb`, and the bump stored in the account via `Pubkey::create_program_address`.
5. Verify P-384 ECDSA signature over the 672-byte report body against `vcek.public_key_xy`.
6. Verify nonce blockhash against `SlotHashes` sysvar (bounded scan, age <= 150 slots).
7. Allocate `UsedNonceAccount` PDA via CPI to prevent in-window replay.
8. Validate measurement against allowlist in the AMD `BackendPolicy` (source 1).
9. Validate component-wise TCB against `PolicyRegistry.min_tcb`.
10. Allocate or refresh `AttestedSignerAccount` PDA.

### 2.3 Stage 2 Mode B Payloads (`verify_atomic` & `verify_atomic_with_nonce`)

Mode B implements stateless and ephemeral atomic attestation for discrete operations (e.g. NAV mark updates, confidential liquidations). The transaction layout passes an 80-byte `VerifyAtomicHeader` followed immediately by the 1,184-byte report slice (1,264 bytes total, requiring Solana v1 4,096-byte MTU).

#### Instruction Data Layout (1,264 Bytes):
- `0x00..0x08`: 8-byte discriminator (`[65, 19, 195, 149, 67, 219, 25, 75]` for `verify_atomic`, or `[209, 4, 10, 239, 3, 142, 223, 250]` for `verify_atomic_with_nonce`)
- `0x08..0x10`: `nonce_slot: u64` (Little-Endian)
- `0x10..0x30`: `action_hash: [u8; 32]` (V3 domain + ordered account count/keys/effective signer-writable flags + length-prefixed complete consumer instruction bytes; no V1/V2 fallback)
- `0x30..0x50`: `consumer_program_id: [u8; 32]` (Pubkey of downstream executing program)
- `0x50..0x4F0`: Raw 1,184-byte AMD SEV-SNP Report (`rest[0x50..0x4F0]`)

#### Accounts:
- **`verify_atomic` (Idempotent, 4 accounts):** `[policy_registry, vcek_pda, slot_hashes_sysvar, clock_sysvar]`. (All read-only; zero writable accounts; zero PDA writes).
- **`verify_atomic_with_nonce` (Non-Idempotent, 7 accounts):** `[payer, policy_registry, vcek_pda, used_nonce_pda, slot_hashes_sysvar, clock_sysvar, system_program]`.

#### Validation Sequence:
1. Zero-copy borrow `report_bytes = &rest[0x50..0x4F0]`.
2. Construct `SnpReportView::try_from_slice(report_bytes)` with zero stack allocations.
3. Validate hardware security policy via `SnpReportView::validate_security_invariants` (DEBUG=0, MIGRATE_MA=0, RESERVED_MUST_BE_ONE=1, SMT allowed, `vmpl == 0`, version `1..=5`, `signature_algo == 1`).
4. Resolve cached `VcekAccount` PDA using `chip_id_hash`, `reported_tcb`, and the bump stored in the account via `Pubkey::create_program_address`.
5. Verify P-384 ECDSA signature over the 672-byte report body against `vcek.public_key_xy` (AMD #56860 Table 141, FIPS 186-4).
6. Resolve `slot_hash` directly from the pinned `SlotHashes` sysvar via the shared `load_slot_hash(nonce_slot)` helper (**Requirement M1**). Reading `view.nonce()` for this resolution is strictly prohibited. Enforce `clock.slot - nonce_slot <= 150` slots.
7. Recompute the 32-byte action commitment with the native SHA-256 syscall:
   $$\text{expected\_commitment} = \text{hashv}(\text{slot\_hash} \parallel \text{action\_hash} \parallel \text{consumer\_program\_id})$$
8. Assert hardware-signed $\text{REPORT\_DATA}[32..64] == \text{expected\_commitment}$ (offset `0x070..0x090` of report).
9. Validate measurement against allowlist in the AMD `BackendPolicy` (source 1) and TCB floors against `PolicyRegistry.min_tcb` using zero-copy account slices.
10. If `verify_atomic_with_nonce`:
    - Read client-provided `nonce_bump` from `rest[72+1184]`.
    - Derive `UsedNonceAccount` PDA seeds: `[b"nonce", view.pubkey().as_ref(), expected_commitment.as_ref(), &[nonce_bump]]` (**Requirement M3**).
    - Allocate `UsedNonceAccount` PDA via System Program CPI `create_account` funded by `payer`.

Shared Stage 2 kernel: `verify_and_register`, `verify_atomic`, and `verify_atomic_with_nonce` MUST call `verify_report_and_policy` for report parsing, security invariants, VCEK key verification, measurement allowlist, and TCB checks. Mode B MUST bind accounts with explicit slices (`[registry, vcek, slot_hashes, clock]` and `[payer, registry, vcek, used_nonce, slot_hashes, clock, system_program]`). Dynamic offset indexing (`accounts[off + 2 + off]`) is prohibited.

---

## 3. SEV-SNP 1,184-Byte Signed Report Memory Offsets (AMD Publication #56860 Table 141)

The on-chain verifier treats the raw 1,184-byte report as an immutable byte slice. No untrusted wrapper structs are deserialized.

| Offset Range | Length | Field Name | Validation & Cryptographic Rules |
| :--- | :--- | :--- | :--- |
| `0x000..0x004` | 4 B | `version` | Must be within `1..=5`. |
| `0x004..0x008` | 4 B | `guest_svn` | Policy validation. |
| `0x008..0x010` | 8 B | `policy` | Bit 19 = 0 (DEBUG prohibited), Bit 18 = 0 (MIGRATE_MA prohibited), Bit 17 = 1 (`RESERVED_MUST_BE_ONE`), Bit 16 = SMT allowed. |
| `0x030..0x034` | 4 B | `vmpl` | Must equal 0 (highest privilege). |
| `0x034..0x038` | 4 B | `signature_algo` | Must equal `1` (ECDSA P-384 with SHA-384 per FIPS 186-4). |
| `0x048..0x04C` | 4 B | `key_sel` | `0` = VCEK, `1` = VLEK. Determines PDA derivation fallback. |
| `0x050..0x070` | 32 B | `pubkey` | Workload Ed25519 signing key. |
| `0x070..0x090` | 32 B | `nonce_or_commitment` | Mode A: Solana slot blockhash (`nonce`). Mode B: SHA-256 commitment (`sha256(slot_hash \|\| action_hash \|\| consumer_program_id)`). |
| `0x090..0x0C0` | 48 B | `measurement` | SHA-384 launch digest (must match AMD `BackendPolicy.measurements` (source 1)). |
| `0x180..0x188` | 8 B | `reported_tcb` | Component-wise check against `PolicyRegistry.min_tcb`. |
| `0x1A0..0x1E0` | 64 B | `chip_id` | Physical CPU ID (SHA-256 hashed to derive `VcekAccount` PDA). |
| `0x000..0x2A0` | 672 B | `signed_body` | The exact byte slice hashed via SHA-384 for signature verification. |
| `0x2A0..0x2E8` | 72 B | `signature_r` | 72-byte LE field: bytes `0..48` is scalar $r$; bytes `48..72` MUST be zero. |
| `0x2E8..0x330` | 72 B | `signature_s` | 72-byte LE field: bytes `0..48` is scalar $s$; bytes `48..72` MUST be zero. FIPS 186-4 valid. |
| `0x330..0x4A0` | 368 B | `reserved` | Padding to 512-byte signature block (total report: 1,184 bytes). |

---

## 4. SlotHashes Sysvar Pinning & Bounded Scan

To inspect `SlotHashes` safely without memory exhaustion:

```rust
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    program_error::ProgramError,
    sysvar::{slot_hashes, Sysvar},
};

pub fn verify_recent_slot_hash(
    slot_hashes_account: &AccountInfo,
    clock: &Clock,
    nonce_slot: u64,
    expected_hash: &[u8; 32],
) -> Result<(), ProgramError> {
    // 1. Mandatory Sysvar Pinning: assert account address matches official ID
    if slot_hashes_account.key != &slot_hashes::ID {
        return Err(ProgramError::InvalidArgument);
    }

    // 2. Enforce max slot age (150 slots)
    if clock.slot < nonce_slot || clock.slot - nonce_slot > 150 {
        return Err(ProgramError::Custom(4)); // StaleNonce
    }

    let data = slot_hashes_account.try_borrow_data()?;
    if data.len() < 8 {
        return Err(ProgramError::InvalidAccountData);
    }

    let num_entries = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidAccountData)?
    ) as usize;
    let max_search = num_entries.min(150);

    // 3. Direct byte offset search over the active window (bounded scan)
    for i in 0..max_search {
        let entry_start = 8 + i * 40;
        let entry_end = entry_start + 40;
        if data.len() < entry_end {
            break;
        }
        let slot = u64::from_le_bytes(
            data[entry_start..entry_start + 8]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?
        );
        if slot == nonce_slot {
            let hash = &data[entry_start + 8..entry_end];
            if hash == expected_hash {
                return Ok(());
            } else {
                return Err(ProgramError::Custom(4)); // StaleNonce
            }
        }
    }

    Err(ProgramError::Custom(4)) // StaleNonce
}

/// Loads the 32-byte slot hash directly from the pinned SlotHashes sysvar.
///
/// Requirement M1: Used by verify_atomic to resolve the raw slot hash without
/// circular dependencies. Reading view.nonce() for this lookup in Mode B is strictly prohibited.
pub fn load_slot_hash(
    slot_hashes_account: &AccountInfo,
    clock: &Clock,
    nonce_slot: u64,
) -> Result<[u8; 32], ProgramError> {
    // 1. Mandatory Sysvar Pinning
    if slot_hashes_account.key != &slot_hashes::ID {
        return Err(ProgramError::InvalidArgument);
    }

    // 2. Enforce max slot age (150 slots)
    if clock.slot < nonce_slot || clock.slot - nonce_slot > 150 {
        return Err(ProgramError::Custom(4)); // StaleNonce
    }

    let data = slot_hashes_account.try_borrow_data()?;
    if data.len() < 8 {
        return Err(ProgramError::InvalidAccountData);
    }

    let num_entries = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidAccountData)?
    ) as usize;
    let max_search = num_entries.min(150);

    for i in 0..max_search {
        let entry_start = 8 + i * 40;
        let entry_end = entry_start + 40;
        if data.len() < entry_end {
            break;
        }
        let slot = u64::from_le_bytes(
            data[entry_start..entry_start + 8]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?
        );
        if slot == nonce_slot {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[entry_start + 8..entry_end]);
            return Ok(hash);
        }
    }

    Err(ProgramError::Custom(4)) // StaleNonce
}
```

---

## 5. TCB Component-Wise Evaluation Rule

AMD TCB byte decomposition from offset `0x180..0x188`:
- Byte 0: `boot_loader`
- Byte 1: `tee`
- Bytes 2..5: `reserved`
- Byte 6: `snp`
- Byte 7: `microcode`

Evaluation gate:
```rust
pub fn assert_tcb_valid(reported: &[u8; 8], policy: &PolicyRegistry) -> Result<(), ProgramError> {
    if reported[0] < policy.min_tcb_boot_loader
        || reported[1] < policy.min_tcb_tee
        || reported[6] < policy.min_tcb_snp
        || reported[7] < policy.min_tcb_microcode
    {
        return Err(ProgramError::Custom(6)); // TcbBelowMinimum
    }
    Ok(())
}
```

---

## 6. On-Chain PDA Lifecycle & CPI Allocation

To comply with the Solana runtime, all new program accounts (`PolicyRegistry`, `VcekAccount`, `AttestedSignerAccount`, `UsedNonceAccount`) are allocated via System Program Cross-Program Invocation (CPI).

### 6.1 Account Creation Pre-Conditions
Before invoking `system_instruction::create_account`:
1. Assert `payer.is_signer == true` and `payer.is_writable == true`.
2. Assert `target_pda.is_writable == true`.
3. Verify PDA bump passed from off-chain client using `Pubkey::create_program_address(signer_seeds, program_id)`. Reject if mismatch.
4. Check if account already contains lamports or data:
   - If `target_pda.data_len() > 0`: check account discriminator and apply type-specific re-initialization rules.
   - If unallocated (`target_pda.data_len() == 0`): execute CPI creation.

### 6.2 CPI Invocation Pattern
```rust
pub fn create_pda_account<'a>(
    payer: &AccountInfo<'a>,
    pda: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    program_id: &Pubkey,
    signer_seeds: &[&[u8]],
    space: usize,
    rent: &Rent,
) -> Result<(), ProgramError> {
    let lamports = rent.minimum_balance(space);
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            pda.key,
            lamports,
            space as u64,
            program_id,
        ),
        &[payer.clone(), pda.clone(), system_program.clone()],
        &[signer_seeds],
    )
}
```

### 6.3 Mode B Nonce PDA Derivation (Requirement M3)
For non-idempotent operations executed via `verify_atomic_with_nonce`, the `UsedNonceAccount` PDA derives from:
```rust
let signer_seeds = [
    b"nonce",
    view.pubkey().as_ref(),
    expected_commitment.as_ref(),
    &[bump],
];
```
This binds replay defense to the exact 32-byte action commitment ($\text{SHA-256}(\text{slot\_hash} \parallel \text{action\_hash} \parallel \text{consumer\_program\_id})$).

---

## 7. On-Chain Consumer Helpers (`solana-confidential-compute-cpi`)

Downstream programs import `solana-confidential-compute-cpi` (`solana-program` only; no `solana-sdk`). `solana-confidential-compute-sdk` re-exports the same types for off-chain callers.

### 7.1 Mode B Introspection (`assert_attestation_atomic`)

```rust
pub struct AtomicAttestationExpectation {
    pub expected_platform: AttestationPlatform,
    pub action_hash: [u8; 32],
    pub expected_measurement: [u8; 48],
    pub expected_signer: Option<[u8; 32]>,
    pub require_nonce: bool, // Must be true; false is rejected by consumer guards.
    pub confidential_compute_ix_index: Option<u16>, // None selects the preceding instruction.
}

pub fn assert_attestation_atomic(
    instructions_sysvar: &AccountInfo,
    expectation: &AtomicAttestationExpectation,
    current_program_id: &Pubkey,
) -> Result<AttestationClaims, ProgramError>;
```

Checks, in order (@spec SCC-VERIFY-013):

1. Pin `instructions_sysvar.key` to `sysvar::instructions::ID`.
2. Load `current_index` with `load_current_index_checked`. The caller does not pass this index.
3. Resolve `confidential_compute_ix_index` to `current_index - 1` when `expectation.confidential_compute_ix_index` is `None`.
4. Assert `confidential_compute_ix_index < current_index`. Reject the same index and any later index.
5. Load the Solana Confidential Compute instruction. Assert `program_id == solana_confidential_compute_verifier::ID`.
6. Match the discriminator to `require_nonce` (`verify_atomic_with_nonce` vs `verify_atomic`).
7. Assert `header.consumer_program_id == current_program_id` and `header.action_hash == expectation.action_hash`.
8. Assert report measurement and optional workload signer.

The consumer guard requires `require_nonce == true`; false is rejected. V2 action hashing does not provide an idempotent or legacy acceptance fallback.

### 7.2 Action Hash Derivation (`hash_action`)

Use V2 `hash_action_account_infos(discriminator, accounts, payload)` on all ordered consumer `AccountInfo`s at the top level before CPI. This binds the actual pubkey, signer and writable privileges. Off-chain `hash_action` takes `AccountMeta` values with effective compiled flags; the old pubkey-only signature is replaced.

The exact SHA-256 preimage is ASCII `teton:action:v2` + NUL, u32LE discriminator length + bytes, u32LE account count, each ordered pubkey32 + signer u8 + writable u8, then u32LE payload length + bytes. Preserve duplicates. See the [source-linked V2 contract](../../crates/solana-confidential-compute-cpi/README.md#4-hash_action) for APIs, complete metadata-template construction before attesting, final compiled validation, LUT/reserved-key rejection, and coordinated migration requiring fresh V2 attestations without legacy fallback.

### 7.3 Mode A Signer Guard (`assert_attestation_signer`)

Stateful consumers validate the `AttestedSignerAccount` PDA (@spec SCC-VERIFY-015):

Source signature: [`crates/solana-confidential-compute-cpi/src/lib.rs`](../../crates/solana-confidential-compute-cpi/src/lib.rs), `assert_attestation_signer` (production Clock lookup):

```rust
pub fn assert_attestation_signer(
    attested_record: &AccountInfo,
    workload_signer: &AccountInfo,
    expected_measurement: &[u8; 48],
    expected_platform: AttestationPlatform,
) -> Result<u64, ProgramError>;
```

Checks: owner, `ATTESTED_SIGNER_DISCRIMINATOR`, PDA seeds `[b"attested_signer_v2", workload_signer.key]`, `workload_signer.is_signer == true`, stored signer equality, expected platform, measurement match, and `clock_slot <= expires_slot` and `0 <= clock.unix_timestamp < expires_unix_timestamp`. Returns `expires_slot`.

---

## 8. Hardware P-384 Compatibility & Signature Malleability Architecture

AMD SEV-SNP Firmware ABI (Publication #56860 Table 141) specifies ECDSA P-384 with SHA-384 per FIPS 186-4.

1. **FIPS 186-4 vs BIP-62 Low-S:** FIPS 186-4 defines ECDSA where scalar $s \in [1, n-1]$. The AMD Platform Security Processor (PSP) firmware does not normalize $s \le \lfloor n / 2 \rfloor$. Enforcing an on-chain low-S assertion would reject approximately 50% of valid hardware attestation reports.
2. **Replay Invariance:** Solana Confidential Compute's on-chain anti-replay and uniqueness keys derive strictly from `(signer_pubkey, nonce)` in Mode A and `(signer_pubkey, commitment)` in Mode B. Signature bytes $(r, s)$ are never used as a database or state key. Therefore, signature malleability $(r, n - s)$ does NOT open a transaction replay hole.
3. **Safety Policy:** The on-chain verifier SHALL NOT fail-closed on high-S signatures. Low-S monitoring is relegated to off-chain observability in `solana-confidential-compute-cli` across target silicon (Milan, Genoa, Turin).

---

## 9. Decoupled Verification Architecture & Execution Backends

To future-proof the verifier for native Solana precompiles while enabling immediate Mainnet deployment via zero-knowledge proofs, the verifier abstracts cryptographic verification across a pluggable backend trait (@spec SCC-ARCH-003).

### 9.1 `SignatureVerifier` Trait Abstraction

```rust
pub trait SignatureVerifier {
    /// Verifies an ECDSA P-384 signature over a SHA-384 message digest.
    fn verify_p384(
        &self,
        public_key_xy: &[u8; 96],
        message_digest: &[u8; 48],
        signature_rs: &[u8; 96],
        instructions_sysvar: Option<&AccountInfo>,
    ) -> Result<(), ProgramError>;
}
```

### 9.2 Verification Backends

1. **`MockVerifier` (Testing & Benchmarks):**
   - Deterministic test double used in `cu_benchmarks` and unit tests to validate account lifecycle, sysvar freshness, and policy gates without SBF point multiplication overflow.

2. **`Groth16SyscallVerifier` (Track B — Production Mainnet Ready):**
   - Validates AMD SEV-SNP reports and certificate chains using a 128-byte Groth16 zk-SNARK proof over BN254.
   - Invokes Solana's native `solana_program::alt_bn128::alt_bn128_pairing` syscall in-process.
   - Consumes ~150,000 CUs. Fits within standard transaction limits without waiting for Solana runtime upgrades.

3. **`InstructionIntrospectionVerifier` (Track A — Future Native SIMD):**
   - Adapts to a native `secp384r1_sigverify` precompile when ratified by Solana.
   - Because native precompiles reject CPI, this backend uses instruction introspection via `sysvar::instructions`.
   - Consumes ~25,000 CUs per signature.
   - Enforces strict security binds (@spec SCC-VERIFY-016):
     - Asserts `instructions_sysvar.key == sysvar::instructions::ID`.
     - Enforces relative index `current_index - 1`.
     - Pins `sig_ix.program_id == EXPECTED_SIGVERIFY_PROGRAM_ID`.
     - Recomputes `SHA-384(report_signed_bytes)` from the borrowed report slice and asserts equality with precompile message bytes.

### 9.3 2-Stage Pipeline Sequencing

The decoupled architecture seamlessly integrates with the 2-Stage caching model:
- **Stage 1 (`register_vcek`):** Verifies Sigs 1 & 2 (`ARK -> ASK` and `ASK -> VCEK`) once per physical server host, caching `VcekAccount` on-chain.
- **Stage 2 (`verify_atomic` / `verify_and_register`):** Verifies Sig 3 (`VCEK -> Report`) per workload action.




### Current Mode A V2 contract

The current account uses seed `[b"attested_signer_v2", signer_pubkey]`, discriminator `sha256("account:AttestedSignerAccountV2")[..8]` = `[43, 255, 114, 40, 233, 28, 127, 238]`, and a 154-byte serialized layout. The bump remains at byte 145; bytes 146..154 contain `expires_unix_timestamp` as signed little-endian i64. V1 (`attested_signer`, 146 bytes, V1 discriminator) is historical and is rejected by the current V2 consumer contract; do not pad or reinterpret it as V2.

A valid session requires both `clock.slot <= expires_slot` and `0 <= clock.unix_timestamp < expires_unix_timestamp`. Slot equality is valid; Unix deadline equality is expired. Both values come from the trusted Clock, not from caller arguments. A decoder alone does not perform session validation. Consumer helpers also check owner/discriminator, workload signature and stored pubkey, caller-pinned measurement and platform; the low-level helper additionally re-derives the PDA. Registration derives the Unix deadline independently of slot duration (and caps GCP sessions at JWT expiry).

Sources: [verifier state](../../programs/solana-confidential-compute-verifier/src/state.rs), [deadline construction](../../programs/solana-confidential-compute-verifier/src/processor.rs) (`session_unix_deadline`), [CPI validation](../../crates/solana-confidential-compute-cpi/src/lib.rs) (`assert_attestation_signer`), [zero-copy adapter](../../crates/solana-confidential-compute-cpi/src/anchor.rs), and [TypeScript decoder](../../sdks/typescript/src/index.ts). These source contracts do not establish deployment or fresh hardware/SBF evidence.

### Backend measurement governance

`BackendPolicy` is authoritative for measurement admission: source 1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space. Each canonical PDA uses `[b"backend_policy", &[source]]` and holds up to eight measurements. Missing, empty, or mismatched backend policy fails closed. The global `PolicyRegistry.measurement_count` / `measurements` fields and `update_policy` measurement payload are deprecated as runtime controls and retained for state/wire compatibility; clearing that global list does not halt admission. There is no implicit global/backend allowlist AND. Registry authority checks and monotonic AMD TCB floors remain active.

To halt new admission, the registry authority uses `set_backend_policy` with an empty list (`[]`) for each relevant backend; update all three policies to halt all backends. Rust exposes `build_set_backend_policy_ix`, TypeScript `buildSetBackendPolicyIx`. This does not revoke existing Mode A sessions: use `revoke_attested_signer` separately for targeted containment. These are source contracts, not evidence of deployment or hardware/SBF validation.
