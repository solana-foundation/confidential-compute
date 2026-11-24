# solana-confidential-compute-core

`solana-confidential-compute-core` holds the domain types for Solana Confidential Compute. The crate can build with `no_std`. Host tools enable the `std` feature. The on-chain programs use the default-features-off workspace dependency.

The crate does not verify a signature. `solana-confidential-compute-crypto` verifies signatures. `solana-confidential-compute-verifier` applies policy. This crate names the bytes those layers read.

`@spec SCC-SEC-001` `@spec SCC-VERIFY-001` `@spec SCC-ARCH-001`

---

## 1. Where this crate sits

```
  AMD PSP / Nitro hypervisor
            |
            |  signed bytes
            v
  +---------------------------+
  | solana-confidential-compute-core                |
  | SnpReportView             |
  | NitroAttestationView      |
  | AttestedSigner            |
  | VerifyAtomicHeader        |
  +---------------------------+
            |
            v
  solana-confidential-compute-crypto  -->  solana-confidential-compute-verifier  -->  consumer
```

A view borrows the input buffer. It does not copy the 1,184-byte report onto the stack.

---

## 2. Crate map

| Module | Role |
| :--- | :--- |
| `report` | Zero-copy view of the AMD SEV-SNP report (AMD Publication #56860). |
| `nitro` | Length constants and the parsed Nitro payload view. |
| `types` | `EnclaveType`, `AttestedSigner`, `VerifyAtomicHeader`, action commitment. |
| `verifier` | `SignatureVerifier` trait and `MockVerifier`. |
| `error` | `ConfidentialComputeError`. |

Build the library tests:

```bash
cargo test -p solana-confidential-compute-core
```

`default = ["std"]` is set on the package. The workspace dependency sets `default-features = false`. A Solana program must keep that setting.

---

## 3. AMD report memory map

`SNP_REPORT_SIZE` is **1184**. `SNP_SIGNED_BODY_SIZE` is **672**. The signature covers bytes `0x000..0x2A0`.

```
 offset     length   field
 --------   ------   ---------------------------------
 0x000        4      version          (u32 LE, must be 1..=5)
 0x004        4      guest_svn        (u32 LE)
 0x008        8      policy           (u64 LE)
 0x030        4      vmpl             (u32 LE, must be 0)
 0x034        4      signature_algo   (u32 LE, must be 1)
 0x038        8      current_tcb      (u64 LE)
 0x048        4      FLAGS            (u32 LE)
 0x050       32      REPORT_DATA pubkey   (workload Ed25519 key)
 0x070       32      REPORT_DATA nonce    (slot hash or Mode B commitment)
 0x090       48      measurement      (SHA-384)
 0x0C0       32      host_data
 0x140       32      report_id
 0x180        8      reported TCB     [boot, tee, rsvd x4, snp, microcode]
 0x1A0       64      chip_id
 0x2A0       72      signature r      (LE; bytes 48..72 must be 0)
 0x2E8       72      signature s      (LE; bytes 48..72 must be 0)
 0x330      ...      rest of the 512-byte signature block
 0x4A0             end of the 1,184-byte report
```

```
 0x000                          0x2A0              0x4A0
 |--------- signed body --------|-- signature block --|
 |  672 bytes                   |  512 bytes          |
 |                              | r @ 0x2A0  s @ 0x2E8|
```

`SnpReportView::try_from_slice` accepts a slice of length 1184 only. A shorter buffer returns `ConfidentialComputeError::ReportSizeInvalid`. `signature_r_be` and `signature_s_be` reverse the first 48 little-endian bytes into a big-endian P-384 scalar (`@spec SCC-SEC-009`).

### 3.1 REPORT_DATA

```
 REPORT_DATA  (64 bytes at 0x050)
 +--------------------------------+--------------------------------+
 | pubkey   0x050 .. 0x070        | nonce    0x070 .. 0x090        |
 | 32-byte Ed25519 workload key   | 32-byte slot hash (Mode A)     |
 |                                | or action commitment (Mode B)  |
 +--------------------------------+--------------------------------+
```

`@spec SCC-VERIFY-001` reads the nonce at `0x070..0x090` during `verify_and_register`. The verifier compares that nonce with the `SlotHashes` entry for `nonce_slot`. The age limit is 150 slots.

`ReportData::new(pubkey, blockhash)` writes those two halves. Mode B does not put the workload key in the first half. The CLI writes zeros in bytes `0..32` and the commitment in bytes `32..64`.

### 3.2 Guest policy (`@spec SCC-SEC-001`)

`validate_security_invariants` checks this set:

| Bit | Constant | Required value |
| :--- | :--- | :--- |
| 16 | `GUEST_POLICY_SMT` (`1 << 16`) | Allowed. The bit is not required. |
| 17 | `GUEST_POLICY_RESERVED_MUST_BE_ONE` | Must be 1. |
| 18 | `GUEST_POLICY_MIGRATE_MA` | Must be 0. |
| 19 | `GUEST_POLICY_DEBUG` | Must be 0. |

The same function requires version `1..=5`, `signature_algo == 1`, `vmpl == 0`, and a measurement that is not 48 zero bytes.

### 3.3 FLAGS and VLEK

The FLAGS word is at offset `0x048`.

```
 FLAGS bits
  bit 0      AUTHOR_KEY_EN
  bit 1      MASK_CHIP_KEY
  bits 4:2   SIGNING_KEY     0 = VCEK,  1 = VLEK,  7 = none
```

`key_sel` is `(flags >> 2) & 0b111`. `is_vlek` is true when `SIGNING_KEY == 1` or when `chip_id` is 64 zero bytes. A FLAGS word equal to 1 is `AUTHOR_KEY_EN` on a VCEK report. That word is not a VLEK report.

---

## 4. Nitro length constants

The COSE parser lives in `solana-confidential-compute-crypto`. This crate publishes the shared limits.

| Constant | Value | Meaning |
| :--- | ---: | :--- |
| `NITRO_PCR_LEN` | 48 | One SHA-384 PCR. |
| `NITRO_USER_DATA_LEN` | 32 | Workload Ed25519 key in `user_data`. |
| `NITRO_NONCE_LEN` | 32 | Slot hash or Mode B commitment in `nonce`. |
| `MAX_NITRO_CERT_LEN` | 1024 | One DER certificate. |
| `MAX_NITRO_CABUNDLE` | 8 | Root plus intermediates. |
| `MAX_NITRO_DOCUMENT_LEN` | **8192** | Maximum COSE Sign1 document. |

`NitroPcrs` stores PCR0, PCR1, PCR2, and PCR8. `pcr0_is_zero` detects the all-zero debug measurement. `NitroAttestationView` borrows `module_id`, `certificate`, and the CA bundle. It copies the PCR bytes, `user_data`, and `nonce`.

A 4,526-byte hardware document fits in 8,192 bytes. It does not fit in a 1,232-byte Solana packet. The client SDKs reject that packet.

---

## 5. Domain records

### 5.1 `EnclaveType`

| Variant | Discriminant |
| :--- | ---: |
| `AmdSevSnp` | 1 |
| `AwsNitro` | 2 |
| `GcpConfidentialSpace` | 3 |
| `Mock` | 255 |

Borsh uses the discriminant (`use_discriminant = true`).

### 5.2 `AttestedSigner` and the 146-byte account

`AttestedSigner` is the inner record. The on-chain account adds an 8-byte discriminator and a 1-byte bump. `ATTESTED_SIGNER_ACCOUNT_SIZE` in `solana-confidential-compute-cpi` is **146**.

```
 AttestedSignerAccount                         146 bytes
 +------+----------+---+----------+----------+-----+-----+-----+---+
 | disc | pubkey   | t | measure  | chip hash| tcb | reg | exp | b |
 |  8   | 32       | 1 | 48       | 32       |  8  |  8  |  8  | 1 |
 +------+----------+---+----------+----------+-----+-----+-----+---+
  0      8          40  41         89         121   129   137   145
```

`t` is `EnclaveType`. `b` is the PDA bump. `is_expired` is true when `current_slot > expires_slot`.

The PDA seed is `[b"attested_signer", signer_pubkey]`. `@spec SCC-ARCH-001` allocates that account with `create_account`.

### 5.3 Mode B header

`VerifyAtomicHeader::SIZE` is **72**. The on-chain instruction places an 8-byte discriminator in front of this header. The full SNP prefix is 80 bytes. The 1,184-byte report follows at offset `0x50`.

```
 verify_atomic_with_nonce instruction data
 +--------+------------------+------------------+------------------+--------+
 | disc 8 | nonce_slot    8  | action_hash   32 | consumer id   32 | report |
 |        |                  |     header = 72 bytes              |  1184  |
 +--------+------------------+------------------+------------------+--------+
  0        8                  16                 48                 80
```

`compute_action_commitment` returns `SHA-256(slot_hash || action_hash || consumer_program_id)` through `solana_program::hash::hashv`.

---

## 6. `SignatureVerifier`

`@spec SCC-ARCH-003`. The trait takes a 96-byte public key, a 48-byte SHA-384 digest, a 96-byte signature, and an optional Instructions sysvar. The return type is `Result<(), ProgramError>`.

```rust
fn verify_p384(
    &self,
    public_key_xy: &[u8; 96],
    message_digest: &[u8; 48],
    signature_rs: &[u8; 96],
    instructions_sysvar: Option<&AccountInfo>,
) -> Result<(), ProgramError>;
```

`MockVerifier::succeeding` returns `Ok(())`. `MockVerifier::failing` returns `ProgramError::InvalidInstructionData`. The verifier program blocks `mock-crypto` on `target_os = "solana"` unless `test-bpf` is set. On that Solana target, `DefaultVerifier` is `SolanaDefaultVerifier`. `DirectCryptoVerifier` calls `solana-confidential-compute-crypto` on a host build. The SHA-384 of the 672-byte body is computed by the caller before `verify_p384`.

---

## 7. Errors you will see from this crate

| Variant | Typical cause |
| :--- | :--- |
| `ReportSizeInvalid` | The buffer length is not 1184. |
| `InvalidSignaturePadding` | Signature bytes 48..72 are not zero. |
| `InvalidSignatureAlgorithm` | `signature_algo` is not 1. |
| `DebugModeProhibited` | Policy bit 19 is set. |
| `UnauthorizedPolicy` | Version, migration bit, or reserved bit failed. |
| `InvalidMeasurement` | The measurement is 48 zero bytes. |
