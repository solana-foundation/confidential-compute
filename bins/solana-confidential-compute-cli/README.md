# solana-confidential-compute-cli

`solana-confidential-compute-cli` is the proof-of-enclave binary. The command name is `solana-confidential-compute`. The Cargo package is `solana-confidential-compute-cli`. Two subcommands exist: `prove` and `verify`.

`prove` builds a dry-run transaction. `verify` prints the Mode A PDA. The binary does not submit a transaction.

`@spec SCC-VERIFY-001` `@spec SCC-SEC-001` `@spec SCC-ARCH-001`

```bash
cargo test -p solana-confidential-compute-cli
cargo run -p solana-confidential-compute-cli -- --help
cargo run -p solana-confidential-compute-cli -- prove --help
cargo run -p solana-confidential-compute-cli -- verify --help
```

---

## 1. Subcommands

```
 solana-confidential-compute
   |
   +-- prove     open /dev/sev-guest or --mock
   |             check the report locally
   |             print transaction_base64 and transaction_hex
   |
   +-- verify    derive the AttestedSigner PDA
                 print the address and the bump
                 do not call RPC
```

Default verifier id:

```
EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh
```

`verify` example:

```bash
cargo run -p solana-confidential-compute-cli -- verify --pubkey <WORKLOAD_ED25519_PUBKEY>
```

Output shape:

```
Derived AttestedSigner PDA: <ADDRESS> (bump: <N>) for <PUBKEY>
```

The seed is `[b"attested_signer", pubkey]`. `@spec SCC-ARCH-001`.

---

## 2. `prove` flags

| Flag | Default | Role |
| :--- | :--- | :--- |
| `--mode` | `stateful` | `stateful` is Mode A. `atomic` is Mode B. |
| `--pubkey` | unset | Required for `--mode stateful`. |
| `--mock` | `false` | Build a local report. Do not open a device. |
| `--vcek-pubkey` | unset | 96-byte hex of X concatenated with Y. Required on the hardware path. |
| `--device` | `/dev/sev-guest` | Guest device node. |
| `--program-id` | verifier id above | Override for tests. |
| `--payer` | workload key, or the consumer id in Mode B | Fee payer pubkey. |
| `--nonce-slot` | `500` | Slot written into the instruction header. |
| `--slot-hash` | 32 bytes of `0x55` | Hex slot hash. |
| `--action-hash` | unset | Required for `--mode atomic`. 32-byte hex. |
| `--consumer-program` | unset | Required for `--mode atomic`. |
| `--stateless-idempotent` | `false` | Always returns an error. |
| `--priority-fee` | unset | Compute-unit price in microlamports. |
| `--dry-run` | `true` | `false` returns an error. |

`--stateless-idempotent` returns an error before any ioctl. Mode B always consumes a nonce.

`--dry-run false` returns `live broadcast is not enabled; pass --dry-run`. The process exit code is 1.

An explicit `--vcek-pubkey` wins over the mock key. `mock_vcek_public_key_xy()` is used only for `--mock` when no key was passed.

---

## 3. Hardware path and mock path

```
                    prove
                      |
          +-----------+-----------+
          |                       |
       --mock                 hardware
          |                       |
          v                       v
 generate_mock_report      open --device
 user_data echoed          ioctl SNP_GET_REPORT
          |                0xC0205300
          |                       |
          +-----------+-----------+
                      v
            validate_security_invariants
            (@spec SCC-SEC-001)
                      |
                      v
            verify_snp_report_signature
                      |
                      v
            assemble_attestation_tx
            print base64 and hex
```

On a host that is not Linux, the hardware path returns `HardwareUnavailable` and tells you to pass `--mock`.

Local mock session:

```bash
cargo run -p solana-confidential-compute-cli -- prove \
    --mode stateful \
    --pubkey <WORKLOAD_ED25519_PUBKEY> \
    --mock \
    --dry-run true
```

Local mock Mode B:

```bash
cargo run -p solana-confidential-compute-cli -- prove \
    --mode atomic \
    --action-hash <64_HEX_CHARS> \
    --consumer-program A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ \
    --mock \
    --dry-run true
```

Hardware Mode A, on a machine that has `/dev/sev-guest`:

```bash
cargo run -p solana-confidential-compute-cli -- prove \
    --mode stateful \
    --pubkey <WORKLOAD_ED25519_PUBKEY> \
    --device /dev/sev-guest \
    --vcek-pubkey <96_BYTE_XY_HEX> \
    --nonce-slot <RECENT_SLOT> \
    --slot-hash <32_BYTE_SLOT_HASH_HEX> \
    --dry-run true
```

`--nonce-slot` must be a slot the verifier can still see. `@spec SCC-VERIFY-001` rejects an age above 150 slots.

---

## 4. SEV-SNP ioctl

`SNP_GET_REPORT` is **`0xC0205300`**. That is `_IOWR('S', 0x00, 32)`.

```
 SnpGuestRequestIoctl                         32 bytes
 +------+------+--------------+--------------+-----------+
 | ver  | pad  | req_data u64 | resp_data u64| exitinfo2 |
 |  1   |  7   | pointer      | pointer      |  8        |
 +------+------+--------------+--------------+-----------+

 SnpReportReq                                 96 bytes
 user_data 64 | vmpl u32 = 0 | key_sel u8 = 0 | reserved 27

 SnpReportResp                                4032 bytes
 data[4000] | reserved tail 32
```

The kernel writes 4,000 bytes into `data`. It does not write the 32-byte tail. `SNP_GUEST_RESP_DATA_LEN` is 4000. `SNP_GUEST_RESP_TAIL_LEN` is 32. Pointers in the ioctl argument point at stack objects that live for the call. A negative return becomes `CliError::HardwareUnavailable` and includes `exitinfo2`.

`key_sel` in the request is 0. The CLI asks the PSP for a VCEK report.

### 4.1 PSP prefix of 32 bytes

`SNP_PSP_REPORT_PREFIX_LEN` is **32**.

```
 guest data[4000]
 |
 +-- bytes 0..4 == 0
 |   bytes 4..8 == 1184 little-endian
 |        |
 |        v
 |   report = data[32 .. 32+1184]
 |
 +-- any other prefix, including version 1..=5
          |
          v
     report = data[0 .. 1184]
```

`has_psp_report_prefix` is true only when the status word is zero, the size word is 1184, and `32 + 1184` fits in 4000. `copy_guest_report_prefix` then copies `data[32..1216]`. Every other buffer is copied from offset 0.

`validate_hardware_report` rejects a size other than 1184. It requires `data[0x50..0x90]` to equal the 64-byte `user_data` that the CLI sent.

A high-S scalar is logged and kept. The log line is `HIGH_S_WARN` in `tx.rs`. The bytes on the wire do not change.

---

## 5. Transaction the CLI prints

`COMPUTE_UNIT_LIMIT` is **700000**. `assemble_attestation_tx` prepends `SetComputeUnitLimit` (compute-budget discriminator 2). `--priority-fee` adds `SetComputeUnitPrice` (discriminator 3).

Mode A accounts match `verify_and_register`: payer, policy registry, VCEK PDA, attested-signer PDA, used-nonce PDA, SlotHashes, Clock, System Program.

Mode A `REPORT_DATA` is `pubkey || slot_hash`. Mode B writes zeros in the first 32 bytes and `SHA-256(slot_hash || action_hash || consumer_program_id)` in the second 32 bytes. The Mode B discriminator is `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR`.

The printed lines are:

```
transaction_base64=...
transaction_hex=...
```

The packet can exceed 1,232 bytes because the report is 1,184 bytes. The CLI still prints the dry-run payload. The Rust SDK public builders return `PacketTooLarge` for that same report. Read both facts before you broadcast the base64 string.

---

## 6. Nitro capture is a script

This binary does not open `/dev/nsm` and it does not open an `AF_VSOCK` socket. Nitro capture is `scripts/run_nitro_hardware_probe.sh`.

```
 enclave                              parent instance
 +-----------------------------+      +---------------------------+
 | ioctl 0xC0200A00            |      | AF_VSOCK listen           |
 | NSM_REQUEST_ATTESTATION     |      | VMADDR_CID_ANY            |
 | on /dev/nsm                 | ---> | port 5005                 |
 | connect parent CID 3        |      | write /tmp/nitro_*.bin    |
 +-----------------------------+      +---------------------------+
```

Parent CID is **3**. Port is **5005**. Address family `AF_VSOCK` is 40. The script has no flags. The closeout capture was 4,552 bytes. The steps and the instance type are in `docs/handoff/grant-handoff-guide.md` and in the root `README.md` section 5.3.

The sidecar, not this CLI, issues `NSM_REQUEST_ATTESTATION` from inside an enclave process. AWS Nitro Enclaves run headless EIF microVMs without interactive terminal or shell access, communicating with the parent host over `AF_VSOCK`. Hardware attestation for Nitro is therefore handled by the unattended `solana-confidential-compute-sidecar` service (`bins/solana-confidential-compute-sidecar/README.md`) rather than this interactive CLI.

## 7. Offline governance and emergency halt

`governance --authority PUBKEY emergency-halt --source N` exports an unsigned `set_backend_policy` transaction with an empty measurement list. Source is required: 1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space. `set-backend-policy --source N --measurement HEX` restores an explicit reviewed allowlist; omitting all measurements also halts that backend. Repeat `--measurement` for up to eight 48-byte values. GCP measurements are the 32-byte image digest followed by 16 zero bytes.

These commands never load keys, contact RPC, or broadcast. They print `unsigned_transaction_base64` and `unsigned_transaction_hex` with a zero blockhash and empty signature slots. Replace the blockhash, collect the registry authority and fee payer signatures externally, submit, check transaction success, and read the canonical backend PDA. `--fee-payer PUBKEY` defaults to the authority; `--program-id PUBKEY` selects the target verifier.

To contain every backend, export, sign, submit, and verify one halt for each source. Three fixed-size policy updates exceed one Solana packet, so the CLI exports one per transaction; containment is partial until all three are confirmed. Existing Mode A sessions require `revoke-attested-signer` separately. `update-policy` only updates active AMD TCB floors and deprecated global measurements; clearing that global list does not halt admission and emits a CLI warning.

The CLI also exposes `revoke-vcek --chip-id-hash HEX32 --tcb-version U64` for permanent AMD identity revocation across TCB versions (and the selected V2 cache, if present); the fee payer funds the identity tombstone, and `set-gcp-tenant-policy --audience VALUE --subject VALUE` for the mandatory governed GCP tenant policy. See the [full incident procedure and resume examples](../../docs-site/src/content/docs/reference/governance.md#emergency-halt-and-resume).
