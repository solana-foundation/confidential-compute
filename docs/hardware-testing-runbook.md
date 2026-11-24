# Hardware enclave testing runbook

Commands for a new AMD SEV-SNP guest and a new AWS Nitro Enclaves host. Tag `v1.0.0`.

The CLI subcommands are `prove` and `verify`. `prove` prints `transaction_base64` and `transaction_hex`. It does not submit a transaction. `--dry-run false` returns an error.

Parser for the AMD report: `SnpReportView` in `crates/solana-confidential-compute-core/src/report.rs`.

Evidence already in the tree:

- [hardware-verification-gcp-sev-snp.md](verification/hardware-verification-gcp-sev-snp.md)
- [hardware-verification-aws-nitro.md](verification/hardware-verification-aws-nitro.md)
- `fixtures/snp_hardware_report_milan.bin` (1,184 bytes)
- `fixtures/vcek_milan.der`
- `fixtures/nitro_hardware_attestation.bin` (4,552 bytes)
- `fixtures/nitro_hardware_document.cose` (4,526 bytes)

The closeout VMs were deleted. Repeat the steps on a new node.

---

## 1. Fixture checks on any host

```bash
cargo test -p solana-confidential-compute-crypto --test milan_kds
cargo test -p solana-confidential-compute-crypto --lib verify_hardware_nitro_attestation_document
```

`milan_kds` loads the Milan report and `fixtures/vcek_milan.der`. The Nitro test reads the 4,552-byte NSM response and verifies the COSE Sign1 at offset 26.

---

## 2. Track A — Google Cloud confidential VM (AMD SEV-SNP)

Recorded closeout node: `teton-sev-snp-node`, `n2d-standard-4`, AMD Milan, zone `us-central1-c`, Ubuntu 24.04. `dmesg` showed SEV-SNP at VMPL 0. `/dev/sev-guest` was present. `us-central1-a` returned `ZONE_RESOURCE_POOL_EXHAUSTED` on that attempt.

### 2.1 Create the VM

```bash
gcloud compute instances create confidential-compute-sev-snp-node \
    --project="<YOUR_PROJECT_ID>" \
    --zone="us-central1-c" \
    --machine-type="n2d-standard-4" \
    --min-cpu-platform="AMD Milan" \
    --confidential-compute-type="SEV_SNP" \
    --maintenance-policy="TERMINATE" \
    --image-family="ubuntu-2404-lts-amd64" \
    --image-project="ubuntu-os-cloud" \
    --boot-disk-size="200GB" \
    --metadata=enable-oslogin=TRUE
```

Live migration is not available with SEV-SNP. Use `TERMINATE`.

### 2.2 Confirm the guest driver

```bash
gcloud compute ssh confidential-compute-sev-snp-node --zone="us-central1-c" --project="<YOUR_PROJECT_ID>"
ls -la /dev/sev-guest
dmesg | grep -i snp
sudo chmod 0666 /dev/sev-guest
```

`dmesg` must show `SEV-SNP` and `VMPL0`. The `chmod` is for this test VM. It lets the login user open the device.

### 2.3 Build tools

```bash
sudo apt-get update
sudo apt-get install -y build-essential curl git pkg-config libssl-dev clang
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
git clone https://github.com/solana-foundation/confidential-compute.git
cd confidential-compute
git checkout v1.0.0
```

### 2.4 Ioctl

`SNP_GET_REPORT` is `0xC0205300` (`_IOWR('S', 0x00, 32)`).

| Object | Length | Layout |
| :--- | ---: | :--- |
| `SnpGuestRequestIoctl` | 32 | version, pad, `req_data`, `resp_data`, `exitinfo2` |
| `SnpReportReq` | 96 | `user_data` 64, `vmpl` 4, `key_sel` 1, reserved 27 |
| Guest `data` | 4000 | Kernel write. The 32-byte tail is not written. |

`key_sel` is 0. The CLI asks for a VCEK report.

`copy_guest_report_prefix` in `bins/solana-confidential-compute-cli/src/lib.rs` copies a raw report from offset 0. When bytes `0..4` are 0 and bytes `4..8` are little-endian 1184, the report starts at offset 32.

`prove` then calls `verify_report_locally`. That function calls `SnpReportView::validate_security_invariants` and then `verify_snp_report_signature`.

The sidecar path is `bins/solana-confidential-compute-sidecar/src/attestation/sev_snp.rs`. On Linux, after the `user_data` echo check, `SevSnpProvider` calls `SnpReportView::validate_security_invariants`. `vcek_cert` is `None` on that path.

The value `0xC0485301` is not this ioctl.

### 2.5 Dry-run

`--vcek-pubkey` is required on the hardware path. Pass the 96-byte point `X || Y` as hex. `--nonce-slot` must still be inside the 150-slot `SlotHashes` window.

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

Mode B on the same device:

```bash
cargo run -p solana-confidential-compute-cli -- prove \
    --mode atomic \
    --action-hash <64_HEX_CHARS> \
    --consumer-program A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ \
    --device /dev/sev-guest \
    --vcek-pubkey <96_BYTE_XY_HEX> \
    --nonce-slot <RECENT_SLOT> \
    --slot-hash <32_BYTE_SLOT_HASH_HEX> \
    --dry-run true
```

Derive the Mode A PDA. This command does not call RPC.

```bash
cargo run -p solana-confidential-compute-cli -- verify --pubkey <WORKLOAD_ED25519_PUBKEY>
```

There is no `attestation fetch` subcommand and no `devnet-verify` subcommand.

---

## 3. Track B — AWS Nitro Enclaves

Recorded closeout node: `teton-nitro-node`, `c6i.xlarge`, Intel Ice Lake, Amazon Linux 2023, Nitro CLI 1.5.0. The enclave ran in production mode with 2 vCPUs and 1024 MiB. Enclave CID on that run was 20. The probe dials parent CID **3** on port **5005**. `AF_VSOCK` is 40.

`bins/solana-confidential-compute-sidecar/Dockerfile.nitro` is not in the tree. Do not pass `-f bins/solana-confidential-compute-sidecar/Dockerfile.nitro`. The probe writes `Dockerfile.nitro_probe` at runtime inside `scripts/run_nitro_hardware_probe.sh`.

The in-enclave ioctl is `NSM_REQUEST_ATTESTATION` (`0xC0200A00`) in `bins/solana-confidential-compute-sidecar/src/attestation/nitro.rs`. The probe script is the path that uses `AF_VSOCK`. The CLI does not open `/dev/nsm`.

### 3.1 Instance

Use a current Amazon Linux 2023 AMI in your region. The type needs at least 4 vCPUs so the allocator can reserve 2.

```bash
aws ec2 run-instances \
    --image-id <AL2023_AMI_ID> \
    --instance-type c6i.xlarge \
    --key-name "<YOUR_KEYPAIR>" \
    --enclave-options '{"Enabled":true}' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=confidential-compute-nitro-node}]'
```

### 3.2 Host packages

```bash
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker python3 git
sudo usermod -aG ne-users "$USER"
sudo usermod -aG docker "$USER"
```

Open a new login so the groups apply. Set `cpu_count: 2` and `memory_mib` of at least 1024 in the allocator file. Then:

```bash
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl enable --now docker.service
git clone https://github.com/solana-foundation/confidential-compute.git
cd confidential-compute
git checkout v1.0.0
bash scripts/run_nitro_hardware_probe.sh
```

The script has no flags. It stops a running enclave, builds a static `nsm_probe` with Alpine musl, builds `nitro-probe.eif`, listens on port 5005, runs the EIF with 2 vCPUs and 1024 MiB in production mode, writes `/tmp/nitro_attestation_hardware.bin` and `/tmp/nitro_attestation_hardware.b64`, and terminates the enclave.

```bash
wc -c /tmp/nitro_attestation_hardware.bin
```

The closeout capture was 4,552 bytes. The COSE Sign1 inside it is 4,526 bytes. `parse_nitro_payload` in `solana-confidential-compute-cpi` accepts the indefinite map (`0xbf` … `0xff`) and CBOR `null` (`0xf6`).

Recorded PCR0, PCR1, and PCR2 for image `nitro-probe` are in the root `README.md` section 5.3 and in the AWS hardware report linked above.

---

## 4. Devnet smoke record

`scripts/smoke_test_devnet.ts` submits `verify_nitro_attestation` Mode A. A raw Mode B report is rejected locally with `PacketTooLargeError` and is not submitted. Payer resolution: `PAYER_KEYPAIR_PATH`, then `SOLANA_KEYPAIR_PATH`, then `~/.config/solana/id.json`.

```bash
NODE_PATH=sdks/typescript/node_modules bun scripts/smoke_test_devnet.ts
```

Recorded v1.0.0 transaction: [`2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH`](https://explorer.solana.com/tx/2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH?cluster=devnet).

| Field | Value |
| :--- | :--- |
| Slot | 505,980,579 |
| Verifier log | `consumed 8122 of 549850 compute units` |
| Transaction meta | `computeUnitsConsumed` 8,272 |
| Result | `Custom(2)` = `VerifierError::VerificationFailed` |

That result is the fail-closed path. The harness treats this error as a completed smoke run. Do not require the log line `Program EKfHCT… success`.

Verifier ELF on that slot's program-data account: 673,784 bytes, `e_flags = 0x3`. Consumer ELF: 127,744 bytes, `e_machine = 0x107`, `e_flags = 0x0`. Details are in the program READMEs.
