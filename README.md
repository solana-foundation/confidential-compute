# Solana Confidential Compute

Hardware-attested verifiable compute for Solana.

> [!WARNING]
> **Do not use this software in its current form.**
>
> - No external security firm has audited this code.
> - This code is not live on mainnet. The only deployment is on Solana Devnet, for tests.
> - The instructions, account layouts and security model can change without notice.
> - Do not use this code to protect funds, keys or production data.

Solana Confidential Compute binds an Ed25519 workload key to a measured enclave. The enclave is an AMD SEV-SNP confidential VM, an AWS Nitro Enclave, or an Intel TDX Trust Domain. The Solana program `solana-confidential-compute-verifier` verifies the hardware report. A consumer program then accepts only that attested key.

Administrative trust stays with the loader upgrade authority and the separate `PolicyRegistry.authority`. Registry governance can change policy without an upgrade. A change to the pinned Nitro and Milan RSA roots requires a code change.

The baseline also has a mutable AMD P-384 field. upstream PR #226 (#173) restricts production AMD to the pinned Milan RSA. In that path, the mutable field has no supported vendor-root meaning. Multisig custody depends on the deployment configuration. See the [authority and trust-root model](SECURITY.md#administrative-authorities-and-trust-roots).

This file is the root documentation for the Solana Confidential Compute repository. The grant closeout narrative is in [docs/milestones/grant-closeout-dossier.md](docs/milestones/grant-closeout-dossier.md).

The [Terraform and manual demo guide](deploy/gcp/README.md) describes an optional GCP demo that the operator runs. The required inputs select native AMD SEV-SNP or a Confidential Space launcher workload. The guide documents local verification and the current limits. Provisioning is billable and is not tested against GCP.

| Item | Value |
| :--- | :--- |
| Repository | [solana-foundation/confidential-compute](https://github.com/solana-foundation/confidential-compute) |
| Documentation portal | Local Astro Starlight portal ([docs-site/README.md](docs-site/README.md)) |
| Integrator quickstart | [15-minute quickstart](docs-site/src/content/docs/integration/quickstart.md) · [GLOSSARY.md](GLOSSARY.md) |
| Release | tag `v1.0.0` |
| Crate version | `0.1.0` (`Cargo.toml` `[workspace.package]`) |
| License | [Apache-2.0](LICENSE) |
| Runtime target | SBPFv3 (`e_flags = 0x3`, SIMD-0178 / SIMD-0500) |
| Grant closeout | [docs/milestones/grant-closeout-dossier.md](docs/milestones/grant-closeout-dossier.md) (`@spec GRANT-M4-001`) |

---

## 1. Executive summary and value proposition

DeFi protocols, tokenized real-world assets, and oracle networks sign with off-chain hot keys. A stolen operator key can move funds or publish a false price in one slot.

Solana Confidential Compute removes that hot key from the operator.

1. The workload generates an Ed25519 key inside encrypted enclave memory.
2. The CPU signs an attestation report. `REPORT_DATA` binds the workload public key. It also binds a fresh Solana slot hash, or a Mode B action commitment.
3. `solana-confidential-compute-verifier` verifies the hardware signature, the certificate chain, the binary measurement, and the nonce.
4. The consumer program runs only when that verification passes.

Supported roots:

- **AMD SEV-SNP** on a Google Cloud confidential VM, through `/dev/sev-guest`.
- **AWS Nitro Enclaves** through `/dev/nsm`, AF_VSOCK, and a COSE Sign1 document under AWS Nitro Root CA G1.
- **Google Cloud OIDC** for a confidential-space image digest. The program verifies it on-chain against a stored JWKS.
- **Intel TDX** (backend source 5). A Trust Domain is a hardware-isolated virtual machine. The CPU encrypts its memory with keys that stay in the processor. A DCAP quote is ECDSA P-256. Solana verifies that signature with the native `secp256r1` precompile. The verification takes two instructions and about 75,000 compute units.

NVIDIA source 4 is reserved. GPU enrollment and atomic authorization are disabled until an authenticated evidence adapter exists. See [NVIDIA status and remaining gates](docs/intent/confidential-compute-nvidia-specs.md).

| Source | Backend | How Solana checks the evidence |
| ---: | :--- | :--- |
| 1 | AMD SEV-SNP | ECDSA P-384. Solana has no P-384 precompile. A P-384 check is a Groth16 proof that `alt_bn128_pairing` verifies. That helper is experimental. It is not the production default. |
| 2 | AWS Nitro | ECDSA P-384, with the same constraint as AMD. |
| 3 | GCP Confidential Space | OIDC JWT. Solana checks it against a stored JWKS key. |
| 4 | NVIDIA Hopper confidential computing | ECDSA P-384, so the same Groth16 path. Enrollment is disabled in this tree. |
| 5 | Intel TDX | ECDSA P-256. Solana uses the native `secp256r1` precompile. It needs no zkVM and no Groth16 proof. |

[GLOSSARY.md](GLOSSARY.md) defines core TEE and Solana attestation terms in plain English. [docs/research/tee-confidential-compute.md](docs/research/tee-confidential-compute.md) is the hardware concepts reference. For a 15-minute integration walkthrough, see [integration/quickstart.md](docs-site/src/content/docs/integration/quickstart.md).

The product goal is a hardware-attested verifiable compute layer for Solana. A compromised operator shell does not reveal the workload private key. DeFi, real-world-asset, and oracle transactions can require the attested key.

This repository records these motivations:

- Loss of an operator key at the scale of the Drift incident (April 2026, stated as $285M in the prior project brief).
- A single oracle Ed25519 signer (`9gKEEcFZsd1PDYBKWAKZi4Sq4ZCUqVX5oTr8kEjdwstR` for Pyth Pro in the same brief). A compromise of that key can move every consumer price in one block.
- Tokenized-fund NAV and redemption flows. These flows need an automated calculation with a hardware measurement, not an unverified operator.

---

## 2. Two-program architecture

`solana-confidential-compute-verifier` performs cryptography and policy. `solana-confidential-compute-consumer-reference` shows how a protocol uses the result.

```
+------------------------------------------------------------------+
| Hardware enclave                                                 |
| AMD SEV-SNP (/dev/sev-guest) or AWS Nitro (/dev/nsm)             |
| Intel TDX: /var/run/dstack.sock, else /dev/tdx-guest             |
|                                                                  |
| 1. Generate an ephemeral Ed25519 key in enclave memory.          |
| 2. Measure the guest (SNP, Nitro PCRs, or TDX MR_TD and RTMRs).  |
| 3. Request a signed report.                                      |
|    REPORT_DATA[0..32]  = workload Ed25519 public key (Mode A)    |
|    REPORT_DATA[32..64] = slot hash, or Mode B commitment         |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
| solana-confidential-compute-verifier                                                   |
| Devnet: EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh              |
|                                                                  |
| 1. Check the vendor signature.                                   |
|    P-384 chain for AMD and Nitro. P-256 precompile for TDX.      |
| 2. Check measurement against its BackendPolicy.                 |
| 3. Check the SlotHashes nonce (age <= 150 slots).                |
| 4. Dispatch Mode A or Mode B.                                    |
+------------------------------------------------------------------+
              |                               |
              | Mode A                        | Mode B
              v                               v
+------------------------------------------------------------------+
| solana-confidential-compute-consumer-reference                                         |
| Devnet: A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ             |
|                                                                  |
| Mode A: read the AttestedSignerAccount PDA (154 bytes).          |
| Mode B: read the previous instruction in sysvar::instructions.   |
+------------------------------------------------------------------+
```

On-chain SBF signature verification delegates to fail-closed instruction introspection against an earlier precompile. See [SECURITY.md](SECURITY.md#8-auditor-scope--runtime-limitations) §8.

`@spec SCC-VERIFY-001` defines SlotHashes freshness for `verify_and_register`. The full catalog is [docs/intent/confidential-compute-verifier-specs.md](docs/intent/confidential-compute-verifier-specs.md).

### 2.1 NVIDIA GPU attestation status

NVIDIA support is scaffolding only. The live sidecar provider always fails with `GpuAttestationFailed`. Dry-run mode fabricates construction bytes. The legacy 81-byte on-chain packet carries a measurement, slot and action hash. It has no NVIDIA signature, no CPU quote, no proof and no authorized appraisal.

Both NVIDIA modes therefore return `NvidiaAttestationUnavailable` (custom 18) before they read or modify accounts. Neither a source-4 allowlist entry nor a workload transaction signature can enable enrollment.

Consumer helpers reject NVIDIA V2 records and NVIDIA atomic packets with `UnsupportedPlatform`. This includes records that the former unauthenticated path created. You must rebuild or upgrade the consumers that are already deployed to receive that rejection. This source change performs no deployment. It cannot revoke records in independently deployed old consumers.

The upstream #320 v3 specification requires a separately qualified proof-backed adapter and versioned records. The [NVIDIA specifications](docs/intent/confidential-compute-nvidia-specs.md) list the identity, evidence, runtime-binding and freshness gates that are still open. Public-input hashes alone do not authenticate the hardware, the CPU/GPU pairing, or the inference.

### 2.2 Intel TDX

Intel TDX runs the workload inside a Trust Domain. That is a virtual machine whose memory the CPU encrypts. The encryption keys stay in the processor. The host cannot read guest memory.

Intel's quoting service returns a DCAP quote. The quote uses ECDSA on the P-256 curve. Solana verifies P-256 with the native `secp256r1` precompile, program id `Secp256r1SigVerify1111111111111111111111111` (SIMD-0075). Intel TDX needs no zero-knowledge proof and no zkVM.

AMD SEV-SNP and NVIDIA Hopper confidential computing sign with ECDSA on P-384. Solana has no P-384 precompile. A P-384 check on Solana needs a Groth16 proof and the `alt_bn128_pairing` syscall. `Groth16SyscallVerifier` in this repository is an experimental prototype. It is not the production default. Section 8 of [SECURITY.md](SECURITY.md#8-auditor-scope--runtime-limitations) describes the fail-closed P-384 path.

One DCAP quote does not fit in a 1,232-byte transaction, because the precompile reads its message from instruction data. Verification uses two instructions on the Devnet program `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`:

1. `verify_tdx_qe_report` (dispatch handler 20). The platform PCK key signs the Quoting Enclave report.
2. `verify_tdx_quote` (dispatch handler 21). The attestation key from step 1 signs the Trust Domain body.

`issue_tdx_challenge` runs first and pins a fresh slot hash. The quote must answer that challenge.

The compute harness in `programs/solana-confidential-compute-verifier/tests/tdx_compute_units.rs` expects 12,000–22,000 CU for the QE step and 40,000–70,000 CU for the quote step. The two steps together are about 75,000 CU. That is under the 200,000 compute-unit default. The harness is ignored unless an SBF artifact is present. These figures are program-test bands, not a recorded Devnet sample.

A successful quote writes the usual Mode A `AttestedSignerAccount` with `EnclaveType::IntelTdx` (value 5). Later transactions use the workload Ed25519 key. The grantee Devnet deployment uses the same program id. These instructions are in this source tree. Deploy a build of this tree before you call them at that address.

---

## 3. Workspace directory map

Workspace members are `crates/*`, `programs/*`, and `bins/*`. Host binaries enable `std`. Library crates `solana-confidential-compute-core` and `solana-confidential-compute-crypto` are `default-features = false` in `[workspace.dependencies]`.

| Path | Role |
| :--- | :--- |
| [`crates/solana-confidential-compute-core`](crates/solana-confidential-compute-core/README.md) | `no_std`-capable domain types and report views. It includes `SnpReportView`, Nitro length constants, and `MAX_NITRO_DOCUMENT_LEN = 8192`. |
| [`crates/solana-confidential-compute-crypto`](crates/solana-confidential-compute-crypto/README.md) | NIST P-384, X.509 DER, CBOR indefinite-map decoder, COSE Sign1, pinned AWS Nitro Root CA G1 (`AWS_NITRO_ROOT_CA_PUBKEY_XY`). It also contains Google JWT (RS256) under `src/jwt/`. |
| [`crates/solana-confidential-compute-cpi`](crates/solana-confidential-compute-cpi/README.md) | On-chain consumer introspection helpers (`assert_attestation_signer`, `assert_attestation_atomic`, `hash_action`). It depends on `solana-program` 2.2. It declares the verifier id. |
| [`crates/solana-confidential-compute-sdk`](crates/solana-confidential-compute-sdk/README.md) | Off-chain Rust client SDK. Transaction builders for Mode A and Mode B. The oversized packers are in `solana_confidential_compute_sdk::internal`. |
| [`programs/solana-confidential-compute-verifier`](programs/solana-confidential-compute-verifier/README.md) | On-chain SBPFv3 attestation program. Devnet program id `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`. |
| [`programs/solana-confidential-compute-consumer-reference`](programs/solana-confidential-compute-consumer-reference/README.md) | Reference consumer for a DeFi, oracle, or RWA program. Devnet program id `A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ`. |
| [`bins/solana-confidential-compute-cli`](bins/solana-confidential-compute-cli/README.md) | Proof-of-enclave CLI. `prove` reads `/dev/sev-guest` or `--mock` and prints a dry-run transaction. Nitro capture is `scripts/run_nitro_hardware_probe.sh`. |
| [`bins/solana-confidential-compute-sidecar`](bins/solana-confidential-compute-sidecar/README.md) | Enclave signing daemon. The modes are `amd-sev-snp`, `aws-nitro`, `gcp-confidential-space`, `nvidia-gpu`, `intel-tdx`, and `mock`. The default bind address is `127.0.0.1:8080`. The default is `DRY_RUN=true`. |
| [`sdks/typescript`](sdks/typescript/README.md) | TypeScript client `@solana/confidential-compute`. Run the tests from this directory. |
| [`SECURITY.md`](SECURITY.md) | Threat model, trust boundaries, `@spec SCC-SEC-*` invariants, and auditor verification commands. |
| [`scripts/`](scripts/README.md) | Operational and verification scripts: SBPFv3 compiler gate (`build-sbpfv3.sh`), AWS Nitro hardware probe (`run_nitro_hardware_probe.sh`), and Devnet smoke harness (`smoke_test_devnet.ts`). |
| [`docs/`](docs/) | High-level design, `@spec` catalog, hardware runbooks, hardware verification proofs (`docs/verification/`), gate reports, closeout dossier. |
| `fixtures/` | Committed hardware artifacts (Milan SNP report, Milan VCEK, Nitro NSM response, Nitro COSE document). |
| [`docs-site/`](docs-site/README.md) | Local Astro Starlight documentation site. Run it locally with `bun run dev`. |

The `declare_id!` sites are:

- `programs/solana-confidential-compute-verifier/src/lib.rs` and `crates/solana-confidential-compute-cpi/src/lib.rs`: `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`
- `programs/solana-confidential-compute-consumer-reference/src/lib.rs`: `A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ`

The program id comes from the deployer keypair at deploy time. A buyer deploys a separate copy and receives a new program id. The ids above belong to the grantee Devnet deployment.

---

## 4. Architectural decisions

### 4.1 Dual-modality verification

`@spec SCC-ARCH-001` covers PDA allocation. Mode A and Mode B are separate instructions.

| Dimension | Mode A | Mode B |
| :--- | :--- | :--- |
| Instruction | `verify_and_register` | `verify_atomic_with_nonce` |
| State | `AttestedSignerAccount` PDA, 154 bytes, seed `[b"attested_signer_v2", signer_pubkey]` | `UsedNonceAccount` PDA, 49 bytes (legacy records: 17 bytes), seed `[b"nonce", signer_pubkey, commitment]`. After 150 slots, `close_stale_nonce` refunds the rent to the payer. |
| Hot path after registration | Native Ed25519 signature. The P-384 verifier does not run again. | Every transaction carries a new attestation instruction. |
| Consumer helper | `solana_confidential_compute_cpi::assert_attestation_signer` | `solana_confidential_compute_cpi::assert_attestation_atomic` |
| Measured consumer check | 355 compute units on Devnet (`@spec SCC-CONSUMER-001`) | about 1,950 compute units (`@spec SCC-CONSUMER-002`) |
| Use | High-frequency oracle or quote updates | One-shot settlement, NAV, or governance |

Mode A uses a session cache. The enclave attests once. Later transactions sign with the workload Ed25519 key, and the consumer reads the PDA. A later transaction spends no verifier P-384 compute units.

The Gate 3 Devnet sample of `execute_session_action` consumed 355 compute units. The Gate 3 program-test note for `execute_atomic_action` is about 1,950 compute units.

Mode B action commitment (`@spec SCC-VERIFY-012`):

```
REPORT_DATA[32..64] = SHA-256(slot_hash || action_hash || consumer_program_id)
```

`action_hash` uses the [V3 canonical full-wire format](SECURITY.md#spec-scc-sec-006). The format contains the ordered account keys with their effective signer and writable flags, and the complete instruction data. Consumers use `hash_action_account_infos`. Clients hash the final compiled message with the final payer. Clients revalidate after they assemble the evidence. The verifier checks the actual next action before it consumes the nonce.

Upgrade the verifier, the consumers, the SDKs and the sidecar together. Obtain fresh V3 evidence. V1 and V2 digests have no fallback.

Mode B transactions use `verify_atomic_with_nonce` (`@spec SCC-SEC-005`, `@spec SCC-VERIFY-011`). The program records nonce consumption on-chain in a `UsedNonceAccount` PDA. This strictly prevents transaction replay.

`@spec SCC-VERIFY-001`: `verify_and_register` checks `sysvar::slot_hashes::ID`, reads the nonce from report bytes `0x070..0x090`, and rejects a nonce older than 150 slots.

### 4.2 SBPFv3 and the Agave v4 toolchain

`@spec SCC-DEPLOY-001`.

SIMD-0500 rejects a new deploy, upgrade, or finalize of an SBPFv0, v1, or v2 program when the gate is active. `solana-confidential-compute-verifier` ships as SBPFv3. It has `e_flags = 0x3`. Syscalls bind at link time with static Murmur3-32 hashes (SIMD-0178).

| Component | Minimum | Project pin |
| :--- | :--- | :--- |
| Solana platform-tools | v1.53 | v1.56 (`SOLANA_CC_SBF_TOOLS_VERSION`, default in `scripts/build-sbpfv3.sh`) |
| `cargo-build-sbf` | A build that accepts `--arch v3` | v4.2.0 or newer passes `-z defs` |
| Agave / Solana CLI | v4.0.0 | v4.4 is the SIMD-0500 feature-gate target |

Platform-tools older than v1.53 must not receive `--arch v3`. Those builds emit a v3 ELF header with v2 semantics.

```bash
bash scripts/build-sbpfv3.sh --self-test
bash scripts/build-sbpfv3.sh
bash scripts/build-sbpfv3.sh --verify
```

The script compiles `programs/solana-confidential-compute-verifier/Cargo.toml` only. A build that passes prints `e_flags=0x3` for `target/deploy/solana_confidential_compute_verifier.so`.

The `v1.0.0` Devnet verifier ELF is 673,784 bytes. The earlier Gate 4 artifact was 618,288 bytes, `e_machine = EM_BPF (0xf7)`. The `v1.0.0` consumer ELF is 127,744 bytes, `e_machine = 0x107`, `e_flags = 0x0`. That consumer header is not SBPFv3. A buyer who redeploys a consumer program compiles it with `cargo-build-sbf --arch v3`.

`@spec SCC-PERF-001` and `@spec SCC-PERF-002` name the verifier compute paths. Section 6.2 lists the measured compute units. The deploy note records a 0 compute-unit runtime delta versus SBPFv0 and an ELF that is 5–15 percent smaller. The ELF omits the dynamic symbol table.

### 4.3 P-384 hardware compatibility

[`@spec SCC-SEC-010`](SECURITY.md#spec-scc-sec-010).

AMD SEV-SNP report signatures are ECDSA P-384 (FIPS 186-4, AMD Publication #56860). The verifier accepts a signature with scalar `s` in `1..n`. It does not require low-S form (`s <= floor(n/2)`). The AMD Platform Security Processor emits both ranges. A high-S signature stays valid under the VCEK.

`solana-confidential-compute-cli` logs a high-S scalar and keeps the original bytes on the wire. The log text is `HIGH_S_WARN` in `bins/solana-confidential-compute-cli/src/tx.rs`.

The signature layout ([`@spec SCC-SEC-009`](SECURITY.md#spec-scc-sec-009)) has a 72-byte little-endian `r` at `0x2A0..0x2E8` and `s` at `0x2E8..0x330`. Bytes 48..72 of each field are zero. The first 48 bytes become the big-endian P-384 scalar.

### 4.4 Indefinite CBOR and AF_VSOCK

The Nitro Security Module returns a CBOR map:

```
{"Attestation": {"document": <COSE_Sign1 bytes>}}
```

The live hypervisor uses an indefinite-length map (`0xbf` … break `0xff`). `CborCursor` in `crates/solana-confidential-compute-crypto/src/cbor.rs` decodes `IndefiniteMap` and the break stop. Major type 7 simple value `0xf6` (`null`) is accepted for `public_key` when the enclave does not pass an internal key.

These are the recorded hardware sizes (`crates/solana-confidential-compute-crypto/src/nitro.rs`, test `verify_hardware_nitro_attestation_document`):

| Artifact | Path | Length |
| :--- | :--- | ---: |
| NSM ioctl response | `fixtures/nitro_hardware_attestation.bin` | 4,552 bytes |
| COSE Sign1 document | bytes `[26..]` of that response, also `fixtures/nitro_hardware_document.cose` | 4,526 bytes |

`MAX_NITRO_DOCUMENT_LEN` is 8,192 in `crates/solana-confidential-compute-core` and in `sdks/typescript`. A 4,526-byte document passes the parser limit. It does not fit in a legacy Solana packet of 1,232 bytes. The Gate 4 smoke test rejected an oversized document locally (`PacketTooLargeError`). The dossier records one such rejection as `8614 > 1232`.

`scripts/run_nitro_hardware_probe.sh` uses this transport:

1. The probe issues `ioctl` `0xC0200A00` (`NSM_REQUEST_ATTESTATION`) on `/dev/nsm`.
2. The enclave connects with `AF_VSOCK` (address family 40) to parent CID 3, port 5005.
3. The parent listens on `VMADDR_CID_ANY` port 5005 and writes `/tmp/nitro_attestation_hardware.bin`.

User data on the recorded probe is 32 bytes of `0x55`. The nonce is 32 bytes of `0x77`.

The SEV-SNP guest path is separate. `SNP_GET_REPORT` is `0xC0205300`. `copy_guest_report_prefix` in `bins/solana-confidential-compute-cli/src/lib.rs` reads a raw AMD report at offset 0. When bytes `0..4` are status 0 and bytes `4..8` are little-endian 1184, it skips the 32-byte PSP `MSG_REPORT_RSP` header. Then it takes the report at offset 32. The canonical report length is 1,184 bytes.

---

## 5. Hardware verification

The closeout nodes were deleted after the runs in the two hardware reports. The steps below provision a new node. Repeat the commands on that node.

Committed fixtures let an auditor repeat the cryptographic check on any host. No cloud VM is required for section 5.1.

### 5.1 Fixture checks on any host

```bash
cargo test -p solana-confidential-compute-crypto --test milan_kds
cargo test -p solana-confidential-compute-crypto --lib verify_hardware_nitro_attestation_document
```

`milan_kds` loads `fixtures/snp_hardware_report_milan.bin` (1,184 bytes) and `fixtures/vcek_milan.der`. It verifies the report signature under the AMD Milan ARK and ASK in `crates/solana-confidential-compute-crypto/tests/data/`.

The Nitro test loads the 4,552-byte NSM response, takes the 4,526-byte COSE Sign1 at offset 26, and verifies it under `AWS_NITRO_ROOT_CA_PUBKEY_XY`.

### 5.2 Google Cloud confidential VM (AMD SEV-SNP)

Evidence: [docs/verification/hardware-verification-gcp-sev-snp.md](docs/verification/hardware-verification-gcp-sev-snp.md).

The successful closeout node was `teton-sev-snp-node`, machine type `n2d-standard-4`, minimum CPU platform AMD Milan, zone `us-central1-c`, kernel `7.0.0-1011-gcp` on Ubuntu 24.04.5 LTS. `dmesg` reported SEV, SEV-ES, and SEV-SNP, at VMPL0, with `/dev/sev-guest` present.

Use an N2D machine type and `--min-cpu-platform="AMD Milan"`. Set the maintenance policy to `TERMINATE`. Live migration is not available with SEV-SNP.

1. Create the VM. Replace the project id. If the zone pool is exhausted, select another SEV-SNP zone. The closeout attempt in `us-central1-a` returned `ZONE_RESOURCE_POOL_EXHAUSTED`. `us-central1-c` succeeded.

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

2. Open a shell on the VM.

```bash
gcloud compute ssh confidential-compute-sev-snp-node --zone="us-central1-c" --project="<YOUR_PROJECT_ID>"
```

3. Confirm the guest driver.

```bash
ls -la /dev/sev-guest
dmesg | grep -i snp
```

`dmesg` must show `SEV-SNP` and `VMPL0`. The device node must exist.

4. Install the build tools.

```bash
sudo apt-get update
sudo apt-get install -y build-essential curl git pkg-config libssl-dev clang
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

5. Grant the login user access to the device for this test VM.

```bash
sudo chmod 0666 /dev/sev-guest
```

6. Clone the repository.

```bash
git clone https://github.com/solana-foundation/confidential-compute.git
cd confidential-compute
```

7. Run the in-guest library tests.

```bash
cargo test -p solana-confidential-compute-core -p solana-confidential-compute-crypto -p solana-confidential-compute-cli
```

The closeout run on AMD Milan reported 91 passed tests for those three packages. The counts are as follows (CLI lib 11, CLI main 24, core 11, crypto lib 33, JWT 12).

8. Build a dry-run attestation transaction from `/dev/sev-guest`.

The CLI subcommands are `prove` and `verify`. `prove` opens `--device` (default `/dev/sev-guest`), issues `SNP_GET_REPORT` (`0xC0205300`), and prints `transaction_base64` and `transaction_hex`. `--dry-run` defaults to `true`. A request with `--dry-run false` returns an error. The binary does not submit the transaction.

`--vcek-pubkey` is required on the hardware path. Pass the 96-byte uncompressed P-384 point `X || Y` as hex. `--mock` is the local path and does not open `/dev/sev-guest`.

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

Run a Mode B dry-run on the same device:

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

9. Derive the Mode A PDA without a cluster call.

```bash
cargo run -p solana-confidential-compute-cli -- verify --pubkey <WORKLOAD_ED25519_PUBKEY>
```

The closeout probe recorded these Milan report fields:

- report version 5
- signature algorithm 1 (P-384 / SHA-384)
- VMPL 0
- debug policy clear
- key select 0 (VCEK)

The saved report in this tree is `fixtures/snp_hardware_report_milan.bin`. The hardware report records the SHA-256 hash of that file: `2e83a575081c72b035e5ad469551d8cda8d7cc29191d9a4842f4c3751899e11c`.

### 5.3 Amazon Web Services Nitro Enclaves

Evidence: [docs/verification/hardware-verification-aws-nitro.md](docs/verification/hardware-verification-aws-nitro.md).

The successful closeout node was `teton-nitro-node`, type `c6i.xlarge` (Intel Ice Lake, 4 vCPUs), Amazon Linux 2023, Nitro CLI 1.5.0. The enclave `nitro-probe` ran in production mode with 2 vCPUs and 1024 MiB. The enclave CID on that run was 20. The probe always dials parent CID 3.

The allocator on that host has `memory_mib: 2048` and `cpu_count: 2` in `/etc/nitro_enclaves/allocator.yaml`. The probe script then starts the enclave with `--cpu-count 2 --memory 1024`.

1. Start an enclave-capable instance. Use a current Amazon Linux 2023 AMI in your region. The instance type must have at least 4 vCPUs. This lets the allocator reserve 2 vCPUs.

```bash
aws ec2 run-instances \
    --image-id <AL2023_AMI_ID> \
    --instance-type c6i.xlarge \
    --key-name "<YOUR_KEYPAIR>" \
    --enclave-options '{"Enabled":true}' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=confidential-compute-nitro-node}]'
```

2. Install the Nitro CLI, Docker, and Python 3. Add the operator to `ne-users` and `docker`. Open a new login session to apply the group membership.

```bash
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker python3 git
sudo usermod -aG ne-users "$USER"
sudo usermod -aG docker "$USER"
```

3. Reserve CPU and memory for enclaves. Set `cpu_count: 2`. Set `memory_mib` to at least 1024. Start the allocator.

```bash
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl enable --now docker.service
```

4. Clone the repository. Run the probe. The script has no flags.

```bash
git clone https://github.com/solana-foundation/confidential-compute.git
cd confidential-compute
bash scripts/run_nitro_hardware_probe.sh
```

The script does these actions, in order:

1. Stop any enclave that runs.
2. Compile `nsm_probe.c` with Alpine musl (`gcc -static -O2`) inside Docker.
3. Build `nitro-probe.eif` with `nitro-cli build-enclave`.
4. Listen on AF_VSOCK port 5005.
5. Run the EIF in production mode (no debug console) with 2 vCPUs and 1024 MiB.
6. Accept the NSM document from parent CID 3.
7. Write `/tmp/nitro_attestation_hardware.bin` and `/tmp/nitro_attestation_hardware.b64`.
8. Terminate the enclave.

5. Compare the captured length with the committed fixture. The closeout capture was 4,552 bytes. The COSE Sign1 inside it is 4,526 bytes.

```bash
wc -c /tmp/nitro_attestation_hardware.bin
```

6. On a checkout that contains the committed fixtures, run the cryptographic test from section 5.1.

These are the recorded PCR values for the enclave image `nitro-probe` on that run:

| Register | Value |
| :--- | :--- |
| PCR0 (EIF image) | `2a86e61029832fc64b047e727b2f2265eb07215d073cd458bf6debf5e557a43a146916546030cf5dd8398175f8441e66` |
| PCR1 (kernel / bootstrap) | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| PCR2 (application) | `cfc7e55365dafbfe29eb90750a83ae38a4ed727402d194f52af6c5714e9afc54714faa9f0989c95fe075b3585b3eefb3` |

The certificate chain in that document has four certificates: AWS Nitro Enclaves Root CA G1, two `us-east-2` intermediates, and leaf `i-0c801b445eeba3a9e-enc01a0daae7e35adef.us-east-2.aws`.

Further operator notes are in [docs/hardware-testing-runbook.md](docs/hardware-testing-runbook.md). The CLI flags in this README match `bins/solana-confidential-compute-cli/src/main.rs`. Use those flags when the runbook and the binary differ.

---

## 6. Devnet deployment and benchmarks

The cluster is Solana Devnet. The release is `v1.0.0`. The upgrade authority is `BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG`. The program data account is `EWShgrBQhkQiTmGTrYm9DuWvUPKRcsbECqXJuGa1BFcX`.

| Component | Address | Status |
| :--- | :--- | :--- |
| `solana-confidential-compute-verifier` | [`EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`](https://explorer.solana.com/address/EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh?cluster=devnet) | Active. SBPFv3 ELF, `e_flags = 0x3`. Slot 505,980,419. 673,784 bytes. |
| `solana-confidential-compute-consumer-reference` | [`A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ`](https://explorer.solana.com/address/A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ?cluster=devnet) | Active. Slot 505,980,264. 127,744 bytes. `e_machine = 0x107`, `e_flags = 0x0`. Buyer redeployments compile with `--arch v3`. |
| `PolicyRegistry` PDA | [`2FX8HZqEXr7x8kHzkhy4KPUuViVt9M6xqhFTB12jaDUf`](https://explorer.solana.com/address/2FX8HZqEXr7x8kHzkhy4KPUuViVt9M6xqhFTB12jaDUf?cluster=devnet) | Initialized |
| Upgrade authority | [`BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG`](https://explorer.solana.com/address/BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG?cluster=devnet) | Active |

### 6.1 Transaction proofs

| Event | Signature | Slot | Result |
| :--- | :--- | ---: | :--- |
| `v1.0.0` `verify_nitro_attestation` Mode A (`mode = 0`) | [`2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH`](https://explorer.solana.com/tx/2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH?cluster=devnet) | Devnet | Fail-closed `Custom(2)` on a 522-byte synthetic COSE document. The parsing path consumed 8,122 compute units. |
| Earlier Gate 4 SBPFv3 upgrade of `solana-confidential-compute-verifier` | [`29h4C33wGxiFTSyvfay3pwUBc1MDCU3AcvYzZJwuCcZFtDR6hzk7Lg57LAr18Bem5Fd9okxmP3pCPRZxGPm5tDf7`](https://explorer.solana.com/tx/29h4C33wGxiFTSyvfay3pwUBc1MDCU3AcvYzZJwuCcZFtDR6hzk7Lg57LAr18Bem5Fd9okxmP3pCPRZxGPm5tDf7?cluster=devnet) | 503,550,668 | Finalized. That artifact was 618,288 bytes. |
| Earlier Gate 4 `verify_nitro_attestation` Mode A | [`S3GWXy9PMFSpxX5LHVWBYZFY4oqokL3Kg5HZvWwXkqxucBn3JKLjw5JowZPwCbeWaXNeDm7a6UVCsR97LGWzkr9`](https://explorer.solana.com/tx/S3GWXy9PMFSpxX5LHVWBYZFY4oqokL3Kg5HZvWwXkqxucBn3JKLjw5JowZPwCbeWaXNeDm7a6UVCsR97LGWzkr9?cluster=devnet) | 503,550,778 | `Custom(2)`. The instruction consumed 7,829 compute units. |

The Gate 4 source is [docs/milestones/gate-4-verification.md](docs/milestones/gate-4-verification.md). The 7,829 compute-unit log line in that report is the `S3GWXy9…` transaction. The `v1.0.0` measurement is `2iEc1e…`.

### 6.2 Compute units

The `v1.0.0` Devnet sample is Nitro Mode A `verify_nitro_attestation` on a 522-byte synthetic COSE Sign1 document. The instruction parsed the document. It aborted at certificate validation. It returned `Custom(2)` (`VerifierError::VerificationFailed`). It did not register a signer. It did not submit the 4,526-byte hardware document.

| Measurement | Instruction | Compute units | Condition |
| :--- | :--- | ---: | :--- |
| `v1.0.0` Devnet parsing path | `verify_nitro_attestation` Mode A | 8,122 | Signature `2iEc1e…buuH`. 522-byte synthetic COSE document. `Custom(2)`. `@spec SCC-PERF-001` |
| Gate 4 Devnet instruction | `verify_nitro_attestation` Mode A | 7,829 | Earlier record. It ended with `custom program error: 0x2`. |
| Gate 4 Devnet transaction | same Gate 4 transaction, plus the compute-budget instruction | 7,979 | Gate 4 §3.2. |
| Policy init | `init_policy_registry` | 7,435 | Devnet. Gate 3 §3.1. |
| Mode A consumer check | `execute_session_action` | 355 | Gate 3 Devnet sample of a rejected call. `@spec SCC-CONSUMER-001` |
| Mode B consumer check | `execute_atomic_action` | about 1,950 | Gate 3 `solana-program-test` note. `@spec SCC-CONSUMER-002` |
| Local mock-crypto | `verify_and_register` (Mode A) | 62,734 | `cu_benchmarks`, 2026-09-20, `--features mock-crypto`. |
| Local mock-crypto | `verify_atomic_with_nonce` (Mode B) | 59,638 | Same harness. `@spec SCC-PERF-002` |
| Intel TDX QE report | `verify_tdx_qe_report` (handler 20) | 12,000–22,000 | Band in `tdx_compute_units.rs`. Ignored without an SBF artifact. |
| Intel TDX quote | `verify_tdx_quote` (handler 21) | 40,000–70,000 | Same harness. Its own `secp256r1` instruction comes first. |
| Intel TDX, both steps | handlers 20 and 21 | about 75,000 | The sum of the two bands is 52,000–92,000. This is under the 200,000 default. |

The mock-crypto rows measure policy and parsing with `MockVerifier`. They are not a P-384 hardware verification on Devnet. The sources are the benchmark harness [`programs/solana-confidential-compute-verifier/tests/cu_benchmarks.rs`](programs/solana-confidential-compute-verifier/tests/cu_benchmarks.rs), [docs/milestones/gate-3-verification.md](docs/milestones/gate-3-verification.md), and [docs/milestones/gate-4-verification.md](docs/milestones/gate-4-verification.md).

The buyer deploys a separate copy. The full steps for registry init and Squads handover are in [docs/milestones/grant-closeout-dossier.md](docs/milestones/grant-closeout-dossier.md) and [docs/handoff/grant-handoff-guide.md](docs/handoff/grant-handoff-guide.md).

```bash
bash scripts/build-sbpfv3.sh
solana program deploy target/deploy/solana_confidential_compute_verifier.so
```

Run the smoke harness:

```bash
NODE_PATH=sdks/typescript/node_modules bun scripts/smoke_test_devnet.ts
```

### 6.3 NVIDIA demo status

`scripts/demo_nvidia_h100.ts` exits before any RPC or transaction. The previous script generated a local key. It submitted a public placeholder measurement. Its transactions demonstrated allowlist membership. The transactions had no NVIDIA hardware identity, no authenticated CPU/GPU binding, and no confidential inference. Its historical success output and transaction links do not count as genuine GPU enrollment.

Use local dry-run sidecar construction and the verifier's rejection tests while the authenticated adapter is not implemented. No live NVIDIA showcase is available in this tree.

---

## 7. Security specifications and verification architecture

Solana Confidential Compute is designed to meet strict, formal security specifications (`@spec SCC-SEC-*`) across the verifier, the consumer helpers, and the enclave clients. [SECURITY.md](SECURITY.md) specifies the full threat model, the trust boundaries, the defense-in-depth matrix, and the verification commands.

### 7.1 Security Invariants

| Specification | Description | Primary Verification Suite |
| :--- | :--- | :--- |
| [`@spec SCC-SEC-001`](SECURITY.md#spec-scc-sec-001) | Rejection of debug and migration guest policies | `test_stage2_rejects_debug_mode` |
| [`@spec SCC-SEC-002`](SECURITY.md#spec-scc-sec-002) | All-zero measurement rejection and allowlist match | `test_stage2_rejects_zero_measurement`, `test_verify_nitro_rejects_unknown_pcr0` |
| [`@spec SCC-SEC-003`](SECURITY.md#spec-scc-sec-003) | Pinned AMD ARK and AWS Nitro Root CA G1 chain validation | `milan_kds`, `verify_hardware_nitro_attestation_document` |
| [`@spec SCC-SEC-004`](SECURITY.md#spec-scc-sec-004) | Slot freshness via `sysvar::slot_hashes` (age $\le 150$ slots) | `test_verify_recent_slot_hash_*` |
| [`@spec SCC-SEC-005`](SECURITY.md#spec-scc-sec-005) | Replay defense and `UsedNonceAccount` PDA nonce record | `test_verify_atomic_requires_nonce`, `test_verify_atomic_with_nonce_happy_mismatch_and_replay` |
| [`@spec SCC-SEC-006`](SECURITY.md#spec-scc-sec-006) | Deterministic action commitment binding | `test_verify_nitro_mode_b_rejects_action_hash_mismatch`, `consumer_tests` |
| [`@spec SCC-SEC-007`](SECURITY.md#spec-scc-sec-007) | Enclave key zeroization on drop and memory hygiene | `drop_zeroizes_the_signing_secret` |
| [`@spec SCC-SEC-008`](SECURITY.md#spec-scc-sec-008) | Safe memory alignment, zero unaligned access, bounded parsers | Unit and integration test suites |
| [`@spec SCC-SEC-009`](SECURITY.md#spec-scc-sec-009) | AMD report signature layout: 72-byte little-endian `r` and `s`, 24-byte zero padding | `signature_r_be`, `signature_s_be` |
| [`@spec SCC-SEC-010`](SECURITY.md#spec-scc-sec-010) | FIPS 186-4 high-S acceptance and CLI telemetry | `log_high_s_if_needed` |

### 7.2 Hardware Verification Evidence

These links lead to hardware attestation captures and reproducible runbooks:

- [docs/verification/hardware-verification-gcp-sev-snp.md](docs/verification/hardware-verification-gcp-sev-snp.md): Genuine GCP AMD SEV-SNP Milan hardware capture.
- [docs/verification/hardware-verification-aws-nitro.md](docs/verification/hardware-verification-aws-nitro.md): Genuine AWS Nitro Enclaves hardware capture.

### 7.3 Milestone Gate Records

| Gate | Record | Status |
| :--- | :--- | :--- |
| Gate 1 | [docs/milestones/gate-1-verification.md](docs/milestones/gate-1-verification.md) | Satisfied |
| Gate 2 | [docs/milestones/gate-2-verification.md](docs/milestones/gate-2-verification.md) | Satisfied |
| Gate 3 | [docs/milestones/gate-3-verification.md](docs/milestones/gate-3-verification.md) | Satisfied |
| Gate 4 | [docs/milestones/gate-4-verification.md](docs/milestones/gate-4-verification.md) | Satisfied for the SBPFv3 deploy and the Nitro Mode A smoke test |
| Milestone 4 dossier | [docs/milestones/grant-closeout-dossier.md](docs/milestones/grant-closeout-dossier.md) | Closeout package |

---

## 8. Build and test

Use [`just`](https://just.systems) to run the tasks. Run the commands from the repository root:

```bash
just install   # cargo-build-sbf and the TypeScript dependencies
just check     # cargo fmt --check and clippy
just test      # Rust, Anchor front end, TypeScript and script suites
just --list    # every recipe
```

Toolchain versions are pinned in `rust-toolchain.toml`, `.nvmrc`, the `packageManager` field of each `package.json`, and the `justfile` variables (`cargo-build-sbf` 4.2.0, platform-tools v1.56).

`cargo test --workspace` on this tree reports 279 passed, 0 failed, and 1 ignored (`test_cu_benchmarks_live_sbf`). `cargo clippy --workspace --all-targets -- -D warnings` reports zero warnings.

For the TypeScript SDK, `just test-ts` runs `tsc` and type-checks the SDK. It then runs `node --test` on `sdks/typescript/test/*.test.cjs`.

For the documentation site (Astro Starlight), `just install-ts` installs its dependencies. To preview or build the technical documentation site locally, run these commands:

```bash
cd docs-site
bun run dev      # Starts local development server at http://localhost:4321
bun run build    # Generates static production build in dist/
```

`cu_benchmarks` loads `target/deploy/solana_confidential_compute_verifier.so`. The test is skipped when that file is absent.

The release profile (`Cargo.toml`) uses `opt-level = 3`, `overflow-checks = true`, and `panic = "abort"`.

---

## 9. Specification anchors

| Anchor | Statement | Primary source |
| :--- | :--- | :--- |
| `@spec SCC-VERIFY-001` | `verify_and_register` checks the SlotHashes sysvar, the nonce at report bytes `0x070..0x090`, and an age of at most 150 slots. | [docs/intent/confidential-compute-verifier-specs.md](docs/intent/confidential-compute-verifier-specs.md) |
| `@spec SCC-ARCH-001` | PDA creation uses `create_account`. Stage 2 nonce and attested-signer PDAs use canonical `find_program_address`, so an alternate bump cannot replay. | Same catalog |
| `@spec SCC-DEPLOY-001` | The deployment ELF is SBPFv3. It has `e_flags = 0x3`. Syscalls use static Murmur3-32 hashes. `scripts/build-sbpfv3.sh` rejects any other flags word. | Same catalog and `scripts/build-sbpfv3.sh` |
| `@spec GRANT-M4-001` | Grant closeout record. The narrative is in the closeout dossier. The hardware evidence is in the two verification reports. | [docs/milestones/grant-closeout-dossier.md](docs/milestones/grant-closeout-dossier.md) |
| `@spec SCC-NVIDIA-002` | Dry-run composite hash construction only. Authenticated GPU/CPU binding is not implemented. | [docs/intent/confidential-compute-nvidia-specs.md](docs/intent/confidential-compute-nvidia-specs.md) |

Related anchors are in the same catalog: `@spec SCC-PERF-001`, `@spec SCC-PERF-002`, `@spec SCC-SEC-009`, `@spec SCC-SEC-010`, `@spec SCC-CONSUMER-001`, `@spec SCC-CONSUMER-002`, `@spec SCC-NITRO-001` through `@spec SCC-NITRO-006`, and `@spec SCC-NVIDIA-001` through `@spec SCC-NVIDIA-005`.

### 9.1 @spec GRANT-M4-001: Grant closeout record

WHEN an auditor or the Solana Foundation reviews the grant closeout, these two requirements apply:

- THE closeout narrative SHALL remain in `docs/milestones/grant-closeout-dossier.md`.
- THE hardware evidence SHALL remain in `docs/verification/hardware-verification-gcp-sev-snp.md` and `docs/verification/hardware-verification-aws-nitro.md`.

This README is the repository documentation. Program ids, paths, and CLI flags in this file match the tree.

---

## 10. Further reading

- [SECURITY.md](SECURITY.md) — security architecture, threat model, trust boundaries, and invariant specifications.
- [docs/handoff/grant-handoff-guide.md](docs/handoff/grant-handoff-guide.md) — grant closeout guide, hardware reproduction, and delivery proofs.
- [docs/high-level-design.md](docs/high-level-design.md) — four-tier design.
- [docs/hardware-testing-runbook.md](docs/hardware-testing-runbook.md) — operator runbook.
- [docs/intent/confidential-compute-verifier-specs.md](docs/intent/confidential-compute-verifier-specs.md) — greppable `@spec` catalog.
- [docs/intent/confidential-compute-nitro-specs.md](docs/intent/confidential-compute-nitro-specs.md) — Nitro specifications.
- [docs/intent/confidential-compute-nvidia-specs.md](docs/intent/confidential-compute-nvidia-specs.md) — NVIDIA Hopper H100 Confidential GPU specifications.


### Current Mode A V2 contract

The current account uses seed `[b"attested_signer_v2", signer_pubkey]`. Its discriminator is `sha256("account:AttestedSignerAccountV2")[..8]` = `[43, 255, 114, 40, 233, 28, 127, 238]`. Its serialized layout is 154 bytes. The bump remains at byte 145 in the layout. Bytes 146..154 contain `expires_unix_timestamp` as a signed little-endian i64.

V1 (`attested_signer`, 146 bytes, V1 discriminator) is historical. The current V2 consumer contract rejects it. Do not pad it or reinterpret it as V2.

A valid session requires both `clock.slot <= expires_slot` and `0 <= clock.unix_timestamp < expires_unix_timestamp`. If the slot equals the slot limit, the session is valid. If the Unix timestamp equals the Unix deadline, the session is expired. Both values come from the trusted Clock, not from caller arguments. A decoder alone does not perform session validation.

Consumer helpers also check these items:

- the owner and the discriminator
- the workload signature and the stored pubkey
- the measurement and the platform that the caller pins

The low-level helper also re-derives the PDA. Registration derives the Unix deadline independently of the slot duration. It also caps GCP sessions at JWT expiry.

The sources are [verifier state](programs/solana-confidential-compute-verifier/src/state.rs), [deadline construction](programs/solana-confidential-compute-verifier/src/processor.rs) (`session_unix_deadline`), [CPI validation](crates/solana-confidential-compute-cpi/src/lib.rs) (`assert_attestation_signer`), [zero-copy adapter](crates/solana-confidential-compute-cpi/src/anchor.rs), and [TypeScript decoder](sdks/typescript/src/index.ts). These source contracts do not establish deployment or fresh hardware/SBF evidence.

### Backend measurement governance

`BackendPolicy` is authoritative for measurement admission. The source numbers are:

- 1 = AMD SEV-SNP
- 2 = AWS Nitro
- 3 = GCP Confidential Space
- 4 = NVIDIA (reserved, does not enroll)
- 5 = Intel TDX

Each canonical PDA uses `[b"backend_policy", &[source]]` and holds up to eight measurements. Missing, empty, or mismatched backend policy fails closed. Registry authority checks and monotonic AMD TCB floors remain active.

The global `PolicyRegistry.measurement_count` / `measurements` fields and `update_policy` measurement payload are deprecated as runtime controls. They are retained for state and wire compatibility. Admission does not halt when you clear that global list. The system does not combine the global allowlist and the backend allowlist with an implicit AND.

To halt new admission, the registry authority uses `set_backend_policy` with an empty list (`[]`) for each relevant backend. Use an empty list for sources 1, 2, 3, and 5 to halt every backend that can enroll. Rust exposes `build_set_backend_policy_ix`, which accepts source `1..=5`. TypeScript exposes `buildSetBackendPolicyIx`.

This does not revoke Mode A sessions that already exist. Use `revoke_attested_signer` separately for targeted containment. These are source contracts, not evidence of deployment or hardware/SBF validation.

### Emergency admission halt and resume

Runtime admission uses source-specific `BackendPolicy` accounts (AMD=1, Nitro=2, GCP=3, Intel TDX=5). Source 4 is reserved and does not enroll.

The operator CLI exports `governance --authority PUBKEY emergency-halt --source N` to empty a backend policy. It also exports `set-backend-policy --source N --measurement HEX` to restore a reviewed allowlist.

To halt every backend that can enroll, sign the halt for sources 1, 2, 3, and 5. Submit each halt. Verify each halt.

If you clear the legacy `update-policy` measurements, admission does not change. Mode A sessions that already exist need a separate, targeted revocation. See the [incident response procedure](docs-site/src/content/docs/reference/governance.md#emergency-halt-and-resume).
