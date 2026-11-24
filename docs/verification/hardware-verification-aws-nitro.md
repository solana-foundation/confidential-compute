# AWS Nitro Enclaves Hardware Verification Report (Amazon Web Services)

**Date:** 2026-09-25  
**Cloud Provider:** Amazon Web Services (AWS)  
**Instance Name:** `teton-nitro-node`  
**Instance Type:** `c6i.xlarge` (Intel Ice Lake, 4 vCPUs, 8 GiB RAM)  
**AMI:** Amazon Linux 2023 (`al2023-ami-2023.6.*-x86_64`)  
**Enclave Configuration:** Enabled (`nitro-cli 1.5.0`, `allocator.yaml: memory_mib: 2048, cpu_count: 2`)  
**Enclave Name:** `nitro-probe`  
**Enclave ID:** `i-0c801b445eeba3a9e-enc1a0daae7e35adef`  
**Enclave CID:** `20`  
**Issue:** **upstream issue #71**  
**Specs:** `@spec SCC-NITRO-001` `@spec SCC-NITRO-002` `@spec SCC-NITRO-003` `@spec SCC-NITRO-004` `@spec SCC-NITRO-005` `@spec SCC-NITRO-006`  

---

## 1. Hardware & Hypervisor Telemetry

### A. Host System Telemetry
```text
[ec2-user@nitro-host ~]$ nitro-cli --version
Nitro CLI 1.5.0

[ec2-user@nitro-host ~]$ cat /etc/nitro_enclaves/allocator.yaml
memory_mib: 2048
cpu_count: 2

[ec2-user@nitro-host ~]$ nitro-cli describe-enclaves
[]
```

### B. Enclave Launch & Hardware Measurements
```json
{
  "Measurements": {
    "HashAlgorithm": "Sha512_48 { .. }",
    "PCR0": "2a86e61029832fc64b047e727b2f2265eb07215d073cd458bf6debf5e557a43a146916546030cf5dd8398175f8441e66",
    "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
    "PCR2": "cfc7e55365dafbfe29eb90750a83ae38a4ed727402d194f52af6c5714e9afc54714faa9f0989c95fe075b3585b3eefb3"
  }
}
```
- **Execution Mode:** Production (non-debug) verified.
- **PCR0 Status:** Verified non-zero hardware measurement of Enclave Image File (EIF).
- **PCR1 Status:** Bootstrap and kernel measurement verified.
- **PCR2 Status:** Application binary measurement verified.

---

## 2. In-Guest Automated Probe Architecture

Canonical script: [`scripts/run_nitro_hardware_probe.sh`](../../scripts/run_nitro_hardware_probe.sh)

### A. Execution Flow
1. **Container Compilation:** Statically compiles `nsm_probe.c` inside an isolated Alpine musl builder container (`gcc -static -O2`).
2. **EIF Packaging:** Packages `nitro-probe:latest` into `nitro-probe.eif` via `nitro-cli build-enclave`.
3. **Host vsock Listener:** Starts a lightweight Python socket listener on AF_VSOCK `VMADDR_CID_ANY:5005`.
4. **Enclave Boot:** Launches `nitro-probe.eif` with 2 vCPUs and 1024 MiB RAM in production mode.
5. **NSM Attestation Query:** Probe calls `ioctl(fd, 0xC0200A00, &msg)` on `/dev/nsm` with 32-byte `user_data` (`[0x55; 32]`) and 32-byte `nonce` (`[0x77; 32]`).
6. **Vsock Transfer:** Connects to parent EC2 host (CID 3, port 5005) and streams the attestation document.
7. **Artifact Extraction:** Host receives 4,552 bytes, terminates enclave, and outputs binary and base64.

---

## 3. Cryptographic Verification & Audit Findings

### A. Verification Results (`solana-confidential-compute-crypto`)
```text
running 1 test
test nitro::tests::verify_hardware_nitro_attestation_document ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured
```

- **Root CA Public Key:** Verified against pinned AWS Nitro Root CA G1 uncompressed P-384 public key (`AWS_NITRO_ROOT_CA_PUBKEY_XY`).
- **Certificate Chain:** Verified 4 DER X.509 certificates:
  1. AWS Nitro Enclaves Root CA G1 (Root)
  2. Intermediate CA 1 (`577c22caffc0b23f.us-east-2.aws.nitro-enclaves`)
  3. Intermediate CA 2 (`f81d16b798bdf31e.zonal.us-east-2.aws.nitro-enclaves`)
  4. Leaf Certificate (`i-0c801b445eeba3a9e-enc01a0daae7e35adef.us-east-2.aws`)
- **Signature Verification:** ECDSA P-384 signature over RFC 9052 `COSE_Sign1` Sig_structure validated under leaf public key.
- **Payload Bindings:**
  - `user_data`: Verified exact echo of 32 bytes `0x55`.
  - `nonce`: Verified exact echo of 32 bytes `0x77`.
  - `timestamp`: `1790375264897` (2026-09-25 22:27:44 UTC, within certificate validity window).

---

## 4. Hardware Findings (Finding HW-02)

| Sub-Finding | Observation on Genuine Hardware | Remediation Implemented |
| :--- | :--- | :--- |
| **HW-02A: NSM Envelope** | `/dev/nsm` ioctl response wraps COSE Sign1 document inside CBOR map `{"Attestation": {"document": <bytes>}}` (26-byte prefix). | Ingestion logic extracts `document` byte string from CBOR map. |
| **HW-02B: Indefinite-Length Map** | Nitro hypervisor encodes payload map as indefinite-length CBOR (`0xbf...0xff`). | `CborCursor` updated with `IndefiniteMap`, `is_break()`, and `read_break()`. |
| **HW-02C: Major Type 7 Values** | Payload contains `public_key: null` (`0xf6`) when internal key generation is omitted. | `CborCursor` and `skip_cbor_value_depth` updated with `Simple(u8)` handling. |
| **HW-02D: Document Size** | Complete 4-certificate AWS PKI chain is `4,526` bytes (exceeding former `4,096` byte limit). | `MAX_NITRO_DOCUMENT_LEN` raised to `8,192` across `solana-confidential-compute-core` and TypeScript SDK. |

---

## 5. Artifact Commitments

- Raw NSM Response: [`fixtures/nitro_hardware_attestation.bin`](../../fixtures/nitro_hardware_attestation.bin) (`4,552` bytes)
- Extracted COSE Document: [`fixtures/nitro_hardware_document.cose`](../../fixtures/nitro_hardware_document.cose) (`4,526` bytes)
- In-Tree Verification Test: `crates/solana-confidential-compute-crypto/src/nitro.rs::verify_hardware_nitro_attestation_document`
- Runbook Script: [`scripts/run_nitro_hardware_probe.sh`](../../scripts/run_nitro_hardware_probe.sh)

---

## 6. Teardown Confirmation
- EC2 instance `teton-nitro-node` terminated.
- Associated EBS volumes deleted.
- Temporary gist deleted via GitHub API.
- Zero persistent cloud costs incurred.
