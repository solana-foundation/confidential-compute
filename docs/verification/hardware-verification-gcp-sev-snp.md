# AMD SEV-SNP Hardware Verification Report (Google Cloud Platform)

**Date:** 2026-09-25  
**Instance:** `teton-sev-snp-node`  
**Zone:** `us-central1-c`  
**Machine Type:** `n2d-standard-4` (AMD Milan)  
**Confidential Compute Type:** `SEV_SNP`  
**Internal IP:** `10.128.0.2`  
**External IP:** `34.66.13.188`  
**Kernel:** `GNU/Linux 7.0.0-1011-gcp x86_64` (Ubuntu 24.04.5 LTS)  
**Issue:** #71  
**Specs:** `@spec SCC-CORE-001` `@spec SCC-VERIFY-003` `@spec SCC-VERIFY-009` `@spec SCC-SIDECAR-001`  

---

## 1. Hardware & Driver Telemetry

### A. Device Node
```text
crw------- 1 root root 10, 260 Sep 25 21:01 /dev/sev-guest
```
- Driver: `sev-guest` active.
- Access: `/dev/sev-guest` character device exposed by AMD SEV firmware.

### B. Kernel Ring Buffer Telemetry (`dmesg`)
```text
[    0.717128] Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP
[    0.717540] SEV: Status: SEV SEV-ES SEV-SNP
[    0.838551] SEV: APIC: wakeup_secondary_cpu() replaced with wakeup_cpu_via_vmgexit()
[    0.927633] SEV: Using SNP CPUID table, 57 entries present.
[    0.927636] SEV: SNP running at VMPL0.
[    1.291737] SEV: SNP guest platform devices initialized.
[    1.468509] sev-guest sev-guest: Initialized SEV guest driver (using VMPCK0 communication key)
```
- **Firmware Status:** Authentic hardware AMD SEV-SNP encryption active.
- **VMPL Level:** VMPL0 execution confirmed.
- **Communication Key:** VMPCK0 active for secure ioctl exchange with AMD PSP.

---

## 2. Environment Provisioning & Setup Runbook

### A. Instance Provisioning Command
```bash
~/development/google-cloud-sdk/bin/gcloud compute instances create teton-sev-snp-node \
    --project="YOUR_PROJECT_ID" \
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

### B. Hardware Configuration & Invariants
- **Machine Type Compatibility:** GCP requires `N2D` instances with `--min-cpu-platform="AMD Milan"` for AMD SEV-SNP. `C3D` instances support only legacy SEV.
- **Maintenance Policy:** Must be set to `TERMINATE`. Live migration is unsupported under SEV-SNP memory encryption.
- **Zone Availability:** `us-central1-a` reported `ZONE_RESOURCE_POOL_EXHAUSTED`. Provisioning succeeded immediately in `us-central1-c`.

### C. In-Guest Toolchain & Dependencies
- **OS:** Ubuntu 24.04.5 LTS
- **Kernel:** `7.0.0-1011-gcp x86_64`
- **Toolchain Versions:**
  - `rustup 1.29.1 (d95a37b6a 2026-08-13)`
  - `rustc 1.98.1 (48a229cea 2026-09-01)`
- **System Packages:**
  ```bash
  sudo apt-get update && sudo apt-get install -y build-essential curl git pkg-config libssl-dev clang
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source $HOME/.cargo/env
  ```
- **Driver Node Access:**
  ```bash
  sudo chmod 0666 /dev/sev-guest
  ```

### D. Source Code Deployment & GitHub Authentication
Two verified deployment paths exist:

#### Path 1: Google Cloud SDK Secure Transport (Headless / Zero-Credentials)
```bash
# 1. Stage minimal workspace source on host (202 KB)
tar -czf /tmp/teton_src.tar.gz Cargo.toml Cargo.lock bins crates programs

# 2. Secure transport to Confidential VM
gcloud compute scp /tmp/teton_src.tar.gz teton-sev-snp-node:~/teton_src.tar.gz \
    --project="YOUR_PROJECT_ID" --zone="us-central1-c"

# 3. Remote extract & clean
mkdir -p ~/teton && tar -xzf ~/teton_src.tar.gz -C ~/teton
find ~/teton -name '._*' -delete
```

#### Path 2: GitHub CLI (`gh`) Web-Device Authentication
```bash
sudo apt-get install -y gh
gh auth login
# 1. Select: GitHub.com
# 2. Protocol: SSH
# 3. New SSH key: No (use existing)
# 4. Authenticate: Login with a web browser
# 5. Open https://github.com/login/device and enter one-time device code.
git clone https://github.com/solana-foundation/confidential-compute.git
```

---

## 3. In-Enclave Test Execution

Running the native test suite on the AMD Milan hardware host:
```bash
cd ~/teton && cargo test -p teton-core -p teton-crypto -p teton-cli
```

### Test Suite Results
```text
test result: ok. 11 passed; 0 failed; 0 ignored; finished in 0.06s (teton_cli lib)
test result: ok. 24 passed; 0 failed; 0 ignored; finished in 0.27s (teton_cli main)
test result: ok. 11 passed; 0 failed; 0 ignored; finished in 0.00s (teton_core lib)
test result: ok. 33 passed; 0 failed; 0 ignored; finished in 0.80s (teton_crypto lib)
test result: ok. 12 passed; 0 failed; 0 ignored; finished in 0.01s (jwt_tests)
Total: 91 passed; 0 failed; 0 ignored (100% clean pass on AMD Milan)
```

---

## 4. Live AMD SEV-SNP Hardware Attestation Probe

### A. Linux Kernel `/dev/sev-guest` ioctl Driver Protocol
The Linux `sev-guest` driver uses ioctl `SNP_GET_REPORT` (`0xC0205300`) with structure `snp_guest_request_ioctl`.
The response buffer (`struct snp_report_resp`) delivers a 32-byte firmware/driver prefix followed by the canonical 1,184-byte report:
- `offset 0x00..0x04`: PSP response status (`0x00000000` = SUCCESS)
- `offset 0x04..0x08`: PSP report size (`0x000004A0` = 1,184 bytes)
- `offset 0x08..0x20`: Reserved padding (24 zero bytes)
- `offset 0x20..0x4C0`: Canonical 1,184-byte AMD SEV-SNP Attestation Report

### B. Hardware Verification Execution
Executed in-enclave via `cargo run -p solana-confidential-compute-cli --example verify_live_hardware`:
```text
===============================================================
    TETON HARDWARE VERIFICATION: AMD SEV-SNP (GCP MILAN)
===============================================================
[+] Successfully opened /dev/sev-guest
[+] Sending SNP_GET_REPORT ioctl (0xC0205300) to AMD PSP...
[+] SNP_GET_REPORT succeeded! (rc=0, exitinfo2=0x0)
[+] PSP Status: 0
[+] PSP Report Size: 1184 bytes
[+] SnpReportView created successfully (1,184 bytes)
[+] teton_core::validate_security_invariants() PASSED!
[+] REPORT_DATA exact echo verified against user_data
[+] Signature R padding (24 zero bytes) and Big-Endian extraction: VALID
[+] Signature S padding (24 zero bytes) and Big-Endian extraction: VALID
[+] Saved report binary to snp_hardware_report_milan.bin

--- Hardware Telemetry Summary ---
Report Version:     5
Guest SVN:          0
Guest Policy:       0x0000000000030000
  - SMT Allowed:    true
  - Reserved Bit:   true
  - Debug Mode:     false
  - Migration MA:   false
VMPL Level:         0
Signature Algo:     1 (P-384 / SHA-384)
Current TCB:        0xDE1D000000000004
Reported TCB:       0xDE1D000000000004
  - Bootloader SPL: 4
  - TEE SPL:        0
  - SNP SPL:        29
  - Microcode SPL:  222
FLAGS:              0x00000000
Key Select:         0 (VCEK)
Chip ID:            75bbd2bb8dfeeb00ea0413ffa0f83557331b7aaf30a6be31efa5a43da77f79699545f7cd0d292495c74a572be5f15ac1d7157dadfb7288cc24a2ee131980559c
Measurement:        7dc7c12e55999ef40d78e4d3c83071588d639b914d619bd0ceb422aa5e899ec37d48afec327950d6d0619c2974125acc
Report ID:          23cd5b5a2419631674a54cf461c3bbd56abd6f955fbca68ebddb0c9d412a04fe
Signature R (BE):   ea2bd0fe547713affa3b802810665e6fa56379ca6bb3277b8e12657e9de54911d59770bd874d9c665caf15a9de8aa8da
Signature S (BE):   2d923fb6fd5ffc4d3174080d0e574579bce9b976b585eebb5d1aa528688b99f889daba673a608fc494809b631384fbd2
===============================================================
```

### C. Cryptographic Evidence & Artifact Invariants
- **Artifact Path:** `fixtures/snp_hardware_report_milan.bin`
- **File Size:** Exact 1,184 bytes (`SNP_REPORT_SIZE`)
- **SHA-256 Digest:** `2e83a575081c72b035e5ad469551d8cda8d7cc29191d9a4842f4c3751899e11c`
- **Policy Compliance:** Non-debug (`DEBUG=0`), no migration agent (`MIGRATE_MA=0`), AMD reserved bit valid (`RESERVED_MUST_BE_ONE=1`).
- **Signature Wire Hygiene:** Both R and S scalars contain exactly 24 zero bytes of high padding as mandated by AMD Publication #56860 and verified by `@spec SCC-SEC-009`.

---

## 5. End-to-End Cryptographic Chain of Custody (AMD KDS Resolution)

### A. AMD Key Distribution Service Query
The physical chip ID and reported TCB components were queried directly against AMD KDS:
```bash
curl -s "https://kdsintf.amd.com/vcek/v1/Milan/75bbd2bb8dfeeb00ea0413ffa0f83557331b7aaf30a6be31efa5a43da77f79699545f7cd0d292495c74a572be5f15ac1d7157dadfb7288cc24a2ee131980559c?blSPL=4&teeSPL=0&snpSPL=29&ucodeSPL=222" \
    -o fixtures/vcek_milan.der
```

- **HTTP Status:** `200 OK`
- **Payload Size:** 1,351 bytes (X.509 DER)
- **SHA-256 Digest:** `ad5c22c869cc9970af07e95797eb3aba07a867497b92c356460564d8842a8109`
- **Issuer:** `CN=SEV-Milan, O=Advanced Micro Devices, ST=CA, L=Santa Clara, C=US`
- **Subject:** `CN=SEV-VCEK, O=Advanced Micro Devices, ST=CA, L=Santa Clara, C=US`
- **Product Name Extension (`1.3.6.1.4.1.3704.1.2`):** `Milan-B0`
- **Hardware ID Extension (`1.3.6.1.4.1.3704.1.4`):** Matches chip ID `75bbd2bb8dfeeb00...` exactly.
- **VCEK Public Key (NIST P-384, Uncompressed X||Y):**
  ```text
  7c07add726f00c1e19ec09b91da262de6e9e8f506cca17a6963d550d47c4af70568807cf81722aad5516010ccbd4192c318a3c58d8b2ae9e65ba0e5da3b86d8df383cf4cd54a08212dbd650d6b5d8c14f66c73e4eada07a1d375f6f628bb9756
  ```

### B. In-Enclave Cryptographic Signature Verification
Executed via `cargo run -p solana-confidential-compute-cli --example verify_kds_cert`:
```text
=== Cryptographic Verification of Hardware Report vs AMD KDS Key ===
Verifying ECDSA P-384 signature over 672-byte signed body using AMD KDS VCEK public key...

[+] CRYPTOGRAPHIC ATTESTATION FULLY VERIFIED!
[+] The hardware report signature generated by AMD Milan Silicon
    cryptographically validates against the official AMD KDS VCEK certificate!
```

- Function: `solana_confidential_compute_crypto::p384::verify_snp_report_signature`
- Input: 672-byte signed body (`0x000..0x2A0`), 96-byte (R || S) scalar, 96-byte VCEK public key
- Result: **Mathematical Proof of Execution on Genuine AMD Milan Hardware**

---

## 6. Empirical Findings & Spec Invariant Discovery

### Finding HW-01: Linux `sev-guest` Response Header Prefix (`@spec SCC-CLI-001`)
- **Discovery:** Upstream kernel header `include/uapi/linux/sev-guest.h` defines:
  ```c
  struct snp_report_resp {
      __u8 data[4000];
  };
  ```
  `@spec SCC-CLI-001` initially presumed that the 1,184-byte AMD report starts at offset 0 (`data[0..1184]`).
- **Empirical Reality on Hardware:** On live Linux kernels (tested Ubuntu 24.04 `7.0.0-1011-gcp`), the AMD Platform Security Processor (PSP) prepends a 32-byte message header:
  - `data[0..4]`: PSP Status (`u32`, `0` = SUCCESS)
  - `data[4..8]`: PSP Report Size (`u32`, `0x04A0` = 1,184 bytes)
  - `data[8..32]`: Reserved (`24` zero bytes)
  - `data[32..32+1184]`: The canonical 1,184-byte AMD SEV-SNP attestation report.
- **Resolution:** `copy_guest_report_prefix` and `@spec SCC-CLI-001` must check `data[0..4] == 0`, assert `data[4..8] == 1184`, and slice `data[32..32+1184]`.

---

## 7. Artifacts Preserved
- Authentic hardware report binary: [`fixtures/snp_hardware_report_milan.bin`](../../fixtures/snp_hardware_report_milan.bin) (SHA-256: `2e83a575081c72b035e5ad469551d8cda8d7cc29191d9a4842f4c3751899e11c`)
- Authentic AMD KDS VCEK certificate: [`fixtures/vcek_milan.der`](../../fixtures/vcek_milan.der) (SHA-256: `ad5c22c869cc9970af07e95797eb3aba07a867497b92c356460564d8842a8109`)

---

## 8. Environment Teardown & Resource Cleanup

Following the capture of telemetry, tests, binary artifacts, and cryptographic verification, the VM instance was immediately deleted to prevent unnecessary cloud compute billing.

```bash
gcloud compute instances delete teton-sev-snp-node \
    --project="YOUR_PROJECT_ID" \
    --zone="us-central1-c" \
    --quiet
```

- **Deletion Status:** Completed (`2026-09-25T21:14:26Z`)
- **Remaining Instances:** 0 running in the project
- **Total VM Lifetime:** ~18 minutes





