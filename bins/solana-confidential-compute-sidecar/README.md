# solana-confidential-compute-sidecar

`solana-confidential-compute-sidecar` is the signing daemon that runs beside the workload. It keeps an Ed25519 key in memory. It exposes a loopback HTTP API. A background task refreshes the attestation before the on-chain record expires.

The binary name is `solana-confidential-compute-sidecar`.

The signing and simulation boundaries below describe the coordinated fixes for upstream issue #162, upstream #178 / PR #223, and upstream issue #208. Require their implementations in the selected release; this documentation does not establish a merge, deployment, or hardware/SBF verification.

`@spec SCC-SEC-001` `@spec SCC-VERIFY-001` `@spec SCC-ARCH-001`

```bash
cargo test -p solana-confidential-compute-sidecar
cargo run -p solana-confidential-compute-sidecar -- --help
```

---

## 1. Process picture

```
 +---------------------------------------------------------------+
 | enclave or local dev process                                  |
 |                                                               |
 |  EphemeralKeyManager          HeartbeatDaemon                |
 |  Ed25519 seed in RAM          every poll_interval_secs       |
 |         |                            |                        |
 |         v                            v                        |
 |  axum on 127.0.0.1:8080       if remaining <= buffer:         |
 |   GET  /v1/status             re-attest the same key          |
 |   POST /v1/attest                                            |
 |   POST /v1/sign               requires live attestation       |
 |   POST /v1/renew              attest, then replace             |
 +---------------------------------------------------------------+
            |
            |  attestation transaction (skipped when DRY_RUN=true)
            v
     solana-confidential-compute-verifier
     EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh
```

Default bind is `127.0.0.1:8080`. `validate_loopback_addr` rejects a non-loopback bind. The daemon is a local signer. It is not a public RPC.

---

## 2. Modes and flags

| Flag | Environment | Default |
| :--- | :--- | :--- |
| `--bind-addr` | `SOLANA_CC_BIND_ADDR` | `127.0.0.1:8080` |
| `--enrollment-token-file` | `SOLANA_CC_ENROLLMENT_TOKEN_FILE` | unset (HTTP enrollment disabled) |
| `--enrollment-min-interval-secs` | `SOLANA_CC_ENROLLMENT_MIN_INTERVAL_SECS` | `300` (range 60–86400) |
| `--solana-rpc-url` | `SOLANA_CC_SOLANA_RPC_URL` | `https://api.devnet.solana.com` |
| `--enclave-mode` | `SOLANA_CC_ENCLAVE_MODE` | `mock` |
| `--renewal-buffer-slots` | `SOLANA_CC_RENEWAL_BUFFER_SLOTS` | `5000` |
| `--poll-interval-secs` | `SOLANA_CC_POLL_INTERVAL_SECS` | `30` |
| `--verifier-program-id` | `SOLANA_CC_VERIFIER_PROGRAM_ID` | unset |
| `--payer-keypair-path` | `SOLANA_CC_PAYER_KEYPAIR_PATH` | unset |
| `--dry-run` | `DRY_RUN` | `true` |
| `--container-image-digest` | `SOLANA_CC_CONTAINER_IMAGE_DIGEST` | unset |
| `--allowed-consumer-program-id` | `SOLANA_CC_ALLOWED_CONSUMER_PROGRAM_ID` | unset |

`EnclaveMode` values: `amd-sev-snp`, `aws-nitro`, `gcp-confidential-space`, `nvidia-gpu`, `intel-tdx` (alias `tdx`), `mock`.

`fail_closed_live_mock` rejects `mock` when `dry_run` is false. A live submission requires a hardware mode.

`--enclave-mode nvidia-gpu` selects NVIDIA scaffolding (`NvidiaH100Provider`).
With `--dry-run true`, it fabricates a placeholder measurement and SPDM-shaped
bytes for local construction; `/v1/sign` remains blocked (HTTP 403). With
`--dry-run false`, the provider always returns `GpuAttestationFailed`. It does
not implement NVML/SPDM appraisal, even when GPU device nodes exist. Both
on-chain NVIDIA modes are independently disabled with custom error 18.

`DRY_RUN=true` is the safe default: it builds the attestation transaction without broadcasting. Registration status is `simulated`, not `active`; attestation/renewal responses identify simulation. A simulated expiry (`current_slot + 216000`) is bookkeeping, not confirmed on-chain registration. `/v1/sign` returns HTTP 403 in dry-run mode regardless of local claims or an expiry value. Live signing eligibility requires confirmed on-chain verification; local claims preflight alone cannot activate signing. `DEFAULT_ATTESTATION_TTL_SLOTS` is **216000**.

Local mock:

```bash
cargo run -p solana-confidential-compute-sidecar -- --enclave-mode mock --dry-run true
```

Confidential GPU simulation:

```bash
cargo run -p solana-confidential-compute-sidecar -- --enclave-mode nvidia-gpu --dry-run true
```

Intel TDX dry-run. This returns a synthetic quote and does not open a guest device or socket:

```bash
cargo run -p solana-confidential-compute-sidecar -- --enclave-mode intel-tdx --dry-run true
```

`--enclave-mode tdx` is the same mode. Live mode (`--dry-run false`) probes the guest and refuses the synthetic quote.

---

## 3. Key life cycle

`EphemeralKeyManager::new` draws a key from the OS CSPRNG. The 32-byte seed is stored in `EphemeralSecret`. That wrapper implements `ZeroizeOnDrop`.

```
 generate -----> secret in RAM -----> pubkey published in /v1/status
                      |
                      |  POST /v1/sign
                      v
                 temporary Keypair
                 sign, then wipe the copy
                      |
                      |  authorized POST /v1/renew
                      v
                 attest candidate secret
                 replace on success; old secret zeroized
```

`solana_sdk::Keypair` does not implement `Zeroize`. The daemon keeps the durable seed in `EphemeralSecret` and wipes each temporary `Keypair` after the signature.

The payer file at `--payer-keypair-path` is the fee payer. It is not the workload key.

`POST /v1/sign` takes the key lock first, then the status lock. A renewal cannot rotate the key while a signature is in progress. The sign handler forbids dry-run signing and then requires a live, unexpired attestation represented by `expires_slot`. A missing value returns HTTP 403 and the text `enclave session is not attested`. An expired slot returns HTTP 403 and `attestation_expired`. The request body is a base64 bincode `VersionedTransaction`. Axum rejects a body larger than 65,536 bytes. The decoded transaction is capped at the same size, and a signature count above 64 is rejected before `bincode` allocates. Every instruction must name the configured verifier program, the Compute Budget program, or `--allowed-consumer-program-id` when that flag is set (`@spec SCC-SIDECAR-001`). The verifier instruction must be an attestation discriminator. System transfers and verifier governance instructions stay rejected, including when the consumer id is the System Program. A transaction that never calls the verifier program is rejected.

Every permitted consumer instruction must immediately follow its own nonce-protected Mode B verifier instruction. The verifier's action hash must match V3 over complete consumer instruction bytes and ordered effective signer/writable flags, including duplicates. The screen resolves the complete final message; it does not guess a discriminator width. Empty and arbitrary instruction data follow the same format. V1/V2 digests have no fallback. Upgrade the coordinated verifier/consumer/SDK/screen bundle and obtain fresh V3 evidence. Standalone Mode A registration remains allowed without consumer instructions, but it does not authorize an accompanying consumer action. Address-table lookups are rejected because the signing policy cannot safely resolve loaded account identities. The Google JWT builder and screen use the canonical `solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR` (PR #223).

---

Consumer signing additionally requires a workload-bound Mode B proof from the sidecar's configured backend. SNP `REPORT_DATA[0..32]` or Nitro `user_data` must equal the signing key; the report measurement (SNP measurement or Nitro PCR0) must equal that key's confirmed V2 signer record. The backend must match both configuration and the record. The same record/Clock snapshot supplies the existing session validation.

GCP Mode B authenticates an action commitment without a workload key, so it cannot authorize sidecar consumer signing. GCP Mode A enrollment and verifier-only signing remain supported. The local screen parses identity; on-chain signature, root, measurement policy, tenant, freshness, consent and action checks remain mandatory. A matching identity is not itself proof of valid evidence or live admission.

## 4. HTTP routes

| Method | Path | Behavior |
| :--- | :--- | :--- |
| `GET` | `/v1/status` | Public key, mode, status (`simulated` for dry-run), and expiry bookkeeping. |
| `POST` | `/v1/attest` | Operator token required; attest the current key using a fresh cluster challenge. |
| `POST` | `/v1/sign` | Sign a screened transaction after confirmed live attestation; HTTP 403 in dry-run mode. |
| `POST` | `/v1/renew` | Operator token required; attest a candidate, then replace the key and zeroize the old seed. |

`/v1/attest` and `/v1/renew` require `Authorization: Bearer <operator-token>`.
Without a configured token file they return 403; missing, malformed, duplicate or
incorrect credentials return 401 when enabled. Credentials are checked before any
provider/RPC work or key/status mutation. Loopback binding remains mandatory.

Generate a high-entropy token (32 random bytes encoded as 64 hex characters) in a
secret file readable only by the sidecar and the trusted operator. For example,
provision `/run/secrets/confidential-compute-enrollment-token` with mode 0400, owned by the
sidecar UID, and pass `--enrollment-token-file` with that path. The file accepts
32–128 URL-safe ASCII characters and an optional trailing newline. It is loaded
once at startup; changing it requires a restart. Never pass the token itself in
command-line arguments, URLs or logs. Keep it out of the workload container and
SSRF-accessible configuration. A process with the same UID or access to sidecar
memory/secrets is within this operator trust boundary; use separate users and
secret mounts for untrusted co-located processes.

Both routes share one in-flight enrollment lock and a monotonic cooldown:
`--enrollment-min-interval-secs` defaults to 300 and cannot be below 60. Repeated
or concurrent authorized calls return 429 with `Retry-After`; rejected credentials
do not consume the cooldown. Failed or cancelled attempts consume it. This bounds
operator-triggered submissions as well as rotations; it is not durable idempotency
or a lifetime SOL budget, and restarts reset it. Do not blindly retry ambiguous
submission errors: chain confirmation may have succeeded before a later read or
staging cleanup failed. The heartbeat shares the enrollment lock, remains usable
without an HTTP token, and follows its own configured renewal schedule. Configure
that schedule and the fee payer balance for the intended operating budget.

A rotation enrolls a private candidate while the old session remains usable.
Only a successful enrollment and confirmed-session read replace the key and all
deadlines together. Failure or cancellation retains the old key and deadlines;
its existing expiry and revocation checks still apply. A failed candidate may
have incurred transaction fees before the failure was reported.

Sequence for a new workload:

```
 client                     sidecar                      verifier
   |                          |                              |
   |  POST /v1/attest         |                              |
   | -----------------------> |  fetch report                |
   |                          |  bind pubkey + slot hash     |
   |                          |  (submit if dry_run is false)|
   | <----------------------- |  expires_slot               |
   |                          |                              |
   |  POST /v1/sign           |                              |
   | -----------------------> |  lock key, then status       |
   | <----------------------- |  signed if live + screened   |
```

`@spec SCC-VERIFY-001` still applies when the transaction is submitted. The nonce inside the report must match a `SlotHashes` entry no older than 150 slots. Refresh the report when the slot window moves. Do not reuse a report whose nonce has left the window.

---

## 5. Attestation refresh

`HeartbeatDaemon` sleeps `poll_interval_secs` (default 30). Each wake reads the cluster slot. If no enrollment deadline exists (including after failed initial enrollment), it retries enrollment of the current key at this interval. Repeated failures remain unattested and are retried on later polls; the heartbeat never rotates the key.

Unix-deadline monitoring is tracked by #270 / PR #277 and must be composed with this recovery path. This retry change does not duplicate that deadline implementation.

```
 remaining = expires_slot - current_slot
 if remaining <= renewal_buffer_slots:     # default 5000
     attest_current_key                    # same public key
```

The heartbeat does not rotate the key. A pubkey change during that call returns `KeyError`. `POST /v1/renew` is the route that rotates and zeroizes.

The on-chain TTL is 216000 slots. The buffer of 5000 slots is the early-renewal window. A slot-query error is logged. The loop continues.

`@spec SCC-ARCH-001` names the PDA the submitted transaction creates: `[b"attested_signer", workload_pubkey]`, 146 bytes.

---

## 6. Hardware providers

### 6.1 AMD SEV-SNP

`src/attestation/sev_snp.rs` opens `/dev/sev-guest` and issues `SNP_GET_REPORT` (`0xC0205300`). That value is `_IOWR('S', 0x00, 32)`. The ioctl argument is 32 bytes. The guest request is 96 bytes. `key_sel` is the first byte of the 28-byte reserved tail and is zero.

`attestation_report_prefix` uses the same PSP rule as `solana_confidential_compute_cli::copy_guest_report_prefix`. When `data[0..4]` is zero and `data[4..8]` is little-endian 1184, the 1,184-byte report starts at offset 32. Every other buffer is copied from offset 0.

On the Linux success path the order is fixed:

1. Reject a zero version word.
2. Require `data[0x50..0x90] == user_data`.
3. Build `SnpReportView` from `crates/solana-confidential-compute-core/src/report.rs`.
4. Call `SnpReportView::validate_security_invariants`.

`vcek_cert` on this path is `None`. A non-Linux build returns `IoctlError` and does not call that function.

### 6.2 AWS Nitro

`src/attestation/nitro.rs` opens `/dev/nsm` inside the enclave.

| Constant | Value |
| :--- | :--- |
| `NSM_REQUEST_ATTESTATION` | `0xC0200A00` |
| `NSM_MESSAGE_SIZE` | 32 |
| `NSM_REQUEST_MAX_SIZE` | `0x1000` (4096) |
| `NSM_RESPONSE_MAX_SIZE` | `0x3000` (12288) |

The enclave process issues the ioctl itself. The hardware probe script is the path that uses `AF_VSOCK`. That script dials parent CID **3** on port **5005** and writes the NSM bytes on the parent. This daemon does not open that socket.

`accept_nitro_document` parses the COSE document and compares `user_data` and `nonce`. It does not call `verify_nitro_document`. The signature and the AWS root check run in `solana-confidential-compute-crypto` when a caller invokes that function, and they run again in `solana-confidential-compute-verifier` when a transaction is submitted. With `DRY_RUN=true` the process can return a simulated expiry after parse-and-bind success; this does not authenticate the document or enable signing.

`MAX_NITRO_DOCUMENT_LEN` on the chain is **8192**.

### 6.3 Google Confidential Space

`gcp_oidc.rs` requests a Confidential Space attestation token using `POST http://localhost/v1/token` over `/run/container_launcher/teeserver.sock`, following the [Google Cloud launcher API](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources). The JSON body contains `token_type: "OIDC"`, the configured audience (default `solana-confidential-compute-verifier`), and two `nonces`: unpadded base64url of the workload key and slot hash, in that order. The launcher socket must be available inside the workload; a missing socket or failed response rejects enrollment. Redirects and HTTP proxies are disabled, and requests have a bounded timeout. The response must match the requested audience and nonce pair and pass the existing Confidential Space claims policy.

When `--container-image-digest` is set, a token with a different `image_digest` fails closed. The on-chain check is `verify_google_jwt` against a `JwksAccount`. Local claims preflight is not authenticated RS256 verification. These changes add no local Google RS256 trust source; live signing eligibility follows confirmed on-chain verification, while dry-run remains simulated and cannot sign.

Controlled Unix-socket tests cover this transport; they do not prove Google issuance, hardware attestation, or successful live registration.

### 6.4 NVIDIA Confidential GPU scaffolding

`src/attestation/nvidia_h100.rs` implements a dry-run provider only. Its default
`DEFAULT_H100_GOLDEN_RIM` is a public placeholder, not a measured VBIOS, driver
or model digest. `compute_composite_nonce` hashes the workload key, measurement
and public slot hash; no CPU quote authenticates that hash. `composite_report`
and synthetic SPDM bytes are not verified by the on-chain instruction.

The SDK and sidecar retain legacy packet construction for local fixtures.
`verify_nvidia_attestation` rejects both modes with
`NvidiaAttestationUnavailable` (custom 18), irrespective of policy entries or
workload signatures. No NVIDIA session can be created or renewed through it.
Consumer helpers also reject legacy NVIDIA V2 records.

Live NVIDIA evidence appraisal, authenticated CPU/workload/GPU relationships,
a versioned proof/record and the #320 v3 runtime and policy gates remain open.
See [the NVIDIA status and specifications](../../docs/intent/confidential-compute-nvidia-specs.md).

### 6.5 Intel TDX

`src/attestation/intel_tdx.rs` collects a DCAP quote for `EnclaveMode::IntelTdx`.

An unprivileged container often cannot open `/dev/tdx-guest`. Phala Cloud and NEAR AI Cloud run the dstack guest agent inside the Trust Domain. That agent quotes the TD and serves the DCAP quote on the Unix socket `/var/run/dstack.sock`. The sidecar tries this socket first, because a device ioctl returns a local TDREPORT and a remote verifier cannot check a TDREPORT.

Socket order:

1. `POST /GetQuote` with JSON `{"report_data": "<hex>"}`.
2. JSON-RPC method `tdx_quote` on `POST /` when the first response has no quote.

The request is local HTTP on that socket. Headers are `Host: localhost`, `Content-Type: application/json`, `Content-Length`, and `Connection: close`. This client sends no `Authorization` bearer token. A guest agent that requires a bearer token rejects the request. The probe then tries `/dev/tdx-guest` and `/dev/tdx_guest` with `TDX_CMD_GET_REPORT0`. A candidate is kept only when it has a version-4 DCAP header. If every probe misses, live mode returns `TdxAttestationFailed`. It does not substitute the synthetic quote.

Dry-run builds a quote that starts with `INTEL-TDX-SYNTHETIC-v1` and does not open the socket or the devices. Live mode rejects that prefix.

The 64-byte `REPORTDATA` is SHA-512 of a preimage. That preimage binds the workload key, the slot hash from `issue_tdx_challenge`, the GPU RIM digest, the model digest, and the challenge nonce. `verify_tdx_quote` recomputes the same digest.

---

## 7. Dockerfile

`bins/solana-confidential-compute-sidecar/Dockerfile` builds the daemon image. `bins/solana-confidential-compute-sidecar/Dockerfile.nitro` is not in the tree. The Nitro hardware probe writes `Dockerfile.nitro_probe` at runtime inside `scripts/run_nitro_hardware_probe.sh`.

Live AMD SNP and Nitro Mode A enrollment uses bounded staging: begin, ordered
700-byte uploads, seal, consume, and close, each confirmed separately with a fresh
blockhash. The signed packet is checked against 1,232 bytes before transmission.
Consume requests an explicit 1,400,000 CU ceiling; this is not a measured cost
or proof of SBF feasibility. After begin, errors attempt close/refund and preserve
the original failure. A successful consume followed by failed cleanup reports
that enrollment was confirmed and its nonce consumed; do not retry that nonce.
Upload deadlines never extend attestation freshness, and staged Mode B remains
unsupported. The existing real handler performs crypto, workload consent,
backend policy, source-specific nonce, legacy migration and freshness checks.
Issue #265 is a runtime prerequisite: this transport does not supply or invent
a deployed P-384 verifier and does not establish production readiness.
GCP dry-run enrollment selects a local synthetic JWT before invoking the metadata
provider. It requires no metadata token and never establishes a verified signing
session: status is `simulated` and `/v1/sign` remains disabled. Live enrollment
uses the configured real provider and propagates its failures.
Enrollment reads the canonical confirmed V2 signer record and Clock after transaction
confirmation. `/v1/status` exposes `expires_slot`, `expires_unix_timestamp`,
`current_unix_timestamp`, and `remaining_seconds`; Unix expiry is exclusive.
A live status is `active` only while both limits pass against the trusted Clock.
Unavailable confirmed state is `unknown`, never a cached active assertion.
Heartbeat renews on either the slot buffer or the Unix buffer (60 seconds by
default, independently adjustable with `with_renewal_buffer_seconds`). Failed
refresh preserves the prior deadlines for retry; it does not extend validity.
Simulation has no confirmed Unix deadline and cannot authorize signing.

Workload keys require a distinct external transaction payer and never pay base
fees. Caller Compute Budget instructions must have no accounts, no duplicate
settings, a zero CU price, a CU limit in 1..=1,400,000, heap size in
32..=256 KiB in 1 KiB steps, and loaded account data in 1..=64 MiB. Deprecated
RequestUnits and nonce-less verify_atomic instructions are rejected before signing.
These bounds preserve the full staged consume compute limit without allowing
caller-selected priority fees; all action and consent screening still applies.
