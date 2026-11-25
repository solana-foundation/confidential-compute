---
title: Sidecar Daemon
description: In-enclave solana-confidential-compute-sidecar. Linux /dev/nsm and /dev/sev-guest, loopback HTTP, Docker build.
---

`solana-confidential-compute-sidecar` runs **inside** the enclave container. It holds the ephemeral Ed25519 workload key in memory, requests hardware attestation, and exposes a loopback HTTP API to the workload.

## Runtime

| Setting | Default | Rule |
| :--- | :--- | :--- |
| Bind | `127.0.0.1:8080` | Only `127.0.0.1` or `::1`. Other addresses fail closed. |
| `DRY_RUN` | `true` | Build transactions. Submit only when `DRY_RUN=false`. |
| Enclave mode | `mock` | `amd-sev-snp`, `aws-nitro`, `gcp-confidential-space`, `intel-tdx`, `mock` |
| Renewal buffer | 5,000 slots | Heartbeat re-attests before `expires_slot` |
| Poll interval | 30 s | Slot poll for the heartbeat task |
| Payer keypair | unset | Fee payer only. Never the workload signer. |
| Enrollment token file | unset | HTTP attest/renew disabled until configured |
| Enrollment minimum interval | 300 s | Shared HTTP cooldown; range 60–86400 s |

```bash
solana-confidential-compute-sidecar \
  --bind-addr 127.0.0.1:8080 \
  --enclave-mode aws-nitro \
  --solana-rpc-url https://api.devnet.solana.com
```

Environment mirrors the flags: `SOLANA_CC_BIND_ADDR`, `SOLANA_CC_ENCLAVE_MODE`, `SOLANA_CC_SOLANA_RPC_URL`, `SOLANA_CC_PAYER_KEYPAIR_PATH`, `SOLANA_CC_CONTAINER_IMAGE_DIGEST`, `DRY_RUN`.

## Hardware providers

### AMD SEV-SNP — `/dev/sev-guest`

Mode `amd-sev-snp` issues `SNP_GET_REPORT` on Linux. The accepted report is exactly **1,184 bytes**. `REPORT_DATA` must echo the 64-byte user data (pubkey ‖ slot hash or commitment). A size or echo failure is `HardwareUnavailable`. The sidecar does not synthesize a production report.

### AWS Nitro — `/dev/nsm`

Mode `aws-nitro` issues `NSM_REQUEST_ATTESTATION` with `user_data = workload_signer.to_bytes()` and `nonce = slot_hash`. Missing device, open failure, ioctl failure, or a non-Linux host returns `SidecarError::IoctlError`. Mock mode is a separate `EnclaveMode::Mock` path for tests.

### Google Confidential Space

Mode `gcp-confidential-space` fetches an OIDC token. `eat_nonce` is unpadded base64url. Mode A uses two 43-character strings (pubkey, slot hash). Mode B uses one 43-character commitment. When `SOLANA_CC_CONTAINER_IMAGE_DIGEST` is set (`sha256:` plus 64 hex), a mismatched `image_digest` fails closed.

### Intel TDX — `/dev/tdx_guest` & ConfigFS

Mode `intel-tdx` probes `/var/run/dstack.sock`, `/dev/tdx-guest`, and `/dev/tdx_guest` (`TDX_CMD_GET_REPORT0`). The sidecar binds the workload public key into `REPORTDATA`, fetches the DCAP quote, and when `DRY_RUN=false`, broadcasts the complete Solana 4.x v1 enrolment transaction.

## Loopback HTTP

Routes:

| Method | Path | Action |
| :--- | :--- | :--- |
| `GET` | `/v1/status` | Pubkey, expiry, remaining slots |
| `POST` | `/v1/attest` | Operator bearer token required; re-attest the current key |
| `POST` | `/v1/sign` | Sign a payload with the workload key |
| `POST` | `/v1/renew` | Operator bearer token required; attest a candidate, then replace and zeroize |

Configure `--enrollment-token-file` / `SOLANA_CC_ENROLLMENT_TOKEN_FILE` with a secret
file containing a random 32–128 character URL-safe ASCII token (for example,
32 random bytes encoded as 64 hex characters). Use mode 0400, owned by the sidecar
UID, and keep the file and token out of workload containers, SSRF-accessible
configuration, URLs, command-line arguments and logs. A trailing newline is
accepted. The token loads once at startup. Separate Unix users and secret mounts
are required when co-located processes are untrusted; same-UID memory/secret
access remains inside the operator trust boundary.

Send `Authorization: Bearer <operator-token>` on both enrollment routes. Missing
configuration returns 403; missing/invalid credentials return 401. Both routes
share a cooldown configured by `--enrollment-min-interval-secs` /
`SOLANA_CC_ENROLLMENT_MIN_INTERVAL_SECS` (default 300, minimum 60). Concurrent,
repeated and failed authorized attempts are bounded; 429 includes `Retry-After`.
The cooldown resets at restart and is not a durable SOL budget or idempotency key.
Do not blindly retry ambiguous chain submission/cleanup failures.

Heartbeat attests the current key without an HTTP token and uses the same
operation lock with its own renewal schedule. `POST /v1/renew` first attests a
candidate and reads confirmed deadlines, then replaces the active key/status and
zeroizes the old secret. Failures retain the old session and its original expiry;
partially completed submissions may still incur fees.

## Container image

Prebuilt container images are published to the GitHub Container Registry:

```bash
docker pull ghcr.io/solana-foundation/solana-confidential-compute-sidecar:latest
```

| Tag | Source |
| :--- | :--- |
| `latest` | The most recent release tag `vX.Y.Z`. A pre-release tag (for example `v1.1.0-rc.1`) does not move `latest`. |
| `X.Y.Z`, `X.Y` | The release tag `vX.Y.Z`. |
| `sha-<short sha>` | Each push to `main` and each release tag. |

A push to `main` does not move `latest`.

Each published image has a GitHub build provenance attestation. Verify the
attestation before you use the image:

```bash
gh attestation verify \
  oci://ghcr.io/solana-foundation/solana-confidential-compute-sidecar:latest \
  --repo solana-foundation/confidential-compute
```

## Docker build

`bins/solana-confidential-compute-sidecar/Dockerfile` is a two-stage image:

1. `rust:1.82-slim-bookworm` builds `solana-confidential-compute-sidecar` and strips the binary.
2. `gcr.io/distroless/cc-debian12:nonroot` copies the binary. User `nonroot` (uid 65532). `ENTRYPOINT` binds `127.0.0.1:8080`.

From the workspace root:

```bash
docker build -f bins/solana-confidential-compute-sidecar/Dockerfile -t solana-confidential-compute-sidecar:local .
```

Pin the image digest in `SOLANA_CC_CONTAINER_IMAGE_DIGEST` and on the GCP `BackendPolicy` measurement allowlist (source 3).

## Related

- [Threat model](/overview/threat-model/)
- [Mode A](/architecture/mode-a-stateful/)
- [TypeScript SDK](/integration/typescript-sdk/)
