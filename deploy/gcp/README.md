# Manual GCP confidential VM demo

**This optional example costs money. Run `make teardown` when finished.** It is
an unmaintained example, validated locally only: no real Terraform plan, apply,
destroy, VM boot, hardware capture, or Solana submission was performed to qualify
it. It targets GCP AMD hardware and implements the manual path in upstream issue #317.
Choose the runtime explicitly: native SNP, or the Confidential Space launcher
reference described below. Machine, boot image, container digest and provider
configuration have **no defaults**; the operator supplies them.

The current endpoint is a real hardware report verified **locally**, plus explicit
demonstrations of the current enrollment/transport limits:

| Step | What it establishes | Current limitation |
| --- | --- | --- |
| Provision / wait | Terraform configuration and guest sidecar startup | Requires an operator's project, authentication, quota and billable resources; untested on GCP |
| Attest / fetch / verify | SNP report signature, pinned Milan certificate chain, certificate dates, chip/TCB, report security flags, workload key and slot-hash binding | Does not approve the boot measurement or authenticate an application binary |
| Enroll / Mode A | Builds enrollment by default; `--submit` attempts existing staged on-chain enrollment and reads the confirmed signer record | Authentic SBF P-384 verification remains blocked by upstream issue #265; registry/backend policy and a matching VCEK cache must already be provisioned by their authority |
| Mode B | Captures an action-bound hardware report and exercises the public SDK's packet guard | Raw SNP evidence exceeds Solana's 1,232-byte packet limit; staged Mode B is unsupported; returns nonzero without broadcasting |

A missing account, policy rejection, stale nonce, RPC error, or `Custom(2)` is an
error, never successful verification. A dry-run is labeled simulated and does not
enable signing. These helpers neither add a P-384 runtime nor bypass its checks.
The reference consumer also pins a sample measurement; accepting an arbitrary new
VM would require an independently reviewed consumer/policy configuration. Mode A
here checks enrollment, not a successful downstream consumer action.


## What gets created

Terraform creates one operator-selected N2D VM on **AMD Milan**, a dedicated
VPC/subnet, an ephemeral external IP for downloads/RPC, an IAP-only TCP/22 firewall
rule, and a dedicated service account. No service-account keys are created. The
sidecar binds only to `127.0.0.1:8080`; no HTTP port is exposed. Terraform state
is local; there is no remote backend or deployment workflow.

| Required `provider_config` | `native_snp` | `confidential_space` |
| --- | --- | --- |
| `confidential_instance_type` | `SEV_SNP` | `SEV` |
| Operator-supplied boot image | Ubuntu from `ubuntu-os-cloud` | From `confidential-space-images` |
| Startup | Native bootstrap below | Google launcher starts the supplied digest-pinned container; no Ubuntu startup script |
| Maintenance | `TERMINATE` | `MIGRATE` |
| Runtime IAM | No project roles/scopes | `roles/confidentialcomputing.workloadUser`, `cloud-platform` scope; private registry access scoped separately |
| Sidecar provider | `amd-sev-snp` / `/dev/sev-guest` | `gcp-confidential-space` / launcher socket from #307 |
| Manual access | OS Login / IAP SSH and SNP helpers | Production image disables SSH; VM status/serial diagnostics only in this wrapper |

Google currently documents Confidential Space with **SEV or TDX**, not SEV-SNP.
This AMD example therefore rejects `confidential_space + SEV_SNP` and rejects an
Ubuntu image with the launcher provider. It does not silently downgrade a native
SNP deployment. See [Confidential Space deployment](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads)
and its [security model](https://docs.cloud.google.com/docs/security/confidential-space).

For `native_snp`, the startup script installs build prerequisites and the repository-pinned Rust
toolchain, checks out the required immutable Git SHA, builds `solana-confidential-compute-sidecar` and
the `gcp-demo` example, and starts `solana-confidential-compute-sidecar.service` as user `confidential-compute` in
`amd-sev-snp` mode with `DRY_RUN=true`. Only that user's group can access
`/dev/sev-guest` (0660). It does not install a Solana payer or submit transactions.
Heartbeat enrollment errors about the missing payer are expected with this
default; the API still starts. The helper supplies an in-memory throwaway payer
for its dry-run enrollment.
The daemon's existing heartbeat also reads the Solana RPC and requests SNP
reports every 30 seconds before rejecting the missing payer; dry-run prevents
broadcasts, while `make attest` performs the explicit certificate/signature check.

An SNP report measures the guest launch. Installing code at boot does **not**
cryptographically bind that downloaded sidecar build to the SNP launch
measurement. The operator, guest OS, Git/Rust/package sources, boot image and
startup script remain trusted in this example. This is a demo VM, not a hardened
reproducible appliance or Confidential Space/OIDC deployment.

The default zone is `us-central1-c`, which worked in the recorded
[hardware run](../../docs/verification/hardware-verification-gcp-sev-snp.md).
[Google's supported configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations)
list current SEV-SNP zones. C3 with Intel TDX is a future option only: it requires
a different attestation implementation and is not selectable in this module.

### Reported manual GCP reference after #307

On 2026-10-21, a team member reported a manual test result: GCP ran successfully
after merged upstream PR #307. Credit that
run as a human-reported working GCP reference; it was not repeated or inspected
as part of this Terraform implementation. The report does not identify the
machine type, boot image, container digest, sidecar flags or on-chain outcome.

Reading #307 establishes the provider contract: `gcp-confidential-space` uses
the Confidential Space launcher socket `/run/container_launcher/teeserver.sock`
and `POST http://localhost/v1/token`, with `token_type: "OIDC"`, the configured
audience (default `solana-confidential-compute-verifier`), and the ordered workload-key/slot-hash nonce
pair. It replaces the GCE metadata identity-token request; that endpoint cannot
provide this custom-nonce contract. The selected source SHA must include #307
if using that provider. This demo's source already includes its merge.

The `native_snp` choice follows the recorded raw SNP N2D/Milan/Ubuntu path above.
The `confidential_space` choice wires the #307 launcher contract through Google's
boot image and `tee-image-reference` / `tee-env-*` metadata. It never installs an
imaginary launcher on Ubuntu. The reported run's actual backend and deployment
values remain unspecified; the required inputs below must be supplied rather
than inferred from #307. Neither configuration is newly cloud-qualified here.

For the launcher path, the **existing supplied image** must start `solana-confidential-compute-sidecar`
as its entrypoint, contain #307, and allow the metadata environment overrides in
its `tee.launch_policy.allow_env_override` launch policy. The required names are
`SOLANA_CC_ENCLAVE_MODE`, `SOLANA_CC_BIND_ADDR`, `SOLANA_CC_SOLANA_RPC_URL`,
`SOLANA_CC_VERIFIER_PROGRAM_ID`, `SOLANA_CC_CONTAINER_IMAGE_DIGEST`, `DRY_RUN`, and
`SOLANA_CC_ALLOWED_CONSUMER_PROGRAM_ID` if used. Otherwise the launcher ignores those
overrides. Obtain that image/digest and its launch-policy evidence from the tested
image's publisher; this task neither builds nor publishes it. See Google's
[launch policies](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies).
Terraform sets dry-run, loopback and the expected image digest explicitly. It
does not inject a payer, allow a debug image as trusted, expose the HTTP signer,
or arrange private registry credentials.

`make provision`, `status`, `logs`, `wait`, and `teardown` support both choices.
For Confidential Space, `wait` proves only VM `RUNNING`, and `logs` reads serial
diagnostics. The SNP capture/enrollment helpers and SSH commands refuse that
mode. Use the supplied workload's runbook for launcher-issued token retrieval,
authenticated JWT verification and enrollment. Its public image, launch policy,
JWKS/tenant policy and protected payer setup are operator inputs; a synthetic
GCP dry-run response cannot prove Google issuance or successful enrollment.

## Inputs the operator must supply

- A billing-enabled GCP project with the Compute Engine and IAP APIs enabled,
  N2D CPU quota and SEV-SNP capacity in the selected zone.
  The launcher choice also needs the Confidential Computing API and the
  permission to grant its single runtime IAM role. Private Artifact Registry
  workloads need the relevant API and repository-scoped reader permission.
- GCP CLI authentication for the operator and Application Default Credentials
  for Terraform. Do not send credentials to the agent or put them in the repo.
- Permissions to create/delete the VM, disk, VPC/subnet, firewall and service
  account, and to attach that account (`iam.serviceAccounts.actAs`). For IAP SSH,
  the operator needs IAP tunnel access, OS Admin Login, and Service Account User
  on the attached account. The native runtime account needs no project roles;
  the launcher account receives only the attestation role listed above.
- An immutable 40-character public Git commit SHA containing this demo. The
  guest fetches that commit from `https://github.com/solana-foundation/confidential-compute.git`.
- A public, unauthenticated Solana RPC URL (devnet by default) and the recipient's
  own verifier program ID. Terraform metadata/state must not contain RPC API
  tokens. For localnet, the RPC must be reachable **from the VM**; `localhost`
  on the workstation is not reachable there. Establish a private route/tunnel
  separately; do not expose an unrestricted validator RPC.
- For optional live enrollment: a funded devnet/localnet fee-payer JSON keypair
  outside the checkout, an owned verifier deployment, its upgrade/registry
  authority, approved measurements/TCB floors/backend policy, and the matching
  VCEK cache. A future positive demo additionally needs #265 resolved and Mode B
  transport support. Never use existing deployment keys.
- An explicit consumer program ID for the Mode B packet demonstration. It is
  public input; this command sends no consumer transaction.

Required runtime inputs have no real defaults or guessed values:

| Input | Where the operator gets it | Wiring |
| --- | --- | --- |
| `machine_type` | The manually tested VM details; confirm current N2D quota/capacity | VM machine type, restricted to this AMD recipe |
| `boot_image` | The tested VM's exact GCE image resource, or a reviewed image from the appropriate Google image project | VM boot disk image; must match provider choice |
| `provider_config` | Select the intended attestation path from the table above and tested sidecar configuration | Confidential type, maintenance, launcher/native startup, IAM and provider environment |
| `container_image` / `container_image_digest` | Tested workload publisher/registry digest and image launch-policy evidence | Launcher image reference and sidecar expected digest; explicitly `""` for both on native SNP |
| `source_ref` | Published public source commit, with #307 for the launcher image | Native source checkout; compare the supplied image's provenance separately |

For native SNP, the recorded configuration is `n2d-standard-4` with Ubuntu 24.04
on Milan in `us-central1-c`; these are reference values, not module defaults.
For Confidential Space, obtain the actual production image and workload digest;
the example file deliberately contains placeholders. Do not substitute a debug
image to obtain SSH: its claims differ and the existing provider policy rejects
debug-enabled evidence.

See Google's [OS Login setup](https://docs.cloud.google.com/compute/docs/oslogin/set-up-oslogin),
[IAP forwarding](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding), and
[service-account authorization](https://docs.cloud.google.com/compute/docs/access/service-accounts).
No IAM grants or API activation are hidden in Terraform or the scripts.

## Local prerequisites and checks (no cloud needed)

Install Terraform 1.9 or newer (below 2.0), GNU Make, Bash, ShellCheck, Python 3, OpenSSL, Git, and the Rust
toolchain from `rust-toolchain.toml`. `gcloud` is needed only for VM operations;
the Solana CLI/SBPF tools are needed only for a recipient's separate program
deployment. TFLint is optional. Provider versions and checksums are committed.
From the repository root:

```bash
make -C deploy/gcp check
# Equivalent Terraform commands; these do not require a project or cloud auth:
terraform -chdir=deploy/gcp fmt -check
terraform -chdir=deploy/gcp init -backend=false -input=false
terraform -chdir=deploy/gcp validate
# Offline Rust fixture/tamper and packet-boundary checks:
cargo test --locked -p solana-confidential-compute-sidecar --example gcp-demo
```

`check` never calls real-project plan/apply, gcloud, or a Solana RPC. Its four
Terraform configuration tests use `mock_provider "google"` with synthetic inputs
only, checking both paths and rejecting mismatched image/provider combinations.
Its eight Python command tests use stub executables. Terraform init downloads
the pinned provider; it does not create resources. On a shared development host,
run the Cargo command through that host's heavy-build queue.

For the existing no-cloud proofs, run `cargo test --locked -p solana-confidential-compute-crypto --test
milan_kds`. The existing [Dockerfile](../../bins/solana-confidential-compute-sidecar/Dockerfile) already
pins Rust 1.98.1, matching the workspace; this VM recipe builds natively and does
not build, publish, or use that container image.

## Manual run

Run these commands yourself, only after choosing a throwaway project and
reviewing the billable resources. They were **not executed against GCP** while
implementing this example.

1. Authenticate and select the intended account/project locally:

   ```bash
   gcloud auth login
   gcloud auth application-default login
   gcloud config set project YOUR_PROJECT_ID
   gcloud auth list
   ```

2. Copy the example configuration, then edit its placeholders. Keep the
   verifier ID and Git SHA explicit. The SHA must already be available in the
   public repository (after merge, use the checked-out commit).

   ```bash
   cd deploy/gcp
   cp terraform.tfvars.example terraform.tfvars
   # Replace ALL required placeholders: project, source_ref, verifier_program_id,
   # machine_type, boot_image, provider_config, container_image/digest.
   # Choose native_snp for the report-capture steps 4–7 below.
   # For confidential_space use the supplied workload runbook after step 3.
   make init
   make provision
   ```

   Terraform displays the resource changes and asks for confirmation. Inspect
   them before typing `yes`. There is no `-auto-approve` default. Outputs include
   the project, VM name, zone and external IP. Keep `terraform.tfstate` until
   cleanup; it is required to destroy exactly this demo. Do not commit state,
   plan files, `.tfvars`, artifacts or payer keys.

3. Wait for the native build and service startup. The default timeout is 30
   minutes; a first build or constrained zone may take longer.

   ```bash
   make wait
   make status
   # On failure:
   make logs
   # Optional longer wait:
   BOOT_TIMEOUT_SECONDS=3600 make wait
   ```

   For native SNP, expected: `Sidecar API is ready`, followed by status JSON for
   `amd_sev_snp`. With no payer, it is not active. Readiness alone is not a
   hardware signature check. For Confidential Space, expected output is only VM
   `RUNNING`; use serial diagnostics and the supplied workload runbook. No SSH
   or HTTP readiness claim is made for that production image.

4. Capture and verify the actual report, then fetch only its public evidence:

   ```bash
   make attest
   make fetch
   make verify
   ```

   `attest` requests a recent confirmed Solana SlotHashes challenge, reads the
   sidecar's current workload public key, issues the SNP ioctl, downloads that
   chip/TCB's VCEK from AMD KDS, and verifies the evidence locally in the VM.
   `fetch` copies only `report.bin`, `vcek.der`, and `manifest.json` to the ignored
   `artifacts/` directory. `verify` repeats the cryptographic checks on the
   workstation without contacting GCP, AMD or Solana. The manifest records the
   expected binding; preserve it with the capture. An offline verification of
   saved evidence does not establish that its slot is still fresh on chain.

5. Demonstrate Mode A enrollment without sending a transaction:

   ```bash
   make enroll
   make mode-a
   ```

   Expected: simulated enrollment, not `active`. Each command creates its own
   fresh workload key **in guest RAM**, attests it, locally verifies its report,
   and exercises the existing enrollment builder. It does not enroll the
   separate daemon's key; the helper key is discarded when the process exits.
   These commands show the enrollment boundary, not a reusable signing session.

6. Optional live attempt: first deploy **your own** verifier and have its
   authority initialize the PolicyRegistry, configure the AMD BackendPolicy
   with an independently approved measurement/TCB, and register the captured
   chip/TCB VCEK in the V2 cache via staged `register_vcek`. These are separate
   authority operations; this module never invents an allowlist or changes
   governance. See the [verifier contract](../../programs/solana-confidential-compute-verifier/README.md),
   [staging SDK](../../crates/solana-confidential-compute-sdk/src/staged.rs), and
   [deployment instructions](../../scripts/README.md).

   The existing Nitro `smoke_test_devnet.ts` uses fixed deployment IDs and a
   sample measurement; it is not a setup script for this AMD VM. A new empty
   verifier will reject enrollment until its authority prepares the accounts.
   Even with those prerequisites, #265 prevents authentic on-chain acceptance
   as shipped. Do not spend deployment fees expecting a positive live result.

   Only when intentionally testing that boundary, put a **demo-only** funded
   payer outside Git/Terraform and install it on the VM privately. For example,
   open `make ssh`, then use a protected channel of your choice to write
   `/var/lib/confidential-compute/demo-payer.json`, owned by `confidential-compute`, mode 0600. Do not pass the
   key bytes in shell arguments, metadata, `.tfvars`, chat or logs. Then:

   ```bash
   make mode-a ARGS='--submit --payer /var/lib/confidential-compute/demo-payer.json'
   ```

   This may spend transaction fees and stage rent before rejection. The
   existing sidecar transport attempts stage cleanup on failure and preserves
   the original error. A confirmed registration followed by cleanup failure
   means the nonce was consumed: do not replay it. Any rejection exits nonzero;
   retain its actual error rather than treating an arbitrary error as proof
   of #265. Only a confirmed live signer record could be reported active.

7. Exercise Mode B's action-bound evidence and packet guard. Set a public
   `consumer_program_id` in the Terraform inputs before provision:

   ```bash
   make mode-b
   ```

   Expected: a nonzero packet-size error from the public SDK before any
   transaction broadcast. This is a documented blocked path, not successful
   atomic verification. The command binds the report to the action commitment;
   it does not reuse the Mode A report or send oversized packets.

8. **Clean up even if any step failed:**

   ```bash
   make teardown
   terraform state list
   ```

   Review the destroy confirmation. After successful destruction, state should
   contain no resources. Destroy removes the VM/boot disk (including any guest
   demo payer), service account, firewall, subnet and network. It does not
   revoke your local GCP login, delete workstation keys, delete artifacts,
   close on-chain accounts or refund Solana fees/rent. Keep only the public
   evidence you need. Never delete state before successful cleanup.

## Costs and troubleshooting

Budget for N2D compute, the SEV-SNP surcharge when selected, persistent disk, external IPv4,
and network egress. Rates vary by region and time; use the official
[Confidential VM pricing](https://cloud.google.com/confidential-computing/confidential-vm/pricing)
and [pricing calculator](https://cloud.google.com/products/calculator) before
applying. There is no automatic expiry. Stopping the VM can retain billable disk
and other resources; use `make teardown` for cleanup.

| Symptom | Action |
| --- | --- |
| `ZONE_RESOURCE_POOL_EXHAUSTED` / insufficient quota | Check N2D quota and another currently supported Milan/SNP zone; update both region and zone, then review Terraform's proposed replacement |
| IAP or SSH denied | Check the selected account, IAP API/tunnel role, OS Admin Login and Service Account User permissions; do not open public SSH as a workaround |
| Slow startup / native build failed | Read `make logs`; inspect free disk/memory. Google notes elevated SNP boot times in some periods. The build uses the pinned commit and locked dependencies; do not substitute a floating branch |
| `/dev/sev-guest` missing / permission denied | Confirm N2D + Milan + SEV_SNP, Ubuntu guest driver, udev ownership and the `confidential-compute` service user; never make the device world-writable |
| Sidecar heartbeat says no payer | Expected at boot. Use the helper's simulated enrollment; live submission requires the separately supplied protected payer |
| AMD KDS unavailable / certificate expired | Check public HTTPS egress and the guest/workstation clock. Preserve actual errors; do not skip the certificate chain or date checks |
| RPC unavailable / stale slot | Use a reachable unauthenticated RPC, retry with a fresh report; captured evidence cannot extend the 150-slot nonce window |
| Enrollment account/policy/runtime rejection | Confirm recipient deployment/accounts and inspect the exact error. #265 is an independent runtime blocker; `Custom(2)` is not acceptance |
| Mode B exceeds 1,232 bytes | Expected current limitation. No oversized send or staged Mode B fallback is provided |
| Lost local state / destroy fails | Recover the correct local state and project before acting. Inspect GCP resources manually with the operator; do not guess or destroy another deployment |

Do not run two applies against the same local state simultaneously. If adapting
this example to a shared remote backend, configure access/locking separately;
remote state is intentionally off by default.
