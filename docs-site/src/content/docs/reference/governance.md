---
title: Governance and Trust Roots
description: Separate loader and registry authorities and their custody assumptions.
---

The loader upgrade authority can replace verifier code, including pinned roots and authorization rules. `PolicyRegistry.authority` separately authorizes registry writes: measurement/TCB policy and Google JWKS registration/revocation. AMD P-384 root rotation is refused: `rotate_root_cert` returns `InvalidInstruction` even for the registry authority (upstream PR #255). A loader authority transfer does not change the stored registry authority.

| Root | Change path |
| :--- | :--- |
| AMD P-384 `ark_pubkey_xy` | Set at `init_policy_registry`; `rotate_root_cert` refused (#255). No supported production vendor-root meaning under #173 / PR #226 |
| AMD RSA Milan `MILAN_ARK_MODULUS` | Code change and program upgrade |
| AWS Nitro `AWS_NITRO_ROOT_CA_PUBKEY_XY` | Code change and program upgrade |

The coordinated upstream #173 fix / PR #226 restricts production AMD verification to pinned Milan RSA. The legacy 96-byte P-384 field does not select a supported AMD vendor root, and the registry authority cannot change it on-chain. Require this fix in the target implementation before relying on that restriction.

The registry signer can be an Ed25519 keypair or a governance PDA signing through CPI. Solana Confidential Compute checks the pubkey and signer privilege. Multisig thresholds and timelocks, if configured, are supplied by the governance program. Repository references to intended Foundation/Squads custody do not prove a deployed vault address, threshold, or completed handoff.

Verify both authorities in the target deployment and check their custody separately. The smoke script initializes with its payer; moving loader authority afterward leaves that registry signer in control.

The following procedure requires the coordinated fixes upstream PR #219 (#161) and upstream PR #229 (#167) in the target program; it does not establish a merge or deployment:

1. Initialize with the canonical loader-owned ProgramData as the fourth account and its current upgrade authority signing. Initialize before finalization. Previously captured registries are not recovered.
2. Transfer registry authority with `rotate_authority`, requiring current and receiving authority signatures in the same transaction. Accounts are `[current authority signer, registry writable, receiving authority signer]`; payload is empty. Governance vault PDAs sign through CPI. There is no pending-state change or recovery after losing the current key.
3. Transfer loader authority separately and verify both resulting custody arrangements.

The coordinated policy fixes upstream PR #230 and upstream PR #231 bound measurement count to eight, retain the legacy measurement payload for compatibility, and prevent ordinary TCB-component decreases. Governance remains trusted for root/key provenance and measurement choices.

The canonical [security model](https://github.com/solana-foundation/confidential-compute/blob/main/SECURITY.md#administrative-authorities-and-trust-roots) records the source boundaries and limitations, including the separate initialization gap upstream issue #161. These descriptions do not establish live deployment state, hardware verification, or SBF feasibility.


### Backend measurement governance

`BackendPolicy` is authoritative for measurement admission: source 1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space, 5 = Intel TDX. Each canonical PDA uses `[b"backend_policy", &[source]]` and holds up to eight measurements. Missing, empty, or mismatched backend policy fails closed. The global `PolicyRegistry.measurement_count` / `measurements` fields and `update_policy` measurement payload are deprecated as runtime controls and retained for state/wire compatibility; clearing that global list does not halt admission. There is no implicit global/backend allowlist AND. Registry authority checks and monotonic AMD TCB floors remain active.

To halt new admission, the registry authority uses `set_backend_policy` with an empty list (`[]`) for each relevant backend; update all relevant policies to halt all backends. Rust exposes `build_set_backend_policy_ix`, TypeScript `buildSetBackendPolicyIx`. This does not revoke existing Mode A sessions: use `revoke_attested_signer` separately for targeted containment. These are source contracts, not evidence of deployment or hardware/SBF validation.

## Emergency halt and resume

Runtime admission and Mode B verification authorize measurements using `BackendPolicy`, never the legacy global measurement list. Source 1 is AMD SEV-SNP, 2 is AWS Nitro, 3 is GCP Confidential Space, and 5 is Intel TDX. Each canonical PDA is derived from `[b"backend_policy", &[source]]` for the target verifier program. Missing or empty backend policy fails closed.

First record the current backend allowlists and verify the target program ID and registry authority. Export a halt for every affected backend:

```bash
# Each invocation exports one unsigned transaction; none is submitted here.
solana-confidential-compute governance --authority "$AUTHORITY" emergency-halt --source 1
solana-confidential-compute governance --authority "$AUTHORITY" emergency-halt --source 2
solana-confidential-compute governance --authority "$AUTHORITY" emergency-halt --source 3
solana-confidential-compute governance --authority "$AUTHORITY" emergency-halt --source 5
```

Each export contains the existing `set_backend_policy` instruction with an empty list, the authority signer, readonly registry, writable backend PDA, fee payer signer, and System Program. `--fee-payer PUBKEY` defaults to the authority; use `--program-id PUBKEY` for a different verifier. The CLI never loads keys, contacts RPC, or broadcasts. Replace the zero blockhash, collect all required signatures externally (or execute through the authority's governance program), submit, and check transaction success. Then read the canonical backend PDA and verify its source and `measurement_count == 0`. An exported payload or a governance log alone is not evidence of containment.

All-backend containment requires successful submission and verification for all three sources. Three fixed-size setter instructions exceed a standard Solana packet, so the CLI exports separate transactions. Other backends remain open until their own halt is confirmed. Exporting `set-backend-policy --source N` without any `--measurement` has the same effect.

Once admission is contained, revoke compromised existing Mode A records separately:

```bash
solana-confidential-compute governance --authority "$AUTHORITY" revoke-attested-signer --signer "$SIGNER"
```

Backend halt does not invalidate sessions that are already registered. Disable compromised JWT issuers with `revoke-jwks-key` as needed; for AMD cache containment the CLI now exposes:

```bash
solana-confidential-compute governance --authority "$AUTHORITY" revoke-vcek \
  --chip-id-hash "$CHIP_ID_SHA256_HEX" --tcb-version "$PACKED_TCB_DECIMAL"
```

The effective AMD identity hash is exactly 32 bytes of hex (normally SHA-256 of the 64-byte chip ID; the zero-chip-ID path uses SHA-256 of the VCEK public key). The TCB is the packed unsigned 64-bit reported TCB version in decimal. Revocation creates a permanent identity tombstone across all TCB versions and marks the selected V2 cache revoked if present. The fee payer funds that tombstone; the exported instruction includes the writable identity PDA, payer signer and System Program. It does not revoke already issued sessions or a different effective identity. Keep the affected backend halted while handling all affected identities and sessions.

Resume only with explicit reviewed measurements:

```bash
solana-confidential-compute governance --authority "$AUTHORITY" set-backend-policy --source 1 \
  --measurement "$REVIEWED_AMD_MEASUREMENT_48_BYTE_HEX"
solana-confidential-compute governance --authority "$AUTHORITY" set-backend-policy --source 2 \
  --measurement "$REVIEWED_NITRO_PCR0_48_BYTE_HEX"
solana-confidential-compute governance --authority "$AUTHORITY" set-backend-policy --source 3 \
  --measurement "$REVIEWED_GCP_DIGEST_WITH_16_ZERO_BYTES_HEX"
solana-confidential-compute governance --authority "$AUTHORITY" set-backend-policy --source 5 \
  --measurement "$REVIEWED_TDX_MEASUREMENT_48_BYTE_HEX"
```

Repeat `--measurement` for up to eight 48-byte entries. GCP encodes its 32-byte image digest followed by 16 zero bytes. This replaces the entire list; retain only reviewed entries. Sign, submit, check success, and read back the backend PDA. Resume remains subject to all other trust, freshness, replay, tenant and AMD TCB checks. It does not undo VCEK, signer, or JWKS revocation.

GCP's mandatory governed tenant configuration is also reachable from the CLI:

```bash
solana-confidential-compute governance --authority "$AUTHORITY" set-gcp-tenant-policy \
  --audience "$EXPECTED_AUDIENCE" --subject "$EXPECTED_SUBJECT"
```

Audience and subject must be nonempty, non-NUL UTF-8, at most 128 and 160 bytes respectively. They must match the expected workload; token claims do not select their own trust scope. This setter changes the tenant policy, not the backend allowlist. Verify the `gcp_tenant_policy` PDA after submission.

`update-policy` remains available for monotonic AMD TCB floors and legacy global measurement bytes. Its global measurement payload is deprecated and the CLI emits a warning: clearing it does **not** halt admission. The registry/account and instruction layouts remain compatible with existing clients. This follows the per-backend design of upstream issue #266 and upstream PR #280.
