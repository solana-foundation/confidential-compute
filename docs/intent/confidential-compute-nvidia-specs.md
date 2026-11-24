# NVIDIA attestation: disabled enrollment and remaining design gates

## Current implementation status

PR #325's original 81-byte instruction accepted a public measurement, fresh
public slot hash and the caller's workload signature. It received no NVIDIA
evidence/certificate, CPU quote, proof or authorized appraiser statement. Anyone
could copy an allowlisted measurement and mint NVIDIA authority in either mode.
Allowlist membership, hashing public inputs and nonce consumption do not
establish hardware identity, model execution or CPU/GPU pairing.

The safe gate rejects both modes with `NvidiaAttestationUnavailable` (custom 18)
before account access or mutation. Invalid packet length/mode is rejected with
`InvalidInstruction`. Dispatch passes the signature verifier, but no crypto
backend, policy entry or extra account can enable this legacy packet.

`solana-confidential-compute-cpi` rejects NVIDIA signer records and atomic packets with
`UnsupportedPlatform`. This includes records minted by the earlier vulnerable
path. Existing consumers must rebuild/upgrade to acquire the check; this fix
does not change deployed binaries. Such records must never be grandfathered into
a genuine attestation namespace or migrated without fresh authenticated evidence.

The live sidecar NVIDIA provider always fails with `GpuAttestationFailed`.
Dry-run bytes and `DEFAULT_H100_GOLDEN_RIM` are synthetic construction fixtures.
The former demo script is disabled before any RPC/transaction. Prior successful
transactions did not demonstrate NVIDIA appraisal or confidential inference.

## Specification catalog

These IDs describe required security properties and remaining work, not shipped
hardware functionality. The upstream #320 v3 specification
takes precedence for genuine enrollment. It requires a separate proof-backed
adapter/record and forbids an implicit oracle/app-key shortcut or mock downgrade.

### @spec SCC-NVIDIA-001: Authenticate evidence and policy

A future adapter must verify full authenticated NVIDIA evidence/appraisal,
including authorized NVIDIA roots/keysets, signatures, certificate/collateral
and revocation/TCB policy, device identity and freshness. Authenticate the CPU
quote and measured runtime as well. A public reference measurement or a local
SPDM-shaped byte string is insufficient. Genuine GPU appraisal remains unbuilt.

### @spec SCC-NVIDIA-002: Bind identity, evidence and runtime

The accepted statement must bind the exact workload key/possession, CPU and GPU
evidence, policy, chain/program domain, one-use challenge and applicable
workload/action. Follow v3's complete REPORTDATA/journal and runtime relationships.
The measured collector's CC/DevTools, device/channel and assignment checks require
qualification. A shared nonce does not prove physical pairing, prevent live
relay/cuckoo attacks or prove per-request GPU execution. State the trust profile.

### @spec SCC-NVIDIA-003: Reference policy is not authorization

Source-4 backend policy entries remain governance-controlled public references.
They cannot authorize a caller to mint a signer or nonce. Genuine proof/policy
acceptance requires the separate immutable versioned policy and adapter in v3.
An alternate trusted-appraiser design would need an explicit reviewed authority,
statement/domain, enrollment/revocation and signature-validation contract; this
patch introduces none.

### @spec SCC-NVIDIA-004: Freshness, replay and expiration

No nonce is consumed while NVIDIA authentication is unavailable. Future genuine
registration must enforce one-use challenges, current policy/domain, evidence
and collateral start/end times, capped expiry and revocation at use, as specified
in v3. A fresh public SlotHashes entry cannot authenticate evidence.

### @spec SCC-NVIDIA-005: Fail closed at registration and consumption

Both legacy modes always reject. No NVIDIA signer is created/renewed, no nonce
account is written and no registration event is emitted. Consumer helpers reject
legacy NVIDIA records and Mode B packets. Re-enabling genuine functionality
requires a reviewed versioned proof adapter and fresh evidence, never a feature
flag, permissive mock, sidecar-only check or governance-added workload key.

## Verification and open qualification

Processor regressions construct canonical source-4 policy, signer/nonce PDAs,
recent SlotHashes and a fresh attacker-owned key. Both copied-measurement modes
must fail through normal and explicit-verifier dispatch without changing account
data or lamports. Active/expired/revoked NVIDIA records must stay unchanged.
Consumer regressions reject legacy NVIDIA records and a matching Mode B packet.
These fixtures prove the rejection gate, not genuine hardware acceptance.

#320 v3 M0–M3 remain open: operator/capacity/custody and runtime qualification,
real DCAP/NRAS captures and authority/collateral, proof guest/verifier integration,
versioned policy/records/challenges, and real packet/CU qualification. No genuine
positive, live GPU/inference, deployment or deployed-binary correspondence is
claimed by this fix.
