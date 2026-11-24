---
title: Threat Model
description: GCE Confidential VM, AWS Nitro Enclaves, and Intel TDX. Cryptographic guarantees and fail-closed boundaries.
---

Solana Confidential Compute treats the host OS, hypervisor, and cloud operator as untrusted. The trusted computing base includes the enclave silicon, the measured workload, the on-chain verifier, and its administrative authorities. The loader can replace verifier code; the separate registry authority can change accepted policy and the mutable AMD P-384 root. See [governance and trust roots](/reference/governance/) for custody assumptions.

## Isolation comparison

| Dimension | GCE Confidential VM (AMD SEV-SNP) | AWS Nitro Enclaves | Intel TDX |
| :--- | :--- | :--- | :--- |
| Isolation | AES memory encryption plus Reverse Map Table | Nitro ASIC core and memory partition | Trust Domain. CPU memory encryption. Host and hypervisor are outside the vault. |
| Device | Linux `/dev/sev-guest` (`SNP_GET_REPORT`) | Linux `/dev/nsm` (`NSM_REQUEST_ATTESTATION`) | `/var/run/dstack.sock`, then `/dev/tdx-guest` or `/dev/tdx_guest` |
| Report | 1,184-byte binary, ECDSA P-384 / SHA-384 | COSE Sign1 CBOR, ECDSA P-384 | Quote v4, ECDSA P-256. Two signatures. |
| Root | AMD ARK → ASK → VCEK / VLEK | AWS Nitro Root CA → intermediate → leaf | Governance-pinned PCK leaf, then the Quoting Enclave, then the attestation key |
| Measurement | 48-byte SHA-384 launch digest | PCR0 (EIF), PCR1, PCR2, PCR8 | `MR_TD` at launch. `RTMR0`–`RTMR2` boot log. `RTMR3` is recorded and not allowlisted. |
| User binding | 64-byte `REPORT_DATA` | `user_data` (32-byte pubkey) and `nonce` | 64-byte `REPORTDATA`, a SHA-512 commitment |
| Network | Full VM, encrypted RAM | No persistent disk, vsock only | Full guest VM, encrypted RAM |
| On-chain path | `register_vcek` then `verify_and_register` / `verify_atomic_with_nonce` | `verify_nitro_attestation` (mode 0 or 1) | `issue_tdx_challenge`, then single v1 transaction (`verify_tdx_qe_report` + `verify_tdx_quote`) |

## Cryptographic guarantees

The verifier binds three facts into every accepted report. AMD SEV-SNP and AWS Nitro use the field layout in this list.

1. **Code identity.** Measurement (SNP digest or Nitro PCR0) is on the source-specific `BackendPolicy` allowlist. An all-zero measurement fails closed (`VerifierError::DisallowedMeasurement`).
2. **Key identity.** Mode A `REPORT_DATA[0..32]` (or Nitro `user_data`) equals the workload Ed25519 pubkey. Mode B `REPORT_DATA[32..64]` equals `SHA-256(slot_hash ‖ action_hash ‖ consumer_program_id)`.
3. **Freshness.** `SlotHashes` at `nonce_slot` must match, with age `clock.slot - nonce_slot ≤ 150` slots. A miss is `VerifierError::StaleNonce`.

### Intel TDX binding

Intel TDX uses the same three facts with a different layout. The full walkthrough is [Intel TDX](/backends/intel-tdx/).

1. **Code identity.** Source `5` allowlists a platform digest. That digest covers `MR_TD` (the launch image), `MR_CONFIG_ID`, `RTMR0`–`RTMR2` (the boot log), the TDX module, and the TD attributes. `MR_TD` is the build-time hash. An `RTMR` is a register the guest extends during boot.
2. **Key identity.** `REPORTDATA` is `SHA-512` of a domain-separated preimage. The preimage commits to the workload Ed25519 pubkey, the challenge slot hash, the challenge nonce, a GPU digest, and a model digest.
3. **Freshness.** `issue_tdx_challenge` copies a `SlotHashes` entry while that slot is at most 150 slots old. The quote must name that same slot. The challenge account stays live for 1,500 slots. The session between the two quote instructions stays live for 150 slots.

The two quote signatures are ECDSA P-256. Solana's `secp256r1` precompile checks them. The two verifier instructions cost about 75,000 compute units. The path uses no zero-knowledge proof and no zkVM. Governance pins the PCK leaf. The program does not walk an Intel certificate chain on chain.

Replay inside that window fails with `VerifierError::NonceAlreadyUsed`. The replay record is a `UsedNonceAccount` PDA seeded `[b"nonce", signer_pubkey, nonce]`. New records are 49 bytes and may be closed with `close_stale_nonce` once they are more than 150 slots old, after which `SlotHashes` freshness rejects the nonce. Legacy 17-byte records are permanent.

Mode B always consumes that PDA. `verify_atomic` returns `VerifierError::NonceRequired` and writes nothing (`@spec SCC-SEC-005`).

## Fail-closed boundaries

| Gate | Failure |
| :--- | :--- |
| Debug / migrate policy bits | `VerifierError::UnauthorizedPolicy` (`@spec SCC-SEC-001`) |
| TCB below `min_tcb_*` | `VerifierError::TcbBelowMinimum` |
| P-384 / COSE signature | `VerifierError::InvalidSignature` |
| Missing `/dev/nsm` or ioctl error | Sidecar `SidecarError::IoctlError` (no synthetic production document) |
| Missing Nitro `cabundle` | `CryptoError::InvalidAttestationPayload` |
| HTTP bind off loopback | Sidecar refuses to listen |
| `require_nonce == false` | `CpiError::NonceRequired` |
| Packet above 1,232 bytes (legacy UDP) | TypeScript `PacketTooLargeError` |
| TDX debug Quoting Enclave or debug Trust Domain | `VerifierError::DisallowedMeasurement` |
| TDX quote signature, QE binding, or `REPORTDATA` mismatch | `VerifierError::InvalidSignature` |
| TDX `verify_tdx_quote` mode other than 0 | `VerifierError::InvalidInstruction` |
| TDX challenge or session outside its window | `VerifierError::StaleNonce` |
| No `secp256r1` instruction before a TDX check | `VerifierError::InvalidSignature` |

The sidecar HTTP API binds only `127.0.0.1` or `::1`. `DRY_RUN` defaults to `true`. The on-disk payer is a fee payer. It is never the workload signer.

## What the TEE covers

- Host memory dumps of the signing key
- Operator phishing of the hot wallet
- Launch-image substitution (measurement changes)

## Residual risk

- Side channels (Spectre, CacheWarp, INCEPTION). Mitigate with `min_tcb` microcode floors. For Intel TDX, pin `TEE_TCB_SVN` and `MR_SEAM` inside the source-5 platform digest.
- Host I/O delay or drop. Sign inside the enclave before the payload leaves vsock.
- Host clock. Freshness uses Solana `SlotHashes`, never guest wall time.
- Intel TDX `RTMR3` changes every boot, so the allowlist omits it. A boot event in that register does not by itself change admission. The signer journal still hashes all four RTMRs.
- The Intel TDX GPU digest is a value the guest declares and governance allowlists. It is not an NVIDIA device signature.
- Mode A sessions require both slot and Unix freshness. The registry authority can target a canonical record with `revoke_attested_signer`, setting its slot deadline to zero (expired at positive current slots). Disable compromised issuer/admission credentials first to prevent fresh enrollment. JWKS revocation alone does not invalidate existing sessions. See [current-source containment and evidence limits](https://github.com/solana-foundation/confidential-compute/blob/main/SECURITY.md#84-residual-risks).

## Related

- [Intel TDX](/backends/intel-tdx/)
- [Mode A](/architecture/mode-a-stateful/)
- [Mode B](/architecture/mode-b-atomic/)
- [Instruction matrix](/reference/instruction-matrix/)
