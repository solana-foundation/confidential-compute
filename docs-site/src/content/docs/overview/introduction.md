---
title: What is Solana Confidential Compute?
description: Hardware trust roots, live program id, and architectural overview for the Solana verifiable compute layer.
---

Solana Confidential Compute is a verifiable compute layer for Solana. It binds Ed25519 signing keys to hardware-isolated enclaves so a protocol can prove that a signature came from measured code on attested silicon.

Private keys are generated inside CPU-encrypted memory. The host operating system and a human operator cannot extract them. Signatures execute only under an attested binary measurement.

## Value proposition

Solana Confidential Compute protects workload signing keys with hardware attestation for high-throughput DeFi, tokenized real-world assets, institutional custody, and decentralized oracles. Administrative custody remains a separate trust assumption; see [governance and trust roots](/reference/governance/).

| Deliverable | Role |
| :--- | :--- |
| On-chain verifier | AMD VCEK / P-384, Google JWT, AWS Nitro COSE Sign1, Intel TDX DCAP |
| Policy and replay | Measurement allowlist, SlotHashes freshness, `UsedNonceAccount` |
| Client SDKs | Rust `solana-confidential-compute-sdk`, TypeScript `@solana/confidential-compute`, CPI helpers |
| Enclave runtime | `solana-confidential-compute-sidecar` daemon, `solana-confidential-compute-cli`, Docker image |
| Documentation | This portal |

## Hardware trust roots

Solana Confidential Compute verifies three silicon roots:

| Root | Platform | Attestation |
| :--- | :--- | :--- |
| AMD SEV-SNP | GCE Confidential VM | 1,184-byte report, ECDSA P-384, `ARK → ASK → VCEK` |
| AWS Nitro Enclaves | Nitro parent + EIF | COSE Sign1 / CBOR, ECDSA P-384, AWS Nitro Root CA |
| Intel TDX | Intel Xeon Trust Domain | DCAP Quote v4, ECDSA P-256 (`secp256r1`), PCK leaf → QE → Attestation Key |

Google Confidential Space adds an OIDC JWT (`verify_google_jwt`) that binds `eat_nonce` and `image_digest` to the same Mode A / Mode B session model.

See the [threat model](/overview/threat-model/) for isolation boundaries.

## Dual modality

| Mode | Instruction | Consumer cost after attest |
| :--- | :--- | :--- |
| **A — Stateful** | `verify_and_register` | Native Ed25519. PDA check ≤ 1,500 CUs. P-384 runs once per session. |
| **B — Atomic** | `verify_atomic_with_nonce` | One transaction. Header is 80 bytes on the wire. Nonce PDA blocks replay. |

:::note
On-chain SBF signature verification uses fail-closed instruction introspection against a preceding precompile. The mechanics are in [SECURITY.md](../../../../../SECURITY.md#8-auditor-scope--runtime-limitations) §8. For plain-English definitions and architecture fundamentals, see [Concepts & Glossary](/overview/concepts/). For a hands-on guide, see the [15-Minute Integrator Quickstart](/integration/quickstart/). The in-depth hardware reference is [docs/research/tee-confidential-compute.md](../../../../../docs/research/tee-confidential-compute.md).
:::

Mode A TTL is `ATTESTATION_TTL_SLOTS = 216_000` (~24 hours at 400 ms). Details: [Mode A](/architecture/mode-a-stateful/) and [Mode B](/architecture/mode-b-atomic/).

## Live program

| Item | Value |
| :--- | :--- |
| Program id | `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh` |
| Crates | `solana-confidential-compute-verifier`, `solana-confidential-compute-cpi` (`declare_id` matches) |
| Cluster | Solana Devnet |
| Compile target | SBPFv3 (`e_flags = 0x3`) |

Stage 2 attestation stays under **550,000 CUs**.

## Workspace map

| Path | Purpose |
| :--- | :--- |
| `programs/solana-confidential-compute-verifier` | On-chain verifier |
| `crates/solana-confidential-compute-core` | `no_std` report types |
| `crates/solana-confidential-compute-crypto` | P-384, VCEK, JWT, Nitro CBOR |
| `crates/solana-confidential-compute-cpi` | Consumer helpers |
| `crates/solana-confidential-compute-sdk` | Rust builders |
| `sdks/typescript` | `@solana/confidential-compute` |
| `bins/solana-confidential-compute-sidecar` | In-enclave daemon |
| `bins/solana-confidential-compute-cli` | Proof-of-enclave CLI |

## Next steps

1. Read the [threat model](/overview/threat-model/).
2. Pick [Mode A](/architecture/mode-a-stateful/) or [Mode B](/architecture/mode-b-atomic/).
3. Wire [Rust CPI](/integration/rust-cpi/) or the [TypeScript SDK](/integration/typescript-sdk/).
4. Run the [sidecar](/deployment/sidecar/) inside the enclave.
