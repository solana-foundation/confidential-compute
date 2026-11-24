---
title: Instruction Matrix
description: On-chain instruction discriminators, wire layouts, and VerifierError / CpiError tables.
---

Registry instructions use a separate administrative authority from the loader upgrade authority. See [governance and trust roots](/reference/governance/) for signer, multisig, and root rotation assumptions.

<!-- @spec SCC-DOCS-001 SCC-ARCH-001 SCC-NITRO-008 SCC-SEC-005 SCC-ANCHOR-001 SCC-CONSUMER-001 SCC-CONSUMER-002 SCC-TDX-001 SCC-TDX-002 SCC-TDX-005 -->

Live program id: `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`.

Instruction discriminators are `sha256("global:<name>")[..8]`. Account discriminators are `sha256("account:<Name>")[..8]`.

## Instructions

| Instruction | Discriminator | Data after disc |
| :--- | :--- | :--- |
| `init_policy_registry` | `[90, 53, 0, 89, 164, 70, 107, 186]` | authority 32, ark_xy 96, min TCB 4×u8, measurement_count u32, measurements `[u8;48];8` |
| `update_policy` | `[227, 150, 114, 217, 142, 172, 100, 228]` | min TCB 4×u8 (monotonic); legacy measurement_count u32 and measurements `[u8;48];8` retained for compatibility, runtime-ignored for admission |
| `register_vcek` | `[228, 65, 209, 71, 242, 135, 131, 17]` | chip_id 64, tcb u64, pubkey_xy 96, ask_len u16, vcek_len u16, then DER |
| `verify_and_register` | `[246, 249, 100, 14, 102, 116, 92, 145]` | `nonce_slot` u64 LE, SNP report 1184 |
| `verify_atomic` | `[65, 19, 195, 149, 67, 219, 25, 75]` | Fail-closed: `NonceRequired` |
| `verify_atomic_with_nonce` | `[209, 4, 10, 239, 3, 142, 223, 250]` | 72-byte header + SNP report 1184 |
| `rotate_root_cert` | `[137, 212, 96, 71, 222, 5, 133, 104]` | new_ark_pubkey_xy 96. Refused: returns `InvalidInstruction` after authority checks (#255) |
| `register_jwks_key` | `[122, 195, 232, 116, 203, 137, 219, 14]` | kid (vec), modulus 256, exponent u32 |
| `revoke_jwks_key` | `[184, 102, 12, 45, 99, 128, 41, 16]` | kid_hash 32 |
| `verify_google_jwt` | `[104, 38, 12, 199, 131, 240, 78, 165]` | mode u8, nonce_slot u64, action_hash 32, jwt string |
| `verify_nitro_attestation` | `[107, 76, 178, 169, 215, 146, 23, 95]` | mode u8, nonce_slot u64 LE, action_hash 32, doc_len u32 LE, COSE bytes |
| `issue_tdx_challenge` | `[70, 183, 171, 140, 168, 137, 54, 149]` | nonce 32, nonce_slot u64 LE |
| `verify_tdx_qe_report` | `[210, 155, 95, 37, 125, 174, 77, 73]` | attestation pubkey 64, PCK pubkey 33, GPU digest 32, model digest 32, auth length u16 LE, auth bytes |
| `verify_tdx_quote` | `[173, 239, 124, 214, 245, 185, 23, 137]` | mode u8 (`0`), nonce_slot u64 LE |

## Mode A SNP (`verify_and_register`)

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | Discriminator |
| 8 | 8 | `nonce_slot` u64 LE |
| 16 | 1184 | SNP report |

Accounts: `payer` (signer, writable), `policy_registry`, `vcek`, `attested_signer` (writable), `used_nonce` (writable), `SlotHashes`, `Clock`, `system_program`.

## Mode B SNP (`verify_atomic_with_nonce`)

80-byte prefix + 1,184-byte report = **1,264 bytes**.

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | Discriminator |
| 8 | 8 | `nonce_slot` u64 LE |
| 16 | 32 | `action_hash` |
| 48 | 32 | `consumer_program_id` |
| 80 | 1184 | SNP report |

Accounts: `payer`, `policy_registry`, `vcek`, `used_nonce` (writable), `SlotHashes`, `Clock`, `system_program`.

## Nitro (`verify_nitro_attestation`)

`mode`: `0` = Mode A, `1` = Mode B. `MAX_NITRO_DOCUMENT_LEN = 8192`.

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | Discriminator |
| 8 | 1 | `mode` |
| 9 | 8 | `nonce_slot` u64 LE |
| 17 | 32 | `expected_action_hash` |
| 49 | 4 | `doc_len` u32 LE |
| 53 | `doc_len` | COSE Sign1 document (exact length) |

Accounts: `payer`, `policy_registry`, `attested_signer` (writable), `used_nonce` (writable), `SlotHashes`, `Clock`, `system_program`. Mode B appends the Instructions sysvar.

## Intel TDX

Source tag `5`. The quote is ECDSA P-256. Each signature is checked by a preceding `secp256r1` instruction (`Secp256r1SigVerify1111111111111111111111111`). The two precompile messages are 384 and 632 bytes (instructions of 497 and 745 bytes). Under Solana 4.x, the entire quote check packs into a single v1 transaction (~2,052 bytes total) holding both precompile instructions and both verifier instructions. Together the two verifier instructions cost about 75,000 compute units. The narrative, allowlist fields, and `REPORTDATA` formula are on the [Intel TDX](/backends/intel-tdx/) page.

`verify_tdx_quote` accepts mode `0` only. Any other mode is `VerifierError::InvalidInstruction`.

### `issue_tdx_challenge`

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | Discriminator |
| 8 | 32 | `nonce` |
| 40 | 8 | `nonce_slot` u64 LE |

Accounts: `challenge` (writable), `payer` (signer, writable), `system_program`, `Clock`, `SlotHashes`.

The program copies the slot hash from `SlotHashes`. `nonce_slot` must be at most 150 slots old. `expires_slot = clock.slot + 1500`. Reissuing a live or consumed challenge returns `VerifierError::StaleNonce`.

### `verify_tdx_qe_report`

The QE report itself is the precompile message (384 bytes). It is not repeated in this instruction.

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | Discriminator |
| 8 | 64 | Attestation public key, uncompressed `X ‖ Y` |
| 72 | 33 | PCK leaf, compressed SEC1 (`0x02` or `0x03`) |
| 105 | 32 | `gpu_rim_digest` |
| 137 | 32 | `model_digest` |
| 169 | 2 | `qe_auth_data` length, u16 LE, at most 256 |
| 171 | length | `qe_auth_data` |

Accounts: `tdx_session` (writable), source-5 `backend_policy`, `payer` (signer, writable), `system_program`, `Clock`, Instructions sysvar.

### `verify_tdx_quote`

The signed region (48-byte header plus 584-byte body) is the precompile message. This instruction is 17 bytes.

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | Discriminator |
| 8 | 1 | `mode` (`0`) |
| 9 | 8 | `nonce_slot` u64 LE |

Accounts: `attested_signer` (writable), `tdx_session`, source-5 `backend_policy`, `used_nonce` (writable), `payer` (signer, writable), `system_program`, `Clock`, `challenge` (writable), workload signer (signer), Instructions sysvar.

The TDX nonce PDA uses seeds `[b"nonce", &[5], seed]`. `seed` is `SHA-256(signer ‖ quote_body_digest ‖ slot_hash ‖ challenge_nonce)`. Other backends keep the seeds in the account table below.

## Account discriminators

| Account | Discriminator | Size | Seeds |
| :--- | :--- | ---: | :--- |
| `AttestedSignerAccount` | `[43, 255, 114, 40, 233, 28, 127, 238]` | 154 | `[b"attested_signer_v2", signer_pubkey]` |
| `VcekAccount` | `[180, 227, 118, 227, 197, 175, 220, 193]` | — | `[b"vcek_v2", chip_id_hash, tcb_le]` |
| `PolicyRegistry` | `[175, 179, 180, 44, 5, 161, 62, 240]` | — | `[b"policy_registry"]` |
| `UsedNonceAccount` | `[138, 99, 69, 17, 9, 177, 205, 94]` (`UsedNonceAccountV2`) | 49 | `[b"nonce", signer_pubkey, nonce]` |
| `UsedNonceAccount` (legacy) | `[157, 75, 223, 206, 73, 132, 216, 154]` | 17 | `[b"nonce", signer_pubkey, nonce]` |
| `TdxSessionAccount` | `[230, 103, 152, 156, 163, 23, 153, 174]` | 146 | `[b"tdx_session", SHA-256(compressed attestation key)]` |
| `ChallengeAccount` | `[96, 128, 44, 165, 71, 172, 60, 12]` | 90 | `[b"challenge", &[5], nonce]` |

PDA allocation uses System Program `create_account` funded by `payer` (`@spec SCC-ARCH-001`).

## `VerifierError`

| Code | Variant | Meaning |
| ---: | :--- | :--- |
| 0 | `InvalidInstruction` | Instruction data failed to parse |
| 1 | `InvalidDiscriminator` | Discriminator mismatch |
| 2 | `VerificationFailed` | Report / cert chain failed |
| 3 | `DisallowedMeasurement` | Measurement missing from allowlist |
| 4 | `StaleNonce` | SlotHashes miss or age > 150 |
| 5 | `NonceAlreadyUsed` | `UsedNonceAccount` already exists |
| 6 | `TcbBelowMinimum` | Hardware TCB below policy |
| 7 | `UnauthorizedPolicy` | Debug / migrate / consumer mismatch |
| 8 | `AttestationExpired` | `clock.slot > expires_slot` or Unix timestamp negative / at or beyond the exclusive deadline |
| 9 | `InvalidAccountAddress` | Unpinned sysvar or bad address |
| 10 | `(Reserved)` | Retired (`SignerAlreadyAttested` retired per PR #77) |
| 11 | `InvalidSignature` | P-384 / COSE signature failed |
| 12 | `ActionHashMismatch` | Mode B commitment mismatch |
| 13 | `SignerMismatch` | Workload pubkey mismatch |
| 14 | `InvalidProof` | Groth16 pairing failed |
| 15 | `InvalidAuthority` | Authority signer mismatch |
| 16 | `NonceRequired` | Mode B without nonce consumption |

## `CpiError`

Aligned subset used by `solana-confidential-compute-cpi`:

| Code | Variant | Meaning |
| ---: | :--- | :--- |
| 3 | `DisallowedMeasurement` | Measurement mismatch |
| 8 | `AttestationExpired` | Session TTL elapsed |
| 12 | `ActionHashMismatch` | Header `action_hash` mismatch |
| 13 | `SignerMismatch` | Workload pubkey mismatch |
| 16 | `NonceRequired` | `require_nonce == false` or `verify_atomic` |
| 17 | `ConsumerProgramMismatch` | Consumer program id mismatch |

`From<CpiError>` maps to `ProgramError::Custom(code)`.
