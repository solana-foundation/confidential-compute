---
title: Intel TDX
description: How Solana Confidential Compute checks an Intel TDX quote on Solana with two native P-256 signatures.
---

Intel TDX (Trust Domain Extensions) is a confidential-computing mode on Intel Xeon processors. Solana Confidential Compute uses it as a third hardware root, next to AMD SEV-SNP and AWS Nitro.

This page is for application developers. You need Solana. You do not need a background in TEE hardware.

## Three pictures

**The Trust Domain is a vault.** A Trust Domain (TD) is a guest that the CPU locks. Memory inside the vault is encrypted by the processor. The cloud host, the hypervisor, and the root operating system cannot read or change that memory. Solana Confidential Compute generates the workload Ed25519 key inside the vault. The private key stays there.

**The quote is a certificate from the chip.** An attestation quote is a document the CPU's quoting stack signs. It names the code in the vault, and it includes 64 bytes the guest chose (`REPORTDATA`). Solana checks the signatures. A valid quote means: this Intel platform measured this guest, and the guest committed to these 64 bytes.

**The check is ordinary signatures.** Intel DCAP quotes use ECDSA on the P-256 curve. Solana already verifies that curve in the native program `Secp256r1SigVerify1111111111111111111111111` (`secp256r1`, SIMD-0075). Solana Confidential Compute therefore checks a quote with two instructions and about 75,000 compute units. The path uses no zero-knowledge proof and no zkVM.

| Signature | Who signs | Signed bytes | Precompile instruction |
| :--- | :--- | ---: | ---: |
| Quoting Enclave report | Platform key (PCK leaf) | 384 | 497 bytes |
| Trust Domain report | Attestation key | 632 | 745 bytes |

Under Solana 4.x, Solana Confidential Compute leverages versioned transactions (v1 transactions, SIMD-0296, 4,096-byte limit). The entire enrolment executes in a **single v1 transaction** measuring ~2,052 bytes: both `secp256r1` precompile instructions and both verifier instructions execute atomically without requiring an Address Lookup Table. The raw quote is about 5 KB; Solana Confidential Compute never uploads it. The signed regions sit inside the precompile instructions, and the program reads those bytes back directly via instruction introspection.

The harness in `tests/tdx_compute_units.rs` targets the bands below. The P-256 math runs inside the native precompile; the SBF program parses, hashes, and writes accounts.

| Instruction | Target CU band |
| :--- | :--- |
| `verify_tdx_qe_report` | 12,000–22,000 CU |
| `verify_tdx_quote` | 40,000–70,000 CU |
| Both, which is one enrolment | about 75,000 CU |

Both instructions are targeted to fit comfortably within the default 200,000 CU budget.

## Words on the quote

| Word | Plain meaning |
| :--- | :--- |
| `MR_TD` | Measurement of the Trust Domain. A 48-byte hash of the guest image at launch: firmware, kernel, and the initial contents the CPU measured. Change one byte of that image and `MR_TD` changes. This is the build-time identity. |
| `RTMR` | Runtime Measurement Register. A 48-byte boot log. Each boot stage extends a register, the way a PCR works. A quote has four: `RTMR0`, `RTMR1`, `RTMR2`, `RTMR3`. `RTMR0` through `RTMR2` record the boot chain. `RTMR3` records later events and changes on every boot. |
| `MR_CONFIG_ID` | A 48-byte launch configuration id. On a dstack guest this binds the configuration document, including the GPU policy the guest enforces at boot. |
| `MR_SEAM` | Hash of the Intel TDX module that hosts the vault. |
| Quoting Enclave (QE) | Intel's small signing enclave. The platform key certifies the QE. The QE certifies one attestation key. |
| PCK | Provisioning Certification Key. The Intel platform leaf key that signs the QE report. Governance puts this key on the allowlist. |
| `REPORTDATA` | The only 64 bytes the guest chooses. Solana Confidential Compute puts a commitment to the workload public key here. |

## Enrolment, step by step

Intel TDX enrolment is Mode A. `verify_tdx_quote` accepts mode `0`. Success writes an [`AttestedSignerAccount`](/architecture/mode-a-stateful/) for 216,000 slots (about 24 hours). Later transactions use the Ed25519 key and skip the quote check.

1. **Allowlist.** The registry authority writes a source-5 `BackendPolicy`. Source `5` is Intel TDX. The list holds up to eight 48-byte entries. An all-zero entry is rejected.
2. **Challenge.** Anyone may call `issue_tdx_challenge`. You pick a 32-byte nonce. The nonce only selects the account address. The program reads the slot hash from the `SlotHashes` sysvar. The slot must be at most 150 slots old. The challenge stays live for 1,500 slots.
3. **Quote.** Inside the Trust Domain, the guest asks for a DCAP quote. `REPORTDATA` is the commitment below. The sidecar mode is `intel-tdx`.
4. **Certify the attestation key & admit the signer.** Under Solana 4.x, the client packs the complete enrolment into a single v1 transaction containing four instructions:
   - `secp256r1` precompile verifying the 384-byte Quoting Enclave report against the allowlisted PCK leaf.
   - `verify_tdx_qe_report` recording the verified attestation key into `TdxSessionAccount`.
   - `secp256r1` precompile verifying the 632-byte Trust Domain report against the certified attestation key.
   - `verify_tdx_quote` verifying the quote body, validating workload key possession, writing `AttestedSignerAccount`, burning the nonce, and retiring the challenge. The workload key must sign the transaction.

```rust
// 1. Issue the challenge. The program copies the slot hash from SlotHashes.
issue_tdx_challenge {
    nonce: [u8; 32],
    nonce_slot: u64, // age <= 150 slots
};

// 2. Certify the attestation key. The precompile instruction comes first.
//    Message: 384-byte QE report. Signer: the allowlisted PCK leaf.
secp256r1_verify(pck_pubkey, qe_report, qe_signature);
verify_tdx_qe_report {
    attestation_pubkey_xy, // 64 bytes, uncompressed X || Y
    pck_pubkey,             // 33 bytes, compressed SEC1 (0x02 or 0x03)
    gpu_rim_digest,         // 32 bytes, also written onto the session
    model_digest,           // 32 bytes, also written onto the session
    qe_auth_data,           // length-prefixed, at most 256 bytes
};

// 3. Admit the workload signer. Versioned transaction, lookup table.
//    Message: 48-byte header || 584-byte TD body. Signer: attestation key.
secp256r1_verify(attestation_pubkey, header_and_body, isv_signature);
verify_tdx_quote {
    mode: 0,       // Mode A
    nonce_slot,    // must equal the challenge's slot
};
```

The workload Ed25519 key must sign transaction two. A third party cannot enrol a key it does not hold.

The precompile instruction must sit earlier in the same transaction. Its program id is `Secp256r1SigVerify1111111111111111111111111`. The pubkey, signature, and message offsets must point at that same instruction (`u16::MAX`). The signature must be low-S. Solana Confidential Compute normalizes `s` to the low half of the P-256 order before the compare.

## What governance pins

Each check looks up one 48-byte value in the source-5 policy. The value occupies the front of the slot. The tail is zeros. Four values must be present:

| Slot contents | What it pins |
| :--- | :--- |
| PCK leaf, 33 bytes | The platform key that signed the QE report. |
| QE identity, 32 bytes | `SHA-256(MRSIGNER ‖ ISVPRODID ‖ ISVSVN)` of the Quoting Enclave. The PCK signs every enclave on the platform. This entry narrows that to Intel's quoting enclave at one revision. |
| TD platform digest, 32 bytes | One configuration of the vault. See the field list below. |
| GPU RIM digest, 32 bytes | The GPU digest the guest placed in `REPORTDATA`. |

The platform digest is one SHA-256 over these fields, in this order:

| Field | Bytes | Role |
| :--- | ---: | :--- |
| `TEE_TCB_SVN` | 16 | Security version of the TDX components. |
| `MR_SEAM` | 48 | Which TDX module is running. |
| `TD_ATTRIBUTES` | 8 | Feature flags for this Trust Domain. |
| `XFAM` | 8 | CPU feature mask. |
| `MR_TD` | 48 | Launch measurement of the image. |
| `MR_CONFIG_ID` | 48 | Launch configuration. |
| `RTMR0 ‖ RTMR1 ‖ RTMR2` | 144 | Boot-chain log. |

`RTMR3` is left out of this digest on purpose. On a running guest it changes every boot. dstack extends an instance id into it, and a GPU check extends a fresh event into it. Putting `RTMR3` on the allowlist would need a new governance transaction per boot.

The signer record still stores a journal over all four registers, so a consumer can see them. The journal hash is:

```text
rtmrs_hash = SHA-256(RTMR0 || RTMR1 || RTMR2 || RTMR3)   // 192 bytes in
journal    = SHA-256(MR_TD || MR_CONFIG_ID || rtmrs_hash)
measurement = journal || 16 zero bytes                   // 48 bytes stored
```

A fixed test vector, when `MR_TD` is `0x11` repeated, `MR_CONFIG_ID` is `0x22` repeated, and `rtmrs_hash` is already `0x33` repeated:

`373e308348c3e5238fc0360bf46de60cd33775eebdbf6ff04379b7d07083e0b9`

Pin that 48-byte measurement in the consumer. Pinning raw `MR_TD` will not match the account.

The debug bit fails closed before the allowlist. A debug Quoting Enclave (`SGX ATTRIBUTES` bit 1) returns `DisallowedMeasurement`. A debug Trust Domain (`TD_ATTRIBUTES` bit 0, `TUD.DEBUG`) returns the same error. A debug TD has no isolation: the host can read the vault. The launch measurement can still match an approved image.

## The commitment inside the quote

`REPORTDATA` binds the workload key to the quote. The domain string is `solana-confidential-compute/v1/report-data` (42 bytes).

```text
composite  = SHA-256(signer || slot_hash || gpu_rim || model)
REPORTDATA = SHA-512(
    42u32_le || "solana-confidential-compute/v1/report-data"
    || signer || composite || slot_hash
    || gpu_rim || model || challenge_nonce
)
```

`signer` is the 32-byte Ed25519 public key. It appears twice: once in the composite, and once in the clear, so a reader can see the key without rehashing. `slot_hash` and `challenge_nonce` come from the challenge account. Two challenges can pin the same slot hash. The nonce keeps their quotes apart.

The QE report has its own binding. Its `user_report_data` must be `SHA-256(attestation_pubkey_xy ‖ qe_auth_data)` followed by 32 zero bytes. The handler recomputes that digest. A mismatched attestation key is `InvalidSignature`.

## Accounts

| Account | Seeds | Size | Lifetime |
| :--- | :--- | ---: | :--- |
| Challenge | `[b"challenge", &[5], nonce]` | 90 | 1,500 slots. Acceptance sets `expires_slot` to 0. |
| Session | `[b"tdx_session", SHA-256(compressed_attestation_key)]` | 146 | 150 slots from the QE step. |
| Nonce | `[b"nonce", &[5], seed]` | 49 | Same reclaim rule as other nonces (150 slots). |
| Attested signer | `[b"attested_signer_v2", signer_pubkey]` | 154 | 216,000 slots. `enclave_type` is `5`. |

The nonce seed is `SHA-256(signer ‖ quote_body_digest ‖ slot_hash ‖ challenge_nonce)`. `quote_body_digest` is SHA-256 of the 632 signed bytes. Two different quotes from the same signer cannot share a nonce.

`chip_id_hash` on the signer record is `SHA-256(MR_TD)`. `tcb_version` is `0`. The measurement field is the 48-byte journal measurement above.

A live session rejects a second QE step that changes `gpu_rim_digest` or `model_digest`. The same digests may be retried. An expired session may be replaced. A revoked signer (`expires_slot == 0`) rejects a new quote with `UnauthorizedPolicy`.

The challenge is retired on success because a nonce account can be closed after 150 slots, while a challenge lives for 1,500. Retiring the challenge closes that gap.

## Consumer check

After enrolment, a consumer checks the session the same way it checks AMD or Nitro. The platform tag is `AttestationPlatform::IntelTdx` (`5`). `EXPECTED_MEASUREMENT` is the journal measurement, including the 16 zero bytes.

```rust
let attested = solana_confidential_compute_cpi::AttestedSignerAccount::try_from_account_info(attested_info)?;
attested.validate_session_signer(
    workload_signer,
    &EXPECTED_MEASUREMENT,
    solana_confidential_compute_cpi::AttestationPlatform::IntelTdx,
)?;
```

`assert_attestation_signer` is the same check and also re-derives the PDA.

## Quote header the parser accepts

| Field | Required value |
| :--- | :--- |
| Version | `4` |
| Attestation key type | `2` (ECDSA P-256) |
| TEE type | `0x81` (TDX) |
| QE vendor id | Intel's 16-byte vendor id |

Anything else is `InvalidInstruction`. The parser then checks that the signature-data length covers the QE report, the QE signature, and the QE auth data.

## Where the quote comes from

Live `intel-tdx` mode probes three sources, in order:

1. Unix socket `/var/run/dstack.sock` (`POST /GetQuote`, then JSON-RPC `tdx_quote`). This source returns a DCAP quote.
2. `/dev/tdx-guest` with `TDX_CMD_GET_REPORT0`.
3. `/dev/tdx_guest` with the same ioctl.

The device nodes return a local TD report. The provider accepts a candidate only when the v4 quote header is present. If every probe misses, live mode stops. It does not substitute a synthetic quote.

Dry-run quotes start with the bytes `INTEL-TDX-SYNTHETIC-v1`. They are a placeholder for local tests.

:::note
`solana-confidential-compute-sidecar` includes an automated on-chain submission pipeline in `intel-tdx` mode (`bins/solana-confidential-compute-sidecar/src/tdx_enrolment.rs`). When `DRY_RUN=false`, the sidecar issues the on-chain challenge, acquires the hardware quote, builds the atomic 4-instruction v1 transaction, and submits it to Solana. See the [sidecar daemon](/deployment/sidecar/) for configuration, bind address, `DRY_RUN`, and fee payer options.
:::

## Fail-closed gates

| Gate | Error |
| :--- | :--- |
| Header, length, or mode other than `0` | `VerifierError::InvalidInstruction` |
| No `secp256r1` instruction before the verifier instruction | `VerifierError::InvalidSignature` |
| PCK, attestation key, QE binding, or `REPORTDATA` mismatch | `VerifierError::InvalidSignature` |
| Debug QE, debug TD, or a value missing from the allowlist | `VerifierError::DisallowedMeasurement` |
| Wrong policy account | `VerifierError::UnauthorizedPolicy` |
| Revoked signer | `VerifierError::UnauthorizedPolicy` |
| Challenge slot mismatch, expired challenge, or expired session | `VerifierError::StaleNonce` |
| Nonce PDA already used | `VerifierError::NonceAlreadyUsed` |
| Workload key did not sign enrolment transaction | `MissingRequiredSignature` |

The full code list is the [instruction matrix](/reference/instruction-matrix/).

## Limits to plan for

- Governance pins the PCK leaf and the QE identity. The program does not walk an Intel X.509 chain on chain, nor does it evaluate Intel TCB status, CRLs, or collateral expiration on chain. Governance must actively authenticate and maintain those pinned public keys, including revocation response and key rotations.
- `RTMR3` is stored in the journal and is not an allowlist entry. A boot event in `RTMR3` does not by itself change admission.
- The GPU RIM check proves that an approved Trust Domain declared an approved digest. It is not an NVIDIA device signature. The guest is expected to appraise GPUs at boot, before it releases keys, and to bind that policy through `MR_CONFIG_ID`.
- The model digest is inside `REPORTDATA` and on the session account. It has no separate allowlist entry.
- Both verification steps execute atomically in one v1 transaction. The challenge account lasts 1,500 slots, which is the time allowed to fetch the quote before the challenge expires.

## Related

- [Concepts](/overview/concepts/)
- [Threat model](/overview/threat-model/)
- [Mode A](/architecture/mode-a-stateful/)
- [Instruction matrix](/reference/instruction-matrix/)
- [Governance](/reference/governance/)
