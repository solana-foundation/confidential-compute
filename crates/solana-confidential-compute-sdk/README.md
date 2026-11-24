# solana-confidential-compute-sdk

`solana-confidential-compute-sdk` builds Solana transactions on the host. It is an off-chain crate. On-chain checks stay in `solana-confidential-compute-cpi`. This crate re-exports those helpers so one dependency can name both surfaces.

`@spec SCC-SDK-001` `@spec SCC-ARCH-001` `@spec SCC-VERIFY-001` `@spec SCC-SEC-001`

The public program id re-export is `solana_confidential_compute_cpi::ID`:

```
EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh
```

```bash
cargo test -p solana-confidential-compute-sdk
```

---

## 1. What the client builds

```
 ConfidentialComputeClient
      |
      +-- derive_*_pda -----------------> Pubkey + bump
      |
      +-- build_register_signer_ix -----> Mode A instruction
      |
      +-- build_session_action_tx ------> consumer tx signed by the workload key
      |
      +-- build_atomic_attestation_tx --> Mode B tx
              instruction 0: verify_atomic_with_nonce
              instruction 1: the consumer instruction
```

`ConfidentialComputeClient::new(program_id)` stores the verifier id. The free functions in `builder` target `solana_confidential_compute_cpi::ID`. The `*_for_program` variants take an explicit id. Tests use those variants.

PDA seeds:

| Account | Seeds |
| :--- | :--- |
| Attested signer | `[b"attested_signer", signer_pubkey]` |
| VCEK | `[b"vcek_v2", chip_id_hash, tcb_version_le]` |
| Policy registry | `[b"policy_registry"]` |
| Used nonce | `[b"nonce", &[source], signer_pubkey, nonce_or_commitment]` (`derive_used_nonce_pda_for_source`, AMD=1, Nitro=2) |
| Legacy nonce guard (readonly, last account) | `[b"nonce", signer_pubkey, nonce_or_commitment]` (`derive_legacy_used_nonce_pda`) |

`is_signer_valid` is `current_slot <= expires_slot`. `@spec SCC-VERIFY-008`.

`mode_b_require_nonce` always returns `true`. `mode_b_discriminator` always returns `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR`. The `stateless_idempotent` argument is ignored. `@spec SCC-SEC-005`.

---

## 2. Instruction layouts

`ATTESTATION_TTL_SLOTS` is **216000**. The on-chain program writes `expires_slot = clock.slot + 216000`. The `expires_slot` argument on `build_register_signer_ix` is caller-side bookkeeping. The verifier does not read it.

| Constant | Value | Body |
| :--- | ---: | :--- |
| `VERIFY_AND_REGISTER_IX_LEN` | 1202 | 8 + 8 + 1184 + 2 bumps |
| `VERIFY_ATOMIC_WITH_NONCE_IX_LEN` | 1265 | 8 + 72 + 1184 + 1 bump |
| `PACKET_DATA_SIZE` | **1232** | `solana_sdk::packet::PACKET_DATA_SIZE` |
| `SNP_REPORT_SIZE` | 1184 | Re-export from `solana-confidential-compute-core` |

```
 Mode A data                         Mode B data
 +------+------+--------+            +------+--------+--------+
 | disc | slot | report | bumps |   | disc | header | report | bump |
 |  8   |  8   |  1184  |   2   |   |  8   |   72   |  1184  |  1   |
 +------+------+--------+-------+   +------+--------+--------+------+
 = 1202 bytes                        = 1265 bytes
```

`VERIFY_AND_REGISTER_DISCRIMINATOR` is `[246, 249, 100, 14, 102, 116, 92, 145]`.

`build_register_signer_ix` checks three facts before it returns the instruction:

1. The report length is 1184.
2. `SnpReportView::pubkey` equals the signer argument.
3. The bincode size of a one-instruction transaction is at most 1232 bytes.

`build_verify_atomic_with_nonce_ix` also requires the report measurement to equal the measurement argument. A mismatch returns `SdkError::MeasurementMismatch`.

A raw 1,184-byte report makes an instruction of 1,200 or 1,264 bytes. With account keys and signatures, the packet exceeds 1,232 bytes. The builder returns `SdkError::PacketTooLarge { len }`. It does not truncate the report.

---

## 3. Compute budget

This crate does not prepend a compute-budget instruction. It does not set a compute-unit price.

The ceiling the verifier must meet is 550,000 CU (`@spec SCC-PERF-001`, `@spec SCC-PERF-002`). The CLI sets the budget when it packs a dry-run transaction. `bins/solana-confidential-compute-cli` uses `COMPUTE_UNIT_LIMIT = 700_000` and optional `--priority-fee`. Put the same compute-budget instruction in front of an SDK instruction when you submit a transaction yourself.

```
 your transaction
 +---------------------------+---------------------------+
 | SetComputeUnitLimit       | solana-confidential-compute-sdk instruction     |
 | (you add this)            | (this crate builds this)  |
 +---------------------------+---------------------------+
```

The CU harness is `programs/solana-confidential-compute-verifier/tests/cu_benchmarks.rs`. It asserts a 550,000 CU ceiling. It does not live in this crate.

---

## 4. Send path and retries

The builders return an `Instruction` or a `Transaction`. They do not open an RPC connection. They do not loop on a failed send.

A retry loop is a caller concern. Build a new transaction when the blockhash expires. Keep the same report only when `nonce_slot` is still inside the 150-slot `SlotHashes` window (`@spec SCC-VERIFY-001`). A new slot hash needs a new hardware report, because the nonce is inside the signed bytes.

The local session builder receives a workload `Keypair` and signs locally. Keep that key inside the enclave; the production signing path is the sidecar `POST /v1/sign`, which this SDK does not call automatically. The coordinated upstream issue #186 fix rejects every System Program instruction before workload-key signing in both SDKs. Custom consumer programs, accounts, and data still require caller policy; the SDK does not provide the sidecar's transaction-screening guarantees. Require the #186 implementation in the selected release before relying on its System Program guard.

`build_atomic_attestation_tx` returns an unsigned transaction. The payer signs later. Instruction 0 is always `verify_atomic_with_nonce`.

---

## 5. Oversized packers

`solana_confidential_compute_sdk::internal` holds packers that skip the 1,232-byte check:

- `build_register_signer_ix_oversized`
- `build_register_signer_ix_for_program_oversized`
- `build_atomic_attestation_tx_oversized`
- `build_atomic_attestation_tx_for_program_oversized`
- `build_verify_atomic_with_nonce_ix_oversized`

Those functions are for tests and for dry inspection of the byte layout. The crate root does not re-export them. A packet larger than 1,232 bytes cannot land on the legacy cluster.

---

## 6. Errors

| Variant | Cause |
| :--- | :--- |
| `InvalidReportSize` | The report is not 1184 bytes. |
| `MeasurementMismatch` | Mode B measurement does not match the argument. |
| `SignerMismatch` | The report workload key does not match the signer argument. |
| `SignError` | `try_partial_sign` failed, or bincode failed. |
| `PacketTooLarge { len }` | Serialized length is greater than 1232. |

---

## 7. Minimal Mode A session

```rust
use solana_sdk::pubkey::Pubkey;
use solana_confidential_compute_sdk::ConfidentialComputeClient;

let program_id = "EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh".parse::<Pubkey>()?;
let client = ConfidentialComputeClient::new(program_id);
let workload_pubkey = Pubkey::new_unique();
let (pda, bump) = client.derive_signer_pda(&workload_pubkey.to_bytes());
```

Registration of a raw report returns `PacketTooLarge` from the public builder. Use a transport that fits the 1,232-byte packet, or keep the session path: attest once through a path that the cluster accepts, then send later transactions with `build_session_action_tx`. Those later transactions carry the Ed25519 signature only. They do not carry the 1,184-byte report.

## Mode B V3 action migration

`hash_compiled_action(message, consumer_index, split_hint)` commits complete consumer wire bytes and ordered effective signer/writable flags, including duplicate keys. The split hint is ignored. Compile complete transaction metadata with the final payer before obtaining evidence; `validate_compiled_action` must then check the final assembled message. Unresolved lookup tables and requested writable reserved accounts reject. Keep digest-derived nonce/upload addresses out of consumer accounts.

Upgrade verifier, consumer/CPI helpers, Rust/TypeScript SDKs and the sidecar final-message screen together, then obtain fresh V3 evidence. V1/V2 split digests have no fallback. The outer slot/action/program commitment is unchanged. See [the canonical format](../../SECURITY.md#spec-scc-sec-006).

---

## 8. Intel TDX

`EnclaveType::IntelTdx` is `5`. `verify_tdx_quote` writes that value on the Mode A signer record. `solana-confidential-compute-cpi` exposes the same tag as `AttestationPlatform::IntelTdx`. This crate re-exports `AttestationPlatform`.

`build_set_backend_policy_ix` and `derive_backend_policy_pda` accept source `5`. Pass source `5` to seat the Intel TDX allowlist (PCK leaf, Quoting Enclave identity, platform digest, and GPU RIM). An empty list halts new TDX admission.

This crate does not pack `issue_tdx_challenge`, `verify_tdx_qe_report`, or `verify_tdx_quote`. Those instructions, their account lists, and their discriminators are in [programs/solana-confidential-compute-verifier/README.md](../../programs/solana-confidential-compute-verifier/README.md). After the quote lands, use `build_session_action_tx` for the workload key. Pin `AttestationPlatform::IntelTdx` in the consumer. A TDX quote is Mode A only, so `build_atomic_attestation_tx` is not the TDX enrollment path.
