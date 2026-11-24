# Solana Confidential Compute Developer CLI Specifications

## Specification Catalog

### @spec SCC-CLI-001: Hardware Interface & Emulated Mock Fallback
WHEN `solana-confidential-compute prove` is invoked without `--mock`,  
THE CLI SHALL query `/dev/sev-guest` using the Linux upstream `SNP_GET_REPORT` ioctl (`_IOWR('S', 0x00, 32)` = `0xC020_5300`) with the 32-byte `snp_guest_request_ioctl` structure;  
WHERE the ioctl returns into the 4,032-byte `snp_report_resp` (leading `data: [u8; 4000]`, then a 32-byte reserved tail),  
THE CLI SHALL extract one 1,184-byte attestation report from that `data` buffer;  
WHERE `data[0..4]` is four zero bytes and `u32::from_le_bytes(data[4..8])` equals 1184,  
THE CLI SHALL take the report from `data[32..32+1184]` (PSP status, little-endian report size, and 24 reserved bytes precede the report);  
OTHERWISE, WHERE `data[0]` is an AMD report version in `1..=5` or the buffer has no PSP prefix,  
THE CLI SHALL take the report from `data[0..1184]`;  
THE CLI SHALL accept that report only when `report_size` equals `SNP_REPORT_SIZE` (1,184);  
THE CLI SHALL reject `report_size == 0` and every other non-1184 size;  
THE CLI SHALL accept the report only when the extracted report's bytes `0x50..0x90` equal the 64-byte `user_data` supplied in the guest request (`REPORT_DATA` echo);  
WHERE the device is missing, the platform is not Linux, `report_size` is not exact, or `REPORT_DATA` does not echo,  
THE CLI SHALL abort with an explicit hardware access error and SHALL NOT synthesize a report;  
WHERE `--mock` is specified,  
THE CLI SHALL generate a cryptographically valid mock report conforming to AMD Publication #56860 signed with an internal P-384 key.

### @spec SCC-CLI-002: Mode A Identity Attestation & Report Encoding
WHEN `solana-confidential-compute prove --mode stateful` (or `--mode-a`) is invoked,  
THE CLI SHALL query the recent slot hash from Solana RPC (or read from flag), encode `workload_pubkey[0..32]` and `slot_hash[0..32]` into `user_data[0..64]` (`REPORT_DATA`), verify the returned report signature locally, and construct the `verify_and_register` instruction targeting `solana-confidential-compute-verifier`;  
OTHERWISE the command SHALL abort with `InvalidArgument`.

### @spec SCC-CLI-003: Mode B Atomic Action Commitment Construction
WHEN `solana-confidential-compute prove --mode atomic` (or `--mode-b`) is invoked,  
THE CLI SHALL require `--action-hash` and `--consumer-program`, fetch the latest `slot_hash`, compute $\text{commitment} = \text{SHA-256}(\text{slot\_hash} \parallel \text{action\_hash} \parallel \text{consumer\_program\_id})$, inject `[0u8; 32] || commitment` into `REPORT_DATA`, and construct `verify_atomic_with_nonce`;  
WHERE `--stateless-idempotent` is specified,  
THE CLI SHALL abort with `InvalidArgument` and SHALL NOT construct `verify_atomic`. Stateless Mode B is disabled on-chain to prevent replay (finding H-01). All Mode B transactions require nonce consumption;  
OTHERWISE the command SHALL abort with `InvalidArgument`.

### @spec SCC-CLI-004: Compute Budget Injection & Dry-Run Transaction Output
WHEN constructing attestation transactions,  
THE CLI SHALL inject `ComputeBudgetProgram::set_compute_unit_limit(700_000)` and optional priority fees;  
WHERE `--dry-run` is active,  
THE CLI SHALL serialize and print the unsigned/signed transaction payload in base64/hex without submitting to the Solana network;  
OTHERWISE THE CLI SHALL sign and broadcast the transaction via Solana RPC.

### @spec SCC-CLI-005: Low-S Observability & Local Cryptographic Pre-Flight
WHEN parsing an attestation report prior to transaction packaging,  
THE CLI SHALL parse the P-384 $(r, s)$ signature, evaluate whether $s > \lfloor n / 2 \rfloor$, and emit a structured log if high-S is detected (@spec SCC-SEC-010);  
WHERE `--vcek-pubkey` is provided,  
THE CLI SHALL verify the signature against that 96-byte uncompressed X||Y public key, including when `--mock` is also set;  
WHERE `--mock` is active and `--vcek-pubkey` is omitted,  
THE CLI SHALL verify against the deterministic mock VCEK public key (`mock_vcek_public_key_xy`) and SHALL NOT use that mock key in any other case;  
WHERE `--mock` is omitted and `--vcek-pubkey` is omitted,  
THE CLI SHALL abort with `InvalidArgument` before opening `/dev/sev-guest`;  
OTHERWISE a signature that does not verify under the selected VCEK SHALL abort with `InvalidSignature` before spending SOL on network fees.

### @spec SCC-CLI-006: Authoritative Offline Incident Controls
WHEN `governance emergency-halt --source N` is invoked with N in 1..=3,
THE CLI SHALL export an unsigned `set_backend_policy` instruction with an empty list for that source's canonical PDA;
WHEN `set-backend-policy` supplies reviewed measurements, THE CLI SHALL export the same setter to resume that source (maximum eight 48-byte measurements);
THE CLI SHALL expose `revoke-vcek` and `set-gcp-tenant-policy` with the existing SDK validation and account privileges;
THE CLI SHALL describe `update-policy` global measurements as deprecated and warn that clearing them does not halt runtime admission. Exports require external blockhash replacement, signatures, submission and on-chain verification. Existing Mode A sessions require separate revocation.
