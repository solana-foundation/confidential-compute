# AWS Nitro Enclaves Attestation Specifications

## Specification Catalog

### @spec SCC-NITRO-001: Zero-Copy CBOR Decoder Core
WHEN decoding binary payloads in `solana-confidential-compute-crypto::cbor`,  
THE system SHALL decode CBOR data items (Major types 0–5: unsigned integer, negative integer, byte string, text string, array, map) without heap allocations, returning zero-copy byte slice references into the input buffer;  
OTHERWISE parsing SHALL fail with `CryptoError::MalformedCbor`.

### @spec SCC-NITRO-002: COSE Sign1 Structure Parser & Sig_structure Construction
WHEN parsing an AWS Nitro attestation document,  
THE system SHALL decode the 4-element COSE Sign1 structure `[protected_headers, unprotected_headers, payload, signature]`, assert protected header contains algorithm ES384 (`alg = -35`), extract the 96-byte P-384 signature `[r || s]`, and construct the canonical CBOR `Sig_structure = ["Signature1", protected_headers, external_aad (b""), payload]` for cryptographic verification;  
OTHERWISE parsing SHALL fail with `CryptoError::InvalidCoseStructure`.

### @spec SCC-NITRO-003: Nitro Attestation Payload Field Extraction
WHEN parsing the CBOR map payload of a Nitro attestation document,  
THE system SHALL parse and extract:
1. `module_id`: UTF-8 text string identifying the Nitro module,
2. `timestamp`: UTC millisecond timestamp (u64),
3. `digest`: text string asserting `"SHA384"`,
4. `pcrs`: map of PCR index (u8) to 48-byte SHA-384 digest, specifically extracting `PCR0` (EIF image), `PCR1` (kernel), `PCR2` (application), and `PCR8` (signing cert),
5. `certificate`: DER-encoded X.509 leaf certificate,
6. `cabundle`: array of DER-encoded X.509 intermediate CA certificates,
7. `user_data`: byte string containing the 32-byte Ed25519 workload public key,
8. `nonce`: byte string containing the 32-byte fresh Solana slot blockhash;  
OTHERWISE the parser SHALL fail with `CryptoError::InvalidAttestationPayload`.

### @spec SCC-NITRO-004: AWS Nitro X.509 Certificate Chain Verification
WHEN verifying the AWS Nitro certificate hierarchy,  
THE system SHALL verify the certificate chain from the pinned AWS Nitro Root CA public key through intermediate CAs in `cabundle` down to the leaf certificate, enforcing valid validity windows, ECDSA P-384 signatures, and SHA-384 digests;  
OTHERWISE verification SHALL fail with `CryptoError::CertificateChainInvalid`.

### @spec SCC-NITRO-005: COSE Sign1 P-384 Signature Verification
WHEN verifying the COSE Sign1 signature against `Sig_structure`,  
THE system SHALL verify the 96-byte ECDSA P-384 signature against the leaf certificate's P-384 public key over `SHA-384(Sig_structure)`;  
OTHERWISE verification SHALL fail with `CryptoError::InvalidSignature`.

### @spec SCC-NITRO-006: PCR0 Measurement Policy Assertion
WHEN an on-chain `verify_nitro_attestation` instruction is executed,  
THE system SHALL assert that `PCR0` (48 bytes) is non-zero and matches an approved entry in the Nitro `BackendPolicy.measurements` (source 2);  
OTHERWISE the transaction SHALL abort with `VerifierError::DisallowedMeasurement`.

### @spec SCC-NITRO-007: Nitro Nonce Freshness and Anti-Replay Gate
WHEN `verify_nitro_attestation` executes in either Mode A or Mode B,  
THE system SHALL verify that the payload `nonce` matches a recent `SlotHashes` sysvar entry (`clock.slot - nonce_slot <= 150`), and enforce that no `UsedNonceAccount` PDA exists for `[b"nonce", signer_pubkey, nonce]`, creating the 49-byte nonce record PDA (which stores the signing payer for `close_stale_nonce` refunds) via CPI;  
OTHERWISE the transaction SHALL abort with `VerifierError::StaleNonce` or `VerifierError::NonceAlreadyUsed`.

### @spec SCC-NITRO-008: On-Chain Instruction Dispatch (Mode A & Mode B)
WHEN executing `verify_nitro_attestation`:
- **Mode A (`verify_and_register_nitro`):** Registers the workload Ed25519 public key in `AttestedSignerAccount` with `enclave_type = EnclaveType::AwsNitro` and `expires_slot = current_slot + ttl_slots`, plus the exclusive `expires_unix_timestamp` deadline. Consumers enforce both slot and Unix expiry (see [V2 contract](confidential-compute-verifier-specs.md#current-mode-a-v2-contract)).
- **Mode B (`verify_atomic_nitro`):** Validates the attestation atomically within Instruction 1 of a multi-instruction transaction, committing to `action_hash` and allowing downstream consumers to introspect via `sysvar::instructions`.


### Backend measurement governance

`BackendPolicy` is authoritative for measurement admission: source 1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space. Each canonical PDA uses `[b"backend_policy", &[source]]` and holds up to eight measurements. Missing, empty, or mismatched backend policy fails closed. The global `PolicyRegistry.measurement_count` / `measurements` fields and `update_policy` measurement payload are deprecated as runtime controls and retained for state/wire compatibility; clearing that global list does not halt admission. There is no implicit global/backend allowlist AND. Registry authority checks and monotonic AMD TCB floors remain active.

To halt new admission, the registry authority uses `set_backend_policy` with an empty list (`[]`) for each relevant backend; update all three policies to halt all backends. Rust exposes `build_set_backend_policy_ix`, TypeScript `buildSetBackendPolicyIx`. This does not revoke existing Mode A sessions: use `revoke_attested_signer` separately for targeted containment. These are source contracts, not evidence of deployment or hardware/SBF validation.
