# Solana Confidential Compute Verifier Specifications

## Specification Catalog

### @spec SCC-VERIFY-001: Report Data Nonce Freshness
WHEN the on-chain verifier executes `verify_and_register`,  
THE system SHALL verify that the passed `slot_hashes_account.key` matches `sysvar::slot_hashes::ID`, parse the nonce from signed report bytes `0x070..0x090`, and verify against the `SlotHashes` entry at `nonce_slot` with an age `clock.slot - nonce_slot <= 150` slots;  
OTHERWISE the transaction SHALL abort with `VerifierError::StaleNonce`.

### @spec SCC-VERIFY-002: Binary Measurement Allowlist
WHEN an attestation report is processed,  
THE system SHALL parse the 48-byte measurement from signed report bytes `0x090..0x0C0`, assert it is not all zeros, and verify that it matches an active entry in the source-specific `BackendPolicy.measurements`;  
OTHERWISE the transaction SHALL abort with `VerifierError::DisallowedMeasurement`.

### @spec SCC-VERIFY-003: P-384 AMD VCEK Chain Validation & 2-Stage Caching
WHEN a `register_vcek` instruction is executed,  
THE system SHALL cryptographically verify the ECDSA P-384 certificate chain from the trusted AMD Root Key (ARK) through the AMD Signing Key (ASK) down to the Versioned Chip Endorsement Key (VCEK), extract `chip_id`, `tcb_version`, and uncompressed P-384 public key from certificate extensions, and allocate an immutable `VcekAccount` PDA derived from `[b"vcek_v2", &sha256(chip_id)[..], &tcb_version.to_le_bytes()]` via System Program CPI `create_account`;  
OTHERWISE the transaction SHALL abort with `VerifierError::VerificationFailed`.

### @spec SCC-VERIFY-004: Attested Signer PDA Registration & Lifecycle
WHERE the attestation report signature, measurement, TCB, and nonce are valid,  
THE system SHALL allocate an `AttestedSignerAccount` PDA derived from `[b"attested_signer_v2", signer_pubkey]` via CPI `create_account` (or reuse existing PDA), prepended with Anchor discriminator `[43, 255, 114, 40, 233, 28, 127, 238]`, storing `registered_slot`, `expires_slot = registered_slot + ttl_slots`, and an exclusive `expires_unix_timestamp` deadline; the V2 serialized size SHALL be 154 bytes. Re-attestation over an existing account SHALL be permitted ONLY IF `current_slot > expires_slot` OR the existing `signer_pubkey` matches and an unused nonce is verified;<br>
OTHERWISE the transaction SHALL abort with `ProgramError::AccountAlreadyInitialized`.

### @spec SCC-VERIFY-005: Root Trust & TCB Policy Authority and Re-Initialization Guard
WHEN `init_policy_registry` is executed on an already initialized registry,  
THE system SHALL abort with `ProgramError::AccountAlreadyInitialized`;  
WHEN `rotate_root_cert` or `update_policy` is executed,  
THE system SHALL verify that the transaction is signed by `policy_registry.authority` before mutating allowlists or minimum TCB parameters;  
AND `rotate_root_cert` SHALL then abort with `VerifierError::InvalidInstruction` without mutating `ark_pubkey_xy` (#255);  
OTHERWISE the transaction SHALL abort with `ProgramError::MissingRequiredSignature`.

The authority may be a keypair or a governance PDA signing through CPI. Solana Confidential Compute does not enforce multisig membership, a threshold, or a timelock. Registry governance and loader upgrade authority are separate; see the [trust model](../../SECURITY.md#administrative-authorities-and-trust-roots).

### @spec SCC-VERIFY-006: In-Window Replay Defense & Nonce Allocation
WHEN an attestation report is verified,  
THE system SHALL assert that no `UsedNonceAccount` PDA exists for `[b"nonce", signer_pubkey, nonce]`, and allocate the `UsedNonceAccount` PDA via CPI `create_account`;  
OTHERWISE the transaction SHALL abort with `VerifierError::NonceAlreadyUsed`.

### @spec SCC-VERIFY-007: Minimum TCB Component-Wise Enforcement
WHEN an attestation report is verified,  
THE system SHALL parse the 8-byte TCB from signed report bytes `0x180..0x188` and assert component-wise that `boot_loader >= min_boot_loader`, `tee >= min_tee`, `snp >= min_snp`, and `microcode >= min_microcode`;  
OTHERWISE the transaction SHALL abort with `VerifierError::TcbBelowMinimum`.

### @spec SCC-SEC-001: Debug and Migration Policy Rejection
WHEN an attestation report is verified,  
THE system SHALL parse the 8-byte guest policy, 4-byte VMPL, 4-byte version, and 4-byte signature algo from signed report bytes and assert that:
1. Policy bit 19 (`GUEST_POLICY_DEBUG`) is 0 (`(policy & (1 << 19)) == 0`),
2. Policy bit 18 (`GUEST_POLICY_MIGRATE_MA`) is 0 (`(policy & (1 << 18)) == 0`),
3. Policy bit 17 (`GUEST_POLICY_RESERVED_MUST_BE_ONE`) is 1 (`(policy & (1 << 17)) != 0`),
4. Policy bit 16 (`GUEST_POLICY_SMT`) is allowed and is not required,
5. `vmpl` is 0,
6. Report `version` is within `1..=5`,
7. `signature_algo` is 1 (P-384 ECDSA);  
OTHERWISE the transaction SHALL abort with `VerifierError::UnauthorizedPolicy`.

### @spec SCC-SEC-002: Measurement Floor & Allowlist Enforcement
WHEN an attestation report or a Nitro document is verified,  
THE system SHALL reject an all-zero launch measurement and an all-zero or uninitialized PCR0;  
AND THE signed measurement SHALL match an active entry in the source-specific `BackendPolicy.measurements`;  
OTHERWISE the transaction SHALL abort with `VerifierError::DisallowedMeasurement`.

### @spec SCC-SEC-003: Pinned Root CA & Cryptographic Chain Validation
WHEN an AMD SEV-SNP report or an AWS Nitro document is verified,  
THE system SHALL validate the AMD chain against the pinned AMD Root Key (ARK) and AMD Signing Key (ASK);  
AND THE system SHALL validate the Nitro chain against the pinned AWS Nitro Root CA G1 (`AWS_NITRO_ROOT_CA_PUBKEY_XY`);  
AND THE system SHALL verify P-384 ECDSA signatures over SHA-384 digests;  
OTHERWISE the transaction SHALL abort with `VerifierError::VerificationFailed` or `VerifierError::InvalidSignature`.

### @spec SCC-PERF-001: Stage 2 Workload Registration Compute Unit Ceiling
WHEN executing the `verify_and_register` instruction on-chain (Stage 2),  
THE total compute units consumed SHALL NOT exceed 550,000 CUs.

### @spec SCC-PERF-002: Mode B Atomic Attestation Compute Unit Ceiling
WHEN executing the `verify_atomic_with_nonce` instruction on-chain (Mode B),  
THE total compute units consumed SHALL NOT exceed 550,000 CUs.

Mode B allocates a `UsedNonceAccount` PDA to prevent replay, so its compute cost is comparable to Mode A `verify_and_register`; both remain bounded by 550,000 CUs.

### @spec SCC-PERF-003: Automated SBF CU Regression Benchmark Suite
WHEN the integration test `cu_benchmarks` is executed,  
THE harness SHALL execute under the Solana program test runtime, measure exact compute units consumed for each instruction, record scalar benchmark metrics, and assert that all instructions satisfy their respective compute unit ceilings.

### @spec SCC-VERIFY-008: Workload Signer Expiration Enforcement
WHEN a consumer protocol validates an `AttestedSignerAccount` PDA,  
THE system SHALL read the trusted Clock and assert both `current_slot <= attested_signer.expires_slot` and `0 <= clock.unix_timestamp < attested_signer.expires_unix_timestamp`;<br>
OTHERWISE the transaction SHALL abort with `VerifierError::AttestationExpired`.

### @spec SCC-VERIFY-009: VLEK Zero Chip ID & KeySel Derivation
WHEN registering or resolving a `VcekAccount` where the AMD report `chip_id` is all zeros (`[0u8; 64]`, e.g. multi-tenant GCP Confidential VMs) or `key_sel == 1`,  
THE system SHALL derive the PDA seed using `sha256(vcek_cert_public_key)` rather than `sha256(chip_id)`;  
OTHERWISE the system SHALL use `sha256(chip_id)`.

### @spec SCC-ARCH-001: On-Chain PDA Lifecycle and System Program CPI Allocation
WHEN allocating any program PDA (`PolicyRegistry`, `VcekAccount`, `AttestedSignerAccount`, `UsedNonceAccount`) or resolving an existing Stage 2 PDA,  
THE system SHALL invoke `system_instruction::create_account` via `invoke_signed` funded by `payer` when the account is unallocated, assert `account.owner == program_id` for program accounts, and assert `account.is_writable == true` for writable accounts;  
AND THE Stage 2 hot path SHALL resolve nonce and attested-signer addresses with canonical `Pubkey::find_program_address` and SHALL require the bump from that call;  
AND THE system SHALL reject a bump that `Pubkey::create_program_address` accepts when that bump is not the canonical `find_program_address` bump, so an alternate bump cannot replay the same report against a different PDA;  
OTHERWISE the transaction SHALL abort with `ProgramError::InvalidAccountData`, `ProgramError::InvalidArgument`, or `VerifierError::InvalidAccountAddress`.

### @spec SCC-ARCH-002: Zero-Copy Instruction Borrowing and SBF Stack Safety
WHEN processing an AMD SEV-SNP attestation report on SBF,  
THE system SHALL borrow the 1,184-byte report slice directly from the instruction data without stack or heap copying, and SHALL read `PolicyRegistry` and `VcekAccount` fields from account data slices without Borsh-deserializing those accounts onto the stack;  
OTHERWISE the transaction risks SBF 4 KiB stack frame overflow.

### @spec SCC-VERIFY-010: Mode B Atomic Attestation (verify_atomic)
WHEN executing the `verify_atomic` instruction on-chain,  
THE system SHALL abort fail-closed with `VerifierError::NonceRequired`;  
AND Mode B verification SHALL proceed only through `verify_atomic_with_nonce`, which zero-copy borrows the 80-byte `VerifyAtomicHeader` and 1,184-byte report at offset `0x50..0x4F0`, loads the 32-byte `slot_hash` directly from the pinned `SlotHashes` sysvar via `load_slot_hash(nonce_slot)` with age $\le 150$ slots, verifies the P-384 ECDSA signature against cached `VcekAccount`, verifies hardware security policies, and consumes a `UsedNonceAccount` PDA;  
OTHERWISE the transaction SHALL abort with `VerifierError::NonceRequired`, `VerifierError::StaleNonce`, `VerifierError::InvalidSignature`, `VerifierError::UnauthorizedPolicy`, or `VerifierError::NonceAlreadyUsed`.

### @spec SCC-VERIFY-011: Mode B Nonce Variant Allocation (verify_atomic_with_nonce)
WHEN executing the `verify_atomic_with_nonce` instruction on-chain (the canonical Mode B path),  
THE system SHALL execute cryptographic and policy checks (zero-copy report borrow, SlotHashes freshness, VCEK signature, hardware policy), assert that no `UsedNonceAccount` PDA exists for `[b"nonce", signer_pubkey, commitment]`, and allocate the 49-byte `UsedNonceAccount` PDA via System Program CPI funded by `payer`, recording `payer` as `refund_pubkey`;  
AND `verify_atomic` SHALL abort fail-closed with `VerifierError::NonceRequired` and SHALL NOT perform those checks;  
OTHERWISE the transaction SHALL abort with `VerifierError::NonceAlreadyUsed`.

### @spec SCC-VERIFY-012: Mode B Action Commitment Binding
WHEN processing a Mode B atomic attestation via `verify_atomic_with_nonce` (the canonical Mode B path),  
THE system SHALL compute $\text{expected\_commitment} = \text{SHA-256}(\text{slot\_hash} \parallel \text{header.action\_hash} \parallel \text{header.consumer\_program\_id})$ using `solana_program::hash::hashv` and assert that $\text{REPORT\_DATA}[32..64] == \text{expected\_commitment}$;  
AND `verify_atomic` SHALL abort fail-closed with `VerifierError::NonceRequired` before commitment evaluation;  
OTHERWISE the transaction SHALL abort with `VerifierError::ActionHashMismatch`.

### @spec SCC-VERIFY-013: Consumer Instruction Introspection & Ordering Guard
WHEN a consumer protocol executes `solana_confidential_compute_cpi::assert_attestation_atomic`,  
THE system SHALL assert `instructions_sysvar.key == sysvar::instructions::ID`, load `current_index` from `load_current_index_checked` (the caller SHALL NOT supply this index), resolve `confidential_compute_ix_index` to `current_index - 1` when the consumer requests the preceding instruction, assert `confidential_compute_ix_index < current_index`, assert `confidential_compute_ix.program_id == solana_confidential_compute_verifier::ID`, reject `require_nonce == false` with `CpiError::NonceRequired`, assert the discriminator equals `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR`, assert `header.consumer_program_id == current_program_id`, assert `header.action_hash == expectation.action_hash`, and assert report measurement and workload signer match expectations;  
OTHERWISE the transaction SHALL abort with `ProgramError::InvalidInstructionData`, `ProgramError::IncorrectProgramId`, `VerifierError::UnauthorizedPolicy`, `VerifierError::ActionHashMismatch`, `VerifierError::DisallowedMeasurement`, `VerifierError::SignerMismatch`, or `VerifierError::NonceRequired`.

### @spec SCC-VERIFY-014: Canonical Action Hash Binding
WHEN a consumer protocol constructs a Mode B `action_hash`,
THE system SHALL compute V3 SHA-256 over `b"solana-confidential-compute:action:v1\0" || account_count:u32LE || (pubkey32 || signer:u8 || writable:u8)* || complete_wire_data_length:u32LE || complete_instruction_data`, retaining ordered duplicates and final compiled-message privileges; the discriminator and payload SHALL concatenate into complete wire bytes without a separately committed split;
AND off-chain preparation SHALL compile complete transaction metadata with the final payer, reject unresolved lookup tables and requested writable reserved accounts, and validate the final assembled message; V1/V2 digests SHALL have no fallback and the coordinated upgrade SHALL require fresh V3 evidence;
THE consumer SHALL hash effective top-level `AccountInfo` flags before CPI; SDK program-id demotion and its upgradeable-loader exception SHALL apply. Consumer data SHALL be final before attesting; other instruction data MAY be empty. Digest-derived nonce/upload addresses SHALL NOT be consumer keys. See the [source-linked wire/API and construction contract](../../crates/solana-confidential-compute-cpi/README.md#4-hash_action).
OTHERWISE account substitution, account-count shifting, or argument tampering is not bound into the attestation commitment.

### @spec SCC-VERIFY-015: Mode A Attested Signer Consumer Guard
WHEN a consumer protocol executes `solana_confidential_compute_cpi::assert_attestation_signer`,  
THE system SHALL load `clock = Clock::get()` and `current_slot = clock.slot` (the caller SHALL NOT supply a slot or Unix timestamp), assert `attested_record.owner == solana_confidential_compute_cpi::ID`, assert the 8-byte discriminator equals `ATTESTED_SIGNER_DISCRIMINATOR`, assert PDA seeds `[b"attested_signer_v2", workload_signer]` match `attested_record.key`, assert `workload_signer.is_signer == true`, assert the stored platform equals caller-pinned `expected_platform`, assert the stored measurement equals `expected_measurement`, and assert `current_slot <= expires_slot` and `0 <= clock.unix_timestamp < expires_unix_timestamp`;<br>
THE system SHALL return `expires_slot` when all checks pass;  
OTHERWISE the transaction SHALL abort with `ProgramError::IncorrectProgramId`, `ProgramError::InvalidAccountData`, `ProgramError::InvalidSeeds`, `ProgramError::MissingRequiredSignature`, `VerifierError::DisallowedMeasurement`, `VerifierError::SignerMismatch`, or `VerifierError::AttestationExpired`.

### @spec SCC-SEC-009: AMD Signature Format & Scalar Bounds
WHEN parsing the 512-byte signature block starting at offset `0x2A0`,  
THE system SHALL extract the 72-byte Little-Endian field for $r$ (offset `0x2A0..0x2E8`) and $s$ (offset `0x2E8..0x330`), verify bytes `48..72` are strictly zero, convert the first 48 bytes to big-endian P-384 scalars, and verify `signature_algo == 1` at offset `0x034`;  
OTHERWISE the transaction SHALL abort with `VerifierError::InvalidSignature`.

### @spec SCC-SEC-010: AMD PSP P-384 Signature Specification & Observability
WHEN verifying ECDSA P-384 signatures from AMD SEV-SNP reports (AMD Publication #56860 Table 141),  
THE system SHALL accept signatures conforming to FIPS 186-4 without requiring canonical low-S normalization ($s \le \lfloor n / 2 \rfloor$);  
AND THE developer CLI (`solana-confidential-compute-cli`) SHALL record off-chain telemetry logging instances where $s > \lfloor n / 2 \rfloor$ across target silicon.

### @spec SCC-ARCH-003: Pluggable Verification Backend Trait
THE system SHALL define a `SignatureVerifier` trait in `solana-confidential-compute-core` / `solana-confidential-compute-verifier` abstracting signature verification across three execution backends:
1. `MockVerifier`: Test double for deterministic SBF unit testing and CU metering.
2. `Groth16SyscallVerifier`: In-process zkVM proof verification invoking Solana's native `alt_bn128_pairing` syscall (~150,000 CUs, Track B).
3. `InstructionIntrospectionVerifier`: Decoupled precompile adapter introspecting preceding signature verification instructions via `sysvar::instructions` (~25,000 CUs, Track A);  
AND THE orchestrator SHALL execute identically across all backends without altering policy, replay, or Mode A/B account lifecycle logic.

### @spec SCC-VERIFY-016: Precompile Instruction Introspection & Security Binding
WHEN the orchestrator utilizes `InstructionIntrospectionVerifier` to validate a signature,  
THE system SHALL assert `instructions_sysvar.key == sysvar::instructions::ID`, load `current_index` via `load_current_index_checked`, resolve the signature instruction at relative index `current_index - 1` (or checked preceding offset), assert `sig_ix.program_id == EXPECTED_SIGVERIFY_PROGRAM_ID`, parse `(pubkey, message_digest, signature)` at fixed offsets, recompute `SHA-384(report_signed_bytes)` from the borrowed report slice, and assert that the precompile `message_digest` strictly equals the recomputed hash;  
OTHERWISE the transaction SHALL abort with `ProgramError::IncorrectProgramId`, `ProgramError::InvalidInstructionData`, or `VerifierError::InvalidSignature`.

### @spec SCC-VERIFY-017: zkVM Groth16 Proof Verification via Native alt_bn128 Syscall
WHEN the orchestrator utilizes `Groth16SyscallVerifier` to validate an AMD SEV-SNP report or VCEK certificate chain (Track B),  
THE system SHALL parse the 128-byte Groth16 proof (compressed points $A \in G_1$, $B \in G_2$, $C \in G_1$), reject the identity/all-zero proof, bind the public input $x_1$ to `sha256(public_key_xy || message_digest)`, compute $L = IC_0 + x_1 \cdot IC_1$ over the verifying key $(\alpha \in G_1, \beta \in G_2, \gamma \in G_2, \delta \in G_2, IC \in [G_1; 2])$, negate $A$ by replacing its $y$-coordinate with $p - y$ modulo the BN254 base-field prime, and evaluate the 4-pairing equation $e(-A, B) \cdot e(\alpha, \beta) \cdot e(L, \gamma) \cdot e(C, \delta) = 1$ over a 768-byte `alt_bn128_pairing` input consuming $\le 150,000$ CUs;  
OTHERWISE the transaction SHALL abort with `VerifierError::InvalidProof`. Dummy proofs with $A = -C$ and mismatched public inputs SHALL be rejected.

### @spec SCC-SEC-004: Zero-Trust Timestamps & Slot Freshness
WHEN the on-chain verifier checks attestation freshness,  
THE system SHALL validate the nonce against `sysvar::slot_hashes::ID` and SHALL reject an age greater than 150 slots;  
AND a consumer helper SHALL load the current slot and Unix timestamp exclusively via `Clock::get()` and SHALL NOT accept a caller-supplied timestamp;<br>
AND `programs/solana-confidential-compute-verifier` SHALL load `Clock::get()` without `unwrap_or_default` so a missing Clock sysvar aborts with `VerifierError::InvalidAccountAddress`;  
OTHERWISE the transaction SHALL abort with `VerifierError::StaleNonce`, `VerifierError::AttestationExpired`, or `VerifierError::InvalidAccountAddress`.

### @spec SCC-SEC-005: Replay Defense & Nonce Single-Use
WHEN Mode B atomic attestation is requested,  
THE on-chain `verify_atomic` path SHALL abort with `VerifierError::NonceRequired`, and `solana_confidential_compute_cpi::assert_attestation_atomic` SHALL require `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR` and reject `require_nonce == false`;  
AND `verify_atomic_with_nonce` SHALL allocate a 49-byte `UsedNonceAccount` PDA seeded `[b"nonce", signer_pubkey, commitment]` so the same report cannot be replayed inside the 150-slot SlotHashes window;  
AND a duplicate submission SHALL abort with `VerifierError::NonceAlreadyUsed` (custom error 5) whether the PDA holds a 49-byte record or a legacy 17-byte record;  
AND `close_stale_nonce` SHALL close a 49-byte record only when `clock.slot - slot > 150` and only to its recorded `refund_pubkey`, and SHALL refuse legacy 17-byte records;  
OTHERWISE the transaction SHALL abort with `VerifierError::NonceRequired` or `VerifierError::NonceAlreadyUsed`.

### @spec SCC-SEC-006: Action Commitment Binding
WHEN a Mode B attestation is verified,  
THE system SHALL require `REPORT_DATA[32..64] = SHA-256(slot_hash || action_hash || consumer_program_id)`;  
AND `action_hash` SHALL use the V3 complete-instruction and effective-privilege encoding in @spec SCC-VERIFY-014; all three Mode B verifier paths SHALL recompute it from the immediately following Instructions-sysvar instruction before any nonce write;
OTHERWISE the transaction SHALL abort with `VerifierError::ActionHashMismatch`.

### @spec SCC-SEC-007: Enclave Memory Hygiene & Key Zeroization
WHEN `bins/solana-confidential-compute-sidecar` holds an enclave signing key,  
THE system SHALL implement `Drop` with `zeroize::Zeroize` and SHALL clear the ephemeral private key from memory on rotation or process exit;  
AND the default bind address SHALL be `127.0.0.1:8080`.

### @spec SCC-SEC-008: Memory Alignment & Bounded Parser Safety
WHEN the verifier or a consumer helper parses account data, CBOR, or DER,  
THE system SHALL use 1-byte-aligned `bytemuck::Pod` representations for introspection accounts;  
AND CBOR skip depth SHALL NOT exceed `MAX_CBOR_SKIP_DEPTH = 8`;  
AND a Nitro document SHALL NOT exceed `MAX_NITRO_DOCUMENT_LEN = 8192`;  
AND deserialization SHALL return `Result` and SHALL NOT panic;  
OTHERWISE the call SHALL return an error.

### @spec SCC-DEPLOY-001: SBPFv3 Target & Agave v4 ELF Conformance
WHEN compiling `programs/solana-confidential-compute-verifier` for cluster deployment or upgrade,  
THE system SHALL produce an SBPFv3 ELF via `cargo-build-sbf --arch v3` (or `cargo build-sbf --arch v3`) whose 64-byte ELF header sets `e_flags = 0x3`, resolve syscalls at link time via static Murmur3-32 hashes (SIMD-0178, required by SIMD-0500) rather than load-time symbol-table relocations, and satisfy strict ELF header validation (fixed `PT_LOAD` segment layout and order, no runtime text relocations, no `.rodata` copy-on-load);  
AND THE build gate (`scripts/build-sbpfv3.sh`) SHALL reject the artifact unless `readelf -h target/deploy/solana_confidential_compute_verifier.so` reports `Flags` matching `0x3`;  
OTHERWISE Agave v4.4 SHALL reject new deployments, upgrades, and finalizations of the program when the SIMD-0500 feature gate is active.

### @spec SCC-ANCHOR-001: Anchor Zero-Copy AttestedSignerAccount Deserialization
WHEN a consumer protocol loads `solana_confidential_compute_cpi::AttestedSignerAccount` from account data,  
THE system SHALL zero-copy decode the 154-byte packed layout via `bytemuck` (`Pod`) without Borsh or heap allocation, assert the 8-byte discriminator equals `ATTESTED_SIGNER_DISCRIMINATOR`, and assert `account.owner == solana_confidential_compute_verifier::ID`;<br>
AND `AttestedSignerAccount::validate` SHALL retrieve the current slot and Unix timestamp exclusively via `clock = Clock::get()` (the caller SHALL NOT supply a slot or Unix timestamp), assert the stored platform equals caller-pinned `expected_platform`, assert the stored measurement equals `expected_measurement`, and assert `current_slot <= expires_slot` and `0 <= clock.unix_timestamp < expires_unix_timestamp`;<br>
AND Mode A session consumers SHALL bind caller authenticity by requiring `workload_signer.is_signer == true` and `attested.signer_pubkey == workload_signer.key.to_bytes()` (via `AttestedSignerAccount::validate_session_signer` or equivalent) before accepting the session; record authenticity remains owner + discriminator (PDA re-derivation is optional defense-in-depth and is not required to stay under the 1,500 CU Mode A ceiling);  
`validate` alone is NOT sufficient to authenticate the caller;  
OTHERWISE the transaction SHALL abort with `ProgramError::IncorrectProgramId`, `ProgramError::InvalidAccountData`, `ProgramError::MissingRequiredSignature`, `VerifierError::SignerMismatch`, `VerifierError::DisallowedMeasurement`, or `VerifierError::AttestationExpired`.

### @spec SCC-ANCHOR-002: Mode B Anchor Instruction Introspection Adapter
WHEN a consumer protocol executes `solana_confidential_compute_cpi::assert_attestation_atomic_ctx` or `assert_attestation_atomic_ctx!`,  
THE system SHALL read the Instructions sysvar from the Anchor instruction context, invoke `solana_confidential_compute_cpi::assert_attestation_atomic`, and reject `require_nonce == false` with `CpiError::NonceRequired` (@spec SCC-SEC-005 SCC-VERIFY-013);  
OTHERWISE the transaction SHALL abort with `VerifierError::NonceRequired` or the errors specified by @spec SCC-VERIFY-013.

### @spec SCC-CONSUMER-001: Mode A Reference Consumer Verification
WHEN a consumer protocol executes `execute_session_action` in `programs/solana-confidential-compute-consumer-reference`,  
THE system SHALL load `attested_info` from `accounts[0]` and `workload_signer` from `accounts[1]`;  
THE system SHALL abort with `ProgramError::MissingRequiredSignature` unless `workload_signer.is_signer == true`;  
THE system SHALL load `solana_confidential_compute_cpi::AttestedSignerAccount` via `try_from_account_info` (owner and discriminator fail-closed);  
THE system SHALL abort with `VerifierError::SignerMismatch` unless `attested.signer_pubkey == workload_signer.key.to_bytes()`;  
THE system SHALL call `attested.validate(&expected_measurement, expected_platform)`, which retrieves both slot and Unix timestamp via `Clock::get()` and checks both expiry bounds (@spec SCC-SEC-004 SCC-ANCHOR-001);<br>
AND the consumer check SHALL consume no more than 1,500 compute units with zero heap allocation in the instruction handler;  
OTHERWISE the transaction SHALL abort with `ProgramError::NotEnoughAccountKeys`, `ProgramError::MissingRequiredSignature`, `ProgramError::IncorrectProgramId`, `ProgramError::InvalidAccountData`, `VerifierError::SignerMismatch`, `VerifierError::DisallowedMeasurement`, or `VerifierError::AttestationExpired`.

### @spec SCC-CONSUMER-002: Mode B Reference Consumer Atomic Introspection
WHEN a consumer protocol executes `execute_atomic_action` in `programs/solana-confidential-compute-consumer-reference`,  
THE system SHALL compute V3 `action_hash` with `solana_confidential_compute_cpi::hash_action_account_infos` over complete instruction bytes (`[IX_EXECUTE_ATOMIC_ACTION]` concatenated with `instruction_data[1..]`) and every ordered account key with its effective signer/writable flags;
THE system SHALL NOT accept a caller-supplied action hash in place of that digest;  
THE system SHALL invoke `solana_confidential_compute_cpi::assert_attestation_atomic_ctx` with that `action_hash` and `require_nonce == true` (@spec SCC-SEC-005 SCC-ANCHOR-002 SCC-VERIFY-013 SCC-VERIFY-014);  
AND the consumer check SHALL consume no more than 2,500 compute units with zero heap allocation in the instruction handler;  
OTHERWISE the transaction SHALL abort with `VerifierError::NonceRequired`, `VerifierError::ActionHashMismatch`, or the errors specified by @spec SCC-VERIFY-013.

### @spec SCC-SDK-001: Rust Client SDK Transaction Builders
WHEN a host client constructs Solana Confidential Compute transactions through `crates/solana-confidential-compute-sdk`,  
THE system SHALL provide `build_register_signer_ix` packing `verify_and_register` (`VERIFY_AND_REGISTER_DISCRIMINATOR`, 8-byte little-endian `nonce_slot`, 1,184-byte SNP report) targeting `[payer, policy_registry, vcek, attested_signer, used_nonce, slot_hashes, clock, system_program]`;  
AND `build_session_action_tx` SHALL wrap a caller-supplied consumer instruction and partial-sign with the attested workload Ed25519 keypair;  
AND `build_atomic_attestation_tx` SHALL pack `verify_atomic_with_nonce` at instruction index 0 and the consumer instruction at index 1, using `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR` with `require_nonce == true` (@spec SCC-SEC-005 SCC-VERIFY-011 SCC-VERIFY-013);  
AND the builders SHALL reject a report that is not exactly 1,184 bytes, a Mode A signer that does not match `REPORT_DATA[0..32]`, and a Mode B measurement that does not match report bytes `0x090..0x0C0`;  
AND `build_register_signer_ix`, `build_register_signer_ix_for_program`, `build_verify_atomic_with_nonce_ix`, and `build_atomic_attestation_tx` SHALL return `SdkError::PacketTooLarge` when the legacy transaction that carries the raw 1,184-byte report exceeds 1,232 bytes (`PACKET_DATA_SIZE`);  
AND the quarantined `*_oversized` builders SHALL produce byte-aligned instruction data of 1,200 bytes (Mode A) and 1,264 bytes (Mode B) with zero extra padding for program-test and dry-run only, and SHALL NOT be submitted to a live cluster;  
OTHERWISE the client SHALL return `SdkError` and SHALL NOT emit `VERIFY_ATOMIC_DISCRIMINATOR`.

### @spec SCC-SDK-002: TypeScript Client SDK & Type Definitions
WHEN a host client constructs Solana Confidential Compute transactions through `sdks/typescript`,  
THE system SHALL derive `AttestedSignerAccount` (`[b"attested_signer_v2", signer]`), `UsedNonceAccount` (`[b"nonce", signer, nonce]`), and `PolicyRegistry` (`[b"policy_registry"]`) PDAs against `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`;<br>
AND THE TypeScript builders SHALL match the Rust SDK packing for Mode A `verify_and_register` and Mode B `verify_atomic_with_nonce` at instruction index 0 with the consumer instruction at index 1, defaulting to `requireNonce == true` (@spec SCC-SEC-005 SCC-SDK-001);  
AND `buildRegisterSignerIx`, `buildVerifyAtomicWithNonceIx`, and `buildAtomicAttestationTx` SHALL throw `PacketTooLargeError` when the legacy transaction that carries the raw 1,184-byte report exceeds 1,232 bytes (`PACKET_DATA_SIZE`);  
AND the quarantined `*Oversized` builders MAY return that raw-report packet for tests and SHALL NOT be submitted to a live cluster;  
AND THE package SHALL export `INIT_POLICY_REGISTRY_DISCRIMINATOR`, TypeScript types for `AttestedSignerAccount` (154-byte layout), and `AtomicAttestationExpectation` (`requireNonce` default true);<br>
OTHERWISE a TypeScript client cannot construct a fail-closed Mode B atomic transaction or decode a Mode A attested-signer PDA.

### @spec SCC-JWT-001: Streaming Zero-Heap JWT Header & Claim Parsing
WHEN a Google Cloud OIDC JWT is supplied to `solana-confidential-compute-crypto` (compact JWS `header.payload.signature`),  
THE system SHALL split the token on exactly two ASCII dots and borrow `header_b64`, `payload_b64`, `signature_b64`, and the signing input `header_b64.payload_b64` directly from the source bytes without heap allocation;  
AND THE system SHALL stream-decode Base64URL (`A-Z`, `a-z`, `0-9`, `-`, `_`, optional terminal `=`) into a caller buffer or a 3-byte decode window;  
AND THE system SHALL parse header and payload JSON with a depth-bounded iterative state machine whose stack frame is $\le 256$ bytes, extracting `alg`, `iss`, `sub`, `aud`, `exp`, `iat`, `secboot`, `dbgstat`, `image_digest` (from `sha256:<hex>` at any object depth), and `eat_nonce`;  
AND THE system SHALL reject duplicate claim keys, malformed JSON, invalid Base64URL, missing required Google claims, a token longer than 4,096 bytes, or an `alg` other than the requested algorithm;  
OTHERWISE the call SHALL return `CryptoError::MalformedJwt`, `CryptoError::DuplicateJwtClaim`, or `CryptoError::UnsupportedJwtAlgorithm`.

### @spec SCC-JWT-002: Google Cloud Security Policy & Debug State Enforcement
WHEN Google Cloud Confidential Space claims have been parsed from a verified JWT,  
THE system SHALL assert `secboot == true` and `dbgstat == "disabled-since-boot"`;  
AND THE system SHALL assert `exp > iat`;  
AND WHEN a wall-clock timestamp `now_unix` is supplied (on-chain: `Clock::get()?.unix_timestamp` as `u64`), THE system SHALL assert `now_unix < exp` and `iat <= now_unix + 120` (clock skew $\le 120$ seconds);  
OTHERWISE the call SHALL return `CryptoError::PolicyViolation`.

### @spec SCC-JWT-003: On-Chain RS256 Montgomery Exponentiation & PKCS#1 v1.5 Verification
WHEN verifying a compact JWS with `alg == "RS256"`,  
THE system SHALL reject an RSA public exponent other than $65537$ and a modulus that is not a 2,048-bit odd integer;  
AND THE system SHALL decode the signature to a 256-byte integer $s$ with $0 < s < n$, convert $s$ and $n$ to 32-limb `U2048` (`[u64; 32]`, 256 bytes), and evaluate $s^{65537} \pmod n$ in Montgomery form using exactly 16 modular squarings plus 1 modular multiplication after Montgomery conversion;  
AND THE encoded message SHALL equal PKCS#1 v1.5 for SHA-256:
`0x00 || 0x01 || [0xFF; 202] || 0x00 || 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 || SHA256(header_b64.payload_b64)`;  
AND THE modular exponentiation plus padding check SHALL be budgeted at $\le 200{,}000$ CUs;  
OTHERWISE the call SHALL return `CryptoError::InvalidJwtSignature`, `CryptoError::InvalidPadding`, or `CryptoError::UnsupportedJwtAlgorithm`.

### @spec SCC-JWT-004: ES256 Native Precompile Introspection & Low-S Normalization
WHEN verifying a compact JWS with `alg == "ES256"` on-chain,  
THE system SHALL assert `instructions_sysvar.key == sysvar::instructions::ID`, load `current_index` via `load_current_index_checked`, and inspect the preceding instruction at `current_index - 1`;  
AND THE preceding instruction `program_id` SHALL equal the native secp256r1 precompile `Secp256r1SigVerify1111111111111111111111111` (SIMD-0075);  
AND THE precompile message bytes SHALL equal the JWT signing input `header_b64.payload_b64`, and the 64-byte signature $(r \parallel s)$ SHALL satisfy $r \ne 0$, $s \ne 0$, and canonical low-S $s \le \lfloor n/2 \rfloor$ over the P-256 group order
$n = \mathrm{FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551}$;  
OTHERWISE the transaction SHALL abort with `CryptoError::InvalidJwtSignature`, `ProgramError::IncorrectProgramId`, or `ProgramError::InvalidInstructionData`.

### @spec SCC-JWT-005: Eat-Nonce Dual-Binding & Nonce Tombstone
WHEN a Google Cloud OIDC JWT is accepted as a Solana Confidential Compute attestation,  
THE system SHALL require an `eat_nonce` claim that is either one string or an array of exactly two strings, and each string SHALL be 10–74 bytes;  
AND THE system SHALL reject every other `eat_nonce` shape;  
AND WHEN `image_digest` is a `sha256:<hex>` string, THE system SHALL accept that string, and WHEN `image_digest` is a one-element array of strings, THE system SHALL accept that element, and SHALL reject every other array shape;  
AND Mode A nonce 0 SHALL be the unpadded base64url encoding of the 32-byte workload pubkey and Mode A nonce 1 SHALL be the unpadded base64url encoding of the 32-byte `SlotHashes` entry at `nonce_slot`, and THE verifier SHALL base64url-decode both before compare;  
AND THE Mode A nonce tombstone seed SHALL be $\mathrm{SHA\text{-}256}$ of the raw 64 bytes `pubkey || slot_hash`;  
AND Mode B SHALL bind the single `eat_nonce` string to the unpadded base64url encoding of the 32-byte commitment $\mathrm{SHA\text{-}256}(\mathrm{slot\_hash} \parallel \mathrm{action\_hash} \parallel \mathrm{consumer\_program\_id})$ (43 characters, inside the 10–74 byte Google limit), and THE verifier SHALL base64url-decode that string before compare;  
AND THE Mode B nonce tombstone seed SHALL be $\mathrm{SHA\text{-}256}$ of those raw 32 bytes;  
AND THE system SHALL assert that no `UsedNonceAccount` PDA exists for seeds `[b"nonce", <32-byte seed>]` (Solana `MAX_SEED_LEN = 32`) and SHALL allocate that PDA as a nonce tombstone via System Program `create_account`;  
AND THE `JwksAccount` passed to `process_verify_google_jwt` SHALL be owned by this program;  
OTHERWISE the transaction SHALL abort with `CryptoError::MalformedJwt`, `CryptoError::PolicyViolation`, `VerifierError::SignerMismatch`, `VerifierError::StaleNonce`, `VerifierError::NonceAlreadyUsed`, or `ProgramError::IllegalOwner`.

### @spec SCC-JWT-006: JwksAccount Governance Lifecycle & PDA Immutability
WHEN `register_jwks` is executed,  
THE system SHALL verify the transaction is signed by `PolicyRegistry.authority`, derive the `JwksAccount` PDA from `[b"jwks", sha256(kid)]`, and write an immutable record `{ kid_hash, modulus[256], exponent=65537, registered_slot, bump }` prepended with the Anchor discriminator `sha256("account:JwksAccount")[..8]`;  
AND THE system SHALL reject a second write to an existing `JwksAccount` with `ProgramError::AccountAlreadyInitialized` (first-writer immutability of the modulus and exponent);  
AND JWT verification SHALL load the `JwksAccount` whose `kid_hash` matches `sha256(header.kid)` and SHALL use that modulus for RS256 (@spec SCC-JWT-003);  
AND `rotate_jwks` SHALL only register a new `kid` PDA under the same authority and SHALL NOT mutate a previously initialized modulus;  
OTHERWISE the transaction SHALL abort with `ProgramError::MissingRequiredSignature`, `ProgramError::AccountAlreadyInitialized`, or `CryptoError::InvalidJwtSignature`.

### @spec SCC-DOCS-001: Local Starlight Documentation Portal
WHEN a reader opens the Solana Confidential Compute documentation portal,  
THE system SHALL serve the Astro Starlight site configured in `docs-site/astro.config.mjs`, with Pagefind search and sidebar slugs `overview/introduction`, `overview/threat-model`, `architecture/mode-a-stateful`, `architecture/mode-b-atomic`, `integration/rust-cpi`, `integration/typescript-sdk`, `deployment/sidecar`, and `reference/instruction-matrix`;  
AND `docs-site/astro.config.mjs`, `docs-site/README.md`, `docs-site/src/content/docs/index.mdx`, and each sidebar page above SHALL cite `@spec SCC-DOCS-001`;  
OTHERWISE a document that does not cite this specification is outside the portal.

### @spec SCC-CORE-001: AMD SEV-SNP FLAGS Signing-Key Word
WHEN `SnpReportView` in `crates/solana-confidential-compute-core/src/report.rs` reads an AMD SEV-SNP report,  
THE system SHALL read the FLAGS word at offset `0x048` as a little-endian `u32` (AMD Table 141);  
AND bit 0 SHALL be `AUTHOR_KEY_EN`, bit 1 SHALL be `MASK_CHIP_KEY`, and bits 4:2 SHALL be `SIGNING_KEY` (`0` = VCEK, `1` = VLEK, `7` = none);  
AND `key_sel()` SHALL return `(flags >> 2) & 0b111`;  
WHEN `SIGNING_KEY == 1` or `chip_id` is `[0u8; 64]`,  
THE system SHALL return `is_vlek() == true` (FLAGS word `4` is `SIGNING_KEY == 1`);  
OTHERWISE THE system SHALL return `is_vlek() == false`, including FLAGS word `1` (`AUTHOR_KEY_EN` only, `SIGNING_KEY == 0`).



### Current Mode A V2 contract

The current account uses seed `[b"attested_signer_v2", signer_pubkey]`, discriminator `sha256("account:AttestedSignerAccountV2")[..8]` = `[43, 255, 114, 40, 233, 28, 127, 238]`, and a 154-byte serialized layout. The bump remains at byte 145; bytes 146..154 contain `expires_unix_timestamp` as signed little-endian i64. V1 (`attested_signer`, 146 bytes, V1 discriminator) is historical and is rejected by the current V2 consumer contract; do not pad or reinterpret it as V2.

A valid session requires both `clock.slot <= expires_slot` and `0 <= clock.unix_timestamp < expires_unix_timestamp`. Slot equality is valid; Unix deadline equality is expired. Both values come from the trusted Clock, not from caller arguments. A decoder alone does not perform session validation. Consumer helpers also check owner/discriminator, workload signature and stored pubkey, caller-pinned measurement and platform; the low-level helper additionally re-derives the PDA. Registration derives the Unix deadline independently of slot duration (and caps GCP sessions at JWT expiry).

Sources: [verifier state](../../programs/solana-confidential-compute-verifier/src/state.rs), [deadline construction](../../programs/solana-confidential-compute-verifier/src/processor.rs) (`session_unix_deadline`), [CPI validation](../../crates/solana-confidential-compute-cpi/src/lib.rs) (`assert_attestation_signer`), [zero-copy adapter](../../crates/solana-confidential-compute-cpi/src/anchor.rs), and [TypeScript decoder](../../sdks/typescript/src/index.ts). These source contracts do not establish deployment or fresh hardware/SBF evidence.

### Backend measurement governance

`BackendPolicy` is authoritative for measurement admission: source 1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space. Each canonical PDA uses `[b"backend_policy", &[source]]` and holds up to eight measurements. Missing, empty, or mismatched backend policy fails closed. The global `PolicyRegistry.measurement_count` / `measurements` fields and `update_policy` measurement payload are deprecated as runtime controls and retained for state/wire compatibility; clearing that global list does not halt admission. There is no implicit global/backend allowlist AND. Registry authority checks and monotonic AMD TCB floors remain active.

To halt new admission, the registry authority uses `set_backend_policy` with an empty list (`[]`) for each relevant backend; update all three policies to halt all backends. Rust exposes `build_set_backend_policy_ix`, TypeScript `buildSetBackendPolicyIx`. This does not revoke existing Mode A sessions: use `revoke_attested_signer` separately for targeted containment. These are source contracts, not evidence of deployment or hardware/SBF validation.
