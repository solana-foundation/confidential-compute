//! # Solana Confidential Compute SDK
//!
//! Rust client SDK to interact with the Solana Confidential Compute on-chain verifier, submit hardware attestations,
//! and verify attested signer PDAs. On-chain helpers live in `solana-confidential-compute-cpi` and are re-exported here.
//!
//! @spec SCC-SDK-001

pub mod builder;
pub mod client;
/// Test and dry-run packers. Not part of the supported client API.
/// @spec SCC-SDK-001 SCC-ANCHOR-001
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod internal;
#[cfg(not(feature = "test-utils"))]
#[allow(dead_code)]
mod internal;
/// AWS Nitro Enclave transaction builders.
/// @spec SCC-NITRO-008 SCC-SDK-001 SCC-PERF-002
pub mod nitro;

pub use builder::{
    build_atomic_attestation_tx, build_atomic_attestation_tx_for_program, build_register_signer_ix,
    build_register_signer_ix_for_program, build_session_action_tx, build_verify_atomic_with_nonce_ix,
    compute_commitment, SdkError, ATTESTATION_TTL_SLOTS, PACKET_DATA_SIZE, VERIFY_AND_REGISTER_DISCRIMINATOR,
    VERIFY_AND_REGISTER_IX_LEN, VERIFY_ATOMIC_WITH_NONCE_IX_LEN,
};
pub use client::ConfidentialComputeClient;
pub use nitro::{
    build_verify_nitro_attestation_ix, build_verify_nitro_attestation_ix_for_program,
    build_verify_nitro_attestation_tx, build_verify_nitro_attestation_tx_for_program,
    NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER, VERIFY_NITRO_ATTESTATION_DISCRIMINATOR,
    VERIFY_NITRO_ATTESTATION_HEADER_LEN, VERIFY_NITRO_MODE_A, VERIFY_NITRO_MODE_B,
};
pub use solana_confidential_compute_core::SNP_REPORT_SIZE;
pub use solana_confidential_compute_cpi::{
    assert_attestation_atomic, assert_attestation_signer, hash_action, hash_action_account_infos,
    AtomicAttestationExpectation, AttestationClaims, AttestationIdentity, AttestationPlatform, AttestedSignerAccount,
    CpiError, ACTION_COMMITMENT_DOMAIN, ATTESTED_SIGNER_DISCRIMINATOR, ATTESTED_SIGNER_SEED, ID,
    MODE_B_REQUIRE_NONCE_DEFAULT, VERIFY_ATOMIC_DISCRIMINATOR, VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
};

#[cfg(feature = "test-bpf")]
pub use solana_confidential_compute_cpi::assert_attestation_signer_at_slot;

pub mod gcp_policy;
pub use gcp_policy::build_set_gcp_tenant_policy_ix;
pub mod backend_policy;
/// Offline governance builders and validated wire arguments.
pub mod governance;
// Global registry measurements are deprecated as runtime admission controls;
// their ABI remains, and min_tcb updates remain monotonic. BackendPolicy is
// authoritative: empty each relevant backend policy to stop new admissions.
// Existing Mode A signer records require separate revocation.
pub use backend_policy::{build_set_backend_policy_ix, derive_backend_policy_pda};
/// NVIDIA Hopper attestation instruction and nonce PDA builders.
/// @spec SCC-NVIDIA-002 SCC-NVIDIA-003 SCC-NVIDIA-004 SCC-NVIDIA-005
pub mod instruction;
pub use instruction::{
    build_verify_nvidia_attestation_ix, build_verify_nvidia_attestation_ix_for_program, derive_nvidia_nonce_pda,
    VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR, VERIFY_NVIDIA_MODE_A, VERIFY_NVIDIA_MODE_B,
};

/// Public builders remain available without harness features.
/// ```
/// use solana_confidential_compute_sdk::build_register_signer_ix;
/// ```
/// Raw SNP packers require explicit opt-in.
/// ```compile_fail
/// use solana_confidential_compute_sdk::internal::build_register_signer_ix_oversized;
/// ```
/// Raw Nitro packers also require explicit opt-in.
/// ```compile_fail
/// use solana_confidential_compute_sdk::nitro::build_verify_nitro_attestation_ix_oversized;
/// ```
#[cfg(not(feature = "test-utils"))]
pub struct PublicApiBoundary;

#[cfg(test)]
extern crate self as solana_confidential_compute_sdk;
#[cfg(test)]
#[path = "../tests/support/builder_tests.rs"]
mod builder_tests;
#[cfg(test)]
#[path = "../tests/support/nitro_builder_tests.rs"]
mod nitro_builder_tests;
#[cfg(test)]
#[path = "../tests/support/vcek_namespace_tests.rs"]
mod vcek_namespace_tests;
/// Canonical V2 cache namespace for off-chain builders.
pub use builder::VCEK_SEED;

/// Bounded account transport for full attestation instructions.
pub mod staged;

pub mod nonce;
pub use nonce::{
    derive_google_used_nonce_pda, derive_legacy_google_used_nonce_pda, derive_legacy_used_nonce_pda,
    derive_used_nonce_pda_for_source, NonceError,
};

/// Compiled-message action commitments (effective privileges, V3 only).
pub mod action;
pub use action::{hash_compiled_action, validate_compiled_action, ActionCommitmentError};
pub use builder::{
    build_atomic_attestation_tx_for_program_with_endorsement, build_register_signer_ix_for_program_with_endorsement,
    build_verify_atomic_with_nonce_ix_with_endorsement,
};
pub mod amd;
pub use amd::derive_amd_revocation_pda;

/// Intel TDX enrolment instruction and transaction builders.
/// @spec SCC-TDX-001 SCC-TDX-002 SCC-TDX-005 SCC-SDK-001
pub mod tdx;
pub use tdx::{
    build_issue_tdx_challenge_ix, build_issue_tdx_challenge_ix_for_program, build_secp256r1_verify_ix,
    build_tdx_enrolment_instructions_for_program, build_tdx_enrolment_tx, build_tdx_enrolment_tx_for_program,
    build_verify_tdx_qe_report_ix, build_verify_tdx_qe_report_ix_for_program, build_verify_tdx_quote_ix,
    build_verify_tdx_quote_ix_for_program, derive_attested_signer_pda, derive_tdx_backend_policy_pda,
    derive_tdx_challenge_pda, derive_tdx_quote_nonce_pda, derive_tdx_session_pda, derive_tdx_session_pda_from_xy,
    derive_tdx_used_nonce_pda, v1_transaction_size, TdxEnrolment, TdxError, ISSUE_TDX_CHALLENGE_DISCRIMINATOR,
    ISV_SIGNED_LEN, QE_REPORT_LEN, TDX_SOURCE, V1_MAX_TRANSACTION_SIZE, VERIFY_TDX_MODE_A,
    VERIFY_TDX_QE_REPORT_DISCRIMINATOR, VERIFY_TDX_QUOTE_DISCRIMINATOR,
};
