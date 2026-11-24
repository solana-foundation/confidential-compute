#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unexpected_cfgs)]

//! # Solana Confidential Compute Core
//!
//! Core types, report data structures, and serialization primitives for Solana Confidential Compute.
//! Provides hardware attestation interfaces for AMD SEV-SNP and AWS Nitro Enclaves.

extern crate alloc;

pub mod action;
pub mod error;
pub mod nitro;
pub mod report;
pub mod types;
pub mod verifier;

// Shared Solana-backed modular exponentiation; no software arithmetic on SBF.
//
// MIGRATION NOTE (solana-program 2.2 -> 4.x): the upstream `big_mod_exp` changed
// its operand byte order from BIG-endian (solana-big-mod-exp 2.2.1,
// `BigUint::from_bytes_be`) to LITTLE-endian (4.0.0, documented: "Inputs and
// output are little-endian unsigned integers"), and additionally began
// validating that the modulus is non-empty, > 1 and ODD -- where "odd" is read
// from `modulus[0]`, i.e. the LITTLE-endian least-significant byte.
//
// Every Solana Confidential Compute caller works in big-endian (RSA moduli, `U2048::from_be_bytes`).
// Feeding big-endian bytes to the 4.x function is silently wrong, so this
// wrapper preserves the original big-endian contract for all callers.
//
// Output padding also matches 2.2: 4.x right-pads the little-endian result to
// `modulus.len()`, so reversing yields the zero-left-padded big-endian value
// of exactly `modulus.len()` bytes that 2.2 produced.
pub fn big_mod_exp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    use alloc::vec::Vec;
    let base_le: Vec<u8> = base.iter().rev().copied().collect();
    let exponent_le: Vec<u8> = exponent.iter().rev().copied().collect();
    let modulus_le: Vec<u8> = modulus.iter().rev().copied().collect();
    let mut out = solana_program::big_mod_exp::big_mod_exp(&base_le, &exponent_le, &modulus_le)?;
    out.reverse();
    Some(out)
}

pub use error::ConfidentialComputeError;
pub use nitro::{
    NitroAttestationView, NitroPcrs, MAX_NITRO_CABUNDLE, MAX_NITRO_CERT_LEN, MAX_NITRO_DOCUMENT_LEN, NITRO_NONCE_LEN,
    NITRO_PCR_LEN, NITRO_USER_DATA_LEN,
};
pub use report::{
    ReportData, SnpReportView, GUEST_POLICY_DEBUG, GUEST_POLICY_MIGRATE_MA, GUEST_POLICY_RESERVED_MUST_BE_ONE,
    GUEST_POLICY_SMT, SNP_REPORT_SIZE, SNP_SIGNED_BODY_SIZE,
};
pub use types::{compute_action_commitment, AttestedSigner, EnclaveType, MeasurementDigest, VerifyAtomicHeader};
#[cfg(not(target_os = "solana"))]
pub use verifier::MockVerifier;
pub use verifier::SignatureVerifier;
