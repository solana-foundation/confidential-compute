#![cfg_attr(not(feature = "std"), no_std)]
// SDLC 3.2.1: this crate runs on chain, so all arithmetic is checked.
#![deny(clippy::arithmetic_side_effects)]

//! # Solana Confidential Compute Crypto
//!
//! Cryptographic verification routines for AMD SEV-SNP (P-384 / VCEK),
//! Google JWTs, and AWS Nitro Enclaves (COSE Sign1 / CBOR).

extern crate alloc;

pub mod cbor;
pub mod error;
pub mod jwt;
pub mod nitro;
mod nitro_path;
pub use nitro_path::validate_nitro_path_constraints;
pub mod p384;
mod rsa_pss;
pub mod vcek;

pub use error::CryptoError;
pub use jwt::{
    parse_google_claims, parse_header_kid_b64, verify_jwt_rs256, verify_jwt_rs256_at, verify_jwt_rs256_with_montgomery,
    GoogleClaims, JwtView,
};
pub use nitro::{
    hash_cose_sig_structure, parse_cose_sign1, parse_nitro_attestation, parse_nitro_cert, validate_nitro_cert_chain,
    verify_cose_sign1, verify_nitro_document, CoseSign1, NitroCertInfo, AWS_NITRO_ROOT_CA_PUBKEY_XY, COSE_ALG_ES384,
};
pub use p384::{verify_p384_signature, verify_snp_report_signature};
pub use vcek::{parse_vcek_identity, validate_vcek_chain, validate_vcek_chain_at, VcekIdentity};
