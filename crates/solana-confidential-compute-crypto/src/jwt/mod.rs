//! Google Cloud OIDC / JWT verification (runtime RS256 + claim policy).
//!
//! @spec SCC-JWT-001 SCC-JWT-002 SCC-JWT-003 SCC-JWT-004 SCC-JWT-005 SCC-JWT-006

pub mod b64;
pub mod claims;
pub mod rsa;

use crate::error::CryptoError;
use sha2::{Digest, Sha256};

pub use b64::{decode_b64url, decode_b64url_exact, B64Decoder};
pub use claims::{
    enforce_google_policy, enforce_google_tenant, parse_google_claims, parse_google_claims_b64,
    parse_header_kid_b64, GoogleClaims, MAX_CLOCK_SKEW_SECS, MAX_KID, REQUIRED_DBGSTAT,
    REQUIRED_ISS,
};
pub use rsa::{
    compute_n0_and_r2, verify_rs256_pkcs1, verify_rs256_pkcs1_with_montgomery, RSA2048_LEN,
    RSA_EXPONENT, U2048,
};

/// Maximum compact JWS length (Solana v1 MTU).
/// @spec SCC-JWT-001
pub const MAX_JWT_LEN: usize = 4096;

/// `JwksAccount` PDA seed prefix.
/// @spec SCC-JWT-006
pub const JWKS_SEED: &[u8] = b"jwks";

/// secp256r1 / P-256 group order $n$.
/// @spec SCC-JWT-004
pub const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// $\lfloor n/2 \rfloor$ for P-256 low-S normalization.
/// @spec SCC-JWT-004
pub const P256_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

/// Solana native secp256r1 precompile (SIMD-0075).
/// @spec SCC-JWT-004
pub const SECP256R1_PROGRAM_ID_STR: &str = "Secp256r1SigVerify1111111111111111111111111";

/// Zero-copy view over a compact JWS.
/// @spec SCC-JWT-001
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JwtView<'a> {
    pub header_b64: &'a [u8],
    pub payload_b64: &'a [u8],
    pub signature_b64: &'a [u8],
    /// `header_b64.payload_b64` (signed bytes).
    pub signing_input: &'a [u8],
}

impl<'a> JwtView<'a> {
    /// Split `header.payload.signature` without allocating.
    pub fn parse(jwt: &'a str) -> Result<Self, CryptoError> {
        let bytes = jwt.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_JWT_LEN {
            return Err(CryptoError::MalformedJwt);
        }
        let mut first = None;
        let mut second = None;
        for (i, b) in bytes.iter().enumerate() {
            if *b == b'.' {
                if first.is_none() {
                    first = Some(i);
                } else if second.is_none() {
                    second = Some(i);
                } else {
                    return Err(CryptoError::MalformedJwt);
                }
            }
        }
        let (d0, d1) = match (first, second) {
            (Some(a), Some(b)) => (a, b),
            _ => return Err(CryptoError::MalformedJwt),
        };
        if d0 == 0 || d1 == d0 + 1 || d1 + 1 == bytes.len() {
            return Err(CryptoError::MalformedJwt);
        }
        Ok(Self {
            header_b64: &bytes[..d0],
            payload_b64: &bytes[d0 + 1..d1],
            signature_b64: &bytes[d1 + 1..],
            signing_input: &bytes[..d1],
        })
    }
}

/// Verify a compact RS256 JWS and enforce Google Cloud policy (no wall clock).
/// @spec SCC-JWT-001 SCC-JWT-002 SCC-JWT-003
pub fn verify_jwt_rs256<'a>(
    jwt: &'a str,
    modulus: &[u8; RSA2048_LEN],
    exponent: u32,
) -> Result<GoogleClaims<'a>, CryptoError> {
    verify_jwt_rs256_at(jwt, modulus, exponent, None)
}

/// Verify a compact RS256 JWS, Google Cloud policy, and `now_unix` freshness.
/// @spec SCC-JWT-001 SCC-JWT-002 SCC-JWT-003
pub fn verify_jwt_rs256_at<'a>(
    jwt: &'a str,
    modulus: &[u8; RSA2048_LEN],
    exponent: u32,
    now_unix: Option<u64>,
) -> Result<GoogleClaims<'a>, CryptoError> {
    verify_jwt_rs256_inner(jwt, modulus, exponent, None, now_unix)
}

/// Verify a compact RS256 JWS using runtime modular exponentiation.
///
/// Cached Montgomery arguments remain for account/API compatibility and are
/// ignored by the arithmetic backend. No software `compute_r2` runs on SBF.
/// @spec SCC-JWT-001 SCC-JWT-002 SCC-JWT-003 SCC-JWT-006
pub fn verify_jwt_rs256_with_montgomery<'a>(
    jwt: &'a str,
    modulus: &[u8; RSA2048_LEN],
    exponent: u32,
    n0: u64,
    r2: &[u8; RSA2048_LEN],
    now_unix: Option<u64>,
) -> Result<GoogleClaims<'a>, CryptoError> {
    verify_jwt_rs256_inner(jwt, modulus, exponent, Some((n0, r2)), now_unix)
}

fn verify_jwt_rs256_inner<'a>(
    jwt: &'a str,
    modulus: &[u8; RSA2048_LEN],
    exponent: u32,
    montgomery: Option<(u64, &[u8; RSA2048_LEN])>,
    now_unix: Option<u64>,
) -> Result<GoogleClaims<'a>, CryptoError> {
    let view = JwtView::parse(jwt)?;
    let alg = claims::parse_header_alg_b64(view.header_b64)?;
    let alg_len = alg.iter().take_while(|b| **b != 0).count();
    if &alg[..alg_len] != b"RS256" {
        return Err(CryptoError::UnsupportedJwtAlgorithm);
    }

    let mut signature = [0u8; RSA2048_LEN];
    decode_b64url_exact(view.signature_b64, &mut signature)?;

    let mut hasher = Sha256::new();
    hasher.update(view.signing_input);
    let hash: [u8; 32] = hasher.finalize().into();
    let sig_err = match montgomery {
        Some((n0, r2)) => {
            verify_rs256_pkcs1_with_montgomery(modulus, exponent, n0, r2, &hash, &signature)
        }
        None => verify_rs256_pkcs1(modulus, exponent, &hash, &signature),
    };
    sig_err.map_err(|err| {
        // PKCS#1 padding failure is a signature failure at the compact-JWS API.
        if err == CryptoError::InvalidPadding {
            CryptoError::InvalidJwtSignature
        } else {
            err
        }
    })?;

    let mut claims = parse_google_claims_b64(view.payload_b64)?;
    if let Ok((kid, kid_len)) = claims::parse_header_kid_with_len(view.header_b64) {
        claims.set_kid(kid, kid_len);
    }
    enforce_google_policy(&claims, now_unix)?;
    Ok(claims)
}

/// True when ES256 scalar $s \le \lfloor n/2 \rfloor$.
/// @spec SCC-JWT-004
pub fn es256_is_low_s(s: &[u8; 32]) -> bool {
    s.as_slice() <= P256_HALF_ORDER.as_slice()
}

/// Decode a 64-byte ES256 signature and reject high-S or zero components.
/// @spec SCC-JWT-004
pub fn parse_es256_signature(sig_b64: &[u8]) -> Result<[u8; 64], CryptoError> {
    let mut out = [0u8; 64];
    decode_b64url_exact(sig_b64, &mut out)?;
    if out[..32].iter().all(|&b| b == 0) || out[32..].iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidJwtSignature);
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(&out[32..]);
    if !es256_is_low_s(&s) {
        return Err(CryptoError::InvalidJwtSignature);
    }
    Ok(out)
}

/// SHA-256 of a JWT `kid` string, used as the `JwksAccount` PDA seed.
/// @spec SCC-JWT-006
pub fn kid_hash(kid: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(kid);
    hasher.finalize().into()
}

/// SHA-256 of `eat_nonce` for the 32-byte UsedNonceAccount seed.
/// @spec SCC-JWT-005
pub fn eat_nonce_tombstone_seed(eat_nonce: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(eat_nonce);
    hasher.finalize().into()
}
