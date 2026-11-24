//! NIST P-384 (secp384r1) ECDSA signature verification.
//!
//! @spec SCC-SEC-003 SCC-SEC-009

use crate::error::CryptoError;
use sha2::{Digest, Sha384};

/// Verifies a NIST P-384 ECDSA signature (r, s) over a 48-byte SHA-384 hash
/// using the 96-byte uncompressed public key (x, y).
///
/// @spec SCC-SEC-003 SCC-SEC-009
///
/// Inputs:
/// - `public_key_xy`: 96 bytes containing big-endian affine coordinates X (48 bytes) and Y (48 bytes).
/// - `hash_sha384`: 48 bytes SHA-384 digest of the signed payload.
/// - `signature_rs`: 96 bytes containing big-endian scalar components r (48 bytes) and s (48 bytes).
///
/// On `target_os = "solana"` this fails closed with [`CryptoError::InvalidP384Signature`].
/// Software P-384 is not an on-chain backend (see `DirectCryptoVerifier` in the verifier
/// program), and `ecdsa` 0.17's `verify_prehashed` needs a 9216-byte stack frame, which
/// exceeds the 4096-byte SBF limit.
// `target_os = "solana"` is not a `target_os` value rustc knows; the core, verifier and consumer crates
// allow `unexpected_cfgs` crate-wide for the same cfg.
#[allow(unexpected_cfgs)]
pub fn verify_p384_signature(
    public_key_xy: &[u8; 96],
    hash_sha384: &[u8; 48],
    signature_rs: &[u8; 96],
) -> Result<bool, CryptoError> {
    // Reject structurally empty inputs before any curve parse.
    if public_key_xy.iter().all(|&b| b == 0)
        || signature_rs.iter().all(|&b| b == 0)
        || hash_sha384.iter().all(|&b| b == 0)
    {
        return Err(CryptoError::InvalidP384Signature);
    }

    #[cfg(target_os = "solana")]
    {
        Err(CryptoError::InvalidP384Signature)
    }
    #[cfg(not(target_os = "solana"))]
    {
        use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
        use p384::Sec1Point;

        let mut sec1_bytes = [0u8; 97];
        sec1_bytes[0] = 0x04;
        sec1_bytes[1..97].copy_from_slice(public_key_xy);

        let encoded_point = Sec1Point::from_bytes(sec1_bytes).map_err(|_| CryptoError::InvalidP384PublicKey)?;

        let verifying_key =
            VerifyingKey::from_sec1_point(&encoded_point).map_err(|_| CryptoError::InvalidP384PublicKey)?;

        let signature =
            Signature::from_slice(signature_rs.as_slice()).map_err(|_| CryptoError::InvalidP384Signature)?;

        verifying_key
            .verify_prehash(hash_sha384, &signature)
            .map(|_| true)
            .map_err(|_| CryptoError::InvalidP384Signature)
    }
}

/// Computes SHA-384 over the 672-byte signed body of an AMD SEV-SNP report
/// and verifies the 96-byte P-384 ECDSA signature using the uncompressed public key.
///
/// @spec SCC-SEC-003 SCC-SEC-009
pub fn verify_snp_report_signature(
    public_key_xy: &[u8; 96],
    signed_body: &[u8; 672],
    signature_rs: &[u8; 96],
) -> Result<bool, CryptoError> {
    let mut hasher = Sha384::new();
    hasher.update(signed_body);
    let hash: [u8; 48] = hasher.finalize().into();
    verify_p384_signature(public_key_xy, &hash, signature_rs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::ecdsa::SigningKey;

    #[test]
    fn test_rejects_zero_keys() {
        let zero_key = [0u8; 96];
        let hash = [1u8; 48];
        let sig = [1u8; 96];
        assert!(verify_p384_signature(&zero_key, &hash, &sig).is_err());
    }

    #[test]
    fn test_valid_p384_signature_roundtrip() {
        // Generate a deterministic P-384 signing key (scalar = 1)
        let mut seed = [0u8; 48];
        seed[47] = 0x01;
        let signing_key = SigningKey::from_slice(&seed).expect("valid scalar");

        // Extract 96-byte uncompressed public key (X || Y)
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_sec1_point(false);
        let mut pubkey_xy = [0u8; 96];
        pubkey_xy[..48].copy_from_slice(encoded_point.x().unwrap());
        pubkey_xy[48..].copy_from_slice(encoded_point.y().unwrap());

        // Message digest (SHA-384)
        let mut msg_hash = [0x42u8; 48];
        msg_hash[0] = 0xAA;

        // Sign precomputed hash
        let (signature, _) = signing_key.sign_prehash(&msg_hash).expect("signing succeeds");
        let sig_bytes = signature.to_bytes();
        let mut sig_rs = [0u8; 96];
        sig_rs.copy_from_slice(sig_bytes.as_slice());

        // 1. Positive verification
        let res = verify_p384_signature(&pubkey_xy, &msg_hash, &sig_rs);
        assert!(res.is_ok());
        assert!(res.unwrap());

        // 2. Tampered hash rejects
        let mut bad_hash = msg_hash;
        bad_hash[0] ^= 0x01;
        assert!(verify_p384_signature(&pubkey_xy, &bad_hash, &sig_rs).is_err());

        // 3. Tampered signature scalar r rejects
        let mut bad_sig = sig_rs;
        bad_sig[0] ^= 0x01;
        assert!(verify_p384_signature(&pubkey_xy, &msg_hash, &bad_sig).is_err());

        // 4. Tampered signature scalar s rejects
        let mut bad_sig_s = sig_rs;
        bad_sig_s[48] ^= 0x01;
        assert!(verify_p384_signature(&pubkey_xy, &msg_hash, &bad_sig_s).is_err());

        // 5. Tampered public key rejects
        let mut bad_pk = pubkey_xy;
        bad_pk[0] ^= 0x01;
        assert!(verify_p384_signature(&bad_pk, &msg_hash, &sig_rs).is_err());
    }

    #[test]
    fn test_snp_report_signature_verification() {
        let mut seed = [0u8; 48];
        seed[47] = 0x02;
        let signing_key = SigningKey::from_slice(&seed).expect("valid scalar");

        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_sec1_point(false);
        let mut pubkey_xy = [0u8; 96];
        pubkey_xy[..48].copy_from_slice(encoded_point.x().unwrap());
        pubkey_xy[48..].copy_from_slice(encoded_point.y().unwrap());

        // Dummy 672-byte signed body
        let body = [0x5Au8; 672];

        let mut hasher = Sha384::new();
        hasher.update(body);
        let hash: [u8; 48] = hasher.finalize().into();

        let (signature, _) = signing_key.sign_prehash(&hash).expect("sign succeeds");
        let mut sig_rs = [0u8; 96];
        sig_rs.copy_from_slice(signature.to_bytes().as_slice());

        // Verify with helper
        let res = verify_snp_report_signature(&pubkey_xy, &body, &sig_rs);
        assert!(res.is_ok());
        assert!(res.unwrap());
    }
}
