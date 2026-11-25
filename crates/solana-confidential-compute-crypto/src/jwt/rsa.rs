//! RSA-2048 verification using Solana modular exponentiation for JWT RS256.
//!
//! Evaluates $s^{65537} \pmod n$ through the runtime modular-exponentiation syscall,
//! then checks PKCS#1 v1.5 SHA-256 padding.
//!
//! @spec SCC-JWT-003

use crate::error::CryptoError;

/// RSA public exponent required by @spec SCC-JWT-003.
pub const RSA_EXPONENT: u32 = 65537;

/// RSA-2048 modulus / signature length in bytes.
pub const RSA2048_LEN: usize = 256;

/// SHA-256 DigestInfo prefix (RFC 8017 Appendix A.2.4).
const DIGESTINFO_SHA256: [u8; 19] =
    [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

/// 2048-bit unsigned integer as 32 little-endian `u64` limbs (256 bytes).
/// @spec SCC-JWT-003
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U2048(pub [u64; 32]);

impl U2048 {
    pub const fn zero() -> Self {
        Self([0u64; 32])
    }

    pub const fn one() -> Self {
        let mut n = Self::zero();
        n.0[0] = 1;
        n
    }

    pub fn from_be_bytes(bytes: &[u8; RSA2048_LEN]) -> Self {
        let mut limbs = [0u64; 32];
        // Limb 0 is the least significant, so it takes the last 8 bytes.
        let (chunks, _) = bytes.as_chunks::<8>();
        for (limb, chunk) in limbs.iter_mut().zip(chunks.iter().rev()) {
            *limb = u64::from_be_bytes(*chunk);
        }
        Self(limbs)
    }

    pub fn to_be_bytes(self) -> [u8; RSA2048_LEN] {
        let mut bytes = [0u8; RSA2048_LEN];
        let (chunks, _) = bytes.as_chunks_mut::<8>();
        for (chunk, limb) in chunks.iter_mut().rev().zip(self.0.iter()) {
            *chunk = limb.to_be_bytes();
        }
        bytes
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&l| l == 0)
    }

    pub fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    /// True when the high bit of a 2048-bit integer is set (RSA-2048 modulus).
    pub fn bit2047_set(&self) -> bool {
        self.0[31] >> 63 == 1
    }
}

/// Precompute Montgomery `$n_0 = -n^{-1} \bmod 2^{64}$` and `$R^2 \bmod n$`.
///
/// Intended for `JwksAccount` registration so on-chain verify skips `compute_r2`.
/// @spec SCC-JWT-003 SCC-JWT-006
pub fn compute_n0_and_r2(modulus: &[u8; RSA2048_LEN]) -> Result<(u64, [u8; RSA2048_LEN]), CryptoError> {
    let n = U2048::from_be_bytes(modulus);
    if !n.is_odd() || !n.bit2047_set() {
        return Err(CryptoError::InvalidJwtSignature);
    }
    let n0 = n0_from_n(&n);
    let r2 = solana_confidential_compute_core::big_mod_exp(&[2], &4096u32.to_be_bytes(), modulus)
        .ok_or(CryptoError::InvalidJwtSignature)?;
    let r2: [u8; RSA2048_LEN] = r2.try_into().map_err(|_| CryptoError::InvalidJwtSignature)?;
    // For an odd modulus, 2^4096 is invertible; zero is a failed computation.
    if r2.iter().all(|b| *b == 0) || r2 >= *modulus {
        return Err(CryptoError::InvalidJwtSignature);
    }
    Ok((n0, r2))
}

/// Verify RS256 through runtime modular exponentiation.
/// Legacy Montgomery arguments remain for account/API compatibility; verification
/// no longer depends on cached arithmetic parameters.
/// @spec SCC-JWT-003
pub fn verify_rs256_pkcs1_with_montgomery(
    modulus: &[u8; RSA2048_LEN],
    exponent: u32,
    _n0: u64,
    _r2: &[u8; RSA2048_LEN],
    message_hash: &[u8; 32],
    signature: &[u8; RSA2048_LEN],
) -> Result<(), CryptoError> {
    if exponent != RSA_EXPONENT {
        return Err(CryptoError::UnsupportedJwtAlgorithm);
    }
    let n = U2048::from_be_bytes(modulus);
    if !n.is_odd() || !n.bit2047_set() {
        return Err(CryptoError::InvalidJwtSignature);
    }
    let s = U2048::from_be_bytes(signature);
    if s.is_zero() || cmp_ge(&s, &n) {
        return Err(CryptoError::InvalidJwtSignature);
    }
    let encoded = solana_confidential_compute_core::big_mod_exp(signature, &[1, 0, 1], modulus)
        .ok_or(CryptoError::InvalidJwtSignature)?;
    let em: &[u8; RSA2048_LEN] = encoded.as_slice().try_into().map_err(|_| CryptoError::InvalidJwtSignature)?;
    verify_pkcs1_sha256(em, message_hash)
}

/// Verify RS256: $s^{65537} \pmod n$ and PKCS#1 v1.5 SHA-256 padding.
/// @spec SCC-JWT-003
pub fn verify_rs256_pkcs1(
    modulus: &[u8; RSA2048_LEN],
    exponent: u32,
    message_hash: &[u8; 32],
    signature: &[u8; RSA2048_LEN],
) -> Result<(), CryptoError> {
    if exponent != RSA_EXPONENT {
        return Err(CryptoError::UnsupportedJwtAlgorithm);
    }
    verify_rs256_pkcs1_with_montgomery(modulus, exponent, 0, &[0; RSA2048_LEN], message_hash, signature)
}

/// $s^{65537} \pmod n$ via 16 Montgomery squarings and 1 Montgomery multiply.
/// @spec SCC-JWT-003
#[cfg(test)]
pub fn modexp_65537(s: &U2048, n: &U2048, n0: u64, r2: &U2048) -> U2048 {
    let s_mont = mont_mul(s, r2, n, n0);
    let mut a = s_mont;
    for _ in 0..16 {
        a = mont_mul(&a, &a, n, n0);
    }
    a = mont_mul(&a, &s_mont, n, n0);
    mont_mul(&a, &U2048::one(), n, n0)
}

fn verify_pkcs1_sha256(em: &[u8; RSA2048_LEN], hash: &[u8; 32]) -> Result<(), CryptoError> {
    // 0x00 || 0x01 || [0xFF; 202] || 0x00 || DigestInfo || hash
    let mut pad_diff = em[0];
    pad_diff |= em[1] ^ 0x01;
    for b in em.iter().take(204).skip(2) {
        pad_diff |= b ^ 0xFF;
    }
    pad_diff |= em[204];
    for (b, p) in em[205..].iter().zip(DIGESTINFO_SHA256.iter()) {
        pad_diff |= b ^ p;
    }
    if pad_diff != 0 {
        return Err(CryptoError::InvalidPadding);
    }
    let mut hash_diff = 0u8;
    for (em_b, hash_b) in em[224..].iter().zip(hash.iter()) {
        hash_diff |= em_b ^ hash_b;
    }
    if hash_diff != 0 {
        return Err(CryptoError::InvalidJwtSignature);
    }
    Ok(())
}

fn n0_from_n(n: &U2048) -> u64 {
    inv64(n.0[0]).wrapping_neg()
}

/// Modular inverse of an odd `u64` modulo $2^{64}$ (Newton–Raphson).
fn inv64(a: u64) -> u64 {
    let mut x = 1u64;
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    x
}

/// $R^2 \bmod n$ with $R = 2^{2048}$, via 2048 modular doublings of $R \bmod n$.
#[cfg(test)]
fn compute_r2(n: &U2048) -> U2048 {
    let mut r = r_minus_n(n);
    if cmp_ge(&r, n) {
        sub_assign(&mut r, n);
    }
    for _ in 0..2048 {
        r = add_mod(&r, &r, n);
    }
    r
}

#[cfg(test)]
fn r_minus_n(n: &U2048) -> U2048 {
    let mut out = U2048::zero();
    let mut borrow = 0u64;
    for i in 0..32 {
        let (d1, b1) = 0u64.overflowing_sub(n.0[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out.0[i] = d2;
        borrow = u64::from(b1 || b2);
    }
    out
}

#[cfg(test)]
fn add_mod(a: &U2048, b: &U2048, n: &U2048) -> U2048 {
    let (mut sum, mut extra) = add_carry(a, b);
    if extra > 0 || cmp_ge(&sum, n) {
        sub_from_33(&mut sum, &mut extra, n);
    }
    sum
}

#[cfg(test)]
// Test-only reference arithmetic. The `u128` sum cannot overflow: 3 * (2^64 - 1) < 2^128.
#[allow(clippy::arithmetic_side_effects)]
fn add_carry(a: &U2048, b: &U2048) -> (U2048, u64) {
    let mut out = U2048::zero();
    let mut carry = 0u64;
    for i in 0..32 {
        let t = a.0[i] as u128 + b.0[i] as u128 + carry as u128;
        out.0[i] = t as u64;
        carry = (t >> 64) as u64;
    }
    (out, carry)
}

#[cfg(test)]
fn sub_assign(a: &mut U2048, b: &U2048) {
    let mut extra = 0u64;
    sub_from_33(a, &mut extra, b);
}

#[cfg(test)]
fn sub_from_33(low: &mut U2048, extra: &mut u64, n: &U2048) {
    let mut borrow = 0u64;
    for i in 0..32 {
        let (d1, b1) = low.0[i].overflowing_sub(n.0[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        low.0[i] = d2;
        borrow = u64::from(b1 || b2);
    }
    *extra = extra.wrapping_sub(borrow);
}

fn cmp_ge(a: &U2048, b: &U2048) -> bool {
    for i in (0..32).rev() {
        if a.0[i] > b.0[i] {
            return true;
        }
        if a.0[i] < b.0[i] {
            return false;
        }
    }
    true
}

/// Montgomery multiplication: $a b R^{-1} \bmod n$.
#[cfg(test)]
// Test-only reference arithmetic. The `u128` sums cannot overflow:
// (2^64 - 1)^2 + 2 * (2^64 - 1) = 2^128 - 1.
#[allow(clippy::arithmetic_side_effects)]
fn mont_mul(a: &U2048, b: &U2048, n: &U2048, n0: u64) -> U2048 {
    let mut t = [0u64; 66];
    for i in 0..32 {
        let mut carry = 0u64;
        for j in 0..32 {
            let p = (a.0[j] as u128) * (b.0[i] as u128) + t[i + j] as u128 + carry as u128;
            t[i + j] = p as u64;
            carry = (p >> 64) as u64;
        }
        let mut k = i + 32;
        while carry != 0 {
            let p = t[k] as u128 + carry as u128;
            t[k] = p as u64;
            carry = (p >> 64) as u64;
            k += 1;
        }
    }
    for i in 0..32 {
        let m = t[i].wrapping_mul(n0);
        let mut carry = 0u64;
        for j in 0..32 {
            let p = (m as u128) * (n.0[j] as u128) + t[i + j] as u128 + carry as u128;
            t[i + j] = p as u64;
            carry = (p >> 64) as u64;
        }
        let mut k = i + 32;
        while carry != 0 {
            let p = t[k] as u128 + carry as u128;
            t[k] = p as u64;
            carry = (p >> 64) as u64;
            k += 1;
        }
    }

    let mut out = U2048::zero();
    out.0.copy_from_slice(&t[32..64]);
    let mut extra = t[64];
    for _ in 0..4 {
        if extra == 0 && !cmp_ge(&out, n) {
            break;
        }
        sub_from_33(&mut out, &mut extra, n);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Limb 0 is the least significant 8 bytes. The limb conversion now
    /// uses chunks, not index arithmetic.
    #[test]
    fn u2048_limb_order_is_little_endian_over_big_endian_bytes() {
        let bytes: [u8; RSA2048_LEN] = core::array::from_fn(|i| i as u8);
        let n = U2048::from_be_bytes(&bytes);
        assert_eq!(n.0[0], u64::from_be_bytes([248, 249, 250, 251, 252, 253, 254, 255]));
        assert_eq!(n.0[31], u64::from_be_bytes([0, 1, 2, 3, 4, 5, 6, 7]));
        assert_eq!(n.to_be_bytes(), bytes);
    }

    #[test]
    fn n0_times_n_is_minus_one() {
        let mut bytes = [0u8; 256];
        bytes[0] = 0x80;
        bytes[255] = 0x03;
        let n = U2048::from_be_bytes(&bytes);
        assert!(n.is_odd());
        let n0 = n0_from_n(&n);
        assert_eq!(n.0[0].wrapping_mul(n0).wrapping_add(1), 0);
    }

    #[test]
    fn be_bytes_roundtrip() {
        let mut bytes = [0u8; 256];
        bytes[0] = 0xAB;
        bytes[255] = 0xCD;
        bytes[17] = 0x11;
        let n = U2048::from_be_bytes(&bytes);
        assert_eq!(n.to_be_bytes(), bytes);
    }

    #[test]
    fn two_pow_65537_matches_known_vector() {
        let n_bytes: [u8; 256] = hex_256(
            "df596e4ccf0ec49a2f9e22e81b5e71f1799c1d3229725d48d07f426b1d8b1f638d7e5a305e319b31ef69e6817aa44ea734602cf82d0cc32f3a809262a171c9bee7e6b8eacc3acaafeb52d78d88c3d984ebf2d1797f72111f0d448f432f9928738a62f23546a63822f639468f8065760c2ce9cd77c15233fd6d16c3d75f069630fc75f6ff6a53ed0291eba3a148cd4e51c0c959cc2128dfaa8bb86ad96de9f5a8fd4d90d7a29fa3efadfb4081aaba041b2f163c1fde7885edbd7d9517a662a4fc08498530fd044c0c294c999b30b1ba6f10632bbc7627c83ea4a9b6c963081ab21cc48a85a2792958185af81849c7aabacf878e9a9c834067492ffae116e966d5",
        );
        let expected: [u8; 256] = hex_256(
            "4da94b1b1c8364a7a7e6526d57270b339c0b9c490a1ad83ad4fa904c3ea2a6e256ed349d489379bf01a3c8f7663292d5d9638572c60be44742b2d75ae23e99c882ae4f632790d69a46b83525f3cdee700a34c08e12b82dc7b2ea23121fd8e789cca934ec6452029cd0e64f625faf9acfd97138142a3c7e0ae75aef98375aa3073eba6c5a4c8d21c1e07e56c5c090f2199c536ca2e52889a3796cd192dc12da25f7bfc3c3b3ec077610fc697a3aa930e6c90717aff2ffde85eaf951f1870ed379f419747ecb7ef36974cfd20b6b9763ca66bc2b48ee548e00bfffd191e29c84ae1b5c8e33ad3ec8eb83e53c348161a4fb1ea72baf9045dd46fbc59c0c41796880",
        );
        let n = U2048::from_be_bytes(&n_bytes);
        let mut two = U2048::zero();
        two.0[0] = 2;
        let n0 = n0_from_n(&n);
        assert_eq!(n.0[0].wrapping_mul(n0).wrapping_add(1), 0);
        let r2 = compute_r2(&n);
        let got = modexp_65537(&two, &n, n0, &r2);
        assert_eq!(got.to_be_bytes(), expected);
    }

    fn hex_256(s: &str) -> [u8; 256] {
        let v = hex::decode(s).expect("hex");
        let mut out = [0u8; 256];
        out.copy_from_slice(&v);
        out
    }
    #[test]
    fn runtime_r2_matches_software_reference() {
        for (top, last) in [(0x80, 3), (0xa5, 0xa5), (0xff, 0xff)] {
            let mut bytes = [top; RSA2048_LEN];
            bytes[255] = last;
            let n = U2048::from_be_bytes(&bytes);
            let (n0, r2) = compute_n0_and_r2(&bytes).unwrap();
            assert_eq!(n0, n0_from_n(&n));
            assert_eq!(r2, compute_r2(&n).to_be_bytes());
        }
        assert!(compute_n0_and_r2(&[0; RSA2048_LEN]).is_err());
        assert!(compute_n0_and_r2(&[0x80; RSA2048_LEN]).is_err());
    }
}
