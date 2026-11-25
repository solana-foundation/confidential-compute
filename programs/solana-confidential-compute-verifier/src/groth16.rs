//! Groth16 verification via Solana's native `alt_bn128_pairing` syscall.
//!
//! This module is an experimental R&D prototype. `Groth16SyscallVerifier` must
//! not be wired as the production `DefaultVerifier` until `signature_rs` is a
//! public input of the SNARK circuit. The proof statement today is
//! `sha256(public_key_xy || message_digest)`, not the AMD report signature.
//!
//! `signature_rs` binding (@spec SCC-VERIFY-017): the 96-byte AMD `(r || s)`
//! must be a public input, with each scalar encoded canonically (`s < r`).
//! A proof that only opens `sha256(public_key_xy || message_digest)` does not
//! prove the hardware signature. Until that input exists, this backend stays
//! unwired.
//!
//! Public inputs must be strictly less than the BN254 scalar modulus `r`.
//! `alt_bn128_multiplication` reduces a 32-byte integer modulo `r`, so `s` and
//! `s + k*r` are the same field element. Values `>= r` are rejected.
//!
//! Verification equation (4 pairings, 768-byte input):
//! \(e(-A, B) \cdot e(\alpha, \beta) \cdot e(L, \gamma) \cdot e(C, \delta) = 1\)
//! where \(L = IC_0 + x_1 \cdot IC_1\).
//!
//! @spec SCC-VERIFY-017

use solana_bn254::compression::prelude::{alt_bn128_g1_decompress, alt_bn128_g2_decompress};
use solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};
use solana_confidential_compute_core::SignatureVerifier;
use solana_program::{account_info::AccountInfo, hash::hashv, program_error::ProgramError};

use crate::error::VerifierError;

/// Compressed G1 `A` (32) || compressed G2 `B` (64) || compressed G1 `C` (32).
pub const GROTH16_PROOF_LEN: usize = 128;
/// Number of public-input IC points: \(IC_0\) and \(IC_1\) for a single Fr element.
pub const GROTH16_IC_LEN: usize = 2;
const G1_COMPRESSED_LEN: usize = 32;
const G2_COMPRESSED_LEN: usize = 64;
const G1_UNCOMPRESSED_LEN: usize = 64;
const G2_UNCOMPRESSED_LEN: usize = 128;
const PAIRING_PAIR_LEN: usize = 192;
const PAIRING_INPUT_LEN: usize = PAIRING_PAIR_LEN * 4;
type UncompressedPoints = ([u8; G1_UNCOMPRESSED_LEN], [u8; G2_UNCOMPRESSED_LEN], [u8; G1_UNCOMPRESSED_LEN]);

/// BN254 base-field modulus \(p\) (big-endian).
const BN254_FIELD_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x97, 0x81, 0x6a,
    0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// BN254 scalar-field modulus \(r\) (big-endian).
///
/// Distinct from [`BN254_FIELD_MODULUS`]. A public input must satisfy `s < r`.
const BN254_SCALAR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8,
    0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Big-endian `scalar < r`. Lexicographic order matches the integer order.
fn is_canonical_fr(scalar: &[u8; 32]) -> bool {
    scalar.as_slice() < BN254_SCALAR_MODULUS.as_slice()
}

/// Groth16 verifying key over BN254.
///
/// Points are uncompressed EIP-197 encodings:
/// \(\alpha \in G_1\), \(\beta, \gamma, \delta \in G_2\), \(IC \in [G_1; k]\) with \(k = 2\).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Groth16VerifyingKey {
    pub alpha_g1: [u8; G1_UNCOMPRESSED_LEN],
    pub beta_g2: [u8; G2_UNCOMPRESSED_LEN],
    pub gamma_g2: [u8; G2_UNCOMPRESSED_LEN],
    pub delta_g2: [u8; G2_UNCOMPRESSED_LEN],
    pub ic: [[u8; G1_UNCOMPRESSED_LEN]; GROTH16_IC_LEN],
}

/// Experimental Groth16 backend. Not the production `DefaultVerifier`.
///
/// Proof points are BN254 compressed. The public input is
/// `sha256(public_key_xy || message_digest)` used as \(x_1 \in \mathbb{F}_r\).
/// `signature_rs` is not committed in the circuit, so this type must stay
/// unwired until that scalar is part of the statement.
/// @spec SCC-VERIFY-017
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Groth16SyscallVerifier {
    proof: [u8; GROTH16_PROOF_LEN],
    public_input: [u8; 32],
    vk: Groth16VerifyingKey,
}

impl Groth16SyscallVerifier {
    pub const fn new(proof: [u8; GROTH16_PROOF_LEN], public_input: [u8; 32], vk: Groth16VerifyingKey) -> Self {
        Self { proof, public_input, vk }
    }

    fn parse_proof(&self) -> Result<UncompressedPoints, ProgramError> {
        let a = alt_bn128_g1_decompress(&self.proof[..G1_COMPRESSED_LEN]).map_err(|_| VerifierError::InvalidProof)?;
        let b_bytes: [u8; G2_COMPRESSED_LEN] = self.proof[G1_COMPRESSED_LEN..G1_COMPRESSED_LEN + G2_COMPRESSED_LEN]
            .try_into()
            .map_err(|_| VerifierError::InvalidProof)?;
        let b = alt_bn128_g2_decompress(&b_bytes).map_err(|_| VerifierError::InvalidProof)?;
        let c = alt_bn128_g1_decompress(&self.proof[G1_COMPRESSED_LEN + G2_COMPRESSED_LEN..])
            .map_err(|_| VerifierError::InvalidProof)?;
        if is_g1_infinity(&a) || is_g2_infinity(&b) || is_g1_infinity(&c) {
            return Err(VerifierError::InvalidProof.into());
        }
        Ok((a, b, c))
    }

    fn compute_l(&self) -> Result<[u8; G1_UNCOMPRESSED_LEN], ProgramError> {
        if !is_canonical_fr(&self.public_input) {
            return Err(VerifierError::InvalidProof.into());
        }
        let mut mul_input = [0u8; 96];
        mul_input[..G1_UNCOMPRESSED_LEN].copy_from_slice(&self.vk.ic[1]);
        mul_input[G1_UNCOMPRESSED_LEN..].copy_from_slice(&self.public_input);
        let x_ic = alt_bn128_multiplication(&mul_input).map_err(|_| VerifierError::InvalidProof)?;
        let mut add_input = [0u8; 128];
        add_input[..G1_UNCOMPRESSED_LEN].copy_from_slice(&self.vk.ic[0]);
        let x_ic_bytes: [u8; G1_UNCOMPRESSED_LEN] =
            x_ic.as_slice().try_into().map_err(|_| VerifierError::InvalidProof)?;
        add_input[G1_UNCOMPRESSED_LEN..].copy_from_slice(&x_ic_bytes);
        let l = alt_bn128_addition(&add_input).map_err(|_| VerifierError::InvalidProof)?;
        l.as_slice().try_into().map_err(|_| VerifierError::InvalidProof.into())
    }
}

fn is_g1_infinity(point: &[u8; G1_UNCOMPRESSED_LEN]) -> bool {
    point.iter().all(|&b| b == 0)
}

fn is_g2_infinity(point: &[u8; G2_UNCOMPRESSED_LEN]) -> bool {
    point.iter().all(|&b| b == 0)
}

/// Negate \(A \in G_1\) by replacing \(y\) with \(p - y\) (big-endian).
fn negate_g1(point: &[u8; G1_UNCOMPRESSED_LEN]) -> [u8; G1_UNCOMPRESSED_LEN] {
    let mut out = *point;
    let mut y = [0u8; 32];
    y.copy_from_slice(&out[32..]);
    if y.iter().all(|&b| b == 0) {
        return out;
    }
    out[32..].copy_from_slice(&sub_be32(&BN254_FIELD_MODULUS, &y));
    out
}

/// Big-endian subtract with borrow: `minuend - subtrahend` over 32 bytes.
///
/// Walks from the least-significant byte. A byte that underflows borrows 1
/// from the next more-significant byte and adds 256 before subtracting.
pub(crate) fn sub_be32(minuend: &[u8; 32], subtrahend: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = false;
    for ((out, left), right) in out.iter_mut().zip(minuend).zip(subtrahend).rev() {
        // Wrapping is the intended semantics: each byte is the difference
        // modulo 256, and the overflow flag is the borrow into the next byte.
        let (diff, borrow_byte) = left.overflowing_sub(*right);
        let (diff, borrow_in) = diff.overflowing_sub(u8::from(borrow));
        *out = diff;
        borrow = borrow_byte || borrow_in;
    }
    out
}

impl SignatureVerifier for Groth16SyscallVerifier {
    fn verify_p384(
        &self,
        public_key_xy: &[u8; 96],
        message_digest: &[u8; 48],
        signature_rs: &[u8; 96],
        instructions_sysvar: Option<&AccountInfo>,
    ) -> Result<(), ProgramError> {
        // `signature_rs` is the AMD P-384 signature `(r || s)`. It is not a
        // circuit public input. Binding it requires a canonical BN254 encoding
        // of those scalars in the statement. Until then this backend must not
        // be `DefaultVerifier`. @spec SCC-VERIFY-017
        let _ = (signature_rs, instructions_sysvar);
        if !is_canonical_fr(&self.public_input) {
            return Err(VerifierError::InvalidProof.into());
        }
        let commitment = hashv(&[public_key_xy.as_slice(), message_digest.as_slice()]).to_bytes();
        if !is_canonical_fr(&commitment) || commitment != self.public_input {
            return Err(VerifierError::InvalidProof.into());
        }

        let (a, b, c) = self.parse_proof()?;
        let l = self.compute_l()?;
        let neg_a = negate_g1(&a);

        let mut pairing_input = [0u8; PAIRING_INPUT_LEN];
        // e(-A, B)
        pairing_input[..64].copy_from_slice(&neg_a);
        pairing_input[64..192].copy_from_slice(&b);
        // e(α, β)
        pairing_input[192..256].copy_from_slice(&self.vk.alpha_g1);
        pairing_input[256..384].copy_from_slice(&self.vk.beta_g2);
        // e(L, γ)
        pairing_input[384..448].copy_from_slice(&l);
        pairing_input[448..576].copy_from_slice(&self.vk.gamma_g2);
        // e(C, δ)
        pairing_input[576..640].copy_from_slice(&c);
        pairing_input[640..768].copy_from_slice(&self.vk.delta_g2);

        let result = alt_bn128_pairing(&pairing_input).map_err(|_| VerifierError::InvalidProof)?;
        if result[..31] != [0u8; 31] || result[31] != 1 {
            return Err(VerifierError::InvalidProof.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_bn254::compression::prelude::{alt_bn128_g1_compress, alt_bn128_g2_compress};

    const PUBKEY: [u8; 96] = [0x11; 96];
    const SIG: [u8; 96] = [0x33; 96];

    /// `sha256(PUBKEY || digest)` is strictly less than the BN254 scalar `r`.
    fn digest() -> [u8; 48] {
        let mut digest = [0x22u8; 48];
        digest[0] = 0;
        digest
    }

    fn g1_generator() -> [u8; 64] {
        let mut g1 = [0u8; 64];
        g1[31] = 1;
        g1[63] = 2;
        g1
    }

    fn g2_generator() -> [u8; 128] {
        [
            0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25, 0xf1, 0xaa,
            0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2, 0x18, 0x00, 0xde, 0xef,
            0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79, 0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e,
            0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed, 0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75,
            0xec, 0x9e, 0x99, 0xad, 0x69, 0x0c, 0x33, 0x95, 0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac,
            0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b, 0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb, 0x4a, 0xab, 0x71, 0x80,
            0x8d, 0xcb, 0x40, 0x8f, 0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b, 0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa,
            0x7d, 0xaa,
        ]
    }

    fn commitment() -> [u8; 32] {
        hashv(&[PUBKEY.as_slice(), digest().as_slice()]).to_bytes()
    }

    fn test_vk() -> Groth16VerifyingKey {
        let g1 = g1_generator();
        let g2 = g2_generator();
        Groth16VerifyingKey { alpha_g1: g1, beta_g2: g2, gamma_g2: g2, delta_g2: g2, ic: [g1, g1] }
    }

    fn g1_add(p: &[u8; 64], q: &[u8; 64]) -> [u8; 64] {
        let mut input = [0u8; 128];
        input[..64].copy_from_slice(p);
        input[64..].copy_from_slice(q);
        alt_bn128_addition(&input).expect("g1 add").as_slice().try_into().expect("g1 add len")
    }

    fn g1_mul(p: &[u8; 64], scalar: &[u8; 32]) -> [u8; 64] {
        let mut input = [0u8; 96];
        input[..64].copy_from_slice(p);
        input[64..].copy_from_slice(scalar);
        alt_bn128_multiplication(&input).expect("g1 mul").as_slice().try_into().expect("g1 mul len")
    }

    fn compress_proof(a: &[u8; 64], b: &[u8; 128], c: &[u8; 64]) -> [u8; GROTH16_PROOF_LEN] {
        let a_c = alt_bn128_g1_compress(a).expect("compress A");
        let b_c = alt_bn128_g2_compress(b).expect("compress B");
        let c_c = alt_bn128_g1_compress(c).expect("compress C");
        let mut proof = [0u8; GROTH16_PROOF_LEN];
        proof[..32].copy_from_slice(&a_c);
        proof[32..96].copy_from_slice(&b_c);
        proof[96..].copy_from_slice(&c_c);
        proof
    }

    /// Satisfies \(e(-A,B)\cdot e(\alpha,\beta)\cdot e(L,\gamma)\cdot e(C,\delta)=1\)
    /// with \(A = L + 2G_1\), \(C = G_1\), and VK generators.
    fn valid_proof() -> [u8; GROTH16_PROOF_LEN] {
        let g1 = g1_generator();
        let g2 = g2_generator();
        let x_ic = g1_mul(&g1, &commitment());
        let l = g1_add(&g1, &x_ic);
        let two_g1 = g1_add(&g1, &g1);
        let a = g1_add(&l, &two_g1);
        compress_proof(&a, &g2, &g1)
    }

    fn dummy_a_neg_c_proof() -> [u8; GROTH16_PROOF_LEN] {
        let g1 = g1_generator();
        let g2 = g2_generator();
        let neg_g1 = negate_g1(&g1);
        compress_proof(&g1, &g2, &neg_g1)
    }

    fn check(verifier: &Groth16SyscallVerifier) -> Result<(), ProgramError> {
        verifier.verify_p384(&PUBKEY, &digest(), &SIG, None)
    }

    #[test]
    fn negate_g1_subtracts_y_from_field_modulus() {
        let g1 = g1_generator();
        let neg = negate_g1(&g1);
        assert_eq!(&neg[..32], &g1[..32]);
        assert_eq!(
            &neg[32..],
            &[
                0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x97,
                0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x45,
            ]
        );
    }

    #[test]
    fn accepts_valid_pairing_and_commitment() {
        let verifier = Groth16SyscallVerifier::new(valid_proof(), commitment(), test_vk());
        assert!(check(&verifier).is_ok());
    }

    #[test]
    fn rejects_malformed_proof() {
        let verifier = Groth16SyscallVerifier::new([0xff; GROTH16_PROOF_LEN], commitment(), test_vk());
        assert_eq!(check(&verifier), Err(VerifierError::InvalidProof.into()));
    }

    #[test]
    fn rejects_all_zero_proof() {
        let verifier = Groth16SyscallVerifier::new([0u8; GROTH16_PROOF_LEN], commitment(), test_vk());
        assert_eq!(check(&verifier), Err(VerifierError::InvalidProof.into()));
    }

    #[test]
    fn rejects_dummy_a_neg_c_proof() {
        let verifier = Groth16SyscallVerifier::new(dummy_a_neg_c_proof(), commitment(), test_vk());
        assert_eq!(check(&verifier), Err(VerifierError::InvalidProof.into()));
    }

    #[test]
    fn rejects_commitment_mismatch() {
        let verifier = Groth16SyscallVerifier::new(valid_proof(), [0x01; 32], test_vk());
        assert_eq!(check(&verifier), Err(VerifierError::InvalidProof.into()));
    }

    #[test]
    fn rejects_noncanonical_public_input() {
        assert!(!is_canonical_fr(&BN254_SCALAR_MODULUS));
        let mut below = BN254_SCALAR_MODULUS;
        below[31] -= 1;
        assert!(is_canonical_fr(&below));
        let verifier = Groth16SyscallVerifier::new(valid_proof(), BN254_SCALAR_MODULUS, test_vk());
        assert_eq!(check(&verifier), Err(VerifierError::InvalidProof.into()));
        let verifier = Groth16SyscallVerifier::new(valid_proof(), [0xff; 32], test_vk());
        assert_eq!(check(&verifier), Err(VerifierError::InvalidProof.into()));
    }
}
