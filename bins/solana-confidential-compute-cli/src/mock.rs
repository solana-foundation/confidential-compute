//! Mock AMD SEV-SNP attestation report generator.
//!
//! @spec SCC-CLI-001

use p384::ecdsa::signature::hazmat::PrehashSigner;
use p384::ecdsa::SigningKey;
use sha2::{Digest, Sha384};
use solana_confidential_compute_core::{SNP_REPORT_SIZE, SNP_SIGNED_BODY_SIZE};

/// Deterministic mock VCEK scalar (least-significant byte of a 48-byte seed).
const MOCK_VCEK_SEED_LSB: u8 = 0x42;

/// Non-zero launch digest so `SnpReportView::validate_security_invariants` accepts the report.
const MOCK_MEASUREMENT: [u8; 48] = [0x11; 48];

/// Non-zero chip ID so the report is treated as VCEK (not VLEK).
const MOCK_CHIP_ID: [u8; 64] = [0xAA; 64];

const MOCK_REPORT_ID: [u8; 32] = [0xBB; 32];

/// Returns the deterministic mock VCEK signing key.
pub fn mock_signing_key() -> SigningKey {
    let mut seed = [0u8; 48];
    seed[47] = MOCK_VCEK_SEED_LSB;
    SigningKey::from_slice(&seed).expect("mock VCEK scalar is a valid P-384 field element")
}

/// Returns the 96-byte uncompressed mock VCEK public key (X || Y).
pub fn mock_vcek_public_key_xy() -> [u8; 96] {
    let encoded = mock_signing_key().verifying_key().to_encoded_point(false);
    let mut xy = [0u8; 96];
    xy[..48].copy_from_slice(encoded.x().expect("uncompressed point has x").as_slice());
    xy[48..].copy_from_slice(encoded.y().expect("uncompressed point has y").as_slice());
    xy
}

/// Synthesizes a valid 1,184-byte AMD Publication #56860 Table 141 report.
///
/// Injects `user_data` into `REPORT_DATA` and signs `report[0..672]` with the
/// deterministic mock VCEK. Signature scalars `r` and `s` are stored little-endian
/// at offsets `0x2A0` and `0x2E8`.
///
/// @spec SCC-CLI-001
pub fn generate_mock_report(user_data: &[u8; 64]) -> [u8; SNP_REPORT_SIZE] {
    let mut report = [0u8; SNP_REPORT_SIZE];

    // version = 2 (accepted range is 1..=5 on-chain)
    report[0..4].copy_from_slice(&2u32.to_le_bytes());
    // policy: GUEST_POLICY_RESERVED_MUST_BE_ONE (bit 17) set; DEBUG (bit 19) and MIGRATE_MA (bit 18) clear
    report[8..16].copy_from_slice(&(1u64 << 17).to_le_bytes());
    // signature_algo = 1 (ECDSA P-384 with SHA-384)
    report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    // REPORT_DATA
    report[0x50..0x90].copy_from_slice(user_data);
    // measurement
    report[0x90..0xC0].copy_from_slice(&MOCK_MEASUREMENT);
    // report_id
    report[0x140..0x160].copy_from_slice(&MOCK_REPORT_ID);
    // reported_tcb components: [boot_loader, tee, reserved..., snp, microcode]
    report[0x180] = 1;
    report[0x181] = 1;
    report[0x186] = 1;
    report[0x187] = 1;
    // chip_id
    report[0x1A0..0x1E0].copy_from_slice(&MOCK_CHIP_ID);

    sign_report_body(&mut report, &mock_signing_key());
    report
}

/// Signs `report[0..672]` and writes little-endian `(r, s)` into the signature block.
pub fn sign_report_body(report: &mut [u8; SNP_REPORT_SIZE], signing_key: &SigningKey) {
    let mut hasher = Sha384::new();
    hasher.update(&report[..SNP_SIGNED_BODY_SIZE]);
    let digest: [u8; 48] = hasher.finalize().into();
    let (signature, _) = signing_key.sign_prehash(&digest).expect("mock P-384 prehash sign succeeds");
    let sig_bytes = signature.to_bytes();
    write_le_scalar(&mut report[0x2A0..0x2E8], &sig_bytes[..48]);
    write_le_scalar(&mut report[0x2E8..0x330], &sig_bytes[48..96]);
}

/// Writes a 48-byte big-endian scalar as a 72-byte little-endian field (upper 24 bytes zero).
pub fn write_le_scalar(dest: &mut [u8], be: &[u8]) {
    dest.fill(0);
    for i in 0..48 {
        dest[i] = be[47 - i];
    }
}

/// Overwrites the 48-byte big-endian `s` scalar in little-endian report layout.
pub fn write_signature_s_be(report: &mut [u8; SNP_REPORT_SIZE], s_be: &[u8; 48]) {
    write_le_scalar(&mut report[0x2E8..0x330], s_be);
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_confidential_compute_core::SnpReportView;

    #[test]
    fn test_mock_report_valid_view_and_report_data() {
        let mut user_data = [0u8; 64];
        user_data[..32].copy_from_slice(&[0xABu8; 32]);
        user_data[32..].copy_from_slice(&[0xCDu8; 32]);

        let report = generate_mock_report(&user_data);
        assert_eq!(report.len(), SNP_REPORT_SIZE);

        let view = SnpReportView::try_from_slice(&report).expect("1184-byte report");
        assert_eq!(view.report_data(), &user_data);
        assert_eq!(view.pubkey(), [0xABu8; 32]);
        assert_eq!(view.nonce(), [0xCDu8; 32]);
        assert_eq!(view.version(), 2);
        assert_eq!(view.signature_algo(), 1);
        assert!(!view.is_debug_enabled());
        assert!(view.validate_security_invariants().is_ok());
        assert!(view.signature_r_be().is_ok());
        assert!(view.signature_s_be().is_ok());
    }
}
