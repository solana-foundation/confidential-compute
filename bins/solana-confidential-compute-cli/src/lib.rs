//! Gate 1 preflight checks for guest-report acceptance and VCEK selection.
//!
//! @spec SCC-CLI-001 SCC-CLI-005

use std::fmt;

use solana_confidential_compute_core::SNP_REPORT_SIZE;

/// `REPORT_DATA` starts at byte `0x50` of an AMD SEV-SNP report (Table 141).
pub const REPORT_DATA_OFFSET: usize = 0x50;

/// `REPORT_DATA` is 64 bytes, ending at byte `0x90`.
pub const REPORT_DATA_END: usize = 0x90;

/// Upstream `struct snp_report_resp` payload (`include/uapi/linux/sev-guest.h`).
///
/// The kernel copies this many bytes into `data`. The AMD report is either the
/// first [`SNP_REPORT_SIZE`] bytes or, when a PSP header is present, the bytes
/// at [`SNP_PSP_REPORT_PREFIX_LEN`].
/// @spec SCC-CLI-001
pub const SNP_GUEST_RESP_DATA_LEN: usize = 4_000;

/// Trailing bytes that bring the guest response object to 4,032.
///
/// The kernel copies [`SNP_GUEST_RESP_DATA_LEN`] bytes. The tail is not a header
/// and is not part of the attestation report.
/// @spec SCC-CLI-001
pub const SNP_GUEST_RESP_TAIL_LEN: usize = 32;

/// PSP `MSG_REPORT_RSP` header that firmware may write at the front of `data`.
///
/// Layout is status `u32` = 0, report size `u32` = 1184, then 24 reserved bytes.
/// The 1,184-byte report begins at this offset. This is not the 32-byte tail on
/// `snp_report_resp`.
/// @spec SCC-CLI-001
pub const SNP_PSP_REPORT_PREFIX_LEN: usize = 32;

/// Guest response failed the exact-size or `REPORT_DATA` echo check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwareReportError {
    /// `report_size` was `0` or any value other than [`SNP_REPORT_SIZE`].
    RejectedSize { report_size: u32 },
    /// `data[0x50..0x90]` did not match the 64-byte guest request.
    ReportDataMismatch,
}

impl fmt::Display for HardwareReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RejectedSize { report_size } => write!(
                f,
                "SNP_GET_REPORT size {report_size}, expected {SNP_REPORT_SIZE}"
            ),
            Self::ReportDataMismatch => {
                f.write_str("SNP_GET_REPORT REPORT_DATA does not echo the requested user_data")
            }
        }
    }
}

impl std::error::Error for HardwareReportError {}

/// Target VCEK public key could not be selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VcekSelectError {
    /// Hardware prove was requested without `--vcek-pubkey`.
    Missing,
    /// `--vcek-pubkey` was not 96-byte uncompressed X||Y hex.
    Invalid(String),
}

impl fmt::Display for VcekSelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("--vcek-pubkey is required unless --mock is set"),
            Self::Invalid(msg) => write!(f, "invalid --vcek-pubkey: {msg}"),
        }
    }
}

impl std::error::Error for VcekSelectError {}

/// Accepts a guest response only at the exact AMD report length, and only when
/// `data[0x50..0x90]` echoes `user_data`.
///
/// `report_size == 0` is rejected. Every other size other than [`SNP_REPORT_SIZE`]
/// is rejected. A matching size with a mismatched echo is rejected.
///
/// @spec SCC-CLI-001
pub fn validate_hardware_report(
    report_size: u32,
    data: &[u8; SNP_REPORT_SIZE],
    user_data: &[u8; 64],
) -> Result<[u8; SNP_REPORT_SIZE], HardwareReportError> {
    if report_size == 0 || report_size as usize != SNP_REPORT_SIZE {
        return Err(HardwareReportError::RejectedSize { report_size });
    }
    if data[0x50..0x90] != user_data[..] {
        return Err(HardwareReportError::ReportDataMismatch);
    }
    Ok(*data)
}

/// Copies the 1,184-byte AMD report out of a 4,000-byte guest response.
///
/// When `data[0..4]` is zero and `data[4..8]` is the little-endian length 1184,
/// firmware prepended a PSP header and the report is `data[32..32+1184]`.
/// Otherwise the buffer is a raw report. That includes AMD report versions whose
/// first byte is `1..=5`, and any other buffer that is not a PSP success prefix.
/// Those reports are `data[0..1184]`.
///
/// Bytes past the extracted report are excluded. The caller passes the returned
/// array to [`validate_hardware_report`] with `report_size == SNP_REPORT_SIZE`.
///
/// @spec SCC-CLI-001
pub fn copy_guest_report_prefix(data: &[u8; SNP_GUEST_RESP_DATA_LEN]) -> [u8; SNP_REPORT_SIZE] {
    let mut report = [0u8; SNP_REPORT_SIZE];
    let offset = if has_psp_report_prefix(data) {
        SNP_PSP_REPORT_PREFIX_LEN
    } else {
        0
    };
    let Some(end) = offset.checked_add(SNP_REPORT_SIZE) else {
        return report;
    };
    let Some(src) = data.get(offset..end) else {
        return report;
    };
    report.copy_from_slice(src);
    report
}

/// PSP success header: status `0` and report size [`SNP_REPORT_SIZE`] at bytes 4..8.
fn has_psp_report_prefix(data: &[u8; SNP_GUEST_RESP_DATA_LEN]) -> bool {
    let status_ok = data.get(..4).is_some_and(|status| status == [0, 0, 0, 0]);
    let size_ok = u32_le_at(data, 4) == Some(SNP_REPORT_SIZE as u32);
    let prefixed_end = SNP_PSP_REPORT_PREFIX_LEN.checked_add(SNP_REPORT_SIZE);
    status_ok && size_ok && prefixed_end.is_some_and(|end| end <= data.len())
}

fn u32_le_at(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = data.get(offset..end)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(bytes);
    Some(u32::from_le_bytes(buf))
}

/// Selects the 96-byte VCEK public key (uncompressed X || Y) for local preflight.
///
/// An explicit `vcek_pubkey_hex` is always the verification key.
/// `mock_xy` runs only when `mock` is true and no target key was supplied.
///
/// @spec SCC-CLI-005
pub fn resolve_vcek_public_key(
    mock: bool,
    vcek_pubkey_hex: Option<&str>,
    mock_xy: impl FnOnce() -> [u8; 96],
) -> Result<[u8; 96], VcekSelectError> {
    if let Some(hex_key) = vcek_pubkey_hex {
        return parse_vcek_pubkey_hex(hex_key);
    }
    if mock {
        return Ok(mock_xy());
    }
    Err(VcekSelectError::Missing)
}

/// Decodes a 96-byte uncompressed VCEK point from hex. Accepts a `0x` prefix.
///
/// @spec SCC-CLI-005
pub fn parse_vcek_pubkey_hex(hex_key: &str) -> Result<[u8; 96], VcekSelectError> {
    let hex_key = hex_key.strip_prefix("0x").unwrap_or(hex_key);
    let raw = hex::decode(hex_key).map_err(|err| VcekSelectError::Invalid(err.to_string()))?;
    if raw.len() != 96 {
        return Err(VcekSelectError::Invalid(format!(
            "expected 96-byte uncompressed X||Y (192 hex characters), got {} bytes",
            raw.len()
        )));
    }
    let mut xy = [0u8; 96];
    xy.copy_from_slice(&raw);
    Ok(xy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::ecdsa::SigningKey;
    use sha2::{Digest, Sha384};

    fn report_with_user_data(user_data: &[u8; 64]) -> [u8; SNP_REPORT_SIZE] {
        let mut data = [0u8; SNP_REPORT_SIZE];
        data[0x50..0x90].copy_from_slice(user_data);
        data
    }

    #[test]
    fn test_report_size_rejects_zero() {
        let user_data = [0x11u8; 64];
        let data = report_with_user_data(&user_data);
        let err = validate_hardware_report(0, &data, &user_data).expect_err("size 0");
        assert_eq!(err, HardwareReportError::RejectedSize { report_size: 0 });
        assert!(err.to_string().contains("expected 1184"));
    }

    #[test]
    fn test_report_size_rejects_noncanonical() {
        let user_data = [0x22u8; 64];
        let data = report_with_user_data(&user_data);
        for size in [1u32, 1183, 1185, u32::MAX] {
            let err =
                validate_hardware_report(size, &data, &user_data).expect_err("non-canonical size");
            assert_eq!(err, HardwareReportError::RejectedSize { report_size: size });
        }
    }

    #[test]
    fn test_report_size_accepts_exact_when_report_data_echoes() {
        let user_data = [0x33u8; 64];
        let data = report_with_user_data(&user_data);
        let accepted = validate_hardware_report(SNP_REPORT_SIZE as u32, &data, &user_data)
            .expect("exact size and echo");
        assert_eq!(accepted, data);
        assert_eq!(&accepted[REPORT_DATA_OFFSET..REPORT_DATA_END], &user_data);
    }

    #[test]
    fn test_report_data_echo_rejects_mismatch() {
        let user_data = [0x44u8; 64];
        let mut data = report_with_user_data(&user_data);
        data[0x50] ^= 0x01;
        let err = validate_hardware_report(SNP_REPORT_SIZE as u32, &data, &user_data)
            .expect_err("echo mismatch");
        assert_eq!(err, HardwareReportError::ReportDataMismatch);
        assert!(err.to_string().contains("REPORT_DATA"));
    }

    #[test]
    fn test_guest_response_prefix_is_the_report_and_echoes() {
        let user_data = [0x66u8; 64];
        let mut data = [0u8; SNP_GUEST_RESP_DATA_LEN];
        data[REPORT_DATA_OFFSET..REPORT_DATA_END].copy_from_slice(&user_data);
        data[SNP_REPORT_SIZE] = 0xEE;
        data[SNP_GUEST_RESP_DATA_LEN - 1] = 0xEE;

        let report = copy_guest_report_prefix(&data);
        assert_eq!(report.len(), SNP_REPORT_SIZE);
        assert_eq!(report[SNP_REPORT_SIZE - 1], 0);
        let accepted = validate_hardware_report(SNP_REPORT_SIZE as u32, &report, &user_data)
            .expect("1184-byte prefix with echoed REPORT_DATA");
        assert_eq!(&accepted[REPORT_DATA_OFFSET..REPORT_DATA_END], &user_data);

        data[REPORT_DATA_OFFSET] ^= 0x01;
        let mismatched = copy_guest_report_prefix(&data);
        assert_eq!(
            validate_hardware_report(SNP_REPORT_SIZE as u32, &mismatched, &user_data),
            Err(HardwareReportError::ReportDataMismatch)
        );
    }

    #[test]
    fn test_report_data_ignores_bytes_outside_echo_window() {
        let user_data = [0x55u8; 64];
        let mut data = report_with_user_data(&user_data);
        data[0x4F] = 0xFF;
        data[0x90] = 0xFF;
        validate_hardware_report(SNP_REPORT_SIZE as u32, &data, &user_data)
            .expect("bytes outside 0x50..0x90 are not REPORT_DATA");
    }

    #[test]
    fn test_mock_vcek_is_used_only_when_mock_and_no_target() {
        let mut calls = 0u32;
        let key = resolve_vcek_public_key(true, None, || {
            calls += 1;
            [0xABu8; 96]
        })
        .expect("mock fallback");
        assert_eq!(calls, 1);
        assert_eq!(key, [0xABu8; 96]);
    }

    #[test]
    fn test_explicit_vcek_pubkey_is_the_preflight_key() {
        let hex_key = format!("0x{}", "11".repeat(96));
        let mut calls = 0u32;
        let key = resolve_vcek_public_key(true, Some(&hex_key), || {
            calls += 1;
            [0xABu8; 96]
        })
        .expect("explicit key");
        assert_eq!(calls, 0, "mock VCEK must not run when --vcek-pubkey is set");
        assert_eq!(key, [0x11u8; 96]);
    }

    #[test]
    fn test_missing_vcek_pubkey_without_mock_does_not_call_mock_key() {
        let mut calls = 0u32;
        let err = resolve_vcek_public_key(false, None, || {
            calls += 1;
            [0xABu8; 96]
        })
        .expect_err("hardware prove requires a target VCEK");
        assert_eq!(calls, 0);
        assert_eq!(err, VcekSelectError::Missing);
        assert!(err.to_string().contains("--vcek-pubkey"));
    }

    #[test]
    fn test_vcek_hex_rejects_wrong_length() {
        let err = parse_vcek_pubkey_hex("aa").expect_err("short key");
        match err {
            VcekSelectError::Invalid(msg) => {
                assert!(msg.contains("96-byte"), "{msg}");
                assert!(msg.contains("1 bytes"), "{msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert!(parse_vcek_pubkey_hex("zz").is_err());
    }

    #[test]
    fn test_selected_vcek_verifies_matching_signature_and_rejects_other() {
        let mut seed = [0u8; 48];
        seed[47] = 0x42;
        let signing_key = SigningKey::from_slice(&seed).expect("valid P-384 scalar");
        let encoded = signing_key.verifying_key().to_encoded_point(false);
        let mut xy = [0u8; 96];
        xy[..48].copy_from_slice(encoded.x().expect("x").as_slice());
        xy[48..].copy_from_slice(encoded.y().expect("y").as_slice());

        let body = [0x5Au8; 672];
        let mut hasher = Sha384::new();
        hasher.update(body);
        let digest: [u8; 48] = hasher.finalize().into();
        let (signature, _) = signing_key.sign_prehash(&digest).expect("prehash sign");
        let sig_bytes = signature.to_bytes();
        let mut sig_rs = [0u8; 96];
        sig_rs.copy_from_slice(&sig_bytes);

        let selected = resolve_vcek_public_key(true, None, || xy).expect("selected mock key");
        assert_eq!(
            solana_confidential_compute_crypto::verify_snp_report_signature(
                &selected, &body, &sig_rs
            ),
            Ok(true)
        );

        let other_hex = "7f".repeat(96);
        let other = resolve_vcek_public_key(false, Some(&other_hex), || {
            panic!("mock VCEK must not be consulted for an explicit key");
        })
        .expect("explicit other key");
        assert_ne!(other, xy);
        assert_ne!(
            solana_confidential_compute_crypto::verify_snp_report_signature(&other, &body, &sig_rs),
            Ok(true)
        );
    }

    fn milan_report() -> &'static [u8; SNP_REPORT_SIZE] {
        include_bytes!("../../../fixtures/snp_hardware_report_milan.bin")
    }

    fn milan_vcek_der() -> &'static [u8] {
        include_bytes!("../../../fixtures/vcek_milan.der")
    }

    /// Uncompressed P-384 point from the VCEK `SubjectPublicKeyInfo`.
    fn p384_xy_from_vcek_der(der: &[u8]) -> [u8; 96] {
        const OID: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        let pos = der
            .windows(OID.len())
            .position(|window| window == OID)
            .expect("secp384r1 oid");
        let rest = &der[pos + OID.len()..];
        assert!(rest.len() >= 4 + 96, "VCEK SPKI truncated after secp384r1");
        assert_eq!(
            &rest[..4],
            &[0x03, 0x62, 0x00, 0x04],
            "expected uncompressed P-384 BIT STRING"
        );
        let mut xy = [0u8; 96];
        xy.copy_from_slice(&rest[4..4 + 96]);
        xy
    }

    fn response_containing(
        report: &[u8; SNP_REPORT_SIZE],
        psp_prefix: bool,
    ) -> [u8; SNP_GUEST_RESP_DATA_LEN] {
        let mut data = [0u8; SNP_GUEST_RESP_DATA_LEN];
        if psp_prefix {
            data[4..8].copy_from_slice(&(SNP_REPORT_SIZE as u32).to_le_bytes());
            data[20] = 0xA5;
            let start = SNP_PSP_REPORT_PREFIX_LEN;
            data[start..start + SNP_REPORT_SIZE].copy_from_slice(report);
        } else {
            data[..SNP_REPORT_SIZE].copy_from_slice(report);
            data[SNP_REPORT_SIZE] = 0xEE;
        }
        data
    }

    #[test]
    fn test_psp_prefix_report_starts_at_offset_32() {
        let user_data = [0x77u8; 64];
        let mut report = report_with_user_data(&user_data);
        report[0] = 2;
        let data = response_containing(&report, true);
        assert_eq!(&data[..4], &[0, 0, 0, 0]);
        assert_eq!(u32_le_at(&data, 4), Some(SNP_REPORT_SIZE as u32));
        assert_eq!(
            data[20], 0xA5,
            "reserved prefix byte must not be required zero"
        );

        let copied = copy_guest_report_prefix(&data);
        assert_eq!(copied, report);
        let accepted = validate_hardware_report(SNP_REPORT_SIZE as u32, &copied, &user_data)
            .expect("prefixed report echoes REPORT_DATA");
        assert_eq!(&accepted[REPORT_DATA_OFFSET..REPORT_DATA_END], &user_data);
    }

    #[test]
    fn test_raw_report_versions_are_not_treated_as_psp_prefix() {
        for version in 1u8..=5 {
            let mut report = report_with_user_data(&[0x21; 64]);
            report[0] = version;
            // guest_svn sits at bytes 4..8. A value of 1184 must not move the
            // window when the version byte shows a raw AMD report.
            report[4..8].copy_from_slice(&1184u32.to_le_bytes());
            let mut data = [0u8; SNP_GUEST_RESP_DATA_LEN];
            data[..SNP_REPORT_SIZE].copy_from_slice(&report);
            let copied = copy_guest_report_prefix(&data);
            assert_eq!(copied[0], version, "version {version} stays at offset 0");
            assert_eq!(copied, report);
        }
    }

    #[test]
    fn test_zero_status_with_other_size_stays_a_raw_buffer() {
        let mut data = [0u8; SNP_GUEST_RESP_DATA_LEN];
        data[4..8].copy_from_slice(&32u32.to_le_bytes());
        data[10] = 0x42;
        let copied = copy_guest_report_prefix(&data);
        assert_eq!(copied[0], 0);
        assert_eq!(copied[10], 0x42);
    }

    #[test]
    fn test_milan_fixture_raw_and_psp_prefix_echo_and_verify() {
        let report = *milan_report();
        assert_eq!(report.len(), SNP_REPORT_SIZE);
        assert!((1u8..=5).contains(&report[0]));
        let mut user_data = [0u8; 64];
        user_data.copy_from_slice(&report[REPORT_DATA_OFFSET..REPORT_DATA_END]);

        for psp_prefix in [false, true] {
            let data = response_containing(&report, psp_prefix);
            let copied = copy_guest_report_prefix(&data);
            assert_eq!(copied, report, "psp_prefix={psp_prefix}");
            validate_hardware_report(SNP_REPORT_SIZE as u32, &copied, &user_data)
                .unwrap_or_else(|_| panic!("echo failed for psp_prefix={psp_prefix}"));
        }

        let vcek = milan_vcek_der();
        assert!(
            vcek.windows(64)
                .any(|window| window == &report[0x1A0..0x1E0]),
            "VCEK hwID must carry the report chip id"
        );
        let xy = p384_xy_from_vcek_der(vcek);
        let view = solana_confidential_compute_core::SnpReportView::from_array(&report);
        let mut sig = [0u8; 96];
        sig[..48].copy_from_slice(&view.signature_r_be().expect("r padding"));
        sig[48..].copy_from_slice(&view.signature_s_be().expect("s padding"));
        assert_eq!(
            solana_confidential_compute_crypto::verify_snp_report_signature(
                &xy,
                view.signed_body(),
                &sig
            ),
            Ok(true)
        );

        let mut tampered = report;
        tampered[0x90] ^= 0x01;
        let tampered_view = solana_confidential_compute_core::SnpReportView::from_array(&tampered);
        let mut tampered_sig = [0u8; 96];
        tampered_sig[..48].copy_from_slice(&tampered_view.signature_r_be().expect("r"));
        tampered_sig[48..].copy_from_slice(&tampered_view.signature_s_be().expect("s"));
        assert_ne!(
            solana_confidential_compute_crypto::verify_snp_report_signature(
                &xy,
                tampered_view.signed_body(),
                &tampered_sig
            ),
            Ok(true)
        );
    }
}
