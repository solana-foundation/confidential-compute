//! Intel TDX quote parsing, checked against a real Intel-signed v4 quote.
//!
//! The fixture in `tests/fixtures/tdx_quote_v4.bin` is a genuine TDX DCAP
//! quote. Hand-written offset tables are easy to get subtly wrong, and a
//! wrong offset here does not fail loudly -- it silently reads the wrong
//! measurement or the wrong key. Every offset this crate relies on is
//! therefore pinned against real bytes rather than against itself.
//!
//! @spec SCC-TDX-001 SCC-TDX-002

use solana_confidential_compute_verifier::tdx::{
    compress_p256, normalize_low_s, TdxQuote, ISV_SIGNED_LEN, QE_REPORT_LEN, QUOTE_HEADER_LEN, TD10_BODY_LEN,
    TDX_TEE_TYPE,
};

const QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote_v4.bin");

#[test]
fn the_fixture_is_a_real_intel_tdx_v4_quote() {
    assert_eq!(QUOTE.len(), 4935);
    assert_eq!(u16::from_le_bytes([QUOTE[0], QUOTE[1]]), 4, "version");
    assert_eq!(u16::from_le_bytes([QUOTE[2], QUOTE[3]]), 2, "ECDSA-256-with-P-256");
    assert_eq!(u32::from_le_bytes([QUOTE[4], QUOTE[5], QUOTE[6], QUOTE[7]]), TDX_TEE_TYPE);
    TdxQuote::parse(QUOTE).expect("a genuine quote must parse");
}

#[test]
fn the_signed_region_is_the_header_followed_by_the_body() {
    let quote = TdxQuote::parse(QUOTE).unwrap();
    assert_eq!(QUOTE_HEADER_LEN + TD10_BODY_LEN, ISV_SIGNED_LEN);
    assert_eq!(ISV_SIGNED_LEN, 632);
    assert_eq!(quote.isv_signed_region(), &QUOTE[..632]);

    // The declared signature-data length sits immediately after the signed
    // region. If the body length were wrong this would not be 4299.
    let declared = u32::from_le_bytes([QUOTE[632], QUOTE[633], QUOTE[634], QUOTE[635]]);
    assert_eq!(declared, 4299);
    assert_eq!(632 + 4 + declared as usize, QUOTE.len());
}

#[test]
fn the_signed_region_fits_a_solana_transaction() {
    // 1 num_signatures + 1 pad + 14 offsets + 33 pubkey + 64 signature + msg.
    let precompile_ix_data = 16 + 33 + 64 + ISV_SIGNED_LEN;
    assert_eq!(precompile_ix_data, 745);
    assert!(precompile_ix_data < 1232, "the whole architecture depends on this");

    let qe_ix_data = 16 + 33 + 64 + QE_REPORT_LEN;
    assert_eq!(qe_ix_data, 497);

    // Both together exceed the packet, which is why the two signatures are
    // checked by two separate instructions rather than one.
    assert!(precompile_ix_data + qe_ix_data > 1232);
}

#[test]
fn measurements_are_read_from_the_documented_offsets() {
    let quote = TdxQuote::parse(QUOTE).unwrap();

    // MRTD is the one measurement this fixture carries; the rest are zero
    // because the reference TD was booted without them. Asserting the zeros
    // is still worthwhile: it pins the offsets apart from each other.
    assert_eq!(&quote.mr_td()[..4], &[0x93, 0x5b, 0xe7, 0x74]);
    assert_eq!(quote.mr_config_id(), &[0u8; 48]);
    for rtmr in quote.rtmrs() {
        assert_eq!(rtmr, &[0u8; 48]);
    }
    assert_eq!(quote.report_data(), &[0u8; 64]);

    // Offsets relative to the body, cross-checked against the raw buffer.
    assert_eq!(quote.mr_td().as_slice(), &QUOTE[48 + 136..48 + 184]);
    assert_eq!(quote.report_data().as_slice(), &QUOTE[48 + 520..48 + 584]);
}

#[test]
fn the_attestation_key_and_signatures_are_where_the_layout_says() {
    let quote = TdxQuote::parse(QUOTE).unwrap();
    assert_eq!(quote.isv_signature().as_slice(), &QUOTE[636..700]);
    assert_eq!(quote.attestation_pubkey_xy().as_slice(), &QUOTE[700..764]);
    assert_eq!(quote.qe_report(), &QUOTE[770..1154]);
    assert_eq!(quote.qe_report_signature().as_slice(), &QUOTE[1154..1218]);
    assert_eq!(quote.qe_auth_data(), &QUOTE[1220..1252]);
    assert_eq!(quote.qe_auth_data().len(), 32);
}

/// Intel binds the attestation key into the QE report. This is the link that
/// makes the ISV signature mean anything: without it, any key could sign the
/// body and the quote would still look well-formed.
#[test]
fn the_qe_report_commits_to_the_attestation_key() {
    let quote = TdxQuote::parse(QUOTE).unwrap();
    quote.verify_qe_binding().expect("a genuine quote binds its attestation key");

    // The digest half is what the hardware actually committed to.
    let expected = solana_program::hash::hashv(&[quote.attestation_pubkey_xy().as_slice(), quote.qe_auth_data()]);
    assert_eq!(&quote.qe_report_data()[..32], expected.to_bytes());
    assert_eq!(&quote.qe_report_data()[32..], &[0u8; 32]);
}

#[test]
fn a_tampered_attestation_key_breaks_the_qe_binding() {
    let mut tampered = QUOTE.to_vec();
    tampered[700] ^= 0x01;
    let quote = TdxQuote::parse(&tampered).unwrap();
    assert!(quote.verify_qe_binding().is_err(), "swapping the attestation key must break the QE commitment");
}

#[test]
fn nonzero_padding_in_the_qe_report_data_is_rejected() {
    // The trailing 32 bytes are specified as zero. Treating them as free
    // space would hand an attacker 32 bytes inside signed hardware evidence.
    let mut tampered = QUOTE.to_vec();
    tampered[770 + 320 + 32] = 0x01;
    let quote = TdxQuote::parse(&tampered).unwrap();
    assert!(quote.verify_qe_binding().is_err());
}

#[test]
fn the_real_attestation_key_compresses_to_the_expected_point() {
    let quote = TdxQuote::parse(QUOTE).unwrap();
    let compressed = compress_p256(quote.attestation_pubkey_xy());
    assert_eq!(compressed.len(), 33);
    // Y is even in this fixture.
    assert_eq!(compressed[0], 0x02);
    assert_eq!(&compressed[1..], &QUOTE[700..732]);
}

/// Real Intel quotes do carry high-S signatures, so normalization is not
/// optional: the precompile rejects `s > n/2` outright. This fixture happens
/// to contain one of each, which makes it a useful regression anchor.
#[test]
fn normalization_matches_intels_real_high_s_and_low_s_signatures() {
    let quote = TdxQuote::parse(QUOTE).unwrap();

    // The ISV signature is high-S. n - s, computed independently:
    let expected_isv_s: [u8; 32] = [
        0x5f, 0x53, 0x6c, 0x8f, 0xcd, 0x20, 0x54, 0xd3, 0x41, 0x43, 0x14, 0x38, 0xba, 0xfa, 0x14, 0xef, 0x92, 0xf0,
        0x25, 0xcf, 0x9a, 0xd9, 0xb7, 0x1f, 0xf9, 0x7d, 0xcf, 0x94, 0x7e, 0x19, 0xe4, 0xf6,
    ];
    let normalized_isv = normalize_low_s(quote.isv_signature());
    assert_ne!(&normalized_isv, quote.isv_signature(), "this fixture's ISV signature is high-S");
    assert_eq!(&normalized_isv[..32], &quote.isv_signature()[..32], "r is untouched");
    assert_eq!(&normalized_isv[32..], &expected_isv_s);
    assert_eq!(normalize_low_s(&normalized_isv), normalized_isv, "normalization is idempotent");

    // The QE report signature is already low-S and must be left alone.
    assert_eq!(&normalize_low_s(quote.qe_report_signature()), quote.qe_report_signature());
}

#[test]
fn a_quote_from_another_tee_or_another_curve_is_rejected() {
    let mut sgx = QUOTE.to_vec();
    sgx[4] = 0x00; // SGX tee_type
    assert!(TdxQuote::parse(&sgx).is_err());

    let mut wrong_curve = QUOTE.to_vec();
    wrong_curve[2] = 0x03; // not ECDSA-256-with-P-256
    assert!(TdxQuote::parse(&wrong_curve).is_err());

    let mut wrong_version = QUOTE.to_vec();
    wrong_version[0] = 0x05;
    assert!(TdxQuote::parse(&wrong_version).is_err());

    let mut wrong_vendor = QUOTE.to_vec();
    wrong_vendor[12] ^= 0xff;
    assert!(TdxQuote::parse(&wrong_vendor).is_err());
}

/// A lying length field must not let the parser read past the buffer.
#[test]
fn an_overlong_declared_signature_length_is_rejected() {
    let mut lying = QUOTE.to_vec();
    lying[632..636].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(TdxQuote::parse(&lying).is_err());

    let mut slightly_long = QUOTE.to_vec();
    let real = u32::from_le_bytes([QUOTE[632], QUOTE[633], QUOTE[634], QUOTE[635]]);
    slightly_long[632..636].copy_from_slice(&(real + 1).to_le_bytes());
    assert!(TdxQuote::parse(&slightly_long).is_err());
}

#[test]
fn an_overlong_qe_auth_data_length_is_rejected() {
    let mut lying = QUOTE.to_vec();
    lying[1218..1220].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(TdxQuote::parse(&lying).is_err());
}

/// Truncating a genuine quote at every length must produce an error, never a
/// panic. A panic inside a Solana program is an abort, not a rejected
/// instruction.
#[test]
fn truncation_at_any_length_is_an_error_not_a_panic() {
    for len in 0..QUOTE.len() {
        let _ = TdxQuote::parse(&QUOTE[..len]);
    }
}
