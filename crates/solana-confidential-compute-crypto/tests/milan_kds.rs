// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Authentic Milan SNP report and KDS VCEK, checked against the AMD Milan ARK.
//!
//! AMD KDS signs the Milan ARK and ASK with RSA-4096 RSASSA-PSS SHA-384.
//! The VCEK leaf key is P-384 and signs the 672-byte report body.
//! ARK and ASK are the `cert_chain` published at
//! `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain`.
//!
//! @spec SCC-CLI-001

use ring::signature::{UnparsedPublicKey, RSA_PSS_2048_8192_SHA384};
use solana_confidential_compute_core::{SnpReportView, SNP_REPORT_SIZE};
use solana_confidential_compute_crypto::{parse_vcek_identity, verify_snp_report_signature, CryptoError};

const REPORT: &[u8] = include_bytes!("../../../fixtures/snp_hardware_report_milan.bin");
const VCEK_DER: &[u8] = include_bytes!("../../../fixtures/vcek_milan.der");
const ASK_DER: &[u8] = include_bytes!("data/milan_ask.der");
const ARK_DER: &[u8] = include_bytes!("data/milan_ark.der");

const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_HWID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x9c, 0x78, 0x01, 0x04];
const OID_PRODUCT: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x9c, 0x78, 0x01, 0x02];
const OID_SPL_PREFIX: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x9c, 0x78, 0x01, 0x03];

struct Tlv<'a> {
    tag: u8,
    full: &'a [u8],
    value: &'a [u8],
    total: usize,
}

type Extension<'a> = (&'a [u8], &'a [u8]);

struct CertView<'a> {
    tbs: &'a [u8],
    signature: &'a [u8],
    key: PublicKey<'a>,
    extensions: Vec<Extension<'a>>,
}

enum PublicKey<'a> {
    Rsa(&'a [u8]),
    P384([u8; 96]),
}

struct VcekFields {
    chip_id: [u8; 64],
    tcb_version: u64,
    product: String,
}

fn read_len(input: &[u8]) -> Result<(usize, usize), &'static str> {
    if input.is_empty() {
        return Err("missing length");
    }
    let first = input[0];
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let nbytes = (first & 0x7f) as usize;
    if nbytes == 0 || nbytes > 3 || input.len() < 1 + nbytes {
        return Err("bad long-form length");
    }
    if input[1] == 0 {
        return Err("non-minimal length");
    }
    let mut len = 0usize;
    for byte in &input[1..1 + nbytes] {
        len = (len << 8) | (*byte as usize);
    }
    if len < 0x80 {
        return Err("non-minimal length");
    }
    Ok((len, 1 + nbytes))
}

fn read_tlv(input: &[u8]) -> Result<Tlv<'_>, &'static str> {
    if input.len() < 2 {
        return Err("truncated tag");
    }
    let tag = input[0];
    let (len, len_len) = read_len(&input[1..])?;
    let header = 1 + len_len;
    let end = header.checked_add(len).ok_or("length overflow")?;
    if end > input.len() {
        return Err("value past end");
    }
    Ok(Tlv { tag, full: &input[..end], value: &input[header..end], total: end })
}

fn parse_cert(der: &[u8]) -> Result<CertView<'_>, &'static str> {
    let cert = read_tlv(der)?;
    if cert.tag != 0x30 || cert.total != der.len() {
        return Err("certificate wrapping");
    }
    let tbs = read_tlv(cert.value)?;
    if tbs.tag != 0x30 {
        return Err("tbs");
    }
    let mut rest = &cert.value[tbs.total..];
    let alg = read_tlv(rest)?;
    if alg.tag != 0x30 {
        return Err("signature algorithm");
    }
    rest = &rest[alg.total..];
    let sig = read_tlv(rest)?;
    if sig.tag != 0x03 || sig.total != rest.len() {
        return Err("signature bit string");
    }
    if sig.value.first() != Some(&0) {
        return Err("signature unused bits");
    }
    let (key, extensions) = parse_tbs(tbs.value)?;
    Ok(CertView { tbs: tbs.full, signature: &sig.value[1..], key, extensions })
}

fn parse_tbs(body: &[u8]) -> Result<(PublicKey<'_>, Vec<Extension<'_>>), &'static str> {
    let mut rest = body;
    let first = read_tlv(rest)?;
    if first.tag == 0xA0 {
        rest = &rest[first.total..];
        let serial = read_tlv(rest)?;
        if serial.tag != 0x02 {
            return Err("serial");
        }
        rest = &rest[serial.total..];
    } else if first.tag == 0x02 {
        rest = &rest[first.total..];
    } else {
        return Err("version or serial");
    }
    for _ in 0..4 {
        let field = read_tlv(rest)?;
        if field.tag != 0x30 {
            return Err("tbs name field");
        }
        rest = &rest[field.total..];
    }
    let spki = read_tlv(rest)?;
    if spki.tag != 0x30 {
        return Err("spki");
    }
    rest = &rest[spki.total..];
    let key = parse_spki(spki.value)?;
    let mut extensions = Vec::new();
    if rest.is_empty() {
        return Ok((key, extensions));
    }
    let wrapper = read_tlv(rest)?;
    if wrapper.tag != 0xA3 || wrapper.total != rest.len() {
        return Err("extensions wrapper");
    }
    let seq = read_tlv(wrapper.value)?;
    if seq.tag != 0x30 || seq.total != wrapper.value.len() {
        return Err("extensions sequence");
    }
    let mut ext_rest = seq.value;
    while !ext_rest.is_empty() {
        let one = read_tlv(ext_rest)?;
        if one.tag != 0x30 {
            return Err("extension");
        }
        extensions.push(parse_extension(one.value)?);
        ext_rest = &ext_rest[one.total..];
    }
    Ok((key, extensions))
}

fn parse_spki(body: &[u8]) -> Result<PublicKey<'_>, &'static str> {
    let alg = read_tlv(body)?;
    if alg.tag != 0x30 {
        return Err("spki algorithm");
    }
    let bit = read_tlv(&body[alg.total..])?;
    if bit.tag != 0x03 || alg.total + bit.total != body.len() {
        return Err("spki bit string");
    }
    if bit.value.first() != Some(&0) {
        return Err("spki unused bits");
    }
    let key_bytes = &bit.value[1..];
    let oid = read_tlv(alg.value)?;
    if oid.tag != 0x06 {
        return Err("spki oid");
    }
    if oid.value == OID_RSA_ENCRYPTION {
        Ok(PublicKey::Rsa(key_bytes))
    } else if key_bytes.first() == Some(&0x04) && key_bytes.len() == 97 {
        let mut xy = [0u8; 96];
        xy.copy_from_slice(&key_bytes[1..]);
        Ok(PublicKey::P384(xy))
    } else {
        Err("unsupported subject public key")
    }
}

fn parse_extension(body: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
    let oid = read_tlv(body)?;
    if oid.tag != 0x06 {
        return Err("extension oid");
    }
    let mut consumed = oid.total;
    let mut rest = &body[oid.total..];
    let next = read_tlv(rest)?;
    let value = if next.tag == 0x01 {
        consumed += next.total;
        rest = &rest[next.total..];
        read_tlv(rest)?
    } else {
        next
    };
    if value.tag != 0x04 {
        return Err("extension octet string");
    }
    consumed += value.total;
    if consumed != body.len() {
        return Err("extension trailing bytes");
    }
    Ok((oid.value, value.value))
}

fn der_u64(value: &[u8]) -> Result<u64, &'static str> {
    let tlv = read_tlv(value)?;
    if tlv.tag != 0x02 || tlv.total != value.len() {
        return Err("integer");
    }
    let content = tlv.value;
    if content.is_empty() || content.len() > 9 || content[0] & 0x80 != 0 {
        return Err("integer sign or width");
    }
    let digits = if content.len() > 1 && content[0] == 0 { &content[1..] } else { content };
    if digits.is_empty() || digits.len() > 8 {
        return Err("integer width");
    }
    let mut be = [0u8; 8];
    be[8 - digits.len()..].copy_from_slice(digits);
    Ok(u64::from_be_bytes(be))
}

fn hwid(value: &[u8]) -> Result<[u8; 64], &'static str> {
    if value.len() == 64 {
        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(value);
        return Ok(chip_id);
    }
    let tlv = read_tlv(value)?;
    if tlv.tag != 0x04 || tlv.value.len() != 64 || tlv.total != value.len() {
        return Err("hwID");
    }
    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(tlv.value);
    Ok(chip_id)
}

fn directory_string(value: &[u8]) -> Result<String, &'static str> {
    let tlv = read_tlv(value)?;
    if tlv.tag != 0x0C && tlv.tag != 0x13 && tlv.tag != 0x16 {
        return Err("product string");
    }
    if tlv.total != value.len() {
        return Err("product trailing bytes");
    }
    std::str::from_utf8(tlv.value).map(str::to_owned).map_err(|_| "product utf-8")
}

/// AMD 57230 little-endian TCB word from SPL OIDs under `1.3.6.1.4.1.3704.1.3`.
fn spl_component_index(oid: &[u8]) -> Option<usize> {
    if oid.len() != OID_SPL_PREFIX.len() + 1 || !oid.starts_with(OID_SPL_PREFIX) {
        return None;
    }
    match oid[oid.len() - 1] {
        1 => Some(0),
        2 => Some(1),
        4 => Some(2),
        5 => Some(3),
        6 => Some(4),
        7 => Some(5),
        3 => Some(6),
        8 => Some(7),
        _ => None,
    }
}

fn vcek_fields(extensions: &[Extension<'_>]) -> Result<VcekFields, &'static str> {
    let mut chip_id = None;
    let mut product = None;
    let mut spl = [None; 8];
    for (oid, value) in extensions {
        if *oid == OID_HWID {
            if chip_id.is_some() {
                return Err("duplicate hwID");
            }
            chip_id = Some(hwid(value)?);
        } else if *oid == OID_PRODUCT {
            if product.is_some() {
                return Err("duplicate product");
            }
            product = Some(directory_string(value)?);
        } else if let Some(index) = spl_component_index(oid) {
            if spl[index].is_some() {
                return Err("duplicate SPL");
            }
            let component = der_u64(value)?;
            let component = u8::try_from(component).map_err(|_| "SPL byte")?;
            spl[index] = Some(component);
        }
    }
    if !spl.iter().any(|component| component.is_some()) {
        return Err("missing SPL");
    }
    let mut bytes = [0u8; 8];
    for (index, component) in spl.iter().enumerate() {
        if let Some(value) = component {
            bytes[index] = *value;
        }
    }
    Ok(VcekFields {
        chip_id: chip_id.ok_or("missing hwID")?,
        tcb_version: u64::from_le_bytes(bytes),
        product: product.ok_or("missing product")?,
    })
}

fn rsa_key<'a>(cert: &'a CertView<'a>) -> &'a [u8] {
    match cert.key {
        PublicKey::Rsa(key) => key,
        PublicKey::P384(_) => panic!("expected RSA subject public key"),
    }
}

fn verify_rsa_pss_sha384(public_key_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, public_key_der).verify(message, signature).is_ok()
}

fn report_signature(view: &SnpReportView<'_>) -> [u8; 96] {
    let mut sig = [0u8; 96];
    sig[..48].copy_from_slice(&view.signature_r_be().expect("r padding"));
    sig[48..].copy_from_slice(&view.signature_s_be().expect("s padding"));
    sig
}

#[test]
fn milan_fixture_chains_to_amd_kds_and_signs_report() {
    assert_eq!(REPORT.len(), SNP_REPORT_SIZE);
    let view = SnpReportView::try_from_slice(REPORT).expect("1184-byte report");
    let version = u8::try_from(view.version()).expect("version byte");
    assert!((1..=5).contains(&version));
    assert_eq!(view.signature_algo(), 1);
    assert_eq!(view.key_sel(), 0);
    assert!(!view.is_vlek());

    let ark = parse_cert(ARK_DER).expect("ARK");
    let ask = parse_cert(ASK_DER).expect("ASK");
    let vcek = parse_cert(VCEK_DER).expect("VCEK");
    let ark_key = rsa_key(&ark);
    let ask_key = rsa_key(&ask);
    let PublicKey::P384(vcek_xy) = vcek.key else {
        panic!("VCEK leaf key is P-384");
    };

    assert!(
        verify_rsa_pss_sha384(ark_key, ark.tbs, ark.signature),
        "ARK self-signature under the pinned AMD Milan root"
    );
    assert!(verify_rsa_pss_sha384(ark_key, ask.tbs, ask.signature), "ASK signed by the AMD Milan ARK");
    assert!(!verify_rsa_pss_sha384(ask_key, ask.tbs, ask.signature), "ASK must not verify under its own key");
    assert!(verify_rsa_pss_sha384(ask_key, vcek.tbs, vcek.signature), "VCEK signed by the AMD Milan ASK");

    let fields = vcek_fields(&vcek.extensions).expect("VCEK extensions");
    assert!(fields.product.contains("Milan"), "product {}", fields.product);
    assert_eq!(fields.chip_id, *view.chip_id());
    assert_eq!(fields.tcb_version, view.reported_tcb());
    assert_eq!(fields.tcb_version, view.current_tcb());

    let sig = report_signature(&view);
    assert_eq!(verify_snp_report_signature(&vcek_xy, view.signed_body(), &sig), Ok(true));

    // The 96-byte governance slot is not the Milan ARK. The chain still verifies
    // under the pinned RSA-4096 AMD root. @spec SCC-VERIFY-003 SCC-SEC-003
    let unrelated_p384_ark = [0x11u8; 96];
    assert_eq!(validate_vcek_chain(&unrelated_p384_ark, ASK_DER, VCEK_DER, &vcek_xy), Ok(()));
    let identity = parse_vcek_identity(VCEK_DER).expect("Milan VCEK identity");
    assert_eq!(identity.chip_id, fields.chip_id);
    assert_eq!(identity.tcb_version, fields.tcb_version);
}

#[test]
fn milan_vcek_rejects_a_tampered_ask_signature() {
    let ask = parse_cert(ASK_DER).expect("ASK");
    let mut der = VCEK_DER.to_vec();
    let last = der.len() - 1;
    der[last] ^= 0xff;
    let vcek = parse_cert(&der).expect("tampered cert still parses");
    assert!(!verify_rsa_pss_sha384(rsa_key(&ask), vcek.tbs, vcek.signature));
    let vcek_key = parse_cert(VCEK_DER).expect("VCEK");
    let PublicKey::P384(vcek_xy) = vcek_key.key else {
        panic!("VCEK leaf key is P-384");
    };
    assert_eq!(validate_vcek_chain(&[0x22u8; 96], ASK_DER, &der, &vcek_xy), Err(CryptoError::UntrustedRoot));
}

#[test]
fn milan_report_rejects_a_tampered_signed_body() {
    let vcek = parse_cert(VCEK_DER).expect("VCEK");
    let PublicKey::P384(vcek_xy) = vcek.key else {
        panic!("VCEK leaf key is P-384");
    };
    let mut raw = REPORT.to_vec();
    raw[0x90] ^= 0x01;
    let view = SnpReportView::try_from_slice(&raw).expect("report");
    let sig = report_signature(&view);
    assert_ne!(verify_snp_report_signature(&vcek_xy, view.signed_body(), &sig), Ok(true));
}

#[test]
fn timed_milan_validation_enforces_validity_and_returns_cache_deadline() {
    let cert = parse_cert(VCEK_DER).unwrap();
    let PublicKey::P384(xy) = cert.key else { panic!("P384") };
    use solana_confidential_compute_crypto::{validate_vcek_chain as no_clock, validate_vcek_chain_at};
    assert!(no_clock(&[0; 96], ASK_DER, VCEK_DER, &xy).is_err());
    let before = 1_790_287_995u64; // 2026-09-24T22:13:15Z
    let after = 2_011_212_795u64; // 2033-09-24T22:13:15Z
    assert_eq!(
        validate_vcek_chain_at(&[0; 96], ASK_DER, VCEK_DER, &xy, before - 1),
        Err(CryptoError::CertificateExpired)
    );
    assert_eq!(validate_vcek_chain_at(&[0; 96], ASK_DER, VCEK_DER, &xy, before), Ok(after));
    assert_eq!(validate_vcek_chain_at(&[0; 96], ASK_DER, VCEK_DER, &xy, after - 1), Ok(after));
    assert_eq!(validate_vcek_chain_at(&[0; 96], ASK_DER, VCEK_DER, &xy, after), Err(CryptoError::CertificateExpired));
    assert_eq!(
        validate_vcek_chain_at(&[0; 96], ASK_DER, VCEK_DER, &xy, 2_208_988_800),
        Err(CryptoError::CertificateExpired)
    );
    let mut tampered = VCEK_DER.to_vec();
    let n = tampered.len();
    tampered[n - 1] ^= 1;
    assert!(validate_vcek_chain(&[0; 96], ASK_DER, &tampered, &xy).is_err());
}

fn validate_vcek_chain(ark: &[u8; 96], ask: &[u8], leaf: &[u8], xy: &[u8; 96]) -> Result<(), CryptoError> {
    solana_confidential_compute_crypto::validate_vcek_chain_at(ark, ask, leaf, xy, 1_800_000_000).map(|_| ())
}
