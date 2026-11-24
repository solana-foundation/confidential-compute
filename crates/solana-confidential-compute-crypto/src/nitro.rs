//! AWS Nitro Enclaves COSE Sign1 parsing and certificate-chain verification.
//!
//! @spec SCC-NITRO-002 SCC-NITRO-003 SCC-NITRO-004 SCC-NITRO-005

use crate::cbor::{write_bstr_header, CborCursor, CborHeader};
use crate::error::CryptoError;
use crate::p384::verify_p384_signature;
use crate::vcek::{parse_certificate, DerCursor};
use sha2::{Digest, Sha384};
use solana_confidential_compute_core::{
    NitroAttestationView, NitroPcrs, MAX_NITRO_CABUNDLE, MAX_NITRO_CERT_LEN, MAX_NITRO_DOCUMENT_LEN, NITRO_NONCE_LEN,
    NITRO_PCR_LEN, NITRO_USER_DATA_LEN,
};

/// COSE header parameter `alg`.
const COSE_HEADER_ALG: i64 = 1;
/// COSE algorithm ES384 (ECDSA P-384 with SHA-384).
/// @spec SCC-NITRO-002
pub const COSE_ALG_ES384: i64 = -35;
/// CBOR tag for COSE_Sign1 (RFC 9052).
const COSE_SIGN1_TAG: u64 = 18;
/// P-384 ECDSA signature length (`r || s`).
const P384_SIG_LEN: usize = 96;

/// AWS Nitro Enclaves Root CA G1 uncompressed P-384 public key (X || Y).
///
/// Certificate SHA-256 fingerprint:
/// `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`
/// @spec SCC-NITRO-004
pub const AWS_NITRO_ROOT_CA_PUBKEY_XY: [u8; 96] = [
    0xfc, 0x02, 0x54, 0xeb, 0xa6, 0x08, 0xc1, 0xf3, 0x68, 0x70, 0xe2, 0x9a, 0xda, 0x90, 0xbe, 0x46, 0x38, 0x32, 0x92,
    0x73, 0x6e, 0x89, 0x4b, 0xff, 0xf6, 0x72, 0xd9, 0x89, 0x44, 0x4b, 0x50, 0x51, 0xe5, 0x34, 0xa4, 0xb1, 0xf6, 0xdb,
    0xe3, 0xc0, 0xbc, 0x58, 0x1a, 0x32, 0xb7, 0xb1, 0x76, 0x07, 0x0e, 0xde, 0x12, 0xd6, 0x9a, 0x3f, 0xea, 0x21, 0x1b,
    0x66, 0xe7, 0x52, 0xcf, 0x7d, 0xd1, 0xdd, 0x09, 0x5f, 0x6f, 0x13, 0x70, 0xf4, 0x17, 0x08, 0x43, 0xd9, 0xdc, 0x10,
    0x01, 0x21, 0xe4, 0xcf, 0x63, 0x01, 0x28, 0x09, 0x66, 0x44, 0x87, 0xc9, 0x79, 0x62, 0x84, 0x30, 0x4d, 0xc5, 0x3f,
    0xf4,
];

/// Zero-copy COSE Sign1 view.
/// @spec SCC-NITRO-002
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoseSign1<'a> {
    /// Protected header map bytes (bstr content).
    pub protected: &'a [u8],
    /// Attestation document payload (bstr content).
    pub payload: &'a [u8],
    /// 96-byte ECDSA P-384 signature `r || s`.
    pub signature_rs: [u8; P384_SIG_LEN],
}

/// Parsed X.509 certificate used in the Nitro chain.
/// @spec SCC-NITRO-004
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NitroCertInfo<'a> {
    pub tbs_der: &'a [u8],
    pub pubkey_xy: [u8; 96],
    pub signature_rs: [u8; P384_SIG_LEN],
    pub not_before: u64,
    pub not_after: u64,
}

/// Parses a tagged or untagged COSE Sign1 Nitro attestation document.
/// @spec SCC-NITRO-002 SCC-NITRO-003
pub fn parse_nitro_attestation(document: &[u8]) -> Result<(CoseSign1<'_>, NitroAttestationView<'_>), CryptoError> {
    if document.is_empty() || document.len() > MAX_NITRO_DOCUMENT_LEN {
        return Err(CryptoError::InvalidCoseStructure);
    }
    let cose = parse_cose_sign1(document)?;
    let attestation = parse_attestation_payload(cose.payload)?;
    Ok((cose, attestation))
}

/// Decodes the 4-element COSE Sign1 array and asserts `alg = -35`.
/// @spec SCC-NITRO-002
pub fn parse_cose_sign1(document: &[u8]) -> Result<CoseSign1<'_>, CryptoError> {
    let mut cur = CborCursor::new(document);
    if cur.peek_major()? == 6 {
        let tag = cur.read_tag().map_err(|_| CryptoError::InvalidCoseStructure)?;
        if tag != COSE_SIGN1_TAG {
            return Err(CryptoError::InvalidCoseStructure);
        }
    }
    let n = cur.read_array_len().map_err(|_| CryptoError::InvalidCoseStructure)?;
    if n != 4 {
        return Err(CryptoError::InvalidCoseStructure);
    }
    let protected = cur.read_bstr().map_err(|_| CryptoError::InvalidCoseStructure)?;
    // Unprotected headers: skip one map (contents ignored).
    let unprot_len = cur.read_map_len().map_err(|_| CryptoError::InvalidCoseStructure)?;
    for _ in 0..unprot_len {
        skip_cbor_value(&mut cur).map_err(|_| CryptoError::InvalidCoseStructure)?;
        skip_cbor_value(&mut cur).map_err(|_| CryptoError::InvalidCoseStructure)?;
    }
    let payload = cur.read_bstr().map_err(|_| CryptoError::InvalidCoseStructure)?;
    let signature = cur.read_bstr().map_err(|_| CryptoError::InvalidCoseStructure)?;
    if !cur.is_empty() {
        return Err(CryptoError::InvalidCoseStructure);
    }
    if signature.len() != P384_SIG_LEN {
        return Err(CryptoError::InvalidCoseStructure);
    }
    let mut signature_rs = [0u8; P384_SIG_LEN];
    signature_rs.copy_from_slice(signature);
    assert_protected_es384(protected)?;
    Ok(CoseSign1 { protected, payload, signature_rs })
}

fn assert_protected_es384(protected: &[u8]) -> Result<(), CryptoError> {
    let mut cur = CborCursor::new(protected);
    let n = cur.read_map_len().map_err(|_| CryptoError::InvalidCoseStructure)?;
    let mut found = false;
    for _ in 0..n {
        let key = cur.read_int().map_err(|_| CryptoError::InvalidCoseStructure)?;
        if key == COSE_HEADER_ALG {
            let alg = cur.read_int().map_err(|_| CryptoError::InvalidCoseStructure)?;
            if alg != COSE_ALG_ES384 {
                return Err(CryptoError::InvalidCoseStructure);
            }
            found = true;
        } else {
            skip_cbor_value(&mut cur).map_err(|_| CryptoError::InvalidCoseStructure)?;
        }
    }
    if !found || !cur.is_empty() {
        return Err(CryptoError::InvalidCoseStructure);
    }
    Ok(())
}

/// Parses the CBOR map payload of a Nitro attestation document.
/// @spec SCC-NITRO-003
pub fn parse_attestation_payload(payload: &[u8]) -> Result<NitroAttestationView<'_>, CryptoError> {
    let mut cur = CborCursor::new(payload);
    let map_header = cur.read_header().map_err(|_| CryptoError::InvalidAttestationPayload)?;
    let is_indefinite = match map_header {
        CborHeader::Map(_) => false,
        CborHeader::IndefiniteMap => true,
        _ => return Err(CryptoError::InvalidAttestationPayload),
    };
    let mut remaining_entries = match map_header {
        CborHeader::Map(n) => n,
        _ => usize::MAX,
    };

    let mut module_id: Option<&str> = None;
    let mut timestamp: Option<u64> = None;
    let mut digest: Option<&str> = None;
    let mut pcrs: Option<NitroPcrs> = None;
    let mut certificate: Option<&[u8]> = None;
    let mut cabundle = [b"".as_slice(); MAX_NITRO_CABUNDLE];
    let mut cabundle_len: u8 = 0;
    let mut saw_cabundle = false;
    let mut user_data: Option<[u8; NITRO_USER_DATA_LEN]> = None;
    let mut nonce: Option<[u8; NITRO_NONCE_LEN]> = None;

    loop {
        if is_indefinite {
            if cur.is_break() {
                cur.read_break().map_err(|_| CryptoError::InvalidAttestationPayload)?;
                break;
            }
        } else {
            if remaining_entries == 0 {
                break;
            }
            remaining_entries -= 1;
        }

        let key = cur.read_tstr().map_err(|_| CryptoError::InvalidAttestationPayload)?;
        match key {
            "module_id" => {
                if module_id.is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                let v = cur.read_tstr().map_err(|_| CryptoError::InvalidAttestationPayload)?;
                if v.is_empty() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                module_id = Some(v);
            }
            "timestamp" => {
                if timestamp.is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                timestamp = Some(cur.read_unsigned().map_err(|_| CryptoError::InvalidAttestationPayload)?);
            }
            "digest" => {
                if digest.is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                let v = cur.read_tstr().map_err(|_| CryptoError::InvalidAttestationPayload)?;
                if v != "SHA384" {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                digest = Some(v);
            }
            "pcrs" => {
                if pcrs.is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                pcrs = Some(parse_pcrs(&mut cur)?);
            }
            "certificate" => {
                if certificate.is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                let der = cur.read_bstr().map_err(|_| CryptoError::InvalidAttestationPayload)?;
                if der.is_empty() || der.len() > MAX_NITRO_CERT_LEN {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                certificate = Some(der);
            }
            "cabundle" => {
                if saw_cabundle {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                saw_cabundle = true;
                cabundle_len = parse_cabundle(&mut cur, &mut cabundle)?;
            }
            "user_data" => {
                if user_data.is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                let raw = cur.read_bstr().map_err(|_| CryptoError::InvalidAttestationPayload)?;
                if raw.len() != NITRO_USER_DATA_LEN {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                let mut pk = [0u8; NITRO_USER_DATA_LEN];
                pk.copy_from_slice(raw);
                user_data = Some(pk);
            }
            "nonce" => {
                if nonce.is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                let raw = cur.read_bstr().map_err(|_| CryptoError::InvalidAttestationPayload)?;
                if raw.len() != NITRO_NONCE_LEN {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
                let mut nce = [0u8; NITRO_NONCE_LEN];
                nce.copy_from_slice(raw);
                nonce = Some(nce);
            }
            _ => {
                skip_cbor_value(&mut cur).map_err(|_| CryptoError::InvalidAttestationPayload)?;
            }
        }
    }
    if !cur.is_empty() {
        return Err(CryptoError::InvalidAttestationPayload);
    }
    // cabundle is required and must contain at least one DER certificate.
    // @spec SCC-NITRO-003
    if !saw_cabundle || cabundle_len == 0 {
        return Err(CryptoError::InvalidAttestationPayload);
    }

    Ok(NitroAttestationView {
        module_id: module_id.ok_or(CryptoError::InvalidAttestationPayload)?,
        timestamp: timestamp.ok_or(CryptoError::InvalidAttestationPayload)?,
        digest: digest.ok_or(CryptoError::InvalidAttestationPayload)?,
        pcrs: pcrs.ok_or(CryptoError::InvalidAttestationPayload)?,
        certificate: certificate.ok_or(CryptoError::InvalidAttestationPayload)?,
        cabundle,
        cabundle_len,
        user_data: user_data.ok_or(CryptoError::InvalidAttestationPayload)?,
        nonce: nonce.ok_or(CryptoError::InvalidAttestationPayload)?,
    })
}

fn parse_pcrs(cur: &mut CborCursor<'_>) -> Result<NitroPcrs, CryptoError> {
    let n = cur.read_map_len().map_err(|_| CryptoError::InvalidAttestationPayload)?;
    let mut pcr0 = None;
    let mut pcr1 = None;
    let mut pcr2 = None;
    let mut pcr8 = None;
    for _ in 0..n {
        let idx = cur.read_unsigned().map_err(|_| CryptoError::InvalidAttestationPayload)?;
        let val = cur.read_bstr().map_err(|_| CryptoError::InvalidAttestationPayload)?;
        if val.len() != NITRO_PCR_LEN {
            return Err(CryptoError::InvalidAttestationPayload);
        }
        let mut digest = [0u8; NITRO_PCR_LEN];
        digest.copy_from_slice(val);
        match idx {
            0 => {
                if pcr0.replace(digest).is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
            }
            1 => {
                if pcr1.replace(digest).is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
            }
            2 => {
                if pcr2.replace(digest).is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
            }
            8 => {
                if pcr8.replace(digest).is_some() {
                    return Err(CryptoError::InvalidAttestationPayload);
                }
            }
            3..=7 | 9..=31 => {}
            _ => return Err(CryptoError::InvalidAttestationPayload),
        }
    }
    Ok(NitroPcrs {
        pcr0: pcr0.ok_or(CryptoError::InvalidAttestationPayload)?,
        pcr1: pcr1.ok_or(CryptoError::InvalidAttestationPayload)?,
        pcr2: pcr2.ok_or(CryptoError::InvalidAttestationPayload)?,
        pcr8: pcr8.ok_or(CryptoError::InvalidAttestationPayload)?,
    })
}

fn parse_cabundle<'a>(cur: &mut CborCursor<'a>, out: &mut [&'a [u8]; MAX_NITRO_CABUNDLE]) -> Result<u8, CryptoError> {
    let n = cur.read_array_len().map_err(|_| CryptoError::InvalidAttestationPayload)?;
    if n == 0 || n > MAX_NITRO_CABUNDLE {
        return Err(CryptoError::InvalidAttestationPayload);
    }
    for slot in out.iter_mut().take(n) {
        let der = cur.read_bstr().map_err(|_| CryptoError::InvalidAttestationPayload)?;
        if der.is_empty() || der.len() > MAX_NITRO_CERT_LEN {
            return Err(CryptoError::InvalidAttestationPayload);
        }
        *slot = der;
    }
    Ok(n as u8)
}

fn skip_cbor_value(cur: &mut CborCursor<'_>) -> Result<(), CryptoError> {
    cur.skip_value()
}

/// SHA-384 of canonical `Sig_structure = ["Signature1", protected, b"", payload]`.
/// Hashes incrementally with no heap allocation.
/// @spec SCC-NITRO-002 SCC-NITRO-005
pub fn hash_cose_sig_structure(protected: &[u8], payload: &[u8]) -> Result<[u8; 48], CryptoError> {
    let mut hasher = Sha384::new();
    hasher.update([0x84]); // array of 4
    hasher.update([0x6a]); // text(10)
    hasher.update(b"Signature1");
    write_bstr_header(protected.len(), |h| hasher.update(h))?;
    hasher.update(protected);
    hasher.update([0x40]); // empty bstr
    write_bstr_header(payload.len(), |h| hasher.update(h))?;
    hasher.update(payload);
    Ok(hasher.finalize().into())
}

/// Verifies the COSE Sign1 signature over `Sig_structure` with the leaf P-384 key.
/// @spec SCC-NITRO-005
pub fn verify_cose_sign1(leaf_pubkey_xy: &[u8; 96], cose: &CoseSign1<'_>) -> Result<(), CryptoError> {
    let digest = hash_cose_sig_structure(cose.protected, cose.payload)?;
    match verify_p384_signature(leaf_pubkey_xy, &digest, &cose.signature_rs) {
        Ok(true) => Ok(()),
        _ => Err(CryptoError::InvalidSignature),
    }
}

/// Parses a DER X.509 certificate, extracting P-384 SPKI, signature, and validity.
/// @spec SCC-NITRO-004
pub fn parse_nitro_cert(der: &[u8]) -> Result<NitroCertInfo<'_>, CryptoError> {
    let parsed = parse_certificate(der).map_err(|_| CryptoError::CertificateChainInvalid)?;
    let (not_before, not_after) = extract_validity(parsed.tbs_der)?;
    if not_before >= not_after {
        return Err(CryptoError::CertificateChainInvalid);
    }
    let pubkey_xy = match parsed.public_key {
        crate::vcek::SubjectPublicKey::P384(xy) => xy,
        crate::vcek::SubjectPublicKey::Rsa4096(_) => return Err(CryptoError::CertificateChainInvalid),
    };
    let signature_rs = match parsed.signature {
        crate::vcek::CertificateSignature::Ecdsa(sig) => sig,
        crate::vcek::CertificateSignature::RsaPssSha384(_) => return Err(CryptoError::CertificateChainInvalid),
    };
    Ok(NitroCertInfo { tbs_der: parsed.tbs_der, pubkey_xy, signature_rs, not_before, not_after })
}

pub(crate) fn extract_validity(tbs_full: &[u8]) -> Result<(u64, u64), CryptoError> {
    let mut outer = DerCursor::new(tbs_full);
    let (tag, body) = outer.read_tlv().map_err(|_| CryptoError::CertificateChainInvalid)?;
    if tag != 0x30 {
        return Err(CryptoError::CertificateChainInvalid);
    }
    let mut d = DerCursor::new(body);
    let (first_tag, _) = d.read_tlv().map_err(|_| CryptoError::CertificateChainInvalid)?;
    if first_tag == 0xa0 {
        let (serial_tag, _) = d.read_tlv().map_err(|_| CryptoError::CertificateChainInvalid)?;
        if serial_tag != 0x02 {
            return Err(CryptoError::CertificateChainInvalid);
        }
    } else if first_tag != 0x02 {
        return Err(CryptoError::CertificateChainInvalid);
    }
    // signature algorithm
    let (alg_tag, _) = d.read_tlv().map_err(|_| CryptoError::CertificateChainInvalid)?;
    if alg_tag != 0x30 {
        return Err(CryptoError::CertificateChainInvalid);
    }
    // issuer
    let (iss_tag, _) = d.read_tlv().map_err(|_| CryptoError::CertificateChainInvalid)?;
    if iss_tag != 0x30 {
        return Err(CryptoError::CertificateChainInvalid);
    }
    let (val_tag, validity) = d.read_tlv().map_err(|_| CryptoError::CertificateChainInvalid)?;
    if val_tag != 0x30 {
        return Err(CryptoError::CertificateChainInvalid);
    }
    let mut v = DerCursor::new(validity);
    let (nb_tag, nb) = v.read_tlv().map_err(|_| CryptoError::CertificateChainInvalid)?;
    let (na_tag, na) = v.read_tlv().map_err(|_| CryptoError::CertificateChainInvalid)?;
    if !v.is_empty() {
        return Err(CryptoError::CertificateChainInvalid);
    }
    Ok((parse_x509_time(nb_tag, nb)?, parse_x509_time(na_tag, na)?))
}

fn parse_x509_time(tag: u8, val: &[u8]) -> Result<u64, CryptoError> {
    let (year, rest) = match tag {
        0x17 => {
            // UTCTime YYMMDDHHMMSSZ
            if val.len() != 13 || val[12] != b'Z' {
                return Err(CryptoError::CertificateChainInvalid);
            }
            let yy = parse_two_digits(&val[0..2])?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &val[2..12])
        }
        0x18 => {
            // GeneralizedTime YYYYMMDDHHMMSSZ
            if val.len() != 15 || val[14] != b'Z' {
                return Err(CryptoError::CertificateChainInvalid);
            }
            let year = parse_two_digits(&val[0..2])? * 100 + parse_two_digits(&val[2..4])?;
            (year, &val[4..14])
        }
        _ => return Err(CryptoError::CertificateChainInvalid),
    };
    let month = parse_two_digits(&rest[0..2])?;
    let day = parse_two_digits(&rest[2..4])?;
    let hour = parse_two_digits(&rest[4..6])?;
    let minute = parse_two_digits(&rest[6..8])?;
    let second = parse_two_digits(&rest[8..10])?;
    civil_to_unix(year, month, day, hour, minute, second)
}

fn parse_two_digits(b: &[u8]) -> Result<i32, CryptoError> {
    if b.len() != 2 || !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
        return Err(CryptoError::CertificateChainInvalid);
    }
    Ok(((b[0] - b'0') * 10 + (b[1] - b'0')) as i32)
}

/// Days from civil date to Unix epoch using Howard Hinnant's algorithm.
fn civil_to_unix(year: i32, month: i32, day: i32, hour: i32, minute: i32, second: i32) -> Result<u64, CryptoError> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return Err(CryptoError::CertificateChainInvalid);
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day > days_in_month {
        return Err(CryptoError::CertificateChainInvalid);
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = if month > 2 { month - 3 } else { month + 9 } as u32;
    let doy = (153 * mp + 2) / 5 + day as u32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era as i64 * 146097 + doe as i64 - 719468;
    let secs = days
        .checked_mul(86400)
        .and_then(|s| s.checked_add(hour as i64 * 3600))
        .and_then(|s| s.checked_add(minute as i64 * 60))
        .and_then(|s| s.checked_add(second as i64))
        .ok_or(CryptoError::CertificateChainInvalid)?;
    u64::try_from(secs).map_err(|_| CryptoError::CertificateChainInvalid)
}

fn sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn cert_in_window(cert: &NitroCertInfo<'_>, now_unix: u64) -> Result<(), CryptoError> {
    if now_unix < cert.not_before || now_unix > cert.not_after {
        return Err(CryptoError::CertificateChainInvalid);
    }
    Ok(())
}

/// Verifies cabundle[0] matches `root_pubkey_xy`, then root → intermediates → leaf.
/// @spec SCC-NITRO-004
pub fn validate_nitro_cert_chain(
    root_pubkey_xy: &[u8; 96],
    cabundle: &[&[u8]],
    leaf_der: &[u8],
    now_unix: u64,
) -> Result<[u8; 96], CryptoError> {
    if cabundle.is_empty() || leaf_der.is_empty() {
        return Err(CryptoError::CertificateChainInvalid);
    }
    crate::validate_nitro_path_constraints(cabundle, leaf_der)?;
    let mut issuer_xy = *root_pubkey_xy;
    for (i, der) in cabundle.iter().enumerate() {
        let cert = parse_nitro_cert(der)?;
        cert_in_window(&cert, now_unix)?;
        if i == 0 {
            if &cert.pubkey_xy != root_pubkey_xy {
                return Err(CryptoError::CertificateChainInvalid);
            }
        } else {
            let hash = sha384(cert.tbs_der);
            match verify_p384_signature(&issuer_xy, &hash, &cert.signature_rs) {
                Ok(true) => {}
                _ => return Err(CryptoError::CertificateChainInvalid),
            }
        }
        issuer_xy = cert.pubkey_xy;
    }
    let leaf = parse_nitro_cert(leaf_der)?;
    cert_in_window(&leaf, now_unix)?;
    let hash = sha384(leaf.tbs_der);
    match verify_p384_signature(&issuer_xy, &hash, &leaf.signature_rs) {
        Ok(true) => Ok(leaf.pubkey_xy),
        _ => Err(CryptoError::CertificateChainInvalid),
    }
}

/// Parses a Nitro document, verifies the AWS cert chain, then the COSE Sign1 signature.
/// @spec SCC-NITRO-002 SCC-NITRO-003 SCC-NITRO-004 SCC-NITRO-005
pub fn verify_nitro_document<'a>(
    document: &'a [u8],
    root_pubkey_xy: &[u8; 96],
    now_unix: u64,
) -> Result<(CoseSign1<'a>, NitroAttestationView<'a>, [u8; 96]), CryptoError> {
    let (cose, attestation) = parse_nitro_attestation(document)?;
    let leaf_xy =
        validate_nitro_cert_chain(root_pubkey_xy, attestation.cabundle_certs(), attestation.certificate, now_unix)?;
    verify_cose_sign1(&leaf_xy, &cose)?;
    Ok((cose, attestation, leaf_xy))
}

#[cfg(test)]
mod tests {
    use super::*;
    mod cert_fixture {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/nitro_cert.rs"));
    }
    use cert_fixture::standard_cert;
    use p384::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
    use p384::ecdsa::{Signature, SigningKey, VerifyingKey};

    const NOW: u64 = 1_800_000_000; // 2027-01-15-ish, inside 2025–2035 test certs.

    fn keypair(seed_lsb: u8) -> (SigningKey, [u8; 96]) {
        let mut seed = [0u8; 48];
        seed[47] = seed_lsb;
        let signing_key = SigningKey::from_slice(&seed).expect("valid scalar");
        let encoded = signing_key.verifying_key().to_encoded_point(false);
        let mut xy = [0u8; 96];
        xy[..48].copy_from_slice(encoded.x().unwrap().as_slice());
        xy[48..].copy_from_slice(encoded.y().unwrap().as_slice());
        (signing_key, xy)
    }

    fn cbor_uint(n: u64) -> Vec<u8> {
        if n <= 23 {
            vec![n as u8]
        } else if n <= 0xff {
            vec![0x18, n as u8]
        } else if n <= 0xffff {
            let b = (n as u16).to_be_bytes();
            vec![0x19, b[0], b[1]]
        } else if n <= 0xffff_ffff {
            let b = (n as u32).to_be_bytes();
            vec![0x1a, b[0], b[1], b[2], b[3]]
        } else {
            let b = n.to_be_bytes();
            let mut v = vec![0x1b];
            v.extend_from_slice(&b);
            v
        }
    }

    fn cbor_header(major: u8, len: usize) -> Vec<u8> {
        if len <= 23 {
            vec![(major << 5) | (len as u8)]
        } else if len <= 0xff {
            vec![(major << 5) | 24, len as u8]
        } else if len <= 0xffff {
            let b = (len as u16).to_be_bytes();
            vec![(major << 5) | 25, b[0], b[1]]
        } else {
            let b = (len as u32).to_be_bytes();
            vec![(major << 5) | 26, b[0], b[1], b[2], b[3]]
        }
    }

    fn cbor_bstr(b: &[u8]) -> Vec<u8> {
        let mut out = cbor_header(2, b.len());
        out.extend_from_slice(b);
        out
    }

    fn cbor_tstr(s: &str) -> Vec<u8> {
        let mut out = cbor_header(3, s.len());
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn cbor_array(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = cbor_header(4, items.len());
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    fn cbor_map_text(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = cbor_header(5, pairs.len());
        for (k, v) in pairs {
            out.extend_from_slice(&cbor_tstr(k));
            out.extend_from_slice(v);
        }
        out
    }

    fn cbor_map_int(pairs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = cbor_header(5, pairs.len());
        for (k, v) in pairs {
            out.extend_from_slice(&cbor_uint(*k));
            out.extend_from_slice(v);
        }
        out
    }

    fn protected_es384() -> Vec<u8> {
        // {1: -35} => 0xa1 0x01 0x38 0x22
        vec![0xa1, 0x01, 0x38, 0x22]
    }

    fn encode_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
        cbor_array(&[cbor_tstr("Signature1"), cbor_bstr(protected), cbor_bstr(b""), cbor_bstr(payload)])
    }

    struct Fixture {
        root_xy: [u8; 96],
        leaf_sk: SigningKey,
        leaf_xy: [u8; 96],
        root_cert: Vec<u8>,
        inter_cert: Vec<u8>,
        leaf_cert: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let (root_sk, root_xy) = keypair(0x21);
        let (inter_sk, inter_xy) = keypair(0x22);
        let (leaf_sk, leaf_xy) = keypair(0x23);
        Fixture {
            root_xy,
            leaf_sk,
            leaf_xy,
            root_cert: standard_cert(&root_xy, &root_sk, b"root", b"root", true),
            inter_cert: standard_cert(&inter_xy, &root_sk, b"root", b"inter", true),
            leaf_cert: standard_cert(&leaf_xy, &inter_sk, b"inter", b"leaf", false),
        }
    }

    fn payload_bytes(fx: &Fixture, pcr0: [u8; 48], user_data: [u8; 32], nonce: [u8; 32]) -> Vec<u8> {
        let pcrs = cbor_map_int(&[
            (0, cbor_bstr(&pcr0)),
            (1, cbor_bstr(&[1u8; 48])),
            (2, cbor_bstr(&[2u8; 48])),
            (8, cbor_bstr(&[8u8; 48])),
        ]);
        let cabundle = cbor_array(&[cbor_bstr(&fx.root_cert), cbor_bstr(&fx.inter_cert)]);
        cbor_map_text(&[
            ("module_id", cbor_tstr("i-teton-nitro-0")),
            ("timestamp", cbor_uint(NOW * 1000)),
            ("digest", cbor_tstr("SHA384")),
            ("pcrs", pcrs),
            ("certificate", cbor_bstr(&fx.leaf_cert)),
            ("cabundle", cabundle),
            ("user_data", cbor_bstr(&user_data)),
            ("nonce", cbor_bstr(&nonce)),
        ])
    }

    fn sign_cose(leaf_sk: &SigningKey, protected: &[u8], payload: &[u8]) -> [u8; 96] {
        let encoded = encode_sig_structure(protected, payload);
        let mut hasher = Sha384::new();
        hasher.update(&encoded);
        let hash: [u8; 48] = hasher.finalize().into();
        let (signature, _) = leaf_sk.sign_prehash(&hash).expect("sign");
        let mut rs = [0u8; 96];
        rs.copy_from_slice(signature.to_bytes().as_slice());
        rs
    }

    fn encode_document(fx: &Fixture, payload: &[u8]) -> Vec<u8> {
        let protected = protected_es384();
        let sig = sign_cose(&fx.leaf_sk, &protected, payload);
        let mut doc = vec![0xd2]; // tag 18
        doc.extend_from_slice(&cbor_array(&[cbor_bstr(&protected), vec![0xa0], cbor_bstr(payload), cbor_bstr(&sig)]));
        doc
    }

    #[test]
    fn parse_and_verify_roundtrip() {
        let fx = fixture();
        let pcr0 = [0x42u8; 48];
        let user = [0x11u8; 32];
        let nonce = [0x22u8; 32];
        let payload = payload_bytes(&fx, pcr0, user, nonce);
        let doc = encode_document(&fx, &payload);

        let (cose, view, leaf_xy) = verify_nitro_document(&doc, &fx.root_xy, NOW).expect("verify");
        assert_eq!(leaf_xy, fx.leaf_xy);
        assert_eq!(view.module_id, "i-teton-nitro-0");
        assert_eq!(view.digest, "SHA384");
        assert_eq!(view.pcrs.pcr0, pcr0);
        assert_eq!(view.user_data, user);
        assert_eq!(view.nonce, nonce);
        assert_eq!(view.cabundle_len, 2);
        assert_eq!(cose.protected, protected_es384().as_slice());
    }

    #[test]
    fn sig_structure_hash_matches_encoded_bytes() {
        let protected = protected_es384();
        let payload = b"\xa0";
        let incremental = hash_cose_sig_structure(&protected, payload).unwrap();
        let encoded = encode_sig_structure(&protected, payload);
        let mut hasher = Sha384::new();
        hasher.update(&encoded);
        let full: [u8; 48] = hasher.finalize().into();
        assert_eq!(incremental, full);
    }

    #[test]
    fn rejects_wrong_alg() {
        let fx = fixture();
        let payload = payload_bytes(&fx, [0x42u8; 48], [0x11u8; 32], [0x22u8; 32]);
        // {1: -7} ES256 instead of ES384
        let protected = vec![0xa1, 0x01, 0x26];
        let sig = sign_cose(&fx.leaf_sk, &protected, &payload);
        let mut doc = vec![0xd2];
        doc.extend_from_slice(&cbor_array(&[cbor_bstr(&protected), vec![0xa0], cbor_bstr(&payload), cbor_bstr(&sig)]));
        assert_eq!(parse_nitro_attestation(&doc).unwrap_err(), CryptoError::InvalidCoseStructure);
    }

    #[test]
    fn rejects_untrusted_root() {
        let fx = fixture();
        let payload = payload_bytes(&fx, [0x42u8; 48], [0x11u8; 32], [0x22u8; 32]);
        let doc = encode_document(&fx, &payload);
        let (_wrong_sk, wrong_xy) = keypair(0x99);
        assert_eq!(verify_nitro_document(&doc, &wrong_xy, NOW).unwrap_err(), CryptoError::CertificateChainInvalid);
    }

    #[test]
    fn rejects_tampered_payload_signature() {
        let fx = fixture();
        let payload = payload_bytes(&fx, [0x42u8; 48], [0x11u8; 32], [0x22u8; 32]);
        let mut doc = encode_document(&fx, &payload);
        let last = doc.len() - 1;
        doc[last] ^= 0x01;
        assert_eq!(verify_nitro_document(&doc, &fx.root_xy, NOW).unwrap_err(), CryptoError::InvalidSignature);
    }

    #[test]
    fn rejects_expired_leaf() {
        let fx = fixture();
        let payload = payload_bytes(&fx, [0x42u8; 48], [0x11u8; 32], [0x22u8; 32]);
        let doc = encode_document(&fx, &payload);
        // 2040-01-01 is after test cert notAfter 2035-01-01.
        assert_eq!(
            verify_nitro_document(&doc, &fx.root_xy, 2_208_988_800).unwrap_err(),
            CryptoError::CertificateChainInvalid
        );
    }

    #[test]
    fn rejects_missing_cabundle() {
        let fx = fixture();
        let pcrs = cbor_map_int(&[
            (0, cbor_bstr(&[0x42u8; 48])),
            (1, cbor_bstr(&[1u8; 48])),
            (2, cbor_bstr(&[2u8; 48])),
            (8, cbor_bstr(&[8u8; 48])),
        ]);
        let payload = cbor_map_text(&[
            ("module_id", cbor_tstr("i-teton-nitro-0")),
            ("timestamp", cbor_uint(NOW * 1000)),
            ("digest", cbor_tstr("SHA384")),
            ("pcrs", pcrs),
            ("certificate", cbor_bstr(&fx.leaf_cert)),
            ("user_data", cbor_bstr(&[0x11u8; 32])),
            ("nonce", cbor_bstr(&[0x22u8; 32])),
        ]);
        let doc = encode_document(&fx, &payload);
        assert_eq!(parse_nitro_attestation(&doc).unwrap_err(), CryptoError::InvalidAttestationPayload);
    }

    #[test]
    fn rejects_missing_user_data() {
        let fx = fixture();
        let pcrs = cbor_map_int(&[
            (0, cbor_bstr(&[0x42u8; 48])),
            (1, cbor_bstr(&[1u8; 48])),
            (2, cbor_bstr(&[2u8; 48])),
            (8, cbor_bstr(&[8u8; 48])),
        ]);
        let cabundle = cbor_array(&[cbor_bstr(&fx.root_cert), cbor_bstr(&fx.inter_cert)]);
        let payload = cbor_map_text(&[
            ("module_id", cbor_tstr("i-teton-nitro-0")),
            ("timestamp", cbor_uint(NOW * 1000)),
            ("digest", cbor_tstr("SHA384")),
            ("pcrs", pcrs),
            ("certificate", cbor_bstr(&fx.leaf_cert)),
            ("cabundle", cabundle),
            ("nonce", cbor_bstr(&[0x22u8; 32])),
        ]);
        let doc = encode_document(&fx, &payload);
        assert_eq!(parse_nitro_attestation(&doc).unwrap_err(), CryptoError::InvalidAttestationPayload);
    }

    #[test]
    fn leaf_pubkey_roundtrip_with_verifying_key() {
        let fx = fixture();
        let encoded = fx.leaf_sk.verifying_key().to_encoded_point(false);
        let vk = VerifyingKey::from_encoded_point(&encoded).unwrap();
        let digest = [0x11u8; 48];
        let (sig, _) = fx.leaf_sk.sign_prehash(&digest).unwrap();
        vk.verify_prehash(&digest, &sig).unwrap();
        let _ = Signature::from_slice(&sig.to_bytes()[..]).unwrap();
    }

    #[test]
    fn skip_cbor_value_depth_bound() {
        use crate::cbor::CborCursor;

        // Exactly 8 nested arrays: allowed
        let mut ok_cbor = vec![0x81u8; 7];
        ok_cbor.push(0x80);
        let mut cur = CborCursor::new(&ok_cbor);
        assert!(skip_cbor_value(&mut cur).is_ok());

        // 9 nested arrays: exceeds MAX_CBOR_SKIP_DEPTH
        let mut deep_cbor = vec![0x81u8; 8];
        deep_cbor.push(0x80);
        let mut cur = CborCursor::new(&deep_cbor);
        assert_eq!(skip_cbor_value(&mut cur).unwrap_err(), CryptoError::MalformedCbor);
    }

    #[test]
    fn verify_hardware_nitro_attestation_document() {
        let nsm_response = include_bytes!("../../../fixtures/nitro_hardware_attestation.bin");
        assert_eq!(nsm_response.len(), 4552);

        // NSM ioctl returns CBOR envelope: {"Attestation": {"document": <COSE_Sign1>}}
        // The COSE_Sign1 payload starts at offset 26.
        let document = &nsm_response[26..];
        assert_eq!(document.len(), 4526);

        // Verify against real AWS Nitro Root CA G1 public key
        // Validity timestamp: Sept 25, 2026 22:30:00 UTC (1790375400)
        let now = 1_790_375_400;
        let (_cose, view, leaf_xy) = verify_nitro_document(document, &AWS_NITRO_ROOT_CA_PUBKEY_XY, now)
            .expect("hardware nitro document cryptographic verification failed");

        assert_eq!(view.module_id, "i-0c801b445eeba3a9e-enc01a0daae7e35adef");
        assert_eq!(view.digest, "SHA384");
        assert_eq!(view.user_data, [0x55u8; 32]);
        assert_eq!(view.nonce, [0x77u8; 32]);

        // Hardware PCR checks
        let expected_pcr0 = hex::decode(
            "2a86e61029832fc64b047e727b2f2265eb07215d073cd458bf6debf5e557a43a146916546030cf5dd8398175f8441e66",
        )
        .unwrap();
        let expected_pcr1 = hex::decode(
            "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
        )
        .unwrap();
        let expected_pcr2 = hex::decode(
            "cfc7e55365dafbfe29eb90750a83ae38a4ed727402d194f52af6c5714e9afc54714faa9f0989c95fe075b3585b3eefb3",
        )
        .unwrap();

        assert_eq!(view.pcrs.pcr0.as_slice(), expected_pcr0.as_slice());
        assert_eq!(view.pcrs.pcr1.as_slice(), expected_pcr1.as_slice());
        assert_eq!(view.pcrs.pcr2.as_slice(), expected_pcr2.as_slice());
        assert!(!view.pcrs.pcr0_is_zero());

        assert_eq!(view.cabundle_len, 4);
        assert!(!leaf_xy.is_empty());
    }

    #[test]
    fn extract_validity_rejects_trailing_bytes() {
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(2 + value.len());
            out.push(tag);
            out.push(value.len() as u8);
            out.extend_from_slice(value);
            out
        }
        fn utc(text: &str) -> Vec<u8> {
            tlv(0x17, text.as_bytes())
        }

        let mut validity = Vec::new();
        validity.extend(utc("250101000000Z"));
        validity.extend(utc("350101000000Z"));
        let clean = {
            let mut body = Vec::new();
            body.extend(tlv(0x02, &[0x01]));
            body.extend(tlv(0x30, &[]));
            body.extend(tlv(0x30, &[]));
            body.extend(tlv(0x30, &validity));
            tlv(0x30, &body)
        };
        assert!(extract_validity(&clean).is_ok());

        validity.push(0xff);
        let mut body = Vec::new();
        body.extend(tlv(0x02, &[0x01]));
        body.extend(tlv(0x30, &[]));
        body.extend(tlv(0x30, &[]));
        body.extend(tlv(0x30, &validity));
        let trailing = tlv(0x30, &body);
        assert_eq!(extract_validity(&trailing), Err(CryptoError::CertificateChainInvalid));
    }
    #[test]
    fn certificate_calendar_rejects_impossible_dates_and_leap_seconds() {
        for value in [b"230229000000Z", b"240231000000Z", b"240431000000Z", b"240101000060Z"] {
            assert!(parse_x509_time(0x17, value).is_err());
        }
        assert!(parse_x509_time(0x17, b"240229000000Z").is_ok());
        assert!(parse_x509_time(0x18, b"21000229000000Z").is_err());
        assert!(parse_x509_time(0x18, b"20000229000000Z").is_ok());
    }
}
