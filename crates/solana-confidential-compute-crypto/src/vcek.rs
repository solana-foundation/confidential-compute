//! AMD Versioned Chip Endorsement Key (VCEK) certificate chain validation.
//!
//! Parses X.509 DER (ARK -> ASK -> VCEK). The supported AMD Milan KDS chains use RSA-4096
//! RSASSA-PSS SHA-384 for the ARK and ASK, and a P-384 VCEK leaf.
//!
//! @spec SCC-VERIFY-003 SCC-SEC-003

use alloc::boxed::Box;

use crate::error::CryptoError;
use crate::rsa_pss::{verify_rsassa_pss_sha384, MILAN_ARK_MODULUS, RSA4096_LEN};
#[cfg(test)]
use sha2::{Digest, Sha384};

/// Reject oversized DER blobs that cannot be a real AMD ASK / VCEK certificate.
pub const MAX_CERT_DER_LEN: usize = 4096;

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_PRINTABLE_STRING: u8 = 0x13;
const TAG_TELETEX_STRING: u8 = 0x14;
const TAG_IA5_STRING: u8 = 0x16;
const TAG_UNIVERSAL_STRING: u8 = 0x1C;
const TAG_BMP_STRING: u8 = 0x1E;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_SPECIFIC_0: u8 = 0xA0;
/// `extensions [3] EXPLICIT` on `TBSCertificate`.
const TAG_EXTENSIONS: u8 = 0xA3;
/// AMD KDS VLEK common name marker (`CN=SEV-VLEK`).
const VLEK_MARKER: &[u8] = b"SEV-VLEK";

/// AMD KDS `tcbVersion` / `structVersion`. OID `1.3.6.1.4.1.3704.1.1`.
///
/// Issue #81 names this OID `tcbVersion`. AMD 57230 names the same OID
/// `structVersion` and spreads the TCB word across the `*SPL` children of
/// `1.3.6.1.4.1.3704.1.3`. When those SPL extensions are present they form
/// `tcb_version`; otherwise the INTEGER at this OID is the full TCB word.
/// @spec SCC-VERIFY-003
const OID_TCB_VERSION: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x01];

/// AMD KDS `hwID`. OID `1.3.6.1.4.1.3704.1.4`.
/// @spec SCC-VERIFY-003
const OID_HWID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x04];

/// Common prefix of `1.3.6.1.4.1.3704.1.3` (the SPL arc). The next byte selects
/// the TCB component (AMD 57230 Table 9).
const OID_SPL_PREFIX: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x03];

/// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3).
const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
/// `id-RSASSA-PSS` (1.2.840.113549.1.1.10).
const OID_RSASSA_PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
/// `rsaEncryption` (1.2.840.113549.1.1.1).
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// `id-sha384` (2.16.840.1.101.3.4.2.2).
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
/// `id-mgf1` (1.2.840.113549.1.1.8).
const OID_MGF1: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08];
const TAG_NULL: u8 = 0x05;

/// Chip id and TCB word bound inside a leaf endorsement certificate.
/// @spec SCC-VERIFY-003 SCC-VERIFY-009
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VcekIdentity {
    pub chip_id: [u8; 64],
    pub tcb_version: u64,
    /// Signed subject directory string contains `VLEK` (`CN=SEV-VLEK`).
    /// @spec SCC-VERIFY-009
    pub subject_is_vlek: bool,
}

/// Subject public key extracted from a certificate SPKI.
/// @spec SCC-VERIFY-003
pub(crate) enum SubjectPublicKey {
    P384([u8; 96]),
    Rsa4096(Box<[u8; RSA4096_LEN]>),
}

/// Signature value on a parsed certificate.
/// @spec SCC-VERIFY-003
pub(crate) enum CertificateSignature<'a> {
    Ecdsa([u8; 96]),
    /// RSASSA-PSS SHA-384 signature bytes borrowed from the certificate.
    RsaPssSha384(&'a [u8]),
}

pub(crate) struct ParsedCert<'a> {
    /// Full DER encoding of `tbsCertificate` (tag + length + body). This is the signed payload.
    pub tbs_der: &'a [u8],
    pub public_key: SubjectPublicKey,
    pub signature: CertificateSignature<'a>,
}

/// A trusted clock is required. Use `validate_vcek_chain_at` for validation.
/// This legacy entrypoint fails closed rather than silently ignoring expiry.
///
/// @spec SCC-VERIFY-003 SCC-SEC-003
pub fn validate_vcek_chain(
    _ark_pubkey_xy: &[u8; 96],
    _ask: &[u8],
    _vcek: &[u8],
    _expected: &[u8; 96],
) -> Result<(), CryptoError> {
    Err(CryptoError::CertificateExpired)
}

/// Validate the supported chain at a trusted Unix time, returning its exclusive
/// cache deadline (the earliest ASK/leaf notAfter). This is not full PKIX or
/// revocation validation. Callers must enforce the returned deadline on reuse.
///
/// The signature profile is that of `validate_vcek_signatures_only`.
///
/// @spec SCC-VERIFY-003 SCC-SEC-003
pub fn validate_vcek_chain_at(
    ark_pubkey_xy: &[u8; 96],
    ask_cert_der: &[u8],
    vcek_cert_der: &[u8],
    expected_vcek_xy: &[u8; 96],
    now_unix: u64,
) -> Result<u64, CryptoError> {
    // Authenticate before treating certificate fields as trusted metadata.
    validate_vcek_signatures_only(ark_pubkey_xy, ask_cert_der, vcek_cert_der, expected_vcek_xy)?;
    let mut expires = u64::MAX;
    for der in [ask_cert_der, vcek_cert_der] {
        let cert = parse_certificate(der)?;
        let (not_before, not_after) = crate::nitro::extract_validity(cert.tbs_der)?;
        if not_before >= not_after || now_unix < not_before || now_unix >= not_after {
            return Err(CryptoError::CertificateExpired);
        }
        expires = expires.min(not_after);
    }
    Ok(expires)
}

/// Offline signature-only check of the AMD SEV-SNP certificate chain:
/// AMD Root Key (ARK) -> AMD Signing Key (ASK) -> Versioned Chip Endorsement Key (VCEK).
///
/// Only RSA-4096 Milan ASK certificates under the pinned AMD Milan ARK modulus
/// are supported. The legacy `ark_pubkey_xy` argument is ignored; synthetic
/// ECDSA roots are not an AMD trust profile. The leaf VCEK subject public key must match
/// `expected_vcek_xy`.
///
/// Does not enforce time, cache expiry, revocation, or a complete RFC 5280
/// profile. Never use for registration.
///
/// @spec SCC-VERIFY-003 SCC-SEC-003
pub fn validate_vcek_signatures_only(
    _ark_pubkey_xy: &[u8; 96],
    ask_cert_der: &[u8],
    vcek_cert_der: &[u8],
    expected_vcek_xy: &[u8; 96],
) -> Result<(), CryptoError> {
    if ask_cert_der.is_empty()
        || vcek_cert_der.is_empty()
        || ask_cert_der.len() > MAX_CERT_DER_LEN
        || vcek_cert_der.len() > MAX_CERT_DER_LEN
    {
        return Err(CryptoError::MalformedCertificate);
    }

    let ask = parse_certificate(ask_cert_der)?;
    let vcek = parse_certificate(vcek_cert_der)?;
    match (&ask.public_key, &ask.signature, &vcek.signature) {
        (
            SubjectPublicKey::Rsa4096(ask_modulus),
            CertificateSignature::RsaPssSha384(ask_sig),
            CertificateSignature::RsaPssSha384(vcek_sig),
        ) => {
            verify_rsassa_pss_sha384(&MILAN_ARK_MODULUS, ask.tbs_der, ask_sig)?;
            verify_rsassa_pss_sha384(ask_modulus, vcek.tbs_der, vcek_sig)?;
        }
        _ => return Err(CryptoError::UntrustedRoot),
    }

    let SubjectPublicKey::P384(vcek_xy) = vcek.public_key else {
        return Err(CryptoError::InvalidP384PublicKey);
    };
    if vcek_xy != *expected_vcek_xy {
        return Err(CryptoError::InvalidP384PublicKey);
    }

    Ok(())
}

/// Reads `hwID` and `tcb_version` from the leaf VCEK extensions.
///
/// `hwID` is OID `1.3.6.1.4.1.3704.1.4` (64 bytes). `tcb_version` is the
/// little-endian TCB word. AMD 57230 encodes that word as SPL integers under
/// `1.3.6.1.4.1.3704.1.3.*` (boot loader, TEE, reserved, SNP, microcode). When
/// those components are absent, the INTEGER at OID `1.3.6.1.4.1.3704.1.1`
/// (`tcbVersion`) is the full TCB word. Real KDS certificates put
/// `structVersion` at that OID and the TCB in the SPL extensions, so the SPL
/// word wins when any component is present.
///
/// Missing `hwID` is accepted only for exact signed subject CN=SEV-VLEK
/// (AMD 58369), represented by a zero chip ID. Missing TCB always fails closed.
/// `subject_is_vlek` is read from the same signed subject `Name`.
///
/// @spec SCC-VERIFY-003 SCC-VERIFY-009
pub fn parse_vcek_identity(vcek_cert_der: &[u8]) -> Result<VcekIdentity, CryptoError> {
    if vcek_cert_der.is_empty() || vcek_cert_der.len() > MAX_CERT_DER_LEN {
        return Err(CryptoError::MalformedCertificate);
    }
    let parsed = parse_certificate(vcek_cert_der)?;
    let tbs_body = tbs_body_from_der(parsed.tbs_der)?;
    let extensions = extensions_sequence(tbs_body)?;

    let mut chip_id = None;
    let mut direct_tcb = None;
    let mut spl = [None; 8];
    let mut cursor = DerCursor::new(extensions);
    if cursor.is_empty() {
        return Err(CryptoError::VcekExtensionMissing);
    }
    while !cursor.is_empty() {
        let (tag, ext_body) = cursor.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(CryptoError::MalformedCertificate);
        }
        let (oid, value) = read_extension(ext_body)?;
        if oid == OID_HWID {
            if chip_id.is_some() {
                return Err(CryptoError::MalformedCertificate);
            }
            chip_id = Some(parse_hwid(value)?);
        } else if oid == OID_TCB_VERSION {
            if direct_tcb.is_some() {
                return Err(CryptoError::MalformedCertificate);
            }
            direct_tcb = Some(parse_integer_u64(value)?);
        } else if let Some(index) = spl_component_index(oid) {
            if spl[index].is_some() {
                return Err(CryptoError::MalformedCertificate);
            }
            let component = parse_integer_u64(value)?;
            let component = u8::try_from(component).map_err(|_| CryptoError::MalformedCertificate)?;
            spl[index] = Some(component);
        }
    }

    let subject_is_vlek = subject_contains_vlek(subject_name(tbs_body)?)?;
    // AMD 58369 VLEK leaves omit hwID. Use the canonical zero sentinel in
    // the registration wire; the PDA binds the authenticated endorsement XY.
    let chip_id = match chip_id {
        Some(value) => value,
        None if subject_is_vlek => [0; 64],
        None => return Err(CryptoError::VcekExtensionMissing),
    };
    let saw_spl = spl.iter().any(|component| component.is_some());
    let tcb_version = if saw_spl {
        let mut bytes = [0u8; 8];
        for (index, component) in spl.iter().enumerate() {
            if let Some(value) = component {
                bytes[index] = *value;
            }
        }
        u64::from_le_bytes(bytes)
    } else {
        direct_tcb.ok_or(CryptoError::VcekExtensionMissing)?
    };
    Ok(VcekIdentity { chip_id, tcb_version, subject_is_vlek })
}

/// Report-byte index for an SPL OID under `1.3.6.1.4.1.3704.1.3`.
///
/// AMD 57230 Table 9, little-endian `TCB_VERSION`:
/// `.1` boot loader, `.2` TEE, `.4`–`.7` reserved, `.3` SNP, `.8` microcode.
fn spl_component_index(oid: &[u8]) -> Option<usize> {
    let &[component] = oid.strip_prefix(OID_SPL_PREFIX)? else {
        return None;
    };
    match component {
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

fn tbs_body_from_der(tbs_der: &[u8]) -> Result<&[u8], CryptoError> {
    let mut cursor = DerCursor::new(tbs_der);
    let (tag, body) = cursor.read_tlv()?;
    if tag != TAG_SEQUENCE || !cursor.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    Ok(body)
}

fn extensions_sequence(tbs_body: &[u8]) -> Result<&[u8], CryptoError> {
    let mut cursor = DerCursor::new(tbs_body);
    let (first_tag, _) = cursor.read_tlv()?;
    if first_tag == TAG_CONTEXT_SPECIFIC_0 {
        let (serial_tag, _) = cursor.read_tlv()?;
        if serial_tag != TAG_INTEGER {
            return Err(CryptoError::MalformedCertificate);
        }
    } else if first_tag != TAG_INTEGER {
        return Err(CryptoError::MalformedCertificate);
    }
    expect_tag(&mut cursor, TAG_SEQUENCE)?;
    expect_tag(&mut cursor, TAG_SEQUENCE)?;
    expect_tag(&mut cursor, TAG_SEQUENCE)?;
    expect_tag(&mut cursor, TAG_SEQUENCE)?;
    expect_tag(&mut cursor, TAG_SEQUENCE)?;

    while !cursor.is_empty() {
        let (tag, value) = cursor.read_tlv()?;
        if tag == TAG_EXTENSIONS {
            let mut explicit = DerCursor::new(value);
            let (seq_tag, seq) = explicit.read_tlv()?;
            if seq_tag != TAG_SEQUENCE || !explicit.is_empty() {
                return Err(CryptoError::MalformedCertificate);
            }
            if !cursor.is_empty() {
                return Err(CryptoError::MalformedCertificate);
            }
            return Ok(seq);
        }
        // issuerUniqueID [1] and subjectUniqueID [2] are optional.
        if tag != 0x81 && tag != 0x82 {
            return Err(CryptoError::MalformedCertificate);
        }
    }
    Err(CryptoError::VcekExtensionMissing)
}

fn read_extension(body: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    let mut cursor = DerCursor::new(body);
    let (oid_tag, oid) = cursor.read_tlv()?;
    if oid_tag != TAG_OID {
        return Err(CryptoError::MalformedCertificate);
    }
    let (next_tag, next_val) = cursor.read_tlv()?;
    let value = if next_tag == TAG_BOOLEAN {
        if next_val.len() != 1 || (next_val[0] != 0x00 && next_val[0] != 0xFF) {
            return Err(CryptoError::MalformedCertificate);
        }
        let (value_tag, value) = cursor.read_tlv()?;
        if value_tag != TAG_OCTET_STRING {
            return Err(CryptoError::MalformedCertificate);
        }
        value
    } else if next_tag == TAG_OCTET_STRING {
        next_val
    } else {
        return Err(CryptoError::MalformedCertificate);
    };
    if !cursor.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    Ok((oid, value))
}

fn parse_hwid(value: &[u8]) -> Result<[u8; 64], CryptoError> {
    // KDS sometimes places the raw 64-byte id in the extension value.
    if value.len() == 64 {
        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(value);
        return Ok(chip_id);
    }
    let mut cursor = DerCursor::new(value);
    let (tag, body) = cursor.read_tlv()?;
    if tag != TAG_OCTET_STRING || !cursor.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    let raw = if body.len() == 64 {
        body
    } else {
        let mut nested = DerCursor::new(body);
        let (inner_tag, inner) = nested.read_tlv()?;
        if inner_tag != TAG_OCTET_STRING || !nested.is_empty() || inner.len() != 64 {
            return Err(CryptoError::MalformedCertificate);
        }
        inner
    };
    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(raw);
    Ok(chip_id)
}

fn parse_integer_u64(value: &[u8]) -> Result<u64, CryptoError> {
    let mut cursor = DerCursor::new(value);
    let (tag, content) = cursor.read_tlv()?;
    if tag != TAG_INTEGER || !cursor.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    der_integer_u64(content)
}

fn der_integer_u64(content: &[u8]) -> Result<u64, CryptoError> {
    if content.is_empty() || content.len() > 9 || content[0] & 0x80 != 0 {
        return Err(CryptoError::MalformedCertificate);
    }
    let digits = if content.len() > 1 && content[0] == 0x00 {
        if content[1] & 0x80 == 0 {
            return Err(CryptoError::MalformedCertificate);
        }
        &content[1..]
    } else {
        content
    };
    if digits.is_empty() || digits.len() > 8 {
        return Err(CryptoError::MalformedCertificate);
    }
    let mut be = [0u8; 8];
    let start = be.len().checked_sub(digits.len()).ok_or(CryptoError::MalformedCertificate)?;
    be[start..].copy_from_slice(digits);
    Ok(u64::from_be_bytes(be))
}

#[cfg(test)]
fn sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub(crate) fn parse_certificate(der: &[u8]) -> Result<ParsedCert<'_>, CryptoError> {
    let mut outer = DerCursor::new(der);
    let (tag, body) = outer.read_tlv()?;
    if tag != TAG_SEQUENCE {
        return Err(CryptoError::MalformedCertificate);
    }

    let mut seq = DerCursor::new(body);
    let (tbs_tag, tbs_full, tbs_body) = seq.read_tlv_full()?;
    if tbs_tag != TAG_SEQUENCE {
        return Err(CryptoError::MalformedCertificate);
    }

    let (alg_tag, alg_body) = seq.read_tlv()?;
    if alg_tag != TAG_SEQUENCE {
        return Err(CryptoError::MalformedCertificate);
    }

    let (sig_tag, sig_val) = seq.read_tlv()?;
    if sig_tag != TAG_BIT_STRING {
        return Err(CryptoError::MalformedCertificate);
    }

    if !seq.is_empty() || !outer.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }

    let signature = match signature_algorithm(alg_body)? {
        SignatureAlgorithm::EcdsaSha384 => CertificateSignature::Ecdsa(parse_ecdsa_sig_bitstring(sig_val)?),
        SignatureAlgorithm::RsaPssSha384 => CertificateSignature::RsaPssSha384(parse_rsa_pss_sig_bitstring(sig_val)?),
    };

    Ok(ParsedCert { tbs_der: tbs_full, public_key: extract_spki(tbs_body)?, signature })
}

enum SignatureAlgorithm {
    EcdsaSha384,
    RsaPssSha384,
}

fn signature_algorithm(body: &[u8]) -> Result<SignatureAlgorithm, CryptoError> {
    let mut cursor = DerCursor::new(body);
    let (oid_tag, oid) = cursor.read_tlv()?;
    if oid_tag != TAG_OID {
        return Err(CryptoError::MalformedCertificate);
    }
    if oid == OID_ECDSA_WITH_SHA384 {
        if !cursor.is_empty() {
            let (tag, value) = cursor.read_tlv()?;
            if tag != TAG_NULL || !value.is_empty() || !cursor.is_empty() {
                return Err(CryptoError::MalformedCertificate);
            }
        }
        return Ok(SignatureAlgorithm::EcdsaSha384);
    }
    if oid == OID_RSASSA_PSS {
        let (tag, params) = cursor.read_tlv()?;
        if tag != TAG_SEQUENCE || !cursor.is_empty() {
            return Err(CryptoError::MalformedCertificate);
        }
        require_pss_sha384_params(params)?;
        return Ok(SignatureAlgorithm::RsaPssSha384);
    }
    Err(CryptoError::MalformedCertificate)
}

/// AMD KDS PSS parameters: SHA-384, MGF1-SHA-384, salt length 48, trailer 1.
fn require_pss_sha384_params(params: &[u8]) -> Result<(), CryptoError> {
    let mut cursor = DerCursor::new(params);
    let (hash_tag, hash_body) = cursor.read_tlv()?;
    if hash_tag != 0xA0 {
        return Err(CryptoError::MalformedCertificate);
    }
    require_sha384_algid(hash_body)?;
    let (mgf_tag, mgf_body) = cursor.read_tlv()?;
    if mgf_tag != 0xA1 {
        return Err(CryptoError::MalformedCertificate);
    }
    require_mgf1_sha384(mgf_body)?;
    let (salt_tag, salt_body) = cursor.read_tlv()?;
    if salt_tag != 0xA2 || !integer_eq(salt_body, &[0x30])? {
        return Err(CryptoError::MalformedCertificate);
    }
    // Trailer field defaults to 1 (0xbc). Milan VCEK omits it; ARK and ASK send it.
    if !cursor.is_empty() {
        let (trailer_tag, trailer_body) = cursor.read_tlv()?;
        if trailer_tag != 0xA3 || !integer_eq(trailer_body, &[0x01])? || !cursor.is_empty() {
            return Err(CryptoError::MalformedCertificate);
        }
    }
    Ok(())
}

fn require_sha384_algid(body: &[u8]) -> Result<(), CryptoError> {
    let mut cursor = DerCursor::new(body);
    let (tag, seq) = cursor.read_tlv()?;
    if tag != TAG_SEQUENCE || !cursor.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    let mut alg = DerCursor::new(seq);
    let (oid_tag, oid) = alg.read_tlv()?;
    let (null_tag, null_val) = alg.read_tlv()?;
    if oid_tag != TAG_OID || oid != OID_SHA384 || null_tag != TAG_NULL || !null_val.is_empty() || !alg.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    Ok(())
}

fn require_mgf1_sha384(body: &[u8]) -> Result<(), CryptoError> {
    let mut cursor = DerCursor::new(body);
    let (tag, seq) = cursor.read_tlv()?;
    if tag != TAG_SEQUENCE || !cursor.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    let mut alg = DerCursor::new(seq);
    let (oid_tag, oid) = alg.read_tlv()?;
    let (param_tag, param) = alg.read_tlv()?;
    if oid_tag != TAG_OID || oid != OID_MGF1 || param_tag != TAG_SEQUENCE || !alg.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    let mut hash = DerCursor::new(param);
    let (hash_oid_tag, hash_oid) = hash.read_tlv()?;
    let (null_tag, null_val) = hash.read_tlv()?;
    if hash_oid_tag != TAG_OID
        || hash_oid != OID_SHA384
        || null_tag != TAG_NULL
        || !null_val.is_empty()
        || !hash.is_empty()
    {
        return Err(CryptoError::MalformedCertificate);
    }
    Ok(())
}

fn integer_eq(body: &[u8], expected: &[u8]) -> Result<bool, CryptoError> {
    let mut cursor = DerCursor::new(body);
    let (tag, value) = cursor.read_tlv()?;
    if tag != TAG_INTEGER || !cursor.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    Ok(value == expected)
}

fn extract_spki(tbs_body: &[u8]) -> Result<SubjectPublicKey, CryptoError> {
    let mut d = DerCursor::new(tbs_body);

    // version [0] EXPLICIT is optional (absent in v1).
    let (first_tag, _) = d.read_tlv()?;
    if first_tag == TAG_CONTEXT_SPECIFIC_0 {
        let (serial_tag, _) = d.read_tlv()?;
        if serial_tag != TAG_INTEGER {
            return Err(CryptoError::MalformedCertificate);
        }
    } else if first_tag != TAG_INTEGER {
        return Err(CryptoError::MalformedCertificate);
    }

    expect_tag(&mut d, TAG_SEQUENCE)?; // signature algorithm
    expect_tag(&mut d, TAG_SEQUENCE)?; // issuer
    expect_tag(&mut d, TAG_SEQUENCE)?; // validity
    expect_tag(&mut d, TAG_SEQUENCE)?; // subject

    let (spki_tag, spki) = d.read_tlv()?;
    if spki_tag != TAG_SEQUENCE {
        return Err(CryptoError::MalformedCertificate);
    }
    parse_spki(spki)
}

fn expect_tag(d: &mut DerCursor<'_>, tag: u8) -> Result<(), CryptoError> {
    let (got, _) = d.read_tlv()?;
    if got != tag {
        return Err(CryptoError::MalformedCertificate);
    }
    Ok(())
}

/// Inner bytes of the TBS `subject` Name.
fn subject_name(tbs_body: &[u8]) -> Result<&[u8], CryptoError> {
    let mut cursor = DerCursor::new(tbs_body);
    let (first_tag, _) = cursor.read_tlv()?;
    if first_tag == TAG_CONTEXT_SPECIFIC_0 {
        let (serial_tag, _) = cursor.read_tlv()?;
        if serial_tag != TAG_INTEGER {
            return Err(CryptoError::MalformedCertificate);
        }
    } else if first_tag != TAG_INTEGER {
        return Err(CryptoError::MalformedCertificate);
    }
    expect_tag(&mut cursor, TAG_SEQUENCE)?; // signature algorithm
    expect_tag(&mut cursor, TAG_SEQUENCE)?; // issuer
    expect_tag(&mut cursor, TAG_SEQUENCE)?; // validity
    let (subject_tag, subject) = cursor.read_tlv()?;
    if subject_tag != TAG_SEQUENCE {
        return Err(CryptoError::MalformedCertificate);
    }
    Ok(subject)
}

/// AMD KDS marks a VLEK leaf with `CN=SEV-VLEK` inside the signed subject.
/// The marker is a directory string. Signature bytes and extensions are ignored.
/// @spec SCC-VERIFY-009
fn subject_contains_vlek(subject: &[u8]) -> Result<bool, CryptoError> {
    let mut name = DerCursor::new(subject);
    let mut saw_common_name = false;
    let mut is_vlek = false;
    while !name.is_empty() {
        let (rdn_tag, rdn) = name.read_tlv()?;
        if rdn_tag != TAG_SET {
            return Err(CryptoError::MalformedCertificate);
        }
        let mut set = DerCursor::new(rdn);
        if set.is_empty() {
            return Err(CryptoError::MalformedCertificate);
        }
        while !set.is_empty() {
            let (atv_tag, atv) = set.read_tlv()?;
            if atv_tag != TAG_SEQUENCE {
                return Err(CryptoError::MalformedCertificate);
            }
            let mut attr = DerCursor::new(atv);
            let (oid_tag, oid) = attr.read_tlv()?;
            if oid_tag != TAG_OID {
                return Err(CryptoError::MalformedCertificate);
            }
            let (value_tag, value) = attr.read_tlv()?;
            if !attr.is_empty() {
                return Err(CryptoError::MalformedCertificate);
            }
            if oid == [0x55, 0x04, 0x03] {
                if saw_common_name {
                    return Err(CryptoError::MalformedCertificate);
                }
                saw_common_name = true;
                is_vlek = directory_string_has_vlek(value_tag, value)?;
            }
        }
    }
    Ok(is_vlek)
}

fn directory_string_has_vlek(tag: u8, value: &[u8]) -> Result<bool, CryptoError> {
    match tag {
        TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_TELETEX_STRING | TAG_IA5_STRING => Ok(value == VLEK_MARKER),
        TAG_BMP_STRING => Ok(contains_be_coded_vlek(value, 2)),
        TAG_UNIVERSAL_STRING => Ok(contains_be_coded_vlek(value, 4)),
        _ => Err(CryptoError::MalformedCertificate),
    }
}

fn contains_be_coded_vlek(value: &[u8], width: usize) -> bool {
    let need = VLEK_MARKER.len().saturating_mul(width);
    if width == 0 || value.len() != need {
        return false;
    }
    value.windows(need).any(|window| {
        window.chunks_exact(width).zip(VLEK_MARKER.iter()).all(|(unit, byte)| match unit.split_last() {
            Some((last, high)) => high.iter().all(|&b| b == 0) && last == byte,
            None => false,
        })
    })
}

fn parse_spki(spki: &[u8]) -> Result<SubjectPublicKey, CryptoError> {
    let mut d = DerCursor::new(spki);
    let (alg_tag, alg) = d.read_tlv()?;
    let (tag, bitstr) = d.read_tlv()?;
    if alg_tag != TAG_SEQUENCE || tag != TAG_BIT_STRING || !d.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    if bitstr.is_empty() || bitstr[0] != 0 {
        return Err(CryptoError::MalformedCertificate);
    }
    let key_bytes = &bitstr[1..];
    // Uncompressed P-384 point: 0x04 || X || Y.
    if key_bytes.len() == 97 && key_bytes[0] == 0x04 {
        let mut algorithm = DerCursor::new(alg);
        let (oid_tag, oid) = algorithm.read_tlv()?;
        let (curve_tag, curve) = algorithm.read_tlv()?;
        if oid_tag != TAG_OID
            || oid != [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
            || curve_tag != TAG_OID
            || curve != [0x2B, 0x81, 0x04, 0x00, 0x22]
            || !algorithm.is_empty()
        {
            return Err(CryptoError::InvalidP384PublicKey);
        }
        p384::PublicKey::from_sec1_bytes(key_bytes).map_err(|_| CryptoError::InvalidP384PublicKey)?;
        let mut xy = [0u8; 96];
        xy.copy_from_slice(&key_bytes[1..]);
        return Ok(SubjectPublicKey::P384(xy));
    }
    if spki_oid(alg)? == OID_RSA_ENCRYPTION {
        return Ok(SubjectPublicKey::Rsa4096(Box::new(parse_rsa4096_public_key(key_bytes)?)));
    }
    Err(CryptoError::InvalidP384PublicKey)
}

fn spki_oid(alg: &[u8]) -> Result<&[u8], CryptoError> {
    let mut cursor = DerCursor::new(alg);
    let (oid_tag, oid) = cursor.read_tlv()?;
    if oid_tag != TAG_OID {
        return Err(CryptoError::MalformedCertificate);
    }
    if !cursor.is_empty() {
        let (tag, value) = cursor.read_tlv()?;
        if tag != TAG_NULL || !value.is_empty() || !cursor.is_empty() {
            return Err(CryptoError::MalformedCertificate);
        }
    }
    Ok(oid)
}

fn parse_rsa4096_public_key(key_bytes: &[u8]) -> Result<[u8; RSA4096_LEN], CryptoError> {
    let mut cursor = DerCursor::new(key_bytes);
    let (tag, body) = cursor.read_tlv()?;
    if tag != TAG_SEQUENCE || !cursor.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    let mut seq = DerCursor::new(body);
    let (n_tag, modulus) = seq.read_tlv()?;
    let (e_tag, exponent) = seq.read_tlv()?;
    if n_tag != TAG_INTEGER || e_tag != TAG_INTEGER || !seq.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    if exponent != [0x01, 0x00, 0x01] {
        return Err(CryptoError::MalformedCertificate);
    }
    let raw = if modulus.len() == RSA4096_LEN + 1 && modulus[0] == 0x00 {
        &modulus[1..]
    } else if modulus.len() == RSA4096_LEN {
        modulus
    } else {
        return Err(CryptoError::MalformedCertificate);
    };
    if raw.len() != RSA4096_LEN || raw[0] & 0x80 == 0 || raw[RSA4096_LEN - 1] & 1 == 0 {
        return Err(CryptoError::MalformedCertificate);
    }
    let mut out = [0u8; RSA4096_LEN];
    out.copy_from_slice(raw);
    Ok(out)
}

fn parse_rsa_pss_sig_bitstring(bitstr: &[u8]) -> Result<&[u8], CryptoError> {
    if bitstr.len() != RSA4096_LEN + 1 || bitstr[0] != 0 {
        return Err(CryptoError::MalformedCertificate);
    }
    Ok(&bitstr[1..])
}

fn parse_ecdsa_sig_bitstring(bitstr: &[u8]) -> Result<[u8; 96], CryptoError> {
    if bitstr.is_empty() || bitstr[0] != 0 {
        return Err(CryptoError::MalformedCertificate);
    }
    let mut d = DerCursor::new(&bitstr[1..]);
    let (tag, seq) = d.read_tlv()?;
    if tag != TAG_SEQUENCE {
        return Err(CryptoError::MalformedCertificate);
    }
    let mut s = DerCursor::new(seq);
    let (r_tag, r) = s.read_tlv()?;
    let (s_tag, s_int) = s.read_tlv()?;
    if r_tag != TAG_INTEGER || s_tag != TAG_INTEGER {
        return Err(CryptoError::MalformedCertificate);
    }
    if !s.is_empty() || !d.is_empty() {
        return Err(CryptoError::MalformedCertificate);
    }
    let mut out = [0u8; 96];
    out[..48].copy_from_slice(&i2osp_48(r)?);
    out[48..].copy_from_slice(&i2osp_48(s_int)?);
    Ok(out)
}

fn i2osp_48(int_bytes: &[u8]) -> Result<[u8; 48], CryptoError> {
    if int_bytes.is_empty() {
        return Err(CryptoError::InvalidP384Signature);
    }
    // DER minimal integer encoding:
    // 1. If leading byte is 0x00, there MUST be at least 2 bytes, and the high bit of byte[1] MUST be set (>= 0x80).
    //    Otherwise, a leading 0x00 is redundant and non-minimal.
    // 2. If leading byte is NOT 0x00, its high bit must NOT be set (otherwise it represents a negative integer).
    if int_bytes[0] == 0 {
        if int_bytes.len() < 2 || int_bytes[1] < 0x80 {
            return Err(CryptoError::InvalidP384Signature);
        }
    } else if int_bytes[0] >= 0x80 {
        return Err(CryptoError::InvalidP384Signature);
    }
    // Drop leading zero bytes, but keep at least one byte.
    let mut int_bytes = int_bytes;
    while let [0, rest @ ..] = int_bytes {
        if rest.is_empty() {
            break;
        }
        int_bytes = rest;
    }
    if int_bytes.is_empty() || int_bytes.len() > 48 {
        return Err(CryptoError::InvalidP384Signature);
    }
    let mut out = [0u8; 48];
    let start = out.len().checked_sub(int_bytes.len()).ok_or(CryptoError::InvalidP384Signature)?;
    out[start..].copy_from_slice(int_bytes);
    Ok(out)
}

pub(crate) struct DerCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerCursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_tag_len(&mut self) -> Result<(u8, usize), CryptoError> {
        let &[tag, first] = self.take(2)? else {
            return Err(CryptoError::MalformedCertificate);
        };
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            // Reject indefinite form (n == 0) and non-minimal long-form lengths.
            if n == 0 || n > 3 {
                return Err(CryptoError::MalformedCertificate);
            }
            let digits = self.take(n)?;
            // Reject leading zeros in long-form length encoding
            if digits.first() == Some(&0x00) {
                return Err(CryptoError::MalformedCertificate);
            }
            let mut parsed = 0usize;
            for &digit in digits {
                parsed = (parsed << 8) | (digit as usize);
            }
            if parsed < 0x80 {
                return Err(CryptoError::MalformedCertificate);
            }
            parsed
        };
        let end = self.pos.checked_add(len).ok_or(CryptoError::MalformedCertificate)?;
        if end > self.buf.len() {
            return Err(CryptoError::MalformedCertificate);
        }
        Ok((tag, len))
    }

    /// Consumes the next `len` bytes. Fails when fewer than `len` bytes remain.
    fn take(&mut self, len: usize) -> Result<&'a [u8], CryptoError> {
        let end = self.pos.checked_add(len).ok_or(CryptoError::MalformedCertificate)?;
        let value = self.buf.get(self.pos..end).ok_or(CryptoError::MalformedCertificate)?;
        self.pos = end;
        Ok(value)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), CryptoError> {
        let (tag, len) = self.read_tag_len()?;
        let value = self.take(len)?;
        Ok((tag, value))
    }

    fn read_tlv_full(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), CryptoError> {
        let start = self.pos;
        let (tag, len) = self.read_tag_len()?;
        let value = self.take(len)?;
        let full = self.buf.get(start..self.pos).ok_or(CryptoError::MalformedCertificate)?;
        Ok((tag, full, value))
    }
}

#[cfg(test)]
// Test-only fixture builders. SDLC 3.2.1 covers program code, not tests.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) mod tests {
    use super::*;
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::ecdsa::SigningKey;

    fn keypair(seed_lsb: u8) -> (SigningKey, [u8; 96]) {
        let mut seed = [0u8; 48];
        seed[47] = seed_lsb;
        let signing_key = SigningKey::from_slice(&seed).expect("valid scalar");
        let encoded = signing_key.verifying_key().to_sec1_point(false);
        let mut xy = [0u8; 96];
        xy[..48].copy_from_slice(encoded.x().unwrap().as_slice());
        xy[48..].copy_from_slice(encoded.y().unwrap().as_slice());
        (signing_key, xy)
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + value.len());
        out.push(tag);
        if value.len() < 0x80 {
            out.push(value.len() as u8);
        } else if value.len() < 0x100 {
            out.push(0x81);
            out.push(value.len() as u8);
        } else {
            out.push(0x82);
            out.push((value.len() >> 8) as u8);
            out.push(value.len() as u8);
        }
        out.extend_from_slice(value);
        out
    }

    fn encode_integer(bytes: &[u8]) -> Vec<u8> {
        let mut start = 0;
        while start + 1 < bytes.len() && bytes[start] == 0 {
            start += 1;
        }
        let trimmed = &bytes[start..];
        if trimmed[0] & 0x80 != 0 {
            let mut prefixed = Vec::with_capacity(trimmed.len() + 1);
            prefixed.push(0x00);
            prefixed.extend_from_slice(trimmed);
            tlv(TAG_INTEGER, &prefixed)
        } else {
            tlv(TAG_INTEGER, trimmed)
        }
    }

    pub(crate) fn encode_minimal_p384_cert(subject_xy: &[u8; 96], issuer: &SigningKey) -> Vec<u8> {
        encode_p384_cert_with_extensions(subject_xy, issuer, &[])
    }

    pub(crate) fn encode_p384_cert_with_extensions(
        subject_xy: &[u8; 96],
        issuer: &SigningKey,
        extensions: &[u8],
    ) -> Vec<u8> {
        encode_named_p384_cert(subject_xy, issuer, &[], &[], extensions)
    }

    fn encode_named_p384_cert(
        subject_xy: &[u8; 96],
        issuer: &SigningKey,
        issuer_rdns: &[u8],
        subject_rdns: &[u8],
        extensions: &[u8],
    ) -> Vec<u8> {
        let mut spki_alg = Vec::new();
        spki_alg.extend(tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])); // ecPublicKey
        spki_alg.extend(tlv(0x06, &[0x2B, 0x81, 0x04, 0x00, 0x22])); // secp384r1
        let spki_alg_seq = tlv(TAG_SEQUENCE, &spki_alg);

        let mut key_bit = Vec::with_capacity(98);
        key_bit.push(0x00);
        key_bit.push(0x04);
        key_bit.extend_from_slice(subject_xy);
        let key_bs = tlv(TAG_BIT_STRING, &key_bit);

        let mut spki_body = Vec::new();
        spki_body.extend(spki_alg_seq);
        spki_body.extend(key_bs);
        let spki = tlv(TAG_SEQUENCE, &spki_body);

        let serial = tlv(TAG_INTEGER, &[0x01]);
        let sigalg = tlv(TAG_SEQUENCE, &tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]));
        let issuer_name = tlv(TAG_SEQUENCE, issuer_rdns);
        let mut validity_body = Vec::new();
        validity_body.extend(tlv(0x17, b"250101000000Z"));
        validity_body.extend(tlv(0x17, b"350101000000Z"));
        let validity = tlv(TAG_SEQUENCE, &validity_body);
        let subject = tlv(TAG_SEQUENCE, subject_rdns);

        let mut tbs_body = Vec::new();
        tbs_body.extend(serial);
        tbs_body.extend(&sigalg);
        tbs_body.extend(issuer_name);
        tbs_body.extend(validity);
        tbs_body.extend(subject);
        tbs_body.extend(spki);
        if !extensions.is_empty() {
            let seq = tlv(TAG_SEQUENCE, extensions);
            tbs_body.extend(tlv(TAG_EXTENSIONS, &seq));
        }
        let tbs = tlv(TAG_SEQUENCE, &tbs_body);

        let hash = sha384(&tbs);
        let (signature, _) = issuer.sign_prehash(&hash).expect("sign TBS");
        let sig_bytes = signature.to_bytes();

        let mut sig_seq_body = Vec::new();
        sig_seq_body.extend(encode_integer(&sig_bytes[..48]));
        sig_seq_body.extend(encode_integer(&sig_bytes[48..]));
        let sig_seq = tlv(TAG_SEQUENCE, &sig_seq_body);
        let mut sig_bit = Vec::new();
        sig_bit.push(0x00);
        sig_bit.extend(sig_seq);
        let sig_bs = tlv(TAG_BIT_STRING, &sig_bit);

        let mut cert_body = Vec::new();
        cert_body.extend(tbs);
        cert_body.extend(sigalg);
        cert_body.extend(sig_bs);
        tlv(TAG_SEQUENCE, &cert_body)
    }

    #[test]
    fn synthetic_p384_chain_is_not_an_amd_trust_path() {
        let (ark_sk, ark_xy) = keypair(0x10);
        let (ask_sk, ask_xy) = keypair(0x11);
        let (_vcek_sk, vcek_xy) = keypair(0x12);

        let ask_cert = encode_minimal_p384_cert(&ask_xy, &ark_sk);
        let vcek_cert = encode_minimal_p384_cert(&vcek_xy, &ask_sk);

        assert_eq!(
            validate_vcek_signatures_only(&ark_xy, &ask_cert, &vcek_cert, &vcek_xy),
            Err(CryptoError::UntrustedRoot)
        );
        assert_eq!(
            validate_vcek_chain_at(&ark_xy, &ask_cert, &vcek_cert, &vcek_xy, 1_800_000_000),
            Err(CryptoError::UntrustedRoot)
        );
    }

    #[test]
    fn test_rejects_untrusted_ark() {
        let (ark_sk, _ark_xy) = keypair(0x10);
        let (_wrong_sk, wrong_ark_xy) = keypair(0x99);
        let (ask_sk, ask_xy) = keypair(0x11);
        let (_vcek_sk, vcek_xy) = keypair(0x12);

        let ask_cert = encode_minimal_p384_cert(&ask_xy, &ark_sk);
        let vcek_cert = encode_minimal_p384_cert(&vcek_xy, &ask_sk);

        assert_eq!(
            validate_vcek_signatures_only(&wrong_ark_xy, &ask_cert, &vcek_cert, &vcek_xy),
            Err(CryptoError::UntrustedRoot)
        );
    }

    #[test]
    fn test_rejects_leaf_pubkey_mismatch() {
        let (ark_sk, ark_xy) = keypair(0x10);
        let (ask_sk, ask_xy) = keypair(0x11);
        let (_vcek_sk, vcek_xy) = keypair(0x12);
        let (_other_sk, other_xy) = keypair(0x13);

        let ask_cert = encode_minimal_p384_cert(&ask_xy, &ark_sk);
        let vcek_cert = encode_minimal_p384_cert(&vcek_xy, &ask_sk);

        assert_eq!(
            validate_vcek_signatures_only(&ark_xy, &ask_cert, &vcek_cert, &other_xy),
            Err(CryptoError::UntrustedRoot)
        );
    }

    #[test]
    fn test_rejects_malformed_der() {
        let xy = [1u8; 96];
        assert_eq!(validate_vcek_signatures_only(&xy, &[], &[0x30, 0x00], &xy), Err(CryptoError::MalformedCertificate));
        assert_eq!(
            validate_vcek_signatures_only(&xy, &[0xff, 0x00], &[0x30, 0x00], &xy),
            Err(CryptoError::MalformedCertificate)
        );
    }

    #[test]
    fn test_rejects_vcek_not_signed_by_ask() {
        let (ark_sk, ark_xy) = keypair(0x10);
        let (_ask_sk, ask_xy) = keypair(0x11);
        let (stranger_sk, _stranger_xy) = keypair(0x77);
        let (_vcek_sk, vcek_xy) = keypair(0x12);

        let ask_cert = encode_minimal_p384_cert(&ask_xy, &ark_sk);
        let vcek_cert = encode_minimal_p384_cert(&vcek_xy, &stranger_sk);

        assert_eq!(
            validate_vcek_signatures_only(&ark_xy, &ask_cert, &vcek_cert, &vcek_xy),
            Err(CryptoError::UntrustedRoot)
        );
    }

    fn x509_extension(oid: &[u8], inner_der: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(tlv(TAG_OID, oid));
        body.extend(tlv(TAG_OCTET_STRING, inner_der));
        tlv(TAG_SEQUENCE, &body)
    }

    fn hwid_and_tcb_extensions(chip_id: &[u8; 64], tcb_version: u64) -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend(x509_extension(OID_HWID, &tlv(TAG_OCTET_STRING, chip_id)));
        extensions.extend(x509_extension(OID_TCB_VERSION, &encode_integer(&tcb_version.to_be_bytes())));
        extensions
    }

    /// OID 1.3.6.1.4.1.3704.1.4 is hwID and OID 1.3.6.1.4.1.3704.1.1 is the
    /// full TCB word when SPL components are absent.
    /// @spec SCC-VERIFY-003
    #[test]
    fn parses_hwid_and_direct_tcb_version_oids() {
        let (issuer, _xy) = keypair(0x21);
        let (_leaf, leaf_xy) = keypair(0x22);
        let chip_id = [0xA5u8; 64];
        let tcb_version = 0x0102_0304_0506_0708u64;
        let cert = encode_p384_cert_with_extensions(&leaf_xy, &issuer, &hwid_and_tcb_extensions(&chip_id, tcb_version));
        assert_eq!(parse_vcek_identity(&cert), Ok(VcekIdentity { chip_id, tcb_version, subject_is_vlek: false }));
    }

    /// AMD 57230 places structVersion at OID 1.1 and the TCB in SPL extensions.
    /// The SPL word is little-endian: bl, tee, reserved, snp, microcode.
    /// @spec SCC-VERIFY-003
    #[test]
    fn spl_components_form_tcb_when_struct_version_is_present() {
        let (issuer, _xy) = keypair(0x31);
        let (_leaf, leaf_xy) = keypair(0x32);
        let mut chip_id = [0u8; 64];
        chip_id[0] = 0x11;
        chip_id[63] = 0x22;

        let mut extensions = Vec::new();
        extensions.extend(x509_extension(OID_TCB_VERSION, &encode_integer(&[1])));
        extensions.extend(x509_extension(
            &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x03, 0x01],
            &encode_integer(&[4]),
        ));
        extensions.extend(x509_extension(
            &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x03, 0x02],
            &encode_integer(&[5]),
        ));
        extensions.extend(x509_extension(
            &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x03, 0x03],
            &encode_integer(&[7]),
        ));
        extensions.extend(x509_extension(
            &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x03, 0x08],
            &encode_integer(&[9]),
        ));
        extensions.extend(x509_extension(OID_HWID, &tlv(TAG_OCTET_STRING, &chip_id)));

        let cert = encode_p384_cert_with_extensions(&leaf_xy, &issuer, &extensions);
        let mut expected = [0u8; 8];
        expected[0] = 4;
        expected[1] = 5;
        expected[6] = 7;
        expected[7] = 9;
        assert_eq!(
            parse_vcek_identity(&cert),
            Ok(VcekIdentity { chip_id, tcb_version: u64::from_le_bytes(expected), subject_is_vlek: false })
        );
    }

    #[test]
    fn missing_vcek_extensions_fail_closed() {
        let (issuer, _xy) = keypair(0x41);
        let (_leaf, leaf_xy) = keypair(0x42);
        let cert = encode_minimal_p384_cert(&leaf_xy, &issuer);
        assert_eq!(parse_vcek_identity(&cert), Err(CryptoError::VcekExtensionMissing));

        let mut hwid_only = Vec::new();
        hwid_only.extend(x509_extension(OID_HWID, &tlv(TAG_OCTET_STRING, &[0u8; 64])));
        let cert = encode_p384_cert_with_extensions(&leaf_xy, &issuer, &hwid_only);
        assert_eq!(parse_vcek_identity(&cert), Err(CryptoError::VcekExtensionMissing));
    }

    #[test]
    fn raw_64_byte_hwid_extension_is_accepted() {
        let (issuer, _xy) = keypair(0x51);
        let (_leaf, leaf_xy) = keypair(0x52);
        let chip_id = [0x5Au8; 64];
        let mut extensions = Vec::new();
        extensions.extend(x509_extension(OID_HWID, &chip_id));
        extensions.extend(x509_extension(OID_TCB_VERSION, &encode_integer(&[42])));
        let cert = encode_p384_cert_with_extensions(&leaf_xy, &issuer, &extensions);
        assert_eq!(parse_vcek_identity(&cert).unwrap().chip_id, chip_id);
        assert_eq!(parse_vcek_identity(&cert).unwrap().tcb_version, 42);
        assert!(!parse_vcek_identity(&cert).unwrap().subject_is_vlek);
    }

    fn common_name_rdn(cn: &[u8]) -> Vec<u8> {
        let mut atv = Vec::new();
        atv.extend(tlv(TAG_OID, &[0x55, 0x04, 0x03]));
        atv.extend(tlv(TAG_UTF8_STRING, cn));
        tlv(TAG_SET, &tlv(TAG_SEQUENCE, &atv))
    }

    /// AMD KDS VLEK leaves use `CN=SEV-VLEK`. A VCEK subject, an issuer that
    /// contains the marker, and an extension that contains the marker do not.
    /// @spec SCC-VERIFY-009
    #[test]
    fn subject_vlek_marker_is_read_from_the_common_name() {
        let (issuer_key, _xy) = keypair(0x71);
        let (_leaf, leaf_xy) = keypair(0x72);
        let chip_id = [0xABu8; 64];
        let extensions = hwid_and_tcb_extensions(&chip_id, 7);

        let vlek = encode_named_p384_cert(&leaf_xy, &issuer_key, &[], &common_name_rdn(b"SEV-VLEK"), &extensions);
        let identity = parse_vcek_identity(&vlek).unwrap();
        assert!(identity.subject_is_vlek);
        assert_eq!(identity.chip_id, chip_id);

        let printable = {
            let mut atv = Vec::new();
            atv.extend(tlv(TAG_OID, &[0x55, 0x04, 0x03]));
            atv.extend(tlv(TAG_PRINTABLE_STRING, b"SEV-VLEK"));
            let rdn = tlv(TAG_SET, &tlv(TAG_SEQUENCE, &atv));
            encode_named_p384_cert(&leaf_xy, &issuer_key, &[], &rdn, &extensions)
        };
        assert!(parse_vcek_identity(&printable).unwrap().subject_is_vlek);

        let vcek = encode_named_p384_cert(
            &leaf_xy,
            &issuer_key,
            &common_name_rdn(b"SEV-VLEK"),
            &common_name_rdn(b"SEV-VCEK"),
            &extensions,
        );
        assert!(!parse_vcek_identity(&vcek).unwrap().subject_is_vlek);

        let mut marked_ext = extensions.clone();
        marked_ext.extend(x509_extension(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x05], b"VLEK"));
        let extension_only = encode_named_p384_cert(&leaf_xy, &issuer_key, &[], &[], &marked_ext);
        assert!(!parse_vcek_identity(&extension_only).unwrap().subject_is_vlek);
    }

    /// Synthetic parser fixture only: its ECDSA issuer is NOT an AMD trust root.
    #[test]
    fn issue_294_vlek_without_hwid_keeps_tcb_and_trust_checks() {
        let (issuer, issuer_xy) = keypair(0x71);
        let (_, xy) = keypair(0x72);
        let tcb = x509_extension(OID_TCB_VERSION, &encode_integer(&7u64.to_be_bytes()));
        let cert = encode_named_p384_cert(&xy, &issuer, &[], &common_name_rdn(b"SEV-VLEK"), &tcb);
        let identity = parse_vcek_identity(&cert).unwrap();
        assert_eq!(identity.chip_id, [0; 64]);
        assert_eq!(identity.tcb_version, 7);
        assert!(identity.subject_is_vlek);
        assert!(validate_vcek_signatures_only(&issuer_xy, &cert, &cert, &xy).is_err());
        for name in [b"SEV-VCEK".as_slice(), b"NOT-SEV-VLEK"] {
            let cert = encode_named_p384_cert(&xy, &issuer, &[], &common_name_rdn(name), &tcb);
            assert_eq!(parse_vcek_identity(&cert), Err(CryptoError::VcekExtensionMissing));
        }
        // A different directory attribute containing the marker is not CN.
        let mut ou = tlv(TAG_OID, &[0x55, 0x04, 0x0b]);
        ou.extend(tlv(TAG_UTF8_STRING, b"SEV-VLEK"));
        let subject = tlv(TAG_SET, &tlv(TAG_SEQUENCE, &ou));
        let cert = encode_named_p384_cert(&xy, &issuer, &[], &subject, &tcb);
        assert_eq!(parse_vcek_identity(&cert), Err(CryptoError::VcekExtensionMissing));
        let duplicate = [common_name_rdn(b"SEV-VLEK"), common_name_rdn(b"SEV-VLEK")].concat();
        let cert = encode_named_p384_cert(&xy, &issuer, &[], &duplicate, &tcb);
        assert_eq!(parse_vcek_identity(&cert), Err(CryptoError::MalformedCertificate));
        let missing_tcb = x509_extension(&[0x55, 0x1d, 0x13], &tlv(TAG_SEQUENCE, &[]));
        let cert = encode_named_p384_cert(&xy, &issuer, &[], &common_name_rdn(b"SEV-VLEK"), &missing_tcb);
        assert_eq!(parse_vcek_identity(&cert), Err(CryptoError::VcekExtensionMissing));
    }

    #[test]
    fn milan_vcek_subject_is_not_vlek() {
        let cert = include_bytes!("../../../fixtures/vcek_milan.der");
        let identity = parse_vcek_identity(cert).expect("Milan VCEK identity");
        assert!(!identity.subject_is_vlek);
    }

    #[test]
    fn non_minimal_der_length_leading_zero_is_rejected() {
        // Tag 0x30, length 2 bytes (0x82) with leading zero: [0x30, 0x82, 0x00, 0x05, ...]
        let invalid_der = [0x30, 0x82, 0x00, 0x02, 0x01, 0x01];
        let mut cursor = DerCursor::new(&invalid_der);
        assert_eq!(cursor.read_tlv(), Err(CryptoError::MalformedCertificate));
    }

    #[test]
    fn trailing_bytes_after_certificate_rejected() {
        let (issuer, _xy) = keypair(0x61);
        let (_leaf, leaf_xy) = keypair(0x62);
        let mut cert = encode_minimal_p384_cert(&leaf_xy, &issuer);
        cert.push(0xFF);
        assert_eq!(parse_certificate(&cert).err(), Some(CryptoError::MalformedCertificate));
    }

    #[test]
    fn ecdsa_sig_rejects_trailing_bytes_and_non_minimal_integers() {
        let r = tlv(TAG_INTEGER, &[0x01]);
        let s_int = tlv(TAG_INTEGER, &[0x02]);

        let mut seq_body = Vec::new();
        seq_body.extend_from_slice(&r);
        seq_body.extend_from_slice(&s_int);
        seq_body.push(0x00);
        let mut bitstr = vec![0x00];
        bitstr.extend(tlv(TAG_SEQUENCE, &seq_body));
        assert_eq!(parse_ecdsa_sig_bitstring(&bitstr), Err(CryptoError::MalformedCertificate));

        let mut seq_body = Vec::new();
        seq_body.extend_from_slice(&r);
        seq_body.extend_from_slice(&s_int);
        let mut bitstr = vec![0x00];
        bitstr.extend(tlv(TAG_SEQUENCE, &seq_body));
        bitstr.push(0xff);
        assert_eq!(parse_ecdsa_sig_bitstring(&bitstr), Err(CryptoError::MalformedCertificate));

        assert_eq!(i2osp_48(&[0x00, 0x10]), Err(CryptoError::InvalidP384Signature));
        assert_eq!(i2osp_48(&[0x00, 0x00, 0x80]), Err(CryptoError::InvalidP384Signature));
        assert_eq!(i2osp_48(&[0x80]), Err(CryptoError::InvalidP384Signature));

        let mut expected = [0u8; 48];
        expected[47] = 0x10;
        assert_eq!(i2osp_48(&[0x10]).unwrap(), expected);
        expected[47] = 0x80;
        assert_eq!(i2osp_48(&[0x00, 0x80]).unwrap(), expected);
    }
    #[test]
    fn spki_rejects_wrong_algorithm_curve_and_off_curve_points() {
        let (_, xy) = keypair(0x55);
        let ec = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        let curve = [0x2B, 0x81, 0x04, 0x00, 0x22];
        let make = |alg: &[u8], curve: &[u8], point: &[u8; 96]| {
            let mut a = tlv(TAG_OID, alg);
            a.extend(tlv(TAG_OID, curve));
            let mut spki = tlv(TAG_SEQUENCE, &a);
            let mut bits = vec![0, 4];
            bits.extend_from_slice(point);
            spki.extend(tlv(TAG_BIT_STRING, &bits));
            spki
        };
        assert!(parse_spki(&make(&ec, &curve, &xy)).is_ok());
        assert!(parse_spki(&make(OID_RSA_ENCRYPTION, &curve, &xy)).is_err());
        assert!(parse_spki(&make(&ec, &[0x2B, 0x81, 0x04, 0x00, 0x23], &xy)).is_err());
        assert!(parse_spki(&make(&ec, &curve, &[0; 96])).is_err());
        assert!(parse_spki(&make(&ec, &curve, &[0xff; 96])).is_err());
    }
}
