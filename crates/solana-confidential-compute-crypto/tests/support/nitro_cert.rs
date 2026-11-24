use p384::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use sha2::{Digest, Sha384};
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
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
        tlv(0x02, &prefixed)
    } else {
        tlv(0x02, trimmed)
    }
}

// Shared by separate test crates that exercise different helper subsets.
#[allow(dead_code)]
pub fn encode_cert(
    subject_xy: &[u8; 96],
    issuer: &SigningKey,
    issuer_rdns: &[u8],
    subject_rdns: &[u8],
    extensions: &[u8],
) -> Vec<u8> {
    encode_cert_until(
        subject_xy,
        issuer,
        issuer_rdns,
        subject_rdns,
        extensions,
        b"350101000000Z",
    )
}

/// `encode_cert` with an explicit notAfter, for tests that need a credential
/// which expires before the session TTL would.
pub fn encode_cert_until(
    subject_xy: &[u8; 96],
    issuer: &SigningKey,
    issuer_rdns: &[u8],
    subject_rdns: &[u8],
    extensions: &[u8],
    not_after: &[u8],
) -> Vec<u8> {
    let mut spki_alg = Vec::new();
    spki_alg.extend(tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]));
    spki_alg.extend(tlv(0x06, &[0x2B, 0x81, 0x04, 0x00, 0x22]));
    let spki_alg_seq = tlv(0x30, &spki_alg);

    let mut key_bit = Vec::with_capacity(98);
    key_bit.push(0x00);
    key_bit.push(0x04);
    key_bit.extend_from_slice(subject_xy);
    let key_bs = tlv(0x03, &key_bit);

    let mut spki_body = Vec::new();
    spki_body.extend(spki_alg_seq);
    spki_body.extend(key_bs);
    let spki = tlv(0x30, &spki_body);

    let serial = tlv(0x02, &[0x01]);
    let sigalg = tlv(
        0x30,
        &tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]),
    );
    let issuer_name = tlv(0x30, issuer_rdns);
    let mut validity_body = Vec::new();
    validity_body.extend(tlv(0x17, b"250101000000Z"));
    validity_body.extend(tlv(0x17, not_after));
    let validity = tlv(0x30, &validity_body);
    let subject = tlv(0x30, subject_rdns);

    let mut tbs_body = Vec::new();
    tbs_body.extend(tlv(0xa0, &tlv(2, &[2])));
    tbs_body.extend(serial);
    tbs_body.extend(&sigalg);
    tbs_body.extend(issuer_name);
    tbs_body.extend(validity);
    tbs_body.extend(subject);
    tbs_body.extend(spki);
    if !extensions.is_empty() {
        tbs_body.extend(tlv(0xa3, &tlv(0x30, extensions)));
    }
    let tbs = tlv(0x30, &tbs_body);

    let mut hasher = Sha384::new();
    hasher.update(&tbs);
    let hash: [u8; 48] = hasher.finalize().into();
    let (signature, _) = issuer.sign_prehash(&hash).expect("sign TBS");
    let sig_bytes = signature.to_bytes();

    let mut sig_seq_body = Vec::new();
    sig_seq_body.extend(encode_integer(&sig_bytes[..48]));
    sig_seq_body.extend(encode_integer(&sig_bytes[48..]));
    let sig_seq = tlv(0x30, &sig_seq_body);
    let mut sig_bit = Vec::new();
    sig_bit.push(0x00);
    sig_bit.extend(sig_seq);
    let sig_bs = tlv(0x03, &sig_bit);

    let mut cert_body = Vec::new();
    cert_body.extend(tbs);
    cert_body.extend(sigalg);
    cert_body.extend(sig_bs);
    tlv(0x30, &cert_body)
}

pub fn name(label: &[u8]) -> Vec<u8> {
    tlv(
        0x31,
        &tlv(0x30, &[tlv(6, &[0x55, 4, 3]), tlv(0x0c, label)].concat()),
    )
}
pub fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut b = tlv(6, oid);
    if critical {
        b.extend(tlv(1, &[255]));
    }
    b.extend(tlv(4, value));
    tlv(0x30, &b)
}
pub fn constraints(ca: bool, path: Option<u8>, usage: u8) -> Vec<u8> {
    let mut bc = if ca { tlv(1, &[255]) } else { vec![] };
    if let Some(n) = path {
        bc.extend(tlv(2, &[n]));
    }
    let mut out = extension(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &bc));
    out.extend(extension(
        &[0x55, 0x1d, 0x0f],
        ca,
        &tlv(3, &[usage.trailing_zeros() as u8, usage]),
    ));
    out
}
pub fn standard_cert(
    xy: &[u8; 96],
    issuer: &SigningKey,
    issuer_label: &[u8],
    subject_label: &[u8],
    ca: bool,
) -> Vec<u8> {
    standard_cert_until(
        xy,
        issuer,
        issuer_label,
        subject_label,
        ca,
        b"350101000000Z",
    )
}

/// `standard_cert` with an explicit notAfter.
pub fn standard_cert_until(
    xy: &[u8; 96],
    issuer: &SigningKey,
    issuer_label: &[u8],
    subject_label: &[u8],
    ca: bool,
    not_after: &[u8],
) -> Vec<u8> {
    encode_cert_until(
        xy,
        issuer,
        &name(issuer_label),
        &name(subject_label),
        &constraints(ca, None, if ca { 4 } else { 128 }),
        not_after,
    )
}
