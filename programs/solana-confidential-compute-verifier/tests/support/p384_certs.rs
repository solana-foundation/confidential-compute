// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Synthetic P-384 certificate builders for `register_vcek` tests.
//!
//! Moved verbatim out of the `processor::tests` module alongside
//! `test_register_vcek_rejects_synthetic_zero_chip_chain`, which was the only
//! consumer of the DER encoders. `test_keypair` is duplicated rather than
//! moved: other tests still inside `processor.rs` use it.
#![allow(dead_code)]

pub fn test_keypair(seed_lsb: u8) -> (p384::ecdsa::SigningKey, [u8; 96]) {
    let mut seed = [0u8; 48];
    seed[47] = seed_lsb;
    let signing_key = p384::ecdsa::SigningKey::from_slice(&seed).expect("valid scalar");
    let encoded = signing_key.verifying_key().to_sec1_point(false);
    let mut xy = [0u8; 96];
    xy[..48].copy_from_slice(encoded.x().unwrap().as_slice());
    xy[48..].copy_from_slice(encoded.y().unwrap().as_slice());
    (signing_key, xy)
}

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

pub fn encode_integer(bytes: &[u8]) -> Vec<u8> {
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

pub fn encode_minimal_p384_cert(subject_xy: &[u8; 96], issuer: &p384::ecdsa::SigningKey) -> Vec<u8> {
    encode_p384_cert(subject_xy, issuer, &[])
}

/// Leaf cert whose `hwID` (1.3.6.1.4.1.3704.1.4) and `tcbVersion`
/// (1.3.6.1.4.1.3704.1.1) extensions match the registration arguments.
pub fn encode_vcek_with_identity(
    subject_xy: &[u8; 96],
    issuer: &p384::ecdsa::SigningKey,
    chip_id: &[u8; 64],
    tcb_version: u64,
) -> Vec<u8> {
    const OID_TCB_VERSION: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x01];
    const OID_HWID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x9C, 0x78, 0x01, 0x04];

    let mut hwid_inner = Vec::with_capacity(66);
    hwid_inner.extend(tlv(0x04, chip_id));
    let mut tcb_be = tcb_version.to_be_bytes().to_vec();
    while tcb_be.len() > 1 && tcb_be[0] == 0 {
        tcb_be.remove(0);
    }
    if tcb_be[0] & 0x80 != 0 {
        tcb_be.insert(0, 0x00);
    }
    let tcb_int = tlv(0x02, &tcb_be);

    let mut extensions = Vec::new();
    for (oid, inner) in [(OID_HWID, hwid_inner.as_slice()), (OID_TCB_VERSION, tcb_int.as_slice())] {
        let mut body = Vec::new();
        body.extend(tlv(0x06, oid));
        body.extend(tlv(0x04, inner));
        extensions.extend(tlv(0x30, &body));
    }
    encode_p384_cert(subject_xy, issuer, &extensions)
}

pub fn encode_p384_cert(subject_xy: &[u8; 96], issuer: &p384::ecdsa::SigningKey, extensions: &[u8]) -> Vec<u8> {
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha384};

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
    let sigalg = tlv(0x30, &tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]));
    let issuer_name = tlv(0x30, &[]);
    let mut validity_body = Vec::new();
    validity_body.extend(tlv(0x17, b"250101000000Z"));
    validity_body.extend(tlv(0x17, b"350101000000Z"));
    let validity = tlv(0x30, &validity_body);
    let subject = tlv(0x30, &[]);

    let mut tbs_body = Vec::new();
    tbs_body.extend(serial);
    tbs_body.extend(&sigalg);
    tbs_body.extend(issuer_name);
    tbs_body.extend(validity);
    tbs_body.extend(subject);
    tbs_body.extend(spki);
    if !extensions.is_empty() {
        let seq = tlv(0x30, extensions);
        tbs_body.extend(tlv(0xA3, &seq));
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
