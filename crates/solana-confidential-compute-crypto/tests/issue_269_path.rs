#[path = "support/nitro_cert.rs"]
mod cert;
use cert::*;
use p384::ecdsa::SigningKey;
use solana_confidential_compute_crypto::{validate_nitro_cert_chain, CryptoError};
fn key(n: u8) -> (SigningKey, [u8; 96]) {
    let mut s = [0; 48];
    s[47] = n;
    let k = SigningKey::from_slice(&s).unwrap();
    let p = k.verifying_key().to_sec1_point(false);
    (k, p.as_bytes()[1..].try_into().unwrap())
}
#[test]
fn signed_ca_path_profile_negatives() {
    let (root, rxy) = key(1);
    let (inter, ixy) = key(2);
    let (_, lxy) = key(3);
    let rc = standard_cert(&rxy, &root, b"r", b"r", true);
    let ic = standard_cert(&ixy, &root, b"r", b"i", true);
    let lc = standard_cert(&lxy, &inter, b"i", b"l", false);
    let verify = |r: &[u8], i: &[u8], l: &[u8]| validate_nitro_cert_chain(&rxy, &[r, i], l, 1_800_000_000);
    assert_eq!(verify(&rc, &ic, &lc).unwrap(), lxy);
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("extensionless", encode_cert(&ixy, &root, &name(b"r"), &name(b"i"), &[])),
        ("not a CA", standard_cert(&ixy, &root, b"r", b"i", false)),
        ("no keyCertSign", encode_cert(&ixy, &root, &name(b"r"), &name(b"i"), &constraints(true, None, 128))),
        ("issuer mismatch", standard_cert(&ixy, &root, b"wrong", b"i", true)),
        ("empty subject", encode_cert(&ixy, &root, &name(b"r"), &[], &constraints(true, None, 4))),
    ];
    let bc = extension(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &tlv(1, &[255])));
    cases.push(("missing KU", encode_cert(&ixy, &root, &name(b"r"), &name(b"i"), &bc)));
    for (label, ext) in [
        ("unknown critical", extension(&[0x2a, 3, 4], true, &tlv(5, &[]))),
        ("noncritical name constraint", extension(&[0x55, 0x1d, 0x1e], false, &tlv(0x30, &[]))),
        ("policy constraint", extension(&[0x55, 0x1d, 0x24], true, &tlv(0x30, &[]))),
        ("duplicate extension", bc),
    ] {
        let mut e = constraints(true, None, 4);
        e.extend(ext);
        cases.push((label, encode_cert(&ixy, &root, &name(b"r"), &name(b"i"), &e)));
    }
    let mut accepted = vec![];
    for (label, i) in cases {
        if verify(&rc, &i, &lc).is_ok() {
            accepted.push(label);
        }
    }
    let r0 = encode_cert(&rxy, &root, &name(b"r"), &name(b"r"), &constraints(true, Some(0), 4));
    if verify(&r0, &ic, &lc).is_ok() {
        accepted.push("pathlen exhausted");
    }
    let badleaf = standard_cert(&lxy, &inter, b"i", b"l", true);
    if verify(&rc, &ic, &badleaf).is_ok() {
        accepted.push("CA leaf");
    }
    assert!(accepted.is_empty(), "signed malformed paths accepted: {accepted:?}");
    let badsig = {
        let mut b = ic.clone();
        let n = b.len();
        b[n - 1] ^= 1;
        b
    };
    assert_eq!(verify(&rc, &badsig, &lc), Err(CryptoError::CertificateChainInvalid));
    // Informational noncritical extensions do not change authorization.
    let mut e = constraints(true, None, 4);
    e.extend(extension(&[0x2a, 3, 4], false, &tlv(5, &[])));
    let informational = encode_cert(&ixy, &root, &name(b"r"), &name(b"i"), &e);
    assert!(verify(&rc, &informational, &lc).is_ok());
    // pathLen=0 permits a leaf, and self-issued rollover does not consume the parent's limit.
    let zero = encode_cert(&ixy, &root, &name(b"r"), &name(b"i"), &constraints(true, Some(0), 4));
    assert!(verify(&rc, &zero, &lc).is_ok());
    let rollover = standard_cert(&ixy, &root, b"r", b"r", true);
    let rollover_leaf = standard_cert(&lxy, &inter, b"r", b"l", false);
    assert!(verify(&r0, &rollover, &rollover_leaf).is_ok());
}
