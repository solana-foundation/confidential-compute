//! Bounded Nitro CA-path profile, not a general purpose PKIX implementation.
//! RFC 5280 §§4.2, 4.2.1.3, 4.2.1.9, 6.1: CA authorization, path length,
//! name chaining and unhandled critical extensions. AWS orders root first.
use crate::{error::CryptoError, vcek::DerCursor};

fn bad() -> CryptoError {
    CryptoError::CertificateChainInvalid
}
fn take<'a>(c: &mut DerCursor<'a>, expected: u8) -> Result<&'a [u8], CryptoError> {
    let (tag, body) = c.read_tlv().map_err(|_| bad())?;
    if tag != expected {
        return Err(bad());
    }
    Ok(body)
}
#[derive(Clone, Copy)]
struct Profile<'a> {
    issuer: &'a [u8],
    subject: &'a [u8],
    ca: bool,
    bc_critical: bool,
    usage: Option<u16>,
    path_len: Option<u32>,
}
fn name(body: &[u8]) -> Result<(), CryptoError> {
    if body.is_empty() {
        return Err(bad());
    }
    let mut n = DerCursor::new(body);
    while !n.is_empty() {
        let mut rdn = DerCursor::new(take(&mut n, 0x31)?);
        if rdn.is_empty() {
            return Err(bad());
        }
        while !rdn.is_empty() {
            let mut attr = DerCursor::new(take(&mut rdn, 0x30)?);
            if take(&mut attr, 6)?.is_empty() {
                return Err(bad());
            }
            let (_, value) = attr.read_tlv().map_err(|_| bad())?;
            if value.is_empty() || !attr.is_empty() {
                return Err(bad());
            }
        }
    }
    Ok(())
}
fn profile(der: &[u8]) -> Result<Profile<'_>, CryptoError> {
    let mut outer = DerCursor::new(der);
    let mut cert = DerCursor::new(take(&mut outer, 0x30)?);
    if !outer.is_empty() {
        return Err(bad());
    }
    let mut tbs = DerCursor::new(take(&mut cert, 0x30)?);
    // The supported AWS profile is X.509 v3, with explicit extensions.
    let mut version = DerCursor::new(take(&mut tbs, 0xa0)?);
    if take(&mut version, 2)? != [2] || !version.is_empty() {
        return Err(bad());
    }
    take(&mut tbs, 2)?; // serial
    take(&mut tbs, 0x30)?; // signature algorithm (validated by parse_nitro_cert)
    let issuer = take(&mut tbs, 0x30)?;
    take(&mut tbs, 0x30)?; // validity (validated by parse_nitro_cert)
    let subject = take(&mut tbs, 0x30)?;
    name(issuer)?;
    name(subject)?;
    take(&mut tbs, 0x30)?; // SPKI
                           // Unique IDs are outside the supported AWS profile.
    let mut explicit = DerCursor::new(take(&mut tbs, 0xa3)?);
    let mut extensions = DerCursor::new(take(&mut explicit, 0x30)?);
    if !explicit.is_empty() || !tbs.is_empty() {
        return Err(bad());
    }
    let mut p = Profile {
        issuer,
        subject,
        ca: false,
        bc_critical: false,
        usage: None,
        path_len: None,
    };
    let mut seen = [&[][..]; 32];
    let mut count = 0;
    while !extensions.is_empty() {
        let mut ext = DerCursor::new(take(&mut extensions, 0x30)?);
        let oid = take(&mut ext, 6)?;
        if oid.is_empty() || count == seen.len() || seen[..count].contains(&oid) {
            return Err(bad());
        }
        seen[count] = oid;
        count += 1;
        let (tag, body) = ext.read_tlv().map_err(|_| bad())?;
        let (critical, value) = if tag == 1 {
            // DER DEFAULT FALSE must be omitted; TRUE is encoded ff.
            if body != [0xff] {
                return Err(bad());
            }
            (true, take(&mut ext, 4)?)
        } else if tag == 4 {
            (false, body)
        } else {
            return Err(bad());
        };
        if !ext.is_empty() {
            return Err(bad());
        }
        match oid {
            [0x55, 0x1d, 0x13] => {
                let mut value = DerCursor::new(value);
                let mut bc = DerCursor::new(take(&mut value, 0x30)?);
                if !value.is_empty() {
                    return Err(bad());
                }
                p.bc_critical = critical;
                if !bc.is_empty() {
                    if take(&mut bc, 1)? != [0xff] {
                        return Err(bad());
                    }
                    p.ca = true;
                    if !bc.is_empty() {
                        let n = take(&mut bc, 2)?;
                        if n.is_empty()
                            || n.len() > 5
                            || n[0] & 0x80 != 0
                            || (n.len() > 1 && n[0] == 0 && n[1] & 0x80 == 0)
                        {
                            return Err(bad());
                        }
                        let mut length = 0u32;
                        for b in n {
                            length = length
                                .checked_mul(256)
                                .and_then(|x| x.checked_add(u32::from(*b)))
                                .ok_or_else(bad)?;
                        }
                        p.path_len = Some(length);
                    }
                    if !bc.is_empty() {
                        return Err(bad());
                    }
                }
            }
            [0x55, 0x1d, 0x0f] => {
                let mut value = DerCursor::new(value);
                let bits = take(&mut value, 3)?;
                if !value.is_empty()
                    || !(2..=3).contains(&bits.len())
                    || bits[0] > 7
                    || bits[bits.len() - 1] == 0
                    || bits[bits.len() - 1].trailing_zeros() != u32::from(bits[0])
                    || (bits.len() == 3 && (bits[0] != 7 || bits[2] != 0x80))
                {
                    return Err(bad());
                }
                p.usage = Some(
                    u16::from(bits[1])
                        | if bits.len() == 3 {
                            u16::from(bits[2]) << 8
                        } else {
                            0
                        },
                );
            }
            // These constraints need processing even if noncritical. They are
            // absent from the authentic supported AWS fixture; reject rather than ignore.
            [0x55, 0x1d, 0x1e | 0x24 | 0x36 | 0x25] => return Err(bad()),
            _ if critical => return Err(bad()),
            _ => {} // Noncritical informational extensions (SKI/AKI/CRLDP, etc.).
        }
    }
    Ok(p)
}

/// Enforces the supported Nitro certificate profile before signature dispatch.
/// Names must have identical DER encodings at each hop. Equivalent differently
/// encoded names are outside this bounded profile. No CRL/network lookup occurs.
/// Root key pinning, signatures and trusted-time validity are separate mandatory checks.
pub fn validate_nitro_path_constraints(cabundle: &[&[u8]], leaf: &[u8]) -> Result<(), CryptoError> {
    if cabundle.is_empty() || cabundle.len() > solana_confidential_compute_core::MAX_NITRO_CABUNDLE
    {
        return Err(bad());
    }
    let mut parent: Option<Profile<'_>> = None;
    let mut remaining: Option<u32> = None;
    for der in cabundle {
        let p = profile(der)?;
        if !p.ca || !p.bc_critical || p.usage.map(|u| u & 4 == 0).unwrap_or(true) {
            return Err(bad());
        }
        if let Some(issuer) = parent {
            if p.issuer != issuer.subject {
                return Err(bad());
            }
            // RFC 5280: self-issued CAs do not consume pathLenConstraint.
            if p.issuer != p.subject {
                if let Some(n) = remaining {
                    remaining = Some(n.checked_sub(1).ok_or_else(bad)?);
                }
            }
        } else if p.issuer != p.subject {
            return Err(bad());
        }
        if let Some(n) = p.path_len {
            remaining = Some(remaining.map_or(n, |r| r.min(n)));
        }
        parent = Some(p);
    }
    let leaf = profile(leaf)?;
    if leaf.issuer != parent.ok_or_else(bad)?.subject
        || leaf.ca
        || leaf
            .usage
            .map(|u| u & 0x80 == 0 || u & 4 != 0)
            .unwrap_or(false)
    {
        return Err(bad());
    }
    Ok(())
}
