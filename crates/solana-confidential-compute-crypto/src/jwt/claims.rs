//! Streaming JSON claim extractor. Stack frame stays under 256 bytes.
//!
//! @spec SCC-JWT-001 SCC-JWT-002

use crate::error::CryptoError;
use crate::jwt::b64::B64Decoder;

/// Maximum `iss` claim length in bytes.
pub const MAX_ISS: usize = 96;
/// Maximum `sub` claim length in bytes.
pub const MAX_SUB: usize = 160;
/// Maximum `aud` claim length in bytes.
pub const MAX_AUD: usize = 128;
/// Maximum `dbgstat` claim length in bytes.
pub const MAX_DBGSTAT: usize = 32;
/// Minimum `eat_nonce` string length in bytes.
/// @spec SCC-JWT-005
pub const MIN_EAT_NONCE: usize = 10;
/// Maximum `eat_nonce` string length in bytes.
/// One unpadded base64url nonce is 43 bytes; Google allows up to 74.
/// @spec SCC-JWT-005
pub const MAX_EAT_NONCE: usize = 74;
/// Mode A carries exactly two `eat_nonce` strings.
/// @spec SCC-JWT-005
pub const MAX_EAT_NONCE_VALUES: usize = 2;
/// Unpadded base64url length of a 32-byte Mode A nonce.
/// @spec SCC-JWT-005
pub const MODE_A_NONCE_B64_LEN: usize = 43;
/// Maximum `alg` header length in bytes.
pub const MAX_ALG: usize = 16;
/// Maximum JWT header `kid` length in bytes.
pub const MAX_KID: usize = 64;
/// `iat` clock-skew allowance in seconds.
/// @spec SCC-JWT-002
pub const MAX_CLOCK_SKEW_SECS: u64 = 120;
/// Required Confidential Space debug state.
/// @spec SCC-JWT-002
pub const REQUIRED_DBGSTAT: &[u8] = b"disabled-since-boot";
/// Required Google Confidential Space issuer.
/// @spec SCC-JWT-002
pub const REQUIRED_ISS: &[u8] = b"https://confidentialcomputing.googleapis.com";

const SEEN_ISS: u16 = 1 << 0;
const SEEN_SUB: u16 = 1 << 1;
const SEEN_AUD: u16 = 1 << 2;
const SEEN_EXP: u16 = 1 << 3;
const SEEN_IAT: u16 = 1 << 4;
const SEEN_SECBOOT: u16 = 1 << 5;
const SEEN_DBGSTAT: u16 = 1 << 6;
const SEEN_IMAGE_DIGEST: u16 = 1 << 7;
const SEEN_EAT_NONCE: u16 = 1 << 8;
const SEEN_ALG: u16 = 1 << 9;
const SEEN_KID: u16 = 1 << 10;

// Structural path labels never capture a claim value.
const PATH_SUBMODS: u16 = 1 << 11;
const PATH_CONTAINER: u16 = 1 << 12;

const REQUIRED_GOOGLE: u16 = SEEN_ISS
    | SEEN_SUB
    | SEEN_AUD
    | SEEN_EXP
    | SEEN_IAT
    | SEEN_SECBOOT
    | SEEN_DBGSTAT
    | SEEN_IMAGE_DIGEST
    | SEEN_EAT_NONCE;

const CTX_OBJ_KEY: u8 = 0;
const CTX_OBJ_NEED_KEY: u8 = 1;
const CTX_OBJ_COMMA: u8 = 2;
const CTX_ARR_VAL: u8 = 3;
const CTX_ARR_NEED_VAL: u8 = 4;
const CTX_ARR_COMMA: u8 = 5;
const MAX_DEPTH: u8 = 8;

/// Parsed Google Cloud Confidential Space claims.
/// String fields are owned copies so the parser can stream-decode Base64URL.
/// @spec SCC-JWT-001 SCC-JWT-002
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoogleClaims<'a> {
    _source: &'a [u8],
    iss: [u8; MAX_ISS],
    iss_len: u8,
    sub: [u8; MAX_SUB],
    sub_len: u8,
    aud: [u8; MAX_AUD],
    aud_len: u8,
    dbgstat: [u8; MAX_DBGSTAT],
    dbgstat_len: u8,
    eat_nonces: [[u8; MAX_EAT_NONCE]; MAX_EAT_NONCE_VALUES],
    eat_nonce_lens: [u8; MAX_EAT_NONCE_VALUES],
    eat_nonce_count: u8,
    alg: [u8; MAX_ALG],
    alg_len: u8,
    kid: [u8; MAX_KID],
    kid_len: u8,
    /// Unix expiry seconds.
    pub exp: u64,
    /// Unix issued-at seconds.
    pub iat: u64,
    /// UEFI Secure Boot claim.
    pub secboot: bool,
    /// Container image digest parsed from `sha256:<hex>`.
    pub image_digest: [u8; 32],
    seen: u16,
}

impl<'a> GoogleClaims<'a> {
    fn empty(source: &'a [u8]) -> Self {
        Self {
            _source: source,
            iss: [0; MAX_ISS],
            iss_len: 0,
            sub: [0; MAX_SUB],
            sub_len: 0,
            aud: [0; MAX_AUD],
            aud_len: 0,
            dbgstat: [0; MAX_DBGSTAT],
            dbgstat_len: 0,
            eat_nonces: [[0; MAX_EAT_NONCE]; MAX_EAT_NONCE_VALUES],
            eat_nonce_lens: [0; MAX_EAT_NONCE_VALUES],
            eat_nonce_count: 0,
            alg: [0; MAX_ALG],
            alg_len: 0,
            kid: [0; MAX_KID],
            kid_len: 0,
            exp: 0,
            iat: 0,
            secboot: false,
            image_digest: [0; 32],
            seen: 0,
        }
    }

    pub fn iss(&self) -> &[u8] {
        &self.iss[..self.iss_len as usize]
    }
    pub fn sub(&self) -> &[u8] {
        &self.sub[..self.sub_len as usize]
    }
    pub fn aud(&self) -> &[u8] {
        &self.aud[..self.aud_len as usize]
    }
    pub fn dbgstat(&self) -> &[u8] {
        &self.dbgstat[..self.dbgstat_len as usize]
    }
    pub fn eat_nonce_count(&self) -> usize {
        usize::from(self.eat_nonce_count)
    }

    pub fn eat_nonce_at(&self, index: usize) -> Option<&[u8]> {
        if index >= usize::from(self.eat_nonce_count) {
            return None;
        }
        let len = usize::from(self.eat_nonce_lens[index]);
        Some(&self.eat_nonces[index][..len])
    }

    /// First `eat_nonce` string. Mode A callers use [`Self::decode_mode_a_binding`].
    pub fn eat_nonce(&self) -> &[u8] {
        self.eat_nonce_at(0).unwrap_or(&[])
    }

    /// Decode Mode A nonce 0 and nonce 1 into raw `pubkey || slot_hash`.
    ///
    /// Each nonce must be the unpadded base64url encoding of 32 bytes.
    /// @spec SCC-JWT-005
    pub fn decode_mode_a_binding(&self) -> Result<[u8; 64], CryptoError> {
        if self.eat_nonce_count != 2 {
            return Err(CryptoError::MalformedJwt);
        }
        let mut raw = [0u8; 64];
        decode_mode_a_nonce(
            self.eat_nonce_at(0).ok_or(CryptoError::MalformedJwt)?,
            &mut raw[..32],
        )?;
        decode_mode_a_nonce(
            self.eat_nonce_at(1).ok_or(CryptoError::MalformedJwt)?,
            &mut raw[32..],
        )?;
        Ok(raw)
    }

    /// Decode the single Mode B `eat_nonce` into the raw 32-byte commitment.
    ///
    /// The string is unpadded base64url (43 characters). The tombstone seed is
    /// SHA-256 of these raw bytes.
    /// @spec SCC-JWT-005
    pub fn decode_mode_b_commitment(&self) -> Result<[u8; 32], CryptoError> {
        if self.eat_nonce_count != 1 {
            return Err(CryptoError::MalformedJwt);
        }
        let mut raw = [0u8; 32];
        decode_mode_a_nonce(
            self.eat_nonce_at(0).ok_or(CryptoError::MalformedJwt)?,
            &mut raw,
        )?;
        Ok(raw)
    }

    pub fn alg(&self) -> &[u8] {
        &self.alg[..self.alg_len as usize]
    }
    pub fn kid(&self) -> &[u8] {
        &self.kid[..self.kid_len as usize]
    }

    pub(crate) fn set_kid(&mut self, kid: [u8; MAX_KID], kid_len: u8) {
        self.kid = kid;
        self.kid_len = kid_len;
    }

    fn mark(&mut self, bit: u16) -> Result<(), CryptoError> {
        if self.seen & bit != 0 {
            return Err(CryptoError::DuplicateJwtClaim);
        }
        self.seen |= bit;
        Ok(())
    }

    fn require_google(&self) -> Result<(), CryptoError> {
        if self.seen & REQUIRED_GOOGLE != REQUIRED_GOOGLE {
            return Err(CryptoError::MalformedJwt);
        }
        if self.eat_nonce_count == 0 {
            return Err(CryptoError::MalformedJwt);
        }
        Ok(())
    }
}

/// Parse Google claims from decoded payload JSON.
/// @spec SCC-JWT-001
pub fn parse_google_claims(payload_json: &[u8]) -> Result<GoogleClaims<'_>, CryptoError> {
    let mut claims = GoogleClaims::empty(payload_json);
    parse_json(SliceSrc::new(payload_json), &mut claims)?;
    claims.require_google()?;
    Ok(claims)
}

/// Parse Google claims by stream-decoding a Base64URL payload.
/// @spec SCC-JWT-001
pub fn parse_google_claims_b64(payload_b64: &[u8]) -> Result<GoogleClaims<'_>, CryptoError> {
    let mut claims = GoogleClaims::empty(payload_b64);
    parse_json(B64Src(B64Decoder::new(payload_b64)), &mut claims)?;
    claims.require_google()?;
    Ok(claims)
}

/// Parse `alg` from a Base64URL JWT header.
pub fn parse_header_alg_b64(header_b64: &[u8]) -> Result<[u8; MAX_ALG], CryptoError> {
    let mut claims = GoogleClaims::empty(header_b64);
    parse_json(B64Src(B64Decoder::new(header_b64)), &mut claims)?;
    if claims.seen & SEEN_ALG == 0 || claims.alg_len == 0 {
        return Err(CryptoError::MalformedJwt);
    }
    Ok(claims.alg)
}

/// Parse `kid` from a Base64URL JWT header (zero-padded to `MAX_KID`).
pub fn parse_header_kid_b64(header_b64: &[u8]) -> Result<[u8; MAX_KID], CryptoError> {
    Ok(parse_header_kid_with_len(header_b64)?.0)
}

pub(crate) fn parse_header_kid_with_len(
    header_b64: &[u8],
) -> Result<([u8; MAX_KID], u8), CryptoError> {
    let mut claims = GoogleClaims::empty(header_b64);
    parse_json(B64Src(B64Decoder::new(header_b64)), &mut claims)?;
    if claims.seen & SEEN_KID == 0 || claims.kid_len == 0 {
        return Err(CryptoError::MalformedJwt);
    }
    Ok((claims.kid, claims.kid_len))
}

/// Enforce Confidential Space policy and optional wall-clock freshness.
/// @spec SCC-JWT-002
pub fn enforce_google_policy(
    claims: &GoogleClaims<'_>,
    now_unix: Option<u64>,
) -> Result<(), CryptoError> {
    if claims.iss() != REQUIRED_ISS {
        return Err(CryptoError::PolicyViolation);
    }
    if !claims.secboot {
        return Err(CryptoError::PolicyViolation);
    }
    if claims.dbgstat() != REQUIRED_DBGSTAT {
        return Err(CryptoError::PolicyViolation);
    }
    if claims.exp <= claims.iat {
        return Err(CryptoError::PolicyViolation);
    }
    if let Some(now) = now_unix {
        if now >= claims.exp {
            return Err(CryptoError::PolicyViolation);
        }
        if claims.iat > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(CryptoError::PolicyViolation);
        }
    }
    Ok(())
}

/// Enforce the deployment's explicit GCP relying-party and subject binding.
/// Empty configuration fails closed. Issuer/security/freshness policy remains
/// the responsibility of `enforce_google_policy` / the signature verifier.
pub fn enforce_google_tenant(
    claims: &GoogleClaims<'_>,
    expected_aud: &[u8],
    expected_sub: &[u8],
) -> Result<(), CryptoError> {
    if expected_aud.is_empty()
        || expected_sub.is_empty()
        || claims.aud() != expected_aud
        || claims.sub() != expected_sub
    {
        return Err(CryptoError::PolicyViolation);
    }
    Ok(())
}

trait Pull {
    fn pull(&mut self) -> Result<Option<u8>, CryptoError>;
}

struct SliceSrc<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceSrc<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl Pull for SliceSrc<'_> {
    fn pull(&mut self) -> Result<Option<u8>, CryptoError> {
        if self.pos >= self.data.len() {
            Ok(None)
        } else {
            let b = self.data[self.pos];
            self.pos += 1;
            Ok(Some(b))
        }
    }
}

struct B64Src<'a>(B64Decoder<'a>);

impl Pull for B64Src<'_> {
    fn pull(&mut self) -> Result<Option<u8>, CryptoError> {
        self.0.next_byte()
    }
}

struct Reader<R> {
    inner: R,
    peek: Option<u8>,
}

impl<R: Pull> Reader<R> {
    fn new(inner: R) -> Self {
        Self { inner, peek: None }
    }

    fn read(&mut self) -> Result<Option<u8>, CryptoError> {
        if let Some(b) = self.peek.take() {
            Ok(Some(b))
        } else {
            self.inner.pull()
        }
    }

    fn peek(&mut self) -> Result<Option<u8>, CryptoError> {
        if self.peek.is_none() {
            self.peek = self.inner.pull()?;
        }
        Ok(self.peek)
    }

    fn read_req(&mut self) -> Result<u8, CryptoError> {
        self.read()?.ok_or(CryptoError::MalformedJwt)
    }
}

fn parse_json<R: Pull>(src: R, out: &mut GoogleClaims<'_>) -> Result<(), CryptoError> {
    let mut r = Reader::new(src);
    skip_ws(&mut r)?;
    if r.read_req()? != b'{' {
        return Err(CryptoError::MalformedJwt);
    }

    let mut stack = [0u8; MAX_DEPTH as usize];
    let mut path = [0u16; MAX_DEPTH as usize];
    let mut sp: u8 = 1;
    stack[0] = CTX_OBJ_KEY;

    loop {
        skip_ws(&mut r)?;
        if sp == 0 {
            if r.peek()?.is_some() {
                return Err(CryptoError::MalformedJwt);
            }
            return Ok(());
        }
        let ctx = stack[(sp - 1) as usize];
        match ctx {
            CTX_OBJ_KEY | CTX_OBJ_NEED_KEY => match r.peek()?.ok_or(CryptoError::MalformedJwt)? {
                b'}' if ctx == CTX_OBJ_KEY => {
                    let _ = r.read()?;
                    sp -= 1;
                }
                b'"' => {
                    let _ = r.read()?;
                    let raw_key = parse_key(&mut r)?;
                    let supported_path = sp == 1
                        || (sp == 2 && path[1] == PATH_SUBMODS && raw_key == PATH_CONTAINER)
                        || (sp == 3
                            && path[1] == PATH_SUBMODS
                            && path[2] == PATH_CONTAINER
                            && raw_key == SEEN_IMAGE_DIGEST);
                    let key_id = if supported_path { raw_key } else { 0 };
                    skip_ws(&mut r)?;
                    if r.read_req()? != b':' {
                        return Err(CryptoError::MalformedJwt);
                    }
                    skip_ws(&mut r)?;
                    let previous_sp = sp;
                    // Duplicate structural objects must not merge separate claim sets.
                    if key_id == PATH_SUBMODS || key_id == PATH_CONTAINER {
                        out.mark(key_id)?;
                        if r.peek()? != Some(b'{') {
                            return Err(CryptoError::MalformedJwt);
                        }
                    }
                    parse_value(&mut r, out, key_id, &mut stack, &mut sp)?;
                    if sp > previous_sp {
                        path[previous_sp as usize] = key_id;
                    }
                }
                _ => return Err(CryptoError::MalformedJwt),
            },
            CTX_OBJ_COMMA => match r.read_req()? {
                b',' => stack[(sp - 1) as usize] = CTX_OBJ_NEED_KEY,
                b'}' => sp -= 1,
                _ => return Err(CryptoError::MalformedJwt),
            },
            CTX_ARR_VAL | CTX_ARR_NEED_VAL => match r.peek()?.ok_or(CryptoError::MalformedJwt)? {
                b']' if ctx == CTX_ARR_VAL => {
                    let _ = r.read()?;
                    sp -= 1;
                }
                _ => {
                    let previous_sp = sp;
                    parse_value(&mut r, out, 0, &mut stack, &mut sp)?;
                    if sp > previous_sp {
                        path[previous_sp as usize] = 0;
                    }
                }
            },
            CTX_ARR_COMMA => match r.read_req()? {
                b',' => stack[(sp - 1) as usize] = CTX_ARR_NEED_VAL,
                b']' => sp -= 1,
                _ => return Err(CryptoError::MalformedJwt),
            },
            _ => return Err(CryptoError::MalformedJwt),
        }
    }
}

fn parse_value<R: Pull>(
    r: &mut Reader<R>,
    out: &mut GoogleClaims<'_>,
    key_id: u16,
    stack: &mut [u8; MAX_DEPTH as usize],
    sp: &mut u8,
) -> Result<(), CryptoError> {
    let b = r.peek()?.ok_or(CryptoError::MalformedJwt)?;
    match b {
        b'{' => {
            let _ = r.read()?;
            finish_parent_value(stack, *sp);
            if *sp >= MAX_DEPTH {
                return Err(CryptoError::MalformedJwt);
            }
            stack[*sp as usize] = CTX_OBJ_KEY;
            *sp += 1;
        }
        b'[' if key_id == SEEN_EAT_NONCE || key_id == SEEN_IMAGE_DIGEST => {
            let _ = r.read()?;
            if key_id == SEEN_EAT_NONCE {
                parse_eat_nonce_array(r, out)?;
            } else {
                parse_image_digest_array(r, out)?;
            }
            finish_parent_value(stack, *sp);
        }
        b'[' => {
            let _ = r.read()?;
            finish_parent_value(stack, *sp);
            if *sp >= MAX_DEPTH {
                return Err(CryptoError::MalformedJwt);
            }
            stack[*sp as usize] = CTX_ARR_VAL;
            *sp += 1;
        }
        b'"' => {
            let _ = r.read()?;
            capture_string(r, out, key_id)?;
            finish_parent_value(stack, *sp);
        }
        b't' | b'f' => {
            let val = parse_bool(r)?;
            if key_id == SEEN_SECBOOT {
                out.mark(SEEN_SECBOOT)?;
                out.secboot = val;
            }
            finish_parent_value(stack, *sp);
        }
        b'n' => {
            let _ = r.read()?;
            expect_bytes(r, b"ull")?;
            finish_parent_value(stack, *sp);
        }
        b'0'..=b'9' => {
            let n = parse_u64(r)?;
            if key_id == SEEN_EXP {
                out.mark(SEEN_EXP)?;
                out.exp = n;
            } else if key_id == SEEN_IAT {
                out.mark(SEEN_IAT)?;
                out.iat = n;
            }
            finish_parent_value(stack, *sp);
        }
        b'-' => return Err(CryptoError::MalformedJwt),
        _ => return Err(CryptoError::MalformedJwt),
    }
    Ok(())
}

fn finish_parent_value(stack: &mut [u8; MAX_DEPTH as usize], sp: u8) {
    if sp == 0 {
        return;
    }
    match stack[(sp - 1) as usize] {
        CTX_OBJ_KEY | CTX_OBJ_NEED_KEY => stack[(sp - 1) as usize] = CTX_OBJ_COMMA,
        CTX_ARR_VAL | CTX_ARR_NEED_VAL => stack[(sp - 1) as usize] = CTX_ARR_COMMA,
        _ => {}
    }
}

fn skip_ws<R: Pull>(r: &mut Reader<R>) -> Result<(), CryptoError> {
    loop {
        match r.peek()? {
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') => {
                let _ = r.read()?;
            }
            _ => return Ok(()),
        }
    }
}

fn parse_key<R: Pull>(r: &mut Reader<R>) -> Result<u16, CryptoError> {
    let mut key = [0u8; 16];
    let mut len = 0usize;
    loop {
        let b = r.read_req()?;
        if b == b'"' {
            break;
        }
        if b == b'\\' || b < 0x20 {
            return Err(CryptoError::MalformedJwt);
        }
        if len < key.len() {
            key[len] = b;
            len += 1;
        } else {
            len += 1;
        }
    }
    if len > key.len() {
        return Ok(0);
    }
    Ok(match &key[..len] {
        b"submods" => PATH_SUBMODS,
        b"container" => PATH_CONTAINER,
        b"iss" => SEEN_ISS,
        b"sub" => SEEN_SUB,
        b"aud" => SEEN_AUD,
        b"exp" => SEEN_EXP,
        b"iat" => SEEN_IAT,
        b"secboot" => SEEN_SECBOOT,
        b"dbgstat" => SEEN_DBGSTAT,
        b"image_digest" => SEEN_IMAGE_DIGEST,
        b"eat_nonce" => SEEN_EAT_NONCE,
        b"alg" => SEEN_ALG,
        b"kid" => SEEN_KID,
        _ => 0,
    })
}

fn capture_string<R: Pull>(
    r: &mut Reader<R>,
    out: &mut GoogleClaims<'_>,
    key_id: u16,
) -> Result<(), CryptoError> {
    match key_id {
        SEEN_ISS => {
            out.mark(SEEN_ISS)?;
            out.iss_len = read_string(r, &mut out.iss)? as u8;
        }
        SEEN_SUB => {
            out.mark(SEEN_SUB)?;
            out.sub_len = read_string(r, &mut out.sub)? as u8;
        }
        SEEN_AUD => {
            out.mark(SEEN_AUD)?;
            out.aud_len = read_string(r, &mut out.aud)? as u8;
        }
        SEEN_DBGSTAT => {
            out.mark(SEEN_DBGSTAT)?;
            out.dbgstat_len = read_string(r, &mut out.dbgstat)? as u8;
        }
        SEEN_EAT_NONCE => {
            out.mark(SEEN_EAT_NONCE)?;
            let n = read_string(r, &mut out.eat_nonces[0])?;
            accept_eat_nonce_len(n)?;
            out.eat_nonce_lens[0] = n as u8;
            out.eat_nonce_count = 1;
        }
        SEEN_ALG => {
            out.mark(SEEN_ALG)?;
            out.alg_len = read_string(r, &mut out.alg)? as u8;
            if out.alg[..out.alg_len as usize].contains(&0) {
                return Err(CryptoError::MalformedJwt);
            }
        }
        SEEN_KID => {
            out.mark(SEEN_KID)?;
            out.kid_len = read_string(r, &mut out.kid)? as u8;
            if out.kid[..out.kid_len as usize].contains(&0) {
                return Err(CryptoError::MalformedJwt);
            }
        }
        SEEN_IMAGE_DIGEST => {
            out.mark(SEEN_IMAGE_DIGEST)?;
            let mut buf = [0u8; 72];
            let n = read_string(r, &mut buf)?;
            out.image_digest = parse_image_digest(&buf[..n])?;
        }
        _ => {
            read_string(r, &mut [])?;
        }
    }
    Ok(())
}

fn read_string<R: Pull>(r: &mut Reader<R>, dest: &mut [u8]) -> Result<usize, CryptoError> {
    let mut len = 0usize;
    let mut escape = false;
    loop {
        let b = r.read_req()?;
        if escape {
            let decoded = match b {
                b'"' | b'\\' | b'/' => b,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'u' => decode_u_escape(r)?,
                _ => return Err(CryptoError::MalformedJwt),
            };
            if !dest.is_empty() {
                if len >= dest.len() {
                    return Err(CryptoError::MalformedJwt);
                }
                dest[len] = decoded;
                len += 1;
            }
            escape = false;
            continue;
        }
        match b {
            b'"' => return Ok(len),
            b'\\' => escape = true,
            0..=0x1f => return Err(CryptoError::MalformedJwt),
            _ => {
                if !dest.is_empty() {
                    if len >= dest.len() {
                        return Err(CryptoError::MalformedJwt);
                    }
                    dest[len] = b;
                    len += 1;
                }
            }
        }
    }
}

fn decode_u_escape<R: Pull>(r: &mut Reader<R>) -> Result<u8, CryptoError> {
    let mut v = 0u16;
    for _ in 0..4 {
        v = (v << 4) | u16::from(hex_nibble(r.read_req()?)?);
    }
    if v > 0x7f {
        return Err(CryptoError::MalformedJwt);
    }
    Ok(v as u8)
}

fn parse_bool<R: Pull>(r: &mut Reader<R>) -> Result<bool, CryptoError> {
    match r.read_req()? {
        b't' => {
            expect_bytes(r, b"rue")?;
            Ok(true)
        }
        b'f' => {
            expect_bytes(r, b"alse")?;
            Ok(false)
        }
        _ => Err(CryptoError::MalformedJwt),
    }
}

fn expect_bytes<R: Pull>(r: &mut Reader<R>, rest: &[u8]) -> Result<(), CryptoError> {
    for expected in rest {
        if r.read_req()? != *expected {
            return Err(CryptoError::MalformedJwt);
        }
    }
    Ok(())
}

fn parse_u64<R: Pull>(r: &mut Reader<R>) -> Result<u64, CryptoError> {
    let first = r.read_req()?;
    if !first.is_ascii_digit() {
        return Err(CryptoError::MalformedJwt);
    }
    let mut n = u64::from(first - b'0');
    let mut digits = 1u8;
    if first == b'0' {
        if matches!(r.peek()?, Some(b'0'..=b'9')) {
            return Err(CryptoError::MalformedJwt);
        }
        return Ok(0);
    }
    loop {
        match r.peek()? {
            Some(b @ b'0'..=b'9') => {
                let _ = r.read()?;
                n = n
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(u64::from(b - b'0')))
                    .ok_or(CryptoError::MalformedJwt)?;
                digits = digits.saturating_add(1);
                if digits > 20 {
                    return Err(CryptoError::MalformedJwt);
                }
            }
            Some(b'.') | Some(b'e') | Some(b'E') => return Err(CryptoError::MalformedJwt),
            _ => return Ok(n),
        }
    }
}

fn accept_eat_nonce_len(n: usize) -> Result<(), CryptoError> {
    if (MIN_EAT_NONCE..=MAX_EAT_NONCE).contains(&n) {
        Ok(())
    } else {
        Err(CryptoError::MalformedJwt)
    }
}

fn decode_mode_a_nonce(encoded: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    if encoded.len() != MODE_A_NONCE_B64_LEN || encoded.contains(&b'=') {
        return Err(CryptoError::MalformedJwt);
    }
    super::b64::decode_b64url_exact(encoded, out)
}

/// `eat_nonce` array of exactly two strings. Any other array shape fails closed.
/// @spec SCC-JWT-005
fn parse_eat_nonce_array<R: Pull>(
    r: &mut Reader<R>,
    out: &mut GoogleClaims<'_>,
) -> Result<(), CryptoError> {
    out.mark(SEEN_EAT_NONCE)?;
    for index in 0..MAX_EAT_NONCE_VALUES {
        skip_ws(r)?;
        if r.read_req()? != b'"' {
            return Err(CryptoError::MalformedJwt);
        }
        let n = read_string(r, &mut out.eat_nonces[index])?;
        accept_eat_nonce_len(n)?;
        out.eat_nonce_lens[index] = n as u8;
        if index + 1 < MAX_EAT_NONCE_VALUES {
            skip_ws(r)?;
            if r.read_req()? != b',' {
                return Err(CryptoError::MalformedJwt);
            }
        }
    }
    out.eat_nonce_count = MAX_EAT_NONCE_VALUES as u8;
    skip_ws(r)?;
    if r.read_req()? != b']' {
        return Err(CryptoError::MalformedJwt);
    }
    Ok(())
}

/// One-element array of `sha256:<hex>` strings. Every other array shape fails closed.
/// @spec SCC-JWT-005
fn parse_image_digest_array<R: Pull>(
    r: &mut Reader<R>,
    out: &mut GoogleClaims<'_>,
) -> Result<(), CryptoError> {
    out.mark(SEEN_IMAGE_DIGEST)?;
    skip_ws(r)?;
    if r.read_req()? != b'"' {
        return Err(CryptoError::MalformedJwt);
    }
    let mut buf = [0u8; 72];
    let n = read_string(r, &mut buf)?;
    out.image_digest = parse_image_digest(&buf[..n])?;
    skip_ws(r)?;
    if r.read_req()? != b']' {
        return Err(CryptoError::MalformedJwt);
    }
    Ok(())
}

fn parse_image_digest(s: &[u8]) -> Result<[u8; 32], CryptoError> {
    const PREFIX: &[u8] = b"sha256:";
    if s.len() != PREFIX.len() + 64 || !s.starts_with(PREFIX) {
        return Err(CryptoError::MalformedJwt);
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(s[PREFIX.len() + 2 * i])?;
        let lo = hex_nibble(s[PREFIX.len() + 2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, CryptoError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(CryptoError::MalformedJwt),
    }
}
