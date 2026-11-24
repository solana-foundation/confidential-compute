//! Zero-heap Base64URL decoder.
//!
//! @spec SCC-JWT-001

use crate::error::CryptoError;

/// Decode Base64URL (`A-Z a-z 0-9 - _`, optional terminal `=`) into `output`.
///
/// Returns the number of bytes written. Does not allocate.
/// @spec SCC-JWT-001
pub fn decode_b64url(input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
    let mut src = input;
    while let Some((last, rest)) = src.split_last() {
        if *last == b'=' {
            src = rest;
        } else {
            break;
        }
    }
    if src.is_empty() {
        return Ok(0);
    }
    if src.len() % 4 == 1 {
        return Err(CryptoError::MalformedJwt);
    }

    let mut written = 0usize;
    let mut i = 0usize;
    while i + 4 <= src.len() {
        let n =
            pack4(decode_char(src[i])?, decode_char(src[i + 1])?, decode_char(src[i + 2])?, decode_char(src[i + 3])?);
        written = write_bytes(output, written, &[(n >> 16) as u8, (n >> 8) as u8, n as u8], 3)?;
        i += 4;
    }

    let rem = src.len() - i;
    if rem == 2 {
        let a = decode_char(src[i])?;
        let b = decode_char(src[i + 1])?;
        if b & 0x0f != 0 {
            return Err(CryptoError::MalformedJwt);
        }
        let n = pack4(a, b, 0, 0);
        written = write_bytes(output, written, &[(n >> 16) as u8], 1)?;
    } else if rem == 3 {
        let a = decode_char(src[i])?;
        let b = decode_char(src[i + 1])?;
        let c = decode_char(src[i + 2])?;
        if c & 0x03 != 0 {
            return Err(CryptoError::MalformedJwt);
        }
        let n = pack4(a, b, c, 0);
        written = write_bytes(output, written, &[(n >> 16) as u8, (n >> 8) as u8], 2)?;
    }

    Ok(written)
}

/// Decode Base64URL into `output` and require an exact fill.
pub fn decode_b64url_exact(input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
    let n = decode_b64url(input, output)?;
    if n != output.len() {
        return Err(CryptoError::MalformedJwt);
    }
    Ok(())
}

/// Streaming Base64URL reader with a 3-byte window. Stack footprint is tiny.
/// @spec SCC-JWT-001
pub struct B64Decoder<'a> {
    src: &'a [u8],
    pos: usize,
    buf: [u8; 3],
    buf_len: u8,
    buf_pos: u8,
}

impl<'a> B64Decoder<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        let mut end = src.len();
        while end > 0 && src[end - 1] == b'=' {
            end -= 1;
        }
        Self { src: &src[..end], pos: 0, buf: [0; 3], buf_len: 0, buf_pos: 0 }
    }

    /// Pull the next decoded byte, or `None` at end of input.
    pub fn next_byte(&mut self) -> Result<Option<u8>, CryptoError> {
        if self.buf_pos < self.buf_len {
            let b = self.buf[self.buf_pos as usize];
            self.buf_pos += 1;
            return Ok(Some(b));
        }
        if self.pos >= self.src.len() {
            return Ok(None);
        }
        self.refill()?;
        if self.buf_pos < self.buf_len {
            let b = self.buf[self.buf_pos as usize];
            self.buf_pos += 1;
            Ok(Some(b))
        } else {
            Ok(None)
        }
    }

    fn refill(&mut self) -> Result<(), CryptoError> {
        self.buf_pos = 0;
        self.buf_len = 0;
        let remain = self.src.len() - self.pos;
        if remain == 0 {
            return Ok(());
        }
        if remain == 1 {
            return Err(CryptoError::MalformedJwt);
        }
        if remain >= 4 {
            let n = pack4(
                decode_char(self.src[self.pos])?,
                decode_char(self.src[self.pos + 1])?,
                decode_char(self.src[self.pos + 2])?,
                decode_char(self.src[self.pos + 3])?,
            );
            self.buf = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
            self.buf_len = 3;
            self.pos += 4;
            return Ok(());
        }
        if remain == 2 {
            let a = decode_char(self.src[self.pos])?;
            let b = decode_char(self.src[self.pos + 1])?;
            if b & 0x0f != 0 {
                return Err(CryptoError::MalformedJwt);
            }
            let n = pack4(a, b, 0, 0);
            self.buf[0] = (n >> 16) as u8;
            self.buf_len = 1;
            self.pos += 2;
            return Ok(());
        }
        let a = decode_char(self.src[self.pos])?;
        let b = decode_char(self.src[self.pos + 1])?;
        let c = decode_char(self.src[self.pos + 2])?;
        if c & 0x03 != 0 {
            return Err(CryptoError::MalformedJwt);
        }
        let n = pack4(a, b, c, 0);
        self.buf[0] = (n >> 16) as u8;
        self.buf[1] = (n >> 8) as u8;
        self.buf_len = 2;
        self.pos += 3;
        Ok(())
    }
}

#[inline]
fn decode_char(c: u8) -> Result<u8, CryptoError> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(CryptoError::MalformedJwt),
    }
}

#[inline]
fn pack4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32)
}

fn write_bytes(output: &mut [u8], written: usize, bytes: &[u8], count: usize) -> Result<usize, CryptoError> {
    if written + count > output.len() {
        return Err(CryptoError::MalformedJwt);
    }
    output[written..written + count].copy_from_slice(&bytes[..count]);
    Ok(written + count)
}
