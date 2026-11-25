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
    let (quads, tail) = src.as_chunks::<4>();
    for &[a, b, c, d] in quads {
        let n = pack4(decode_char(a)?, decode_char(b)?, decode_char(c)?, decode_char(d)?);
        written = write_bytes(output, written, &[(n >> 16) as u8, (n >> 8) as u8, n as u8])?;
    }

    match *tail {
        [a, b] => {
            let a = decode_char(a)?;
            let b = decode_char(b)?;
            if b & 0x0f != 0 {
                return Err(CryptoError::MalformedJwt);
            }
            let n = pack4(a, b, 0, 0);
            written = write_bytes(output, written, &[(n >> 16) as u8])?;
        }
        [a, b, c] => {
            let a = decode_char(a)?;
            let b = decode_char(b)?;
            let c = decode_char(c)?;
            if c & 0x03 != 0 {
                return Err(CryptoError::MalformedJwt);
            }
            let n = pack4(a, b, c, 0);
            written = write_bytes(output, written, &[(n >> 16) as u8, (n >> 8) as u8])?;
        }
        // An empty tail ends the input. A one-byte tail was rejected above.
        _ => {}
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
    buf: [u8; 3],
    buf_len: u8,
    buf_pos: u8,
}

impl<'a> B64Decoder<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        let mut src = src;
        while let Some((b'=', rest)) = src.split_last() {
            src = rest;
        }
        Self { src, buf: [0; 3], buf_len: 0, buf_pos: 0 }
    }

    /// Pull the next decoded byte, or `None` at end of input.
    pub fn next_byte(&mut self) -> Result<Option<u8>, CryptoError> {
        if self.buf_pos < self.buf_len {
            return self.take_buffered().map(Some);
        }
        if self.src.is_empty() {
            return Ok(None);
        }
        self.refill()?;
        if self.buf_pos < self.buf_len {
            self.take_buffered().map(Some)
        } else {
            Ok(None)
        }
    }

    fn take_buffered(&mut self) -> Result<u8, CryptoError> {
        let b = self.buf[self.buf_pos as usize];
        self.buf_pos = self.buf_pos.checked_add(1).ok_or(CryptoError::MalformedJwt)?;
        Ok(b)
    }

    fn refill(&mut self) -> Result<(), CryptoError> {
        self.buf_pos = 0;
        self.buf_len = 0;
        match *self.src {
            [] => Ok(()),
            [_] => Err(CryptoError::MalformedJwt),
            [a, b] => {
                let a = decode_char(a)?;
                let b = decode_char(b)?;
                if b & 0x0f != 0 {
                    return Err(CryptoError::MalformedJwt);
                }
                let n = pack4(a, b, 0, 0);
                self.buf[0] = (n >> 16) as u8;
                self.buf_len = 1;
                self.src = &[];
                Ok(())
            }
            [a, b, c] => {
                let a = decode_char(a)?;
                let b = decode_char(b)?;
                let c = decode_char(c)?;
                if c & 0x03 != 0 {
                    return Err(CryptoError::MalformedJwt);
                }
                let n = pack4(a, b, c, 0);
                self.buf[0] = (n >> 16) as u8;
                self.buf[1] = (n >> 8) as u8;
                self.buf_len = 2;
                self.src = &[];
                Ok(())
            }
            [a, b, c, d, ref rest @ ..] => {
                let n = pack4(decode_char(a)?, decode_char(b)?, decode_char(c)?, decode_char(d)?);
                self.buf = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
                self.buf_len = 3;
                self.src = rest;
                Ok(())
            }
        }
    }
}

#[inline]
fn decode_char(c: u8) -> Result<u8, CryptoError> {
    let (first, value_of_first) = match c {
        b'A'..=b'Z' => (b'A', 0),
        b'a'..=b'z' => (b'a', 26),
        b'0'..=b'9' => (b'0', 52),
        b'-' => return Ok(62),
        b'_' => return Ok(63),
        _ => return Err(CryptoError::MalformedJwt),
    };
    c.checked_sub(first).and_then(|v| v.checked_add(value_of_first)).ok_or(CryptoError::MalformedJwt)
}

#[inline]
fn pack4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32)
}

fn write_bytes(output: &mut [u8], written: usize, bytes: &[u8]) -> Result<usize, CryptoError> {
    let end = written.checked_add(bytes.len()).ok_or(CryptoError::MalformedJwt)?;
    output.get_mut(written..end).ok_or(CryptoError::MalformedJwt)?.copy_from_slice(bytes);
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn encode(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in bytes.chunks(3) {
            let mut block = [0u8; 3];
            block[..chunk.len()].copy_from_slice(chunk);
            let n = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
            let sextets = [n >> 18, n >> 12, n >> 6, n].map(|v| ALPHABET[(v & 0x3f) as usize]);
            out.extend_from_slice(&sextets[..=chunk.len()]);
        }
        out
    }

    fn stream(input: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut decoder = B64Decoder::new(input);
        let mut out = Vec::new();
        while let Some(b) = decoder.next_byte()? {
            out.push(b);
        }
        Ok(out)
    }

    /// The slice decoder and the streaming decoder both round-trip every tail
    /// length, with and without padding.
    #[test]
    fn both_decoders_round_trip_every_length() {
        for len in 0..=40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let encoded = encode(&bytes);
            let mut out = [0u8; 64];
            let n = decode_b64url(&encoded, &mut out).unwrap();
            assert_eq!(&out[..n], bytes.as_slice(), "slice decoder, length {len}");
            assert_eq!(stream(&encoded).unwrap(), bytes, "stream decoder, length {len}");

            let mut padded = encoded.clone();
            padded.extend_from_slice(b"==");
            assert_eq!(stream(&padded).unwrap(), bytes, "padded stream, length {len}");
            let n = decode_b64url(&padded, &mut out).unwrap();
            assert_eq!(&out[..n], bytes.as_slice(), "padded slice, length {len}");
        }
    }

    #[test]
    fn both_decoders_reject_the_same_malformed_input() {
        for bad in [&b"A"[..], b"AAAAA", b"AB", b"ABC", b"A+AA", b"AA/A", b"AA A", b"AA=A"] {
            let mut out = [0u8; 8];
            assert!(decode_b64url(bad, &mut out).is_err(), "slice decoder accepted {bad:?}");
            assert!(stream(bad).is_err(), "stream decoder accepted {bad:?}");
        }
    }

    #[test]
    fn slice_decoder_rejects_a_short_output_buffer() {
        let mut out = [0u8; 2];
        assert_eq!(decode_b64url(b"AAAA", &mut out), Err(CryptoError::MalformedJwt));
        assert_eq!(decode_b64url(b"AAA", &mut out), Ok(2));
        let mut out = [0u8; 3];
        assert_eq!(decode_b64url_exact(b"AAA", &mut out), Err(CryptoError::MalformedJwt));
    }
}
