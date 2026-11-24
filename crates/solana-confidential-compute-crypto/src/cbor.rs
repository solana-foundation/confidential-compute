//! Zero-copy CBOR decoder (RFC 8949 major types 0–5).
//!
//! @spec SCC-NITRO-001

use crate::error::CryptoError;

/// Streaming, allocation-free cursor over a CBOR buffer.
/// @spec SCC-NITRO-001
#[derive(Debug, Clone, Copy)]
pub struct CborCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// Decoded CBOR header (major type + argument).
/// @spec SCC-NITRO-001
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborHeader {
    Unsigned(u64),
    Negative(u64),
    Bytes(usize),
    Text(usize),
    Array(usize),
    Map(usize),
    /// Major type 4, additional info 31 (`0x9f`). Closed by a break stop.
    IndefiniteArray,
    /// Major type 5, additional info 31 (`0xbf`). Closed by a break stop.
    IndefiniteMap,
    /// CBOR break stop code (`0xff`). Not simple value 31.
    /// @spec SCC-NITRO-003
    Break,
    Simple(u8),
}

/// Nested containers the skipper will walk before returning [`CryptoError::MalformedCbor`].
/// @spec SCC-NITRO-001
const MAX_CBOR_SKIP_DEPTH: u8 = 8;

impl<'a> CborCursor<'a> {
    /// Creates a cursor over `buf`.
    #[inline]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Remaining unparsed bytes.
    #[inline]
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// True when every input byte has been consumed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Absolute offset into the original buffer.
    #[inline]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// True if the next byte is the CBOR "break" stop code (0xFF).
    #[inline]
    pub fn is_break(&self) -> bool {
        self.pos < self.buf.len() && self.buf[self.pos] == 0xff
    }

    /// Consumes the CBOR "break" stop code (0xFF).
    #[inline]
    pub fn read_break(&mut self) -> Result<(), CryptoError> {
        if self.is_break() {
            self.pos += 1;
            Ok(())
        } else {
            Err(CryptoError::MalformedCbor)
        }
    }

    /// Major type of the next data item (0–7) without advancing.
    pub fn peek_major(&self) -> Result<u8, CryptoError> {
        if self.pos >= self.buf.len() {
            return Err(CryptoError::MalformedCbor);
        }
        Ok(self.buf[self.pos] >> 5)
    }

    /// Consumes a CBOR tag (major type 6) and returns the tag number.
    /// Used by COSE Sign1 tag 18; generic item decode still rejects tags.
    pub fn read_tag(&mut self) -> Result<u64, CryptoError> {
        let (major, additional) = self.read_initial()?;
        if major != 6 {
            return Err(CryptoError::MalformedCbor);
        }
        self.read_argument(additional)
    }

    /// Decodes the next data-item header for major types 0–5 and 7.
    ///
    /// Additional info 31 is indefinite length on arrays and maps, and the
    /// break stop on major type 7. It is not simple value 31.
    /// @spec SCC-NITRO-001 SCC-NITRO-003
    pub fn read_header(&mut self) -> Result<CborHeader, CryptoError> {
        let (major, additional) = self.read_initial()?;
        if additional == 31 {
            return match major {
                4 => Ok(CborHeader::IndefiniteArray),
                5 => Ok(CborHeader::IndefiniteMap),
                7 => Ok(CborHeader::Break),
                _ => Err(CryptoError::MalformedCbor),
            };
        }
        if major == 7 {
            return Ok(CborHeader::Simple(additional));
        }
        let arg = self.read_argument(additional)?;
        match major {
            0 => Ok(CborHeader::Unsigned(arg)),
            1 => Ok(CborHeader::Negative(arg)),
            2 => Ok(CborHeader::Bytes(arg_to_len(arg)?)),
            3 => Ok(CborHeader::Text(arg_to_len(arg)?)),
            4 => Ok(CborHeader::Array(arg_to_len(arg)?)),
            5 => Ok(CborHeader::Map(arg_to_len(arg)?)),
            _ => Err(CryptoError::MalformedCbor),
        }
    }

    /// Reads an unsigned integer (major type 0).
    pub fn read_unsigned(&mut self) -> Result<u64, CryptoError> {
        match self.read_header()? {
            CborHeader::Unsigned(v) => Ok(v),
            _ => Err(CryptoError::MalformedCbor),
        }
    }

    /// Reads a CBOR integer as `i64` (major types 0 and 1).
    pub fn read_int(&mut self) -> Result<i64, CryptoError> {
        match self.read_header()? {
            CborHeader::Unsigned(v) => i64::try_from(v).map_err(|_| CryptoError::MalformedCbor),
            CborHeader::Negative(n) => {
                if n > i64::MAX as u64 {
                    return Err(CryptoError::MalformedCbor);
                }
                Ok(-1 - (n as i64))
            }
            _ => Err(CryptoError::MalformedCbor),
        }
    }

    /// Reads a byte string and returns a zero-copy slice into the input.
    /// @spec SCC-NITRO-001
    pub fn read_bstr(&mut self) -> Result<&'a [u8], CryptoError> {
        match self.read_header()? {
            CborHeader::Bytes(len) => self.read_exact(len),
            _ => Err(CryptoError::MalformedCbor),
        }
    }

    /// Reads a text string and returns a zero-copy UTF-8 slice into the input.
    /// @spec SCC-NITRO-001
    pub fn read_tstr(&mut self) -> Result<&'a str, CryptoError> {
        match self.read_header()? {
            CborHeader::Text(len) => {
                let bytes = self.read_exact(len)?;
                core::str::from_utf8(bytes).map_err(|_| CryptoError::MalformedCbor)
            }
            _ => Err(CryptoError::MalformedCbor),
        }
    }

    /// Reads an array header and returns the element count.
    pub fn read_array_len(&mut self) -> Result<usize, CryptoError> {
        match self.read_header()? {
            CborHeader::Array(len) => Ok(len),
            _ => Err(CryptoError::MalformedCbor),
        }
    }

    /// Reads a map header and returns the pair count.
    pub fn read_map_len(&mut self) -> Result<usize, CryptoError> {
        match self.read_header()? {
            CborHeader::Map(len) => Ok(len),
            _ => Err(CryptoError::MalformedCbor),
        }
    }

    fn read_initial(&mut self) -> Result<(u8, u8), CryptoError> {
        if self.pos >= self.buf.len() {
            return Err(CryptoError::MalformedCbor);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok((b >> 5, b & 0x1f))
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, CryptoError> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => {
                let b = self.read_exact(1)?;
                Ok(b[0] as u64)
            }
            25 => {
                let b = self.read_exact(2)?;
                Ok(u16::from_be_bytes([b[0], b[1]]) as u64)
            }
            26 => {
                let b = self.read_exact(4)?;
                Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64)
            }
            27 => {
                let b = self.read_exact(8)?;
                Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            }
            _ => Err(CryptoError::MalformedCbor),
        }
    }

    /// Advances the cursor by `len` bytes without copying.
    pub fn skip(&mut self, len: usize) -> Result<(), CryptoError> {
        let _ = self.read_exact(len)?;
        Ok(())
    }

    /// Skips one well-formed CBOR value, including indefinite maps and arrays.
    ///
    /// A break stop inside an indefinite map is the end of the map only when it
    /// falls on a key boundary. A break where a value is required is malformed
    /// and leaves the cursor on that break so the following bytes stay unread.
    /// @spec SCC-NITRO-003
    pub(crate) fn skip_value(&mut self) -> Result<(), CryptoError> {
        self.skip_value_depth(MAX_CBOR_SKIP_DEPTH)
    }

    fn skip_value_depth(&mut self, remaining_depth: u8) -> Result<(), CryptoError> {
        if remaining_depth == 0 {
            return Err(CryptoError::MalformedCbor);
        }
        let child_depth = remaining_depth - 1;
        match self.read_header()? {
            CborHeader::Unsigned(_) | CborHeader::Negative(_) | CborHeader::Simple(_) => Ok(()),
            CborHeader::Bytes(len) | CborHeader::Text(len) => self.skip(len),
            CborHeader::Array(n) => {
                for _ in 0..n {
                    self.skip_value_depth(child_depth)?;
                }
                Ok(())
            }
            CborHeader::Map(n) => {
                for _ in 0..(n.saturating_mul(2)) {
                    self.skip_value_depth(child_depth)?;
                }
                Ok(())
            }
            CborHeader::IndefiniteArray => {
                while !self.is_break() {
                    self.skip_value_depth(child_depth)?;
                }
                self.read_break()
            }
            CborHeader::IndefiniteMap => loop {
                if self.is_break() {
                    return self.read_break();
                }
                self.skip_value_depth(child_depth)?;
                if self.is_break() {
                    return Err(CryptoError::MalformedCbor);
                }
                self.skip_value_depth(child_depth)?;
            },
            CborHeader::Break => Err(CryptoError::MalformedCbor),
        }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], CryptoError> {
        let end = self.pos.checked_add(len).ok_or(CryptoError::MalformedCbor)?;
        if end > self.buf.len() {
            return Err(CryptoError::MalformedCbor);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
}

fn arg_to_len(arg: u64) -> Result<usize, CryptoError> {
    usize::try_from(arg).map_err(|_| CryptoError::MalformedCbor)
}

/// Writes a CBOR byte-string header for `len` bytes into `hasher`.
pub fn write_bstr_header(len: usize, mut write: impl FnMut(&[u8])) -> Result<(), CryptoError> {
    if len <= 23 {
        write(&[0x40 | (len as u8)]);
    } else if len <= 0xff {
        write(&[0x58, len as u8]);
    } else if len <= 0xffff {
        let n = (len as u16).to_be_bytes();
        write(&[0x59, n[0], n[1]]);
    } else if len <= 0xffff_ffff {
        let n = (len as u32).to_be_bytes();
        write(&[0x5a, n[0], n[1], n[2], n[3]]);
    } else {
        return Err(CryptoError::MalformedCbor);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_unsigned_and_negative() {
        let mut c = CborCursor::new(&[0x05]);
        assert_eq!(c.read_unsigned().unwrap(), 5);
        assert!(c.is_empty());

        let mut c = CborCursor::new(&[0x18, 0x22]);
        assert_eq!(c.read_unsigned().unwrap(), 0x22);

        // -35 => nint 34 => 0x38 0x22
        let mut c = CborCursor::new(&[0x38, 0x22]);
        assert_eq!(c.read_int().unwrap(), -35);
    }

    #[test]
    fn byte_and_text_are_zero_copy() {
        let buf = [0x43, b'a', b'b', b'c'];
        let mut c = CborCursor::new(&buf);
        let bstr = c.read_bstr().unwrap();
        assert_eq!(bstr, b"abc");
        assert_eq!(bstr.as_ptr(), buf[1..].as_ptr());

        let buf = *b"\x63foo";
        let mut c = CborCursor::new(&buf);
        let tstr = c.read_tstr().unwrap();
        assert_eq!(tstr, "foo");
        assert_eq!(tstr.as_ptr(), buf[1..].as_ptr());
    }

    #[test]
    fn array_and_map_headers() {
        let mut c = CborCursor::new(&[0x84, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(c.read_array_len().unwrap(), 4);
        assert_eq!(c.read_unsigned().unwrap(), 1);

        let mut c = CborCursor::new(&[0xa1, 0x01, 0x18, 0x2a]);
        assert_eq!(c.read_map_len().unwrap(), 1);
        assert_eq!(c.read_unsigned().unwrap(), 1);
        assert_eq!(c.read_unsigned().unwrap(), 42);
    }

    #[test]
    fn parses_simple_and_rejects_indefinite_bstr() {
        // Indefinite byte string (major 2, ai 31).
        let mut c = CborCursor::new(&[0x5f]);
        assert_eq!(c.read_header(), Err(CryptoError::MalformedCbor));
        // Simple major 7 (0xf4 = false, 0xf6 = null).
        let mut c = CborCursor::new(&[0xf4]);
        assert_eq!(c.read_header(), Ok(CborHeader::Simple(20)));
        let mut c = CborCursor::new(&[0xf6]);
        assert_eq!(c.read_header(), Ok(CborHeader::Simple(22)));
    }

    #[test]
    fn rejects_truncated_and_bad_utf8() {
        let mut c = CborCursor::new(&[0x43, b'a']);
        assert_eq!(c.read_bstr(), Err(CryptoError::MalformedCbor));
        let mut c = CborCursor::new(&[0x62, 0xff, 0xfe]);
        assert_eq!(c.read_tstr(), Err(CryptoError::MalformedCbor));
    }

    #[test]
    fn read_tag_eighteen() {
        let mut c = CborCursor::new(&[0xd2, 0x80]);
        assert_eq!(c.read_tag().unwrap(), 18);
        assert_eq!(c.read_array_len().unwrap(), 0);
    }

    #[test]
    fn break_stop_is_not_simple_31() {
        let mut c = CborCursor::new(&[0xff]);
        assert_eq!(c.read_header(), Ok(CborHeader::Break));
        assert!(c.is_empty());
        assert_ne!(CborCursor::new(&[0xff]).read_header(), Ok(CborHeader::Simple(31)));
    }

    #[test]
    fn skip_indefinite_array_stops_at_break() {
        // [_ 1, 2] then a sibling unsigned 3.
        let buf = [0x9f, 0x01, 0x02, 0xff, 0x03];
        let mut c = CborCursor::new(&buf);
        c.skip_value().unwrap();
        assert_eq!(c.position(), 4);
        assert_eq!(c.read_unsigned().unwrap(), 3);
    }

    #[test]
    fn skip_indefinite_map_stops_at_break() {
        // {_ 1: 2} then a sibling unsigned 3.
        let buf = [0xbf, 0x01, 0x02, 0xff, 0x03];
        let mut c = CborCursor::new(&buf);
        c.skip_value().unwrap();
        assert_eq!(c.position(), 4);
        assert_eq!(c.read_unsigned().unwrap(), 3);
    }

    #[test]
    fn uneven_indefinite_map_does_not_consume_the_sibling() {
        // {_ 1: <break>} then 0x18 0x2a. The break is not a value.
        let buf = [0xbf, 0x01, 0xff, 0x18, 0x2a];
        let mut c = CborCursor::new(&buf);
        assert_eq!(c.skip_value(), Err(CryptoError::MalformedCbor));
        assert_eq!(c.position(), 2);
        assert_eq!(c.remaining(), &[0xff, 0x18, 0x2a]);
    }

    #[test]
    fn skip_nested_indefinite_map_and_array() {
        // {_ 1: [_ 2]}
        let buf = [0xbf, 0x01, 0x9f, 0x02, 0xff, 0xff];
        let mut c = CborCursor::new(&buf);
        c.skip_value().unwrap();
        assert!(c.is_empty());
    }
}
