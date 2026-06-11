//! UDP (RFC 768) header view.

use super::{be16, ensure, ParseError, ParseResult};

const LEN: usize = 8;

/// Borrowed view of a UDP datagram, bounded by its length field.
#[derive(Debug, Clone, Copy)]
pub struct UdpDatagram<'a> {
    buf: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    /// Validates the length field.
    ///
    /// # Errors
    ///
    /// Returns an error if the header is truncated or the length is invalid.
    pub fn new(buf: &'a [u8]) -> ParseResult<Self> {
        ensure("udp", buf, LEN)?;
        let len = usize::from(be16(buf, 4));
        if len < LEN {
            return Err(ParseError::Malformed {
                proto: "udp",
                field: "length",
            });
        }
        ensure("udp", buf, len)?;
        Ok(Self { buf: &buf[..len] })
    }

    /// Source port.
    pub fn src_port(&self) -> u16 {
        be16(self.buf, 0)
    }

    /// Destination port.
    pub fn dst_port(&self) -> u16 {
        be16(self.buf, 2)
    }

    /// Bytes after the header.
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[LEN..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_by_length() {
        let d = [0, 53, 0x30, 0x39, 0, 10, 0, 0, 1, 2, 3, 4];
        let u = UdpDatagram::new(&d).unwrap();
        assert_eq!((u.src_port(), u.dst_port()), (53, 12345));
        assert_eq!(u.payload(), &[1, 2]);
        assert!(UdpDatagram::new(&[0, 0, 0, 0, 0, 4, 0, 0]).is_err());
        assert!(UdpDatagram::new(&[0, 0, 0, 0, 0, 20, 0, 0]).is_err());
    }
}
