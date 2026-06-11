//! IPv4 (RFC 791).

use std::net::Ipv4Addr;

use super::{be16, ensure, ParseError, ParseResult};

/// ICMP protocol number.
pub const PROTO_ICMP: u8 = 1;
/// TCP protocol number.
pub const PROTO_TCP: u8 = 6;
/// UDP protocol number.
pub const PROTO_UDP: u8 = 17;

const MIN_LEN: usize = 20;

/// Borrowed view of an IPv4 datagram, bounded by its total-length field.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Packet<'a> {
    buf: &'a [u8],
    header_len: usize,
}

impl<'a> Ipv4Packet<'a> {
    /// Validates version, IHL and total length; trailing Ethernet padding is
    /// trimmed away.
    ///
    /// # Errors
    ///
    /// Returns an error if the header is truncated or inconsistent.
    pub fn new(buf: &'a [u8]) -> ParseResult<Self> {
        ensure("ipv4", buf, MIN_LEN)?;
        if buf[0] >> 4 != 4 {
            return Err(ParseError::Malformed {
                proto: "ipv4",
                field: "version",
            });
        }
        let header_len = usize::from(buf[0] & 0x0f) * 4;
        let total = usize::from(be16(buf, 2));
        if header_len < MIN_LEN || total < header_len {
            return Err(ParseError::Malformed {
                proto: "ipv4",
                field: "length",
            });
        }
        ensure("ipv4", buf, total)?;
        Ok(Self {
            buf: &buf[..total],
            header_len,
        })
    }

    /// Source address.
    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[12], self.buf[13], self.buf[14], self.buf[15])
    }

    /// Destination address.
    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[16], self.buf[17], self.buf[18], self.buf[19])
    }

    /// Payload protocol number.
    pub fn protocol(&self) -> u8 {
        self.buf[9]
    }

    /// Time to live.
    pub fn ttl(&self) -> u8 {
        self.buf[8]
    }

    /// True unless this is a non-initial fragment (offset > 0).
    pub fn is_first_fragment(&self) -> bool {
        be16(self.buf, 6) & 0x1fff == 0
    }

    /// Total datagram length in bytes.
    pub fn total_len(&self) -> usize {
        self.buf.len()
    }

    /// Bytes after the header.
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.header_len..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(total: u16) -> Vec<u8> {
        let mut h = vec![
            0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, PROTO_UDP, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        h[2..4].copy_from_slice(&total.to_be_bytes());
        h
    }

    #[test]
    fn trims_padding() {
        let mut p = header(24);
        p.extend_from_slice(&[1, 2, 3, 4, 0, 0, 0]);
        let ip = Ipv4Packet::new(&p).unwrap();
        assert_eq!(ip.payload(), &[1, 2, 3, 4]);
        assert_eq!(ip.src(), Ipv4Addr::new(10, 0, 0, 1));
        assert!(ip.is_first_fragment());
        assert_eq!(ip.ttl(), 64);
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(Ipv4Packet::new(&header(10)).is_err());
        assert!(Ipv4Packet::new(&header(40)).is_err());
        let mut p = header(20);
        p[0] = 0x44;
        assert!(Ipv4Packet::new(&p).is_err());
        p[0] = 0x65;
        assert!(Ipv4Packet::new(&p).is_err());
    }
}
