//! IPv6 (RFC 8200) with extension-header traversal.

use std::net::Ipv6Addr;

use super::{be16, ensure, ParseError, ParseResult};

/// `ICMPv6` next-header value.
pub const PROTO_ICMPV6: u8 = 58;

const HEADER_LEN: usize = 40;
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const DEST_OPTS: u8 = 60;
const NO_NEXT: u8 = 59;
const MAX_EXT_HEADERS: usize = 8;

/// Borrowed view of an IPv6 datagram, bounded by its payload-length field.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Packet<'a> {
    buf: &'a [u8],
}

impl<'a> Ipv6Packet<'a> {
    /// Validates version and payload length.
    ///
    /// # Errors
    ///
    /// Returns an error if the header is truncated or inconsistent.
    pub fn new(buf: &'a [u8]) -> ParseResult<Self> {
        ensure("ipv6", buf, HEADER_LEN)?;
        if buf[0] >> 4 != 6 {
            return Err(ParseError::Malformed {
                proto: "ipv6",
                field: "version",
            });
        }
        let total = HEADER_LEN + usize::from(be16(buf, 4));
        ensure("ipv6", buf, total)?;
        Ok(Self { buf: &buf[..total] })
    }

    /// Source address.
    pub fn src(&self) -> Ipv6Addr {
        addr_at(self.buf, 8)
    }

    /// Destination address.
    pub fn dst(&self) -> Ipv6Addr {
        addr_at(self.buf, 24)
    }

    /// Hop limit.
    pub fn hop_limit(&self) -> u8 {
        self.buf[7]
    }

    /// Total datagram length in bytes.
    pub fn total_len(&self) -> usize {
        self.buf.len()
    }

    /// Walks extension headers and returns the upper-layer protocol and its
    /// bytes. The body is `None` for non-initial fragments and "no next header".
    ///
    /// # Errors
    ///
    /// Returns an error if an extension header is truncated or the chain is
    /// implausibly long.
    pub fn upper_layer(&self) -> ParseResult<(u8, Option<&'a [u8]>)> {
        let mut next = self.buf[6];
        let mut rest = &self.buf[HEADER_LEN..];
        for _ in 0..MAX_EXT_HEADERS {
            match next {
                HOP_BY_HOP | ROUTING | DEST_OPTS => {
                    ensure("ipv6-ext", rest, 2)?;
                    let len = (usize::from(rest[1]) + 1) * 8;
                    ensure("ipv6-ext", rest, len)?;
                    next = rest[0];
                    rest = &rest[len..];
                }
                FRAGMENT => {
                    ensure("ipv6-frag", rest, 8)?;
                    let offset = be16(rest, 2) >> 3;
                    next = rest[0];
                    if offset != 0 {
                        return Ok((next, None));
                    }
                    rest = &rest[8..];
                }
                NO_NEXT => return Ok((next, None)),
                proto => return Ok((proto, Some(rest))),
            }
        }
        Err(ParseError::Malformed {
            proto: "ipv6",
            field: "extension header chain",
        })
    }
}

fn addr_at(buf: &[u8], off: usize) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&buf[off..off + 16]);
    Ipv6Addr::from(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(next: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        p.extend_from_slice(&[next, 64]);
        p.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        p.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn skips_hop_by_hop() {
        let mut body = vec![17, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&[9, 9, 9]);
        let p = packet(HOP_BY_HOP, &body);
        let ip = Ipv6Packet::new(&p).unwrap();
        assert_eq!(ip.upper_layer().unwrap(), (17, Some(&[9u8, 9, 9][..])));
        assert_eq!(ip.dst(), Ipv6Addr::LOCALHOST);
        assert_eq!(ip.hop_limit(), 64);
    }

    #[test]
    fn later_fragment_has_no_body() {
        let p = packet(FRAGMENT, &[6, 0, 0, 0x08, 0, 0, 0, 1]);
        let ip = Ipv6Packet::new(&p).unwrap();
        assert_eq!(ip.upper_layer().unwrap(), (6, None));
    }

    #[test]
    fn endless_chain_is_rejected() {
        let mut body = Vec::new();
        for _ in 0..10 {
            body.extend_from_slice(&[DEST_OPTS, 0, 0, 0, 0, 0, 0, 0]);
        }
        let p = packet(DEST_OPTS, &body);
        assert!(Ipv6Packet::new(&p).unwrap().upper_layer().is_err());
    }
}
