//! ARP for IPv4 over Ethernet (RFC 826).

use std::net::Ipv4Addr;

use super::ethernet::mac_at;
use super::{be16, ensure, MacAddr, ParseError, ParseResult};

const LEN: usize = 28;

/// ARP operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    /// Who-has.
    Request,
    /// Is-at.
    Reply,
    /// RARP or other opcode.
    Other(u16),
}

/// Borrowed view of an Ethernet/IPv4 ARP packet.
#[derive(Debug, Clone, Copy)]
pub struct ArpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> ArpPacket<'a> {
    /// Validates hardware/protocol types and lengths.
    ///
    /// # Errors
    ///
    /// Returns an error for truncated packets or non-Ethernet/IPv4 ARP.
    pub fn new(buf: &'a [u8]) -> ParseResult<Self> {
        ensure("arp", buf, LEN)?;
        if be16(buf, 0) != 1 || be16(buf, 2) != 0x0800 || buf[4] != 6 || buf[5] != 4 {
            return Err(ParseError::Malformed {
                proto: "arp",
                field: "hardware/protocol type",
            });
        }
        Ok(Self { buf })
    }

    /// Operation.
    pub fn op(&self) -> ArpOp {
        match be16(self.buf, 6) {
            1 => ArpOp::Request,
            2 => ArpOp::Reply,
            o => ArpOp::Other(o),
        }
    }

    /// Sender hardware address.
    pub fn sender_mac(&self) -> MacAddr {
        MacAddr(mac_at(self.buf, 8))
    }

    /// Sender protocol address.
    pub fn sender_ip(&self) -> Ipv4Addr {
        ip_at(self.buf, 14)
    }

    /// Target hardware address.
    pub fn target_mac(&self) -> MacAddr {
        MacAddr(mac_at(self.buf, 18))
    }

    /// Target protocol address.
    pub fn target_ip(&self) -> Ipv4Addr {
        ip_at(self.buf, 24)
    }

    /// Gratuitous ARP: the sender announces its own address.
    pub fn is_gratuitous(&self) -> bool {
        self.sender_ip() == self.target_ip() && !self.sender_ip().is_unspecified()
    }
}

fn ip_at(buf: &[u8], off: usize) -> Ipv4Addr {
    Ipv4Addr::new(buf[off], buf[off + 1], buf[off + 2], buf[off + 3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reply() {
        let mut p = vec![0, 1, 8, 0, 6, 4, 0, 2];
        p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 192, 168, 1, 1]);
        p.extend_from_slice(&[7, 8, 9, 10, 11, 12, 192, 168, 1, 1]);
        let a = ArpPacket::new(&p).unwrap();
        assert_eq!(a.op(), ArpOp::Reply);
        assert_eq!(a.sender_ip(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(a.target_mac(), MacAddr([7, 8, 9, 10, 11, 12]));
        assert!(a.is_gratuitous());
    }

    #[test]
    fn rejects_non_ethernet() {
        let mut p = vec![0, 6, 8, 0, 6, 4, 0, 1];
        p.resize(LEN, 0);
        assert!(matches!(
            ArpPacket::new(&p),
            Err(ParseError::Malformed { .. })
        ));
    }
}
