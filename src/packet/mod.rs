//! Zero-copy protocol parsers.
//!
//! Every parser wraps a borrowed byte slice and validates lengths up front, so
//! field accessors never index out of bounds. [`parse`] decodes a whole
//! Ethernet frame into borrowed layer views without allocating.

pub mod arp;
pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

use std::fmt;
use std::net::IpAddr;

pub use arp::ArpPacket;
pub use dns::DnsMessage;
pub use ethernet::{EtherType, EthernetFrame, MacAddr};
pub use icmp::IcmpPacket;
pub use ipv4::Ipv4Packet;
pub use ipv6::Ipv6Packet;
pub use tcp::{TcpFlags, TcpSegment};
pub use udp::UdpDatagram;

/// Errors produced while decoding a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The buffer is shorter than the protocol requires.
    #[error("{proto}: truncated (need {need} bytes, have {have})")]
    Truncated {
        /// Protocol being decoded.
        proto: &'static str,
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// A header field holds a value the protocol does not allow.
    #[error("{proto}: malformed {field}")]
    Malformed {
        /// Protocol being decoded.
        proto: &'static str,
        /// Offending field.
        field: &'static str,
    },
}

/// Result alias for parser functions.
pub type ParseResult<T> = Result<T, ParseError>;

/// Fails with [`ParseError::Truncated`] unless `buf` holds at least `need` bytes.
pub(crate) fn ensure(proto: &'static str, buf: &[u8], need: usize) -> ParseResult<()> {
    if buf.len() < need {
        Err(ParseError::Truncated {
            proto,
            need,
            have: buf.len(),
        })
    } else {
        Ok(())
    }
}

/// Reads a big-endian `u16` at `off`; callers validate the length first.
pub(crate) fn be16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

/// Network-layer view of a frame.
#[derive(Debug, Clone, Copy)]
pub enum Network<'a> {
    /// ARP request or reply.
    Arp(ArpPacket<'a>),
    /// IPv4 datagram.
    Ipv4(Ipv4Packet<'a>),
    /// IPv6 datagram.
    Ipv6(Ipv6Packet<'a>),
    /// Any other EtherType.
    Other(u16),
}

/// Transport-layer view of an IP datagram.
#[derive(Debug, Clone, Copy)]
pub enum Transport<'a> {
    /// TCP segment.
    Tcp(TcpSegment<'a>),
    /// UDP datagram.
    Udp(UdpDatagram<'a>),
    /// ICMP or `ICMPv6` message.
    Icmp(IcmpPacket<'a>),
    /// Non-first fragment or unsupported protocol number.
    Other(u8),
}

/// A fully decoded frame; all views borrow from the original buffer.
#[derive(Debug, Clone, Copy)]
pub struct Packet<'a> {
    /// Link layer.
    pub ethernet: EthernetFrame<'a>,
    /// Network layer.
    pub network: Network<'a>,
    /// Transport layer, present for IP datagrams that carry one.
    pub transport: Option<Transport<'a>>,
}

impl Packet<'_> {
    /// Source and destination IP addresses, if this is an IP packet.
    pub fn ip_pair(&self) -> Option<(IpAddr, IpAddr)> {
        match self.network {
            Network::Ipv4(ip) => Some((IpAddr::V4(ip.src()), IpAddr::V4(ip.dst()))),
            Network::Ipv6(ip) => Some((IpAddr::V6(ip.src()), IpAddr::V6(ip.dst()))),
            Network::Arp(_) | Network::Other(_) => None,
        }
    }
}

/// Decodes an Ethernet frame down to the transport layer.
///
/// # Errors
///
/// Returns [`ParseError`] if any present layer is truncated or malformed.
pub fn parse(frame: &[u8]) -> ParseResult<Packet<'_>> {
    let ethernet = EthernetFrame::new(frame)?;
    let payload = ethernet.payload();
    let (network, transport) = match ethernet.ether_type() {
        EtherType::Arp => (Network::Arp(ArpPacket::new(payload)?), None),
        EtherType::Ipv4 => {
            let ip = Ipv4Packet::new(payload)?;
            let transport = if ip.is_first_fragment() {
                Some(parse_transport(ip.protocol(), ip.payload())?)
            } else {
                Some(Transport::Other(ip.protocol()))
            };
            (Network::Ipv4(ip), transport)
        }
        EtherType::Ipv6 => {
            let ip = Ipv6Packet::new(payload)?;
            let (proto, body) = ip.upper_layer()?;
            let transport = match body {
                Some(body) => parse_transport(proto, body)?,
                None => Transport::Other(proto),
            };
            (Network::Ipv6(ip), Some(transport))
        }
        EtherType::Other(t) => (Network::Other(t), None),
    };
    Ok(Packet {
        ethernet,
        network,
        transport,
    })
}

fn parse_transport(proto: u8, body: &[u8]) -> ParseResult<Transport<'_>> {
    Ok(match proto {
        ipv4::PROTO_TCP => Transport::Tcp(TcpSegment::new(body)?),
        ipv4::PROTO_UDP => Transport::Udp(UdpDatagram::new(body)?),
        ipv4::PROTO_ICMP | ipv6::PROTO_ICMPV6 => Transport::Icmp(IcmpPacket::new(body)?),
        other => Transport::Other(other),
    })
}

impl fmt::Display for Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.ethernet.src(), self.ethernet.dst())?;
        if let Some((s, d)) = self.ip_pair() {
            write!(f, " {s} -> {d}")?;
        }
        Ok(())
    }
}
