//! Owned per-packet summary passed from the parser stage to detectors.
//!
//! Parsing happens on borrowed views ([`crate::packet`]); only the fields the
//! detectors and the dashboard need are copied out, so the capture buffer can
//! be released immediately.

use std::net::{IpAddr, Ipv4Addr};

use crate::packet::{
    self, arp::ArpOp, dns::Question, DnsMessage, MacAddr, Network, ParseResult, TcpFlags, Transport,
};
use crate::time::Timestamp;

const DNS_PORT: u16 = 53;

/// Coarse protocol class used for traffic statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    /// ARP
    Arp,
    /// TCP over IPv4/IPv6
    Tcp,
    /// UDP over IPv4/IPv6
    Udp,
    /// ICMP / `ICMPv6`
    Icmp,
    /// Other IP protocol or later fragment
    OtherIp,
    /// Non-IP EtherType
    Other,
}

impl Proto {
    /// All classes, in display order.
    pub const ALL: [Self; 6] = [
        Self::Tcp,
        Self::Udp,
        Self::Icmp,
        Self::Arp,
        Self::OtherIp,
        Self::Other,
    ];

    /// Short label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Arp => "ARP",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::OtherIp => "IP-other",
            Self::Other => "non-IP",
        }
    }
}

/// TCP fields used by the port-scan detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpInfo {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Control flags.
    pub flags: TcpFlags,
}

/// ARP fields used by the spoofing detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpInfo {
    /// Operation.
    pub op: ArpOp,
    /// Sender hardware address.
    pub sender_mac: MacAddr,
    /// Sender protocol address.
    pub sender_ip: Ipv4Addr,
    /// Target hardware address.
    pub target_mac: MacAddr,
    /// Target protocol address.
    pub target_ip: Ipv4Addr,
}

impl ArpInfo {
    /// Sender announces its own address.
    pub fn is_gratuitous(&self) -> bool {
        self.sender_ip == self.target_ip && !self.sender_ip.is_unspecified()
    }
}

/// DNS fields used by the anomaly detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsInfo {
    /// Transaction ID.
    pub id: u16,
    /// Response (true) or query (false).
    pub response: bool,
    /// Response code.
    pub rcode: u8,
    /// Decoded question names.
    pub questions: Vec<Question>,
}

/// Everything downstream stages know about one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketSummary {
    /// Capture time.
    pub ts: Timestamp,
    /// Frame length on the wire.
    pub len: usize,
    /// Ethernet source.
    pub src_mac: MacAddr,
    /// Ethernet destination.
    pub dst_mac: MacAddr,
    /// Outer VLAN ID.
    pub vlan: Option<u16>,
    /// Protocol class.
    pub proto: Proto,
    /// Source IP for IP packets.
    pub src_ip: Option<IpAddr>,
    /// Destination IP for IP packets.
    pub dst_ip: Option<IpAddr>,
    /// TCP details.
    pub tcp: Option<TcpInfo>,
    /// UDP ports `(src, dst)`.
    pub udp: Option<(u16, u16)>,
    /// ARP details.
    pub arp: Option<ArpInfo>,
    /// DNS details for well-formed UDP/53 payloads.
    pub dns: Option<DnsInfo>,
}

impl PacketSummary {
    /// Parses `frame` and extracts a summary.
    ///
    /// `wire_len` is the original length when the capture was truncated.
    ///
    /// # Errors
    ///
    /// Returns the parser error for malformed link, network or transport
    /// headers. Malformed DNS payloads only clear [`PacketSummary::dns`].
    pub fn from_frame(ts: Timestamp, frame: &[u8], wire_len: usize) -> ParseResult<Self> {
        let p = packet::parse(frame)?;
        let (src_ip, dst_ip) = p.ip_pair().unzip();
        let mut s = Self {
            ts,
            len: wire_len.max(frame.len()),
            src_mac: p.ethernet.src(),
            dst_mac: p.ethernet.dst(),
            vlan: p.ethernet.vlan(),
            proto: Proto::Other,
            src_ip,
            dst_ip,
            tcp: None,
            udp: None,
            arp: None,
            dns: None,
        };
        match p.network {
            Network::Arp(a) => {
                s.proto = Proto::Arp;
                s.arp = Some(ArpInfo {
                    op: a.op(),
                    sender_mac: a.sender_mac(),
                    sender_ip: a.sender_ip(),
                    target_mac: a.target_mac(),
                    target_ip: a.target_ip(),
                });
            }
            Network::Ipv4(_) | Network::Ipv6(_) => s.proto = Proto::OtherIp,
            Network::Other(_) => {}
        }
        match p.transport {
            Some(Transport::Tcp(t)) => {
                s.proto = Proto::Tcp;
                s.tcp = Some(TcpInfo {
                    src_port: t.src_port(),
                    dst_port: t.dst_port(),
                    flags: t.flags(),
                });
            }
            Some(Transport::Udp(u)) => {
                s.proto = Proto::Udp;
                s.udp = Some((u.src_port(), u.dst_port()));
                if u.src_port() == DNS_PORT || u.dst_port() == DNS_PORT {
                    s.dns = parse_dns(u.payload());
                }
            }
            Some(Transport::Icmp(_)) => s.proto = Proto::Icmp,
            Some(Transport::Other(_)) | None => {}
        }
        Ok(s)
    }
}

fn parse_dns(payload: &[u8]) -> Option<DnsInfo> {
    let m = DnsMessage::new(payload).ok()?;
    Some(DnsInfo {
        id: m.id(),
        response: m.is_response(),
        rcode: m.rcode(),
        questions: m.questions().ok()?,
    })
}
