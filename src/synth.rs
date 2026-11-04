//! Synthetic traffic for tests, fixtures and demos.
//!
//! Builds checksummed Ethernet/ARP/IPv4/IPv6/TCP/UDP/DNS frames and scripted
//! home-network scenarios, one per detector. `cargo run --example
//! gen_fixtures` writes them to `tests/fixtures/`; the integration tests
//! verify the committed files still match this generator byte for byte.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::packet::arp::ArpOp;
use crate::packet::{MacAddr, TcpFlags};
use crate::time::Timestamp;

/// A scripted frame sequence.
pub type Trace = Vec<(Timestamp, Vec<u8>)>;

/// A named scenario generator.
pub type Fixture = (&'static str, fn() -> Trace);

/// Scenario start: 2026-03-14T09:00:00Z.
pub const EPOCH: u64 = 1_773_478_800;

const ETH_IPV4: u16 = 0x0800;
const ETH_ARP: u16 = 0x0806;
const ETH_IPV6: u16 = 0x86dd;
const MIN_FRAME: usize = 60;

/// One endpoint on the synthetic network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    /// Hardware address.
    pub mac: MacAddr,
    /// IPv4 address.
    pub ip: Ipv4Addr,
}

impl Host {
    /// Creates a host.
    pub const fn new(mac: [u8; 6], ip: [u8; 4]) -> Self {
        Self {
            mac: MacAddr(mac),
            ip: Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
        }
    }
}

/// Home router (AVM).
pub const ROUTER: Host = Host::new([0x38, 0x10, 0xd5, 0xaa, 0x00, 0x01], [192, 168, 1, 1]);
/// Laptop (Apple).
pub const LAPTOP: Host = Host::new([0xa4, 0x5e, 0x60, 0x11, 0x22, 0x33], [192, 168, 1, 20]);
/// Home server (Raspberry Pi).
pub const PI: Host = Host::new([0xb8, 0x27, 0xeb, 0x44, 0x55, 0x66], [192, 168, 1, 30]);
/// Smart TV (Roku).
pub const TV: Host = Host::new([0xb0, 0xa7, 0x37, 0x10, 0x20, 0x30], [192, 168, 1, 40]);
/// Attacker with a randomised MAC.
pub const ATTACKER: Host = Host::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x66], [192, 168, 1, 66]);
/// Unknown IoT plug (Espressif) that joins mid-capture.
pub const IOT: Host = Host::new([0x24, 0x0a, 0xc4, 0x9a, 0xbc, 0xde], [192, 168, 1, 77]);
/// A public web server.
pub const WEB: Ipv4Addr = Ipv4Addr::new(93, 184, 215, 14);

/// Internet checksum (RFC 1071) over `data` starting from `initial`.
pub fn checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    for chunk in data.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], chunk.get(1).copied().unwrap_or(0)]);
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

fn len16(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes()
}

/// Ethernet II frame, zero-padded to the 60-byte minimum.
pub fn ethernet(src: MacAddr, dst: MacAddr, ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst.0);
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&ether_type.to_be_bytes());
    f.extend_from_slice(payload);
    if f.len() < MIN_FRAME {
        f.resize(MIN_FRAME, 0);
    }
    f
}

/// ARP frame; the Ethernet source is `eth_src`.
pub fn arp(
    eth_src: MacAddr,
    op: ArpOp,
    sender: Host,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let opcode: u16 = match op {
        ArpOp::Request => 1,
        ArpOp::Reply => 2,
        ArpOp::Other(o) => o,
    };
    let mut p = vec![0, 1, 0x08, 0x00, 6, 4];
    p.extend_from_slice(&opcode.to_be_bytes());
    p.extend_from_slice(&sender.mac.0);
    p.extend_from_slice(&sender.ip.octets());
    p.extend_from_slice(&target_mac.0);
    p.extend_from_slice(&target_ip.octets());
    let dst = if op == ArpOp::Request || target_mac == MacAddr::ZERO {
        MacAddr::BROADCAST
    } else {
        target_mac
    };
    ethernet(eth_src, dst, ETH_ARP, &p)
}

/// IPv4 header plus payload with a valid header checksum.
pub fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0x45, 0];
    h.extend_from_slice(&len16(20 + payload.len()));
    h.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    let c = checksum(&h, 0);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

/// IPv6 header plus payload.
pub fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0x60, 0, 0, 0];
    h.extend_from_slice(&len16(payload.len()));
    h.extend_from_slice(&[next, 64]);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    h.extend_from_slice(payload);
    h
}

fn pseudo_v4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> u32 {
    let mut p = Vec::with_capacity(12);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&[0, proto]);
    p.extend_from_slice(&len16(len));
    u32::from(!checksum(&p, 0))
}

/// TCP segment with a valid IPv4 pseudo-header checksum.
pub fn tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    flags: u8,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(20 + payload.len());
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    let ack = u32::from(flags & TcpFlags::ACK != 0);
    t.extend_from_slice(&ack.to_be_bytes());
    t.extend_from_slice(&[0x50, flags, 0xfa, 0xf0, 0, 0, 0, 0]);
    t.extend_from_slice(payload);
    let c = checksum(&t, pseudo_v4(src, dst, 6, t.len()));
    t[16..18].copy_from_slice(&c.to_be_bytes());
    t
}

/// UDP datagram with a valid IPv4 pseudo-header checksum.
pub fn udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::with_capacity(8 + payload.len());
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&len16(8 + payload.len()));
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    let c = checksum(&u, pseudo_v4(src, dst, 17, u.len()));
    u[6..8].copy_from_slice(&c.to_be_bytes());
    u
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = &label.as_bytes()[..label.len().min(63)];
        out.push(u8::try_from(bytes.len()).unwrap_or(63));
        out.extend_from_slice(bytes);
    }
    out.push(0);
    out
}

/// DNS message with one question. Responses carry `rcode` and, when it is
/// zero, one A record pointing at 192.0.2.1 via a compression pointer.
pub fn dns(id: u16, name: &str, qtype: u16, response: bool, rcode: u8) -> Vec<u8> {
    let flags: u16 = if response {
        0x8180 | u16::from(rcode & 0x0f)
    } else {
        0x0100
    };
    let answers: u16 = u16::from(response && rcode == 0 && qtype == 1);
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&answers.to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend_from_slice(&encode_name(name));
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    if answers == 1 {
        m.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 192, 0, 2, 1]);
    }
    m
}

/// Complete Ethernet/IPv4/TCP frame.
pub fn tcp_frame(
    from: Host,
    to_mac: MacAddr,
    to_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    flags: u8,
) -> Vec<u8> {
    let seg = tcp(from.ip, to_ip, sport, dport, flags, 1000, &[]);
    ethernet(from.mac, to_mac, ETH_IPV4, &ipv4(from.ip, to_ip, 6, &seg))
}

/// Complete Ethernet/IPv4/UDP frame.
pub fn udp_frame(from: Host, to: Host, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let d = udp(from.ip, to.ip, sport, dport, payload);
    ethernet(from.mac, to.mac, ETH_IPV4, &ipv4(from.ip, to.ip, 17, &d))
}

/// Builder that keeps frames ordered by a running clock.
#[derive(Debug, Default)]
pub struct Script {
    now: u64,
    frames: Trace,
    dns_id: u16,
}

impl Script {
    /// Starts at [`EPOCH`] plus `offset_ms`.
    pub fn at(offset_ms: u64) -> Self {
        Self {
            now: EPOCH * 1_000_000 + offset_ms * 1000,
            frames: Vec::new(),
            dns_id: 0x4a00,
        }
    }

    /// Advances the clock.
    pub fn wait_ms(&mut self, ms: u64) -> &mut Self {
        self.now += ms * 1000;
        self
    }

    /// Appends a frame at the current time and advances 1 ms.
    pub fn push(&mut self, frame: Vec<u8>) -> &mut Self {
        self.frames.push((Timestamp(self.now), frame));
        self.now += 1000;
        self
    }

    /// Normal background chatter: ARP, DNS lookup, HTTPS handshake, IPv6 ND.
    pub fn background(&mut self, client: Host) -> &mut Self {
        self.push(arp(
            client.mac,
            ArpOp::Request,
            client,
            MacAddr::ZERO,
            ROUTER.ip,
        ));
        self.push(arp(ROUTER.mac, ArpOp::Reply, ROUTER, client.mac, client.ip));
        self.lookup(client, "www.example.com", 0);
        let port = 50_000 + (self.dns_id % 1000);
        self.push(tcp_frame(client, ROUTER.mac, WEB, port, 443, TcpFlags::SYN));
        let syn_ack = tcp(
            WEB,
            client.ip,
            443,
            port,
            TcpFlags::SYN | TcpFlags::ACK,
            7,
            &[],
        );
        self.push(ethernet(
            ROUTER.mac,
            client.mac,
            ETH_IPV4,
            &ipv4(WEB, client.ip, 6, &syn_ack),
        ));
        let data = tcp(
            client.ip,
            WEB,
            port,
            443,
            TcpFlags::ACK | TcpFlags::PSH,
            1001,
            &[0x16, 3, 1, 0, 4, 1, 0, 0, 0],
        );
        self.push(ethernet(
            client.mac,
            ROUTER.mac,
            ETH_IPV4,
            &ipv4(client.ip, WEB, 6, &data),
        ));
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, u16::from(client.mac.0[5]));
        let ns = [135u8, 0, 0, 0, 0, 0, 0, 0];
        self.push(ethernet(
            client.mac,
            MacAddr([0x33, 0x33, 0, 0, 0, 1]),
            ETH_IPV6,
            &ipv6(
                ll,
                "ff02::1".parse().unwrap_or(Ipv6Addr::UNSPECIFIED),
                58,
                &ns,
            ),
        ))
    }

    /// DNS query from `client` and the router's answer.
    pub fn lookup(&mut self, client: Host, name: &str, rcode: u8) -> &mut Self {
        self.dns_id = self.dns_id.wrapping_add(1);
        let id = self.dns_id;
        let sport = 40_000 + id % 20_000;
        self.push(udp_frame(
            client,
            ROUTER,
            sport,
            53,
            &dns(id, name, 1, false, 0),
        ));
        self.push(udp_frame(
            ROUTER,
            client,
            53,
            sport,
            &dns(id, name, 1, true, rcode),
        ))
    }

    /// Finishes the script.
    pub fn build(&mut self) -> Trace {
        std::mem::take(&mut self.frames)
    }
}

/// SYN scan of 40 ports, then XMAS, NULL and FIN probes and a /24 host sweep.
pub fn portscan() -> Trace {
    let mut s = Script::at(0);
    s.background(LAPTOP);
    for port in 1..=40u16 {
        s.push(tcp_frame(
            ATTACKER,
            PI.mac,
            PI.ip,
            61_000,
            port,
            TcpFlags::SYN,
        ));
        let rst = if port == 22 {
            TcpFlags::SYN | TcpFlags::ACK
        } else {
            TcpFlags::RST | TcpFlags::ACK
        };
        s.push(tcp_frame(PI, ATTACKER.mac, ATTACKER.ip, port, 61_000, rst));
        s.wait_ms(20);
    }
    s.wait_ms(500);
    for (flags, base) in [
        (TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG, 1000),
        (0, 2000),
        (TcpFlags::FIN, 3000),
    ] {
        for i in 0..4u16 {
            s.push(tcp_frame(ATTACKER, PI.mac, PI.ip, 61_001, base + i, flags));
            s.wait_ms(30);
        }
    }
    s.wait_ms(500);
    for host in 100..=120u8 {
        s.push(tcp_frame(
            ATTACKER,
            ROUTER.mac,
            Ipv4Addr::new(192, 168, 1, host),
            61_002,
            22,
            TcpFlags::SYN,
        ));
        s.wait_ms(10);
    }
    s.background(TV);
    s.build()
}

/// Attacker poisons the router's binding, floods gratuitous ARP and sends a
/// reply whose Ethernet source does not match the ARP sender.
pub fn arp_spoof() -> Trace {
    let mut s = Script::at(0);
    s.background(LAPTOP);
    s.background(PI);
    s.wait_ms(1000);
    let fake_router = Host {
        mac: ATTACKER.mac,
        ip: ROUTER.ip,
    };
    for _ in 0..3 {
        s.push(arp(
            ATTACKER.mac,
            ArpOp::Reply,
            fake_router,
            LAPTOP.mac,
            LAPTOP.ip,
        ));
        s.wait_ms(200);
    }
    for _ in 0..6 {
        s.push(arp(
            ATTACKER.mac,
            ArpOp::Reply,
            fake_router,
            MacAddr::ZERO,
            ROUTER.ip,
        ));
        s.wait_ms(300);
    }
    s.push(arp(
        ATTACKER.mac,
        ArpOp::Reply,
        Host {
            mac: TV.mac,
            ip: PI.ip,
        },
        LAPTOP.mac,
        LAPTOP.ip,
    ));
    s.build()
}

/// Known devices talk, then an unknown IoT plug joins via DHCP and ARP.
pub fn new_device() -> Trace {
    let mut s = Script::at(0);
    s.background(LAPTOP);
    s.background(TV);
    s.wait_ms(2000);
    let unknown = Host {
        mac: IOT.mac,
        ip: Ipv4Addr::UNSPECIFIED,
    };
    let bcast = Host {
        mac: MacAddr::BROADCAST,
        ip: Ipv4Addr::BROADCAST,
    };
    s.push(udp_frame(
        unknown,
        bcast,
        68,
        67,
        &[1, 1, 6, 0, 0x39, 0x03, 0xf3, 0x26],
    ));
    s.push(arp(IOT.mac, ArpOp::Request, IOT, MacAddr::ZERO, IOT.ip));
    s.lookup(IOT, "a2.tuyaeu.com", 0);
    s.background(IOT);
    s.build()
}

/// DNS tunnelling (long, high-entropy names) and an NXDOMAIN burst.
pub fn dns_anomaly() -> Trace {
    let mut s = Script::at(0);
    s.background(LAPTOP);
    let chunks = [
        "mzxw6ytboi4dqnbsgezdgnbvgy3tqojqgeztqnrvhe2dimrsg44dmmzt",
        "nbswy3dpeb3w64tmmqqgc3tpnb2gk4tfmqqgk6dbnfzw4ylmn5sxi5dp",
        "orsxg5bamzzg633nebuw45dfojxgc3dbnrzxk4tfmvzwy2lkn5xgk2lt",
    ];
    for c in chunks {
        s.lookup(PI, &format!("{c}.{c}.t.exfil-cdn.net"), 0);
        s.wait_ms(150);
    }
    s.lookup(PI, "k7xq2v9mzr4tw8pl3nb6yc5h.exfil-cdn.net", 0);
    s.wait_ms(1000);
    let dga = [
        "qwkfjzu",
        "pplxaqvd",
        "zmrtoeiwq",
        "hbvcnxas",
        "lkjdwqp",
        "vbneuwqo",
        "rtyuixcv",
        "mnbvqwer",
        "asdpoiuy",
        "zxcmnbvl",
        "qazwsxed",
        "plmoknij",
    ];
    for d in dga {
        s.lookup(TV, &format!("{d}.com"), 3);
        s.wait_ms(250);
    }
    s.build()
}

/// All scenarios on one 20-second timeline; used for the demo recording.
pub fn mixed() -> Trace {
    let mut all = Trace::new();
    for (offset_s, trace) in [
        (0, new_device()),
        (4, portscan()),
        (9, arp_spoof()),
        (14, dns_anomaly()),
    ] {
        let shift = offset_s * 1_000_000;
        all.extend(trace.into_iter().map(|(t, f)| (Timestamp(t.0 + shift), f)));
    }
    all.sort_by_key(|(t, _)| *t);
    all
}

/// Fixture file names and their generators.
pub const FIXTURES: [Fixture; 5] = [
    ("portscan.pcap", portscan),
    ("arp_spoof.pcap", arp_spoof),
    ("new_device.pcap", new_device),
    ("dns_anomaly.pcap", dns_anomaly),
    ("mixed.pcapng", mixed),
];

/// Serialises `trace` as pcap or, if `name` ends in `.pcapng`, pcapng.
///
/// # Errors
///
/// Propagates I/O errors from the writer.
pub fn encode(name: &str, trace: &[(Timestamp, Vec<u8>)]) -> std::io::Result<Vec<u8>> {
    if std::path::Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("pcapng"))
    {
        let mut w = crate::capture::pcapng::PcapNgWriter::new(Vec::new())?;
        for (ts, f) in trace {
            w.write(*ts, f)?;
        }
        w.finish()
    } else {
        let mut w = crate::capture::pcap::PcapWriter::new(Vec::new())?;
        for (ts, f) in trace {
            w.write(*ts, f)?;
        }
        w.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::PacketSummary;

    #[test]
    fn checksum_known_vector() {
        let h = [
            0x45, 0, 0, 0x73, 0, 0, 0x40, 0, 0x40, 0x11, 0, 0, 0xc0, 0xa8, 0, 1, 0xc0, 0xa8, 0,
            0xc7,
        ];
        assert_eq!(checksum(&h, 0), 0xb861);
    }

    #[test]
    fn every_fixture_frame_parses() {
        for (name, gen) in FIXTURES {
            let trace = gen();
            assert!(!trace.is_empty(), "{name}");
            assert!(
                trace.windows(2).all(|w| w[0].0 <= w[1].0),
                "{name} not sorted"
            );
            for (ts, f) in &trace {
                PacketSummary::from_frame(*ts, f, f.len())
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
            }
        }
    }
}
