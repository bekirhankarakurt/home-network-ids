//! Property tests: parsers never panic on arbitrary input and round-trip
//! what the synthetic builders produce.

use std::io::Cursor;
use std::net::Ipv4Addr;

use proptest::prelude::*;

use home_network_ids::capture::{self, Next};
use home_network_ids::config::Config;
use home_network_ids::packet::{self, DnsMessage, MacAddr, Network, TcpFlags, Transport};
use home_network_ids::summary::PacketSummary;
use home_network_ids::synth::{self, Host};
use home_network_ids::time::Timestamp;

fn drain(bytes: Vec<u8>) {
    if let Ok(mut src) = capture::open_reader(Cursor::new(bytes)) {
        for _ in 0..1000 {
            match src.next_frame() {
                Ok(Next::Frame(f)) => {
                    let _ = PacketSummary::from_frame(f.ts, &f.data, f.wire_len);
                }
                Ok(Next::Idle) => {}
                Ok(Next::End) | Err(_) => break,
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = packet::parse(&data);
        let _ = PacketSummary::from_frame(Timestamp(0), &data, data.len());
        if let Ok(m) = DnsMessage::new(&data) {
            let _ = m.questions();
        }
    }

    #[test]
    fn mutated_frames_never_panic(idx in 0usize..10_000, byte in any::<u8>(), cut in 0usize..200) {
        let trace = synth::mixed();
        let mut frame = trace[idx % trace.len()].1.clone();
        let i = idx % frame.len();
        frame[i] = byte;
        frame.truncate(frame.len().saturating_sub(cut % frame.len()));
        let _ = PacketSummary::from_frame(Timestamp(0), &frame, frame.len());
    }

    #[test]
    fn capture_readers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let mut pcap = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0];
        pcap.extend_from_slice(&data);
        drain(pcap);
        let mut ng = synth::encode("x.pcapng", &[]).unwrap();
        ng.extend_from_slice(&data);
        drain(ng);
        drain(data);
    }

    #[test]
    fn corrupted_fixture_never_panics(pos in any::<usize>(), byte in any::<u8>()) {
        for name in ["a.pcap", "b.pcapng"] {
            let mut bytes = synth::encode(name, &synth::arp_spoof()).unwrap();
            let p = pos % bytes.len();
            bytes[p] = byte;
            drain(bytes);
        }
    }

    #[test]
    fn tcp_round_trip(sport in any::<u16>(), dport in any::<u16>(), flags in 0u8..64, a in any::<[u8; 4]>(), b in any::<[u8; 4]>()) {
        let from = Host::new([2, 0, 0, 0, 0, 1], a);
        let frame = synth::tcp_frame(from, MacAddr([2, 0, 0, 0, 0, 2]), Ipv4Addr::from(b), sport, dport, flags);
        let p = packet::parse(&frame).unwrap();
        let Network::Ipv4(ip) = p.network else { panic!("not ipv4") };
        prop_assert_eq!(ip.src(), Ipv4Addr::from(a));
        prop_assert_eq!(ip.dst(), Ipv4Addr::from(b));
        let Some(Transport::Tcp(t)) = p.transport else { panic!("not tcp") };
        prop_assert_eq!((t.src_port(), t.dst_port(), t.flags()), (sport, dport, TcpFlags(flags)));
        // A valid header checksum folds to zero.
        prop_assert_eq!(synth::checksum(&frame[14..34], 0), 0);
    }

    #[test]
    fn dns_name_round_trip(labels in proptest::collection::vec("[a-z0-9-]{1,20}", 1..6), qtype in any::<u16>(), id in any::<u16>()) {
        let name = labels.join(".");
        let msg = synth::dns(id, &name, qtype, false, 0);
        let m = DnsMessage::new(&msg).unwrap();
        let q = m.questions().unwrap();
        prop_assert_eq!(m.id(), id);
        prop_assert_eq!(&q[0].name, &name);
        prop_assert_eq!(q[0].qtype, qtype);
    }

    #[test]
    fn pcap_round_trip(frames in proptest::collection::vec((any::<u32>(), 0u32..1_000_000, proptest::collection::vec(any::<u8>(), 0..100)), 0..20)) {
        let trace: Vec<_> = frames.iter().map(|(s, us, d)| (Timestamp::from_secs_micros(u64::from(*s), u64::from(*us)), d.clone())).collect();
        for name in ["a.pcap", "a.pcapng"] {
            let bytes = synth::encode(name, &trace).unwrap();
            let mut src = capture::open_reader(Cursor::new(bytes)).unwrap();
            for (ts, data) in &trace {
                let Next::Frame(f) = src.next_frame().unwrap() else { panic!("missing frame") };
                prop_assert_eq!(f.ts, *ts);
                prop_assert_eq!(&f.data, data);
            }
            prop_assert!(matches!(src.next_frame().unwrap(), Next::End));
        }
    }

    #[test]
    fn mac_round_trip(bytes in any::<[u8; 6]>()) {
        let mac = MacAddr(bytes);
        prop_assert_eq!(mac.to_string().parse::<MacAddr>().unwrap(), mac);
    }

    #[test]
    fn config_never_panics(text in "\\PC{0,200}") {
        let _ = Config::from_toml(&text);
    }
}
