//! ARP spoofing detection.
//!
//! Learns IPv4-to-MAC bindings from every ARP sender and reports:
//! * `arp_static_mismatch` (critical): a configured static binding is contradicted,
//! * `arp_binding_change` (high): a learned binding moves to a different MAC,
//! * `arp_sender_mismatch` (medium): Ethernet source differs from ARP sender,
//! * `gratuitous_arp_flood` (medium): too many gratuitous ARPs from one MAC.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::window::EventWindow;
use super::Detector;
use crate::alert::{Alert, Severity};
use crate::config::Arp;
use crate::packet::MacAddr;
use crate::summary::PacketSummary;

const NAME: &str = "arp";
const MAX_BINDINGS: usize = 65_536;

/// ARP spoofing detector; see the module docs.
pub struct ArpDetector {
    static_bindings: BTreeMap<Ipv4Addr, MacAddr>,
    bindings: HashMap<Ipv4Addr, MacAddr>,
    gratuitous: HashMap<MacAddr, EventWindow>,
    span: Duration,
    threshold: usize,
    window_secs: u64,
}

impl ArpDetector {
    /// Creates the detector from its configuration section.
    pub fn new(cfg: &Arp) -> Self {
        Self {
            static_bindings: cfg.static_bindings.clone(),
            bindings: HashMap::new(),
            gratuitous: HashMap::new(),
            span: Duration::from_secs(cfg.gratuitous_window_secs),
            threshold: cfg.gratuitous_threshold,
            window_secs: cfg.gratuitous_window_secs,
        }
    }

    /// Currently learned binding for `ip`.
    pub fn binding(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.bindings.get(&ip).copied()
    }
}

impl Detector for ArpDetector {
    fn name(&self) -> &'static str {
        NAME
    }

    fn inspect(&mut self, pkt: &PacketSummary, out: &mut Vec<Alert>) {
        let Some(arp) = pkt.arp else { return };
        let ip = arp.sender_ip;
        let mac = arp.sender_mac;
        if ip.is_unspecified() || !mac.is_unicast() {
            return;
        }

        if pkt.src_mac != mac {
            out.push(
                Alert::new(
                    pkt.ts,
                    NAME,
                    "arp_sender_mismatch",
                    Severity::Medium,
                    format!("ARP for {ip} claims {mac} but was sent by {}", pkt.src_mac),
                )
                .ip(IpAddr::V4(ip))
                .mac(pkt.src_mac)
                .detail("arp_sender_mac", mac.to_string()),
            );
        }

        if let Some(&expected) = self.static_bindings.get(&ip) {
            if expected != mac {
                out.push(
                    Alert::new(
                        pkt.ts,
                        NAME,
                        "arp_static_mismatch",
                        Severity::Critical,
                        format!("{mac} claims protected address {ip} (expected {expected})"),
                    )
                    .ip(IpAddr::V4(ip))
                    .mac(mac)
                    .detail("expected_mac", expected.to_string()),
                );
            }
        } else {
            match self.bindings.get(&ip) {
                Some(&old) if old != mac => out.push(
                    Alert::new(
                        pkt.ts,
                        NAME,
                        "arp_binding_change",
                        Severity::High,
                        format!("{ip} moved from {old} to {mac} (possible ARP spoofing)"),
                    )
                    .ip(IpAddr::V4(ip))
                    .mac(mac)
                    .detail("old_mac", old.to_string())
                    .detail("new_mac", mac.to_string()),
                ),
                _ => {}
            }
            if self.bindings.len() >= MAX_BINDINGS && !self.bindings.contains_key(&ip) {
                self.bindings.clear();
            }
            self.bindings.insert(ip, mac);
        }

        if arp.is_gratuitous() {
            if self.gratuitous.len() >= MAX_BINDINGS && !self.gratuitous.contains_key(&mac) {
                let now = pkt.ts;
                self.gratuitous.retain(|_, w| {
                    w.expire(now);
                    !w.is_empty()
                });
            }
            let count = self
                .gratuitous
                .entry(mac)
                .or_insert_with(|| EventWindow::new(self.span))
                .record(pkt.ts);
            if count >= self.threshold {
                out.push(
                    Alert::new(
                        pkt.ts,
                        NAME,
                        "gratuitous_arp_flood",
                        Severity::Medium,
                        format!(
                            "{mac} sent {count} gratuitous ARPs in {}s (last for {ip})",
                            self.window_secs
                        ),
                    )
                    .mac(mac)
                    .detail("count", count)
                    .detail("window_secs", self.window_secs)
                    .detail("claimed_ip", ip.to_string()),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::arp::ArpOp;
    use crate::summary::{ArpInfo, Proto};
    use crate::time::Timestamp;

    fn arp(ms: u64, eth: [u8; 6], mac: [u8; 6], ip: [u8; 4], target: [u8; 4]) -> PacketSummary {
        PacketSummary {
            ts: Timestamp(ms * 1000),
            len: 60,
            src_mac: MacAddr(eth),
            dst_mac: MacAddr::BROADCAST,
            vlan: None,
            proto: Proto::Arp,
            src_ip: None,
            dst_ip: None,
            tcp: None,
            udp: None,
            arp: Some(ArpInfo {
                op: ArpOp::Reply,
                sender_mac: MacAddr(mac),
                sender_ip: Ipv4Addr::from(ip),
                target_mac: MacAddr::ZERO,
                target_ip: Ipv4Addr::from(target),
            }),
            dns: None,
        }
    }

    const GW: [u8; 6] = [0xb8, 0x27, 0xeb, 0, 0, 1];
    const EVIL: [u8; 6] = [0xb8, 0x27, 0xeb, 0, 0, 0x66];

    fn kinds(d: &mut ArpDetector, pkts: &[PacketSummary]) -> Vec<&'static str> {
        let mut out = Vec::new();
        for p in pkts {
            d.inspect(p, &mut out);
        }
        out.iter().map(|a| a.kind).collect()
    }

    #[test]
    fn binding_change() {
        let mut d = ArpDetector::new(&Arp::default());
        let k = kinds(
            &mut d,
            &[
                arp(0, GW, GW, [192, 168, 1, 1], [192, 168, 1, 5]),
                arp(10, GW, GW, [192, 168, 1, 1], [192, 168, 1, 6]),
                arp(20, EVIL, EVIL, [192, 168, 1, 1], [192, 168, 1, 5]),
            ],
        );
        assert_eq!(k, vec!["arp_binding_change"]);
        assert_eq!(
            d.binding(Ipv4Addr::new(192, 168, 1, 1)),
            Some(MacAddr(EVIL))
        );
    }

    #[test]
    fn static_binding_and_sender_mismatch() {
        let mut cfg = Arp::default();
        cfg.static_bindings
            .insert(Ipv4Addr::new(192, 168, 1, 1), MacAddr(GW));
        let mut d = ArpDetector::new(&cfg);
        let k = kinds(
            &mut d,
            &[
                arp(0, GW, GW, [192, 168, 1, 1], [192, 168, 1, 5]),
                arp(10, GW, EVIL, [192, 168, 1, 1], [192, 168, 1, 5]),
            ],
        );
        assert_eq!(k, vec!["arp_sender_mismatch", "arp_static_mismatch"]);
    }

    #[test]
    fn gratuitous_flood_and_probe_ignored() {
        let mut d = ArpDetector::new(&Arp::default());
        let mut pkts: Vec<_> = (0..6)
            .map(|i| arp(i * 100, GW, GW, [192, 168, 1, 9], [192, 168, 1, 9]))
            .collect();
        pkts.push(arp(700, EVIL, EVIL, [0, 0, 0, 0], [192, 168, 1, 9]));
        assert_eq!(
            kinds(&mut d, &pkts),
            vec!["gratuitous_arp_flood", "gratuitous_arp_flood"]
        );
    }
}
