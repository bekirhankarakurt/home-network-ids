//! DNS anomaly detection.
//!
//! * `dns_long_name`: query names longer than the configured limit
//!   (data exfiltration via DNS tunnelling),
//! * `dns_high_entropy`: random-looking subdomains (tunnelling, DGA),
//! * `dns_nxdomain_burst`: many NXDOMAIN answers to one client
//!   (malware cycling through generated domains).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use super::window::EventWindow;
use super::Detector;
use crate::alert::{Alert, Severity};
use crate::config::Dns;
use crate::packet::dns::RCODE_NXDOMAIN;
use crate::summary::PacketSummary;

const NAME: &str = "dns";
const MAX_CLIENTS: usize = 16_384;

/// Shannon entropy of `s` in bits per byte.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[usize::from(b)] += 1;
    }
    let len = f64::from(u32::try_from(s.len()).unwrap_or(u32::MAX));
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

/// Splits `name` into (subdomain labels joined without dots, registered domain).
///
/// The registered domain is approximated as the last two labels.
pub fn split_subdomain(name: &str) -> (String, &str) {
    let name = name.trim_end_matches('.');
    let mut dots = name.rmatch_indices('.').map(|(i, _)| i);
    dots.next();
    match dots.next() {
        Some(i) => (name[..i].replace('.', ""), &name[i + 1..]),
        None => (String::new(), name),
    }
}

/// DNS anomaly detector; see the module docs.
pub struct DnsDetector {
    cfg: Dns,
    span: Duration,
    nxdomain: HashMap<IpAddr, EventWindow>,
}

impl DnsDetector {
    /// Creates the detector from its configuration section.
    pub fn new(cfg: &Dns) -> Self {
        let mut cfg = cfg.clone();
        for s in &mut cfg.ignore_suffixes {
            *s = s.trim_matches('.').to_ascii_lowercase();
        }
        Self {
            span: Duration::from_secs(cfg.nxdomain_window_secs),
            cfg,
            nxdomain: HashMap::new(),
        }
    }

    fn ignored(&self, name: &str) -> bool {
        self.cfg
            .ignore_suffixes
            .iter()
            .any(|s| name == s || name.ends_with(&format!(".{s}")))
    }

    fn check_query(&self, pkt: &PacketSummary, name: &str, out: &mut Vec<Alert>) {
        if self.ignored(name) {
            return;
        }
        let alert = |kind, msg: String, base: &str| {
            let mut a = Alert::new(pkt.ts, NAME, kind, Severity::Medium, msg)
                .mac(pkt.src_mac)
                .detail("query", name)
                .dedup(base);
            if let Some(ip) = pkt.src_ip {
                a = a.ip(ip);
            }
            a
        };
        let (sub, base) = split_subdomain(name);
        if name.len() > self.cfg.max_name_len {
            out.push(
                alert(
                    "dns_long_name",
                    format!("{}-character DNS query under {base}", name.len()),
                    base,
                )
                .detail("length", name.len()),
            );
        }
        if sub.len() >= self.cfg.entropy_min_len {
            let h = shannon_entropy(&sub);
            if h >= self.cfg.entropy_threshold {
                let rounded = (h * 100.0).round() / 100.0;
                out.push(
                    alert(
                        "dns_high_entropy",
                        format!("high-entropy DNS query ({rounded:.2} bits/char) under {base}"),
                        base,
                    )
                    .detail("entropy", rounded)
                    .detail("subdomain_length", sub.len()),
                );
            }
        }
    }
}

impl Detector for DnsDetector {
    fn name(&self) -> &'static str {
        NAME
    }

    fn inspect(&mut self, pkt: &PacketSummary, out: &mut Vec<Alert>) {
        let Some(dns) = &pkt.dns else { return };
        if !dns.response {
            for q in &dns.questions {
                self.check_query(pkt, &q.name, out);
            }
            return;
        }
        if dns.rcode != RCODE_NXDOMAIN {
            return;
        }
        let Some(client) = pkt.dst_ip else { return };
        if self.nxdomain.len() >= MAX_CLIENTS && !self.nxdomain.contains_key(&client) {
            let now = pkt.ts;
            self.nxdomain.retain(|_, w| {
                w.expire(now);
                !w.is_empty()
            });
        }
        let count = self
            .nxdomain
            .entry(client)
            .or_insert_with(|| EventWindow::new(self.span))
            .record(pkt.ts);
        if count >= self.cfg.nxdomain_threshold {
            let last = dns
                .questions
                .first()
                .map(|q| q.name.clone())
                .unwrap_or_default();
            out.push(
                Alert::new(
                    pkt.ts,
                    NAME,
                    "dns_nxdomain_burst",
                    Severity::High,
                    format!(
                        "{client} received {count} NXDOMAIN answers in {}s (possible DGA malware)",
                        self.cfg.nxdomain_window_secs
                    ),
                )
                .ip(client)
                .mac(pkt.dst_mac)
                .detail("count", count)
                .detail("window_secs", self.cfg.nxdomain_window_secs)
                .detail("last_query", last),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::dns::Question;
    use crate::packet::MacAddr;
    use crate::summary::{DnsInfo, Proto};
    use crate::time::Timestamp;

    fn dns(ms: u64, name: &str, response: bool, rcode: u8) -> PacketSummary {
        PacketSummary {
            ts: Timestamp(ms * 1000),
            len: 80,
            src_mac: MacAddr([2, 0, 0, 0, 0, 1]),
            dst_mac: MacAddr([2, 0, 0, 0, 0, 2]),
            vlan: None,
            proto: Proto::Udp,
            src_ip: Some(IpAddr::from([192, 168, 1, 50])),
            dst_ip: Some(IpAddr::from([192, 168, 1, 60])),
            tcp: None,
            udp: Some((50_000, 53)),
            arp: None,
            dns: Some(DnsInfo {
                id: 1,
                response,
                rcode,
                questions: vec![Question {
                    name: name.into(),
                    qtype: 1,
                }],
            }),
        }
    }

    fn kinds(d: &mut DnsDetector, pkts: &[PacketSummary]) -> Vec<&'static str> {
        let mut out = Vec::new();
        for p in pkts {
            d.inspect(p, &mut out);
        }
        out.iter().map(|a| a.kind).collect()
    }

    #[test]
    fn entropy_values() {
        assert!(shannon_entropy("") < f64::EPSILON);
        assert!(shannon_entropy("aaaa") < f64::EPSILON);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn subdomain_split() {
        assert_eq!(
            split_subdomain("example.com"),
            (String::new(), "example.com")
        );
        assert_eq!(
            split_subdomain("a.b.example.com"),
            ("ab".into(), "example.com")
        );
        assert_eq!(
            split_subdomain("x.example.com."),
            ("x".into(), "example.com")
        );
    }

    #[test]
    fn normal_names_are_quiet() {
        let mut d = DnsDetector::new(&Dns::default());
        let names = [
            "www.google.com",
            "connectivity-check.ubuntu.com",
            "lh3.googleusercontent.com",
            "1.1.168.192.in-addr.arpa",
            "e6858.dscx.akamaiedge.net",
            "safebrowsing.googleapis.com",
        ];
        let pkts: Vec<_> = names.iter().map(|n| dns(0, n, false, 0)).collect();
        assert!(kinds(&mut d, &pkts).is_empty());
    }

    #[test]
    fn tunnel_queries() {
        let mut d = DnsDetector::new(&Dns::default());
        let long = format!("{}.t.evil.example", "a1b2c3d4e5f6g7h8".repeat(7));
        let random = "x9k2q7v4m1z8w3p6r5t0y2u8.evil.example";
        let k = kinds(&mut d, &[dns(0, &long, false, 0), dns(1, random, false, 0)]);
        assert_eq!(
            k,
            vec!["dns_long_name", "dns_high_entropy", "dns_high_entropy"]
        );
    }

    #[test]
    fn nxdomain_burst() {
        let mut d = DnsDetector::new(&Dns::default());
        let pkts: Vec<_> = (0..12)
            .map(|i| dns(i * 100, "nope.example", true, RCODE_NXDOMAIN))
            .collect();
        assert_eq!(kinds(&mut d, &pkts).len(), 3);
        let ok: Vec<_> = (0..20).map(|i| dns(i, "ok.example", true, 0)).collect();
        assert!(kinds(&mut DnsDetector::new(&Dns::default()), &ok).is_empty());
    }
}
