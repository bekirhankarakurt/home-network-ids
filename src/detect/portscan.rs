//! TCP port-scan detection.
//!
//! Per source IP, three sliding windows are kept:
//! * distinct `(host, port)` targets of SYN probes (vertical scan),
//! * distinct hosts probed (horizontal sweep),
//! * SYN probe rate.
//!
//! FIN, NULL and XMAS probes never occur in legitimate TCP, so a handful of
//! them within the window is reported as a stealth scan.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use super::window::{DistinctWindow, EventWindow};
use super::Detector;
use crate::alert::{Alert, Severity};
use crate::config::PortScan;
use crate::summary::PacketSummary;
use crate::time::Timestamp;

const NAME: &str = "portscan";
const MAX_SOURCES: usize = 16_384;
const SAMPLE_PORTS: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stealth {
    Fin,
    Null,
    Xmas,
}

impl Stealth {
    fn kind(self) -> &'static str {
        match self {
            Self::Fin => "fin_scan",
            Self::Null => "null_scan",
            Self::Xmas => "xmas_scan",
        }
    }
}

struct SourceState {
    targets: DistinctWindow<(IpAddr, u16)>,
    hosts: DistinctWindow<IpAddr>,
    syns: EventWindow,
    stealth: [EventWindow; 3],
    last_seen: Timestamp,
}

impl SourceState {
    fn new(span: Duration) -> Self {
        Self {
            targets: DistinctWindow::new(span),
            hosts: DistinctWindow::new(span),
            syns: EventWindow::new(span),
            stealth: [
                EventWindow::new(span),
                EventWindow::new(span),
                EventWindow::new(span),
            ],
            last_seen: Timestamp(0),
        }
    }
}

/// Port-scan detector; see the module docs.
pub struct PortScanDetector {
    cfg: PortScan,
    span: Duration,
    sources: HashMap<IpAddr, SourceState>,
    last_prune: Timestamp,
}

impl PortScanDetector {
    /// Creates the detector from its configuration section.
    pub fn new(cfg: &PortScan) -> Self {
        Self {
            cfg: cfg.clone(),
            span: Duration::from_secs(cfg.window_secs),
            sources: HashMap::new(),
            last_prune: Timestamp(0),
        }
    }

    fn prune(&mut self, now: Timestamp) {
        if now.since(self.last_prune) < self.span && self.sources.len() < MAX_SOURCES {
            return;
        }
        self.last_prune = now;
        let cutoff = now.minus(self.span);
        self.sources.retain(|_, s| s.last_seen >= cutoff);
        if self.sources.len() >= MAX_SOURCES {
            self.sources.clear();
        }
    }

    fn sample_ports(state: &SourceState) -> Vec<u16> {
        let mut ports: Vec<u16> = state.targets.keys().map(|&(_, p)| p).collect();
        ports.sort_unstable();
        ports.dedup();
        ports.truncate(SAMPLE_PORTS);
        ports
    }
}

impl Detector for PortScanDetector {
    fn name(&self) -> &'static str {
        NAME
    }

    fn inspect(&mut self, pkt: &PacketSummary, out: &mut Vec<Alert>) {
        let (Some(tcp), Some(src), Some(dst)) = (pkt.tcp, pkt.src_ip, pkt.dst_ip) else {
            return;
        };
        let flags = tcp.flags;
        let stealth = if flags.is_fin_probe() {
            Some(Stealth::Fin)
        } else if flags.is_null_probe() {
            Some(Stealth::Null)
        } else if flags.is_xmas_probe() {
            Some(Stealth::Xmas)
        } else {
            None
        };
        if !flags.is_syn_probe() && stealth.is_none() {
            return;
        }
        if self.cfg.ignore_sources.contains(&src) {
            return;
        }
        self.prune(pkt.ts);
        let span = self.span;
        let state = self
            .sources
            .entry(src)
            .or_insert_with(|| SourceState::new(span));
        state.last_seen = pkt.ts;
        let window = self.cfg.window_secs;

        if let Some(kind) = stealth {
            let count = state.stealth[kind as usize].record(pkt.ts);
            state.targets.record(pkt.ts, (dst, tcp.dst_port));
            if count >= self.cfg.stealth_threshold {
                let probe = kind.kind().trim_end_matches("_scan").to_uppercase();
                out.push(
                    Alert::new(
                        pkt.ts,
                        NAME,
                        kind.kind(),
                        Severity::High,
                        format!("{src} sent {count} {probe} probes (flags {flags}) in {window}s"),
                    )
                    .ip(src)
                    .mac(pkt.src_mac)
                    .detail("probes", count)
                    .detail("window_secs", window)
                    .detail("last_target", format!("{dst}:{}", tcp.dst_port)),
                );
            }
            return;
        }

        let targets = state.targets.record(pkt.ts, (dst, tcp.dst_port));
        let hosts = state.hosts.record(pkt.ts, dst);
        let syns = state.syns.record(pkt.ts);
        let base = |kind, severity, msg: String| {
            Alert::new(pkt.ts, NAME, kind, severity, msg)
                .ip(src)
                .mac(pkt.src_mac)
                .detail("window_secs", window)
        };

        if targets >= self.cfg.port_threshold {
            out.push(
                base(
                    "syn_scan",
                    Severity::High,
                    format!("{src} probed {targets} ports across {hosts} host(s) in {window}s"),
                )
                .detail("distinct_targets", targets)
                .detail("distinct_hosts", hosts)
                .detail("sample_ports", Self::sample_ports(state)),
            );
        }
        if hosts >= self.cfg.host_threshold {
            out.push(
                base(
                    "host_sweep",
                    Severity::Medium,
                    format!("{src} contacted {hosts} hosts with SYN probes in {window}s"),
                )
                .detail("distinct_hosts", hosts),
            );
        }
        let per_sec = self.cfg.syn_rate_threshold;
        if syns as u64 >= u64::from(per_sec).saturating_mul(window) {
            out.push(
                base(
                    "syn_rate",
                    Severity::High,
                    format!("{src} sent {syns} SYNs in {window}s (threshold {per_sec}/s)"),
                )
                .detail("syns", syns)
                .detail("threshold_per_sec", per_sec),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{MacAddr, TcpFlags};
    use crate::summary::{Proto, TcpInfo};

    fn syn(ms: u64, src: [u8; 4], dst: [u8; 4], port: u16, flags: u8) -> PacketSummary {
        PacketSummary {
            ts: Timestamp(ms * 1000),
            len: 60,
            src_mac: MacAddr([2, 0, 0, 0, 0, src[3]]),
            dst_mac: MacAddr([2, 0, 0, 0, 0, dst[3]]),
            vlan: None,
            proto: Proto::Tcp,
            src_ip: Some(IpAddr::from(src)),
            dst_ip: Some(IpAddr::from(dst)),
            tcp: Some(TcpInfo {
                src_port: 40_000,
                dst_port: port,
                flags: TcpFlags(flags),
            }),
            udp: None,
            arp: None,
            dns: None,
        }
    }

    fn run(d: &mut PortScanDetector, pkts: &[PacketSummary]) -> Vec<Alert> {
        let mut out = Vec::new();
        for p in pkts {
            d.inspect(p, &mut out);
        }
        out
    }

    #[test]
    fn vertical_scan() {
        let mut d = PortScanDetector::new(&PortScan::default());
        let pkts: Vec<_> = (1..=25)
            .map(|p| {
                syn(
                    u64::from(p) * 10,
                    [10, 0, 0, 66],
                    [10, 0, 0, 1],
                    p,
                    TcpFlags::SYN,
                )
            })
            .collect();
        let a = run(&mut d, &pkts);
        assert_eq!(a.iter().filter(|a| a.kind == "syn_scan").count(), 6);
        assert_eq!(a[0].details["distinct_targets"], 20);
    }

    #[test]
    fn slow_scan_stays_below_window() {
        let mut d = PortScanDetector::new(&PortScan::default());
        let pkts: Vec<_> = (1..=40)
            .map(|p| {
                syn(
                    u64::from(p) * 1000,
                    [10, 0, 0, 66],
                    [10, 0, 0, 1],
                    p,
                    TcpFlags::SYN,
                )
            })
            .collect();
        assert_eq!(run(&mut d, &pkts).len(), 0);
    }

    #[test]
    fn host_sweep_and_rate() {
        let cfg = PortScan {
            syn_rate_threshold: 2,
            ..PortScan::default()
        };
        let mut d = PortScanDetector::new(&cfg);
        let pkts: Vec<_> = (1..=20)
            .map(|h| {
                syn(
                    u64::from(h),
                    [10, 0, 0, 66],
                    [10, 0, 1, h],
                    22,
                    TcpFlags::SYN,
                )
            })
            .collect();
        let a = run(&mut d, &pkts);
        assert!(a.iter().any(|a| a.kind == "host_sweep"));
        assert!(a.iter().any(|a| a.kind == "syn_rate"));
    }

    #[test]
    fn stealth_scans_and_normal_traffic() {
        let mut d = PortScanDetector::new(&PortScan::default());
        let mut pkts = Vec::new();
        for (i, flags) in [TcpFlags::FIN, 0, 0x29].into_iter().enumerate() {
            for p in 0..3 {
                pkts.push(syn(
                    u64::try_from(i).unwrap() * 100 + p,
                    [10, 0, 0, 7],
                    [10, 0, 0, 1],
                    100 + u16::try_from(p).unwrap(),
                    flags,
                ));
            }
        }
        for p in 0..50 {
            pkts.push(syn(
                500 + p,
                [10, 0, 0, 8],
                [10, 0, 0, 1],
                443,
                TcpFlags::ACK | TcpFlags::PSH,
            ));
        }
        let kinds: Vec<_> = run(&mut d, &pkts).iter().map(|a| a.kind).collect();
        assert_eq!(kinds, vec!["fin_scan", "null_scan", "xmas_scan"]);
    }

    #[test]
    fn ignored_source() {
        let cfg = PortScan {
            ignore_sources: vec![IpAddr::from([10, 0, 0, 66])],
            ..PortScan::default()
        };
        let mut d = PortScanDetector::new(&cfg);
        let pkts: Vec<_> = (1..=30)
            .map(|p| {
                syn(
                    u64::from(p),
                    [10, 0, 0, 66],
                    [10, 0, 0, 1],
                    p,
                    TcpFlags::SYN,
                )
            })
            .collect();
        assert_eq!(run(&mut d, &pkts).len(), 0);
    }
}
