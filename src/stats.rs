//! Live traffic statistics shared with the terminal dashboard.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::alert::{Alert, Severity};
use crate::oui::OuiTable;
use crate::packet::MacAddr;
use crate::summary::{PacketSummary, Proto};
use crate::time::Timestamp;

/// Seconds of per-second packet counts kept for the traffic sparkline.
pub const TIMELINE_SECS: usize = 120;
/// Most recent alerts kept for display.
pub const RECENT_ALERTS: usize = 500;
const MAX_HOSTS: usize = 4096;

/// Per-MAC traffic counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostStats {
    /// Hardware address.
    pub mac: MacAddr,
    /// Vendor from the OUI table.
    pub vendor: Option<String>,
    /// Most recent IP address used.
    pub ip: Option<IpAddr>,
    /// Frames sent.
    pub packets: u64,
    /// Bytes sent.
    pub bytes: u64,
    /// Last frame time.
    pub last_seen: Timestamp,
}

/// Aggregated counters for the dashboard.
#[derive(Debug)]
pub struct Stats {
    oui: Arc<OuiTable>,
    hosts: HashMap<MacAddr, HostStats>,
    proto: HashMap<Proto, u64>,
    timeline: VecDeque<(u64, u64)>,
    alerts: VecDeque<Alert>,
    by_severity: [u64; 5],
    /// Frames observed.
    pub packets: u64,
    /// Bytes observed.
    pub bytes: u64,
    /// Time of the most recent frame.
    pub last_ts: Timestamp,
}

/// Thread-safe handle to [`Stats`].
#[derive(Debug, Clone)]
pub struct SharedStats(Arc<Mutex<Stats>>);

impl SharedStats {
    /// New, empty statistics.
    pub fn new(oui: Arc<OuiTable>) -> Self {
        Self(Arc::new(Mutex::new(Stats::new(oui))))
    }

    /// Locks the statistics; a poisoned lock is recovered since the data is
    /// only counters.
    pub fn lock(&self) -> MutexGuard<'_, Stats> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Stats {
    /// New, empty statistics.
    pub fn new(oui: Arc<OuiTable>) -> Self {
        Self {
            oui,
            hosts: HashMap::new(),
            proto: HashMap::new(),
            timeline: VecDeque::new(),
            alerts: VecDeque::new(),
            by_severity: [0; 5],
            packets: 0,
            bytes: 0,
            last_ts: Timestamp(0),
        }
    }

    /// Accounts one packet.
    pub fn observe(&mut self, pkt: &PacketSummary) {
        let len = pkt.len as u64;
        self.packets += 1;
        self.bytes += len;
        self.last_ts = self.last_ts.max(pkt.ts);
        *self.proto.entry(pkt.proto).or_insert(0) += 1;

        let sec = pkt.ts.secs();
        match self.timeline.back_mut() {
            Some((s, n)) if *s == sec => *n += 1,
            Some((s, _)) if *s > sec => {}
            _ => {
                self.timeline.push_back((sec, 1));
                while self.timeline.len() > TIMELINE_SECS {
                    self.timeline.pop_front();
                }
            }
        }

        if !pkt.src_mac.is_unicast() {
            return;
        }
        if self.hosts.len() >= MAX_HOSTS && !self.hosts.contains_key(&pkt.src_mac) {
            return;
        }
        let oui = &self.oui;
        let host = self.hosts.entry(pkt.src_mac).or_insert_with(|| HostStats {
            mac: pkt.src_mac,
            vendor: oui.lookup(pkt.src_mac).map(str::to_owned),
            ip: None,
            packets: 0,
            bytes: 0,
            last_seen: pkt.ts,
        });
        host.packets += 1;
        host.bytes += len;
        host.last_seen = host.last_seen.max(pkt.ts);
        let ip = pkt
            .arp
            .map(|a| IpAddr::V4(a.sender_ip))
            .or(pkt.src_ip)
            .filter(|ip| crate::detect::inventory::is_local_ip(*ip));
        // Prefer an IPv4 address for display; IPv6 only fills an empty slot.
        if ip.is_some_and(|ip| ip.is_ipv4() || host.ip.is_none()) {
            host.ip = ip;
        }
    }

    /// Records an emitted alert.
    pub fn push_alert(&mut self, alert: Alert) {
        self.by_severity[alert.severity as usize] += 1;
        if self.alerts.len() >= RECENT_ALERTS {
            self.alerts.pop_front();
        }
        self.alerts.push_back(alert);
    }

    /// Hosts sorted by packets sent, descending.
    pub fn top_hosts(&self, n: usize) -> Vec<&HostStats> {
        let mut v: Vec<_> = self.hosts.values().collect();
        v.sort_by(|a, b| b.packets.cmp(&a.packets).then(a.mac.cmp(&b.mac)));
        v.truncate(n);
        v
    }

    /// Number of distinct unicast hosts seen.
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Packet counts per protocol class, in [`Proto::ALL`] order.
    pub fn protocols(&self) -> Vec<(Proto, u64)> {
        Proto::ALL
            .iter()
            .map(|p| (*p, self.proto.get(p).copied().unwrap_or(0)))
            .collect()
    }

    /// Packets per second for the last `n` seconds of capture time, oldest first.
    pub fn timeline(&self, n: usize) -> Vec<u64> {
        let Some(&(last, _)) = self.timeline.back() else {
            return Vec::new();
        };
        let n64 = n as u64;
        let first = last.saturating_sub(n64.saturating_sub(1));
        let mut out = vec![0u64; usize::try_from(last - first + 1).unwrap_or(n)];
        for &(s, c) in &self.timeline {
            if s >= first {
                if let Some(slot) = out.get_mut(usize::try_from(s - first).unwrap_or(usize::MAX)) {
                    *slot = c;
                }
            }
        }
        out
    }

    /// Recent alerts, newest first.
    pub fn recent_alerts(&self) -> impl Iterator<Item = &Alert> {
        self.alerts.iter().rev()
    }

    /// Alert count for `severity`.
    pub fn alerts_with(&self, severity: Severity) -> u64 {
        self.by_severity[severity as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(secs: u64, mac: u8) -> PacketSummary {
        PacketSummary {
            ts: Timestamp::from_secs_micros(secs, 0),
            len: 100,
            src_mac: MacAddr([0xb8, 0x27, 0xeb, 0, 0, mac]),
            dst_mac: MacAddr::BROADCAST,
            vlan: None,
            proto: Proto::Udp,
            src_ip: Some(IpAddr::from([192, 168, 1, mac])),
            dst_ip: None,
            tcp: None,
            udp: Some((1, 2)),
            arp: None,
            dns: None,
        }
    }

    #[test]
    fn aggregates() {
        let mut s = Stats::new(Arc::new(OuiTable::builtin()));
        for (t, m) in [(10, 1), (10, 1), (12, 2), (12, 1)] {
            s.observe(&pkt(t, m));
        }
        assert_eq!((s.packets, s.bytes, s.host_count()), (4, 400, 2));
        let top = s.top_hosts(5);
        assert_eq!(top[0].packets, 3);
        assert_eq!(top[0].vendor.as_deref(), Some("Raspberry Pi"));
        assert_eq!(s.timeline(5), vec![0, 0, 2, 0, 2]);
        assert_eq!(s.protocols()[1], (Proto::Udp, 4));
        s.push_alert(Alert::new(Timestamp(0), "x", "y", Severity::High, "m"));
        assert_eq!(s.alerts_with(Severity::High), 1);
        assert_eq!(s.recent_alerts().count(), 1);
    }
}
