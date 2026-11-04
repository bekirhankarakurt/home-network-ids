//! Detection engine: runs every enabled detector on each packet and applies
//! alert cooldowns.

pub mod arp;
pub mod dns;
pub mod inventory;
pub mod portscan;
pub mod window;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::alert::Alert;
use crate::config::Config;
use crate::oui::OuiTable;
use crate::summary::PacketSummary;
use crate::time::Timestamp;

/// Maximum cooldown entries kept before old ones are pruned.
const MAX_COOLDOWN_KEYS: usize = 16_384;

/// A stateful packet inspector.
pub trait Detector: Send {
    /// Short identifier used in alerts.
    fn name(&self) -> &'static str;

    /// Inspects one packet and appends any findings to `out`.
    fn inspect(&mut self, pkt: &PacketSummary, out: &mut Vec<Alert>);

    /// Persists state; called periodically and at shutdown.
    ///
    /// # Errors
    ///
    /// Returns a description of the persistence failure.
    fn checkpoint(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// Runs detectors and suppresses repeated alerts.
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
    cooldown: Duration,
    last_fired: HashMap<String, Timestamp>,
    suppressed: u64,
    scratch: Vec<Alert>,
}

impl Engine {
    /// Builds every detector enabled in `config`.
    ///
    /// # Errors
    ///
    /// Returns an error if the inventory file exists but cannot be loaded.
    pub fn from_config(
        config: &Config,
        oui: Arc<OuiTable>,
    ) -> Result<Self, inventory::InventoryError> {
        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
        if config.portscan.enabled {
            detectors.push(Box::new(portscan::PortScanDetector::new(&config.portscan)));
        }
        if config.arp.enabled {
            detectors.push(Box::new(arp::ArpDetector::new(&config.arp)));
        }
        if config.inventory.enabled {
            detectors.push(Box::new(inventory::InventoryDetector::open(
                &config.inventory,
                oui,
            )?));
        }
        if config.dns.enabled {
            detectors.push(Box::new(dns::DnsDetector::new(&config.dns)));
        }
        Ok(Self::new(
            detectors,
            Duration::from_secs(config.general.alert_cooldown_secs),
        ))
    }

    /// Engine over an explicit detector list.
    pub fn new(detectors: Vec<Box<dyn Detector>>, cooldown: Duration) -> Self {
        Self {
            detectors,
            cooldown,
            last_fired: HashMap::new(),
            suppressed: 0,
            scratch: Vec::new(),
        }
    }

    /// Names of the active detectors.
    pub fn detector_names(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.name()).collect()
    }

    /// Alerts dropped by the cooldown so far.
    pub fn suppressed(&self) -> u64 {
        self.suppressed
    }

    /// Runs all detectors on `pkt`, appending alerts that pass the cooldown.
    pub fn process(&mut self, pkt: &PacketSummary, out: &mut Vec<Alert>) {
        self.scratch.clear();
        for d in &mut self.detectors {
            d.inspect(pkt, &mut self.scratch);
        }
        for alert in self.scratch.drain(..) {
            if let Some(&last) = self.last_fired.get(&alert.dedup_key) {
                if alert.ts.since(last) < self.cooldown {
                    self.suppressed += 1;
                    continue;
                }
            }
            if self.last_fired.len() >= MAX_COOLDOWN_KEYS {
                let cutoff = alert.ts.minus(self.cooldown);
                self.last_fired.retain(|_, t| *t >= cutoff);
            }
            self.last_fired.insert(alert.dedup_key.clone(), alert.ts);
            out.push(alert);
        }
    }

    /// Checkpoints every detector, collecting failures.
    pub fn checkpoint(&mut self) -> Vec<String> {
        self.detectors
            .iter_mut()
            .filter_map(|d| d.checkpoint().err().map(|e| format!("{}: {e}", d.name())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Severity;
    use crate::packet::MacAddr;
    use crate::summary::Proto;

    struct Always;

    impl Detector for Always {
        fn name(&self) -> &'static str {
            "always"
        }
        fn inspect(&mut self, pkt: &PacketSummary, out: &mut Vec<Alert>) {
            out.push(Alert::new(pkt.ts, "always", "hit", Severity::Low, "hit"));
        }
    }

    fn pkt(secs: u64) -> PacketSummary {
        PacketSummary {
            ts: Timestamp::from_secs_micros(secs, 0),
            len: 60,
            src_mac: MacAddr::ZERO,
            dst_mac: MacAddr::BROADCAST,
            vlan: None,
            proto: Proto::Other,
            src_ip: None,
            dst_ip: None,
            tcp: None,
            udp: None,
            arp: None,
            dns: None,
        }
    }

    #[test]
    fn cooldown_suppresses_repeats() {
        let mut e = Engine::new(vec![Box::new(Always)], Duration::from_secs(60));
        let mut out = Vec::new();
        for s in [0, 10, 59, 60, 61] {
            e.process(&pkt(s), &mut out);
        }
        assert_eq!(out.len(), 2);
        assert_eq!(e.suppressed(), 3);
        assert_eq!(e.detector_names(), vec!["always"]);
        assert!(e.checkpoint().is_empty());
    }
}
