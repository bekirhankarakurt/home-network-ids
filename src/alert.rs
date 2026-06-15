//! Alert records emitted by detectors.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::packet::MacAddr;
use crate::time::Timestamp;

/// Alert severity, ordered from least to most severe.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational.
    Info,
    /// Worth a look.
    #[default]
    Low,
    /// Suspicious.
    Medium,
    /// Likely hostile.
    High,
    /// Active attack on a trusted binding.
    Critical,
}

impl Severity {
    /// All severities, ascending.
    pub const ALL: [Self; 5] = [
        Self::Info,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];

    /// Lower-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// RFC 5424 syslog severity number.
    pub fn syslog_level(self) -> u8 {
        match self {
            Self::Info => 6,
            Self::Low => 5,
            Self::Medium => 4,
            Self::High => 3,
            Self::Critical => 2,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One detection result, serialised as a single JSON line.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alert {
    /// Packet time that triggered the alert.
    pub ts: Timestamp,
    /// Detector name (`portscan`, `arp`, `inventory`, `dns`).
    pub detector: &'static str,
    /// Specific finding, e.g. `syn_scan`.
    pub kind: &'static str,
    /// Severity.
    pub severity: Severity,
    /// Offending IP, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<IpAddr>,
    /// Offending MAC, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_mac: Option<MacAddr>,
    /// Human-readable summary.
    pub message: String,
    /// Detector-specific evidence.
    pub details: Map<String, Value>,
    /// Key used to suppress duplicates during the cooldown period.
    #[serde(skip)]
    pub dedup_key: String,
}

impl Alert {
    /// Starts an alert; the dedup key defaults to `kind` plus the source.
    pub fn new(
        ts: Timestamp,
        detector: &'static str,
        kind: &'static str,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            ts,
            detector,
            kind,
            severity,
            src_ip: None,
            src_mac: None,
            message: message.into(),
            details: Map::new(),
            dedup_key: kind.to_owned(),
        }
    }

    /// Sets the source IP and extends the dedup key with it.
    #[must_use]
    pub fn ip(mut self, ip: IpAddr) -> Self {
        self.src_ip = Some(ip);
        self.dedup_key = format!("{}|{ip}", self.dedup_key);
        self
    }

    /// Sets the source MAC and extends the dedup key with it.
    #[must_use]
    pub fn mac(mut self, mac: MacAddr) -> Self {
        self.src_mac = Some(mac);
        self.dedup_key = format!("{}|{mac}", self.dedup_key);
        self
    }

    /// Adds a detail field.
    #[must_use]
    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details.insert(key.to_owned(), value.into());
        self
    }

    /// Appends extra context to the dedup key.
    #[must_use]
    pub fn dedup(mut self, extra: impl fmt::Display) -> Self {
        self.dedup_key = format!("{}|{extra}", self.dedup_key);
        self
    }

    /// Serialises to a compact JSON line (without newline).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"alert serialisation failed: {e}\"}}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape() {
        let a = Alert::new(Timestamp(0), "portscan", "syn_scan", Severity::High, "scan")
            .ip("10.0.0.5".parse().unwrap())
            .detail("ports", 42);
        let v: Value = serde_json::from_str(&a.to_json()).unwrap();
        assert_eq!(v["severity"], "high");
        assert_eq!(v["src_ip"], "10.0.0.5");
        assert_eq!(v["details"]["ports"], 42);
        assert!(v.get("src_mac").is_none());
        assert!(v.get("dedup_key").is_none());
        assert_eq!(a.dedup_key, "syn_scan|10.0.0.5");
    }

    #[test]
    fn severity_order() {
        assert!(Severity::Critical > Severity::High);
        assert_eq!(Severity::Medium.syslog_level(), 4);
        assert_eq!(Severity::ALL.len(), 5);
    }
}
