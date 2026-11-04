//! TOML rule configuration.
//!
//! Every section and field is optional; missing values fall back to the
//! defaults documented in `hnids.example.toml`. Unknown keys are rejected so
//! typos do not silently disable a rule.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::alert::Severity;
use crate::packet::MacAddr;

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// File path.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// The file is not valid TOML for this schema.
    #[error("invalid configuration: {0}")]
    Parse(#[from] toml::de::Error),
    /// A value is out of range.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Top-level configuration.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Settings shared by all detectors.
    pub general: General,
    /// Capture pipeline sizing.
    pub pipeline: Pipeline,
    /// Port-scan detector.
    pub portscan: PortScan,
    /// ARP-spoofing detector.
    pub arp: Arp,
    /// Device inventory / rogue-device detector.
    pub inventory: Inventory,
    /// DNS anomaly detector.
    pub dns: Dns,
    /// Alert outputs.
    pub output: Output,
}

/// `[general]`
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    /// Identical alerts (same kind and source) are suppressed for this long.
    pub alert_cooldown_secs: u64,
}

impl Default for General {
    fn default() -> Self {
        Self {
            alert_cooldown_secs: 60,
        }
    }
}

/// `[pipeline]`
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Pipeline {
    /// Capacity of each bounded inter-stage channel, in packets.
    pub channel_capacity: usize,
}

impl Default for Pipeline {
    fn default() -> Self {
        Self {
            channel_capacity: 8192,
        }
    }
}

/// `[portscan]`
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PortScan {
    /// Enable the detector.
    pub enabled: bool,
    /// Sliding-window length in seconds.
    pub window_secs: u64,
    /// Distinct (host, port) targets probed by one source within the window.
    pub port_threshold: usize,
    /// Distinct hosts probed by one source within the window (host sweep).
    pub host_threshold: usize,
    /// SYN probes per second averaged over the window.
    pub syn_rate_threshold: u32,
    /// FIN, NULL or XMAS probes of one type within the window.
    pub stealth_threshold: usize,
    /// Sources never reported (e.g. your own vulnerability scanner).
    pub ignore_sources: Vec<IpAddr>,
}

impl Default for PortScan {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: 10,
            port_threshold: 20,
            host_threshold: 16,
            syn_rate_threshold: 100,
            stealth_threshold: 3,
            ignore_sources: Vec::new(),
        }
    }
}

/// `[arp]`
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Arp {
    /// Enable the detector.
    pub enabled: bool,
    /// Sliding window for counting gratuitous ARPs, in seconds.
    pub gratuitous_window_secs: u64,
    /// Gratuitous ARPs from one MAC within the window.
    pub gratuitous_threshold: usize,
    /// Known-good IP to MAC bindings (e.g. the router); violations are critical.
    pub static_bindings: BTreeMap<Ipv4Addr, MacAddr>,
}

impl Default for Arp {
    fn default() -> Self {
        Self {
            enabled: true,
            gratuitous_window_secs: 10,
            gratuitous_threshold: 5,
            static_bindings: BTreeMap::new(),
        }
    }
}

/// `[inventory]`
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Inventory {
    /// Enable the detector.
    pub enabled: bool,
    /// JSON file holding the persistent MAC inventory.
    pub path: PathBuf,
    /// Alert when a MAC is seen for the first time.
    pub alert_on_new: bool,
    /// If non-empty, any MAC not listed is reported as a rogue device.
    pub allowlist: Vec<MacAddr>,
    /// Optional IEEE `oui.csv` (or `PREFIX,Vendor` lines) extending the
    /// built-in vendor table.
    pub oui_file: Option<PathBuf>,
}

impl Default for Inventory {
    fn default() -> Self {
        Self {
            enabled: true,
            path: PathBuf::from("hnids-inventory.json"),
            alert_on_new: true,
            allowlist: Vec::new(),
            oui_file: None,
        }
    }
}

/// `[dns]`
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    /// Enable the detector.
    pub enabled: bool,
    /// Query names longer than this many characters are reported.
    pub max_name_len: usize,
    /// Shannon entropy (bits per character) of the subdomain part.
    pub entropy_threshold: f64,
    /// Minimum subdomain length before entropy is evaluated.
    pub entropy_min_len: usize,
    /// Sliding window for counting NXDOMAIN responses, in seconds.
    pub nxdomain_window_secs: u64,
    /// NXDOMAIN responses to one client within the window.
    pub nxdomain_threshold: usize,
    /// Domain suffixes never checked for length or entropy.
    pub ignore_suffixes: Vec<String>,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            enabled: true,
            max_name_len: 100,
            entropy_threshold: 4.0,
            entropy_min_len: 24,
            nxdomain_window_secs: 30,
            nxdomain_threshold: 10,
            ignore_suffixes: vec!["in-addr.arpa".into(), "ip6.arpa".into()],
        }
    }
}

/// `[output]`
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Output {
    /// Alerts below this severity are not emitted.
    pub min_severity: Severity,
    /// JSON-lines destination: a file path, or `-` / unset for stdout.
    pub alerts: Option<PathBuf>,
    /// Optional syslog forwarding.
    pub syslog: Syslog,
}

/// `[output.syslog]`
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Syslog {
    /// Enable syslog forwarding.
    pub enabled: bool,
    /// `unix:/dev/log` or `udp:HOST:PORT`.
    pub target: String,
    /// Facility number (16 = local0).
    pub facility: u8,
}

impl Default for Syslog {
    fn default() -> Self {
        Self {
            enabled: false,
            target: "unix:/dev/log".into(),
            facility: 16,
        }
    }
}

impl Config {
    /// Parses and validates a TOML document.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for syntax errors, unknown keys or invalid values.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reads, parses and validates a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file is unreadable or invalid.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml(&text)
    }

    /// Checks value ranges.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] naming the first bad field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let checks: [(&str, bool); 11] = [
            (
                "pipeline.channel_capacity",
                self.pipeline.channel_capacity > 0,
            ),
            ("portscan.window_secs", self.portscan.window_secs > 0),
            ("portscan.port_threshold", self.portscan.port_threshold > 0),
            ("portscan.host_threshold", self.portscan.host_threshold > 0),
            (
                "portscan.syn_rate_threshold",
                self.portscan.syn_rate_threshold > 0,
            ),
            (
                "portscan.stealth_threshold",
                self.portscan.stealth_threshold > 0,
            ),
            (
                "arp.gratuitous_window_secs",
                self.arp.gratuitous_window_secs > 0,
            ),
            (
                "arp.gratuitous_threshold",
                self.arp.gratuitous_threshold > 0,
            ),
            (
                "dns.nxdomain_window_secs",
                self.dns.nxdomain_window_secs > 0,
            ),
            ("dns.nxdomain_threshold", self.dns.nxdomain_threshold > 0),
            (
                "dns.entropy_threshold",
                self.dns.entropy_threshold.is_finite() && self.dns.entropy_threshold > 0.0,
            ),
        ];
        for (field, ok) in checks {
            if !ok {
                return Err(ConfigError::Invalid(format!(
                    "{field} must be greater than zero"
                )));
            }
        }
        if self.output.syslog.facility > 23 {
            return Err(ConfigError::Invalid(
                "output.syslog.facility must be 0-23".into(),
            ));
        }
        Ok(())
    }

    /// The annotated example configuration, equal to the defaults.
    pub fn default_toml() -> &'static str {
        include_str!("../hnids.example.toml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_default() {
        assert_eq!(Config::from_toml("").unwrap(), Config::default());
    }

    #[test]
    fn partial_override() {
        let c = Config::from_toml(
            "[portscan]\nport_threshold = 5\nignore_sources = [\"192.168.1.10\"]\n\
             [arp.static_bindings]\n\"192.168.1.1\" = \"aa:bb:cc:dd:ee:ff\"\n",
        )
        .unwrap();
        assert_eq!(c.portscan.port_threshold, 5);
        assert_eq!(c.portscan.window_secs, 10);
        assert_eq!(c.arp.static_bindings.len(), 1);
    }

    #[test]
    fn rejects_unknown_and_invalid() {
        assert!(matches!(
            Config::from_toml("[portscan]\nport_treshold = 5"),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::from_toml("[portscan]\nwindow_secs = 0"),
            Err(ConfigError::Invalid(_))
        ));
        assert!(matches!(
            Config::from_toml("[output.syslog]\nfacility = 30"),
            Err(ConfigError::Invalid(_))
        ));
        assert!(Config::from_toml("[inventory]\nallowlist = [\"nope\"]").is_err());
    }

    #[test]
    fn example_file_matches_defaults() {
        let text = Config::default_toml();
        assert_eq!(Config::from_toml(text).unwrap(), Config::default());
    }
}
