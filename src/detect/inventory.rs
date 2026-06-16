//! Persistent device inventory and new/rogue device detection.
//!
//! Every unicast source MAC is recorded with its vendor, local IP addresses
//! and first/last-seen times. The inventory is stored as JSON and written
//! atomically (temp file + rename) at checkpoints.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::Detector;
use crate::alert::{Alert, Severity};
use crate::config::Inventory as InventoryConfig;
use crate::oui::OuiTable;
use crate::packet::MacAddr;
use crate::summary::PacketSummary;

const NAME: &str = "inventory";
const MAX_IPS_PER_DEVICE: usize = 16;
const FORMAT_VERSION: u32 = 1;

/// Inventory persistence errors.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// The file exists but could not be read or written.
    #[error("inventory {path}: {source}")]
    Io {
        /// File path.
        path: PathBuf,
        /// Cause.
        source: io::Error,
    },
    /// The file is not a valid inventory.
    #[error("inventory {path}: {source}")]
    Format {
        /// File path.
        path: PathBuf,
        /// Cause.
        source: serde_json::Error,
    },
}

/// One known device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Hardware address.
    pub mac: MacAddr,
    /// Vendor from the OUI table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Local addresses seen from this MAC.
    #[serde(default)]
    pub ips: BTreeSet<IpAddr>,
    /// First sighting, Unix seconds.
    pub first_seen: u64,
    /// Last sighting, Unix seconds.
    pub last_seen: u64,
    /// Frames seen from this MAC.
    #[serde(default)]
    pub packets: u64,
}

/// The on-disk inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    version: u32,
    devices: BTreeMap<MacAddr, Device>,
}

impl Inventory {
    /// Loads `path`; a missing file yields an empty inventory.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError`] if the file exists but is unreadable or invalid.
    pub fn load(path: &Path) -> Result<Self, InventoryError> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| InventoryError::Format {
                path: path.to_owned(),
                source,
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(InventoryError::Io {
                path: path.to_owned(),
                source,
            }),
        }
    }

    /// Writes the inventory atomically.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError::Io`] on write or rename failure.
    pub fn save(&self, path: &Path) -> Result<(), InventoryError> {
        let io_err = |source| InventoryError::Io {
            path: path.to_owned(),
            source,
        };
        let mut doc = self.clone();
        doc.version = FORMAT_VERSION;
        let json = serde_json::to_vec_pretty(&doc).map_err(|e| io_err(io::Error::other(e)))?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, json).map_err(io_err)?;
        std::fs::rename(&tmp, path).map_err(io_err)
    }

    /// Known devices ordered by MAC.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    /// Number of known devices.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// True if no devices are known.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

/// True for addresses that belong to the local network segment.
pub fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            first & 0xffc0 == 0xfe80 || first & 0xfe00 == 0xfc00
        }
    }
}

/// New/rogue device detector; see the module docs.
pub struct InventoryDetector {
    inventory: Inventory,
    path: PathBuf,
    oui: Arc<OuiTable>,
    alert_on_new: bool,
    allowlist: HashSet<MacAddr>,
    dirty: bool,
}

impl InventoryDetector {
    /// Loads the inventory named in `cfg`.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryError`] if an existing inventory file is invalid.
    pub fn open(cfg: &InventoryConfig, oui: Arc<OuiTable>) -> Result<Self, InventoryError> {
        Ok(Self {
            inventory: Inventory::load(&cfg.path)?,
            path: cfg.path.clone(),
            oui,
            alert_on_new: cfg.alert_on_new,
            allowlist: cfg.allowlist.iter().copied().collect(),
            dirty: false,
        })
    }

    /// The in-memory inventory.
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }

    fn observe_ip(device: &mut Device, ip: Option<IpAddr>) -> bool {
        match ip {
            Some(ip)
                if is_local_ip(ip)
                    && !device.ips.contains(&ip)
                    && device.ips.len() < MAX_IPS_PER_DEVICE =>
            {
                device.ips.insert(ip);
                true
            }
            _ => false,
        }
    }
}

impl Detector for InventoryDetector {
    fn name(&self) -> &'static str {
        NAME
    }

    fn inspect(&mut self, pkt: &PacketSummary, out: &mut Vec<Alert>) {
        let mac = pkt.src_mac;
        if !mac.is_unicast() {
            return;
        }
        let ip = pkt
            .arp
            .map(|a| IpAddr::V4(a.sender_ip))
            .filter(|ip| !ip.is_unspecified())
            .or(pkt.src_ip);
        let secs = pkt.ts.secs();
        if let Some(dev) = self.inventory.devices.get_mut(&mac) {
            dev.last_seen = dev.last_seen.max(secs);
            dev.packets += 1;
            Self::observe_ip(dev, ip);
            self.dirty = true;
            return;
        }

        let vendor = self.oui.lookup(mac).map(str::to_owned);
        let mut dev = Device {
            mac,
            vendor: vendor.clone(),
            ips: BTreeSet::new(),
            first_seen: secs,
            last_seen: secs,
            packets: 1,
        };
        Self::observe_ip(&mut dev, ip);
        let first_ip = dev.ips.iter().next().copied();
        self.inventory.devices.insert(mac, dev);
        self.dirty = true;

        let vendor_label = vendor.clone().unwrap_or_else(|| {
            if mac.is_locally_administered() {
                "randomised MAC".into()
            } else {
                "unknown vendor".into()
            }
        });
        let rogue = !self.allowlist.is_empty() && !self.allowlist.contains(&mac);
        if !rogue && !self.alert_on_new {
            return;
        }
        let (kind, severity, what) = if rogue {
            ("rogue_device", Severity::High, "Device not in allowlist")
        } else {
            ("new_device", Severity::Medium, "New device")
        };
        let mut alert = Alert::new(
            pkt.ts,
            NAME,
            kind,
            severity,
            format!(
                "{what}: {mac} ({vendor_label}){}",
                first_ip.map(|ip| format!(" at {ip}")).unwrap_or_default()
            ),
        )
        .mac(mac)
        .detail("vendor", vendor)
        .detail("locally_administered", mac.is_locally_administered());
        if let Some(ip) = first_ip {
            alert.src_ip = Some(ip);
        }
        out.push(alert);
    }

    fn checkpoint(&mut self) -> Result<(), String> {
        if !self.dirty {
            return Ok(());
        }
        self.inventory.save(&self.path).map_err(|e| e.to_string())?;
        self.dirty = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::Proto;
    use crate::time::Timestamp;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hnids-test-{}-{name}.json", std::process::id()))
    }

    fn frame(secs: u64, mac: &str, ip: Option<&str>) -> PacketSummary {
        PacketSummary {
            ts: Timestamp::from_secs_micros(secs, 0),
            len: 60,
            src_mac: mac.parse().unwrap(),
            dst_mac: MacAddr::BROADCAST,
            vlan: None,
            proto: Proto::OtherIp,
            src_ip: ip.map(|s| s.parse().unwrap()),
            dst_ip: None,
            tcp: None,
            udp: None,
            arp: None,
            dns: None,
        }
    }

    #[test]
    fn learns_persists_and_reloads() {
        let path = tmp_path("persist");
        let cfg = InventoryConfig {
            path: path.clone(),
            ..InventoryConfig::default()
        };
        let mut d = InventoryDetector::open(&cfg, Arc::new(OuiTable::builtin())).unwrap();
        let mut out = Vec::new();
        d.inspect(
            &frame(100, "b8:27:eb:00:00:01", Some("192.168.1.20")),
            &mut out,
        );
        d.inspect(&frame(200, "b8:27:eb:00:00:01", Some("8.8.8.8")), &mut out);
        d.inspect(&frame(300, "01:00:5e:00:00:01", None), &mut out);
        d.inspect(&frame(300, "06:11:22:33:44:55", None), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].kind, "new_device");
        assert!(out[0].message.contains("Raspberry Pi"));
        assert!(out[1].message.contains("randomised"));
        d.checkpoint().unwrap();

        let mut again = InventoryDetector::open(&cfg, Arc::new(OuiTable::builtin())).unwrap();
        let dev = again
            .inventory()
            .devices()
            .find(|d| d.mac.0[0] == 0xb8)
            .unwrap();
        assert_eq!((dev.first_seen, dev.last_seen, dev.packets), (100, 200, 2));
        assert_eq!(dev.ips.len(), 1);
        let mut out = Vec::new();
        again.inspect(&frame(400, "b8:27:eb:00:00:01", None), &mut out);
        assert!(out.is_empty());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn allowlist_flags_rogue() {
        let cfg = InventoryConfig {
            path: tmp_path("rogue"),
            alert_on_new: false,
            allowlist: vec!["b8:27:eb:00:00:01".parse().unwrap()],
            ..InventoryConfig::default()
        };
        let mut d = InventoryDetector::open(&cfg, Arc::new(OuiTable::default())).unwrap();
        let mut out = Vec::new();
        d.inspect(&frame(1, "b8:27:eb:00:00:01", None), &mut out);
        d.inspect(&frame(1, "b8:27:eb:00:00:02", None), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "rogue_device");
        assert_eq!(out[0].severity, Severity::High);
    }

    #[test]
    fn corrupt_file_is_error() {
        let path = tmp_path("corrupt");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(
            Inventory::load(&path),
            Err(InventoryError::Format { .. })
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn local_ip_ranges() {
        for (ip, local) in [
            ("10.1.2.3", true),
            ("169.254.1.1", true),
            ("8.8.8.8", false),
            ("fe80::1", true),
            ("fd00::1", true),
            ("2001:db8::1", false),
        ] {
            assert_eq!(is_local_ip(ip.parse().unwrap()), local, "{ip}");
        }
    }
}
