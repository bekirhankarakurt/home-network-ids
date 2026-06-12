//! Home network intrusion detection for Linux.
//!
//! `hnids` captures traffic from an `AF_PACKET` raw socket or replays
//! pcap/pcapng files (parsed natively, no libpcap), decodes
//! Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP/DNS with zero-copy views and runs four
//! detectors:
//!
//! | detector    | finds                                                   |
//! |-------------|---------------------------------------------------------|
//! | `portscan`  | SYN/FIN/NULL/XMAS scans, host sweeps, SYN rate spikes   |
//! | `arp`       | IP-MAC binding changes, gratuitous ARP floods           |
//! | `inventory` | new and non-allowlisted devices (persistent inventory)  |
//! | `dns`       | very long / high-entropy names, NXDOMAIN bursts         |
//!
//! # Example
//!
//! ```
//! use std::sync::{atomic::AtomicBool, Arc};
//! use home_network_ids::{capture, config::Config, detect::Engine, oui::OuiTable,
//!     pipeline::{Options, Pipeline}, sink::Collector, synth};
//!
//! let bytes = synth::encode("scan.pcap", &synth::portscan()).unwrap();
//! let source = capture::open_reader(std::io::Cursor::new(bytes)).unwrap();
//! let mut config = Config::default();
//! config.inventory.enabled = false;
//! let engine = Engine::from_config(&config, Arc::new(OuiTable::builtin())).unwrap();
//! let alerts = Collector::default();
//! let pipeline = Pipeline::start(source, engine, vec![Box::new(alerts.clone())],
//!     Options::default(), Arc::new(AtomicBool::new(false))).unwrap();
//! let report = pipeline.join().unwrap();
//! assert!(report.counters.parse_errors == 0);
//! assert!(alerts.alerts().iter().any(|a| a.kind == "syn_scan"));
//! ```

#![deny(unsafe_code)]

pub mod capture;
pub mod packet;
pub mod time;
