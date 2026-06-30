# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-04

### Added

- Live capture from Linux `AF_PACKET` raw sockets with optional promiscuous mode.
- Offline replay of pcap (µs/ns, both byte orders) and pcapng files without libpcap,
  with optional real-time pacing (`--speed`).
- Zero-copy parsers for Ethernet (802.1Q/802.1ad), ARP, IPv4, IPv6 (extension
  headers), TCP, UDP, ICMP/ICMPv6 and DNS (with compression-loop protection).
- Port-scan detector: SYN scans, host sweeps, SYN rate and FIN/NULL/XMAS stealth
  scans over sliding windows.
- ARP-spoofing detector: binding changes, static-binding violations, sender
  mismatches and gratuitous-ARP floods.
- Persistent device inventory with an embedded OUI vendor table, new-device and
  allowlist-based rogue-device alerts.
- DNS anomaly detector: long names, high-entropy subdomains, NXDOMAIN bursts.
- TOML rule configuration with validation and an annotated example file.
- JSON-lines and RFC 5424 syslog (Unix socket or UDP) alert sinks, per-alert cooldown.
- Multithreaded capture, parse, detect and sink pipeline with bounded channels and
  drop counters.
- ratatui terminal dashboard with hosts, alerts, packet rate and protocol mix.
- Synthetic pcap fixtures for every detector, plus property, end-to-end and CLI tests.

[Unreleased]: https://github.com/bekirhankarakurt/home-network-ids/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bekirhankarakurt/home-network-ids/releases/tag/v1.0.0
