# home-network-ids

**A single-binary intrusion detection system for your home LAN: catches port scans, ARP spoofing, unknown devices and DNS tunnelling from a raw socket or a pcap file, with no libpcap and no runtime dependencies.**

[![CI](https://github.com/bekirhankarakurt/home-network-ids/actions/workflows/ci.yml/badge.svg)](https://github.com/bekirhankarakurt/home-network-ids/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](#requirements)

## Why

- **See what is on your network.** A persistent MAC inventory with an embedded vendor table reports every new or non-allowlisted device.
- **Catch the classic LAN attacks.** It detects SYN/FIN/NULL/XMAS scans, host sweeps, ARP cache poisoning, gratuitous-ARP floods, DNS tunnelling and DGA-style NXDOMAIN bursts.
- **Small and auditable.** About 7k lines of Rust, tests included. Packets are parsed in place with zero-copy views, and `unsafe` appears only in the `AF_PACKET` socket FFI, where each block has a `SAFETY:` comment.
- **Built for automation.** Alerts are JSON lines (plus optional syslog). Rules live in TOML. Results are deterministic offline replay, so you can regression-test rules in CI.
- **Watch it live.** The ratatui dashboard shows hosts, alerts, packet rate and protocol mix in the terminal.

## Demo

Replaying the bundled ARP-spoofing fixture and keeping only high-severity alerts:

```console
$ hnids replay tests/fixtures/arp_spoof.pcap --min-severity high -q
{"ts":"2026-03-14T09:00:01.016000Z","detector":"arp","kind":"arp_binding_change","severity":"high","src_ip":"192.168.1.1","src_mac":"de:ad:be:ef:00:66","message":"192.168.1.1 moved from 38:10:d5:aa:00:01 to de:ad:be:ef:00:66 (possible ARP spoofing)","details":{"new_mac":"de:ad:be:ef:00:66","old_mac":"38:10:d5:aa:00:01"}}
```

## Quick start (60 seconds)

```bash
git clone https://github.com/bekirhankarakurt/home-network-ids && cd home-network-ids
```

```bash
cargo build --release
```

```bash
./target/release/hnids replay tests/fixtures/mixed.pcapng --dashboard --speed 2
```

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/hnids
```

```bash
./target/release/hnids live -i eth0 --dashboard -o alerts.jsonl
```

Press `q` to leave the dashboard. Without `--dashboard`, alerts stream to stdout and a summary goes to stderr when the run ends.

## Requirements

| Requirement | Version / note |
|---|---|
| OS | Linux (`AF_PACKET`). Offline replay also builds on other Unix systems |
| Rust | 1.85 or newer (edition 2021), stable toolchain |
| Privileges (live mode only) | `CAP_NET_RAW` (+ `CAP_NET_ADMIN` for promiscuous mode) or root |
| Link type | Ethernet (`LINKTYPE_ETHERNET`, incl. 802.1Q/802.1ad VLAN tags) |
| Runtime libraries | none (no libpcap) |

| Build option | Command | Effect |
|---|---|---|
| Debug | `cargo build` | Fast compile, with debug assertions |
| Release | `cargo build --release` | Thin LTO, stripped binary |
| Install | `cargo install --path .` | Puts `hnids` in `~/.cargo/bin` |
| Fixtures | `cargo run --example gen_fixtures` | Regenerates `tests/fixtures/*` |
| API docs | `cargo doc --no-deps --open` | Library documentation |

## Usage

| Command | Purpose |
|---|---|
| `hnids live -i <IF>` | Capture from an interface (`--no-promisc` to stay non-promiscuous) |
| `hnids replay <FILE>` | Replay `.pcap` / `.pcapng` (`--speed N` for N x real time) |
| `hnids inventory` | Print known devices (`--json` for machine output) |
| `hnids config default` | Print the annotated default configuration |
| `hnids config check <FILE>` | Validate a configuration file |

Options shared by `live` and `replay`:

| Option | Default | Description |
|---|---|---|
| `-c, --config <FILE>` | built-in defaults | TOML rule file |
| `-o, --alerts <FILE>` | stdout | Append JSON-lines alerts to a file (`-` = stdout) |
| `--min-severity <LEVEL>` | `low` | `info`, `low`, `medium`, `high`, `critical` |
| `--syslog <TARGET>` | off | `unix:/dev/log` or `udp:HOST:PORT` (RFC 5424) |
| `--inventory <FILE>` | `hnids-inventory.json` | Persistent device inventory |
| `-d, --dashboard` | off | Terminal UI; alerts go only to the UI unless `-o FILE` is given |
| `--fail-on-alert` | off | Exit with status `2` if any alert was emitted |
| `-q, --quiet` | off | No summary on stderr |

### Recipes

**1. Run as a daemon on a Raspberry Pi and forward to syslog**

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/hnids
hnids live -i eth0 -c /etc/hnids.toml --inventory /var/lib/hnids/inventory.json \
  -o /var/log/hnids/alerts.jsonl --syslog unix:/dev/log --min-severity medium -q
```

**2. Learn your devices first, then switch to allowlist mode**

```bash
hnids live -i eth0 --inventory inv.json -q > /dev/null   # Ctrl-C after a day
hnids inventory --inventory inv.json --json | jq -r '.devices | keys[]'
```

Paste the MACs into `allowlist = [...]` under `[inventory]`. From then on, any other device raises a `rogue_device` alert.

**3. Pin your router so ARP poisoning is critical**

```toml
[arp.static_bindings]
"192.168.1.1" = "38:10:d5:aa:00:01"
```

**4. Triage a capture from tcpdump/Wireshark**

```bash
sudo tcpdump -i wlan0 -w home.pcap -c 50000
hnids replay home.pcap --inventory /tmp/scratch.json | jq -r '[.severity,.kind,.message] | @tsv'
```

**5. Regression-test your rules in CI**

```bash
hnids replay tests/fixtures/portscan.pcap -c hnids.example.toml --min-severity high --fail-on-alert -q -o /dev/null
test $? -eq 2   # the scan must still be detected
```

## Architecture

```
               bounded           bounded              bounded
 ┌─────────┐   channel  ┌───────┐ channel  ┌────────┐ channel  ┌──────────┐
 │ capture │──Frame────▶│ parse │──Packet─▶│ detect │──Alert──▶│   sink   │
 │ thread  │            │thread │ Summary  │ thread │          │  thread  │
 └────┬────┘            └───┬───┘          └───┬────┘          └────┬─────┘
      │ AF_PACKET socket    │ zero-copy        │ portscan  arp      │ JSON lines
      │ pcap / pcapng       │ Ethernet→DNS     │ inventory dns      │ syslog
      │                     │ views            │ + cooldown         │ dashboard
      └──── atomic counters: captured, dropped, parse_errors, alerts ──┘
                                              │
                                     SharedStats (Mutex) ──▶ ratatui dashboard
```

| Decision | Trade-off |
|---|---|
| Own pcap/pcapng readers, no libpcap | No C dependency or BPF filters. Parsing is fuzzed with property tests |
| Zero-copy views, then an owned `PacketSummary` | Parsing never allocates, and only about 100 bytes per packet cross threads, so capture buffers are released immediately |
| Bounded `std::sync::mpsc` channels | Replay applies back-pressure and is lossless. Live capture drops and counts instead of stalling the socket |
| Packet timestamps drive all windows | Replays are deterministic and testable. Live mode uses the receive time |
| Per-key cooldown in the engine | One alert per (kind, source) per 60 s by default. Repeats are counted as `suppressed` |
| Hard caps on per-source state | Memory stays bounded under floods, at the cost of approximate counts above 65k events per window |
| `recv` with a 200 ms timeout instead of a `PACKET_MMAP` ring | Simpler and good for home links (replay runs at about 850k packets/s on 4 vCPUs). A ring buffer is on the roadmap |

## Detection rules

| Detector | Alert `kind` | Severity | Fires when (defaults) |
|---|---|---|---|
| portscan | `syn_scan` | high | ≥ 20 distinct `host:port` SYN targets from one IP in 10 s |
| portscan | `host_sweep` | medium | ≥ 16 distinct hosts SYN-probed from one IP in 10 s |
| portscan | `syn_rate` | high | ≥ 100 SYN/s averaged over the window |
| portscan | `fin_scan` / `null_scan` / `xmas_scan` | high | ≥ 3 FIN-only / no-flag / FIN+PSH+URG probes in 10 s |
| arp | `arp_binding_change` | high | A learned IP→MAC binding moves to a new MAC |
| arp | `arp_static_mismatch` | critical | ARP contradicts `[arp.static_bindings]` |
| arp | `arp_sender_mismatch` | medium | Ethernet source ≠ ARP sender MAC |
| arp | `gratuitous_arp_flood` | medium | ≥ 5 gratuitous ARPs from one MAC in 10 s |
| inventory | `new_device` | medium | First sighting of a unicast MAC |
| inventory | `rogue_device` | high | MAC not in a non-empty `allowlist` |
| dns | `dns_long_name` | medium | Query name > 100 characters |
| dns | `dns_high_entropy` | medium | Subdomain ≥ 24 chars with ≥ 4.0 bits/char Shannon entropy |
| dns | `dns_nxdomain_burst` | high | ≥ 10 NXDOMAIN answers to one client in 30 s |

### Configuration format

Every key is optional, and unknown keys are rejected. `hnids config default` prints the full annotated file ([`hnids.example.toml`](hnids.example.toml)).

| Section | Keys |
|---|---|
| `[general]` | `alert_cooldown_secs` |
| `[pipeline]` | `channel_capacity` |
| `[portscan]` | `enabled`, `window_secs`, `port_threshold`, `host_threshold`, `syn_rate_threshold`, `stealth_threshold`, `ignore_sources` |
| `[arp]` | `enabled`, `gratuitous_window_secs`, `gratuitous_threshold`, `[arp.static_bindings]` |
| `[inventory]` | `enabled`, `path`, `alert_on_new`, `allowlist`, `oui_file` |
| `[dns]` | `enabled`, `max_name_len`, `entropy_threshold`, `entropy_min_len`, `nxdomain_window_secs`, `nxdomain_threshold`, `ignore_suffixes` |
| `[output]` | `min_severity`, `alerts`, `[output.syslog]` `enabled` / `target` / `facility` |

### Alert format

| Field | Type | Example |
|---|---|---|
| `ts` | RFC 3339 UTC (packet time) | `2026-03-14T09:00:01.016000Z` |
| `detector` | string | `arp` |
| `kind` | string | `arp_binding_change` |
| `severity` | string | `high` |
| `src_ip` / `src_mac` | string, optional | `192.168.1.1` / `de:ad:be:ef:00:66` |
| `message` | string | human-readable summary |
| `details` | object | detector evidence (`old_mac`, `sample_ports`, `entropy`, ...) |

## Testing

```bash
cargo test
```

| Layer | What is covered |
|---|---|
| Unit tests (`src/**`) | Every parser, sliding windows, each detector, sinks (UDP + Unix syslog round trips), dashboard rendering via `TestBackend` |
| Property tests (`tests/parser_props.rs`) | Random and mutated bytes never panic packet, DNS, pcap, pcapng or TOML parsers. Builder→parser round trips for TCP, DNS, pcap and MAC |
| Fixtures (`tests/fixtures.rs`) | Each committed pcap triggers its detector end to end. The files must match the `synth` generator byte for byte |
| CLI (`tests/cli.rs`) | Exit codes, JSON output, inventory listing, config validation, error messages |
| CI | fmt, clippy pedantic `-D warnings`, tests on stable + MSRV 1.85, rustdoc, cargo-deny, cargo-audit |

The fixtures in `tests/fixtures/` (`portscan.pcap`, `arp_spoof.pcap`, `new_device.pcap`, `dns_anomaly.pcap`, `mixed.pcapng`) are generated by `src/synth.rs` with valid checksums and open cleanly in Wireshark.

## Troubleshooting / FAQ

**`socket(AF_PACKET) failed: Operation not permitted`**
Live capture needs `CAP_NET_RAW`. Use `CAP_NET_ADMIN` too if you want promiscuous mode. Grant both once per build:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v hnids)"
getcap "$(command -v hnids)"
```

File capabilities are cleared when the binary is rebuilt or copied, and they are ignored on `nosuid` mounts. With systemd, use `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` instead. Without `CAP_NET_ADMIN`, run with `--no-promisc`.

**`if_nametoindex failed: No such device`**
The interface name is wrong. List interfaces with `ip -br link`.

**I only see my own traffic.**
On a switched network, a host only sees its own frames plus broadcast and multicast. ARP and new-device detection still work, because ARP is broadcast. To see everything, run `hnids` on the router, on a mirror/SPAN port, or on a bridge.

**`unsupported link type 113`**
That capture used `-i any` (Linux cooked capture). Re-capture on a specific Ethernet or Wi-Fi interface.

**Too many `new_device` alerts on the first run.**
That is expected: the inventory starts empty. Run once with `alert_on_new = false`, or accept the first batch. Phones with MAC randomisation show up as `randomised MAC`.

**The dashboard reports `dropped > 0`.**
The detect stage could not keep up. Raise `[pipeline] channel_capacity` or use a release build.

**Where is state stored?**
Only in the inventory JSON (`--inventory`), which is written atomically every 30 s and on exit.

## Project layout

```
.
├── src/
│   ├── main.rs            # CLI (clap): live, replay, inventory, config
│   ├── lib.rs             # library root and crate docs
│   ├── packet/            # zero-copy parsers: ethernet, arp, ipv4, ipv6, tcp, udp, icmp, dns
│   ├── capture/           # pcap + pcapng readers/writers, AF_PACKET live capture (only unsafe code)
│   ├── summary.rs         # owned per-packet summary handed to detectors
│   ├── detect/            # engine + cooldown, sliding windows, portscan/arp/inventory/dns
│   ├── pipeline.rs        # capture → parse → detect → sink threads, counters
│   ├── sink/              # JSON lines, RFC 5424 syslog, in-memory collector
│   ├── stats.rs           # host/protocol/timeline aggregates for the dashboard
│   ├── dashboard.rs       # ratatui terminal UI
│   ├── config.rs          # TOML schema, defaults, validation
│   ├── oui.rs             # MAC vendor lookup (embedded table + IEEE csv)
│   ├── alert.rs, time.rs  # alert model, timestamps
│   └── synth.rs           # synthetic traffic and scenario generator for fixtures
├── data/oui.csv           # curated vendor prefixes embedded at build time
├── examples/gen_fixtures.rs
├── tests/                 # fixtures/, end-to-end, CLI and property tests
├── hnids.example.toml     # annotated default configuration
├── deny.toml              # cargo-deny policy
└── .github/workflows/     # CI
```

## Roadmap

- [x] pcap / pcapng replay without libpcap
- [x] `AF_PACKET` live capture with promiscuous mode
- [x] Port-scan, ARP-spoofing, inventory and DNS detectors
- [x] JSON lines, syslog and terminal dashboard
- [ ] `PACKET_MMAP` (TPACKET_V3) ring buffer for multi-gigabit links
- [ ] DHCP fingerprinting for device type identification
- [ ] Rogue DHCP server and IPv6 router advertisement detection
- [ ] Prometheus metrics endpoint
- [ ] Linux cooked capture (`LINKTYPE_LINUX_SLL`) support

## License

MIT, see [LICENSE](LICENSE).

Bekirhan Karakurt - [github.com/bekirhankarakurt](https://github.com/bekirhankarakurt)
