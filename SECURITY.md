# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | yes       |
| < 1.0   | no        |

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/bekirhankarakurt/home-network-ids/security/advisories/new).
Include:

- the affected version or commit,
- a description of the issue and its impact,
- steps to reproduce, ideally with a minimal pcap file.

You can expect an acknowledgement within 7 days. A fix or mitigation is
targeted within 30 days, depending on severity. Credit is given in the release
notes unless you prefer otherwise.

## Scope

`hnids` parses untrusted network traffic and capture files, so the following
are in scope:

- panics, infinite loops or unbounded memory growth triggered by crafted
  packets or capture files,
- memory-safety issues in the `AF_PACKET` FFI (`src/capture/live.rs`),
- detection bypasses that defeat a documented rule with default settings.

## Hardening notes

- Grant only `CAP_NET_RAW` (and `CAP_NET_ADMIN` for promiscuous mode) instead
  of running as root.
- The inventory file and alert log may contain device identifiers. Protect
  them with appropriate file permissions.
