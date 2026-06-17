//! RFC 5424 syslog output over a Unix datagram socket or UDP.

use std::io;
use std::net::UdpSocket;
use std::os::unix::net::UnixDatagram;

use super::AlertSink;
use crate::alert::Alert;

enum Transport {
    Unix(UnixDatagram, String),
    Udp(UdpSocket),
}

/// Sends each alert as one syslog message with the JSON as its body.
pub struct Syslog {
    transport: Transport,
    facility: u8,
    hostname: String,
    target: String,
}

/// Parses `unix:/path` or `udp:host:port`.
///
/// # Errors
///
/// Returns `InvalidInput` for any other form.
fn parse_target(target: &str) -> io::Result<(&str, &str)> {
    target
        .split_once(':')
        .filter(|(scheme, rest)| matches!(*scheme, "unix" | "udp") && !rest.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("syslog target {target:?} must be unix:/path or udp:host:port"),
            )
        })
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_owned())
        .ok()
        .filter(|h| !h.is_empty() && !h.contains(' '))
        .unwrap_or_else(|| "-".into())
}

impl Syslog {
    /// Connects to `target` (`unix:/dev/log` or `udp:192.168.1.10:514`).
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the target is malformed or unreachable.
    pub fn connect(target: &str, facility: u8) -> io::Result<Self> {
        let (scheme, rest) = parse_target(target)?;
        let transport = if scheme == "unix" {
            Transport::Unix(UnixDatagram::unbound()?, rest.to_owned())
        } else {
            let sock = UdpSocket::bind(("0.0.0.0", 0))?;
            sock.connect(rest)?;
            Transport::Udp(sock)
        };
        Ok(Self {
            transport,
            facility,
            hostname: hostname(),
            target: target.to_owned(),
        })
    }

    /// Formats one RFC 5424 message.
    pub fn format(&self, alert: &Alert) -> String {
        let pri = u16::from(self.facility) * 8 + u16::from(alert.severity.syslog_level());
        format!(
            "<{pri}>1 {} {} hnids {} {} - {}",
            alert.ts,
            self.hostname,
            std::process::id(),
            alert.kind,
            alert.to_json()
        )
    }
}

impl AlertSink for Syslog {
    fn name(&self) -> &str {
        &self.target
    }

    fn emit(&mut self, alert: &Alert) -> io::Result<()> {
        let msg = self.format(alert);
        match &self.transport {
            Transport::Unix(sock, path) => sock.send_to(msg.as_bytes(), path)?,
            Transport::Udp(sock) => sock.send(msg.as_bytes())?,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Severity;
    use crate::time::Timestamp;

    #[test]
    fn udp_round_trip() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let mut s = Syslog::connect(&format!("udp:{addr}"), 16).unwrap();
        let a = Alert::new(
            Timestamp(0),
            "arp",
            "arp_binding_change",
            Severity::High,
            "m",
        );
        s.emit(&a).unwrap();
        let mut buf = [0u8; 2048];
        let n = server.recv(&mut buf).unwrap();
        let msg = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            msg.starts_with("<131>1 1970-01-01T00:00:00.000000Z "),
            "{msg}"
        );
        assert!(msg.contains(" hnids ") && msg.ends_with('}'));
    }

    #[test]
    fn unix_round_trip() {
        let path = std::env::temp_dir().join(format!("hnids-syslog-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let server = UnixDatagram::bind(&path).unwrap();
        let mut s = Syslog::connect(&format!("unix:{}", path.display()), 1).unwrap();
        s.emit(&Alert::new(Timestamp(0), "dns", "x", Severity::Info, "m"))
            .unwrap();
        let mut buf = [0u8; 2048];
        let n = server.recv(&mut buf).unwrap();
        assert!(buf[..n].starts_with(b"<14>1 "));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn bad_target() {
        for t in ["", "tcp:1.2.3.4:514", "unix:", "/dev/log"] {
            assert!(Syslog::connect(t, 16).is_err(), "{t}");
        }
    }
}
