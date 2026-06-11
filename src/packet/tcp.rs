//! TCP (RFC 9293) header view.

use std::fmt;

use super::{be16, ensure, ParseError, ParseResult};

const MIN_LEN: usize = 20;

/// TCP control flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    /// FIN
    pub const FIN: u8 = 0x01;
    /// SYN
    pub const SYN: u8 = 0x02;
    /// RST
    pub const RST: u8 = 0x04;
    /// PSH
    pub const PSH: u8 = 0x08;
    /// ACK
    pub const ACK: u8 = 0x10;
    /// URG
    pub const URG: u8 = 0x20;

    /// True if every bit in `mask` is set.
    pub fn has(self, mask: u8) -> bool {
        self.0 & mask == mask
    }

    /// Connection attempt: SYN without ACK.
    pub fn is_syn_probe(self) -> bool {
        self.0 & (Self::SYN | Self::ACK | Self::RST) == Self::SYN
    }

    /// FIN scan: FIN alone.
    pub fn is_fin_probe(self) -> bool {
        self.0 & 0x3f == Self::FIN
    }

    /// NULL scan: no flags at all.
    pub fn is_null_probe(self) -> bool {
        self.0 & 0x3f == 0
    }

    /// XMAS scan: FIN, PSH and URG without SYN/ACK/RST.
    pub fn is_xmas_probe(self) -> bool {
        self.0 & 0x3f == Self::FIN | Self::PSH | Self::URG
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(u8, char); 6] = [
            (TcpFlags::URG, 'U'),
            (TcpFlags::ACK, 'A'),
            (TcpFlags::PSH, 'P'),
            (TcpFlags::RST, 'R'),
            (TcpFlags::SYN, 'S'),
            (TcpFlags::FIN, 'F'),
        ];
        if self.0 & 0x3f == 0 {
            return f.write_str("none");
        }
        for (bit, c) in NAMES {
            if self.0 & bit != 0 {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

/// Borrowed view of a TCP segment.
#[derive(Debug, Clone, Copy)]
pub struct TcpSegment<'a> {
    buf: &'a [u8],
    header_len: usize,
}

impl<'a> TcpSegment<'a> {
    /// Validates the data offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the header is truncated or the offset is invalid.
    pub fn new(buf: &'a [u8]) -> ParseResult<Self> {
        ensure("tcp", buf, MIN_LEN)?;
        let header_len = usize::from(buf[12] >> 4) * 4;
        if header_len < MIN_LEN {
            return Err(ParseError::Malformed {
                proto: "tcp",
                field: "data offset",
            });
        }
        ensure("tcp", buf, header_len)?;
        Ok(Self { buf, header_len })
    }

    /// Source port.
    pub fn src_port(&self) -> u16 {
        be16(self.buf, 0)
    }

    /// Destination port.
    pub fn dst_port(&self) -> u16 {
        be16(self.buf, 2)
    }

    /// Control flags.
    pub fn flags(&self) -> TcpFlags {
        TcpFlags(self.buf[13])
    }

    /// Bytes after the header.
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.header_len..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_classification() {
        assert!(TcpFlags(TcpFlags::SYN).is_syn_probe());
        assert!(!TcpFlags(TcpFlags::SYN | TcpFlags::ACK).is_syn_probe());
        assert!(TcpFlags(TcpFlags::FIN).is_fin_probe());
        assert!(!TcpFlags(TcpFlags::FIN | TcpFlags::ACK).is_fin_probe());
        assert!(TcpFlags(0).is_null_probe());
        assert!(TcpFlags(0x29).is_xmas_probe());
        assert_eq!(TcpFlags(0x12).to_string(), "AS");
        assert_eq!(TcpFlags(0).to_string(), "none");
    }

    #[test]
    fn options_are_skipped() {
        let mut s = vec![
            0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0x60, 0x02, 0, 0, 0, 0, 0, 0,
        ];
        s.extend_from_slice(&[1, 1, 1, 0, 0xee]);
        let t = TcpSegment::new(&s).unwrap();
        assert_eq!((t.src_port(), t.dst_port()), (80, 443));
        assert_eq!(t.payload(), &[0xee]);
        s[12] = 0x40;
        assert!(TcpSegment::new(&s).is_err());
    }
}
