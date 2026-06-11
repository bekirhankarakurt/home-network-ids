//! Ethernet II frames with optional 802.1Q / 802.1ad VLAN tags.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{be16, ensure, ParseResult};

const HEADER_LEN: usize = 14;
const TPID_8021Q: u16 = 0x8100;
const TPID_8021AD: u16 = 0x88a8;
const MAX_VLAN_TAGS: usize = 2;

/// A 48-bit IEEE MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The broadcast address `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);
    /// The all-zero address.
    pub const ZERO: Self = Self([0; 6]);

    /// True for group (multicast and broadcast) addresses.
    pub fn is_multicast(self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// True if the locally-administered bit is set (randomised or virtual MACs).
    pub fn is_locally_administered(self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// True for a globally unique unicast address that identifies real hardware.
    pub fn is_unicast(self) -> bool {
        !self.is_multicast() && self != Self::ZERO
    }

    /// The 24-bit organisationally unique identifier.
    pub fn oui(self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// Error returned when a MAC address string is not `xx:xx:xx:xx:xx:xx`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid MAC address {0:?}")]
pub struct MacParseError(pub String);

impl FromStr for MacAddr {
    type Err = MacParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || MacParseError(s.to_owned());
        let mut out = [0u8; 6];
        let mut parts = s.split([':', '-']);
        for byte in &mut out {
            let part = parts.next().ok_or_else(err)?;
            if part.len() != 2 {
                return Err(err());
            }
            *byte = u8::from_str_radix(part, 16).map_err(|_| err())?;
        }
        if parts.next().is_some() {
            return Err(err());
        }
        Ok(Self(out))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Payload protocol of an Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    /// `0x0800`
    Ipv4,
    /// `0x0806`
    Arp,
    /// `0x86dd`
    Ipv6,
    /// Anything else.
    Other(u16),
}

impl From<u16> for EtherType {
    fn from(v: u16) -> Self {
        match v {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86dd => Self::Ipv6,
            other => Self::Other(other),
        }
    }
}

/// Borrowed view of an Ethernet II frame.
#[derive(Debug, Clone, Copy)]
pub struct EthernetFrame<'a> {
    buf: &'a [u8],
    ether_type: u16,
    payload_off: usize,
    vlan: Option<u16>,
}

impl<'a> EthernetFrame<'a> {
    /// Validates the header (and up to two VLAN tags).
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is shorter than its headers.
    pub fn new(buf: &'a [u8]) -> ParseResult<Self> {
        ensure("ethernet", buf, HEADER_LEN)?;
        let mut ether_type = be16(buf, 12);
        let mut off = HEADER_LEN;
        let mut vlan = None;
        for _ in 0..MAX_VLAN_TAGS {
            if ether_type != TPID_8021Q && ether_type != TPID_8021AD {
                break;
            }
            ensure("ethernet", buf, off + 4)?;
            vlan.get_or_insert(be16(buf, off) & 0x0fff);
            ether_type = be16(buf, off + 2);
            off += 4;
        }
        Ok(Self {
            buf,
            ether_type,
            payload_off: off,
            vlan,
        })
    }

    /// Destination MAC.
    pub fn dst(&self) -> MacAddr {
        MacAddr(mac_at(self.buf, 0))
    }

    /// Source MAC.
    pub fn src(&self) -> MacAddr {
        MacAddr(mac_at(self.buf, 6))
    }

    /// Inner EtherType after any VLAN tags.
    pub fn ether_type(&self) -> EtherType {
        EtherType::from(self.ether_type)
    }

    /// Outer VLAN ID, if tagged.
    pub fn vlan(&self) -> Option<u16> {
        self.vlan
    }

    /// Bytes after the link-layer header.
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.payload_off..]
    }

    /// Total frame length in bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Always false: a valid frame has at least a full header.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Copies six bytes starting at `off`; callers validate the length first.
pub(crate) fn mac_at(buf: &[u8], off: usize) -> [u8; 6] {
    let mut m = [0u8; 6];
    m.copy_from_slice(&buf[off..off + 6]);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_round_trip() {
        let m: MacAddr = "B8:27:eb:01:02:03".parse().unwrap();
        assert_eq!(m.to_string(), "b8:27:eb:01:02:03");
        assert_eq!(m.oui(), 0x00b8_27eb);
        assert!(m.is_unicast());
        assert!(!m.is_locally_administered());
        assert!("b8-27-eb-01-02-03".parse::<MacAddr>().is_ok());
    }

    #[test]
    fn mac_rejects_garbage() {
        for s in [
            "",
            "b8:27:eb",
            "b8:27:eb:01:02:03:04",
            "zz:27:eb:01:02:03",
            "b827:eb:01:02:03",
        ] {
            assert!(s.parse::<MacAddr>().is_err(), "{s}");
        }
    }

    #[test]
    fn vlan_tag_is_skipped() {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x2a, 0x08, 0x06]);
        f.extend_from_slice(&[0xaa; 4]);
        let e = EthernetFrame::new(&f).unwrap();
        assert_eq!(e.vlan(), Some(42));
        assert_eq!(e.ether_type(), EtherType::Arp);
        assert_eq!(e.payload(), &[0xaa; 4]);
        assert!(e.src().is_locally_administered());
    }

    #[test]
    fn truncated_vlan_is_error() {
        let mut f = vec![0; 12];
        f.extend_from_slice(&[0x81, 0x00, 0x00]);
        assert!(EthernetFrame::new(&f).is_err());
    }
}
