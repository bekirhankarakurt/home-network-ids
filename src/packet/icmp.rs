//! ICMP and `ICMPv6` header view.

use super::{ensure, ParseResult};

/// Borrowed view of an ICMP message (v4 or v6 share the first two fields).
#[derive(Debug, Clone, Copy)]
pub struct IcmpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    /// Validates the minimal header.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than four bytes are present.
    pub fn new(buf: &'a [u8]) -> ParseResult<Self> {
        ensure("icmp", buf, 4)?;
        Ok(Self { buf })
    }

    /// Message type.
    pub fn icmp_type(&self) -> u8 {
        self.buf[0]
    }

    /// Message code.
    pub fn code(&self) -> u8 {
        self.buf[1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_request() {
        let i = IcmpPacket::new(&[8, 0, 0xf7, 0xff]).unwrap();
        assert_eq!((i.icmp_type(), i.code()), (8, 0));
        assert!(IcmpPacket::new(&[8, 0]).is_err());
    }
}
