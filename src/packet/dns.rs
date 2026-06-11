//! DNS message parsing (RFC 1035): header, question names and response code.
//!
//! Names are decoded label by label straight from the message buffer,
//! following compression pointers with a hop limit so hostile packets cannot
//! loop forever.

use super::{be16, ensure, ParseError, ParseResult};

const HEADER_LEN: usize = 12;
const MAX_POINTER_HOPS: usize = 16;
const MAX_NAME_LEN: usize = 255;
/// Upper bound on questions decoded from one message.
pub const MAX_QUESTIONS: usize = 8;

/// DNS response code `NXDOMAIN`.
pub const RCODE_NXDOMAIN: u8 = 3;

/// Borrowed view of a DNS message.
#[derive(Debug, Clone, Copy)]
pub struct DnsMessage<'a> {
    buf: &'a [u8],
}

/// One entry of the question section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Dotted, lower-cased name without the trailing dot.
    pub name: String,
    /// Query type (A = 1, AAAA = 28, TXT = 16, ...).
    pub qtype: u16,
}

impl<'a> DnsMessage<'a> {
    /// Validates the fixed header.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than twelve bytes are present.
    pub fn new(buf: &'a [u8]) -> ParseResult<Self> {
        ensure("dns", buf, HEADER_LEN)?;
        Ok(Self { buf })
    }

    /// Transaction ID.
    pub fn id(&self) -> u16 {
        be16(self.buf, 0)
    }

    /// True for responses (QR bit set).
    pub fn is_response(&self) -> bool {
        self.buf[2] & 0x80 != 0
    }

    /// Response code (low four bits of the flags).
    pub fn rcode(&self) -> u8 {
        self.buf[3] & 0x0f
    }

    /// Number of entries in the question section.
    pub fn question_count(&self) -> u16 {
        be16(self.buf, 4)
    }

    /// Decodes up to [`MAX_QUESTIONS`] questions.
    ///
    /// # Errors
    ///
    /// Returns an error if a name is truncated, too long or loops.
    pub fn questions(&self) -> ParseResult<Vec<Question>> {
        let count = usize::from(self.question_count()).min(MAX_QUESTIONS);
        let mut out = Vec::with_capacity(count);
        let mut off = HEADER_LEN;
        for _ in 0..count {
            let (name, next) = read_name(self.buf, off)?;
            ensure("dns", self.buf, next + 4)?;
            out.push(Question {
                name,
                qtype: be16(self.buf, next),
            });
            off = next + 4;
        }
        Ok(out)
    }
}

fn malformed(field: &'static str) -> ParseError {
    ParseError::Malformed {
        proto: "dns",
        field,
    }
}

/// Reads a possibly-compressed name at `off`; returns it and the offset just
/// past its in-place encoding.
fn read_name(buf: &[u8], mut off: usize) -> ParseResult<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut hops = 0;
    loop {
        ensure("dns", buf, off + 1)?;
        let len = buf[off];
        match len & 0xc0 {
            0x00 if len == 0 => {
                let end = end.unwrap_or(off + 1);
                return Ok((name, end));
            }
            0x00 => {
                let len = usize::from(len);
                ensure("dns", buf, off + 1 + len)?;
                if name.len() + len + 1 > MAX_NAME_LEN {
                    return Err(malformed("name length"));
                }
                if !name.is_empty() {
                    name.push('.');
                }
                for &b in &buf[off + 1..=off + len] {
                    name.push(char::from(b.to_ascii_lowercase()));
                }
                off += 1 + len;
            }
            0xc0 => {
                ensure("dns", buf, off + 2)?;
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(malformed("compression loop"));
                }
                end.get_or_insert(off + 2);
                off = usize::from(be16(buf, off) & 0x3fff);
            }
            _ => return Err(malformed("label type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(flags: u16, qd: u16) -> Vec<u8> {
        let mut h = vec![0x12, 0x34];
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&qd.to_be_bytes());
        h.extend_from_slice(&[0; 6]);
        h
    }

    #[test]
    fn decodes_question() {
        let mut m = header(0x0100, 1);
        m.extend_from_slice(b"\x03WWW\x07example\x03com\x00\x00\x01\x00\x01");
        let d = DnsMessage::new(&m).unwrap();
        assert!(!d.is_response());
        assert_eq!(d.id(), 0x1234);
        let q = d.questions().unwrap();
        assert_eq!(q[0].name, "www.example.com");
        assert_eq!(q[0].qtype, 1);
    }

    #[test]
    fn follows_pointer_and_detects_loop() {
        let mut m = header(0x8183, 2);
        m.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        m.extend_from_slice(b"\x03api\xc0\x0c\x00\x1c\x00\x01");
        let d = DnsMessage::new(&m).unwrap();
        assert!(d.is_response());
        assert_eq!(d.rcode(), RCODE_NXDOMAIN);
        let q = d.questions().unwrap();
        assert_eq!(q[1].name, "api.example.com");
        assert_eq!(q[1].qtype, 28);

        let mut looped = header(0, 1);
        looped.extend_from_slice(&[0xc0, 0x0c]);
        assert!(DnsMessage::new(&looped).unwrap().questions().is_err());
    }

    #[test]
    fn rejects_reserved_label_and_truncation() {
        let mut m = header(0, 1);
        m.extend_from_slice(&[0x40, 0]);
        assert!(DnsMessage::new(&m).unwrap().questions().is_err());
        let mut t = header(0, 1);
        t.extend_from_slice(b"\x05ab");
        assert!(DnsMessage::new(&t).unwrap().questions().is_err());
    }
}
