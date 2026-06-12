//! Classic libpcap file format, read and written without libpcap.

use std::io::{Read, Write};

use super::{read_exact, read_exact_or_eof, CaptureError, Frame, Next, PacketSource};
use super::{LINKTYPE_ETHERNET, MAX_SNAPLEN};
use crate::time::Timestamp;

const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
const MAGIC_NANOS: u32 = 0xa1b2_3c4d;

/// Streaming reader for `.pcap` files (both byte orders, µs and ns stamps).
pub struct PcapReader<R> {
    reader: R,
    big_endian: bool,
    nanos: bool,
}

impl<R: Read> PcapReader<R> {
    /// Parses the global header.
    ///
    /// # Errors
    ///
    /// Returns an error if the magic or link type is not supported.
    pub fn new(mut reader: R) -> Result<Self, CaptureError> {
        let mut magic = [0u8; 4];
        read_exact(&mut reader, &mut magic)?;
        Self::with_magic(reader, magic)
    }

    /// Parses the rest of the global header after the four magic bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the magic or link type is not supported.
    pub fn with_magic(mut reader: R, magic: [u8; 4]) -> Result<Self, CaptureError> {
        let (big_endian, nanos) = match (u32::from_le_bytes(magic), u32::from_be_bytes(magic)) {
            (MAGIC_MICROS, _) => (false, false),
            (MAGIC_NANOS, _) => (false, true),
            (_, MAGIC_MICROS) => (true, false),
            (_, MAGIC_NANOS) => (true, true),
            (m, _) => return Err(CaptureError::UnknownFormat(m)),
        };
        let mut rest = [0u8; 20];
        read_exact(&mut reader, &mut rest)?;
        let me = Self {
            reader,
            big_endian,
            nanos,
        };
        let linktype = me.u32_at(&rest, 16) & 0x0fff_ffff;
        if linktype != LINKTYPE_ETHERNET {
            return Err(CaptureError::UnsupportedLinkType(linktype));
        }
        Ok(me)
    }

    fn u32_at(&self, b: &[u8], off: usize) -> u32 {
        let bytes = [b[off], b[off + 1], b[off + 2], b[off + 3]];
        if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    }

    /// Reads the next record, `None` at end of file.
    ///
    /// # Errors
    ///
    /// Returns an error on truncated or oversized records.
    pub fn read_frame(&mut self) -> Result<Option<Frame>, CaptureError> {
        let mut hdr = [0u8; 16];
        if !read_exact_or_eof(&mut self.reader, &mut hdr)? {
            return Ok(None);
        }
        let secs = u64::from(self.u32_at(&hdr, 0));
        let frac = u64::from(self.u32_at(&hdr, 4));
        let incl = self.u32_at(&hdr, 8) as usize;
        let orig = self.u32_at(&hdr, 12) as usize;
        if incl > MAX_SNAPLEN {
            return Err(CaptureError::Corrupt("record length exceeds snap limit"));
        }
        let mut data = vec![0u8; incl];
        read_exact(&mut self.reader, &mut data)?;
        let micros = if self.nanos { frac / 1000 } else { frac };
        Ok(Some(Frame {
            ts: Timestamp::from_secs_micros(secs, micros),
            data,
            wire_len: orig,
        }))
    }
}

impl<R: Read + Send> PacketSource for PcapReader<R> {
    fn next_frame(&mut self) -> Result<Next, CaptureError> {
        Ok(self.read_frame()?.map_or(Next::End, Next::Frame))
    }
}

/// Writes little-endian microsecond pcap files (used for fixtures).
pub struct PcapWriter<W> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    /// Writes the global header for an Ethernet capture.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors.
    pub fn new(mut writer: W) -> std::io::Result<Self> {
        writer.write_all(&MAGIC_MICROS.to_le_bytes())?;
        writer.write_all(&2u16.to_le_bytes())?;
        writer.write_all(&4u16.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&65_535u32.to_le_bytes())?;
        writer.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
        Ok(Self { writer })
    }

    /// Appends one record.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors; frames longer than `u32::MAX` are rejected.
    pub fn write(&mut self, ts: Timestamp, data: &[u8]) -> std::io::Result<()> {
        let len = u32::try_from(data.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large")
        })?;
        let secs = u32::try_from(ts.secs()).unwrap_or(u32::MAX);
        let micros = u32::try_from(ts.0 % 1_000_000).unwrap_or(0);
        self.writer.write_all(&secs.to_le_bytes())?;
        self.writer.write_all(&micros.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(data)
    }

    /// Flushes and returns the inner writer.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors from the final flush.
    pub fn finish(mut self) -> std::io::Result<W> {
        self.writer.flush()?;
        Ok(self.writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write(Timestamp(1_500_000), &[1, 2, 3]).unwrap();
        w.write(Timestamp(2_000_001), &[4; 60]).unwrap();
        let bytes = w.finish().unwrap();
        let mut r = PcapReader::new(&bytes[..]).unwrap();
        let a = r.read_frame().unwrap().unwrap();
        assert_eq!(
            (a.ts, a.data.as_slice(), a.wire_len),
            (Timestamp(1_500_000), &[1u8, 2, 3][..], 3)
        );
        let b = r.read_frame().unwrap().unwrap();
        assert_eq!(b.ts, Timestamp(2_000_001));
        assert!(r.read_frame().unwrap().is_none());
    }

    #[test]
    fn big_endian_nanos() {
        let mut f = MAGIC_NANOS.to_be_bytes().to_vec();
        f.extend_from_slice(&[
            0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 1,
        ]);
        f.extend_from_slice(&10u32.to_be_bytes());
        f.extend_from_slice(&5_000u32.to_be_bytes());
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(&64u32.to_be_bytes());
        f.push(0xab);
        let mut r = PcapReader::new(&f[..]).unwrap();
        let fr = r.read_frame().unwrap().unwrap();
        assert_eq!(fr.ts, Timestamp::from_secs_micros(10, 5));
        assert_eq!(fr.wire_len, 64);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(matches!(
            PcapReader::new(&[0u8; 24][..]),
            Err(CaptureError::UnknownFormat(0))
        ));
        let mut f = MAGIC_MICROS.to_le_bytes().to_vec();
        f.extend_from_slice(&[0; 16]);
        f.extend_from_slice(&113u32.to_le_bytes());
        assert!(matches!(
            PcapReader::new(&f[..]),
            Err(CaptureError::UnsupportedLinkType(113))
        ));
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write(Timestamp(0), &[1, 2, 3]).unwrap();
        let mut bytes = w.finish().unwrap();
        bytes.pop();
        let mut r = PcapReader::new(&bytes[..]).unwrap();
        assert!(r.read_frame().is_err());
    }
}
