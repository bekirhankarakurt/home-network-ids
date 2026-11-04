//! pcapng reader (Section Header, Interface Description, Enhanced and Simple
//! Packet blocks); unknown blocks are skipped.

use std::io::{Read, Write};

use super::{read_exact, read_exact_or_eof, CaptureError, Frame, Next, PacketSource};
use super::{LINKTYPE_ETHERNET, MAX_SNAPLEN};
use crate::time::Timestamp;

/// Section Header Block type; also the file magic.
pub const SHB_TYPE: u32 = 0x0a0d_0d0a;
const IDB_TYPE: u32 = 0x0000_0001;
const SPB_TYPE: u32 = 0x0000_0003;
const EPB_TYPE: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;
const OPT_IF_TSRESOL: u16 = 9;
const MAX_BLOCK_LEN: usize = MAX_SNAPLEN + 1024;
const MAX_INTERFACES: usize = 64;

#[derive(Debug, Clone, Copy)]
struct Interface {
    linktype: u32,
    /// Timestamp units per second.
    units_per_sec: u64,
}

/// Streaming pcapng reader.
pub struct PcapNgReader<R> {
    reader: R,
    big_endian: bool,
    interfaces: Vec<Interface>,
}

impl<R: Read> PcapNgReader<R> {
    /// Parses the first Section Header Block.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream does not start with a valid SHB.
    pub fn new(mut reader: R) -> Result<Self, CaptureError> {
        let mut magic = [0u8; 4];
        read_exact(&mut reader, &mut magic)?;
        if u32::from_le_bytes(magic) != SHB_TYPE {
            return Err(CaptureError::UnknownFormat(u32::from_le_bytes(magic)));
        }
        Self::with_magic(reader)
    }

    /// Continues after the four SHB type bytes have been consumed.
    ///
    /// # Errors
    ///
    /// Returns an error if the Section Header Block is invalid.
    pub fn with_magic(reader: R) -> Result<Self, CaptureError> {
        let mut me = Self {
            reader,
            big_endian: false,
            interfaces: Vec::new(),
        };
        me.read_section_header()?;
        Ok(me)
    }

    fn u16_at(&self, b: &[u8], off: usize) -> u16 {
        let bytes = [b[off], b[off + 1]];
        if self.big_endian {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        }
    }

    fn u32_at(&self, b: &[u8], off: usize) -> u32 {
        let bytes = [b[off], b[off + 1], b[off + 2], b[off + 3]];
        if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    }

    /// Reads an SHB whose type field was already consumed.
    fn read_section_header(&mut self) -> Result<(), CaptureError> {
        let mut head = [0u8; 8];
        read_exact(&mut self.reader, &mut head)?;
        let bom = [head[4], head[5], head[6], head[7]];
        self.big_endian = if u32::from_le_bytes(bom) == BYTE_ORDER_MAGIC {
            false
        } else if u32::from_be_bytes(bom) == BYTE_ORDER_MAGIC {
            true
        } else {
            return Err(CaptureError::Corrupt("bad byte-order magic"));
        };
        let total = self.u32_at(&head, 0) as usize;
        if !(28..=MAX_BLOCK_LEN).contains(&total) || total % 4 != 0 {
            return Err(CaptureError::Corrupt("bad section header length"));
        }
        let mut rest = vec![0u8; total - 12];
        read_exact(&mut self.reader, &mut rest)?;
        self.interfaces.clear();
        Ok(())
    }

    fn parse_idb(&mut self, body: &[u8]) -> Result<(), CaptureError> {
        if body.len() < 8 {
            return Err(CaptureError::Corrupt("short interface block"));
        }
        if self.interfaces.len() >= MAX_INTERFACES {
            return Err(CaptureError::Corrupt("too many interfaces"));
        }
        let linktype = u32::from(self.u16_at(body, 0));
        let mut units_per_sec = 1_000_000;
        let mut off = 8;
        while off + 4 <= body.len() {
            let code = self.u16_at(body, off);
            let len = usize::from(self.u16_at(body, off + 2));
            let val = off + 4;
            if code == 0 || val + len > body.len() {
                break;
            }
            if code == OPT_IF_TSRESOL && len >= 1 {
                let r = body[val];
                let exp = u32::from(r & 0x7f);
                units_per_sec = if r & 0x80 == 0 {
                    10u64.checked_pow(exp)
                } else {
                    2u64.checked_pow(exp)
                }
                .filter(|&u| u > 0)
                .ok_or(CaptureError::Corrupt("bad timestamp resolution"))?;
            }
            off = val + len.div_ceil(4) * 4;
        }
        self.interfaces.push(Interface {
            linktype,
            units_per_sec,
        });
        Ok(())
    }

    fn interface(&self, id: usize) -> Result<Interface, CaptureError> {
        let iface = *self
            .interfaces
            .get(id)
            .ok_or(CaptureError::Corrupt("packet references unknown interface"))?;
        if iface.linktype != LINKTYPE_ETHERNET {
            return Err(CaptureError::UnsupportedLinkType(iface.linktype));
        }
        Ok(iface)
    }

    fn parse_epb(&self, body: &[u8]) -> Result<Frame, CaptureError> {
        if body.len() < 20 {
            return Err(CaptureError::Corrupt("short enhanced packet block"));
        }
        let iface = self.interface(self.u32_at(body, 0) as usize)?;
        let raw = (u64::from(self.u32_at(body, 4)) << 32) | u64::from(self.u32_at(body, 8));
        let cap = self.u32_at(body, 12) as usize;
        let orig = self.u32_at(body, 16) as usize;
        let data = body
            .get(20..20 + cap)
            .ok_or(CaptureError::Corrupt("packet data exceeds block"))?;
        let secs = raw / iface.units_per_sec;
        let frac = raw % iface.units_per_sec;
        let micros = u64::try_from(u128::from(frac) * 1_000_000 / u128::from(iface.units_per_sec))
            .unwrap_or(0);
        Ok(Frame {
            ts: Timestamp::from_secs_micros(secs, micros),
            data: data.to_vec(),
            wire_len: orig,
        })
    }

    fn parse_spb(&self, body: &[u8]) -> Result<Frame, CaptureError> {
        if body.len() < 4 {
            return Err(CaptureError::Corrupt("short simple packet block"));
        }
        self.interface(0)?;
        let orig = self.u32_at(body, 0) as usize;
        let data = &body[4..];
        let data = &data[..orig.min(data.len())];
        Ok(Frame {
            ts: Timestamp(0),
            data: data.to_vec(),
            wire_len: orig,
        })
    }

    /// Reads blocks until the next packet, `None` at end of file.
    ///
    /// # Errors
    ///
    /// Returns an error on malformed blocks.
    pub fn read_frame(&mut self) -> Result<Option<Frame>, CaptureError> {
        loop {
            let mut ty = [0u8; 4];
            if !read_exact_or_eof(&mut self.reader, &mut ty)? {
                return Ok(None);
            }
            if u32::from_le_bytes(ty) == SHB_TYPE {
                self.read_section_header()?;
                continue;
            }
            let block_type = self.u32_at(&ty, 0);
            let mut len = [0u8; 4];
            read_exact(&mut self.reader, &mut len)?;
            let total = self.u32_at(&len, 0) as usize;
            if !(12..=MAX_BLOCK_LEN).contains(&total) || total % 4 != 0 {
                return Err(CaptureError::Corrupt("bad block length"));
            }
            let mut rest = vec![0u8; total - 8];
            read_exact(&mut self.reader, &mut rest)?;
            let body = &rest[..rest.len() - 4];
            match block_type {
                IDB_TYPE => self.parse_idb(body)?,
                EPB_TYPE => return self.parse_epb(body).map(Some),
                SPB_TYPE => return self.parse_spb(body).map(Some),
                _ => {}
            }
        }
    }
}

impl<R: Read + Send> PacketSource for PcapNgReader<R> {
    fn next_frame(&mut self) -> Result<Next, CaptureError> {
        Ok(self.read_frame()?.map_or(Next::End, Next::Frame))
    }
}

/// Minimal little-endian pcapng writer: one SHB, one Ethernet IDB with
/// microsecond resolution, then Enhanced Packet Blocks.
pub struct PcapNgWriter<W> {
    writer: W,
}

fn block(ty: u32, body: &[u8]) -> Vec<u8> {
    let padded = body.len().div_ceil(4) * 4;
    let total = u32::try_from(12 + padded).unwrap_or(u32::MAX);
    let mut b = Vec::with_capacity(12 + padded);
    b.extend_from_slice(&ty.to_le_bytes());
    b.extend_from_slice(&total.to_le_bytes());
    b.extend_from_slice(body);
    b.resize(8 + padded, 0);
    b.extend_from_slice(&total.to_le_bytes());
    b
}

impl<W: Write> PcapNgWriter<W> {
    /// Writes the section and interface headers.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors.
    pub fn new(mut writer: W) -> std::io::Result<Self> {
        let mut shb = BYTE_ORDER_MAGIC.to_le_bytes().to_vec();
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        writer.write_all(&block(SHB_TYPE, &shb))?;
        let mut idb = u16::try_from(LINKTYPE_ETHERNET)
            .unwrap_or(1)
            .to_le_bytes()
            .to_vec();
        idb.extend_from_slice(&[0, 0]);
        idb.extend_from_slice(&65_535u32.to_le_bytes());
        idb.extend_from_slice(&OPT_IF_TSRESOL.to_le_bytes());
        idb.extend_from_slice(&1u16.to_le_bytes());
        idb.extend_from_slice(&[6, 0, 0, 0]);
        idb.extend_from_slice(&[0, 0, 0, 0]);
        writer.write_all(&block(IDB_TYPE, &idb))?;
        Ok(Self { writer })
    }

    /// Appends one Enhanced Packet Block.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors; frames longer than `u32::MAX` are rejected.
    pub fn write(&mut self, ts: Timestamp, data: &[u8]) -> std::io::Result<()> {
        let len = u32::try_from(data.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large")
        })?;
        let mut epb = 0u32.to_le_bytes().to_vec();
        epb.extend_from_slice(&u32::try_from(ts.0 >> 32).unwrap_or(0).to_le_bytes());
        epb.extend_from_slice(&u32::try_from(ts.0 & 0xffff_ffff).unwrap_or(0).to_le_bytes());
        epb.extend_from_slice(&len.to_le_bytes());
        epb.extend_from_slice(&len.to_le_bytes());
        epb.extend_from_slice(data);
        self.writer.write_all(&block(EPB_TYPE, &epb))
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
    fn round_trip_with_unknown_block() {
        let mut w = PcapNgWriter::new(Vec::new()).unwrap();
        w.write(Timestamp(7_000_123), &[1, 2, 3, 4, 5]).unwrap();
        let mut bytes = w.finish().unwrap();
        bytes.extend_from_slice(&block(0x0000_0bad, &[9; 6]));
        let mut w2 = PcapNgWriter::new(Vec::new()).unwrap();
        w2.write(Timestamp(8_000_000), &[6; 64]).unwrap();
        bytes.extend_from_slice(&w2.finish().unwrap());

        let mut r = PcapNgReader::new(&bytes[..]).unwrap();
        let a = r.read_frame().unwrap().unwrap();
        assert_eq!(a.ts, Timestamp(7_000_123));
        assert_eq!(a.data, vec![1, 2, 3, 4, 5]);
        let b = r.read_frame().unwrap().unwrap();
        assert_eq!(b.ts, Timestamp(8_000_000));
        assert!(r.read_frame().unwrap().is_none());
    }

    #[test]
    fn nanosecond_resolution() {
        let mut w = PcapNgWriter::new(Vec::new()).unwrap();
        w.write(Timestamp(0), &[0; 4]).unwrap();
        let mut bytes = w.finish().unwrap();
        // Patch if_tsresol from 10^-6 to 10^-9 and the stamp to 1.5 s.
        let pos = bytes.windows(4).position(|x| x == [9, 0, 1, 0]).unwrap();
        bytes[pos + 4] = 9;
        let epb = bytes.len() - 4 - 4 - 20 - 8;
        bytes[epb + 16..epb + 20].copy_from_slice(&1_500_000_000u32.to_le_bytes());
        let f = PcapNgReader::new(&bytes[..])
            .unwrap()
            .read_frame()
            .unwrap()
            .unwrap();
        assert_eq!(f.ts, Timestamp(1_500_000));
    }

    #[test]
    fn packet_before_interface_is_corrupt() {
        let mut shb = BYTE_ORDER_MAGIC.to_le_bytes().to_vec();
        shb.extend_from_slice(&[1, 0, 0, 0]);
        shb.extend_from_slice(&[0xff; 8]);
        let mut bytes = block(SHB_TYPE, &shb);
        bytes.extend_from_slice(&block(EPB_TYPE, &[0; 20]));
        let mut r = PcapNgReader::new(&bytes[..]).unwrap();
        assert!(matches!(r.read_frame(), Err(CaptureError::Corrupt(_))));
    }
}
