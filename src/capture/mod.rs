//! Packet sources: offline pcap/pcapng replay and live `AF_PACKET` capture.

#[allow(unsafe_code)] // raw-socket FFI; every block carries a SAFETY comment
pub mod live;
pub mod pcap;
pub mod pcapng;

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use crate::time::Timestamp;

/// Ethernet link type (`LINKTYPE_ETHERNET`).
pub const LINKTYPE_ETHERNET: u32 = 1;
/// Largest frame accepted from a capture file; protects against bogus
/// length fields allocating gigabytes.
pub const MAX_SNAPLEN: usize = 262_144;

/// One captured frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Capture time.
    pub ts: Timestamp,
    /// Captured bytes (possibly truncated to the snap length).
    pub data: Vec<u8>,
    /// Length on the wire.
    pub wire_len: usize,
}

/// Errors from packet sources.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// Underlying I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// The file is not a pcap or pcapng capture.
    #[error("unrecognised capture format (magic {0:#010x})")]
    UnknownFormat(u32),
    /// A header or block is inconsistent.
    #[error("corrupt capture: {0}")]
    Corrupt(&'static str),
    /// Only Ethernet captures are supported.
    #[error("unsupported link type {0} (only Ethernet/1 is supported)")]
    UnsupportedLinkType(u32),
    /// A system call on the raw socket failed.
    #[error("{call} failed: {source}")]
    Os {
        /// Failing call.
        call: &'static str,
        /// OS error.
        source: io::Error,
    },
}

/// Outcome of polling a source.
#[derive(Debug)]
pub enum Next {
    /// A frame is available.
    Frame(Frame),
    /// Nothing arrived before the poll timeout (live capture only).
    Idle,
    /// The source is exhausted.
    End,
}

/// Anything that yields frames.
pub trait PacketSource: Send {
    /// Returns the next frame, [`Next::Idle`] on timeout or [`Next::End`].
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError`] on I/O failure or corrupt input.
    fn next_frame(&mut self) -> Result<Next, CaptureError>;

    /// True for live sources, where back-pressure must drop instead of block.
    fn is_live(&self) -> bool {
        false
    }
}

/// Opens a pcap or pcapng file, detecting the format from its magic number.
///
/// # Errors
///
/// Returns [`CaptureError`] if the file cannot be read or is not a supported
/// capture.
pub fn open_file(path: &Path) -> Result<Box<dyn PacketSource>, CaptureError> {
    let file = File::open(path)?;
    open_reader(BufReader::new(file))
}

/// Like [`open_file`] for any reader.
///
/// # Errors
///
/// Returns [`CaptureError`] if the stream is not a supported capture.
pub fn open_reader<R: Read + Send + 'static>(
    mut reader: R,
) -> Result<Box<dyn PacketSource>, CaptureError> {
    let mut magic = [0u8; 4];
    read_exact_or_eof(&mut reader, &mut magic)?
        .then_some(())
        .ok_or(CaptureError::Corrupt("empty file"))?;
    if magic == pcapng::SHB_TYPE.to_le_bytes() {
        Ok(Box::new(pcapng::PcapNgReader::with_magic(reader)?))
    } else {
        Ok(Box::new(pcap::PcapReader::with_magic(reader, magic)?))
    }
}

/// Fills `buf` completely; returns `Ok(false)` on a clean EOF before the
/// first byte and an error on EOF mid-buffer.
pub(crate) fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, CaptureError> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(CaptureError::Corrupt("unexpected end of file")),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

/// Reads exactly `buf.len()` bytes, treating EOF as corruption.
pub(crate) fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), CaptureError> {
    if read_exact_or_eof(r, buf)? || buf.is_empty() {
        Ok(())
    } else {
        Err(CaptureError::Corrupt("unexpected end of file"))
    }
}
