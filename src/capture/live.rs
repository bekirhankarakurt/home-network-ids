//! Live capture from a Linux `AF_PACKET` raw socket.
//!
//! Requires `CAP_NET_RAW` (or root). The socket is bound to one interface,
//! optionally put into promiscuous mode, and read with a short receive
//! timeout so the pipeline can observe shutdown requests.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use super::{CaptureError, Frame, Next, PacketSource, MAX_SNAPLEN};
use crate::time::Timestamp;

/// Default receive timeout used to poll the stop flag.
pub const POLL_TIMEOUT: Duration = Duration::from_millis(200);

/// Raw-socket capture handle; the socket is closed on drop.
pub struct LiveCapture {
    fd: OwnedFd,
    buf: Vec<u8>,
}

fn os_err(call: &'static str) -> CaptureError {
    CaptureError::Os {
        call,
        source: io::Error::last_os_error(),
    }
}

/// `ETH_P_ALL` in network byte order, as `socket(2)` and `sockaddr_ll` expect.
fn eth_p_all_be() -> u16 {
    u16::try_from(libc::ETH_P_ALL).unwrap_or(3).to_be()
}

impl LiveCapture {
    /// Opens a raw socket on `interface`.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::Os`] when the interface does not exist or the
    /// process lacks `CAP_NET_RAW`.
    pub fn open(interface: &str, promiscuous: bool) -> Result<Self, CaptureError> {
        let name = CString::new(interface).map_err(|_| CaptureError::Os {
            call: "if_nametoindex",
            source: io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"),
        })?;
        // SAFETY: `name` is a valid NUL-terminated C string that outlives the call.
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            return Err(os_err("if_nametoindex"));
        }
        let ifindex = i32::try_from(ifindex).map_err(|_| CaptureError::Os {
            call: "if_nametoindex",
            source: io::Error::new(io::ErrorKind::InvalidData, "interface index out of range"),
        })?;

        // SAFETY: plain syscall with constant arguments; the return value is checked.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(eth_p_all_be()),
            )
        };
        if raw < 0 {
            return Err(os_err("socket(AF_PACKET)"));
        }
        // SAFETY: `raw` is a freshly created, valid descriptor owned by nobody else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: an all-zero `sockaddr_ll` is a valid value of the C struct.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = u16::try_from(libc::AF_PACKET).unwrap_or(17);
        addr.sll_protocol = eth_p_all_be();
        addr.sll_ifindex = ifindex;
        let addr_len = socklen_of::<libc::sockaddr_ll>();
        // SAFETY: `addr` is a properly initialised sockaddr_ll and `addr_len`
        // is its exact size; `fd` is a valid socket.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                addr_len,
            )
        };
        if rc < 0 {
            return Err(os_err("bind"));
        }

        if promiscuous {
            // SAFETY: an all-zero `packet_mreq` is a valid value of the C struct.
            let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
            mreq.mr_ifindex = ifindex;
            mreq.mr_type = u16::try_from(libc::PACKET_MR_PROMISC).unwrap_or(1);
            set_opt(
                &fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mreq,
                "PACKET_ADD_MEMBERSHIP",
            )?;
        }

        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: libc::suseconds_t::try_from(POLL_TIMEOUT.as_micros()).unwrap_or(200_000),
        };
        set_opt(&fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv, "SO_RCVTIMEO")?;

        Ok(Self {
            fd,
            buf: vec![0u8; MAX_SNAPLEN],
        })
    }
}

fn socklen_of<T>() -> libc::socklen_t {
    libc::socklen_t::try_from(std::mem::size_of::<T>()).unwrap_or(libc::socklen_t::MAX)
}

fn set_opt<T>(
    fd: &OwnedFd,
    level: i32,
    name: i32,
    value: &T,
    call: &'static str,
) -> Result<(), CaptureError> {
    // SAFETY: `value` points to a live, initialised `T` and the length passed
    // is exactly `size_of::<T>()`; `fd` is a valid socket.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            std::ptr::from_ref(value).cast::<libc::c_void>(),
            socklen_of::<T>(),
        )
    };
    if rc < 0 {
        Err(os_err(call))
    } else {
        Ok(())
    }
}

impl PacketSource for LiveCapture {
    fn next_frame(&mut self) -> Result<Next, CaptureError> {
        // SAFETY: `buf` is a valid writable region of `buf.len()` bytes and
        // `MSG_TRUNC` makes the kernel report the real frame length without
        // writing past it.
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                self.buf.as_mut_ptr().cast::<libc::c_void>(),
                self.buf.len(),
                libc::MSG_TRUNC,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            return match err.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted => Ok(Next::Idle),
                _ => Err(CaptureError::Os {
                    call: "recv",
                    source: err,
                }),
            };
        }
        let wire_len = usize::try_from(n).unwrap_or(0);
        let captured = wire_len.min(self.buf.len());
        Ok(Next::Frame(Frame {
            ts: Timestamp::now(),
            data: self.buf[..captured].to_vec(),
            wire_len,
        }))
    }

    fn is_live(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_interface_is_reported() {
        let err = LiveCapture::open("hnids-no-such-if0", false).err().unwrap();
        assert!(
            matches!(
                err,
                CaptureError::Os {
                    call: "if_nametoindex",
                    ..
                }
            ),
            "{err}"
        );
        let err = LiveCapture::open("bad\0name", false).err().unwrap();
        assert!(err.to_string().contains("NUL"));
    }
}
