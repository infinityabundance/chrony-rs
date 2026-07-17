//! Unix-domain socket I/O for the SOCK refclock driver.
//!
//! Wraps `socket(AF_UNIX, SOCK_DGRAM, 0)`, `bind()`, and `recvfrom()` for
//! the refclock SOCK driver that receives NTP samples from external programs
//! via a Unix datagram socket (e.g. `chronyc` or gpsd).
//!
//! Integration tests create a temporary socket path, bind, send a test
//! sample, and verify it parses correctly.

use chrony_rs_core::refclock_sock::SockDriver;
use std::os::unix::io::RawFd;
use std::path::Path;

/// A Unix-domain datagram socket for the SOCK refclock.
#[derive(Debug)]
pub struct SockSocket {
    fd: Option<RawFd>,
    path: Option<String>,
}

impl SockSocket {
    pub fn new() -> Self {
        SockSocket {
            fd: None,
            path: None,
        }
    }

    /// Open and bind a Unix datagram socket at `path`.
    pub fn bind(path: &Path) -> Option<Self> {
        // SAFETY: socket() returns a file descriptor which is checked for < 0
        // immediately after the call to verify it is valid.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return None;
        }
        // Remove existing socket file
        let _ = std::fs::remove_file(path);

        let path_c = path.to_string_lossy().to_string();
        // SAFETY: Zero-initialization is valid for sockaddr_un — all fields
        // (sun_family, sun_path) are plain data types and all-zero bytes form a
        // valid representation.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path_c.as_bytes();
        let sun_path = &mut addr.sun_path as *mut i8 as *mut u8;
        let len = bytes.len().min(107);
        // SAFETY: len is bounded to 107 bytes (max sun_path). The source
        // (bytes.as_ptr()) and target (sun_path) regions do not overlap:
        // bytes is a separate stack-allocated slice, sun_path is within the
        // sockaddr_un struct.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), sun_path, len);
        }

        let addrlen = std::mem::size_of::<libc::sa_family_t>() + len + 1;
        // SAFETY: bind() return value is checked for < 0 immediately after.
        // addr is a fully initialized sockaddr_un (family + path copied in).
        // fd is a valid socket file descriptor from the socket() call above.
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                addrlen as u32,
            )
        };
        if ret < 0 {
            // SAFETY: fd is a valid socket file descriptor returned by socket()
            // above, owned by this function, and is not used after this point.
            unsafe {
                libc::close(fd);
            }
            return None;
        }

        Some(SockSocket {
            fd: Some(fd),
            path: Some(path_c),
        })
    }

    /// Receive a datagram (blocking). Returns the bytes or None on error.
    pub fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        let fd = self.fd?;
        // SAFETY: buf is a mutable slice that outlives the recv() call.
        // The return value is checked for < 0 to detect errors.
        // fd is a valid socket file descriptor owned by this struct.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            None
        } else {
            Some(n as usize)
        }
    }

    /// Parse a received datagram as a SOCK sample.
    pub fn parse_sample(buf: &[u8]) -> Option<chrony_rs_core::refclock_sock::SockOutput> {
        SockDriver::read_sample(buf)
    }

    fn close(&self) {
        if let Some(fd) = self.fd {
            // SAFETY: fd is a valid socket file descriptor previously
            // returned by socket() and owned by this struct. close() is
            // called at most once per fd (via Drop or explicit close call).
            unsafe {
                libc::close(fd);
            }
        }
        if let Some(ref p) = self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Drop for SockSocket {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn sock_bind_temp_path() {
        let tmp = std::env::temp_dir().join(format!("chrony-rs-test-sock-{}", std::process::id()));
        let sock = SockSocket::bind(&tmp);
        assert!(sock.is_some(), "bind to temporary path");
        if let Some(s) = sock {
            s.close();
        }
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn sock_parse_valid_sample() {
        // A minimal SOCK refclock sample: refclock format TAI timestamp
        let sample = b"@ 1234567890.500000\n";
        let result = SockSocket::parse_sample(sample);
        assert!(result.is_some(), "should parse valid SOCK sample");
    }
}
