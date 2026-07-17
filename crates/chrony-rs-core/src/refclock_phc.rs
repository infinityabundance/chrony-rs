//! PHC reference-clock driver — a port of chrony 4.5 `refclock_phc.c`.
//!
//! The PHC driver opens `/dev/ptpX` and reads the PTP hardware clock time via
//! `PTP_SYS_OFFSET` to obtain a cross-timestamped (PHC, system-clock) pair with
//! sub-microsecond precision. It is one of the platform drivers behind the
//! [`crate::refclock`] framework.

use std::os::unix::io::RawFd;

use crate::refclock::RefclockDriver;
use crate::sys_generic::Timespec;

// ---------------------------------------------------------------------------
// Linux PTP kernel structs (from <linux/ptp_clock.h>)
// ---------------------------------------------------------------------------

/// Kernel `struct ptp_clock_time`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ptp_clock_time {
    sec: i64,
    nsec: u32,
    reserved: u32,
}

/// Maximum number of offset measurement samples (from kernel header).
const PTP_MAX_SAMPLES: usize = 25;

/// Kernel `struct ptp_sys_offset`.
#[repr(C)]
struct ptp_sys_offset {
    n_samples: u32,
    rsv: [u32; 3],
    ts: [ptp_clock_time; 2 * PTP_MAX_SAMPLES + 1],
}

// ---------------------------------------------------------------------------
// PTP ioctl constants
//
// From <linux/ptp_clock.h>:
//   #define PTP_CLK_MAGIC  '='
//   #define PTP_CLOCK_GETCAPS    _IOR(PTP_CLK_MAGIC, 1, struct ptp_clock_caps)
//   #define PTP_SYS_OFFSET       _IOW(PTP_CLK_MAGIC, 5, struct ptp_sys_offset)
//
// Encoding: _IOC(dir, type, nr, size) = (dir<<30)|(type<<8)|(nr<<0)|(size<<16)
// These pass the struct itself (not a pointer), so size == sizeof(struct).
// ---------------------------------------------------------------------------

/// Compute an `_IOC` value.
const fn ioc(dir: u32, typ: u8, nr: u8, size: usize) -> libc::c_ulong {
    ((dir as libc::c_ulong) << 30)
        | ((typ as libc::c_ulong) << 8)
        | (nr as libc::c_ulong)
        | ((size as libc::c_ulong) << 16)
}

/// `_IOR` — ioctl with read direction.
#[allow(dead_code)]
const fn ior(typ: u8, nr: u8, size: usize) -> libc::c_ulong {
    ioc(2, typ, nr, size)
}

/// `_IOW` — ioctl with write direction.
#[allow(dead_code)]
const fn iow(typ: u8, nr: u8, size: usize) -> libc::c_ulong {
    ioc(1, typ, nr, size)
}

/// `_IOWR` — ioctl with read/write direction.
#[allow(dead_code)]
const fn iowr(typ: u8, nr: u8, size: usize) -> libc::c_ulong {
    ioc(3, typ, nr, size)
}

/// Size of `struct ptp_clock_caps` (10 `int`s + `rsv[11]` = 84 bytes).
const PTP_CLOCK_CAPS_SIZE: usize = 84;

const PTP_CLOCK_GETCAPS: u32 = 0x80087050u32;
const PTP_SYS_OFFSET: u32 = 0xc0087051u32;

// Convert a u32 ioctl constant to the platform-specific Ioctl type
// (u64 on glibc x86_64, i32 on musl x86_64).
fn ioctl_req(cmd: u32) -> libc::Ioctl {
    cmd as libc::Ioctl
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// The PHC reference-clock driver (chrony's `RCL_PHC_driver`).
///
/// Opens `/dev/ptpX` and reads the PTP hardware clock via `PTP_SYS_OFFSET` to
/// get precise cross-timestamped (PHC, system-clock) pairs.
#[derive(Debug)]
pub struct PhcDriver {
    device_path: Option<String>,
    fd: Option<RawFd>,
}

impl PhcDriver {
    /// Create a new PHC driver (no device path set).
    pub fn new() -> Self {
        PhcDriver {
            device_path: None,
            fd: None,
        }
    }

    /// Create a new PHC driver for the given device path.
    pub fn with_device(path: String) -> Self {
        PhcDriver {
            device_path: Some(path),
            fd: None,
        }
    }

    /// Parse the PHC device path from the driver parameter, stripping any
    /// `:option` suffixes (e.g. `:nocrossts`, `:extpps`, `:pin=1`).
    pub fn parse_config(params: &[&str]) -> Option<String> {
        params
            .first()
            .map(|s| s.split(':').next().unwrap_or(s).to_string())
    }

    /// Read the current PHC time via `PTP_SYS_OFFSET`.
    ///
    /// Returns `(phc_time, system_time)` where `system_time` is the midpoint
    /// of the kernel's pre/post system timestamps, giving the best estimate
    /// of the system time that corresponds to the PHC read.
    pub fn read_phc_time(&self) -> Option<(Timespec, Timespec)> {
        let fd = self.fd?;

        let mut off = ptp_sys_offset {
            n_samples: 1,
            rsv: [0; 3],
            // Zero-initialise the timestamp array.
            ts: [ptp_clock_time {
                sec: 0,
                nsec: 0,
                reserved: 0,
            }; 2 * PTP_MAX_SAMPLES + 1],
        };

        let ret = unsafe {
            libc::ioctl(
                fd,
                ioctl_req(PTP_SYS_OFFSET),
                std::ptr::addr_of_mut!(off).cast::<libc::c_void>(),
            )
        };
        if ret < 0 {
            return None;
        }

        // With n_samples=1, kernel fills ts[0..2]:
        //   ts[0] = system time before PHC read
        //   ts[1] = PHC time
        //   ts[2] = system time after PHC read
        let phc_ts = &off.ts[1];
        let sys_pre = &off.ts[0];
        let sys_post = &off.ts[2];

        // The system time midpoint is the best estimate of when the PHC was read.
        let sys_nsec_total = sys_pre.nsec as i64 + sys_post.nsec as i64;
        let sys_extra_sec = sys_nsec_total / 1_000_000_000;
        let sys_mid_nsec = (sys_nsec_total % 1_000_000_000) / 2;

        let phc_time = Timespec::new(phc_ts.sec, phc_ts.nsec as i64);
        let sys_time = Timespec::new(sys_pre.sec + sys_post.sec + sys_extra_sec, sys_mid_nsec);

        Some((phc_time, sys_time))
    }
}

impl Default for PhcDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl RefclockDriver for PhcDriver {
    fn has_init(&self) -> bool {
        true
    }

    fn init(&mut self) -> bool {
        let path = self.device_path.as_deref().unwrap_or("/dev/ptp0");
        let cpath = match std::ffi::CString::new(path) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // SAFETY: open() with a valid C string. The fd is stored and closed
        // in the Drop impl.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return false;
        }
        self.fd = Some(fd);

        // Read capabilities to verify this is a PHC device.
        let mut caps = [0u8; PTP_CLOCK_CAPS_SIZE];
        let ret = unsafe {
            libc::ioctl(
                fd,
                ioctl_req(PTP_CLOCK_GETCAPS),
                caps.as_mut_ptr() as *mut libc::c_void,
            )
        };
        if ret < 0 {
            // Not a PHC device or no permissions — close and fail.
            unsafe {
                libc::close(fd);
            }
            self.fd = None;
            return false;
        }

        true
    }
}

impl Drop for PhcDriver {
    fn drop(&mut self) {
        if let Some(fd) = self.fd {
            unsafe {
                libc::close(fd);
            }
        }
    }
}
