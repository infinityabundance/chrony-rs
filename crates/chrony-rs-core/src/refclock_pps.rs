//! PPS reference-clock driver — a port of chrony 4.5 `refclock_pps.c`.
//!
//! The PPS driver opens `/dev/ppsX` and uses the `PPS_GETPARAMS`/`PPS_SETPARAMS`/
//! `PPS_FETCH` ioctls to capture precise timestamps from the kernel's PPS
//! subsystem. It is one of the platform drivers behind the [`crate::refclock`]
//! framework.

use std::os::unix::io::RawFd;

use crate::refclock::RefclockDriver;
use crate::sys_generic::Timespec;

// ---------------------------------------------------------------------------
// Linux PPS kernel structs (from <linux/pps.h>)
// ---------------------------------------------------------------------------

/// Kernel `struct pps_ktime`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct pps_ktime {
    sec: i64,
    nsec: i32,
    flags: u32,
}

/// Kernel `struct pps_kparams`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct pps_kparams {
    api_version: i32,
    mode: i32,
    assert_off_tu: pps_ktime,
    clear_off_tu: pps_ktime,
}

/// Kernel `struct pps_kinfo`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct pps_kinfo {
    assert_sequence: u32,
    clear_sequence: u32,
    assert_tu: pps_ktime,
    clear_tu: pps_ktime,
    current_mode: i32,
}

/// Kernel `struct pps_fdata`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct pps_fdata {
    info: pps_kinfo,
    timeout: pps_ktime,
}

// ---------------------------------------------------------------------------
// PPS ioctl constants
//
// From <linux/pps.h>:
//   #define PPS_GETPARAMS  _IOR('p', 0xa1, struct pps_kparams *)
//   #define PPS_SETPARAMS  _IOW('p', 0xa2, struct pps_kparams *)
//   #define PPS_FETCH      _IOWR('p', 0xa4, struct pps_fdata *)
//
// Encoding: _IOC(dir, type, nr, size) = (dir<<30)|(type<<8)|(nr<<0)|(size<<16)
// Since these pass pointers, size = sizeof(void *) = 8 on 64-bit.
// ---------------------------------------------------------------------------

// Use c_int for ioctl since libc::ioctl on this platform expects i32 request number
const PPS_GETPARAMS: u32 = 0x800870a1u32;
const PPS_SETPARAMS: u32 = 0x400870a2u32;
const PPS_FETCH: u32 = 0xc00870a4u32;

// Convert a u32 ioctl constant to the platform-specific Ioctl type
// (u64 on glibc x86_64, i32 on musl x86_64).
fn ioctl_req(cmd: u32) -> libc::Ioctl {
    cmd as libc::Ioctl
}

// ---------------------------------------------------------------------------
// Mode bits (from <linux/pps.h>)
// ---------------------------------------------------------------------------

/// Capture assert (rising-edge) events.
const PPS_CAPTUREASSERT: i32 = 0x01;
/// Capture clear (falling-edge) events.
const PPS_CAPTURECLEAR: i32 = 0x02;

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// The PPS reference-clock driver (chrony's `RCL_PPS_driver`).
///
/// Opens `/dev/ppsX` and uses the kernel PPS subsystem ioctls to capture
/// assert or clear timestamps with nanosecond precision.
#[derive(Debug)]
pub struct PpsDriver {
    device_path: Option<String>,
    fd: Option<RawFd>,
    clear: bool,
    /// Polling interval in seconds passed to `PPS_FETCH` as the timeout.
    poll_interval: f64,
}

impl PpsDriver {
    /// Create a new PPS driver with default settings (no device path, assert mode).
    pub fn new() -> Self {
        PpsDriver {
            device_path: None,
            fd: None,
            clear: false,
            poll_interval: 1.0,
        }
    }

    /// Create a new PPS driver for the given device path.
    pub fn with_device(path: String) -> Self {
        PpsDriver {
            device_path: Some(path),
            fd: None,
            clear: false,
            poll_interval: 1.0,
        }
    }

    /// Create a PPS driver for the given device path in `:clear` mode.
    pub fn with_clear(path: String) -> Self {
        PpsDriver {
            device_path: Some(path),
            fd: None,
            clear: true,
            poll_interval: 1.0,
        }
    }

    /// Parse the PPS device path and optional `:clear` flag from the driver
    /// parameter (the first colon-delimited segment, e.g. `/dev/pps0:clear`).
    pub fn parse_config(params: &[&str]) -> Option<(String, bool)> {
        let part = params.first()?;
        let mut parts = part.split(':');
        let path = parts.next().unwrap_or("/dev/pps0").to_string();
        let clear = parts.any(|s| s == "clear");
        Some((path, clear))
    }

    /// Set the poll interval (in seconds) used as the `PPS_FETCH` timeout.
    pub fn set_poll_interval(&mut self, interval: f64) {
        self.poll_interval = interval;
    }

    /// Set the capture mode: `true` for clear events, `false` for assert events.
    pub fn set_capture_clear(&mut self, clear: bool) {
        self.clear = clear;
    }

    /// Fetch a PPS timestamp from the device.
    ///
    /// Blocks up to `timeout_secs` seconds waiting for the next PPS event.
    /// Returns `Some(timestamp)` on success, or `None` on timeout or error.
    pub fn read_pps(&self, timeout_secs: f64) -> Option<Timespec> {
        let fd = self.fd?;

        let mut fdata = pps_fdata {
            info: pps_kinfo {
                assert_sequence: 0,
                clear_sequence: 0,
                assert_tu: pps_ktime {
                    sec: 0,
                    nsec: 0,
                    flags: 0,
                },
                clear_tu: pps_ktime {
                    sec: 0,
                    nsec: 0,
                    flags: 0,
                },
                current_mode: 0,
            },
            timeout: pps_ktime {
                sec: timeout_secs as i64,
                nsec: ((timeout_secs - (timeout_secs as i64 as f64)) * 1.0e9) as i32,
                flags: 0,
            },
        };

        // Set the event mask: PPS_CAPTUREASSERT or PPS_CAPTURECLEAR
        // The event mask is stored in the upper 8 bits of info.current_mode,
        // but the actual filtering is done by the kernel based on params.mode.
        // The PPS_FETCH ioctl expects the timeout to be set in the timeout field.
        // The kernel returns the captured timestamp in info.assert_tu or info.clear_tu.

        let ret = unsafe {
            libc::ioctl(
                fd,
                ioctl_req(PPS_FETCH),
                &mut fdata as *mut pps_fdata as *mut libc::c_void,
            )
        };
        if ret < 0 {
            return None;
        }

        // Extract the appropriate timestamp
        let ts = if self.clear {
            fdata.info.clear_tu
        } else {
            fdata.info.assert_tu
        };

        Some(Timespec::new(ts.sec, ts.nsec as i64))
    }
}

impl Default for PpsDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl RefclockDriver for PpsDriver {
    fn has_init(&self) -> bool {
        true
    }

    fn init(&mut self) -> bool {
        let path = self.device_path.as_deref().unwrap_or("/dev/pps0");
        let cpath = match std::ffi::CString::new(path) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // SAFETY: open() with a valid C string path. The fd is stored and
        // closed in the Drop impl.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return false;
        }
        self.fd = Some(fd);

        // Read current PPS parameters via PPS_GETPARAMS.
        let mut params = pps_kparams {
            api_version: 0,
            mode: 0,
            assert_off_tu: pps_ktime {
                sec: 0,
                nsec: 0,
                flags: 0,
            },
            clear_off_tu: pps_ktime {
                sec: 0,
                nsec: 0,
                flags: 0,
            },
        };

        let ret = unsafe {
            libc::ioctl(
                fd,
                ioctl_req(PPS_GETPARAMS),
                &mut params as *mut pps_kparams as *mut libc::c_void,
            )
        };
        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            self.fd = None;
            return false;
        }

        // Set the capture mode: assert or clear (or both).
        params.api_version = 1;
        params.mode = if self.clear {
            PPS_CAPTURECLEAR
        } else {
            PPS_CAPTUREASSERT
        };

        let ret = unsafe {
            libc::ioctl(
                fd,
                ioctl_req(PPS_SETPARAMS),
                &params as *const pps_kparams as *const libc::c_void,
            )
        };
        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            self.fd = None;
            return false;
        }

        true
    }
}

impl Drop for PpsDriver {
    fn drop(&mut self) {
        if let Some(fd) = self.fd {
            unsafe {
                libc::close(fd);
            }
        }
    }
}
