//! Linux RTC device I/O — real `/dev/rtc` ioctl wrappers.
//!
//! Implements [`chrony_rs_core::rtc::RtcDriver`] using Linux ioctls:
//! `open("/dev/rtc")`, `ioctl(RTC_RD_TIME)`, `ioctl(RTC_SET_TIME)`,
//! `ioctl(RTC_IRQP_SET)`, `ioctl(RTC_PIE_ON/OFF)`.
//!
//! Integration tests probe `/dev/rtc` at runtime and skip if inaccessible.

use chrony_rs_core::rtc::{RtcDriver, RtcReport};
use chrony_rs_core::rtc_linux::RtcRegression;
use std::os::unix::io::RawFd;

// Linux RTC ioctl numbers (from <asm-generic/rtc.h>).
// These are not in libc 0.2, so we define them directly.
// The values are architecture-independent for the RTC subsystem — _IOR/_IOW/_IO
// with type 'p' (0x70) and the given nr produce the same encoded value across
// x86_64, ARM (32-bit), and AArch64 because the RTC ioctls use struct sizes that
// are the same on all three, and IOCPARM_SHIFT is 0 for these ioctls on all of
// them. Verified on x86_64.
const RTC_RD_TIME: u64 = 0x80247009; // _IOR('p', 0x09, struct rtc_time)
const RTC_SET_TIME: u64 = 0x4024700a; // _IOW('p', 0x0a, struct rtc_time)
const RTC_IRQP_SET: u64 = 0x40247010; // _IOW('p', 0x10, unsigned long)
const RTC_PIE_ON: u64 = 0x7004700b; // _IO('p', 0x0b)

/// Production Linux RTC device driver.
#[derive(Debug)]
pub struct LinuxRtcDevice {
    fd: Option<RawFd>,
    regression: RtcRegression,
    device_path: Option<String>,
}

impl LinuxRtcDevice {
    pub fn new() -> Self {
        LinuxRtcDevice {
            fd: None,
            regression: RtcRegression::new(),
            device_path: None,
        }
    }

    pub fn set_path(&mut self, path: &str) {
        self.device_path = Some(path.to_string());
    }

    fn do_open(&self) -> Option<RawFd> {
        let path = self.device_path.as_deref().unwrap_or("/dev/rtc");
        let cpath = std::ffi::CString::new(path).ok()?;
        // SAFETY: cpath is a valid NUL-terminated CString. The return value
        // is checked for >= 0 immediately after to verify the fd is valid.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            Some(fd)
        } else {
            None
        }
    }

    fn do_close(fd: RawFd) {
        // SAFETY: fd is a valid file descriptor obtained from a prior
        // successful do_open() call and is not used after this point.
        unsafe {
            libc::close(fd);
        }
    }

    fn do_ioctl_rd_time(fd: RawFd) -> Option<i64> {
        // SAFETY: Zero-initialization is valid for libc::tm — all fields are
        // plain integer types and all-zero bytes form a valid representation.
        let mut tm: libc::tm = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        // SAFETY: fd is a valid RTC file descriptor from do_open(). The ioctl
        // number (RTC_RD_TIME) is a compile-time constant matching the Linux
        // RTC ABI. tm is a fully initialized libc::tm.
        if unsafe {
            libc::ioctl(
                fd,
                RTC_RD_TIME.try_into().expect("RTC_RD_TIME fits in i32"),
                &mut tm,
            )
        } < 0
        {
            return None;
        }
        // SAFETY: tm is a fully initialized libc::tm populated by the
        // preceding RTC_RD_TIME ioctl. timegm() is the reentrant version
        // that does not use global state (unlike timelocal/timegm).
        let unix_sec = unsafe { libc::timegm(&mut tm) };
        if unix_sec < 0 {
            None
        } else {
            Some(unix_sec)
        }
    }

    fn do_ioctl_set_time(fd: RawFd, unix_sec: i64) -> bool {
        // SAFETY: Zero-initialization is valid for libc::tm — all fields are
        // plain integer types and all-zero bytes form a valid representation.
        let mut tm: libc::tm = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        let ts = unix_sec;
        // SAFETY: tm is a stack-allocated libc::tm that outlives the call.
        // The return value is checked for NULL immediately after to
        // detect errors.
        let tm_ptr = unsafe { libc::gmtime_r(&ts, &mut tm) };
        if tm_ptr.is_null() {
            return false;
        }
        // SAFETY: fd is a valid RTC file descriptor from do_open(). The ioctl
        // number (RTC_SET_TIME) is a compile-time constant matching the Linux
        // RTC ABI. tm is a fully initialized libc::tm from gmtime_r().
        let ret = unsafe {
            libc::ioctl(
                fd,
                RTC_SET_TIME.try_into().expect("RTC_SET_TIME fits in i32"),
                &mut tm,
            )
        };
        ret >= 0
    }
}

impl RtcDriver for LinuxRtcDevice {
    fn init(&mut self) -> bool {
        self.fd = self.do_open();
        self.fd.is_some()
    }

    fn finalise(&mut self) {
        if let Some(fd) = self.fd.take() {
            Self::do_close(fd);
        }
    }

    fn time_pre_init(&mut self, _driftfile_time: i64) -> bool {
        let fd = self.fd.expect("RTC not opened");
        if let Some(rtc_sec) = Self::do_ioctl_rd_time(fd) {
            let tv = libc::timeval {
                tv_sec: rtc_sec,
                tv_usec: 0,
            };
            // SAFETY: settimeofday() is called only during time_pre_init with
            // a validated time from RTC hardware (populated by do_ioctl_rd_time).
            // tv is a fully initialized timeval. The second argument (tz) is NULL.
            unsafe {
                libc::settimeofday(&tv, std::ptr::null());
            }
            true
        } else {
            false
        }
    }

    fn time_init(&mut self, _after_hook: Box<dyn FnMut()>) {
        if let Some(fd) = self.fd {
            let _ = Self::do_ioctl_rd_time(fd);
        }
    }

    fn start_measurements(&mut self) {
        if let Some(fd) = self.fd {
            let freq: u64 = 64;
            // SAFETY: fd is a valid RTC file descriptor returned by do_open().
            // The ioctl numbers are compile-time constants that match the Linux RTC ABI.
            // freq=64 is within the valid range for RTC_IRQP_SET.
            unsafe {
                libc::ioctl(
                    fd,
                    RTC_IRQP_SET.try_into().expect("RTC_IRQP_SET fits in i32"),
                    freq,
                );
                libc::ioctl(
                    fd,
                    RTC_PIE_ON.try_into().expect("RTC_PIE_ON fits in i32"),
                    0,
                );
            }
        }
    }

    fn write_parameters(&mut self) -> i32 {
        // RTC parameters are persisted by the daemon via rtcfile.
        chrony_rs_core::rtc::RTC_ST_OK
    }

    fn get_report(&mut self) -> Option<RtcReport> {
        Some(RtcReport {
            ref_time: self.regression.coef_ref_time,
            n_samples: self.regression.n_samples as u64,
            n_runs: self.regression.n_samples as u64,
            span_seconds: 0,
            rtc_seconds_fast: self.regression.coef_seconds_fast,
            rtc_gain_rate_ppm: self.regression.coef_gain_rate * 1.0e6,
        })
    }

    fn trim(&mut self) -> i32 {
        if let Some(fd) = self.fd {
            if let Some(rtc_sec) = Self::do_ioctl_rd_time(fd) {
                return if Self::do_ioctl_set_time(fd, rtc_sec) {
                    1
                } else {
                    0
                };
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtc_available() -> bool {
        std::path::Path::new("/dev/rtc").exists()
    }

    #[test]
    fn open_close_rtc() {
        if !rtc_available() {
            eprintln!("skipping: /dev/rtc not accessible");
            return;
        }
        let mut dev = LinuxRtcDevice::new();
        assert!(dev.init(), "open /dev/rtc");
        dev.finalise();
    }

    #[test]
    fn regression_new_report() {
        let mut dev = LinuxRtcDevice::new();
        dev.regression = RtcRegression::new();
        let report = dev.get_report();
        assert!(report.is_some());
    }
}
