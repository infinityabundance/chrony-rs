//! SOCK reference-clock driver — a complete port of chrony 4.5 `refclock_sock.c`.
//!
//! # What this module is
//!
//! The SOCK driver receives time samples as datagrams on a Unix-domain socket in the
//! format used by `gpsd` and similar daemons (`struct sock_sample`, protocol magic
//! `0x534f434b` = `"SOCK"`). It is the second platform driver behind the
//! [`crate::refclock`] framework ported in file 33.
//!
//! # The wire format (`struct sock_sample`, 64-bit `time_t`)
//!
//! ```text
//! tv_sec:i64  tv_usec:i64  offset:f64  pulse:i32  leap:i32  _pad:i32  magic:i32
//! ```
//!
//! 40 bytes, native-endian. `magic` must be `"SOCK"`; `pulse` routes the sample to a
//! PPS pulse rather than a normal offset sample.
//!
//! # What it ports
//!
//! `read_sample`'s logic: the datagram length check, the magic-number gate, the
//! `timeval`→`timespec` conversion + normalisation, the time-offset sanity gate, and
//! the pulse-vs-sample routing (a `pulse` sample becomes `RCL_AddPulse(sys_ts,
//! offset)`; otherwise `RCL_AddSample(sys_ts, sys_ts + offset, leap)`). `sock_initialise`
//! is the socket open + file-handler registration (the host's).
//!
//! # Adaptations (documented, not silent)
//!
//! * **The datagram socket is the host's.** chrony opens it in `sock_initialise` and
//!   the scheduler calls `read_sample` on input; here [`SockDriver::read_sample`]
//!   takes the received bytes and returns the [`SockOutput`] for the daemon to hand to
//!   the framework ([`crate::refclock::RefclockManager::add_sample`] / `add_pulse`).
//! * **The 32-bit-`time_t` conversion path** (`CONVERT_TIMEVAL`, only compiled on
//!   glibc ≥ 2.34 with a 32-bit `__TIMESIZE`) is not modelled; this port targets the
//!   native 40-byte layout, exactly as the differential oracle's build does.
//!
//! # Oracle
//!
//! `read_sample` is differential-tested against the **real compiled
//! `refclock_sock.c`**: a C generator builds `sock_sample` datagrams (so the bytes
//! carry the C struct layout), feeds them to the real `read_sample` (captured via the
//! file-handler stub, with `recv` returning the crafted bytes), and records both the
//! raw datagram bytes and the `RCL_AddSample`/`RCL_AddPulse` arguments, plus the
//! magic / length / sanity rejections (`research/oracle/refclock_sock-c-vectors.txt`).
//! [`tests`] feeds the identical bytes to the port and matches every field; the
//! routing is exercised across normal, pulse, and rejected datagrams. See the tests.

use crate::reference::Timespec;

/// chrony `SOCK_MAGIC` (`"SOCK"`).
pub const SOCK_MAGIC: i32 = 0x534f_434b;

/// `sizeof(struct sock_sample)` on a 64-bit `time_t` build.
pub const SOCK_SAMPLE_SIZE: usize = 40;

/// A decoded `struct sock_sample`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SockSample {
    pub tv_sec: i64,
    pub tv_usec: i64,
    pub offset: f64,
    pub pulse: i32,
    pub leap: i32,
    pub magic: i32,
}

/// What `read_sample` extracted: the framework call it would make, or nothing.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SockOutput {
    /// `RCL_AddSample(sys_ts, ref_ts, leap)`.
    Sample { sys_ts: Timespec, ref_ts: Timespec, leap: i32 },
    /// `RCL_AddPulse(sys_ts, offset)`.
    Pulse { sys_ts: Timespec, offset: f64 },
}

/// The SOCK reference-clock driver (chrony's `RCL_SOCK_driver`).
pub struct SockDriver;

impl SockDriver {
    /// Decode a `sock_sample` from a native-endian datagram, or `None` if the length
    /// is not exactly `sizeof(struct sock_sample)`.
    pub fn parse_sample(buf: &[u8]) -> Option<SockSample> {
        if buf.len() != SOCK_SAMPLE_SIZE {
            return None;
        }
        let rd_i64 = |o: usize| i64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
        let rd_f64 = |o: usize| f64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
        let rd_i32 = |o: usize| i32::from_ne_bytes(buf[o..o + 4].try_into().unwrap());
        Some(SockSample {
            tv_sec: rd_i64(0),
            tv_usec: rd_i64(8),
            offset: rd_f64(16),
            pulse: rd_i32(24),
            leap: rd_i32(28),
            // _pad at 32
            magic: rd_i32(36),
        })
    }

    /// chrony `read_sample`: decode one received datagram and produce the framework
    /// call, or `None` if it is rejected (bad length / magic / insane offset).
    pub fn read_sample(buf: &[u8]) -> Option<SockOutput> {
        let sample = Self::parse_sample(buf)?;

        if sample.magic != SOCK_MAGIC {
            return None;
        }

        // UTI_TimevalToTimespec + UTI_NormaliseTimespec.
        let total_nsec = sample.tv_usec * 1000;
        let sys_ts = Timespec {
            sec: sample.tv_sec + total_nsec.div_euclid(1_000_000_000),
            nsec: total_nsec.rem_euclid(1_000_000_000) as i32,
        };

        if !crate::refclock::is_time_offset_sane(sys_ts, sample.offset) {
            return None;
        }

        let ref_ts = sys_ts.add_double(sample.offset);

        if sample.pulse != 0 {
            Some(SockOutput::Pulse { sys_ts, offset: sample.offset })
        } else {
            Some(SockOutput::Sample { sys_ts, ref_ts, leap: sample.leap })
        }
    }
}

#[cfg(test)]
mod tests;
