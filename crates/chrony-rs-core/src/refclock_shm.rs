//! SHM reference-clock driver — a complete port of chrony 4.5 `refclock_shm.c`.
//!
//! # What this module is
//!
//! The SHM driver reads time from a System-V shared-memory segment in the format
//! shared by `ntpd`/`gpsd` (`struct shmTime`, segment key `0x4e545030 + unit`). It is
//! one of the platform drivers behind the [`crate::refclock`] framework ported in
//! file 33: GPS daemons write timestamps into the segment and chrony polls them.
//!
//! # What it ports
//!
//! `shm_poll`'s sample-extraction *logic*: the validity gates (mode 0/1, the mode-1
//! count-stability check against a concurrent writer, the `valid` flag), clearing
//! `valid`, and the timestamp assembly — chrony prefers the nanosecond fields when
//! they are consistent with the microsecond fields, else falls back to
//! microseconds — followed by normalisation. The resulting `(receive, clock, leap)`
//! is what the framework feeds to `RCL_AddSample`. `shm_initialise`'s option/permission
//! parsing (`perm` octal, the `SHMKEY + unit` segment key) is ported as
//! [`ShmDriver::config`].
//!
//! # Adaptations (documented, not silent)
//!
//! * **The shared-memory segment is injected** via [`ShmSource`] (chrony's
//!   `shmget`/`shmat` and the `RCL_SetDriverData` pointer); the snapshot semantics
//!   (`t = *shm` then a re-read of `shm->count`) are preserved exactly.
//! * **The framework calls are the daemon's**: `poll` returns the extracted sample
//!   for the daemon to hand to [`crate::refclock::RefclockManager::add_sample`],
//!   resolving the driver↔framework re-entrancy as the rest of the refclock port does.
//!
//! # Oracle
//!
//! `shm_poll` is differential-tested against the **real compiled `refclock_shm.c`**:
//! a C generator drives the real `RCL_SHM_driver.poll` over a controlled `shmTime`
//! segment (stubbed `shmget`/`shmat`) and records the `(receive_ts, clock_ts, leap)`
//! handed to a stubbed `RCL_AddSample`, plus the validity rejections
//! (`research/oracle/refclock_shm-c-vectors.txt`). The port replays the identical
//! snapshots and matches every field and decision; the key/permission parsing is
//! unit-tested. See the tests.

use crate::reference::Timespec;

/// chrony `SHMKEY` — the base System-V IPC key (`+ unit`).
pub const SHMKEY: i32 = 0x4e54_5030;

/// chrony's `struct shmTime` (the `ntpd`/`gpsd` shared-memory layout).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShmTime {
    /// 0 = plain valid flag; 1 = use only if `count` is stable across the read.
    pub mode: i32,
    pub count: i32,
    pub clock_sec: i64,
    pub clock_usec: i32,
    pub recv_sec: i64,
    pub recv_usec: i32,
    pub leap: i32,
    pub precision: i32,
    pub nsamples: i32,
    pub valid: i32,
    pub clock_nsec: i32,
    pub recv_nsec: i32,
}

/// The shared-memory segment, injected (chrony reaches it through the `shmat`
/// pointer stored as the driver's data).
pub trait ShmSource {
    /// `t = *shm`: an atomic-enough snapshot of the whole segment.
    fn snapshot(&mut self) -> ShmTime;
    /// Re-read `shm->count` (used to detect a concurrent writer in mode 1).
    fn current_count(&mut self) -> i32;
    /// `shm->valid = 0`: consume the sample.
    fn clear_valid(&mut self);
}

/// `UTI_NormaliseTimespec`: bring `nsec` into `[0, 1e9)`.
fn normalise(ts: &mut Timespec) {
    if ts.nsec >= 1_000_000_000 || ts.nsec < 0 {
        ts.sec += (ts.nsec / 1_000_000_000) as i64;
        ts.nsec %= 1_000_000_000;
        if ts.nsec < 0 {
            ts.sec -= 1;
            ts.nsec += 1_000_000_000;
        }
    }
}

/// The SHM reference-clock driver (chrony's `RCL_SHM_driver`).
pub struct ShmDriver;

impl ShmDriver {
    /// chrony `shm_initialise`'s configuration: parse the unit number from the driver
    /// parameter and the optional octal `perm` option, returning the segment key and
    /// permission bits handed to `shmget(SHMKEY + unit, …, IPC_CREAT | perm)`.
    pub fn config(param: &str, perm_option: Option<&str>) -> (i32, u32) {
        // atoi: leading integer, 0 on garbage.
        let unit: i32 = {
            let t = param.trim();
            let end = t
                .find(|c: char| !c.is_ascii_digit() && c != '-' && c != '+')
                .unwrap_or(t.len());
            t[..end].parse().unwrap_or(0)
        };
        let perm = match perm_option {
            // strtol(s, NULL, 8) & 0777
            Some(s) => i64::from_str_radix(octal_prefix(s.trim()), 8).unwrap_or(0) as u32 & 0o777,
            None => 0o600,
        };
        (SHMKEY.wrapping_add(unit), perm)
    }

    /// chrony `shm_poll`: extract a sample from the segment, or `None` if it is not
    /// valid. Returns `(receive_ts, clock_ts, leap)` for the framework to accumulate.
    pub fn poll(&self, shm: &mut dyn ShmSource) -> Option<(Timespec, Timespec, i32)> {
        let t = shm.snapshot();

        if (t.mode == 1 && t.count != shm.current_count())
            || !(t.mode == 0 || t.mode == 1)
            || t.valid == 0
        {
            return None;
        }

        shm.clear_valid();

        let mut receive_ts = Timespec { sec: t.recv_sec, nsec: 0 };
        let mut clock_ts = Timespec { sec: t.clock_sec, nsec: 0 };

        // Prefer the nanosecond fields when consistent with the microsecond fields.
        if t.clock_nsec / 1000 == t.clock_usec && t.recv_nsec / 1000 == t.recv_usec {
            receive_ts.nsec = t.recv_nsec;
            clock_ts.nsec = t.clock_nsec;
        } else {
            receive_ts.nsec = 1000 * t.recv_usec;
            clock_ts.nsec = 1000 * t.clock_usec;
        }

        normalise(&mut clock_ts);
        normalise(&mut receive_ts);

        Some((receive_ts, clock_ts, t.leap))
    }
}

/// The leading octal digits of `s` (what `strtol(s, NULL, 8)` consumes).
fn octal_prefix(s: &str) -> &str {
    let end = s.find(|c: char| !('0'..='7').contains(&c)).unwrap_or(s.len());
    if end == 0 {
        "0"
    } else {
        &s[..end]
    }
}

#[cfg(test)]
mod tests;
