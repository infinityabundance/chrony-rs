//! Real event-loop host primitives — the injected `select()` and clock that turn the
//! (already-ported, pure) `chrony_rs_core::sched::Scheduler` into a live event loop.
//!
//! The scheduler's dispatch logic, timeout queue, and file-handler registry are ported and
//! unit-tested in core; only the two host primitives it takes by injection live here: the raw
//! clock (`clock_gettime`) and `select()`. This lets the daemon run a genuine event loop while
//! the scheduling *logic* stays `unsafe`-free and differential-tested.
//!
//! Also provides **drift file I/O** — `read_drift_file` and `write_drift_file` — using the
//! ported coefficient serialization format from `rtc_linux.rs` and atomic file operations.

use chrony_rs_core::sched::{Scheduler, SelectResult, Timespec};
use std::os::raw::c_int;

/// Read `CLOCK_REALTIME` into a [`Timespec`] (chrony's `LCL_ReadRawTime` in undisciplined
/// lab mode — the clock offset/frequency discipline is applied elsewhere).
fn read_realtime() -> Timespec {
    // SAFETY: clock_gettime into a local timespec.
    let mut ts: libc::timespec = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    Timespec::new(ts.tv_sec, ts.tv_nsec)
}

/// The real `select()` primitive: wait on the requested descriptor sets with an optional
/// timeout (seconds; `None` blocks), reporting readiness. Restarts on `EINTR` like chrony.
fn real_select(
    timeout: Option<f64>,
    rd: &[usize],
    wr: &[usize],
    ex: &[usize],
) -> SelectResult {
    // SAFETY: fd_set zeroing/setting and select over locally-built sets.
    unsafe {
        let mut readfds: libc::fd_set = std::mem::MaybeUninit::zeroed().assume_init();
        let mut writefds: libc::fd_set = std::mem::MaybeUninit::zeroed().assume_init();
        let mut exceptfds: libc::fd_set = std::mem::MaybeUninit::zeroed().assume_init();
        libc::FD_ZERO(&mut readfds);
        libc::FD_ZERO(&mut writefds);
        libc::FD_ZERO(&mut exceptfds);

        let mut nfds: c_int = 0;
        for &fd in rd {
            libc::FD_SET(fd as c_int, &mut readfds);
            nfds = nfds.max(fd as c_int + 1);
        }
        for &fd in wr {
            libc::FD_SET(fd as c_int, &mut writefds);
            nfds = nfds.max(fd as c_int + 1);
        }
        for &fd in ex {
            libc::FD_SET(fd as c_int, &mut exceptfds);
            nfds = nfds.max(fd as c_int + 1);
        }

        // Preserve original timeout before select() modifies it (Linux writes
        // remaining time into the timeval in-place on early return).
        let orig_timeval = timeout.map(|secs| {
            let secs = secs.max(0.0);
            libc::timeval {
                tv_sec: secs as libc::time_t,
                tv_usec: ((secs.fract()) * 1e6) as libc::suseconds_t,
            }
        });
        let orig_tv = orig_timeval.map(|tv| (tv.tv_sec as i64, tv.tv_usec as i64));

        let mut tv = orig_timeval;
        let status = loop {
            let tv_ptr = match &mut tv {
                Some(ref mut t) => t as *mut libc::timeval,
                None => std::ptr::null_mut(),
            };
            let r = libc::select(nfds, &mut readfds, &mut writefds, &mut exceptfds, tv_ptr);
            if r < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            break r;
        };

        let collect = |set: &libc::fd_set, fds: &[usize]| -> Vec<usize> {
            fds.iter()
                .copied()
                .filter(|&fd| libc::FD_ISSET(fd as c_int, set as *const libc::fd_set as *mut _))
                .collect()
        };

        // Capture the remaining timeout from the kernel-modified timeval.
        let rem_tv = if status == 0 {
            // select timed out — full timeout consumed
            orig_tv.map(|_| (0i64, 0i64))
        } else {
            orig_tv.map(|_| {
                let t = tv.unwrap_or(libc::timeval { tv_sec: 0, tv_usec: 0 });
                (t.tv_sec as i64, t.tv_usec as i64)
            })
        };

        SelectResult {
            status,
            ready_read: if status > 0 { collect(&readfds, rd) } else { Vec::new() },
            ready_write: if status > 0 { collect(&writefds, wr) } else { Vec::new() },
            ready_except: if status > 0 { collect(&exceptfds, ex) } else { Vec::new() },
            rem_tv,
        }
    }
}

/// A tiny non-cryptographic RNG for the scheduler's timeout jitter / tqe ids, seeded from the
/// clock (chrony uses `UTI_GetRandom`; the lab driver only needs uniform-ish spread).
fn make_rng() -> Box<dyn FnMut() -> u32> {
    let seed = read_realtime();
    let mut state = (seed.tv_nsec as u64) ^ 0x9E37_79B9_7F4A_7C15 ^ ((seed.tv_sec as u64) << 21);
    if state == 0 {
        state = 0x1234_5678_9ABC_DEF0;
    }
    Box::new(move || {
        // xorshift64.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state >> 32) as u32
    })
}

/// Build a live [`Scheduler`] (`SCH_Initialise`) driven by the real clock and `select()`. The
/// `cook_time` is the identity (raw == cooked) for undisciplined lab mode; a disciplined daemon
/// injects the clock's offset/frequency here.
pub fn new_scheduler() -> Scheduler {
    Scheduler::new(
        Box::new(read_realtime),
        Box::new(|raw| (raw, 0.0)),
        make_rng(),
        Box::new(real_select),
    )
}

/// Parse chrony's standard drift file format: `<freq_ppm> <skew_ppm>`.
/// Returns `(freq_ppm, skew_ppm)` or `None` if the file cannot be parsed.
fn parse_drift_file(content: &str) -> Option<(f64, f64)> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    let freq_ppm = parts[0].parse::<f64>().ok()?;
    let skew_ppm = parts.get(1).and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);
    Some((freq_ppm, skew_ppm))
}

/// Format frequency and skew as chrony's standard drift file line.
fn format_drift_file(freq_ppm: f64, skew_ppm: f64) -> String {
    format!("{:.6} {:.6}\n", freq_ppm, skew_ppm)
}

/// Read a chrony drift file. Returns `(freq_ppm, skew_ppm)` if the file exists and
/// parses correctly. The file format is chrony's standard single-line
/// `"<freq_ppm> <skew_ppm>\n"`.
pub fn read_drift_file(path: &str) -> Option<(f64, f64)> {
    let text = std::fs::read_to_string(path).ok()?;
    parse_drift_file(&text)
}

/// Write a chrony drift file atomically using a temp file + rename.
/// `path` is the final path; a temporary file is written next to it and renamed.
pub fn write_drift_file(path: &str, freq_ppm: f64, skew_ppm: f64) -> bool {
    let tmp = format!("{}.tmp", path);
    let line = format_drift_file(freq_ppm, skew_ppm);
    match std::fs::write(&tmp, &line) {
        Ok(_) => {
            match std::fs::rename(&tmp, path) {
                Ok(_) => true,
                Err(_) => {
                    let _ = std::fs::remove_file(&tmp);
                    false
                }
            }
        }
        Err(_) => false,
    }
}

/// Create an `fn()` closure that implements `read_drift_file` for use in `RefHost`.
pub fn make_drift_reader(path: String) -> Box<dyn FnMut() -> Option<(f64, f64)>> {
    Box::new(move || read_drift_file(&path))
}

/// Create an `fn(f64, f64)` closure that implements `write_drift_file` for use in `RefHost`.
pub fn make_drift_writer(path: String) -> Box<dyn FnMut(f64, f64)> {
    Box::new(move |freq_ppm, skew_ppm| { write_drift_file(&path, freq_ppm, skew_ppm); })
}

/// The real `adjtimex()` syscall: convert [`chrony_rs_core::sys_timex::Timex`] to
/// `libc::timex`, call `adjtimex`, and convert back.
///
/// This wires the ported `sys_timex` driver to the actual kernel syscall,
/// enabling real system-clock frequency/offset/tick adjustment.
pub fn real_adjtimex(tx: &mut chrony_rs_core::sys_timex::Timex) -> i32 {
    // Convert core Timex to libc::timex
    let mut ltx: libc::timex = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    ltx.modes = tx.modes as libc::c_uint;
    ltx.offset = tx.offset as libc::c_long;
    ltx.freq = tx.freq as libc::c_long;
    ltx.maxerror = tx.maxerror as libc::c_long;
    ltx.esterror = tx.esterror as libc::c_long;
    ltx.status = tx.status as libc::c_int;
    ltx.constant = tx.constant as libc::c_long;

    // SAFETY: adjtimex is a Linux syscall that reads/writes a timex struct.
    let rc: i32;
    unsafe {
        rc = libc::adjtimex(&mut ltx);
    }

    // Convert libc::timex back to core Timex (read fields the driver uses)
    tx.modes = ltx.modes as u32;
    tx.freq = ltx.freq as i64;
    tx.status = ltx.status as i32;
    tx.offset = ltx.offset as i64;
    tx.esterror = ltx.esterror as i64;
    tx.maxerror = ltx.maxerror as i64;
    tx.constant = ltx.constant as i64;
    rc
}

/// Step the system clock by `offset_secs` using the `ADJ_SETOFFSET` adjtimex
/// mode. This is the kernel-level equivalent of `LCL_ApplyStepOffset`.
/// Requires `CAP_SYS_TIME`. Returns `true` on success.
pub fn real_step_clock(offset_secs: f64) -> bool {
    let mut tx: libc::timex = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    tx.modes = libc::ADJ_SETOFFSET;
    let total_us = (offset_secs * 1_000_000.0) as i64;
    tx.time.tv_sec = total_us.div_euclid(1_000_000) as libc::time_t;
    tx.time.tv_usec = total_us.rem_euclid(1_000_000) as libc::suseconds_t;
    unsafe { libc::adjtimex(&mut tx) == 0 }
}

/// Create a `SysTimex` wired to the real `adjtimex()` syscall.
pub fn new_sys_timex(rtcsync: bool) -> chrony_rs_core::sys_timex::SysTimex {
    chrony_rs_core::sys_timex::SysTimex::new(Box::new(real_adjtimex), rtcsync)
}
