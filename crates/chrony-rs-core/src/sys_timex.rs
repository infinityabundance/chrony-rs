//! `adjtimex()`/`ntp_adjtime()` clock driver — a complete port of chrony 4.5
//! `sys_timex.c` (all 10 functions), the Linux/POSIX system-call driver that sits
//! under the generic slew layer ([`crate::sys_generic`]).
//!
//! # What this module is
//!
//! `sys_timex.c` is the thin driver that talks to the kernel's `adjtimex` /
//! `ntp_adjtime` system call: it reads and sets the clock frequency, reports
//! synchronization status and estimated/maximum error, and arms/disarms a leap
//! second (and the TAI offset). The only OS boundary is the single syscall; the
//! rest is frequency scaling and status-flag bookkeeping over the kernel's
//! `struct timex` ABI. It completes the generic driver by registering its
//! frequency read/set with [`crate::sys_generic`].
//!
//! # Adaptations (documented, not silent)
//!
//! * **The syscall is injected.** `adjtimex` is a closure `FnMut(&mut Timex) -> i32`
//!   that may modify the [`Timex`] (the kernel writes back the current frequency
//!   etc.) and returns the clock state. This keeps the brain free of real syscalls
//!   while reproducing exactly what chrony submits.
//! * **`struct timex`, the read fields only.** chrony leaves the fields it is not
//!   setting *uninitialized* and relies on the kernel ignoring any field whose
//!   `modes` bit is clear. [`Timex`] is zero-initialized and the port sets exactly
//!   the fields chrony sets; the differential oracle compares only the fields the
//!   given `modes` selects, which is precisely what the kernel reads.
//! * **Linux build.** This targets chrony's Linux configuration (`-DLINUX`): the
//!   `UNSYNC` flag is cleared only when `rtcsync` is enabled (injected as config),
//!   and the leap path compiles the `MOD_TAI` branch.
//!
//! # Oracles
//!
//! Differential-tested against the **real compiled `sys_timex.c`** (+ `sys_generic.c`):
//! a C generator replaces `adjtimex` with a recording stub modeling a kernel
//! frequency register and captures every submitted `struct timex` across an
//! initialise / set-frequency / set-sync-status / set-leap sequence
//! (`research/oracle/sys_timex-c-vectors.txt`). The port drives the identical
//! sequence and must submit the identical `timex` values (masked by `modes`). A
//! second, independent check verifies the ppm⇄kernel-freq scaling
//! (`freq = ppm·-2^16`, `ppm = -freq/2^16`). See the tests.

use crate::sys_generic::{FreqDriver, SysGeneric, Timespec};

// ---- kernel `struct timex` mode bits (Linux ABI) ----
const MOD_OFFSET: u32 = 0x0001;
const MOD_FREQUENCY: u32 = 0x0002;
const MOD_MAXERROR: u32 = 0x0004;
const MOD_ESTERROR: u32 = 0x0008;
const MOD_STATUS: u32 = 0x0010;
#[allow(dead_code)]
const MOD_TIMECONST: u32 = 0x0020;
const MOD_TAI: u32 = 0x0080;

// ---- status bits ----
const STA_PLL: i32 = 0x0001;
const STA_INS: i32 = 0x0010;
const STA_DEL: i32 = 0x0020;
const STA_UNSYNC: i32 = 0x0040;

/// Clock state returned by `adjtimex` meaning a leap second has occurred
/// (`TIME_WAIT`).
pub const TIME_WAIT: i32 = 4;
/// Clock state `TIME_OK`.
pub const TIME_OK: i32 = 0;

/// chrony `MAX_FREQ`: maximum frequency offset the kernel accepts (ppm).
pub const MAX_FREQ: f64 = 500.0;
/// chrony `FREQ_SCALE`: ppm → kernel `freq` units (`2^16`).
const FREQ_SCALE: f64 = 65536.0;
/// chrony `MAX_SYNC_ERROR`: threshold for the kernel's UNSYNC flag (seconds).
const MAX_SYNC_ERROR: f64 = 16.0;
/// chrony `MIN_TICK_RATE`: assumed minimum kernel clock-update rate.
const MIN_TICK_RATE: f64 = 100.0;

/// The subset of the kernel `struct timex` chrony's `sys_timex.c` touches, with the
/// kernel's field widths (`long` ⇒ `i64`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timex {
    /// Which fields are being set (`MOD_*` bits).
    pub modes: u32,
    /// Frequency offset, kernel units (`ppm · 2^16`, scaled, negated).
    pub freq: i64,
    /// Clock status (`STA_*` bits).
    pub status: i32,
    /// PLL time offset.
    pub offset: i64,
    /// Estimated error, microseconds.
    pub esterror: i64,
    /// Maximum error, microseconds.
    pub maxerror: i64,
    /// PLL time constant / TAI offset (when `MOD_TAI`).
    pub constant: i64,
}

/// The `adjtimex`/`ntp_adjtime` driver state (chrony's `sys_timex.c` statics) over
/// an injected syscall.
pub struct SysTimex {
    /// Injected `adjtimex` syscall.
    adjtimex: Box<dyn FnMut(&mut Timex) -> i32>,
    /// chrony `sys_status`: the saved timex status flags.
    sys_status: i32,
    /// chrony `sys_tai_offset`.
    sys_tai_offset: i32,
    /// Whether `rtcsync` is enabled (Linux: gate clearing the UNSYNC flag).
    rtcsync: bool,
}

impl SysTimex {
    /// Create the driver over an injected `adjtimex` syscall and `rtcsync` setting,
    /// running chrony's `initialise_timex` (resets the PLL, leaves the clock
    /// unsynchronized).
    pub fn new(adjtimex: Box<dyn FnMut(&mut Timex) -> i32>, rtcsync: bool) -> Self {
        let mut t = SysTimex { adjtimex, sys_status: 0, sys_tai_offset: 0, rtcsync };
        t.initialise_timex();
        t
    }

    /// chrony `SYS_Timex_Adjust`: submit a `timex` to the kernel (Linux build — no
    /// Solaris `constant` fixup).
    pub fn adjust(&mut self, txc: &mut Timex) -> i32 {
        (self.adjtimex)(txc)
    }

    /// chrony `convert_timex_frequency`: kernel `freq` → ppm (negated).
    pub fn convert_timex_frequency(txc: &Timex) -> f64 {
        let freq_ppm = txc.freq as f64 / FREQ_SCALE;
        -freq_ppm
    }

    /// chrony `read_frequency`.
    pub fn read_frequency(&mut self) -> f64 {
        let mut txc = Timex { modes: 0, ..Default::default() };
        self.adjust(&mut txc);
        Self::convert_timex_frequency(&txc)
    }

    /// chrony `set_frequency`.
    pub fn set_frequency(&mut self, freq_ppm: f64) -> f64 {
        let mut txc = Timex {
            modes: MOD_FREQUENCY,
            freq: (freq_ppm * -FREQ_SCALE) as i64,
            ..Default::default()
        };
        self.adjust(&mut txc);
        Self::convert_timex_frequency(&txc)
    }

    /// chrony `set_leap`: arm/disarm a leap second and set the TAI offset.
    pub fn set_leap(&mut self, leap: i32, tai_offset: i32) {
        let mut txc = Timex { modes: 0, ..Default::default() };
        let applied = self.adjust(&mut txc) == TIME_WAIT;

        let prev_status = self.sys_status;
        self.sys_status &= !(STA_INS | STA_DEL);

        if leap > 0 {
            self.sys_status |= STA_INS;
        } else if leap < 0 {
            self.sys_status |= STA_DEL;
        }

        let mut txc = Timex { modes: MOD_STATUS, status: self.sys_status, ..Default::default() };

        // MOD_TAI branch (compiled on Linux).
        if tai_offset != 0 {
            txc.modes |= MOD_TAI;
            txc.constant = tai_offset as i64;

            if applied && (self.sys_status & (STA_INS | STA_DEL)) == 0 {
                self.sys_tai_offset += if prev_status & STA_INS != 0 { 1 } else { -1 };
            }
            if self.sys_tai_offset != tai_offset {
                self.sys_tai_offset = tai_offset;
            }
        }

        self.adjust(&mut txc);
    }

    /// chrony `set_sync_status`.
    pub fn set_sync_status(&mut self, synchronised: bool, est_error: f64, max_error: f64) {
        let mut synchronised = synchronised;
        let mut est_error = est_error;
        let mut max_error = max_error;

        if synchronised {
            if est_error > MAX_SYNC_ERROR {
                est_error = MAX_SYNC_ERROR;
            }
            if max_error >= MAX_SYNC_ERROR {
                max_error = MAX_SYNC_ERROR;
                synchronised = false;
            }
        } else {
            est_error = MAX_SYNC_ERROR;
            max_error = MAX_SYNC_ERROR;
        }

        // Linux: clear the UNSYNC flag only if rtcsync is enabled.
        if !self.rtcsync {
            synchronised = false;
        }

        if synchronised {
            self.sys_status &= !STA_UNSYNC;
        } else {
            self.sys_status |= STA_UNSYNC;
        }

        let mut txc = Timex {
            modes: MOD_STATUS | MOD_ESTERROR | MOD_MAXERROR,
            status: self.sys_status,
            esterror: (est_error * 1.0e6) as i64,
            maxerror: (max_error * 1.0e6) as i64,
            ..Default::default()
        };
        self.adjust(&mut txc);
    }

    /// chrony `initialise_timex`: reset the PLL offset, then turn the PLL off,
    /// leaving the clock unsynchronized.
    fn initialise_timex(&mut self) {
        self.sys_status = STA_UNSYNC;
        self.sys_tai_offset = 0;

        // Reset PLL offset.
        let mut txc = Timex {
            modes: MOD_OFFSET | MOD_STATUS,
            status: STA_PLL | self.sys_status,
            offset: 0,
            ..Default::default()
        };
        self.adjust(&mut txc);

        // Turn PLL off.
        let mut txc = Timex { modes: MOD_STATUS, status: self.sys_status, ..Default::default() };
        self.adjust(&mut txc);
    }

    /// chrony `SYS_Timex_InitialiseWithFunctions`: complete the generic slew driver
    /// with this timex driver underneath. Returns the assembled [`SysGeneric`].
    #[allow(clippy::too_many_arguments)]
    pub fn initialise_with_functions(
        self,
        max_set_freq_ppm: f64,
        max_set_freq_delay: f64,
        min_fastslew_offset: f64,
        max_fastslew_rate: f64,
        max_slew_rate_ppm: f64,
        raw_clock: Box<dyn FnMut() -> Timespec>,
        dispersion_notify: Box<dyn FnMut(f64)>,
        set_time: Option<Box<dyn FnMut(Timespec) -> bool>>,
    ) -> SysGeneric<SysTimex> {
        SysGeneric::complete_freq_driver(
            self,
            max_set_freq_ppm,
            max_set_freq_delay,
            min_fastslew_offset,
            max_fastslew_rate,
            max_slew_rate_ppm,
            raw_clock,
            dispersion_notify,
            set_time,
        )
    }

    /// chrony `SYS_Timex_Initialise`: the daemon's default wiring (max 500 ppm,
    /// `1/MIN_TICK_RATE` delay, no fast slew, given max slew rate and hooks).
    #[allow(clippy::too_many_arguments)]
    pub fn initialise(
        adjtimex: Box<dyn FnMut(&mut Timex) -> i32>,
        rtcsync: bool,
        max_slew_rate_ppm: f64,
        raw_clock: Box<dyn FnMut() -> Timespec>,
        dispersion_notify: Box<dyn FnMut(f64)>,
        set_time: Option<Box<dyn FnMut(Timespec) -> bool>>,
    ) -> SysGeneric<SysTimex> {
        let t = SysTimex::new(adjtimex, rtcsync);
        t.initialise_with_functions(
            MAX_FREQ,
            1.0 / MIN_TICK_RATE,
            0.0,
            0.0,
            max_slew_rate_ppm,
            raw_clock,
            dispersion_notify,
            set_time,
        )
    }
}

/// `SysTimex` is the base frequency driver under the generic slew layer
/// (chrony registers `read_frequency`/`set_frequency`/`set_sync_status`).
impl FreqDriver for SysTimex {
    fn read_frequency(&mut self) -> f64 {
        SysTimex::read_frequency(self)
    }
    fn set_frequency(&mut self, freq_ppm: f64) -> f64 {
        SysTimex::set_frequency(self, freq_ppm)
    }
    fn set_sync_status(&mut self, synchronised: bool, est_error: f64, max_error: f64) -> bool {
        SysTimex::set_sync_status(self, synchronised, est_error, max_error);
        true
    }
}

#[cfg(test)]
mod tests;
