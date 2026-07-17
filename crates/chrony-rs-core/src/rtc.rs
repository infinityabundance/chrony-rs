//! Real-time-clock abstraction — a complete port of chrony 4.5 `rtc.c` (all 9
//! functions).
//!
//! # What this module is
//!
//! `rtc.c` is the OS-independent layer over the platform RTC driver (on Linux,
//! `rtc_linux.c`). It decides whether to load the driver, forwards the lifecycle
//! and measurement calls to it, and implements the **drift-file time restore**: at
//! startup, if the driver's pre-init did not set the clock, the system time is
//! stepped forward to the drift file's modification time when that is in the future
//! (so a machine with a dead/missing RTC still comes up near the true time).
//!
//! # Adaptations (documented, not silent)
//!
//! * **Driver injected.** The platform RTC driver (chrony's static `driver` table
//!   of function pointers, or all-NULL when unsupported) is the [`RtcDriver`] trait;
//!   `None` models "no driver". This is the same boundary pattern as the `sys_*`
//!   clock drivers.
//! * **Host reads injected.** The drift-file modification time (chrony's
//!   `stat()`), the cooked clock read, and the clock step (`LCL_ApplyStepOffset`)
//!   are injected closures; the config (`rtcfile`/`rtcsync`/`driftfile`) is passed
//!   in. The brain performs no filesystem or clock I/O itself.
//! * **`RTC_TimeInit` hook.** chrony's `time_init` takes an `after_hook` called once
//!   the RTC read completes (or immediately if there is no usable driver); it is a
//!   `FnOnce`-style closure here.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `rtc.c`** (`-DLINUX -DFEAT_RTC`,
//! its `RTC_Linux_*` driver replaced by recording stubs): a C generator drives
//! initialise (pre-init ok / pre-init fail→drift-file step / `rtcfile`+`rtcsync`
//! fatal) and the forwarded lifecycle/measurement calls, recording the driver/clock
//! call log and the forwarded return codes (`research/oracle/rtc-c-vectors.txt`).
//! The port replays the identical scenarios and matches the call log. See the tests.

/// chrony `RTC_ST_OK`.
pub const RTC_ST_OK: i32 = 0;
/// chrony `RTC_ST_NODRV`.
pub const RTC_ST_NODRV: i32 = 1;
/// chrony `RTC_ST_BADFILE`.
pub const RTC_ST_BADFILE: i32 = 2;

/// chrony `RPT_RTC_Report`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RtcReport {
    /// Reference time (seconds; nanoseconds folded out for this layer).
    pub ref_time: i64,
    /// Number of samples.
    pub n_samples: u64,
    /// Number of runs.
    pub n_runs: u64,
    /// Span in seconds.
    pub span_seconds: u64,
    /// RTC fast offset, seconds.
    pub rtc_seconds_fast: f64,
    /// RTC gain rate, ppm.
    pub rtc_gain_rate_ppm: f64,
}

/// The platform RTC driver (chrony's `driver` function-pointer table). All methods
/// have defaults so a partial driver can be expressed; absence is `None` at the
/// manager level.
pub trait RtcDriver {
    /// `init`: bring the driver up. Returns success.
    fn init(&mut self) -> bool;
    /// `fini`: shut the driver down.
    fn finalise(&mut self);
    /// `time_pre_init`: optionally set the clock from the RTC before the scheduler
    /// starts (given the drift-file time). Returns whether it set the clock.
    fn time_pre_init(&mut self, driftfile_time: i64) -> bool;
    /// `time_init`: start the measurement that trims the system clock, calling
    /// `after_hook` when done.
    fn time_init(&mut self, after_hook: Box<dyn FnMut()>);
    /// `start_measurements`: begin periodic RTC measurements.
    fn start_measurements(&mut self);
    /// `write_parameters`: persist RTC parameters. Returns an `RTC_ST_*` code.
    fn write_parameters(&mut self) -> i32;
    /// `get_report`: fill a report. Returns `None` on failure.
    fn get_report(&mut self) -> Option<RtcReport>;
    /// `trim`: trim the system clock from the RTC. Returns success (1) / failure (0).
    fn trim(&mut self) -> i32;
}

/// The RTC abstraction (chrony's `rtc.c` module state) over an injected driver.
pub struct RtcManager {
    driver: Option<Box<dyn RtcDriver>>,
    driver_initialised: bool,
    driver_preinit_ok: bool,

    rtc_file: Option<String>,
    rtc_sync: bool,
    /// chrony `get_driftfile_time`: the drift file's mtime, or 0 if none.
    get_driftfile_time: Box<dyn FnMut() -> i64>,
    /// chrony `LCL_ReadCookedTime` (seconds; only the seconds field is used here).
    read_cooked_secs: Box<dyn FnMut() -> i64>,
    /// chrony `LCL_ApplyStepOffset`. Returns whether the step was applied.
    apply_step: Box<dyn FnMut(f64) -> bool>,
}

impl RtcManager {
    /// Construct the manager. `driver` is `None` when the platform has no RTC driver
    /// (chrony's all-NULL table). `rtc_file`/`rtc_sync` are `CNF_GetRtcFile` /
    /// `CNF_GetRtcSync`.
    pub fn new(
        driver: Option<Box<dyn RtcDriver>>,
        rtc_file: Option<String>,
        rtc_sync: bool,
        get_driftfile_time: Box<dyn FnMut() -> i64>,
        read_cooked_secs: Box<dyn FnMut() -> i64>,
        apply_step: Box<dyn FnMut(f64) -> bool>,
    ) -> Self {
        RtcManager {
            driver,
            driver_initialised: false,
            driver_preinit_ok: false,
            rtc_file,
            rtc_sync,
            get_driftfile_time,
            read_cooked_secs,
            apply_step,
        }
    }

    /// chrony `apply_driftfile_time`: step the clock to the drift-file time `t` if
    /// the current time is behind it. Returns whether a step was applied.
    fn apply_driftfile_time(&mut self, t: i64) -> bool {
        let now = (self.read_cooked_secs)();
        if now < t {
            return (self.apply_step)((now - t) as f64);
        }
        false
    }

    /// chrony `RTC_Initialise`.
    pub fn initialise(&mut self, initial_set: bool) {
        if initial_set {
            let driftfile_time = (self.get_driftfile_time)();
            let preinit = self
                .driver
                .as_mut()
                .map(|d| d.time_pre_init(driftfile_time))
                .unwrap_or(false);
            if preinit {
                self.driver_preinit_ok = true;
            } else {
                self.driver_preinit_ok = false;
                if driftfile_time != 0 {
                    self.apply_driftfile_time(driftfile_time);
                }
            }
        }

        self.driver_initialised = false;

        // A configured rtcfile is how the user asks to load the RTC driver.
        if self.rtc_file.is_some() {
            assert!(!self.rtc_sync, "rtcfile directive cannot be used with rtcsync");
            match self.driver.as_mut() {
                Some(d) => {
                    if d.init() {
                        self.driver_initialised = true;
                    }
                    // else: chrony logs "RTC driver could not be initialised"
                }
                None => { /* chrony logs "RTC not supported on this operating system" */ }
            }
        }
    }

    /// chrony `RTC_Finalise`.
    pub fn finalise(&mut self) {
        if self.driver_initialised {
            if let Some(ref mut driver) = self.driver {
                driver.finalise();
            }
        }
    }

    /// chrony `RTC_TimeInit`: trim the clock from the RTC, calling `after_hook` when
    /// done (or immediately if there is no usable driver).
    pub fn time_init(&mut self, after_hook: Box<dyn FnMut()>) {
        if self.driver_initialised && self.driver_preinit_ok {
            if let Some(ref mut driver) = self.driver {
                driver.time_init(after_hook);
            }
        } else {
            let mut hook = after_hook;
            hook();
        }
    }

    /// chrony `RTC_StartMeasurements`.
    pub fn start_measurements(&mut self) {
        if self.driver_initialised {
            if let Some(ref mut driver) = self.driver {
                driver.start_measurements();
            }
        }
    }

    /// chrony `RTC_WriteParameters`: `RTC_ST_NODRV` if no driver is running.
    pub fn write_parameters(&mut self) -> i32 {
        if self.driver_initialised {
            match self.driver.as_mut() {
                Some(ref mut driver) => driver.write_parameters(),
                None => RTC_ST_NODRV,
            }
        } else {
            RTC_ST_NODRV
        }
    }

    /// chrony `RTC_GetReport`: `None` (return 0) if no driver is running.
    pub fn get_report(&mut self) -> Option<RtcReport> {
        if self.driver_initialised {
            match self.driver.as_mut() {
                Some(ref mut driver) => driver.get_report(),
                None => None,
            }
        } else {
            None
        }
    }

    /// chrony `RTC_Trim`: 0 if no driver is running.
    pub fn trim(&mut self) -> i32 {
        if self.driver_initialised {
            match self.driver.as_mut() {
                Some(ref mut driver) => driver.trim(),
                None => 0,
            }
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests;
