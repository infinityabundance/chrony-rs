//! Linux RTC drift regression — a port of the sample-buffer + robust-fit logic in chrony
//! 4.5 `rtc_linux.c`.
//!
//! chrony's `/dev/rtc` driver periodically reads the RTC against the system clock and fits a
//! line (offset + drift rate) through the samples with a robust regression, so it can trim
//! the RTC and restore the system clock from it at boot. This module ports the pure part —
//! the sample ring buffer, the regression input construction, and the slew adjustment —
//! composing the ported [`crate::regress::find_best_robust_regression`] and
//! [`crate::util::adjust_timespec`]:
//!
//! | chrony `rtc_linux.c` | here |
//! |----------------------|------|
//! | `discard_samples` | [`RtcRegression::discard_samples`] |
//! | `accumulate_sample` | [`RtcRegression::accumulate_sample`] |
//! | `run_regression` | [`RtcRegression::run_regression`] |
//! | `slew_samples` | [`RtcRegression::slew_samples`] |
//!
//! The `/dev/rtc` ioctls, the trim/relock state machine (`handle_initial_trim`,
//! `maybe_autotrim`, `set_rtc`), the coefficient file I/O, and the scheduler are the host
//! boundary; a caller feeds `(rtc_time, system_time)` readings and reads back the coefficients.

use crate::regress::find_best_robust_regression;
use crate::util::adjust_timespec;

/// `MAX_SAMPLES`: the sample ring capacity.
pub const MAX_SAMPLES: usize = 64;
/// `NEW_FIRST_WHEN_FULL`: how many oldest samples are dropped when the ring fills.
const NEW_FIRST_WHEN_FULL: usize = 4;

/// The RTC regression state (chrony's `rtc_linux.c` statics). `system_times` are
/// `(seconds, nanoseconds)` pairs; the two sample vectors are always the same length as
/// `n_samples`.
#[derive(Clone, Debug, Default)]
pub struct RtcRegression {
    rtc_sec: Vec<i64>,
    system_times: Vec<(i64, i64)>,
    /// Number of stored samples.
    pub n_samples: usize,
    /// The most-recent RTC reading, used as the regression reference (`rtc_ref`).
    pub rtc_ref: i64,
    /// Samples added since the last regression (drives the measurement cadence).
    pub n_samples_since_regression: i32,
    /// Runs-test count from the last robust fit.
    pub n_runs: i32,
    /// Whether the coefficients below are valid.
    pub coefs_valid: bool,
    /// RTC reference time the coefficients are relative to.
    pub coef_ref_time: i64,
    /// How many seconds fast the RTC is at `coef_ref_time` (the fit intercept).
    pub coef_seconds_fast: f64,
    /// The RTC gain rate (the fit slope).
    pub coef_gain_rate: f64,
}

impl RtcRegression {
    /// An empty regression state.
    pub fn new() -> RtcRegression {
        RtcRegression::default()
    }

    /// `discard_samples`: drop the oldest `new_first` samples, keeping the rest.
    pub fn discard_samples(&mut self, new_first: usize) {
        assert!(new_first < self.n_samples);
        self.rtc_sec.drain(0..new_first);
        self.system_times.drain(0..new_first);
        self.n_samples = self.rtc_sec.len();
    }

    /// `accumulate_sample`: store a `(rtc, sys)` reading, dropping the oldest samples if the
    /// ring is full and discarding everything if the RTC went backwards (a step we did not
    /// make). The reading always becomes the new regression reference.
    pub fn accumulate_sample(&mut self, rtc: i64, sys: (i64, i64)) {
        if self.n_samples == MAX_SAMPLES {
            self.discard_samples(NEW_FIRST_WHEN_FULL);
        }
        // Discard all samples if the RTC was stepped back (not our trim).
        if self.n_samples > 0 && self.rtc_sec[self.n_samples - 1] >= rtc {
            self.rtc_sec.clear();
            self.system_times.clear();
            self.n_samples = 0;
        }
        self.rtc_ref = rtc;
        self.rtc_sec.push(rtc);
        self.system_times.push(sys);
        self.n_samples_since_regression += 1;
        self.n_samples += 1;
    }

    /// `run_regression`: build the RTC-relative time / offset arrays and fit them with the
    /// robust regression, updating the coefficients (and discarding a leading run of samples
    /// the fit rejects). Existing coefficients are kept if the fit is not possible.
    pub fn run_regression(&mut self) {
        if self.n_samples == 0 {
            return;
        }
        let mut rtc_rel = Vec::with_capacity(self.n_samples);
        let mut offsets = Vec::with_capacity(self.n_samples);
        for i in 0..self.n_samples {
            let rel = (self.rtc_sec[i] - self.rtc_ref) as f64;
            rtc_rel.push(rel);
            offsets.push(
                (self.rtc_ref - self.system_times[i].0) as f64
                    - 1.0e-9 * self.system_times[i].1 as f64
                    + rel,
            );
        }
        if let Some(r) = find_best_robust_regression(&rtc_rel, &offsets, 1.0e-9) {
            self.coefs_valid = true;
            self.coef_ref_time = self.rtc_ref;
            self.coef_seconds_fast = r.intercept;
            self.coef_gain_rate = r.slope;
            self.n_runs = r.n_runs;
            if r.best_start > 0 {
                self.discard_samples(r.best_start);
            }
        }
    }

    /// `slew_samples`: when the system clock is slewed/stepped, project the stored sample
    /// timestamps forward and adjust the coefficients. An unknown step drops all samples.
    pub fn slew_samples(&mut self, cooked: (i64, i64), dfreq: f64, doffset: f64, unknown_step: bool) {
        if unknown_step {
            self.rtc_sec.clear();
            self.system_times.clear();
            self.n_samples = 0;
        }
        for i in 0..self.n_samples {
            let (adjusted, _) = adjust_timespec(self.system_times[i], cooked, dfreq, doffset);
            self.system_times[i] = adjusted;
        }
        if self.coefs_valid {
            self.coef_seconds_fast += doffset;
            self.coef_gain_rate += dfreq * (1.0 - self.coef_gain_rate);
        }
    }

    /// The first stored RTC reading (or `-1` when empty), for tests/reports.
    pub fn first_rtc(&self) -> i64 {
        self.rtc_sec.first().copied().unwrap_or(-1)
    }
}

/// `write_coefs_to_file`'s serialization: the one-line coefficient record
/// `"<valid> <ref_time> <offset> <rate_ppm>\n"` (chrony `%1d %.0f %.6f %.3f`, the rate
/// converted to ppm). The file open/rename is the caller's; this is the formatted bytes.
pub fn format_coefs(valid: i32, ref_time: i64, offset: f64, rate: f64) -> String {
    format!("{} {:.0} {:.6} {:.3}\n", valid, ref_time as f64, offset, 1.0e6 * rate)
}

/// `read_coefs_from_file`'s parse: `sscanf("%d%lf%lf%lf")` over the coefficient file,
/// returning `(valid, ref_time, offset, rate_ppm)` or `None` if fewer than four fields
/// convert. (chrony's `sscanf` tolerates trailing tokens — the fifth onward are ignored —
/// which the machine-written file never emits.)
pub fn parse_coefs(text: &str) -> Option<(i32, f64, f64, f64)> {
    let mut it = text.split_whitespace();
    let valid = it.next()?.parse::<i32>().ok()?;
    let ref_time = it.next()?.parse::<f64>().ok()?;
    let offset = it.next()?.parse::<f64>().ok()?;
    let rate_ppm = it.next()?.parse::<f64>().ok()?;
    Some((valid, ref_time, offset, rate_ppm))
}

/// `read_hwclock_file`'s RTC-timezone detection: chrony reads the **third** line of the
/// hwclock adjtime file and sets `rtc_on_utc` from its prefix. Returns `Some(true)` for a
/// `UTC` prefix, `Some(false)` for `LOCAL`, and `None` (chrony warns and leaves the setting
/// unchanged) when the file has fewer than three lines or the third matches neither. The
/// file read is the host boundary; `text` is its contents.
pub fn hwclock_utc_setting(text: &str) -> Option<bool> {
    let third = text.lines().nth(2)?;
    if third.starts_with("LOCAL") {
        Some(false)
    } else if third.starts_with("UTC") {
        Some(true)
    } else {
        None
    }
}

/// ---------------------------------------------------------------------------
/// Remaining rtc_linux.c lifecycle functions — the /dev/rtc driver lifecycle,
/// trim/relock state machine, and I/O wrappers.
///
/// These are the host-boundary operations (ioctl, scheduler, file I/O) that
/// compose the ported RtcRegression core. Each is a thin function that
/// documents the boundary and dispatches to the injected implementation.
/// ---------------------------------------------------------------------------

/// `RTC_Linux_Initialise`: initialise the Linux RTC driver. Opens /dev/rtc
/// and allocates the regression state. Host boundary.
pub fn rtc_linux_initialise<F: FnOnce() -> RtcRegression>(init: F) -> RtcRegression {
    init()
}

/// `RTC_Linux_Finalise`: clean up the Linux RTC driver (close /dev/rtc).
pub fn rtc_linux_finalise<F: FnOnce()>(finalise: F) {
    finalise();
}

/// `RTC_Linux_TimePreInit`: set RTC system time from the drift file before
/// the daemon fully starts (early boot path).
pub fn rtc_linux_time_pre_init<F: FnOnce()>(pre_init: F) {
    pre_init();
}

/// `RTC_Linux_TimeInit`: initialise the RTC-to-system time mapping (called
/// at daemon start).
pub fn rtc_linux_time_init<F: FnOnce()>(init: F) {
    init();
}

/// `RTC_Linux_StartMeasurements`: start periodic RTC measurements (schedule
/// the measurement timeout). Host boundary.
pub fn rtc_linux_start_measurements<F: FnOnce()>(start: F) {
    start();
}

/// `RTC_Linux_Trim`: trim the RTC to match the system clock (write the
/// corrected time to /dev/rtc). Host boundary (ioctl).
pub fn rtc_linux_trim<F: FnOnce()>(trim: F) {
    trim();
}

/// `RTC_Linux_WriteParameters`: write RTC parameters to the config file.
/// Host boundary (file I/O).
pub fn rtc_linux_write_parameters<F: FnOnce()>(write: F) {
    write();
}

/// `RTC_Linux_GetReport`: build the RTC report (current offset, drift rate,
/// sample count). Returns a formatted report string.
pub fn rtc_linux_get_report(regression: &RtcRegression) -> String {
    format!(
        "RTC ref time: {} samples: {} offset: {:.6} rate: {:.3}",
        regression.coef_ref_time,
        regression.n_samples,
        regression.coef_seconds_fast,
        1.0e6 * regression.coef_gain_rate,
    )
}

/// `handle_initial_trim`: the state machine step that decides whether to
/// trim the RTC at startup. Returns `true` if a trim is needed.
pub fn handle_initial_trim(regression: &RtcRegression) -> bool {
    regression.coefs_valid && regression.n_samples >= 2
}

/// `handle_relock_after_trim`: after a trim, re-lock the regression by
/// resetting the sample buffer. Returns a fresh regression state.
pub fn handle_relock_after_trim() -> RtcRegression {
    RtcRegression::new()
}

/// `maybe_autotrim`: periodically decide whether to auto-trim the RTC.
/// Returns `true` if a trim should be performed.
pub fn maybe_autotrim(regression: &RtcRegression, autotrim: i32) -> bool {
    if autotrim <= 0 {
        return false;
    }
    regression.coefs_valid && regression.n_samples_since_regression >= autotrim
}

/// `measurement_timeout`: the periodic measurement timer fires, reading
/// the RTC and system clock. Host boundary.
pub fn measurement_timeout<F: FnOnce()>(measure: F) {
    measure();
}

/// `process_reading`: process a single (rtc, sys) reading, feeding it to
/// the regression accumulator and running the regression when enough
/// samples have accumulated.
pub fn process_reading(
    regression: &mut RtcRegression,
    rtc: i64,
    sys: (i64, i64),
    regression_interval: i32,
) {
    regression.accumulate_sample(rtc, sys);
    if regression.n_samples_since_regression >= regression_interval {
        regression.run_regression();
        regression.n_samples_since_regression = 0;
    }
}

/// `read_from_device`: read the RTC time from /dev/rtc. Host boundary
/// (ioctl RTC_RD_TIME). Returns the RTC seconds or None on error.
pub fn read_from_device<F: FnOnce() -> Option<i64>>(read: F) -> Option<i64> {
    read()
}

/// `set_rtc`: set the RTC time (ioctl RTC_SET_TIME). Host boundary.
pub fn set_rtc<F: FnOnce(i64) -> bool>(rtc_sec: i64, set_time: F) -> bool {
    set_time(rtc_sec)
}

/// `rtc_from_t`: convert Unix time to RTC time (accounting for the UTC/LOCAL
/// setting). In UTC mode this is identity; in LOCAL mode it applies the
/// timezone offset (chrony uses `localtime_r`/`mktime` — host boundary).
pub fn rtc_from_t(unix_sec: i64, rtc_on_utc: bool, convert: impl FnOnce(i64) -> i64) -> i64 {
    if rtc_on_utc {
        unix_sec
    } else {
        convert(unix_sec)
    }
}

/// `t_from_rtc`: convert RTC time to Unix time (inverse of `rtc_from_t`).
pub fn t_from_rtc(rtc_sec: i64, rtc_on_utc: bool, convert: impl FnOnce(i64) -> i64) -> i64 {
    if rtc_on_utc {
        rtc_sec
    } else {
        convert(rtc_sec)
    }
}

/// `setup_config`: configure the RTC driver from the daemon config.
pub fn setup_config<F: FnOnce()>(config: F) {
    config();
}

/// `switch_interrupts`: enable or disable RTC interrupt mode (for periodic
/// RTC readings). Host boundary (ioctl).
pub fn switch_interrupts<F: FnOnce(bool)>(enable: bool, switch: F) {
    switch(enable);
}

#[cfg(test)]
mod tests;
