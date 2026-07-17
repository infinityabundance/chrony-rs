//! Reference clocks — a complete port of chrony 4.5 `refclock.c` (all 34
//! functions). The local hardware-reference-clock framework (`RCL_*`).
//!
//! # What this module is
//!
//! `refclock.c` is the framework that feeds *local* reference clocks (GPS/SHM,
//! socket, PPS, PHC) into chrony's source machinery. Each refclock has a driver, a
//! sample filter, and a source; this module turns the driver's raw timestamps into
//! filtered, dispersion-tracked samples, handles the pulse-per-second (PPS)
//! alignment, drives the poll loop, and forwards combined samples to source
//! selection. It was unblocked by file 32 ([`crate::reference`], `REF_*`).
//!
//! # What it composes
//!
//! The heavy lifting is done by already-ported, separately-verified modules: the
//! sample filter [`crate::samplefilt`] (`SPF_*`), the robust regression
//! [`crate::regress`], the local clock [`crate::local`], the scheduler
//! [`crate::sched`], and the reference layer [`crate::reference`]. Those, plus the
//! source machinery (`SRC_*`) and the platform refclock driver, are reached through
//! one injected [`RefclockHost`] trait; the driver is a [`RefclockDriver`].
//!
//! # Adaptations (documented, not silent)
//!
//! * **All cross-module calls are injected** via [`RefclockHost`] (`SPF_*`/`SRC_*`/
//!   `REF_*`/`LCL_*`/`SCH_*`), keyed by the instance index where chrony would deref
//!   a per-instance pointer. The driver↔framework re-entrancy (`driver->poll` calls
//!   `RCL_AddSample`) is resolved by the daemon calling [`RefclockManager::add_sample`]
//!   directly.
//! * **The `':'`-separated driver-parameter buffer is a `Vec<String>`** of options;
//!   the option lookup reproduces chrony's `name`/`name=value` matching.
//! * **`UTI_IsTimeOffsetSane` uses the 32-bit `time_t` bound** (the no-`HAVE_LONG_TIME_T`
//!   build, which the differential oracle compiles); chrony's 64-bit build instead
//!   bounds by the mapped NTP era. The tested sample times satisfy both.
//!
//! # Oracle
//!
//! The computational core — `RCL_AddSample` / `RCL_AddPulse` / `RCL_AddCookedPulse`
//! (the offset computation, PPS interval folding, lock-reference alignment, pulse-edge
//! and sanity gates), `pps_stratum`, `valid_sample_time`, and `convert_tai_offset` —
//! is differential-tested against the **real compiled `refclock.c`** (+ `array.c`,
//! `memory.c`) over recording `SPF_*`/`SRC_*`/`REF_*`/`LCL_*` stubs
//! (`research/oracle/refclock-c-vectors.txt`): it captures the exact offset and
//! dispersion handed to the filter and the accept/reject decision. The port replays
//! the identical inputs and matches them. The manager/driver/option glue is
//! unit-tested. See the tests.

use crate::reference::{time_to_log_form, Timespec};

/// chrony `PPS_LOCK_LIMIT`.
const PPS_LOCK_LIMIT: f64 = 0.4;
/// `MAX_OFFSET` (`util.c`).
const MAX_OFFSET: f64 = 4294967296.0;
/// `MIN_ENDOFTIME_DISTANCE` (`util.c`).
const MIN_ENDOFTIME_DISTANCE: f64 = 365.0 * 24.0 * 3600.0;

/// chrony `NTP_Leap` values used here.
const LEAP_NORMAL: i32 = 0;
const LEAP_INSERT_SECOND: i32 = 1;
const LEAP_DELETE_SECOND: i32 = 2;
const LEAP_UNSYNCHRONISED: i32 = 3;

/// An `NTP_Sample` as it crosses the filter/source boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Sample {
    /// Local time the sample is considered to have been made.
    pub time: Timespec,
    /// Offset (positive = local clock slow relative to the source).
    pub offset: f64,
    pub peer_delay: f64,
    pub peer_dispersion: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
}

/// chrony's `REF_GetReferenceParams` out-parameters.
#[derive(Clone, Copy, Debug, Default)]
pub struct RefParams {
    pub is_synchronised: bool,
    pub leap: i32,
    pub stratum: i32,
    pub ref_id: u32,
    pub ref_time: Timespec,
    pub root_delay: f64,
    pub root_dispersion: f64,
}

/// Tracking data from `SRC_GetSourcestats`/`SST_GetTrackingData` for the local mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct TrackingData {
    /// `< min_samples` -> `None` is signalled by the host; this carries the data.
    pub ref_time: Timespec,
    pub offset: f64,
    pub freq: f64,
}

/// chrony `RefclockParameters` (the configured options of one refclock).
#[derive(Clone, Debug, Default)]
pub struct RefclockParameters {
    pub driver_name: String,
    pub driver_parameter: String,
    pub driver_poll: i32,
    pub poll: i32,
    pub filter_length: i32,
    pub local: bool,
    pub pps_forced: bool,
    pub pps_rate: i32,
    pub min_samples: i32,
    pub max_samples: i32,
    pub sel_options: i32,
    pub max_lock_age: i32,
    pub stratum: i32,
    pub tai: bool,
    pub ref_id: u32,
    pub lock_ref_id: u32,
    pub offset: f64,
    pub delay: f64,
    pub precision: f64,
    pub max_dispersion: f64,
    pub pulse_width: f64,
}

/// A platform refclock driver (`RefclockDriver`: `init`/`fini`/`poll`).
pub trait RefclockDriver {
    /// Whether the driver provides `init` (chrony's non-null function pointer).
    fn has_init(&self) -> bool {
        false
    }
    /// Whether the driver provides `poll`.
    fn has_poll(&self) -> bool {
        false
    }
    /// `driver->init`.
    fn init(&mut self) -> bool {
        true
    }
    /// `driver->fini`.
    fn fini(&mut self) {}
    /// `driver->poll`.
    fn poll(&mut self) {}
}

/// The host boundary chrony reaches through `SPF_*`/`SRC_*`/`REF_*`/`LCL_*`/`SCH_*`
/// globals, keyed by the refclock instance index.
pub trait RefclockHost {
    // ---- sample filter (SPF_*) ----
    fn spf_accumulate_sample(&mut self, idx: usize, sample: &Sample) -> bool;
    fn spf_get_last_sample(&mut self, idx: usize) -> Option<Sample>;
    fn spf_get_avg_sample_dispersion(&mut self, idx: usize) -> f64;
    fn spf_drop_samples(&mut self, idx: usize);
    fn spf_get_filtered_sample(&mut self, idx: usize) -> Option<Sample>;
    fn spf_slew_samples(&mut self, idx: usize, now: Timespec, dfreq: f64, doffset: f64);
    fn spf_correct_offset(&mut self, idx: usize, correction: f64);
    fn spf_add_dispersion(&mut self, idx: usize, dispersion: f64);

    // ---- source machinery (SRC_*) ----
    fn src_accumulate_sample(&mut self, idx: usize, sample: &Sample);
    fn src_reset_instance(&mut self, idx: usize);
    fn src_update_reachability(&mut self, idx: usize, reachable: bool);
    fn src_update_status(&mut self, idx: usize, stratum: i32, leap: i32);
    fn src_select_source(&mut self, idx: usize);
    fn src_set_active(&mut self, idx: usize);
    /// `SRC_GetSourcestats` + `SST_GetTrackingData`, or `None` if `< min_samples`.
    fn src_get_tracking_data(&mut self, idx: usize) -> Option<TrackingData>;

    // ---- reference layer (REF_*) ----
    fn ref_get_reference_params(&mut self, ts: Timespec) -> RefParams;
    fn ref_get_tai_offset(&mut self, ts: Timespec) -> i32;
    fn ref_adjust_reference(&mut self, doffset: f64, dfreq: f64) -> bool;

    // ---- local clock (LCL_*) ----
    /// `LCL_GetOffsetCorrection` -> (correction, dispersion).
    fn lcl_get_offset_correction(&mut self, ts: Timespec) -> (f64, f64);
    /// `LCL_ReadCookedTime`.
    fn lcl_read_cooked_time(&mut self) -> Timespec;
    /// `LCL_GetSysPrecisionAsQuantum`.
    fn lcl_sys_precision(&mut self) -> f64;

    // ---- scheduler (SCH_*) ----
    fn sch_add_timeout_by_delay(&mut self, delay: f64) -> u32;

    // ---- logging ----
    fn log_sample(&mut self, line: &str);
    fn log_message(&mut self, msg: &str);
}

/// One reference clock (chrony's `RCL_Instance_Record`, minus the injected
/// filter/source/driver pointers).
struct RclInstance {
    driver: Box<dyn RefclockDriver>,
    driver_parameter: Vec<String>,
    driver_poll: i32,
    driver_polled: i32,
    poll: i32,
    leap_status: i32,
    local: bool,
    pps_forced: bool,
    pps_rate: i32,
    pps_active: bool,
    max_lock_age: i32,
    stratum: i32,
    tai: bool,
    ref_id: u32,
    /// `-1` means "no lock"; otherwise the index of the locked refclock.
    lock_ref: i64,
    offset: f64,
    delay: f64,
    precision: f64,
    pulse_width: f64,
    timeout_id: u32,
}

/// `UTI_IsTimeOffsetSane` (32-bit `time_t` build, as the oracle compiles).
pub(crate) fn is_time_offset_sane(ts: Timespec, offset: f64) -> bool {
    if !(offset > -MAX_OFFSET && offset < MAX_OFFSET) {
        return false;
    }
    let t = (ts.sec as f64 + 1.0e-9 * ts.nsec as f64) + offset;
    if t < 0.0 {
        return false;
    }
    if t > (0x7fff_ffffi64 as f64 - MIN_ENDOFTIME_DISTANCE) {
        return false;
    }
    true
}

/// `UTI_Log2ToDouble`.
fn log2_to_double(l: i32) -> f64 {
    if l >= 0 {
        let l = l.min(31);
        (1u32 << l) as f64
    } else {
        let l = (-l).min(31);
        1.0 / ((1u32 << l) as f64)
    }
}

/// The reference-clock framework (chrony's `refclock.c` module state).
#[derive(Default)]
pub struct RefclockManager {
    refclocks: Vec<RclInstance>,
    log_refclocks: bool,
}

impl RefclockManager {
    /// chrony `RCL_Initialise` (config-driven `CNF_AddRefclocks` is the daemon's; the
    /// refclocks are added with [`RefclockManager::add_refclock`]).
    pub fn new(log_refclocks: bool) -> RefclockManager {
        RefclockManager { refclocks: Vec::new(), log_refclocks }
    }

    /// Number of configured refclocks.
    pub fn len(&self) -> usize {
        self.refclocks.len()
    }
    /// Whether no refclocks are configured.
    pub fn is_empty(&self) -> bool {
        self.refclocks.is_empty()
    }

    /// chrony `RCL_AddRefclock`: register one refclock. Returns its index.
    pub fn add_refclock(
        &mut self,
        host: &mut dyn RefclockHost,
        driver: Box<dyn RefclockDriver>,
        mut params: RefclockParameters,
    ) -> usize {
        let index = self.refclocks.len();

        let driver_parameter: Vec<String> = if params.driver_parameter.is_empty() {
            Vec::new()
        } else {
            params.driver_parameter.split(':').map(|s| s.to_string()).collect()
        };

        let mut pps_rate = params.pps_rate;
        if pps_rate < 1 {
            pps_rate = 1;
        }

        // refid: configured, or derived from the driver name + index.
        let ref_id = if params.ref_id != 0 {
            params.ref_id
        } else {
            let name = params.driver_name.as_bytes();
            let mut r = [0u8; 4];
            for i in 0..3 {
                r[i] = if i < name.len() { name[i] } else { 0 };
            }
            r[3] = (index % 10) as u8 + b'0';
            if index >= 10 {
                r[2] = ((index / 10) % 10) as u8 + b'0';
            }
            (r[0] as u32) << 24 | (r[1] as u32) << 16 | (r[2] as u32) << 8 | r[3] as u32
        };

        let mut local = params.local;
        let mut pps_forced = params.pps_forced;
        let mut lock_ref = params.lock_ref_id as i64;
        let mut leap_status = LEAP_NORMAL;
        let mut max_lock_age = params.max_lock_age;
        if local {
            pps_forced = true;
            lock_ref = ref_id as i64;
            leap_status = LEAP_UNSYNCHRONISED;
            max_lock_age = max_lock_age.max(3);
        }
        let _ = &mut local;

        let mut driver_poll = params.driver_poll;
        if driver.has_poll() {
            if driver_poll > params.poll {
                driver_poll = params.poll;
            }
            let max_samples = 1 << (params.poll - driver_poll);
            if max_samples < params.filter_length {
                params.filter_length = max_samples;
            }
        }

        let mut precision = host.lcl_sys_precision();
        precision = precision.max(params.precision);

        let inst = RclInstance {
            driver,
            driver_parameter,
            driver_poll,
            driver_polled: 0,
            poll: params.poll,
            leap_status,
            local,
            pps_forced,
            pps_rate,
            pps_active: false,
            max_lock_age,
            stratum: params.stratum,
            tai: params.tai,
            ref_id,
            lock_ref,
            offset: params.offset,
            delay: params.delay,
            precision,
            pulse_width: params.pulse_width,
            timeout_id: 0,
        };
        self.refclocks.push(inst);

        // (driver init and SPF/SRC creation are the daemon's wiring.)
        if self.refclocks[index].driver.has_init() {
            self.refclocks[index].driver.init();
        }
        index
    }

    /// chrony `RCL_StartRefclocks`: activate sources, schedule polls, and resolve the
    /// lock refids to indices.
    pub fn start_refclocks(&mut self, host: &mut dyn RefclockHost) {
        let n = self.refclocks.len();
        for i in 0..n {
            host.src_set_active(i);
            self.refclocks[i].timeout_id = host.sch_add_timeout_by_delay(0.0);

            let lock_ref = self.refclocks[i].lock_ref;
            let mut lock_index: i64 = -1;
            if lock_ref != 0 {
                for (j, inst2) in self.refclocks.iter().enumerate() {
                    if lock_ref != inst2.ref_id as i64 {
                        continue;
                    }
                    lock_index = j as i64;
                    break;
                }
                if lock_index == -1 || (lock_index == i as i64 && !self.refclocks[i].local) {
                    host.log_message("Invalid lock refid");
                }
            }
            self.refclocks[i].lock_ref = lock_index;
        }
    }

    /// chrony `RCL_Finalise`: tear down each refclock (driver `fini` + the daemon's
    /// filter/source destruction).
    pub fn finalise(&mut self) {
        for inst in self.refclocks.iter_mut() {
            inst.driver.fini();
        }
        self.refclocks.clear();
    }

    /// chrony `RCL_ReportSource`: fill the poll/mode of the refclock with `ref_id`
    /// (the report's `in4` address). Returns whether a refclock matched.
    pub fn report_source(&self, ref_id: u32) -> Option<i32> {
        self.refclocks.iter().find(|i| i.ref_id == ref_id).map(|i| i.poll)
    }

    /// chrony `RCL_GetPrecision`.
    pub fn precision(&self, idx: usize) -> f64 {
        self.refclocks[idx].precision
    }
    /// chrony `RCL_GetDriverPoll`.
    pub fn driver_poll(&self, idx: usize) -> i32 {
        self.refclocks[idx].driver_poll
    }
    /// chrony `RCL_GetDriverParameter` (the first `':'`-segment).
    pub fn driver_parameter(&self, idx: usize) -> Option<&str> {
        self.refclocks[idx].driver_parameter.first().map(|s| s.as_str())
    }

    /// chrony `RCL_GetDriverOption`: look up `name` or `name=value` among the options.
    pub fn driver_option(&self, idx: usize, name: &str) -> Option<&str> {
        // chrony skips the first segment (the driver parameter proper).
        for option in self.refclocks[idx].driver_parameter.iter().skip(1) {
            if let Some(rest) = option.strip_prefix(name) {
                if let Some(value) = rest.strip_prefix('=') {
                    return Some(value);
                }
                if rest.is_empty() {
                    return Some(rest);
                }
            }
        }
        None
    }

    /// chrony `RCL_CheckDriverOptions`: every option must match one of `valid`.
    /// Returns the first invalid option, if any.
    pub fn check_driver_options(&self, idx: usize, valid: &[&str]) -> Option<String> {
        for option in self.refclocks[idx].driver_parameter.iter().skip(1) {
            let ok = valid.iter().any(|v| {
                option.strip_prefix(v).map(|r| r.is_empty() || r.starts_with('=')).unwrap_or(false)
            });
            if !ok {
                return Some(option.clone());
            }
        }
        None
    }

    /// chrony `convert_tai_offset`: convert a TAI sample offset to UTC. Returns the
    /// adjusted offset, or `None` if the TAI-UTC offset is unknown.
    fn convert_tai_offset(host: &mut dyn RefclockHost, sample_time: Timespec, offset: f64) -> Option<f64> {
        let tai_ts = sample_time.add_double(offset);
        let tai_offset = host.ref_get_tai_offset(tai_ts);
        let utc_ts = tai_ts.add_double(-(tai_offset as f64));
        let tai_offset = host.ref_get_tai_offset(utc_ts);
        if tai_offset == 0 {
            return None;
        }
        Some(offset - tai_offset as f64)
    }

    /// chrony `accumulate_sample`.
    fn accumulate_sample(
        &mut self,
        host: &mut dyn RefclockHost,
        idx: usize,
        sample_time: Timespec,
        offset: f64,
        dispersion: f64,
    ) -> bool {
        let delay = self.refclocks[idx].delay;
        let sample = Sample {
            time: sample_time,
            offset,
            peer_delay: delay,
            root_delay: delay,
            peer_dispersion: dispersion,
            root_dispersion: dispersion,
        };
        host.spf_accumulate_sample(idx, &sample)
    }

    /// chrony `valid_sample_time`.
    fn valid_sample_time(&self, host: &mut dyn RefclockHost, idx: usize, sample_time: Timespec) -> bool {
        let now = host.lcl_read_cooked_time();
        let diff = now.diff_to(sample_time);
        !(diff < 0.0 || diff > log2_to_double(self.refclocks[idx].poll + 1))
    }

    /// chrony `RCL_AddSample`.
    pub fn add_sample(
        &mut self,
        host: &mut dyn RefclockHost,
        idx: usize,
        sample_time: Timespec,
        ref_time: Timespec,
        leap: i32,
    ) -> bool {
        if self.refclocks[idx].pps_forced {
            let second = 1.0e-9 * (sample_time.nsec - ref_time.nsec) as f64;
            return self.add_pulse(host, idx, sample_time, second);
        }

        let raw_offset = ref_time.diff_to(sample_time);

        let (correction, mut dispersion) = host.lcl_get_offset_correction(sample_time);
        let cooked_time = sample_time.add_double(correction);
        dispersion += self.refclocks[idx].precision;

        if !is_time_offset_sane(sample_time, raw_offset)
            || !self.valid_sample_time(host, idx, cooked_time)
        {
            return false;
        }

        match leap {
            LEAP_NORMAL | LEAP_INSERT_SECOND | LEAP_DELETE_SECOND => {
                self.refclocks[idx].leap_status = leap;
            }
            _ => return false,
        }

        // offset = raw_offset - correction + instance.offset, computed in parts.
        let inst_offset = self.refclocks[idx].offset;
        let mut offset = (ref_time.sec - sample_time.sec - correction.trunc() as i64
            + inst_offset.trunc() as i64) as f64;
        offset += 1.0e-9 * (ref_time.nsec - sample_time.nsec) as f64 - (correction - correction.trunc())
            + (inst_offset - inst_offset.trunc());

        if self.refclocks[idx].tai {
            match Self::convert_tai_offset(host, sample_time, offset) {
                Some(o) => offset = o,
                None => return false,
            }
        }

        if !self.accumulate_sample(host, idx, cooked_time, offset, dispersion) {
            return false;
        }

        self.refclocks[idx].pps_active = false;
        let line = self.format_sample(idx, cooked_time, false, 0, raw_offset, offset, dispersion);
        host.log_sample(&line);
        if !self.refclocks[idx].driver.has_poll() {
            self.refclocks[idx].driver_polled += 1;
        }
        true
    }

    /// chrony `RCL_AddPulse`.
    pub fn add_pulse(
        &mut self,
        host: &mut dyn RefclockHost,
        idx: usize,
        pulse_time: Timespec,
        mut second: f64,
    ) -> bool {
        let (correction, dispersion) = host.lcl_get_offset_correction(pulse_time);
        let cooked_time = pulse_time.add_double(correction);
        second += correction;

        if !is_time_offset_sane(pulse_time, 0.0) {
            return false;
        }
        self.add_cooked_pulse(host, idx, cooked_time, second, dispersion, correction)
    }

    /// chrony `check_pulse_edge`.
    fn check_pulse_edge(&self, idx: usize, offset: f64, distance: f64) -> bool {
        let inst = &self.refclocks[idx];
        if inst.pulse_width <= 0.0 {
            return true;
        }
        let mut max_error = 1.0 / inst.pps_rate as f64 - inst.pulse_width;
        max_error = inst.pulse_width.min(max_error);
        max_error *= 0.5;
        !(offset.abs() > max_error || distance > max_error)
    }

    /// chrony `RCL_AddCookedPulse`.
    pub fn add_cooked_pulse(
        &mut self,
        host: &mut dyn RefclockHost,
        idx: usize,
        cooked_time: Timespec,
        second: f64,
        mut dispersion: f64,
        raw_correction: f64,
    ) -> bool {
        if !is_time_offset_sane(cooked_time, second)
            || !self.valid_sample_time(host, idx, cooked_time)
        {
            return false;
        }

        let leap;
        dispersion += self.refclocks[idx].precision;
        let rate = self.refclocks[idx].pps_rate;
        let ratef = rate as f64;

        let mut offset = -second + self.refclocks[idx].offset;

        // Fold into [-0.5/rate, 0.5/rate).
        offset -= ((offset * ratef) as i64) as f64 / ratef;
        if offset < -0.5 / ratef {
            offset += 1.0 / ratef;
        } else if offset >= 0.5 / ratef {
            offset -= 1.0 / ratef;
        }

        if self.refclocks[idx].lock_ref != -1 {
            let lock_idx = self.refclocks[idx].lock_ref as usize;
            let mut ref_sample = match host.spf_get_last_sample(lock_idx) {
                Some(s) => s,
                None => {
                    if self.refclocks[idx].local {
                        Sample { time: cooked_time, offset, ..Default::default() }
                    } else {
                        return false;
                    }
                }
            };
            ref_sample.root_dispersion += host.spf_get_avg_sample_dispersion(lock_idx);

            let sample_diff = cooked_time.diff_to(ref_sample.time);
            if sample_diff.abs() >= self.refclocks[idx].max_lock_age as f64 / ratef {
                if self.refclocks[idx].local {
                    host.log_message("Local refclock lost lock");
                    host.spf_drop_samples(idx);
                    host.src_reset_instance(idx);
                }
                return false;
            }

            // Align the offset to the reference sample.
            let shift = ((ref_sample.offset - offset) * ratef).round() / ratef;
            offset += shift;

            if (ref_sample.offset - offset).abs() + ref_sample.root_dispersion + dispersion
                > PPS_LOCK_LIMIT / ratef
            {
                return false;
            }
            if !self.check_pulse_edge(idx, ref_sample.offset - offset, 0.0) {
                return false;
            }
            // leap comes from the locked refclock instance (same module's array).
            leap = self.refclocks[lock_idx].leap_status;
        } else {
            let params = host.ref_get_reference_params(cooked_time);
            leap = params.leap;
            let distance = params.root_delay.abs() / 2.0 + params.root_dispersion;
            if leap == LEAP_UNSYNCHRONISED || distance >= 0.5 / ratef {
                host.spf_drop_samples(idx);
                return false;
            }
            if !self.check_pulse_edge(idx, offset, distance) {
                return false;
            }
        }

        if !self.accumulate_sample(host, idx, cooked_time, offset, dispersion) {
            return false;
        }

        self.refclocks[idx].leap_status = leap;
        self.refclocks[idx].pps_active = true;
        let raw_offset = offset + raw_correction - self.refclocks[idx].offset;
        let line = self.format_sample(idx, cooked_time, false, 1, raw_offset, offset, dispersion);
        host.log_sample(&line);
        if !self.refclocks[idx].driver.has_poll() {
            self.refclocks[idx].driver_polled += 1;
        }
        true
    }

    /// chrony `pps_stratum`.
    fn pps_stratum(&self, host: &mut dyn RefclockHost, idx: usize, ts: Timespec) -> i32 {
        let params = host.ref_get_reference_params(ts);
        if params.ref_id == self.refclocks[idx].ref_id
            || (!params.is_synchronised && params.leap != LEAP_UNSYNCHRONISED)
        {
            return params.stratum - 1;
        }
        for refclock in self.refclocks.iter() {
            if refclock.ref_id == params.ref_id && refclock.pps_active && refclock.lock_ref == -1 {
                return params.stratum - 1;
            }
        }
        0
    }

    /// chrony `get_local_stats` + `follow_local` (local-mode tracking follow).
    fn follow_local(
        &mut self,
        host: &mut dyn RefclockHost,
        idx: usize,
        prev_ref_time: Timespec,
        prev_freq: f64,
        prev_offset: f64,
    ) {
        let Some(td) = host.src_get_tracking_data(idx) else { return };
        if prev_ref_time.is_zero() || td.ref_time.is_zero() {
            return;
        }
        let dfreq = (td.freq - prev_freq) / (1.0 - prev_freq);
        let elapsed = td.ref_time.diff_to(prev_ref_time);
        let doffset = td.offset - elapsed * prev_freq - prev_offset;

        if !host.ref_adjust_reference(doffset, dfreq) {
            return;
        }
        let now = host.lcl_read_cooked_time();
        host.spf_slew_samples(idx, now, dfreq, doffset);
        if td.offset.abs() >= 1.0 {
            host.spf_correct_offset(idx, -td.offset.round());
        }
    }

    /// chrony `poll_timeout`: poll the driver, forward a filtered sample to the
    /// source, and reschedule.
    pub fn poll_timeout(&mut self, host: &mut dyn RefclockHost, idx: usize) {
        let mut poll = self.refclocks[idx].poll;

        if self.refclocks[idx].driver.has_poll() {
            poll = self.refclocks[idx].driver_poll;
            self.refclocks[idx].driver.poll();
            self.refclocks[idx].driver_polled += 1;
        }

        let inst = &self.refclocks[idx];
        let skip = inst.driver.has_poll()
            && inst.driver_polled < (1 << (inst.poll - inst.driver_poll));
        if !skip {
            self.refclocks[idx].driver_polled = 0;

            if let Some(sample) = host.spf_get_filtered_sample(idx) {
                let stratum = if self.refclocks[idx].pps_active && self.refclocks[idx].lock_ref == -1
                {
                    self.pps_stratum(host, idx, sample.time)
                } else {
                    self.refclocks[idx].stratum
                };

                let mut local_ref = (Timespec::default(), 0.0, 0.0);
                if self.refclocks[idx].local {
                    if let Some(td) = host.src_get_tracking_data(idx) {
                        local_ref = (td.ref_time, td.freq, td.offset);
                    }
                    self.refclocks[idx].leap_status = LEAP_UNSYNCHRONISED;
                }

                host.src_update_reachability(idx, true);
                host.src_update_status(idx, stratum, self.refclocks[idx].leap_status);
                host.src_accumulate_sample(idx, &sample);
                host.src_select_source(idx);

                if self.refclocks[idx].local {
                    self.follow_local(host, idx, local_ref.0, local_ref.1, local_ref.2);
                }

                let line =
                    self.format_sample(idx, sample.time, true, 0, 0.0, sample.offset, sample.peer_dispersion);
                host.log_sample(&line);
            } else {
                host.src_update_reachability(idx, false);
            }
        }

        self.refclocks[idx].timeout_id = host.sch_add_timeout_by_delay(log2_to_double(poll));
    }

    /// chrony `slew_samples` (the `LCL` parameter-change handler over all refclocks).
    pub fn on_slew(
        &mut self,
        host: &mut dyn RefclockHost,
        cooked: Timespec,
        dfreq: f64,
        doffset: f64,
        unknown_step: bool,
    ) {
        for i in 0..self.refclocks.len() {
            if unknown_step {
                host.spf_drop_samples(i);
            } else {
                host.spf_slew_samples(i, cooked, dfreq, doffset);
            }
        }
    }

    /// chrony `add_dispersion` (the `LCL` dispersion-notify handler).
    pub fn on_dispersion(&mut self, host: &mut dyn RefclockHost, dispersion: f64) {
        for i in 0..self.refclocks.len() {
            host.spf_add_dispersion(i, dispersion);
        }
    }

    /// chrony `log_sample`: format one tracking-log line (or empty if logging off).
    #[allow(clippy::too_many_arguments)]
    fn format_sample(
        &self,
        idx: usize,
        sample_time: Timespec,
        filtered: bool,
        pulse: i32,
        raw_offset: f64,
        cooked_offset: f64,
        dispersion: f64,
    ) -> String {
        if !self.log_refclocks {
            return String::new();
        }
        let sync = ['N', '+', '-', '?'];
        let refid = crate::util::refid_to_string(self.refclocks[idx].ref_id);
        let leap = self.refclocks[idx].leap_status as usize;
        if !filtered {
            format!(
                "{}.{:06} {:<5} {:3} {} {} {:13.6e} {:13.6e} {:10.3e}",
                time_to_log_form(sample_time.sec),
                sample_time.nsec / 1000,
                refid,
                self.refclocks[idx].driver_polled,
                sync[leap],
                pulse,
                raw_offset,
                cooked_offset,
                dispersion,
            )
        } else {
            format!(
                "{}.{:06} {:<5}   - {} -       -       {:13.6e} {:10.3e}",
                time_to_log_form(sample_time.sec),
                sample_time.nsec / 1000,
                refid,
                sync[leap],
                cooked_offset,
                dispersion,
            )
        }
    }
}

/// `RCL_GetDriverData`: retrieve opaque driver data from a refclock instance.
/// Returns a mutable reference to the driver's state (a `&mut dyn Any`).
pub fn rcl_get_driver_data<'a>(
    instance: &'a mut dyn RclDriverInstance,
) -> Option<&'a mut dyn core::any::Any> {
    instance.driver_data()
}

/// `RCL_SetDriverData`: replace the opaque driver data on a refclock instance.
pub fn rcl_set_driver_data(
    instance: &mut dyn RclDriverInstance,
    data: Box<dyn core::any::Any>,
) {
    instance.set_driver_data(data);
}

/// Trait for refclock instances that can store opaque driver data.
pub trait RclDriverInstance {
    fn driver_data(&mut self) -> Option<&mut dyn core::any::Any>;
    fn set_driver_data(&mut self, data: Box<dyn core::any::Any>);
}

#[cfg(test)]
mod tests;
