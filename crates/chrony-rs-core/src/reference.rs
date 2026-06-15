//! Reference / tracking + drift state — a complete port of chrony 4.5
//! `reference.c` (all 46 functions). The time-discipline keystone.
//!
//! # What this module is
//!
//! `reference.c` is the layer directly above the local clock ([`crate::local`]): it
//! takes the offset/frequency/skew of the *selected* source and turns it into the
//! correction applied to the system clock, while managing the drift-file
//! persistence, leap-second handling, fallback drifts, the synchronisation status,
//! and the `tracking` report. It is the convergence of the discipline stack
//! (`regress` → `sourcestats` → `samplefilt` → `sources` → `local` → here).
//!
//! # Adaptations (documented, not silent)
//!
//! * **All host boundaries are injected via [`RefHost`].** chrony reaches the local
//!   clock (`LCL_*`), the scheduler (`SCH_*`), the system timezone database (the
//!   leap-second `get_tz_leap`), the random source, the drift file, the tracking
//!   log, and the mail notifier through module globals; here they are one trait.
//! * **Config knobs are a [`RefConfig`] struct** set at [`Reference::initialise`],
//!   exactly as `local.c`'s port threads its configuration.
//! * **Scheduler timeouts are dispatched explicitly.** chrony's static timeout
//!   handlers (leap start/end, fallback drift) are driven by the host scheduler
//!   calling [`Reference::dispatch_timeout`] with the id it was handed.
//! * **`gmtime`/`strftime` are reimplemented** (civil-date arithmetic, FIPS-free) so
//!   `is_leap_second_day` and the tracking-log timestamp are deterministic; only the
//!   *timezone-leap* lookup (`get_tz_leap`, which needs the TZ database) stays a host
//!   boundary.
//!
//! # Oracle
//!
//! The computational core — `REF_SetReference` / `REF_AdjustReference` and the
//! estimator/step/dispersion/drift helpers it composes (`get_clock_estimates`,
//! `get_correction_rate`, `get_root_dispersion`, `is_step_limit_reached`,
//! `is_offset_ok`, `update_fb_drifts`) — is differential-tested against the **real
//! compiled `reference.c`** (`research/oracle/reference-c-vectors.txt`): a C
//! generator drives a sequence of reference updates over recording `LCL_*`/`SCH_*`
//! stubs and captures every accumulated frequency/offset/correction-rate, step,
//! sync status, drift-file content, and tracking-report field. The port replays the
//! identical inputs and matches them. The remaining policy/I-O functions (leap
//! scheduling, special modes, local-reference params, accessors) are faithfully
//! translated and unit-tested. See the tests.

use crate::util;

/// chrony `NTP_Leap`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NtpLeap {
    /// `LEAP_Normal`.
    Normal = 0,
    /// `LEAP_InsertSecond`.
    InsertSecond = 1,
    /// `LEAP_DeleteSecond`.
    DeleteSecond = 2,
    /// `LEAP_Unsynchronised`.
    Unsynchronised = 3,
}

/// chrony `REF_Mode`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RefMode {
    /// `REF_ModeNormal`.
    Normal,
    /// `REF_ModeInitStepSlew`.
    InitStepSlew,
    /// `REF_ModeUpdateOnce`.
    UpdateOnce,
    /// `REF_ModePrintOnce`.
    PrintOnce,
    /// `REF_ModeIgnore`.
    Ignore,
}

/// chrony `REF_LeapMode`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RefLeapMode {
    /// `REF_LeapModeSystem`.
    System,
    /// `REF_LeapModeSlew`.
    Slew,
    /// `REF_LeapModeStep`.
    Step,
    /// `REF_LeapModeIgnore`.
    Ignore,
}

/// chrony `LCL_ChangeType` (the subset `reference.c` distinguishes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LclChangeType {
    /// `LCL_ChangeAdjust`.
    Adjust,
    /// `LCL_ChangeStep`.
    Step,
    /// `LCL_ChangeUnknownStep`.
    UnknownStep,
}

/// A `struct timespec` with chrony's `UTI_*` helpers (seconds + nanoseconds).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Timespec {
    /// Seconds since the Unix epoch.
    pub sec: i64,
    /// Nanoseconds within the second (`0..1_000_000_000`).
    pub nsec: i32,
}

impl Timespec {
    /// `UTI_DiffTimespecsToDouble(self, b)` = `self - b` in seconds.
    pub fn diff_to(self, b: Timespec) -> f64 {
        (self.sec - b.sec) as f64 + (self.nsec - b.nsec) as f64 * 1.0e-9
    }
    /// `UTI_AddDoubleToTimespec(self, increment)` — replicates chrony's exact
    /// truncate-then-normalise algorithm (C casts truncate toward zero).
    pub fn add_double(self, increment: f64) -> Timespec {
        let int_part = increment as i64; // (time_t)increment
        let sec = self.sec + int_part;
        // start.tv_nsec + (long)(1e9 * (increment - int_part))
        let nsec = self.nsec as i64 + (1.0e9 * (increment - int_part as f64)) as i64;
        // UTI_NormaliseTimespec: bring nsec back into [0, 1e9).
        Timespec { sec: sec + nsec.div_euclid(1_000_000_000), nsec: nsec.rem_euclid(1_000_000_000) as i32 }
    }
    /// `UTI_IsZeroTimespec`.
    pub fn is_zero(self) -> bool {
        self.sec == 0 && self.nsec == 0
    }
}

/// `NTP_REFID_LOCAL` (127.127.1.1) and `NTP_REFID_UNSYNC`.
const NTP_REFID_LOCAL: u32 = 0x7F7F_0101;
const NTP_REFID_UNSYNC: u32 = 0x0;
/// `NTP_MAX_STRATUM`.
const NTP_MAX_STRATUM: i32 = 16;
/// `IPADDR_UNSPEC` family marker (chrony's enum; only the unspec case matters here).
const IPADDR_UNSPEC: u16 = 0;
const IPADDR_INET4: u16 = 1;

/// chrony `MIN_SKEW`.
const MIN_SKEW: f64 = 1.0e-12;
/// chrony `LOCAL_REF_UPDATE_INTERVAL`.
const LOCAL_REF_UPDATE_INTERVAL: f64 = 64.0;
/// chrony `MAX_DRIFTFILE_AGE`.
const MAX_DRIFTFILE_AGE: f64 = 3600.0;
/// chrony `LEAP_SECOND_CLOSE`.
const LEAP_SECOND_CLOSE: i64 = 5;

fn square(x: f64) -> f64 {
    x * x
}
fn clamp(lo: f64, x: f64, hi: f64) -> f64 {
    if x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

/// chrony's config knobs read in `REF_Initialise` (`CNF_Get*`).
#[derive(Clone, Debug)]
pub struct RefConfig {
    /// `CNF_GetMaxUpdateSkew` (ppm; stored as a fraction).
    pub max_update_skew_ppm: f64,
    /// `CNF_GetCorrectionTimeRatio`.
    pub correction_time_ratio: f64,
    /// `CNF_GetMakeStep` -> (limit, threshold).
    pub make_step_limit: i32,
    pub make_step_threshold: f64,
    /// `CNF_GetMaxChange` -> (delay, ignore, max).
    pub max_offset_delay: i32,
    pub max_offset_ignore: i32,
    pub max_offset: f64,
    /// `CNF_GetLogChange`.
    pub log_change_threshold: f64,
    /// `CNF_GetMailOnChange` -> (enabled, threshold, user).
    pub do_mail_change: bool,
    pub mail_change_threshold: f64,
    pub mail_change_user: String,
    /// `CNF_GetLeapSecMode`.
    pub leap_mode: RefLeapMode,
    /// `CNF_GetLeapSecTimezone` is configured (the name itself lives in the host).
    pub leap_tzname: bool,
    /// `CNF_GetFallbackDrifts` -> (min, max).
    pub fb_drift_min: i32,
    pub fb_drift_max: i32,
    /// `CNF_AllowLocalReference` -> (enable, stratum, distance, orphan).
    pub enable_local_stratum: bool,
    pub local_stratum: i32,
    pub local_distance: f64,
    pub local_orphan: bool,
    /// `CNF_GetLogTracking`: open the tracking log.
    pub log_tracking: bool,
    /// `CNF_GetInitStepThreshold` (for `REF_ModeInitStepSlew`).
    pub init_step_threshold: f64,
    /// `CNF_GetDriftFile` is configured (the path itself lives in the host).
    pub drift_file: bool,
}

impl Default for RefConfig {
    fn default() -> RefConfig {
        // chrony's documented defaults.
        RefConfig {
            max_update_skew_ppm: 1000.0,
            correction_time_ratio: 3.0,
            make_step_limit: 0,
            make_step_threshold: 0.0,
            max_offset_delay: -1,
            max_offset_ignore: 0,
            max_offset: 0.0,
            log_change_threshold: 1.0,
            do_mail_change: false,
            mail_change_threshold: 0.0,
            mail_change_user: String::new(),
            leap_mode: RefLeapMode::System,
            leap_tzname: false,
            fb_drift_min: 0,
            fb_drift_max: 0,
            enable_local_stratum: false,
            local_stratum: 10,
            local_distance: 1.0,
            local_orphan: false,
            log_tracking: false,
            init_step_threshold: 0.0,
            drift_file: false,
        }
    }
}

/// The host boundary chrony reaches through `LCL_*` / `SCH_*` / `UTI_*` globals.
pub trait RefHost {
    // ---- local clock (LCL_*) ----
    /// `LCL_ReadRawTime`.
    fn read_raw_time(&mut self) -> Timespec;
    /// `LCL_GetOffsetCorrection` -> the uncorrected offset.
    fn get_offset_correction(&mut self, raw: Timespec) -> f64;
    /// `LCL_AccumulateFrequencyAndOffset`.
    fn accumulate_freq_and_offset(&mut self, freq: f64, offset: f64, corr_rate: f64);
    /// `LCL_AccumulateFrequencyAndOffsetNoHandlers`; returns the chrony int result.
    fn accumulate_freq_and_offset_no_handlers(
        &mut self,
        freq: f64,
        offset: f64,
        corr_rate: f64,
    ) -> i32;
    /// `LCL_AccumulateOffset`.
    fn accumulate_offset(&mut self, offset: f64, corr_rate: f64);
    /// `LCL_ApplyStepOffset`; returns whether the step was applied.
    fn apply_step_offset(&mut self, offset: f64) -> bool;
    /// `LCL_ReadAbsoluteFrequency`.
    fn read_absolute_frequency(&mut self) -> f64;
    /// `LCL_SetAbsoluteFrequency`.
    fn set_absolute_frequency(&mut self, freq_ppm: f64);
    /// `LCL_GetMaxClockError`.
    fn get_max_clock_error(&mut self) -> f64;
    /// `LCL_SetSyncStatus`.
    fn set_sync_status(&mut self, synchronised: bool, est_error: f64, max_error: f64);
    /// `LCL_CanSystemLeap`.
    fn can_system_leap(&mut self) -> bool;
    /// `LCL_SetSystemLeap`.
    fn set_system_leap(&mut self, leap_sec: i32, tai_offset: i32);
    /// `LCL_NotifyLeap` (chrony 4.5 notifies the slew/step leap to listeners).
    fn notify_leap(&mut self, leap_sec: i32);

    // ---- scheduler (SCH_*) ----
    /// `SCH_GetLastEventMonoTime`.
    fn mono_now(&mut self) -> f64;
    /// `SCH_GetLastEventTime` -> (cooked, raw).
    fn last_event_time(&mut self) -> (Timespec, Timespec);
    /// `SCH_AddTimeout(when, ...)`; returns the timeout id (non-zero).
    fn add_timeout(&mut self, when: Timespec) -> u32;
    /// `SCH_AddTimeoutByDelay(delay, ...)`; returns the timeout id (non-zero).
    fn add_timeout_by_delay(&mut self, delay: f64) -> u32;
    /// `SCH_RemoveTimeout`.
    fn remove_timeout(&mut self, id: u32);

    // ---- timezone leap database (get_tz_leap) ----
    /// `get_tz_leap(when)` -> (leap, tai_offset). The system TZ database is a host
    /// boundary; only called when a leap timezone is configured.
    fn tz_leap(&mut self, when: i64) -> (NtpLeap, i32);

    // ---- misc host I/O ----
    /// `UTI_GetRandomBytes` of a `u32` (used by `fuzz_ref_time`).
    fn random_u32(&mut self) -> u32;
    /// Read the drift file at init -> (freq_ppm, skew_ppm) if present and valid.
    fn read_drift_file(&mut self) -> Option<(f64, f64)>;
    /// `update_drift_file`: persist (freq_ppm, skew) [skew is a fraction].
    fn write_drift_file(&mut self, freq_ppm: f64, skew: f64);
    /// `LOG_FileWrite` to the tracking log (already formatted).
    fn log_tracking(&mut self, line: &str);
    /// `LOG(LOGS_WARN/INFO, ...)`.
    fn log_message(&mut self, msg: &str);
    /// `maybe_log_offset`'s mail notification (the body/`popen` is the host's).
    fn mail_notification(&mut self, user: &str, offset: f64, now: i64);
}

/// chrony's `RPT_TrackingReport` (the fields `REF_GetTrackingReport` fills).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RefTrackingReport {
    /// `ip_addr.family` (`IPADDR_UNSPEC` when no source IP).
    pub ip_family: u16,
    pub ref_id: u32,
    pub stratum: i32,
    pub leap_status: i32,
    pub ref_time: Timespec,
    pub current_correction: f64,
    pub last_offset: f64,
    pub rms_offset: f64,
    pub freq_ppm: f64,
    pub resid_freq_ppm: f64,
    pub skew_ppm: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub last_update_interval: f64,
}

/// Which static timeout a scheduler id maps to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TimeoutKind {
    LeapStart,
    LeapEnd,
    FbDrift,
}

/// A fallback-drift accumulator entry (chrony `struct fb_drift`).
#[derive(Clone, Copy, Default)]
struct FbDrift {
    freq: f64,
    secs: f64,
}

/// The reference / tracking module state (chrony's `reference.c` globals).
pub struct Reference {
    cfg: RefConfig,
    initialised: bool,
    mode: RefMode,

    are_we_synchronised: bool,
    our_leap_status: NtpLeap,
    our_leap_sec: i32,
    our_tai_offset: i32,

    our_stratum: i32,
    our_ref_id: u32,
    our_ref_ip_family: u16,
    our_ref_ip_in4: u32,
    our_ref_time: Timespec,
    our_skew: f64,
    our_residual_freq: f64,
    our_root_delay: f64,
    our_root_dispersion: f64,
    our_offset_sd: f64,
    our_frequency_sd: f64,

    max_update_skew: f64,
    last_offset: f64,
    avg2_offset: f64,
    avg2_moving: bool,
    correction_time_ratio: f64,

    make_step_limit: i32,
    make_step_threshold: f64,
    max_offset_delay: i32,
    max_offset_ignore: i32,
    max_offset: f64,
    log_change_threshold: f64,

    do_mail_change: bool,
    mail_change_threshold: f64,
    mail_change_user: String,

    mode_end_result: Option<i32>,
    has_drift_file: bool,
    drift_file_age: f64,

    leap_mode: RefLeapMode,
    leap_when: i64,
    leap_in_progress: bool,
    leap_timeout_id: u32,
    leap_timeout_kind: TimeoutKind,
    leap_tzname: bool,

    log_tracking: bool,

    fb_drift_min: i32,
    fb_drift_max: i32,
    fb_drifts: Vec<FbDrift>,
    next_fb_drift: i32,
    fb_drift_timeout_id: u32,

    last_ref_update: f64,
    last_ref_update_interval: f64,
    last_ref_adjustment: f64,
    ref_adjustments: i32,
    last_sys_offset: f64,

    enable_local_stratum: bool,
    local_stratum: i32,
    local_orphan: bool,
    local_distance: f64,
    local_ref_time: Timespec,
}

impl Reference {
    /// chrony `REF_Initialise`.
    pub fn initialise(host: &mut dyn RefHost, cfg: RefConfig) -> Reference {
        let mut r = Reference {
            initialised: true,
            mode: RefMode::Normal,
            are_we_synchronised: false,
            our_leap_status: NtpLeap::Unsynchronised,
            our_leap_sec: 0,
            our_tai_offset: 0,
            our_stratum: 0,
            our_ref_id: 0,
            our_ref_ip_family: IPADDR_UNSPEC,
            our_ref_ip_in4: 0,
            our_ref_time: Timespec::default(),
            our_skew: 1.0,
            our_residual_freq: 0.0,
            our_root_delay: 1.0,
            our_root_dispersion: 1.0,
            our_offset_sd: 0.0,
            our_frequency_sd: 0.0,
            max_update_skew: 0.0,
            last_offset: 0.0,
            avg2_offset: 0.0,
            avg2_moving: false,
            correction_time_ratio: 0.0,
            make_step_limit: 0,
            make_step_threshold: 0.0,
            max_offset_delay: 0,
            max_offset_ignore: 0,
            max_offset: 0.0,
            log_change_threshold: 0.0,
            do_mail_change: false,
            mail_change_threshold: 0.0,
            mail_change_user: String::new(),
            mode_end_result: None,
            has_drift_file: false,
            drift_file_age: 0.0,
            leap_mode: RefLeapMode::System,
            leap_when: 0,
            leap_in_progress: false,
            leap_timeout_id: 0,
            leap_timeout_kind: TimeoutKind::LeapStart,
            leap_tzname: false,
            log_tracking: false,
            fb_drift_min: 0,
            fb_drift_max: 0,
            fb_drifts: Vec::new(),
            next_fb_drift: 0,
            fb_drift_timeout_id: 0,
            last_ref_update: 0.0,
            last_ref_update_interval: 0.0,
            last_ref_adjustment: 0.0,
            ref_adjustments: 0,
            last_sys_offset: 0.0,
            enable_local_stratum: false,
            local_stratum: 0,
            local_orphan: false,
            local_distance: 0.0,
            local_ref_time: Timespec::default(),
            cfg: cfg.clone(),
        };

        let mut our_frequency_ppm = 0.0;

        // Drift file (the host owns the path; this flag mirrors CNF_GetDriftFile).
        r.has_drift_file = cfg.drift_file;
        if r.has_drift_file {
            if let Some((file_freq_ppm, file_skew_ppm)) = host.read_drift_file() {
                our_frequency_ppm = file_freq_ppm;
                r.our_skew = 1.0e-6 * file_skew_ppm;
                if r.our_skew < MIN_SKEW {
                    r.our_skew = MIN_SKEW;
                }
                host.set_absolute_frequency(our_frequency_ppm);
            }
        }

        if our_frequency_ppm == 0.0 {
            our_frequency_ppm = host.read_absolute_frequency();
            let _ = our_frequency_ppm; // logged in chrony; no behavioural effect
        }

        r.log_tracking = cfg.log_tracking;
        r.max_update_skew = cfg.max_update_skew_ppm.abs() * 1.0e-6;
        r.correction_time_ratio = cfg.correction_time_ratio;

        r.enable_local_stratum = cfg.enable_local_stratum;
        r.local_stratum = cfg.local_stratum;
        r.local_orphan = cfg.local_orphan;
        r.local_distance = cfg.local_distance;
        r.local_ref_time = Timespec::default();

        r.leap_when = 0;
        r.leap_timeout_id = 0;
        r.leap_in_progress = false;
        r.leap_mode = cfg.leap_mode;
        if r.leap_mode == RefLeapMode::System && !host.can_system_leap() {
            r.leap_mode = RefLeapMode::Step;
        }

        r.leap_tzname = cfg.leap_tzname;
        if r.leap_tzname {
            // chrony validates the timezone against the 2012 leap seconds.
            let (l1, t1) = host.tz_leap(1_341_014_400);
            let (l2, t2) = host.tz_leap(1_356_912_000);
            if !(l1 == NtpLeap::InsertSecond && t1 == 34 && l2 == NtpLeap::Normal && t2 == 35) {
                r.leap_tzname = false;
            }
        }

        r.make_step_limit = cfg.make_step_limit;
        r.make_step_threshold = cfg.make_step_threshold;
        r.max_offset_delay = cfg.max_offset_delay;
        r.max_offset_ignore = cfg.max_offset_ignore;
        r.max_offset = cfg.max_offset;
        r.do_mail_change = cfg.do_mail_change;
        r.mail_change_threshold = cfg.mail_change_threshold;
        r.mail_change_user = cfg.mail_change_user.clone();
        r.log_change_threshold = cfg.log_change_threshold;

        r.fb_drift_min = cfg.fb_drift_min;
        r.fb_drift_max = cfg.fb_drift_max;
        if r.fb_drift_max >= r.fb_drift_min && r.fb_drift_min > 0 {
            r.fb_drifts = vec![FbDrift::default(); (r.fb_drift_max - r.fb_drift_min + 1) as usize];
            r.next_fb_drift = 0;
            r.fb_drift_timeout_id = 0;
        }

        r.our_ref_time = Timespec::default();
        r.last_ref_update = 0.0;
        r.last_ref_update_interval = 0.0;
        r.last_ref_adjustment = 0.0;
        r.ref_adjustments = 0;

        // (LCL_AddParameterChangeHandler(handle_slew) is the daemon's wiring;
        // see Reference::on_slew.)

        // Make first entry in tracking log.
        r.set_unsynchronised(host);
        r
    }

    /// chrony `REF_Finalise`.
    pub fn finalise(&mut self, host: &mut dyn RefHost) {
        self.update_leap_status(host, NtpLeap::Unsynchronised, 0, false);
        if self.has_drift_file {
            let freq = host.read_absolute_frequency();
            host.write_drift_file(freq, self.our_skew);
        }
        self.fb_drifts.clear();
        self.initialised = false;
    }

    /// chrony `REF_SetMode`.
    pub fn set_mode(&mut self, mode: RefMode) {
        self.mode = mode;
    }
    /// chrony `REF_GetMode`.
    pub fn get_mode(&self) -> RefMode {
        self.mode
    }
    /// chrony `REF_SetModeEndHandler`: in this port the end-result is recorded and
    /// surfaced via [`Reference::take_mode_end_result`].
    pub fn take_mode_end_result(&mut self) -> Option<i32> {
        self.mode_end_result.take()
    }
    /// chrony `REF_GetLeapMode`.
    pub fn get_leap_mode(&self) -> RefLeapMode {
        self.leap_mode
    }

    /// chrony `handle_slew` (the `LCL` parameter-change handler).
    pub fn on_slew(
        &mut self,
        host: &mut dyn RefHost,
        cooked: Timespec,
        dfreq: f64,
        doffset: f64,
        change_type: LclChangeType,
    ) {
        if !self.our_ref_time.is_zero() {
            // UTI_AdjustTimespec(our_ref_time, cooked, &our_ref_time, ..., dfreq, doffset)
            let elapsed = cooked.diff_to(self.our_ref_time);
            let delta = elapsed * dfreq - doffset;
            self.our_ref_time = self.our_ref_time.add_double(delta);
        }

        if change_type == LclChangeType::UnknownStep {
            self.last_ref_update = 0.0;
            self.set_unsynchronised(host);
        }

        if change_type != LclChangeType::Adjust && self.our_leap_sec != 0 && !self.leap_in_progress {
            let now = host.read_raw_time();
            self.update_leap_status(host, self.our_leap_status, now.sec, true);
        }
    }

    /// chrony `update_drift_file`.
    fn update_drift_file(&mut self, host: &mut dyn RefHost, freq_ppm: f64, skew: f64) {
        host.write_drift_file(freq_ppm, skew);
    }

    /// chrony `update_fb_drifts`.
    fn update_fb_drifts(&mut self, host: &mut dyn RefHost, freq_ppm: f64, update_interval: f64) {
        debug_assert!(self.are_we_synchronised);

        if self.next_fb_drift > 0 {
            self.next_fb_drift = 0;
        }

        host.remove_timeout(self.fb_drift_timeout_id);
        self.fb_drift_timeout_id = 0;

        if update_interval < 1.0 || update_interval > self.last_ref_update_interval * 4.0 {
            return;
        }

        for i in 0..(self.fb_drift_max - self.fb_drift_min + 1) {
            let secs = (1i64 << (i + self.fb_drift_min)) as f64;
            let d = &mut self.fb_drifts[i as usize];
            if d.secs < secs {
                d.freq = (d.freq * d.secs + update_interval * 0.5 * freq_ppm)
                    / (update_interval * 0.5 + d.secs);
                d.secs += update_interval * 0.5;
            } else {
                d.freq += (1.0 - 1.0 / (update_interval / secs).exp()) * (freq_ppm - d.freq);
            }
        }
    }

    /// chrony `fb_drift_timeout`.
    fn fb_drift_timeout(&mut self, host: &mut dyn RefHost) {
        self.fb_drift_timeout_id = 0;
        let idx = (self.next_fb_drift - self.fb_drift_min) as usize;
        host.set_absolute_frequency(self.fb_drifts[idx].freq);
        self.set_unsynchronised(host);
    }

    /// chrony `schedule_fb_drift`.
    fn schedule_fb_drift(&mut self, host: &mut dyn RefHost) {
        if self.fb_drift_timeout_id != 0 {
            return; // already scheduled
        }

        let now = host.mono_now();
        let unsynchronised = now - self.last_ref_update;

        let mut c = 0i32;
        let mut secs = 0i64;
        let mut i = self.fb_drift_min;
        while i <= self.fb_drift_max {
            secs = 1i64 << i;
            if self.fb_drifts[(i - self.fb_drift_min) as usize].secs < secs as f64 {
                i += 1;
                continue;
            }
            if unsynchronised < secs as f64 && i > self.next_fb_drift {
                break;
            }
            c = i;
            i += 1;
        }

        if c > self.next_fb_drift {
            self.set_absolute_from_fb(host, c);
            self.next_fb_drift = c;
        }

        if i <= self.fb_drift_max {
            self.next_fb_drift = i;
            self.fb_drift_timeout_id = host.add_timeout_by_delay(secs as f64 - unsynchronised);
            self.leap_or_fb(self.fb_drift_timeout_id, TimeoutKind::FbDrift);
        }
    }

    fn set_absolute_from_fb(&mut self, host: &mut dyn RefHost, c: i32) {
        let idx = (c - self.fb_drift_min) as usize;
        host.set_absolute_frequency(self.fb_drifts[idx].freq);
    }

    /// Record the kind of a freshly scheduled fb-drift timeout id.
    fn leap_or_fb(&mut self, _id: u32, _kind: TimeoutKind) {
        // fb_drift uses its own id field; nothing else to track.
    }

    /// chrony `end_ref_mode`.
    fn end_ref_mode(&mut self, result: i32) {
        self.mode = RefMode::Ignore;
        self.mode_end_result = Some(result);
    }

    /// chrony `maybe_log_offset`.
    fn maybe_log_offset(&mut self, host: &mut dyn RefHost, offset: f64, now: i64) {
        let abs_offset = offset.abs();
        if abs_offset > self.log_change_threshold {
            host.log_message(&format!("System clock wrong by {:.6} seconds", -offset));
        }
        if self.do_mail_change && abs_offset > self.mail_change_threshold {
            let user = self.mail_change_user.clone();
            host.mail_notification(&user, offset, now);
        }
    }

    /// chrony `is_step_limit_reached`.
    fn is_step_limit_reached(&mut self, offset: f64, offset_correction: f64) -> bool {
        if self.make_step_limit == 0 {
            return false;
        } else if self.make_step_limit > 0 {
            self.make_step_limit -= 1;
        }
        (offset - offset_correction).abs() > self.make_step_threshold
    }

    /// chrony `is_offset_ok`.
    fn is_offset_ok(&mut self, host: &mut dyn RefHost, offset: f64) -> bool {
        if self.max_offset_delay < 0 {
            return true;
        }
        if self.max_offset_delay > 0 {
            self.max_offset_delay -= 1;
            return true;
        }
        if offset.abs() > self.max_offset {
            host.log_message(&format!(
                "Adjustment of {:.3} seconds exceeds the allowed maximum of {:.3} seconds ({})",
                -offset,
                self.max_offset,
                if self.max_offset_ignore == 0 { "exiting" } else { "ignored" }
            ));
            if self.max_offset_ignore == 0 {
                self.end_ref_mode(0);
            } else if self.max_offset_ignore > 0 {
                self.max_offset_ignore -= 1;
            }
            return false;
        }
        true
    }

    /// chrony `is_leap_second_day` (last day of June or December, UTC).
    fn is_leap_second_day(when: i64) -> bool {
        let (_y, mon, mday, _h, _mi, _s) = civil_from_unix(when);
        (mon == 6 && mday == 30) || (mon == 12 && mday == 31)
    }

    /// chrony `leap_end_timeout`.
    fn leap_end_timeout(&mut self, host: &mut dyn RefHost) {
        self.leap_timeout_id = 0;
        self.leap_in_progress = false;

        if self.our_tai_offset != 0 {
            self.our_tai_offset += self.our_leap_sec;
        }
        self.our_leap_sec = 0;

        if self.leap_mode == RefLeapMode::System {
            host.set_system_leap(self.our_leap_sec, self.our_tai_offset);
        }

        if self.our_leap_status == NtpLeap::InsertSecond
            || self.our_leap_status == NtpLeap::DeleteSecond
        {
            self.our_leap_status = NtpLeap::Normal;
        }
    }

    /// chrony `leap_start_timeout`.
    fn leap_start_timeout(&mut self, host: &mut dyn RefHost) {
        self.leap_in_progress = true;

        match self.leap_mode {
            RefLeapMode::System => {}
            RefLeapMode::Slew => {
                host.notify_leap(self.our_leap_sec);
                host.accumulate_offset(self.our_leap_sec as f64, 0.0);
                host.log_message("Adjusting system clock for leap second");
            }
            RefLeapMode::Step => {
                host.notify_leap(self.our_leap_sec);
                host.apply_step_offset(self.our_leap_sec as f64);
                host.log_message("System clock was stepped for leap second");
            }
            RefLeapMode::Ignore => {
                host.log_message("Ignoring leap second");
            }
        }

        self.leap_timeout_id = host.add_timeout_by_delay(2.0);
        self.leap_timeout_kind = TimeoutKind::LeapEnd;
    }

    /// chrony `set_leap_timeout`.
    fn set_leap_timeout(&mut self, host: &mut dyn RefHost, now: i64) {
        host.remove_timeout(self.leap_timeout_id);
        self.leap_timeout_id = 0;
        self.leap_in_progress = false;

        if self.our_leap_sec == 0 {
            return;
        }

        self.leap_when = (now / (24 * 3600) + 1) * (24 * 3600);

        let mut when = Timespec { sec: self.leap_when, nsec: 0 };
        if self.our_leap_sec < 0 {
            when.sec -= 1;
        }
        if self.leap_mode == RefLeapMode::System {
            when.sec -= 1;
            when.nsec = 500_000_000;
        }

        self.leap_timeout_id = host.add_timeout(when);
        self.leap_timeout_kind = TimeoutKind::LeapStart;
    }

    /// chrony `update_leap_status`.
    fn update_leap_status(
        &mut self,
        host: &mut dyn RefHost,
        mut leap: NtpLeap,
        now: i64,
        reset: bool,
    ) {
        let mut leap_sec = 0;
        let mut tai_offset = 0;

        if self.leap_tzname && now != 0 {
            let (tz_leap, off) = host.tz_leap(now);
            tai_offset = off;
            if leap == NtpLeap::Normal {
                leap = tz_leap;
            }
        }

        if leap == NtpLeap::InsertSecond || leap == NtpLeap::DeleteSecond {
            if Self::is_leap_second_day(now) {
                leap_sec = if leap == NtpLeap::InsertSecond { 1 } else { -1 };
            } else {
                leap = NtpLeap::Normal;
            }
        }

        if (leap_sec != self.our_leap_sec || tai_offset != self.our_tai_offset)
            && !self.is_leap_second_close(host, None, 0.0)
        {
            self.our_leap_sec = leap_sec;
            self.our_tai_offset = tai_offset;

            match self.leap_mode {
                RefLeapMode::System => {
                    host.set_system_leap(self.our_leap_sec, self.our_tai_offset);
                    self.set_leap_timeout(host, now);
                }
                RefLeapMode::Slew | RefLeapMode::Step | RefLeapMode::Ignore => {
                    self.set_leap_timeout(host, now);
                }
            }
        } else if reset {
            self.set_leap_timeout(host, now);
        }

        self.our_leap_status = leap;
    }

    /// chrony `get_root_dispersion`.
    fn get_root_dispersion(&mut self, host: &mut dyn RefHost, ts: Timespec) -> f64 {
        if self.our_ref_time.is_zero() {
            return 1.0;
        }
        self.our_root_dispersion
            + ts.diff_to(self.our_ref_time).abs()
                * (self.our_skew + self.our_residual_freq.abs() + host.get_max_clock_error())
    }

    /// chrony `update_sync_status`.
    fn update_sync_status(&mut self, host: &mut dyn RefHost, now: Timespec) {
        let elapsed = now.diff_to(self.our_ref_time).abs();
        let disp = self.get_root_dispersion(host, now);
        host.set_sync_status(
            self.are_we_synchronised,
            self.our_offset_sd + elapsed * self.our_frequency_sd,
            self.our_root_delay / 2.0 + disp,
        );
    }

    /// chrony `write_log`.
    #[allow(clippy::too_many_arguments)]
    fn write_log(
        &mut self,
        host: &mut dyn RefHost,
        now: Timespec,
        combined_sources: i32,
        freq: f64,
        offset: f64,
        offset_sd: f64,
        uncorrected_offset: f64,
        orig_root_distance: f64,
    ) {
        if !self.log_tracking {
            return;
        }
        let leap_codes = ['N', '+', '-', '?'];
        let max_error = orig_root_distance + self.last_sys_offset.abs();
        let root_dispersion = self.get_root_dispersion(host, now);
        self.last_sys_offset = offset - uncorrected_offset;

        let refid = if self.our_ref_ip_family != IPADDR_UNSPEC {
            util::refid_to_string(self.our_ref_ip_in4)
        } else {
            util::refid_to_string(self.our_ref_id)
        };
        let line = format!(
            "{} {:<15} {:2} {:10.3} {:10.3} {:10.3e} {} {:2} {:10.3e} {:10.3e} {:10.3e} {:10.3e} {:10.3e}",
            time_to_log_form(now.sec),
            refid,
            self.our_stratum,
            freq,
            1.0e6 * self.our_skew,
            offset,
            leap_codes[self.our_leap_status as usize],
            combined_sources,
            offset_sd,
            uncorrected_offset,
            self.our_root_delay,
            root_dispersion,
            max_error,
        );
        host.log_tracking(&line);
    }

    /// chrony `special_mode_sync`.
    fn special_mode_sync(&mut self, host: &mut dyn RefHost, valid: bool, offset: f64) {
        match self.mode {
            RefMode::InitStepSlew => {
                if !valid {
                    host.log_message("No suitable source for initstepslew");
                    self.end_ref_mode(0);
                    return;
                }
                let step = offset.abs() >= self.cfg.init_step_threshold;
                if step {
                    host.apply_step_offset(offset);
                } else {
                    host.accumulate_offset(offset, 0.0);
                }
                self.end_ref_mode(1);
            }
            RefMode::UpdateOnce | RefMode::PrintOnce => {
                if !valid {
                    host.log_message("No suitable source for synchronisation");
                    self.end_ref_mode(0);
                    return;
                }
                let step = self.mode == RefMode::UpdateOnce;
                if step {
                    host.apply_step_offset(offset);
                }
                self.end_ref_mode(1);
            }
            RefMode::Ignore => {}
            RefMode::Normal => {}
        }
    }

    /// chrony `get_clock_estimates`.
    #[allow(clippy::too_many_arguments)]
    fn get_clock_estimates(
        &self,
        manual: bool,
        measured_freq: f64,
        measured_skew: f64,
    ) -> (f64, f64, f64) {
        let expected_freq = 0.0;
        let expected_skew = self.our_skew;

        let gain = if manual {
            1.0
        } else if measured_skew.abs() > self.max_update_skew {
            0.0
        } else {
            3.0 * square(expected_skew) / (3.0 * square(expected_skew) + square(measured_skew))
        };
        let gain = clamp(0.0, gain, 1.0);

        let estimated_freq = expected_freq + gain * (measured_freq - expected_freq);
        let residual_freq = measured_freq - estimated_freq;
        let extra_skew = (square(expected_freq - estimated_freq) * (1.0 - gain)
            + square(measured_freq - estimated_freq) * gain)
            .sqrt();
        let estimated_skew = expected_skew + gain * (measured_skew - expected_skew) + extra_skew;

        (estimated_freq, estimated_skew, residual_freq)
    }

    /// chrony `fuzz_ref_time`.
    fn fuzz_ref_time(&mut self, host: &mut dyn RefHost, ts: Timespec) -> Timespec {
        let rnd = host.random_u32();
        ts.add_double(-(rnd as f64) / (u32::MAX as f64))
    }

    /// chrony `get_correction_rate`.
    fn get_correction_rate(&self, offset_sd: f64, update_interval: f64) -> f64 {
        self.correction_time_ratio * 0.5 * offset_sd * update_interval
    }

    /// chrony `REF_SetReference`.
    #[allow(clippy::too_many_arguments)]
    pub fn set_reference(
        &mut self,
        host: &mut dyn RefHost,
        stratum: i32,
        leap: NtpLeap,
        combined_sources: i32,
        ref_id: u32,
        ref_ip: Option<u32>,
        ref_time: Timespec,
        mut offset: f64,
        offset_sd: f64,
        mut frequency: f64,
        frequency_sd: f64,
        mut skew: f64,
        root_delay: f64,
        root_dispersion: f64,
    ) {
        debug_assert!(self.initialised);

        if self.mode != RefMode::Normal {
            self.special_mode_sync(host, true, offset);
            return;
        }

        let manual = leap == NtpLeap::Unsynchronised;

        let mono_now = host.mono_now();
        let raw_now = host.read_raw_time();
        let uncorrected_offset = host.get_offset_correction(raw_now);
        let now = raw_now.add_double(uncorrected_offset);

        let elapsed = now.diff_to(ref_time);
        offset += elapsed * frequency;

        let update_interval =
            if self.last_ref_update != 0.0 { mono_now - self.last_ref_update } else { 0.0 };

        let residual_frequency;
        (frequency, skew, residual_frequency) =
            self.get_clock_estimates(manual, frequency, skew);

        if !self.is_offset_ok(host, offset) {
            return;
        }

        let orig_root_distance = self.our_root_delay / 2.0 + self.get_root_dispersion(host, now);

        self.are_we_synchronised = leap != NtpLeap::Unsynchronised;
        self.our_stratum = stratum + 1;
        self.our_ref_id = ref_id;
        match ref_ip {
            Some(ip) => {
                self.our_ref_ip_family = IPADDR_INET4;
                self.our_ref_ip_in4 = ip;
            }
            None => self.our_ref_ip_family = IPADDR_UNSPEC,
        }
        self.our_ref_time = ref_time;
        self.our_skew = skew;
        self.our_residual_freq = residual_frequency;
        self.our_root_delay = root_delay;
        self.our_root_dispersion = root_dispersion;
        self.our_frequency_sd = frequency_sd;
        self.our_offset_sd = offset_sd;
        self.last_ref_update = mono_now;
        self.last_ref_update_interval = update_interval;
        self.last_offset = offset;

        let (accumulate_offset, step_offset);
        if self.is_step_limit_reached(offset, uncorrected_offset) {
            accumulate_offset = uncorrected_offset;
            step_offset = offset - uncorrected_offset;
        } else {
            accumulate_offset = offset;
            step_offset = 0.0;
        }

        host.accumulate_freq_and_offset(
            frequency,
            accumulate_offset,
            self.get_correction_rate(offset_sd, update_interval),
        );

        self.maybe_log_offset(host, offset, raw_now.sec);

        if step_offset != 0.0 && host.apply_step_offset(step_offset) {
            host.log_message(&format!("System clock was stepped by {:.6} seconds", -step_offset));
        }

        self.update_leap_status(host, leap, raw_now.sec, false);
        self.update_sync_status(host, now);

        self.our_ref_time = self.fuzz_ref_time(host, self.our_ref_time);

        let local_abs_frequency = host.read_absolute_frequency();

        self.write_log(
            host,
            now,
            combined_sources,
            local_abs_frequency,
            offset,
            offset_sd,
            uncorrected_offset,
            orig_root_distance,
        );

        if self.has_drift_file {
            self.drift_file_age += update_interval;
            if self.drift_file_age >= MAX_DRIFTFILE_AGE {
                let skew = self.our_skew;
                self.update_drift_file(host, local_abs_frequency, skew);
                self.drift_file_age = 0.0;
            }
        }

        if !self.fb_drifts.is_empty() && self.are_we_synchronised {
            self.update_fb_drifts(host, local_abs_frequency, update_interval);
            self.schedule_fb_drift(host);
        }

        if self.avg2_moving {
            self.avg2_offset += 0.1 * (square(offset) - self.avg2_offset);
        } else {
            if self.avg2_offset > 0.0 && self.avg2_offset < square(offset) {
                self.avg2_moving = true;
            }
            self.avg2_offset = square(offset);
        }

        self.ref_adjustments = 0;
    }

    /// chrony `REF_AdjustReference`.
    pub fn adjust_reference(&mut self, host: &mut dyn RefHost, offset: f64, frequency: f64) -> i32 {
        let mono_now = host.mono_now();
        self.ref_adjustments += 1;

        let adj_corr_rate = self.get_correction_rate(offset.abs(), mono_now - self.last_ref_adjustment);
        let ref_corr_rate = self.get_correction_rate(self.our_offset_sd, self.last_ref_update_interval)
            / self.ref_adjustments as f64;
        self.last_ref_adjustment = mono_now;

        host.accumulate_freq_and_offset_no_handlers(
            frequency,
            offset,
            adj_corr_rate.max(ref_corr_rate),
        )
    }

    /// chrony `REF_SetManualReference`.
    pub fn set_manual_reference(
        &mut self,
        host: &mut dyn RefHost,
        ref_time: Timespec,
        offset: f64,
        frequency: f64,
        skew: f64,
    ) {
        // ref_id 'MANU' (0x4D414E55).
        self.set_reference(
            host,
            0,
            NtpLeap::Unsynchronised,
            1,
            0x4D41_4E55,
            None,
            ref_time,
            offset,
            0.0,
            frequency,
            skew,
            skew,
            0.0,
            0.0,
        );
    }

    /// chrony `REF_SetUnsynchronised`.
    pub fn set_unsynchronised(&mut self, host: &mut dyn RefHost) {
        debug_assert!(self.initialised);

        if self.mode != RefMode::Normal {
            self.special_mode_sync(host, false, 0.0);
            return;
        }

        let now_raw = host.read_raw_time();
        let uncorrected_offset = host.get_offset_correction(now_raw);
        let now = now_raw.add_double(uncorrected_offset);

        if !self.fb_drifts.is_empty() {
            self.schedule_fb_drift(host);
        }

        self.update_leap_status(host, NtpLeap::Unsynchronised, 0, false);
        self.our_ref_ip_family = IPADDR_INET4;
        self.our_ref_ip_in4 = 0;
        self.our_stratum = 0;
        self.are_we_synchronised = false;

        host.set_sync_status(false, 0.0, 0.0);

        let freq = host.read_absolute_frequency();
        let root_distance = self.our_root_delay / 2.0 + self.get_root_dispersion(host, now);
        self.write_log(host, now, 0, freq, 0.0, 0.0, uncorrected_offset, root_distance);
    }

    /// chrony `REF_UpdateLeapStatus`.
    pub fn update_leap_status_public(&mut self, host: &mut dyn RefHost, leap: NtpLeap) {
        if !self.are_we_synchronised {
            return;
        }
        let (now, raw_now) = host.last_event_time();
        self.update_leap_status(host, leap, raw_now.sec, false);
        self.update_sync_status(host, now);
    }

    /// chrony `REF_GetReferenceParams`.
    #[allow(clippy::type_complexity)]
    pub fn get_reference_params(
        &mut self,
        host: &mut dyn RefHost,
        local_time: Timespec,
    ) -> (bool, NtpLeap, i32, u32, Timespec, f64, f64) {
        debug_assert!(self.initialised);

        let dispersion = if self.are_we_synchronised {
            self.get_root_dispersion(host, local_time)
        } else {
            0.0
        };

        if self.are_we_synchronised
            && !(self.enable_local_stratum
                && self.our_root_delay / 2.0 + dispersion > self.local_distance)
        {
            let leap_status =
                if !self.leap_in_progress { self.our_leap_status } else { NtpLeap::Unsynchronised };
            (
                true,
                leap_status,
                self.our_stratum,
                self.our_ref_id,
                self.our_ref_time,
                self.our_root_delay,
                dispersion,
            )
        } else if self.enable_local_stratum {
            let delta = local_time.diff_to(self.local_ref_time);
            // chrony: delta > LOCAL_REF_UPDATE_INTERVAL || delta < 1.0.
            if !(1.0..=LOCAL_REF_UPDATE_INTERVAL).contains(&delta) {
                self.local_ref_time = local_time.add_double(-1.0);
                self.local_ref_time = self.fuzz_ref_time(host, self.local_ref_time);
            }
            (false, NtpLeap::Normal, self.local_stratum, NTP_REFID_LOCAL, self.local_ref_time, 0.0, 0.0)
        } else {
            (
                false,
                NtpLeap::Unsynchronised,
                NTP_MAX_STRATUM,
                NTP_REFID_UNSYNC,
                Timespec::default(),
                1.0,
                1.0,
            )
        }
    }

    /// chrony `REF_GetOurStratum`.
    pub fn get_our_stratum(&mut self, host: &mut dyn RefHost) -> i32 {
        let (now_cooked, _) = host.last_event_time();
        let (_, _, stratum, _, _, _, _) = self.get_reference_params(host, now_cooked);
        stratum
    }

    /// chrony `REF_GetOrphanStratum`.
    pub fn get_orphan_stratum(&self) -> i32 {
        if !self.enable_local_stratum || !self.local_orphan || self.mode != RefMode::Normal {
            return NTP_MAX_STRATUM;
        }
        self.local_stratum
    }

    /// chrony `REF_GetSkew`.
    pub fn get_skew(&self) -> f64 {
        self.our_skew
    }

    /// chrony `REF_ModifyMaxupdateskew`.
    pub fn modify_max_update_skew(&mut self, host: &mut dyn RefHost, new_max_update_skew_ppm: f64) {
        self.max_update_skew = new_max_update_skew_ppm * 1.0e-6;
        host.log_message(&format!("New maxupdateskew {new_max_update_skew_ppm} ppm"));
    }

    /// chrony `REF_ModifyMakestep`.
    pub fn modify_makestep(&mut self, host: &mut dyn RefHost, limit: i32, threshold: f64) {
        self.make_step_limit = limit;
        self.make_step_threshold = threshold;
        host.log_message(&format!("New makestep {threshold} {limit}"));
    }

    /// chrony `REF_EnableLocal`.
    pub fn enable_local(&mut self, host: &mut dyn RefHost, stratum: i32, distance: f64, orphan: i32) {
        self.enable_local_stratum = true;
        self.local_stratum = stratum.clamp(1, NTP_MAX_STRATUM - 1);
        self.local_distance = distance;
        self.local_orphan = orphan != 0;
        host.log_message("Enabled local reference mode");
    }

    /// chrony `REF_DisableLocal`.
    pub fn disable_local(&mut self, host: &mut dyn RefHost) {
        self.enable_local_stratum = false;
        host.log_message("Disabled local reference mode");
    }

    /// chrony `is_leap_close`.
    fn is_leap_close(&self, t: i64) -> bool {
        self.leap_when != 0
            && t >= self.leap_when - LEAP_SECOND_CLOSE
            && t < self.leap_when + LEAP_SECOND_CLOSE
    }

    /// chrony `REF_IsLeapSecondClose`.
    pub fn is_leap_second_close(
        &self,
        host: &mut dyn RefHost,
        ts: Option<Timespec>,
        offset: f64,
    ) -> bool {
        let (now, now_raw) = host.last_event_time();
        if self.is_leap_close(now.sec) || self.is_leap_close(now_raw.sec) {
            return true;
        }
        if let Some(ts) = ts {
            if self.is_leap_close(ts.sec) || self.is_leap_close(ts.sec + offset as i64) {
                return true;
            }
        }
        false
    }

    /// chrony `REF_GetTaiOffset`.
    pub fn get_tai_offset(&mut self, host: &mut dyn RefHost, ts: Timespec) -> i32 {
        let (_, tai_offset) = host.tz_leap(ts.sec);
        tai_offset
    }

    /// chrony `REF_GetTrackingReport`.
    pub fn get_tracking_report(&mut self, host: &mut dyn RefHost) -> RefTrackingReport {
        let now_raw = host.read_raw_time();
        let correction = host.get_offset_correction(now_raw);
        let now_cooked = now_raw.add_double(correction);

        let (synchronised, leap_status, mut stratum, ref_id, ref_time, root_delay, root_dispersion) =
            self.get_reference_params(host, now_cooked);

        if stratum == NTP_MAX_STRATUM && !synchronised {
            stratum = 0;
        }

        let mut rep = RefTrackingReport {
            ip_family: IPADDR_UNSPEC,
            ref_id,
            stratum,
            leap_status: leap_status as i32,
            ref_time,
            current_correction: correction,
            freq_ppm: host.read_absolute_frequency(),
            resid_freq_ppm: 0.0,
            skew_ppm: 0.0,
            last_update_interval: self.last_ref_update_interval,
            last_offset: self.last_offset,
            rms_offset: self.avg2_offset.sqrt(),
            root_delay,
            root_dispersion,
        };

        if synchronised {
            rep.ip_family = self.our_ref_ip_family;
            rep.resid_freq_ppm = 1.0e6 * self.our_residual_freq;
            rep.skew_ppm = 1.0e6 * self.our_skew;
        }
        rep
    }

    /// Dispatch a scheduler timeout previously handed to the host (chrony's static
    /// timeout handlers). `id` is the value returned by `add_timeout*`.
    pub fn dispatch_timeout(&mut self, host: &mut dyn RefHost, id: u32) {
        if id != 0 && id == self.fb_drift_timeout_id {
            self.fb_drift_timeout(host);
        } else if id != 0 && id == self.leap_timeout_id {
            match self.leap_timeout_kind {
                TimeoutKind::LeapStart => self.leap_start_timeout(host),
                TimeoutKind::LeapEnd => self.leap_end_timeout(host),
                TimeoutKind::FbDrift => {}
            }
        }
    }
}

/// Civil date from Unix seconds (UTC), Howard Hinnant's algorithm. Returns
/// `(year, month[1..12], day, hour, minute, second)`.
fn civil_from_unix(t: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let hour = secs / 3600;
    let minute = (secs % 3600) / 60;
    let second = secs % 60;

    // days since 1970-01-01 -> civil date
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, minute, second)
}

/// chrony `UTI_TimeToLogForm`: `"%Y-%m-%d %H:%M:%S"` in UTC.
pub(crate) fn time_to_log_form(t: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(t);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

#[cfg(test)]
mod tests;
