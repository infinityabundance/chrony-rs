//! Tests for the `reference.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `reference.c`.** A C generator
//! drives `REF_SetReference` (small offset, then a stepping offset), then
//! `REF_AdjustReference` and `REF_GetTrackingReport`, over recording `LCL_*`/`SCH_*`
//! stubs with the discipline core isolated (no drift file / leap tz / fallback drift
//! / tracking log). It captures every accumulated frequency/offset/correction-rate,
//! the step offset, the sync status, the no-handlers adjust, and the tracking-report
//! fields (`research/oracle/reference-c-vectors.txt`).
//! [`matches_real_c_reference_vectors`] replays the identical inputs through
//! [`Reference`] over a recording [`RefHost`] — including the same deterministic LCG
//! that feeds `fuzz_ref_time` (and hence the report's root dispersion) — and matches
//! every value.
//!
//! **Oracle #2 (independent): the civil-date / log-form helpers and policy logic.**
//! `is_leap_second_day` and the tracking-log timestamp are checked against known UTC
//! dates; the leap/local-reference/accessor paths are unit-tested directly.

use super::*;

/// The deterministic LCG (`UTI_GetRandomBytes`), one byte per call, project seed.
struct Lcg(u64);
impl Lcg {
    fn byte(&mut self) -> u8 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) as u8
    }
    fn u32_le(&mut self) -> u32 {
        let b = [self.byte(), self.byte(), self.byte(), self.byte()];
        u32::from_le_bytes(b)
    }
}

/// A recording host mirroring the C oracle's stubs.
struct RecHost {
    mono: f64,
    raw: Timespec,
    uncorrected: f64,
    abs_freq: f64,
    max_clock_error: f64,
    next_id: u32,
    rng: Lcg,

    acc_n: i32,
    acc_freq: f64,
    acc_off: f64,
    acc_rate: f64,
    accnh_n: i32,
    accnh_freq: f64,
    accnh_off: f64,
    accnh_rate: f64,
    step_n: i32,
    step_off: f64,
    sync_n: i32,
    sync_synch: bool,
    sync_est: f64,
    sync_max: f64,
}

impl RecHost {
    fn new() -> RecHost {
        RecHost {
            mono: 0.0,
            raw: Timespec { sec: 2_000_000_000, nsec: 0 },
            uncorrected: 0.001,
            abs_freq: 5.0,
            max_clock_error: 1.0e-6,
            next_id: 100,
            rng: Lcg(0x1234567890abcdef),
            acc_n: 0,
            acc_freq: 0.0,
            acc_off: 0.0,
            acc_rate: 0.0,
            accnh_n: 0,
            accnh_freq: 0.0,
            accnh_off: 0.0,
            accnh_rate: 0.0,
            step_n: 0,
            step_off: 0.0,
            sync_n: 0,
            sync_synch: false,
            sync_est: 0.0,
            sync_max: 0.0,
        }
    }
}

impl RefHost for RecHost {
    fn read_raw_time(&mut self) -> Timespec {
        self.raw
    }
    fn get_offset_correction(&mut self, _raw: Timespec) -> f64 {
        self.uncorrected
    }
    fn accumulate_freq_and_offset(&mut self, freq: f64, offset: f64, corr_rate: f64) {
        self.acc_freq = freq;
        self.acc_off = offset;
        self.acc_rate = corr_rate;
        self.acc_n += 1;
    }
    fn accumulate_freq_and_offset_no_handlers(
        &mut self,
        freq: f64,
        offset: f64,
        corr_rate: f64,
    ) -> i32 {
        self.accnh_freq = freq;
        self.accnh_off = offset;
        self.accnh_rate = corr_rate;
        self.accnh_n += 1;
        1
    }
    fn accumulate_offset(&mut self, _offset: f64, _corr_rate: f64) {}
    fn apply_step_offset(&mut self, offset: f64) -> bool {
        self.step_off = offset;
        self.step_n += 1;
        true
    }
    fn read_absolute_frequency(&mut self) -> f64 {
        self.abs_freq
    }
    fn set_absolute_frequency(&mut self, freq_ppm: f64) {
        self.abs_freq = freq_ppm;
    }
    fn get_max_clock_error(&mut self) -> f64 {
        self.max_clock_error
    }
    fn set_sync_status(&mut self, synchronised: bool, est_error: f64, max_error: f64) {
        self.sync_synch = synchronised;
        self.sync_est = est_error;
        self.sync_max = max_error;
        self.sync_n += 1;
    }
    fn can_system_leap(&mut self) -> bool {
        true
    }
    fn set_system_leap(&mut self, _leap_sec: i32, _tai_offset: i32) {}
    fn notify_leap(&mut self, _leap_sec: i32) {}
    fn mono_now(&mut self) -> f64 {
        self.mono
    }
    fn last_event_time(&mut self) -> (Timespec, Timespec) {
        (self.raw, self.raw)
    }
    fn add_timeout(&mut self, _when: Timespec) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
    fn add_timeout_by_delay(&mut self, _delay: f64) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
    fn remove_timeout(&mut self, _id: u32) {}
    fn tz_leap(&mut self, _when: i64) -> (NtpLeap, i32) {
        (NtpLeap::Normal, 0)
    }
    fn random_u32(&mut self) -> u32 {
        self.rng.u32_le()
    }
    fn read_drift_file(&mut self) -> Option<(f64, f64)> {
        None
    }
    fn write_drift_file(&mut self, _freq_ppm: f64, _skew: f64) {}
    fn log_tracking(&mut self, _line: &str) {}
    fn log_message(&mut self, _msg: &str) {}
    fn mail_notification(&mut self, _user: &str, _offset: f64, _now: i64) {}
}

/// The config matching the C oracle's `CNF_*` stubs.
fn oracle_cfg() -> RefConfig {
    RefConfig {
        max_update_skew_ppm: 1000.0,
        correction_time_ratio: 3.0,
        make_step_limit: -1,
        make_step_threshold: 0.5,
        max_offset_delay: -1,
        max_offset_ignore: 0,
        max_offset: 0.0,
        log_change_threshold: 1.0e9,
        do_mail_change: false,
        mail_change_threshold: 0.0,
        mail_change_user: String::new(),
        leap_mode: RefLeapMode::Slew,
        leap_tzname: false,
        fb_drift_min: 0,
        fb_drift_max: 0,
        enable_local_stratum: false,
        local_stratum: 0,
        local_distance: 0.0,
        local_orphan: false,
        log_tracking: false,
        init_step_threshold: 0.0,
        drift_file: false,
    }
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}
fn f(line: &str, key: &str) -> f64 {
    field(line, key).parse().unwrap()
}
fn i(line: &str, key: &str) -> i64 {
    field(line, key).parse().unwrap()
}

/// Floats are produced by identical IEEE-754 f64 sequences on both sides, so they
/// should match to the last ULP; allow a hair of slack for printf round-tripping.
fn close(a: f64, b: f64, what: &str) {
    let tol = 1e-12 * (1.0 + a.abs().max(b.abs()));
    assert!((a - b).abs() <= tol, "{what}: rust={a:.17e} c={b:.17e} (diff {:.3e})", (a - b).abs());
}

#[test]
fn matches_real_c_reference_vectors() {
    let vectors = include_str!("../../../../research/oracle/reference-c-vectors.txt");
    let line = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    let mut host = RecHost::new();
    let mut r = Reference::initialise(&mut host, oracle_cfg());

    let check_set = |host: &RecHost, l: &str| {
        assert_eq!(host.acc_n as i64, i(l, "acc_n"), "acc_n");
        close(host.acc_freq, f(l, "freq"), "acc freq");
        close(host.acc_off, f(l, "off"), "acc off");
        close(host.acc_rate, f(l, "rate"), "acc rate");
        assert_eq!(host.step_n as i64, i(l, "step_n"), "step_n");
        close(host.step_off, f(l, "step"), "step off");
        assert_eq!(host.sync_n as i64, i(l, "sync_n"), "sync_n");
        assert_eq!(host.sync_synch as i64, i(l, "synch"), "synch");
        close(host.sync_est, f(l, "est"), "sync est");
        close(host.sync_max, f(l, "max"), "sync max");
    };

    // ---- SET1: small offset, no step ----
    host.mono = 1000.0;
    let ref_time = Timespec { sec: host.raw.sec - 5, nsec: 0 };
    r.set_reference(
        &mut host, 2, NtpLeap::Normal, 4, 0x0A00_0001, None, ref_time, 0.02, 0.005, 1.0e-6, 0.1e-6,
        1.0e-6, 0.01, 0.02,
    );
    check_set(&host, line("SET1"));

    // ---- SET2: 64 s later ----
    host.mono = 1064.0;
    let ref_time = Timespec { sec: host.raw.sec - 2, nsec: 0 };
    r.set_reference(
        &mut host, 2, NtpLeap::Normal, 4, 0x0A00_0001, None, ref_time, 0.005, 0.002, 0.5e-6,
        0.05e-6, 0.8e-6, 0.01, 0.02,
    );
    check_set(&host, line("SET2"));

    // ---- SET3: large offset -> step ----
    host.mono = 1128.0;
    let ref_time = Timespec { sec: host.raw.sec - 1, nsec: 0 };
    r.set_reference(
        &mut host, 2, NtpLeap::Normal, 4, 0x0A00_0001, None, ref_time, 1.0, 0.01, 0.3e-6, 0.05e-6,
        0.6e-6, 0.01, 0.02,
    );
    check_set(&host, line("SET3"));

    // ---- ADJ ----
    host.mono = 1130.0;
    let adj = r.adjust_reference(&mut host, 0.001, 2.0e-6);
    let al = line("ADJ");
    assert_eq!(adj as i64, i(al, "ret"), "adjust ret");
    assert_eq!(host.accnh_n as i64, i(al, "accnh_n"), "accnh_n");
    close(host.accnh_freq, f(al, "freq"), "accnh freq");
    close(host.accnh_off, f(al, "off"), "accnh off");
    close(host.accnh_rate, f(al, "rate"), "accnh rate");

    // ---- REPORT (root dispersion depends on the fuzzed ref time) ----
    let rep = r.get_tracking_report(&mut host);
    let rl = line("REP");
    assert_eq!(rep.stratum as i64, i(rl, "stratum"), "stratum");
    assert_eq!(rep.ref_id as i64, i(rl, "refid"), "refid");
    assert_eq!(rep.leap_status as i64, i(rl, "leap"), "leap");
    close(rep.current_correction, f(rl, "corr"), "corr");
    close(rep.freq_ppm, f(rl, "freq"), "rep freq");
    close(rep.resid_freq_ppm, f(rl, "resid"), "resid");
    close(rep.skew_ppm, f(rl, "skew"), "skew");
    close(rep.last_offset, f(rl, "lastoff"), "lastoff");
    close(rep.rms_offset, f(rl, "rms"), "rms");
    close(rep.last_update_interval, f(rl, "interval"), "interval");
    close(rep.root_delay, f(rl, "rootdelay"), "rootdelay");
    close(rep.root_dispersion, f(rl, "rootdisp"), "rootdisp");
}

#[test]
fn civil_date_and_log_form() {
    // 2000-01-01 00:00:00 UTC = 946684800.
    assert_eq!(time_to_log_form(946684800), "2000-01-01 00:00:00");
    // A leap-second instant: 2016-12-31 23:59:59 UTC = 1483228799.
    assert_eq!(time_to_log_form(1483228799), "2016-12-31 23:59:59");
    // Leap-second days are the last day of June / December.
    assert!(Reference::is_leap_second_day(1483228799)); // Dec 31 2016
    assert!(Reference::is_leap_second_day(1341014400)); // Jun 30 2012 00:00
    assert!(!Reference::is_leap_second_day(946684800)); // Jan 1 2000
}

#[test]
fn unsynchronised_then_orphan_and_local_params() {
    let mut host = RecHost::new();
    let mut cfg = oracle_cfg();
    cfg.enable_local_stratum = true;
    cfg.local_stratum = 8;
    cfg.local_orphan = true;
    let mut r = Reference::initialise(&mut host, cfg);

    // No source yet: orphan stratum is the configured local stratum.
    assert_eq!(r.get_orphan_stratum(), 8);

    // Reference params with no sync fall to the local-reference branch.
    let now = Timespec { sec: host.raw.sec, nsec: 0 };
    let (synch, leap, stratum, ref_id, _t, rd, rdisp) = r.get_reference_params(&mut host, now);
    assert!(!synch, "not synchronised");
    assert_eq!(stratum, 8, "local stratum");
    assert_eq!(ref_id, 0x7F7F_0101, "NTP_REFID_LOCAL");
    assert_eq!(leap, NtpLeap::Normal);
    assert_eq!(rd, 0.0);
    assert_eq!(rdisp, 0.0);
}

#[test]
fn modify_makestep_changes_step_decision() {
    let mut host = RecHost::new();
    let mut r = Reference::initialise(&mut host, oracle_cfg());

    // Disable stepping, then a huge offset must NOT step.
    r.modify_makestep(&mut host, 0, 1.0);
    host.mono = 1000.0;
    let ref_time = Timespec { sec: host.raw.sec, nsec: 0 };
    r.set_reference(
        &mut host, 1, NtpLeap::Normal, 1, 0x01020304, None, ref_time, 10.0, 0.01, 0.0, 0.0, 0.0,
        0.0, 0.0,
    );
    assert_eq!(host.step_n, 0, "stepping disabled => no step even for a 10 s offset");
    assert_eq!(host.acc_n, 1, "the offset is accumulated instead");
}
