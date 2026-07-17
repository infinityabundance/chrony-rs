//! The "null" system clock driver — a complete port of chrony 4.5 `sys_null.c`.
//!
//! This is the driver chrony installs under `-x` (and prints *"Disabled control of
//! system clock"* for): it never touches the hardware clock, but it still models
//! the clock's behavior, tracking an accumulating offset from an applied frequency
//! so the rest of the daemon sees a consistent (virtual) clock. It is the same
//! driver the lab `chronyd -x` oracle in this repo runs under.
//!
//! All 8 functions of `sys_null.c` have counterparts here:
//!
//! | chrony `sys_null.c` | here |
//! |---------------------|------|
//! | `SYS_Null_Initialise` | [`NullClock::new`] |
//! | `SYS_Null_Finalise` | `Drop` (no-op) |
//! | `update_offset` | [`NullClock::update_offset`] |
//! | `read_frequency` | [`NullClock::read_frequency`] |
//! | `set_frequency` | [`NullClock::set_frequency`] |
//! | `accrue_offset` | [`NullClock::accrue_offset`] |
//! | `apply_step_offset` | [`NullClock::apply_step_offset`] |
//! | `offset_convert` | [`NullClock::offset_convert`] |
//!
//! # Adaptations (documented, not hidden)
//!
//! chrony reads the raw time from the global `LCL_ReadRawTime` and diffs timespecs
//! with `UTI_DiffTimespecsToDouble`; here the raw time is passed in as seconds
//! (`f64`), which is exactly what that diff produces — so the arithmetic is
//! identical without depending on an unported global clock. chrony's
//! `lcl_RegisterSystemDrivers` call (registering the five callbacks with the local
//! clock) becomes "this struct *is* the driver"; there is no global LCL to register
//! with in `core`.

/// Minimum interval (seconds) between offset updates when frequency is constant
/// (chrony's `MIN_UPDATE_INTERVAL`).
const MIN_UPDATE_INTERVAL: f64 = 1000.0;

/// The null clock driver state (chrony's `freq` / `offset_register` / `last_update`
/// statics, made explicit).
pub struct NullClock {
    /// Current frequency offset of the (virtual) system clock, ppm.
    freq: f64,
    /// Accumulated offset of the clock at the last update, seconds.
    offset_register: f64,
    /// Raw time of the last update, seconds.
    last_update: f64,
}

impl NullClock {
    /// `SYS_Null_Initialise`: start the driver at raw time `now` (seconds), with a
    /// zero offset and frequency.
    pub fn new(now: f64) -> Self {
        NullClock { freq: 0.0, offset_register: 0.0, last_update: now }
    }

    /// `update_offset`: accrue the offset that the current frequency produced over
    /// the time since the last update, then move the update mark to `now`.
    fn update_offset(&mut self, now: f64) {
        let duration = now - self.last_update;
        self.offset_register += 1.0e-6 * self.freq * duration;
        self.last_update = now;
    }

    /// `read_frequency`: the current frequency offset (ppm).
    pub fn read_frequency(&self) -> f64 {
        self.freq
    }

    /// `set_frequency`: bank the offset accrued at the old frequency, then set the
    /// new one. Returns the frequency now in effect.
    pub fn set_frequency(&mut self, now: f64, freq_ppm: f64) -> f64 {
        self.update_offset(now);
        self.freq = freq_ppm;
        self.freq
    }

    /// `accrue_offset`: add `offset` (seconds) to the accumulated offset. The
    /// correction rate is ignored, exactly as chrony's null driver does.
    pub fn accrue_offset(&mut self, offset: f64, _corr_rate: f64) {
        self.offset_register += offset;
    }

    /// `apply_step_offset`: the null driver cannot step the clock, so this always
    /// fails (returns 0, chrony's failure code).
    pub fn apply_step_offset(&mut self, _offset: f64) -> i32 {
        0
    }

    /// `offset_convert`: the correction (and error estimate) to map a raw time to
    /// cooked time. Returns `(correction, error)`; the null driver's error is 0.
    pub fn offset_convert(&mut self, raw: f64) -> (f64, f64) {
        let mut duration = raw - self.last_update;
        if duration > MIN_UPDATE_INTERVAL {
            self.update_offset(raw);
            duration = 0.0;
        }
        let corr = -1.0e-6 * self.freq * duration - self.offset_register;
        (corr, 0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequency_round_trip_and_step_failure() {
        let mut c = NullClock::new(0.0);
        assert_eq!(c.read_frequency(), 0.0);
        assert_eq!(c.set_frequency(0.0, 20.0), 20.0);
        assert_eq!(c.read_frequency(), 20.0);
        // The null driver can never step.
        assert_eq!(c.apply_step_offset(1.0), 0);
    }

    #[test]
    fn offset_accrues_from_frequency_and_explicit_offset() {
        let mut c = NullClock::new(0.0);
        c.set_frequency(0.0, 20.0); // 20 ppm
        c.accrue_offset(0.001, 0.0); // +1 ms explicit

        // duration 50 s < MIN_UPDATE_INTERVAL: no offset bank, instantaneous corr.
        // corr = -1e-6*20*50 - 0.001 = -0.001 - 0.001 = -0.002
        let (corr, err) = c.offset_convert(50.0);
        assert!((corr - (-0.002)).abs() < 1e-12, "corr {corr}");
        assert_eq!(err, 0.0);

        // duration 2000 s > MIN_UPDATE_INTERVAL: banks 1e-6*20*2000 = 0.04 into the
        // register (now 0.041), then corr = -0.041 with duration reset to 0.
        let (corr, _) = c.offset_convert(2000.0);
        assert!((corr - (-0.041)).abs() < 1e-12, "corr {corr}");
    }

    #[test]
    fn set_frequency_banks_old_frequency_offset() {
        let mut c = NullClock::new(0.0);
        c.set_frequency(0.0, 10.0);
        // At t=100 change frequency: update_offset banks 1e-6*10*100 = 1e-3.
        c.set_frequency(100.0, -5.0);
        // Immediately convert at t=100: duration 0 -> corr = -offset_register.
        let (corr, _) = c.offset_convert(100.0);
        assert!((corr - (-1.0e-3)).abs() < 1e-12, "corr {corr}");
    }

    /// Differential oracle: the full driver op sequence (init, read/set frequency,
    /// accrue, step, and offset_convert across both the `<MIN_UPDATE_INTERVAL`
    /// instantaneous path and the `>MIN_UPDATE_INTERVAL` flush path) driven identically
    /// through the REAL compiled `sys_null.c` (`research/oracle/sys_null-c-vectors.txt`),
    /// matching the returned frequency/correction/error plus the internal
    /// `freq`/`offset_register`/`last_update` state after every op.
    ///
    /// The oracle drives raw times whose fractional part is exactly representable
    /// (0 or 0.5 s), so chrony's ns-granular `timespec` diff (`UTI_DiffTimespecsToDouble`)
    /// equals this port's `f64`-seconds subtraction to the bit — the modeling boundary
    /// documented in the module header collapses to exact parity for these inputs.
    #[test]
    fn matches_real_c_sys_null_vectors() {
        let vectors = include_str!("../../../research/oracle/sys_null-c-vectors.txt");
        fn f(line: &str, key: &str) -> f64 {
            line.split_whitespace()
                .find_map(|t| t.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("missing {key} in: {line}"))
                .parse()
                .unwrap()
        }
        // Identical IEEE-754 f64 op sequences on both sides -> match to the last ULP.
        let close = |a: f64, b: f64, what: &str| {
            let tol = 1e-15 * (1.0 + a.abs().max(b.abs()));
            assert!((a - b).abs() <= tol, "{what}: rust={a:.17e} c={b:.17e}");
        };

        // NullClock::new does not exist until the INIT line; seed a placeholder.
        let mut c = NullClock::new(0.0);
        let check_state = |c: &NullClock, line: &str| {
            close(c.freq, f(line, "freq"), "freq");
            close(c.offset_register, f(line, "reg"), "offset_register");
            close(c.last_update, f(line, "lu"), "last_update");
        };

        let mut n = 0;
        for line in vectors.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
            let tag = line.split_whitespace().next().unwrap();
            assert_eq!(f(line, "n") as i32, n, "op order");
            match tag {
                "OP" => {
                    // INIT or ACCRUE, distinguished by the op= field.
                    if line.contains("op=INIT") {
                        c = NullClock::new(f(line, "arg"));
                    } else {
                        c.accrue_offset(f(line, "arg"), 0.0);
                    }
                    check_state(&c, line);
                }
                "RF" => close(c.read_frequency(), f(line, "val"), "read_frequency"),
                "SF" => {
                    let ret = c.set_frequency(f(line, "now"), f(line, "in"));
                    close(ret, f(line, "ret"), "set_frequency ret");
                    check_state(&c, line);
                }
                "OC" => {
                    let (corr, err) = c.offset_convert(f(line, "raw"));
                    close(corr, f(line, "corr"), "offset_convert corr");
                    close(err, f(line, "err"), "offset_convert err");
                    check_state(&c, line);
                }
                "STEP" => {
                    assert_eq!(c.apply_step_offset(f(line, "in")), f(line, "ret") as i32, "step");
                }
                other => panic!("unknown tag {other}"),
            }
            n += 1;
        }
        assert_eq!(n, 12, "expected 12 recorded ops");
    }
}
