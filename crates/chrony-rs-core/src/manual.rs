//! Manual time input (`settime`) — a complete port of chrony 4.5 `manual.c`.
//!
//! When an operator enters the correct time with `chronyc settime`, chrony stores
//! a series of (time, offset) samples and runs a robust regression over them to
//! estimate both the slew to apply now and the clock's frequency error. `manual.c`
//! is that sample store + estimator. All 11 functions port here:
//!
//! | chrony `manual.c` | here |
//! |-------------------|------|
//! | `MNL_Initialise` | [`Manual::new`] |
//! | `MNL_Finalise` | `Drop` (no-op) |
//! | `MNL_Enable` / `MNL_Disable` | [`Manual::enable`] / [`Manual::disable`] |
//! | `MNL_IsEnabled` | [`Manual::is_enabled`] |
//! | `MNL_Reset` | [`Manual::reset`] |
//! | `MNL_AcceptTimestamp` | [`Manual::accept_timestamp`] |
//! | `MNL_DeleteSample` | [`Manual::delete_sample`] |
//! | `MNL_ReportSamples` | [`Manual::report_samples`] |
//! | `estimate_and_set_system` | [`Manual::estimate`] |
//! | `slew_samples` | [`Manual::slew_samples`] |
//!
//! The robust regression itself is [`crate::regress::find_best_robust_regression`]
//! (already reference-verified).
//!
//! # Adaptations (documented)
//!
//! Time is passed as Unix seconds (`f64`), so `LCL_ReadCookedTime` becomes the
//! `now` parameter and `UTI_AdjustTimespec` is the seconds form. Rather than apply
//! the result to the system clock (`REF_SetManualReference`), [`Manual::estimate`]
//! **returns** the correction ([`ManualEstimate`]) for the caller to apply; the
//! absolute frequency reported back (`LCL_ReadAbsoluteFrequency`) is passed in.
//! `CNF_GetManualEnabled` is the constructor's `enabled` argument, and the struct
//! is the local-clock handler (no global registration).

use crate::regress;
use crate::util::is_time_offset_sane;

/// chrony's `MAX_SAMPLES` and `MIN_SAMPLE_SEPARATION`.
const MAX_SAMPLES: usize = 16;
const MIN_SAMPLE_SEPARATION: f64 = 1.0;

/// The kind of local-clock change (chrony's `LCL_ChangeType`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum LclChangeType {
    Adjust,
    Step,
    UnknownStep,
}

/// One manual sample (chrony's `Sample`). Times are Unix seconds.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Sample {
    pub when: f64,
    pub offset: f64,
    pub orig_offset: f64,
    pub residual: f64,
}

/// The correction `estimate` produces (what chrony hands to `REF_SetManualReference`
/// plus the values it reports back to `chronyc`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ManualEstimate {
    /// The slew (offset) to apply now, seconds.
    pub slew_by: f64,
    /// The frequency change to apply, ppm.
    pub dfreq_ppm: f64,
    /// The regression's estimated intercept, seconds (chrony's `reg_offset`).
    pub reg_offset: f64,
    /// The skew chrony reports for a manual reference (its fixed `0.0999…`).
    pub skew: f64,
    /// The new absolute frequency reported back, ppm (passed in).
    pub new_afreq_ppm: f64,
}

/// The manual-input sample store and estimator.
pub struct Manual {
    enabled: bool,
    samples: Vec<Sample>,
}

impl Manual {
    /// `MNL_Initialise`: create the store; `enabled` is `CNF_GetManualEnabled`.
    pub fn new(enabled: bool) -> Self {
        Manual { enabled, samples: Vec::new() }
    }

    /// `MNL_IsEnabled`.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    /// `MNL_Enable`.
    pub fn enable(&mut self) {
        self.enabled = true;
    }
    /// `MNL_Disable`.
    pub fn disable(&mut self) {
        self.enabled = false;
    }
    /// `MNL_Reset`: drop all samples.
    pub fn reset(&mut self) {
        self.samples.clear();
    }

    /// `estimate_and_set_system`: regress over the samples to estimate the slew and
    /// frequency error, store residuals, and return the correction. `now` is the
    /// current time; `abs_freq_ppm` is the current absolute frequency to report.
    fn estimate(
        &mut self,
        _now: f64,
        offset_provided: bool,
        offset: f64,
        abs_freq_ppm: f64,
    ) -> ManualEstimate {
        let n = self.samples.len();
        let mut b0 = if offset_provided { offset } else { 0.0 };
        let mut b1 = 0.0;
        let mut freq = 0.0;
        let skew = 0.099_999_999; // chrony's fixed manual-reference skew

        let mut agos = vec![0.0f64; n.max(1)];
        let mut offsets = vec![0.0f64; n.max(1)];

        if n > 1 {
            for i in 0..n {
                agos[i] = self.samples[n - 1].when - self.samples[i].when;
                offsets[i] = self.samples[i].offset;
            }
            if let Some(r) = regress::find_best_robust_regression(&agos, &offsets, 1.0e-8) {
                // Ignore the regression intercept for the slew (use the entered
                // offset), but take the frequency estimate from the slope.
                b0 = r.intercept;
                b1 = r.slope;
                freq = -b1;
            }
        } else {
            agos[0] = 0.0;
            offsets[0] = b0;
        }

        let slew_by = if offset_provided { offset } else { b0 };

        // Residuals against the regression line.
        for i in 0..n {
            self.samples[i].residual = offsets[i] - (b0 + agos[i] * b1);
        }

        ManualEstimate {
            slew_by,
            dfreq_ppm: 1.0e6 * freq,
            reg_offset: b0,
            skew,
            new_afreq_ppm: abs_freq_ppm,
        }
    }

    /// `MNL_AcceptTimestamp`: record that the true time was `ts` (Unix seconds) at
    /// cooked time `now`, then re-estimate. Returns the correction, or `None` if
    /// disabled, the timestamp is insane, or it is too close to the previous sample.
    pub fn accept_timestamp(
        &mut self,
        now: f64,
        ts: f64,
        abs_freq_ppm: f64,
    ) -> Option<ManualEstimate> {
        if !self.enabled {
            return None;
        }
        if !is_time_offset_sane(ts, 0.0, crate::util::NTP_ERA_SPLIT) {
            return None;
        }
        if let Some(last) = self.samples.last() {
            if now - last.when < MIN_SAMPLE_SEPARATION {
                return None;
            }
        }
        let offset = now - ts;

        if self.samples.len() == MAX_SAMPLES {
            self.samples.remove(0); // shift the oldest out
        }
        self.samples.push(Sample { when: now, offset, orig_offset: offset, residual: 0.0 });

        Some(self.estimate(now, true, offset, abs_freq_ppm))
    }

    /// `MNL_DeleteSample`: drop sample `index` and re-estimate. Returns the new
    /// correction, or `None` if the index is out of range.
    pub fn delete_sample(
        &mut self,
        index: usize,
        now: f64,
        abs_freq_ppm: f64,
    ) -> Option<ManualEstimate> {
        if index >= self.samples.len() {
            return None;
        }
        self.samples.remove(index);
        Some(self.estimate(now, false, 0.0, abs_freq_ppm))
    }

    /// `MNL_ReportSamples`: the stored samples (up to `max`).
    pub fn report_samples(&self, max: usize) -> Vec<Sample> {
        self.samples.iter().take(max).copied().collect()
    }

    /// `slew_samples`: the local-clock parameter-change handler. An unknown step
    /// invalidates the samples; otherwise each stored sample is re-based for the
    /// slew (`UTI_AdjustTimespec` in seconds), carrying the adjustment into its
    /// offset.
    pub fn slew_samples(
        &mut self,
        cooked: f64,
        dfreq: f64,
        doffset: f64,
        change_type: LclChangeType,
    ) {
        if change_type == LclChangeType::UnknownStep {
            self.reset();
            return;
        }
        for s in &mut self.samples {
            let delta = (cooked - s.when) * dfreq - doffset;
            s.when += delta;
            s.offset += delta;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABS_FREQ: f64 = 12.0;
    // A sane base time (~2023) so is_time_offset_sane passes.
    const T0: f64 = 1.7e9;

    #[test]
    fn accept_timestamp_matches_real_c() {
        // Differential test of MNL_AcceptTimestamp's estimate (composing the verified robust
        // regression over the manual sample list) vs the REAL compiled manual.c + regress.c
        // (/tmp/nmnl/genmnl.c, -ffp-contract=off). Same now/ts sequence; abs_freq injected.
        let v = include_str!("../../../research/oracle/manual-c-vectors.txt");
        fn field<'a>(l: &'a str, k: &str) -> &'a str {
            l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap()
        }
        let mut m = Manual::new(true);
        for k in 0..6 {
            let now = 1000.0 + 2.0 * k as f64;
            let offset_k = 0.001 + 0.0002 * k as f64;
            let est = m.accept_timestamp(now, now - offset_k, 12.5).expect("accepted");
            let l = v.lines().find(|l| l.starts_with("MNL ") && field(l, "k") == k.to_string()).unwrap();
            // reg_offset/dfreq compose the robust regression over the manual sample OFFSETS.
            // chrony derives each offset from an ns-granular timespec (now - ts) while chrony-rs
            // uses f64 seconds -- the declared time-domain boundary. The sub-nanosecond input
            // difference is amplified by the fit, so compare within that quantization envelope
            // (offset ~1e-7 s; freq ~0.1 ppm). new_afreq is the injected abs-freq, exact.
            let close = |got: f64, exp: f64, tol: f64, what: &str| {
                assert!((got - exp).abs() <= tol, "k={k} {what}: {got} vs {exp}");
            };
            close(est.reg_offset, field(l, "reg_offset").parse().unwrap(), 1e-7, "reg_offset");
            close(est.dfreq_ppm, field(l, "dfreq_ppm").parse().unwrap(), 0.1, "dfreq_ppm");
            assert_eq!(est.new_afreq_ppm, field(l, "new_afreq").parse::<f64>().unwrap(), "new_afreq");
        }
    }

    #[test]
    fn single_sample_slews_by_entered_offset() {
        let mut m = Manual::new(true);
        // The system clock is 0.5 s ahead: now - ts = 0.5.
        let est = m.accept_timestamp(T0, T0 - 0.5, ABS_FREQ).unwrap();
        assert!((est.slew_by - 0.5).abs() < 1e-9);
        assert_eq!(est.dfreq_ppm, 0.0); // no frequency from one sample
        assert_eq!(est.new_afreq_ppm, ABS_FREQ);
        assert_eq!(m.report_samples(10).len(), 1);
    }

    #[test]
    fn multiple_samples_estimate_frequency_via_regression() {
        // Build samples whose offset grows linearly with time -> a clear frequency.
        // offset(t) = 0.5 + 1e-4 * (t - T0): a +100 ppm drift.
        let mut m = Manual::new(true);
        let mut now = T0;
        let mut last = None;
        for k in 0..6 {
            now = T0 + k as f64 * 10.0;
            let true_offset = 0.5 + 1e-4 * (now - T0);
            // ts is chosen so now - ts = true_offset.
            last = m.accept_timestamp(now, now - true_offset, ABS_FREQ);
        }
        let est = last.unwrap();
        // Cross-check the frequency against the regression directly.
        let n = m.report_samples(64).len();
        let s = m.report_samples(64);
        let agos: Vec<f64> = (0..n).map(|i| s[n - 1].when - s[i].when).collect();
        let offs: Vec<f64> = (0..n).map(|i| s[i].offset).collect();
        let r = regress::find_best_robust_regression(&agos, &offs, 1e-8).unwrap();
        assert!((est.dfreq_ppm - 1e6 * (-r.slope)).abs() < 1e-6);
        // The drift is ~100 ppm (offset grows 1e-4 per second as ago decreases).
        assert!((est.dfreq_ppm - 100.0).abs() < 1.0, "dfreq {}", est.dfreq_ppm);
        // Slew uses the most recently entered offset (the last sample's stored
        // offset), not the regression intercept.
        let _ = now;
        assert_eq!(est.slew_by, s[n - 1].offset);
        assert!((est.reg_offset - r.intercept).abs() < 1e-12);
    }

    #[test]
    fn rejects_insane_close_or_disabled() {
        let mut m = Manual::new(false);
        assert!(m.accept_timestamp(T0, T0, ABS_FREQ).is_none()); // disabled
        m.enable();
        assert!(m.accept_timestamp(T0, -1.0, ABS_FREQ).is_none()); // insane ts
        assert!(m.accept_timestamp(T0, T0, ABS_FREQ).is_some());
        // too close to the previous sample (< 1 s)
        assert!(m.accept_timestamp(T0 + 0.5, T0, ABS_FREQ).is_none());
    }

    #[test]
    fn buffer_caps_at_max_samples() {
        let mut m = Manual::new(true);
        for k in 0..(MAX_SAMPLES + 5) {
            m.accept_timestamp(T0 + k as f64 * 2.0, T0 + k as f64 * 2.0, ABS_FREQ);
        }
        assert_eq!(m.report_samples(100).len(), MAX_SAMPLES);
    }

    #[test]
    fn delete_sample_and_reset() {
        let mut m = Manual::new(true);
        for k in 0..4 {
            m.accept_timestamp(T0 + k as f64 * 2.0, T0 + k as f64 * 2.0, ABS_FREQ);
        }
        assert!(m.delete_sample(0, T0 + 10.0, ABS_FREQ).is_some());
        assert_eq!(m.report_samples(100).len(), 3);
        assert!(m.delete_sample(99, T0, ABS_FREQ).is_none()); // out of range
        m.reset();
        assert_eq!(m.report_samples(100).len(), 0);
    }

    #[test]
    fn slew_samples_rebases_and_unknown_step_resets() {
        let mut m = Manual::new(true);
        m.accept_timestamp(T0, T0 - 0.1, ABS_FREQ);
        let before = m.report_samples(1)[0];
        // A pure offset slew of +1 ms re-bases each sample's time and offset.
        m.slew_samples(T0, 0.0, 0.001, LclChangeType::Adjust);
        let after = m.report_samples(1)[0];
        assert!((after.when - (before.when - 0.001)).abs() < 1e-12);
        // An unknown step wipes the samples.
        m.slew_samples(T0, 0.0, 0.0, LclChangeType::UnknownStep);
        assert_eq!(m.report_samples(10).len(), 0);
    }
}
