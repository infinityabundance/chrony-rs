//! NTP sample filter — a complete port of chrony 4.5 `samplefilt.c`.
//!
//! With the `filter` source option, chrony collects several raw NTP measurements
//! and combines them into one filtered sample before feeding `sourcestats`. It
//! keeps a circular buffer of [`NtpSample`]s; on demand it selects the
//! lowest-dispersion, middle-offset ones and combines them with a weighted
//! regression. This composes the already-ported, verified regression
//! ([`crate::regress`]). All 18 functions port here:
//!
//! | chrony `samplefilt.c` | here |
//! |-----------------------|------|
//! | `SPF_CreateInstance` | [`SampleFilter::new`] |
//! | `SPF_DestroyInstance` | `Drop` |
//! | `SPF_AccumulateSample` | [`SampleFilter::accumulate_sample`] |
//! | `SPF_GetFilteredSample` | [`SampleFilter::get_filtered_sample`] |
//! | `SPF_GetLastSample` | [`SampleFilter::last_sample`] |
//! | `SPF_GetNumberOfSamples` | [`SampleFilter::number_of_samples`] |
//! | `SPF_GetMaxSamples` | [`SampleFilter::max_samples`] |
//! | `SPF_GetAvgSampleDispersion` | [`SampleFilter::avg_sample_dispersion`] |
//! | `SPF_SlewSamples` | [`SampleFilter::slew_samples`] |
//! | `SPF_CorrectOffset` | [`SampleFilter::correct_offset`] |
//! | `SPF_AddDispersion` | [`SampleFilter::add_dispersion`] |
//! | `check_sample` / `compare_samples` / `select_samples` | private |
//! | `combine_selected_samples` / `get_first_last` / `drop_samples` | private |
//!
//! # Adaptations (documented)
//!
//! Time is seconds (`f64`); `LCL_GetSysPrecisionAsQuantum` (the initial variance)
//! is a constructor argument. `select_samples`' intricate in-place index-permutation
//! is computed directly: it yields the kept samples' buffer indices in chronological
//! order, which is exactly chrony's result.

use crate::regress;

const MIN_SAMPLES: usize = 1;
const MAX_SAMPLES: usize = 256;

/// A saved NTP measurement (chrony's `NTP_Sample`). `time` is seconds; a positive
/// `offset` means the local clock is slow relative to the source.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct NtpSample {
    pub time: f64,
    pub offset: f64,
    pub peer_delay: f64,
    pub peer_dispersion: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
}

/// The per-source sample filter (chrony's `SPF_Instance_Record`).
#[derive(Debug)]
pub struct SampleFilter {
    min_samples: usize,
    max_samples: usize,
    /// Circular-buffer index of the newest sample (-1 = empty).
    index: i32,
    used: usize,
    /// Index of the last accumulated sample (kept across a drop; -1 = none).
    last: i32,
    avg_var_n: i32,
    avg_var: f64,
    max_var: f64,
    combine_ratio: f64,
    samples: Vec<NtpSample>,
}

impl SampleFilter {
    /// `SPF_CreateInstance`. `sys_precision` seeds the average variance
    /// (`LCL_GetSysPrecisionAsQuantum`).
    pub fn new(
        min_samples: usize,
        max_samples: usize,
        max_dispersion: f64,
        combine_ratio: f64,
        sys_precision: f64,
    ) -> Self {
        let min_samples = min_samples.clamp(MIN_SAMPLES, MAX_SAMPLES);
        let max_samples = max_samples.clamp(MIN_SAMPLES, MAX_SAMPLES).max(min_samples);
        SampleFilter {
            min_samples,
            max_samples,
            index: -1,
            used: 0,
            last: -1,
            avg_var_n: 0,
            avg_var: sys_precision * sys_precision,
            max_var: max_dispersion * max_dispersion,
            combine_ratio: combine_ratio.clamp(0.0, 1.0),
            samples: vec![NtpSample::default(); max_samples],
        }
    }

    /// `check_sample`: sample times must be strictly increasing.
    fn check_sample(&self, sample: &NtpSample) -> bool {
        if self.used == 0 {
            return true;
        }
        self.samples[self.last as usize].time < sample.time
    }

    /// `SPF_AccumulateSample`: add a sample (rejecting non-increasing times).
    pub fn accumulate_sample(&mut self, sample: NtpSample) -> bool {
        if !self.check_sample(&sample) {
            return false;
        }
        self.index = (self.index + 1) % self.max_samples as i32;
        self.last = self.index;
        if self.used < self.max_samples {
            self.used += 1;
        }
        self.samples[self.index as usize] = sample;
        true
    }

    /// `SPF_GetLastSample`.
    pub fn last_sample(&self) -> Option<NtpSample> {
        if self.last < 0 {
            None
        } else {
            Some(self.samples[self.last as usize])
        }
    }

    /// `SPF_GetNumberOfSamples`.
    pub fn number_of_samples(&self) -> usize {
        self.used
    }
    /// `SPF_GetMaxSamples`.
    pub fn max_samples(&self) -> usize {
        self.max_samples
    }
    /// `SPF_GetAvgSampleDispersion`.
    pub fn avg_sample_dispersion(&self) -> f64 {
        self.avg_var.sqrt()
    }

    /// Chronological position (0 = oldest) of a circular-buffer index.
    fn chrono(&self, c: usize) -> usize {
        let o = self.used - self.index as usize - 1;
        (c + o) % self.used
    }

    /// `select_samples`: choose the samples to combine. Filters by peer dispersion
    /// (with >4 samples), drops extreme offsets per `combine_ratio`, and returns the
    /// kept buffer indices in chronological order (chrony's net result).
    fn select_samples(&self) -> Vec<usize> {
        if self.used < self.min_samples {
            return Vec::new();
        }

        // With >4 samples keep those within 1.5x the minimum peer dispersion.
        let mut selected: Vec<usize> = if self.used > 4 {
            let min_disp = (0..self.used)
                .map(|i| self.samples[i].peer_dispersion)
                .fold(f64::INFINITY, f64::min);
            (0..self.used)
                .filter(|&i| self.samples[i].peer_dispersion <= 1.5 * min_disp)
                .collect()
        } else {
            Vec::new()
        };
        if selected.len() < 4 {
            selected = (0..self.used).collect();
        }

        // Sort by offset, then drop `from` extremes on each side.
        let j = selected.len();
        selected.sort_by(|&a, &b| {
            self.samples[a]
                .offset
                .partial_cmp(&self.samples[b].offset)
                .unwrap()
        });
        let from = if j > 2 {
            ((j as f64 * (1.0 - self.combine_ratio) / 2.0) as usize).clamp(1, (j - 1) / 2)
        } else {
            0
        };
        let to = j - from;

        // Re-order the kept samples chronologically.
        let mut kept: Vec<usize> = selected[from..to].to_vec();
        kept.sort_by_key(|&c| self.chrono(c));
        kept
    }

    /// `combine_selected_samples`: weighted-regression combine of `selected` (buffer
    /// indices in time order) into one sample, updating the average-variance EMA.
    /// Returns `None` if the dispersion exceeds the configured maximum.
    fn combine_selected_samples(&mut self, selected: &[usize]) -> Option<NtpSample> {
        let n = selected.len();
        let last_time = self.samples[selected[n - 1]].time;

        let mut x: Vec<f64> = Vec::with_capacity(n);
        let mut y: Vec<f64> = Vec::with_capacity(n);
        let mut w: Vec<f64> = Vec::with_capacity(n);
        for &s in selected {
            let sm = &self.samples[s];
            x.push(sm.time - last_time);
            y.push(sm.offset);
            w.push(sm.peer_dispersion);
        }

        let mean_x = x.iter().sum::<f64>() / n as f64;
        let mean_y = y.iter().sum::<f64>() / n as f64;

        let (mut var, mut disp);
        let dof;
        if n >= 4 {
            // Shift x to the mean time, then fit; the intercept SD is the dispersion.
            for xi in x.iter_mut() {
                *xi -= mean_x;
            }
            let r = regress::weighted_regression(&x, &y, &w);
            var = r.variance;
            disp = r.sd_intercept;
            dof = (n - 2) as i32;
        } else if n >= 2 {
            var = y
                .iter()
                .map(|&yi| (yi - mean_y) * (yi - mean_y))
                .sum::<f64>()
                / (n - 1) as f64;
            disp = var.sqrt();
            dof = (n - 1) as i32;
        } else {
            var = self.avg_var;
            disp = var.sqrt();
            dof = 1;
        }

        if var < 1e-20 {
            var = 1e-20;
            disp = var.sqrt();
        }

        if self.max_var > 0.0 && var > self.max_var {
            return None; // dispersion too large
        }

        let mut prev_avg_var = self.avg_var;
        if self.avg_var_n > 50 {
            self.avg_var += dof as f64 / (dof as f64 + 50.0) * (var - self.avg_var);
        } else {
            self.avg_var = (self.avg_var * self.avg_var_n as f64 + var * dof as f64)
                / (dof as f64 + self.avg_var_n as f64);
            if self.avg_var_n == 0 {
                prev_avg_var = self.avg_var;
            }
            self.avg_var_n += dof;
        }

        // Prefer the long-term average variance unless this estimate is much smaller.
        if var * dof as f64 / regress::chi2_coef(dof) < prev_avg_var {
            disp = self.avg_var.sqrt() * disp / var.sqrt();
        }

        let mut mean_peer_dispersion = 0.0;
        let mut mean_root_dispersion = 0.0;
        let mut mean_peer_delay = 0.0;
        let mut mean_root_delay = 0.0;
        for &s in selected {
            let sm = &self.samples[s];
            mean_peer_dispersion += sm.peer_dispersion;
            mean_root_dispersion += sm.root_dispersion;
            mean_peer_delay += sm.peer_delay;
            mean_root_delay += sm.root_delay;
        }
        let nf = n as f64;
        mean_peer_dispersion /= nf;
        mean_root_dispersion /= nf;
        mean_peer_delay /= nf;
        mean_root_delay /= nf;

        Some(NtpSample {
            time: last_time + mean_x,
            offset: mean_y,
            peer_delay: mean_peer_delay,
            peer_dispersion: disp.max(mean_peer_dispersion),
            root_delay: mean_root_delay,
            root_dispersion: disp.max(mean_root_dispersion),
        })
    }

    /// `SPF_GetFilteredSample`: select, combine, and clear the window (keeping the
    /// last sample). Returns the combined sample, or `None` if there are too few
    /// samples or the dispersion is too large.
    pub fn get_filtered_sample(&mut self) -> Option<NtpSample> {
        let selected = self.select_samples();
        if selected.is_empty() {
            return None;
        }
        let result = self.combine_selected_samples(&selected)?;
        self.drop_samples(true);
        Some(result)
    }

    /// `SPF_DropSamples`: discard all samples, including the last.
    pub fn drop_all_samples(&mut self) {
        self.drop_samples(false);
    }

    /// `drop_samples`: reset the window, optionally keeping `last` accessible.
    fn drop_samples(&mut self, keep_last: bool) {
        self.index = -1;
        self.used = 0;
        if !keep_last {
            self.last = -1;
        }
    }

    /// `get_first_last`: the index range to adjust (the last sample is always
    /// included as it may be returned even with no new samples).
    fn get_first_last(&self) -> Option<(usize, usize)> {
        if self.last < 0 {
            return None;
        }
        if self.used > 0 {
            Some((0, self.used - 1))
        } else {
            Some((self.last as usize, self.last as usize))
        }
    }

    /// `SPF_SlewSamples`: re-base stored sample times/offsets for a clock slew.
    pub fn slew_samples(&mut self, when: f64, dfreq: f64, doffset: f64) {
        let Some((first, last)) = self.get_first_last() else {
            return;
        };
        for i in first..=last {
            let delta = (when - self.samples[i].time) * dfreq - doffset;
            self.samples[i].time += delta;
            self.samples[i].offset -= delta;
        }
    }

    /// `SPF_CorrectOffset`: subtract `doffset` from stored offsets.
    pub fn correct_offset(&mut self, doffset: f64) {
        let Some((first, last)) = self.get_first_last() else {
            return;
        };
        for i in first..=last {
            self.samples[i].offset -= doffset;
        }
    }

    /// `SPF_AddDispersion`: add `dispersion` to every stored sample's dispersions.
    pub fn add_dispersion(&mut self, dispersion: f64) {
        for s in self.samples.iter_mut().take(self.used) {
            s.peer_dispersion += dispersion;
            s.root_dispersion += dispersion;
        }
    }
}

#[cfg(test)]
impl SampleFilter {
    /// Test hook exposing the private `select_samples` (the buffer-index selection) so it can be
    /// differential-tested against the verbatim C `select_samples`.
    fn test_select_samples(&self) -> Vec<usize> {
        self.select_samples()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_filtered_sample_matches_real_c() {
        // End-to-end differential test of SPF_GetFilteredSample (select_samples +
        // combine_selected_samples, composing the verified regress) vs the REAL compiled
        // samplefilt.c + regress.c (/tmp/nspf/genspf2.c, -ffp-contract=off). Sample times are
        // exact integer seconds so the timespec<->f64 domains agree; sys_precision=1e-6 matches
        // the oracle's LCL_GetSysPrecisionAsQuantum stub.
        let v = include_str!("../../../research/oracle/samplefilt-filtered-c-vectors.txt");
        let off8 = [0.005, -0.002, 0.001, 0.003, -0.001, 0.0, 0.004, -0.003];
        let pd8 = [1e-4, 2e-4, 1.1e-4, 5e-4, 1.2e-4, 1.05e-4, 3e-4, 1.3e-4];
        let dl8 = [0.01, 0.011, 0.012, 0.013, 0.014, 0.015, 0.016, 0.017];
        let rd8 = [2e-4, 2.1e-4, 2.2e-4, 2.3e-4, 2.4e-4, 2.5e-4, 2.6e-4, 2.7e-4];
        let rdl8 = [0.02, 0.021, 0.022, 0.023, 0.024, 0.025, 0.026, 0.027];
        let off5 = &off8[..5];
        let pd5 = &pd8[..5];
        let dl5 = &dl8[..5];
        let rd5 = &rd8[..5];
        let rdl5 = &rdl8[..5];
        // (id, min, max, max_disp, cr, n, offs, pdisp, pdelay, rdisp, rdelay)
        #[allow(clippy::type_complexity)]
        let cases: &[(
            &str,
            usize,
            usize,
            f64,
            f64,
            usize,
            &[f64],
            &[f64],
            &[f64],
            &[f64],
            &[f64],
        )] = &[
            ("five", 3, 8, 1.0, 0.5, 5, off5, pd5, dl5, rd5, rdl5),
            ("eight", 4, 8, 1.0, 0.5, 8, &off8, &pd8, &dl8, &rd8, &rdl8),
            (
                "eight_cr0",
                4,
                8,
                1.0,
                0.0,
                8,
                &off8,
                &pd8,
                &dl8,
                &rd8,
                &rdl8,
            ),
            ("two", 2, 8, 1.0, 0.5, 2, off5, pd5, dl5, rd5, rdl5),
            ("three", 3, 8, 1.0, 0.5, 3, off5, pd5, dl5, rd5, rdl5),
            (
                "too_disp", 4, 8, 1e-5, 0.5, 8, &off8, &pd8, &dl8, &rd8, &rdl8,
            ),
        ];
        let f = |l: &str, k: &str| {
            l.split_whitespace()
                .find_map(|t| t.strip_prefix(&format!("{k}=")))
                .unwrap()
                .parse::<f64>()
                .unwrap()
        };
        for (id, min_s, max_s, max_disp, cr, n, offs, pdisp, pdelay, rdisp, rdelay) in cases {
            let mut filt = SampleFilter::new(*min_s, *max_s, *max_disp, *cr, 1e-6);
            for i in 0..*n {
                filt.accumulate_sample(NtpSample {
                    time: (i * 10) as f64,
                    offset: offs[i],
                    peer_delay: pdelay[i],
                    peer_dispersion: pdisp[i],
                    root_delay: rdelay[i],
                    root_dispersion: rdisp[i],
                });
            }
            let got = filt.get_filtered_sample();
            let l = v
                .lines()
                .find(|l| l.split_whitespace().nth(1) == Some(&format!("id={id}")))
                .unwrap();
            if l.contains("ok=0") {
                assert!(got.is_none(), "{id} expected filtered-out");
                continue;
            }
            let s = got.unwrap_or_else(|| panic!("{id} expected a sample"));
            // The combined time is the only field that passes through chrony's ns-granular
            // timespec (UTI_AddDoubleToTimespec) while chrony-rs keeps f64 seconds; compare within
            // a nanosecond (the declared "time as f64 seconds" modeling boundary). Every other
            // field is pure f64 and matches exactly.
            assert!(
                (s.time - f(l, "time")).abs() < 1e-9,
                "{id} time {} vs {}",
                s.time,
                f(l, "time")
            );
            assert_eq!(s.offset, f(l, "offset"), "{id} offset");
            assert_eq!(s.peer_dispersion, f(l, "peer_disp"), "{id} peer_disp");
            assert_eq!(s.root_dispersion, f(l, "root_disp"), "{id} root_disp");
            assert_eq!(s.peer_delay, f(l, "peer_delay"), "{id} peer_delay");
            assert_eq!(s.root_delay, f(l, "root_delay"), "{id} root_delay");
        }
    }

    #[test]
    fn select_samples_matches_real_c() {
        // Differential test of the intricate index-permutation vs the VERBATIM samplefilt.c
        // select_samples (/tmp/nspf). Each case accumulates the same samples (offset +
        // peer_dispersion; time/delay irrelevant to the selection) and compares the buffer
        // indices, in order.
        let v = include_str!("../../../research/oracle/samplefilt-select-c-vectors.txt");
        // (id, min_samples, max_samples, combine_ratio, offsets, dispersions)
        let d5 = [1e-4, 2e-4, 1.1e-4, 5e-4, 1.2e-4];
        let o5 = [0.005, -0.002, 0.001, 0.003, -0.001];
        let o8 = [0.005, -0.002, 0.001, 0.003, -0.001, 0.0, 0.004, -0.003];
        let d8 = [1e-4, 2e-4, 1.1e-4, 5e-4, 1.2e-4, 1.05e-4, 3e-4, 1.3e-4];
        let o6 = [0.001, 0.002, 0.003, 0.004, 0.005, 0.006];
        let d6 = [1e-4; 6];
        let cases: &[(&str, usize, usize, f64, &[f64], &[f64])] = &[
            ("five_a", 3, 8, 0.5, &o5, &d5),
            ("five_tight", 3, 8, 0.5, &o5, &[1e-4; 5]),
            ("eight_a", 4, 8, 0.5, &o8, &d8),
            ("eight_cr0", 4, 8, 0.0, &o8, &d8),
            ("eight_cr1", 4, 8, 1.0, &o8, &d8),
            ("three", 3, 8, 0.5, &o5[..3], &d5[..3]),
            ("four", 4, 8, 0.5, &o5[..4], &d5[..4]),
            ("six_sorted", 4, 8, 0.6, &o6, &d6),
            ("six_cr03", 4, 8, 0.3, &o6, &d6),
        ];
        for (id, min_s, max_s, cr, off, disp) in cases {
            let mut f = SampleFilter::new(*min_s, *max_s, 1.0, *cr, 1e-9);
            for i in 0..off.len() {
                f.accumulate_sample(sample(i as f64, off[i], disp[i]));
            }
            let got = f.test_select_samples();
            let l = v
                .lines()
                .find(|l| l.split_whitespace().nth(1) == Some(&format!("id={id}")))
                .unwrap();
            let count: usize = l
                .split_whitespace()
                .find_map(|t| t.strip_prefix("count="))
                .unwrap()
                .parse()
                .unwrap();
            let idx = l
                .split_whitespace()
                .find_map(|t| t.strip_prefix("indices="))
                .unwrap();
            let expected: Vec<usize> = if idx.is_empty() {
                vec![]
            } else {
                idx.split(',').map(|s| s.parse().unwrap()).collect()
            };
            assert_eq!(got.len(), count, "{id} count");
            assert_eq!(got, expected, "{id} indices");
        }
    }

    fn sample(time: f64, offset: f64, disp: f64) -> NtpSample {
        NtpSample {
            time,
            offset,
            peer_delay: 0.001,
            peer_dispersion: disp,
            root_delay: 0.002,
            root_dispersion: disp + 0.0001,
        }
    }

    #[test]
    fn accumulate_rejects_non_increasing_time() {
        let mut f = SampleFilter::new(1, 8, 0.0, 1.0, 1e-6);
        assert!(f.accumulate_sample(sample(1.0, 0.0, 1e-6)));
        assert!(!f.accumulate_sample(sample(1.0, 0.0, 1e-6))); // equal time
        assert!(!f.accumulate_sample(sample(0.5, 0.0, 1e-6))); // earlier time
        assert!(f.accumulate_sample(sample(2.0, 0.0, 1e-6)));
        assert_eq!(f.number_of_samples(), 2);
        assert_eq!(f.max_samples(), 8);
    }

    #[test]
    fn combines_a_clean_line_via_weighted_regression() {
        // 4 samples on a line offset = 0.01 + 0.0 (constant), equal dispersion;
        // combine_ratio 1.0 keeps all. Result offset = mean, time = last sample.
        let mut f = SampleFilter::new(1, 8, 0.0, 1.0, 1e-6);
        for k in 0..4 {
            f.accumulate_sample(sample(k as f64, 0.01, 1e-5));
        }
        let r = f.get_filtered_sample().unwrap();
        assert!((r.offset - 0.01).abs() < 1e-12);
        // Combined time is the mean of {0,1,2,3} = 1.5 (last_time + mean_x).
        assert!((r.time - 1.5).abs() < 1e-9);
        // peer_dispersion is at least the mean of inputs.
        assert!(r.peer_dispersion >= 1e-5 - 1e-9);
        // window cleared but last sample retained.
        assert_eq!(f.number_of_samples(), 0);
        assert_eq!(f.last_sample().unwrap().time, 3.0);
    }

    #[test]
    fn rejects_when_dispersion_exceeds_max() {
        // max_dispersion small; samples with large offset scatter -> var > max_var.
        let mut f = SampleFilter::new(1, 8, 1e-4, 1.0, 1e-6);
        for (k, off) in [0.0, 0.1, -0.1, 0.05].into_iter().enumerate() {
            f.accumulate_sample(sample(k as f64, off, 1e-5));
        }
        assert!(f.get_filtered_sample().is_none());
    }

    #[test]
    fn slew_and_correct_adjust_samples() {
        let mut f = SampleFilter::new(1, 8, 0.0, 1.0, 1e-6);
        f.accumulate_sample(sample(0.0, 0.01, 1e-5));
        f.accumulate_sample(sample(1.0, 0.01, 1e-5));
        f.correct_offset(0.005);
        assert!((f.last_sample().unwrap().offset - 0.005).abs() < 1e-12);
        // A pure +1 ms offset slew re-bases time by -1 ms and offset by +1 ms.
        f.slew_samples(1.0, 0.0, 0.001);
        assert!((f.last_sample().unwrap().time - 0.999).abs() < 1e-12);
        // SPF_DropSamples discards everything, including the last sample.
        f.drop_all_samples();
        assert_eq!(f.number_of_samples(), 0);
        assert!(f.last_sample().is_none());
    }

    #[test]
    fn select_returns_too_few_below_min() {
        let mut f = SampleFilter::new(3, 8, 0.0, 1.0, 1e-6);
        f.accumulate_sample(sample(0.0, 0.0, 1e-5));
        f.accumulate_sample(sample(1.0, 0.0, 1e-5));
        assert!(f.get_filtered_sample().is_none()); // 2 < min 3
    }
}
