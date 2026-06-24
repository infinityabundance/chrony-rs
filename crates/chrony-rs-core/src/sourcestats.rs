//! Per-source statistics — a complete port of chrony 4.5 `sourcestats.c`.
//!
//! This is the daemon-side statistics engine behind `chronyc sourcestats`: it
//! keeps a history of NTP samples per source and, on demand, runs a weighted
//! robust regression to estimate the clock offset, frequency, skew, and standard
//! deviation, optionally correcting for asymmetric network jitter. It is the
//! keystone that ties together every piece of the ported [`crate::regress`]
//! engine: [`find_best_regression`](crate::regress::find_best_regression),
//! [`find_median`](crate::regress::find_median),
//! [`multiple_regress`](crate::regress::multiple_regress), and
//! [`get_t_coef`](crate::regress::t_coef), plus
//! [`crate::util::is_time_offset_sane`].
//!
//! All 32 functions of `sourcestats.c` are ported (the publics below, plus the
//! private buffer/index/asymmetry helpers).
//!
//! # Dual circular buffers
//!
//! Samples live in two interleaved index spaces, exactly as in chrony: a
//! "runs buffer" of `MAX_SAMPLES * REGRESS_RUNS_RATIO` entries (sample times,
//! offsets, peer delays — holding `n_samples` current plus `runs_samples` older
//! samples used only to extend the runs test) and a plain buffer of `MAX_SAMPLES`
//! entries (the other per-sample arrays). [`get_runsbuf_index`](SourceStats::get_runsbuf_index)
//! and [`get_buf_index`](SourceStats::get_buf_index) map a logical sample index
//! `i ∈ [-runs_samples, n_samples)` into each.
//!
//! # Adaptations (documented)
//!
//! Times are seconds (`f64`); `LCL_GetSysPrecisionAsQuantum` / `CNF_GetMaxJitter` /
//! `LCL_ReadCookedTime` are passed in where used. The dump/reload (`SST_SaveToFile`/
//! `SST_LoadFromFile`) operate on a string instead of a `FILE*`. Report-filling
//! functions return structs. Statistics-log writing is dropped.

use crate::samplefilt::NtpSample;
use crate::util::is_time_offset_sane;
use crate::{regress, regress::REGRESS_RUNS_RATIO};

const MAX_SAMPLES: usize = 64;
const MIN_SAMPLES_FOR_REGRESS: i32 = 3;
const RUNSBUF: usize = MAX_SAMPLES * REGRESS_RUNS_RATIO;

const WORST_CASE_FREQ_BOUND: f64 = 2000.0 / 1.0e6;
const WORST_CASE_STDDEV_BOUND: f64 = 4.0;
const MIN_SKEW: f64 = 1.0e-12;
const MAX_SKEW: f64 = 1.0e2;
const MIN_STDDEV: f64 = 1.0e-9;

const MAX_ASYMMETRY: f64 = 0.5;
const MIN_ASYMMETRY: f64 = 0.45;
const MIN_ASYMMETRY_RUN: i32 = 10;
const MAX_ASYMMETRY_RUN: i32 = 1000;
const SD_TO_DIST_RATIO: f64 = 0.7;

/// `SST_GetSelectionData` outputs (returned only when selection is OK).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SelectionData {
    pub offset_lo_limit: f64,
    pub offset_hi_limit: f64,
    pub root_distance: f64,
    pub std_dev: f64,
    pub first_sample_ago: f64,
    pub last_sample_ago: f64,
}

/// `SST_GetTrackingData` outputs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TrackingData {
    pub ref_time: f64,
    pub average_offset: f64,
    pub offset_sd: f64,
    pub frequency: f64,
    pub frequency_sd: f64,
    pub skew: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
}

/// `SST_GetDelayTestData` outputs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DelayTestData {
    pub last_sample_ago: f64,
    pub predicted_offset: f64,
    pub min_delay: f64,
    pub skew: f64,
    pub std_dev: f64,
}

/// `SST_DoSourceReport` outputs (`RPT_SourceReport` subset).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SourceReport {
    pub orig_latest_meas: f64,
    pub latest_meas: f64,
    pub latest_meas_err: f64,
    /// Seconds since the latest measurement; `f64` of `u32::MAX` when no samples.
    pub latest_meas_ago: f64,
}

/// `SST_DoSourcestatsReport` outputs (`RPT_SourcestatsReport` subset).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SourcestatsReport {
    pub n_samples: i32,
    pub n_runs: i32,
    pub span_seconds: f64,
    pub est_offset: f64,
    pub est_offset_err: f64,
    pub resid_freq_ppm: f64,
    pub skew_ppm: f64,
    pub sd: f64,
}

/// Per-source statistics history (chrony's `SST_Stats_Record`).
pub struct SourceStats {
    refid: u32,
    has_ip: bool,
    min_samples: i32,
    max_samples: i32,
    fixed_min_delay: f64,
    fixed_asymmetry: f64,
    n_samples: i32,
    runs_samples: i32,
    last_sample: i32,
    regression_ok: bool,
    best_single_sample: i32,
    min_delay_sample: i32,
    estimated_offset: f64,
    estimated_offset_sd: f64,
    offset_time: f64,
    nruns: i32,
    asymmetry_run: i32,
    asymmetry: f64,
    estimated_frequency: f64,
    estimated_frequency_sd: f64,
    skew: f64,
    std_dev: f64,
    // runs-buffer arrays (size RUNSBUF)
    sample_times: Vec<f64>,
    offsets: Vec<f64>,
    peer_delays: Vec<f64>,
    // plain-buffer arrays (size MAX_SAMPLES)
    orig_offsets: Vec<f64>,
    peer_dispersions: Vec<f64>,
    root_delays: Vec<f64>,
    root_dispersions: Vec<f64>,
}

/// `SST_Initialise` — no-op (the statistics log is not emitted here).
pub fn initialise() {}
/// `SST_Finalise` — no-op.
pub fn finalise() {}

impl SourceStats {
    /// `SST_CreateInstance`.
    pub fn new(
        refid: u32,
        has_ip: bool,
        min_samples: i32,
        max_samples: i32,
        min_delay: f64,
        asymmetry: f64,
    ) -> Self {
        let max_samples = if max_samples > 0 {
            max_samples.clamp(1, MAX_SAMPLES as i32)
        } else {
            MAX_SAMPLES as i32
        };
        let min_samples = min_samples.clamp(1, max_samples);
        let mut inst = SourceStats {
            refid,
            has_ip,
            min_samples,
            max_samples,
            fixed_min_delay: min_delay,
            fixed_asymmetry: asymmetry,
            n_samples: 0,
            runs_samples: 0,
            last_sample: 0,
            regression_ok: false,
            best_single_sample: 0,
            min_delay_sample: 0,
            estimated_offset: 0.0,
            estimated_offset_sd: 0.0,
            offset_time: 0.0,
            nruns: 0,
            asymmetry_run: 0,
            asymmetry: 0.0,
            estimated_frequency: 0.0,
            estimated_frequency_sd: 0.0,
            skew: 0.0,
            std_dev: 0.0,
            sample_times: vec![0.0; RUNSBUF],
            offsets: vec![0.0; RUNSBUF],
            peer_delays: vec![0.0; RUNSBUF],
            orig_offsets: vec![0.0; MAX_SAMPLES],
            peer_dispersions: vec![0.0; MAX_SAMPLES],
            root_delays: vec![0.0; MAX_SAMPLES],
            root_dispersions: vec![0.0; MAX_SAMPLES],
        };
        inst.reset();
        inst
    }

    /// `SST_ResetInstance`.
    pub fn reset(&mut self) {
        self.n_samples = 0;
        self.runs_samples = 0;
        self.last_sample = 0;
        self.regression_ok = false;
        self.best_single_sample = 0;
        self.min_delay_sample = 0;
        self.estimated_frequency = 0.0;
        self.estimated_frequency_sd = WORST_CASE_FREQ_BOUND;
        self.skew = WORST_CASE_FREQ_BOUND;
        self.estimated_offset = 0.0;
        self.estimated_offset_sd = WORST_CASE_STDDEV_BOUND;
        self.offset_time = 0.0;
        self.std_dev = WORST_CASE_STDDEV_BOUND;
        self.nruns = 0;
        self.asymmetry_run = 0;
        self.asymmetry = 0.0;
    }

    /// `SST_SetRefid`.
    pub fn set_refid(&mut self, refid: u32, has_ip: bool) {
        self.refid = refid;
        self.has_ip = has_ip;
    }

    /// `get_runsbuf_index`: runs-buffer index of logical sample `i`.
    fn get_runsbuf_index(&self, i: i32) -> usize {
        let rb = RUNSBUF as i32;
        ((self.last_sample + 2 * rb - self.n_samples + i + 1).rem_euclid(rb)) as usize
    }

    /// `get_buf_index`: plain-buffer index of logical sample `i`.
    fn get_buf_index(&self, i: i32) -> usize {
        let rb = RUNSBUF as i32;
        ((self.last_sample + rb - self.n_samples + i + 1).rem_euclid(MAX_SAMPLES as i32)) as usize
    }

    /// `prune_register`: discard the `new_oldest` oldest samples, moving them into
    /// the runs-test reserve.
    fn prune_register(&mut self, new_oldest: i32) {
        if new_oldest == 0 {
            return;
        }
        self.n_samples -= new_oldest;
        self.runs_samples += new_oldest;
        if self.runs_samples > self.n_samples * (REGRESS_RUNS_RATIO as i32 - 1) {
            self.runs_samples = self.n_samples * (REGRESS_RUNS_RATIO as i32 - 1);
        }
        self.find_min_delay_sample();
    }

    /// `SST_AccumulateSample`.
    pub fn accumulate_sample(&mut self, sample: &NtpSample) {
        if self.n_samples > 0
            && (self.n_samples == MAX_SAMPLES as i32 || self.n_samples == self.max_samples)
        {
            self.prune_register(1);
        }

        if self.n_samples > 0 && self.sample_times[self.last_sample as usize] >= sample.time {
            // Out-of-order sample: discard history.
            self.reset();
        }

        let n = (self.last_sample + 1).rem_euclid(RUNSBUF as i32);
        self.last_sample = n;
        let n = n as usize;
        let m = n % MAX_SAMPLES;

        // The sense of offset is flipped here (local fast => positive).
        self.sample_times[n] = sample.time;
        self.offsets[n] = -sample.offset;
        self.orig_offsets[m] = -sample.offset;
        self.peer_delays[n] = sample.peer_delay;
        self.peer_dispersions[m] = sample.peer_dispersion;
        self.root_delays[m] = sample.root_delay;
        self.root_dispersions[m] = sample.root_dispersion;

        if self.peer_delays[n] < self.fixed_min_delay {
            self.peer_delays[n] = 2.0 * self.fixed_min_delay - self.peer_delays[n];
        }

        if self.n_samples == 0
            || self.peer_delays[n] < self.peer_delays[self.min_delay_sample as usize]
        {
            self.min_delay_sample = n as i32;
        }

        self.n_samples += 1;
    }

    /// `find_min_delay_sample`.
    fn find_min_delay_sample(&mut self) {
        self.min_delay_sample = self.get_runsbuf_index(-self.runs_samples) as i32;
        for i in (-self.runs_samples + 1)..self.n_samples {
            let index = self.get_runsbuf_index(i);
            if self.peer_delays[index] < self.peer_delays[self.min_delay_sample as usize] {
                self.min_delay_sample = index as i32;
            }
        }
    }

    /// `convert_to_intervals`: fill `times_back[i + runs_samples]` (negative values)
    /// with each sample's time relative to the newest.
    fn convert_to_intervals(&self, times_back: &mut [f64]) {
        let ts = self.sample_times[self.last_sample as usize];
        for i in (-self.runs_samples)..self.n_samples {
            times_back[(i + self.runs_samples) as usize] =
                self.sample_times[self.get_runsbuf_index(i)] - ts;
        }
    }

    /// `find_best_sample_index`: the sample with the tightest root-distance bound.
    fn find_best_sample_index(&mut self, times_back: &[f64]) {
        if self.n_samples == 0 {
            return;
        }
        let mut best_index = -1;
        let mut best_root_distance = f64::MAX;
        for i in 0..self.n_samples {
            let j = self.get_buf_index(i);
            let elapsed = -times_back[i as usize];
            let root_distance =
                self.root_dispersions[j] + elapsed * self.skew + 0.5 * self.root_delays[j];
            if root_distance < best_root_distance {
                best_root_distance = root_distance;
                best_index = i;
            }
        }
        self.best_single_sample = best_index;
    }

    /// `estimate_asymmetry`: slope of offset against delay via multiple regression,
    /// with sign-run hysteresis. Updates `asymmetry`/`asymmetry_run`; returns
    /// whether the correction is active.
    fn estimate_asymmetry(
        times_back: &[f64],
        offsets: &[f64],
        delays: &[f64],
        asymmetry: &mut f64,
        asymmetry_run: &mut i32,
    ) -> bool {
        // Reset when the regression fails or the asymmetry sign changes.
        let a = match regress::multiple_regress(times_back, delays, offsets) {
            Some(a) if a * (*asymmetry_run as f64) >= 0.0 => a,
            _ => {
                *asymmetry = 0.0;
                *asymmetry_run = 0;
                return false;
            }
        };
        if a <= -MIN_ASYMMETRY && *asymmetry_run > -MAX_ASYMMETRY_RUN {
            *asymmetry_run -= 1;
        } else if a >= MIN_ASYMMETRY && *asymmetry_run < MAX_ASYMMETRY_RUN {
            *asymmetry_run += 1;
        }
        if asymmetry_run.abs() < MIN_ASYMMETRY_RUN {
            return false;
        }
        *asymmetry = a.clamp(-MAX_ASYMMETRY, MAX_ASYMMETRY);
        true
    }

    /// `correct_asymmetry`: correct `offsets` for estimated network-jitter asymmetry.
    fn correct_asymmetry(&mut self, times_back: &[f64], offsets: &mut [f64]) {
        if self.fixed_asymmetry == 0.0 {
            return;
        }
        let min_delay = self.min_round_trip_delay();
        let n = (self.runs_samples + self.n_samples) as usize;
        let mut delays = vec![0.0f64; n];
        for (i, d) in delays.iter_mut().enumerate() {
            *d = self.peer_delays[self.get_runsbuf_index(i as i32 - self.runs_samples)] - min_delay;
        }
        if self.fixed_asymmetry.abs() <= MAX_ASYMMETRY {
            self.asymmetry = self.fixed_asymmetry;
        } else if !Self::estimate_asymmetry(
            &times_back[..n],
            &offsets[..n],
            &delays,
            &mut self.asymmetry,
            &mut self.asymmetry_run,
        ) {
            return;
        }
        for i in 0..n {
            offsets[i] -= self.asymmetry * delays[i];
        }
    }

    /// `SST_DoNewRegression`: re-fit and truncate the register to the best window.
    /// `precision` is `LCL_GetSysPrecisionAsQuantum`.
    pub fn do_new_regression(&mut self, precision: f64) {
        let m = self.runs_samples as usize;
        let nn = self.n_samples as usize;
        let total = m + nn;

        let mut times_back = vec![0.0f64; RUNSBUF];
        let mut offsets = vec![0.0f64; RUNSBUF];
        let mut peer_distances = vec![0.0f64; MAX_SAMPLES];
        let mut weights = vec![0.0f64; RUNSBUF];

        // convert_to_intervals already applies the runs_samples offset internally,
        // so it is given the whole array (extras land at [0, runs_samples)).
        self.convert_to_intervals(&mut times_back);

        if self.n_samples > 0 {
            for i in (-self.runs_samples)..self.n_samples {
                offsets[(i + self.runs_samples) as usize] = self.offsets[self.get_runsbuf_index(i)];
            }
            let mut min_distance = f64::MAX;
            for i in 0..self.n_samples {
                let j = self.get_buf_index(i);
                let pd = 0.5 * self.peer_delays[self.get_runsbuf_index(i)] + self.peer_dispersions[j];
                peer_distances[i as usize] = pd;
                if pd < min_distance {
                    min_distance = pd;
                }
            }
            let median_distance = regress::find_median(&peer_distances[..nn]);
            let mut sd = (median_distance - min_distance) / SD_TO_DIST_RATIO;
            sd = sd.clamp(precision, min_distance);
            min_distance += precision;
            for i in 0..nn {
                let mut sd_weight = 1.0;
                if peer_distances[i] > min_distance {
                    sd_weight += (peer_distances[i] - min_distance) / sd;
                }
                // weights are indexed at the main offset (after the m extras)
                weights[m + i] = sd_weight * sd_weight;
            }
        }

        self.correct_asymmetry(&times_back, &mut offsets);

        let reg = if self.n_samples > 0 {
            regress::find_best_regression(
                &times_back[..total],
                &offsets[..total],
                &weights[..total],
                nn,
                m,
                self.min_samples as usize,
            )
        } else {
            None
        };
        self.regression_ok = reg.is_some();

        let times_back_start;
        if let Some(r) = reg {
            self.estimated_frequency = r.slope;
            self.estimated_frequency_sd = r.sd_slope.clamp(MIN_SKEW, MAX_SKEW);
            self.skew = r.sd_slope * regress::t_coef(r.dof as i32);
            self.estimated_offset = r.intercept;
            self.offset_time = self.sample_times[self.last_sample as usize];
            self.estimated_offset_sd = r.sd_intercept;
            self.std_dev = r.variance.sqrt().max(MIN_STDDEV);
            self.nruns = r.n_runs;
            self.skew = self.skew.clamp(MIN_SKEW, MAX_SKEW);
            times_back_start = self.runs_samples as usize + r.new_start;
            self.prune_register(r.new_start as i32);
        } else {
            self.estimated_frequency_sd = WORST_CASE_FREQ_BOUND;
            self.skew = WORST_CASE_FREQ_BOUND;
            self.estimated_offset_sd = WORST_CASE_STDDEV_BOUND;
            self.std_dev = WORST_CASE_STDDEV_BOUND;
            self.nruns = 0;
            if self.n_samples > 0 {
                self.estimated_offset = self.offsets[self.last_sample as usize];
                self.offset_time = self.sample_times[self.last_sample as usize];
            } else {
                self.estimated_offset = 0.0;
                self.offset_time = 0.0;
            }
            times_back_start = 0;
        }
        // Re-borrow times_back for the best-sample search.
        let tb = times_back[times_back_start..].to_vec();
        self.find_best_sample_index(&tb);
    }

    /// `SST_GetFrequencyRange`.
    pub fn frequency_range(&self) -> (f64, f64) {
        let (mut lo, mut hi) = (
            self.estimated_frequency - self.skew,
            self.estimated_frequency + self.skew,
        );
        if self.skew > WORST_CASE_FREQ_BOUND {
            lo = -WORST_CASE_FREQ_BOUND;
            hi = WORST_CASE_FREQ_BOUND;
        }
        (lo, hi)
    }

    /// `SST_GetSelectionData`. `max_jitter` is `CNF_GetMaxJitter`.
    pub fn selection_data(&self, now: f64, max_jitter: f64) -> Option<SelectionData> {
        if self.n_samples == 0 {
            return None;
        }
        let i = self.get_runsbuf_index(self.best_single_sample);
        let j = self.get_buf_index(self.best_single_sample);
        let mut std_dev = self.std_dev;

        let sample_elapsed = (now - self.sample_times[i]).abs();
        let offset = self.offsets[i] + sample_elapsed * self.estimated_frequency;
        let root_distance =
            0.5 * self.root_delays[j] + self.root_dispersions[j] + sample_elapsed * self.skew;

        let first = self.get_runsbuf_index(0);
        let last = self.get_runsbuf_index(self.n_samples - 1);
        let first_sample_ago = now - self.sample_times[first];
        let last_sample_ago = now - self.sample_times[last];

        let mut select_ok = self.regression_ok;
        if !select_ok
            && self.n_samples < MIN_SAMPLES_FOR_REGRESS
            && self.n_samples == self.max_samples
        {
            std_dev = max_jitter;
            select_ok = true;
        }
        if !select_ok {
            return None;
        }
        Some(SelectionData {
            offset_lo_limit: offset - root_distance,
            offset_hi_limit: offset + root_distance,
            root_distance,
            std_dev,
            first_sample_ago,
            last_sample_ago,
        })
    }

    /// `SST_GetTrackingData`.
    pub fn tracking_data(&self) -> TrackingData {
        assert!(self.n_samples > 0);
        let i = self.get_runsbuf_index(self.best_single_sample);
        let j = self.get_buf_index(self.best_single_sample);
        let elapsed_sample = self.offset_time - self.sample_times[i];
        TrackingData {
            ref_time: self.offset_time,
            average_offset: self.estimated_offset,
            offset_sd: self.estimated_offset_sd,
            frequency: self.estimated_frequency,
            frequency_sd: self.estimated_frequency_sd,
            skew: self.skew,
            root_delay: self.root_delays[j],
            root_dispersion: self.root_dispersions[j]
                + self.skew * elapsed_sample
                + self.estimated_offset_sd,
        }
    }

    /// `SST_SlewSamples`: adjust stored samples and the estimate for a clock slew.
    pub fn slew_samples(&mut self, when: f64, dfreq: f64, doffset: f64) {
        if self.n_samples == 0 {
            return;
        }
        for mi in (-self.runs_samples)..self.n_samples {
            let i = self.get_runsbuf_index(mi);
            let delta = (when - self.sample_times[i]) * dfreq - doffset;
            self.sample_times[i] += delta;
            self.offsets[i] += delta;
        }
        let delta = (when - self.offset_time) * dfreq - doffset;
        self.offset_time += delta;
        self.estimated_offset += delta;
        self.estimated_frequency = (self.estimated_frequency - dfreq) / (1.0 - dfreq);
    }

    /// `SST_CorrectOffset`.
    pub fn correct_offset(&mut self, doffset: f64) {
        if self.n_samples == 0 {
            return;
        }
        for i in (-self.runs_samples)..self.n_samples {
            let idx = self.get_runsbuf_index(i);
            self.offsets[idx] += doffset;
        }
        self.estimated_offset += doffset;
    }

    /// `SST_AddDispersion`.
    pub fn add_dispersion(&mut self, dispersion: f64) {
        for m in 0..self.n_samples {
            let i = self.get_buf_index(m);
            self.root_dispersions[i] += dispersion;
            self.peer_dispersions[i] += dispersion;
        }
    }

    /// `SST_PredictOffset`.
    pub fn predict_offset(&self, when: f64) -> f64 {
        if self.n_samples < MIN_SAMPLES_FOR_REGRESS {
            if self.n_samples > 0 {
                self.offsets[self.last_sample as usize]
            } else {
                0.0
            }
        } else {
            (when - self.offset_time) * self.estimated_frequency + self.estimated_offset
        }
    }

    /// `SST_MinRoundTripDelay`.
    pub fn min_round_trip_delay(&self) -> f64 {
        if self.fixed_min_delay > 0.0 {
            return self.fixed_min_delay;
        }
        if self.n_samples == 0 {
            return f64::MAX;
        }
        self.peer_delays[self.min_delay_sample as usize]
    }

    /// `SST_GetDelayTestData`.
    pub fn delay_test_data(&self, sample_time: f64) -> Option<DelayTestData> {
        if self.n_samples < 6 {
            return None;
        }
        let last_sample_ago = sample_time - self.offset_time;
        Some(DelayTestData {
            last_sample_ago,
            predicted_offset: self.estimated_offset + last_sample_ago * self.estimated_frequency,
            min_delay: self.min_round_trip_delay(),
            skew: self.skew,
            std_dev: self.std_dev,
        })
    }

    /// `SST_Samples`.
    pub fn samples(&self) -> i32 {
        self.n_samples
    }
    /// `SST_GetMinSamples`.
    pub fn min_samples(&self) -> i32 {
        self.min_samples
    }
    /// `SST_GetJitterAsymmetry`.
    pub fn jitter_asymmetry(&self) -> f64 {
        self.asymmetry
    }

    /// `SST_SaveToFile`: serialise the register to a string (one header line plus
    /// one line per sample). Returns `None` if there are no samples.
    pub fn save_to_string(&self) -> Option<String> {
        if self.n_samples < 1 {
            return None;
        }
        let mut s = format!("{} {}\n", self.n_samples, self.asymmetry_run);
        for m in 0..self.n_samples {
            let i = self.get_runsbuf_index(m);
            let j = self.get_buf_index(m);
            s.push_str(&format!(
                "{:.9} {:.6e} {:.6e} {:.6e} {:.6e} {:.6e} {:.6e}\n",
                self.sample_times[i],
                self.offsets[i],
                self.orig_offsets[j],
                self.peer_delays[i],
                self.peer_dispersions[j],
                self.root_delays[j],
                self.root_dispersions[j],
            ));
        }
        Some(s)
    }

    /// `SST_LoadFromFile`: reload a register from a [`save_to_string`](Self::save_to_string)
    /// dump. `now` is the current cooked time (for sanity checks). Returns whether
    /// the load succeeded.
    pub fn load_from_string(&mut self, content: &str, now: f64) -> bool {
        let mut lines = content.lines();
        let header = match lines.next() {
            Some(h) => h,
            None => return false,
        };
        let mut hi = header.split_whitespace();
        let n_samples = match hi.next().and_then(|s| s.parse::<i32>().ok()) {
            Some(n) if (1..=MAX_SAMPLES as i32).contains(&n) => n,
            _ => return false,
        };
        let arun = match hi.next().and_then(|s| s.parse::<i32>().ok()) {
            Some(a) => a,
            None => return false,
        };

        self.reset();

        for i in 0..n_samples as usize {
            let line = match lines.next() {
                Some(l) => l,
                None => return false,
            };
            let v: Vec<f64> = line.split_whitespace().filter_map(|s| s.parse::<f64>().ok()).collect();
            if v.len() != 7 {
                return false;
            }
            let sample_time = v[0];
            self.offsets[i] = v[1];
            self.orig_offsets[i] = v[2];
            self.peer_delays[i] = v[3];
            self.peer_dispersions[i] = v[4];
            self.root_delays[i] = v[5];
            self.root_dispersions[i] = v[6];
            self.sample_times[i] = sample_time;

            if !is_time_offset_sane(self.sample_times[i], -self.offsets[i], crate::util::NTP_ERA_SPLIT)
                || now < self.sample_times[i]
                || !(self.peer_delays[i].abs() < 1.0e6
                    && self.peer_dispersions[i].abs() < 1.0e6
                    && self.root_delays[i].abs() < 1.0e6
                    && self.root_dispersions[i].abs() < 1.0e6)
                || (i > 0 && self.sample_times[i] <= self.sample_times[i - 1])
            {
                return false;
            }
        }

        self.n_samples = n_samples;
        self.last_sample = self.n_samples - 1;
        self.asymmetry_run = arun.clamp(-MAX_ASYMMETRY_RUN, MAX_ASYMMETRY_RUN);
        self.find_min_delay_sample();
        // do_new_regression needs a precision; load passes the system precision.
        self.do_new_regression(1e-9);
        true
    }

    /// `SST_DoSourceReport`.
    pub fn source_report(&self, now: f64) -> SourceReport {
        if self.n_samples > 0 {
            let i = self.get_runsbuf_index(self.n_samples - 1);
            let j = self.get_buf_index(self.n_samples - 1);
            SourceReport {
                orig_latest_meas: self.orig_offsets[j],
                latest_meas: self.offsets[i],
                latest_meas_err: 0.5 * self.root_delays[j] + self.root_dispersions[j],
                latest_meas_ago: now - self.sample_times[i],
            }
        } else {
            SourceReport {
                orig_latest_meas: 0.0,
                latest_meas: 0.0,
                latest_meas_err: 0.0,
                latest_meas_ago: u32::MAX as f64,
            }
        }
    }

    /// `SST_DoSourcestatsReport`.
    pub fn sourcestats_report(&self, now: f64) -> SourcestatsReport {
        let (span_seconds, est_offset, est_offset_err) = if self.n_samples > 0 {
            let bi = self.get_runsbuf_index(self.best_single_sample);
            let bj = self.get_buf_index(self.best_single_sample);
            let dspan =
                self.sample_times[self.last_sample as usize] - self.sample_times[self.get_runsbuf_index(0)];
            let elapsed = now - self.offset_time;
            let sample_elapsed = now - self.sample_times[bi];
            (
                dspan.round(),
                self.estimated_offset + elapsed * self.estimated_frequency,
                self.estimated_offset_sd
                    + sample_elapsed * self.skew
                    + (0.5 * self.root_delays[bj] + self.root_dispersions[bj]),
            )
        } else {
            (0.0, 0.0, 0.0)
        };
        SourcestatsReport {
            n_samples: self.n_samples,
            n_runs: self.nruns,
            span_seconds,
            est_offset,
            est_offset_err,
            resid_freq_ppm: 1.0e6 * self.estimated_frequency,
            skew_ppm: 1.0e6 * self.skew,
            sd: self.std_dev,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(time: f64, offset: f64) -> NtpSample {
        NtpSample {
            time,
            offset,
            peer_delay: 0.001,
            peer_dispersion: 1e-6,
            root_delay: 0.002,
            root_dispersion: 1e-5,
        }
    }

    #[test]
    fn index_helpers_round_trip_logical_samples() {
        let mut s = SourceStats::new(0, false, 1, 8, 0.0, 0.0);
        for k in 0..5 {
            s.accumulate_sample(&sample(k as f64, 0.0));
        }
        // Logical sample n-1 is the newest (== last_sample); 0 is the oldest.
        assert_eq!(s.get_runsbuf_index(s.n_samples - 1), s.last_sample as usize);
        // Newest sample time is the most recent we fed.
        assert_eq!(s.sample_times[s.get_runsbuf_index(s.n_samples - 1)], 4.0);
        assert_eq!(s.sample_times[s.get_runsbuf_index(0)], 0.0);
    }

    #[test]
    fn regression_recovers_offset_and_frequency() {
        // Source whose offset drifts linearly: the local clock is fast by
        // 1e-4 s per second relative to it (a +100 ppm frequency). Sampled every
        // 10 s. Note accumulate flips the offset sign internally.
        let mut s = SourceStats::new(0, false, 4, 16, 0.0, 0.0);
        for k in 0..8 {
            let t = k as f64 * 10.0;
            // measured offset = local - source = +1e-4 * t (local fast)
            s.accumulate_sample(&sample(t, 1e-4 * t));
        }
        s.do_new_regression(1e-6);
        assert!(s.regression_ok);
        // accumulate flips the offset sign (stored = "local fast of source"); a
        // measured offset that GROWS +1e-4/s means the stored value SHRINKS, i.e.
        // the local clock is slow of the source -> estimated_frequency ~ -1e-4.
        assert!((s.estimated_frequency + 1e-4).abs() < 1e-7, "freq {}", s.estimated_frequency);
        let report = s.sourcestats_report(70.0);
        assert_eq!(report.n_samples, s.n_samples);
        assert!((report.resid_freq_ppm + 100.0).abs() < 0.1, "ppm {}", report.resid_freq_ppm);
    }

    #[test]
    fn out_of_order_sample_resets_history() {
        let mut s = SourceStats::new(0, false, 1, 8, 0.0, 0.0);
        s.accumulate_sample(&sample(10.0, 0.0));
        s.accumulate_sample(&sample(20.0, 0.0));
        assert_eq!(s.samples(), 2);
        s.accumulate_sample(&sample(15.0, 0.0)); // earlier than 20 -> reset, then add
        assert_eq!(s.samples(), 1);
    }

    #[test]
    fn predict_and_min_delay() {
        let mut s = SourceStats::new(0, false, 1, 8, 0.0, 0.0);
        assert_eq!(s.predict_offset(100.0), 0.0); // no samples
        s.accumulate_sample(&sample(0.0, 0.05));
        // Below MIN_SAMPLES_FOR_REGRESS -> returns last (negated) offset.
        assert_eq!(s.predict_offset(100.0), -0.05);
        assert!((s.min_round_trip_delay() - 0.001).abs() < 1e-12);
    }

    #[test]
    fn pruning_keeps_runs_samples_and_regresses() {
        // max_samples=4 forces pruning; do_new_regression after each sample moves
        // pruned samples into the runs reserve (exercises the runs-buffer offset).
        let mut s = SourceStats::new(0, false, 3, 4, 0.0, 0.0);
        for k in 0..12 {
            let t = k as f64 * 10.0;
            s.accumulate_sample(&sample(t, 1e-4 * t));
            s.do_new_regression(1e-6);
        }
        assert!(s.runs_samples >= 0 && s.n_samples <= 4);
        assert!(s.regression_ok);
        assert!((s.estimated_frequency + 1e-4).abs() < 1e-6, "freq {}", s.estimated_frequency);
        // Index helpers must still map the newest/oldest correctly post-prune.
        assert_eq!(s.get_runsbuf_index(s.n_samples - 1), s.last_sample as usize);
    }

    #[test]
    fn fixed_asymmetry_corrects_offsets() {
        // A fixed asymmetry within the cap is applied directly; with a non-flat
        // delay, the offset correction changes the regression. This exercises
        // correct_asymmetry (and, with a > cap, estimate_asymmetry's regression).
        let mut s = SourceStats::new(0, false, 4, 16, 0.0, 0.3);
        for k in 0..8 {
            let t = k as f64 * 10.0;
            let mut sm = sample(t, 1e-4 * t);
            sm.peer_delay = 0.001 + 1e-4 * (k % 3) as f64; // varying delay
            s.accumulate_sample(&sm);
        }
        s.do_new_regression(1e-6);
        assert!(s.regression_ok);
        assert!((s.jitter_asymmetry() - 0.3).abs() < 1e-12);

        // A fixed asymmetry above the cap triggers the multiple-regression estimate
        // (which must receive equal-length slices — the bug this guards).
        let mut s2 = SourceStats::new(0, false, 4, 16, 0.0, 1.0);
        for k in 0..8 {
            let t = k as f64 * 10.0;
            let mut sm = sample(t, 1e-4 * t);
            sm.peer_delay = 0.001 + 1e-4 * (k % 3) as f64;
            s2.accumulate_sample(&sm);
        }
        s2.do_new_regression(1e-6); // must not panic
        assert!(s2.regression_ok);
    }

    #[test]
    fn save_load_round_trips() {
        let mut s = SourceStats::new(0x0a000001, true, 4, 16, 0.0, 0.0);
        for k in 0..6 {
            s.accumulate_sample(&sample(1.7e9 + k as f64 * 10.0, 1e-4 * k as f64 * 10.0));
        }
        s.do_new_regression(1e-6);
        let dump = s.save_to_string().unwrap();
        let mut t = SourceStats::new(0x0a000001, true, 4, 16, 0.0, 0.0);
        let now = 1.7e9 + 100.0;
        assert!(t.load_from_string(&dump, now));
        assert_eq!(t.samples(), 6);
        // The reloaded register produces the same number of samples and a sane regression.
        assert!(t.regression_ok || t.samples() < MIN_SAMPLES_FOR_REGRESS);
    }
}
