//! Hardware-clock tracking — a complete port of chrony 4.5 `hwclock.c`.
//!
//! chrony models a hardware clock (e.g. a NIC's PHC) relative to the system clock
//! so it can convert raw HW timestamps to system time. It keeps a short history of
//! `(local interval, hw interval)` samples and fits a robust line through them; new
//! readings are first filtered by their measured delay using a streaming quantile
//! estimator. This file therefore composes three already-ported, verified pieces:
//! the sample buffers (chrony's `ARR_*`, here `Vec<f64>`), the delay quantiles
//! ([`crate::quantiles`]), and the robust regression ([`crate::regress`]). All 7
//! functions port here:
//!
//! | chrony `hwclock.c` | here |
//! |--------------------|------|
//! | `HCL_CreateInstance` | [`HwClock::new`] |
//! | `HCL_DestroyInstance` | `Drop` |
//! | `HCL_NeedsNewSample` | [`HwClock::needs_new_sample`] |
//! | `HCL_ProcessReadings` | [`HwClock::process_readings`] |
//! | `HCL_AccumulateSample` | [`HwClock::accumulate_sample`] |
//! | `HCL_CookTime` | [`HwClock::cook_time`] |
//! | `handle_slew` | [`HwClock::handle_slew`] |
//!
//! # Adaptations (documented)
//!
//! Time is seconds (`f64`). `LCL_ReadAbsoluteFrequency` is passed in to
//! [`accumulate_sample`](HwClock::accumulate_sample); `LCL_CookTime` and
//! `LCL_GetSysPrecisionAsQuantum` are passed to
//! [`process_readings`](HwClock::process_readings) (a cook closure and a precision).
//! The struct is the local-clock handler (no global registration).

use crate::quantiles::QuantileEstimator;
use crate::regress;

const MIN_SAMPLES: usize = 2;
const MAX_SAMPLES: usize = 64;
/// Maximum acceptable fractional frequency offset of the HW clock.
const MAX_FREQ_OFFSET: f64 = 2.0 / 3.0;

// Quantiles for filtering readings by delay (chrony's DELAY_QUANT_*).
const DELAY_QUANT_MIN_K: i32 = 1;
const DELAY_QUANT_MAX_K: i32 = 2;
const DELAY_QUANT_Q: i32 = 10;
const DELAY_QUANT_REPEAT: i32 = 7;
const DELAY_QUANT_MIN_STEP: f64 = 1.0e-9;

/// A tracked hardware clock (chrony's `HCL_Instance_Record`).
pub struct HwClock {
    /// HW and local reference timestamps (seconds).
    hw_ref: f64,
    local_ref: f64,
    /// Samples stored as intervals relative to the refs; the newest is at the end
    /// (index `max_samples - 1`, always `(0, 0)`), older ones below it.
    x_data: Vec<f64>,
    y_data: Vec<f64>,
    min_samples: usize,
    max_samples: usize,
    n_samples: usize,
    last_err: f64,
    min_separation: f64,
    precision: f64,
    valid_coefs: bool,
    offset: f64,
    frequency: f64,
    delay_quants: QuantileEstimator,
}

impl HwClock {
    /// `HCL_CreateInstance`.
    pub fn new(min_samples: usize, max_samples: usize, min_separation: f64, precision: f64) -> Self {
        let min_samples = min_samples.clamp(MIN_SAMPLES, MAX_SAMPLES);
        let max_samples = max_samples.clamp(MIN_SAMPLES, MAX_SAMPLES).max(min_samples);
        HwClock {
            hw_ref: 0.0,
            local_ref: 0.0,
            x_data: vec![0.0; max_samples],
            y_data: vec![0.0; max_samples],
            min_samples,
            max_samples,
            n_samples: 0,
            last_err: 0.0,
            min_separation,
            precision,
            valid_coefs: false,
            offset: 0.0,
            frequency: 0.0,
            delay_quants: QuantileEstimator::new(
                DELAY_QUANT_MIN_K,
                DELAY_QUANT_MAX_K,
                DELAY_QUANT_Q,
                DELAY_QUANT_REPEAT,
                DELAY_QUANT_MIN_STEP,
            ),
        }
    }

    /// `HCL_NeedsNewSample`: whether enough time has elapsed for a fresh sample.
    pub fn needs_new_sample(&self, now: f64) -> bool {
        self.n_samples == 0 || (now - self.local_ref).abs() >= self.min_separation
    }

    /// `HCL_ProcessReadings`: combine `readings` — each `[local_before, hw, local_after]`
    /// (seconds) — into one `(hw_ts, local_ts, err)` sample, filtering by delay.
    /// `cook` is the local-clock raw→cooked map (`LCL_CookTime`); `sys_precision` is
    /// `LCL_GetSysPrecisionAsQuantum`. Returns `None` if a reading is malformed or
    /// the single accepted reading adds nothing over the current model.
    pub fn process_readings(
        &mut self,
        readings: &[[f64; 3]],
        cook: impl Fn(f64) -> f64,
        sys_precision: f64,
    ) -> Option<(f64, f64, f64)> {
        let n = readings.len();
        if n < 1 {
            return None;
        }

        // Current local-clock rate over the reading window.
        let (first, last) = (readings[0][0], readings[n - 1][2]);
        let freq = if first < last {
            (cook(first) - cook(last)) / (first - last)
        } else {
            1.0
        };

        let mut min_delay = 0.0;
        let mut min_reading = 0;
        for (i, r) in readings.iter().enumerate() {
            let delay = freq * (r[2] - r[0]);
            if delay < 0.0 {
                return None; // step in the middle of a reading
            }
            if i == 0 || delay < min_delay {
                min_delay = delay;
                min_reading = i;
            }
            self.delay_quants.accumulate(delay);
        }

        let local_prec = sys_precision;
        let mut low_delay = self.delay_quants.get_quantile(DELAY_QUANT_MIN_K);
        let mut high_delay = self.delay_quants.get_quantile(DELAY_QUANT_MAX_K);
        low_delay = low_delay.min(high_delay);
        high_delay = high_delay.max(low_delay + local_prec);

        // Combine readings whose delay is in the expected interval.
        let (mut combined, mut delay_sum, mut hw_sum, mut local_sum) = (0usize, 0.0, 0.0, 0.0);
        for r in readings {
            let raw_delay = r[2] - r[0];
            let delay = freq * raw_delay;
            if delay < low_delay || delay > high_delay {
                continue;
            }
            delay_sum += delay;
            hw_sum += r[1] - readings[0][1];
            local_sum += (r[0] - readings[0][0]) + raw_delay / 2.0;
            combined += 1;
        }

        if combined > 0 {
            let c = combined as f64;
            let hw_ts = readings[0][1] + hw_sum / c;
            let local_ts = readings[0][0] + local_sum / c;
            let err = (delay_sum / c / 2.0).max(self.precision);
            return Some((hw_ts, local_ts, err));
        }

        // Otherwise accept the minimum-delay reading, but only if it is not already
        // predicted by the current model.
        let hw_ts = readings[min_reading][1];
        let local_ts = readings[min_reading][0] + min_delay / freq / 2.0;
        let err = (min_delay / 2.0).max(self.precision);
        let ts1 = cook(local_ts);
        match self.cook_time(hw_ts) {
            None => Some((hw_ts, local_ts, err)),
            Some((ts2, _)) => {
                let pred_err = ts1 - ts2;
                if pred_err > err {
                    Some((hw_ts, local_ts, err))
                } else {
                    None
                }
            }
        }
    }

    /// `HCL_AccumulateSample`: add a `(hw_ts, local_ts)` sample with error `err` and
    /// re-fit the model; `abs_freq_ppm` is `LCL_ReadAbsoluteFrequency`.
    pub fn accumulate_sample(&mut self, hw_ts: f64, local_ts: f64, err: f64, abs_freq_ppm: f64) {
        let local_freq = 1.0 - abs_freq_ppm / 1.0e6;

        if self.n_samples > 0 {
            if self.n_samples >= self.max_samples {
                self.n_samples -= 1;
            }
            let hw_delta = hw_ts - self.hw_ref;
            let local_delta = (local_ts - self.local_ref) / local_freq;
            if hw_delta <= 0.0 || local_delta < self.min_separation / 2.0 {
                self.n_samples = 0;
            }
            let ms = self.max_samples;
            for i in (ms - self.n_samples)..ms {
                self.y_data[i - 1] = self.y_data[i] - hw_delta;
                self.x_data[i - 1] = self.x_data[i] - local_delta;
            }
        }

        self.n_samples += 1;
        self.hw_ref = hw_ts;
        self.local_ref = local_ts;
        self.last_err = err;

        let ms = self.max_samples;
        let start = ms - self.n_samples;
        let reg = regress::find_best_robust_regression(
            &self.x_data[start..ms],
            &self.y_data[start..ms],
            1.0e-10,
        );
        self.valid_coefs = reg.is_some();
        let Some(reg) = reg else { return };

        self.offset = reg.intercept;
        self.frequency = reg.slope / local_freq;
        if self.n_samples > self.min_samples {
            self.n_samples -= reg.best_start.min(self.n_samples - self.min_samples);
        }
        // Drop everything if the fit misses the last sample's error interval or the
        // frequency is insane.
        if self.offset.abs() > err || (self.frequency - 1.0).abs() > MAX_FREQ_OFFSET {
            self.n_samples = 0;
            self.valid_coefs = false;
        }
    }

    /// `HCL_CookTime`: convert a raw HW time to local (cooked) time using the model,
    /// returning `(cooked, err)`, or `None` if the model is not yet valid.
    pub fn cook_time(&self, raw: f64) -> Option<(f64, f64)> {
        if !self.valid_coefs {
            return None;
        }
        let elapsed = raw - self.hw_ref;
        let cooked = self.local_ref + (elapsed / self.frequency - self.offset);
        Some((cooked, self.last_err))
    }

    /// `handle_slew`: re-base the local reference and rescale the frequency when the
    /// local clock is adjusted.
    pub fn handle_slew(&mut self, cooked: f64, dfreq: f64, doffset: f64) {
        if self.n_samples > 0 {
            let delta = (cooked - self.local_ref) * dfreq - doffset;
            self.local_ref += delta;
        }
        if self.valid_coefs {
            self.frequency /= 1.0 - dfreq;
        }
    }

    /// Whether the model currently has valid coefficients.
    pub fn is_valid(&self) -> bool {
        self.valid_coefs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn models_a_clean_offset_clock() {
        // HW clock runs at the local rate but 5 s ahead. Sampled at local 0,10,20,30.
        let mut hc = HwClock::new(2, 8, 1.0, 1e-6);
        for lt in [0.0, 10.0, 20.0, 30.0] {
            hc.accumulate_sample(lt + 5.0, lt, 1e-6, 0.0);
        }
        assert!(hc.is_valid());
        assert!(hc.offset.abs() < 1e-12, "offset {}", hc.offset);
        assert!((hc.frequency - 1.0).abs() < 1e-12, "freq {}", hc.frequency);
        // cook a raw HW time of 37 -> local 32 (37 - 5 s offset).
        let (cooked, err) = hc.cook_time(37.0).unwrap();
        assert!((cooked - 32.0).abs() < 1e-9, "cooked {cooked}");
        assert_eq!(err, 1e-6);
    }

    #[test]
    fn needs_new_sample_respects_separation() {
        let mut hc = HwClock::new(2, 8, 5.0, 1e-6);
        assert!(hc.needs_new_sample(100.0)); // no samples yet
        hc.accumulate_sample(10.0, 5.0, 1e-6, 0.0); // local_ref = 5
        assert!(!hc.needs_new_sample(7.0)); // 2 s < 5 s separation
        assert!(hc.needs_new_sample(12.0)); // 7 s >= 5 s
    }

    #[test]
    fn process_readings_combines_and_rejects_bad() {
        let mut hc = HwClock::new(2, 8, 1.0, 1e-9);
        // Three readings, each a ~2 us round trip; cook = identity (local rate 1).
        let readings = [
            [100.0, 100.000_001, 100.000_002],
            [110.0, 110.000_001, 110.000_002],
            [120.0, 120.000_001, 120.000_002],
        ];
        let out = hc.process_readings(&readings, |t| t, 1e-9);
        assert!(out.is_some());
        let (hw_ts, local_ts, err) = out.unwrap();
        assert!(hw_ts > 100.0 && local_ts > 100.0 && err >= 1e-9);

        // A reading whose local_after precedes local_before -> negative delay.
        let bad = [[100.0, 100.0, 99.0]];
        assert!(hc.process_readings(&bad, |t| t, 1e-9).is_none());
    }

    #[test]
    fn handle_slew_rebases_reference() {
        let mut hc = HwClock::new(2, 8, 1.0, 1e-6);
        hc.accumulate_sample(10.0, 5.0, 1e-6, 0.0);
        let before = hc.local_ref;
        // Pure offset slew of +1 ms re-bases local_ref by -doffset.
        hc.handle_slew(5.0, 0.0, 0.001);
        assert!((hc.local_ref - (before - 0.001)).abs() < 1e-12);
    }
}
