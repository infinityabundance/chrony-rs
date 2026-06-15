//! Streaming quantile estimation — a complete port of chrony 4.5 `quantiles.c`.
//!
//! # What it is
//!
//! chrony estimates quantiles of a stream (e.g. of NTP delays) without storing the
//! samples, using a stochastic step estimator: each tracked quantile nudges its
//! estimate up or down by an adaptive step, gated by a random draw against the
//! target probability. Several independent estimators per quantile (`repeat`) are
//! kept and their **median** ([`crate::regress::find_median`]) is reported, which
//! is the only cross-module dependency.
//!
//! All 8 functions of `quantiles.c` have counterparts here:
//!
//! | chrony `quantiles.c` | here |
//! |----------------------|------|
//! | `QNT_CreateInstance` | [`QuantileEstimator::new`] |
//! | `QNT_DestroyInstance` | `Drop` (automatic) |
//! | `QNT_Reset` | [`QuantileEstimator::reset`] |
//! | `QNT_Accumulate` | [`QuantileEstimator::accumulate`] |
//! | `QNT_GetMinK` | [`QuantileEstimator::min_k`] |
//! | `QNT_GetQuantile` | [`QuantileEstimator::get_quantile`] |
//! | `insert_initial_value` | [`QuantileEstimator::insert_initial_value`] |
//! | `update_estimate` | [`update_estimate`] |
//!
//! # Witnessing (honest)
//!
//! This is a **structural** port, not a byte-witnessed one. chrony seeds
//! `random()` from `UTI_GetRandomBytes`, so its estimator is non-deterministic and
//! cannot be reproduced bit-for-bit — there is nothing stable to witness against.
//! What *is* verified: [`update_estimate`] (deterministic given the random draw)
//! and [`QuantileEstimator::insert_initial_value`] are tested exactly, and the full
//! estimator is tested for statistical convergence to known quantiles with a fixed
//! seed (so the test itself is deterministic). The RNG here is a deterministic
//! stand-in for chrony's randomly-seeded `random()`.

use crate::regress;

/// Largest `repeat` (chrony's `MAX_REPEAT`); also bounds the per-quantile median.
pub const MAX_REPEAT: i32 = 64;

/// One tracked quantile estimator (chrony's `struct Quantile`).
#[derive(Clone, Copy, Debug)]
struct Quantile {
    est: f64,
    step: f64,
    sign: i32,
}

/// `update_estimate`: nudge one quantile toward `value`, gated by `rand` against
/// the target probability `p`. A faithful port of chrony's logic.
fn update_estimate(q: &mut Quantile, value: f64, p: f64, rand: f64, min_step: f64) {
    if value > q.est && rand > 1.0 - p {
        q.step += if q.sign > 0 { min_step } else { -min_step };
        q.est += if q.step > 0.0 { q.step.abs() } else { min_step };
        if q.est > value {
            q.step += value - q.est;
            q.est = value;
        }
        if q.sign < 0 && q.step > min_step {
            q.step = min_step;
        }
        q.sign = 1;
    } else if value < q.est && rand > p {
        q.step += if q.sign < 0 { min_step } else { -min_step };
        q.est -= if q.step > 0.0 { q.step.abs() } else { min_step };
        if q.est < value {
            q.step += q.est - value;
            q.est = value;
        }
        if q.sign > 0 && q.step > min_step {
            q.step = min_step;
        }
        q.sign = -1;
    }
}

/// A streaming quantile estimator (chrony's `QNT_Instance_Record`).
pub struct QuantileEstimator {
    quants: Vec<Quantile>,
    n_quants: i32,
    repeat: i32,
    q: i32,
    min_k: i32,
    min_step: f64,
    n_set: i32,
    /// Deterministic stand-in for chrony's randomly-seeded `random()`.
    rng: u64,
}

impl QuantileEstimator {
    /// `QNT_CreateInstance`: estimate quantiles `k/q` for `k` in `min_k..=max_k`,
    /// keeping `repeat` estimators each with initial/min step `min_step`. Panics on
    /// invalid parameters, matching chrony's `assert(0)`.
    pub fn new(min_k: i32, max_k: i32, q: i32, repeat: i32, min_step: f64) -> Self {
        Self::with_seed(min_k, max_k, q, repeat, min_step, 0x9E37_79B9_7F4A_7C15)
    }

    /// As [`new`](Self::new) but with an explicit RNG seed, so the stochastic
    /// updates are reproducible (chrony seeds randomly; here it is a parameter).
    pub fn with_seed(min_k: i32, max_k: i32, q: i32, repeat: i32, min_step: f64, seed: u64) -> Self {
        assert!(
            q >= 2
                && min_k <= max_k
                && min_k >= 1
                && max_k < q
                && (1..=MAX_REPEAT).contains(&repeat)
                && min_step > 0.0,
            "invalid quantile parameters"
        );
        let n_quants = (max_k - min_k + 1) * repeat;
        let mut inst = QuantileEstimator {
            quants: vec![Quantile { est: 0.0, step: min_step, sign: 1 }; n_quants as usize],
            n_quants,
            repeat,
            q,
            min_k,
            min_step,
            n_set: 0,
            rng: seed,
        };
        inst.reset();
        inst
    }

    /// `QNT_Reset`: forget all samples and reset every estimator.
    pub fn reset(&mut self) {
        self.n_set = 0;
        for q in &mut self.quants {
            q.est = 0.0;
            q.step = self.min_step;
            q.sign = 1;
        }
    }

    /// `QNT_GetMinK`: the smallest tracked `k`.
    pub fn min_k(&self) -> i32 {
        self.min_k
    }

    /// SplitMix64 step mapped to `[0, 1)` — the stochastic gate source.
    fn next_rand(&mut self) -> f64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 53) as f64
    }

    /// `insert_initial_value`: seed the estimators with the first samples, kept
    /// repeated and ordered (chrony's warm-up before stochastic updating begins).
    fn insert_initial_value(&mut self, value: f64) {
        let r = self.repeat as usize;
        assert!((self.n_set as usize) * r < self.n_quants as usize);

        let mut i = self.n_set as usize;
        while i > 0 && self.quants[(i - 1) * r].est > value {
            let carry = self.quants[(i - 1) * r].est;
            for j in 0..r {
                self.quants[i * r + j].est = carry;
            }
            i -= 1;
        }
        for j in 0..r {
            self.quants[i * r + j].est = value;
        }
        self.n_set += 1;

        // Duplicate the largest value into the still-unset estimators.
        for i in (self.n_set as usize * r)..self.n_quants as usize {
            self.quants[i].est = self.quants[i - 1].est;
        }
    }

    /// `QNT_Accumulate`: fold one sample into the estimators.
    pub fn accumulate(&mut self, value: f64) {
        if self.n_set * self.repeat < self.n_quants {
            self.insert_initial_value(value);
            return;
        }
        for i in 0..self.n_quants as usize {
            let p = (i / self.repeat as usize + self.min_k as usize) as f64 / self.q as f64;
            let rand = self.next_rand();
            update_estimate(&mut self.quants[i], value, p, rand, self.min_step);
        }
    }

    /// `QNT_GetQuantile`: the current estimate of quantile `k/q` (the median of the
    /// `repeat` estimators). Panics on out-of-range `k`, matching chrony.
    pub fn get_quantile(&self, k: i32) -> f64 {
        assert!(
            k >= self.min_k && k - self.min_k < self.n_quants,
            "quantile index out of range"
        );
        let base = (k - self.min_k) as usize * self.repeat as usize;
        let estimates: Vec<f64> =
            (0..self.repeat as usize).map(|i| self.quants[base + i].est).collect();
        regress::find_median(&estimates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_estimate_upward_and_downward_branches() {
        // Upward: value above estimate, rand passes the (1 - p) gate.
        let mut q = Quantile { est: 1.0, step: 0.1, sign: 1 };
        update_estimate(&mut q, 5.0, 0.5, 0.99, 0.1);
        // step += min_step (sign>0) -> 0.2; est += |0.2| -> 1.2; sign -> 1.
        assert!((q.step - 0.2).abs() < 1e-12);
        assert!((q.est - 1.2).abs() < 1e-12);
        assert_eq!(q.sign, 1);

        // Downward: value below estimate, rand passes the p gate.
        let mut q = Quantile { est: 1.0, step: 0.1, sign: 1 };
        update_estimate(&mut q, 0.0, 0.5, 0.99, 0.1);
        // sign>0 so step += -min_step -> 0.0; est -= min_step (step not >0) -> 0.9; sign -> -1.
        assert!((q.step - 0.0).abs() < 1e-12);
        assert!((q.est - 0.9).abs() < 1e-12);
        assert_eq!(q.sign, -1);

        // No move when the random gate fails.
        let mut q = Quantile { est: 1.0, step: 0.1, sign: 1 };
        update_estimate(&mut q, 5.0, 0.5, 0.1, 0.1);
        assert_eq!(q.est, 1.0);
    }

    #[test]
    fn initial_values_are_inserted_ordered() {
        // During warm-up each sample is inserted in order across the estimators.
        let mut e = QuantileEstimator::new(1, 3, 4, 1, 0.01); // n_quants = 3
        e.accumulate(3.0);
        e.accumulate(1.0);
        e.accumulate(2.0);
        // get_quantile returns the (single) estimator value; they should be sorted.
        assert_eq!(e.get_quantile(1), 1.0);
        assert_eq!(e.get_quantile(2), 2.0);
        assert_eq!(e.get_quantile(3), 3.0);
        assert_eq!(e.min_k(), 1);
    }

    #[test]
    fn converges_to_known_quantiles_uniform_stream() {
        // Deciles of U(0,1): k=5 -> 0.5, k=1 -> 0.1, k=9 -> 0.9. Deterministic
        // input + fixed seed, so this test is reproducible.
        let mut e = QuantileEstimator::with_seed(1, 9, 10, 11, 0.0005, 0xDEAD_BEEF);
        let mut s: u64 = 0x1234_5678;
        let mut uniform = || {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (s >> 11) as f64 / (1u64 << 53) as f64
        };
        for _ in 0..20000 {
            e.accumulate(uniform());
        }
        assert!((e.get_quantile(5) - 0.5).abs() < 0.05, "median = {}", e.get_quantile(5));
        assert!((e.get_quantile(1) - 0.1).abs() < 0.05, "p10 = {}", e.get_quantile(1));
        assert!((e.get_quantile(9) - 0.9).abs() < 0.05, "p90 = {}", e.get_quantile(9));
    }

    #[test]
    fn reset_clears_state() {
        let mut e = QuantileEstimator::new(1, 9, 10, 3, 0.01);
        for i in 0..100 {
            e.accumulate(i as f64);
        }
        e.reset();
        assert_eq!(e.get_quantile(5), 0.0);
    }

    #[test]
    #[should_panic(expected = "invalid quantile parameters")]
    fn invalid_parameters_panic() {
        QuantileEstimator::new(0, 9, 10, 1, 0.01); // min_k < 1
    }
}
