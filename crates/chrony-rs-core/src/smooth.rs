//! Served-time smoothing — a complete port of chrony 4.5 `smooth.c`.
//!
//! When `smoothtime` is configured, chrony does not expose clock corrections to
//! NTP clients abruptly; it spreads them over a bounded-frequency, bounded-wander
//! trajectory so served time moves smoothly. `smooth.c` builds that trajectory as
//! up to three constant-wander stages whose integral equals the offset to absorb,
//! and evaluates it at any instant. All 12 functions port here:
//!
//! | chrony `smooth.c` | here |
//! |-------------------|------|
//! | `SMT_Initialise` | [`Smoothing::new`] |
//! | `SMT_Finalise` | `Drop` (no-op) |
//! | `SMT_IsEnabled` | [`Smoothing::is_enabled`] |
//! | `SMT_GetOffset` | [`Smoothing::get_offset`] |
//! | `SMT_Activate` | [`Smoothing::activate`] |
//! | `SMT_Reset` | [`Smoothing::reset`] |
//! | `SMT_Leap` | [`Smoothing::leap`] |
//! | `get_smoothing` | [`Smoothing::get_smoothing`] |
//! | `update_stages` | [`Smoothing::update_stages`] |
//! | `update_smoothing` | [`Smoothing::update_smoothing`] |
//! | `handle_slew` | [`Smoothing::handle_slew`] |
//! | `SMT_GetSmoothingReport` | [`Smoothing::report`] |
//!
//! # Adaptations (documented)
//!
//! Time is passed as seconds (`f64`) instead of `struct timespec` — that is exactly
//! what `UTI_DiffTimespecsToDouble` yields, and `UTI_AdjustTimespec` becomes
//! `old + ((when-old)*dfreq - doffset)`. The smoothing config (max frequency/wander
//! in ppm, leap-only mode) is a constructor parameter rather than `CNF_GetSmooth`,
//! and `REF_GetSkew` is passed in where the auto-activation check needs it. The
//! struct *is* the LCL parameter-change handler (no global registration).

/// chrony's `NUM_STAGES`.
const NUM_STAGES: usize = 3;
/// chrony's `UNLOCK_SKEW_WANDER_RATIO`: how small the clock skew (relative to max
/// wander) must get before a locked smoother auto-activates.
const UNLOCK_SKEW_WANDER_RATIO: f64 = 10000.0;

/// One constant-wander stage of the trajectory.
#[derive(Clone, Copy, Debug, Default)]
struct Stage {
    wander: f64,
    length: f64,
}

/// The kind of local-clock change (chrony's `LCL_ChangeType`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LclChangeType {
    Adjust,
    Step,
    UnknownStep,
}

/// A current-smoothing snapshot (chrony's `RPT_SmoothingReport` subset).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SmoothingReport {
    pub active: bool,
    pub leap_only: bool,
    pub offset: f64,
    pub freq_ppm: f64,
    pub wander_ppm: f64,
}

/// Served-time smoothing state (chrony's `smooth.c` statics, made explicit).
pub struct Smoothing {
    enabled: bool,
    locked: bool,
    leap_only_mode: bool,
    /// Max frequency and wander, in absolute units (chrony converts ppm at init).
    max_freq: f64,
    max_wander: f64,
    smooth_offset: f64,
    smooth_freq: f64,
    /// Raw time of the last update, seconds; `last_update_zero` is the
    /// not-yet-set sentinel (chrony's zero timespec).
    last_update: f64,
    last_update_zero: bool,
    stages: [Stage; NUM_STAGES],
}

impl Smoothing {
    /// `SMT_Initialise`: configure the smoother. `max_freq_ppm`/`max_wander_ppm`
    /// must be positive for it to be enabled.
    pub fn new(max_freq_ppm: f64, max_wander_ppm: f64, leap_only_mode: bool) -> Self {
        let enabled = max_freq_ppm > 0.0 && max_wander_ppm > 0.0;
        Smoothing {
            enabled,
            locked: true,
            leap_only_mode,
            max_freq: max_freq_ppm * 1e-6,
            max_wander: max_wander_ppm * 1e-6,
            smooth_offset: 0.0,
            smooth_freq: 0.0,
            last_update: 0.0,
            last_update_zero: true,
            stages: [Stage::default(); NUM_STAGES],
        }
    }

    /// `SMT_IsEnabled`.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// `get_smoothing`: evaluate the trajectory at `now`, returning
    /// `(offset, freq, wander)`.
    fn get_smoothing(&self, now: f64) -> (f64, f64, f64) {
        let mut elapsed = now - self.last_update;
        let mut offset = self.smooth_offset;
        let mut freq = self.smooth_freq;
        let mut wander = 0.0;

        for st in &self.stages {
            if elapsed <= 0.0 {
                break;
            }
            let mut length = st.length;
            if length >= elapsed {
                length = elapsed;
            }
            wander = st.wander;
            offset -= length * (2.0 * freq + wander * length) / 2.0;
            freq += wander * length;
            elapsed -= length;
        }
        if elapsed > 0.0 {
            wander = 0.0;
            offset -= elapsed * freq;
        }
        (offset, freq, wander)
    }

    /// `update_stages`: build the three stages so the frequency-offset integral
    /// equals `smooth_offset`, respecting the max frequency/wander limits.
    fn update_stages(&mut self) {
        let s1 = self.smooth_offset / self.max_wander;
        let s2 = (self.smooth_freq * self.smooth_freq) / (2.0 * self.max_wander * self.max_wander);

        // 1st/3rd stage lengths assuming no frequency limit; pick the direction
        // that avoids negative lengths (smaller error on ties).
        let mut l1t = [0.0f64; 2];
        let mut l3t = [0.0f64; 2];
        let mut err = [0.0f64; 2];
        let mut d = -1.0;
        for i in 0..2 {
            let mut s = d * s1 + s2;
            if s < 0.0 {
                err[i] += -s;
                s = 0.0;
            }
            l3t[i] = s.sqrt();
            l1t[i] = l3t[i] - d * self.smooth_freq / self.max_wander;
            if l1t[i] < 0.0 {
                err[i] += l1t[i] * l1t[i];
                l1t[i] = 0.0;
            }
            d += 2.0;
        }

        let (mut l1, mut l3, dir) = if err[0] < err[1] {
            (l1t[0], l3t[0], -1.0)
        } else {
            (l1t[1], l3t[1], 1.0)
        };
        let mut l2 = 0.0;

        // If the frequency limit is reached, shorten 1st+3rd and add a 2nd stage.
        let f = dir * self.smooth_freq + l1 * self.max_wander - self.max_freq;
        if f > 0.0 {
            let mut lc = f / self.max_wander;
            let f2;
            if lc > l1 {
                lc = l1;
                f2 = dir * self.smooth_freq;
            } else {
                f2 = self.max_freq;
            }
            l2 = lc * (2.0 + f / f2);
            l1 -= lc;
            l3 -= lc;
        }

        self.stages[0] = Stage { wander: dir * self.max_wander, length: l1 };
        self.stages[1] = Stage { wander: 0.0, length: l2 };
        self.stages[2] = Stage { wander: -dir * self.max_wander, length: l3 };
    }

    /// `update_smoothing`: fold a clock adjustment (`offset`, `freq`) into the
    /// smoothing at time `now`. While locked, updates are ignored until the clock
    /// skew is small enough (or in leap-only mode), at which point it activates.
    fn update_smoothing(&mut self, now: f64, offset: f64, freq: f64, skew: f64) {
        if self.locked {
            if skew / self.max_wander < UNLOCK_SKEW_WANDER_RATIO || self.leap_only_mode {
                self.activate(now);
            }
            return;
        }
        let (o, f, _) = self.get_smoothing(now);
        self.smooth_offset = o + offset;
        self.smooth_freq = (f - freq) / (1.0 - freq);
        self.last_update = now;
        self.last_update_zero = false;
        self.update_stages();
    }

    /// `handle_slew`: the local-clock parameter-change handler. On an adjustment it
    /// folds the slew into the smoothing; it always re-bases `last_update` for the
    /// slew (chrony's `UTI_AdjustTimespec`).
    pub fn handle_slew(
        &mut self,
        cooked: f64,
        dfreq: f64,
        doffset: f64,
        change_type: LclChangeType,
        skew: f64,
    ) {
        if change_type == LclChangeType::Adjust {
            if self.leap_only_mode {
                self.update_smoothing(cooked, 0.0, 0.0, skew);
            } else {
                self.update_smoothing(cooked, doffset, dfreq, skew);
            }
        }
        if !self.last_update_zero {
            // UTI_AdjustTimespec in seconds: old + ((when-old)*dfreq - doffset).
            let delta = (cooked - self.last_update) * dfreq - doffset;
            self.last_update += delta;
        }
    }

    /// `SMT_GetOffset`: the smoothing offset to apply to served time at `now`.
    pub fn get_offset(&self, now: f64) -> f64 {
        if !self.enabled {
            return 0.0;
        }
        self.get_smoothing(now).0
    }

    /// `SMT_Activate`: unlock and start smoothing from `now`.
    pub fn activate(&mut self, now: f64) {
        if !self.enabled || !self.locked {
            return;
        }
        self.locked = false;
        self.last_update = now;
        self.last_update_zero = false;
    }

    /// `SMT_Reset`: clear the trajectory, re-basing at `now`.
    pub fn reset(&mut self, now: f64) {
        if !self.enabled {
            return;
        }
        self.smooth_offset = 0.0;
        self.smooth_freq = 0.0;
        self.last_update = now;
        self.last_update_zero = false;
        self.stages = [Stage::default(); NUM_STAGES];
    }

    /// `SMT_Leap`: in leap-only mode, absorb a leap second of `leap` seconds.
    pub fn leap(&mut self, now: f64, leap: i32, skew: f64) {
        if !self.enabled || !self.leap_only_mode {
            return;
        }
        self.update_smoothing(now, leap as f64, 0.0, skew);
    }

    /// `SMT_GetSmoothingReport`: the current offset/freq/wander at `now` (ppm for
    /// freq/wander), as `chronyc smoothing` reports.
    pub fn report(&self, now: f64) -> SmoothingReport {
        let (offset, freq, wander) = if self.enabled {
            self.get_smoothing(now)
        } else {
            (0.0, 0.0, 0.0)
        };
        SmoothingReport {
            active: self.enabled && !self.locked,
            leap_only: self.leap_only_mode,
            offset,
            freq_ppm: freq * 1e6,
            wander_ppm: wander * 1e6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_limits_non_positive() {
        assert!(!Smoothing::new(0.0, 10.0, false).is_enabled());
        assert!(!Smoothing::new(100.0, 0.0, false).is_enabled());
        let s = Smoothing::new(0.0, 0.0, false);
        assert_eq!(s.get_offset(123.0), 0.0);
    }

    #[test]
    fn smooths_an_offset_over_the_trajectory() {
        // 100 ppm max freq, 10 ppm max wander; absorb a 1 ms offset.
        let mut s = Smoothing::new(100.0, 10.0, false);
        s.activate(0.0);
        s.update_smoothing(0.0, 0.001, 0.0, 0.0); // private, but in-module
        // Two symmetric 10 s stages, no middle stage.
        assert!((s.stages[0].wander - 1e-5).abs() < 1e-15);
        assert!((s.stages[0].length - 10.0).abs() < 1e-9);
        assert_eq!(s.stages[1].length, 0.0);
        assert!((s.stages[2].wander - (-1e-5)).abs() < 1e-15);

        // Golden offsets along the trajectory (reference implementation).
        let want = [(0.0, 0.001), (5.0, 0.000875), (10.0, 0.0005), (15.0, 0.000125), (20.0, 0.0)];
        for (t, off) in want {
            assert!((s.get_offset(t) - off).abs() < 1e-12, "t={t} got {}", s.get_offset(t));
        }
    }

    #[test]
    fn frequency_limit_inserts_middle_stage() {
        // A large offset hits the max-frequency limit -> a non-zero 2nd stage.
        let mut s = Smoothing::new(100.0, 10.0, false);
        s.activate(0.0);
        s.update_smoothing(0.0, 0.1, 0.0, 0.0);
        assert!((s.stages[0].length - 10.0).abs() < 1e-6, "l1 {}", s.stages[0].length);
        assert!((s.stages[1].length - 990.0).abs() < 1e-6, "l2 {}", s.stages[1].length);
        assert!((s.stages[2].length - 10.0).abs() < 1e-6, "l3 {}", s.stages[2].length);
    }

    #[test]
    fn locked_smoother_ignores_updates_until_skew_small() {
        let mut s = Smoothing::new(100.0, 10.0, false);
        // Large skew -> stays locked, update ignored.
        s.update_smoothing(0.0, 0.001, 0.0, 1.0); // skew/max_wander huge
        assert_eq!(s.get_offset(5.0), 0.0);
        // Small skew -> auto-activates.
        s.update_smoothing(0.0, 0.001, 0.0, 1e-9);
        assert!(s.report(0.0).active);
    }

    #[test]
    fn reset_clears_trajectory() {
        let mut s = Smoothing::new(100.0, 10.0, false);
        s.activate(0.0);
        s.update_smoothing(0.0, 0.001, 0.0, 0.0);
        s.reset(0.0);
        assert_eq!(s.get_offset(5.0), 0.0);
    }

    #[test]
    fn handle_slew_adjust_folds_offset_and_rebases() {
        let mut s = Smoothing::new(100.0, 10.0, false);
        s.activate(0.0);
        // An Adjust slew of +1 ms offset; non-Adjust would not fold.
        s.handle_slew(0.0, 0.0, 0.001, LclChangeType::Adjust, 0.0);
        // last_update was rebased by UTI_AdjustTimespec: 0 + ((0-0)*0 - 0.001).
        assert!((s.last_update - (-0.001)).abs() < 1e-12);
        // A step change does not fold an offset into the smoothing.
        let mut s2 = Smoothing::new(100.0, 10.0, false);
        s2.activate(0.0);
        s2.handle_slew(0.0, 0.0, 0.001, LclChangeType::Step, 0.0);
        assert_eq!(s2.smooth_offset, 0.0);
    }
}
