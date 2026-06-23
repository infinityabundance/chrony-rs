//! Generic software-slew clock-discipline driver — a complete port of chrony 4.5
//! `sys_generic.c` (all 14 functions).
//!
//! # What this module is
//!
//! `sys_generic.c` sits between chrony's local-clock abstraction and a
//! system-specific frequency driver. The OS driver can only *set the clock
//! frequency* (and maybe step it); everything else — correcting an accumulated
//! time *offset* by temporarily slewing the frequency, spreading that correction
//! over a bounded duration at a bounded rate, tracking how much offset remains,
//! and converting a raw timestamp to cooked time mid-slew — is this generic layer.
//! It is pure time-discipline arithmetic, which is exactly what `chrony-rs-core`
//! exists to reconstruct.
//!
//! The model: an `offset_register` holds the outstanding offset to correct. Each
//! update reads the elapsed time, credits the achieved slew against the register,
//! picks a new slew duration from the suggested `correction_rate` (clamped by the
//! min/max slew duration and the tracked scheduling excess), derives the frequency
//! offset needed to drain the register over that duration (clamped to
//! `max_corr_freq`), asks the driver to set `base_freq + corr` (clamped to
//! `max_freq`), and schedules the next update at the end of the slew. Changing the
//! frequency introduces a small dispersion (`slew_error`) reported upward.
//!
//! # Adaptations (documented, not silent)
//!
//! * **Host boundary.** chrony reads the raw clock (`LCL_ReadRawTime`), schedules a
//!   timeout (`SCH_AddTimeout`), notifies dispersion handlers, and reaches the OS
//!   through driver function pointers. Here all of that is injected: the raw clock
//!   and the dispersion sink are closures, the base driver is the [`FreqDriver`]
//!   trait, and the scheduler is modeled as a single stored end-of-slew time fired
//!   explicitly by [`SysGeneric::fire_end_of_slew`] (the only timeout this module
//!   ever sets, always `handle_end_of_slew`).
//! * **Timespecs, exactly.** The slew math depends on `UTI_DiffTimespecsToDouble` /
//!   `UTI_AddDoubleToTimespec`, which work on integer seconds + **integer
//!   nanoseconds** (with `(long)` truncation). [`Timespec`] reproduces that bit for
//!   bit, so the scheduled-timeout instants match the C to the nanosecond.
//! * **`PRV_SetTime`.** chrony's own `apply_step_offset` steps the clock via the
//!   privileged helper; that is injected as an optional `set_time` closure. (When
//!   the OS driver supplies its own step, chrony uses that and this path is unused.)
//!
//! # Oracles
//!
//! Differential-tested against the **real compiled `sys_generic.c`**: a C generator
//! completes the driver with a fake frequency-only base driver and drives a
//! sequence of `set_frequency`/`accrue_offset`/clock-advance/end-of-slew actions,
//! recording the frequency set, the scheduled slew end, the `offset_convert`
//! correction, and the dispersion notified (`research/oracle/sys_generic-c-vectors.txt`).
//! The port replays the identical actions and must match every value. A second,
//! independent check verifies the steady-state slew relationship (a pure offset
//! correction drains the register at the clamped rate). See the tests.

/// A `struct timespec` with the exact integer-nanosecond semantics chrony's
/// `UTI_*` helpers rely on.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds.
    pub tv_nsec: i64,
}

const NSEC_PER_SEC: i64 = 1_000_000_000;

impl Timespec {
    /// Construct from seconds and nanoseconds.
    pub fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Timespec { tv_sec, tv_nsec }
    }

    /// Build from a floating-point number of seconds the way the test clock does
    /// (`tv_sec = (time_t)t`, `tv_nsec = (long)(frac * 1e9)`).
    pub fn from_seconds(t: f64) -> Self {
        let sec = t as i64;
        let nsec = ((t - sec as f64) * 1.0e9) as i64;
        Timespec { tv_sec: sec, tv_nsec: nsec }
    }

    /// Seconds as `f64` (`sec + nsec*1e-9`), as the oracle reports timeout instants.
    pub fn as_seconds(self) -> f64 {
        self.tv_sec as f64 + self.tv_nsec as f64 * 1.0e-9
    }

    /// chrony `UTI_NormaliseTimespec`.
    fn normalise(&mut self) {
        if self.tv_nsec >= NSEC_PER_SEC || self.tv_nsec < 0 {
            self.tv_sec += self.tv_nsec / NSEC_PER_SEC;
            self.tv_nsec %= NSEC_PER_SEC;
            if self.tv_nsec < 0 {
                self.tv_sec -= 1;
                self.tv_nsec += NSEC_PER_SEC;
            }
        }
    }

    /// chrony `UTI_DiffTimespecsToDouble(self, b)` = `self - b` in seconds.
    pub(crate) fn diff_to_double(self, b: Timespec) -> f64 {
        (self.tv_sec as f64 - b.tv_sec as f64) + 1.0e-9 * (self.tv_nsec - b.tv_nsec) as f64
    }

    /// chrony `UTI_AddDoubleToTimespec(self, increment)` with `(long)` truncation.
    pub(crate) fn add_double(self, increment: f64) -> Timespec {
        let int_part = increment as i64;
        let mut end = Timespec {
            tv_sec: self.tv_sec + int_part,
            tv_nsec: self.tv_nsec + (1.0e9 * (increment - int_part as f64)) as i64,
        };
        end.normalise();
        end
    }

    /// chrony `UTI_AverageDiffTimespecs(earlier=self, later)`: returns
    /// `(average, diff)` where `diff = later - self` and `average = self + diff/2`.
    pub(crate) fn average_diff(self, later: Timespec) -> (Timespec, f64) {
        let diff = later.diff_to_double(self);
        (self.add_double(diff / 2.0), diff)
    }

    /// chrony `UTI_AdjustTimespec(old=self, when, dfreq, doffset)`: slew `self` by the
    /// elapsed-time-scaled frequency error minus the offset correction.
    pub(crate) fn adjust(self, when: Timespec, dfreq: f64, doffset: f64) -> Timespec {
        let elapsed = when.diff_to_double(self);
        let delta = elapsed * dfreq - doffset;
        self.add_double(delta)
    }
}

/// chrony `LCL_ChangeType` (subset this module reacts to).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChangeType {
    /// A slew adjustment.
    Adjust,
    /// A known step.
    Step,
    /// An unknown step.
    UnknownStep,
}

/// The system-specific frequency driver chrony completes (`lcl_*Driver` pointers).
/// The required ops are frequency read/set; the rest are optional capabilities a
/// real OS driver may provide (fast slew, offset-correction readback, its own step,
/// sync-status reporting). Defaults mirror a NULL function pointer in chrony.
pub trait FreqDriver {
    /// `drv_read_freq`: current base frequency, ppm.
    fn read_frequency(&mut self) -> f64;
    /// `drv_set_freq`: set the real frequency (ppm); returns the actual value set.
    fn set_frequency(&mut self, freq_ppm: f64) -> f64;

    /// `drv_accrue_offset`: hand an offset to the driver for a fast slew. Present
    /// only if [`FreqDriver::has_accrue_offset`] is true.
    fn accrue_offset(&mut self, _offset: f64, _corr_rate: f64) {}
    /// Whether `drv_accrue_offset` is wired (chrony's non-NULL pointer check).
    fn has_accrue_offset(&self) -> bool {
        false
    }
    /// `drv_get_offset_correction`: remaining fast-slew correction for a raw time.
    fn get_offset_correction(&mut self, _raw: Timespec) -> (f64, f64) {
        (0.0, 0.0)
    }
    /// Whether `drv_get_offset_correction` is wired (chrony's non-NULL check).
    fn has_get_offset_correction(&self) -> bool {
        false
    }
    /// `drv_set_sync_status`: report sync status to the driver. `None` ⇒ NULL.
    fn set_sync_status(&mut self, _synchronised: bool, _est_error: f64, _max_error: f64) -> bool {
        false
    }
}

/// chrony `MIN_OFFSET_CORRECTION`.
const MIN_OFFSET_CORRECTION: f64 = 1.0e-9;
/// chrony `MIN_SLEW_DURATION`.
const MIN_SLEW_DURATION: f64 = 1.0;
/// chrony `MAX_SLEW_DURATION`.
const MAX_SLEW_DURATION: f64 = 1.0e4;
/// chrony `MAX_SLEW_EXCESS_DURATION`.
const MAX_SLEW_EXCESS_DURATION: f64 = 100.0;
/// chrony `MIN_SLEW_DURATION_EXCESS_RATIO`.
const MIN_SLEW_DURATION_EXCESS_RATIO: f64 = 5.0;
/// chrony `SLEW_EXCESS_DURATION_DECAY`.
const SLEW_EXCESS_DURATION_DECAY: f64 = 0.9;

/// The generic software-slew driver state (chrony's `sys_generic.c` statics) over
/// an injected base [`FreqDriver`], raw clock, and dispersion sink.
pub struct SysGeneric<D: FreqDriver> {
    driver: D,
    raw_clock: Box<dyn FnMut() -> Timespec>,
    dispersion_notify: Box<dyn FnMut(f64)>,
    /// Optional clock-step primitive (chrony `PRV_SetTime`), used only by the
    /// generic `apply_step_offset`.
    set_time: Option<Box<dyn FnMut(Timespec) -> bool>>,

    base_freq: f64,
    max_freq: f64,
    max_freq_change_delay: f64,
    max_corr_freq: f64,
    offset_register: f64,
    slew_freq: f64,
    slew_start: Timespec,
    /// The scheduled end-of-slew instant (chrony schedules a `SCH_AddTimeout` here).
    slew_timeout_at: Timespec,
    /// Non-zero when a slew timeout is pending (chrony's `slew_timeout_id`).
    slew_timeout_id: u32,
    next_timeout_id: u32,
    slew_duration: f64,
    slew_excess_duration: f64,
    correction_rate: f64,
    slew_error: f64,
    fastslew_min_offset: f64,
    fastslew_max_rate: f64,
    fastslew_active: bool,
}

impl<D: FreqDriver> SysGeneric<D> {
    /// chrony `SYS_Generic_CompleteFreqDriver`: initialise the generic layer over a
    /// base driver. `max_slew_rate_ppm` is chrony's `CNF_GetMaxSlewRate()`.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_freq_driver(
        mut driver: D,
        max_set_freq_ppm: f64,
        max_set_freq_delay: f64,
        min_fastslew_offset: f64,
        max_fastslew_rate: f64,
        max_slew_rate_ppm: f64,
        raw_clock: Box<dyn FnMut() -> Timespec>,
        dispersion_notify: Box<dyn FnMut(f64)>,
        set_time: Option<Box<dyn FnMut(Timespec) -> bool>>,
    ) -> Self {
        let base_freq = driver.read_frequency();
        SysGeneric {
            driver,
            raw_clock,
            dispersion_notify,
            set_time,
            base_freq,
            max_freq: max_set_freq_ppm,
            max_freq_change_delay: max_set_freq_delay * (1.0 + max_set_freq_ppm / 1.0e6),
            max_corr_freq: max_slew_rate_ppm / 1.0e6,
            offset_register: 0.0,
            slew_freq: 0.0,
            slew_start: Timespec::default(),
            slew_timeout_at: Timespec::default(),
            slew_timeout_id: 0,
            next_timeout_id: 1,
            slew_duration: 0.0,
            slew_excess_duration: 0.0,
            correction_rate: 0.0,
            slew_error: 0.0,
            fastslew_min_offset: min_fastslew_offset,
            fastslew_max_rate: max_fastslew_rate / 1.0e6,
            fastslew_active: false,
        }
    }

    fn read_raw_time(&mut self) -> Timespec {
        (self.raw_clock)()
    }

    /// chrony `handle_step`.
    pub fn handle_step(&mut self, doffset: f64, change_type: ChangeType) {
        if change_type == ChangeType::Step {
            self.slew_start = self.slew_start.add_double(-doffset);
        }
    }

    /// chrony `start_fastslew`.
    fn start_fastslew(&mut self) {
        if !self.driver.has_accrue_offset() {
            return;
        }
        self.driver.accrue_offset(self.offset_register, 0.0);
        self.offset_register = 0.0;
        self.fastslew_active = true;
    }

    /// chrony `stop_fastslew`.
    fn stop_fastslew(&mut self, now: Timespec) {
        if !self.driver.has_get_offset_correction() || !self.fastslew_active {
            return;
        }
        let (corr, _) = self.driver.get_offset_correction(now);
        self.driver.accrue_offset(corr, 0.0);
        self.offset_register -= corr;
    }

    /// chrony `clamp_freq`.
    fn clamp_freq(&self, freq: f64) -> f64 {
        if freq > self.max_freq {
            self.max_freq
        } else if freq < -self.max_freq {
            -self.max_freq
        } else {
            freq
        }
    }

    /// chrony `update_slew`: end the running slew and start a new one.
    fn update_slew(&mut self) {
        // Remove the currently running timeout.
        self.slew_timeout_id = 0;

        let now = self.read_raw_time();

        // Credit the achieved slew against the offset register.
        let mut duration = now.diff_to_double(self.slew_start);
        self.offset_register -= self.slew_freq * duration;

        self.stop_fastslew(now);

        // Update the decaying maximum excess duration.
        self.slew_excess_duration =
            (self.slew_excess_duration + 1.0e-9) * SLEW_EXCESS_DURATION_DECAY;
        let excess_duration = duration - self.slew_duration;
        if self.slew_excess_duration < excess_duration
            && excess_duration <= MAX_SLEW_EXCESS_DURATION
        {
            self.slew_excess_duration = excess_duration;
        }

        // Duration of the new slew from the correction rate and past delays.
        if self.offset_register.abs() < MIN_OFFSET_CORRECTION {
            duration = MAX_SLEW_DURATION;
        } else {
            duration = self.correction_rate / self.offset_register.abs();
            if duration < MIN_SLEW_DURATION {
                duration = MIN_SLEW_DURATION;
            }
            if duration < MIN_SLEW_DURATION_EXCESS_RATIO * self.slew_excess_duration {
                duration = MIN_SLEW_DURATION_EXCESS_RATIO * self.slew_excess_duration;
            }
        }

        // Frequency offset to slew the register in the duration, clamped.
        let mut corr_freq = self.offset_register / duration;
        if corr_freq < -self.max_corr_freq {
            corr_freq = -self.max_corr_freq;
        } else if corr_freq > self.max_corr_freq {
            corr_freq = self.max_corr_freq;
        }

        // Hand off to the driver's fast slew if the frequency offset is too large.
        if self.driver.has_accrue_offset()
            && corr_freq.abs() >= self.fastslew_max_rate
            && self.offset_register.abs() > self.fastslew_min_offset
        {
            self.start_fastslew();
            corr_freq = 0.0;
        }

        // New real frequency, clamped, then actually set (driver may round).
        let mut total_freq = self.clamp_freq(self.base_freq + corr_freq * (1.0e6 - self.base_freq));
        total_freq = self.driver.set_frequency(total_freq);

        // New slewing frequency, relative to the real frequency.
        let old_slew_freq = self.slew_freq;
        self.slew_freq = (total_freq - self.base_freq) / (1.0e6 - total_freq);

        // Dispersion from changing frequency.
        self.slew_error = ((old_slew_freq - self.slew_freq) * self.max_freq_change_delay).abs();
        if self.slew_error >= MIN_OFFSET_CORRECTION {
            (self.dispersion_notify)(self.slew_error);
        }

        // Duration of the new slew, clamped (max timeout on wrong/zero sign).
        if self.offset_register.abs() < MIN_OFFSET_CORRECTION
            || self.offset_register * self.slew_freq <= 0.0
        {
            duration = MAX_SLEW_DURATION;
        } else {
            // chrony clamps `duration` to [MIN_SLEW_DURATION, MAX_SLEW_DURATION].
            duration = (self.offset_register / self.slew_freq)
                .clamp(MIN_SLEW_DURATION, MAX_SLEW_DURATION);
        }

        // Restart the timer.
        self.slew_timeout_at = now.add_double(duration);
        self.slew_timeout_id = self.next_timeout_id;
        self.next_timeout_id += 1;
        self.slew_start = now;
        self.slew_duration = duration;
    }

    /// chrony `handle_end_of_slew`: invoke when the scheduled slew timeout fires.
    pub fn fire_end_of_slew(&mut self) {
        self.slew_timeout_id = 0;
        self.update_slew();
    }

    /// chrony `read_frequency`.
    pub fn read_frequency(&self) -> f64 {
        self.base_freq
    }

    /// chrony `set_frequency`.
    pub fn set_frequency(&mut self, freq_ppm: f64) -> f64 {
        self.base_freq = freq_ppm;
        self.update_slew();
        self.base_freq
    }

    /// chrony `accrue_offset`.
    pub fn accrue_offset(&mut self, offset: f64, corr_rate: f64) {
        self.offset_register += offset;
        self.correction_rate = corr_rate;
        self.update_slew();
    }

    /// chrony `offset_convert`: correction (and optional error) to cook `raw`.
    pub fn offset_convert(&mut self, raw: Timespec) -> (f64, f64) {
        let duration = raw.diff_to_double(self.slew_start);

        let (fastslew_corr, fastslew_err) =
            if self.driver.has_get_offset_correction() && self.fastslew_active {
                let (c, e) = self.driver.get_offset_correction(raw);
                if c == 0.0 && e == 0.0 {
                    self.fastslew_active = false;
                }
                (c, e)
            } else {
                (0.0, 0.0)
            };

        let corr = self.slew_freq * duration + fastslew_corr - self.offset_register;

        let mut err = fastslew_err;
        if duration.abs() <= self.max_freq_change_delay {
            err += self.slew_error;
        }
        (corr, err)
    }

    /// chrony `apply_step_offset`: step the clock by `-offset` via the injected
    /// `set_time` primitive. Returns whether the step succeeded.
    pub fn apply_step_offset(&mut self, offset: f64) -> bool {
        let old_time = self.read_raw_time();
        let new_time = old_time.add_double(-offset);

        let Some(set_time) = self.set_time.as_mut() else {
            return false;
        };
        if !set_time(new_time) {
            return false;
        }

        let old_time = self.read_raw_time();
        let err = old_time.diff_to_double(new_time);
        (self.dispersion_notify)(err.abs());
        true
    }

    /// chrony `set_sync_status`: widen the error bounds by the outstanding offset
    /// and forward to the driver.
    pub fn set_sync_status(&mut self, synchronised: bool, mut est_error: f64, mut max_error: f64) {
        let offset = self.offset_register.abs();
        if est_error < offset {
            est_error = offset;
        }
        max_error += offset;
        self.driver.set_sync_status(synchronised, est_error, max_error);
    }

    /// chrony `SYS_Generic_Finalise`: cancel the slew and set the clamped base
    /// frequency so the clock does not keep drifting.
    pub fn finalise(&mut self) {
        self.slew_timeout_id = 0;
        let clamped = self.clamp_freq(self.base_freq);
        self.driver.set_frequency(clamped);
        let now = self.read_raw_time();
        self.stop_fastslew(now);
    }

    /// The scheduled end-of-slew instant (for tests / introspection).
    pub fn scheduled_timeout(&self) -> Timespec {
        self.slew_timeout_at
    }
}

#[cfg(test)]
mod tests;
