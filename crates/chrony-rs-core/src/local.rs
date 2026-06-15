//! The local clock abstraction — a complete port of chrony 4.5 `local.c`.
//!
//! `local.c` (`LCL_*`) is chrony's clock hub: it sits between the discipline
//! algorithms and the system-specific clock driver, holding the current frequency,
//! temperature compensation, and clock precision, converting raw↔cooked time, and
//! dispatching every clock change to a list of registered handlers. It composes the
//! ported clock driver ([`crate::sys_null::NullClock`] implements [`ClockDriver`])
//! and, on steps/leaps, the ported [`crate::smooth`] (via optional hooks). All 35
//! functions port here (the publics below plus the private precision/clamp/handler
//! helpers).
//!
//! # Adaptations (documented)
//!
//! Time is seconds (`f64`); the raw clock (`LCL_ReadRawTime`) and config
//! (`CNF_Get*`) are injected. The system driver is a [`ClockDriver`] trait object
//! rather than C function pointers, and — since Rust closures can't be compared
//! like C pointers — parameter-change / dispersion handlers are registered by
//! closure and removed by the returned id. `SMT_Reset`/`SMT_Leap` become optional
//! hooks. The discipline arithmetic is faithful.

use crate::util::is_time_offset_sane;

/// The kind of local-clock change passed to handlers (chrony's `LCL_ChangeType`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LclChangeType {
    Adjust,
    Step,
    UnknownStep,
}

/// The system-specific clock driver (chrony's `lcl_*Driver` function pointers).
/// [`crate::sys_null::NullClock`] is one implementation.
pub trait ClockDriver {
    /// `read_frequency`: current frequency offset, ppm.
    fn read_frequency(&self) -> f64;
    /// `set_frequency`: set the frequency at raw time `now`; returns the value set.
    fn set_frequency(&mut self, now: f64, freq_ppm: f64) -> f64;
    /// `accrue_offset`: apply an offset correction at the given rate.
    fn accrue_offset(&mut self, offset: f64, corr_rate: f64);
    /// `apply_step_offset`: step the clock; returns whether it succeeded.
    fn apply_step_offset(&mut self, offset: f64) -> bool;
    /// `offset_convert`: the `(correction, error)` mapping raw→cooked at `raw`.
    fn offset_convert(&mut self, raw: f64) -> (f64, f64);
    /// Whether the driver can apply leap seconds (`drv_set_leap != NULL`).
    fn supports_leap(&self) -> bool {
        false
    }
    /// `set_leap`: inform the driver of a pending leap second.
    fn set_leap(&mut self, _leap: i32, _tai_offset: i32) {}
    /// `set_sync_status`: inform the driver of sync status.
    fn set_sync_status(&mut self, _synchronised: bool, _est_error: f64, _max_error: f64) {}
}

type ChangeHandler = Box<dyn FnMut(f64, f64, f64, f64, LclChangeType)>;
type DispersionHandler = Box<dyn FnMut(f64)>;

/// The local clock (chrony's `local.c` module state).
pub struct LocalClock {
    driver: Box<dyn ClockDriver>,
    raw_clock: Box<dyn FnMut() -> f64>,
    current_freq_ppm: f64,
    max_freq_ppm: f64,
    temp_comp_ppm: f64,
    precision_quantum: f64,
    precision_log: i32,
    max_clock_error: f64,
    change_handlers: Vec<(usize, ChangeHandler)>,
    dispersion_handlers: Vec<(usize, DispersionHandler)>,
    next_id: usize,
    handlers_enabled: bool,
    /// Optional `SMT_Reset` hook (called with the cooked time on a step).
    smooth_reset: Option<Box<dyn FnMut(f64)>>,
    /// Optional `SMT_Leap` hook (called with the cooked time and leap on a leap).
    smooth_leap: Option<Box<dyn FnMut(f64, i32)>>,
}

impl LocalClock {
    /// `LCL_Initialise` + `lcl_RegisterSystemDrivers`: build the hub over `driver`
    /// and a raw-time source `raw_clock`. `clock_precision` of `<= 0` triggers
    /// [`measure_clock_precision`](Self::measure_clock_precision); the result is
    /// clamped to `[1e-9, 1.0]`. Initial frequency comes from the driver.
    pub fn new(
        driver: Box<dyn ClockDriver>,
        mut raw_clock: Box<dyn FnMut() -> f64>,
        max_drift_ppm: f64,
        max_clock_error: f64,
        clock_precision: f64,
    ) -> Self {
        let mut precision_quantum = if clock_precision > 0.0 {
            clock_precision
        } else {
            Self::measure_clock_precision(&mut raw_clock)
        };
        precision_quantum = precision_quantum.clamp(1.0e-9, 1.0);
        let precision_log = (precision_quantum.ln() / 2f64.ln()).round() as i32;
        assert!(precision_log >= -30, "precision log too small");

        let current_freq_ppm = driver.read_frequency();
        LocalClock {
            driver,
            raw_clock,
            current_freq_ppm,
            max_freq_ppm: max_drift_ppm,
            temp_comp_ppm: 0.0,
            precision_quantum,
            precision_log,
            max_clock_error,
            change_handlers: Vec::new(),
            dispersion_handlers: Vec::new(),
            next_id: 0,
            handlers_enabled: true,
            smooth_reset: None,
            smooth_leap: None,
        }
    }

    /// `measure_clock_precision`: read the raw clock until `NITERS` increasing
    /// deltas are seen and return the smallest (the clock resolution).
    pub fn measure_clock_precision(raw_clock: &mut dyn FnMut() -> f64) -> f64 {
        const NITERS: i32 = 100;
        let mut old = raw_clock();
        let mut best = 1.0; // assume better than a second
        let mut iters = 0;
        while iters < NITERS {
            let ts = raw_clock();
            let diff = ts - old;
            old = ts;
            if diff > 0.0 {
                if diff < best {
                    best = diff;
                }
                iters += 1;
            }
        }
        best
    }

    /// Wire up the smoothing hooks (`SMT_Reset` on step, `SMT_Leap` on leap).
    pub fn set_smoothing_hooks(
        &mut self,
        on_step: Box<dyn FnMut(f64)>,
        on_leap: Box<dyn FnMut(f64, i32)>,
    ) {
        self.smooth_reset = Some(on_step);
        self.smooth_leap = Some(on_leap);
    }

    /// `LCL_AddParameterChangeHandler`: register a clock-change handler; returns an
    /// id for later removal.
    pub fn add_parameter_change_handler(&mut self, handler: ChangeHandler) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.change_handlers.push((id, handler));
        id
    }

    /// `LCL_RemoveParameterChangeHandler`.
    pub fn remove_parameter_change_handler(&mut self, id: usize) {
        let n = self.change_handlers.len();
        self.change_handlers.retain(|(i, _)| *i != id);
        assert!(self.change_handlers.len() < n, "handler not found");
    }

    /// `LCL_IsFirstParameterChangeHandler`.
    pub fn is_first_parameter_change_handler(&self, id: usize) -> bool {
        self.change_handlers.first().map(|(i, _)| *i == id).unwrap_or(false)
    }

    /// `LCL_AddDispersionNotifyHandler`.
    pub fn add_dispersion_notify_handler(&mut self, handler: DispersionHandler) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.dispersion_handlers.push((id, handler));
        id
    }

    /// `LCL_RemoveDispersionNotifyHandler`.
    pub fn remove_dispersion_notify_handler(&mut self, id: usize) {
        let n = self.dispersion_handlers.len();
        self.dispersion_handlers.retain(|(i, _)| *i != id);
        assert!(self.dispersion_handlers.len() < n, "handler not found");
    }

    fn invoke_parameter_change_handlers(
        &mut self,
        raw: f64,
        cooked: f64,
        dfreq: f64,
        doffset: f64,
        change_type: LclChangeType,
    ) {
        if !self.handlers_enabled {
            return;
        }
        for (_, h) in &mut self.change_handlers {
            h(raw, cooked, dfreq, doffset, change_type);
        }
    }

    fn invoke_dispersion_notify_handlers(&mut self, dispersion: f64) {
        for (_, h) in &mut self.dispersion_handlers {
            h(dispersion);
        }
    }

    /// `LCL_ReadRawTime`.
    pub fn read_raw_time(&mut self) -> f64 {
        (self.raw_clock)()
    }

    /// `LCL_ReadCookedTime`: `(cooked, err)`.
    pub fn read_cooked_time(&mut self) -> (f64, f64) {
        let raw = self.read_raw_time();
        self.cook_time(raw)
    }

    /// `LCL_CookTime`: apply the driver's offset correction to a raw time.
    pub fn cook_time(&mut self, raw: f64) -> (f64, f64) {
        let (correction, err) = self.get_offset_correction(raw);
        (raw + correction, err)
    }

    /// `LCL_GetOffsetCorrection`.
    pub fn get_offset_correction(&mut self, raw: f64) -> (f64, f64) {
        self.driver.offset_convert(raw)
    }

    /// `LCL_ReadAbsoluteFrequency`: current frequency with temperature compensation
    /// undone.
    pub fn read_absolute_frequency(&self) -> f64 {
        let mut freq = self.current_freq_ppm;
        if self.temp_comp_ppm != 0.0 {
            freq = (freq + self.temp_comp_ppm) / (1.0 - 1.0e-6 * self.temp_comp_ppm);
        }
        freq
    }

    fn clamp_freq(&self, freq: f64) -> f64 {
        if freq <= self.max_freq_ppm && freq >= -self.max_freq_ppm {
            freq
        } else {
            freq.clamp(-self.max_freq_ppm, self.max_freq_ppm)
        }
    }

    /// `check_offset`: whether `now + (-offset)` is still a sane time.
    fn check_offset(now: f64, offset: f64) -> bool {
        is_time_offset_sane(now, -offset)
    }

    /// `LCL_SetAbsoluteFrequency`.
    pub fn set_absolute_frequency(&mut self, afreq_ppm: f64) {
        let mut afreq_ppm = self.clamp_freq(afreq_ppm);
        if self.temp_comp_ppm != 0.0 {
            afreq_ppm = afreq_ppm * (1.0 - 1.0e-6 * self.temp_comp_ppm) - self.temp_comp_ppm;
        }
        let raw = self.read_raw_time();
        afreq_ppm = self.driver.set_frequency(raw, afreq_ppm);
        let dfreq = (afreq_ppm - self.current_freq_ppm) / (1.0e6 - self.current_freq_ppm);
        let (cooked, _) = self.cook_time(raw);
        self.invoke_parameter_change_handlers(raw, cooked, dfreq, 0.0, LclChangeType::Adjust);
        self.current_freq_ppm = afreq_ppm;
    }

    /// `LCL_AccumulateDeltaFrequency`.
    pub fn accumulate_delta_frequency(&mut self, mut dfreq: f64) {
        let old_freq_ppm = self.current_freq_ppm;
        self.current_freq_ppm += dfreq * (1.0e6 - self.current_freq_ppm);
        self.current_freq_ppm = self.clamp_freq(self.current_freq_ppm);
        let raw = self.read_raw_time();
        self.current_freq_ppm = self.driver.set_frequency(raw, self.current_freq_ppm);
        dfreq = (self.current_freq_ppm - old_freq_ppm) / (1.0e6 - old_freq_ppm);
        let (cooked, _) = self.cook_time(raw);
        self.invoke_parameter_change_handlers(raw, cooked, dfreq, 0.0, LclChangeType::Adjust);
    }

    /// `LCL_AccumulateOffset`.
    pub fn accumulate_offset(&mut self, offset: f64, corr_rate: f64) -> bool {
        let raw = self.read_raw_time();
        let (cooked, _) = self.cook_time(raw);
        if !Self::check_offset(cooked, offset) {
            return false;
        }
        self.driver.accrue_offset(offset, corr_rate);
        self.invoke_parameter_change_handlers(raw, cooked, 0.0, offset, LclChangeType::Adjust);
        true
    }

    /// `LCL_ApplyStepOffset`.
    pub fn apply_step_offset(&mut self, offset: f64) -> bool {
        let raw = self.read_raw_time();
        let (cooked, _) = self.cook_time(raw);
        if !Self::check_offset(raw, offset) {
            return false;
        }
        if !self.driver.apply_step_offset(offset) {
            return false;
        }
        if let Some(h) = &mut self.smooth_reset {
            h(cooked); // SMT_Reset on every step
        }
        self.invoke_parameter_change_handlers(raw, cooked, 0.0, offset, LclChangeType::Step);
        true
    }

    /// `LCL_NotifyExternalTimeStep`.
    pub fn notify_external_time_step(&mut self, raw: f64, cooked: f64, offset: f64, dispersion: f64) {
        self.cancel_offset_correction();
        self.invoke_parameter_change_handlers(raw, cooked, 0.0, offset, LclChangeType::UnknownStep);
        self.invoke_dispersion_notify_handlers(dispersion);
    }

    /// `LCL_NotifyLeap`.
    pub fn notify_leap(&mut self, leap: i32) {
        let raw = self.read_raw_time();
        let (cooked, _) = self.cook_time(raw);
        if let Some(h) = &mut self.smooth_leap {
            h(cooked, leap);
        }
        self.invoke_parameter_change_handlers(raw, cooked, 0.0, -leap as f64, LclChangeType::Step);
    }

    /// `LCL_AccumulateFrequencyAndOffset`.
    pub fn accumulate_frequency_and_offset(
        &mut self,
        mut dfreq: f64,
        doffset: f64,
        corr_rate: f64,
    ) -> bool {
        let raw = self.read_raw_time();
        let (cooked, _) = self.cook_time(raw);
        if !Self::check_offset(cooked, doffset) {
            return false;
        }
        let old_freq_ppm = self.current_freq_ppm;
        self.current_freq_ppm += dfreq * (1.0e6 - self.current_freq_ppm);
        self.current_freq_ppm = self.clamp_freq(self.current_freq_ppm);
        self.current_freq_ppm = self.driver.set_frequency(raw, self.current_freq_ppm);
        dfreq = (self.current_freq_ppm - old_freq_ppm) / (1.0e6 - old_freq_ppm);
        self.driver.accrue_offset(doffset, corr_rate);
        self.invoke_parameter_change_handlers(raw, cooked, dfreq, doffset, LclChangeType::Adjust);
        true
    }

    /// `LCL_AccumulateFrequencyAndOffsetNoHandlers`: as above with handlers
    /// temporarily disabled.
    pub fn accumulate_frequency_and_offset_no_handlers(
        &mut self,
        dfreq: f64,
        doffset: f64,
        corr_rate: f64,
    ) -> bool {
        let prev = self.handlers_enabled;
        self.handlers_enabled = false;
        let r = self.accumulate_frequency_and_offset(dfreq, doffset, corr_rate);
        self.handlers_enabled = prev;
        r
    }

    /// `LCL_MakeStep`: step the clock to cancel the current offset correction.
    pub fn make_step(&mut self) -> bool {
        let raw = self.read_raw_time();
        let (correction, _) = self.get_offset_correction(raw);
        if !Self::check_offset(raw, -correction) {
            return false;
        }
        self.accumulate_offset(correction, 0.0);
        self.apply_step_offset(-correction)
    }

    /// `LCL_CancelOffsetCorrection`.
    pub fn cancel_offset_correction(&mut self) {
        let raw = self.read_raw_time();
        let (correction, _) = self.get_offset_correction(raw);
        self.accumulate_offset(correction, 0.0);
    }

    /// `LCL_CanSystemLeap`.
    pub fn can_system_leap(&self) -> bool {
        self.driver.supports_leap()
    }

    /// `LCL_SetSystemLeap`.
    pub fn set_system_leap(&mut self, leap: i32, tai_offset: i32) {
        if self.driver.supports_leap() {
            self.driver.set_leap(leap, tai_offset);
        }
    }

    /// `LCL_SetTempComp`: set the temperature compensation, re-deriving the absolute
    /// frequency. Returns the compensation actually in effect.
    pub fn set_temp_comp(&mut self, comp: f64) -> f64 {
        if self.temp_comp_ppm == comp {
            return comp;
        }
        // Undo previous compensation.
        self.current_freq_ppm =
            (self.current_freq_ppm + self.temp_comp_ppm) / (1.0 - 1.0e-6 * self.temp_comp_ppm);
        let uncomp_freq_ppm = self.current_freq_ppm;
        // Apply new compensation.
        self.current_freq_ppm = self.current_freq_ppm * (1.0 - 1.0e-6 * comp) - comp;
        let raw = self.read_raw_time();
        self.current_freq_ppm = self.driver.set_frequency(raw, self.current_freq_ppm);
        self.temp_comp_ppm =
            (uncomp_freq_ppm - self.current_freq_ppm) / (1.0e-6 * uncomp_freq_ppm + 1.0);
        self.temp_comp_ppm
    }

    /// `LCL_SetSyncStatus`.
    pub fn set_sync_status(&mut self, synchronised: bool, est_error: f64, max_error: f64) {
        self.driver.set_sync_status(synchronised, est_error, max_error);
    }

    /// `LCL_GetSysPrecisionAsLog`.
    pub fn sys_precision_as_log(&self) -> i32 {
        self.precision_log
    }
    /// `LCL_GetSysPrecisionAsQuantum`.
    pub fn sys_precision_as_quantum(&self) -> f64 {
        self.precision_quantum
    }
    /// `LCL_GetMaxClockError`.
    pub fn max_clock_error(&self) -> f64 {
        self.max_clock_error
    }
}

/// The ported null clock driver ([`crate::sys_null::NullClock`]) is a [`ClockDriver`].
impl ClockDriver for crate::sys_null::NullClock {
    fn read_frequency(&self) -> f64 {
        crate::sys_null::NullClock::read_frequency(self)
    }
    fn set_frequency(&mut self, now: f64, freq_ppm: f64) -> f64 {
        crate::sys_null::NullClock::set_frequency(self, now, freq_ppm)
    }
    fn accrue_offset(&mut self, offset: f64, corr_rate: f64) {
        crate::sys_null::NullClock::accrue_offset(self, offset, corr_rate)
    }
    fn apply_step_offset(&mut self, offset: f64) -> bool {
        crate::sys_null::NullClock::apply_step_offset(self, offset) != 0
    }
    fn offset_convert(&mut self, raw: f64) -> (f64, f64) {
        crate::sys_null::NullClock::offset_convert(self, raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys_null::NullClock;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A controllable raw clock for tests.
    fn clock_source(now: Rc<RefCell<f64>>) -> Box<dyn FnMut() -> f64> {
        Box::new(move || *now.borrow())
    }

    fn make(now: Rc<RefCell<f64>>) -> LocalClock {
        let driver = Box::new(NullClock::new(*now.borrow()));
        LocalClock::new(driver, clock_source(now), 1000.0, 1.0, 1e-9)
    }

    #[test]
    fn precision_measurement_finds_quantum() {
        // A clock that advances by 4 ms each read -> precision 4 ms (clamped <= 1s).
        let t = Rc::new(RefCell::new(0.0));
        let t2 = t.clone();
        let mut src: Box<dyn FnMut() -> f64> = Box::new(move || {
            let mut v = t2.borrow_mut();
            *v += 0.004;
            *v
        });
        let q = LocalClock::measure_clock_precision(&mut src);
        assert!((q - 0.004).abs() < 1e-9, "quantum {q}");

        // new() with clock_precision <= 0 must measure it (advancing clock so the
        // busy-wait terminates, exactly as chrony's does on a real clock).
        let tick = Rc::new(RefCell::new(0.0));
        let tk = tick.clone();
        let src2: Box<dyn FnMut() -> f64> = Box::new(move || {
            let mut v = tk.borrow_mut();
            *v += 0.002;
            *v
        });
        let lc = LocalClock::new(Box::new(NullClock::new(0.0)), src2, 1000.0, 1.0, 0.0);
        assert!((lc.sys_precision_as_quantum() - 0.002).abs() < 1e-9);
    }

    #[test]
    fn cooked_time_tracks_driver_offset() {
        let now = Rc::new(RefCell::new(100.0));
        let mut lc = make(now.clone());
        // Driver starts at zero offset -> cooked == raw.
        let (cooked, _) = lc.read_cooked_time();
        assert!((cooked - 100.0).abs() < 1e-9);
        // Accumulate a +0.5 s offset; cooked time shifts by -0.5 (offset_register).
        assert!(lc.accumulate_offset(0.5, 0.0));
        let (cooked, _) = lc.cook_time(100.0);
        assert!((cooked - 99.5).abs() < 1e-9, "cooked {cooked}");
    }

    #[test]
    fn frequency_set_read_with_temp_comp() {
        let now = Rc::new(RefCell::new(0.0));
        let mut lc = make(now);
        lc.set_absolute_frequency(20.0);
        assert!((lc.read_absolute_frequency() - 20.0).abs() < 1e-9);
        // Temperature compensation changes current freq but read undoes it.
        lc.set_temp_comp(5.0);
        assert!((lc.read_absolute_frequency() - 20.0).abs() < 1e-6, "{}", lc.read_absolute_frequency());
    }

    #[test]
    fn handlers_fire_and_can_be_removed_and_disabled() {
        // A sane wall-clock base so a small offset stays post-1970 (check_offset).
        let now = Rc::new(RefCell::new(1.7e9));
        let mut lc = make(now);
        let count = Rc::new(RefCell::new(0));
        let c2 = count.clone();
        let id = lc.add_parameter_change_handler(Box::new(move |_, _, _, _, _| {
            *c2.borrow_mut() += 1;
        }));
        assert!(lc.is_first_parameter_change_handler(id));
        lc.accumulate_offset(0.001, 0.0);
        assert_eq!(*count.borrow(), 1);
        // No-handlers variant doesn't fire.
        lc.accumulate_frequency_and_offset_no_handlers(0.0, 0.001, 0.0);
        assert_eq!(*count.borrow(), 1);
        lc.remove_parameter_change_handler(id);
        lc.accumulate_offset(0.001, 0.0);
        assert_eq!(*count.borrow(), 1);
    }

    #[test]
    fn step_is_rejected_by_null_driver() {
        // The null driver cannot step, so apply_step_offset fails.
        let now = Rc::new(RefCell::new(1.7e9));
        let mut lc = make(now);
        assert!(!lc.apply_step_offset(0.001));
        // precision getters
        assert!(lc.sys_precision_as_quantum() > 0.0);
        assert!(lc.sys_precision_as_log() <= 0);
        assert_eq!(lc.max_clock_error(), 1.0);
        assert!(!lc.can_system_leap());
    }
}
