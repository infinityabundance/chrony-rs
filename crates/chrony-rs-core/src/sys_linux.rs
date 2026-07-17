//! Linux clock-discipline arithmetic — a port of the pure tick/frequency logic in chrony
//! 4.5 `sys_linux.c`.
//!
//! On Linux chrony disciplines the system clock through **two** `adjtimex` knobs: the coarse
//! `tick` (microseconds per scheduler tick) and the fine `freq` (a scaled ppm offset).
//! `sys_linux.c` splits a requested frequency into a whole number of tick steps plus a
//! residual frequency, so large corrections use the tick and the remainder uses `freq`.
//!
//! This module ports that arithmetic — the parts with no syscall:
//!
//! | chrony `sys_linux.c` | here |
//! |----------------------|------|
//! | `kernelvercmp` | [`kernel_version_cmp`] |
//! | `guess_hz` | [`guess_hz`] |
//! | `get_version_specific_details` (pure core) | [`version_specific_details`] |
//! | `set_frequency` (the split) | [`compute_frequency_split`] + [`SysLinux::set_frequency`] |
//! | `read_frequency` / the return value | [`reconstruct_freq_ppm`] + [`SysLinux::read_frequency`] |
//!
//! The `adjtimex` call itself ([`SYS_Timex_Adjust`](crate::sys_timex)), the `sysconf`/`uname`
//! probes (`get_hz`/`get_kernel_version`), and the `LOG_FATAL` exits are the host boundary:
//! `hz` and the kernel version are inputs here, the syscall is an injected closure, and the
//! fatal cases return `None`.

/// `FREQ_SCALE`: ppm → kernel `freq` units (`2^16`).
const FREQ_SCALE: f64 = 65536.0;

/// `ADJ_TICK` (`sys/timex.h`).
pub const ADJ_TICK: u32 = 0x4000;
/// `ADJ_FREQUENCY`.
pub const ADJ_FREQUENCY: u32 = 0x0002;

/// chrony `kernelvercmp`: lexicographic compare of `(major, minor, patch)`, returning a
/// negative / zero / positive difference like the C.
pub fn kernel_version_cmp(a: (i32, i32, i32), b: (i32, i32, i32)) -> i32 {
    if a.0 != b.0 {
        return a.0 - b.0;
    }
    if a.1 != b.1 {
        return a.1 - b.1;
    }
    a.2 - b.2
}

/// chrony `guess_hz`: estimate `USER_HZ` from the kernel `tick` value (the only credible
/// values are 100 or a power of two, within the kernel's ±⅓ tick bounds). `None` where
/// chrony `LOG_FATAL`s because no `hz` fits.
pub fn guess_hz(tick: i32) -> Option<i32> {
    // The hz = 100 case (Linux/x86) first.
    if (9000..=11000).contains(&tick) {
        return Some(100);
    }
    for i in 4..16 {
        let ihz = 1 << i;
        let tick_nominal = 1.0e6 / ihz as f64;
        let tick_lo = (0.5 + tick_nominal * 2.0 / 3.0) as i32;
        let tick_hi = (0.5 + tick_nominal * 4.0 / 3.0) as i32;
        if tick_lo < tick && tick <= tick_hi {
            return Some(ihz);
        }
    }
    None
}

/// The kernel-version-dependent clock parameters (chrony's `get_version_specific_details`
/// globals).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VersionDetails {
    /// `dhz`: `hz` as a double.
    pub dhz: f64,
    /// `nominal_tick`: microseconds per tick (`(1e6 + hz/2) / hz`).
    pub nominal_tick: i32,
    /// `max_tick_bias`: how far `tick` may move (`nominal_tick / 10`).
    pub max_tick_bias: i32,
    /// `tick_update_hz`: the rate at which the kernel applies a frequency change.
    pub tick_update_hz: i32,
    /// `have_setoffset`: `ADJ_SETOFFSET` support (kernel ≥ 2.6.39).
    pub have_setoffset: bool,
}

/// chrony `get_version_specific_details`' pure core: derive the clock parameters from `hz`
/// and the kernel `version`. `None` where chrony `LOG_FATAL`s (kernel < 2.2.0).
pub fn version_specific_details(hz: i32, version: (i32, i32, i32)) -> Option<VersionDetails> {
    let nominal_tick = (1_000_000 + hz / 2) / hz;
    let max_tick_bias = nominal_tick / 10;

    if kernel_version_cmp(version, (2, 2, 0)) < 0 {
        return None;
    }

    // Modern kernels update the frequency immediately; older ones lag.
    let tick_update_hz = if kernel_version_cmp(version, (2, 6, 27)) >= 0
        && kernel_version_cmp(version, (2, 6, 33)) < 0
    {
        // Tickless kernels before 2.6.33: half-second interval.
        2
    } else if kernel_version_cmp(version, (4, 19, 0)) < 0 {
        // Before 4.19 the frequency is updated only on internal CONFIG_HZ ticks.
        100
    } else {
        100_000
    };

    let have_setoffset = kernel_version_cmp(version, (2, 6, 39)) >= 0;

    Some(VersionDetails { dhz: hz as f64, nominal_tick, max_tick_bias, tick_update_hz, have_setoffset })
}

/// The tick/frequency split chrony `set_frequency` computes for a requested ppm.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FrequencySplit {
    /// `required_delta_tick`: whole tick steps away from nominal.
    pub delta_tick: i32,
    /// `required_freq`: residual frequency in ppm (unscaled; the caller multiplies by
    /// `FREQ_SCALE` for the kernel).
    pub freq: f64,
    /// `required_tick`: the tick value to set (`nominal_tick - delta_tick`).
    pub tick: i64,
}

/// chrony `set_frequency`'s split (no syscall): round the requested ppm to a whole number of
/// tick steps, apply the `hz ≤ 250` anti-thrash hysteresis (stick with the current tick when
/// the requested step is adjacent to it), and compute the residual frequency and tick.
pub fn compute_frequency_split(
    freq_ppm: f64,
    dhz: f64,
    nominal_tick: i32,
    current_delta_tick: i32,
    hz: i32,
) -> FrequencySplit {
    let mut required_delta_tick = (freq_ppm / dhz).round() as i32;

    if hz <= 250
        && (required_delta_tick + 1 == current_delta_tick
            || required_delta_tick - 1 == current_delta_tick)
    {
        required_delta_tick = current_delta_tick;
    }

    let required_freq = -(freq_ppm - dhz * required_delta_tick as f64);
    let required_tick = (nominal_tick - required_delta_tick) as i64;

    FrequencySplit { delta_tick: required_delta_tick, freq: required_freq, tick: required_tick }
}

/// chrony's frequency reconstruction `dhz * delta_tick - kernel_freq / FREQ_SCALE`, shared by
/// `set_frequency`'s return value and `read_frequency`. `kernel_freq` is the scaled `freq`
/// the kernel reports (`txc.freq`).
pub fn reconstruct_freq_ppm(dhz: f64, delta_tick: i32, kernel_freq: f64) -> f64 {
    dhz * delta_tick as f64 - kernel_freq / FREQ_SCALE
}

/// A minimal `struct timex` view for the `adjtimex` boundary (only the fields
/// `sys_linux.c`'s frequency path touches).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinuxTimex {
    pub modes: u32,
    /// Scaled frequency (`ppm · FREQ_SCALE`).
    pub freq: i64,
    /// Microseconds per tick.
    pub tick: i64,
}

/// The Linux clock driver state (chrony's `sys_linux.c` statics). The `adjtimex` syscall is
/// injected per call as a closure, so the discipline arithmetic is exercised without touching
/// the real clock.
#[derive(Clone, Copy, Debug)]
pub struct SysLinux {
    pub hz: i32,
    pub dhz: f64,
    pub nominal_tick: i32,
    pub max_tick_bias: i32,
    pub current_delta_tick: i32,
    pub tick_update_hz: i32,
    pub have_setoffset: bool,
}

impl SysLinux {
    /// Build from `hz` and the kernel `version` (chrony's `get_version_specific_details`).
    /// `None` on an unsupported kernel.
    pub fn new(hz: i32, version: (i32, i32, i32)) -> Option<SysLinux> {
        let d = version_specific_details(hz, version)?;
        Some(SysLinux {
            hz,
            dhz: d.dhz,
            nominal_tick: d.nominal_tick,
            max_tick_bias: d.max_tick_bias,
            current_delta_tick: 0,
            tick_update_hz: d.tick_update_hz,
            have_setoffset: d.have_setoffset,
        })
    }

    /// chrony `set_frequency`: split the requested ppm across tick + freq, apply it via the
    /// injected `adjust` (the `adjtimex` boundary, which may clamp), and return the frequency
    /// now in effect.
    pub fn set_frequency(
        &mut self,
        freq_ppm: f64,
        mut adjust: impl FnMut(&mut LinuxTimex),
    ) -> f64 {
        let split =
            compute_frequency_split(freq_ppm, self.dhz, self.nominal_tick, self.current_delta_tick, self.hz);
        let mut txc = LinuxTimex {
            modes: ADJ_TICK | ADJ_FREQUENCY,
            freq: (split.freq * FREQ_SCALE) as i64,
            tick: split.tick,
        };
        adjust(&mut txc);
        self.current_delta_tick = split.delta_tick;
        reconstruct_freq_ppm(self.dhz, self.current_delta_tick, txc.freq as f64)
    }

    /// chrony `read_frequency`: read the kernel tick/freq via the injected `adjust` and
    /// reconstruct the ppm frequency.
    pub fn read_frequency(&mut self, mut adjust: impl FnMut(&mut LinuxTimex)) -> f64 {
        let mut txc = LinuxTimex::default();
        adjust(&mut txc);
        self.current_delta_tick = self.nominal_tick - txc.tick as i32;
        reconstruct_freq_ppm(self.dhz, self.current_delta_tick, txc.freq as f64)
    }
}

/// ---------------------------------------------------------------------------
/// Remaining sys_linux.c functions — lifecycle, frequency read/write wrappers,
/// kernel version detection, and step offset handling.
/// ---------------------------------------------------------------------------

/// chrony `SYS_Linux_CheckKernelVersion`: check whether the kernel version
/// meets the minimum requirement (2.2.0). Returns `true` if supported.
pub fn sys_linux_check_kernel_version(version: (i32, i32, i32)) -> bool {
    kernel_version_cmp(version, (2, 2, 0)) >= 0
}

/// chrony `SYS_Linux_Initialise`: initialise the Linux clock driver state.
/// Returns the SysLinux state if the kernel is supported.
pub fn sys_linux_initialise(hz: i32, version: (i32, i32, i32)) -> Option<SysLinux> {
    if !sys_linux_check_kernel_version(version) {
        return None;
    }
    SysLinux::new(hz, version)
}

/// chrony `SYS_Linux_Finalise`: clean up the Linux clock driver. No-op in
/// this port (the adjtimex state is managed by the kernel).
pub fn sys_linux_finalise() {}

/// chrony `apply_step_offset`: apply a step offset to the stored local
/// frequency adjustment (the `current_delta_tick`). After a step there is
/// no residual frequency to compensate, so the tick is reset to nominal.
pub fn apply_step_offset(sys: &mut SysLinux) {
    sys.current_delta_tick = 0;
}

/// chrony `get_hz`: estimate the kernel CONFIG_HZ value from sysconf.
/// Returns `None` if the tick value does not match any known HZ.
pub fn get_hz(tick: i32) -> Option<i32> {
    guess_hz(tick)
}

/// chrony `get_kernel_version`: parse a `uname` release string into
/// `(major, minor, patch)`. Returns zeros for an unparseable string.
pub fn get_kernel_version(release: &str) -> (i32, i32, i32) {
    let parts: Vec<&str> = release.splitn(3, '.').collect();
    let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.get(1).and_then(|s| {
        // Strip any non-numeric suffix (e.g. "8" from "5.8.0-arch")
        let s = s.split(|c: char| !c.is_ascii_digit()).next().unwrap_or(s);
        s.parse().ok()
    }).unwrap_or(0);
    let patch = parts.get(2).and_then(|s| {
        let s = s.split(|c: char| !c.is_ascii_digit()).next().unwrap_or(s);
        s.parse().ok()
    }).unwrap_or(0);
    (major, minor, patch)
}

/// chrony `report_time_adjust_blockers`: check for processes that may
/// interfere with clock adjustment. Returns 0 (clean) in the port — this
/// is a diagnostic / platform-specific function.
pub fn report_time_adjust_blockers() -> i32 {
    0
}

/// chrony `reset_adjtime_offset`: reset the kernel adjtime offset after
/// a step. This is a thin wrapper over adjtimex with ADJ_OFFSET=0; the
/// injected `adjust` closure represents the syscall.
pub fn reset_adjtime_offset(mut adjust: impl FnMut(&mut LinuxTimex)) {
    let mut txc = LinuxTimex {
        modes: 0x0002, // ADJ_FREQUENCY
        freq: 0,
        tick: 0,
    };
    adjust(&mut txc);
}

/// chrony `test_step_offset`: test whether a step offset would be accepted
/// by the kernel. Returns `true` if the step should proceed.
pub fn test_step_offset(sys: &SysLinux, offset: f64, _adjust: &mut impl FnMut(&mut LinuxTimex)) -> bool {
    // If the kernel supports ADJ_SETOFFSET, test that the offset is within
    // the maximum settable offset (chrony uses MAX_TICK * hz / 1e6).
    if sys.have_setoffset {
        let max_step = (sys.max_tick_bias as f64 * sys.hz as f64) / 1.0e6;
        offset.abs() <= max_step
    } else {
        // Without ADJ_SETOFFSET, any offset can be set via the tick/freq split.
        true
    }
}

#[cfg(test)]
mod tests;
