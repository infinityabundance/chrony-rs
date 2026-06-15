//! Clock abstraction and the deterministic simulated clock.
//!
//! The [`SystemClock`] trait is the seam between the deterministic brain and the
//! host. The brain only ever talks to this trait; whether it is driving a real
//! `adjtimex` or a simulation is invisible to it. That invisibility is what makes
//! discipline decisions replayable.
//!
//! [`SimulatedClock`] is the replay/test implementation. It mutates **nothing**
//! outside its own struct — the cardinal rule that host-clock mutation never
//! happens in ordinary tests is enforced structurally here: there is simply no
//! syscall in this file.
//!
//! # Model
//!
//! Two time bases:
//!
//!   * **Monotonic** (`mono_ns`) — advanced by the replay harness as it walks the
//!     event list. Never moves backwards. This is the trace's clock.
//!   * **Wall** (`wall_ns`) — what the brain is disciplining. Derived as
//!     `mono_ns + offset_ns`, where `offset_ns` is changed only by [`step`]. A
//!     real discipline model will also apply a frequency *slew*; that is modeled
//!     as a rate but deliberately left inert until the discipline campaign so we
//!     do not ship untested slew math.
//!
//! [`step`]: SystemClock::step

/// The host-clock seam. Kept intentionally small; richer operations (frequency
/// read/set) are added per court rather than speculatively.
pub trait SystemClock {
    /// Current wall-clock time in nanoseconds since an unspecified but fixed
    /// epoch. For the simulated clock this is `mono + offset`; for a real clock it
    /// would be `CLOCK_REALTIME`. Absolute epoch is unimportant — only *deltas*
    /// and *steps* are compared in courts.
    fn wall_ns(&self) -> i128;

    /// Apply an instantaneous step of `delta_ns` to wall time (positive = forward).
    /// On a real clock this is a discontinuous jump (chrony's `makestep` path); in
    /// simulation it just adjusts the offset.
    fn step(&mut self, delta_ns: i128);
}

/// Deterministic, side-effect-free clock for replay and tests.
#[derive(Clone, Debug)]
pub struct SimulatedClock {
    mono_ns: u64,
    /// Offset added to monotonic time to produce wall time. Changed only by steps.
    offset_ns: i128,
    /// Number of steps applied — observable so discipline courts can assert "chrony
    /// stepped exactly once here" without inspecting wall time directly.
    step_count: u64,
}

impl SimulatedClock {
    /// A fresh clock whose wall time initially equals its monotonic time.
    pub fn new() -> Self {
        SimulatedClock {
            mono_ns: 0,
            offset_ns: 0,
            step_count: 0,
        }
    }

    /// Advance monotonic time to `mono_ns`. Monotonic means non-decreasing: an
    /// attempt to move backwards is a programming error in the harness (the trace
    /// is validated for ordering before replay), so it is rejected with `false`
    /// rather than silently clamping, which would hide a real bug.
    #[must_use]
    pub fn advance_to(&mut self, mono_ns: u64) -> bool {
        if mono_ns < self.mono_ns {
            return false;
        }
        self.mono_ns = mono_ns;
        true
    }

    /// Current monotonic time.
    pub fn mono_ns(&self) -> u64 {
        self.mono_ns
    }

    /// How many steps have been applied so far.
    pub fn step_count(&self) -> u64 {
        self.step_count
    }
}

impl Default for SimulatedClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemClock for SimulatedClock {
    fn wall_ns(&self) -> i128 {
        self.mono_ns as i128 + self.offset_ns
    }

    fn step(&mut self, delta_ns: i128) {
        self.offset_ns += delta_ns;
        self.step_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_tracks_monotonic_without_steps() {
        let mut c = SimulatedClock::new();
        assert!(c.advance_to(1_000_000_000));
        assert_eq!(c.wall_ns(), 1_000_000_000);
        assert_eq!(c.step_count(), 0);
    }

    #[test]
    fn step_offsets_wall_but_not_monotonic() {
        let mut c = SimulatedClock::new();
        assert!(c.advance_to(2_000_000_000));
        c.step(-500_000_000); // pull wall back half a second
        assert_eq!(c.wall_ns(), 1_500_000_000);
        assert_eq!(c.mono_ns(), 2_000_000_000, "monotonic must be unaffected by a step");
        assert_eq!(c.step_count(), 1);
    }

    #[test]
    fn monotonic_cannot_go_backwards() {
        let mut c = SimulatedClock::new();
        assert!(c.advance_to(10));
        assert!(!c.advance_to(5), "backwards advance must be refused");
        assert_eq!(c.mono_ns(), 10);
    }
}
