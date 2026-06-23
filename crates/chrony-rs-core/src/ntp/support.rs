//! NTP protocol support helpers — `ntp_core.c` Stage 16 (`handle_slew`,
//! `has_saved_response`, `check_delay_quant`).
//!
//! * [`handle_slew`] ports the server monotonic-clock tracking: chrony keeps a monotonic
//!   reference (offset + epoch) for the experimental monotonic-root extension field
//!   ([`crate::ntp::exp_ef::add_ef_mono_root`]); a clock *slew* accumulates into the
//!   offset, while a *step* resets the offset and starts a new epoch.
//! * [`has_saved_response`] ports the predicate for a pending saved (delayed) response.
//! * [`check_delay_quant`] ports test C's quantile variant — accept when the delay is
//!   within the configured quantile estimate.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness (`research/oracle/ntp_core-support-c-vectors.txt`): the slew/step offset
//! tracking (epoch reseed witnessed by the `UTI_GetRandomBytes` stub), the saved-response
//! predicate, and the quantile comparison. See the tests.

/// chrony `LCL_ChangeType` (the subset `handle_slew` distinguishes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeType {
    Adjust,
    Step,
    UnknownStep,
}

/// The result of [`handle_slew`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SlewResult {
    /// The new `server_mono_offset`.
    pub mono_offset: f64,
    /// Whether a new monotonic epoch must be drawn (chrony reseeds `server_mono_epoch`
    /// from the CSPRNG on a step — a host-boundary concern).
    pub reseed_epoch: bool,
}

/// chrony `handle_slew`: update the server monotonic-clock offset for a local clock
/// change. A slew (`Adjust`) accumulates `doffset` into the offset; a step (`Step` /
/// `UnknownStep`) zeroes the offset and signals a new epoch.
pub fn handle_slew(server_mono_offset: f64, change_type: ChangeType, doffset: f64) -> SlewResult {
    match change_type {
        ChangeType::Adjust => SlewResult { mono_offset: server_mono_offset + doffset, reseed_epoch: false },
        ChangeType::Step | ChangeType::UnknownStep => SlewResult { mono_offset: 0.0, reseed_epoch: true },
    }
}

/// chrony `has_saved_response`: whether a saved (delayed) response with a pending timeout
/// is held for this source.
pub fn has_saved_response(saved_response_present: bool, timeout_id: i32) -> bool {
    saved_response_present && timeout_id > 0
}

/// chrony `check_delay_quant`: test C's quantile variant — accept the sample when its
/// `delay` does not exceed the configured `quantile` estimate.
pub fn check_delay_quant(quantile: f64, delay: f64) -> bool {
    delay <= quantile
}

#[cfg(test)]
mod tests;
