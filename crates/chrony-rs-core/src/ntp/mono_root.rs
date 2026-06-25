//! Monotonic-root sample selection — `ntp_core.c` (`process_response`'s
//! `EF_EXP_MONO_ROOT` handling).
//!
//! When a response carries the experimental monotonic-root extension field, chrony takes
//! the root delay/dispersion from it (in the higher-precision 4.28 fixed point rather than
//! the header's 16.16), and — when the field is from the same monotonic epoch as the
//! previous one — separates the source's *time* corrections from its *frequency*
//! corrections by accumulating a monotonic offset (`mono_doffset`) that retroactively
//! corrects the samples held in sourcestats.
//!
//! This module ports the three pure pieces:
//! * [`select_root`] — root delay/dispersion from the EF (f28) or the header (ntp32);
//! * [`compute_mono_doffset`] — the per-exchange monotonic offset, clamped to
//!   ±[`MAX_MONO_DOFFSET`];
//! * [`update_mono_state`] — the epoch / monotonic-receive / accumulator update the
//!   instance keeps for the next exchange.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`**: `process_response` is
//! driven over a valid client exchange with (and without) a real `add_ef_mono_root`-built
//! extension field (linking the real `ntp_ext.c`), capturing the resulting
//! `report.root_delay`/`root_dispersion`, the offset handed to `SST_CorrectOffset`, and
//! the instance's `remote_mono_epoch`/`remote_ntp_monorx`
//! (`/tmp/ncor/genmono.c`, `research/oracle/ntp_core-monoroot-c-vectors.txt`).

use crate::util::ntp32f28_to_double;

/// chrony `MAX_MONO_DOFFSET`: a monotonic offset larger than this (seconds) is rejected.
pub const MAX_MONO_DOFFSET: f64 = 16.0;

/// chrony `NSEC_PER_NTP64`: `1e9 * NSEC_PER_NTP64 == 2³²`, the NTP fraction-per-second.
const NSEC_PER_NTP64: f64 = 4.294_967_296;

/// chrony `UTI_Ntp32ToDouble`: a 16.16 NTP-short value (host order) to seconds.
fn ntp32_to_double(x: u32) -> f64 {
    x as f64 / 65_536.0
}

/// chrony `UTI_DiffNtp64ToDouble`: `a - b` in seconds, computed as the (era-wrapping)
/// 32-bit seconds difference plus the *true* (non-borrowing) fraction difference scaled —
/// matching the C exactly (the seconds and fraction halves are differenced separately).
/// `a`/`b` are host-order `(hi, lo)` packed as `u64`.
fn diff_ntp64_to_double(a: u64, b: u64) -> f64 {
    let (a_hi, a_lo) = ((a >> 32) as u32, a as u32);
    let (b_hi, b_lo) = ((b >> 32) as u32, b as u32);
    (a_hi.wrapping_sub(b_hi) as i32) as f64
        + (a_lo as f64 - b_lo as f64) / (1.0e9 * NSEC_PER_NTP64)
}

/// `process_response`'s root selection: when a monotonic-root EF is present, the root
/// delay/dispersion come from it as 4.28 fixed point (`ef = Some((root_delay, root_dispersion))`,
/// host-order raw); otherwise from the packet header's 16.16 ntp32 fields
/// (`hdr_root_delay`/`hdr_root_dispersion`, host order). Returns `(root_delay, root_dispersion)`.
pub fn select_root(ef: Option<(u32, u32)>, hdr_root_delay: u32, hdr_root_dispersion: u32) -> (f64, f64) {
    match ef {
        Some((rd, rdsp)) => (ntp32f28_to_double(rd), ntp32f28_to_double(rdsp)),
        None => (ntp32_to_double(hdr_root_delay), ntp32_to_double(hdr_root_dispersion)),
    }
}

/// `process_response`'s monotonic offset: when the EF is present, the stored
/// `remote_mono_epoch` matches the EF's epoch, and both monotonic-receive timestamps are
/// non-zero, the offset is the change in the monotonic-vs-realtime gap between this
/// exchange and the previous; anything larger than ±[`MAX_MONO_DOFFSET`] is dropped to 0.
/// Otherwise 0. All timestamps are host-order `(hi, lo)` packed as `u64`.
#[allow(clippy::too_many_arguments)]
pub fn compute_mono_doffset(
    ef_present: bool,
    epoch_match: bool,
    ef_mono_receive_ts: u64,
    inst_remote_ntp_monorx: u64,
    msg_receive_ts: u64,
    inst_remote_ntp_rx: u64,
) -> f64 {
    if ef_present && epoch_match && ef_mono_receive_ts != 0 && inst_remote_ntp_monorx != 0 {
        let doffset = diff_ntp64_to_double(ef_mono_receive_ts, inst_remote_ntp_monorx)
            - diff_ntp64_to_double(msg_receive_ts, inst_remote_ntp_rx);
        if doffset.abs() > MAX_MONO_DOFFSET {
            0.0
        } else {
            doffset
        }
    } else {
        0.0
    }
}

/// The instance's monotonic state carried to the next exchange.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MonoState {
    pub remote_mono_epoch: u32,
    pub remote_ntp_monorx: u64,
    /// The accumulated monotonic offset (`inst->mono_doffset`).
    pub mono_doffset: f64,
}

/// `process_response`'s monotonic-state update (the `if (ef_mono_root && !IsZero(...))`
/// branch): when the EF is present with a non-zero monotonic-receive timestamp, adopt its
/// epoch and receive timestamp and *accumulate* `mono_doffset` onto the prior total;
/// otherwise reset the whole state to zero. `prev_doffset` is the instance's accumulator
/// before this exchange.
pub fn update_mono_state(
    ef_present: bool,
    ef_mono_receive_ts: u64,
    ef_mono_epoch: u32,
    mono_doffset: f64,
    prev_doffset: f64,
) -> MonoState {
    if ef_present && ef_mono_receive_ts != 0 {
        MonoState {
            remote_mono_epoch: ef_mono_epoch,
            remote_ntp_monorx: ef_mono_receive_ts,
            mono_doffset: prev_doffset + mono_doffset,
        }
    } else {
        MonoState { remote_mono_epoch: 0, remote_ntp_monorx: 0, mono_doffset: 0.0 }
    }
}

#[cfg(test)]
mod tests;
