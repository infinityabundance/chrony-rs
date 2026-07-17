//! NTP poll-interval control and delay sanity tests — the first stage of a faithful
//! port of chrony 4.5 `ntp_core.c` (`NCR_*`), the NTP protocol engine.
//!
//! # Scope of this stage
//!
//! `ntp_core.c` is chrony's largest translation unit (69 functions, ~3300 lines); the
//! heart (`NCR_ProcessResponse` / `transmit_packet`) is socket- and instance-bound, so
//! the file is ported in stages. **Stage 1 (this module): the pure poll-interval and
//! delay-sanity arithmetic** that the response/transmit paths compose:
//!
//! * [`get_separation`] — the sampling separation for a poll interval,
//! * [`get_poll_adj`] — the poll-interval adjustment from the prediction error and the
//!   sourcestats sample count,
//! * [`adjust_poll`] — apply an adjustment to the running poll/score with clamping to
//!   `[minpoll, maxpoll]` and the non-LAN sub-second floor,
//! * [`check_delay_ratio`] / [`check_delay_dev_ratio`] — the max-delay-ratio and
//!   max-delay-dev-ratio tests that drop a sample whose round-trip delay is too high.
//!
//! Later stages: packet parse/validity, `NCR_ProcessResponse` (offset/delay/dispersion
//! + the tests), transmit, the instance lifecycle, and the access/report surface.
//!
//! # Adaptations (documented, not silent)
//!
//! * **The functions are pure**: chrony reads the per-source state and the sourcestats
//!   (`SST_*`) off the instance; here the relevant scalars and the
//!   [`crate::sourcestats::DelayTestData`] are passed in. The `MIN_NONLAN_POLL`
//!   sub-second gate in `adjust_poll` (reachability + measured LAN delay) is supplied
//!   as a precomputed `force_nonlan` flag.
//!
//! # Oracle
//!
//! These functions are differential-tested against the **real compiled `ntp_core.c`**
//! (the static functions and the `NCR_Instance_Record` struct are reached by
//! `#include`-ing the translation unit into the C generator and stubbing the external
//! surface): a minimal instance is built and each function is called in isolation, and
//! the outputs are matched (`research/oracle/ntp_core-c-vectors.txt`). The port replays
//! the identical inputs and matches every value. See the tests.

use crate::sourcestats::DelayTestData;

/// chrony `MIN_SAMPLING_SEPARATION`.
const MIN_SAMPLING_SEPARATION: f64 = 0.002;
/// chrony `MAX_SAMPLING_SEPARATION`.
const MAX_SAMPLING_SEPARATION: f64 = 0.2;
/// chrony `MIN_POLL` / `MAX_POLL`.
pub const MIN_POLL: i32 = -7;
pub const MAX_POLL: i32 = 24;
/// chrony `MIN_NONLAN_POLL`.
pub const MIN_NONLAN_POLL: i32 = 0;

/// chrony `NTP_Mode` values used here.
pub const MODE_ACTIVE: i32 = 1;
pub const MODE_CLIENT: i32 = 3;
/// chrony `OperatingMode` values.
pub const MD_OFFLINE: i32 = 0;
pub const MD_ONLINE: i32 = 1;
pub const MD_BURST_WAS_OFFLINE: i32 = 2;
pub const MD_BURST_WAS_ONLINE: i32 = 3;
/// chrony transmit-timing constants.
const WARM_UP_DELAY: f64 = 2.0;
const PEER_SAMPLING_ADJ: f64 = 1.1;
const MAX_BURST_INTERVAL: f64 = 2.0;
const MAX_BURST_POLL_RATIO: f64 = 0.25;

fn f64_to_i32_safe(v: f64) -> i32 {
    if v.is_nan() || v.is_infinite() { return 0; }
    if v > i32::MAX as f64 { return i32::MAX; }
    if v < i32::MIN as f64 { return i32::MIN; }
    v as i32
}

fn clamp(lo: f64, x: f64, hi: f64) -> f64 {
    if x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

/// `UTI_Log2ToDouble` (the subset used here).
fn log2_to_double(l: i32) -> f64 {
    if l >= 0 {
        (1u64 << l.min(31)) as f64
    } else {
        1.0 / (1u64 << (-l).min(31)) as f64
    }
}

/// chrony `get_separation`: the sampling separation for a polling interval.
pub fn get_separation(poll: i32) -> f64 {
    debug_assert!((MIN_POLL..=MAX_POLL).contains(&poll));
    // Allow up to 8 sources using the same short interval.
    let separation = log2_to_double(poll - 3);
    clamp(MIN_SAMPLING_SEPARATION, separation, MAX_SAMPLING_SEPARATION)
}

/// chrony `get_poll_adj`: the poll-interval adjustment. `samples` is the current
/// sourcestats sample count, `poll_target` the configured target.
pub fn get_poll_adj(
    samples: i32,
    poll_target: i32,
    error_in_estimate: f64,
    peer_distance: f64,
) -> f64 {
    if error_in_estimate > peer_distance {
        // Not tracking the peer well; back off proportionally to how bad it is.
        -(error_in_estimate / peer_distance).ln() / 2.0f64.ln()
    } else {
        // Keep the sample count near the target.
        let mut poll_adj =
            (samples as f64 / poll_target as f64 - 1.0) / poll_target as f64;
        if samples < poll_target {
            poll_adj *= 2.0;
        }
        poll_adj
    }
}

/// chrony `adjust_poll`: apply `adj` to the running `(local_poll, poll_score)`, clamp
/// to `[minpoll, maxpoll]`, and apply the non-LAN sub-second floor when `force_nonlan`.
/// Returns the new `(local_poll, poll_score)`.
pub fn adjust_poll(
    mut local_poll: i32,
    mut poll_score: f64,
    adj: f64,
    minpoll: i32,
    maxpoll: i32,
    force_nonlan: bool,
) -> (i32, f64) {
    poll_score += adj;

    if poll_score >= 1.0 {
        local_poll += f64_to_i32_safe(poll_score);
        poll_score -= f64_to_i32_safe(poll_score) as f64;
    }
    if poll_score < 0.0 {
        local_poll += f64_to_i32_safe(poll_score - 1.0);
        poll_score -= f64_to_i32_safe(poll_score - 1.0) as f64;
    }

    if local_poll < minpoll {
        local_poll = minpoll;
        poll_score = 0.0;
    } else if local_poll > maxpoll {
        local_poll = maxpoll;
        poll_score = 1.0;
    }

    if local_poll < MIN_NONLAN_POLL && force_nonlan {
        local_poll = MIN_NONLAN_POLL;
    }

    (local_poll, poll_score)
}

/// chrony `check_delay_ratio`: accept the sample unless its delay exceeds
/// `min_delay * max_delay_ratio + age * (skew + max_clock_error)`. `delay_test` is the
/// sourcestats delay-test data (`None` = not enough data, accept).
pub fn check_delay_ratio(
    max_delay_ratio: f64,
    delay: f64,
    delay_test: Option<DelayTestData>,
    max_clock_error: f64,
) -> bool {
    if max_delay_ratio < 1.0 {
        return true;
    }
    let Some(d) = delay_test else { return true };
    let max_delay = d.min_delay * max_delay_ratio + d.last_sample_ago * (d.skew + max_clock_error);
    delay <= max_delay
}

/// chrony `check_delay_dev_ratio`: accept unless the delay increase over the minimum,
/// relative to the standard deviation, is too large (with the offset-error escape).
pub fn check_delay_dev_ratio(
    max_delay_dev_ratio: f64,
    offset: f64,
    delay: f64,
    delay_test: Option<DelayTestData>,
    max_clock_error: f64,
) -> bool {
    let Some(d) = delay_test else { return true };
    let max_delta =
        d.std_dev * max_delay_dev_ratio + d.last_sample_ago * (d.skew + max_clock_error);
    let delta = (delay - d.min_delay) / 2.0;
    if delta <= max_delta {
        return true;
    }
    let error_in_estimate = offset + d.predicted_offset;
    // Don't drop if the offset error is not much larger than the delay increase.
    if error_in_estimate.abs() - delta > max_delta {
        return true;
    }
    false
}

/// chrony `get_transmit_poll`: the poll interval to use for the next transmission. In
/// symmetric active mode, if the peer is reachable, use the shorter of the local and
/// remote poll (not below `minpoll`).
pub fn get_transmit_poll(
    local_poll: i32,
    mode: i32,
    remote_poll: i32,
    minpoll: i32,
    reachable: bool,
) -> i32 {
    let mut poll = local_poll;
    if mode == MODE_ACTIVE && poll > remote_poll && reachable {
        poll = remote_poll.max(minpoll);
    }
    poll
}

/// chrony `get_transmit_delay`: the delay until the next transmission. `last_tx` is the
/// time since the last transmission (chrony computes it as `now - local_tx.ts` when
/// `!on_tx` and the tx timestamp is set, else 0).
#[allow(clippy::too_many_arguments)]
pub fn get_transmit_delay(
    on_tx: bool,
    local_tx_zero: bool,
    now_minus_local_tx: f64,
    local_poll: i32,
    mode: i32,
    remote_poll: i32,
    minpoll: i32,
    reachable: bool,
    opmode: i32,
    presend_done: bool,
    remote_stratum: i32,
    our_stratum: i32,
) -> f64 {
    let last_tx = if !on_tx && !local_tx_zero { now_minus_local_tx } else { 0.0 };

    let poll_to_use = get_transmit_poll(local_poll, mode, remote_poll, minpoll, reachable);
    let mut delay_time = log2_to_double(poll_to_use);

    match opmode {
        MD_ONLINE => match mode {
            MODE_CLIENT => {
                if presend_done {
                    delay_time = WARM_UP_DELAY;
                }
            }
            MODE_ACTIVE => {
                // Wait a bit for a higher-stratum peer / interleave with an equal peer.
                let stratum_diff = remote_stratum - our_stratum;
                if (stratum_diff > 0 && last_tx * PEER_SAMPLING_ADJ < delay_time)
                    || (!on_tx
                        && stratum_diff == 0
                        && last_tx / delay_time > PEER_SAMPLING_ADJ - 0.5)
                {
                    delay_time *= PEER_SAMPLING_ADJ;
                }
            }
            _ => {}
        },
        MD_BURST_WAS_ONLINE | MD_BURST_WAS_OFFLINE => {
            delay_time = MAX_BURST_INTERVAL.min(MAX_BURST_POLL_RATIO * delay_time);
        }
        // MD_OFFLINE is asserted unreachable in chrony.
        _ => {}
    }

    if last_tx > 0.0 {
        delay_time -= last_tx;
    }
    if delay_time < 0.0 {
        delay_time = 0.0;
    }
    delay_time
}

#[cfg(test)]
mod tests;
