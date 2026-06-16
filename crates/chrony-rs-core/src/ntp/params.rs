//! NTP source runtime parameters — `ntp_core.c` Stage 9 (`NCR_Modify*` setters).
//!
//! [`SourceParams`] holds the per-source NTP parameters that chronyc can reconfigure at
//! runtime (`minpoll`, `maxpoll`, `maxdelay`, `maxdelayratio`, `maxdelaydevratio`,
//! `minstratum`, `polltarget`). The `modify_*` methods port chrony's `NCR_Modify*`
//! setters faithfully, including:
//!
//! * the `[MIN_POLL, MAX_POLL]` range guard on `minpoll`/`maxpoll` (out-of-range is a
//!   no-op) and their mutual adjustment (raising `minpoll` above `maxpoll` raises
//!   `maxpoll` to match, and vice versa),
//! * the `CLAMP(0, x, MAX)` bounds on the delay limits,
//! * the `MAX(1, x)` floor on `polltarget`,
//! * the unclamped `minstratum` set.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness: an instance is built, each `NCR_Modify*` is called, and the resulting
//! parameter fields are captured (`research/oracle/ntp_core-modify-c-vectors.txt`). See
//! the tests.

/// chrony `MIN_POLL` / `MAX_POLL`.
const MIN_POLL: i32 = -7;
const MAX_POLL: i32 = 24;
/// chrony `MAX_MAXDELAY`, `MAX_MAXDELAYRATIO`, `MAX_MAXDELAYDEVRATIO`.
const MAX_MAXDELAY: f64 = 1.0e3;
const MAX_MAXDELAYRATIO: f64 = 1.0e6;
const MAX_MAXDELAYDEVRATIO: f64 = 1.0e6;

fn clamp(lo: f64, x: f64, hi: f64) -> f64 {
    if x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

/// The per-source NTP parameters reconfigurable at runtime (chrony `NCR_Instance`
/// subset). Field semantics match the instance record.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SourceParams {
    pub minpoll: i32,
    pub maxpoll: i32,
    pub max_delay: f64,
    pub max_delay_ratio: f64,
    pub max_delay_dev_ratio: f64,
    pub min_stratum: i32,
    pub poll_target: i32,
}

impl SourceParams {
    /// chrony `NCR_ModifyMinpoll`: out-of-range is a no-op; otherwise set `minpoll` and,
    /// if it now exceeds `maxpoll`, raise `maxpoll` to match.
    pub fn modify_minpoll(&mut self, new_minpoll: i32) {
        // chrony: new_minpoll < MIN_POLL || new_minpoll > MAX_POLL.
        if !(MIN_POLL..=MAX_POLL).contains(&new_minpoll) {
            return;
        }
        self.minpoll = new_minpoll;
        if self.maxpoll < self.minpoll {
            self.modify_maxpoll(self.minpoll);
        }
    }

    /// chrony `NCR_ModifyMaxpoll`: out-of-range is a no-op; otherwise set `maxpoll` and,
    /// if `minpoll` now exceeds it, lower `minpoll` to match.
    pub fn modify_maxpoll(&mut self, new_maxpoll: i32) {
        // chrony: new_maxpoll < MIN_POLL || new_maxpoll > MAX_POLL.
        if !(MIN_POLL..=MAX_POLL).contains(&new_maxpoll) {
            return;
        }
        self.maxpoll = new_maxpoll;
        if self.minpoll > self.maxpoll {
            self.modify_minpoll(self.maxpoll);
        }
    }

    /// chrony `NCR_ModifyMaxdelay`.
    pub fn modify_max_delay(&mut self, new_max_delay: f64) {
        self.max_delay = clamp(0.0, new_max_delay, MAX_MAXDELAY);
    }

    /// chrony `NCR_ModifyMaxdelayratio`.
    pub fn modify_max_delay_ratio(&mut self, new_max_delay_ratio: f64) {
        self.max_delay_ratio = clamp(0.0, new_max_delay_ratio, MAX_MAXDELAYRATIO);
    }

    /// chrony `NCR_ModifyMaxdelaydevratio`.
    pub fn modify_max_delay_dev_ratio(&mut self, new_max_delay_dev_ratio: f64) {
        self.max_delay_dev_ratio = clamp(0.0, new_max_delay_dev_ratio, MAX_MAXDELAYDEVRATIO);
    }

    /// chrony `NCR_ModifyMinstratum`: set directly (no clamp).
    pub fn modify_min_stratum(&mut self, new_min_stratum: i32) {
        self.min_stratum = new_min_stratum;
    }

    /// chrony `NCR_ModifyPolltarget`: floored at 1.
    pub fn modify_poll_target(&mut self, new_poll_target: i32) {
        self.poll_target = new_poll_target.max(1);
    }
}

#[cfg(test)]
mod tests;
