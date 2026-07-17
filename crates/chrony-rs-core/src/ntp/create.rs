//! NTP source instance configuration — `ntp_core.c` Stage 13 (`NCR_CreateInstance`
//! parameter mapping).
//!
//! When chrony processes a `server`/`peer` directive (or `chronyc add`), it builds a new
//! per-source instance from the configured [`SourceParameters`]. [`create_instance_config`]
//! ports the parameter→field mapping at the heart of `NCR_CreateInstance`: the
//! client/active mode from the source type, the poll-interval defaults and clamps, the
//! min-stratum cap, the peer presend handling, the delay-limit clamps, the
//! copy-only-for-clients rule, the poll-target floor, and the NTP version selection.
//!
//! # Adaptation (documented, not silent)
//!
//! `NCR_CreateInstance` also allocates the instance and creates the authentication,
//! source-registry, delay-quantile, and median-filter sub-instances — all host-boundary
//! resources here, handled by the caller. The version selection's "no ext fields / not
//! interleaved" branch reads the suggested version from the (auth) NAU instance
//! (`NAU_GetSuggestedNtpVersion`); that value is passed in as `suggested_version`.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness: an instance is built from each parameter set and the mapped fields captured
//! (`research/oracle/ntp_core-create-c-vectors.txt`). See the tests.

/// chrony `MIN_POLL` / `MAX_POLL` and the source defaults.
const MIN_POLL: i32 = -7;
const MAX_POLL: i32 = 24;
const SRC_DEFAULT_MINPOLL: i32 = 6;
const SRC_DEFAULT_MAXPOLL: i32 = 10;
/// chrony `NTP_MAX_STRATUM`.
const NTP_MAX_STRATUM: i32 = 16;
/// chrony `NTP_VERSION` / `NTP_MIN_COMPAT_VERSION`.
const NTP_VERSION: i32 = 4;
const NTP_MIN_COMPAT_VERSION: i32 = 1;
/// chrony `MAX_MAXDELAY`, `MAX_MAXDELAYRATIO`, `MAX_MAXDELAYDEVRATIO`.
const MAX_MAXDELAY: f64 = 1.0e3;
const MAX_MAXDELAYRATIO: f64 = 1.0e6;
const MAX_MAXDELAYDEVRATIO: f64 = 1.0e6;

/// chrony `MODE_CLIENT` / `MODE_ACTIVE`.
const MODE_CLIENT: i32 = 3;
const MODE_ACTIVE: i32 = 1;

fn clamp(lo: f64, x: f64, hi: f64) -> f64 {
    if x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

/// chrony `NTP_Source_Type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum SourceType {
    Server,
    Peer,
}

/// The subset of chrony `SourceParameters` that [`create_instance_config`] maps to
/// instance fields. (Fields consumed only by the host-boundary resource creation — auth
/// keys, NTS, sample counts, etc. — are omitted.)
#[derive(Clone, Copy, Debug)]
pub struct SourceParameters {
    pub minpoll: i32,
    pub maxpoll: i32,
    pub min_stratum: i32,
    pub presend_minpoll: i32,
    pub poll_target: i32,
    pub version: i32,
    pub interleaved: bool,
    pub ext_fields: i32,
    pub copy: bool,
    pub iburst: bool,
    pub burst: bool,
    pub auto_offline: bool,
    pub max_delay: f64,
    pub max_delay_ratio: f64,
    pub max_delay_dev_ratio: f64,
    pub offset: f64,
}

/// The instance fields produced from the configuration (chrony `NCR_Instance_Record`
/// subset).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InstanceConfig {
    pub mode: i32,
    pub interleaved: bool,
    pub minpoll: i32,
    pub maxpoll: i32,
    pub min_stratum: i32,
    pub presend_minpoll: i32,
    pub max_delay: f64,
    pub max_delay_ratio: f64,
    pub max_delay_dev_ratio: f64,
    pub offset_correction: f64,
    pub auto_iburst: bool,
    pub auto_burst: bool,
    pub auto_offline: bool,
    pub copy: bool,
    pub poll_target: i32,
    pub ext_field_flags: i32,
    pub version: i32,
}

/// chrony `NCR_CreateInstance` parameter mapping: derive the instance fields from the
/// source `type`, the configured `params`, and the auth-`suggested_version`.
pub fn create_instance_config(
    source_type: SourceType,
    params: &SourceParameters,
    suggested_version: i32,
) -> InstanceConfig {
    let mode = match source_type {
        SourceType::Server => MODE_CLIENT,
        SourceType::Peer => MODE_ACTIVE,
    };

    // minpoll: default when below range, cap at MAX_POLL.
    let mut minpoll = params.minpoll;
    if minpoll < MIN_POLL {
        minpoll = SRC_DEFAULT_MINPOLL;
    } else if minpoll > MAX_POLL {
        minpoll = MAX_POLL;
    }

    // maxpoll: default when below range, cap at MAX_POLL, never below minpoll.
    let mut maxpoll = params.maxpoll;
    if maxpoll < MIN_POLL {
        maxpoll = SRC_DEFAULT_MAXPOLL;
    } else if maxpoll > MAX_POLL {
        maxpoll = MAX_POLL;
    }
    if maxpoll < minpoll {
        maxpoll = minpoll;
    }

    let mut min_stratum = params.min_stratum;
    if min_stratum >= NTP_MAX_STRATUM {
        min_stratum = NTP_MAX_STRATUM - 1;
    }

    // Presend doesn't work in symmetric mode: disable it for peers.
    let mut presend_minpoll = params.presend_minpoll;
    if presend_minpoll <= MAX_POLL && mode != MODE_CLIENT {
        presend_minpoll = MAX_POLL + 1;
    }

    let copy = params.copy && mode == MODE_CLIENT;

    // Version: extension fields / interleaved force the latest; otherwise take the
    // auth-suggested version; an explicit configured version overrides (clamped).
    let mut version = if params.ext_fields != 0 || params.interleaved {
        NTP_VERSION
    } else {
        suggested_version
    };
    if params.version != 0 {
        version = clamp(NTP_MIN_COMPAT_VERSION as f64, params.version as f64, NTP_VERSION as f64) as i32;
    }

    InstanceConfig {
        mode,
        interleaved: params.interleaved,
        minpoll,
        maxpoll,
        min_stratum,
        presend_minpoll,
        max_delay: clamp(0.0, params.max_delay, MAX_MAXDELAY),
        max_delay_ratio: clamp(0.0, params.max_delay_ratio, MAX_MAXDELAYRATIO),
        max_delay_dev_ratio: clamp(0.0, params.max_delay_dev_ratio, MAX_MAXDELAYDEVRATIO),
        offset_correction: params.offset,
        auto_iburst: params.iburst,
        auto_burst: params.burst,
        auto_offline: params.auto_offline,
        copy,
        poll_target: params.poll_target.max(1),
        ext_field_flags: params.ext_fields,
        version,
    }
}

#[cfg(test)]
mod tests;
