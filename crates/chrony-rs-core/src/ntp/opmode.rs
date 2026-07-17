//! NTP source operating-mode state machine — `ntp_core.c` Stage 12 (`set_connectivity`,
//! `NCR_IncrementActivityCounters`, the online-change predicate).
//!
//! A source's [`OperatingMode`] tracks whether chrony is actively polling it
//! (online/offline) and whether an initial burst is in progress. chronyc's `online` /
//! `offline` commands drive [`set_connectivity`]; `chronyc activity` tallies sources by
//! mode via [`increment_activity_counters`].
//!
//! # Adaptation (documented, not silent)
//!
//! chrony's `set_connectivity` performs side effects for the online/offline transitions
//! (resetting the instance + arming the initial timeout when going online, and tearing
//! the source down when going offline). Those touch the scheduler, the source registry,
//! and sockets — all host boundaries here — so [`set_connectivity`] is a pure transition
//! that returns the new mode plus the [`ConnectivityAction`] the caller must carry out.
//! `SRC_MAYBE_ONLINE` is resolved to online/offline by the host (chrony's
//! `NIO_IsServerConnectable`) before calling.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness: the full `set_connectivity` transition table is exercised (the resulting
//! `opmode` observed, the action witnessed by the `SRC_SetActive`/`SRC_UnsetActive`
//! stubs) and `NCR_IncrementActivityCounters` is run for every mode
//! (`research/oracle/ntp_core-opmode-c-vectors.txt`). See the tests.

/// chrony `OperatingMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum OperatingMode {
    Offline = 0,
    Online = 1,
    BurstWasOffline = 2,
    BurstWasOnline = 3,
}

/// The resolved connectivity request (chrony `SRC_Connectivity` after `MAYBE_ONLINE`
/// resolution).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum Connectivity {
    Offline,
    Online,
}

/// The host-boundary side effect a [`set_connectivity`] transition requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum ConnectivityAction {
    /// No side effect.
    None,
    /// Going online from offline: reset the instance, arm the initial timeout, and (when
    /// `auto_iburst`) initiate a sample burst.
    GoOnline { auto_iburst: bool },
    /// Going offline from online: tear the source down (`take_offline`).
    TakeOffline,
}

/// chrony `set_connectivity`: the pure operating-mode transition for a connectivity
/// request. Returns the new mode and the side effect the caller must perform. `connectivity`
/// is the already-resolved online/offline request; `auto_iburst` is the instance's config.
pub fn set_connectivity(
    opmode: OperatingMode,
    connectivity: Connectivity,
    auto_iburst: bool,
) -> (OperatingMode, ConnectivityAction) {
    use ConnectivityAction::*;
    use OperatingMode::*;
    match connectivity {
        Connectivity::Online => match opmode {
            Online => (Online, None),
            Offline => (Online, GoOnline { auto_iburst }),
            BurstWasOnline => (BurstWasOnline, None),
            BurstWasOffline => (BurstWasOnline, None),
        },
        Connectivity::Offline => match opmode {
            Online => (Offline, TakeOffline),
            Offline => (Offline, None),
            BurstWasOnline => (BurstWasOffline, None),
            BurstWasOffline => (BurstWasOffline, None),
        },
    }
}

/// chrony `NCR_SetConnectivity`'s online-change test: whether an important
/// online↔offline change occurred between two modes (used to log it).
pub fn online_changed(prev: OperatingMode, now: OperatingMode) -> bool {
    fn is_online(m: OperatingMode) -> bool {
        matches!(m, OperatingMode::Online | OperatingMode::BurstWasOnline)
    }
    is_online(prev) != is_online(now)
}

/// The four `chronyc activity` source tallies (`NCR_IncrementActivityCounters` targets).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivityCounters {
    pub online: i32,
    pub offline: i32,
    pub burst_online: i32,
    pub burst_offline: i32,
}

/// chrony `NCR_IncrementActivityCounters`: bump the counter for this source's mode.
pub fn increment_activity_counters(opmode: OperatingMode, c: &mut ActivityCounters) {
    match opmode {
        OperatingMode::BurstWasOffline => c.burst_offline += 1,
        OperatingMode::BurstWasOnline => c.burst_online += 1,
        OperatingMode::Online => c.online += 1,
        OperatingMode::Offline => c.offline += 1,
    }
}

#[cfg(test)]
mod tests;
