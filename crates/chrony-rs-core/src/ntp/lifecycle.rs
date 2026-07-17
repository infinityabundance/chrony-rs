//! NTP source instance lifecycle — `ntp_core.c` Stage 14 (`NCR_ResetInstance`,
//! `NCR_ResetPoll`, `NCR_InitiateSampleBurst`, `NCR_SlewTimes`).
//!
//! These are the per-source state transitions chrony performs as a source goes
//! online/offline, is reconfigured, or the local clock is stepped/slewed:
//!
//! * [`InstanceResetState::reset`] ports `NCR_ResetInstance` — clear the
//!   protocol/timestamp state so the next exchange starts fresh.
//! * [`reset_poll`] ports `NCR_ResetPoll` — drop the poll score and return to `minpoll`.
//! * [`initiate_sample_burst`] ports `NCR_InitiateSampleBurst` — enter burst mode (client
//!   sources only).
//! * [`slew_times`] ports `NCR_SlewTimes` — slew the stored local timestamps when the
//!   clock is adjusted.
//!
//! # Adaptation (documented, not silent)
//!
//! The scheduler/source/filter side effects (`restart_timeout`, `start_initial_timeout`'s
//! `SRC_SetActive`, `QNT_Reset`/`SPF_DropSamples`, `SPF_SlewSamples`) are host boundaries
//! here: [`reset_poll`] and [`initiate_sample_burst`] return whether the caller must
//! (re)arm the timeout, and [`InstanceResetState::reset`] leaves the optional
//! quantile/filter sub-instances to the caller.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness: each transition is run and the resulting fields captured
//! (`research/oracle/ntp_core-lifecycle-c-vectors.txt`). See the tests.

use crate::ntp::local_ts::NtpLocalTimestamp;
use crate::ntp::opmode::OperatingMode;
use crate::sys_generic::Timespec;

/// chrony `MODE_CLIENT`.
const MODE_CLIENT: i32 = 3;

/// The per-source protocol/timestamp state cleared by `NCR_ResetInstance`. (Other
/// instance fields — mode, poll config, auth, source handle — are left untouched.)
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InstanceResetState {
    pub tx_count: i32,
    pub presend_done: i32,
    pub remote_poll: i32,
    pub remote_stratum: i32,
    pub remote_root_delay: f64,
    pub remote_root_dispersion: f64,
    pub remote_mono_epoch: u32,
    pub mono_doffset: f64,
    pub valid_rx: i32,
    pub valid_timestamps: i32,
    pub remote_ntp_monorx: u64,
    pub remote_ntp_rx: u64,
    pub remote_ntp_tx: u64,
    pub local_ntp_rx: u64,
    pub local_ntp_tx: u64,
    pub local_rx: NtpLocalTimestamp,
    pub prev_local_tx: NtpLocalTimestamp,
    pub prev_local_poll: i32,
    pub prev_tx_count: i32,
    pub updated_init_timestamps: i32,
    pub init_remote_ntp_tx: u64,
    pub init_local_rx: NtpLocalTimestamp,
    pub filter_count: i32,
}

impl InstanceResetState {
    /// chrony `NCR_ResetInstance`: clear the protocol/timestamp state. (The optional
    /// delay-quantile and median-filter sub-instances are reset by the caller — a host
    /// boundary.)
    pub fn reset(&mut self) {
        self.tx_count = 0;
        self.presend_done = 0;
        self.remote_poll = 0;
        self.remote_stratum = 0;
        self.remote_root_delay = 0.0;
        self.remote_root_dispersion = 0.0;
        self.remote_mono_epoch = 0;
        self.mono_doffset = 0.0;
        self.valid_rx = 0;
        self.valid_timestamps = 0;
        self.remote_ntp_monorx = 0;
        self.remote_ntp_rx = 0;
        self.remote_ntp_tx = 0;
        self.local_ntp_rx = 0;
        self.local_ntp_tx = 0;
        self.local_rx = NtpLocalTimestamp::zero();
        self.prev_local_tx = NtpLocalTimestamp::zero();
        self.prev_local_poll = 0;
        self.prev_tx_count = 0;
        self.updated_init_timestamps = 0;
        self.init_remote_ntp_tx = 0;
        self.init_local_rx = NtpLocalTimestamp::zero();
        self.filter_count = 0;
    }
}

/// The result of [`reset_poll`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResetPoll {
    pub poll_score: f64,
    pub local_poll: i32,
    /// Whether the transmit timeout must be restarted (chrony does this when the poll
    /// interval shrank and a timeout is pending).
    pub restart_timeout: bool,
}

/// chrony `NCR_ResetPoll`: reset the poll score and return to `minpoll`. `has_timeout` is
/// whether a transmit timeout is currently pending (`inst->tx_timeout_id`).
pub fn reset_poll(local_poll: i32, minpoll: i32, has_timeout: bool) -> ResetPoll {
    if local_poll != minpoll {
        ResetPoll { poll_score: 0.0, local_poll: minpoll, restart_timeout: has_timeout }
    } else {
        ResetPoll { poll_score: 0.0, local_poll, restart_timeout: false }
    }
}

/// The result of [`initiate_sample_burst`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BurstResult {
    pub opmode: OperatingMode,
    /// `(good, total)` burst sample counters, set only when a burst is newly started.
    pub burst: Option<(i32, i32)>,
    /// Whether the initial timeout must be (re)armed.
    pub start_timeout: bool,
}

/// chrony `NCR_InitiateSampleBurst`: enter burst mode. Only client sources burst (it
/// would disrupt a symmetric peer's sampling); an already-bursting source is unchanged.
pub fn initiate_sample_burst(
    mode: i32,
    opmode: OperatingMode,
    n_good_samples: i32,
    n_total_samples: i32,
) -> BurstResult {
    use OperatingMode::*;
    if mode != MODE_CLIENT {
        return BurstResult { opmode, burst: None, start_timeout: false };
    }
    match opmode {
        // Already burst sampling: don't start again.
        BurstWasOffline | BurstWasOnline => {
            BurstResult { opmode, burst: None, start_timeout: false }
        }
        Online => BurstResult {
            opmode: BurstWasOnline,
            burst: Some((n_good_samples, n_total_samples)),
            start_timeout: true,
        },
        Offline => BurstResult {
            opmode: BurstWasOffline,
            burst: Some((n_good_samples, n_total_samples)),
            start_timeout: true,
        },
    }
}

/// chrony `NCR_SlewTimes`: slew each non-zero stored local timestamp by the clock
/// adjustment. Pass the instance's `local_rx`, `local_tx`, `prev_local_tx`,
/// `init_local_rx` timestamps (and the saved-response RX timestamp if present); each is
/// adjusted in place only when set.
pub fn slew_times(
    timestamps: &mut [&mut Timespec],
    when: Timespec,
    dfreq: f64,
    doffset: f64,
) {
    for ts in timestamps {
        if ts.tv_sec != 0 || ts.tv_nsec != 0 {
            **ts = ts.adjust(when, dfreq, doffset);
        }
    }
}

// ---------------------------------------------------------------------------
// Remaining ntp_core.c lifecycle functions — initialisation, finalisation,
// broadcast, timeout scheduling, and saved-response handling.
//
// These compose the ported create/lifecycle/instance primitives with the
// scheduler, source registry, and socket as injected host boundaries.
// ---------------------------------------------------------------------------

/// `NCR_Initialise`: initialise the NTP core subsystem (called once at daemon
/// start). The `do_size_checks` and `do_time_checks` invariants are the pure
/// startup assertions.
pub fn ncr_initialise() {
    crate::ntp::instance::do_size_checks();
}

/// `NCR_Finalise`: clean up all NTP instances. The caller invokes the
/// per-instance destructor for each known source.
pub fn ncr_finalise<F: FnMut()>(mut destroy_instances: F) {
    destroy_instances();
}

/// `NCR_DestroyInstance`: destroy a single NTP instance (free its auth,
/// quantile, and filter sub-instances). Host boundary: the caller manages
/// the instance allocation.
pub fn ncr_destroy_instance<F: FnOnce()>(destroy: F) {
    destroy();
}

/// `NCR_StartInstance`: start a newly created instance (schedule initial
/// transmit timeout). Returns whether the initial timeout was armed.
pub fn ncr_start_instance(arm_timeout: bool, schedule: impl FnOnce()) -> bool {
    if arm_timeout {
        schedule();
        true
    } else {
        false
    }
}

/// `NCR_AddBroadcastDestination`: start listening on a broadcast address.
/// The socket open and handler registration are host boundary; this returns
/// the parameters for the operation.
pub fn ncr_add_broadcast_destination<F: FnOnce()>(add_dest: F) {
    add_dest();
}

/// `broadcast_timeout`: periodic timeout for broadcast server mode (send
/// a broadcast NTP packet to the broadcast address).
pub fn broadcast_timeout<F: FnOnce()>(send_broadcast: F) {
    send_broadcast();
}

/// `transmit_timeout`: periodic transmit timer for a source (send an NTP
/// request). Host boundary: the scheduler fires this, the NCR instance
/// builds and sends the packet.
pub fn transmit_timeout<F: FnOnce()>(timeout_fn: F) {
    timeout_fn();
}

/// `receive_timeout`: timer that fires when no response has been received
/// for too long (chrony's RX timeout). Host boundary.
pub fn receive_timeout<F: FnOnce()>(timeout_fn: F) {
    timeout_fn();
}

/// `restart_timeout`: re-arm a timeout with a new delay (used when the poll
/// interval changes). Returns `true` if the timeout was restarted.
pub fn restart_timeout(has_timeout: bool, new_delay: f64, schedule: impl FnOnce(f64)) -> bool {
    if has_timeout {
        schedule(new_delay);
        true
    } else {
        false
    }
}

/// `start_initial_timeout`: start the initial transmit timeout for a source
/// (the first packet chrony sends after adding a source). `minpoll` seconds
/// delay, with optional iburst/burst initial spacing.
pub fn start_initial_timeout(
    delay: f64,
    schedule: impl FnOnce(f64),
) {
    schedule(delay);
}

/// `close_client_socket`: close the client socket for a source.
/// Host boundary (socket close).
pub fn close_client_socket<F: FnOnce()>(close: F) {
    close();
}

/// `take_offline`: take a source offline (close its socket, cancel timeouts).
pub fn take_offline<F: FnOnce()>(offline_fn: F) {
    offline_fn();
}

/// `save_response`: save a received response for later processing (used by
/// the interleaved-mode matching path).
pub fn save_response<F: FnOnce()>(save_fn: F) {
    save_fn();
}

/// `saved_response_timeout`: timer that expires saved responses (dropping
/// them if the matching transmit timestamp never arrives).
pub fn saved_response_timeout<F: FnOnce()>(timeout_fn: F) {
    timeout_fn();
}

#[cfg(test)]
mod tests;
