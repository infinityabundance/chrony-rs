//! NTP response-sample acceptance gate — `ntp_core.c` Stage 15 (`process_response`
//! test A, client path).
//!
//! Test A is the first of the four additional tests a response must pass (B/C/D are the
//! delay-ratio / delay-dev-ratio / sync-loop tests already ported in
//! [`crate::ntp::poll`] and [`crate::ntp::sync`]). For a **client** source it requires
//! that:
//!
//! 1. the minimum estimate of the peer delay is within the configured maximum
//!    (`peer_delay − peer_dispersion ≤ max_delay`),
//! 2. the clock precision itself is within that maximum,
//! 3. this is not a `presend` warm-up exchange,
//! 4. the server's processing time is sane (`response_time ≤ MAX_SERVER_INTERVAL`),
//! 5. and, in interleaved mode, that the response is not the first interleaved one that
//!    would reuse the basic-mode timestamps (which would give a misleading delay).
//!
//! The symmetric-active variant ([`passes_test_a_active`]) replaces the client-only checks
//! with the interleaved "missed response" checks.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`**: with tests B/C/D
//! forced to pass, `good_packet == testA`, so the gate is observed by whether
//! `process_response` accumulates a sample. Each condition is failed in turn and the
//! outcome captured (`research/oracle/ntp_core-testa-c-vectors.txt`). See the tests.

/// chrony `MAX_SERVER_INTERVAL`.
const MAX_SERVER_INTERVAL: f64 = 4.0;

/// chrony `process_response` test A for a client source. `presend_done` is the instance's
/// presend counter; `response_time` the server's measured processing time. The
/// `interleaved` / `prev_local_tx_zero` / `local_transmit_is_local_tx` inputs gate the
/// interleaved-reuse rejection (condition 5); pass `interleaved = false` for the basic
/// path.
#[allow(clippy::too_many_arguments)]
pub fn passes_test_a_client(
    peer_delay: f64,
    peer_dispersion: f64,
    precision: f64,
    max_delay: f64,
    presend_done: i32,
    response_time: f64,
    interleaved: bool,
    prev_local_tx_zero: bool,
    local_transmit_is_local_tx: bool,
) -> bool {
    peer_delay - peer_dispersion <= max_delay
        && precision <= max_delay
        && presend_done <= 0
        && response_time < MAX_SERVER_INTERVAL
        // Reject the first interleaved response that would reuse the basic-mode timestamps.
        && !(interleaved && prev_local_tx_zero && local_transmit_is_local_tx)
}

/// chrony `process_response` test A for a **symmetric-active** (`MODE_ACTIVE`) source. The
/// common gate (peer-delay, precision, presend) is the same as the client variant, but the
/// client-only checks (server processing time, basic-mode reuse) do not apply; instead, in
/// interleaved mode, a "missed response" is rejected when any of three hold:
///
/// 1. the peer delay exceeds half the assumed minimum remote poll interval,
/// 2. the receive timestamp is not strictly after the transmit timestamp
///    (`CompareNtp64(receive, transmit) <= 0`),
/// 3. the remote poll is no larger than our previous local poll *and* the gap between this
///    and the previous remote transmit exceeds 1.5× the assumed interval.
///
/// `prev_remote_poll_interval` is `UTI_Log2ToDouble(min(remote_poll, prev_local_poll))`,
/// computed here. `receive_ts`/`transmit_ts` are host-order `(hi, lo)` packed as `u64`;
/// `remote_transmit`/`prev_remote_transmit` are `(sec, nsec)` timespecs.
#[allow(clippy::too_many_arguments)]
pub fn passes_test_a_active(
    peer_delay: f64,
    peer_dispersion: f64,
    precision: f64,
    max_delay: f64,
    presend_done: i32,
    interleaved: bool,
    receive_ts: u64,
    transmit_ts: u64,
    remote_poll: i32,
    prev_local_poll: i32,
    remote_transmit: (i64, i64),
    prev_remote_transmit: (i64, i64),
) -> bool {
    let common = peer_delay - peer_dispersion <= max_delay
        && precision <= max_delay
        && presend_done <= 0;

    // chrony: UTI_Log2ToDouble(MIN(remote_poll, prev_local_poll)).
    let prev_remote_poll_interval = crate::util::log2_to_double(remote_poll.min(prev_local_poll));
    let cmp = crate::util::compare_ntp64(
        (receive_ts >> 32) as u32,
        receive_ts as u32,
        (transmit_ts >> 32) as u32,
        transmit_ts as u32,
    );
    let missed = interleaved
        && (peer_delay > 0.5 * prev_remote_poll_interval
            || cmp <= 0
            || (remote_poll <= prev_local_poll
                && crate::util::diff_timespecs_to_double(remote_transmit, prev_remote_transmit)
                    > 1.5 * prev_remote_poll_interval));

    common && !missed
}

#[cfg(test)]
mod tests;
