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
//! The symmetric-active variant of test A (the missed-response checks) is a later stage.
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
        && response_time <= MAX_SERVER_INTERVAL
        // Reject the first interleaved response that would reuse the basic-mode timestamps.
        && !(interleaved && prev_local_tx_zero && local_transmit_is_local_tx)
}

#[cfg(test)]
mod tests;
