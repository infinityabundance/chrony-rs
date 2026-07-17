//! NTP response-sample corrections — `ntp_core.c` Stage 4 (`apply_net_correction`).
//!
//! [`apply_net_correction`] is chrony's PTP-transparent-clock correction: when both
//! the receive and transmit directions carry network-correction data (from PTP
//! transparent clocks, via the experimental net-correction extension field), it
//! adjusts the sample's offset and peer delay to approximate a direct connection to
//! the server, keeping a small uncorrected margin so up-to-100-ppm-fast transparent
//! clocks cannot over-correct. The correction is unauthenticated, so it is gated by a
//! sanity check.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness (the static `apply_net_correction` reached directly): samples with
//! present/absent/insane corrections are run and the corrected offset + peer delay
//! captured (`research/oracle/ntp_core-netcorr-c-vectors.txt`). See the tests.
//!
//! # Stage 6: the response-sample computation
//!
//! [`compute_response_sample`] is the offset/delay/dispersion arithmetic at the heart of
//! `NCR_ProcessResponse`: from the four timestamps of an NTP exchange (server receive +
//! transmit, our transmit + receive) it derives the clock offset, the round-trip peer
//! delay, the peer dispersion (precision + skew × measurement span), and the root
//! delay/dispersion, then folds in [`apply_net_correction`]. **Scope of this stage: the
//! basic (non-interleaved) client path.** The interleaved and monotonic-root timestamp
//! selection variants are a later stage.
//!
//! It is differential-tested by reaching the **real compiled `process_response`** (with
//! `saved=1` to bypass authentication, and the validity tests configured to pass) and
//! capturing the sample chrony hands to `SRC_AccumulateSample`
//! (`research/oracle/ntp_core-sample-c-vectors.txt`).

use crate::ntp::timestamp::NtpTimestamp;
use crate::sys_generic::Timespec;

/// chrony `MAX_NET_CORRECTION_FREQ`.
const MAX_NET_CORRECTION_FREQ: f64 = 100.0e-6;

/// Seconds from the NTP epoch (1900) to the Unix epoch (1970): chrony `JAN_1970`.
const JAN_1970: i64 = 0x83aa_7e80;
/// chrony `NSEC_PER_NTP64` = `1e9 / 2^32`: scales an NTP 32-bit fraction to nanoseconds.
const NSEC_PER_NTP64: f64 = 4.294_967_296;

/// chrony `UTI_Ntp64ToTimespec` (default build: no era split, 64-bit `time_t`). The
/// nanosecond field is truncated toward zero exactly as the C `(long)` cast.
fn ntp64_to_timespec(ts: NtpTimestamp) -> Timespec {
    if ts.to_bits() == 0 {
        return Timespec::new(0, 0);
    }
    Timespec::new(
        ts.seconds() as i64 - JAN_1970,
        (ts.fraction() as f64 / NSEC_PER_NTP64) as i64,
    )
}

/// The sample [`compute_response_sample`] produces, matching chrony's `NTP_Sample`
/// (the subset computed from a response). `time` is the local epoch midway through the
/// measurement.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResponseSample {
    pub offset: f64,
    pub peer_delay: f64,
    pub peer_dispersion: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub time: Timespec,
}

/// chrony `NCR_ProcessResponse` sample arithmetic (basic, non-interleaved client path).
///
/// `remote_receive` / `remote_transmit` are the server's receive/transmit timestamps
/// from the response; `local_transmit` / `local_receive` are our transmit/receive
/// timestamps with their error bounds. `message_precision` is the server's advertised
/// precision (signed log2 seconds); `sys_precision` is our system precision as a quantum
/// (`LCL_GetSysPrecisionAsQuantum`). `source_freq_lo`/`hi` bound the estimated frequency
/// (their half-range is the skew); `offset_correction` is the configured correction;
/// `root_delay`/`root_dispersion` are the packet's (already converted to seconds). The
/// `*_net_correction` / `rx_duration` inputs feed [`apply_net_correction`] (zero on the
/// basic path).
#[allow(clippy::too_many_arguments)]
pub fn compute_response_sample(
    remote_receive: NtpTimestamp,
    remote_transmit: NtpTimestamp,
    local_transmit: Timespec,
    local_transmit_err: f64,
    local_receive: Timespec,
    local_receive_err: f64,
    message_precision: i32,
    sys_precision: f64,
    source_freq_lo: f64,
    source_freq_hi: f64,
    offset_correction: f64,
    root_delay: f64,
    root_dispersion: f64,
    rx_net_correction: f64,
    rx_rx_duration: f64,
    tx_net_correction: f64,
) -> ResponseSample {
    let remote_receive = ntp64_to_timespec(remote_receive);
    let remote_transmit = ntp64_to_timespec(remote_transmit);

    // Intervals between the remote and local timestamp pairs.
    let (remote_average, remote_interval) = remote_receive.average_diff(remote_transmit);
    let (local_average, local_interval) = local_transmit.average_diff(local_receive);

    let precision = sys_precision + crate::util::log2_to_double(message_precision);

    // Round-trip peer delay, floored at the clock precision.
    let mut peer_delay = (local_interval - remote_interval).abs();
    if peer_delay < precision {
        peer_delay = precision;
    }

    // Offset (NTP sign: negative if we are fast of the source), plus configured correction.
    let offset = remote_average.diff_to_double(local_average) + offset_correction;

    // The sample's time is midway through our measurement period.
    let time = local_average;

    let skew = (source_freq_hi - source_freq_lo) / 2.0;
    let peer_dispersion =
        precision.max(local_transmit_err.max(local_receive_err)) + skew * local_interval.abs();

    // Root delay/dispersion include the peer values; they are NOT touched by the net
    // correction (chrony keeps the estimated maximum error).
    let sample_root_delay = root_delay + peer_delay;
    let sample_root_dispersion = root_dispersion + peer_dispersion;

    let corrected = apply_net_correction(
        offset,
        peer_delay,
        rx_net_correction,
        rx_rx_duration,
        tx_net_correction,
        precision,
    );

    ResponseSample {
        offset: corrected.offset,
        peer_delay: corrected.peer_delay,
        peer_dispersion,
        root_delay: sample_root_delay,
        root_dispersion: sample_root_dispersion,
        time,
    }
}

/// The outcome of [`apply_net_correction`]: the (possibly) adjusted offset + peer
/// delay. When no correction applies, the inputs are returned unchanged.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CorrectedSample {
    pub offset: f64,
    pub peer_delay: f64,
}

/// chrony `MAX_INTERLEAVED_L2L_RATIO`.
const MAX_INTERLEAVED_L2L_RATIO: f64 = 0.1;

/// chrony `NCR_ProcessResponse` sample arithmetic for the **interleaved** client path.
///
/// Interleaved mode differs from the basic path only in *which* timestamps and root
/// values feed the sample: when a previous local transmit timestamp is available and
/// using it makes the local-to-local interval significantly shorter (the
/// `MAX_INTERLEAVED_L2L_RATIO` test), chrony prefers the previous transmit and the
/// source's last receive timestamp (with the remote root delay/dispersion); otherwise it
/// uses the current exchange (with `MAX` of the packet and remote roots). The local
/// receive timestamp is always the instance's stored `local_rx`. The selected timestamps
/// then flow through [`compute_response_sample`].
///
/// `prev_local_tx_is_zero` is chrony's `UTI_IsZeroTimespec(&prev_local_tx)`. (The
/// monotonic-root correction is assumed absent here, matching the basic-path scope.)
#[allow(clippy::too_many_arguments)]
pub fn compute_interleaved_response_sample(
    message_receive: NtpTimestamp,
    message_transmit: NtpTimestamp,
    remote_ntp_rx: NtpTimestamp,
    prev_local_tx: Timespec,
    prev_local_tx_err: f64,
    prev_local_tx_is_zero: bool,
    local_tx: Timespec,
    local_tx_err: f64,
    local_rx: Timespec,
    local_rx_err: f64,
    message_precision: i32,
    sys_precision: f64,
    source_freq_lo: f64,
    source_freq_hi: f64,
    offset_correction: f64,
    pkt_root_delay: f64,
    pkt_root_dispersion: f64,
    remote_root_delay: f64,
    remote_root_dispersion: f64,
) -> ResponseSample {
    // Prefer the previous local TX / remote RX timestamps when they make the measured
    // local interval significantly shorter (improves the delay accuracy).
    let prefer_prev = !prev_local_tx_is_zero
        && MAX_INTERLEAVED_L2L_RATIO * local_tx.diff_to_double(local_rx)
            > local_rx.diff_to_double(prev_local_tx);

    let (remote_receive, local_transmit, local_transmit_err, root_delay, root_dispersion) =
        if prefer_prev {
            (remote_ntp_rx, prev_local_tx, prev_local_tx_err, remote_root_delay, remote_root_dispersion)
        } else {
            (
                message_receive,
                local_tx,
                local_tx_err,
                pkt_root_delay.max(remote_root_delay),
                pkt_root_dispersion.max(remote_root_dispersion),
            )
        };

    compute_response_sample(
        remote_receive,
        message_transmit,
        local_transmit,
        local_transmit_err,
        local_rx,
        local_rx_err,
        message_precision,
        sys_precision,
        source_freq_lo,
        source_freq_hi,
        offset_correction,
        root_delay,
        root_dispersion,
        0.0,
        0.0,
        0.0,
    )
}

/// chrony `apply_net_correction`: adjust `offset`/`peer_delay` using the PTP
/// transparent-clock corrections carried in the RX and TX timestamps. `rx_net_correction`
/// / `tx_net_correction` are the accumulated transparent-clock residence times,
/// `rx_rx_duration` the local receive duration, `precision` the clock precision.
pub fn apply_net_correction(
    offset: f64,
    peer_delay: f64,
    rx_net_correction: f64,
    rx_rx_duration: f64,
    tx_net_correction: f64,
    precision: f64,
) -> CorrectedSample {
    let unchanged = CorrectedSample { offset, peer_delay };

    // Require correction in both directions (not just the local RX correction).
    if rx_net_correction <= rx_rx_duration || tx_net_correction <= 0.0 {
        return unchanged;
    }

    let rx_correction = rx_net_correction - rx_rx_duration;
    let tx_correction = tx_net_correction - rx_rx_duration;

    // Keep a small margin so up-to-100-ppm-fast transparent clocks don't overcorrect.
    let low_delay_correction = (rx_correction + tx_correction) * (1.0 - MAX_NET_CORRECTION_FREQ);

    // The corrections are not authenticated: sanity-check before applying.
    if low_delay_correction < 0.0 || low_delay_correction > peer_delay {
        return unchanged;
    }

    let mut s = CorrectedSample {
        offset: offset + (rx_correction - tx_correction) / 2.0,
        peer_delay: peer_delay - low_delay_correction,
    };
    if s.peer_delay < precision {
        s.peer_delay = precision;
    }
    s
}

#[cfg(test)]
mod tests;
