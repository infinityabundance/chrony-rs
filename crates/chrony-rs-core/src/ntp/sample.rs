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

/// chrony `MAX_NET_CORRECTION_FREQ`.
const MAX_NET_CORRECTION_FREQ: f64 = 100.0e-6;

/// The outcome of [`apply_net_correction`]: the (possibly) adjusted offset + peer
/// delay. When no correction applies, the inputs are returned unchanged.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CorrectedSample {
    pub offset: f64,
    pub peer_delay: f64,
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
