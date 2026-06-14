//! Offset/delay measurement from a four-timestamp NTP exchange (RFC 5905 §8).
//!
//! A client/server exchange yields four instants:
//!
//! ```text
//!   T1  origin     — client transmit time     (we sent the request)
//!   T2  receive    — server receive time       (server got it)
//!   T3  transmit   — server transmit time       (server replied)
//!   T4  destination — client receive time       (we got the reply, local)
//! ```
//!
//! From these, RFC 5905 (and chrony, which follows the same algebra) computes:
//!
//! ```text
//!   offset θ = ((T2 - T1) + (T3 - T4)) / 2
//!   delay  δ = (T4 - T1) - (T3 - T2)
//! ```
//!
//! `offset` is how far ahead the server's clock is of ours (positive ⇒ server
//! ahead). `delay` is the round-trip network delay with server processing time
//! removed.
//!
//! # The era/wrap trap (do not "simplify" the subtraction)
//!
//! NTP timestamps are 64-bit fixed point (32.32) whose seconds field wraps every
//! ~136 years. We therefore never convert a *timestamp* to absolute seconds and
//! subtract — that loses precision and breaks at the era boundary. Instead we
//! subtract the raw 64-bit values with wrapping arithmetic and reinterpret the
//! result as signed. Because the four instants of one exchange are within seconds
//! of each other, the wrapping difference is exact even when the exchange straddles
//! an era rollover. This is the same reason chrony works in differences, not
//! absolute NTP time, at this layer. Changing this to f64-of-absolute-seconds would
//! reintroduce the bug; if you think you can, re-derive the 2036 rollover first.

use super::timestamp::{NtpShort, NtpTimestamp};
use crate::sources::source::SampleSummary;

/// Units of one NTP fraction step: 2^-32 seconds. Used to scale a raw 64-bit
/// difference back into seconds.
const FRAC_PER_SEC: f64 = 4_294_967_296.0; // 2^32

/// The result of one measurement.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Measurement {
    /// Clock offset in seconds (positive ⇒ remote clock ahead of local).
    pub offset: f64,
    /// Round-trip delay in seconds (network + server processing removed).
    pub delay: f64,
}

/// Signed difference `a - b` of two NTP timestamps, in seconds.
///
/// Computed by wrapping the raw 64-bit values and reinterpreting as `i64`, so a
/// small true difference is recovered correctly even across an era boundary.
pub fn ts_diff_seconds(a: NtpTimestamp, b: NtpTimestamp) -> f64 {
    let raw = a.to_bits().wrapping_sub(b.to_bits()) as i64;
    raw as f64 / FRAC_PER_SEC
}

impl Measurement {
    /// Compute offset and delay from the four exchange timestamps.
    pub fn from_exchange(
        t1_origin: NtpTimestamp,
        t2_receive: NtpTimestamp,
        t3_transmit: NtpTimestamp,
        t4_destination: NtpTimestamp,
    ) -> Measurement {
        let t2_t1 = ts_diff_seconds(t2_receive, t1_origin);
        let t3_t4 = ts_diff_seconds(t3_transmit, t4_destination);
        let t4_t1 = ts_diff_seconds(t4_destination, t1_origin);
        let t3_t2 = ts_diff_seconds(t3_transmit, t2_receive);

        Measurement {
            offset: (t2_t1 + t3_t4) / 2.0,
            // RFC note: with very low delay and coarse timestamp resolution, δ can
            // come out slightly negative. We return the raw value here; clamping to
            // a non-negative floor is a *policy* decision (chrony bounds it by the
            // clock precision) and belongs in the filter stage, not in the algebra.
            delay: t4_t1 - t3_t2,
        }
    }

    /// Turn a measurement into a [`SampleSummary`] for the selector, folding the
    /// server's advertised root delay/dispersion together with this hop's measured
    /// delay. chrony accumulates the path: a source's root delay includes the
    /// server's root delay plus the measured round-trip; its root dispersion
    /// includes the server's plus local error terms.
    ///
    /// We model the well-understood part — `root_delay = server_root_delay + δ`,
    /// `root_dispersion = server_root_dispersion` — and leave the local error
    /// budget (precision, frequency error × age) to the filter stage, where it is
    /// time-dependent. This is intentionally a *floor* on dispersion, not chrony's
    /// full budget; see `docs/filtering-atlas.md`.
    pub fn to_sample_summary(
        &self,
        server_root_delay: NtpShort,
        server_root_dispersion: NtpShort,
    ) -> SampleSummary {
        SampleSummary {
            offset: self.offset,
            root_delay: server_root_delay.as_seconds_f64() + self.delay,
            root_dispersion: server_root_dispersion.as_seconds_f64(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an NTP timestamp from era-relative seconds (with fraction). Test-only;
    /// the wire type stays free of lossy float constructors.
    fn ts(secs: f64) -> NtpTimestamp {
        let whole = secs.trunc() as u64;
        let frac = (secs.fract() * FRAC_PER_SEC).round() as u64;
        NtpTimestamp::from_bits((whole << 32) | (frac & 0xFFFF_FFFF))
    }

    #[test]
    fn symmetric_exchange_recovers_offset_and_delay() {
        // Construct an exchange with true offset O=0.5s and one-way delay d=0.1s.
        // T1=100.0, T2=100.6, T3=100.6, T4=100.2 (derived in the module reasoning).
        let m = Measurement::from_exchange(ts(100.0), ts(100.6), ts(100.6), ts(100.2));
        assert!((m.offset - 0.5).abs() < 1e-6, "offset was {}", m.offset);
        assert!((m.delay - 0.2).abs() < 1e-6, "delay was {}", m.delay);
    }

    #[test]
    fn zero_offset_zero_delay() {
        let m = Measurement::from_exchange(ts(50.0), ts(50.0), ts(50.0), ts(50.0));
        assert!(m.offset.abs() < 1e-9);
        assert!(m.delay.abs() < 1e-9);
    }

    #[test]
    fn negative_offset_when_local_clock_is_ahead() {
        // Local clock ahead by 0.3s, delay 0.1s (d=0.05 each way).
        // server = client - 0.3. T1=200.0; server recv at client 200.05 → T2=199.75;
        // T3=199.75; T4=200.10.
        let m = Measurement::from_exchange(ts(200.0), ts(199.75), ts(199.75), ts(200.10));
        assert!((m.offset - (-0.3)).abs() < 1e-6, "offset was {}", m.offset);
        assert!((m.delay - 0.1).abs() < 1e-6, "delay was {}", m.delay);
    }

    #[test]
    fn difference_is_correct_across_era_rollover() {
        // a is just after the era wrap (seconds = 1), b just before (seconds near
        // 2^32-1). True difference: 2 seconds forward.
        let b = NtpTimestamp::from_bits(0xFFFF_FFFFu64 << 32); // secs = 2^32-1, frac 0
        let a = NtpTimestamp::from_bits((1u64) << 32); // secs = 1 in the next era
        // (1) - (2^32 - 1) with 32-bit-seconds wrap = 2 seconds.
        assert!((ts_diff_seconds(a, b) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn measurement_feeds_a_sample_summary() {
        let m = Measurement::from_exchange(ts(100.0), ts(100.6), ts(100.6), ts(100.2));
        // Server advertises 4ms root delay, 2ms root dispersion.
        let rd = NtpShort::from_bits((0.004 * 65536.0) as u32);
        let rdisp = NtpShort::from_bits((0.002 * 65536.0) as u32);
        let s = m.to_sample_summary(rd, rdisp);
        assert!((s.offset - 0.5).abs() < 1e-6);
        // root_delay = server 0.004 + measured 0.2.
        assert!((s.root_delay - 0.204).abs() < 1e-3, "root_delay {}", s.root_delay);
    }
}
