//! End-to-end pipeline court: NTP timestamps → measurement → sample → selection.
//!
//! This is the integration that the Stage-4 work was waiting on. Crucially, the
//! source offsets here are **computed** from four-timestamp exchanges via the
//! RFC 5905 algebra — they are not hand-written into the sources. That is the
//! whole point: with a real measurement stage we can drive selection with derived
//! values instead of fabricated ones.
//!
//! It remains an *algorithmic* court (constructed exchanges, not a captured
//! chronyd run). See docs/filtering-atlas.md and docs/source-selection-atlas.md.

use chrony_rs_core::ntp::{Measurement, NtpShort, NtpTimestamp};
use chrony_rs_core::sources::{select, Source};

/// Build an NTP timestamp from era-relative seconds with fraction.
fn ts(secs: f64) -> NtpTimestamp {
    let whole = secs.trunc() as u64;
    let frac = (secs.fract() * 4_294_967_296.0).round() as u64;
    NtpTimestamp::from_bits((whole << 32) | (frac & 0xFFFF_FFFF))
}

/// A source whose sample is derived from an exchange with the given true offset
/// and one-way delay `d`. Mirrors the algebra in the measurement module:
/// T1=base, T2=base+d+offset, T3=T2, T4=base+2d.
fn source_from_exchange(id: &str, base: f64, offset: f64, d: f64) -> Source {
    let t1 = ts(base);
    let t2 = ts(base + d + offset);
    let t3 = t2;
    let t4 = ts(base + 2.0 * d);

    let m = Measurement::from_exchange(t1, t2, t3, t4);

    let mut s = Source::new(id);
    s.stratum = 2;
    s.reach.register(true);
    // Server advertises small root delay/dispersion (4ms / 2ms).
    let rd = NtpShort::from_bits((0.004 * 65536.0) as u32);
    let rdisp = NtpShort::from_bits((0.002 * 65536.0) as u32);
    s.last_sample = Some(m.to_sample_summary(rd, rdisp));
    s
}

#[test]
fn computed_offsets_drive_falseticker_selection() {
    // Three honest servers near +0.5s, one liar at +5.0s, all with the same small
    // delay. The offsets are computed, so this exercises the real pipeline.
    let sources = vec![
        source_from_exchange("good1", 1000.0, 0.500, 0.01),
        source_from_exchange("good2", 1000.0, 0.502, 0.01),
        source_from_exchange("good3", 1000.0, 0.498, 0.01),
        source_from_exchange("liar", 1000.0, 5.000, 0.01),
    ];

    // Sanity: the computed offsets are what we expect from the exchanges.
    let liar_offset = sources[3].last_sample.unwrap().offset;
    assert!((liar_offset - 5.0).abs() < 1e-3, "computed liar offset {liar_offset}");

    let out = select(&sources);
    assert!(out.majority, "three agreeing servers form a majority");
    assert_eq!(out.truechimers, vec!["good1", "good2", "good3"]);
    assert_eq!(out.falsetickers, vec!["liar"], "the liar must be rejected");
    assert!(matches!(out.selected.as_deref(), Some("good1" | "good2" | "good3")));
}

#[test]
fn agreeing_sources_have_no_falsetickers() {
    let sources = vec![
        source_from_exchange("a", 2000.0, -0.020, 0.005),
        source_from_exchange("b", 2000.0, -0.018, 0.005),
        source_from_exchange("c", 2000.0, -0.022, 0.005),
    ];
    let out = select(&sources);
    assert!(out.majority);
    assert!(out.falsetickers.is_empty());
    assert_eq!(out.truechimers.len(), 3);
}
