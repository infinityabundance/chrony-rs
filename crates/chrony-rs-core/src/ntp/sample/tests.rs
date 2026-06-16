//! Tests for `ntp_core.c` Stage 4 (`apply_net_correction`).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** The static
//! `apply_net_correction` is reached by `#include`-ing the translation unit into a C
//! generator (`/tmp/ncor/gennc.c`, the ~130-symbol external surface stubbed). An
//! `NTP_Sample` plus RX/TX `NTP_Local_Timestamp` are built and the function is called
//! in isolation across the present/absent/insane/clamp branches, capturing the
//! corrected offset + peer delay (`research/oracle/ntp_core-netcorr-c-vectors.txt`).
//! [`matches_real_c_net_correction_vectors`] replays the identical inputs and matches
//! every value.
//!
//! **Oracle #2 (independent): the gating + margin algebra.** The both-directions gate,
//! the sanity bound, and the 100-ppm margin are checked directly at their boundaries.

use super::*;

fn field(line: &str, key: &str) -> f64 {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap()
        .parse()
        .unwrap()
}
fn close(a: f64, b: f64, what: &str) {
    let tol = 1e-12 * (1.0 + a.abs().max(b.abs()));
    assert!((a - b).abs() <= tol, "{what}: rust={a:.17e} c={b:.17e}");
}

#[test]
fn matches_real_c_net_correction_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-netcorr-c-vectors.txt");
    let find = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();
    let check = |tag: &str, args: [f64; 6]| {
        let l = find(tag);
        let [offset, peer_delay, rx_net, rx_dur, tx_net, precision] = args;
        let s = apply_net_correction(offset, peer_delay, rx_net, rx_dur, tx_net, precision);
        close(s.offset, field(l, "offset"), &format!("{tag} offset"));
        close(s.peer_delay, field(l, "peer_delay"), &format!("{tag} peer_delay"));
    };

    // (offset, peer_delay, rx_net, rx_dur, tx_net, precision) — mirrors gennc.c.
    check("NC_NONE_RX", [0.001, 0.02, 0.005, 0.005, 0.01, 1e-6]);
    check("NC_NONE_TX", [0.001, 0.02, 0.01, 0.005, 0.0, 1e-6]);
    check("NC_INSANE", [0.001, 0.02, 0.5, 0.001, 0.5, 1e-6]);
    check("NC_APPLY_SYM", [0.001, 0.02, 0.01, 0.001, 0.01, 1e-6]);
    check("NC_APPLY_ASYM", [0.001, 0.05, 0.02, 0.002, 0.012, 1e-6]);
    check("NC_CLAMP", [0.0, 0.02, 0.011, 0.001, 0.011, 1e-3]);
}

#[test]
fn requires_correction_in_both_directions() {
    let base = CorrectedSample { offset: 0.001, peer_delay: 0.02 };
    // RX correction not above the local receive duration -> unchanged.
    assert_eq!(apply_net_correction(0.001, 0.02, 0.005, 0.005, 0.01, 1e-6), base, "rx gate");
    // TX correction not positive -> unchanged.
    assert_eq!(apply_net_correction(0.001, 0.02, 0.01, 0.005, 0.0, 1e-6), base, "tx gate");
    // A correction exceeding the peer delay is insane (unauthenticated) -> unchanged.
    assert_eq!(apply_net_correction(0.001, 0.02, 0.5, 0.001, 0.5, 1e-6), base, "sanity gate");
}

#[test]
fn applies_margin_and_offset_and_clamp() {
    // Symmetric correction: offset unchanged, peer_delay reduced by the 100-ppm margin.
    let s = apply_net_correction(0.001, 0.02, 0.01, 0.001, 0.01, 1e-6);
    close(s.offset, 0.001, "sym offset");
    let rx_c = 0.009;
    let tx_c = 0.009;
    close(s.peer_delay, 0.02 - (rx_c + tx_c) * (1.0 - MAX_NET_CORRECTION_FREQ), "sym delay");

    // Asymmetric correction shifts the offset by (rx_correction - tx_correction)/2.
    let s = apply_net_correction(0.001, 0.05, 0.02, 0.002, 0.012, 1e-6);
    close(s.offset, 0.001 + (0.018 - 0.010) / 2.0, "asym offset");

    // Correction drives the delay below precision -> clamped to precision.
    let s = apply_net_correction(0.0, 0.02, 0.011, 0.001, 0.011, 1e-3);
    close(s.peer_delay, 1e-3, "clamp");
}
