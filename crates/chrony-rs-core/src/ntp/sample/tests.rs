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
//!
//! ## Stage 6 (`compute_response_sample`)
//!
//! **Oracle #1 (gold standard): the real compiled `process_response`.** The full
//! response path is reached (`/tmp/ncor/gensc.c`, `saved=1` to bypass auth, the validity
//! tests configured to pass) and the sample chrony hands to `SRC_AccumulateSample` is
//! captured with its raw inputs (`research/oracle/ntp_core-sample-c-vectors.txt`).
//! [`matches_real_c_response_sample_vectors`] replays the inputs and matches all five
//! sample fields plus the sample time. **Oracle #2 (independent): RFC 5905 §8.** For a
//! zero-correction exchange the offset and delay are recomputed from the four timestamps
//! by the textbook formula.
//!
//! ## Stage 7 (`compute_interleaved_response_sample`)
//!
//! The interleaved timestamp selection is driven in the real `process_response`
//! (`/tmp/ncor/gensc.c` `run_il`, `inst.interleaved = 1`) across both sub-branches
//! (prefer-previous-TX and use-current-exchange) and the captured samples matched by
//! [`matches_real_c_interleaved_sample_vectors`].

use super::*;
use crate::sys_generic::Timespec;

fn field(line: &str, key: &str) -> f64 {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap()
        .parse()
        .unwrap()
}
fn fieldi<T: std::str::FromStr>(line: &str, key: &str) -> T
where
    T::Err: std::fmt::Debug,
{
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

fn ts64(sec: u32, frac: u32) -> NtpTimestamp {
    NtpTimestamp::from_bits(((sec as u64) << 32) | frac as u64)
}

#[test]
fn matches_real_c_response_sample_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-sample-c-vectors.txt");
    for l in vectors.lines().map(str::trim).filter(|l| l.starts_with("RS_")) {
        let tag = l.split_whitespace().next().unwrap();
        let s = compute_response_sample(
            ts64(fieldi(l, "rr_sec"), fieldi(l, "rr_frac")),
            ts64(fieldi(l, "rt_sec"), fieldi(l, "rt_frac")),
            Timespec::new(fieldi(l, "ltx_sec"), fieldi(l, "ltx_nsec")),
            field(l, "ltx_err"),
            Timespec::new(fieldi(l, "lrx_sec"), fieldi(l, "lrx_nsec")),
            field(l, "lrx_err"),
            fieldi(l, "prec"),
            field(l, "sysq"),
            field(l, "flo"),
            field(l, "fhi"),
            field(l, "offc"),
            field(l, "rd"),
            field(l, "rdsp"),
            0.0,
            0.0,
            0.0,
        );
        close(s.offset, field(l, "offset"), &format!("{tag} offset"));
        close(s.peer_delay, field(l, "peer_delay"), &format!("{tag} peer_delay"));
        close(s.peer_dispersion, field(l, "peer_disp"), &format!("{tag} peer_disp"));
        close(s.root_delay, field(l, "root_delay"), &format!("{tag} root_delay"));
        close(s.root_dispersion, field(l, "root_disp"), &format!("{tag} root_disp"));
        assert_eq!(s.time.tv_sec, fieldi::<i64>(l, "time_sec"), "{tag} time_sec");
        assert_eq!(s.time.tv_nsec, fieldi::<i64>(l, "time_nsec"), "{tag} time_nsec");
    }
}

#[test]
fn matches_real_c_interleaved_sample_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-sample-c-vectors.txt");
    for l in vectors.lines().map(str::trim).filter(|l| l.starts_with("IL_")) {
        let tag = l.split_whitespace().next().unwrap();
        let s = compute_interleaved_response_sample(
            ts64(fieldi(l, "mr_sec"), fieldi(l, "mr_frac")),
            ts64(fieldi(l, "rt_sec"), fieldi(l, "rt_frac")),
            ts64(fieldi(l, "rrx_sec"), fieldi(l, "rrx_frac")),
            Timespec::new(fieldi(l, "plt_sec"), fieldi(l, "plt_nsec")),
            field(l, "plt_err"),
            fieldi::<i32>(l, "plt_zero") != 0,
            Timespec::new(fieldi(l, "ltx_sec"), fieldi(l, "ltx_nsec")),
            field(l, "ltx_err"),
            Timespec::new(fieldi(l, "lrx_sec"), fieldi(l, "lrx_nsec")),
            field(l, "lrx_err"),
            fieldi(l, "prec"),
            field(l, "sysq"),
            field(l, "flo"),
            field(l, "fhi"),
            field(l, "offc"),
            field(l, "pkt_rd"),
            field(l, "pkt_rdsp"),
            field(l, "rem_rd"),
            field(l, "rem_rdsp"),
        );
        close(s.offset, field(l, "offset"), &format!("{tag} offset"));
        close(s.peer_delay, field(l, "peer_delay"), &format!("{tag} peer_delay"));
        close(s.peer_dispersion, field(l, "peer_disp"), &format!("{tag} peer_disp"));
        close(s.root_delay, field(l, "root_delay"), &format!("{tag} root_delay"));
        close(s.root_dispersion, field(l, "root_disp"), &format!("{tag} root_disp"));
        assert_eq!(s.time.tv_sec, fieldi::<i64>(l, "time_sec"), "{tag} time_sec");
        assert_eq!(s.time.tv_nsec, fieldi::<i64>(l, "time_nsec"), "{tag} time_nsec");
    }
}

#[test]
fn offset_and_delay_match_rfc5905() {
    // RFC 5905 §8: for an exchange with timestamps T1 (our tx), T2 (server rx),
    // T3 (server tx), T4 (our rx), offset = ((T2-T1)+(T3-T4))/2 and
    // delay = (T4-T1)-(T3-T2). chrony computes the same via timestamp averages.
    // Use whole-second-fraction NTP timestamps so the textbook arithmetic is exact.
    let t1 = Timespec::new(1000, 0); // our transmit
    let t4 = Timespec::new(1000, 200_000_000); // our receive (+0.2s)
    // Server rx/tx at +0.05 / +0.06 relative to T1, expressed as NTP64.
    let t2 = ts64(1000 + 0x83aa_7e80, (0.05 * NSEC_PER_NTP64 * 1e9) as u32);
    let t3 = ts64(1000 + 0x83aa_7e80, (0.06 * NSEC_PER_NTP64 * 1e9) as u32);

    let s = compute_response_sample(
        t2, t3, t1, 0.0, t4, 0.0, -30, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    );

    let (t2s, t3s) = (0.05, 0.06);
    let (t1s, t4s) = (0.0, 0.2);
    let expect_offset = ((t2s - t1s) + (t3s - t4s)) / 2.0;
    let expect_delay = (t4s - t1s) - (t3s - t2s);
    // The server timestamps round-trip through the NTP 64-bit format, so allow for the
    // fraction->nanosecond quantization (~1 ns) on top of the textbook value.
    let q = 2e-9;
    assert!((s.offset - expect_offset).abs() <= q, "rfc offset: {} vs {}", s.offset, expect_offset);
    assert!((s.peer_delay - expect_delay).abs() <= q, "rfc delay: {} vs {}", s.peer_delay, expect_delay);
}
