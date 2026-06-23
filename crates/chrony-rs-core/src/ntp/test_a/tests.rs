//! Tests for `ntp_core.c` Stage 15 (`process_response` test A, client path).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** With B/C/D forced to
//! pass, `good_packet == testA`; each condition is failed in turn and the gate observed
//! by whether a sample is accumulated (`/tmp/ncor/genta.c`,
//! `research/oracle/ntp_core-testa-c-vectors.txt`). [`matches_real_c_test_a`] replays the
//! captured gate inputs and matches the accept/reject outcome.
//!
//! **Oracle #2 (independent): the interleaved-reuse rejection.** Condition 5 (the first
//! interleaved response reusing basic-mode timestamps) is checked directly — this mirrors
//! the Stage 7 observation that a zero-`prev_local_tx` interleaved response yields no
//! sample.

use super::*;

fn field(line: &str, key: &str) -> f64 {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().parse().unwrap()
}

#[test]
fn matches_real_c_test_a() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-testa-c-vectors.txt");
    for l in vectors.lines().map(str::trim).filter(|l| l.starts_with("TA_")) {
        let tag = l.split_whitespace().next().unwrap();
        let got = passes_test_a_client(
            field(l, "peer_delay"),
            field(l, "peer_disp"),
            field(l, "precision"),
            field(l, "max_delay"),
            field(l, "presend_done") as i32,
            field(l, "response_time"),
            false, // basic (non-interleaved) path
            false,
            false,
        );
        let want = field(l, "good") != 0.0;
        assert_eq!(got, want, "{tag}");
    }
}

#[test]
fn each_condition_gates_independently() {
    // A baseline that passes.
    let pass = || passes_test_a_client(0.1, 1e-6, 1e-6, 16.0, 0, 0.01, false, false, false);
    assert!(pass(), "baseline passes");

    // 1. peer_delay - peer_dispersion above max_delay.
    assert!(!passes_test_a_client(0.1, 1e-6, 1e-6, 0.0001, 0, 0.01, false, false, false), "delay");
    // 2. precision above max_delay.
    assert!(!passes_test_a_client(0.1, 1e-6, 2.0, 1.0, 0, 0.01, false, false, false), "precision");
    // 3. presend in progress.
    assert!(!passes_test_a_client(0.1, 1e-6, 1e-6, 16.0, 1, 0.01, false, false, false), "presend");
    // 4. server processing time too long.
    assert!(!passes_test_a_client(0.1, 1e-6, 1e-6, 16.0, 0, 4.5, false, false, false), "response_time");
    // exactly MAX_SERVER_INTERVAL is still accepted.
    assert!(passes_test_a_client(0.1, 1e-6, 1e-6, 16.0, 0, MAX_SERVER_INTERVAL, false, false, false), "boundary");
}

#[test]
fn interleaved_reuse_rejected() {
    // First interleaved response (zero prev_local_tx, reusing local_tx) is rejected...
    assert!(!passes_test_a_client(0.1, 1e-6, 1e-6, 16.0, 0, 0.01, true, true, true), "reuse");
    // ...but an interleaved response with a real previous TX is fine.
    assert!(passes_test_a_client(0.1, 1e-6, 1e-6, 16.0, 0, 0.01, true, false, true), "has prev");
    // Non-interleaved is unaffected by those flags.
    assert!(passes_test_a_client(0.1, 1e-6, 1e-6, 16.0, 0, 0.01, false, true, true), "basic");
}
