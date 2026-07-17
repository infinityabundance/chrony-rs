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

fn sfield<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

#[test]
fn matches_real_c_test_a_active() {
    use crate::util::ntp64_to_timespec;
    let v = include_str!("../../../../../research/oracle/ntp_core-testa-active-c-vectors.txt");
    // sys precision quantum the generator used; precision = sysq + 2^precision_log.
    const SYSQ: f64 = 1e-9;
    for tag in ["TA_ACT_PASS", "TA_ACT_CMP", "TA_ACT_POLL", "TA_ACT_DELAY"] {
        let l = v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap();
        let precision_log: i32 = sfield(l, "precision_log").parse().unwrap();
        let precision = SYSQ + crate::util::log2_to_double(precision_log);
        let transmit_ts: u64 = sfield(l, "transmit_ts").parse().unwrap();
        let prior_remote_ntp_tx: u64 = sfield(l, "prior_remote_ntp_tx").parse().unwrap();
        // remote_transmit = Ntp64ToTimespec(transmit_ts); prev = Ntp64ToTimespec(prior tx). (era split 0)
        let remote_transmit = ntp64_to_timespec((transmit_ts >> 32) as u32, transmit_ts as u32, 0);
        let prev_remote_transmit =
            ntp64_to_timespec((prior_remote_ntp_tx >> 32) as u32, prior_remote_ntp_tx as u32, 0);
        let got = passes_test_a_active(
            field(l, "peer_delay"),
            field(l, "peer_dispersion"),
            precision,
            16.0,
            0,
            true,
            sfield(l, "receive_ts").parse().unwrap(),
            transmit_ts,
            sfield(l, "remote_poll").parse().unwrap(),
            sfield(l, "prev_local_poll").parse().unwrap(),
            remote_transmit,
            prev_remote_transmit,
        );
        let expected = sfield(l, "testA") == "1";
        assert_eq!(got, expected, "{tag}");
    }
}
