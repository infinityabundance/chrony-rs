//! Tests for `ntp_core.c` Stage 1 (poll-interval + delay-sanity arithmetic).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** The static
//! functions and the `NCR_Instance_Record` struct are reached by `#include`-ing the
//! translation unit into a C generator (the ~130-symbol external surface stubbed,
//! `UTI_Log2ToDouble` kept real, and the sourcestats/source inputs made
//! controllable). A minimal instance is built and `get_separation`, `get_poll_adj`,
//! `adjust_poll`, `check_delay_ratio`, and `check_delay_dev_ratio` are called in
//! isolation (`research/oracle/ntp_core-c-vectors.txt`).
//! [`matches_real_c_ntp_core_poll_vectors`] replays the identical inputs and matches
//! every value.
//!
//! **Oracle #2 (independent): the clamp/branch edges.** The separation clamp and the
//! delay-dev-ratio offset-error escape are checked at their boundaries.

use super::*;

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}
fn close(a: f64, b: f64, what: &str) {
    let tol = 1e-12 * (1.0 + a.abs().max(b.abs()));
    assert!((a - b).abs() <= tol, "{what}: rust={a:.17e} c={b:.17e}");
}

fn dtd(ago: f64, pred: f64, min: f64, skew: f64, std: f64) -> DelayTestData {
    DelayTestData {
        last_sample_ago: ago,
        predicted_offset: pred,
        min_delay: min,
        skew,
        std_dev: std,
    }
}

#[test]
fn matches_real_c_ntp_core_poll_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-c-vectors.txt");
    let lines: Vec<&str> = vectors.lines().map(str::trim).collect();
    let find = |p: &str| *lines.iter().find(|l| l.starts_with(p)).unwrap();

    // ---- get_separation ----
    for l in lines.iter().filter(|l| l.starts_with("SEP ")) {
        let poll: i32 = field(l, "poll").parse().unwrap();
        close(get_separation(poll), field(l, "sep").parse().unwrap(), &format!("sep poll={poll}"));
    }

    // ---- get_poll_adj (poll_target = 8) ----
    close(get_poll_adj(4, 8, 0.01, 0.1), field(find("POLLADJ1"), "adj").parse().unwrap(), "polladj1");
    close(get_poll_adj(12, 8, 0.01, 0.1), field(find("POLLADJ2"), "adj").parse().unwrap(), "polladj2");
    close(get_poll_adj(4, 8, 0.5, 0.1), field(find("POLLADJ3"), "adj").parse().unwrap(), "polladj3");

    // ---- adjust_poll (minpoll 2, maxpoll 10) ----
    let check_adjpoll = |tag: &str, lp0: i32, adj: f64| {
        let l = find(tag);
        let (lp, sc) = adjust_poll(lp0, 0.0, adj, 2, 10, false);
        assert_eq!(lp, field(l, "local_poll").parse::<i32>().unwrap(), "{tag} local_poll");
        close(sc, field(l, "poll_score").parse().unwrap(), &format!("{tag} poll_score"));
    };
    check_adjpoll("ADJPOLL1", 6, 1.3);
    check_adjpoll("ADJPOLL2", 6, -2.5);
    check_adjpoll("ADJPOLL3", 1, 0.0);

    // ---- check_delay_ratio (max_delay_ratio 3, max_clock_error 1e-6) ----
    let d = dtd(4.0, 0.0, 0.01, 1e-5, 0.001);
    assert_eq!(
        check_delay_ratio(3.0, 0.02, Some(d), 1e-6) as i32,
        field(find("DELAYR1"), "ok").parse::<i32>().unwrap(),
        "delayr1"
    );
    assert_eq!(
        check_delay_ratio(3.0, 0.5, Some(d), 1e-6) as i32,
        field(find("DELAYR2"), "ok").parse::<i32>().unwrap(),
        "delayr2"
    );

    // ---- check_delay_dev_ratio (max_delay_dev_ratio 1) ----
    assert_eq!(
        check_delay_dev_ratio(1.0, 0.0, 0.012, Some(d), 1e-6) as i32,
        field(find("DELAYD1"), "ok").parse::<i32>().unwrap(),
        "delayd1"
    );
    assert_eq!(
        check_delay_dev_ratio(1.0, 0.0, 0.5, Some(d), 1e-6) as i32,
        field(find("DELAYD2"), "ok").parse::<i32>().unwrap(),
        "delayd2"
    );
}

#[test]
fn separation_clamps_and_missing_data_accepts() {
    // The separation is clamped to [0.002, 0.2].
    assert_eq!(get_separation(MIN_POLL), 0.002, "floor");
    assert_eq!(get_separation(MAX_POLL), 0.2, "ceiling");

    // With no delay-test data both checks accept; a sub-1.0 ratio also accepts.
    assert!(check_delay_ratio(0.5, 1e9, None, 0.0), "ratio < 1.0 accepts");
    assert!(check_delay_ratio(3.0, 1e9, None, 0.0), "no data accepts");
    assert!(check_delay_dev_ratio(1.0, 0.0, 1e9, None, 0.0), "no data accepts (dev)");
}

#[test]
fn delay_dev_ratio_offset_error_escape() {
    // A large delay increase is normally rejected, but when the offset error is much
    // larger than the increase the sample is kept (the escape hatch).
    let d = dtd(0.0, 0.0, 0.0, 0.0, 0.0); // max_delta = 0
    // delta = delay/2 = 0.05 > max_delta(0); error = offset = 0 -> |0| - 0.05 > 0? no -> reject.
    assert!(!check_delay_dev_ratio(1.0, 0.0, 0.1, Some(d), 0.0), "no escape -> reject");
    // Now a big offset error: |1.0| - 0.05 > 0 -> accept.
    assert!(check_delay_dev_ratio(1.0, 1.0, 0.1, Some(d), 0.0), "offset error escape -> accept");
}

#[test]
fn matches_real_c_transmit_timing_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-tx-c-vectors.txt");
    let find = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();
    let pi = |l: &str| field(l, "poll").parse::<i32>().unwrap();
    let pd = |l: &str| field(l, "delay").parse::<f64>().unwrap();

    // ---- get_transmit_poll ----
    assert_eq!(get_transmit_poll(6, MODE_CLIENT, 4, 2, true), pi(find("TXPOLL_CLIENT")), "client");
    assert_eq!(get_transmit_poll(6, MODE_ACTIVE, 4, 2, true), pi(find("TXPOLL_ACTIVE")), "active");
    assert_eq!(get_transmit_poll(6, MODE_ACTIVE, 1, 2, true), pi(find("TXPOLL_ACTIVE2")), "active2");

    // ---- get_transmit_delay ----
    // ONLINE client, local_tx zero, no presend -> 2^6.
    close(
        get_transmit_delay(false, true, 0.0, 6, MODE_CLIENT, 0, 2, true, MD_ONLINE, false, 0, 0),
        pd(find("TXDELAY_ONLINE")),
        "online",
    );
    // ONLINE client, presend, last_tx = 1s -> WARM_UP_DELAY - 1.
    close(
        get_transmit_delay(false, false, 1.0, 6, MODE_CLIENT, 0, 2, true, MD_ONLINE, true, 0, 0),
        pd(find("TXDELAY_PRESEND")),
        "presend",
    );
    // BURST online -> min(2.0, 0.25 * 2^6).
    close(
        get_transmit_delay(false, true, 0.0, 6, MODE_CLIENT, 0, 2, true, MD_BURST_WAS_ONLINE, false, 0, 0),
        pd(find("TXDELAY_BURST")),
        "burst",
    );
    // ACTIVE, remote stratum 3 > our 1, last_tx 1s, poll 6 -> 2^6 * 1.1 - 1.
    close(
        get_transmit_delay(false, false, 1.0, 6, MODE_ACTIVE, 6, 2, true, MD_ONLINE, false, 3, 1),
        pd(find("TXDELAY_ACTIVE")),
        "active",
    );
}
