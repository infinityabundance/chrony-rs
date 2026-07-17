//! Tests for `ntp_core.c` Stage 9 (`NCR_Modify*` setters).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** An instance is built,
//! each `NCR_Modify*` is called, and the resulting parameter fields are captured
//! (`/tmp/ncor/genmod.c`, `research/oracle/ntp_core-modify-c-vectors.txt`).
//! [`matches_real_c_modify_vectors`] reproduces each scenario from the same initial
//! fields and matches every parameter.
//!
//! **Oracle #2 (independent): the clamp / range / cross-adjust invariants.** The mutual
//! minpoll/maxpoll adjustment and the delay/polltarget bounds are checked directly.

use super::*;

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

/// Reproduce a scenario tag from the same initial instance fields the generator used.
fn scenario(tag: &str) -> SourceParams {
    let mut p = SourceParams {
        minpoll: 0,
        maxpoll: 0,
        max_delay: 0.0,
        max_delay_ratio: 0.0,
        max_delay_dev_ratio: 0.0,
        min_stratum: 0,
        poll_target: 0,
    };
    match tag {
        "MINPOLL_OK" => { p.minpoll = 2; p.maxpoll = 6; p.modify_minpoll(4); }
        "MINPOLL_BUMPS_MAX" => { p.minpoll = 2; p.maxpoll = 6; p.modify_minpoll(10); }
        "MINPOLL_RANGE" => { p.minpoll = 2; p.maxpoll = 6; p.modify_minpoll(-100); }
        "MINPOLL_RANGE_HI" => { p.minpoll = 2; p.maxpoll = 6; p.modify_minpoll(99); }
        "MAXPOLL_OK" => { p.minpoll = 4; p.maxpoll = 10; p.modify_maxpoll(8); }
        "MAXPOLL_LOWERS_MIN" => { p.minpoll = 4; p.maxpoll = 10; p.modify_maxpoll(2); }
        "MAXPOLL_RANGE" => { p.minpoll = 4; p.maxpoll = 10; p.modify_maxpoll(25); }
        "MAXDELAY_OK" => p.modify_max_delay(0.5),
        "MAXDELAY_NEG" => p.modify_max_delay(-1.0),
        "MAXDELAY_HI" => p.modify_max_delay(1.0e9),
        "MAXDELAYRATIO_OK" => p.modify_max_delay_ratio(3.0),
        "MAXDELAYRATIO_HI" => p.modify_max_delay_ratio(1.0e9),
        "MAXDELAYDEVRATIO_OK" => p.modify_max_delay_dev_ratio(1.5),
        "MAXDELAYDEVRATIO_NEG" => p.modify_max_delay_dev_ratio(-2.0),
        "MINSTRATUM" => p.modify_min_stratum(3),
        "POLLTARGET_OK" => p.modify_poll_target(12),
        "POLLTARGET_FLOOR" => p.modify_poll_target(0),
        "POLLTARGET_NEG" => p.modify_poll_target(-5),
        other => panic!("unknown scenario {other}"),
    }
    p
}

#[test]
fn matches_real_c_modify_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-modify-c-vectors.txt");
    for l in vectors.lines().map(str::trim).filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let tag = l.split_whitespace().next().unwrap();
        let p = scenario(tag);
        assert_eq!(p.minpoll, fieldi::<i32>(l, "minpoll"), "{tag} minpoll");
        assert_eq!(p.maxpoll, fieldi::<i32>(l, "maxpoll"), "{tag} maxpoll");
        assert_eq!(p.max_delay, fieldi::<f64>(l, "max_delay"), "{tag} max_delay");
        assert_eq!(p.max_delay_ratio, fieldi::<f64>(l, "max_delay_ratio"), "{tag} ratio");
        assert_eq!(
            p.max_delay_dev_ratio,
            fieldi::<f64>(l, "max_delay_dev_ratio"),
            "{tag} dev_ratio"
        );
        assert_eq!(p.min_stratum, fieldi::<i32>(l, "min_stratum"), "{tag} min_stratum");
        assert_eq!(p.poll_target, fieldi::<i32>(l, "poll_target"), "{tag} poll_target");
    }
}

#[test]
fn cross_adjust_and_bounds() {
    let base = SourceParams {
        minpoll: 2,
        maxpoll: 6,
        max_delay: 0.0,
        max_delay_ratio: 0.0,
        max_delay_dev_ratio: 0.0,
        min_stratum: 0,
        poll_target: 1,
    };

    // Raising minpoll past maxpoll raises maxpoll to match.
    let mut p = base;
    p.modify_minpoll(9);
    assert_eq!((p.minpoll, p.maxpoll), (9, 9), "minpoll bumps maxpoll");

    // Lowering maxpoll below minpoll lowers minpoll to match.
    let mut p = base;
    p.modify_maxpoll(0);
    assert_eq!((p.minpoll, p.maxpoll), (0, 0), "maxpoll lowers minpoll");

    // Out-of-range poll values are no-ops.
    let mut p = base;
    p.modify_minpoll(MIN_POLL - 1);
    p.modify_maxpoll(MAX_POLL + 1);
    assert_eq!((p.minpoll, p.maxpoll), (2, 6), "out-of-range no-op");

    // Delay limits clamp to [0, MAX]; polltarget floors at 1.
    let mut p = base;
    p.modify_max_delay(-5.0);
    assert_eq!(p.max_delay, 0.0);
    p.modify_max_delay(f64::INFINITY);
    assert_eq!(p.max_delay, MAX_MAXDELAY);
    p.modify_poll_target(-3);
    assert_eq!(p.poll_target, 1);
}
