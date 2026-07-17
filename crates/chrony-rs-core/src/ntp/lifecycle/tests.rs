//! Tests for `ntp_core.c` Stage 14 (instance lifecycle).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** Each transition is run
//! via the `#include` harness and the resulting fields captured (`/tmp/ncor/genlc.c`,
//! `research/oracle/ntp_core-lifecycle-c-vectors.txt`). The reset clears every field, the
//! poll reset / burst transitions are matched (with the timeout/active side effects
//! witnessed by the `SCH_AddTimeoutInClass` / `SRC_SetActive` stubs), and the slewed
//! timestamps are matched to the nanosecond.
//!
//! **Oracle #2 (independent): `UTI_AdjustTimespec` algebra.** The slew is recomputed by
//! `old + (elapsed·dfreq − doffset)` directly.

use super::*;
use crate::ntp::local_ts::{NtpLocalTimestamp, TimestampSource};

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}
fn line<'a>(v: &'a str, tag: &str) -> &'a str {
    v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap()
}

fn nonzero_local(sec: i64) -> NtpLocalTimestamp {
    NtpLocalTimestamp {
        ts: Timespec::new(sec, 123),
        err: 1e-3,
        source: TimestampSource::Hardware,
        rx_duration: 1.0,
        net_correction: 2.0,
    }
}

#[test]
fn reset_clears_all_state() {
    let mut s = InstanceResetState {
        tx_count: 7,
        presend_done: 1,
        remote_poll: 9,
        remote_stratum: 3,
        remote_root_delay: 0.5,
        remote_root_dispersion: 0.6,
        remote_mono_epoch: 0x1122_3344,
        mono_doffset: 1.5,
        valid_rx: 1,
        valid_timestamps: 1,
        remote_ntp_monorx: 0x1_0000_0002,
        remote_ntp_rx: 0x3_0000_0004,
        remote_ntp_tx: 0x5_0000_0006,
        local_ntp_rx: 0x7_0000_0008,
        local_ntp_tx: 0x9_0000_000a,
        local_rx: nonzero_local(100),
        prev_local_tx: nonzero_local(300),
        prev_local_poll: 5,
        prev_tx_count: 4,
        updated_init_timestamps: 1,
        init_remote_ntp_tx: 0xb_0000_000c,
        init_local_rx: nonzero_local(400),
        filter_count: 6,
    };
    s.reset();

    let vectors = include_str!("../../../../../research/oracle/ntp_core-lifecycle-c-vectors.txt");
    let l = line(vectors, "RESET ");
    let i = |k| field(l, k).parse::<i64>().unwrap();
    assert_eq!(s.tx_count as i64, i("tx_count"));
    assert_eq!(s.presend_done as i64, i("presend_done"));
    assert_eq!(s.remote_poll as i64, i("remote_poll"));
    assert_eq!(s.remote_stratum as i64, i("remote_stratum"));
    assert_eq!(s.remote_root_delay, field(l, "remote_root_delay").parse::<f64>().unwrap());
    assert_eq!(s.remote_root_dispersion, field(l, "remote_root_dispersion").parse::<f64>().unwrap());
    assert_eq!(s.remote_mono_epoch as i64, i("remote_mono_epoch"));
    assert_eq!(s.mono_doffset, field(l, "mono_doffset").parse::<f64>().unwrap());
    assert_eq!(s.valid_rx as i64, i("valid_rx"));
    assert_eq!(s.valid_timestamps as i64, i("valid_timestamps"));
    assert_eq!(s.remote_ntp_monorx, field(l, "monorx").parse::<u64>().unwrap());
    assert_eq!(s.remote_ntp_rx, field(l, "rrx").parse::<u64>().unwrap());
    assert_eq!(s.remote_ntp_tx, field(l, "rtx").parse::<u64>().unwrap());
    assert_eq!(s.local_ntp_rx, field(l, "lrx").parse::<u64>().unwrap());
    assert_eq!(s.local_ntp_tx, field(l, "ltx").parse::<u64>().unwrap());
    assert_eq!(s.prev_local_poll as i64, i("prev_local_poll"));
    assert_eq!(s.prev_tx_count as i64, i("prev_tx_count"));
    assert_eq!(s.updated_init_timestamps as i64, i("updated_init"));
    assert_eq!(s.init_remote_ntp_tx, field(l, "init_rtx").parse::<u64>().unwrap());
    assert_eq!(s.filter_count as i64, i("filter_count"));
    // The three local timestamps are reset to an empty daemon timestamp.
    for (name, t) in [
        ("local_rx", &s.local_rx),
        ("prev_local_tx", &s.prev_local_tx),
        ("init_local_rx", &s.init_local_rx),
    ] {
        assert_eq!(t.ts.tv_sec, field(l, &format!("{name}_sec")).parse::<i64>().unwrap(), "{name} sec");
        assert_eq!(t.ts.tv_nsec, field(l, &format!("{name}_nsec")).parse::<i64>().unwrap(), "{name} nsec");
        assert_eq!(t.err, field(l, &format!("{name}_err")).parse::<f64>().unwrap(), "{name} err");
        assert_eq!(t.source as i32, field(l, &format!("{name}_src")).parse::<i32>().unwrap(), "{name} src");
        assert_eq!(*t, NtpLocalTimestamp::zero(), "{name} fully reset");
    }
}

#[test]
fn reset_poll_matches_real_c() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-lifecycle-c-vectors.txt");
    let check = |tag: &str, local_poll: i32, minpoll: i32, has_timeout: bool| {
        let l = line(vectors, tag);
        let r = reset_poll(local_poll, minpoll, has_timeout);
        assert_eq!(r.poll_score, field(l, "poll_score").parse::<f64>().unwrap(), "{tag} score");
        assert_eq!(r.local_poll, field(l, "local_poll").parse::<i32>().unwrap(), "{tag} poll");
        assert_eq!(r.restart_timeout as i32, field(l, "restart").parse::<i32>().unwrap(), "{tag} restart");
    };
    check("RESETPOLL_CHANGED", 10, 4, true);
    check("RESETPOLL_SAME", 4, 4, true);
    check("RESETPOLL_NOTIMER", 10, 4, false);
}

#[test]
fn initiate_burst_matches_real_c() {
    use crate::ntp::opmode::OperatingMode::*;
    let vectors = include_str!("../../../../../research/oracle/ntp_core-lifecycle-c-vectors.txt");
    const MODE_CLIENT: i32 = 3;
    const MODE_ACTIVE: i32 = 1;
    let check = |tag: &str, mode: i32, op: crate::ntp::opmode::OperatingMode| {
        let l = line(vectors, tag);
        let r = initiate_sample_burst(mode, op, 4, 8);
        assert_eq!(r.opmode as i32, field(l, "opmode").parse::<i32>().unwrap(), "{tag} opmode");
        let (good, total) = r.burst.unwrap_or((0, 0));
        assert_eq!(good, field(l, "burst_good").parse::<i32>().unwrap(), "{tag} good");
        assert_eq!(total, field(l, "burst_total").parse::<i32>().unwrap(), "{tag} total");
        assert_eq!(r.start_timeout as i32, field(l, "set_active").parse::<i32>().unwrap(), "{tag} start");
    };
    check("BURST_CLIENT_ONLINE", MODE_CLIENT, Online);
    check("BURST_CLIENT_OFFLINE", MODE_CLIENT, Offline);
    check("BURST_CLIENT_BWON", MODE_CLIENT, BurstWasOnline);
    check("BURST_CLIENT_BWOFF", MODE_CLIENT, BurstWasOffline);
    check("BURST_ACTIVE_ONLINE", MODE_ACTIVE, Online);
}

#[test]
fn slew_times_matches_real_c() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-lifecycle-c-vectors.txt");
    let l = line(vectors, "SLEW");

    let mut local_rx = Timespec::new(2_000_000_000, 100_000_000);
    let mut local_tx = Timespec::new(2_000_000_000, 50_000_000);
    let mut prev_local_tx = Timespec::new(0, 0); // zero -> not slewed
    let mut init_local_rx = Timespec::new(2_000_000_000, 0);
    let when = Timespec::new(2_000_000_010, 0);

    slew_times(
        &mut [&mut local_rx, &mut local_tx, &mut prev_local_tx, &mut init_local_rx],
        when,
        1.0e-5,
        1.0e-3,
    );

    let chk = |name: &str, t: Timespec| {
        assert_eq!(t.tv_sec, field(l, &format!("{name}_sec")).parse::<i64>().unwrap(), "{name} sec");
        assert_eq!(t.tv_nsec, field(l, &format!("{name}_nsec")).parse::<i64>().unwrap(), "{name} nsec");
    };
    chk("local_rx", local_rx);
    chk("local_tx", local_tx);
    chk("prev_local_tx", prev_local_tx);
    chk("init_local_rx", init_local_rx);

    // Independent: the adjust formula on local_rx.
    let old = 2_000_000_000.1_f64;
    let elapsed = 2_000_000_010.0 - old;
    let delta = elapsed * 1.0e-5 - 1.0e-3;
    let expect = old + delta;
    assert!((local_rx.as_seconds() - expect).abs() < 2e-9, "adjust algebra");
}
