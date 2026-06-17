//! Tests for `ntp_core.c` Stage 11 (local-timestamp helpers).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** `update_tx_timestamp`
//! and `zero_local_timestamp` are reached via the `#include` harness and run across the
//! accept/reject branches; the resulting timestamp fields are captured
//! (`/tmp/ncor/genutx.c`, `research/oracle/ntp_core-localts-c-vectors.txt`).
//! [`matches_real_c_localts_vectors`] reproduces each scenario and matches every field.
//!
//! **Oracle #2 (independent): the accept condition.** The three rejection reasons
//! (unset original, packet mismatch, out-of-range delay) and the accept case are checked
//! directly.

use super::*;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

const RX: u64 = 0x1111_2222_3333_4444;
const TX: u64 = 0x5555_6666_7777_8888;

fn base_tx() -> NtpLocalTimestamp {
    NtpLocalTimestamp {
        ts: Timespec::new(2_000_000_000, 100_000_000),
        err: 1e-6,
        source: TimestampSource::Hardware,
        rx_duration: 5e-6,
        net_correction: 1e-5,
    }
}
fn new_tx(ts: Timespec) -> NtpLocalTimestamp {
    NtpLocalTimestamp { ts, err: 2e-7, source: TimestampSource::Hardware, rx_duration: 6e-6, net_correction: 2e-5 }
}

/// Reproduce a scenario tag exactly as `/tmp/ncor/genutx.c` does.
fn scenario(tag: &str) -> NtpLocalTimestamp {
    let d50us = Timespec::new(2_000_000_000, 100_050_000);
    let neg = Timespec::new(2_000_000_000, 99_950_000);
    let big = Timespec::new(2_000_000_002, 100_000_000);
    let (mut tx_ts, new, use_rx, use_tx, rx_match, tx_match) = match tag {
        "UTX_OK" => (base_tx(), new_tx(d50us), true, true, true, true),
        "UTX_ZERO_TX" => {
            let mut t = base_tx();
            t.ts = Timespec::new(0, 0);
            (t, new_tx(d50us), true, true, true, true)
        }
        "UTX_RX_MISMATCH" => (base_tx(), new_tx(d50us), true, true, false, true),
        "UTX_TX_MISMATCH" => (base_tx(), new_tx(d50us), true, true, true, false),
        "UTX_NEG_DELAY" => (base_tx(), new_tx(neg), true, true, true, true),
        "UTX_BIG_DELAY" => (base_tx(), new_tx(big), true, true, true, true),
        "UTX_NULL_RX_OK" => (base_tx(), new_tx(d50us), false, true, false, true),
        "UTX_NULL_TX_OK" => (base_tx(), new_tx(d50us), true, false, true, false),
        other => panic!("unknown scenario {other}"),
    };
    let msg_rx = if rx_match { RX } else { RX ^ 1 };
    let msg_tx = if tx_match { TX } else { TX ^ 1 };
    update_tx_timestamp(
        &mut tx_ts,
        &new,
        use_rx.then_some(RX),
        use_tx.then_some(TX),
        msg_rx,
        msg_tx,
    );
    tx_ts
}

#[test]
fn matches_real_c_localts_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-localts-c-vectors.txt");
    for l in vectors.lines().map(str::trim).filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let tag = l.split_whitespace().next().unwrap();
        let t = if tag == "ZLT" {
            // zero_local_timestamp on a populated value.
            NtpLocalTimestamp::zero()
        } else {
            scenario(tag)
        };
        assert_eq!(t.ts.tv_sec, field(l, "ts_sec").parse::<i64>().unwrap(), "{tag} ts_sec");
        assert_eq!(t.ts.tv_nsec, field(l, "ts_nsec").parse::<i64>().unwrap(), "{tag} ts_nsec");
        assert_eq!(t.err, field(l, "err").parse::<f64>().unwrap(), "{tag} err");
        assert_eq!(t.source as i32, field(l, "source").parse::<i32>().unwrap(), "{tag} source");
        assert_eq!(t.rx_duration, field(l, "rx_duration").parse::<f64>().unwrap(), "{tag} rx_duration");
        assert_eq!(
            t.net_correction,
            field(l, "net_correction").parse::<f64>().unwrap(),
            "{tag} net_correction"
        );
    }
}

#[test]
fn accept_only_when_consistent_and_in_range() {
    let new = new_tx(Timespec::new(2_000_000_000, 100_050_000));

    // Accept: set, matching, small positive delay.
    let mut t = base_tx();
    assert!(update_tx_timestamp(&mut t, &new, Some(RX), Some(TX), RX, TX));
    assert_eq!(t.ts, new.ts);

    // Reject: unset original.
    let mut t = NtpLocalTimestamp::zero();
    assert!(!update_tx_timestamp(&mut t, &new, Some(RX), Some(TX), RX, TX));

    // Reject: response is for a different packet.
    let mut t = base_tx();
    assert!(!update_tx_timestamp(&mut t, &new, Some(RX), Some(TX), RX ^ 7, TX));
    assert_eq!(t, base_tx(), "unchanged on mismatch");

    // Reject: delay above MAX_TX_DELAY.
    let far = new_tx(Timespec::new(2_000_000_003, 0));
    let mut t = base_tx();
    assert!(!update_tx_timestamp(&mut t, &far, None, None, 0, 0));

    // Reject: negative delay.
    let earlier = new_tx(Timespec::new(2_000_000_000, 0));
    let mut t = base_tx();
    assert!(!update_tx_timestamp(&mut t, &earlier, None, None, 0, 0));
}
