//! Tests for `ntp_core.c` Stage 18 (`NCR_ReportSource`).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** `NCR_ReportSource` is
//! run via the `#include` harness and the report poll + mode captured
//! (`/tmp/ncor/genrs.c`, `research/oracle/ntp_core-report-c-vectors.txt`).
//! [`matches_real_c_report_vectors`] reproduces each scenario and matches both.
//!
//! **Oracle #2 (independent): the mode mapping.** Client/peer classification is checked
//! directly.

use super::*;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

#[test]
fn matches_real_c_report_vectors() {
    let v = include_str!("../../../../../research/oracle/ntp_core-report-c-vectors.txt");
    let scenarios = [
        ("RS_CLIENT", MODE_CLIENT, 6, 4, 2, true),
        ("RS_PEER_SHORT", MODE_ACTIVE, 6, 4, 2, true),
        ("RS_PEER_BELOWMIN", MODE_ACTIVE, 6, 1, 2, true),
        ("RS_PEER_UNREACH", MODE_ACTIVE, 6, 4, 2, false),
    ];
    for (tag, mode, local_poll, remote_poll, minpoll, reachable) in scenarios {
        let l = v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap();
        let (poll, rm) = report_source(local_poll, mode, remote_poll, minpoll, reachable);
        assert_eq!(poll, field(l, "poll").parse::<i32>().unwrap(), "{tag} poll");
        assert_eq!(rm as i32, field(l, "mode").parse::<i32>().unwrap(), "{tag} mode");
    }
}

#[test]
fn mode_classification() {
    assert_eq!(report_source(6, MODE_CLIENT, 4, 2, true).1, ReportMode::NtpClient);
    assert_eq!(report_source(6, MODE_ACTIVE, 4, 2, true).1, ReportMode::NtpPeer);
}
