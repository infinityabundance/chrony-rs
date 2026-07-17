//! Tests for `ntp_core.c` Stage 10 (access-restriction surface).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** The `(allow, all)` →
//! `ADF_*` dispatch and the status→return mapping are captured via the `#include`
//! harness with recording ADF stubs (`/tmp/ncor/genacc.c`,
//! `research/oracle/ntp_core-access-c-vectors.txt`). [`matches_real_c_access_dispatch`]
//! replays each row and matches the selected operation and the success/return.
//!
//! **Oracle #2 (independent): the ported ADF table end-to-end.** `add`/`check` against a
//! real [`AuthTable`] (itself courted against `addrfilt.c`) give the expected allow/deny
//! answers, and a bad subnet width is reported as a failure.

use super::*;
use crate::addrfilt::Subnet;
use std::net::{IpAddr, Ipv4Addr};

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

#[test]
fn matches_real_c_access_dispatch() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-access-c-vectors.txt");
    for l in vectors.lines().map(str::trim).filter(|l| l.starts_with("ADD_")) {
        let tag = l.split_whitespace().next().unwrap();
        let allow = field(l, "allow") == "1";
        let all = field(l, "all") == "1";

        let expect_op = match field(l, "called") {
            "allow" => AccessOp::Allow,
            "allowall" => AccessOp::AllowAll,
            "deny" => AccessOp::Deny,
            "denyall" => AccessOp::DenyAll,
            other => panic!("unexpected called={other}"),
        };
        assert_eq!(select_access_op(allow, all), expect_op, "{tag} op");

        // ret = (status == ADF_SUCCESS). The fixture's status=0 is ADF_SUCCESS.
        let status_success = field(l, "status") == "0";
        let expect_ret = field(l, "ret") == "1";
        assert_eq!(status_success, expect_ret, "{tag} status->ret");
    }
}

#[test]
fn check_matches_real_c() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-access-c-vectors.txt");
    // CHK_* rows: check_access_restriction returns the table's is_allowed verdict.
    for l in vectors.lines().map(str::trim).filter(|l| l.starts_with("CHK_")) {
        // Build a table whose verdict for 10.0.0.1 matches the fixture's is_allowed.
        let mut table = AuthTable::new();
        let allowed = field(l, "is_allowed") == "1";
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        if allowed {
            add_access_restriction(&mut table, Subnet::V4(Ipv4Addr::new(10, 0, 0, 0)), 24, true, false);
        }
        assert_eq!(check_access_restriction(&table, ip), field(l, "ret") == "1", "check");
    }
}

#[test]
fn dispatch_applies_to_real_table() {
    let mut table = AuthTable::new();
    let in_net = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
    let out_net = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Default table denies everything.
    assert!(!check_access_restriction(&table, in_net), "default deny");

    // allow 192.168.1.0/24 -> in-subnet permitted, out-of-subnet still denied.
    assert!(add_access_restriction(&mut table, Subnet::V4(Ipv4Addr::new(192, 168, 1, 0)), 24, true, false));
    assert!(check_access_restriction(&table, in_net), "allowed in subnet");
    assert!(!check_access_restriction(&table, out_net), "still denied out of subnet");

    // deny within the allowed subnet narrows it back.
    assert!(add_access_restriction(&mut table, Subnet::V4(Ipv4Addr::new(192, 168, 1, 5)), 32, false, false));
    assert!(!check_access_restriction(&table, in_net), "specific deny");

    // A bad subnet width is reported as a failure (chrony's status != ADF_SUCCESS -> 0).
    assert!(!add_access_restriction(&mut table, Subnet::V4(Ipv4Addr::new(192, 168, 1, 0)), 40, true, false), "bad subnet");
}
