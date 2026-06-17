//! Tests for `ntp_core.c` Stage 12 (operating-mode state machine).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** The `set_connectivity`
//! transition table (with the action witnessed by the `SRC_SetActive`/`SRC_UnsetActive`
//! stubs) and `NCR_IncrementActivityCounters` for every mode are captured via the
//! `#include` harness (`/tmp/ncor/genopm.c`,
//! `research/oracle/ntp_core-opmode-c-vectors.txt`). [`matches_real_c_opmode_vectors`]
//! replays them and matches the resulting mode, action, and counters.
//!
//! **Oracle #2 (independent): the online-change predicate.** The online↔offline change
//! detection is checked directly.

use super::*;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

fn parse_mode(s: &str) -> OperatingMode {
    match s {
        "OFFLINE" => OperatingMode::Offline,
        "ONLINE" => OperatingMode::Online,
        "BURST_WAS_OFFLINE" => OperatingMode::BurstWasOffline,
        "BURST_WAS_ONLINE" => OperatingMode::BurstWasOnline,
        other => panic!("bad mode {other}"),
    }
}

#[test]
fn matches_real_c_opmode_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-opmode-c-vectors.txt");
    for l in vectors.lines().map(str::trim) {
        if let Some(tag) = l.split_whitespace().next() {
            if tag.starts_with("SC_") {
                let start = parse_mode(field(l, "start"));
                // conn: 0 = SRC_OFFLINE, 1 = SRC_ONLINE.
                let conn = match field(l, "conn") {
                    "0" => Connectivity::Offline,
                    "1" => Connectivity::Online,
                    other => panic!("bad conn {other}"),
                };
                // The generator uses auto_iburst = 0.
                let (mode, action) = set_connectivity(start, conn, false);
                assert_eq!(mode, parse_mode(field(l, "result")), "{tag} result");
                let action_name = match action {
                    ConnectivityAction::None => "None",
                    ConnectivityAction::GoOnline { .. } => "GoOnline",
                    ConnectivityAction::TakeOffline => "TakeOffline",
                };
                assert_eq!(action_name, field(l, "action"), "{tag} action");
            } else if tag.starts_with("ACT_") {
                let mut c = ActivityCounters::default();
                increment_activity_counters(parse_mode(field(l, "opmode")), &mut c);
                assert_eq!(c.online, field(l, "online").parse::<i32>().unwrap(), "{tag} online");
                assert_eq!(c.offline, field(l, "offline").parse::<i32>().unwrap(), "{tag} offline");
                assert_eq!(
                    c.burst_online,
                    field(l, "burst_online").parse::<i32>().unwrap(),
                    "{tag} burst_online"
                );
                assert_eq!(
                    c.burst_offline,
                    field(l, "burst_offline").parse::<i32>().unwrap(),
                    "{tag} burst_offline"
                );
            }
        }
    }
}

#[test]
fn go_online_carries_iburst_flag() {
    // The GoOnline action carries auto_iburst through for the caller to act on.
    let (_, action) = set_connectivity(OperatingMode::Offline, Connectivity::Online, true);
    assert_eq!(action, ConnectivityAction::GoOnline { auto_iburst: true });
}

#[test]
fn online_change_detection() {
    use OperatingMode::*;
    // Online and BurstWasOnline both count as online; the rest as offline.
    assert!(online_changed(Offline, Online), "offline->online");
    assert!(online_changed(Online, Offline), "online->offline");
    assert!(!online_changed(Online, BurstWasOnline), "online->burst-online: no change");
    assert!(!online_changed(Offline, BurstWasOffline), "offline->burst-offline: no change");
    assert!(online_changed(BurstWasOnline, BurstWasOffline), "burst online->offline");
    assert!(!online_changed(Online, Online), "no change");
}
