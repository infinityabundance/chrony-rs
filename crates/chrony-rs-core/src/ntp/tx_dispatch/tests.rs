//! Tests for `ntp_core.c` Stage 20 (TX mode dispatch).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** `NCR_ProcessTxKnown`'s
//! route is witnessed by whether `inst->local_tx` was updated, and
//! `NCR_ProcessTxUnknown`'s by whether it reached the client-log timestamp lookup
//! (`/tmp/ncor/gentxd.c`, `research/oracle/ntp_core-txdispatch-c-vectors.txt`).
//!
//! **Oracle #2 (independent): the request/response split.** Client/active are requests we
//! sent; broadcast carries no recordable timestamp.

use super::*;
use crate::ntp::rx_dispatch::{MODE_ACTIVE, MODE_BROADCAST, MODE_CLIENT, MODE_PASSIVE, MODE_SERVER, MODE_UNDEFINED};

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

#[test]
fn matches_real_c_tx_dispatch() {
    let v = include_str!("../../../../../research/oracle/ntp_core-txdispatch-c-vectors.txt");
    for l in v.lines().map(str::trim) {
        if l.starts_with("TXK_") {
            let mode = field(l, "packet_mode").parse::<i32>().unwrap();
            // 'updated' is 1 exactly when the known (request) path ran update_tx_timestamp.
            let updated = field(l, "updated") == "1";
            assert_eq!(tx_known_is_response(mode), updated, "{l}");
        } else if let Some(rest) = l.strip_prefix("TXU_mode") {
            let mode: i32 = rest.split_whitespace().next().unwrap().parse().unwrap();
            let reached = field(l, "reached_clg") == "1";
            assert_eq!(tx_unknown_should_process(mode), reached, "{l}");
        }
    }
}

#[test]
fn request_response_split() {
    // Requests we sent (client / symmetric-active) update our stored TX timestamp.
    assert!(tx_known_is_response(MODE_CLIENT));
    assert!(tx_known_is_response(MODE_ACTIVE));
    // Responses we sent to others are routed to the unknown path.
    assert!(!tx_known_is_response(MODE_SERVER));
    assert!(!tx_known_is_response(MODE_PASSIVE));
    assert!(!tx_known_is_response(MODE_BROADCAST));

    // Only broadcast is ignored on the unknown path.
    assert!(tx_unknown_should_process(MODE_SERVER));
    assert!(tx_unknown_should_process(MODE_CLIENT));
    assert!(tx_unknown_should_process(MODE_UNDEFINED));
    assert!(!tx_unknown_should_process(MODE_BROADCAST));
}
