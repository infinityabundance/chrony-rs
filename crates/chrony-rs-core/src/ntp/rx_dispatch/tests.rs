//! Tests for `ntp_core.c` Stage 19 (RX mode dispatch).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** `NCR_ProcessRxKnown`'s
//! branch is witnessed by the `SRC_GetSourcestats` / `NIO_IsServerSocket` stubs and
//! `NCR_ProcessRxUnknown`'s reply mode is read from the captured response packet
//! (`/tmp/ncor/genrx.c`, `research/oracle/ntp_core-rxdispatch-c-vectors.txt`).
//! [`matches_real_c_rx_dispatch`] replays the captured inputs and matches every decision.
//!
//! **Oracle #2 (independent): the RFC 5905 mode pairings.** The client/server and
//! symmetric pairings are checked directly.

use super::*;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

#[test]
fn matches_real_c_rx_dispatch() {
    let v = include_str!("../../../../../research/oracle/ntp_core-rxdispatch-c-vectors.txt");
    for l in v.lines().map(str::trim) {
        if l.starts_with("RK_") {
            let got = classify_rx_known(
                field(l, "packet_mode").parse().unwrap(),
                field(l, "our_mode").parse().unwrap(),
            );
            let want = match field(l, "action") {
                "ProcResponse" => RxKnownAction::ProcessResponse,
                "ProcAsUnknown" => RxKnownAction::ProcessAsUnknown,
                "Discard" => RxKnownAction::Discard,
                other => panic!("bad action {other}"),
            };
            assert_eq!(got, want, "{l}");
        } else if l.starts_with("RU_") {
            let got = classify_rx_unknown(
                field(l, "packet_mode").parse().unwrap(),
                field(l, "version").parse().unwrap(),
                field(l, "port").parse().unwrap(),
            );
            let want = match field(l, "reply_mode") {
                "none" => None,
                m => Some(m.parse::<i32>().unwrap()),
            };
            assert_eq!(got, want, "{l}");
        }
    }
}

#[test]
fn known_pairings() {
    use RxKnownAction::*;
    // Client/server: a server reply is processed only when we are the client.
    assert_eq!(classify_rx_known(MODE_SERVER, MODE_CLIENT), ProcessResponse);
    assert_eq!(classify_rx_known(MODE_SERVER, MODE_ACTIVE), Discard);
    // Symmetric: active<->active and passive->active are replies.
    assert_eq!(classify_rx_known(MODE_ACTIVE, MODE_ACTIVE), ProcessResponse);
    assert_eq!(classify_rx_known(MODE_PASSIVE, MODE_ACTIVE), ProcessResponse);
    // Any client request, and a server treating us as a peer, are "unknown".
    assert_eq!(classify_rx_known(MODE_CLIENT, MODE_CLIENT), ProcessAsUnknown);
    assert_eq!(classify_rx_known(MODE_ACTIVE, MODE_CLIENT), ProcessAsUnknown);
    // Broadcast is ignored.
    assert_eq!(classify_rx_known(MODE_BROADCAST, MODE_CLIENT), Discard);
}

#[test]
fn unknown_reply_modes() {
    assert_eq!(classify_rx_unknown(MODE_CLIENT, 4, 50000), Some(MODE_SERVER));
    assert_eq!(classify_rx_unknown(MODE_ACTIVE, 4, 123), Some(MODE_PASSIVE));
    // NTPv1 (no mode field) from a non-123 port is a client request.
    assert_eq!(classify_rx_unknown(MODE_UNDEFINED, 1, 50000), Some(MODE_SERVER));
    // ...but not from port 123, and not for v4.
    assert_eq!(classify_rx_unknown(MODE_UNDEFINED, 1, 123), None);
    assert_eq!(classify_rx_unknown(MODE_UNDEFINED, 4, 50000), None);
    // A server packet to an unknown source is never answered.
    assert_eq!(classify_rx_unknown(MODE_SERVER, 4, 50000), None);
}
