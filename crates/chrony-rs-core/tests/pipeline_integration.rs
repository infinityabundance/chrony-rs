//! Integration test: full NTP receive pipeline with auth.
//!
//! Tests that `process_received_response()` correctly classifies,
//! authenticates, and gates received NTP packets through the
//! complete ported pipeline: classification → auth → test A.

use chrony_rs_core::ntp::ext::NtpPacketBuf;
use chrony_rs_core::ntp::parse::parse_packet;
use chrony_rs_core::ntp::rx_dispatch::{
    process_received_response, MODE_CLIENT, MODE_SERVER,
};
use chrony_rs_core::ntp_auth::NauInstance;
use chrony_rs_core::keys::KeyStore;
/// Build a minimal server response packet (mode 4, stratum 2).
fn make_server_response() -> (NtpPacketBuf, usize) {
    let mut buf = NtpPacketBuf::default();
    buf.bytes[0] = 0b00_100_100; // VN=4, Mode=4 (server)
    buf.bytes[1] = 2;            // stratum 2
    buf.bytes[2] = 6;            // poll
    buf.bytes[3] = 252;          // precision = -4 log2 seconds
    // root delay (32 bits at offset 4)
    // root dispersion (32 bits at offset 8)
    // reference id (32 bits at offset 12)
    // reference timestamp (64 bits at offset 16)
    // originate timestamp (64 bits at offset 24)
    // receive timestamp (64 bits at offset 32)
    buf.bytes[32] = 0x83; buf.bytes[33] = 0xAA; // receive timestamp high
    buf.bytes[36] = 0x83; buf.bytes[37] = 0xAA; // transmit timestamp high
    // transmit timestamp (64 bits at offset 40)
    buf.bytes[40] = 0x83; buf.bytes[41] = 0xAB;
    (buf, 48)
}

#[test]
fn full_pipeline_accepts_plain_server_response() {
    let (buf, len) = make_server_response();
    let info = parse_packet(&buf, len as i32)
        .expect("server response should parse");

    let result = process_received_response(
        MODE_SERVER,              // packet mode
        MODE_CLIENT,              // our mode
        &mut NauInstance::create_none(),
        &mut KeyStore::initialise(None),
        &buf, &info,
        0.001,                    // peer_delay
        0.0001,                   // peer_dispersion
        0.0625,                   // precision
        1.0,                      // max_delay
        1,                        // presend_done
        0.001,                    // response_time
        false,                    // interleaved
    );

    assert!(result.accepted, "plain server response should be accepted");
    assert!(result.auth_ok, "no auth → auth_ok should be true");
    assert!(result.test_a_ok, "test A should pass for valid response");
}

#[test]
fn full_pipeline_rejects_excessive_delay() {
    let (buf, len) = make_server_response();
    let info = parse_packet(&buf, len as i32).unwrap();

    // peer_delay - peer_dispersion > max_delay → test A should fail
    let result = process_received_response(
        MODE_SERVER, MODE_CLIENT,
        &mut NauInstance::create_none(),
        &mut KeyStore::initialise(None),
        &buf, &info,
        10.0,     // peer_delay >> max_delay
        0.0001,   // peer_dispersion
        0.0625,   // precision
        1.0,      // max_delay
        1,        // presend_done
        0.001,    // response_time
        false,
    );

    assert!(!result.accepted, "excessive delay should be rejected");
    assert!(result.auth_ok, "auth should still pass");
    assert!(!result.test_a_ok, "test A should fail");
}

#[test]
fn full_pipeline_with_auth_instance() {
    let (buf, len) = make_server_response();
    let info = parse_packet(&buf, len as i32).unwrap();

    // Create a symmetric auth instance with key_id 42
    let mut auth = NauInstance::create_symmetric(42);
    assert!(auth.is_auth_enabled(), "symmetric auth should be enabled");

    let result = process_received_response(
        MODE_SERVER, MODE_CLIENT,
        &mut auth,
        &mut KeyStore::initialise(None),
        &buf, &info,
        0.001, 0.0001, 0.0625, 1.0, 1, 0.001, false,
    );

    // With symmetric auth enabled but no MAC in packet:
    // auth_check_response returns false because packet auth_mode != instance mode
    assert!(!result.accepted, "symmetric auth expected but no MAC → reject");
    assert!(!result.auth_ok, "auth should fail");
}

#[test]
fn client_mode_routes_server_response_to_process() {
    use chrony_rs_core::ntp::rx_dispatch::classify_rx_known;
    let action = classify_rx_known(MODE_SERVER, MODE_CLIENT);
    assert_eq!(action, chrony_rs_core::ntp::rx_dispatch::RxKnownAction::ProcessResponse);
}

#[test]
fn client_mode_routes_client_request_to_unknown() {
    use chrony_rs_core::ntp::rx_dispatch::classify_rx_known;
    let action = classify_rx_known(MODE_CLIENT, MODE_SERVER);
    assert_eq!(action, chrony_rs_core::ntp::rx_dispatch::RxKnownAction::ProcessAsUnknown);
}

#[test]
fn parse_packet_extracts_mode_and_stratum() {
    let (buf, len) = make_server_response();
    let info = parse_packet(&buf, len as i32).unwrap();
    assert_eq!(info.version, 4, "should be NTPv4");
    assert_eq!(info.mode, 4, "should be MODE_SERVER");
    assert_eq!(info.auth_mode, 0, "no auth mode");
}

#[test]
fn parse_packet_rejects_too_short() {
    let buf = NtpPacketBuf::default();
    let info = parse_packet(&buf, 10);
    assert!(info.is_none(), "too-short packet should not parse");
}
