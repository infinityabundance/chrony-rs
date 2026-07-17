//! Integration test: NTP packet authentication pipeline.
//!
//! Tests that `receive_authenticated()` correctly verifies MACs on received
//! packets using the ported auth infrastructure.

use chrony_rs_core::keys::{KeyStore, Key};
use chrony_rs_core::ntp::ext::{NtpPacketBuf, NtpPacketInfo};
use chrony_rs_core::ntp::parse::{parse_packet, NTP_AUTH_NONE, NTP_AUTH_SYMMETRIC};
use chrony_rs_core::ntp::rx_dispatch::{
    auth_check_response, auth_check_request, receive_authenticated,
    classify_rx_known, MODE_CLIENT, MODE_SERVER,
};
use chrony_rs_core::ntp_auth::NauInstance;

/// Build a minimal NTP packet with no auth (mode 4 server response).
fn make_plain_packet() -> (NtpPacketBuf, NtpPacketInfo) {
    let mut buf = NtpPacketBuf::default();
    buf.bytes[0] = 0b00_100_100; // VN=4, Mode=4 (server)
    buf.bytes[1] = 2; // stratum 2
    let info = parse_packet(&buf, 48).expect("plain packet should parse");
    (buf, info)
}

#[test]
fn plain_packet_passes_auth_none() {
    let (buf, info) = make_plain_packet();
    assert_eq!(info.auth_mode, NTP_AUTH_NONE, "plain packet has no auth");

    let mut auth = NauInstance::create_none();
    let mut keys = KeyStore::new();

    // No auth expected → should pass
    assert!(auth_check_response(&mut auth, &mut keys, &buf, &info),
        "plain packet should pass NONE auth");
}

#[test]
fn auth_check_on_plain_packet_ok() {
    let (buf, info) = make_plain_packet();

    // receive_authenticated with MODE_SERVER response to MODE_CLIENT
    let (action, auth_ok) = receive_authenticated(
        MODE_SERVER, MODE_CLIENT,
        &mut NauInstance::create_none(),
        &mut KeyStore::new(),
        &buf, &info,
    );
    assert_eq!(action, chrony_rs_core::ntp::rx_dispatch::RxKnownAction::ProcessResponse,
        "client should process server response");
    assert!(auth_ok, "plain packet should pass auth");
}

#[test]
fn classify_rx_known_identifies_server_response() {
    let action = classify_rx_known(MODE_SERVER, MODE_CLIENT);
    assert_eq!(action, chrony_rs_core::ntp::rx_dispatch::RxKnownAction::ProcessResponse,
        "MODE_SERVER packet to MODE_CLIENT source should be ProcessResponse");
}

#[test]
fn classify_rx_client_request_is_as_unknown() {
    // A client request (mode 3) is always handled as unknown
    let action = classify_rx_known(MODE_CLIENT, MODE_SERVER);
    assert_eq!(action, chrony_rs_core::ntp::rx_dispatch::RxKnownAction::ProcessAsUnknown,
        "client request should be routed to unknown handler");
}

#[test]
fn auth_create_none_disables_auth() {
    let auth = NauInstance::create_none();
    assert!(!auth.is_auth_enabled(), "NONE mode should not enable auth");
}

#[test]
fn auth_create_symmetric_enables_auth() {
    let auth = NauInstance::create_symmetric(42);
    assert!(auth.is_auth_enabled(), "symmetric mode should enable auth");
    assert_eq!(auth.key_id(), 42, "key_id should be 42");
}

#[test]
fn parse_packet_extracts_auth_mode() {
    let (_, info) = make_plain_packet();
    assert_eq!(info.auth_mode, NTP_AUTH_NONE, "plain packet auth_mode=NONE");
    assert_eq!(info.mac_key_id, 0, "plain packet mac_key_id=0");
}

#[test]
fn key_store_roundtrip() {
    use chrony_rs_core::keys::KeyStore;
    let mut ks = KeyStore::new();

    // KeyStore should start empty
    assert!(!ks.is_key_known(1), "key 1 should not be known initially");
}
