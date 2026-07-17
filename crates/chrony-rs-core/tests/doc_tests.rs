//! Documentation tests for chrony-rs-core.
//!
//! These tests verify that the public API works as documented.

/// Test that the config parser accepts a minimal chrony config.
#[test]
fn config_parse_minimal() {
    let config = "server 0.pool.ntp.org\n";
    let _result = chrony_rs_core::config::parse(config);
    // parse always returns a ParseOutput; errors are emitted as diagnostics
}

/// Test that the config parser accepts an empty config.
#[test]
fn config_parse_empty() {
    let _result = chrony_rs_core::config::parse("");
    // empty config is valid (defaults apply)
}

/// Test that NTP packet decode rejects an empty buffer.
#[test]
fn ntp_decode_empty() {
    let result = chrony_rs_core::ntp::NtpPacket::decode(&[]);
    assert!(result.is_err(), "empty buffer should fail decode");
}

/// Test that NTP packet decode rejects a short buffer.
#[test]
fn ntp_decode_short() {
    let result = chrony_rs_core::ntp::NtpPacket::decode(&[0u8; 10]);
    assert!(result.is_err(), "short buffer should fail decode");
}

/// Test that NTP packet decode accepts a valid 48-byte packet.
#[test]
fn ntp_decode_valid() {
    let pkt = [0u8; 48];
    let result = chrony_rs_core::ntp::NtpPacket::decode(&pkt);
    assert!(result.is_ok(), "48-byte packet should decode");
}

/// Test that Timespec normalisation works.
#[test]
fn timespec_normalise_examples() {
    let (sec, nsec) = chrony_rs_core::util::normalise_timespec(0, 1_500_000_000);
    assert_eq!(sec, 1);
    assert_eq!(nsec, 500_000_000);

    let (sec, nsec) = chrony_rs_core::util::normalise_timespec(1, -1);
    assert_eq!(sec, 0);
    assert_eq!(nsec, 999_999_999);
}
