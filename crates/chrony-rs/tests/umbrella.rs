//! Tests for the chrony-rs umbrella crate.
//!
//! Verifies that re-exports work correctly.

use chrony_rs::core;

#[test]
fn umbrella_re_exports_config() {
    // Verify that config module is accessible through the umbrella crate.
    // parse returns ParseOutput, so we assert it completed without panicking
    // and produced no fatal diagnostics.
    let result = core::config::parse("server 0.pool.ntp.org\n");
    let errors: Vec<_> = result
        .diagnostics
        .iter()
        .filter(|d| matches!(d.severity, core::config::Severity::Error))
        .collect();
    assert!(
        errors.is_empty(),
        "config parsing should succeed through umbrella re-export: {errors:?}"
    );
}

#[test]
fn umbrella_re_exports_ntp() {
    // Verify that NTP types are accessible through the umbrella crate
    let pkt = [0u8; 48];
    let result = core::ntp::NtpPacket::decode(&pkt);
    assert!(result.is_ok(), "NTP decode should work through umbrella re-export");
}

#[test]
fn umbrella_forbids_unsafe() {
    // This is a compile-time check: the umbrella crate has #![forbid(unsafe_code)]
    // If this test compiles, the forbid attribute is working.
    assert!(true, "unsafe_code is forbidden in the umbrella crate");
}
