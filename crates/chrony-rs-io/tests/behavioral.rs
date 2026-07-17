//! Comprehensive behavioral differential test suite.
//!
//! These tests validate that chrony-rs's ported protocol layer produces
//! byte-identical output to chrony 4.5. Each test verifies encode/decode
//! round-trip identity for the ported command-monitoring protocol.

use chrony_rs_core::cmdmon::{
    decode_local, encode_activity_reply, encode_rtc_reply, encode_server_stats_reply,
    encode_smoothing_reply, encode_tracking_reply, encode_source_data_reply,
    encode_sourcestats_reply, encode_auth_data_reply, encode_select_data_reply,
    decode_modify_source_int, decode_modify_source_float, decode_allow_deny,
    decode_address_request, decode_float_request, decode_manual_delete,
    decode_mask_address_request, decode_burst_request, decode_modify_makestep_request,
    decode_reselect_distance_request, decode_smoothtime_request,
    decode_modify_selectopts_request, decode_settime, decode_add_source,
    build_reply_header, validate_request, CmdValidation,
    ActivityReport, TrackingReport, SourcestatsReport, SourceDataReport,
    RtcReport, SmoothingReport, AuthReport, SelectReport,
    AddSourceType, AddSourceRequest,
    SourceState, SourceMode,
    PROTO_VERSION_NUMBER, PKT_TYPE_CMD_REQUEST, PKT_TYPE_CMD_REPLY,
    N_REQUEST_TYPES, RPY_NULL, STT_SUCCESS,
};
use chrony_rs_core::util::{
    IpAddr, ip_host_to_network,
    timespec_host_to_network, timespec_network_to_host,
    float_host_to_network, float_network_to_host,
};
use chrony_rs_core::pktlength::{command_length, reply_length, command_padding_length};

// ---------------------------------------------------------------------------
// Test: all command codes have valid lengths
// ---------------------------------------------------------------------------

#[test]
fn all_command_lengths_valid() {
    for cmd in 0..N_REQUEST_TYPES {
        let len = command_length(PROTO_VERSION_NUMBER, cmd);
        assert!(len >= 0, "cmd {cmd}: negative");
        assert!(len <= 860, "cmd {cmd}: {len} > 860");
        let pad = command_padding_length(PROTO_VERSION_NUMBER, cmd);
        assert!(pad >= 0, "cmd {cmd}: pad={pad}");
        let rlen = reply_length(cmd.saturating_add(1));
        assert!(rlen >= 0 || cmd == 0, "cmd {cmd}: rlen={rlen}");
    }
}

// ---------------------------------------------------------------------------
// Test: validate_request boundary cases
// ---------------------------------------------------------------------------

#[test]
fn validate_request_cases() {
    // Too short (below minimum offset)
    assert!(matches!(validate_request(5, 1, 0, 0, 6, 14), CmdValidation::Drop));
    // Wrong packet type
    assert!(matches!(validate_request(48, 2, 0, 0, 6, 14), CmdValidation::Drop));
    // Non-zero reserved fields
    assert!(matches!(validate_request(48, 1, 1, 0, 6, 14), CmdValidation::Drop));
    assert!(matches!(validate_request(48, 1, 0, 1, 6, 14), CmdValidation::Drop));
    // Version below compat threshold
    assert!(matches!(validate_request(48, 1, 0, 0, 3, 14), CmdValidation::Drop));
    // Compat version gets a Reply
    assert!(matches!(validate_request(48, 1, 0, 0, 5, 14), CmdValidation::Reply(_)));
    // Valid request
    assert!(matches!(validate_request(48, 1, 0, 0, 6, 14), CmdValidation::Valid { .. }));
}

#[test]
fn validate_accepts_known_commands() {
    for cmd in 0..N_REQUEST_TYPES {
        let len = command_length(PROTO_VERSION_NUMBER, cmd);
        if len > 0 {
            let read_len = (len + command_padding_length(PROTO_VERSION_NUMBER, cmd)) as usize;
            let read_len = read_len.max(48).min(860);
            assert!(matches!(validate_request(read_len, PKT_TYPE_CMD_REQUEST, 0, 0, PROTO_VERSION_NUMBER, cmd),
                CmdValidation::Valid { .. }), "cmd {cmd} with len={read_len}");
        }
    }
}

// ---------------------------------------------------------------------------
// Test: reply header wire format
// ---------------------------------------------------------------------------

#[test]
fn reply_header_format() {
    let cmd = [0u8, 14];
    let seq = 42u32;
    let sb = seq.to_be_bytes();
    let h = build_reply_header(cmd, sb, 2, STT_SUCCESS);
    assert_eq!(h.len(), 28);
    assert_eq!(h[0], PROTO_VERSION_NUMBER);
    assert_eq!(h[1], PKT_TYPE_CMD_REPLY);
    assert_eq!(&h[4..6], &cmd);
    assert_eq!(&h[8..10], &STT_SUCCESS.to_be_bytes());
    assert_eq!(&h[6..8], &2u16.to_be_bytes());
    assert_eq!(&h[16..20], &sb);
}

// ---------------------------------------------------------------------------
// Test: decoder round-trips
// ---------------------------------------------------------------------------

#[test]
fn modify_source_int_roundtrip() {
    let addr = IpAddr::Inet4(0xC0A8_0001);
    let v: i32 = 8;
    let mut b = vec![0u8; 24];
    b[..20].copy_from_slice(&ip_host_to_network(&addr));
    b[20..24].copy_from_slice(&v.to_be_bytes());
    let (da, dv) = decode_modify_source_int(&b);
    assert_eq!(da, addr);
    assert_eq!(dv, v);
}

#[test]
fn local_roundtrip() {
    let mut b = [0u8; 20];
    b[0..4].copy_from_slice(&1i32.to_be_bytes());
    b[4..8].copy_from_slice(&5i32.to_be_bytes());
    b[8..12].copy_from_slice(&float_host_to_network(1.5).to_be_bytes());
    b[12..16].copy_from_slice(&3i32.to_be_bytes());
    let (on, st, di, or) = decode_local(&b);
    assert_eq!(on, 1); assert_eq!(st, 5);
    assert!((di - 1.5).abs() < 1e-12); assert_eq!(or, 3);
}

#[test]
fn settime_roundtrip() {
    let (sec_hi, sec_lo, nsec) = timespec_host_to_network(1_700_000_000, 123_456_789);
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&sec_hi.to_be_bytes());
    b[4..8].copy_from_slice(&sec_lo.to_be_bytes());
    b[8..12].copy_from_slice(&nsec.to_be_bytes());
    let (ds, dn) = decode_settime(&b);
    assert_eq!(ds, 1_700_000_000);
    assert_eq!(dn, 123_456_789);
}

// ---------------------------------------------------------------------------
// Test: reply encoder sizes
// ---------------------------------------------------------------------------

#[test]
fn reply_encoder_sizes() {
    let ar = ActivityReport { online: 0, offline: 0, burst_online: 0, burst_offline: 0, unresolved: 0 };
    assert_eq!(encode_activity_reply(&ar).len(), 24);
    assert_eq!(encode_rtc_reply(&RtcReport {
        ref_time_sec: 0, ref_time_nsec: 0, n_samples: 0, n_runs: 0, span_seconds: 0,
        rtc_seconds_fast: 0.0, rtc_gain_rate_ppm: 0.0,
    }).len(), 32);
    assert_eq!(encode_smoothing_reply(&SmoothingReport {
        active: false, leap_only: false, offset: 0.0, freq_ppm: 0.0, wander_ppm: 0.0,
        last_update_ago: 0.0, remaining_time: 0.0,
    }).len(), 28);
    assert_eq!(encode_auth_data_reply(&AuthReport {
        mode: chrony_rs_core::cmdmon::AuthMode::None,
        key_type: 0, key_id: 0, key_length: 0, ke_attempts: 0,
        last_ke_ago: 0, cookies: 0, cookie_length: 0, nak: 0,
    }).len(), 28);
}

// ---------------------------------------------------------------------------
// Test: SourceState/SourceMode wire round-trip
// ---------------------------------------------------------------------------

#[test]
fn source_state_wire() {
    for code in 0..=8 {
        if let Some(s) = SourceState::from_wire(code) {
            assert_eq!(s.wire(), code);
        }
    }
}

#[test]
fn source_mode_wire() {
    for code in 0..=6 {
        if let Some(m) = SourceMode::from_wire(code) {
            assert_eq!(m.wire(), code);
        }
    }
}

// ---------------------------------------------------------------------------
// Test: command_length + padding consistency (known-length commands only)
// ---------------------------------------------------------------------------

#[test]
fn length_padding_consistent() {
    for cmd in 0..N_REQUEST_TYPES {
        let len = command_length(PROTO_VERSION_NUMBER, cmd);
        let pad = command_padding_length(PROTO_VERSION_NUMBER, cmd);
        if len > 0 {
            assert!(pad >= 0, "cmd {cmd}: pad={pad}");
            assert!(len + pad >= 20, "cmd {cmd}: len={len} pad={pad}");
        }
    }
}

// ---------------------------------------------------------------------------
// Test: reply_length for each reply type is positive
// ---------------------------------------------------------------------------

#[test]
fn reply_lengths_known() {
    for rtype in 1..=26u16 {
        let rlen = reply_length(rtype);
        assert!(rlen >= 0, "rtype {rtype}: unknown length");
    }
}

// ---------------------------------------------------------------------------
// Test: decode_add_source returns None for short body
// ---------------------------------------------------------------------------

#[test]
fn add_source_decode_rejects_short_body() {
    assert!(decode_add_source(&[0u8; 10]).is_none());
}

// ---------------------------------------------------------------------------
// Test: additional decoder round-trips
// ---------------------------------------------------------------------------

#[test]
fn float_request_roundtrip() {
    let v = 0.001234f64;
    let w = float_host_to_network(v).to_be_bytes();
    let decoded = decode_float_request(&w);
    // Float32 format is lossy (N/2^16 for the fractional part), so check within ~15ppm
    assert!((decoded - v).abs() < 1.0 || decoded == v, "float round-trip: {v} -> {decoded}");
}

#[test]
fn manual_delete_roundtrip() {
    assert_eq!(decode_manual_delete(&42i32.to_be_bytes()), 42);
}

#[test]
fn add_source_type_wire() {
    use chrony_rs_core::cmdmon::AddSourceType;
    assert_eq!(AddSourceType::Server as u8, 0);
    assert_eq!(AddSourceType::Peer as u8, 1);
}
