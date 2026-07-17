//! Tests for chronyc's request-builder wire codec (`client.c` `process_cmd_*` +
//! `submit_request`).
//!
//! Oracle: a generator that builds each `CMD_Request` body with the REAL `util.c` encoders
//! (`/tmp/nutil/genclient.c`, `research/oracle/client-request-c-vectors.txt`), byte-for-byte.
//! Cross-checked by round-tripping through the [`crate::cmdmon`] decoders.

use super::*;
use crate::cmdmon;
use crate::util::{bytes_to_hex, string_to_ip};

fn line<'a>(v: &'a str, tag: &str) -> &'a str {
    v.lines().find(|l| l.split_whitespace().next() == Some(tag)).unwrap()
}
fn field<'a>(l: &'a str, k: &str) -> &'a str {
    l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap()
}

#[test]
fn matches_real_c_request_builders() {
    let v = include_str!("../../../../research/oracle/client-request-c-vectors.txt");
    let hex = |tag: &str| field(line(v, tag), "bytes").to_string();

    // Request header (submit_request prep): command 34, attempt 2, version 6, seq 0x11223344.
    assert_eq!(
        bytes_to_hex(&build_request_header(34, 2, 0x1122_3344u32.to_be_bytes(), 6)).to_lowercase(),
        hex("HDR")
    );

    // Modify int (minpoll 6, IPv4).
    assert_eq!(
        bytes_to_hex(&encode_modify_address_int_request(&string_to_ip("192.168.1.5").unwrap(), 6)).to_lowercase(),
        hex("MODINT")
    );
    // Modify float (maxdelayratio 2.5, IPv6).
    assert_eq!(
        bytes_to_hex(&encode_modify_address_float_request(&string_to_ip("2001:db8::1").unwrap(), 2.5)).to_lowercase(),
        hex("MODFLT")
    );
    // Local.
    assert_eq!(
        bytes_to_hex(&encode_local_request(1, 5, 0.25, 1)).to_lowercase(),
        hex("LOCAL")
    );
    // Allow/deny.
    assert_eq!(
        bytes_to_hex(&encode_allow_deny_request(&string_to_ip("10.1.2.0").unwrap(), 24)).to_lowercase(),
        hex("ALLOWDENY")
    );
    // Single-address (accheck / del_source).
    assert_eq!(
        bytes_to_hex(&encode_address_request(&string_to_ip("192.0.2.33").unwrap())).to_lowercase(),
        hex("ACCHECK")
    );
    assert_eq!(
        bytes_to_hex(&encode_address_request(&string_to_ip("2001:db8::dead:beef").unwrap())).to_lowercase(),
        hex("DELSOURCE")
    );
    // Single-float (dfreq / doffset).
    assert_eq!(bytes_to_hex(&encode_float_request(-12.5)).to_lowercase(), hex("DFREQ"));
    assert_eq!(bytes_to_hex(&encode_float_request(0.000123)).to_lowercase(), hex("DOFFSET"));
    // Single-word (manual option / manual_delete index / index-only reports).
    assert_eq!(bytes_to_hex(&encode_word_request(2)).to_lowercase(), hex("MANUAL"));
    assert_eq!(bytes_to_hex(&encode_word_request(7)).to_lowercase(), hex("MANUALDEL"));
    assert_eq!(bytes_to_hex(&encode_word_request(3)).to_lowercase(), hex("SRCDATA"));
    assert_eq!(bytes_to_hex(&encode_word_request(4)).to_lowercase(), hex("SRCSTATS"));
    // Settime.
    assert_eq!(
        bytes_to_hex(&encode_settime_request(1_700_000_000, 250_000_000)).to_lowercase(),
        hex("SETTIME")
    );

    // convert_addsrc_sel_options over the whole swept table.
    for l in v.lines().filter(|l| l.split_whitespace().next() == Some("SELOPT")) {
        let options: i32 = field(l, "options").parse().unwrap();
        let result: u32 = field(l, "result").parse().unwrap();
        assert_eq!(convert_addsrc_sel_options(options), result, "SELOPT options={options}");
    }

    // add_source: byte-exact vs the real REQ_NTP_Source build.
    let params = AddSourceParams {
        source_type: AddSourceType::Server,
        name: "ntp.example.org".to_string(),
        port: 123,
        minpoll: 4,
        maxpoll: 10,
        presend_minpoll: 2,
        min_stratum: 1,
        poll_target: 8,
        version: 4,
        max_sources: 1,
        min_samples: 6,
        max_samples: 12,
        authkey: 5,
        nts_port: 4460,
        max_delay: 0.1,
        max_delay_ratio: 3.0,
        max_delay_dev_ratio: 10.0,
        min_delay: 1e-5,
        asymmetry: 0.25,
        offset: -0.001,
        filter_length: 64,
        cert_set: 2,
        max_delay_quant: 0.05,
        connectivity_online: true,
        auto_offline: false,
        iburst: true,
        interleaved: false,
        burst: false,
        nts: true,
        copy: false,
        ext_fields: 0,
        sel_options: 0x2 | 0x4, // PREFER | TRUST
    };
    assert_eq!(
        bytes_to_hex(&encode_add_source_request(&params).unwrap()).to_lowercase(),
        hex("ADDSRC")
    );
    // The flags word the C oracle computed.
    let flags: u32 = field(line(v, "ADDSRC"), "flags").parse().unwrap();
    let body = encode_add_source_request(&params).unwrap();
    assert_eq!(u32::from_be_bytes(body[332..336].try_into().unwrap()), flags);

    // Name too long is rejected (chronyc checks strlen >= 256 before building).
    let mut too_long = params.clone();
    too_long.name = "x".repeat(256);
    assert!(encode_add_source_request(&too_long).is_none());
}

#[test]
fn client_encoders_roundtrip_through_cmdmon_decoders() {
    // Every client request encoder is the exact inverse of a cmdmon decoder.
    let ip4 = string_to_ip("192.168.1.5").unwrap();
    let ip6 = string_to_ip("2001:db8::1").unwrap();

    let (a, v) = cmdmon::decode_modify_source_int(&encode_modify_address_int_request(&ip4, -3));
    assert_eq!((a, v), (ip4, -3));
    let (a, v) = cmdmon::decode_modify_source_float(&encode_modify_address_float_request(&ip6, 2.5));
    assert_eq!(a, ip6);
    assert_eq!(v, 2.5);

    let (on, st, dist, orph) = cmdmon::decode_local(&encode_local_request(1, 5, 0.25, 1));
    assert_eq!((on, st, dist, orph), (1, 5, 0.25, 1));

    let (a, sb) = cmdmon::decode_allow_deny(&encode_allow_deny_request(&ip4, 24));
    assert_eq!((a, sb), (ip4, 24));

    assert_eq!(cmdmon::decode_address_request(&encode_address_request(&ip6)), ip6);
    assert_eq!(cmdmon::decode_float_request(&encode_float_request(-12.5)), -12.5);
    assert_eq!(cmdmon::decode_manual_delete(&encode_word_request(7)), 7);
    assert_eq!(cmdmon::decode_manual_option(2), Some(cmdmon::ManualOption::Reset));
    assert_eq!(cmdmon::decode_settime(&encode_settime_request(1_700_000_000, 250_000_000)), (1_700_000_000, 250_000_000));

    // add_source encode -> cmdmon decode preserves every field, incl. the flag fan-out.
    let params = AddSourceParams {
        source_type: AddSourceType::Pool,
        name: "pool.example".to_string(),
        port: 123,
        minpoll: 4,
        maxpoll: 10,
        presend_minpoll: 2,
        min_stratum: 1,
        poll_target: 8,
        version: 4,
        max_sources: 4,
        min_samples: 6,
        max_samples: 12,
        authkey: 0,
        nts_port: 4460,
        max_delay: 0.1,
        max_delay_ratio: 3.0,
        max_delay_dev_ratio: 10.0,
        min_delay: 1e-5,
        asymmetry: 0.25,
        offset: -0.001,
        filter_length: 64,
        cert_set: 2,
        max_delay_quant: 0.05,
        connectivity_online: true,
        auto_offline: true,
        iburst: true,
        interleaved: true,
        burst: false,
        nts: true,
        copy: false,
        ext_fields: 0x2, // NTP_EF_FLAG_EXP_MONO_ROOT
        sel_options: 0x2 | 0x8, // PREFER | REQUIRE
    };
    let decoded = add_source_roundtrip(&params).unwrap();
    assert_eq!(decoded.source_type, AddSourceType::Pool);
    assert_eq!(decoded.name, "pool.example");
    assert_eq!(decoded.max_sources, 4);
    assert!(decoded.connectivity_online && decoded.auto_offline && decoded.iburst && decoded.interleaved && decoded.nts);
    assert!(!decoded.burst && !decoded.copy);
    // sel_options survives the encode(SRC_SELECT->REQ_ADDSRC) / decode(REQ_ADDSRC->SRC_SELECT) trip.
    assert_eq!(decoded.sel_options, 0x2 | 0x8);
    // ext_fields survives too.
    assert_eq!(decoded.ext_fields, 0x2);
}

#[test]
fn reply_decoders_are_inverse_of_cmdmon_encoders() {
    use crate::cmdmon::{
        encode_activity_reply, encode_auth_data_reply, encode_manual_timestamp, encode_rtc_reply,
        encode_select_data_reply, encode_smoothing_reply, encode_source_data_reply,
        encode_sourcestats_reply, encode_tracking_reply, ActivityReport, AuthMode, AuthReport,
        RtcReport, SelectReport, SmoothingReport, SourceDataReport, SourceMode, SourceState,
        SourcestatsReport, TrackingReport,
    };
    use crate::util::IpAddr;

    // chrony's 32-bit wire Float is lossy, so the inverse is verified at the WIRE level:
    // encode(decode(bytes)) == bytes proves the decoder reads every field exactly (any misread
    // field would re-encode differently), without relying on f64 round-trip equality.

    // Tracking: round-trip our own encoding, and decode the REAL C bytes and re-encode them.
    let trk = TrackingReport {
        ref_id: 0x0a01_0203,
        ip_addr: IpAddr::Inet4(0xc0a8_0105),
        stratum: 3,
        leap_status: 0,
        ref_time_sec: 1_700_000_000,
        ref_time_nsec: 123_456_789,
        current_correction: 1.5e-3,
        last_offset: -2.5e-4,
        rms_offset: 3.0e-4,
        freq_ppm: -12.5,
        resid_freq_ppm: 0.05,
        skew_ppm: 0.2,
        root_delay: 0.01,
        root_dispersion: 0.02,
        last_update_interval: 64.0,
    };
    let b = encode_tracking_reply(&trk);
    assert_eq!(encode_tracking_reply(&decode_tracking_reply(&b)), b);
    // Non-float fields still decode exactly (independent of the Float codec).
    let d = decode_tracking_reply(&b);
    assert_eq!((d.ref_id, d.ip_addr, d.stratum, d.leap_status), (trk.ref_id, trk.ip_addr, trk.stratum, trk.leap_status));
    assert_eq!((d.ref_time_sec, d.ref_time_nsec), (trk.ref_time_sec, trk.ref_time_nsec));

    // Tracking decode of the REAL C bytes (the V4 vector from the cmdmon oracle) re-encodes byte-identically.
    let tv = include_str!("../../../../research/oracle/cmdmon-tracking-c-vectors.txt");
    let v4_bytes = crate::util::hex_to_bytes(
        tv.lines()
            .find(|l| l.split_whitespace().any(|t| t == "tag=V4"))
            .unwrap()
            .split_whitespace()
            .find_map(|t| t.strip_prefix("bytes="))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(&encode_tracking_reply(&decode_tracking_reply(&v4_bytes))[..], &v4_bytes[..]);

    // Sourcestats.
    let ss = SourcestatsReport {
        ref_id: 0x0a01_0203,
        ip_addr: IpAddr::Inet4(0xc0a8_0105),
        n_samples: 64,
        n_runs: 12,
        span_seconds: 3600,
        resid_freq_ppm: 0.05,
        skew_ppm: 0.2,
        sd: 1.5e-6,
        est_offset: -3e-4,
        est_offset_err: 2e-5,
    };
    let b = encode_sourcestats_reply(&ss);
    assert_eq!(encode_sourcestats_reply(&decode_sourcestats_reply(&b)), b);

    // Source data — round-trip each state/mode so the wire un-remap is exercised.
    let base = SourceDataReport {
        ip_addr: string_to_ip("2001:db8::1").unwrap(),
        poll: 6,
        stratum: 2,
        state: SourceState::Selected,
        mode: SourceMode::NtpPeer,
        reachability: 255,
        latest_meas_ago: 17,
        orig_latest_meas: 1e-3,
        latest_meas: -2e-4,
        latest_meas_err: 5e-5,
    };
    for state in [
        SourceState::Nonselectable,
        SourceState::Falseticker,
        SourceState::Jittery,
        SourceState::Selectable,
        SourceState::Unselected,
        SourceState::Selected,
    ] {
        for mode in [SourceMode::NtpClient, SourceMode::NtpPeer, SourceMode::LocalReference] {
            let sd = SourceDataReport { state, mode, ..base };
            let b = encode_source_data_reply(&sd);
            let d = decode_source_data_reply(&b).unwrap();
            // State/mode are exact enums; verify them directly and the rest via re-encode.
            assert_eq!((d.state, d.mode), (state, mode));
            assert_eq!(encode_source_data_reply(&d), b);
        }
    }
    // An unrecognized state code decodes to None.
    let mut bad = encode_source_data_reply(&base);
    bad[24..26].copy_from_slice(&9u16.to_be_bytes());
    assert!(decode_source_data_reply(&bad).is_none());

    // Activity (all integer fields -> exact struct equality is fine).
    // decode_activity_reply now returns report::ActivityReport
    let act = crate::report::ActivityReport { online: 5, offline: 2, burst_online: 1, burst_offline: 0, unknown: 3 };
    let decoded = decode_activity_reply(&cmdmon::encode_activity_reply(
        &cmdmon::ActivityReport { online: 5, offline: 2, burst_online: 1, burst_offline: 0, unresolved: 3 },
    ));
    assert_eq!(decoded.online, act.online);
    assert_eq!(decoded.offline, act.offline);

    // RTC.
    let rtc = RtcReport {
        ref_time_sec: 1_700_000_000,
        ref_time_nsec: 250_000_000,
        n_samples: 40,
        n_runs: 8,
        span_seconds: 7200,
        rtc_seconds_fast: 0.125,
        rtc_gain_rate_ppm: -1.5,
    };
    let b = encode_rtc_reply(&rtc);
    assert_eq!(encode_rtc_reply(&decode_rtc_reply(&b)), b);

    // Smoothing (both flags, then active-only) — flags decode exactly, floats via re-encode.
    let smt = SmoothingReport {
        active: true,
        leap_only: true,
        offset: 1.5e-3,
        freq_ppm: 0.5,
        wander_ppm: 0.02,
        last_update_ago: 12.0,
        remaining_time: 300.0,
    };
    for s in [smt, SmoothingReport { leap_only: false, ..smt }] {
        let b = encode_smoothing_reply(&s);
        let d = decode_smoothing_reply(&b);
        assert_eq!((d.active, d.leap_only), (s.active, s.leap_only));
        assert_eq!(encode_smoothing_reply(&d), b);
    }

    // Auth data (each mode) — all integer fields, exact equality.
    for mode in [AuthMode::None, AuthMode::Symmetric, AuthMode::Nts] {
        let ad = AuthReport {
            mode,
            key_type: 1,
            key_id: 42,
            key_length: 128,
            ke_attempts: 3,
            last_ke_ago: 100,
            cookies: 8,
            cookie_length: 100,
            nak: 1,
        };
        assert_eq!(decode_auth_data_reply(&encode_auth_data_reply(&ad)).unwrap(), ad);
    }

    // Select data (the option masks are the interesting part) — verify them exactly, rest via re-encode.
    let sel = SelectReport {
        ref_id: 0x7f00_0001,
        ip_addr: string_to_ip("192.168.1.5").unwrap(),
        state_char: '*',
        authentication: 1,
        leap: 0,
        conf_options: 0x2 | 0x4, // PREFER | TRUST
        eff_options: 0x2,
        last_sample_ago: 17,
        score: 1.25,
        lo_limit: -0.5,
        hi_limit: 0.5,
    };
    let b = encode_select_data_reply(&sel);
    let d = decode_select_data_reply(&b);
    assert_eq!(
        (d.ref_id, d.ip_addr, d.state_char, d.authentication, d.leap, d.conf_options, d.eff_options, d.last_sample_ago),
        (sel.ref_id, sel.ip_addr, sel.state_char, sel.authentication, sel.leap, sel.conf_options, sel.eff_options, sel.last_sample_ago)
    );
    assert_eq!(encode_select_data_reply(&d), b);

    // Manual timestamp — verify at the wire level.
    let mb = encode_manual_timestamp(0.0025, -0.75, 12.0);
    let (a, b2, c) = decode_manual_timestamp_reply(&mb);
    assert_eq!(encode_manual_timestamp(a, b2, c), mb);

    // n_sources.
    assert_eq!(decode_n_sources_reply(&42u32.to_be_bytes()), 42);

    // ntp_data: encode via cmdmon -> decode here -> re-encode is byte-identical, with the
    // remote addr/port and the flags-word unpack (tests + interleaved/authenticated) exact.
    use crate::ntp::ntp_report::NtpReport;
    use crate::sys_generic::Timespec;
    let ntp = NtpReport {
        local_addr: string_to_ip("10.0.0.1").unwrap(),
        leap: 1,
        version: 4,
        mode: 4,
        stratum: 2,
        poll: 6,
        precision: -24,
        root_delay: 0.01,
        root_dispersion: 0.02,
        ref_id: 0x7f00_0001,
        ref_time: Timespec::new(1_700_000_000, 500_000_000),
        offset: -1.5e-4,
        peer_delay: 0.001,
        peer_dispersion: 2e-6,
        response_time: 1e-5,
        jitter_asymmetry: 0.25,
        tests: 0x2aa,
        interleaved: true,
        authenticated: true,
        tx_tss_char: 'K',
        rx_tss_char: 'H',
        total_tx_count: 100,
        total_rx_count: 99,
        total_valid_count: 98,
        total_good_count: 97,
    };
    let remote = string_to_ip("192.168.1.5").unwrap();
    let wire = cmdmon::encode_ntp_data_reply(&ntp, &remote, 123);
    let (d, d_remote, d_port) = decode_ntp_data_reply(&wire);
    assert_eq!((d_remote, d_port), (remote, 123));
    assert_eq!(
        (d.tests, d.interleaved, d.authenticated, d.tx_tss_char, d.rx_tss_char, d.stratum, d.local_addr, d.ref_id),
        (ntp.tests, ntp.interleaved, ntp.authenticated, ntp.tx_tss_char, ntp.rx_tss_char, ntp.stratum, ntp.local_addr, ntp.ref_id)
    );
    assert_eq!(&cmdmon::encode_ntp_data_reply(&d, &d_remote, d_port)[..], &wire[..]);
}

#[test]
fn reply_header_validation_and_status() {
    // A well-formed reply that echoes the request: Valid.
    assert_eq!(
        validate_reply_header(80, 6, PKT_TYPE_CMD_REPLY, 0, 0, 5, 0xdead, STT_SUCCESS, 5, 0xdead, 6, 80),
        ReplyValidation::Valid
    );
    // Wrong pkt_type / reserved / command echo / sequence echo -> Invalid.
    assert_eq!(
        validate_reply_header(80, 6, 1, 0, 0, 5, 0xdead, STT_SUCCESS, 5, 0xdead, 6, 80),
        ReplyValidation::Invalid
    );
    assert_eq!(
        validate_reply_header(80, 6, PKT_TYPE_CMD_REPLY, 0, 0, 5, 0xdead, STT_SUCCESS, 6, 0xdead, 6, 80),
        ReplyValidation::Invalid
    );
    assert_eq!(
        validate_reply_header(80, 6, PKT_TYPE_CMD_REPLY, 0, 0, 5, 0xbeef, STT_SUCCESS, 5, 0xdead, 6, 80),
        ReplyValidation::Invalid
    );
    // Too short for the header.
    assert_eq!(
        validate_reply_header(20, 6, PKT_TYPE_CMD_REPLY, 0, 0, 5, 0xdead, STT_SUCCESS, 5, 0xdead, 6, 80),
        ReplyValidation::Invalid
    );
    // A v5 reply to our v6 request -> downgrade.
    assert_eq!(
        validate_reply_header(80, 5, PKT_TYPE_CMD_REPLY, 0, 0, 5, 0xdead, STT_BADPKTVERSION, 5, 0xdead, 6, 80),
        ReplyValidation::VersionDowngrade
    );
    // A mismatched-but-compatible version carrying a non-BADPKTVERSION status is Invalid.
    assert_eq!(
        validate_reply_header(80, 4, PKT_TYPE_CMD_REPLY, 0, 0, 5, 0xdead, STT_SUCCESS, 5, 0xdead, 6, 80),
        ReplyValidation::Invalid
    );
    // Body shorter than the declared reply length -> TooShort.
    assert_eq!(
        validate_reply_header(40, 6, PKT_TYPE_CMD_REPLY, 0, 0, 5, 0xdead, STT_SUCCESS, 5, 0xdead, 6, 80),
        ReplyValidation::TooShort
    );

    // Status classification.
    assert!(status_is_ok(STT_SUCCESS));
    assert!(status_is_ok(STT_ACCESSALLOWED));
    assert!(status_is_ok(STT_ACCESSDENIED));
    assert!(!status_is_ok(1)); // STT_FAILED
    assert_eq!(status_message(0), "200 OK");
    assert_eq!(status_message(4), "503 No such source");
    assert_eq!(status_message(18), "517 Protocol version mismatch");
    assert_eq!(status_message(21), "521 Invalid name");
    assert_eq!(status_message(999), "520 Got unexpected error from daemon");
}

#[test]
fn format_name_truncation_matches_real_c() {
    let v = include_str!("../../../../research/oracle/format-name-trunc-c-vectors.txt");
    for l in v.lines().filter(|l| l.starts_with("TR ")) {
        let name = field(l, "name");
        let trunc: i32 = field(l, "trunc").parse().unwrap();
        let start = l.find(" |").unwrap() + 2;
        let end = l.rfind('|').unwrap();
        assert_eq!(truncate_dns_name(name, trunc), &l[start..end], "name={name} trunc={trunc}");
    }
    // The four branch outcomes of format_name.
    assert_eq!(format_name(FormatName::Reference(0x4750_5300), 25), "GPS");
    assert_eq!(format_name(FormatName::SourceName(Some("pool-a")), 25), "pool-a");
    assert_eq!(format_name(FormatName::SourceName(None), 25), "?");
    assert_eq!(format_name(FormatName::IpLiteral(&string_to_ip("192.168.1.5").unwrap()), 25), "192.168.1.5");
    assert_eq!(
        format_name(FormatName::Dns("this.name.is.too.long.for.the.column"), 25),
        "this.name.is.too.long.fo>"
    );
}

#[test]
fn cli_dispatch_helpers_match_chrony() {
    // parse_sources_options: -a all, -v verbose (only when not CSV), unknown ignored.
    assert_eq!(parse_sources_options("", false), (false, false));
    assert_eq!(parse_sources_options("-a", false), (true, false));
    assert_eq!(parse_sources_options("-v", false), (false, true));
    assert_eq!(parse_sources_options("-v", true), (false, false)); // verbose suppressed in CSV
    assert_eq!(parse_sources_options("-a -v", false), (true, true));
    assert_eq!(parse_sources_options("-a  -x  -v", false), (true, true)); // -x ignored

    // waitsync stop condition.
    assert_eq!(WAITSYNC_LOCAL_REFID, 0x7f7f_0101);
    // Real IP reference (not unspec) with no bounds: done.
    assert!(is_waitsync_done(false, 0x0a01_0203, 1e-6, 0.1, 0.0, 0.0));
    // Unspec address with a real refid: done.
    assert!(is_waitsync_done(true, 0x4750_5300, 1e-6, 0.1, 0.0, 0.0));
    // Unspec + refid 0 (no reference): not done.
    assert!(!is_waitsync_done(true, 0, 1e-6, 0.1, 0.0, 0.0));
    // Unspec + LOCAL refid: not synchronised.
    assert!(!is_waitsync_done(true, WAITSYNC_LOCAL_REFID, 1e-6, 0.1, 0.0, 0.0));
    // Bounds: correction/skew must be within the (nonzero) limits.
    assert!(is_waitsync_done(false, 1, 0.005, 0.5, 0.01, 1.0));
    assert!(!is_waitsync_done(false, 1, 0.02, 0.5, 0.01, 1.0)); // correction over limit
    assert!(!is_waitsync_done(false, 1, 0.005, 2.0, 0.01, 1.0)); // skew over limit

    // interval floor.
    assert_eq!(waitsync_interval_floor(10.0), 10.0);
    assert_eq!(waitsync_interval_floor(0.05), 0.1);
    assert_eq!(waitsync_interval_floor(0.1), 0.1);

    // dns subcommand.
    assert_eq!(parse_dns_command("-46"), Some(DnsCommand::FamilyBoth));
    assert_eq!(parse_dns_command("-4"), Some(DnsCommand::FamilyInet4));
    assert_eq!(parse_dns_command("-6"), Some(DnsCommand::FamilyInet6));
    assert_eq!(parse_dns_command("-n"), Some(DnsCommand::NoDnsOn));
    assert_eq!(parse_dns_command("+n"), Some(DnsCommand::NoDnsOff));
    assert_eq!(parse_dns_command("-x"), None);

    // timeout: atoi + floor 100.
    assert_eq!(parse_timeout_command("1000"), Some(1000));
    assert_eq!(parse_timeout_command("100"), Some(100));
    assert_eq!(parse_timeout_command("99"), None);
    assert_eq!(parse_timeout_command("500ms"), Some(500)); // atoi trailing junk
    assert_eq!(parse_timeout_command("abc"), None); // atoi -> 0 -> too short
}

#[test]
fn matches_real_c_connectivity_request_codec() {
    use crate::cmdmon;
    use crate::util::{bytes_to_hex, string_to_ip, IpAddr};
    let v = include_str!("../../../../research/oracle/cmdmon-connectivity-c-vectors.txt");
    let hex = |tag: &str| field(line(v, tag), "bytes").to_string();

    // online/offline (mask + address).
    let mask = string_to_ip("255.0.0.0").unwrap();
    let addr = string_to_ip("10.0.0.0").unwrap();
    let b = encode_mask_address_request(&mask, &addr);
    assert_eq!(bytes_to_hex(&b).to_lowercase(), hex("ONLINE"));
    assert_eq!(cmdmon::decode_mask_address_request(&b), (mask, addr));

    // burst (unspec mask/addr).
    let b = encode_burst_request(&IpAddr::Unspec, &IpAddr::Unspec, 4, 8);
    assert_eq!(bytes_to_hex(&b).to_lowercase(), hex("BURST"));
    assert_eq!(cmdmon::decode_burst_request(&b), (IpAddr::Unspec, IpAddr::Unspec, 4, 8));

    // burst with address.
    let m2 = string_to_ip("255.255.255.255").unwrap();
    let a2 = string_to_ip("192.168.1.5").unwrap();
    let b = encode_burst_request(&m2, &a2, 2, 16);
    assert_eq!(bytes_to_hex(&b).to_lowercase(), hex("BURST_ADDR"));
    assert_eq!(cmdmon::decode_burst_request(&b), (m2, a2, 2, 16));

    // makestep: limit is exact; threshold goes through the lossy Float, so verify at wire level.
    let b = encode_modify_makestep_request(3, 1.5);
    assert_eq!(bytes_to_hex(&b).to_lowercase(), hex("MAKESTEP"));
    let (dlimit, dthresh) = cmdmon::decode_modify_makestep_request(&b);
    assert_eq!(dlimit, 3);
    assert_eq!(encode_modify_makestep_request(dlimit, dthresh), b);

    // reselectdist (lossy Float -> wire-level round-trip).
    let b = encode_reselect_distance_request(0.01);
    assert_eq!(bytes_to_hex(&b).to_lowercase(), hex("RESELECTDIST"));
    assert_eq!(encode_reselect_distance_request(cmdmon::decode_reselect_distance_request(&b)), b);

    // smoothtime.
    let b = encode_smoothtime_request(1);
    assert_eq!(bytes_to_hex(&b).to_lowercase(), hex("SMOOTHTIME"));
    assert_eq!(cmdmon::decode_smoothtime_request(&b), 1);

    // modify_selectopts: mask raw SRC_SELECT bits, options remapped through REQ_ADDSRC.
    let so_addr = string_to_ip("1.2.3.4").unwrap();
    let b = encode_modify_selectopts_request(&so_addr, 0, 0x2 | 0x4, 0x2);
    assert_eq!(bytes_to_hex(&b).to_lowercase(), hex("SELECTOPTS"));
    let (da, dref, dmask, dopts) = cmdmon::decode_modify_selectopts_request(&b);
    assert_eq!((da, dref, dmask, dopts), (so_addr, 0, 0x2 | 0x4, 0x2));
}

#[test]
fn req_command_codes_match_candm_probe() {
    // Every REQ_* code chronyc sends, pinned against the compiled candm.h enum probe.
    let v = include_str!("../../../../research/oracle/chronyc-req-codes-c-vectors.txt");
    let code = |name: &str| -> u16 {
        v.lines()
            .find_map(|l| l.strip_prefix("REQ ").and_then(|r| r.strip_prefix(&format!("{name}="))))
            .unwrap_or_else(|| panic!("no probe for {name}"))
            .parse()
            .unwrap()
    };
    assert_eq!(req::ONLINE, code("REQ_ONLINE"));
    assert_eq!(req::OFFLINE, code("REQ_OFFLINE"));
    assert_eq!(req::MODIFY_MINPOLL, code("REQ_MODIFY_MINPOLL"));
    assert_eq!(req::LOCAL2, code("REQ_LOCAL2"));
    assert_eq!(req::DOFFSET2, code("REQ_DOFFSET2"));
    assert_eq!(req::MAKESTEP, code("REQ_MAKESTEP"));
    assert_eq!(req::MODIFY_MAKESTEP, code("REQ_MODIFY_MAKESTEP"));
    assert_eq!(req::ADD_SOURCE, code("REQ_ADD_SOURCE"));
    assert_eq!(req::ALLOW, code("REQ_ALLOW"));
    assert_eq!(req::ALLOWALL, code("REQ_ALLOWALL"));
    assert_eq!(req::CMDDENYALL, code("REQ_CMDDENYALL"));
    assert_eq!(req::RELOAD_SOURCES, code("REQ_RELOAD_SOURCES"));
    assert_eq!(req::RESET_SOURCES, code("REQ_RESET_SOURCES"));
    assert_eq!(req::MODIFY_SELECTOPTS, code("REQ_MODIFY_SELECTOPTS"));
    assert_eq!(req::MANUAL_DELETE, code("REQ_MANUAL_DELETE"));
    assert_eq!(req::SHUTDOWN, code("REQ_SHUTDOWN"));
}

#[test]
fn classify_command_matches_process_line() {
    use Command::*;
    // Empty / whitespace / comment lines are no-ops.
    assert_eq!(classify_command(""), Empty);
    assert_eq!(classify_command("   "), Empty);
    assert_eq!(classify_command("# comment"), Empty);

    // Report (self-submitting) commands.
    for c in ["activity", "authdata", "clients", "ntpdata", "rtcdata", "selectdata",
              "serverstats", "settime", "smoothing", "sourcename", "sources", "sourcestats",
              "tracking", "waitsync"] {
        assert_eq!(classify_command(c), Report, "{c}");
    }

    // Client-side-only commands.
    for c in ["dns", "keygen", "retries", "timeout", "help", "exit", "quit"] {
        assert_eq!(classify_command(c), Local, "{c}");
    }

    // Deprecated no-ops.
    assert_eq!(classify_command("authhash md5"), Deprecated);
    assert_eq!(classify_command("password foo"), Deprecated);

    // Submit commands with their exact REQ code.
    assert_eq!(classify_command("minpoll 1.2.3.4 6"), Submit(req::MODIFY_MINPOLL));
    assert_eq!(classify_command("local stratum 5"), Submit(req::LOCAL2));
    assert_eq!(classify_command("doffset 0.1"), Submit(req::DOFFSET2));
    assert_eq!(classify_command("add server pool.ntp.org"), Submit(req::ADD_SOURCE));
    assert_eq!(classify_command("delete 1.2.3.4"), Submit(req::DEL_SOURCE));
    assert_eq!(classify_command("onoffline"), Submit(req::ONOFFLINE));
    assert_eq!(classify_command("reload sources"), Submit(req::RELOAD_SOURCES));
    assert_eq!(classify_command("reset sources"), Submit(req::RESET_SOURCES));

    // makestep: arg-dependent code.
    assert_eq!(classify_command("makestep"), Submit(req::MAKESTEP));
    assert_eq!(classify_command("makestep 1.0 3"), Submit(req::MODIFY_MAKESTEP));

    // allow/deny family: the (base, all) pair.
    assert_eq!(classify_command("allow 10.0.0.0/8"), AllowDeny(AllowDenyReqs { base: req::ALLOW, all: req::ALLOWALL }));
    assert_eq!(classify_command("cmddeny all"), AllowDeny(AllowDenyReqs { base: req::CMDDENY, all: req::CMDDENYALL }));

    // manual subcommands.
    assert_eq!(classify_command("manual on"), Submit(req::MANUAL));
    assert_eq!(classify_command("manual list"), Report);
    assert_eq!(classify_command("manual delete 3"), Submit(req::MANUAL_DELETE));

    // Unrecognized.
    assert_eq!(classify_command("frobnicate"), Unrecognized);

    // Normalization: leading/collapsed whitespace does not change the classification.
    assert_eq!(classify_command("   tracking   "), Report);
    assert_eq!(classify_command("\tminpoll\t1.2.3.4\t6"), Submit(req::MODIFY_MINPOLL));
}

#[test]
fn header_constants_match_chrony() {
    assert_eq!(PKT_TYPE_CMD_REQUEST, 1);
    assert_eq!(PROTO_VERSION_NUMBER, 6);
    assert_eq!(PKT_TYPE_CMD_REPLY, 2);
    assert_eq!(PROTO_VERSION_MISMATCH_COMPAT_CLIENT, 4);
}
