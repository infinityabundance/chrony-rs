//! Tests for the cmdmon request-validation framing (`cmdmon.c` `read_from_cmd_socket`).
//!
//! Oracle: a verbatim copy of the validation using the real `PKL_CommandLength`
//! (`/tmp/ncmd/gencmdval.c`, `research/oracle/cmdmon-validate-c-vectors.txt`).

use super::*;

#[test]
fn matches_real_c_validation() {
    let v = include_str!("../../../../research/oracle/cmdmon-validate-c-vectors.txt");
    for l in v.lines().map(str::trim).filter(|l| l.starts_with("CV ")) {
        let f = |k: &str| l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap();
        let read_len: usize = f("read_len").parse().unwrap();
        let got = validate_request(
            read_len,
            f("pkt_type").parse().unwrap(),
            f("res1").parse().unwrap(),
            f("res2").parse().unwrap(),
            f("version").parse().unwrap(),
            f("command").parse::<i64>().unwrap() as u16,
        );
        let outcome: i32 = f("outcome").parse().unwrap();
        let status: i32 = f("status").parse().unwrap();
        let expected: i32 = f("expected").parse().unwrap();
        let tag = f("tag");
        match outcome {
            0 => assert_eq!(got, CmdValidation::Drop, "{tag}"),
            1 => assert_eq!(got, CmdValidation::Reply(status as u16), "{tag}"),
            2 => assert_eq!(got, CmdValidation::Valid { expected_length: expected }, "{tag}"),
            _ => unreachable!("{tag}"),
        }
    }
}

#[test]
fn matches_real_c_tracking_encoding() {
    use crate::util::{bytes_to_hex, string_to_ip, IpAddr};
    let v = include_str!("../../../../research/oracle/cmdmon-tracking-c-vectors.txt");
    let bytes = |tag: &str| {
        v.lines()
            .find(|l| l.split_whitespace().any(|t| t == format!("tag={tag}")))
            .unwrap()
            .split_whitespace()
            .find_map(|t| t.strip_prefix("bytes="))
            .unwrap()
    };

    // The V4 report the generator used.
    let v4 = TrackingReport {
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
    assert_eq!(bytes_to_hex(&encode_tracking_reply(&v4)).to_lowercase(), bytes("V4"));

    // The V6, mostly-zero report (leap 3, zero ref_time).
    let v6 = TrackingReport {
        ref_id: 0,
        ip_addr: string_to_ip("2001:db8::1").unwrap(),
        stratum: 0,
        leap_status: 3,
        ref_time_sec: 0,
        ref_time_nsec: 0,
        current_correction: 0.0,
        last_offset: 0.0,
        rms_offset: 0.0,
        freq_ppm: 0.0,
        resid_freq_ppm: 0.0,
        skew_ppm: 0.0,
        root_delay: 0.0,
        root_dispersion: 0.0,
        last_update_interval: 0.0,
    };
    assert_eq!(bytes_to_hex(&encode_tracking_reply(&v6)).to_lowercase(), bytes("V6_ZERO"));
}

#[test]
fn matches_real_c_source_encodings() {
    use crate::util::{bytes_to_hex, string_to_ip, IpAddr};
    let v = include_str!("../../../../research/oracle/cmdmon-source-c-vectors.txt");
    let bytes = |tag: &str| {
        v.lines()
            .find(|l| l.split_whitespace().any(|t| t == format!("{tag}")))
            .unwrap()
            .split_whitespace()
            .find_map(|t| t.strip_prefix("bytes="))
            .unwrap()
    };

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
    assert_eq!(bytes_to_hex(&encode_sourcestats_reply(&ss)).to_lowercase(), bytes("SS"));

    // Source data — a base report, then re-run with each state/mode remap.
    let v6 = string_to_ip("2001:db8::1").unwrap();
    let base = SourceDataReport {
        ip_addr: v6,
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
    assert_eq!(bytes_to_hex(&encode_source_data_reply(&base)).to_lowercase(), bytes("SD_SEL"));
    let selectable = SourceDataReport { state: SourceState::Selectable, mode: SourceMode::NtpClient, ..base };
    assert_eq!(bytes_to_hex(&encode_source_data_reply(&selectable)).to_lowercase(), bytes("SD_SELECTABLE"));
    let unsel = SourceDataReport { state: SourceState::Unselected, mode: SourceMode::NtpClient, ..base };
    assert_eq!(bytes_to_hex(&encode_source_data_reply(&unsel)).to_lowercase(), bytes("SD_UNSEL"));
}

#[test]
fn matches_real_c_misc_encodings() {
    use crate::ntp::ntp_report::NtpReport;
    use crate::sys_generic::Timespec;
    use crate::util::{bytes_to_hex, string_to_ip, IpAddr};
    let v = include_str!("../../../../research/oracle/cmdmon-misc-c-vectors.txt");
    let bytes = |tag: &str| {
        v.lines()
            .find(|l| l.split_whitespace().any(|t| t == tag))
            .unwrap()
            .split_whitespace()
            .find_map(|t| t.strip_prefix("bytes="))
            .unwrap()
    };

    // Activity.
    let act = ActivityReport { online: 5, offline: 2, burst_online: 1, burst_offline: 0, unresolved: 3 };
    assert_eq!(bytes_to_hex(&encode_activity_reply(&act)).to_lowercase(), bytes("ACT"));

    // Server stats: 17 distinct 40-bit counters (matching the generator).
    let counters = std::array::from_fn(|i| 0x1000000000u64 + i as u64);
    assert_eq!(
        bytes_to_hex(&encode_server_stats_reply(&ServerStatsReport { counters })).to_lowercase(),
        bytes("SS")
    );

    // NTP data — the ntpdata report + remote address/port.
    let report = NtpReport {
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
    assert_eq!(
        bytes_to_hex(&encode_ntp_data_reply(&report, &remote, 123)).to_lowercase(),
        bytes("NTP")
    );
    // Sanity on the flags packing (independent of the byte layout).
    let _ = IpAddr::Unspec;
}

#[test]
fn matches_real_c_rtc_smoothing_encodings() {
    use crate::util::bytes_to_hex;
    let v = include_str!("../../../../research/oracle/cmdmon-rtc-smt-c-vectors.txt");
    let bytes = |tag: &str| {
        v.lines()
            .find(|l| l.split_whitespace().any(|t| t == tag))
            .unwrap()
            .split_whitespace()
            .find_map(|t| t.strip_prefix("bytes="))
            .unwrap()
    };

    let rtc = RtcReport {
        ref_time_sec: 1_700_000_000,
        ref_time_nsec: 250_000_000,
        n_samples: 40,
        n_runs: 8,
        span_seconds: 7200,
        rtc_seconds_fast: 0.125,
        rtc_gain_rate_ppm: -1.5,
    };
    assert_eq!(bytes_to_hex(&encode_rtc_reply(&rtc)).to_lowercase(), bytes("RTC"));

    let smt = SmoothingReport {
        active: true,
        leap_only: true,
        offset: 1.5e-3,
        freq_ppm: 0.5,
        wander_ppm: 0.02,
        last_update_ago: 12.0,
        remaining_time: 300.0,
    };
    assert_eq!(bytes_to_hex(&encode_smoothing_reply(&smt)).to_lowercase(), bytes("SMT_BOTH"));
    let active_only = SmoothingReport { leap_only: false, ..smt };
    assert_eq!(bytes_to_hex(&encode_smoothing_reply(&active_only)).to_lowercase(), bytes("SMT_ACTIVE"));
}

#[test]
fn matches_real_c_auth_select_encodings() {
    use crate::util::{bytes_to_hex, string_to_ip};
    let v = include_str!("../../../../research/oracle/cmdmon-auth-sel-c-vectors.txt");
    let bytes = |tag: &str| {
        v.lines()
            .find(|l| l.split_whitespace().any(|t| t == tag))
            .unwrap()
            .split_whitespace()
            .find_map(|t| t.strip_prefix("bytes="))
            .unwrap()
    };

    let ad = AuthReport {
        mode: AuthMode::Symmetric,
        key_type: 1,
        key_id: 42,
        key_length: 128,
        ke_attempts: 3,
        last_ke_ago: 100,
        cookies: 8,
        cookie_length: 100,
        nak: 1,
    };
    assert_eq!(bytes_to_hex(&encode_auth_data_reply(&ad)).to_lowercase(), bytes("AD"));

    let sel = SelectReport {
        ref_id: 0x7f00_0001,
        ip_addr: string_to_ip("192.168.1.5").unwrap(),
        state_char: '*',
        authentication: 1,
        leap: 0,
        conf_options: 0x2 | 0x4, // PREFER | TRUST
        eff_options: 0x2,        // PREFER
        last_sample_ago: 17,
        score: 1.25,
        lo_limit: -0.5,
        hi_limit: 0.5,
    };
    assert_eq!(bytes_to_hex(&encode_select_data_reply(&sel)).to_lowercase(), bytes("SEL"));

    // The option remap coincides with the SRC_SELECT bit values.
    assert_eq!(convert_sd_sel_options(0x1 | 0x2 | 0x4 | 0x8), 0xf);
    assert_eq!(convert_sd_sel_options(0), 0);
}

#[test]
fn matches_real_c_modify_request_decode() {
    use crate::util::{hex_to_bytes, string_to_ip, IpAddr};
    let v = include_str!("../../../../research/oracle/cmdmon-modify-c-vectors.txt");
    let line = |tag: &str| v.lines().find(|l| l.starts_with(tag)).unwrap();
    fn f<'a>(l: &'a str, k: &str) -> &'a str {
        l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap()
    }
    let raw = |tag: &str| hex_to_bytes(f(line(tag), "bytes")).unwrap();

    // INT (minpoll 6, IPv4).
    let (addr, val) = decode_modify_source_int(&raw("INT"));
    assert_eq!(addr, IpAddr::Inet4(f(line("INT"), "in4").parse().unwrap()));
    assert_eq!(val, f(line("INT"), "value").parse::<i32>().unwrap());

    // INT_V6 (negative value, IPv6).
    let (addr, val) = decode_modify_source_int(&raw("INT_V6"));
    assert_eq!(addr, string_to_ip("2001:db8::1").unwrap());
    assert_eq!(val, f(line("INT_V6"), "value").parse::<i32>().unwrap());
    assert_eq!(val, -3);

    // FLT (maxdelayratio 2.5).
    let (addr, val) = decode_modify_source_float(&raw("FLT"));
    assert_eq!(addr, IpAddr::Inet4(f(line("FLT"), "in4").parse().unwrap()));
    assert_eq!(val, f(line("FLT"), "value").parse::<f64>().unwrap());
}

#[test]
fn matches_real_c_list_and_decode() {
    use crate::util::{bytes_to_hex, hex_to_bytes, string_to_ip, IpAddr};
    let v = include_str!("../../../../research/oracle/cmdmon-listdecode-c-vectors.txt");
    // Match on the exact first whitespace token so LOCAL does not swallow LOCAL_OFF.
    fn line<'a>(v: &'a str, tag: &str) -> &'a str {
        v.lines().find(|l| l.split_whitespace().next() == Some(tag)).unwrap()
    }
    fn f<'a>(l: &'a str, k: &str) -> &'a str {
        l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap()
    }
    let raw = |tag: &str| hex_to_bytes(f(line(v, tag), "bytes")).unwrap();

    // REQ_Local decode (both the enable and disable vectors).
    for tag in ["LOCAL", "LOCAL_OFF"] {
        let l = line(v, tag);
        let (on_off, stratum, distance, orphan) = decode_local(&raw(tag));
        assert_eq!(on_off, f(l, "on_off").parse::<i32>().unwrap(), "{tag} on_off");
        assert_eq!(stratum, f(l, "stratum").parse::<i32>().unwrap(), "{tag} stratum");
        assert_eq!(distance, f(l, "distance").parse::<f64>().unwrap(), "{tag} distance");
        assert_eq!(orphan, f(l, "orphan").parse::<i32>().unwrap(), "{tag} orphan");
    }

    // REQ_Allow_Deny decode (v4 and v6).
    for tag in ["ALLOWDENY", "ALLOWDENY_V6"] {
        let l = line(v, tag);
        let (ip, subnet_bits) = decode_allow_deny(&raw(tag));
        assert_eq!(ip, string_to_ip(f(l, "ip")).unwrap(), "{tag} ip");
        assert_eq!(subnet_bits, f(l, "subnet_bits").parse::<i32>().unwrap(), "{tag} subnet_bits");
    }

    // Single-address requests (ac_check / del_source share the shape).
    assert_eq!(decode_address_request(&raw("ACCHECK")), string_to_ip(f(line(v, "ACCHECK"), "ip")).unwrap());
    assert_eq!(decode_address_request(&raw("DELSOURCE")), string_to_ip(f(line(v, "DELSOURCE"), "ip")).unwrap());

    // Single-float requests (dfreq / doffset share the shape).
    assert_eq!(decode_float_request(&raw("DFREQ")), f(line(v, "DFREQ"), "dfreq").parse::<f64>().unwrap());
    assert_eq!(decode_float_request(&raw("DOFFSET")), f(line(v, "DOFFSET"), "doffset").parse::<f64>().unwrap());

    // Manual delete index.
    assert_eq!(decode_manual_delete(&raw("MANUALDEL")), f(line(v, "MANUALDEL"), "index").parse::<i32>().unwrap());

    // Settime timespec.
    let (sec, nsec) = decode_settime(&raw("SETTIME"));
    assert_eq!(sec, f(line(v, "SETTIME"), "sec").parse::<i64>().unwrap());
    assert_eq!(nsec, f(line(v, "SETTIME"), "nsec").parse::<i64>().unwrap());

    // convert_addsrc_select_options against the whole swept table.
    for l in v.lines().filter(|l| l.split_whitespace().next() == Some("SELOPT")) {
        let flags: u32 = f(l, "flags").parse::<u32>().unwrap();
        let result: i32 = f(l, "result").parse().unwrap();
        assert_eq!(convert_addsrc_select_options(flags), result, "SELOPT flags={flags}");
    }

    // REQ_NTP_Source full decode.
    let l = line(v, "ADDSRC");
    let req = decode_add_source(&raw("ADDSRC")).unwrap();
    assert_eq!(req.source_type, AddSourceType::Pool);
    assert_eq!(req.name, f(l, "name"));
    assert_eq!(req.port, f(l, "port").parse::<u32>().unwrap());
    assert_eq!(req.minpoll, f(l, "minpoll").parse::<i32>().unwrap());
    assert_eq!(req.maxpoll, f(l, "maxpoll").parse::<i32>().unwrap());
    assert_eq!(req.presend_minpoll, f(l, "presend").parse::<i32>().unwrap());
    assert_eq!(req.min_stratum, f(l, "min_stratum").parse::<u32>().unwrap());
    assert_eq!(req.poll_target, f(l, "poll_target").parse::<u32>().unwrap());
    assert_eq!(req.version, f(l, "version").parse::<u32>().unwrap());
    assert_eq!(req.max_sources, f(l, "max_sources").parse::<u32>().unwrap());
    assert_eq!(req.min_samples, f(l, "min_samples").parse::<i32>().unwrap());
    assert_eq!(req.max_samples, f(l, "max_samples").parse::<i32>().unwrap());
    assert_eq!(req.authkey, f(l, "authkey").parse::<u32>().unwrap());
    assert_eq!(req.nts_port, f(l, "nts_port").parse::<u32>().unwrap());
    assert_eq!(req.max_delay, f(l, "max_delay").parse::<f64>().unwrap());
    assert_eq!(req.max_delay_ratio, f(l, "mdr").parse::<f64>().unwrap());
    assert_eq!(req.max_delay_dev_ratio, f(l, "mddr").parse::<f64>().unwrap());
    assert_eq!(req.min_delay, f(l, "min_delay").parse::<f64>().unwrap());
    assert_eq!(req.asymmetry, f(l, "asym").parse::<f64>().unwrap());
    assert_eq!(req.offset, f(l, "offset").parse::<f64>().unwrap());
    assert_eq!(req.flags, f(l, "flags").parse::<u32>().unwrap());
    assert_eq!(req.filter_length, f(l, "filter_length").parse::<i32>().unwrap());
    assert_eq!(req.cert_set, f(l, "cert_set").parse::<u32>().unwrap());
    assert_eq!(req.max_delay_quant, f(l, "mdq").parse::<f64>().unwrap());
    assert_eq!(req.sel_options, f(l, "selopt").parse::<i32>().unwrap());
    assert_eq!(req.connectivity_online, f(l, "online") == "1");
    assert_eq!(req.auto_offline, f(l, "autooffline") == "1");
    assert_eq!(req.iburst, f(l, "iburst") == "1");
    assert_eq!(req.interleaved, f(l, "interleaved") == "1");
    assert_eq!(req.burst, f(l, "burst") == "1");
    assert_eq!(req.nts, f(l, "nts") == "1");
    assert_eq!(req.copy, f(l, "copy") == "1");
    // Unrecognized type => None (STT_INVALID).
    let mut bad = raw("ADDSRC");
    bad[0..4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(decode_add_source(&bad), None);
    // Unterminated name => None (STT_INVALIDNAME).
    let mut unterminated = raw("ADDSRC");
    unterminated[4 + 255] = b'x';
    assert_eq!(decode_add_source(&unterminated), None);

    // RPY_ManualTimestamp encode (12-byte body the generator dumped).
    assert_eq!(
        bytes_to_hex(&encode_manual_timestamp(0.0025, -0.75, 12.0)).to_lowercase(),
        f(line(v, "MANUALTS"), "bytes")
    );

    // RPY_ClientAccesses_Client encode.
    let client = ClientAccessReport {
        ip_addr: string_to_ip("203.0.113.9").unwrap(),
        ntp_hits: 100,
        nke_hits: 5,
        cmd_hits: 2,
        ntp_drops: 3,
        nke_drops: 1,
        cmd_drops: 0,
        ntp_interval: 6,
        nke_interval: -4,
        cmd_interval: 8,
        ntp_timeout_interval: -2,
        last_ntp_hit_ago: 30,
        last_nke_hit_ago: 3600,
        last_cmd_hit_ago: 0,
    };
    assert_eq!(bytes_to_hex(&encode_client_access_entry(&client)).to_lowercase(), f(line(v, "CLIENT"), "bytes"));

    // RPY_ManualListSample encode.
    let sample = ManualSampleReport {
        when_sec: 1_600_000_000,
        when_nsec: 123_456_789,
        slewed_offset: 0.01,
        orig_offset: 0.02,
        residual: -0.005,
    };
    assert_eq!(bytes_to_hex(&encode_manual_list_sample(&sample)).to_lowercase(), f(line(v, "MLSAMPLE"), "bytes"));

    // Manual option validation (pure logic, no fixture line needed).
    assert_eq!(decode_manual_option(0), Some(ManualOption::Disable));
    assert_eq!(decode_manual_option(1), Some(ManualOption::Enable));
    assert_eq!(decode_manual_option(2), Some(ManualOption::Reset));
    assert_eq!(decode_manual_option(3), None);
    assert_eq!(decode_manual_option(-1), None);
    let _ = IpAddr::Unspec;
}

#[test]
fn matches_real_c_permissions_and_header() {
    use crate::util::{bytes_to_hex, hex_to_bytes};
    let v = include_str!("../../../../research/oracle/cmdmon-perm-header-c-vectors.txt");
    fn f<'a>(l: &'a str, k: &str) -> &'a str {
        l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap()
    }
    let line = |tag: &str| v.lines().find(|l| l.split_whitespace().next() == Some(tag)).unwrap();

    // The PERMIT_* numeric values line up with our enum.
    let pv = line("PERMVAL");
    assert_eq!(Permit::Open.value(), f(pv, "OPEN").parse::<u8>().unwrap());
    assert_eq!(Permit::Local.value(), f(pv, "LOCAL").parse::<u8>().unwrap());
    assert_eq!(Permit::Auth.value(), f(pv, "AUTH").parse::<u8>().unwrap());

    // The whole 73-entry permissions[] table, checked against the awk-extracted real array.
    let pc = line("PERM_COUNT");
    assert_eq!(PERMISSIONS.len(), f(pc, "n").parse::<usize>().unwrap());
    assert_eq!(PERMISSIONS.len(), N_REQUEST_TYPES as usize);
    for l in v.lines().filter(|l| l.split_whitespace().next() == Some("PERM")) {
        let idx: usize = f(l, "idx").parse().unwrap();
        let value: u8 = f(l, "value").parse().unwrap();
        assert_eq!(PERMISSIONS[idx].value(), value, "permissions[{idx}]");
    }

    // Reply-header framing: default dispatch header (RPY_NULL / STT_SUCCESS), command 34,
    // sequence 0xdeadbeef.
    let hd = line("HDR_DEFAULT");
    let command_be = 34u16.to_be_bytes();
    let sequence_be = 0xdead_beefu32.to_be_bytes();
    assert_eq!(
        bytes_to_hex(&build_reply_header(command_be, sequence_be, RPY_NULL, STT_SUCCESS)).to_lowercase(),
        f(hd, "bytes")
    );

    // Error header (bad version): status overridden, reply stays RPY_NULL.
    let hb = line("HDR_BADVER");
    assert_eq!(
        bytes_to_hex(&build_reply_header(0u16.to_be_bytes(), 1u32.to_be_bytes(), RPY_NULL, STT_BADPKTVERSION))
            .to_lowercase(),
        f(hb, "bytes")
    );
    // Cross-check the raw fixture bytes decode to our field values.
    let raw = hex_to_bytes(f(hd, "bytes")).unwrap();
    assert_eq!(raw[0], PROTO_VERSION_NUMBER);
    assert_eq!(raw[1], PKT_TYPE_CMD_REPLY);
    assert_eq!(u16::from_be_bytes([raw[4], raw[5]]), 34);
    assert_eq!(u16::from_be_bytes([raw[6], raw[7]]), RPY_NULL);
    assert_eq!(u32::from_be_bytes([raw[16], raw[17], raw[18], raw[19]]), 0xdead_beef);
}

#[test]
fn command_authority_state_machine() {
    // Unix-domain socket: everything is allowed regardless of the permission level.
    assert!(is_command_allowed(1 /* ONLINE = Auth */, true, false));
    assert!(is_command_allowed(33 /* TRACKING = Open */, true, false));

    // Over IP: Open is always allowed; Auth never; Local only from loopback.
    assert_eq!(command_permission(33), Permit::Open); // TRACKING
    assert!(is_command_allowed(33, false, false));
    assert!(is_command_allowed(33, false, true));

    assert_eq!(command_permission(1), Permit::Auth); // ONLINE
    assert!(!is_command_allowed(1, false, true));
    assert!(!is_command_allowed(1, false, false));

    // reply_fits mirrors transmit_reply's request_length >= reply_length gate.
    assert!(reply_fits(100, 80));
    assert!(reply_fits(80, 80));
    assert!(!reply_fits(28, 80));
}

#[test]
fn header_constants_match_chrony() {
    assert_eq!(PROTO_VERSION_NUMBER, 6);
    assert_eq!(N_REQUEST_TYPES, 73);
    assert_eq!((STT_INVALID, STT_BADPKTVERSION, STT_BADPKTLENGTH), (3, 18, 19));
}

#[test]
fn do_size_checks_invariant_holds() {
    // chrony aborts at startup if any command/reply length escapes the CMD envelope; the
    // ported PKL length tables must satisfy the same bounds (as chrony's own do_size_checks).
    assert!(do_size_checks());
    assert_eq!(N_REPLY_TYPES, 26);
    assert_eq!(MAX_PADDING_LENGTH, 484);
}
