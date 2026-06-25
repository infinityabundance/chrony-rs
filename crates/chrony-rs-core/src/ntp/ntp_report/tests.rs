//! Tests for the NTP ntpdata report assembly (`ntp_core.c` report-update block).
//!
//! Oracle: the real compiled `ntp_core.c`. `process_response` is driven over a valid
//! client exchange and the resulting `inst->report` dumped by `/tmp/ncor/genrep.c`
//! (`research/oracle/ntp_core-report-c-vectors.txt`). Each scenario rebuilds the report
//! from the same inputs and matches every field.

use super::*;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

#[test]
fn pack_tests_matches_chrony_layout() {
    assert_eq!(pack_tests([true; 10]), 0x3ff);
    assert_eq!(pack_tests([false; 10]), 0);
    // test1 is the most-significant of the 10 bits, testD the least.
    assert_eq!(pack_tests([true, false, false, false, false, false, false, false, false, false]), 1 << 9);
    assert_eq!(pack_tests([false, false, false, false, false, false, false, false, false, true]), 1);
    // testA (index 6) cleared, rest set -> 0x3ff & !(1<<3) = 0x3f7.
    assert_eq!(pack_tests([true, true, true, true, true, true, false, true, true, true]), 0x3f7);
}

#[test]
fn tss_char_maps_sources() {
    assert_eq!(tss_char(0), 'D');
    assert_eq!(tss_char(1), 'K');
    assert_eq!(tss_char(2), 'H');
}

#[test]
fn matches_real_c_report_update() {
    let v = include_str!("../../../../../research/oracle/ntp_core-ntpreport-c-vectors.txt");
    let line = |tag: &str| v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap();

    // The fixed packet inputs the generator used (lvm = leap1|ver4|mode4, reference_ts).
    const LVM: u8 = (1 << 6) | (4 << 3) | 4; // = 100
    const REF_TS: u64 = 0xc0ff_ee00_0000_0001;

    // (tag, tests array, tx_source, rx_source, good)
    let scenarios: &[(&str, [bool; 10], u8, u8, bool)] = &[
        ("REP_PASS", [true; 10], 0, 0, true),
        ("REP_FAILA", [true, true, true, true, true, true, false, true, true, true], 0, 0, false),
        ("REP_AUX", [true; 10], 1, 2, true),
    ];

    for (tag, tests, tx_source, rx_source, good) in scenarios {
        let l = line(tag);
        let fd = |k: &str| field(l, k).parse::<f64>().unwrap();
        let inp = ReportInputs {
            local_addr: IpAddr::Inet4(field(l, "la_in4").parse().unwrap()),
            leap: field(l, "leap").parse().unwrap(),
            version: field(l, "version").parse().unwrap(),
            lvm: LVM,
            stratum: field(l, "stratum").parse().unwrap(),
            poll: field(l, "poll").parse().unwrap(),
            precision: field(l, "precision").parse().unwrap(),
            root_delay: fd("root_delay"),
            root_dispersion: fd("root_dispersion"),
            ref_id: field(l, "ref_id").parse().unwrap(),
            reference_ts: REF_TS,
            offset: fd("offset"),
            peer_delay: fd("peer_delay"),
            peer_dispersion: fd("peer_dispersion"),
            response_time: fd("response_time"),
            jitter_asymmetry: fd("jitter_asymmetry"),
            tests: *tests,
            interleaved: field(l, "interleaved") == "1",
            authenticated: field(l, "authenticated") == "1",
            tx_source: *tx_source,
            rx_source: *rx_source,
            good_packet: *good,
        };
        // A zeroed prior report (the generator's instance was memset before the call).
        let prev = NtpReport {
            local_addr: IpAddr::Unspec,
            leap: 0, version: 0, mode: 0, stratum: 0, poll: 0, precision: 0,
            root_delay: 0.0, root_dispersion: 0.0, ref_id: 0,
            ref_time: Timespec::new(0, 0),
            offset: 0.0, peer_delay: 0.0, peer_dispersion: 0.0, response_time: 0.0,
            jitter_asymmetry: 0.0, tests: 0, interleaved: false, authenticated: false,
            tx_tss_char: '\0', rx_tss_char: '\0',
            total_valid_count: 0, total_good_count: 0, total_tx_count: 0, total_rx_count: 0,
        };
        let r = build_ntp_report(&prev, &inp, 0);

        assert_eq!(r.local_addr, IpAddr::Inet4(field(l, "la_in4").parse().unwrap()), "{tag} local_addr");
        assert_eq!(r.local_addr.family(), field(l, "la_family").parse::<u16>().unwrap(), "{tag} family");
        assert_eq!(r.leap, field(l, "leap").parse::<u8>().unwrap(), "{tag} leap");
        assert_eq!(r.version, field(l, "version").parse::<u8>().unwrap(), "{tag} version");
        assert_eq!(r.mode, field(l, "mode").parse::<u8>().unwrap(), "{tag} mode");
        assert_eq!(r.stratum, field(l, "stratum").parse::<u8>().unwrap(), "{tag} stratum");
        assert_eq!(r.poll, field(l, "poll").parse::<i8>().unwrap(), "{tag} poll");
        assert_eq!(r.precision, field(l, "precision").parse::<i8>().unwrap(), "{tag} precision");
        assert_eq!(r.root_delay, fd("root_delay"), "{tag} root_delay");
        assert_eq!(r.root_dispersion, fd("root_dispersion"), "{tag} root_dispersion");
        assert_eq!(r.ref_id, field(l, "ref_id").parse::<u32>().unwrap(), "{tag} ref_id");
        assert_eq!(r.ref_time.tv_sec, field(l, "ref_sec").parse::<i64>().unwrap(), "{tag} ref_sec");
        assert_eq!(r.ref_time.tv_nsec, field(l, "ref_nsec").parse::<i64>().unwrap(), "{tag} ref_nsec");
        assert_eq!(r.offset, fd("offset"), "{tag} offset");
        assert_eq!(r.peer_delay, fd("peer_delay"), "{tag} peer_delay");
        assert_eq!(r.peer_dispersion, fd("peer_dispersion"), "{tag} peer_dispersion");
        assert_eq!(r.response_time, fd("response_time"), "{tag} response_time");
        assert_eq!(r.jitter_asymmetry, fd("jitter_asymmetry"), "{tag} jitter_asymmetry");
        assert_eq!(r.tests, field(l, "tests").parse::<u16>().unwrap(), "{tag} tests");
        assert_eq!(r.interleaved as i32, field(l, "interleaved").parse::<i32>().unwrap(), "{tag} interleaved");
        assert_eq!(r.authenticated as i32, field(l, "authenticated").parse::<i32>().unwrap(), "{tag} authenticated");
        assert_eq!(r.tx_tss_char, field(l, "tx_tss").chars().next().unwrap(), "{tag} tx_tss");
        assert_eq!(r.rx_tss_char, field(l, "rx_tss").chars().next().unwrap(), "{tag} rx_tss");
        assert_eq!(r.total_valid_count, field(l, "valid").parse::<u32>().unwrap(), "{tag} valid");
        assert_eq!(r.total_good_count, field(l, "good").parse::<u32>().unwrap(), "{tag} good");
        assert_eq!(r.total_tx_count, field(l, "tx_count").parse::<u32>().unwrap(), "{tag} tx_count");
        assert_eq!(r.total_rx_count, field(l, "rx_count").parse::<u32>().unwrap(), "{tag} rx_count");
    }
}
