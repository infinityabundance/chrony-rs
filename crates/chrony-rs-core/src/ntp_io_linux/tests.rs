//! Differential oracle for `extract_udp_data` vs a verbatim copy of chrony's
//! `ntp_io_linux.c` function (`research/oracle/ntp_io_linux-c-vectors.txt`), over crafted
//! Ethernet/IPv4/IPv6/UDP frames.

use super::*;
use crate::util::add_double_to_timespec;

fn f<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("missing {key} in: {line}"))
}
fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".to_string();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn matches_real_c_extract_udp_data_vectors() {
    let vectors = include_str!("../../../../research/oracle/ntp_io_linux-c-vectors.txt");
    let mut n = 0;
    for line in vectors.lines().filter(|l| l.starts_with("EUD ")) {
        let name = f(line, "name");
        let mut frame = unhex(f(line, "in"));
        let (ret, ra) = extract_udp_data(&mut frame);

        assert_eq!(ret as i64, f(line, "ret").parse::<i64>().unwrap(), "{name} ret");
        assert_eq!(ra.family as i64, f(line, "fam").parse::<i64>().unwrap(), "{name} fam");
        assert_eq!(ra.port as i64, f(line, "port").parse::<i64>().unwrap(), "{name} port");

        let addr = match ra.family {
            IPADDR_INET4 => format!("{:08x}", ra.in4),
            IPADDR_INET6 => hex(&ra.in6),
            _ => "-".to_string(),
        };
        assert_eq!(addr, f(line, "addr"), "{name} addr");

        // On success the payload has been moved to the front of the frame.
        assert_eq!(hex(&frame[..ret]), f(line, "payload"), "{name} payload");
        n += 1;
    }
    assert_eq!(n, 10, "expected all frame cases");
}

/// Differential oracle for the HW/SW timestamp processors vs verbatim copies of chrony's
/// `process_hw_timestamp` / `process_sw_timestamp` (the poll_phc/HCL_CookTime/LCL_CookTime
/// boundary replaced by a deterministic mock cook identical on both sides:
/// `cooked = raw + 0.5 s`; `research/oracle/ntp_io_linux-hwts-c-vectors.txt`).
#[test]
fn matches_real_c_hwts_vectors() {
    let vectors = include_str!("../../../../research/oracle/ntp_io_linux-hwts-c-vectors.txt");
    fn fl(line: &str, key: &str) -> f64 {
        f(line, key).parse().unwrap()
    }
    fn n(line: &str, key: &str) -> i64 {
        f(line, key).parse().unwrap()
    }
    fn close(a: f64, b: f64, what: &str) {
        assert!((a - b).abs() <= 1e-15 * (1.0 + a.abs().max(b.abs())), "{what}: {a} vs {b}");
    }

    let hw = (1000i64, 100_000_000i64);
    // The daemon timestamp before processing: near the cooked value so most cases accept.
    let base = LocalTimestamp { ts: (1000, 600_000_000), err: 0.0, source: 0, rx_duration: 0.0, net_correction: 0.0 };
    let cook_ok = |t: (i64, i64)| Some((add_double_to_timespec(t, 0.5), 1.0e-6));
    let cook_fail = |_t: (i64, i64)| None;
    let cook_sw = |t: (i64, i64)| (add_double_to_timespec(t, 0.5), 2.0e-6);

    // (rx_ntp_length, family, l2_length, link_speed, tx_comp, rx_comp), and whether cook fails.
    let hw_params = |rx, fam, l2, spd, txc, rxc| HwTsParams {
        hw_ts: hw,
        rx_ntp_length: rx,
        family: fam,
        l2_length: l2,
        link_speed: spd,
        l2_udp4_ntp_start: 42,
        l2_udp6_ntp_start: 62,
        tx_comp: txc,
        rx_comp: rxc,
    };

    for line in vectors.lines().filter(|l| l.starts_with("HW ") || l.starts_with("SW ")) {
        let name = f(line, "name");
        let result = match (line.split_whitespace().next().unwrap(), name) {
            ("HW", "rx_v4_default_l2") => {
                process_hw_timestamp(&base, &hw_params(90, IPADDR_INET4, 0, 1000, 0.0, 3.0e-7), cook_ok)
            }
            ("HW", "rx_v6_default_l2") => {
                process_hw_timestamp(&base, &hw_params(90, IPADDR_INET6, 0, 1000, 0.0, 3.0e-7), cook_ok)
            }
            ("HW", "rx_explicit_l2") => {
                process_hw_timestamp(&base, &hw_params(90, IPADDR_INET4, 200, 1000, 0.0, 0.0), cook_ok)
            }
            ("HW", "tx_txcomp") => {
                process_hw_timestamp(&base, &hw_params(0, IPADDR_INET4, 0, 1000, 5.0e-7, 0.0), cook_ok)
            }
            ("HW", "rx_no_linkspeed") => {
                process_hw_timestamp(&base, &hw_params(90, IPADDR_INET4, 0, 0, 0.0, 0.0), cook_ok)
            }
            ("HW", "cook_fail") => {
                process_hw_timestamp(&base, &hw_params(90, IPADDR_INET4, 0, 1000, 0.0, 0.0), cook_fail)
            }
            ("HW", "delay_reject") => {
                let far = LocalTimestamp { ts: (2000, 0), source: 9, rx_duration: 9.0, net_correction: 9.0, ..base };
                process_hw_timestamp(&far, &hw_params(90, IPADDR_INET4, 0, 1000, 0.0, 0.0), cook_ok)
            }
            ("SW", "accept") => {
                let l = LocalTimestamp { ts: (2000, 700_000_000), ..base };
                process_sw_timestamp(&l, (2000, 200_000_000), cook_sw)
            }
            ("SW", "delay_reject") => {
                let l = LocalTimestamp { ts: (2005, 0), ..base };
                process_sw_timestamp(&l, (2000, 200_000_000), cook_sw)
            }
            (tag, other) => panic!("unknown case {tag} {other}"),
        };

        let want_ret = n(line, "ret") == 1;
        assert_eq!(result.is_some(), want_ret, "{name} ret");
        if let Some(r) = result {
            assert_eq!(r.ts.0, n(line, "sec"), "{name} sec");
            assert_eq!(r.ts.1, n(line, "nsec"), "{name} nsec");
            close(r.err, fl(line, "err"), "err");
            assert_eq!(r.source as i64, n(line, "src"), "{name} src");
            close(r.rx_duration, fl(line, "rxdur"), "rxdur");
            close(r.net_correction, fl(line, "netcorr"), "netcorr");
        }
    }
}
