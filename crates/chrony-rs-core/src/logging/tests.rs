//! Differential tests for the logging core vs a verbatim copy of chrony logging.c's timestamp
//! (strftime), body format, banner cadence, and severity clamp (research/oracle/logging-c-vectors.txt).

use super::*;
use crate::util::time_to_iso8601;

const VECTORS: &str = include_str!("../../../../research/oracle/logging-c-vectors.txt");

fn field<'a>(l: &'a str, k: &str) -> &'a str {
    l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap()
}

#[test]
fn iso_timestamp_matches_strftime() {
    let mut n = 0;
    for l in VECTORS.lines().filter(|l| l.starts_with("ISO ")) {
        let t: i64 = field(l, "t").parse().unwrap();
        assert_eq!(time_to_iso8601(t), field(l, "s"), "ISO t={t}");
        n += 1;
    }
    assert!(n >= 6);
}

#[test]
fn severity_clamp_matches() {
    let mut lg = Logger::initialise();
    for l in VECTORS.lines().filter(|l| l.starts_with("CLAMP ")) {
        let inp: i32 = field(l, "in").parse().unwrap();
        let out: i32 = field(l, "out").parse().unwrap();
        lg.set_min_severity(inp);
        assert_eq!(lg.min_severity(), out, "CLAMP in={inp}");
    }
}

#[test]
fn banner_cadence_matches() {
    for l in VECTORS.lines().filter(|l| l.starts_with("BANNER ")) {
        let banner: i32 = field(l, "banner").parse().unwrap();
        let writes: u64 = field(l, "writes").parse().unwrap();
        let emit: i32 = field(l, "emit").parse().unwrap();
        let got = log_banner_lines("mybanner", writes, banner).is_some();
        assert_eq!(got as i32, emit, "BANNER banner={banner} writes={writes}");
    }
    let lines = log_banner_lines("HELLO", 0, 4).unwrap();
    assert_eq!(lines, ["=====".to_string(), "HELLO".to_string(), "=====".to_string()]);
}

#[test]
fn log_line_and_body_format() {
    assert_eq!(format_log_body("boom", false), "boom\n");
    assert_eq!(format_log_body("boom", true), "Fatal error : boom\n");
    assert_eq!(format_log_line(0, "hi", false), "1970-01-01T00:00:00Z hi\n");
    assert_eq!(format_log_line(1_700_000_000, "x", true), "2023-11-14T22:13:20Z Fatal error : x\n");

    let mut lg = Logger::initialise();
    assert_eq!(lg.get_context_severity(0b10), LOGS_DEBUG);
    lg.set_context(0b10);
    assert_eq!(lg.get_context_severity(0b10), LOGS_INFO);
    assert_eq!(lg.get_context_severity(0b01), LOGS_DEBUG);
    lg.unset_context(0b10);
    assert_eq!(lg.get_context_severity(0b10), LOGS_DEBUG);
}
