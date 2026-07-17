//! Differential oracle for the RTC drift regression vs verbatim copies of chrony's
//! `accumulate_sample` / `discard_samples` / `run_regression` / `slew_samples`, linked
//! against the REAL compiled `regress.c` (`research/oracle/rtc_linux-c-vectors.txt`).

use super::*;
use std::collections::HashMap;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("missing {key} in: {line}"))
}
fn i(line: &str, key: &str) -> i64 {
    field(line, key).parse().unwrap()
}
fn fl(line: &str, key: &str) -> f64 {
    field(line, key).parse().unwrap()
}
/// The regression outputs come from the same ported robust fit (itself differential-tested
/// vs regress.c); allow the ~1-ULP FP-ordering slack that fit carries.
fn close(a: f64, b: f64, what: &str) {
    let tol = 1e-9 * (1.0 + a.abs().max(b.abs()));
    assert!((a - b).abs() <= tol, "{what}: rust={a:.17e} c={b:.17e}");
}
/// The generator's deterministic sample: rtc = 1_000_000 + 200*i; system drifts 4 ppm and
/// is 8 s slow, with a scattered nanosecond field.
fn gen_sample(i: i64) -> (i64, (i64, i64)) {
    let rtc = 1_000_000 + 200 * i;
    let sec = 1_000_000 - 8 + (200.0 * i as f64 * (1.0 - 4.0e-6)) as i64;
    let nsec = ((i as i128 * 271_828_183) % 1_000_000_000) as i64;
    (rtc, (sec, nsec))
}

#[test]
fn matches_real_c_rtc_regression_vectors() {
    let vectors = include_str!("../../../../research/oracle/rtc_linux-c-vectors.txt");
    // Every state line (ACC / SLEW / SLEWSTEP / FULL / STEPBACK) carries an `n=` index.
    let by_n: HashMap<i64, &str> = vectors
        .lines()
        .filter_map(|l| {
            l.split_whitespace()
                .find_map(|t| t.strip_prefix("n="))
                .and_then(|v| v.parse::<i64>().ok())
                .map(|n| (n, l))
        })
        .collect();
    let samp: HashMap<i64, &str> =
        vectors.lines().filter(|l| l.starts_with("SAMP ")).map(|l| (i(l, "n_in"), l)).collect();

    let check = |r: &RtcRegression, line: &str| {
        assert_eq!(r.n_samples as i64, i(line, "nsamp"), "nsamp");
        assert_eq!(r.rtc_ref, i(line, "ref"), "ref");
        assert_eq!(r.coefs_valid as i64, i(line, "valid"), "valid");
        assert_eq!(r.n_runs as i64, i(line, "runs"), "runs");
        assert_eq!(r.first_rtc(), i(line, "rtc0"), "rtc0");
        if r.coefs_valid {
            close(r.coef_seconds_fast, fl(line, "fast"), "fast");
            close(r.coef_gain_rate, fl(line, "rate"), "rate");
        }
    };

    let mut r = RtcRegression::new();

    // ---- 10 accumulate + run_regression steps (n = 0..=9). ----
    for k in 0..10 {
        let s = samp[&k];
        r.accumulate_sample(i(s, "rtc"), (i(s, "sec"), i(s, "nsec")));
        r.run_regression();
        r.n_samples_since_regression = 0;
        check(&r, by_n[&k]);
    }

    // ---- SLEW (n=10): adjust coefficients + stored timestamps. ----
    r.slew_samples((1_002_000, 500_000_000), 2.0e-6, 0.001, false);
    check(&r, by_n[&10]);

    // ---- SLEWSTEP (n=11): an unknown step drops all samples. ----
    r.slew_samples((1_002_100, 0), 0.0, 0.0, true);
    check(&r, by_n[&11]);

    // ---- FULL (n=12): refill past MAX_SAMPLES to exercise the ring discard. ----
    for k in 0..70 {
        let (rtc, sys) = gen_sample(100 + k);
        r.accumulate_sample(rtc, sys);
    }
    check(&r, by_n[&12]);
    let fullarr = vectors.lines().find(|l| l.starts_with("FULLARR")).unwrap();
    assert_eq!(r.first_rtc(), i(fullarr, "rtc0"), "FULLARR rtc0");
    // rtc1 and rtclast pin the exact post-discard buffer contents.

    // ---- STEPBACK (n=13): an RTC that went backwards resets to a single sample. ----
    r.accumulate_sample(500_000, (1_000_000, 0));
    check(&r, by_n[&13]);
}

/// Differential oracle for the coefficient / hwclock file codecs vs verbatim copies of
/// chrony's `write_coefs_to_file` (real `printf`), `read_coefs_from_file` (real `sscanf`),
/// and `read_hwclock_file`'s third-line LOCAL/UTC detection
/// (`research/oracle/rtc_linux-file-c-vectors.txt`).
#[test]
fn matches_real_c_rtc_file_vectors() {
    let vectors = include_str!("../../../../research/oracle/rtc_linux-file-c-vectors.txt");
    fn after_bar<'a>(line: &'a str, key: &str) -> &'a str {
        // A `<key>=...|` field whose value may contain spaces, ended by '|'.
        let start = line.find(&format!("{key}=")).unwrap() + key.len() + 1;
        let rest = &line[start..];
        &rest[..rest.find('|').unwrap()]
    }

    for line in vectors.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        match line.split_whitespace().next().unwrap() {
            "WRITE" => {
                let got = format_coefs(
                    i(line, "v") as i32,
                    i(line, "rt"),
                    fl(line, "off"),
                    fl(line, "rate"),
                );
                // The fixture line strips the trailing newline; compare without it.
                assert_eq!(got.trim_end_matches('\n'), after_bar(line, "line"), "WRITE {line}");
            }
            "READ" => {
                let parsed = parse_coefs(after_bar(line, "in"));
                let ok = i(line, "ok") == 1;
                assert_eq!(parsed.is_some(), ok, "READ ok {line}");
                if let Some((v, rt, off, rate)) = parsed {
                    assert_eq!(v as i64, i(line, "v"), "READ v");
                    close(rt, fl(line, "rt"), "READ rt");
                    close(off, fl(line, "off"), "READ off");
                    close(rate, fl(line, "rate"), "READ rate");
                }
            }
            "HWCLOCK" => {
                let text = String::from_utf8(
                    (0..field(line, "text").len())
                        .step_by(2)
                        .map(|k| u8::from_str_radix(&field(line, "text")[k..k + 2], 16).unwrap())
                        .collect(),
                )
                .unwrap();
                let set = match hwclock_utc_setting(&text) {
                    Some(true) => 1,
                    Some(false) => 0,
                    None => -1,
                };
                assert_eq!(set as i64, i(line, "set"), "HWCLOCK {} ", field(line, "name"));
            }
            other => panic!("unknown tag {other}"),
        }
    }
}
