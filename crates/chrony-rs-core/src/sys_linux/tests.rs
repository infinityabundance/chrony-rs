//! Differential oracle for the Linux tick/frequency arithmetic vs verbatim copies of
//! chrony's `kernelvercmp` / `guess_hz` / `get_version_specific_details` / `set_frequency`
//! split / frequency reconstruction (`research/oracle/sys_linux-arith-c-vectors.txt`).

use super::*;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("missing {key} in: {line}"))
}
fn i(line: &str, key: &str) -> i32 {
    field(line, key).parse().unwrap()
}
fn d(line: &str, key: &str) -> f64 {
    field(line, key).parse().unwrap()
}
fn ver(s: &str) -> (i32, i32, i32) {
    let p: Vec<i32> = s.split('.').map(|x| x.parse().unwrap()).collect();
    (p[0], p[1], p[2])
}
/// Identical IEEE-754 f64 arithmetic on both sides — expect a bit-for-bit match (with -0.0
/// == 0.0 handled naturally by float equality).
fn close(a: f64, b: f64, what: &str) {
    assert!((a - b).abs() <= 1e-12 * (1.0 + a.abs().max(b.abs())), "{what}: rust={a} c={b}");
}

#[test]
fn matches_real_c_sys_linux_arith_vectors() {
    let vectors = include_str!("../../../../research/oracle/sys_linux-arith-c-vectors.txt");
    let mut counts = (0, 0, 0, 0, 0);
    for line in vectors.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        match line.split_whitespace().next().unwrap() {
            "VCMP" => {
                let cmp = kernel_version_cmp(ver(field(line, "a")), ver(field(line, "b")));
                // chrony only relies on the sign; the oracle records the exact value.
                assert_eq!(cmp, i(line, "cmp"), "VCMP {line}");
                counts.0 += 1;
            }
            "GHZ" => {
                let hz = guess_hz(i(line, "tick"));
                assert_eq!(hz.unwrap_or(-1), i(line, "hz"), "GHZ {line}");
                counts.1 += 1;
            }
            "VDET" => {
                let det = version_specific_details(i(line, "hz"), ver(field(line, "ver")));
                let ok = i(line, "ok") == 1;
                assert_eq!(det.is_some(), ok, "VDET ok {line}");
                if let Some(det) = det {
                    close(det.dhz, d(line, "dhz"), "VDET dhz");
                    assert_eq!(det.nominal_tick, i(line, "ntick"), "VDET ntick");
                    assert_eq!(det.max_tick_bias, i(line, "mtb"), "VDET mtb");
                    assert_eq!(det.tick_update_hz, i(line, "tuh"), "VDET tuh");
                    assert_eq!(det.have_setoffset as i32, i(line, "hso"), "VDET hso");
                }
                counts.2 += 1;
            }
            "SPLIT" => {
                let s = compute_frequency_split(
                    d(line, "fppm"),
                    d(line, "hz"),
                    i(line, "nom"),
                    i(line, "cdt"),
                    i(line, "hz"),
                );
                assert_eq!(s.delta_tick, i(line, "delta"), "SPLIT delta {line}");
                close(s.freq, d(line, "freq"), "SPLIT freq");
                assert_eq!(s.tick, i(line, "tick") as i64, "SPLIT tick {line}");
                counts.3 += 1;
            }
            "RECON" => {
                let ppm = reconstruct_freq_ppm(d(line, "dhz"), i(line, "dt"), d(line, "kf"));
                close(ppm, d(line, "ppm"), "RECON {line}");
                counts.4 += 1;
            }
            other => panic!("unknown tag {other}"),
        }
    }
    assert_eq!(counts, (6, 10, 8, 15, 4), "expected the full battery");
}

/// A `SysLinux` built for a modern kernel composes the split + reconstruct into a
/// `set_frequency` whose applied value round-trips through an identity `adjtimex`, and whose
/// intermediate tick/freq match the split. `read_frequency` inverts it.
#[test]
fn set_and_read_frequency_over_identity_adjtimex() {
    let mut clock = SysLinux::new(100, (5, 4, 0)).expect("supported kernel");
    assert_eq!(clock.nominal_tick, 10000);

    // Capture what set_frequency sends to adjtimex; identity keeps it unchanged.
    let mut sent = LinuxTimex::default();
    let applied = clock.set_frequency(250.0, |txc| sent = *txc);
    assert_eq!(sent.tick, 9997); // nominal 10000 - delta 3
    assert_eq!(sent.freq, (50.0 * FREQ_SCALE) as i64);
    assert_eq!(clock.current_delta_tick, 3);
    // With an identity adjtimex the effective frequency is exactly the request.
    close(applied, 250.0, "applied");

    // read_frequency reconstructs the same ppm from the kernel tick/freq.
    let read = clock.read_frequency(|txc| {
        txc.tick = 9997;
        txc.freq = (50.0 * FREQ_SCALE) as i64;
    });
    close(read, 250.0, "read");
    assert_eq!(clock.current_delta_tick, 3);
}
