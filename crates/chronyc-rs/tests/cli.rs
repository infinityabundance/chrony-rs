//! End-to-end CLI behavior for `chronyc-rs`.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_chronyc-rs")
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn render_tracking_matches_known_layout() {
    let out = Command::new(bin())
        .arg("render-tracking")
        .arg(fixture("tracking.json"))
        .output()
        .expect("run chronyc-rs");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    // Byte-exact comparison of the whole block, including alignment and newline.
    let expected = "\
Reference ID    : 0A000001 (ntp.example.com)
Stratum         : 2
Ref time (UTC)  : Wed May 25 10:20:30 2022
System time     : 0.000020390 seconds fast of NTP time
Last offset     : +0.000001234 seconds
RMS offset      : 0.000005678 seconds
Frequency       : 12.345 ppm fast
Residual freq   : +0.001 ppm
Skew            : 0.234 ppm
Root delay      : 0.001234567 seconds
Root dispersion : 0.000456789 seconds
Update interval : 64.5 seconds
Leap status     : Normal
";
    assert_eq!(String::from_utf8_lossy(&out.stdout), expected);
}

#[test]
fn live_tracking_fails_closed_with_explanation() {
    // The deferred capability must be visible at the point of use, not silent.
    let out = Command::new(bin()).arg("tracking").output().expect("run");
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not yet implemented"), "stderr was: {stderr}");
}

#[test]
fn invalid_fixture_exits_one() {
    let out = Command::new(bin())
        .arg("render-tracking")
        .arg("/no/such/fixture.json")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2)); // IO error → usage class
}
