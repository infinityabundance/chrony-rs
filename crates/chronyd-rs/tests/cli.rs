//! End-to-end CLI behavior for `chronyd-rs`.
//!
//! These assert the *observable* contract operators and scripts depend on: exit
//! codes and the shape of stdout/stderr. Exit-code parity with chrony's
//! `--check-config` (0 clean, non-zero on error) is court `CHRONYC.12`-adjacent
//! and is enforced here, not just unit-tested in the parser.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_chronyd-rs")
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn check_config_clean_file_exits_zero() {
    let out = Command::new(bin())
        .arg("--check-config")
        .arg(fixture("good.conf"))
        .output()
        .expect("run chronyd-rs");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("OK"));
}

#[test]
fn check_config_bad_file_exits_one() {
    let out = Command::new(bin())
        .arg("--check-config")
        .arg(fixture("bad.conf"))
        .output()
        .expect("run chronyd-rs");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("CFG_UNKNOWN_DIRECTIVE"), "stderr was: {stderr}");
}

#[test]
fn check_config_missing_file_exits_two() {
    let out = Command::new(bin())
        .arg("--check-config")
        .arg("/no/such/file.conf")
        .output()
        .expect("run chronyd-rs");
    // Usage/IO errors are distinguished from config errors: 2, not 1.
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn replay_executes_trace_and_reports_hash() {
    let out = Command::new(bin())
        .arg("--replay")
        .arg(fixture("sample-trace.json"))
        .output()
        .expect("run chronyd-rs");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("replayed 3 event(s)"), "stdout: {stdout}");
    // A 64-char hex decision-log hash must be present and stable across runs.
    assert!(stdout.contains("decision-log sha256:"), "stdout: {stdout}");

    let out2 = Command::new(bin())
        .arg("--replay")
        .arg(fixture("sample-trace.json"))
        .output()
        .expect("run chronyd-rs");
    assert_eq!(out.stdout, out2.stdout, "replay output must be deterministic");
}

#[test]
fn version_mentions_target_chrony() {
    let out = Command::new(bin()).arg("--version").output().expect("run");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("chrony 4.5"));
}

#[test]
fn no_args_prints_usage_and_exits_two() {
    let out = Command::new(bin()).output().expect("run");
    assert_eq!(out.status.code(), Some(2));
}
