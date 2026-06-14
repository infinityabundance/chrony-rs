//! `chronyd-rs` — the chrony-rs daemon and replay binary.
//!
//! # Deployment boundary (this is load-bearing, not boilerplate)
//!
//! This binary does **not** discipline a real system clock. The only modes wired
//! up today are read-only/offline:
//!
//!   * `--check-config <file>` — parse and validate a chrony config, report
//!     diagnostics, exit non-zero on error.
//!   * `--replay <trace.json>` — structurally load a deterministic replay trace
//!     (the runner that compares against an oracle is a later campaign).
//!
//! A `--lab-daemon` mode that mutates a clock is intentionally absent and will be
//! gated behind explicit opt-in and lab-only guards when it lands (see
//! `docs/deployment-boundary.md`, Stage 6+). Refusing to ship a clock-mutating
//! default is a deliberate safety posture, not an unfinished TODO.
//!
//! Argument parsing is hand-rolled to keep the dependency tree minimal; this is a
//! tiny, explicit surface and a CLI framework would be more code than it saves.

use std::process::ExitCode;

use chrony_rs_core::replay::{self, CheckResult};
use chrony_rs_core::trace::Trace;
use chrony_rs_core::{config, TARGET_CHRONY_VERSION, TRACE_SCHEMA};

const USAGE: &str = "\
chronyd-rs — forensic chrony reconstruction (lab/replay only)

USAGE:
    chronyd-rs --check-config <FILE>    Parse and validate a chrony config
    chronyd-rs --replay <TRACE.json>    Load and validate a replay trace
    chronyd-rs --version                Print version information
    chronyd-rs --help                   Print this message

This binary does not mutate the host clock. See docs/deployment-boundary.md.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Some((flag, rest)) => match flag.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                ExitCode::SUCCESS
            }
            "--version" | "-v" => {
                println!(
                    "chronyd-rs {} (targeting chrony {}, trace schema {})",
                    env!("CARGO_PKG_VERSION"),
                    TARGET_CHRONY_VERSION,
                    TRACE_SCHEMA
                );
                ExitCode::SUCCESS
            }
            "--check-config" => match rest.first() {
                Some(path) => check_config(path),
                None => {
                    eprintln!("error: --check-config requires a FILE argument\n\n{USAGE}");
                    ExitCode::from(2)
                }
            },
            "--replay" => match rest.first() {
                Some(path) => replay(path),
                None => {
                    eprintln!("error: --replay requires a TRACE.json argument\n\n{USAGE}");
                    ExitCode::from(2)
                }
            },
            other => {
                eprintln!("error: unknown argument '{other}'\n\n{USAGE}");
                ExitCode::from(2)
            }
        },
    }
}

/// Parse a config file and print diagnostics. Exit code mirrors chrony's
/// `--check-config`: 0 when clean, non-zero when any error diagnostic is present.
fn check_config(path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            // Fail closed with a typed, legible error rather than a panic — config
            // file trust is a security boundary (CHRONY.SECURITY.3).
            eprintln!("error: cannot read config '{path}': {e}");
            return ExitCode::from(2);
        }
    };

    let out = config::parse(&text);
    for d in &out.diagnostics {
        // Diagnostics go to stderr so a clean run produces no stdout noise, matching
        // the quiet-on-success convention of check tools.
        eprintln!("{path}: {d}");
    }

    if out.has_errors() {
        eprintln!("{path}: configuration has errors");
        ExitCode::from(1)
    } else {
        let sources = out.config.sources().count();
        println!("{path}: OK ({sources} source(s), {} directive(s))", out.config.directives.len());
        ExitCode::SUCCESS
    }
}

/// Load a replay trace and run it through the deterministic brain
/// (`chrony_rs_core::replay`). Prints the decision-log hash and the placeholder
/// selection, and — if the trace pins `expected.decision_events_sha256` — reports
/// whether the run matched, exiting non-zero on a mismatch (a regression).
///
/// Note on scope: this executes *deterministic event processing*, not chrony's
/// source-selection or discipline policy (Stages 4–5). The runner's own module
/// doc and `docs/negative-capabilities.md` state exactly what is and isn't decided.
fn replay(path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read trace '{path}': {e}");
            return ExitCode::from(2);
        }
    };

    let trace = match Trace::from_json(&text) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: invalid trace '{path}': {e}");
            return ExitCode::from(1);
        }
    };

    let report = match replay::run(&trace) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: replay failed for '{path}': {e}");
            return ExitCode::from(1);
        }
    };

    println!(
        "{path}: replayed {} event(s) (chrony {}, schema {})",
        report.events_processed, trace.chrony_version, trace.trace_schema
    );
    println!("  selected source (placeholder): {}", report.selected_source.as_deref().unwrap_or("none"));
    println!("  decision-log sha256: {}", report.decision_log_sha256);

    match report.check_against(&trace) {
        CheckResult::Match => {
            println!("  expectation: MATCH");
            ExitCode::SUCCESS
        }
        CheckResult::NothingToCheck => {
            println!("  expectation: none pinned");
            ExitCode::SUCCESS
        }
        CheckResult::Mismatch { field, expected, actual } => {
            eprintln!("  expectation: MISMATCH on {field}\n    expected: {expected}\n    actual:   {actual}");
            ExitCode::from(1)
        }
    }
}
