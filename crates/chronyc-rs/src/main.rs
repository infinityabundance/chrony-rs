//! `chronyc-rs` — chrony-rs control client and output-parity tool.
//!
//! # What works today
//!
//! `chronyc-rs render-tracking <fixture.json>` renders a `tracking` report from a
//! structured JSON fixture, reproducing `chronyc tracking`'s exact label-aligned
//! layout (see [`chrony_rs_core::report`]). This is the output-parity surface: it
//! lets us byte-compare formatting against real chrony output *before* a live
//! daemon and control socket exist.
//!
//! # What does not work yet (and why that's stated, not hidden)
//!
//! Connecting to a running daemon over chrony's Unix/UDP control protocol is a
//! deferred negative capability (`docs/negative-capabilities.md`). `chronyc-rs`
//! therefore cannot yet run `chronyc-rs tracking` against `chronyd`; it renders
//! reports you supply. Pretending otherwise would be exactly the kind of fake
//! parity the project forbids.

use std::process::ExitCode;

use chrony_rs_core::report::{SourcesReport, TrackingReport};

const USAGE: &str = "\
chronyc-rs — chrony-rs control/output-parity tool

USAGE:
    chronyc-rs render-tracking <FIXTURE.json>   Render a tracking report from JSON
    chronyc-rs render-sources [-v] <FIXTURE.json>
                                                Render a sources report from JSON
    chronyc-rs --version                        Print version information
    chronyc-rs --help                           Print this message

The live control-socket transport is not yet implemented; commands that would
query a running daemon (tracking, sources, sourcestats) are deferred. See
docs/negative-capabilities.md and docs/chronyc-parity.md.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Some((cmd, rest)) => match cmd.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                ExitCode::SUCCESS
            }
            "--version" | "-v" => {
                println!("chronyc-rs {}", env!("CARGO_PKG_VERSION"));
                ExitCode::SUCCESS
            }
            "render-tracking" => match rest.first() {
                Some(path) => render_tracking(path),
                None => {
                    eprintln!("error: render-tracking requires a FIXTURE.json argument\n\n{USAGE}");
                    ExitCode::from(2)
                }
            },
            "render-sources" => {
                // Accept an optional `-v` (verbose legend) flag before the path.
                let (verbose, path) = match rest.split_first() {
                    Some((flag, tail)) if flag == "-v" || flag == "--verbose" => {
                        (true, tail.first())
                    }
                    _ => (false, rest.first()),
                };
                match path {
                    Some(path) => render_sources(path, verbose),
                    None => {
                        eprintln!(
                            "error: render-sources requires a FIXTURE.json argument\n\n{USAGE}"
                        );
                        ExitCode::from(2)
                    }
                }
            }
            // A bare `tracking`/`sources`/... is what a user would reach for. We
            // fail *closed* with an explanation instead of silently doing nothing,
            // so the deferred capability is visible at the point of use.
            "tracking" | "sources" | "sourcestats" | "activity" | "ntpdata" => {
                eprintln!(
                    "error: '{cmd}' needs a live control-socket connection, which is not yet \
                     implemented.\n       Use 'render-tracking <fixture.json>' for offline output \
                     parity. See docs/negative-capabilities.md."
                );
                ExitCode::from(3)
            }
            other => {
                eprintln!("error: unknown command '{other}'\n\n{USAGE}");
                ExitCode::from(2)
            }
        },
    }
}

fn render_tracking(path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read fixture '{path}': {e}");
            return ExitCode::from(2);
        }
    };
    match serde_json::from_str::<TrackingReport>(&text) {
        Ok(report) => {
            // render() includes the trailing newline; use print! not println!.
            print!("{}", report.render());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: invalid tracking fixture '{path}': {e}");
            ExitCode::from(1)
        }
    }
}

fn render_sources(path: &str, verbose: bool) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read fixture '{path}': {e}");
            return ExitCode::from(2);
        }
    };
    match serde_json::from_str::<SourcesReport>(&text) {
        Ok(report) => {
            print!("{}", report.render(verbose));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: invalid sources fixture '{path}': {e}");
            ExitCode::from(1)
        }
    }
}
