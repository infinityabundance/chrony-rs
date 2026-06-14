//! `xtask` — chrony-rs build automation, in Rust (the conventional `cargo xtask`
//! pattern; no Make, no shell for the parts that must be portable and tested).
//!
//! # Why generated docs + a freshness gate
//!
//! The machine-derivable facts in chrony-rs's docs — the declared chrony version,
//! the directive recognition set, the source-option tables, the `unsafe` count,
//! the oracle fixture inventory — are exactly the things that go stale when code
//! changes and prose doesn't. So those facts are **generated from the code** (the
//! single source of truth) and written to `docs/generated/`, and a freshness gate
//! refuses to let the generated files drift.
//!
//! Subcommands:
//!
//! * `cargo xtask gen`   — regenerate `docs/generated/*` from the code.
//! * `cargo xtask check` — verify the generated docs are up to date (and the
//!   `unsafe` ledger is accurate); exit non-zero if not. This is what the
//!   pre-commit hook runs.
//!
//! Generated output is **deterministic** — no timestamps, no host paths — so the
//! freshness comparison is a pure content diff. Adding a timestamp here would make
//! every check fail spuriously; don't.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod generate;

fn repo_root() -> PathBuf {
    // xtask lives at <root>/xtask, so the manifest dir's parent is the repo root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent dir")
        .to_path_buf()
}

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1);
    match cmd.as_deref() {
        Some("gen") => gen(),
        Some("check") => check(),
        Some(other) => {
            eprintln!("xtask: unknown subcommand '{other}'\n\nUSAGE: cargo xtask [gen|check]");
            ExitCode::from(2)
        }
        None => {
            eprintln!("USAGE: cargo xtask [gen|check]\n  gen    regenerate docs/generated/*\n  check  fail if generated docs are stale");
            ExitCode::from(2)
        }
    }
}

/// Every generated artifact: (path relative to repo root, content).
fn artifacts(root: &Path) -> Vec<(PathBuf, String)> {
    vec![(
        root.join("docs/generated/status.md"),
        generate::status_md(root),
    )]
}

fn gen() -> ExitCode {
    let root = repo_root();
    for (path, content) in artifacts(&root) {
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("xtask: cannot create {}: {e}", parent.display());
                return ExitCode::FAILURE;
            }
        }
        if let Err(e) = std::fs::write(&path, content) {
            eprintln!("xtask: cannot write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!("generated {}", path.display());
    }
    ExitCode::SUCCESS
}

fn check() -> ExitCode {
    let root = repo_root();
    let mut stale = Vec::new();
    for (path, expected) in artifacts(&root) {
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
        if on_disk != expected {
            stale.push(path);
        }
    }

    // Also verify the documented `unsafe` count is accurate: a hard invariant of
    // the security boundary that prose alone could silently break.
    let actual_unsafe = generate::count_unsafe(&root);
    let security = std::fs::read_to_string(root.join("docs/security-boundary.md")).unwrap_or_default();
    let unsafe_claim_ok = security.contains(&format!("count: {actual_unsafe}"));

    if stale.is_empty() && unsafe_claim_ok {
        println!("xtask check: generated docs are up to date; unsafe ledger accurate ({actual_unsafe}).");
        return ExitCode::SUCCESS;
    }
    for p in &stale {
        eprintln!("xtask check: STALE generated doc: {}", p.display());
    }
    if !unsafe_claim_ok {
        eprintln!(
            "xtask check: docs/security-boundary.md does not state the actual unsafe count ({actual_unsafe})"
        );
    }
    eprintln!("\nRun `cargo xtask gen` and commit the result.");
    ExitCode::FAILURE
}
