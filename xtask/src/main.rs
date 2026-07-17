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

mod capture_trace;
mod compare_diagnostics;
mod generate;
mod parity;
mod verify;

fn repo_root() -> PathBuf {
    // xtask lives at <root>/xtask, so the manifest dir's parent is the repo root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent dir")
        .to_path_buf()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str());
    match cmd {
        Some("gen") => gen(),
        Some("check") => check(),
        Some("capture-trace") => {
            let root = repo_root();
            let mut chronyd_path = PathBuf::from("chronyd");
            let mut config_path = root.join("tools/oracle/config-fixtures/valid_minimal.conf");
            let mut output_path = root.join("research/oracle/captured-trace.json");
            let mut duration_secs = 10u64;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--chronyd" => { i += 1; chronyd_path = args[i].clone().into(); }
                    "--config" => { i += 1; config_path = root.join(&args[i]); }
                    "--output" => { i += 1; output_path = root.join(&args[i]); }
                    "--duration" => { i += 1; duration_secs = args[i].parse().unwrap_or(10); }
                    _ => {}
                }
                i += 1;
            }

            match capture_trace::run_capture(
                &capture_trace::CaptureArgs {
                    chronyd_path: &chronyd_path,
                    config_path: &config_path,
                    output_path: &output_path,
                    duration_secs,
                }
            ) {
                Ok((path, msg)) => {
                    println!("{msg}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("capture-trace: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("verify") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            let output_path = args.iter().position(|a| a == "--output").and_then(|i| args.get(i + 1).map(|s| s.as_str()));
            let court_mode = args.iter().any(|a| a == "--court");
            let receipt = verify::run_verification(output_path, court_mode);
            let passed = receipt.checks.iter().all(|c| c.passed);
            eprintln!("verify: {}/{} checks passed", receipt.checks.iter().filter(|c| c.passed).count(), receipt.checks.len());
            if passed { ExitCode::SUCCESS } else { ExitCode::FAILURE }
        }
        Some(other) => {
            eprintln!("xtask: unknown subcommand '{other}'\n\nUSAGE: cargo xtask [gen|check|verify|capture-trace|compare-diagnostics]\n  gen                  regenerate docs/generated/*\n  check                fail if generated docs are stale\n  verify               run verification suite and produce receipt\n  capture-trace        capture chronyd trace for oracle comparison court\n  compare-diagnostics  compare parser diagnostics against real chronyd [--chronyd <path>]");
            ExitCode::from(2)
        }
        None => {
            eprintln!("USAGE: cargo xtask [gen|check|verify|capture-trace|compare-diagnostics]\n  gen                  regenerate docs/generated/*\n  check                fail if generated docs are stale\n  verify               run verification suite and produce receipt\n  capture-trace        capture chronyd trace for oracle comparison court\n  compare-diagnostics  compare parser diagnostics against real chronyd [--chronyd <path>]");
            ExitCode::from(2)
        }
    }
}

/// Every generated artifact: (path relative to repo root, content).
fn artifacts(root: &Path) -> Vec<(PathBuf, String)> {
    vec![
        (root.join("docs/generated/status.md"), generate::status_md(root)),
        (root.join("docs/generated/port-parity.md"), parity::port_parity_md(root)),
        (
            root.join("docs/generated/port-parity-functions.md"),
            parity::port_parity_functions_md(root),
        ),
        (
            root.join("docs/negative-capabilities.md"),
            generate::negative_capabilities_md(root),
        ),
        (root.join("README.md"), generate::root_readme(root)),
        (root.join("crates/chrony-rs/README.md"), generate::facade_readme(root)),
        (root.join("crates/chrony-rs-core/README.md"), generate::core_readme(root)),
        (root.join("crates/chronyd-rs/README.md"), generate::chronyd_readme(root)),
        (root.join("crates/chronyc-rs/README.md"), generate::chronyc_readme(root)),
    ]
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

/// A machine-derived fact that a *curated* (non-generated) doc restates, and the
/// distinctive phrase that doc must therefore contain. This is how prose docs are
/// freshness-gated without being fully generated: the fact comes from the code, and
/// the gate fails closed if its canonical home stops stating the current value.
struct AssertedFact {
    /// Doc path, relative to repo root.
    doc: &'static str,
    /// Human label for the failure message.
    label: String,
    /// Exact substring the doc must contain (built from the code-derived value).
    needle: String,
}

/// The curated map of headline facts → their canonical home docs. Every fact here
/// is derived from code/inventory, so a doc that drifts away from the live value
/// fails `cargo xtask check`. New drift-prone claims should be added here (or the
/// doc made fully generated) rather than left ungated.
fn asserted_facts(root: &Path) -> Vec<AssertedFact> {
    let ver = chrony_rs_core::TARGET_CHRONY_VERSION;
    let directives = chrony_rs_core::config::known_directives().len();
    let facts = parity::canonical_facts(root);
    let unsafe_count = generate::count_unsafe(root);
    let inventory = format!("{} `.c` files / {} functions", facts.c_files, facts.c_functions);

    let mut v = Vec::new();

    // Target chrony version — pinned in EVERY living doc that names the oracle, so
    // a version bump must touch all of them. (Evidence receipts under reports/ and
    // research/ are deliberately NOT pinned: they are frozen snapshots of what was
    // witnessed and must keep stating the version they actually saw.)
    for doc in [
        // (README.md is generated, so byte-gated, not pinned here.)
        "docs/README.md",
        "docs/chronyc-parity.md",
        "docs/compatibility.md",
        "docs/config-atlas.md",
        "docs/deployment-boundary.md",
        "docs/distro-defaults.md",
        "docs/oracle.md",
        "docs/port-parity.md",
        "docs/source-archaeology.md",
        "docs/version-lineage.md",
    ] {
        v.push(AssertedFact {
            doc,
            label: format!("target chrony version ({ver})"),
            needle: format!("chrony {ver}"),
        });
    }

    // Recognized directive-set size, in each living doc that restates it.
    for doc in ["docs/config-atlas.md", "docs/oracle.md", "docs/source-archaeology.md"] {
        v.push(AssertedFact {
            doc,
            label: format!("recognized directive count ({directives})"),
            needle: format!("{directives} entries"),
        });
    }
    v.push(AssertedFact {
        doc: "docs/compatibility.md",
        label: format!("recognized directive count ({directives})"),
        needle: format!("{directives} `KNOWN_DIRECTIVES`"),
    });

    // chrony source inventory totals.
    for doc in ["docs/port-parity.md", "docs/source-archaeology.md"] {
        v.push(AssertedFact {
            doc,
            label: format!("inventory size ({} files / {} fns)", facts.c_files, facts.c_functions),
            needle: inventory.clone(),
        });
    }

    // unsafe ledger.
    v.push(AssertedFact {
        doc: "docs/security-boundary.md",
        label: format!("unsafe count ({unsafe_count})"),
        needle: format!("count: {unsafe_count}"),
    });

    v.sort_by(|a, b| a.doc.cmp(b.doc).then(a.needle.cmp(&b.needle)));
    v
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

    // Verify every curated doc still states the live value of the machine fact it
    // restates — the prose-doc analogue of the generated-doc freshness diff.
    let mut wrong_facts = Vec::new();
    for fact in asserted_facts(&root) {
        let text = std::fs::read_to_string(root.join(fact.doc)).unwrap_or_default();
        if !text.contains(&fact.needle) {
            wrong_facts.push(fact);
        }
    }

    if stale.is_empty() && wrong_facts.is_empty() {
        println!(
            "xtask check: generated docs up to date; {} pinned doc facts accurate.",
            asserted_facts(&root).len()
        );
        return ExitCode::SUCCESS;
    }
    for p in &stale {
        eprintln!("xtask check: STALE generated doc: {}", p.display());
    }
    for f in &wrong_facts {
        eprintln!(
            "xtask check: {} does not state the live {} (expected to contain {:?})",
            f.doc, f.label, f.needle
        );
    }
    eprintln!("\nRun `cargo xtask gen` and/or update the doc so it states the current value.");
    ExitCode::FAILURE
}
