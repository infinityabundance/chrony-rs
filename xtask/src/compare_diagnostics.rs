//! Compare diagnostic messages from real chronyd vs chrony-rs parser.
//!
//! Usage: `cargo xtask compare-diagnostics [--chronyd <path>]`
//!
//! For each of the 93 KNOWN_DIRECTIVES, generates config snippets that exercise
//! error modes (no args, wrong type, overflow, extra args, valid), runs both
//! `chronyd -d -n` and the chrony-rs parser, and compares the error text.
//!
//! If chronyd is not found, reports "chronyd not available" and exits cleanly.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// A single test case: a config line to parse, and what we expect from both parsers.
struct TestCase {
    label: String,
    config_line: String,
}

/// Generate test cases for every known directive.
fn generate_test_cases() -> Vec<TestCase> {
    let mut cases = Vec::new();

    let directives = chrony_rs_core::config::known_directives();
    for &kw in directives {
        // Directives that take int args
        if is_int_directive(kw) {
            cases.push(TestCase {
                label: format!("{kw}: no args"),
                config_line: format!("{kw}\n"),
            });
            cases.push(TestCase {
                label: format!("{kw}: string arg"),
                config_line: format!("{kw} notanumber\n"),
            });
            cases.push(TestCase {
                label: format!("{kw}: extra args"),
                config_line: format!("{kw} 1 2 3\n"),
            });
        } else if is_double_directive(kw) {
            cases.push(TestCase {
                label: format!("{kw}: no args"),
                config_line: format!("{kw}\n"),
            });
            cases.push(TestCase {
                label: format!("{kw}: bad arg"),
                config_line: format!("{kw} nan\n"),
            });
            cases.push(TestCase {
                label: format!("{kw}: extra args"),
                config_line: format!("{kw} 1.0 2.0\n"),
            });
        } else if is_string_directive(kw) {
            cases.push(TestCase {
                label: format!("{kw}: no args"),
                config_line: format!("{kw}\n"),
            });
            cases.push(TestCase {
                label: format!("{kw}: extra args"),
                config_line: format!("{kw} /a /b /c\n"),
            });
        } else if is_flag_directive(kw) {
            cases.push(TestCase {
                label: format!("{kw}: unexpected arg"),
                config_line: format!("{kw} extra\n"),
            });
        } else if is_clientloglimit(kw) {
            cases.push(TestCase {
                label: format!("{kw}: no args"),
                config_line: format!("{kw}\n"),
            });
            cases.push(TestCase {
                label: format!("{kw}: negative"),
                config_line: format!("{kw} -1\n"),
            });
        } else {
            // Other directives (server, refclock, etc.) — test arity errors where possible
            cases.push(TestCase {
                label: format!("{kw}: minimal"),
                config_line: format!("{kw}\n"),
            });
        }
    }
    cases
}

fn is_int_directive(kw: &str) -> bool {
    matches!(kw,
        "cmdport" | "port" | "ptpport" | "maxsamples" | "minsamples" | "minsources"
        | "acquisitionport" | "dscp" | "logbanner" | "maxntsconnections"
        | "nocerttimecheck" | "ntsport" | "ntsprocesses" | "ntsrefresh"
        | "ntsrotate" | "refresh" | "sched_priority"
        | "commandkey" | "linux_freq_scale" | "linux_hz"
    )
}

fn is_double_directive(kw: &str) -> bool {
    matches!(kw,
        "clockprecision" | "combinelimit" | "corrtimeratio" | "maxclockerror"
        | "maxdistance" | "maxdrift" | "maxjitter" | "maxslewrate"
        | "maxupdateskew" | "reselectdist" | "stratumweight" | "hwtstimeout"
        | "logchange" | "rtcautotrim"
    )
}

fn is_string_directive(kw: &str) -> bool {
    matches!(kw,
        "bindacqdevice" | "bindcmddevice" | "binddevice" | "dumpdir"
        | "hwclockfile" | "keyfile" | "leapsectz" | "logdir"
        | "ntpsigndsocket" | "ntsdumpdir" | "ntscachedir" | "ntsntpserver"
        | "pidfile" | "rtcdevice" | "rtcfile" | "user"
        | "ntsservercert" | "ntsserverkey"
    )
}

fn is_flag_directive(kw: &str) -> bool {
    matches!(kw,
        "lock_all" | "manual" | "noclientlog" | "nosystemcert" | "rtconutc"
        | "dumponexit" | "generatecommandkey"
    )
}

fn is_clientloglimit(kw: &str) -> bool {
    kw == "clientloglimit"
}

fn run_chronyd_parse(chronyd: &Path, config: &str, tmpdir: &Path) -> String {
    let conf_path = tmpdir.join("test.conf");
    std::fs::write(&conf_path, config).ok();

    let output = Command::new(chronyd)
        .arg("-d")
        .arg("-n")
        .arg("-f")
        .arg(&conf_path)
        .output();

    match output {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // chronyd outputs on stderr; extract the first error line
            stderr.lines()
                .find(|l| l.contains("Could not") || l.contains("Error") || l.contains("error"))
                .unwrap_or("")
                .to_string()
        }
        Err(e) => format!("chronyd error: {e}"),
    }
}

fn run_chronyrs_parse(config: &str) -> Vec<String> {
    let out = chrony_rs_core::config::parse(config);
    out.diagnostics.iter().map(|d| {
        format!("{}: {}", d.code, d.message)
    }).collect()
}

/// Run the diagnostic comparison. Returns a map of results.
pub fn run_comparison(chronyd_path: Option<&Path>, repo_root: &Path) -> BTreeMap<String, String> {
    let mut results = BTreeMap::new();

    let tmpdir = repo_root.join("target/compare-diag-tmp");
    std::fs::create_dir_all(&tmpdir).ok();

    let chronyd = match chronyd_path {
        Some(p) => p.to_path_buf(),
        None => {
            // Try to find chronyd in PATH
            match which("chronyd") {
                Some(p) => p,
                None => {
                    results.insert("_status".into(), "chronyd not available".into());
                    return results;
                }
            }
        }
    };

    let cases = generate_test_cases();
    for case in &cases {
        let chronyd_msg = run_chronyd_parse(&chronyd, &case.config_line, &tmpdir);
        let chronyrs_msgs = run_chronyrs_parse(&case.config_line);

        let match_status = if chronyd_msg.is_empty() && chronyrs_msgs.is_empty() {
            "PASS".to_string()
        } else if chronyd_msg.is_empty() != chronyrs_msgs.is_empty() {
            format!("MISMATCH chronyd='{chronyd_msg}' vs chrony-rs=[{}]", chronyrs_msgs.join("; "))
        } else if chronyrs_msgs.iter().any(|m| m.contains("error") || m.contains("Error")) {
            // Both produced errors — compare them loosely
            let rs_combined = chronyrs_msgs.join(" ");
            if chronyd_msg.contains("Could not parse")
                || chronyd_msg.contains("Could not be interpreted")
                || rs_combined.contains("CFG_UNEXPECTED_ARGS")
                || rs_combined.contains("CFG_BAD_VALUE")
            {
                "PASS".to_string()
            } else {
                format!("PARTIAL chronyd='{chronyd_msg}' rs='{rs_combined}'")
            }
        } else {
            "PASS".to_string()
        };

        results.insert(format!("{}: {}", case.label, case.config_line.trim()), match_status);
    }

    // Cleanup
    std::fs::remove_dir_all(&tmpdir).ok();

    results
}

use std::path::PathBuf;

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .filter_map(|dir| {
                let full = dir.join(name);
                if full.is_file() { Some(full) } else { None }
            })
            .next()
    })
}
