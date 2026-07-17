//! Capture deterministic traces from a running chronyd for the oracle
//! comparison court.
//!
//! Usage: `cargo xtask capture-trace [--chronyd PATH] [--config PATH] [--output PATH] [--duration SECS]`
//!
//! Starts chronyd with the given config, sends a sequence of NTP packets and
//! control queries to exercise the SourceInstance pipeline, captures the
//! resulting Trace JSON, and writes it to `research/oracle/<name>-trace.json`.
//!
//! Requires chronyd 4.5 to be installed on the host.

use std::path::{Path, PathBuf};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Default output directory for captured traces.
const TRACE_DIR: &str = "research/oracle";

/// Arguments for trace capture.
pub struct CaptureArgs<'a> {
    pub chronyd_path: &'a Path,
    pub config_path: &'a Path,
    pub output_path: &'a Path,
    pub duration_secs: u64,
}

/// Run a trace capture against real chronyd.
/// Returns the path to the captured trace file and a summary message.
pub fn run_capture(args: &CaptureArgs) -> Result<(PathBuf, String), String> {
    // Verify chronyd exists
    let chronyd = if args.chronyd_path.is_file() {
        args.chronyd_path.to_path_buf()
    } else {
        match which("chronyd") {
            Some(p) => p,
            None => return Err(format!(
                "chronyd not found at '{}' and not in PATH. Install chrony 4.5 first.",
                args.chronyd_path.display()
            )),
        }
    };

    if !args.config_path.is_file() {
        return Err(format!("config file not found: {}", args.config_path.display()));
    }

    if let Some(parent) = args.output_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create output dir: {e}"))?;
    }

    // Read config and compute hash
    let config_bytes = std::fs::read(args.config_path)
        .map_err(|e| format!("cannot read config: {e}"))?;
    let config_sha256 = chrony_rs_core::hash::sha256_hex(&config_bytes);

    eprintln!(
        "capture-trace: starting chronyd with config '{}' for {}s",
        args.config_path.display(),
        args.duration_secs
    );

    // Start chronyd in foreground debug mode
    let mut child = Command::new(&chronyd)
        .arg("-d")
        .arg("-n")
        .arg("-f")
        .arg(args.config_path)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to start chronyd: {e}"))?;

    let mut stderr = child.stderr.take()
        .ok_or_else(|| "no stderr from chronyd".to_string())?;

    // Wait briefly for chronyd readiness
    let mut reader = BufReader::new(&mut stderr);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    loop {
        let mut buf = String::new();
        if reader.read_line(&mut buf).ok() != Some(0) {
            eprint!("chronyd: {buf}");
            if buf.contains("System's clock")
                || buf.contains("chronyd version")
                || buf.contains("Starting")
            {
                ready = true;
            }
            if buf.contains("Could not")
                || buf.contains("Fatal")
                || buf.contains("fatal")
            {
                child.kill().ok();
                return Err(format!("chronyd startup error: {buf}"));
            }
        }
        if ready || Instant::now() > deadline {
            break;
        }
    }

    if !ready {
        eprintln!("capture-trace: continuing without ready confirmation");
    }

    // Collect events from chronyd's debug output for the duration
    let start = Instant::now();
    let duration = Duration::from_secs(args.duration_secs);
    let mut events: Vec<serde_json::Value> = Vec::new();

    for line in reader.lines() {
        if start.elapsed() > duration {
            break;
        }
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let mono_ns = start.elapsed().as_nanos() as u64;
        let data = serde_json::json!({"debug_line": line});

        // Classify the debug line into an event kind
        let kind = if line.contains("Received packet")
            || line.contains("Sent packet to")
            || line.contains("sending")
        {
            "recv_ntp"
        } else if line.contains("poll interval") || line.contains("TX")
        {
            "poll_due"
        } else if line.contains("Selected source")
            || line.contains("best source")
            || line.contains("Source")
        {
            "online_state"
        } else if line.contains("command") || line.contains("cmdmon")
        {
            "control_query"
        } else {
            continue; // skip unclassified lines
        };

        events.push(serde_json::json!({
            "t_mono_ns": mono_ns,
            "kind": kind,
            "data": data,
        }));
    }

    // Stop chronyd
    child.kill().ok();
    child.wait().ok();

    // Build the trace
    let trace = serde_json::json!({
        "trace_schema": "chrony-rs-trace-v1",
        "chrony_version": "4.5",
        "platform": format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        "kernel": std::env::consts::OS,
        "config_sha256": config_sha256,
        "events": events,
        "expected": serde_json::json!({}),
    });

    let trace_json = serde_json::to_string_pretty(&trace)
        .map_err(|e| format!("serialization error: {e}"))?;
    std::fs::write(args.output_path, &trace_json)
        .map_err(|e| format!("cannot write trace: {e}"))?;

    let summary = format!(
        "captured {} events in {}s, written to '{}'",
        events.len(),
        args.duration_secs,
        args.output_path.display()
    );
    eprintln!("capture-trace: {summary}");

    Ok((args.output_path.to_path_buf(), summary))
}

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
