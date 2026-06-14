//! Deterministic replay runner (Stage 3 foundation).
//!
//! Walks a validated [`Trace`] event-by-event against a [`SimulatedClock`],
//! producing a **deterministic decision log** and a content hash of it. Same trace
//! in ⇒ same log out, byte-for-byte, on any machine. That reproducibility is the
//! whole point: it turns "did behavior change?" into a hash comparison.
//!
//! # Honest scope — read before trusting the word "decision"
//!
//! This runner currently performs **deterministic event processing**, not chrony's
//! source-selection or clock-discipline *policy*. Concretely it:
//!
//!   * advances the simulated clock to each event's monotonic time,
//!   * decodes `recv_ntp` packets with the real NTP codec (so packet-court
//!     guarantees apply) and records what arrived,
//!   * tracks a per-source last-seen registry and online/offline state,
//!   * answers `control_query` by snapshotting current observed state.
//!
//! It does **not** yet decide which source chrony would select, accept/reject
//! samples per chrony's filters, or compute offset/frequency/step decisions. Those
//! are Stages 4–5 and are listed in `docs/negative-capabilities.md`. The
//! `selected_source` it reports is the most-recently-seen online source — a
//! transparent placeholder, explicitly **not** a chrony selection claim.
//!
//! Because of that, [`ReplayReport::check_against`] compares only what the runner
//! can honestly own: its decision-log hash (a self-consistency / regression pin).
//! It does **not** assert parity of `selected_source` against a chrony oracle.

use std::collections::BTreeMap;

use crate::clock::SimulatedClock;
use crate::hash::sha256_hex;
use crate::ntp::NtpPacket;
use crate::trace::{Event, EventKind, Trace, TraceError};

/// Outcome of replaying a trace.
#[derive(Clone, Debug)]
pub struct ReplayReport {
    pub events_processed: usize,
    /// Most-recently-seen online source — a placeholder, not a chrony selection.
    pub selected_source: Option<String>,
    /// Human/diff-readable, deterministic log of what happened per event.
    pub decision_log: Vec<String>,
    /// SHA-256 hex of the decision log (newline-joined). The regression pin.
    pub decision_log_sha256: String,
}

/// Result of comparing a report against a trace's `expected` block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckResult {
    /// No expectations were recorded that this runner can honor.
    NothingToCheck,
    /// All honorable expectations matched.
    Match,
    /// A recorded expectation did not match.
    Mismatch { field: &'static str, expected: String, actual: String },
}

impl ReplayReport {
    /// Compare against the trace's `expected`, but **only** for fields this Stage-3
    /// runner can legitimately produce — currently the decision-log hash. The
    /// `selected_source` and tracking-output expectations require chrony policy and
    /// are intentionally not asserted here (doing so would be a false parity claim).
    pub fn check_against(&self, trace: &Trace) -> CheckResult {
        let Some(expected) = &trace.expected else {
            return CheckResult::NothingToCheck;
        };
        if let Some(want) = &expected.decision_events_sha256 {
            if want != &self.decision_log_sha256 {
                return CheckResult::Mismatch {
                    field: "decision_events_sha256",
                    expected: want.clone(),
                    actual: self.decision_log_sha256.clone(),
                };
            }
            return CheckResult::Match;
        }
        CheckResult::NothingToCheck
    }
}

/// What we know about a source as events arrive. Deliberately minimal — this is
/// observation, not chrony's rich `SRC_Instance` state, and must not be mistaken
/// for it.
#[derive(Clone, Debug, Default)]
struct SourceObservation {
    online: bool,
    last_seen_mono_ns: Option<u64>,
    last_stratum: Option<u8>,
    samples: u64,
}

/// Replay a validated trace. Returns [`TraceError`] if the trace is structurally
/// invalid (wrong schema or out-of-order events); see [`Trace::validate`].
pub fn run(trace: &Trace) -> Result<ReplayReport, TraceError> {
    trace.validate()?;

    let mut clock = SimulatedClock::new();
    let mut sources: BTreeMap<String, SourceObservation> = BTreeMap::new();
    let mut selected: Option<String> = None;
    let mut log: Vec<String> = Vec::with_capacity(trace.events.len());

    for ev in &trace.events {
        // Trace ordering was validated, so advance must succeed; if it ever didn't,
        // that is a contract violation worth surfacing rather than hiding.
        if !clock.advance_to(ev.t_mono_ns) {
            log.push(format!("[{}] ERROR: non-monotonic event time", ev.t_mono_ns));
            continue;
        }
        process_event(ev, &clock, &mut sources, &mut selected, &mut log);
    }

    let joined = log.join("\n");
    Ok(ReplayReport {
        events_processed: trace.events.len(),
        selected_source: selected,
        decision_log_sha256: sha256_hex(joined.as_bytes()),
        decision_log: log,
    })
}

fn process_event(
    ev: &Event,
    clock: &SimulatedClock,
    sources: &mut BTreeMap<String, SourceObservation>,
    selected: &mut Option<String>,
    log: &mut Vec<String>,
) {
    let t = ev.t_mono_ns;
    match ev.kind {
        EventKind::RecvNtp => {
            let peer = str_field(ev, "peer").unwrap_or_else(|| "<unknown>".to_string());
            let decoded = hex_field(ev, "packet_hex").map(|bytes| NtpPacket::decode(&bytes));
            let obs = sources.entry(peer.clone()).or_default();
            obs.samples += 1;
            obs.last_seen_mono_ns = Some(clock.mono_ns());
            match decoded {
                Some(Ok(pkt)) => {
                    obs.last_stratum = Some(pkt.stratum);
                    // First contact implies the source is reachable/online.
                    obs.online = true;
                    log.push(format!(
                        "[{t}] recv_ntp peer={peer} mode={} stratum={} leap={:?}",
                        pkt.mode.0, pkt.stratum, pkt.leap
                    ));
                    // Placeholder selection: latest online source wins. NOT chrony.
                    *selected = Some(peer);
                }
                Some(Err(e)) => {
                    log.push(format!("[{t}] recv_ntp peer={peer} REJECT decode: {e}"));
                }
                None => {
                    log.push(format!("[{t}] recv_ntp peer={peer} (no packet_hex)"));
                }
            }
        }
        EventKind::PollDue => {
            let src = str_field(ev, "source").unwrap_or_else(|| "<unknown>".to_string());
            log.push(format!("[{t}] poll_due source={src}"));
        }
        EventKind::OnlineState => {
            let src = str_field(ev, "source").unwrap_or_else(|| "<unknown>".to_string());
            let online = bool_field(ev, "online").unwrap_or(true);
            sources.entry(src.clone()).or_default().online = online;
            if !online && selected.as_deref() == Some(src.as_str()) {
                *selected = None;
            }
            log.push(format!("[{t}] online_state source={src} online={online}"));
        }
        EventKind::ControlQuery => {
            let cmd = str_field(ev, "command").unwrap_or_else(|| "<none>".to_string());
            let sel = selected.as_deref().unwrap_or("none");
            log.push(format!(
                "[{t}] control_query command={cmd} selected={sel} sources={}",
                sources.len()
            ));
        }
    }
}

// --- loose JSON field accessors -------------------------------------------------
// The trace schema keeps `data` permissive at v1 (see trace.rs). These helpers read
// the fields each event kind expects without forcing a schema bump for fields the
// brain doesn't yet consume.

fn str_field(ev: &Event, key: &str) -> Option<String> {
    ev.data.get(key)?.as_str().map(|s| s.to_string())
}

fn bool_field(ev: &Event, key: &str) -> Option<bool> {
    ev.data.get(key)?.as_bool()
}

fn hex_field(ev: &Event, key: &str) -> Option<Vec<u8>> {
    let hex = ev.data.get(key)?.as_str()?;
    decode_hex(hex)
}

/// Decode an even-length hex string; returns `None` on any non-hex or odd input
/// (a malformed trace field must not panic the runner).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace_json(extra_expected: &str) -> String {
        // A 48-byte server reply (mode 4, stratum 2) as hex, then a poll and query.
        let mut pkt = [0u8; 48];
        pkt[0] = 0b00_100_100; // VN=4 Mode=4
        pkt[1] = 2; // stratum 2
        let hex: String = pkt.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            r#"{{
              "trace_schema": "chrony-rs-trace-v1",
              "chrony_version": "4.6",
              "platform": "x86_64-linux",
              "kernel": "6.18.5",
              "config_sha256": "00",
              "events": [
                {{"t_mono_ns": 0, "kind": "recv_ntp", "data": {{"peer": "192.0.2.1", "packet_hex": "{hex}"}}}},
                {{"t_mono_ns": 1000000000, "kind": "poll_due", "data": {{"source": "192.0.2.1"}}}},
                {{"t_mono_ns": 2000000000, "kind": "control_query", "data": {{"command": "tracking"}}}}
              ]{extra_expected}
            }}"#
        )
    }

    #[test]
    fn replay_is_deterministic_and_processes_all_events() {
        let trace = Trace::from_json(&trace_json("")).unwrap();
        let r1 = run(&trace).unwrap();
        let r2 = run(&trace).unwrap();
        assert_eq!(r1.events_processed, 3);
        assert_eq!(r1.selected_source.as_deref(), Some("192.0.2.1"));
        // Same input ⇒ identical hash.
        assert_eq!(r1.decision_log_sha256, r2.decision_log_sha256);
        // The packet decoded, so the log records the stratum we put in.
        assert!(r1.decision_log[0].contains("stratum=2"), "{:?}", r1.decision_log);
    }

    #[test]
    fn offline_clears_placeholder_selection() {
        let json = r#"{
          "trace_schema": "chrony-rs-trace-v1",
          "chrony_version": "4.6", "platform": "x", "kernel": "x", "config_sha256": "00",
          "events": [
            {"t_mono_ns": 0, "kind": "recv_ntp", "data": {"peer": "a", "packet_hex": "1c0206e9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}},
            {"t_mono_ns": 1, "kind": "online_state", "data": {"source": "a", "online": false}}
          ]
        }"#;
        let trace = Trace::from_json(json).unwrap();
        let r = run(&trace).unwrap();
        assert_eq!(r.selected_source, None);
    }

    #[test]
    fn decision_hash_expectation_is_checkable() {
        // First run to learn the hash, then pin it as an expectation and confirm it
        // matches — the regression-pin workflow.
        let trace = Trace::from_json(&trace_json("")).unwrap();
        let hash = run(&trace).unwrap().decision_log_sha256;
        let pinned = trace_json(&format!(
            r#", "expected": {{"decision_events_sha256": "{hash}"}}"#
        ));
        let trace2 = Trace::from_json(&pinned).unwrap();
        let report = run(&trace2).unwrap();
        assert_eq!(report.check_against(&trace2), CheckResult::Match);
    }

    #[test]
    fn wrong_decision_hash_is_a_mismatch() {
        let pinned = trace_json(r#", "expected": {"decision_events_sha256": "deadbeef"}"#);
        let trace = Trace::from_json(&pinned).unwrap();
        let report = run(&trace).unwrap();
        assert!(matches!(
            report.check_against(&trace),
            CheckResult::Mismatch { field: "decision_events_sha256", .. }
        ));
    }

    #[test]
    fn malformed_hex_does_not_panic() {
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex("abc"), None); // odd length
        assert_eq!(decode_hex("ab"), Some(vec![0xab]));
    }
}
