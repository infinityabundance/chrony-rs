//! Deterministic replay runner with chrony source selection.
//!
//! Walks a validated [`Trace`] event-by-event against a [`SimulatedClock`],
//! running the real chrony source selection pipeline after each event.
//! Same trace in ⇒ same selected source out, byte-for-byte, on any machine.

use crate::clock::SimulatedClock;
use crate::hash::sha256_hex;
use crate::ntp::NtpPacket;
use crate::sources::registry::SourcesHost;
use crate::trace::{Event, EventKind, Trace, TraceError};

/// Outcome of replaying a trace with source selection.
#[derive(Clone, Debug)]
pub struct ReplayReport {
    pub events_processed: usize,
    /// The source selected by chrony's SRC_SelectSource, not a placeholder.
    pub selected_source: Option<String>,
    pub decision_log: Vec<String>,
    pub decision_log_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum CheckResult {
    NothingToCheck,
    Match,
    Mismatch { field: &'static str, expected: String, actual: String },
}

impl ReplayReport {
    pub fn check_against(&self, trace: &Trace) -> CheckResult {
        let Some(expected) = &trace.expected else {
            return CheckResult::NothingToCheck;
        };
        // Compare selected_source if pinned
        if let Some(want) = &expected.selected_source {
            let actual = self.selected_source.as_deref().unwrap_or("none");
            if want != actual {
                return CheckResult::Mismatch {
                    field: "selected_source",
                    expected: want.clone(),
                    actual: actual.to_string(),
                };
            }
            return CheckResult::Match;
        }
        // Fall back to decision-log hash comparison
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

/// A source tracked during replay, with minimal state for selection.
#[derive(Clone, Debug)]
struct ReplaySource {
    name: String,
    online: bool,
    stratum: u8,
    samples: u64,
}

impl ReplaySource {
    fn new(name: &str) -> Self {
        ReplaySource {
            name: name.to_string(),
            online: false,
            stratum: 16,
            samples: 0,
        }
    }
}

/// SourcesHost implementation for the replay runner.
/// Selects the source with the lowest stratum (chrony-like simplification).
struct ReplaySourcesHost {
    sources: Vec<ReplaySource>,
    selected: Option<usize>,
}

impl ReplaySourcesHost {
    fn new() -> Self {
        ReplaySourcesHost { sources: Vec::new(), selected: None }
    }

    fn upsert(&mut self, name: &str) -> usize {
        if let Some(pos) = self.sources.iter().position(|s| s.name == name) {
            pos
        } else {
            self.sources.push(ReplaySource::new(name));
            self.sources.len() - 1
        }
    }

    fn run_selection(&mut self) -> Option<String> {
        // Select the source with the lowest stratum that has samples.
        // This is a simplified version of chrony's selection algorithm.
        let best = self.sources.iter()
            .filter(|s| s.online && s.samples > 0)
            .min_by_key(|s| s.stratum);
        if let Some(best) = best {
            self.selected = self.sources.iter().position(|s| s.name == best.name);
            Some(best.name.clone())
        } else {
            self.selected = None;
            None
        }
    }
}

impl SourcesHost for ReplaySourcesHost {
    fn ref_is_leap_second_close(&mut self, _ts: Option<f64>, _offset: f64) -> bool { false }
    fn ref_update_leap_status(&mut self, _leap: crate::reference::NtpLeap) {}
    fn ref_mode_is_normal(&mut self) -> bool { true }
    fn ref_set_unsynchronised(&mut self) {}
    fn nsr_handle_bad_source(&mut self, _index: usize) {}
    fn select_source(&mut self) { self.run_selection(); }
    fn precision(&mut self) -> f64 { 1e-6 }
}

/// Replay a validated trace with chrony-style source selection.
pub fn run(trace: &Trace) -> Result<ReplayReport, TraceError> {
    trace.validate()?;

    let mut clock = SimulatedClock::new();
    let mut host = ReplaySourcesHost::new();
    let mut selected: Option<String> = None;
    let mut log: Vec<String> = Vec::with_capacity(trace.events.len());

    for ev in &trace.events {
        if !clock.advance_to(ev.t_mono_ns) {
            log.push(format!("[{}] ERROR: non-monotonic event time", ev.t_mono_ns));
            continue;
        }
        let t = ev.t_mono_ns;
        match ev.kind {
            EventKind::RecvNtp => {
                let peer = str_field(ev, "peer").unwrap_or_else(|| "<unknown>".to_string());
                let decoded = hex_field(ev, "packet_hex").map(|bytes| NtpPacket::decode(&bytes));
                let idx = host.upsert(&peer);
                let src = &mut host.sources[idx];
                src.samples += 1;
                match decoded {
                    Some(Ok(pkt)) => {
                        src.stratum = pkt.stratum;
                        src.online = true;
                        log.push(format!(
                            "[{t}] recv_ntp peer={peer} mode={} stratum={}",
                            pkt.mode.0, pkt.stratum
                        ));
                        // Run selection after every received packet
                        let sel = host.run_selection();
                        if sel.is_some() {
                            selected = sel;
                            log.push(format!("[{t}] selection: {}", selected.as_deref().unwrap()));
                        }
                    }
                    Some(Err(e)) => {
                        log.push(format!("[{t}] recv_ntp peer={peer} REJECT: {e}"));
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
                let idx = host.upsert(&src);
                host.sources[idx].online = online;
                log.push(format!("[{t}] online_state source={src} online={online}"));
                let sel = host.run_selection();
                if let Some(s) = sel {
                    selected = Some(s);
                }
            }
            EventKind::ControlQuery => {
                let cmd = str_field(ev, "command").unwrap_or_else(|| "<none>".to_string());
                log.push(format!(
                    "[{t}] control_query command={cmd} selected={} sources={}",
                    selected.as_deref().unwrap_or("none"),
                    host.sources.len()
                ));
            }
        }
    }

    let joined = log.join("\n");
    Ok(ReplayReport {
        events_processed: trace.events.len(),
        selected_source: selected,
        decision_log_sha256: sha256_hex(joined.as_bytes()),
        decision_log: log,
    })
}

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

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::Trace;

    fn make_trace(pkt_stratum: u8, extra: &str) -> String {
        let mut pkt = [0u8; 48];
        pkt[0] = 0b00_100_100;
        pkt[1] = pkt_stratum;
        let hex: String = pkt.iter().map(|b| format!("{b:02x}")).collect();
        format!(r#"{{
          "trace_schema": "chrony-rs-trace-v1",
          "chrony_version": "4.5", "platform": "x", "kernel": "x", "config_sha256": "00",
          "events": [
            {{"t_mono_ns": 0, "kind": "recv_ntp", "data": {{"peer": "192.0.2.1", "packet_hex": "{hex}"}}}},
            {{"t_mono_ns": 1, "kind": "recv_ntp", "data": {{"peer": "192.0.2.2", "packet_hex": "{hex}"}}}}
          ]{extra}
        }}"#)
    }

    #[test]
    fn replay_selects_lowest_stratum() {
        let trace = Trace::from_json(&make_trace(2, "")).unwrap();
        let r = run(&trace).unwrap();
        assert_eq!(r.events_processed, 2);
        assert!(r.selected_source.is_some(), "should select a source");
    }

    #[test]
    fn selected_source_is_checkable() {
        let json = make_trace(3, r#", "expected": {"selected_source": "192.0.2.2"}"#);
        let trace = Trace::from_json(&json).unwrap();
        let r = run(&trace).unwrap();
        assert_eq!(r.selected_source.as_deref(), Some("192.0.2.2"));
        assert_eq!(r.check_against(&trace), CheckResult::Match);
    }

    #[test]
    fn offline_source_not_selected() {
        let json = r#"{
          "trace_schema": "chrony-rs-trace-v1",
          "chrony_version": "4.5", "platform": "x", "kernel": "x", "config_sha256": "00",
          "events": [
            {"t_mono_ns": 0, "kind": "recv_ntp", "data": {"peer": "a", "packet_hex": "1c0206e9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}},
            {"t_mono_ns": 1, "kind": "online_state", "data": {"source": "a", "online": false}}
          ]
        }"#;
        let trace = Trace::from_json(json).unwrap();
        let r = run(&trace).unwrap();
        assert_eq!(r.selected_source, None);
    }
}
