//! Deterministic trace-replay schema (`chrony-rs-trace-v1`).
//!
//! The trace harness is the *foundation* of the forensic method, not an add-on:
//! before we discipline a real clock we replay captured event streams against the
//! deterministic brain and compare outputs. A trace pins everything that affects
//! a decision — chrony version, platform, config hash, initial drift, and an
//! ordered list of timestamped events — so a result is reproducible byte-for-byte
//! on any machine.
//!
//! # Why monotonic nanoseconds, not wall clock
//!
//! Every event is stamped with `t_mono_ns`, a monotonic offset from trace start.
//! Wall-clock time is exactly what chrony is *manipulating*, so it cannot also be
//! the trace's time base without circularity. The simulated clock derives wall
//! time from the brain's own state; the trace only advances monotonic time and
//! delivers inputs. Do not add a wall-clock field to events to "make it easier" —
//! that reintroduces the circularity this design removes.
//!
//! The schema is intentionally permissive on the event payload (`serde_json::Value`
//! for kind-specific fields) at this stage so the capture tool can record events
//! we have not yet given the brain semantics for, without a schema bump. Typed
//! event variants are promoted per court as the replay runner learns to consume
//! them.

use serde::{Deserialize, Serialize};

use crate::TRACE_SCHEMA;

/// A complete replay trace: provenance header, events, and expected outputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Trace {
    /// Must equal [`crate::TRACE_SCHEMA`]. Validated by [`Trace::validate`].
    pub trace_schema: String,
    /// The chrony version this trace was captured against (the oracle).
    pub chrony_version: String,
    pub platform: String,
    pub kernel: String,
    /// SHA-256 of the exact config bytes used. Hex, lowercase. The hash — not the
    /// config text — is stored so the trace stays small and the config can't drift
    /// out from under the receipt.
    pub config_sha256: String,
    /// Opaque initial drift-file contents (or a hash thereof), platform-defined.
    #[serde(default)]
    pub initial_drift_state: Option<String>,
    pub events: Vec<Event>,
    #[serde(default)]
    pub expected: Option<Expected>,
}

/// One timestamped input to the brain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    /// Monotonic nanoseconds since trace start. Must be non-decreasing across the
    /// event list; [`Trace::validate`] enforces this because an out-of-order event
    /// would make replay non-deterministic.
    pub t_mono_ns: u64,
    pub kind: EventKind,
    /// Kind-specific payload, kept loose at this schema version (see module doc).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub data: serde_json::Value,
}

/// The categories of input a trace can deliver. Mirrors the inputs chrony's event
/// loop reacts to. New kinds are additive; renaming or removing one is a schema
/// break (`trace_schema` bump).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// An NTP packet arrived from a peer (`data.packet_hex`, `data.peer`).
    RecvNtp,
    /// A source's poll timer fired (`data.source`).
    PollDue,
    /// A control client issued a query (`data.command`, e.g. `tracking`).
    ControlQuery,
    /// A source was taken offline / brought online (`data.source`, `data.online`).
    OnlineState,
}

/// Expected outputs for differential comparison. Stored as hashes/identifiers so
/// the trace file stays lean; the full rendered outputs live under `reports/`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Expected {
    #[serde(default)]
    pub tracking_output_sha256: Option<String>,
    #[serde(default)]
    pub selected_source: Option<String>,
    #[serde(default)]
    pub decision_events_sha256: Option<String>,
}

/// Why a trace is structurally invalid (independent of whether replay *matches*).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceError {
    WrongSchema { found: String },
    EventsOutOfOrder { index: usize, prev: u64, this: u64 },
}

impl core::fmt::Display for TraceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TraceError::WrongSchema { found } => {
                write!(f, "unsupported trace schema '{found}', expected '{TRACE_SCHEMA}'")
            }
            TraceError::EventsOutOfOrder { index, prev, this } => write!(
                f,
                "event {index} has t_mono_ns {this} < previous {prev}; events must be non-decreasing"
            ),
        }
    }
}

impl std::error::Error for TraceError {}

impl Trace {
    /// Structural validation: correct schema tag and monotonic event ordering.
    /// This is a precondition for replay; it says nothing about whether outputs
    /// match the oracle (that is the runner's job).
    pub fn validate(&self) -> Result<(), TraceError> {
        if self.trace_schema != TRACE_SCHEMA {
            return Err(TraceError::WrongSchema {
                found: self.trace_schema.clone(),
            });
        }
        let mut prev = 0u64;
        for (index, ev) in self.events.iter().enumerate() {
            if ev.t_mono_ns < prev {
                return Err(TraceError::EventsOutOfOrder {
                    index,
                    prev,
                    this: ev.t_mono_ns,
                });
            }
            prev = ev.t_mono_ns;
        }
        Ok(())
    }

    /// Parse a trace from JSON, then structurally validate it.
    pub fn from_json(s: &str) -> Result<Trace, Box<dyn std::error::Error>> {
        let trace: Trace = serde_json::from_str(s)?;
        trace.validate()?;
        Ok(trace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
          "trace_schema": "chrony-rs-trace-v1",
          "chrony_version": "4.5",
          "platform": "x86_64-linux",
          "kernel": "6.18.5",
          "config_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
          "events": [
            {"t_mono_ns": 0, "kind": "recv_ntp", "data": {"peer": "192.0.2.1", "packet_hex": "1c..."}},
            {"t_mono_ns": 1000000000, "kind": "poll_due", "data": {"source": "192.0.2.1"}},
            {"t_mono_ns": 2000000000, "kind": "control_query", "data": {"command": "tracking"}}
          ],
          "expected": {"selected_source": "192.0.2.1"}
        }"#
    }

    #[test]
    fn sample_trace_parses_and_validates() {
        let trace = Trace::from_json(sample_json()).expect("valid trace");
        assert_eq!(trace.events.len(), 3);
        assert_eq!(trace.events[0].kind, EventKind::RecvNtp);
        assert_eq!(
            trace.expected.unwrap().selected_source.as_deref(),
            Some("192.0.2.1")
        );
    }

    #[test]
    fn wrong_schema_is_rejected() {
        let bad = sample_json().replace("chrony-rs-trace-v1", "chrony-rs-trace-v99");
        let err = Trace::from_json(&bad).unwrap_err();
        assert!(err.to_string().contains("unsupported trace schema"));
    }

    #[test]
    fn out_of_order_events_are_rejected() {
        let mut trace = Trace::from_json(sample_json()).unwrap();
        trace.events[2].t_mono_ns = 0; // now decreasing relative to event 1
        assert_eq!(
            trace.validate(),
            Err(TraceError::EventsOutOfOrder {
                index: 2,
                prev: 1_000_000_000,
                this: 0
            })
        );
    }

    #[test]
    fn roundtrips_through_json() {
        let trace = Trace::from_json(sample_json()).unwrap();
        let s = serde_json::to_string(&trace).unwrap();
        let again = Trace::from_json(&s).unwrap();
        assert_eq!(again.events.len(), trace.events.len());
    }
}
