//! Forensic court mode — ultra-verbose deterministic logging for chrony-rs.
//!
//! When `court_mode` is enabled, every decision, comparison, and state
//! transition is logged to a structured receipt that can be compared
//! against a reference chrony run to verify behavioral parity.
//!
//! A **court receipt** is a JSON Lines (`.jsonl`) file where each line is
//! one forensic event with a timestamp, category, and structured payload.
//! Receipts are deterministic: given the same inputs, the same receipt is
//! produced, enabling reproducible trust verification.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::{fs, io::Write};

/// Categories of forensic events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum CourtCategory {
    Config,
    Packet,
    Selection,
    Discipline,
    Scheduler,
    Control,
    Auth,
    NtsKe,
    Refclock,
    Rtc,
    Platform,
    Test,
    Marker,
}

impl CourtCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Packet => "packet",
            Self::Selection => "selection",
            Self::Discipline => "discipline",
            Self::Scheduler => "scheduler",
            Self::Control => "control",
            Self::Auth => "auth",
            Self::NtsKe => "nts_ke",
            Self::Refclock => "refclock",
            Self::Rtc => "rtc",
            Self::Platform => "platform",
            Self::Test => "test",
            Self::Marker => "marker",
        }
    }
}

/// A single forensic event.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CourtEvent {
    pub index: u64,
    pub t_mono_ns: u64,
    pub category: String,
    pub description: String,
    pub payload: BTreeMap<String, String>,
    pub source: String,
}

impl CourtEvent {
    pub fn new(
        index: u64,
        t_mono_ns: u64,
        category: CourtCategory,
        description: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        CourtEvent {
            index,
            t_mono_ns,
            category: category.as_str().to_string(),
            description: description.into(),
            payload: BTreeMap::new(),
            source: source.into(),
        }
    }

    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.payload.insert(key.into(), value.into());
        self
    }
}

impl fmt::Display for CourtEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).map_err(|_| fmt::Error)?)
    }
}

thread_local! {
    static COURT: RefCell<Court> = const { RefCell::new(Court::silent()) };
}

/// The forensic court — collects structured events into a deterministic receipt.
pub struct Court {
    events: Vec<CourtEvent>,
    start_nanos: u64,
    pub enabled: bool,
    pub output_path: Option<String>,
    /// If set, also mirror events to stderr (for live debugging).
    pub verbose_stderr: bool,
}

impl Court {
    pub fn new(start_nanos: u64, enabled: bool) -> Self {
        Court {
            events: Vec::new(),
            start_nanos,
            enabled,
            output_path: None,
            verbose_stderr: false,
        }
    }

    pub const fn silent() -> Self {
        Court {
            events: Vec::new(),
            start_nanos: 0,
            enabled: false,
            output_path: None,
            verbose_stderr: false,
        }
    }

    pub fn enabled() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Court::new(now, true)
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn record(&mut self, event: CourtEvent) {
        if !self.enabled {
            return;
        }
        if self.verbose_stderr {
            eprintln!("[COURT] {} {}: {} {:?}",
                event.category, event.index, event.description, event.payload);
        }
        self.events.push(event);
    }

    pub fn event(&mut self, category: CourtCategory, description: impl Into<String>, source: impl Into<String>) {
        if !self.enabled { return; }
        let index = self.events.len() as u64;
        self.record(CourtEvent::new(index, self.start_nanos.saturating_add(index * 1000), category, description, source));
    }

    pub fn event_with(
        &mut self,
        category: CourtCategory,
        description: impl Into<String>,
        source: impl Into<String>,
        kv: Vec<(&str, String)>,
    ) {
        if !self.enabled { return; }
        let index = self.events.len() as u64;
        let mut event = CourtEvent::new(index, self.start_nanos.saturating_add(index * 1000), category, description, source);
        for (k, v) in kv {
            event = event.with(k, v);
        }
        self.record(event);
    }

    pub fn events(&self) -> &[CourtEvent] {
        &self.events
    }

    pub fn to_jsonl(&self) -> String {
        self.events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn flush(&mut self) {
        if let Some(ref path) = self.output_path.clone() {
            let jsonl = self.to_jsonl();
            if let Ok(mut f) = fs::File::create(path) {
                let _ = write!(f, "{}", jsonl);
            }
        }
    }
}

/// Run a closure with court access.
pub fn with_court<F, R>(f: F) -> R
where
    F: FnOnce(&mut Court) -> R,
{
    COURT.with(|c| f(&mut c.borrow_mut()))
}

/// Enable the court and optionally set an output path.
pub fn enable(output_path: Option<String>) {
    with_court(|court| {
        court.enabled = true;
        court.output_path = output_path;
        court.start_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        court.event(CourtCategory::Marker, "court_mode_enabled", "court.rs:enable");
    });
}

/// Enable verbose stderr mirroring.
pub fn set_verbose() {
    with_court(|court| {
        court.verbose_stderr = true;
    });
}

/// Flush the court receipt to disk (if output_path is set).
pub fn flush() {
    with_court(|court| {
        court.flush();
    });
}

/// Record a court event via the thread-local court.
#[macro_export]
macro_rules! court_event {
    ($category:expr, $description:expr) => {
        $crate::court::with_court(|court| {
            court.event($category, $description, format!("{}:{}", file!(), line!()));
        });
    };
    ($category:expr, $description:expr, $(($k:expr, $v:expr)),+) => {
        $crate::court::with_court(|court| {
            court.event_with(
                $category,
                $description,
                format!("{}:{}", file!(), line!()),
                vec![$(($k, $v)),+],
            );
        });
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn court_records_events() {
        with_court(|court| {
            let start = court.len();
            court.event(CourtCategory::Marker, "test_event", "test.rs:1");
            assert_eq!(court.len(), start + 1);
        });
    }

    #[test]
    fn court_disabled_no_events() {
        with_court(|court| {
            court.enabled = false;
            let start = court.len();
            court.event(CourtCategory::Marker, "should_not_appear", "test.rs:1");
            assert_eq!(court.len(), start);
        });
    }

    #[test]
    fn court_event_payload() {
        with_court(|court| {
            court.enabled = true;
            court.event_with(
                CourtCategory::Discipline,
                "offset_applied",
                "test.rs:1",
                vec![("offset_sec", "0.001234".into()), ("freq_ppm", "-5.25".into())],
            );
            let events = court.events();
            let last = events.last().unwrap();
            assert_eq!(last.payload.get("offset_sec").unwrap(), "0.001234");
            assert_eq!(last.payload.get("freq_ppm").unwrap(), "-5.25");
        });
    }

    #[test]
    fn court_jsonl_valid() {
        with_court(|court| {
            court.enabled = true;
            court.event(CourtCategory::Marker, "jsonl_test", "test.rs:1");
            let jsonl = court.to_jsonl();
            for line in jsonl.lines() {
                let _: serde_json::Value = serde_json::from_str(line).unwrap();
            }
        });
    }

    #[test]
    fn court_macro_works() {
        court_event!(CourtCategory::Test, "macro_test");
        with_court(|court| {
            assert!(court.len() > 0);
        });
    }
}
