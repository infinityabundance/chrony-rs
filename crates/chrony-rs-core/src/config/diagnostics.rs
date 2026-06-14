//! Diagnostics emitted while parsing a chrony config.
//!
//! The goal is *diagnostic parity*: matching not only whether chrony accepts a
//! file but the messages it emits when it doesn't. chrony's own messages are
//! produced by `LOG_Message`/`command_parse_error`-style call sites in `conf.c`;
//! reproducing them byte-for-byte is court `CHRONY.CONFIG.14`. Until a given
//! message is witnessed against the oracle, our text is marked *normalized* (our
//! own wording) rather than claimed as exact chrony output. See
//! `docs/config-atlas.md` for which messages are admitted as exact.

use serde::{Deserialize, Serialize};

/// Severity of a diagnostic. chrony fatally rejects most config errors at
/// startup (`--check-config` exits non-zero), so `Error` is the common case;
/// `Warning` is reserved for things chrony tolerates but reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Severity {
    Warning,
    Error,
}

/// A single diagnostic tied to a source line.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    /// 1-based source line, or 0 for file-level diagnostics with no single line.
    pub line_no: usize,
    /// Stable machine code (e.g. `CFG_UNKNOWN_DIRECTIVE`). Codes are part of the
    /// contract: tooling and tests match on the code, while `message` may be
    /// refined toward exact chrony wording over time.
    pub code: &'static str,
    /// Human-readable message. Marked normalized until witnessed (see module doc).
    pub message: String,
}

impl Diagnostic {
    pub fn error(line_no: usize, code: &'static str, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Error,
            line_no,
            code,
            message: message.into(),
        }
    }

    pub fn warning(line_no: usize, code: &'static str, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Warning,
            line_no,
            code,
            message: message.into(),
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(self.severity, Severity::Error)
    }
}

impl core::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match self.severity {
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        if self.line_no == 0 {
            write!(f, "{kind}: {} [{}]", self.message, self.code)
        } else {
            write!(
                f,
                "{kind}: line {}: {} [{}]",
                self.line_no, self.message, self.code
            )
        }
    }
}
