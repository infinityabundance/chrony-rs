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
    #[non_exhaustive]
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
    /// The directive keyword this diagnostic concerns, when known. Needed to
    /// render chrony's exact reason text, which embeds the keyword (e.g. "Could
    /// not parse `server` directive").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directive: Option<String>,
}

impl Diagnostic {
    pub fn error(line_no: usize, code: &'static str, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Error,
            line_no,
            code,
            message: message.into(),
            directive: None,
        }
    }

    pub fn warning(line_no: usize, code: &'static str, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Warning,
            line_no,
            code,
            message: message.into(),
            directive: None,
        }
    }

    /// Attach the directive keyword this diagnostic concerns (builder style).
    pub fn for_directive(mut self, directive: impl Into<String>) -> Self {
        self.directive = Some(directive.into());
        self
    }

    pub fn is_error(&self) -> bool {
        matches!(self.severity, Severity::Error)
    }

    /// Render this diagnostic in chrony's exact `chronyd -p` phrasing, with the
    /// host-specific parts (timestamp prefix, absolute path) replaced by the
    /// `<FILE>` placeholder — i.e. the *normalized* form captured by the oracle
    /// harness (`tools/oracle/capture-config.sh`).
    ///
    /// Returns `None` for diagnostics whose chrony equivalent has not been
    /// witnessed against the 4.5 oracle. The reason→code mapping below is anchored
    /// to receipts under `reports/oracle/config/`; do not extend it without a
    /// matching captured fixture.
    ///
    /// Note a deliberate, documented divergence: chrony fails *fatally on the first*
    /// bad directive, so it emits exactly one such line; chrony-rs collects all
    /// diagnostics. Each individual line still matches chrony's wording. See
    /// `docs/config-atlas.md`.
    pub fn chrony_message(&self) -> Option<String> {
        let reason = match self.code {
            "CFG_UNKNOWN_DIRECTIVE" => "Invalid directive".to_string(),
            "CFG_MISSING_ADDRESS" | "CFG_BAD_NUMBER" | "CFG_BAD_ARITY" => {
                format!("Could not parse {} directive", self.directive.as_ref()?)
            }
            "CFG_MISSING_PATH" | "CFG_MISSING_VALUE" => {
                format!("Missing arguments for {} directive", self.directive.as_ref()?)
            }
            "CFG_UNEXPECTED_ARGS" => {
                format!("Too many arguments for {} directive", self.directive.as_ref()?)
            }
            // chrony `other_parse_error(message)`: the message itself is the full reason.
            "CFG_INVALID_LOG_PARAM" => "Invalid log parameter".to_string(),
            "CFG_INVALID_REFCLOCK_OPT" => "Invalid refclock option".to_string(),
            _ => return None,
        };
        Some(format!(
            "Fatal error : {reason} at line {} in file <FILE>",
            self.line_no
        ))
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
