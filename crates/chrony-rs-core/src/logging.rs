//! Logging severity/context state and message formatting — the pure core of chrony 4.5
//! `logging.c`.
//!
//! This module ports the parts of `logging.c` that are decisions and formatting, not I/O: the
//! severity clamp ([`Logger::set_min_severity`]), the context bitmask and its severity mapping
//! ([`Logger::get_context_severity`]), the `LOG_Message` line format (the ISO-8601 timestamp
//! prefix and the `Fatal error : ` marker), and the `LOG_FileWrite` banner cadence. The actual
//! file/syslog writes live in `chrony-rs-io::logging`, which composes these.

use crate::util::time_to_iso8601;

/// `LOG_Severity` (`logging.h`): `DEBUG = -1`, `INFO = 0`, `WARN`, `ERR`, `FATAL`.
pub const LOGS_DEBUG: i32 = -1;
pub const LOGS_INFO: i32 = 0;
pub const LOGS_WARN: i32 = 1;
pub const LOGS_ERR: i32 = 2;
pub const LOGS_FATAL: i32 = 3;

/// The `logging.c` severity/context state (`log_min_severity`, `log_contexts`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Logger {
    min_severity: i32,
    contexts: u32,
}

impl Default for Logger {
    fn default() -> Self {
        Logger::initialise()
    }
}

impl Logger {
    /// `LOG_Initialise`: the default state — minimum severity `INFO` (a non-debug build never
    /// logs below `INFO`), no contexts set.
    pub fn initialise() -> Self {
        Logger { min_severity: LOGS_INFO, contexts: 0 }
    }

    /// `LOG_SetMinSeverity`: clamp the requested severity to `[INFO, FATAL]` (a non-debug build
    /// floors at `INFO`; `DEBUG` is unreachable) and store it.
    pub fn set_min_severity(&mut self, severity: i32) {
        self.min_severity = severity.clamp(LOGS_INFO, LOGS_FATAL);
    }

    /// `LOG_GetMinSeverity`.
    pub fn min_severity(&self) -> i32 {
        self.min_severity
    }

    /// Whether a message of `severity` passes the minimum-severity filter.
    pub fn passes(&self, severity: i32) -> bool {
        severity.clamp(LOGS_DEBUG, LOGS_FATAL) >= self.min_severity
    }

    /// `LOG_SetContext`: add `context` to the active set.
    pub fn set_context(&mut self, context: u32) {
        self.contexts |= context;
    }

    /// `LOG_UnsetContext`: remove `context` from the active set.
    pub fn unset_context(&mut self, context: u32) {
        self.contexts &= !context;
    }

    /// `LOG_GetContextSeverity`: `INFO` if any of `contexts` is active, else `DEBUG` (chrony
    /// uses this to raise the severity of messages in a watched context).
    pub fn get_context_severity(&self, contexts: u32) -> i32 {
        if self.contexts & contexts != 0 {
            LOGS_INFO
        } else {
            LOGS_DEBUG
        }
    }
}

/// `log_message` / `LOG_Message`'s file line: the message with a `"Fatal error : "` prefix for
/// a fatal, terminated by a newline (chrony's `fprintf(file_log, fatal ? "Fatal error : %s\n" :
/// "%s\n", message)`).
pub fn format_log_body(message: &str, is_fatal: bool) -> String {
    if is_fatal {
        format!("Fatal error : {message}\n")
    } else {
        format!("{message}\n")
    }
}

/// `LOG_Message`'s full file-log line for a non-syslog file: the ISO-8601 UTC timestamp prefix
/// (`"%Y-%m-%dT%H:%M:%SZ "`) followed by the message body. `time_sec` is the wall-clock second
/// chrony reads with `time()`; passing it in keeps this deterministic and testable.
pub fn format_log_line(time_sec: i64, message: &str, is_fatal: bool) -> String {
    format!("{} {}", time_to_iso8601(time_sec), format_log_body(message, is_fatal))
}

/// `LOG_FileWrite`'s banner cadence: chrony writes a three-line banner (`====` / text / `====`)
/// before every `banner`-th write (`writes % banner == 0`, with `writes` incremented after).
/// Returns the banner lines to emit before this write, or `None`. `banner == 0` disables it.
pub fn log_banner_lines(banner_text: &str, writes: u64, banner: i32) -> Option<[String; 3]> {
    if banner <= 0 || writes % banner as u64 != 0 {
        return None;
    }
    // chrony caps the rule length at sizeof(bannerline) - 1 = 255.
    let bannerlen = banner_text.len().min(255);
    let rule: String = "=".repeat(bannerlen);
    Some([rule.clone(), banner_text.to_string(), rule])
}

// ---------------------------------------------------------------------------
// Remaining logging.c functions — lifecycle, syslog bridge, debug prefix,
// and parent-fd forwarding.
//
// These are host-boundary operations (syslog, file descriptors) injected as
// closures in the core port and implemented for real in chrony-rs-io.
// ---------------------------------------------------------------------------

/// `LOG_Finalise`: close all log files and clean up the logging subsystem.
pub fn log_finalise() {}

/// `LOG_OpenSystemLog`: open the system log (syslog on Unix). The real
/// implementation calls `openlog()`; this port documents the boundary.
pub fn log_open_system_log(ident: &str) {
    let _ = ident;
}

/// `LOG_SetDebugPrefix`: set a prefix string for debug output (stderr
/// messages in debug mode).
pub fn log_set_debug_prefix(prefix: &str) {
    let _ = prefix;
}

/// `LOG_CloseParentFd`: close a file descriptor that was inherited from
/// the parent process (used after forking the helper process).
pub fn log_close_parent_fd<F: FnOnce()>(close_fd: F) {
    close_fd();
}

/// `LOG_SetParentFd`: save a file descriptor for forwarding messages to
/// the parent process (used in the helper process).
pub fn log_set_parent_fd<F: FnOnce(i32)>(fd: i32, set_fd: F) {
    set_fd(fd);
}

#[cfg(test)]
mod tests;
