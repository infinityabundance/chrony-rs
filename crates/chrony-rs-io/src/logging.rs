//! File logging — the I/O half of chrony 4.5 `logging.c` (`LOG_OpenFileLog`, `LOG_FileOpen`,
//! `LOG_FileWrite`, `LOG_CycleLogFiles`), composing the pure formatting/banner/severity logic
//! from [`chrony_rs_core::logging`].
//!
//! The statistics logs (tracking/measurements/statistics/…) are append-mode files under the
//! configured `logdir`; chrony writes a `====`/banner/`====` header every `logbanner`-th line.
//! This uses safe `std::fs` (no FFI, no raw syscalls). The syslog path (`LOG_OpenSystemLog`)
//! and the parent-fd forwarding are host boundaries.

use chrony_rs_core::config::accessors::ConfigValues;
use chrony_rs_core::logging::log_banner_lines;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// `LOG_FileID`.
pub type LogFileId = i32;
/// `MAX_FILELOGS`.
const MAX_FILELOGS: usize = 6;

struct LogFileEntry {
    name: Option<String>,
    banner: String,
    file: Option<File>,
    writes: u64,
}

/// The `logging.c` statistics-log registry (`logfiles[]` / `n_filelogs`).
#[derive(Default)]
pub struct LogFiles {
    entries: Vec<LogFileEntry>,
}

impl LogFiles {
    pub fn new() -> Self {
        LogFiles {
            entries: Vec::new(),
        }
    }

    /// `LOG_FileOpen`: register a statistics log by `name` and `banner`, returning its id (or
    /// `-1` if the fixed table is full). The file is opened lazily on the first write.
    pub fn file_open(&mut self, name: &str, banner: &str) -> LogFileId {
        if self.entries.len() >= MAX_FILELOGS {
            return -1;
        }
        self.entries.push(LogFileEntry {
            name: Some(name.to_string()),
            banner: banner.to_string(),
            file: None,
            writes: 0,
        });
        (self.entries.len() - 1) as LogFileId
    }

    /// `LOG_FileWrite`: append `line` to log `id`, lazily opening `<logdir>/<name>.log` and
    /// writing the `====`/banner/`====` header every `logbanner`-th write (chrony's cadence).
    /// A missing `logdir` disables the log (chrony warns and clears the name). `line` is the
    /// already-formatted record (chrony's `vfprintf(format, ...)`); a trailing newline is added.
    pub fn file_write(&mut self, config: &ConfigValues, id: LogFileId, line: &str) {
        let idx = id as usize;
        if id < 0 || idx >= self.entries.len() || self.entries[idx].name.is_none() {
            return;
        }

        if self.entries[idx].file.is_none() {
            let Some(logdir) = config.log_dir() else {
                // chrony: "logdir not specified" -> disable this log.
                self.entries[idx].name = None;
                return;
            };
            let mut path = PathBuf::from(logdir);
            let Some(name) = self.entries[idx].name.as_ref() else {
                return;
            };
            path.push(format!("{name}.log"));
            match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(f) => self.entries[idx].file = Some(f),
                Err(_) => {
                    self.entries[idx].name = None;
                    return;
                }
            }
        }

        let banner = config.log_banner();
        let writes = self.entries[idx].writes;
        let banner_lines = log_banner_lines(&self.entries[idx].banner, writes, banner);
        self.entries[idx].writes += 1;

        let Some(f) = self.entries[idx].file.as_mut() else {
            return;
        };
        if let Some(lines) = banner_lines {
            for bl in &lines {
                let _ = writeln!(f, "{bl}");
            }
        }
        let _ = writeln!(f, "{line}");
        let _ = f.flush();
    }

    /// `LOG_CycleLogFiles`: close every open statistics log (they reopen lazily on the next
    /// write) — chrony's SIGHUP log-rotation handling.
    pub fn cycle_log_files(&mut self) {
        for e in &mut self.entries {
            e.file = None;
        }
    }

    /// The number of registered logs (for tests).
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Open syslog connection (chrony's `LOG_OpenSystemLog`).
pub fn open_syslog() {
    let ident = b"chronyd-rs\0";
    // SAFETY: ident is a valid NUL-terminated byte string. openlog
    // does not capture the pointer; it copies the ident internally.
    // The option and facility constants are valid libc values.
    unsafe {
        libc::openlog(
            ident.as_ptr() as *const i8,
            libc::LOG_NDELAY | libc::LOG_PID,
            libc::LOG_DAEMON,
        );
    }
}

/// Send a message to syslog.
pub fn syslog_message(priority: i32, msg: &str) {
    let cmsg = std::ffi::CString::new(msg).unwrap_or_default();
    // SAFETY: cmsg is a valid NUL-terminated CString. syslog does not
    // capture the pointer for later use (it formats immediately). The
    // priority is a caller-supplied libc constant.
    unsafe {
        libc::syslog(priority, cmsg.as_ptr());
    }
}

/// Close syslog connection.
pub fn close_syslog() {
    // SAFETY: closelog() closes the syslog connection. It is safe to call
    // even if openlog() was never called. No resources are leaked.
    unsafe {
        libc::closelog();
    }
}

/// `LOG_OpenFileLog`: open the daemon's main message log (`<log_file>`, append mode). `None`
/// selects stderr in chrony; here it returns `None` (the caller uses stderr). Returns the open
/// file for the message log.
pub fn open_file_log(log_file: Option<&str>) -> Option<File> {
    let path = log_file?;
    OpenOptions::new().create(true).append(true).open(path).ok()
}
