//! NTP source report — `ntp_core.c` Stage 18 (`NCR_ReportSource`).
//!
//! [`report_source`] ports `NCR_ReportSource`, which fills the per-source poll interval
//! and mode for a `chronyc sources` report. The poll interval is the one the next
//! transmission would use ([`crate::ntp::poll::get_transmit_poll`], already courted), and
//! the mode maps the internal NTP mode to the report's client/peer classification.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness (`research/oracle/ntp_core-report-c-vectors.txt`). See the tests.

use crate::ntp::poll::get_transmit_poll;

/// chrony `MODE_CLIENT` / `MODE_ACTIVE`.
const MODE_CLIENT: i32 = 3;
const MODE_ACTIVE: i32 = 1;

/// chrony `RPT_SourceReport` mode (`RPT_NTP_CLIENT` / `RPT_NTP_PEER`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum ReportMode {
    NtpClient = 0,
    NtpPeer = 1,
}

/// chrony `NCR_ReportSource`: the reported poll interval and mode for a source. The poll
/// is the next transmission's interval (the symmetric local/remote selection); the mode
/// is the client/peer classification.
pub fn report_source(
    local_poll: i32,
    mode: i32,
    remote_poll: i32,
    minpoll: i32,
    reachable: bool,
) -> (i32, ReportMode) {
    let poll = get_transmit_poll(local_poll, mode, remote_poll, minpoll, reachable);
    let report_mode = match mode {
        MODE_CLIENT => ReportMode::NtpClient,
        MODE_ACTIVE => ReportMode::NtpPeer,
        _ => ReportMode::NtpClient, // fallback for unexpected modes
    };
    (poll, report_mode)
}

#[cfg(test)]
mod tests;
