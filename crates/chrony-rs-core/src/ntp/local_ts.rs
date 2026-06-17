//! NTP local-timestamp helpers — `ntp_core.c` Stage 11 (`zero_local_timestamp`,
//! `update_tx_timestamp`).
//!
//! [`NtpLocalTimestamp`] is chrony's `NTP_Local_Timestamp`: a captured local time with
//! its error bound, the timestamping source (daemon/kernel/hardware), and the PTP
//! receive-duration / net-correction metadata.
//!
//! * [`NtpLocalTimestamp::zero`] ports `zero_local_timestamp` — reset to an empty daemon
//!   timestamp.
//! * [`update_tx_timestamp`] ports the hardware-TX-timestamp update: when a more
//!   accurate transmit timestamp arrives (e.g. from a NIC), adopt it **only** if the
//!   original timestamp is set, the response refers to the packet we actually sent (the
//!   stored NTP receive/transmit timestamps still match), and the improvement is a
//!   non-negative delay no larger than `MAX_TX_DELAY`.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness: both helpers are run across the accept/reject branches and the resulting
//! timestamp fields captured (`research/oracle/ntp_core-localts-c-vectors.txt`). See the
//! tests.

use crate::sys_generic::Timespec;

/// chrony `MAX_TX_DELAY`.
const MAX_TX_DELAY: f64 = 1.0;

/// chrony `NTP_Timestamp_Source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampSource {
    Daemon = 0,
    Kernel = 1,
    Hardware = 2,
}

/// chrony `NTP_Local_Timestamp`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NtpLocalTimestamp {
    pub ts: Timespec,
    pub err: f64,
    pub source: TimestampSource,
    pub rx_duration: f64,
    pub net_correction: f64,
}

impl NtpLocalTimestamp {
    /// chrony `zero_local_timestamp`: an empty timestamp attributed to the daemon.
    pub fn zero() -> Self {
        NtpLocalTimestamp {
            ts: Timespec::new(0, 0),
            err: 0.0,
            source: TimestampSource::Daemon,
            rx_duration: 0.0,
            net_correction: 0.0,
        }
    }

    /// Whether the timestamp is unset (`UTI_IsZeroTimespec`).
    fn is_zero(&self) -> bool {
        self.ts.tv_sec == 0 && self.ts.tv_nsec == 0
    }
}

/// chrony `update_tx_timestamp`: replace `tx_ts` with the more accurate `new_tx_ts` when
/// it is consistent with the last packet sent and within `MAX_TX_DELAY`.
///
/// `local_ntp_rx` / `local_ntp_tx` are the stored NTP receive/transmit timestamps the
/// response must still match (each optional, as chrony passes `NULL` to skip a side);
/// `message_receive` / `message_transmit` are the response's. The comparison is exact on
/// the packed 64-bit values (chrony `UTI_CompareNtp64`). Returns whether the update was
/// applied (chrony mutates in place; the bool is for the tests).
#[allow(clippy::too_many_arguments)]
pub fn update_tx_timestamp(
    tx_ts: &mut NtpLocalTimestamp,
    new_tx_ts: &NtpLocalTimestamp,
    local_ntp_rx: Option<u64>,
    local_ntp_tx: Option<u64>,
    message_receive: u64,
    message_transmit: u64,
) -> bool {
    // The original timestamp must be set.
    if tx_ts.is_zero() {
        return false;
    }

    // The response must refer to the packet we last sent.
    if local_ntp_rx.is_some_and(|rx| message_receive != rx)
        || local_ntp_tx.is_some_and(|tx| message_transmit != tx)
    {
        return false;
    }

    let delay = new_tx_ts.ts.diff_to_double(tx_ts.ts);
    // chrony: delay < 0.0 || delay > MAX_TX_DELAY.
    if !(0.0..=MAX_TX_DELAY).contains(&delay) {
        return false;
    }

    *tx_ts = *new_tx_ts;
    true
}

#[cfg(test)]
mod tests;
