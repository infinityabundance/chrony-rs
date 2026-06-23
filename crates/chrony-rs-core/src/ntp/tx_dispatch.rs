//! NTP transmit-path mode dispatch — `ntp_core.c` Stage 20 (`NCR_ProcessTxKnown` /
//! `NCR_ProcessTxUnknown`).
//!
//! When a hardware/kernel transmit timestamp for a packet we sent becomes available,
//! chrony routes it by the packet's NTP mode:
//!
//! * [`tx_known_is_response`] ports `NCR_ProcessTxKnown`'s split — a client/active-mode
//!   packet is a request *we* sent, so its TX timestamp updates our stored
//!   `local_tx` (via the already-ported [`crate::ntp::local_ts::update_tx_timestamp`]);
//!   any other mode is a response we sent to an unknown source, routed to
//!   `NCR_ProcessTxUnknown`.
//! * [`tx_unknown_should_process`] ports `NCR_ProcessTxUnknown`'s guard — broadcast
//!   packets carry no per-client timestamp to record, so they are ignored.
//!
//! The timestamp update itself ([`crate::ntp::local_ts::update_tx_timestamp`]) and the
//! client-log lookup/store (`CLG_*`) are ported / host-boundary respectively; these
//! functions are the mode routing.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness: `NCR_ProcessTxKnown` is driven and the route witnessed by whether
//! `inst->local_tx` was updated; `NCR_ProcessTxUnknown` by whether it reached the
//! client-log timestamp lookup (`research/oracle/ntp_core-txdispatch-c-vectors.txt`).
//! See the tests.

use crate::ntp::rx_dispatch::{MODE_ACTIVE, MODE_BROADCAST, MODE_CLIENT};

/// chrony `NCR_ProcessTxKnown`: whether the TX timestamp is for a request we sent (client
/// or symmetric-active mode), and so updates our stored transmit timestamp. Otherwise the
/// packet is a response to an unknown source and is routed to `NCR_ProcessTxUnknown`.
pub fn tx_known_is_response(packet_mode: i32) -> bool {
    packet_mode == MODE_CLIENT || packet_mode == MODE_ACTIVE
}

/// chrony `NCR_ProcessTxUnknown`: whether to record this response's TX timestamp.
/// Broadcast packets are ignored (no per-client timestamp to store).
pub fn tx_unknown_should_process(packet_mode: i32) -> bool {
    packet_mode != MODE_BROADCAST
}

#[cfg(test)]
mod tests;
