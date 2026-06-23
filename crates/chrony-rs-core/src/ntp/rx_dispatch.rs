//! NTP receive-path mode dispatch — `ntp_core.c` Stage 19 (`NCR_ProcessRxKnown` /
//! `NCR_ProcessRxUnknown` classification).
//!
//! When a packet arrives, chrony first decides *what kind* of packet it is from the NTP
//! mode field and the local association's mode:
//!
//! * [`classify_rx_known`] ports `NCR_ProcessRxKnown`'s dispatch table for a packet from
//!   a **configured** source — is it a reply to process, an unsolicited request to handle
//!   as if from an unknown host, or junk to discard?
//! * [`classify_rx_unknown`] ports `NCR_ProcessRxUnknown`'s reply-mode mapping for a
//!   packet from an **unknown** source — what server/passive mode (if any) should we
//!   answer in?
//!
//! # Adaptation (documented, not silent)
//!
//! Everything around the decision — the socket-ownership and offline checks, access
//! control, rate limiting, authentication, the interleaved-timestamp lookup, and the
//! actual `process_response` / `transmit_packet` calls — is host-boundary or already
//! ported elsewhere; these functions are the pure classification at the core.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness: `NCR_ProcessRxKnown` is driven and the branch witnessed by the
//! `SRC_GetSourcestats` / `NIO_IsServerSocket` stubs; `NCR_ProcessRxUnknown` is driven to
//! completion and the reply mode read from the captured response packet
//! (`research/oracle/ntp_core-rxdispatch-c-vectors.txt`). See the tests.

/// chrony `NTP_Mode`.
pub const MODE_UNDEFINED: i32 = 0;
pub const MODE_ACTIVE: i32 = 1;
pub const MODE_PASSIVE: i32 = 2;
pub const MODE_CLIENT: i32 = 3;
pub const MODE_SERVER: i32 = 4;
pub const MODE_BROADCAST: i32 = 5;

/// chrony `NTP_PORT`.
const NTP_PORT: u16 = 123;

/// What [`classify_rx_known`] decides to do with a packet from a configured source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxKnownAction {
    /// Process it as a reply (chrony's `process_response`).
    ProcessResponse,
    /// Handle it as a request from an unknown source (chrony's `NCR_ProcessRxUnknown`).
    ProcessAsUnknown,
    /// Discard it.
    Discard,
}

/// chrony `NCR_ProcessRxKnown` dispatch: classify a packet (`packet_mode`) from a source
/// we have configured in `our_mode`.
pub fn classify_rx_known(packet_mode: i32, our_mode: i32) -> RxKnownAction {
    use RxKnownAction::*;
    match packet_mode {
        MODE_ACTIVE => match our_mode {
            MODE_ACTIVE => ProcessResponse, // ordinary symmetric peering
            MODE_CLIENT => ProcessAsUnknown, // they treat us as a peer; we treat as unknown
            _ => Discard,
        },
        MODE_PASSIVE => match our_mode {
            MODE_ACTIVE => ProcessResponse, // we peer with them, they don't configure us
            _ => Discard,
        },
        // A client request is always handled as if from an unknown source.
        MODE_CLIENT => ProcessAsUnknown,
        MODE_SERVER => match our_mode {
            MODE_CLIENT => ProcessResponse, // standard client/server
            _ => Discard,
        },
        // Broadcast and anything else.
        _ => Discard,
    }
}

/// chrony `NCR_ProcessRxUnknown` reply-mode mapping: given a request (`packet_mode`,
/// `version`, source `port`) from an unknown host, the mode to answer in, or `None` to
/// not respond. (NTPv1 requests carry no mode field; an `MODE_UNDEFINED` v1 packet from a
/// non-123 port is treated as a client request.)
pub fn classify_rx_unknown(packet_mode: i32, version: i32, port: u16) -> Option<i32> {
    match packet_mode {
        MODE_ACTIVE => Some(MODE_PASSIVE), // symmetric passive (we never lock to them)
        MODE_CLIENT => Some(MODE_SERVER),
        MODE_UNDEFINED if version == 1 && port != NTP_PORT => Some(MODE_SERVER),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
