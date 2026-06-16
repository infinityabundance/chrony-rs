//! NTP synchronisation-loop guard — `ntp_core.c` Stage 5 (`check_sync_loop`, test D).
//!
//! [`check_sync_loop`] is **test D** of `NCR_ProcessResponse`: it rejects a response
//! that would create a synchronisation loop — either the source is synchronised to the
//! address we send requests from, or the source's reference data (stratum, reference id,
//! root delay, reference timestamp) matches our own exactly, which means it *is* us (a
//! misconfiguration). The test only applies when we are actually serving time (a server
//! socket is open and the reference clock is in normal mode); otherwise no loop is
//! possible and the response is accepted.
//!
//! # Adaptations (documented, not silent)
//!
//! chrony reads the local reference identity off `REF_*` / `NIO_*` and derives the
//! comparison values with the `UTI_*` codecs. Here those are passed in already reduced
//! to the comparison granularity: host-order reference ids, the raw 16.16 NTP-short
//! `root_delay` bits (`UTI_DoubleToNtp32`), and the packed 64-bit NTP timestamps
//! (`UTI_TimespecToNtp64`). The codecs themselves are courted separately
//! ([`crate::ntp::timestamp`]); this module ports test D's decision logic.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness (the static `check_sync_loop` reached directly, the `REF`/`NIO`/refid inputs
//! made controllable and the small `UTI_*` codecs kept real): the socket/mode guards,
//! the synced-to-our-address branch, the exact-match "it is me" branch, and the
//! differing/zero reference-timestamp escapes are exercised and the return captured with
//! its inputs (`research/oracle/ntp_core-syncloop-c-vectors.txt`). See the tests.

/// chrony `check_sync_loop` (test D): `true` if the response is safe (no loop), `false`
/// if accepting it would synchronise us in a loop (the source is synced to our address,
/// or it is us). `server_socket_open` / `ref_mode_normal` gate the test (chrony's
/// `NIO_IsServerSocketOpen()` and `REF_GetMode() == REF_ModeNormal`).
#[allow(clippy::too_many_arguments)]
pub fn check_sync_loop(
    server_socket_open: bool,
    ref_mode_normal: bool,
    msg_stratum: i32,
    msg_refid: u32,
    local_refid: u32,
    our_stratum: i32,
    our_refid: u32,
    msg_root_delay: u32,
    our_root_delay_ntp32: u32,
    msg_reference_ts: u64,
    our_reference_ts: u64,
) -> bool {
    // A client/peer can only be synchronised to us if we are actually serving time.
    if !server_socket_open || !ref_mode_normal {
        return true;
    }

    // The source indicates it is synchronised to the address we send requests from.
    if msg_stratum > 1 && msg_refid == local_refid {
        return false;
    }

    // The source's reference data matches ours exactly -> it is us.
    if msg_stratum == our_stratum
        && msg_refid == our_refid
        && msg_root_delay == our_root_delay_ntp32
        && msg_reference_ts != 0
        && msg_reference_ts == our_reference_ts
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests;
