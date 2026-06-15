//! `chrony-rs-core` — the deterministic time-discipline brain of chrony-rs.
//!
//! # What this crate is
//!
//! This is the part of `chrony-rs` that is meant to be testable *without* a real
//! system clock, a real network, or root privileges. Everything that touches the
//! host (mutating the clock, opening raw sockets, dropping privileges) lives in
//! the daemon binary behind narrow trait boundaries; the brain here only computes.
//!
//! # Parity doctrine
//!
//! `chrony-rs` is a *forensic reconstruction* of chrony, not a clean-room NTP
//! daemon. Three kinds of parity are pursued, and the modules below are organized
//! around them:
//!
//! * **Byte parity** — [`ntp`] encodes/decodes NTP packets and timestamps so that
//!   the exact observable bytes match. See `docs/packet-atlas.md`.
//! * **Behavior parity** — [`config`] reproduces chrony's config parsing and
//!   diagnostics; later campaigns add source selection and discipline. See
//!   `docs/config-atlas.md`.
//! * **Operational-knowledge parity** — the *comments* in this crate are part of
//!   the deliverable. They record why chrony behaves as it does, not just what the
//!   code does. See `docs/source-archaeology.md`.
//!
//! # Claim boundary
//!
//! Nothing here claims production readiness. The real `chronyd` remains the
//! primary oracle for chrony-specific semantics; independent NTP oracles are used
//! only to classify protocol truth versus chrony policy. See
//! `docs/deployment-boundary.md` and `docs/negative-capabilities.md` for what is
//! intentionally *not* admitted yet.

pub mod addrfilt;
pub mod array;
pub mod clientlog;
pub mod clock;
pub mod cmac_nettle;
pub mod cmdparse;
pub mod config;
pub mod hash;
pub mod hash_intmd5;
pub mod hwclock;
pub mod keys;
pub mod local;
pub mod manual;
pub mod md5;
pub mod nameserv;
pub mod nts_ntp_auth;
pub mod nts_ntp_client;
pub mod nts_ntp_server;
pub mod ntp;
pub mod pktlength;
pub mod quantiles;
pub mod regress;
pub mod replay;
pub mod report;
pub mod samplefilt;
pub mod sched;
pub mod siv_nettle;
pub mod siv_nettle_int;
pub mod smooth;
pub mod sourcestats;
pub mod sources;
pub mod sys_generic;
pub mod sys_null;
pub mod sys_timex;
pub mod tempcomp;
pub mod trace;
pub mod util;

/// The chrony upstream version whose behavior this reconstruction currently
/// targets as its primary oracle. This is a *declared target*, not a claim of
/// achieved parity — see `docs/compatibility.md` for the admitted court matrix.
///
/// The doc gate (see `docs/`) is intended to fail if this value drifts away from
/// the version recorded in the evidence receipts under `reports/`.
pub const TARGET_CHRONY_VERSION: &str = "4.5";

/// The trace-schema identifier emitted and accepted by [`trace`]. Bumping the
/// schema is a breaking change for every stored replay fixture, so the value is
/// surfaced here and asserted in tests rather than scattered as a string literal.
pub const TRACE_SCHEMA: &str = "chrony-rs-trace-v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_constants_are_stable() {
        // These constants gate stored evidence. If you intend to change them, you
        // are also intending to re-cut every receipt under reports/ — do that
        // deliberately, not as a drive-by edit.
        assert_eq!(TRACE_SCHEMA, "chrony-rs-trace-v1");
        assert_eq!(TARGET_CHRONY_VERSION, "4.5");
    }
}
