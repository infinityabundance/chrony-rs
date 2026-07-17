//! NTP-instance accessors and startup invariant checks — a port of the small standalone
//! functions in chrony 4.5 `ntp_core.c` that are not part of the larger staged sub-ports:
//! `NCR_GetLocalRefid`, `reset_report`, `do_size_checks`, and `do_time_checks`.
//!
//! The instance lifecycle, scheduler timeouts, and socket handling around these remain the
//! host boundary; these are the pure pieces.

use crate::util::{ip_to_refid, ntp64_to_timespec, timespec_to_ntp64, IpAddr};

/// The on-wire byte offsets of the NTP packet header fields (chrony `NTP_Packet`), asserted
/// by [`do_size_checks`] and used by the packet codec.
/// Offset to the leap-version-mode field.
pub const OFF_LVM: usize = 0;
/// Offset to the stratum field.
pub const OFF_STRATUM: usize = 1;
/// Offset to the poll interval field.
pub const OFF_POLL: usize = 2;
/// Offset to the precision field.
pub const OFF_PRECISION: usize = 3;
/// Offset to the root delay field.
pub const OFF_ROOT_DELAY: usize = 4;
/// Offset to the root dispersion field.
pub const OFF_ROOT_DISPERSION: usize = 8;
/// Offset to the reference ID field.
pub const OFF_REFERENCE_ID: usize = 12;
/// Offset to the reference timestamp field.
pub const OFF_REFERENCE_TS: usize = 16;
/// Offset to the originate timestamp field.
pub const OFF_ORIGINATE_TS: usize = 24;
/// Offset to the receive timestamp field.
pub const OFF_RECEIVE_TS: usize = 32;
/// Offset to the transmit timestamp field.
pub const OFF_TRANSMIT_TS: usize = 40;
/// `NTP_HEADER_LENGTH`.
pub const NTP_HEADER_LENGTH: usize = 48;

/// chrony `NCR_GetLocalRefid`: the reference id derived from an instance's local address.
pub fn get_local_refid(local_addr: &IpAddr) -> u32 {
    ip_to_refid(local_addr)
}

/// The zeroed portion of a source's NTP report that `reset_report` fills in: the remote
/// address and port (every other field is cleared). Modeled as the pair chrony sets, so the
/// caller can reset its report without depending on the full `NtpReport`/daemon state.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ReportAddress {
    pub remote_addr: Option<IpAddr>,
    pub remote_port: u16,
}

/// chrony `reset_report`: clear a report and set only its remote address / port. Returns the
/// address fields (the rest of chrony's `report` struct is a zeroed default).
pub fn reset_report(remote_addr: IpAddr, remote_port: u16) -> ReportAddress {
    ReportAddress { remote_addr: Some(remote_addr), remote_port }
}

/// chrony `do_size_checks`: assert the NTP packet header field offsets (RFC 5905 §7.3). A
/// wrong offset here would silently corrupt every packet, so this pins the wire layout the
/// codec relies on. Panics (like chrony's `assert`) on a mismatch.
pub fn do_size_checks() {
    assert_eq!(OFF_LVM, 0);
    assert_eq!(OFF_STRATUM, 1);
    assert_eq!(OFF_POLL, 2);
    assert_eq!(OFF_PRECISION, 3);
    assert_eq!(OFF_ROOT_DELAY, 4);
    assert_eq!(OFF_ROOT_DISPERSION, 8);
    assert_eq!(OFF_REFERENCE_ID, 12);
    assert_eq!(OFF_REFERENCE_TS, 16);
    assert_eq!(OFF_ORIGINATE_TS, 24);
    assert_eq!(OFF_RECEIVE_TS, 32);
    assert_eq!(OFF_TRANSMIT_TS, 40);
    assert_eq!(NTP_HEADER_LENGTH, 48);
}

/// chrony `do_time_checks`: assert that a timestamp exactly at `ntp_era_split` and one a
/// second before it round-trip through the NTP-64 mapping correctly — the second underflows
/// to `split + (2³² − 1)` seconds — proving the era-split arithmetic is sound. Panics (like
/// chrony's `assert`) if the invariant does not hold.
pub fn do_time_checks(ntp_era_split: i64) {
    // ts1 = {split, 1 ns}; ts2 = {split - 1, 1 ns}.
    let (hi1, lo1) = timespec_to_ntp64(ntp_era_split, 1, None);
    let (hi2, lo2) = timespec_to_ntp64(ntp_era_split - 1, 1, None);
    let (sec1, _) = ntp64_to_timespec(hi1, lo1, ntp_era_split);
    let (sec2, _) = ntp64_to_timespec(hi2, lo2, ntp_era_split);

    assert!(sec1 == ntp_era_split, "era-split round-trip: sec1 should equal {} but got {}", ntp_era_split, sec1);
    assert!(
        sec1 + (1i64 << 32) - 1 == sec2,
        "era-split underflow: sec2 should be {} but got {}",
        sec1 + (1i64 << 32) - 1,
        sec2,
    );
}

use crate::ntp::mono_root::MAX_MONO_DOFFSET;
use crate::ntp::poll::get_poll_adj;

/// chrony `process_sample`'s error-in-estimate: how far the measured offset is from the
/// offset predicted by past samples. chrony's convention negates the sample offset (positive
/// = local clock fast of reference).
pub fn sample_error_in_estimate(sample_offset: f64, estimated_offset: f64) -> f64 {
    (-sample_offset - estimated_offset).abs()
}

/// chrony `process_sample`'s monotonic-correction gate: apply the accumulated monotonic
/// offset only when it is non-zero and within ±[`MAX_MONO_DOFFSET`].
pub fn should_apply_mono_correction(mono_doffset: f64) -> bool {
    mono_doffset != 0.0 && mono_doffset.abs() <= MAX_MONO_DOFFSET
}

/// chrony `process_sample`'s poll adjustment: the peer distance is `peer_dispersion +
/// 0.5·peer_delay`, and the poll is adjusted by [`get_poll_adj`] from the error-in-estimate
/// against that distance. Returns `(error_in_estimate, poll_adjustment)`; the caller applies
/// it via `adjust_poll` (the sample filtering, `SST`/`SRC` accumulation, and source selection
/// are the already-ported layers this composes).
pub fn process_sample_poll_adjustment(
    sample_offset: f64,
    estimated_offset: f64,
    peer_dispersion: f64,
    peer_delay: f64,
    samples: i32,
    poll_target: i32,
) -> (f64, f64) {
    let error_in_estimate = sample_error_in_estimate(sample_offset, estimated_offset);
    let peer_distance = peer_dispersion + 0.5 * peer_delay;
    let adj = get_poll_adj(samples, poll_target, error_in_estimate, peer_distance);
    (error_in_estimate, adj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_and_time_checks_hold() {
        // chrony aborts if these fail; here they must simply pass for the reference era.
        do_size_checks();
        do_time_checks(crate::util::NTP_ERA_SPLIT);
        // The era-split underflow also holds at a non-zero split.
        do_time_checks(1_000_000_000);
    }

    #[test]
    fn local_refid_delegates_to_ip_to_refid() {
        let a = IpAddr::Inet4(0xc000_0207);
        assert_eq!(get_local_refid(&a), ip_to_refid(&a));
        let b = IpAddr::Inet6([0x20; 16]);
        assert_eq!(get_local_refid(&b), ip_to_refid(&b));
    }

    #[test]
    fn reset_report_sets_only_the_address() {
        let r = reset_report(IpAddr::Inet4(0x0a00_0001), 123);
        assert_eq!(r.remote_addr, Some(IpAddr::Inet4(0x0a00_0001)));
        assert_eq!(r.remote_port, 123);
    }

    #[test]
    fn process_sample_kernel_matches_the_formula() {
        // error = |-offset - estimated|.
        assert_eq!(sample_error_in_estimate(0.002, -0.0015), (-0.002f64 + 0.0015).abs());
        // Mono correction gate: non-zero and within ±MAX_MONO_DOFFSET.
        assert!(should_apply_mono_correction(1.0));
        assert!(!should_apply_mono_correction(0.0));
        assert!(!should_apply_mono_correction(MAX_MONO_DOFFSET + 0.1));
        assert!(should_apply_mono_correction(-MAX_MONO_DOFFSET));

        // The poll adjustment matches get_poll_adj over peer_dispersion + 0.5*peer_delay.
        let (err, adj) = process_sample_poll_adjustment(0.002, -0.0015, 1e-4, 2e-4, 8, 6);
        assert_eq!(err, (-0.002f64 + 0.0015).abs());
        assert_eq!(adj, get_poll_adj(8, 6, err, 1e-4 + 0.5 * 2e-4));
    }
}
