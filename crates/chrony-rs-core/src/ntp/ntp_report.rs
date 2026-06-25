//! The per-source NTP ntpdata report — `ntp_core.c` (`process_response`'s report-update
//! block + `NCR_GetNTPReport`).
//!
//! After `process_response` accepts a packet as valid (tests 1/2/3 passed, so a sample is
//! computed), it records a snapshot of the exchange into the instance's `RPT_NTPReport`
//! ([`NtpReport`]) — the data `chronyc ntpdata` later reads via `NCR_GetNTPReport` (a bare
//! struct copy). [`build_ntp_report`] ports that field mapping.
//!
//! Most fields are direct copies of the packet header / computed sample. The computed
//! parts are: the mode (`NTP_LVM_TO_MODE`), the reference timestamp (decoded with
//! [`crate::util::ntp64_to_timespec`]), the `tests` bitmask (the eight RFC tests packed
//! big-endian, [`pack_tests`]), the receive/transmit timestamp-source characters
//! ([`tss_char`]), and the valid/good counters.
//!
//! # Scope and adaptations
//!
//! * `remote_addr`/`remote_port` are set when the instance is created (not in this block),
//!   so they are out of scope here.
//! * `jitter_asymmetry` (`SST_GetJitterAsymmetry`) and `authenticated` (`NAU_IsAuthEnabled`)
//!   are host inputs supplied by the caller.
//! * `total_tx_count`/`total_rx_count` are bumped elsewhere (transmit / the receive tail),
//!   so they pass through unchanged.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`**: `process_response` is
//! driven over a valid client exchange and the resulting `inst->report` dumped
//! (`/tmp/ncor/genrep.c`, `research/oracle/ntp_core-report-c-vectors.txt`). See the tests.

use crate::sys_generic::Timespec;
use crate::util::{ntp64_to_timespec, IpAddr};

/// chrony's `tss_chars[3] = {'D', 'K', 'H'}`: the character for a timestamp source
/// (`NTP_TS_DAEMON`, `NTP_TS_KERNEL`, `NTP_TS_HARDWARE`).
pub fn tss_char(source: u8) -> char {
    match source {
        0 => 'D', // NTP_TS_DAEMON
        1 => 'K', // NTP_TS_KERNEL
        2 => 'H', // NTP_TS_HARDWARE
        _ => '?',
    }
}

/// chrony's `tests` bitmask: `test1 test2 test3 test5 test6 test7 testA testB testC testD`
/// packed most-significant-first into the low 10 bits, exactly as `process_response` does.
pub fn pack_tests(tests: [bool; 10]) -> u16 {
    let mut v = 0u16;
    for t in tests {
        v = (v << 1) | t as u16;
    }
    v
}

/// chrony's `RPT_NTPReport`, restricted to the fields `process_response`'s report-update
/// block writes (the create-time `remote_addr`/`remote_port` are out of scope here).
#[derive(Clone, Debug, PartialEq)]
pub struct NtpReport {
    pub local_addr: IpAddr,
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub ref_id: u32,
    pub ref_time: Timespec,
    pub offset: f64,
    pub peer_delay: f64,
    pub peer_dispersion: f64,
    pub response_time: f64,
    pub jitter_asymmetry: f64,
    pub tests: u16,
    pub interleaved: bool,
    pub authenticated: bool,
    pub tx_tss_char: char,
    pub rx_tss_char: char,
    pub total_valid_count: u32,
    pub total_good_count: u32,
    pub total_tx_count: u32,
    pub total_rx_count: u32,
}

/// All the per-exchange inputs `process_response` has computed by the time it updates the
/// report. Grouping them keeps [`build_ntp_report`] from a 25-argument signature.
#[derive(Clone, Debug)]
pub struct ReportInputs {
    pub local_addr: IpAddr,
    /// `pkt_leap` / `pkt_version` (copied straight into the report).
    pub leap: u8,
    pub version: u8,
    /// The packet's `lvm` byte; the report mode is `lvm & 7` (`NTP_LVM_TO_MODE`).
    pub lvm: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub ref_id: u32,
    /// The packet's reference timestamp (host-order `(hi, lo)` packed as a `u64`).
    pub reference_ts: u64,
    pub offset: f64,
    pub peer_delay: f64,
    pub peer_dispersion: f64,
    pub response_time: f64,
    pub jitter_asymmetry: f64,
    /// `[test1, test2, test3, test5, test6, test7, testA, testB, testC, testD]`.
    pub tests: [bool; 10],
    pub interleaved: bool,
    pub authenticated: bool,
    pub tx_source: u8,
    pub rx_source: u8,
    pub good_packet: bool,
}

/// `process_response`'s report-update block: snapshot the exchange into a fresh
/// [`NtpReport`], carrying the counters forward from `prev` (valid `+= 1`, good `+= 1` when
/// `good_packet`; the tx/rx counts are untouched here). `ntp_era_split` is the build
/// constant for decoding the reference timestamp (see [`crate::util::NTP_ERA_SPLIT`]).
pub fn build_ntp_report(prev: &NtpReport, inp: &ReportInputs, ntp_era_split: i64) -> NtpReport {
    let (ref_sec, ref_nsec) = ntp64_to_timespec(
        (inp.reference_ts >> 32) as u32,
        inp.reference_ts as u32,
        ntp_era_split,
    );
    NtpReport {
        local_addr: inp.local_addr,
        leap: inp.leap,
        version: inp.version,
        mode: inp.lvm & 0x7, // NTP_LVM_TO_MODE
        stratum: inp.stratum,
        poll: inp.poll,
        precision: inp.precision,
        root_delay: inp.root_delay,
        root_dispersion: inp.root_dispersion,
        ref_id: inp.ref_id,
        ref_time: Timespec::new(ref_sec, ref_nsec),
        offset: inp.offset,
        peer_delay: inp.peer_delay,
        peer_dispersion: inp.peer_dispersion,
        response_time: inp.response_time,
        jitter_asymmetry: inp.jitter_asymmetry,
        tests: pack_tests(inp.tests),
        interleaved: inp.interleaved,
        authenticated: inp.authenticated,
        tx_tss_char: tss_char(inp.tx_source),
        rx_tss_char: tss_char(inp.rx_source),
        total_valid_count: prev.total_valid_count + 1,
        total_good_count: prev.total_good_count + inp.good_packet as u32,
        total_tx_count: prev.total_tx_count,
        total_rx_count: prev.total_rx_count,
    }
}

#[cfg(test)]
mod tests;
