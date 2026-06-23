//! NTP request transmission — `ntp_core.c` Stage 17 (`transmit_packet`, client path).
//!
//! [`build_client_request`] ports the client-request half of chrony's `transmit_packet`:
//! it lays out the 48-byte NTP header a client sends to a server. A client deliberately
//! reveals nothing about its own clock — the leap/stratum/precision/reference fields and
//! the originate/receive timestamps are all blanked — so the only live field is the
//! transmit timestamp (read from the local clock).
//!
//! # Scope and adaptations (documented, not silent)
//!
//! * **Client mode only.** The server / symmetric-active branches of `transmit_packet`
//!   (reference parameters, smoothing, the interleaved originate/receive timestamps, the
//!   server RX-flag bits) are a later stage.
//! * **The transmit timestamp's anti-replay fuzz** (`UTI_GetNtp64Fuzz`) is host-boundary
//!   randomness; the unfuzzed timestamp is produced. chrony's retry loop (which redraws
//!   the fuzz until the timestamp differs from the receive/originate/previous-transmit
//!   timestamps) therefore runs once here.
//! * **Authentication and the actual send** (`NAU_GenerateRequestAuth`, `NIO_SendPacket`)
//!   are host boundaries; this returns the header bytes the caller authenticates + sends.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness: `transmit_packet` is driven in client mode and the packet captured by the
//! `NIO_SendPacket` stub (`research/oracle/ntp_core-transmit-c-vectors.txt`). See the
//! tests.

use crate::ntp::exp_ef::timespec_to_ntp64;
use crate::sys_generic::Timespec;

/// chrony `NTP_VERSION` and `MODE_CLIENT`, and the header length.
const NTP_VERSION: i32 = 4;
const MODE_CLIENT: i32 = 3;
const NTP_HEADER_LENGTH: usize = 48;
/// A client request reveals no clock state: chrony sets `precision = 32`.
const CLIENT_PRECISION: i8 = 32;
/// chrony `MODE_SERVER`, `NTP_MAX_STRATUM`, `NTP_INVALID_STRATUM`.
const MODE_SERVER: i32 = 4;
const NTP_MAX_STRATUM: i32 = 16;
const NTP_INVALID_STRATUM: u8 = 0;

/// chrony `UTI_DoubleToNtp32`: seconds to the 16.16 NTP-short fixed point (host order).
fn double_to_ntp32(x: f64) -> u32 {
    const MAX_NTP_INT32: f64 = 4_294_967_295.0 / 65536.0;
    if x >= MAX_NTP_INT32 {
        0xffff_ffff
    } else if x <= 0.0 {
        0
    } else {
        let xs = x * 65536.0;
        let mut r = xs as u32;
        if (r as f64) < xs {
            r += 1;
        }
        r
    }
}

/// chrony `NTP_LVM`: pack leap/version/mode into the first header byte.
fn ntp_lvm(leap: u8, version: i32, mode: i32) -> u8 {
    ((leap << 6) & 0xc0) | (((version as u8) << 3) & 0x38) | ((mode as u8) & 0x07)
}

/// A built client request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRequest {
    /// The 48-byte NTP header.
    pub packet: [u8; NTP_HEADER_LENGTH],
    pub length: i32,
    /// The transmit timestamp placed in the packet (chrony's output `local_ntp_tx`).
    pub local_ntp_tx: u64,
    /// The receive timestamp (always zero in a client request — output `local_ntp_rx`).
    pub local_ntp_rx: u64,
    /// The saved local transmit time (chrony's `local_tx.ts`, source `NTP_TS_DAEMON`).
    pub local_tx: Timespec,
}

/// chrony `transmit_packet` for a client request. `local_transmit` is the local time the
/// packet is timestamped with; `prev_local_ntp_tx` is the previous transmit timestamp
/// (used by chrony's anti-replay retry — see the module docs). `version` is capped to
/// `NTP_VERSION`.
pub fn build_client_request(
    my_poll: i32,
    version: i32,
    local_transmit: Timespec,
    prev_local_ntp_tx: u64,
) -> ClientRequest {
    let version = version.min(NTP_VERSION);

    let mut packet = [0u8; NTP_HEADER_LENGTH];
    packet[0] = ntp_lvm(0, version, MODE_CLIENT);
    // stratum (1), root_delay/dispersion, reference_id, reference/originate/receive
    // timestamps all stay zero for a client request.
    packet[2] = my_poll as u8;
    packet[3] = CLIENT_PRECISION as u8;

    // Transmit timestamp (the only live field). The anti-replay fuzz is host-boundary;
    // with it zeroed the value is the plain conversion (one retry-loop iteration).
    let (hi, lo) = timespec_to_ntp64(local_transmit);
    let transmit_ts = ((hi as u64) << 32) | lo as u64;
    let _ = prev_local_ntp_tx; // only consulted by the (host-RNG) retry loop
    packet[40..44].copy_from_slice(&hi.to_be_bytes());
    packet[44..48].copy_from_slice(&lo.to_be_bytes());

    ClientRequest {
        packet,
        length: NTP_HEADER_LENGTH as i32,
        local_ntp_tx: transmit_ts,
        local_ntp_rx: 0,
        local_tx: local_transmit,
    }
}

/// Our reference parameters for a server response (chrony's `REF_GetReferenceParams`
/// outputs), supplied by the caller (a host boundary).
#[derive(Clone, Copy, Debug)]
pub struct ReferenceParams {
    pub leap: u8,
    pub stratum: i32,
    pub ref_id: u32,
    pub ref_time: Timespec,
    pub root_delay: f64,
    pub root_dispersion: f64,
}

/// A built server response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerResponse {
    pub packet: [u8; NTP_HEADER_LENGTH],
    pub length: i32,
}

/// chrony `transmit_packet` for a basic (non-interleaved) server response to a client
/// request. The response carries our reference state (`params`), echoes the client's
/// transmit timestamp as the originate timestamp (`request_transmit_ts`, the packed
/// NTP64 of the request), and stamps the receive (`local_receive`) and transmit
/// (`cooked_transmit`, read just before sending) times. As a server it encodes the
/// interleaved-mode RX flag: the receive timestamp's low bit is set and the transmit
/// timestamp's cleared.
///
/// Scope/adaptation: non-interleaved server mode; smoothing, the anti-replay fuzz, auth,
/// and the send are host boundaries (see [`build_client_request`]). `version` is capped.
#[allow(clippy::too_many_arguments)]
pub fn build_server_response(
    my_poll: i32,
    version: i32,
    params: &ReferenceParams,
    request_transmit_ts: u64,
    local_receive: Timespec,
    cooked_transmit: Timespec,
    precision_log: i8,
) -> ServerResponse {
    let version = version.min(NTP_VERSION);

    let mut packet = [0u8; NTP_HEADER_LENGTH];
    packet[0] = ntp_lvm(params.leap, version, MODE_SERVER);
    packet[1] = if params.stratum < NTP_MAX_STRATUM { params.stratum as u8 } else { NTP_INVALID_STRATUM };
    packet[2] = my_poll as u8;
    packet[3] = precision_log as u8;
    packet[4..8].copy_from_slice(&double_to_ntp32(params.root_delay).to_be_bytes());
    packet[8..12].copy_from_slice(&double_to_ntp32(params.root_dispersion).to_be_bytes());
    packet[12..16].copy_from_slice(&params.ref_id.to_be_bytes());

    let (rhi, rlo) = timespec_to_ntp64(params.ref_time);
    packet[16..20].copy_from_slice(&rhi.to_be_bytes());
    packet[20..24].copy_from_slice(&rlo.to_be_bytes());

    // Originate = the client's transmit timestamp, echoed verbatim.
    packet[24..28].copy_from_slice(&((request_transmit_ts >> 32) as u32).to_be_bytes());
    packet[28..32].copy_from_slice(&(request_transmit_ts as u32).to_be_bytes());

    // Receive (RX flag bit set) and transmit (RX flag bit cleared). The fuzz is zero.
    let (rxhi, rxlo) = timespec_to_ntp64(local_receive);
    packet[32..36].copy_from_slice(&rxhi.to_be_bytes());
    packet[36..40].copy_from_slice(&(rxlo | 1).to_be_bytes());
    let (txhi, txlo) = timespec_to_ntp64(cooked_transmit);
    packet[40..44].copy_from_slice(&txhi.to_be_bytes());
    packet[44..48].copy_from_slice(&(txlo & !1).to_be_bytes());

    ServerResponse { packet, length: NTP_HEADER_LENGTH as i32 }
}

#[cfg(test)]
mod tests;
