//! PTP-over-NTP transport framing — a port of `wrap_message` / `NIO_UnwrapMessage`'s PTP
//! path from chrony 4.5 `ntp_io.c` (with the `ptp.h` message format).
//!
//! chrony can send/receive NTP messages wrapped in a PTP (IEEE 1588) `Delay_Req` frame so
//! they traverse PTP transparent clocks, which stamp their residence time into the PTP
//! *correction* field — letting chrony subtract switch delays. Each wrapped message is a
//! 48-byte PTP prefix (PTP header + origin timestamp + a TLV header) followed by the NTP
//! message:
//!
//! ```text
//! [ PTP_Header (34) | origin_ts (10) | PTP_TlvHeader (4) ] [ NTP message … ]
//! ```
//!
//! This is pure byte framing of untrusted input; the socket I/O and the `is_ptp_socket`
//! decision are the host boundary. Composes the ported [`crate::util::integer64_network_to_host`].

use crate::ntp::ext::{NTP_HEADER_LENGTH, NTP_PACKET_SIZE};
use crate::util::integer64_network_to_host;

/// `PTP_VERSION`.
pub const PTP_VERSION: u8 = 2;
/// `PTP_TYPE_DELAY_REQ`.
pub const PTP_TYPE_DELAY_REQ: u8 = 1;
/// `PTP_DOMAIN_NTP`.
pub const PTP_DOMAIN_NTP: u8 = 123;
/// `PTP_FLAG_UNICAST` = `1 << (2 + 8)`.
pub const PTP_FLAG_UNICAST: u16 = 1 << 10;
/// `PTP_TLV_NTP`.
pub const PTP_TLV_NTP: u16 = 0x2023;
/// `PTP_NTP_PREFIX_LENGTH` = `offsetof(PTP_NtpMessage, ntp_msg)`.
pub const PTP_NTP_PREFIX_LENGTH: usize = 48;
/// `sizeof(PTP_NtpMessage)` = prefix + a full `NTP_Packet`.
pub const PTP_MAX_MESSAGE: usize = PTP_NTP_PREFIX_LENGTH + NTP_PACKET_SIZE as usize;

/// chrony `wrap_message` (PTP path): wrap `ntp_msg` in a PTP `Delay_Req` frame stamped with
/// `sequence_id`. Returns the wrapped bytes, or `None` if the NTP message is shorter than an
/// NTP header or would overflow the PTP message buffer.
pub fn wrap_message(ntp_msg: &[u8], sequence_id: u16) -> Option<Vec<u8>> {
    let length = ntp_msg.len();
    if length < NTP_HEADER_LENGTH as usize || length + PTP_NTP_PREFIX_LENGTH > PTP_MAX_MESSAGE {
        return None;
    }

    let mut out = vec![0u8; PTP_NTP_PREFIX_LENGTH + length];
    out[0] = PTP_TYPE_DELAY_REQ;
    out[1] = PTP_VERSION;
    out[2..4].copy_from_slice(&((PTP_NTP_PREFIX_LENGTH + length) as u16).to_be_bytes());
    out[4] = PTP_DOMAIN_NTP;
    out[6..8].copy_from_slice(&PTP_FLAG_UNICAST.to_be_bytes());
    out[30..32].copy_from_slice(&sequence_id.to_be_bytes());
    out[44..46].copy_from_slice(&PTP_TLV_NTP.to_be_bytes());
    out[46..48].copy_from_slice(&(length as u16).to_be_bytes());
    out[PTP_NTP_PREFIX_LENGTH..].copy_from_slice(ntp_msg);
    Some(out)
}

/// chrony `NIO_UnwrapMessage`'s PTP path: validate the PTP prefix on `msg`, strip it, and
/// return the NTP payload plus the PTP correction in seconds (from the transparent-clock
/// residence time in the correction field). Returns `None` on a malformed PTP message.
///
/// The caller adds the correction to the network correction only when an RX duration is
/// already known (a hardware timestamp), which chrony expresses as `net_correction > 0`.
pub fn unwrap_message(msg: &[u8]) -> Option<(Vec<u8>, f64)> {
    let length = msg.len();
    if length <= PTP_NTP_PREFIX_LENGTH {
        return None;
    }

    let be16 = |i: usize| u16::from_be_bytes([msg[i], msg[i + 1]]);
    if msg[0] != PTP_TYPE_DELAY_REQ
        || msg[1] != PTP_VERSION
        || be16(2) as usize != length
        || msg[4] != PTP_DOMAIN_NTP
        || be16(6) != PTP_FLAG_UNICAST
        || be16(44) != PTP_TLV_NTP
        || be16(46) as usize != length - PTP_NTP_PREFIX_LENGTH
    {
        return None;
    }

    let ntp = msg[PTP_NTP_PREFIX_LENGTH..].to_vec();

    // The 8-byte correction field is an Integer64 (ns << 16) in network order.
    let high = u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]);
    let low = u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]);
    let ptp_correction =
        integer64_network_to_host(high, low) as f64 / ((1u64 << 16) as f64 * 1.0e9);

    Some((ntp, ptp_correction))
}

/// `NIO_IsHwTsEnabled`: whether hardware timestamping is enabled for NTP
/// sockets. On non-Linux platforms this always returns false; on Linux it
/// checks whether a HW timestamping interface has been configured.
pub fn nio_is_hw_ts_enabled(hwts_interface: Option<&str>) -> bool {
    hwts_interface.is_some()
}

#[cfg(test)]
mod tests;
