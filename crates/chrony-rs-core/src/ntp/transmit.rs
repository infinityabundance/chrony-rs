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
//! * **The transmit timestamp's anti-replay fuzz** draws its randomness from the host
//!   CSPRNG (a boundary), but its *deterministic* placement — which sub-precision bits get
//!   randomized — is the ported [`crate::util::get_ntp64_fuzz`] (differential-tested vs the
//!   real `UTI_GetNtp64Fuzz`). Here the unfuzzed timestamp is produced; chrony's retry loop
//!   (which redraws the fuzz until the timestamp differs from the
//!   receive/originate/previous-transmit timestamps) therefore runs once.
//! * **Authentication and the actual send** (`NAU_GenerateRequestAuth`, `NIO_SendPacket`)
//!   are host boundaries; this returns the header bytes the caller authenticates + sends.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness: `transmit_packet` is driven in client mode and the packet captured by the
//! `NIO_SendPacket` stub (`research/oracle/ntp_core-transmit-c-vectors.txt`). See the
//! tests.

use crate::md5::Md5;
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
/// chrony `MODE_ACTIVE` / `MODE_PASSIVE` (symmetric peer modes).
const MODE_ACTIVE: i32 = 1;
const MODE_PASSIVE: i32 = 2;
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
    /// The NTP header, possibly followed by a MAC.
    pub packet: Vec<u8>,
    pub length: i32,
    /// The transmit timestamp placed in the packet (chrony's output `local_ntp_tx`).
    pub local_ntp_tx: u64,
    /// The receive timestamp (always zero in a client request — output `local_ntp_rx`).
    pub local_ntp_rx: u64,
    /// The saved local transmit time (chrony's `local_tx.ts`, source `NTP_TS_DAEMON`).
    pub local_tx: Timespec,
}

/// chrony `transmit_packet` for a client request. `event_time` is the scheduler event
/// time stamped into the packet's transmit field; `cooked_transmit` is the more accurate
/// reading taken just before sending and *saved* as the instance's `local_tx` (these
/// differ — chrony reads a fresh cooked time at the tail of `transmit_packet`).
/// `prev_local_ntp_tx` is the previous transmit timestamp (used by chrony's anti-replay
/// retry — see the module docs). `version` is capped to `NTP_VERSION`.
/// `auth_key` provides optional symmetric-key authentication: `(key_id, key_material)`.
/// When present, a MAC (key_id + MD5 digest) is appended to the packet.
/// `auth_delay` adjusts the saved transmit time for the MAC computation delay.
pub fn build_client_request(
    my_poll: i32,
    version: i32,
    event_time: Timespec,
    cooked_transmit: Timespec,
    prev_local_ntp_tx: u64,
    auth_key: Option<(u32, &[u8])>,
    auth_delay: f64,
) -> ClientRequest {
    let local_transmit = event_time;
    let version = version.min(NTP_VERSION);

    let mut packet = vec![0u8; NTP_HEADER_LENGTH];
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

    let mut length = NTP_HEADER_LENGTH as i32;

    // Symmetric-key MAC
    let local_tx = if let Some((key_id, key)) = auth_key {
        // The NTP symmetric MAC is MD5(key || packet_header).
        // Wire format: [48-byte header][key_id: 4 bytes BE][MD5 digest: 16 bytes]
        let mut mac = Md5::new();
        mac.update(key);
        mac.update(&packet);
        let digest = mac.finalize();

        packet.extend_from_slice(&key_id.to_be_bytes());
        packet.extend_from_slice(&digest);
        length += 20; // 4 + 16

        // Adjust the saved transmit time for the MAC computation delay.
        cooked_transmit.add_double(auth_delay)
    } else {
        cooked_transmit
    };

    ClientRequest {
        packet,
        length,
        local_ntp_tx: transmit_ts,
        local_ntp_rx: 0,
        // The saved transmit timestamp is the cooked reading taken just before sending,
        // not the event time stamped into the packet.
        local_tx,
    }
}

/// chrony `transmit_packet` for an **interleaved** client request. Unlike the basic
/// request, an interleaved one reveals timestamps so the server can match the exchange:
/// the originate timestamp echoes the server's last receive timestamp (`remote_ntp_rx`),
/// the receive timestamp is our last receive (`local_receive`), and the transmit
/// timestamp is the *previously sent* transmit time (`prev_local_tx`, the saved HW
/// timestamp) rather than a fresh reading. (Client mode: no server RX-flag bits; the fuzz
/// is host-boundary.)
pub fn build_interleaved_client_request(
    my_poll: i32,
    version: i32,
    remote_ntp_rx: u64,
    local_receive: Timespec,
    prev_local_tx: Timespec,
) -> [u8; NTP_HEADER_LENGTH] {
    let version = version.min(NTP_VERSION);
    let mut packet = [0u8; NTP_HEADER_LENGTH];
    packet[0] = ntp_lvm(0, version, MODE_CLIENT);
    packet[2] = my_poll as u8;
    packet[3] = CLIENT_PRECISION as u8;

    // Originate = the server's last receive timestamp, echoed.
    packet[24..28].copy_from_slice(&((remote_ntp_rx >> 32) as u32).to_be_bytes());
    packet[28..32].copy_from_slice(&(remote_ntp_rx as u32).to_be_bytes());
    let (rxhi, rxlo) = timespec_to_ntp64(local_receive);
    packet[32..36].copy_from_slice(&rxhi.to_be_bytes());
    packet[36..40].copy_from_slice(&rxlo.to_be_bytes());
    let (txhi, txlo) = timespec_to_ntp64(prev_local_tx);
    packet[40..44].copy_from_slice(&txhi.to_be_bytes());
    packet[44..48].copy_from_slice(&txlo.to_be_bytes());
    packet
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
    /// Client's transmit timestamp to echo in the originate field (NTP wire format u64).
    pub origin_ts: u64,
    /// Our receive timestamp (NTP wire format u64).
    pub rx_ts: u64,
    /// Our transmit timestamp (NTP wire format u64).
    pub tx_ts: u64,
}

/// Convert an NTP-format u64 timestamp to a `Timespec`.
pub fn ntp64_to_timespec(ntp: u64) -> Timespec {
    const JAN_1970: u64 = 2_208_988_800;
    let secs = (ntp >> 32) as u64;
    let frac = ntp as u32;
    let nsec = ((frac as u64) * 1_000_000_000 >> 32) as i64;
    let tv_sec = if secs >= JAN_1970 {
        (secs - JAN_1970) as i64
    } else {
        0
    };
    Timespec::new(tv_sec, nsec)
}

/// A built server response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerResponse {
    pub packet: [u8; NTP_HEADER_LENGTH],
    pub length: i32,
}

/// Amplification attack mitigation: check that the response packet length does not
/// exceed the request packet length by more than a safe margin. If the response would
/// be disproportionately large, truncate it. Returns `true` if the response is safe,
/// `false` if truncated.
pub fn check_amplification_margin(request_len: usize, response_len: usize) -> bool {
    if response_len > request_len * 2 && response_len > 128 {
        eprintln!("ntp: amplification attack mitigation — truncating oversized response (req={request_len} resp={response_len})");
        return false;
    }
    true
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
    packet[1] = if params.stratum < NTP_MAX_STRATUM {
        params.stratum as u8
    } else {
        NTP_INVALID_STRATUM
    };
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

    ServerResponse {
        packet,
        length: NTP_HEADER_LENGTH as i32,
    }
}

/// chrony `transmit_packet` for a basic (non-interleaved) **symmetric** (peer) packet,
/// `MODE_ACTIVE` or `MODE_PASSIVE`. Like a server response it reveals our reference state
/// (`params`); the originate timestamp is the peer's last *transmit* timestamp
/// (`remote_ntp_tx`, echoed so the packet is not its own valid response), the receive
/// timestamp is `local_receive` and the transmit timestamp is `cooked_transmit` (read
/// just before sending).
///
/// The interleaved-mode RX flag (receive low bit set, transmit low bit cleared) is encoded
/// only in `MODE_PASSIVE` — exactly as chrony applies it to `MODE_SERVER || MODE_PASSIVE`
/// but not to `MODE_ACTIVE`.
///
/// Scope/adaptation: non-interleaved symmetric mode; the anti-replay fuzz, auth, and send
/// are host boundaries (see [`build_client_request`]). `version` is capped. `my_mode` must
/// be [`MODE_ACTIVE`] or [`MODE_PASSIVE`].
#[allow(clippy::too_many_arguments)]
pub fn build_symmetric_packet(
    my_mode: i32,
    my_poll: i32,
    version: i32,
    params: &ReferenceParams,
    remote_ntp_tx: u64,
    local_receive: Timespec,
    cooked_transmit: Timespec,
    precision_log: i8,
) -> ServerResponse {
    debug_assert!(my_mode == MODE_ACTIVE || my_mode == MODE_PASSIVE);
    let version = version.min(NTP_VERSION);

    let mut packet = [0u8; NTP_HEADER_LENGTH];
    packet[0] = ntp_lvm(params.leap, version, my_mode);
    packet[1] = if params.stratum < NTP_MAX_STRATUM {
        params.stratum as u8
    } else {
        NTP_INVALID_STRATUM
    };
    packet[2] = my_poll as u8;
    packet[3] = precision_log as u8;
    packet[4..8].copy_from_slice(&double_to_ntp32(params.root_delay).to_be_bytes());
    packet[8..12].copy_from_slice(&double_to_ntp32(params.root_dispersion).to_be_bytes());
    packet[12..16].copy_from_slice(&params.ref_id.to_be_bytes());

    let (rhi, rlo) = timespec_to_ntp64(params.ref_time);
    packet[16..20].copy_from_slice(&rhi.to_be_bytes());
    packet[20..24].copy_from_slice(&rlo.to_be_bytes());

    // Originate = the peer's last transmit timestamp, echoed verbatim.
    packet[24..28].copy_from_slice(&((remote_ntp_tx >> 32) as u32).to_be_bytes());
    packet[28..32].copy_from_slice(&(remote_ntp_tx as u32).to_be_bytes());

    // Receive / transmit timestamps (fuzz zero). The RX flag is encoded only for PASSIVE.
    let (rxhi, rxlo) = timespec_to_ntp64(local_receive);
    let (txhi, txlo) = timespec_to_ntp64(cooked_transmit);
    let (rxlo, txlo) = if my_mode == MODE_PASSIVE {
        (rxlo | 1, txlo & !1)
    } else {
        (rxlo, txlo)
    };
    packet[32..36].copy_from_slice(&rxhi.to_be_bytes());
    packet[36..40].copy_from_slice(&rxlo.to_be_bytes());
    packet[40..44].copy_from_slice(&txhi.to_be_bytes());
    packet[44..48].copy_from_slice(&txlo.to_be_bytes());

    ServerResponse {
        packet,
        length: NTP_HEADER_LENGTH as i32,
    }
}

/// Build a broadcast (mode 5) NTP server packet.
/// Broadcast packets are sent periodically by a server to advertise its time
/// to all clients on the local network. They carry full server reference
/// parameters and a transmit timestamp but zero originate/receive timestamps.
pub fn build_broadcast_packet(
    params: &ReferenceParams,
    my_poll: i32,
    precision_log: i8,
    transmit_time: Timespec,
) -> ServerResponse {
    let mut packet = [0u8; NTP_HEADER_LENGTH];
    packet[0] = ntp_lvm(params.leap, NTP_VERSION, 5);
    packet[1] = if params.stratum < NTP_MAX_STRATUM {
        params.stratum as u8
    } else {
        NTP_INVALID_STRATUM
    };
    packet[2] = my_poll as u8;
    packet[3] = precision_log as u8;
    packet[4..8].copy_from_slice(&double_to_ntp32(params.root_delay).to_be_bytes());
    packet[8..12].copy_from_slice(&double_to_ntp32(params.root_dispersion).to_be_bytes());
    packet[12..16].copy_from_slice(&params.ref_id.to_be_bytes());
    // Reference timestamp
    let (rthi, rtlo) = timespec_to_ntp64(params.ref_time);
    packet[16..20].copy_from_slice(&rthi.to_be_bytes());
    packet[20..24].copy_from_slice(&rtlo.to_be_bytes());
    // Originate and receive timestamps are zero in broadcast (RFC 5905 §3)
    // Transmit timestamp
    let (txhi, txlo) = timespec_to_ntp64(transmit_time);
    packet[40..44].copy_from_slice(&txhi.to_be_bytes());
    packet[44..48].copy_from_slice(&txlo.to_be_bytes());

    ServerResponse {
        packet,
        length: NTP_HEADER_LENGTH as i32,
    }
}

/// Build a manycast client solicitation (mode 3 to multicast address 224.0.1.1).
/// Manycast clients send these to discover nearby NTP servers that respond
/// with a standard server (mode 4) reply. The response allows the client to
/// select the best server from all respondents.
pub fn build_manycast_solicitation(transmit_time: Timespec) -> [u8; 48] {
    let mut pkt = [0u8; 48];
    pkt[0] = (0 << 6) | (4 << 3) | 3; // LI=0, VN=4, Mode=3 (client)
    pkt[2] = 6; // default poll
    pkt[3] = 32; // default precision
    let (hi, lo) = timespec_to_ntp64(transmit_time);
    pkt[40..44].copy_from_slice(&hi.to_be_bytes());
    pkt[44..48].copy_from_slice(&lo.to_be_bytes());
    pkt
}

#[cfg(test)]
mod tests;
