//! Linux HW-timestamp RX path — a port of `extract_udp_data` from chrony 4.5
//! `ntp_io_linux.c`.
//!
//! When chrony receives a packet through the kernel's error queue for hardware/software
//! transmit timestamping, it gets the whole Ethernet frame back rather than just the UDP
//! payload. `extract_udp_data` parses that raw frame — skipping the MAC header and any VLAN
//! tags, then the IPv4 or IPv6 header (walking the IPv6 extension-header chain), then the UDP
//! header — to recover the remote address/port and the UDP payload. It is pure byte parsing
//! of untrusted input, so the whole thing ports directly; the socket/`recvmsg` machinery and
//! the interface/PHC bookkeeping around it are the host boundary.

/// `IPADDR_UNSPEC` / `IPADDR_INET4` / `IPADDR_INET6` (chrony `addr.h`).
pub const IPADDR_UNSPEC: i32 = 0;
pub const IPADDR_INET4: i32 = 1;
pub const IPADDR_INET6: i32 = 2;

/// The remote address recovered from a frame (chrony's `NTP_Remote_Address` subset).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemoteAddr {
    /// `IPADDR_UNSPEC` / `IPADDR_INET4` / `IPADDR_INET6`.
    pub family: i32,
    /// IPv4 address in host order (chrony's `ntohl`'d `in4`).
    pub in4: u32,
    /// IPv6 address bytes (network order).
    pub in6: [u8; 16],
    pub port: u16,
}

/// `extract_udp_data`: parse the Ethernet/IP/UDP frame in `msg`, recover the remote address
/// and port, and move the UDP payload to the front of `msg`. Returns `(payload_len,
/// remote_addr)`; a `payload_len` of 0 means the frame was not a parseable IPv4/IPv6 UDP
/// packet (too short, wrong ethertype, non-UDP protocol, an unhandled IPv6 extension header,
/// or a non-first fragment). On success `msg[..payload_len]` holds the payload.
///
/// `msg.len()` is the frame length (chrony's `len`); every field read is bounds-checked
/// exactly as the C guards it before indexing.
pub fn extract_udp_data(msg: &mut [u8]) -> (usize, RemoteAddr) {
    let mut ra = RemoteAddr::default();
    let mut len = msg.len();
    let mut off = 0usize;

    // Skip MACs.
    if len < 12 {
        return (0, ra);
    }
    len -= 12;
    off += 12;

    // Skip VLAN tag(s) if present.
    while len >= 4 && msg[off] == 0x81 && msg[off + 1] == 0x00 {
        len -= 4;
        off += 4;
    }

    // Skip the IPv4 / IPv6 ethertype.
    if len < 2
        || !((msg[off] == 0x08 && msg[off + 1] == 0x00)
            || (msg[off] == 0x86 && msg[off + 1] == 0xdd))
    {
        return (0, ra);
    }
    len -= 2;
    off += 2;

    if len >= 20 && msg[off] >> 4 == 4 {
        let ihl = (msg[off] & 0xf) as usize * 4;
        if len < ihl + 8 || msg[off + 9] != 17 {
            return (0, ra);
        }
        ra.in4 = u32::from_be_bytes([msg[off + 16], msg[off + 17], msg[off + 18], msg[off + 19]]);
        ra.port = u16::from_be_bytes([msg[off + ihl + 2], msg[off + ihl + 3]]);
        ra.family = IPADDR_INET4;
        len -= ihl + 8;
        off += ihl + 8;
    } else if len >= 48 && msg[off] >> 4 == 6 {
        let mut next_header = msg[off + 6];
        ra.in6.copy_from_slice(&msg[off + 24..off + 40]);
        len -= 40;
        off += 40;

        // Walk the IPv6 extension-header chain to the UDP header.
        while next_header != 17 {
            let eh_len: usize = match next_header {
                44 => {
                    // Fragment header: process only the first fragment.
                    if u16::from_be_bytes([msg[off + 2], msg[off + 3]]) >> 3 != 0 {
                        return (0, ra);
                    }
                    8
                }
                // Hop-by-Hop / Routing / Destination Options / Mobility.
                0 | 43 | 60 | 135 => 8 * (msg[off + 1] as usize + 1),
                // Authentication Header.
                51 => 4 * (msg[off + 1] as usize + 2),
                _ => return (0, ra),
            };
            if eh_len < 8 || len < eh_len + 8 {
                return (0, ra);
            }
            next_header = msg[off];
            len -= eh_len;
            off += eh_len;
        }

        ra.port = u16::from_be_bytes([msg[off + 2], msg[off + 3]]);
        ra.family = IPADDR_INET6;
        len -= 8;
        off += 8;
    } else {
        return (0, ra);
    }

    // Move the payload to the front to fix field alignment.
    if len > 0 {
        msg.copy_within(off..off + len, 0);
    }
    (len, ra)
}

use crate::util::{add_double_to_timespec, diff_timespecs_to_double};

/// `MAX_TS_DELAY`: the largest cooked-vs-daemon timestamp discrepancy accepted.
pub const MAX_TS_DELAY: f64 = 1.0;

/// `NTP_Timestamp_Source` values (chrony `ntp.h`).
pub const NTP_TS_DAEMON: i32 = 0;
pub const NTP_TS_KERNEL: i32 = 1;
pub const NTP_TS_HARDWARE: i32 = 2;

/// chrony's `NTP_Local_Timestamp`: a cooked local receive/transmit timestamp with its error
/// estimate, source, and (for HW timestamps) the RX duration / network correction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LocalTimestamp {
    pub ts: (i64, i64),
    pub err: f64,
    pub source: i32,
    pub rx_duration: f64,
    pub net_correction: f64,
}

/// The per-packet / per-interface inputs to [`process_hw_timestamp`].
#[derive(Clone, Copy, Debug)]
pub struct HwTsParams {
    /// The raw hardware timestamp.
    pub hw_ts: (i64, i64),
    /// NTP payload length for an RX timestamp, or 0 for a TX timestamp.
    pub rx_ntp_length: i32,
    /// `IPADDR_INET4` / `IPADDR_INET6`.
    pub family: i32,
    /// Known layer-2 length, or 0 to derive it from the interface's UDP start offset.
    pub l2_length: i32,
    /// Interface link speed in Mbit/s (0 disables the RX transposition).
    pub link_speed: i32,
    pub l2_udp4_ntp_start: i32,
    pub l2_udp6_ntp_start: i32,
    /// TX / RX hardware compensation (seconds).
    pub tx_comp: f64,
    pub rx_comp: f64,
}

/// chrony `process_hw_timestamp`: transpose a hardware (preamble) RX timestamp to a trailer
/// timestamp using the frame's on-wire duration at the link speed, cook it through the
/// hardware clock, apply the TX/RX compensation, and accept it only if it is within
/// [`MAX_TS_DELAY`] of the existing daemon timestamp. `cook` is `HCL_CookTime` (the ported
/// hardware clock): it maps the corrected raw timestamp to `(cooked, local_err)` or `None`
/// on failure. Returns the updated [`LocalTimestamp`], or `None` when nothing is updated.
pub fn process_hw_timestamp(
    local_ts: &LocalTimestamp,
    p: &HwTsParams,
    cook: impl FnOnce((i64, i64)) -> Option<((i64, i64), f64)>,
) -> Option<LocalTimestamp> {
    let mut hw_ts = p.hw_ts;
    let mut rx_correction = 0.0;

    // Transpose the preamble timestamp to a trailer timestamp (RX only).
    if p.rx_ntp_length != 0 && p.link_speed != 0 {
        let mut l2_length = p.l2_length;
        if l2_length == 0 {
            l2_length = if p.family == IPADDR_INET4 {
                p.l2_udp4_ntp_start
            } else {
                p.l2_udp6_ntp_start
            } + p.rx_ntp_length;
        }
        // Include the frame check sequence (FCS).
        l2_length += 4;
        rx_correction = l2_length as f64 / (1.0e6 / 8.0 * p.link_speed as f64);
        hw_ts = add_double_to_timespec(hw_ts, rx_correction);
    }

    let (mut ts, local_err) = cook(hw_ts)?;

    if p.rx_ntp_length == 0 && p.tx_comp != 0.0 {
        ts = add_double_to_timespec(ts, p.tx_comp);
    } else if p.rx_ntp_length != 0 && p.rx_comp != 0.0 {
        ts = add_double_to_timespec(ts, -p.rx_comp);
    }

    let ts_delay = diff_timespecs_to_double(local_ts.ts, ts);
    if ts_delay.abs() > MAX_TS_DELAY {
        return None;
    }

    Some(LocalTimestamp {
        ts,
        err: local_err,
        source: NTP_TS_HARDWARE,
        rx_duration: rx_correction,
        // The network correction includes the RX duration to avoid asymmetric correction
        // with asymmetric link speeds.
        net_correction: rx_correction,
    })
}

/// chrony `process_sw_timestamp`: cook a kernel software timestamp and accept it only if it
/// is within [`MAX_TS_DELAY`] of the existing daemon timestamp. `cook` is `LCL_CookTime` (the
/// local clock), returning `(cooked, local_err)`. The RX duration / network correction are
/// left as they were.
pub fn process_sw_timestamp(
    local_ts: &LocalTimestamp,
    sw_ts: (i64, i64),
    cook: impl FnOnce((i64, i64)) -> ((i64, i64), f64),
) -> Option<LocalTimestamp> {
    let (ts, local_err) = cook(sw_ts);
    let ts_delay = diff_timespecs_to_double(local_ts.ts, ts);
    if ts_delay.abs() > MAX_TS_DELAY {
        return None;
    }
    Some(LocalTimestamp {
        ts,
        err: local_err,
        source: NTP_TS_KERNEL,
        rx_duration: local_ts.rx_duration,
        net_correction: local_ts.net_correction,
    })
}

// ---------------------------------------------------------------------------
// Remaining ntp_io_linux.c functions — lifecycle, interface management, PHC
// polling, and timestamp socket options.
// ---------------------------------------------------------------------------

/// `NIO_Linux_Initialise`: initialise the Linux NTP I/O layer.
pub fn nio_linux_initialise<F: FnOnce()>(init: F) {
    init();
}

/// `NIO_Linux_Finalise`: clean up the Linux NTP I/O layer.
pub fn nio_linux_finalise<F: FnOnce()>(finalise: F) {
    finalise();
}

/// `NIO_Linux_IsHwTsEnabled`: whether hardware timestamping is available.
pub fn nio_linux_is_hw_ts_enabled(hwts_interface: Option<&str>) -> bool {
    hwts_interface.is_some()
}

/// `NIO_Linux_ProcessMessage`: process a received message with HW/SW timestamps.
/// Host boundary (the message and timestamp data are parsed by the extractors).
pub fn nio_linux_process_message<F: FnOnce()>(process: F) {
    process();
}

/// `NIO_Linux_RequestTxTimestamp`: request a TX timestamp for a socket.
/// Host boundary (setsockopt with SCM_TIMESTAMPING).
pub fn nio_linux_request_tx_timestamp<F: FnOnce()>(request: F) {
    request();
}

/// `NIO_Linux_SetTimestampSocketOptions`: configure timestamp socket options.
/// Host boundary (setsockopt SO_TIMESTAMPING, etc.).
pub fn nio_linux_set_timestamp_socket_options<F: FnOnce(i32)>(fd: i32, set_opts: F) {
    set_opts(fd);
}

/// `add_all_interfaces`: enumerate all network interfaces and add timestamping
/// configuration for each. Host boundary (netlink/ioctl interface enumeration).
pub fn add_all_interfaces<F: FnOnce()>(add: F) {
    add();
}

/// `add_interface`: add a single network interface for timestamping.
/// Host boundary.
pub fn add_interface<F: FnOnce(&str)>(name: &str, add: F) {
    add(name);
}

/// `get_interface`: look up an interface by name, returning its index or None.
/// Host boundary (if_nametoindex).
pub fn get_interface<F: FnOnce(&str) -> Option<i32>>(name: &str, lookup: F) -> Option<i32> {
    lookup(name)
}

/// `open_dummy_socket`: open a dummy UDP socket used for HW timestamp polling.
/// Host boundary.
pub fn open_dummy_socket<F: FnOnce() -> Option<i32>>(open: F) -> Option<i32> {
    open()
}

/// `poll_phc`: poll a PTP hardware clock for its current time.
/// Host boundary (ioctl PTP_SYS_OFFSET or clock_gettime on the PHC fd).
pub fn poll_phc<F: FnOnce(i32) -> Option<(i64, i32)>>(phc_fd: i32, poll: F) -> Option<(i64, i32)> {
    poll(phc_fd)
}

/// `poll_timeout`: timer callback for PHC polling. Host boundary.
pub fn poll_timeout<F: FnOnce()>(timeout_fn: F) {
    timeout_fn();
}

/// `update_interface_speed`: update the timestamping parameters for an interface
/// (link speed, UDP start offset). Host boundary (ethtool ioctl).
pub fn update_interface_speed<F: FnOnce(i32)>(if_index: i32, update: F) {
    update(if_index);
}

#[cfg(test)]
mod tests;
