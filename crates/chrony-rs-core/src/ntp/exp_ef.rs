//! NTP experimental extension-field builders — `ntp_core.c` Stage 8
//! (`add_ef_mono_root`, `add_ef_net_correction`).
//!
//! These are the *transmit* side of chrony's two pre-NTPv5 experimental extension
//! fields, completing the story whose receive side is parsed in
//! [`crate::ntp::parse`] (Stage 2) and whose correction is applied in
//! [`crate::ntp::sample::apply_net_correction`] (Stage 4):
//!
//! * [`add_ef_mono_root`] — the monotonic-root EF, carrying the server's monotonic
//!   receive timestamp + root delay/dispersion (in the f28 fixed-point form). In client
//!   mode only the magic is sent (no server state is revealed).
//! * [`add_ef_net_correction`] — the PTP net-correction EF, carrying the accumulated
//!   transparent-clock correction. Gated on `ptpport` being enabled; in client mode (or
//!   when no correction exceeds the receive duration) only the magic is sent.
//!
//! # Adaptations (documented, not silent)
//!
//! chrony adds random *fuzz* to the monotonic receive timestamp (`UTI_GetNtp64Fuzz`,
//! seeded from the system CSPRNG). Randomness is a host-boundary concern injected
//! elsewhere in the reconstruction, so these builders produce the **unfuzzed** body;
//! the caller XORs in fuzz if required. (The oracle zeroes the fuzz to match.)
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness (the real `ntp_ext.c` linked for `NEF_AddField`, the fuzz RNG zeroed, the
//! `server_mono_*` statics and `ptpport` made controllable): each builder is run across
//! client/server modes and the present/absent correction cases, and the appended
//! extension-field body bytes + flags are captured
//! (`research/oracle/ntp_core-ef-c-vectors.txt`). See the tests.

use crate::ntp::ext::{add_field, NtpPacketBuf, NtpPacketInfo};
use crate::sys_generic::Timespec;

/// chrony experimental EF types and flags.
const NTP_EF_EXP_MONO_ROOT: i32 = 0xF323;
const NTP_EF_EXP_NET_CORRECTION: i32 = 0xF324;
const NTP_EF_FLAG_EXP_MONO_ROOT: i32 = 0x1;
const NTP_EF_FLAG_EXP_NET_CORRECTION: i32 = 0x2;
const NTP_EF_EXP_MONO_ROOT_MAGIC: u32 = 0xF5BE_DD9A;
const NTP_EF_EXP_NET_CORRECTION_MAGIC: u32 = 0x07AC_2CEB;

/// chrony `MODE_CLIENT`.
const MODE_CLIENT: i32 = 3;
/// chrony `JAN_1970` and `NSEC_PER_NTP64`.
const JAN_1970: u32 = 0x83aa_7e80;
const NSEC_PER_NTP64: f64 = 4.294_967_296;

/// chrony `UTI_DoubleToNtp32f28`: a 4.28 fixed-point value (host order).
fn double_to_ntp32f28(x: f64) -> u32 {
    const SCALE: f64 = (1u32 << 28) as f64;
    if x >= 4_294_967_295.0 / SCALE {
        0xffff_ffff
    } else if x <= 0.0 {
        0
    } else {
        let xs = x * SCALE;
        let mut r = xs as u32;
        if (r as f64) < xs {
            r += 1;
        }
        r
    }
}

/// chrony `UTI_DoubleToNtp64`: a 32.32 signed-seconds fixed-point value, returned as the
/// `(hi, lo)` host-order halves.
fn double_to_ntp64(mut src: f64) -> (u32, u32) {
    src = src.clamp(i32::MIN as f64, i32::MAX as f64);
    let mut hi = src.round() as i32;
    if hi as f64 > src {
        hi -= 1;
    }
    let lo = ((src - hi as f64) * (1.0e9 * NSEC_PER_NTP64)) as u32;
    (hi as u32, lo)
}

/// chrony `UTI_TimespecToNtp64` without fuzz, returned as the `(hi, lo)` host-order
/// halves (the no-era-split build).
fn timespec_to_ntp64(ts: Timespec) -> (u32, u32) {
    let sec = ts.tv_sec as u32;
    let nsec = ts.tv_nsec as u32;
    if sec == 0 && nsec == 0 {
        return (0, 0);
    }
    (sec.wrapping_add(JAN_1970), (NSEC_PER_NTP64 * nsec as f64) as u32)
}

/// chrony `add_ef_mono_root`: append the monotonic-root experimental extension field to
/// `packet`/`info`. In client mode only the magic is filled; otherwise the server's root
/// delay/dispersion (f28), the monotonic receive timestamp (`rx + server_mono_offset`,
/// or zero when `rx` is absent) and the monotonic epoch are carried. Returns `false` if
/// the field could not be appended (chrony's `0`).
pub fn add_ef_mono_root(
    packet: &mut NtpPacketBuf,
    info: &mut NtpPacketInfo,
    rx: Option<Timespec>,
    server_mono_offset: f64,
    server_mono_epoch: u32,
    root_delay: f64,
    root_dispersion: f64,
) -> bool {
    let mut body = [0u8; 24];
    body[0..4].copy_from_slice(&NTP_EF_EXP_MONO_ROOT_MAGIC.to_be_bytes());

    if info.mode != MODE_CLIENT {
        body[4..8].copy_from_slice(&double_to_ntp32f28(root_delay).to_be_bytes());
        body[8..12].copy_from_slice(&double_to_ntp32f28(root_dispersion).to_be_bytes());
        let mono_rx = match rx {
            Some(t) => t.add_double(server_mono_offset),
            None => Timespec::new(0, 0),
        };
        let (hi, lo) = timespec_to_ntp64(mono_rx);
        body[12..16].copy_from_slice(&hi.to_be_bytes());
        body[16..20].copy_from_slice(&lo.to_be_bytes());
        body[20..24].copy_from_slice(&server_mono_epoch.to_be_bytes());
    }

    if !add_field(packet, info, NTP_EF_EXP_MONO_ROOT, &body) {
        return false;
    }
    info.ext_field_flags |= NTP_EF_FLAG_EXP_MONO_ROOT;
    true
}

/// chrony `add_ef_net_correction`: append the PTP net-correction experimental extension
/// field. When `ptp_port == 0` the field is disabled and nothing is appended (chrony
/// returns `1`). Otherwise only the magic is sent in client mode or when the local
/// receive correction does not exceed the receive duration; in server mode with a
/// correction present, the correction is carried. Returns `false` only on append
/// failure.
pub fn add_ef_net_correction(
    packet: &mut NtpPacketBuf,
    info: &mut NtpPacketInfo,
    ptp_port: i32,
    local_rx_net_correction: f64,
    local_rx_rx_duration: f64,
) -> bool {
    if ptp_port == 0 {
        return true;
    }

    let mut body = [0u8; 24];
    body[0..4].copy_from_slice(&NTP_EF_EXP_NET_CORRECTION_MAGIC.to_be_bytes());

    if info.mode != MODE_CLIENT && local_rx_net_correction > local_rx_rx_duration {
        let (hi, lo) = double_to_ntp64(local_rx_net_correction);
        body[4..8].copy_from_slice(&hi.to_be_bytes());
        body[8..12].copy_from_slice(&lo.to_be_bytes());
    }

    if !add_field(packet, info, NTP_EF_EXP_NET_CORRECTION, &body) {
        return false;
    }
    info.ext_field_flags |= NTP_EF_FLAG_EXP_NET_CORRECTION;
    true
}

#[cfg(test)]
mod tests;
