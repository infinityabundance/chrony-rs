//! NTP packet parsing/validation — `ntp_core.c` Stage 2 (`parse_packet` +
//! `is_zero_data` / `is_exp_ef`).
//!
//! [`parse_packet`] is chrony's first-pass packet validator: it checks the length and
//! version, fills [`NtpPacketInfo`] (version, mode, extension-field count + flags), and
//! classifies the authentication trailer — a plain packet, an NTPv3 MAC (with MS-SNTP /
//! extended-MS-SNTP detection via [`is_zero_data`]), a crypto-NAK, NTPv4 extension
//! fields (NTS detection + the experimental EFs via [`is_exp_ef`]), or a trailing
//! symmetric MAC. It composes the ported extension-field parser
//! ([`crate::ntp::ext::parse_field`], chrony's `NEF_ParseField`).
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness (the static `parse_packet` reached directly): crafted packets — plain v4,
//! an NTPv3 MAC, an MS-SNTP authenticator, a crypto-NAK, an NTS extension field, and a
//! v4 MAC after an EF — are parsed and every `NTP_PacketInfo` field captured
//! (`research/oracle/ntp_core-parse-c-vectors.txt`). See the tests.

use crate::ntp::ext::{parse_field, ef_dispatch, EfAction, NtpPacketBuf, NTP_HEADER_LENGTH, NTP_MAX_V4_MAC_LENGTH};
use crate::ntp::ext::NtpPacketInfo;

/// chrony auth modes (`NTP_AuthMode`).
pub const NTP_AUTH_NONE: i32 = 0;
pub const NTP_AUTH_SYMMETRIC: i32 = 1;
pub const NTP_AUTH_MSSNTP: i32 = 2;
pub const NTP_AUTH_MSSNTP_EXT: i32 = 3;
pub const NTP_AUTH_NTS: i32 = 4;

/// chrony `NTP_MIN_COMPAT_VERSION` / `NTP_MAX_COMPAT_VERSION`.
const NTP_MIN_COMPAT_VERSION: i32 = 1;
const NTP_MAX_COMPAT_VERSION: i32 = 4;
/// chrony `NTP_MIN_MAC_LENGTH`.
const NTP_MIN_MAC_LENGTH: i32 = 4 + 16;

/// NTS extension-field types.
const NTP_EF_NTS_UNIQUE_IDENTIFIER: i32 = 0x0104;
const NTP_EF_NTS_COOKIE: i32 = 0x0204;
const NTP_EF_NTS_COOKIE_PLACEHOLDER: i32 = 0x0304;
const NTP_EF_NTS_AUTH_AND_EEF: i32 = 0x0404;
/// Experimental extension-field types + flags + magics.
const NTP_EF_EXP_MONO_ROOT: i32 = 0xE001;
const NTP_EF_EXP_NET_CORRECTION: i32 = 0xE002;
const NTP_EF_FLAG_EXP_MONO_ROOT: i32 = 0x1;
const NTP_EF_FLAG_EXP_NET_CORRECTION: i32 = 0x2;
const NTP_EF_EXP_MONO_ROOT_MAGIC: u32 = 0xF5BE_DD9A;
const NTP_EF_EXP_NET_CORRECTION_MAGIC: u32 = 0x07AC_2CEB;
/// `sizeof(NTP_EFExpMonoRoot)` and `sizeof(NTP_EFExpNetCorrection)`.
const EXP_EF_BODY_LENGTH: i32 = 24;

/// chrony `is_zero_data`: whether all `bytes` are zero.
pub fn is_zero_data(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// chrony `is_exp_ef`: whether an experimental EF body has the expected length and its
/// leading 4-byte magic (network order) matches.
pub fn is_exp_ef(body: &[u8], expected_body_length: i32, magic: u32) -> bool {
    body.len() as i32 == expected_body_length
        && body.len() >= 4
        && u32::from_be_bytes([body[0], body[1], body[2], body[3]]) == magic
}

/// chrony `parse_packet`: validate `packet` (the first `length` bytes) and fill the
/// returned [`NtpPacketInfo`], or `None` if the packet is malformed.
pub fn parse_packet(packet: &NtpPacketBuf, length: i32) -> Option<NtpPacketInfo> {
    let data = packet.bytes();

    if length < NTP_HEADER_LENGTH || length % 4 != 0 {
        return None;
    }

    let lvm = data[0];
    let leap = ((lvm >> 6) & 0x3) as i32;
    // LI=3 means the clock is unsynchronised (alarm condition).
    if leap == 3 {
        return None;
    }
    let mut info = NtpPacketInfo {
        length,
        version: ((lvm >> 3) & 0x7) as i32,
        leap,
        mode: (lvm & 0x7) as i32,
        ext_fields: 0,
        ext_field_flags: 0,
        auth_mode: NTP_AUTH_NONE,
        ..Default::default()
    };

    if info.version < NTP_MIN_COMPAT_VERSION || info.version > NTP_MAX_COMPAT_VERSION {
        return None;
    }

    let mut parsed = NTP_HEADER_LENGTH;
    let mut remainder = info.length - parsed;

    // A plain packet with no extension fields or MAC.
    if remainder <= 0 {
        return Some(info);
    }

    let rd_u32 = |off: i32| -> u32 {
        let o = off as usize;
        u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
    };

    // NTPv3 and older: everything after the header is a MAC.
    if info.version <= 3 {
        info.auth_mode = NTP_AUTH_SYMMETRIC;
        info.mac_start = parsed;
        info.mac_length = remainder;
        info.mac_key_id = rd_u32(parsed);

        if info.version == 3 && info.mac_key_id != 0 {
            let start = parsed as usize;
            if remainder == 20 && is_zero_data(&data[start + 4..start + remainder as usize]) {
                info.auth_mode = NTP_AUTH_MSSNTP;
            } else if remainder == 72 && is_zero_data(&data[start + 8..start + remainder as usize]) {
                info.auth_mode = NTP_AUTH_MSSNTP_EXT;
            }
        }
        return Some(info);
    }

    // Crypto NAK.
    if remainder == 4 && rd_u32(parsed) == 0 {
        info.auth_mode = NTP_AUTH_SYMMETRIC;
        info.mac_start = parsed;
        info.mac_length = remainder;
        info.mac_key_id = 0;
        return Some(info);
    }

    // Parse the rest of the NTPv4 packet.
    while remainder > 0 {
        // The remaining data is a MAC (chrony: remainder in [MIN_MAC, MAX_V4_MAC]).
        if (NTP_MIN_MAC_LENGTH..=NTP_MAX_V4_MAC_LENGTH).contains(&remainder) {
            break;
        }

        let ef = parse_field(packet, info.length, parsed)?;

        match ef.field_type {
            NTP_EF_NTS_UNIQUE_IDENTIFIER
            | NTP_EF_NTS_COOKIE
            | NTP_EF_NTS_COOKIE_PLACEHOLDER
            | NTP_EF_NTS_AUTH_AND_EEF => {
                info.auth_mode = NTP_AUTH_NTS;
            }
            NTP_EF_EXP_MONO_ROOT => {
                let body = &data[ef.body_offset..ef.body_offset + ef.body_length as usize];
                if is_exp_ef(body, EXP_EF_BODY_LENGTH, NTP_EF_EXP_MONO_ROOT_MAGIC) {
                    info.ext_field_flags |= NTP_EF_FLAG_EXP_MONO_ROOT;
                }
            }
            NTP_EF_EXP_NET_CORRECTION => {
                let body = &data[ef.body_offset..ef.body_offset + ef.body_length as usize];
                if is_exp_ef(body, EXP_EF_BODY_LENGTH, NTP_EF_EXP_NET_CORRECTION_MAGIC) {
                    info.ext_field_flags |= NTP_EF_FLAG_EXP_NET_CORRECTION;
                }
            }
            _ => {
                let action = ef_dispatch(&ef, packet, info.length);
                match action {
                    EfAction::UnknownCritical => return None,
                    EfAction::Handled | EfAction::Skip => {}
                }
            }
        }

        info.ext_fields += 1;
        parsed += ef.length;
        remainder = info.length - parsed;
    }

    if remainder == 0 {
        // No MAC.
        Some(info)
    } else if remainder >= NTP_MIN_MAC_LENGTH {
        info.auth_mode = NTP_AUTH_SYMMETRIC;
        info.mac_start = parsed;
        info.mac_length = remainder;
        info.mac_key_id = rd_u32(parsed);
        Some(info)
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
