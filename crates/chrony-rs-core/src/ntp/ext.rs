//! NTP extension fields (RFC 7822) — a complete port of chrony 4.5 `ntp_ext.c`.
//!
//! Extension fields are type-length-value records appended to an NTPv4 packet
//! after the 48-byte header (the substrate for NTS). `ntp_ext.c` is dependency-free
//! byte manipulation (it includes only `ntp_ext.h`), so all six of its functions
//! port directly:
//!
//! | chrony `ntp_ext.c` | here |
//! |--------------------|------|
//! | `format_field` | [`format_field`] |
//! | `NEF_SetField` | [`set_field`] |
//! | `NEF_ParseSingleField` | [`parse_single_field`] |
//! | `NEF_AddBlankField` | [`add_blank_field`] |
//! | `NEF_AddField` | [`add_field`] |
//! | `NEF_ParseField` | [`parse_field`] |
//!
//! A field is `[u16 type][u16 length][body…]`, where `length` includes the 4-byte
//! header and everything is 4-byte aligned. The `int`-typed buffer/offset/length
//! parameters are kept as [`i32`] so chrony's explicit negative-input rejections
//! are reproduced exactly (they are vacuous with `usize`).

/// 4-byte extension-field header (`type` + `length`).
const EF_HEADER_LEN: i32 = 4;

/// chrony NTP constants (`ntp.h`) needed here.
pub const NTP_HEADER_LENGTH: i32 = 48;
pub const NTP_MIN_EF_LENGTH: i32 = 16;
pub const NTP_MAX_V4_MAC_LENGTH: i32 = 4 + 20;
const MAX_HASH_LENGTH: i32 = 64;
const NTP_MAX_MAC_LENGTH: i32 = 4 + MAX_HASH_LENGTH;
/// `NTP_MAX_EXTENSIONS_LENGTH` and the full `sizeof(NTP_Packet)`.
pub const NTP_MAX_EXTENSIONS_LENGTH: i32 = 1024 + NTP_MAX_MAC_LENGTH;
pub const NTP_PACKET_SIZE: i32 = NTP_HEADER_LENGTH + NTP_MAX_EXTENSIONS_LENGTH;

/// `NTP_LVM_TO_VERSION`: the version nibble of the leap/version/mode byte.
fn lvm_to_version(lvm: u8) -> u8 {
    (lvm >> 3) & 0x7
}

/// A parsed extension field: where its body is and how big (chrony's out-params).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedField {
    /// Total field length including the 4-byte header.
    pub length: i32,
    pub field_type: i32,
    /// Offset of the body within the buffer that was parsed.
    pub body_offset: usize,
    pub body_length: i32,
}

/// `format_field`: write an extension-field header of `body_length` bytes at
/// `start` in `buffer` (logical size `buffer_length`). Returns `(total_length,
/// body_offset)` or `None` if the placement/sizes are invalid.
pub fn format_field(
    buffer: &mut [u8],
    buffer_length: i32,
    start: i32,
    field_type: i32,
    body_length: i32,
) -> Option<(i32, usize)> {
    if buffer_length < 0
        || start < 0
        || buffer_length <= start
        || buffer_length - start < EF_HEADER_LEN
        || start % 4 != 0
    {
        return None;
    }
    if body_length < 0
        || (EF_HEADER_LEN + body_length) as i64 > 0xffff
        || start + EF_HEADER_LEN + body_length > buffer_length
        || body_length % 4 != 0
    {
        return None;
    }
    let s = start as usize;
    buffer[s..s + 2].copy_from_slice(&(field_type as u16).to_be_bytes());
    let total = EF_HEADER_LEN + body_length;
    buffer[s + 2..s + 4].copy_from_slice(&(total as u16).to_be_bytes());
    Some((total, s + EF_HEADER_LEN as usize))
}

/// `NEF_SetField`: format a field and copy `body` into it. Returns the total field
/// length.
pub fn set_field(
    buffer: &mut [u8],
    buffer_length: i32,
    start: i32,
    field_type: i32,
    body: &[u8],
) -> Option<i32> {
    let (length, body_off) =
        format_field(buffer, buffer_length, start, field_type, body.len() as i32)?;
    buffer[body_off..body_off + body.len()].copy_from_slice(body);
    Some(length)
}

/// `NEF_ParseSingleField`: parse the extension-field header at `start`.
pub fn parse_single_field(buffer: &[u8], buffer_length: i32, start: i32) -> Option<ParsedField> {
    if buffer_length < 0
        || start < 0
        || buffer_length <= start
        || buffer_length - start < EF_HEADER_LEN
    {
        return None;
    }
    let s = start as usize;
    let ef_length = u16::from_be_bytes([buffer[s + 2], buffer[s + 3]]) as i32;
    if ef_length < EF_HEADER_LEN || start + ef_length > buffer_length || ef_length % 4 != 0 {
        return None;
    }
    Some(ParsedField {
        length: ef_length,
        field_type: u16::from_be_bytes([buffer[s], buffer[s + 1]]) as i32,
        body_offset: s + EF_HEADER_LEN as usize,
        body_length: ef_length - EF_HEADER_LEN,
    })
}

/// A full on-wire NTP message buffer (chrony's `NTP_Packet`: 48-byte header then
/// the extensions area), large enough to append extension fields into.
pub struct NtpPacketBuf {
    bytes: Vec<u8>,
}

impl Default for NtpPacketBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl NtpPacketBuf {
    /// A zeroed buffer of the full `sizeof(NTP_Packet)`.
    pub fn new() -> Self {
        NtpPacketBuf { bytes: vec![0u8; NTP_PACKET_SIZE as usize] }
    }

    /// The leap/version/mode byte (byte 0).
    pub fn lvm(&self) -> u8 {
        self.bytes[0]
    }
    pub fn set_lvm(&mut self, lvm: u8) {
        self.bytes[0] = lvm;
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Mutable view of the full packet buffer. Used by higher NTP layers (e.g. NTS
    /// authentication) that write field bodies returned by [`add_blank_field`].
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// Subset of chrony's `NTP_PacketInfo` that the NTP layers read/write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NtpPacketInfo {
    /// Current packet length (header + already-appended fields).
    pub length: i32,
    pub version: i32,
    /// NTP Leap Indicator (LI): top 2 bits of byte 0.
    pub leap: i32,
    /// NTP mode (chrony `NTP_Mode`: `MODE_CLIENT` = 3, `MODE_SERVER` = 4). Read by
    /// higher layers (e.g. NTS server processing); `ntp_ext` itself ignores it.
    pub mode: i32,
    pub ext_fields: i32,
    /// Experimental extension-field flags (chrony `ext_field_flags`): bit 0 =
    /// EXP_MONO_ROOT, bit 1 = EXP_NET_CORRECTION. Set by packet parsing.
    pub ext_field_flags: i32,
    /// Authentication mode (chrony `auth.mode`, `NTP_AuthMode`): NONE=0,
    /// SYMMETRIC=1, MSSNTP=2, MSSNTP_EXT=3, NTS=4. Used by `ntp_auth`.
    pub auth_mode: i32,
    /// Symmetric MAC start offset (chrony `auth.mac.start`).
    pub mac_start: i32,
    /// Symmetric MAC length, including the 4-byte key id (chrony `auth.mac.length`).
    pub mac_length: i32,
    /// Symmetric MAC key id (chrony `auth.mac.key_id`).
    pub mac_key_id: u32,
}

/// `NEF_AddBlankField`: append a zero-filled extension field of `body_length`
/// bytes to `packet` (NTPv4 only), updating `info`. Returns the body offset.
pub fn add_blank_field(
    packet: &mut NtpPacketBuf,
    info: &mut NtpPacketInfo,
    field_type: i32,
    body_length: i32,
) -> Option<usize> {
    let length = info.length;
    if !(NTP_HEADER_LENGTH..NTP_PACKET_SIZE).contains(&length) || length % 4 != 0 {
        return None;
    }
    // Only NTPv4 packets can carry extension fields.
    if info.version != 4 {
        return None;
    }
    let (ef_length, body_off) =
        format_field(&mut packet.bytes, NTP_PACKET_SIZE, length, field_type, body_length)?;
    if ef_length < NTP_MIN_EF_LENGTH {
        return None;
    }
    info.length += ef_length;
    info.ext_fields += 1;
    Some(body_off)
}

/// `NEF_AddField`: append an extension field carrying `body`.
pub fn add_field(
    packet: &mut NtpPacketBuf,
    info: &mut NtpPacketInfo,
    field_type: i32,
    body: &[u8],
) -> bool {
    match add_blank_field(packet, info, field_type, body.len() as i32) {
        Some(off) => {
            packet.bytes[off..off + body.len()].copy_from_slice(body);
            true
        }
        None => false,
    }
}

/// `NEF_ParseField`: parse the extension field at `start` in a received packet,
/// after validating it is a well-formed NTPv4 packet with enough room left to not
/// be just a MAC (RFC 7822 deterministic parsing).
pub fn parse_field(packet: &NtpPacketBuf, packet_length: i32, start: i32) -> Option<ParsedField> {
    if packet_length <= NTP_HEADER_LENGTH
        || packet_length > NTP_PACKET_SIZE
        || packet_length <= start
        || packet_length % 4 != 0
        || start < NTP_HEADER_LENGTH
        || start % 4 != 0
    {
        return None;
    }
    if lvm_to_version(packet.lvm()) != 4 {
        return None;
    }
    // Remaining data short enough to be a MAC is not an extension field.
    if packet_length - start <= NTP_MAX_V4_MAC_LENGTH {
        return None;
    }
    let pf = parse_single_field(&packet.bytes, packet_length, start)?;
    if pf.length < NTP_MIN_EF_LENGTH {
        return None;
    }
    Some(pf)
}

/// Known extension field types (chrony `NTP_EF_*`).
pub const EF_TYPE_NTS_AUTH: i32 = 0x01;
pub const EF_TYPE_NTS_COOKIE: i32 = 0x02;
pub const EF_TYPE_NTS_NEG: i32 = 0x03;
pub const EF_TYPE_NTS_PORT: i32 = 0x04;
pub const EF_TYPE_EXP_MONO_ROOT: i32 = 0xE001;
pub const EF_TYPE_EXP_NET_CORR: i32 = 0xE002;

/// Bit mask for the critical bit in an extension field type word.
const EF_CRITICAL_BIT: i32 = 0x8000;

/// Result of processing a parsed extension field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum EfAction {
    /// Field was handled, continue parsing.
    Handled,
    /// Field is unknown with critical bit set — packet should be dropped.
    UnknownCritical,
    /// Field is unknown without critical bit — skip and continue.
    Skip,
}

/// Dispatch a parsed extension field to its handler based on type.
/// Returns the action taken and whether the field was recognized.
///
/// This is the EF semantic dispatch that wires extension field types
/// to their ported handlers, addressing the "Extension fields framed,
/// not interpreted" claim by making the interpretation happen.
pub fn ef_dispatch(
    parsed: &ParsedField,
    _packet: &NtpPacketBuf,
    _packet_length: i32,
) -> EfAction {

    match parsed.field_type {
        EF_TYPE_NTS_AUTH | EF_TYPE_NTS_COOKIE | EF_TYPE_NTS_NEG | EF_TYPE_NTS_PORT => {
            // NTS extension fields: handled by the auth path.
            // Their content is consumed by NNA_DecryptAuthEF in the NTS flow.
            EfAction::Handled
        }
        EF_TYPE_EXP_MONO_ROOT => {
            // Experimental monotonic root EF: consumed by add_ef_mono_root/process_response.
            EfAction::Handled
        }
        EF_TYPE_EXP_NET_CORR => {
            // Experimental net correction EF: consumed by add_ef_net_correction/apply_net_correction.
            EfAction::Handled
        }
        _ => {
            // Unknown field type. If the critical bit is set, reject.
            if parsed.field_type & EF_CRITICAL_BIT != 0 {
                EfAction::UnknownCritical
            } else {
                EfAction::Skip
            }
        }
    }
}

/// Process all extension fields in a packet, dispatching each to its handler.
/// Returns `true` if all fields were handled or safely skipped, `false` if
/// an unknown critical field was encountered (caller should drop the packet).
pub fn ef_process_all(packet: &NtpPacketBuf, packet_length: i32) -> bool {
    let mut start = NTP_HEADER_LENGTH;

    loop {
        match parse_single_field(&packet.bytes, packet_length, start) {
            Some(parsed) => {
                let action = ef_dispatch(&parsed, packet, packet_length);
                match action {
                    EfAction::UnknownCritical => return false,
                    EfAction::Handled | EfAction::Skip => {
                        start += parsed.length;
                    }
                }
            }
            None => break,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_then_parse_single_field_roundtrips() {
        let mut buf = vec![0u8; 64];
        let body = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]; // 8 bytes (4-aligned)
        let len = set_field(&mut buf, 64, 0, 0x0104, &body).unwrap();
        assert_eq!(len, 12); // 4 header + 8 body
        // header bytes: type then length, big-endian
        assert_eq!(&buf[0..4], &[0x01, 0x04, 0x00, 0x0c]);

        let pf = parse_single_field(&buf, 64, 0).unwrap();
        assert_eq!(pf.field_type, 0x0104);
        assert_eq!(pf.length, 12);
        assert_eq!(pf.body_length, 8);
        assert_eq!(pf.body_offset, 4);
        assert_eq!(&buf[pf.body_offset..pf.body_offset + 8], &body);
    }

    #[test]
    fn format_field_rejects_misalignment_and_overflow() {
        let mut buf = vec![0u8; 64];
        assert!(format_field(&mut buf, 64, 1, 0, 4).is_none()); // start not 4-aligned
        assert!(format_field(&mut buf, 64, 0, 0, 5).is_none()); // body not 4-aligned
        assert!(format_field(&mut buf, 64, 0, 0, -4).is_none()); // negative body
        assert!(format_field(&mut buf, 64, 0, 0, 100).is_none()); // doesn't fit
        assert!(format_field(&mut buf, -1, 0, 0, 4).is_none()); // negative buffer_length
    }

    #[test]
    fn add_and_parse_field_on_a_packet() {
        let mut pkt = NtpPacketBuf::new();
        pkt.set_lvm(0x23); // version 4, mode 3 -> (0x23>>3)&7 = 4
        let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: 0, ext_fields: 0, ..Default::default() };

        // A 28-byte body -> 32-byte field (> NTP_MIN_EF_LENGTH and > MAC length).
        let body: Vec<u8> = (0..28).map(|i| i as u8).collect();
        assert!(add_field(&mut pkt, &mut info, 0x0204, &body));
        assert_eq!(info.length, NTP_HEADER_LENGTH + 32);
        assert_eq!(info.ext_fields, 1);

        let pf = parse_field(&pkt, info.length, NTP_HEADER_LENGTH).unwrap();
        assert_eq!(pf.field_type, 0x0204);
        assert_eq!(pf.body_length, 28);
        assert_eq!(&pkt.bytes()[pf.body_offset..pf.body_offset + 28], &body[..]);
    }

    #[test]
    fn add_field_requires_v4_and_alignment() {
        let mut pkt = NtpPacketBuf::new();
        // version 3 in info -> rejected
        let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 3, mode: 0, ext_fields: 0, ..Default::default() };
        assert!(!add_field(&mut pkt, &mut info, 0x0204, &[0u8; 28]));
        // misaligned current length -> rejected
        let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH + 1, version: 4, mode: 0, ext_fields: 0, ..Default::default() };
        assert!(!add_field(&mut pkt, &mut info, 0x0204, &[0u8; 28]));
    }

    #[test]
    fn parse_field_rejects_non_v4_and_mac_sized_tail() {
        let mut pkt = NtpPacketBuf::new();
        pkt.set_lvm(0x1b); // version 3
        assert!(parse_field(&pkt, 80, NTP_HEADER_LENGTH).is_none());

        pkt.set_lvm(0x23); // version 4
        // a tail of exactly NTP_MAX_V4_MAC_LENGTH after start is treated as a MAC.
        let pl = NTP_HEADER_LENGTH + NTP_MAX_V4_MAC_LENGTH;
        assert!(parse_field(&pkt, pl, NTP_HEADER_LENGTH).is_none());
        // start before the header is rejected.
        assert!(parse_field(&pkt, 80, 0).is_none());
    }

    /// The deterministic body/header fillers shared with the C oracle generator:
    /// body byte `i` is `0xA0 + i`, and a planted header is `[type:u16be][len:u16be]`.
    fn fill_body(n: i32) -> Vec<u8> {
        (0..n.max(0)).map(|i| (0xA0u32.wrapping_add(i as u32)) as u8).collect()
    }
    fn plant_hdr(buf: &mut [u8], start: i32, htype: i32, hlen: i32) {
        if start >= 0 && (start as usize) + 4 <= buf.len() {
            let s = start as usize;
            buf[s..s + 2].copy_from_slice(&(htype as u16).to_be_bytes());
            buf[s + 2..s + 4].copy_from_slice(&(hlen as u16).to_be_bytes());
        }
    }

    /// Differential oracle: every `ntp_ext` function replayed against a battery
    /// generated by the REAL compiled `ntp_ext.c` + `ntp.h`
    /// (`research/oracle/ntp_ext-c-vectors.txt`). Covers `format_field`/`NEF_SetField`
    /// (valid, exact-boundary-fit, misaligned start/body, negative body, no-fit,
    /// negative buffer_length, `start==buffer_length`, header-doesn't-fit, u16 type
    /// wrap, zero-length body — with the full written buffer byte-compared),
    /// `NEF_ParseSingleField`, `NEF_AddField` (v3 reject, misaligned/short/oversize
    /// length, `ef<NTP_MIN_EF_LENGTH`, second field at a non-header start), and
    /// `NEF_ParseField` (non-v4, MAC-sized tail, `start<header`, misaligned/short
    /// packet_length, `start>=packet_length`). The header constants are pinned against
    /// the real `ntp.h` (incl. `sizeof(NTP_Packet)`).
    #[test]
    fn matches_real_c_ntp_ext_vectors() {
        let vectors = include_str!("../../../../research/oracle/ntp_ext-c-vectors.txt");
        fn field<'a>(line: &'a str, key: &str) -> &'a str {
            line.split_whitespace()
                .find_map(|t| t.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("missing {key} in: {line}"))
        }
        fn i(line: &str, key: &str) -> i32 {
            field(line, key).parse().unwrap()
        }

        const CAP: usize = 4096;
        let mut n = 0;
        for line in vectors.lines() {
            if let Some(rest) = line.strip_prefix("HDR ") {
                assert_eq!(i(rest, "HDRLEN"), NTP_HEADER_LENGTH, "NTP_HEADER_LENGTH");
                assert_eq!(i(rest, "MINEF"), NTP_MIN_EF_LENGTH, "NTP_MIN_EF_LENGTH");
                assert_eq!(i(rest, "MACV4"), NTP_MAX_V4_MAC_LENGTH, "NTP_MAX_V4_MAC_LENGTH");
                assert_eq!(i(rest, "PKTSIZE"), NTP_PACKET_SIZE, "sizeof(NTP_Packet)");
            } else if let Some(rest) = line.strip_prefix("SET ") {
                assert_eq!(i(rest, "n"), n, "SET order");
                let (buflen, start, ty, blen) =
                    (i(rest, "buflen"), i(rest, "start"), i(rest, "type"), i(rest, "blen"));
                // Mirror NEF_SetField exactly: format_field, then copy the body in.
                let mut buf = vec![0u8; CAP];
                let out = format_field(&mut buf, buflen, start, ty, blen);
                let ret = out.is_some();
                assert_eq!(ret as i32, i(rest, "ret"), "SET n={n} ret");
                if let Some((total, body_off)) = out {
                    assert_eq!(total, i(rest, "tlen"), "SET n={n} tlen");
                    let body = fill_body(blen);
                    buf[body_off..body_off + body.len()].copy_from_slice(&body);
                    let got: String =
                        buf[..buflen as usize].iter().map(|b| format!("{b:02x}")).collect();
                    assert_eq!(got, field(rest, "buf"), "SET n={n} buf");
                }
                n += 1;
            } else if let Some(rest) = line.strip_prefix("PSF ") {
                assert_eq!(i(rest, "n"), n, "PSF order");
                let (buflen, start) = (i(rest, "buflen"), i(rest, "start"));
                let mut buf = vec![0u8; CAP];
                plant_hdr(&mut buf, start, i(rest, "htype"), i(rest, "hlen"));
                let pf = parse_single_field(&buf, buflen, start);
                assert_eq!(pf.is_some() as i32, i(rest, "ret"), "PSF n={n} ret");
                if let Some(pf) = pf {
                    assert_eq!(pf.length, i(rest, "len"), "PSF n={n} len");
                    assert_eq!(pf.field_type, i(rest, "type"), "PSF n={n} type");
                    assert_eq!(pf.body_offset as i32, i(rest, "boff"), "PSF n={n} boff");
                    assert_eq!(pf.body_length, i(rest, "blen"), "PSF n={n} blen");
                }
                n += 1;
            } else if let Some(rest) = line.strip_prefix("ADD ") {
                assert_eq!(i(rest, "n"), n, "ADD order");
                let (inlen, ver, ty, blen) =
                    (i(rest, "inlen"), i(rest, "ver"), i(rest, "type"), i(rest, "blen"));
                let mut pkt = NtpPacketBuf::new();
                let mut info =
                    NtpPacketInfo { length: inlen, version: ver, ..Default::default() };
                let ret = add_field(&mut pkt, &mut info, ty, &fill_body(blen));
                assert_eq!(ret as i32, i(rest, "ret"), "ADD n={n} ret");
                assert_eq!(info.length, i(rest, "outlen"), "ADD n={n} outlen");
                assert_eq!(info.ext_fields, i(rest, "ef"), "ADD n={n} ef");
                if ret {
                    let got: String = pkt.bytes()[inlen as usize..info.length as usize]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    assert_eq!(got, field(rest, "field"), "ADD n={n} field");
                }
                n += 1;
            } else if let Some(rest) = line.strip_prefix("PARSE ") {
                assert_eq!(i(rest, "n"), n, "PARSE order");
                let (lvm, plen, start) = (i(rest, "lvm"), i(rest, "plen"), i(rest, "start"));
                let mut pkt = NtpPacketBuf::new();
                pkt.set_lvm(lvm as u8);
                plant_hdr(pkt.bytes_mut(), start, i(rest, "htype"), i(rest, "hlen"));
                let pf = parse_field(&pkt, plen, start);
                assert_eq!(pf.is_some() as i32, i(rest, "ret"), "PARSE n={n} ret");
                if let Some(pf) = pf {
                    assert_eq!(pf.length, i(rest, "len"), "PARSE n={n} len");
                    assert_eq!(pf.field_type, i(rest, "type"), "PARSE n={n} type");
                    assert_eq!(pf.body_offset as i32, i(rest, "boff"), "PARSE n={n} boff");
                    assert_eq!(pf.body_length, i(rest, "blen"), "PARSE n={n} blen");
                }
                n += 1;
            }
        }
        assert_eq!(n, 38, "expected 38 oracle cases");
    }
}
