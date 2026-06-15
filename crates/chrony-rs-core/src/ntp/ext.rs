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

/// Subset of chrony's `NTP_PacketInfo` that `ntp_ext.c` reads/writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NtpPacketInfo {
    /// Current packet length (header + already-appended fields).
    pub length: i32,
    pub version: i32,
    pub ext_fields: i32,
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
        let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, ext_fields: 0 };

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
        let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 3, ext_fields: 0 };
        assert!(!add_field(&mut pkt, &mut info, 0x0204, &[0u8; 28]));
        // misaligned current length -> rejected
        let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH + 1, version: 4, ext_fields: 0 };
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
}
