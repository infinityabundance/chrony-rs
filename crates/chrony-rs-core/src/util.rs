//! Dependency-free utility primitives — a subset of chrony 4.5 `util.c`.
//!
//! `util.c` is a 76-function grab-bag (`UTI_*`). Many entries are pure, total
//! functions with no chrony state; this module ports those that are exactly
//! testable and reused elsewhere in the reconstruction:
//!
//! | chrony `util.c` | here |
//! |-----------------|------|
//! | `UTI_Log2ToDouble` | [`log2_to_double`] |
//! | `UTI_BytesToHex` | [`bytes_to_hex`] |
//! | `UTI_HexToBytes` | [`hex_to_bytes`] |
//!
//! (`UTI_DoubleToNtp32`/`UTI_Ntp32ToDouble` live with the NTP short type in
//! [`crate::ntp::timestamp`]; `UTI_DiffNtp64ToDouble` with the era-safe difference
//! in [`crate::ntp::measurements`].) The broad remainder of `util.c` — file/dir
//! permissions, randomness, socket-address formatting — is out of scope here.

/// `UTI_Log2ToDouble`: `2^l`, with chrony's saturation to `l ∈ [-31, 31]`. Used to
/// turn a log2 polling interval into seconds.
pub fn log2_to_double(l: i32) -> f64 {
    if l >= 0 {
        let l = l.min(31);
        (1u32 << l) as f64
    } else {
        let l = (-l).min(31);
        1.0 / ((1u32 << l) as f64)
    }
}

/// `UTI_IsTimeOffsetSane`: whether `ts` (Unix seconds) plus `offset` is a valid
/// wall-clock time. The offset must be finite and within ±2³², and the resulting
/// time must lie in the NTP-mapped window. With the default build
/// (`NTP_ERA_SPLIT = 0`, 64-bit `time_t`) that window is `[0, 2³²]` seconds since
/// 1970 (years 1970–2106); a non-default era split would shift it.
pub fn is_time_offset_sane(ts: f64, offset: f64) -> bool {
    // chrony's MAX_OFFSET.
    const MAX_OFFSET: f64 = 4_294_967_296.0; // 2^32
    // The `!(…)` form rejects NaN, matching chrony's comment.
    if !(offset > -MAX_OFFSET && offset < MAX_OFFSET) {
        return false;
    }
    let t = ts + offset;
    // Time before 1970, or beyond the NTP era window (split 0 -> [0, 2^32]).
    (0.0..=MAX_OFFSET).contains(&t)
}

/// `UTI_RefidToString`: render a 32-bit reference ID as its printable bytes
/// (MSB first), silently dropping non-printable ones. The inverse-ish of
/// [`crate::cmdparse::parse_refid`]. E.g. `0x47505300` ("GPS\0") → `"GPS"`; the
/// local refclock id `0x7F7F0101` (all non-printable) → `""`.
pub fn refid_to_string(ref_id: u32) -> String {
    let mut s = String::with_capacity(4);
    for i in 0..4 {
        let c = ((ref_id >> (24 - i * 8)) & 0xff) as u8;
        // C `isprint`: the printable ASCII range 0x20..=0x7E.
        if (0x20..=0x7e).contains(&c) {
            s.push(c as char);
        }
    }
    s
}

/// `UTI_BytesToHex`: uppercase, no-separator hex (chrony's `%02hhX` per byte).
pub fn bytes_to_hex(buf: &[u8]) -> String {
    let mut s = String::with_capacity(buf.len() * 2);
    for b in buf {
        // `{:02X}` is exactly chrony's `%02hhX` for an unsigned byte.
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// `UTI_HexToBytes`: parse a contiguous hex string into bytes. Returns `None` for
/// odd length or any non-hex digit (chrony returns 0 = failure in those cases).
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let h = hex.as_bytes();
    if h.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    for pair in h.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log2_to_double_matches_chrony_branches() {
        assert_eq!(log2_to_double(0), 1.0);
        assert_eq!(log2_to_double(6), 64.0); // a typical minpoll
        assert_eq!(log2_to_double(-1), 0.5);
        assert_eq!(log2_to_double(-4), 1.0 / 16.0);
        // Saturation at ±31.
        assert_eq!(log2_to_double(40), (1u32 << 31) as f64);
        assert_eq!(log2_to_double(-40), 1.0 / (1u32 << 31) as f64);
    }

    #[test]
    fn is_time_offset_sane_window() {
        assert!(is_time_offset_sane(1.7e9, 0.0)); // ~2023, valid
        assert!(is_time_offset_sane(0.0, 0.0)); // 1970 boundary
        assert!(!is_time_offset_sane(-1.0, 0.0)); // before 1970
        assert!(!is_time_offset_sane(5e9, 0.0)); // beyond 2^32 (after 2106)
        assert!(!is_time_offset_sane(1.7e9, f64::NAN)); // NaN offset
        assert!(!is_time_offset_sane(1.7e9, 5e9)); // offset out of range
    }

    #[test]
    fn refid_to_string_keeps_printable_bytes() {
        assert_eq!(refid_to_string(0x4750_5300), "GPS"); // trailing NUL dropped
        assert_eq!(refid_to_string(0x4C4F_434C), "LOCL");
        assert_eq!(refid_to_string(0x7F7F_0101), ""); // all non-printable
        assert_eq!(refid_to_string(0x4142_4344), "ABCD");
    }

    #[test]
    fn hex_codec_roundtrips_and_rejects_bad_input() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff, 0x10];
        assert_eq!(bytes_to_hex(&bytes), "000FA5FF10");
        assert_eq!(hex_to_bytes("000FA5FF10").unwrap(), bytes);
        // lowercase accepted on parse
        assert_eq!(hex_to_bytes("deadBEEF").unwrap(), [0xde, 0xad, 0xbe, 0xef]);
        // odd length and non-hex are rejected
        assert!(hex_to_bytes("abc").is_none());
        assert!(hex_to_bytes("zz").is_none());
        assert_eq!(bytes_to_hex(&[]), "");
        assert_eq!(hex_to_bytes("").unwrap(), Vec::<u8>::new());
    }
}
