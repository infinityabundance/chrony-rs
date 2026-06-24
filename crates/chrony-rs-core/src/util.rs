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

const NSEC_PER_SEC: i64 = 1_000_000_000;

/// `UTI_NormaliseTimespec`: carry an out-of-range nanosecond field into the seconds,
/// keeping `0 <= tv_nsec < 1e9`.
pub fn normalise_timespec(mut sec: i64, mut nsec: i64) -> (i64, i64) {
    // chrony: nsec >= NSEC_PER_SEC || nsec < 0.
    if !(0..NSEC_PER_SEC).contains(&nsec) {
        sec += nsec / NSEC_PER_SEC;
        nsec %= NSEC_PER_SEC;
        if nsec < 0 {
            sec -= 1;
            nsec += NSEC_PER_SEC;
        }
    }
    (sec, nsec)
}

/// `UTI_TimespecToDouble`: `sec + 1e-9 * nsec`.
pub fn timespec_to_double(sec: i64, nsec: i64) -> f64 {
    sec as f64 + 1.0e-9 * nsec as f64
}

/// `UTI_DoubleToTimespec`: split `d` into a normalised `(sec, nsec)` with chrony's
/// `(time_t)`/`(long)` truncation.
pub fn double_to_timespec(d: f64) -> (i64, i64) {
    let sec = d as i64;
    let nsec = (1.0e9 * (d - sec as f64)) as i64;
    normalise_timespec(sec, nsec)
}

/// `UTI_NormaliseTimeval`: reduce `tv_usec` to `[0, 1e6)`. (Note chrony's `>=`/`<=`
/// reduction bound, distinct from the timespec form.)
pub fn normalise_timeval(mut sec: i64, mut usec: i64) -> (i64, i64) {
    if usec >= 1_000_000 || usec <= -1_000_000 {
        sec += usec / 1_000_000;
        usec %= 1_000_000;
    }
    if usec < 0 {
        sec -= 1;
        usec += 1_000_000;
    }
    (sec, usec)
}

/// `UTI_TimevalToDouble`: `sec + 1e-6 * usec`.
pub fn timeval_to_double(sec: i64, usec: i64) -> f64 {
    sec as f64 + 1.0e-6 * usec as f64
}

/// `UTI_DoubleToTimeval`: split `d` into a normalised `(sec, usec)`; the microseconds are
/// rounded (chrony's `round()`).
pub fn double_to_timeval(d: f64) -> (i64, i64) {
    let sec = d as i64;
    let usec = (1.0e6 * (d - sec as f64)).round() as i64;
    normalise_timeval(sec, usec)
}

/// chrony `MAX_NTP_INT32` (the 16.16 NTP-short maximum, also returned by the f28 max).
const MAX_NTP_INT32: f64 = 4_294_967_295.0 / 65536.0;

/// `UTI_DoubleToNtp32f28`: seconds to 4.28 fixed point (host-order raw value).
pub fn double_to_ntp32f28(x: f64) -> u32 {
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

/// `UTI_Ntp32f28ToDouble`: 4.28 fixed point (host-order raw) to seconds. The all-ones
/// value is special-cased to `MAX_NTP_INT32` (matching chrony).
pub fn ntp32f28_to_double(r: u32) -> f64 {
    if r == 0xffff_ffff {
        MAX_NTP_INT32
    } else {
        r as f64 / (1u32 << 28) as f64
    }
}

/// `UTI_IsZeroNtp64`: whether both halves of the 64-bit NTP timestamp are zero.
pub fn is_zero_ntp64(hi: u32, lo: u32) -> bool {
    hi == 0 && lo == 0
}

/// `UTI_CompareNtp64`: order two 64-bit NTP timestamps by their host-order halves
/// (`-1`/`0`/`1`).
pub fn compare_ntp64(a_hi: u32, a_lo: u32, b_hi: u32, b_lo: u32) -> i32 {
    if a_hi == b_hi && a_lo == b_lo {
        return 0;
    }
    let diff = (a_hi as i32).wrapping_sub(b_hi as i32);
    if diff < 0 {
        -1
    } else if diff > 0 {
        1
    } else if a_lo < b_lo {
        -1
    } else {
        1
    }
}

/// `UTI_IsEqualAnyNtp64`: whether `a` equals any of `b1`/`b2`/`b3` (each optional, as
/// chrony skips `NULL` operands).
pub fn is_equal_any_ntp64(
    a: (u32, u32),
    b1: Option<(u32, u32)>,
    b2: Option<(u32, u32)>,
    b3: Option<(u32, u32)>,
) -> bool {
    [b1, b2, b3].into_iter().flatten().any(|b| b == a)
}

/// `UTI_CompareTimespecs`: order two timespecs by seconds then nanoseconds (`-1`/`0`/`1`).
pub fn compare_timespecs(a: (i64, i64), b: (i64, i64)) -> i32 {
    if a.0 < b.0 {
        -1
    } else if a.0 > b.0 {
        1
    } else if a.1 < b.1 {
        -1
    } else if a.1 > b.1 {
        1
    } else {
        0
    }
}

/// `UTI_DiffTimespecsToDouble`: `a - b` in seconds.
pub fn diff_timespecs_to_double(a: (i64, i64), b: (i64, i64)) -> f64 {
    (a.0 as f64 - b.0 as f64) + 1.0e-9 * (a.1 - b.1) as f64
}

/// `UTI_DiffTimespecs`: `a - b` as a normalised timespec.
pub fn diff_timespecs(a: (i64, i64), b: (i64, i64)) -> (i64, i64) {
    normalise_timespec(a.0 - b.0, a.1 - b.1)
}

/// `UTI_AddDoubleToTimespec`: `start + increment` seconds, with chrony's `(time_t)`
/// truncation of the integer part.
pub fn add_double_to_timespec(start: (i64, i64), increment: f64) -> (i64, i64) {
    let int_part = increment as i64;
    let sec = start.0 + int_part;
    let nsec = start.1 + (1.0e9 * (increment - int_part as f64)) as i64;
    normalise_timespec(sec, nsec)
}

/// `UTI_AddDiffToTimespec`: `c + (a - b)` (the difference taken as a double).
pub fn add_diff_to_timespec(a: (i64, i64), b: (i64, i64), c: (i64, i64)) -> (i64, i64) {
    add_double_to_timespec(c, diff_timespecs_to_double(a, b))
}

/// `UTI_TimevalToTimespec`: microseconds to nanoseconds.
pub fn timeval_to_timespec(sec: i64, usec: i64) -> (i64, i64) {
    (sec, 1000 * usec)
}

/// `UTI_TimespecToTimeval`: nanoseconds to microseconds (truncating).
pub fn timespec_to_timeval(sec: i64, nsec: i64) -> (i64, i64) {
    (sec, nsec / 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(line: &'a str, key: &str) -> &'a str {
        line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
    }

    #[test]
    fn matches_real_c_time_conversions() {
        let v = include_str!("../../../research/oracle/util-time-c-vectors.txt");
        let line = |tag: &str| v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap();

        // DoubleToTimespec / TimespecToDouble round trips.
        for tag in ["TS_POS", "TS_FRAC", "TS_NEG", "TS_ZERO"] {
            let l = line(tag);
            let (sec, nsec) = double_to_timespec(field(l, "in").parse().unwrap());
            assert_eq!(sec, field(l, "sec").parse::<i64>().unwrap(), "{tag} sec");
            assert_eq!(nsec, field(l, "nsec").parse::<i64>().unwrap(), "{tag} nsec");
            assert_eq!(timespec_to_double(sec, nsec), field(l, "back").parse::<f64>().unwrap(), "{tag} back");
        }
        // DoubleToTimeval / TimevalToDouble round trips.
        for tag in ["TV_POS", "TV_FRAC", "TV_NEG"] {
            let l = line(tag);
            let (sec, usec) = double_to_timeval(field(l, "in").parse().unwrap());
            assert_eq!(sec, field(l, "sec").parse::<i64>().unwrap(), "{tag} sec");
            assert_eq!(usec, field(l, "usec").parse::<i64>().unwrap(), "{tag} usec");
            assert_eq!(timeval_to_double(sec, usec), field(l, "back").parse::<f64>().unwrap(), "{tag} back");
        }
        // f28 fixed point.
        for tag in ["F28_SMALL", "F28_ONE", "F28_NEG", "F28_BIG"] {
            let l = line(tag);
            let raw = double_to_ntp32f28(field(l, "in").parse().unwrap());
            assert_eq!(raw, field(l, "raw").parse::<u32>().unwrap(), "{tag} raw");
            assert_eq!(ntp32f28_to_double(raw), field(l, "back").parse::<f64>().unwrap(), "{tag} back");
        }
        // CompareNtp64 / IsZeroNtp64.
        assert_eq!(compare_ntp64(5, 10, 5, 10), field(line("CMP_EQ"), "r").parse::<i32>().unwrap());
        assert_eq!(compare_ntp64(5, 10, 5, 11), field(line("CMP_LO"), "r").parse::<i32>().unwrap());
        assert_eq!(compare_ntp64(6, 0, 5, 10), field(line("CMP_HI"), "r").parse::<i32>().unwrap());
        assert_eq!(is_zero_ntp64(0, 0) as i32, field(line("ISZERO_Y"), "r").parse::<i32>().unwrap());
        assert_eq!(is_zero_ntp64(5, 10) as i32, field(line("ISZERO_N"), "r").parse::<i32>().unwrap());
    }

    #[test]
    fn matches_real_c_timespec_arithmetic() {
        let v = include_str!("../../../research/oracle/util-time-c-vectors.txt");
        let line = |tag: &str| v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap();

        // IsEqualAnyNtp64: same values the C oracle used (a=5:10, b=5:10, c=5:11, d=6:0, z=0:0).
        let (a, b, c, d, z) = ((5, 10), (5, 10), (5, 11), (6, 0), (0, 0));
        assert_eq!(
            is_equal_any_ntp64(a, Some(b), Some(c), Some(d)) as i32,
            field(line("EQANY_B1"), "r").parse::<i32>().unwrap()
        );
        assert_eq!(
            is_equal_any_ntp64(d, Some(c), Some(z), Some(d)) as i32,
            field(line("EQANY_B3"), "r").parse::<i32>().unwrap()
        );
        assert_eq!(
            is_equal_any_ntp64(a, Some(c), Some(d), Some(z)) as i32,
            field(line("EQANY_NONE"), "r").parse::<i32>().unwrap()
        );
        assert_eq!(
            is_equal_any_ntp64(a, None, None, None) as i32,
            field(line("EQANY_NULLS"), "r").parse::<i32>().unwrap()
        );

        // CompareTimespecs: p=100:5e8, q=100:2e8, rr=50:9e8.
        let (p, q, rr) = ((100i64, 500000000i64), (100i64, 200000000i64), (50i64, 900000000i64));
        assert_eq!(compare_timespecs(p, q), field(line("CMPTS_GT"), "r").parse::<i32>().unwrap());
        assert_eq!(compare_timespecs(q, p), field(line("CMPTS_LT"), "r").parse::<i32>().unwrap());
        assert_eq!(compare_timespecs(p, p), field(line("CMPTS_EQ"), "r").parse::<i32>().unwrap());

        // DiffTimespecs (p - rr) plus DiffTimespecsToDouble.
        let l = line("DIFFTS");
        let (ds, dn) = diff_timespecs(p, rr);
        assert_eq!(ds, field(l, "sec").parse::<i64>().unwrap(), "DIFFTS sec");
        assert_eq!(dn, field(l, "nsec").parse::<i64>().unwrap(), "DIFFTS nsec");
        assert_eq!(diff_timespecs_to_double(p, rr), field(l, "d").parse::<f64>().unwrap(), "DIFFTS d");

        // AddDoubleToTimespec(q, 1.75).
        let l = line("ADDDBL");
        let (asec, ansec) = add_double_to_timespec(q, 1.75);
        assert_eq!(asec, field(l, "sec").parse::<i64>().unwrap(), "ADDDBL sec");
        assert_eq!(ansec, field(l, "nsec").parse::<i64>().unwrap(), "ADDDBL nsec");

        // AddDiffToTimespec(p, rr, q) = q + (p - rr).
        let l = line("ADDDIFF");
        let (fsec, fnsec) = add_diff_to_timespec(p, rr, q);
        assert_eq!(fsec, field(l, "sec").parse::<i64>().unwrap(), "ADDDIFF sec");
        assert_eq!(fnsec, field(l, "nsec").parse::<i64>().unwrap(), "ADDDIFF nsec");

        // timeval <-> timespec.
        let l = line("TV2TS");
        let (tsec, tnsec) = timeval_to_timespec(123, 456789);
        assert_eq!(tsec, field(l, "sec").parse::<i64>().unwrap(), "TV2TS sec");
        assert_eq!(tnsec, field(l, "nsec").parse::<i64>().unwrap(), "TV2TS nsec");
        let l = line("TS2TV");
        let (vsec, vusec) = timespec_to_timeval(123, 456789999);
        assert_eq!(vsec, field(l, "sec").parse::<i64>().unwrap(), "TS2TV sec");
        assert_eq!(vusec, field(l, "usec").parse::<i64>().unwrap(), "TS2TV usec");
    }

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
