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

/// chrony's `NTP_ERA_SPLIT`: the configure-time constant (`--with-ntp-era`, in seconds
/// since 1970) that anchors the 32-bit NTP timestamp window for the `HAVE_LONG_TIME_T`
/// build. Production 64-bit builds derive it from the build date (`build_epoch − 50 yr`),
/// so it is a per-build constant rather than a universal value; this reconstruction pins
/// the era-split-0 configuration (a valid, reproducible build via `--with-ntp-era=0`).
/// Functions that depend on it take it as an explicit parameter so any build can be
/// modelled.
pub const NTP_ERA_SPLIT: i64 = 0;

/// `UTI_IsTimeOffsetSane`: whether `ts` (Unix seconds) plus `offset` is a valid
/// wall-clock time, for the `HAVE_LONG_TIME_T` (64-bit `time_t`) build. The offset must
/// be finite and within ±2³², the time must not predate 1970, and it must lie in the
/// NTP-mapped window `[ntp_era_split, ntp_era_split + 2³²]`. With `ntp_era_split = 0`
/// that window is `[0, 2³²]` (years 1970–2106).
pub fn is_time_offset_sane(ts: f64, offset: f64, ntp_era_split: i64) -> bool {
    // chrony's MAX_OFFSET.
    const MAX_OFFSET: f64 = 4_294_967_296.0; // 2^32
    // The `!(…)` form rejects NaN, matching chrony's comment.
    if !(offset > -MAX_OFFSET && offset < MAX_OFFSET) {
        return false;
    }
    let t = ts + offset;
    // Time before 1970 is not considered valid.
    if t < 0.0 {
        return false;
    }
    // HAVE_LONG_TIME_T: the interval to which NTP time is mapped.
    let split = ntp_era_split as f64;
    !(t < split || t > split + MAX_OFFSET)
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

/// chrony `JAN_1970`: seconds between the NTP epoch (1900) and the Unix epoch (1970).
const JAN_1970: u32 = 0x83aa_7e80;
/// chrony `NSEC_PER_NTP64` = `2³² / 1e9`, so `nanoseconds × NSEC_PER_NTP64` is an NTP
/// 32-bit fraction.
const NSEC_PER_NTP64: f64 = 4.294_967_296;

/// `UTI_ZeroNtp64`: the all-zero 64-bit NTP timestamp (chrony's "unknown" sentinel),
/// as host-order `(hi, lo)`.
pub fn zero_ntp64() -> (u32, u32) {
    (0, 0)
}

/// `UTI_ZeroTimespec`: the all-zero timespec, as `(sec, nsec)`.
pub fn zero_timespec() -> (i64, i64) {
    (0, 0)
}

/// `UTI_IsZeroTimespec`: whether both fields of the timespec are zero.
pub fn is_zero_timespec(sec: i64, nsec: i64) -> bool {
    sec == 0 && nsec == 0
}

/// `UTI_TimespecToNtp64`: convert a timespec to a 64-bit NTP timestamp (host-order
/// `(hi, lo)`). Zero maps to zero (chrony's "unknown" sentinel). The seconds field is
/// taken modulo 2³² (`(uint32_t)tv_sec`), so this forward direction is independent of
/// `time_t` width / NTP era split. An optional `fuzz` is XORed into the result, exactly
/// as chrony adds sub-precision randomness; the XOR commutes with byte order, so it is
/// applied to the host-order halves here.
pub fn timespec_to_ntp64(sec: i64, nsec: i64, fuzz: Option<(u32, u32)>) -> (u32, u32) {
    let sec = sec as u32;
    let nsec = nsec as u32;
    // Recognize zero as a special case - it always signifies an 'unknown' value.
    if nsec == 0 && sec == 0 {
        return (0, 0);
    }
    let mut hi = sec.wrapping_add(JAN_1970);
    let mut lo = (NSEC_PER_NTP64 * nsec as f64) as u32;
    if let Some((fhi, flo)) = fuzz {
        hi ^= fhi;
        lo ^= flo;
    }
    (hi, lo)
}

/// `UTI_AverageDiffTimespecs`: returns `(average, diff)` where `diff = later - earlier`
/// (seconds) and `average = earlier + diff/2`.
pub fn average_diff_timespecs(earlier: (i64, i64), later: (i64, i64)) -> ((i64, i64), f64) {
    let diff = diff_timespecs_to_double(later, earlier);
    let average = add_double_to_timespec(earlier, diff / 2.0);
    (average, diff)
}

/// `UTI_AdjustTimespec`: project `old_ts` forward by a frequency/offset adjustment over
/// the elapsed time to `when`. Returns `(new_ts, delta_time)` where
/// `delta_time = elapsed × dfreq − doffset` and `new_ts = old_ts + delta_time`.
pub fn adjust_timespec(
    old_ts: (i64, i64),
    when: (i64, i64),
    dfreq: f64,
    doffset: f64,
) -> ((i64, i64), f64) {
    let elapsed = diff_timespecs_to_double(when, old_ts);
    let delta_time = elapsed * dfreq - doffset;
    let new_ts = add_double_to_timespec(old_ts, delta_time);
    (new_ts, delta_time)
}

/// `UTI_Integer64HostToNetwork`: split a 64-bit integer into chrony's wire `Integer64`
/// `(high, low)` 32-bit halves. Returned in host order (the values `ntohl` would yield
/// from the on-wire struct), making the representation byte-order independent.
pub fn integer64_host_to_network(i: u64) -> (u32, u32) {
    ((i >> 32) as u32, i as u32)
}

/// `UTI_Integer64NetworkToHost`: recombine chrony's wire `Integer64` `(high, low)` halves
/// (host order) into a 64-bit integer. Inverse of [`integer64_host_to_network`].
pub fn integer64_network_to_host(high: u32, low: u32) -> u64 {
    (high as u64) << 32 | low as u64
}

// chrony's custom 32-bit wire float: a 7-bit signed exponent and a 25-bit signed
// coefficient (no hidden bit). Value = coef × 2^(exp − 25). See candm.h `Float`.
const FLOAT_EXP_BITS: i32 = 7;
const FLOAT_EXP_MIN: i32 = -(1 << (FLOAT_EXP_BITS - 1)); // -64
const FLOAT_EXP_MAX: i32 = -FLOAT_EXP_MIN - 1; // 63
const FLOAT_COEF_BITS: i32 = 32 - FLOAT_EXP_BITS; // 25
const FLOAT_COEF_MIN: i32 = -(1 << (FLOAT_COEF_BITS - 1)); // -2^24
const FLOAT_COEF_MAX: i32 = -FLOAT_COEF_MIN - 1; // 2^24 - 1

/// `UTI_FloatNetworkToHost`: decode chrony's custom 32-bit wire float (host-order raw
/// `word`) to a `f64`.
pub fn float_network_to_host(word: u32) -> f64 {
    let x = word;
    let mut exp = (x >> FLOAT_COEF_BITS) as i32;
    if exp >= 1 << (FLOAT_EXP_BITS - 1) {
        exp -= 1 << FLOAT_EXP_BITS;
    }
    exp -= FLOAT_COEF_BITS;

    let mut coef = (x % (1u32 << FLOAT_COEF_BITS)) as i32;
    if coef >= 1 << (FLOAT_COEF_BITS - 1) {
        coef -= 1 << FLOAT_COEF_BITS;
    }

    coef as f64 * 2.0f64.powi(exp)
}

/// `UTI_FloatHostToNetwork`: encode a `f64` into chrony's custom 32-bit wire float,
/// returned as the host-order raw 32-bit `word` (the value `ntohl` would yield from the
/// on-wire `Float`). NaN is saved as zero; values saturate to the format's range.
pub fn float_host_to_network(x: f64) -> u32 {
    let mut x = x;
    let neg;
    if x < 0.0 {
        x = -x;
        neg = 1;
    } else if x >= 0.0 {
        neg = 0;
    } else {
        // Save NaN as zero.
        x = 0.0;
        neg = 0;
    }

    let mut exp: i32;
    let mut coef: i32;
    if x < 1.0e-100 {
        exp = 0;
        coef = 0;
    } else if x > 1.0e100 {
        exp = FLOAT_EXP_MAX;
        coef = FLOAT_COEF_MAX + neg;
    } else {
        exp = (x.ln() / 2.0f64.ln()) as i32 + 1;
        coef = (x * 2.0f64.powi(-exp + FLOAT_COEF_BITS) + 0.5) as i32;

        debug_assert!(coef > 0);

        // We may need to shift up to two bits down.
        while coef > FLOAT_COEF_MAX + neg {
            coef >>= 1;
            exp += 1;
        }

        if exp > FLOAT_EXP_MAX {
            // Overflow.
            exp = FLOAT_EXP_MAX;
            coef = FLOAT_COEF_MAX + neg;
        } else if exp < FLOAT_EXP_MIN {
            // Underflow.
            if exp + FLOAT_COEF_BITS >= FLOAT_EXP_MIN {
                coef >>= FLOAT_EXP_MIN - exp;
                exp = FLOAT_EXP_MIN;
            } else {
                exp = 0;
                coef = 0;
            }
        }
    }

    // Negate back.
    if neg != 0 {
        // chrony: (uint32_t)-coef << FLOAT_EXP_BITS >> FLOAT_EXP_BITS — mask to coef bits.
        coef = (((-(coef as i64) as u32) << FLOAT_EXP_BITS) >> FLOAT_EXP_BITS) as i32;
    }

    (exp as u32) << FLOAT_COEF_BITS | (coef as u32 & ((1u32 << FLOAT_COEF_BITS) - 1))
}

/// chrony's `TV_NOHIGHSEC`: the `tv_sec_high` sentinel a 32-bit-`time_t` sender writes,
/// which a 64-bit receiver treats as a zero high word.
const TV_NOHIGHSEC: u32 = 0x7fff_ffff;

/// `UTI_Ntp64ToTimespec` (`HAVE_LONG_TIME_T` build): convert a 64-bit NTP timestamp
/// (host-order `(hi, lo)`) to a Unix timespec `(sec, nsec)`. Zero maps to zero (the
/// "unknown" sentinel). The seconds map through the era split: the `(uint32_t)`
/// subtraction wraps modulo 2³² before being widened to `time_t` and re-anchored at
/// `ntp_era_split`, exactly as chrony does — `ntp_era_split` is the configure-time
/// [`NTP_ERA_SPLIT`] constant.
pub fn ntp64_to_timespec(hi: u32, lo: u32, ntp_era_split: i64) -> (i64, i64) {
    if is_zero_ntp64(hi, lo) {
        return zero_timespec();
    }
    let ntp_sec = hi;
    let ntp_frac = lo;
    // chrony: ntp_sec - (uint32_t)(NTP_ERA_SPLIT + JAN_1970) + (time_t)NTP_ERA_SPLIT.
    // The subtraction is in uint32 (wrapping), then widened to time_t.
    let split_plus = ntp_era_split.wrapping_add(JAN_1970 as i64) as u32;
    let tv_sec = ntp_sec.wrapping_sub(split_plus) as i64 + ntp_era_split;
    let tv_nsec = (ntp_frac as f64 / NSEC_PER_NTP64) as i64;
    (tv_sec, tv_nsec)
}

/// `UTI_TimespecHostToNetwork` (`HAVE_LONG_TIME_T` build): serialize a Unix timespec
/// `(sec, nsec)` into chrony's wire `Timespec` halves, returned host-order as
/// `(tv_sec_high, tv_sec_low, tv_nsec)` (the values `ntohl` would yield from the on-wire
/// struct). `tv_sec_high` carries the seconds above 2³².
pub fn timespec_host_to_network(sec: i64, nsec: i64) -> (u32, u32, u32) {
    let tv_nsec = nsec as u32;
    let tv_sec_high = ((sec as u64) >> 32) as u32;
    let tv_sec_low = sec as u32;
    (tv_sec_high, tv_sec_low, tv_nsec)
}

/// `UTI_TimespecNetworkToHost` (`HAVE_LONG_TIME_T` build): deserialize chrony's wire
/// `Timespec` halves (host-order `tv_sec_high`/`tv_sec_low`/`tv_nsec`) into a Unix
/// timespec `(sec, nsec)`. A `tv_sec_high` of [`TV_NOHIGHSEC`] (a 32-bit sender) is read
/// as zero, and `tv_nsec` is clamped to `999_999_999`.
pub fn timespec_network_to_host(tv_sec_high: u32, tv_sec_low: u32, tv_nsec: u32) -> (i64, i64) {
    let sec_low = tv_sec_low;
    let mut sec_high = tv_sec_high;
    if sec_high == TV_NOHIGHSEC {
        sec_high = 0;
    }
    let tv_sec = ((sec_high as u64) << 32 | sec_low as u64) as i64;
    let tv_nsec = tv_nsec.min(999_999_999) as i64;
    (tv_sec, tv_nsec)
}

/// chrony's `IPAddr` (addressing.h): a tagged address that is one of unspecified, IPv4
/// (host-order `u32`), IPv6 (16 raw bytes), or a synthetic numeric id. The family tags
/// match chrony's `IPADDR_*` constants (`UNSPEC=0`, `INET4=1`, `INET6=2`, `ID=3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddr {
    /// `IPADDR_UNSPEC`.
    Unspec,
    /// `IPADDR_INET4`: an IPv4 address in host byte order.
    Inet4(u32),
    /// `IPADDR_INET6`: the 16 address bytes, network order (as stored on the wire).
    Inet6([u8; 16]),
    /// `IPADDR_ID`: a synthetic numeric source id.
    Id(u32),
}

impl IpAddr {
    /// The chrony `IPADDR_*` family tag.
    pub fn family(&self) -> u16 {
        match self {
            IpAddr::Unspec => 0,
            IpAddr::Inet4(_) => 1,
            IpAddr::Inet6(_) => 2,
            IpAddr::Id(_) => 3,
        }
    }
}

/// `UTI_IsIPReal`: whether the address is a real (routable) IP — i.e. INET4 or INET6,
/// not the unspecified or synthetic-id pseudo-families.
pub fn is_ip_real(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::Inet4(_) | IpAddr::Inet6(_))
}

/// `UTI_CompareIPs`: chrony's address ordering. Returns the raw integer difference (NOT
/// clamped to -1/0/1), reproducing the C subtraction semantics exactly — including the
/// signed wraparound of the IPv4/id `uint32` subtraction and the first-differing-byte
/// difference for IPv6. Different families compare by family tag. An optional `mask` is
/// ignored unless its family matches `b`'s.
pub fn compare_ips(a: &IpAddr, b: &IpAddr, mask: Option<&IpAddr>) -> i32 {
    if a.family() != b.family() {
        return a.family() as i32 - b.family() as i32;
    }
    // chrony drops the mask if its family doesn't match b's.
    let mask = mask.filter(|m| m.family() == b.family());
    match (a, b) {
        (IpAddr::Unspec, _) => 0,
        (IpAddr::Inet4(x), IpAddr::Inet4(y)) => match mask {
            Some(IpAddr::Inet4(m)) => (x & m).wrapping_sub(y & m) as i32,
            _ => x.wrapping_sub(*y) as i32,
        },
        (IpAddr::Inet6(x), IpAddr::Inet6(y)) => {
            let mut d = 0i32;
            let mut i = 0;
            while d == 0 && i < 16 {
                d = match mask {
                    Some(IpAddr::Inet6(m)) => (x[i] & m[i]) as i32 - (y[i] & m[i]) as i32,
                    _ => x[i] as i32 - y[i] as i32,
                };
                i += 1;
            }
            d
        }
        (IpAddr::Id(x), IpAddr::Id(y)) => x.wrapping_sub(*y) as i32,
        _ => 0,
    }
}

/// `UTI_IPHostToNetwork`: serialize an `IPAddr` into chrony's 20-byte on-wire image
/// (`sizeof(IPAddr)`): the 16-byte address region, then the family as a big-endian
/// `u16`, then a zero `_pad`. Uninitialized bytes are zeroed, exactly as chrony does to
/// avoid leaking stack contents. The IPv4/id value goes out in network byte order.
pub fn ip_host_to_network(ip: &IpAddr) -> [u8; 20] {
    let mut w = [0u8; 20];
    w[16..18].copy_from_slice(&ip.family().to_be_bytes());
    match ip {
        IpAddr::Inet4(v) | IpAddr::Id(v) => w[0..4].copy_from_slice(&v.to_be_bytes()),
        IpAddr::Inet6(b) => w[0..16].copy_from_slice(b),
        IpAddr::Unspec => {}
    }
    w
}

/// `UTI_IPNetworkToHost`: deserialize chrony's 20-byte on-wire `IPAddr` image. An
/// unrecognized family decodes to [`IpAddr::Unspec`].
pub fn ip_network_to_host(wire: &[u8; 20]) -> IpAddr {
    let family = u16::from_be_bytes([wire[16], wire[17]]);
    let v = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]);
    match family {
        1 => IpAddr::Inet4(v),
        2 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&wire[0..16]);
            IpAddr::Inet6(b)
        }
        3 => IpAddr::Id(v),
        _ => IpAddr::Unspec,
    }
}

/// `UTI_CmacNameToAlgorithm`: map a CMAC algorithm name to chrony's `CMC_Algorithm`
/// value, `CMC_INVALID` (0) if unknown.
pub fn cmac_name_to_algorithm(name: &str) -> i32 {
    match name {
        "AES128" => 13, // CMC_AES128
        "AES256" => 14, // CMC_AES256
        _ => 0,         // CMC_INVALID
    }
}

/// `UTI_HashNameToAlgorithm`: map a hash algorithm name to chrony's `HSH_Algorithm`
/// value, `HSH_INVALID` (0) if unknown.
pub fn hash_name_to_algorithm(name: &str) -> i32 {
    match name {
        "MD5" => 1,
        "SHA1" => 2,
        "SHA256" => 3,
        "SHA384" => 4,
        "SHA512" => 5,
        "SHA3-224" => 6,
        "SHA3-256" => 7,
        "SHA3-384" => 8,
        "SHA3-512" => 9,
        "TIGER" => 10,
        "WHIRLPOOL" => 11,
        _ => 0, // HSH_INVALID
    }
}

/// `UTI_TimespecToString`: render a timespec as `seconds.nanoseconds`, the nanoseconds
/// zero-padded to 9 digits, for diagnostic display. The seconds keep their sign; the
/// nanoseconds are formatted unsigned (chrony's `(unsigned long)`).
pub fn timespec_to_string(sec: i64, nsec: i64) -> String {
    format!("{}.{:09}", sec, nsec as u64)
}

/// `UTI_Ntp64ToString`: render a 64-bit NTP timestamp as a diagnostic string by mapping
/// it to a timespec ([`ntp64_to_timespec`], so era-split-aware) and formatting that via
/// [`timespec_to_string`].
pub fn ntp64_to_string(hi: u32, lo: u32, ntp_era_split: i64) -> String {
    let (sec, nsec) = ntp64_to_timespec(hi, lo, ntp_era_split);
    timespec_to_string(sec, nsec)
}

/// Civil date `(year, month, day)` from a count of days since 1970-01-01 (Howard
/// Hinnant's algorithm), matching `gmtime`'s proleptic-Gregorian calendar.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (y + i64::from(m <= 2), m as u32, d as u32)
}

/// `UTI_TimeToLogForm`: format a Unix time (UTC) as `"%Y-%m-%d %H:%M:%S"`, matching
/// chrony's `gmtime` + `strftime`. Years are rendered with at least four digits (chrony
/// never logs years before 1000, where `strftime`'s `%Y` would differ).
pub fn time_to_log_form(t: i64) -> String {
    // gmtime: floor-divide into whole days and the second-of-day, for negative t too.
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs / 3600;
    let min = (secs % 3600) / 60;
    let sec = secs % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
}

/// `UTI_PathToDir`: the directory part of a path (a `dirname`-like split on the last
/// `/`). No slash → `"."`; a single leading slash → `"/"`; otherwise the prefix before
/// the last slash.
pub fn path_to_dir(path: &str) -> String {
    match path.rfind('/') {
        None => ".".to_string(),
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
}

/// `UTI_SplitString`: split on runs of ASCII whitespace, returning the words and the
/// total word count. chrony fills a caller buffer of `max_saved_words` and returns the
/// full count (which may exceed it), so the returned `Vec` is capped at `max_saved_words`
/// while the count is not.
pub fn split_string(string: &str, max_saved_words: usize) -> (Vec<String>, usize) {
    let mut words = Vec::new();
    let mut count = 0;
    // chrony uses C isspace: space, \t, \n, \v, \f, \r.
    for word in string.split([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']) {
        if word.is_empty() {
            continue;
        }
        if count < max_saved_words {
            words.push(word.to_string());
        }
        count += 1;
    }
    (words, count)
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
    fn matches_real_c_ntp64_wire_serialization() {
        let v = include_str!("../../../research/oracle/util-time-c-vectors.txt");
        let line = |tag: &str| v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap();

        // ZeroNtp64 / ZeroTimespec.
        let l = line("ZNTP64");
        assert_eq!(zero_ntp64(), (field(l, "hi").parse().unwrap(), field(l, "lo").parse().unwrap()));
        let l = line("ZTS");
        assert_eq!(zero_timespec(), (field(l, "sec").parse().unwrap(), field(l, "nsec").parse().unwrap()));

        // IsZeroTimespec.
        assert_eq!(is_zero_timespec(0, 0) as i32, field(line("ISZTS_ZZ"), "r").parse::<i32>().unwrap());
        assert_eq!(is_zero_timespec(0, 5) as i32, field(line("ISZTS_ZN"), "r").parse::<i32>().unwrap());
        assert_eq!(is_zero_timespec(5, 0) as i32, field(line("ISZTS_SZ"), "r").parse::<i32>().unwrap());

        // TimespecToNtp64: plain, zero, and with fuzz XOR (fuzz = 0xdeadbeef:0x12345678).
        let l = line("TS2N_POS");
        assert_eq!(
            timespec_to_ntp64(1234, 500000000, None),
            (field(l, "hi").parse().unwrap(), field(l, "lo").parse().unwrap())
        );
        let l = line("TS2N_ZERO");
        assert_eq!(
            timespec_to_ntp64(0, 0, None),
            (field(l, "hi").parse().unwrap(), field(l, "lo").parse().unwrap())
        );
        let l = line("TS2N_FUZZ");
        assert_eq!(
            timespec_to_ntp64(1234, 500000000, Some((0xdead_beef, 0x1234_5678))),
            (field(l, "hi").parse().unwrap(), field(l, "lo").parse().unwrap())
        );

        // AverageDiffTimespecs (earlier=100:2e8, later=103:7e8).
        let l = line("AVGDIFF");
        let ((asec, ansec), diff) = average_diff_timespecs((100, 200000000), (103, 700000000));
        assert_eq!(asec, field(l, "sec").parse::<i64>().unwrap(), "AVGDIFF sec");
        assert_eq!(ansec, field(l, "nsec").parse::<i64>().unwrap(), "AVGDIFF nsec");
        assert_eq!(diff, field(l, "diff").parse::<f64>().unwrap(), "AVGDIFF diff");

        // AdjustTimespec (old=1000:0, when=1010:0, dfreq=1e-5, doffset=0.5).
        let l = line("ADJ");
        let ((nsec_s, nsec_n), delta) = adjust_timespec((1000, 0), (1010, 0), 1.0e-5, 0.5);
        assert_eq!(nsec_s, field(l, "sec").parse::<i64>().unwrap(), "ADJ sec");
        assert_eq!(nsec_n, field(l, "nsec").parse::<i64>().unwrap(), "ADJ nsec");
        assert_eq!(delta, field(l, "delta").parse::<f64>().unwrap(), "ADJ delta");

        // Integer64 host<->network round trip (i = 0x123456789abcdef0).
        let l = line("I64");
        let (high, low) = integer64_host_to_network(0x1234_5678_9abc_def0);
        assert_eq!(high, field(l, "hi").parse::<u32>().unwrap(), "I64 hi");
        assert_eq!(low, field(l, "lo").parse::<u32>().unwrap(), "I64 lo");
        assert_eq!(
            integer64_network_to_host(high, low),
            field(l, "back").parse::<u64>().unwrap(),
            "I64 back"
        );

        // Float host<->network: chrony's custom 7-exp/25-coef wire float.
        let cases = [
            ("FLT_ZERO", 0.0),
            ("FLT_ONE", 1.0),
            ("FLT_NEGONE", -1.0),
            ("FLT_HALF", 0.5),
            ("FLT_NEGHALF", -0.5),
            ("FLT_BIG", 1234.5),
            ("FLT_NEGBIG", -1234.5),
            ("FLT_TINY", 1.0e-9),
            ("FLT_PI", 3.141_592_653_589_79),
            ("FLT_UNDER", 1.0e-120),
            ("FLT_OVER", 1.0e120),
            ("FLT_NEGOVER", -1.0e120),
            ("FLT_NEARMAX", 65535.99),
            ("FLT_POW2", 0.001953125),
        ];
        for (tag, x) in cases {
            let l = line(tag);
            let raw = float_host_to_network(x);
            assert_eq!(raw, field(l, "raw").parse::<u32>().unwrap(), "{tag} raw");
            assert_eq!(
                float_network_to_host(raw),
                field(l, "back").parse::<f64>().unwrap(),
                "{tag} back"
            );
        }
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
        // Era-split-0 build: window [0, 2^32].
        assert!(is_time_offset_sane(1.7e9, 0.0, 0)); // ~2023, valid
        assert!(is_time_offset_sane(0.0, 0.0, 0)); // split boundary
        assert!(!is_time_offset_sane(-1.0, 0.0, 0)); // before 1970
        assert!(!is_time_offset_sane(5e9, 0.0, 0)); // beyond 2^32 (after 2106)
        assert!(!is_time_offset_sane(1.7e9, f64::NAN, 0)); // NaN offset
        assert!(!is_time_offset_sane(1.7e9, 5e9, 0)); // offset out of range
    }

    #[test]
    fn matches_real_c_era_split_conversions() {
        // Oracle built with HAVE_LONG_TIME_T and a pinned NTP_ERA_SPLIT (see genera.c).
        let v = include_str!("../../../research/oracle/util-era-c-vectors.txt");
        let line = |tag: &str| v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap();
        let split: i64 = field(line("ERA_SPLIT"), "v").parse().unwrap();
        let jan_1970: u32 = field(line("JAN_1970"), "v").parse().unwrap();
        assert_eq!(split, 123_200_000);
        assert_eq!(jan_1970, JAN_1970);

        // Ntp64ToTimespec.
        let l = line("N2TS_ZERO");
        assert_eq!(
            ntp64_to_timespec(0, 0, split),
            (field(l, "sec").parse().unwrap(), field(l, "nsec").parse().unwrap())
        );
        let l = line("N2TS_MID");
        let frac: u32 = field(l, "nsec_in").parse().unwrap();
        let ntp_sec = 1_700_000_000u32.wrapping_add(JAN_1970);
        let (sec, nsec) = ntp64_to_timespec(ntp_sec, frac, split);
        assert_eq!(sec, field(l, "sec").parse::<i64>().unwrap(), "N2TS_MID sec");
        assert_eq!(nsec, field(l, "nsec").parse::<i64>().unwrap(), "N2TS_MID nsec");
        let l = line("N2TS_LOW");
        let (sec, _) = ntp64_to_timespec(JAN_1970.wrapping_add(100), 0, split);
        assert_eq!(sec, field(l, "sec").parse::<i64>().unwrap(), "N2TS_LOW sec");

        // TimespecHostToNetwork.
        let l = line("TSH2N_MID");
        let (h, lo, n) = timespec_host_to_network(1_700_000_000, 123_456_789);
        assert_eq!(h, field(l, "high").parse::<u32>().unwrap(), "TSH2N_MID high");
        assert_eq!(lo, field(l, "low").parse::<u32>().unwrap(), "TSH2N_MID low");
        assert_eq!(n, field(l, "nsec").parse::<u32>().unwrap(), "TSH2N_MID nsec");
        let l = line("TSH2N_BIG");
        let (h, lo, n) = timespec_host_to_network(0x12_3456_7890, 999_999_999);
        assert_eq!(h, field(l, "high").parse::<u32>().unwrap(), "TSH2N_BIG high");
        assert_eq!(lo, field(l, "low").parse::<u32>().unwrap(), "TSH2N_BIG low");
        assert_eq!(n, field(l, "nsec").parse::<u32>().unwrap(), "TSH2N_BIG nsec");

        // TimespecNetworkToHost (round trips of the above, plus the NOHIGH case).
        let l = line("TSN2H_MID");
        let (h, lo, n) = timespec_host_to_network(1_700_000_000, 123_456_789);
        assert_eq!(
            timespec_network_to_host(h, lo, n),
            (field(l, "sec").parse().unwrap(), field(l, "nsec").parse().unwrap())
        );
        let l = line("TSN2H_BIG");
        let (h, lo, n) = timespec_host_to_network(0x12_3456_7890, 999_999_999);
        assert_eq!(
            timespec_network_to_host(h, lo, n),
            (field(l, "sec").parse().unwrap(), field(l, "nsec").parse().unwrap())
        );
        let l = line("TSN2H_NOHIGH");
        // tv_sec_high = TV_NOHIGHSEC, low = 42, nsec = 1.5e9 (clamped).
        assert_eq!(
            timespec_network_to_host(0x7fff_ffff, 42, 1_500_000_000),
            (field(l, "sec").parse().unwrap(), field(l, "nsec").parse().unwrap())
        );

        // IsTimeOffsetSane window [split, split + 2^32].
        assert_eq!(
            is_time_offset_sane((split - 10) as f64, 0.0, split) as i32,
            field(line("SANE_LO"), "r").parse::<i32>().unwrap()
        );
        assert_eq!(
            is_time_offset_sane(1.7e9, 0.0, split) as i32,
            field(line("SANE_IN"), "r").parse::<i32>().unwrap()
        );
        assert_eq!(
            is_time_offset_sane((split + (1i64 << 32) + 10) as f64, 0.0, split) as i32,
            field(line("SANE_HI"), "r").parse::<i32>().unwrap()
        );
        assert_eq!(
            is_time_offset_sane(1.7e9, f64::NAN, split) as i32,
            field(line("SANE_NAN"), "r").parse::<i32>().unwrap()
        );
    }

    #[test]
    fn matches_real_c_ip_address_algebra() {
        let v = include_str!("../../../research/oracle/util-ip-c-vectors.txt");
        let line = |tag: &str| v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap();
        let r = |tag: &str| field(line(tag), "r").parse::<i32>().unwrap();
        let val = |tag: &str| field(line(tag), "v").parse::<i32>().unwrap();

        // The 20-byte wire image must match sizeof(IPAddr).
        assert_eq!(field(line("SIZEOF"), "v").parse::<usize>().unwrap(), 20);

        // The fixtures' addresses, mirrored from genip.c.
        let a4 = IpAddr::Inet4(0xC0A8_0101);
        let b4 = IpAddr::Inet4(0xC0A8_0102);
        let m4 = IpAddr::Inet4(0xFFFF_FF00);
        let hi4 = IpAddr::Inet4(0x8000_0000);
        let lo4 = IpAddr::Inet4(0x0000_0000);
        let mut a6b = [0u8; 16];
        for (i, x) in a6b.iter_mut().enumerate() {
            *x = i as u8 + 1;
        }
        let a6 = IpAddr::Inet6(a6b);
        let mut b6b = a6b;
        b6b[8] = 0xFF;
        let b6 = IpAddr::Inet6(b6b);
        let mut m6b = [0u8; 16];
        m6b[..8].fill(0xFF);
        let m6 = IpAddr::Inet6(m6b);
        let id1 = IpAddr::Id(100);
        let id2 = IpAddr::Id(250);
        let un = IpAddr::Unspec;

        // IsIPReal.
        assert_eq!(is_ip_real(&a4) as i32, r("REAL_4"));
        assert_eq!(is_ip_real(&a6) as i32, r("REAL_6"));
        assert_eq!(is_ip_real(&id1) as i32, r("REAL_ID"));
        assert_eq!(is_ip_real(&un) as i32, r("REAL_UN"));

        // CompareIPs (raw integer differences, not clamped).
        assert_eq!(compare_ips(&a4, &b4, None), r("CMP_4_LT"));
        assert_eq!(compare_ips(&b4, &a4, None), r("CMP_4_GT"));
        assert_eq!(compare_ips(&a4, &a4, None), r("CMP_4_EQ"));
        assert_eq!(compare_ips(&a4, &b4, Some(&m4)), r("CMP_4_MASK"));
        assert_eq!(compare_ips(&hi4, &lo4, None), r("CMP_4_WRAP"));
        assert_eq!(compare_ips(&a6, &b6, None), r("CMP_6_LT"));
        assert_eq!(compare_ips(&b6, &a6, None), r("CMP_6_GT"));
        assert_eq!(compare_ips(&a6, &a6, None), r("CMP_6_EQ"));
        assert_eq!(compare_ips(&a6, &b6, Some(&m6)), r("CMP_6_MASK"));
        assert_eq!(compare_ips(&id1, &id2, None), r("CMP_ID_LT"));
        assert_eq!(compare_ips(&id2, &id1, None), r("CMP_ID_GT"));
        assert_eq!(compare_ips(&un, &un, None), r("CMP_UN"));
        assert_eq!(compare_ips(&a4, &a6, None), r("CMP_FAM_46"));
        assert_eq!(compare_ips(&a6, &a4, None), r("CMP_FAM_64"));
        // Mask whose family != b's is ignored.
        assert_eq!(compare_ips(&a4, &b4, Some(&m6)), r("CMP_MASK_FAMMISMATCH"));

        // IPHostToNetwork / IPNetworkToHost: exact wire image + round trip.
        let wire = |tag: &str| field(line(tag), "bytes");
        assert_eq!(bytes_to_hex(&ip_host_to_network(&a4)), wire("H2N_4").to_uppercase());
        assert_eq!(ip_network_to_host(&ip_host_to_network(&a4)), a4);
        assert_eq!(bytes_to_hex(&ip_host_to_network(&a6)), wire("H2N_6").to_uppercase());
        assert_eq!(ip_network_to_host(&ip_host_to_network(&a6)), a6);
        assert_eq!(bytes_to_hex(&ip_host_to_network(&id1)), wire("H2N_ID").to_uppercase());
        assert_eq!(ip_network_to_host(&ip_host_to_network(&id1)), id1);
        assert_eq!(bytes_to_hex(&ip_host_to_network(&un)), wire("H2N_UN").to_uppercase());
        assert_eq!(ip_network_to_host(&ip_host_to_network(&un)), un);

        // Cmac/Hash name -> algorithm.
        assert_eq!(cmac_name_to_algorithm("AES128"), val("CMAC_AES128"));
        assert_eq!(cmac_name_to_algorithm("AES256"), val("CMAC_AES256"));
        assert_eq!(cmac_name_to_algorithm("AES999"), val("CMAC_BAD"));
        for name in [
            "MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA3-224", "SHA3-256", "SHA3-384",
            "SHA3-512", "TIGER", "WHIRLPOOL",
        ] {
            assert_eq!(hash_name_to_algorithm(name), val(&format!("HASH_{name}")), "{name}");
        }
        assert_eq!(hash_name_to_algorithm("BOGUS"), val("HASH_BOGUS"));
    }

    #[test]
    fn matches_real_c_string_path_split() {
        let v = include_str!("../../../research/oracle/util-str-c-vectors.txt");
        // Match the tag as the exact first token (tags like PATHDIR_A are prefixes of
        // PATHDIR_ABC, so a plain starts_with would mis-match).
        let line = |tag: &str| {
            v.lines().map(str::trim).find(|l| l.split_whitespace().next() == Some(tag)).unwrap()
        };
        // Everything after "key=" to end of line (for values that may contain spaces).
        let after = |tag: &str, key: &str| {
            line(tag).split_once(&format!("{key}=")).unwrap().1.to_string()
        };
        let split: i64 = 123_200_000; // matches the oracle build's NTP_ERA_SPLIT

        // TimespecToString.
        assert_eq!(timespec_to_string(1_700_000_000, 123_456_789), after("TS2STR_A", "s"));
        assert_eq!(timespec_to_string(42, 7), after("TS2STR_B", "s"));
        assert_eq!(timespec_to_string(0, 0), after("TS2STR_C", "s"));
        assert_eq!(timespec_to_string(-5, 500_000_000), after("TS2STR_D", "s"));

        // Ntp64ToString.
        assert_eq!(ntp64_to_string(0, 0, split), after("N642STR_ZERO", "s"));
        let ntp_sec = 1_700_000_000u32.wrapping_add(JAN_1970);
        assert_eq!(ntp64_to_string(ntp_sec, 2_147_483_648, split), after("N642STR_MID", "s"));

        // TimeToLogForm.
        assert_eq!(time_to_log_form(0), after("T2LOG_EPOCH", "s"));
        assert_eq!(time_to_log_form(1_700_000_000), after("T2LOG_Y2023", "s"));
        assert_eq!(time_to_log_form(951_782_400), after("T2LOG_Y2000", "s")); // leap day
        assert_eq!(time_to_log_form(86_399), after("T2LOG_DAY1", "s"));
        assert_eq!(time_to_log_form(32_503_680_000), after("T2LOG_Y3000", "s"));
        assert_eq!(time_to_log_form(-1), after("T2LOG_NEG1", "s")); // pre-1970
        assert_eq!(time_to_log_form(-2_208_988_800), after("T2LOG_Y1900", "s"));

        // PathToDir.
        assert_eq!(path_to_dir("/a/b/c"), after("PATHDIR_ABC", "s"));
        assert_eq!(path_to_dir("/a"), after("PATHDIR_A", "s"));
        assert_eq!(path_to_dir("a"), after("PATHDIR_REL", "s"));
        assert_eq!(path_to_dir("noslash"), after("PATHDIR_NOSLASH", "s"));
        assert_eq!(path_to_dir("/"), after("PATHDIR_ROOT", "s"));
        assert_eq!(path_to_dir("a/b"), after("PATHDIR_AB", "s"));
        assert_eq!(path_to_dir("/usr/local/bin/x"), after("PATHDIR_DEEP", "s"));

        // SplitString: words + total count (capped at max_saved_words = 4).
        let chk = |input: &str, tag: &str| {
            let (words, count) = split_string(input, 4);
            assert_eq!(count, field(line(tag), "count").parse::<usize>().unwrap(), "{tag} count");
            for (i, w) in words.iter().enumerate() {
                assert_eq!(w.as_str(), field(line(tag), &format!("w{i}")), "{tag} w{i}");
            }
        };
        chk("  hello   world  foo ", "SPLIT_A");
        chk("a b c d e f", "SPLIT_B");
        chk("single", "SPLIT_C");
        chk("", "SPLIT_D");
        chk("   \t\n  ", "SPLIT_E");
        chk("tab\tsep\tx", "SPLIT_F");
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
