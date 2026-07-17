//! NTP timestamp and short-format fixed-point types.
//!
//! Two on-wire fixed-point formats appear in an NTP packet (RFC 5905 §6):
//!
//! * **NTP timestamp** — 64 bits: a 32-bit count of seconds since the NTP epoch
//!   (1900-01-01 00:00:00 UTC) and a 32-bit binary fraction of a second. Stored
//!   and transmitted big-endian.
//! * **NTP short** — 32 bits: 16 bits of seconds, 16 bits of fraction. Used for
//!   root delay and root dispersion, which are durations rather than instants.
//!
//! # The era trap (read before "fixing" the epoch math)
//!
//! The 32-bit seconds field rolls over every ~136 years. Era 0 began in 1900 and
//! ends in 2036; era 1 runs 2036–2172. A raw NTP timestamp is therefore ambiguous
//! without an era number. chrony resolves this with the running system clock, not
//! with the packet alone. We intentionally *do not* bake a Unix-epoch conversion
//! into the wire type: the 64-bit value is preserved verbatim so that byte parity
//! is never lost to a lossy seconds conversion. Era-aware conversion is a separate,
//! later court (`CHRONY.DISCIPLINE.15`) and must not be smuggled in here.

use serde::{Deserialize, Serialize};

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01),
/// i.e. 70 years including 17 leap days. Kept as a named constant so era-aware
/// conversions (in a later campaign) reference the same well-known value rather
/// than an unexplained magic number.
///
/// Deliberately not yet consumed by non-test code: era-aware Unix conversion is a
/// later court (`CHRONY.DISCIPLINE.15`). Exposed now so the constant has one
/// canonical home and is checked by tests, rather than being reintroduced ad hoc.
// Used for NTP timestamp era calculations; currently unused but documents the constant
#[allow(dead_code)]
pub const NTP_UNIX_EPOCH_DELTA_SECS: u64 = 2_208_988_800;

/// A 64-bit NTP timestamp: 32 bits of seconds (since the NTP epoch, within an
/// unspecified era) and 32 bits of binary fraction.
///
/// The value is stored as its raw `u64` so that decode→encode is bit-exact. Two
/// distinct timestamps that happen to denote the same instant in different eras
/// are *not* equal here, and that is correct: at the wire level they are different
/// bytes, and byte parity is the contract this type upholds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NtpTimestamp(u64);

impl NtpTimestamp {
    /// The all-zero timestamp. On the wire this is the conventional "not set"
    /// value chrony uses for the origin timestamp of a fresh client request.
    pub const ZERO: NtpTimestamp = NtpTimestamp(0);

    /// Construct from the raw 64-bit on-wire representation (host integer, not
    /// bytes). Use [`NtpTimestamp::from_be_bytes`] when reading a packet.
    #[inline]
    pub const fn from_bits(bits: u64) -> Self {
        NtpTimestamp(bits)
    }

    /// The raw 64-bit on-wire representation.
    #[inline]
    pub const fn to_bits(self) -> u64 {
        self.0
    }

    /// The 32-bit seconds field (era-relative).
    #[inline]
    pub const fn seconds(self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// The 32-bit binary fraction field.
    #[inline]
    pub const fn fraction(self) -> u32 {
        self.0 as u32
    }

    /// Decode from 8 big-endian bytes exactly as they appear in a packet.
    #[inline]
    pub const fn from_be_bytes(b: [u8; 8]) -> Self {
        NtpTimestamp(u64::from_be_bytes(b))
    }

    /// Encode to 8 big-endian bytes for placement in a packet.
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Interpret as seconds — a port of chrony `UTI_Ntp64ToDouble` (`util.c`),
    /// which is `UTI_DiffNtp64ToDouble` against zero: the seconds field is read as
    /// a **signed** 32-bit value, plus the binary fraction over 2³².
    pub fn to_seconds_f64(self) -> f64 {
        (self.seconds() as i32) as f64 + self.fraction() as f64 / (1.0e9 * NSEC_PER_NTP64)
    }

    /// Encode seconds — a port of chrony `UTI_DoubleToNtp64` (`util.c`). The value
    /// is clamped to the signed 32-bit second range, the seconds field is the floor
    /// (round-then-step-down), and the fraction is the remainder scaled by 2³².
    pub fn from_seconds_f64(src: f64) -> Self {
        let src = src.clamp(i32::MIN as f64, i32::MAX as f64);
        let mut hi = src.round() as i32;
        if hi as f64 > src {
            hi = hi.wrapping_sub(1); // round() may round up; step down to the floor
        }
        let lo = ((src - hi as f64) * (1.0e9 * NSEC_PER_NTP64)) as u32;
        NtpTimestamp(((hi as u32 as u64) << 32) | lo as u64)
    }
}

/// chrony's `NSEC_PER_NTP64` (`util.c`): `2³² / 1e9`, so `1e9 * NSEC_PER_NTP64`
/// is exactly `2³²`, the number of binary-fraction units per second.
const NSEC_PER_NTP64: f64 = 4.294967296;

impl core::fmt::Debug for NtpTimestamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Render seconds.fraction split out; this is a debugging aid only and is
        // never compared for byte parity (which uses the raw bits).
        write!(f, "NtpTimestamp({}.{:08x})", self.seconds(), self.fraction())
    }
}

/// A 32-bit NTP "short" fixed-point value: 16 bits seconds, 16 bits fraction.
/// Used for root delay and root dispersion.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NtpShort(u32);

impl NtpShort {
    /// The all-zero short value.
    pub const ZERO: NtpShort = NtpShort(0);

    /// Construct from the raw 32-bit on-wire representation.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        NtpShort(bits)
    }

    /// The raw 32-bit on-wire representation.
    #[inline]
    pub const fn to_bits(self) -> u32 {
        self.0
    }

    /// Decode from 4 big-endian bytes.
    #[inline]
    pub const fn from_be_bytes(b: [u8; 4]) -> Self {
        NtpShort(u32::from_be_bytes(b))
    }

    /// Encode to 4 big-endian bytes.
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Interpret the value as seconds (for human-facing reporting only — never for
    /// byte parity). 16.16 fixed point means dividing the raw value by 2^16.
    #[inline]
    pub fn as_seconds_f64(self) -> f64 {
        self.0 as f64 / 65_536.0
    }

    /// Encode seconds into 16.16 fixed point — a port of chrony `UTI_DoubleToNtp32`
    /// (`util.c`). Saturates: `>= 2^16` clamps to all-ones, `<= 0` to zero; the
    /// fractional truncation rounds **up** (chrony's `if (r < x) r++`), so the
    /// result is never an underestimate of the represented delay/dispersion.
    pub fn from_seconds_f64(x: f64) -> Self {
        let bits = if x >= 65_536.0 {
            0xffff_ffff
        } else if x <= 0.0 {
            0
        } else {
            let scaled = x * 65_536.0;
            let mut r = scaled as u32;
            if (r as f64) < scaled {
                r = r.wrapping_add(1);
            }
            r
        };
        NtpShort(bits)
    }
}

impl core::fmt::Debug for NtpShort {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NtpShort({:.9}s)", self.as_seconds_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_roundtrips_bit_exact() {
        // CHRONY.PACKET.2 — a transmit timestamp captured from a chronyd reply.
        let bytes = [0xE9, 0x12, 0x34, 0x56, 0x80, 0x00, 0x00, 0x00];
        let ts = NtpTimestamp::from_be_bytes(bytes);
        assert_eq!(ts.to_be_bytes(), bytes, "decode→encode must be bit-exact");
        assert_eq!(ts.seconds(), 0xE912_3456);
        // 0x80000000 fraction == exactly half a second.
        assert_eq!(ts.fraction(), 0x8000_0000);
    }

    #[test]
    fn short_half_second_is_one_half() {
        let s = NtpShort::from_be_bytes([0x00, 0x00, 0x80, 0x00]);
        assert!((s.as_seconds_f64() - 0.5).abs() < 1e-12);
        assert_eq!(s.to_be_bytes(), [0x00, 0x00, 0x80, 0x00]);
    }

    #[test]
    fn ntp64_double_roundtrip_and_known_values() {
        // UTI_DoubleToNtp64 / UTI_Ntp64ToDouble.
        let half = NtpTimestamp::from_seconds_f64(0.5);
        assert_eq!(half.seconds(), 0);
        assert_eq!(half.fraction(), 0x8000_0000); // exactly half
        assert!((half.to_seconds_f64() - 0.5).abs() < 1e-12);

        let two = NtpTimestamp::from_seconds_f64(2.0);
        assert_eq!(two.seconds(), 2);
        assert_eq!(two.fraction(), 0);

        // floor behaviour and round-trip for a few values
        for &x in &[0.0, 1.25, 3.999_999, 100.5, -1.5, -0.25] {
            let r = NtpTimestamp::from_seconds_f64(x).to_seconds_f64();
            assert!((r - x).abs() < 1e-6, "roundtrip {x} -> {r}");
        }
    }

    #[test]
    fn double_to_ntp32_saturation_and_rounding() {
        // UTI_DoubleToNtp32 semantics.
        assert_eq!(NtpShort::from_seconds_f64(0.5).to_bits(), 0x0000_8000);
        assert_eq!(NtpShort::from_seconds_f64(0.0).to_bits(), 0); // <= 0 -> zero
        assert_eq!(NtpShort::from_seconds_f64(-1.0).to_bits(), 0);
        assert_eq!(NtpShort::from_seconds_f64(70000.0).to_bits(), 0xffff_ffff); // >= 2^16
        assert_eq!(NtpShort::from_seconds_f64(1.0).to_bits(), 0x0001_0000);
        // Round-up: a value just above an integer tick must not underestimate.
        let r = NtpShort::from_seconds_f64(1.0 / 65_536.0 + 1e-12).to_bits();
        assert_eq!(r, 2);
    }

    #[test]
    fn epoch_delta_is_the_canonical_value() {
        // 70 years (1900→1970) with 17 leap days.
        assert_eq!(NTP_UNIX_EPOCH_DELTA_SECS, 70 * 365 * 86_400 + 17 * 86_400);
    }
}
