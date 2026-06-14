//! NTP packet decode/encode (RFC 5905 §7.3, the 48-byte header).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Root Delay                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Root Dispersion                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Reference Identifier                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Reference Timestamp (64)                   |
//! |                              ...                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Origin Timestamp (64)                      |
//! |                              ...                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Receive Timestamp (64)                     |
//! |                              ...                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Transmit Timestamp (64)                    |
//! |                              ...                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Extension fields, the MAC/key-id (authentication), and NTS records may follow
//! the 48-byte header. They are *not* decoded here yet — see the negative-
//! capability ledger (`docs/negative-capabilities.md`) and `extension_fields`/
//! `nts` campaigns. We preserve any trailing bytes verbatim in [`NtpPacket::tail`]
//! so that a decode→encode round trip stays byte-identical even for packets whose
//! tail we don't yet interpret. Silently dropping the tail would break byte parity
//! and is forbidden.

use serde::{Deserialize, Serialize};

use super::timestamp::{NtpShort, NtpTimestamp};

/// The fixed NTP header length. Anything shorter is malformed.
pub const NTP_PACKET_MIN_LEN: usize = 48;

/// Leap Indicator (RFC 5905 §7.3): the two high bits of byte 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LeapIndicator {
    /// No warning.
    NoWarning,
    /// Last minute of the day has 61 seconds.
    InsertSecond,
    /// Last minute of the day has 59 seconds.
    DeleteSecond,
    /// Clock unsynchronized (also chrony's "alarm" condition on startup).
    Unsynchronized,
}

impl LeapIndicator {
    #[inline]
    const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => LeapIndicator::NoWarning,
            1 => LeapIndicator::InsertSecond,
            2 => LeapIndicator::DeleteSecond,
            _ => LeapIndicator::Unsynchronized,
        }
    }

    #[inline]
    const fn to_bits(self) -> u8 {
        match self {
            LeapIndicator::NoWarning => 0,
            LeapIndicator::InsertSecond => 1,
            LeapIndicator::DeleteSecond => 2,
            LeapIndicator::Unsynchronized => 3,
        }
    }
}

/// NTP association mode (RFC 5905 §7.3): the three low bits of byte 0.
///
/// chrony as a client sends mode 3 (client) and expects mode 4 (server) in
/// replies; symmetric modes 1/2 are used for `peer`. Modes are preserved exactly
/// rather than normalized, because chrony's response to an unexpected mode is a
/// behavior we must be able to reproduce, not paper over.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Mode(pub u8);

impl Mode {
    pub const RESERVED: Mode = Mode(0);
    pub const SYMMETRIC_ACTIVE: Mode = Mode(1);
    pub const SYMMETRIC_PASSIVE: Mode = Mode(2);
    pub const CLIENT: Mode = Mode(3);
    pub const SERVER: Mode = Mode(4);
    pub const BROADCAST: Mode = Mode(5);
    pub const CONTROL: Mode = Mode(6);
    pub const PRIVATE: Mode = Mode(7);
}

/// A decoded NTP packet header plus any uninterpreted trailing bytes.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct NtpPacket {
    pub leap: LeapIndicator,
    /// NTP version (bits 3..6 of byte 0). chrony emits version 4; it accepts 3.
    pub version: u8,
    pub mode: Mode,
    /// Stratum. 0 is "kiss-o-death" or unspecified; 1 is a primary reference;
    /// 16 means unsynchronized.
    pub stratum: u8,
    /// Poll interval, log2 seconds, *signed* (chrony uses values like 6..10, and
    /// negative values appear in some modes). Stored as the raw byte.
    pub poll: i8,
    /// Clock precision, log2 seconds, signed. Typically a small negative number.
    pub precision: i8,
    pub root_delay: NtpShort,
    pub root_dispersion: NtpShort,
    /// Reference identifier: 4 raw bytes. For stratum 1 this is an ASCII refid
    /// (e.g. `GPS\0`); for stratum >1 over IPv4 it is the upstream address; for a
    /// kiss-o-death it is an ASCII kiss code (e.g. `RATE`). We keep the raw bytes
    /// because the *interpretation* is context-dependent and is itself a court
    /// (`CHRONY.PACKET.5`, `CHRONY.PACKET.7`).
    pub reference_id: [u8; 4],
    pub reference_timestamp: NtpTimestamp,
    pub origin_timestamp: NtpTimestamp,
    pub receive_timestamp: NtpTimestamp,
    pub transmit_timestamp: NtpTimestamp,
    /// Bytes after the 48-byte header (extension fields / MAC / NTS), preserved
    /// verbatim and re-emitted on encode so round trips are byte-identical even
    /// though we do not yet parse them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tail: Vec<u8>,
}

/// Why a byte slice could not be decoded as an NTP packet. Decoding is total: it
/// returns one of these instead of ever panicking, which is the load-bearing
/// safety property behind `CHRONY.PACKET.8` and `CHRONY.SECURITY.2`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PacketError {
    /// Fewer than [`NTP_PACKET_MIN_LEN`] bytes were supplied.
    TooShort { got: usize },
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PacketError::TooShort { got } => write!(
                f,
                "NTP packet too short: got {got} bytes, need at least {NTP_PACKET_MIN_LEN}"
            ),
        }
    }
}

impl std::error::Error for PacketError {}

impl NtpPacket {
    /// Decode a packet from raw bytes. Never panics: the only failure mode is a
    /// buffer shorter than the fixed header. Every field of the 48-byte header is
    /// representable for *any* 48+ byte input — there are no "invalid" bit patterns
    /// at this layer, because rejecting e.g. a bad stratum is a *policy* decision
    /// that happens later in source selection, not a wire-format decision here.
    pub fn decode(buf: &[u8]) -> Result<NtpPacket, PacketError> {
        if buf.len() < NTP_PACKET_MIN_LEN {
            return Err(PacketError::TooShort { got: buf.len() });
        }

        let b0 = buf[0];
        let leap = LeapIndicator::from_bits(b0 >> 6);
        let version = (b0 >> 3) & 0b111;
        let mode = Mode(b0 & 0b111);

        // Fixed-width fields read with explicit byte ranges. The `unwrap`s below
        // can never fire: we have already proven `buf.len() >= 48`, and every
        // slice is within that bound. They are `expect`ed with a message so that
        // if the constant ever changes incorrectly, the failure is legible.
        let r4 = |start: usize| -> [u8; 4] {
            buf[start..start + 4].try_into().expect("bounds checked above")
        };
        let r8 = |start: usize| -> [u8; 8] {
            buf[start..start + 8].try_into().expect("bounds checked above")
        };

        let packet = NtpPacket {
            leap,
            version,
            mode,
            stratum: buf[1],
            poll: buf[2] as i8,
            precision: buf[3] as i8,
            root_delay: NtpShort::from_be_bytes(r4(4)),
            root_dispersion: NtpShort::from_be_bytes(r4(8)),
            reference_id: r4(12),
            reference_timestamp: NtpTimestamp::from_be_bytes(r8(16)),
            origin_timestamp: NtpTimestamp::from_be_bytes(r8(24)),
            receive_timestamp: NtpTimestamp::from_be_bytes(r8(32)),
            transmit_timestamp: NtpTimestamp::from_be_bytes(r8(40)),
            tail: buf[NTP_PACKET_MIN_LEN..].to_vec(),
        };
        Ok(packet)
    }

    /// Encode back to wire bytes. This is the exact inverse of [`decode`] for any
    /// value that came from `decode`, including the preserved [`tail`].
    ///
    /// [`decode`]: NtpPacket::decode
    /// [`tail`]: NtpPacket::tail
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NTP_PACKET_MIN_LEN + self.tail.len());

        // Re-pack byte 0. We mask `version` and `mode` to their field widths so a
        // caller that constructed an out-of-range value can't corrupt neighboring
        // bits — but note this is a *write-side* guard only; decode never produces
        // out-of-range values.
        let b0 = (self.leap.to_bits() << 6) | ((self.version & 0b111) << 3) | (self.mode.0 & 0b111);
        out.push(b0);
        out.push(self.stratum);
        out.push(self.poll as u8);
        out.push(self.precision as u8);
        out.extend_from_slice(&self.root_delay.to_be_bytes());
        out.extend_from_slice(&self.root_dispersion.to_be_bytes());
        out.extend_from_slice(&self.reference_id);
        out.extend_from_slice(&self.reference_timestamp.to_be_bytes());
        out.extend_from_slice(&self.origin_timestamp.to_be_bytes());
        out.extend_from_slice(&self.receive_timestamp.to_be_bytes());
        out.extend_from_slice(&self.transmit_timestamp.to_be_bytes());
        out.extend_from_slice(&self.tail);
        out
    }

    /// Interpret [`reference_id`] as an ASCII kiss/refid code, trimming trailing
    /// NULs. Returns `None` if the bytes are not printable ASCII. This is a
    /// *reporting* helper, not part of the wire contract.
    ///
    /// [`reference_id`]: NtpPacket::reference_id
    pub fn reference_id_ascii(&self) -> Option<String> {
        let trimmed: Vec<u8> = self
            .reference_id
            .iter()
            .copied()
            .take_while(|&b| b != 0)
            .collect();
        if trimmed.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
            Some(String::from_utf8_lossy(&trimmed).into_owned())
        } else {
            None
        }
    }

    /// True if this looks like a kiss-o-death packet: stratum 0 in a server reply.
    /// The specific code (RATE, DENY, RSTR, …) lives in [`reference_id`]. chrony's
    /// *reaction* to each code is a separate behavior court (`CHRONY.PACKET.7`).
    ///
    /// [`reference_id`]: NtpPacket::reference_id
    pub fn is_kiss_of_death(&self) -> bool {
        self.stratum == 0 && self.mode == Mode::SERVER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real-shaped client request: LI=0, VN=4, Mode=3 → byte 0 = 0b00_100_011.
    fn sample_client_request() -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0] = 0b00_100_011;
        b[1] = 0; // stratum 0 in a request
        b[2] = 6; // poll 2^6 = 64s
        b[3] = 0xE9_u8 as i8 as u8; // precision -23
        // Transmit timestamp in the last 8 bytes; the rest left zero, as chrony
        // does for a fresh client poll (origin/receive are zero).
        b[40..48].copy_from_slice(&[0xE9, 0x12, 0x34, 0x56, 0x80, 0x00, 0x00, 0x00]);
        b
    }

    #[test]
    fn decode_then_encode_is_byte_identical() {
        // CHRONY.PACKET.12 — roundtrip byte identity.
        let bytes = sample_client_request();
        let pkt = NtpPacket::decode(&bytes).expect("valid 48-byte header");
        assert_eq!(pkt.version, 4);
        assert_eq!(pkt.mode, Mode::CLIENT);
        assert_eq!(pkt.leap, LeapIndicator::NoWarning);
        assert_eq!(pkt.poll, 6);
        assert_eq!(pkt.precision, -23);
        assert_eq!(pkt.encode(), bytes.to_vec());
    }

    #[test]
    fn tail_is_preserved_verbatim() {
        // CHRONY.PACKET.9 (boundary) — a 4-byte key id appended after the header
        // must survive a round trip even though we don't parse it yet.
        let mut bytes = sample_client_request().to_vec();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let pkt = NtpPacket::decode(&bytes).expect("valid header + tail");
        assert_eq!(pkt.tail, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(pkt.encode(), bytes);
    }

    #[test]
    fn short_buffer_is_rejected_not_panicked() {
        // CHRONY.PACKET.8 / CHRONY.SECURITY.2 — malformed (too short) input must
        // fail closed with a typed error, never panic.
        for len in 0..NTP_PACKET_MIN_LEN {
            let buf = vec![0u8; len];
            assert_eq!(
                NtpPacket::decode(&buf),
                Err(PacketError::TooShort { got: len }),
                "len {len} must be rejected"
            );
        }
    }

    #[test]
    fn kiss_of_death_rate_is_detected() {
        // CHRONY.PACKET.7 — a server reply (mode 4) with stratum 0 and refid RATE.
        let mut b = [0u8; 48];
        b[0] = 0b00_100_100; // VN=4, Mode=4 (server)
        b[1] = 0; // stratum 0
        b[12..16].copy_from_slice(b"RATE");
        let pkt = NtpPacket::decode(&b).unwrap();
        assert!(pkt.is_kiss_of_death());
        assert_eq!(pkt.reference_id_ascii().as_deref(), Some("RATE"));
    }

    #[test]
    fn reference_id_non_ascii_is_none() {
        let mut b = sample_client_request();
        b[12..16].copy_from_slice(&[192, 168, 1, 1]); // an IPv4 refid, not ASCII text
        let pkt = NtpPacket::decode(&b).unwrap();
        assert_eq!(pkt.reference_id_ascii(), None);
    }

    #[test]
    fn byte_zero_fields_pack_independently() {
        // Guard against a field bleeding into its neighbor when re-packing byte 0.
        let mut b = [0u8; 48];
        b[0] = 0b11_011_010; // LI=3, VN=3, Mode=2
        let pkt = NtpPacket::decode(&b).unwrap();
        assert_eq!(pkt.leap, LeapIndicator::Unsynchronized);
        assert_eq!(pkt.version, 3);
        assert_eq!(pkt.mode, Mode::SYMMETRIC_PASSIVE);
        assert_eq!(pkt.encode()[0], 0b11_011_010);
    }
}
