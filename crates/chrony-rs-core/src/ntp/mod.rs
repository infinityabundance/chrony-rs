//! NTP wire-format primitives — the byte-parity surface of chrony-rs.
//!
//! This module is deliberately small and total: every decode path is fallible,
//! no input can cause a panic, and every encode is the exact inverse of decode
//! for the admitted fixtures (see `docs/packet-atlas.md`, courts
//! `CHRONY.PACKET.1`–`CHRONY.PACKET.13`).
//!
//! # Why we don't just use an existing NTP crate
//!
//! Generic NTP crates encode *RFC 5905 correctness*. `chrony-rs` needs
//! *chrony-observed bytes*, which is a stricter and sometimes different target:
//! chrony has its own conventions for reference IDs, kiss codes, precision
//! encoding, and which fields it populates as a client. Conflating "RFC correct"
//! with "chrony compatible" is explicitly forbidden by the project doctrine, so
//! we own the wire format here and witness it against both chronyd captures and
//! independent RFC fixtures.

pub mod ext;
mod measurements;
mod packet;
pub mod poll;
mod timestamp;

pub use measurements::{ts_diff_seconds, Measurement};
pub use packet::{LeapIndicator, Mode, NtpPacket, PacketError, NTP_PACKET_MIN_LEN};
pub use timestamp::{NtpShort, NtpTimestamp};
