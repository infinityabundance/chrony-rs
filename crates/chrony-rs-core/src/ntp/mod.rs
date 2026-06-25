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

pub mod access;
pub mod create;
pub mod exp_ef;
pub mod ext;
pub mod lifecycle;
pub mod local_ts;
mod measurements;
pub mod mono_root;
pub mod ntp_report;
pub mod opmode;
mod packet;
pub mod params;
pub mod parse;
pub mod poll;
pub mod report;
pub mod rx_dispatch;
pub mod sample;
pub mod support;
pub mod sync;
pub mod test_a;
mod timestamp;
pub mod transmit;
pub mod tx_dispatch;

pub use measurements::{ts_diff_seconds, Measurement};
pub use packet::{LeapIndicator, Mode, NtpPacket, PacketError, NTP_PACKET_MIN_LEN};
pub use timestamp::{NtpShort, NtpTimestamp};
