//! Control-protocol message lengths — a complete port of chrony 4.5 `pktlength.c`.
//!
//! chrony's command/monitoring protocol (`cmdmon`) has a fixed request struct per
//! command type and reply struct per reply type. `pktlength.c` computes the
//! on-wire length of each from a table built with `offsetof(CMD_Request, …)` /
//! `offsetof(CMD_Reply, …)`. All 3 functions port directly:
//!
//! | chrony `pktlength.c` | here |
//! |----------------------|------|
//! | `PKL_CommandLength` | [`command_length`] |
//! | `PKL_CommandPaddingLength` | [`command_padding_length`] |
//! | `PKL_ReplyLength` | [`reply_length`] |
//!
//! (chrony reads `command`/`version`/`reply` out of the message header; here those
//! scalars are the parameters, which is all the functions use.)
//!
//! # Provenance of the tables
//!
//! [`REQUEST_LENGTHS`]/[`REPLY_LENGTHS`] are **not** guessed — they are the exact
//! `request_lengths[]`/`reply_lengths[]` values from `pktlength.c`, extracted by
//! compiling those table initializers against the real `candm.h` and printing each
//! `offsetof`. A zero command length marks an unsupported/removed command, which
//! both chrony and this port treat as length 0 (invalid).

/// `N_REQUEST_TYPES` — the number of command types.
pub const N_REQUEST_TYPES: u16 = 73;
/// `N_REPLY_TYPES` — the number of reply types (codes start at 1).
pub const N_REPLY_TYPES: u16 = 26;
/// `PROTO_VERSION_PADDING` — the first protocol version that pads requests up to
/// the reply size (to limit amplification).
pub const PROTO_VERSION_PADDING: u8 = 6;

/// Per-command `(command_length, padding_length)`, indexed by command type.
/// Derived from `offsetof` against `candm.h` (see module docs).
const REQUEST_LENGTHS: [(u16, u16); 73] = [
    (20, 8), (60, 0), (60, 0), (68, 0), (44, 0), (44, 0), (24, 4), (44, 0), (44, 0), (24, 4),
    (32, 0), (32, 8), (0, 0), (24, 4), (20, 12), (24, 52), (20, 8), (44, 0), (44, 0), (44, 0),
    (44, 0), (44, 0), (44, 0), (44, 0), (44, 0), (40, 0), (40, 0), (0, 0), (0, 0), (40, 0),
    (20, 8), (24, 4), (0, 0), (20, 84), (24, 60), (20, 36), (20, 8), (20, 8), (0, 0), (0, 0),
    (0, 0), (20, 396), (24, 4), (20, 8), (20, 28), (44, 0), (44, 0), (44, 0), (20, 8), (24, 4),
    (28, 0), (20, 32), (24, 4), (20, 8), (20, 176), (0, 0), (36, 0), (40, 112), (0, 0), (0, 0),
    (0, 0), (0, 0), (20, 8), (20, 8), (372, 0), (40, 244), (20, 8), (40, 12), (36, 484), (24, 52),
    (20, 8), (24, 4), (52, 0),
];

/// Per-reply length, indexed by reply type (index 0 is unused — codes start at 1).
const REPLY_LENGTHS: [u16; 26] = [
    0, 28, 32, 76, 0, 104, 84, 56, 0, 0, 0, 0, 48, 52, 0, 0, 152, 40, 416, 284, 52, 520, 0, 76, 0,
    196,
];

/// `PKL_CommandLength`: the on-wire length of a request of type `command` from a
/// client at protocol `version`, or 0 if the command is out of range or
/// unsupported (zero base length).
pub fn command_length(version: u8, command: u16) -> i32 {
    if command >= N_REQUEST_TYPES {
        return 0;
    }
    let base = REQUEST_LENGTHS[command as usize].0;
    if base == 0 {
        return 0;
    }
    base as i32 + command_padding_length(version, command)
}

/// `PKL_CommandPaddingLength`: the padding appended to a request of type `command`,
/// which is zero before [`PROTO_VERSION_PADDING`].
pub fn command_padding_length(version: u8, command: u16) -> i32 {
    if version < PROTO_VERSION_PADDING {
        return 0;
    }
    if command >= N_REQUEST_TYPES {
        return 0;
    }
    REQUEST_LENGTHS[command as usize].1 as i32
}

/// `PKL_ReplyLength`: the on-wire length of a reply of type `reply`, or 0 if out of
/// range (reply codes start at 1).
pub fn reply_length(reply: u16) -> i32 {
    if !(1..N_REPLY_TYPES).contains(&reply) {
        return 0;
    }
    REPLY_LENGTHS[reply as usize] as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_length_includes_padding_only_from_v6() {
        // Command 0 (NULL): base 20, padding 8.
        assert_eq!(command_length(6, 0), 28); // v6 -> padded
        assert_eq!(command_length(5, 0), 20); // pre-v6 -> no padding
        assert_eq!(command_padding_length(6, 0), 8);
        assert_eq!(command_padding_length(5, 0), 0);
    }

    #[test]
    fn unsupported_or_out_of_range_commands_are_zero() {
        // Command 12 (LOCAL) has a zero base length -> unsupported.
        assert_eq!(command_length(6, 12), 0);
        // Out of range.
        assert_eq!(command_length(6, N_REQUEST_TYPES), 0);
        assert_eq!(command_padding_length(6, 1000), 0);
    }

    #[test]
    fn known_command_lengths() {
        // Command 15 (SOURCE_DATA): base 24, padding 52 -> 76 at v6.
        assert_eq!(command_length(6, 15), 76);
        // Command 33 (TRACKING request): base 20, padding 84 -> 104 at v6.
        assert_eq!(command_length(6, 33), 104);
    }

    #[test]
    fn reply_lengths_and_range() {
        assert_eq!(reply_length(0), 0); // codes start at 1
        assert_eq!(reply_length(1), 28); // NULL reply
        assert_eq!(reply_length(5), 104); // TRACKING reply
        assert_eq!(reply_length(N_REPLY_TYPES), 0); // out of range
    }
}
