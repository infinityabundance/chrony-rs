//! Tests for `ntp_core.c` Stage 8 (`add_ef_mono_root`, `add_ef_net_correction`).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** The builders are
//! reached by `#include`-ing the translation unit into a C generator
//! (`/tmp/ncor/genef.c`) with the real `ntp_ext.c` linked (so `NEF_AddField` frames the
//! field for real), the fuzz RNG zeroed, and the `server_mono_*` statics + `ptpport`
//! made controllable. Each builder is run across client/server modes and the
//! present/absent correction cases; the appended extension-field body bytes, type, and
//! resulting `ext_field_flags` are captured
//! (`research/oracle/ntp_core-ef-c-vectors.txt`). [`matches_real_c_ef_builder_vectors`]
//! replays the inputs and matches the body bytes and flags exactly.
//!
//! **Oracle #2 (independent): the magic + framing invariants.** Each body is 24 bytes,
//! begins with the field's big-endian magic, and round-trips through the ported
//! [`crate::ntp::ext::parse_field`].

use super::*;
use crate::ntp::ext::parse_field;

fn vec_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}=")))
}

/// Build a fresh v4 packet/info pair and run the named scenario, returning the appended
/// 24-byte body (or `None` if no field was appended) and the resulting flags.
fn run(tag: &str) -> (Option<[u8; 24]>, i32) {
    let mut pkt = NtpPacketBuf::new();
    pkt.set_lvm(4 << 3); // NTPv4 so parse_field accepts the packet
    let mut info = NtpPacketInfo {
        length: crate::ntp::ext::NTP_HEADER_LENGTH,
        version: 4,
        ..Default::default()
    };
    let server = 4; // chrony MODE_SERVER
    let client = MODE_CLIENT;
    let rx = Timespec::new(2_000_000_000, 250_000_000);

    let ret = match tag {
        "MR_CLIENT" => {
            info.mode = client;
            add_ef_mono_root(&mut pkt, &mut info, Some(rx), 0.0, 0, 0.01, 0.02)
        }
        "MR_SERVER" => {
            info.mode = server;
            add_ef_mono_root(&mut pkt, &mut info, Some(rx), 0.001, 0x1234_5678, 0.01, 0.02)
        }
        "MR_SERVER_NORX" => {
            info.mode = server;
            add_ef_mono_root(&mut pkt, &mut info, None, 0.001, 0x9abc_def0, 0.05, 0.1)
        }
        "NC_DISABLED" => {
            info.mode = server;
            add_ef_net_correction(&mut pkt, &mut info, 0, 0.01, 0.001)
        }
        "NC_CLIENT" => {
            info.mode = client;
            add_ef_net_correction(&mut pkt, &mut info, 319, 0.01, 0.001)
        }
        "NC_SERVER" => {
            info.mode = server;
            add_ef_net_correction(&mut pkt, &mut info, 319, 0.0123, 0.001)
        }
        "NC_SERVER_NOCORR" => {
            info.mode = server;
            add_ef_net_correction(&mut pkt, &mut info, 319, 0.0005, 0.001)
        }
        other => panic!("unknown scenario {other}"),
    };
    assert!(ret, "{tag}: builder returned false");

    if info.length <= crate::ntp::ext::NTP_HEADER_LENGTH {
        return (None, info.ext_field_flags);
    }
    let pf = parse_field(&pkt, info.length, crate::ntp::ext::NTP_HEADER_LENGTH).unwrap();
    let mut body = [0u8; 24];
    assert_eq!(pf.body_length, 24, "{tag}: body length");
    body.copy_from_slice(&pkt.bytes()[pf.body_offset..pf.body_offset + 24]);
    (Some(body), info.ext_field_flags)
}

#[test]
fn matches_real_c_ef_builder_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-ef-c-vectors.txt");
    for l in vectors.lines().map(str::trim).filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let tag = l.split_whitespace().next().unwrap();
        let (body, flags) = run(tag);

        assert_eq!(flags, vec_field(l, "flags").unwrap().parse::<i32>().unwrap(), "{tag} flags");

        match vec_field(l, "body") {
            Some(hex) => {
                let body = body.unwrap_or_else(|| panic!("{tag}: expected a field"));
                let got: String = body.iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(got, hex, "{tag} body");
            }
            None => assert!(body.is_none(), "{tag}: expected no field"),
        }
    }
}

#[test]
fn bodies_carry_magic_and_round_trip() {
    for (tag, magic) in [
        ("MR_SERVER", NTP_EF_EXP_MONO_ROOT_MAGIC),
        ("NC_SERVER", NTP_EF_EXP_NET_CORRECTION_MAGIC),
    ] {
        let (body, _) = run(tag);
        let body = body.unwrap();
        assert_eq!(&body[0..4], &magic.to_be_bytes(), "{tag} magic");
        assert_eq!(body.len(), 24, "{tag} length");
    }
}
