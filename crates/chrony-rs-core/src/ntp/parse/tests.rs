//! Tests for `ntp_core.c` `parse_packet` (Stage 2).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`** (the static
//! `parse_packet` reached via the `#include` harness, with the real `ntp_ext.c`
//! linked for `NEF_ParseField`). A C generator crafts a plain v4 packet, an NTPv3 MAC,
//! an MS-SNTP authenticator, a crypto-NAK, an NTS extension field followed by a MAC,
//! and a bad-length packet, capturing every `NTP_PacketInfo` field
//! (`research/oracle/ntp_core-parse-c-vectors.txt`).
//! [`matches_real_c_parse_vectors`] parses the byte-identical packets and matches.
//!
//! **Oracle #2 (independent): `is_zero_data` / `is_exp_ef`.**

use super::*;

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}
fn i(line: &str, key: &str) -> i32 {
    field(line, key).parse().unwrap()
}

/// Build the exact packet the C generator built for `tag` (mirrors `genparse.c`).
fn build(tag: &str) -> (NtpPacketBuf, i32) {
    let mut p = NtpPacketBuf::new();
    let b = p.bytes_mut();
    match tag {
        "PLAIN" => {
            b[0] = (4 << 3) | 4;
            (p, 48)
        }
        "V3MAC" => {
            b[0] = (3 << 3) | 3;
            b[48..52].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
            for (k, x) in b[52..68].iter_mut().enumerate() {
                *x = (52 + k) as u8;
            }
            (p, 68)
        }
        "MSSNTP" => {
            b[0] = (3 << 3) | 4;
            b[48..52].copy_from_slice(&[0, 0, 0, 5]); // key id 5, zero digest
            (p, 68)
        }
        "CRYPTONAK" => {
            b[0] = (4 << 3) | 3;
            (p, 52) // remainder 4 == 0
        }
        "NTSEF" => {
            b[0] = (4 << 3) | 3;
            b[48..52].copy_from_slice(&[0x02, 0x04, 0x00, 0x10]); // NTS cookie EF, len 16
            for (k, x) in b[52..64].iter_mut().enumerate() {
                *x = (52 + k) as u8;
            }
            b[64..68].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]); // MAC key id
            for (k, x) in b[68..84].iter_mut().enumerate() {
                *x = (68 + k) as u8;
            }
            (p, 84)
        }
        "BADLEN" => {
            b[0] = (4 << 3) | 4;
            (p, 50) // not a multiple of 4
        }
        _ => unreachable!(),
    }
}

#[test]
fn matches_real_c_parse_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-parse-c-vectors.txt");
    let find = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    for tag in ["PLAIN", "V3MAC", "MSSNTP", "CRYPTONAK", "NTSEF"] {
        let l = find(tag);
        let (p, len) = build(tag);
        let info = parse_packet(&p, len).unwrap_or_else(|| panic!("{tag} should parse"));
        assert_eq!(i(l, "ret"), 1, "{tag} ret");
        assert_eq!(info.version, i(l, "ver"), "{tag} version");
        assert_eq!(info.mode, i(l, "mode"), "{tag} mode");
        assert_eq!(info.ext_fields, i(l, "ef"), "{tag} ext_fields");
        assert_eq!(info.ext_field_flags, i(l, "efflags"), "{tag} ext_field_flags");
        assert_eq!(info.auth_mode, i(l, "auth"), "{tag} auth_mode");
        assert_eq!(info.mac_start, i(l, "macstart"), "{tag} mac_start");
        assert_eq!(info.mac_length, i(l, "maclen"), "{tag} mac_length");
        let want_key =
            u32::from_str_radix(field(l, "mackey").trim_start_matches("0x"), 16).unwrap();
        assert_eq!(info.mac_key_id, want_key, "{tag} mac_key_id");
    }

    // BADLEN: a length that is not a multiple of 4 is rejected.
    let l = find("BADLEN");
    let (p, len) = build("BADLEN");
    assert_eq!(parse_packet(&p, len).is_none(), i(l, "ret") == 0, "BADLEN rejected");
}

#[test]
fn zero_data_and_exp_ef_helpers() {
    assert!(is_zero_data(&[0, 0, 0]));
    assert!(is_zero_data(&[]));
    assert!(!is_zero_data(&[0, 1, 0]));

    // is_exp_ef: correct length + leading big-endian magic.
    let mut body = vec![0u8; 24];
    body[0..4].copy_from_slice(&0xF5BE_DD9Au32.to_be_bytes());
    assert!(is_exp_ef(&body, 24, 0xF5BE_DD9A), "matching magic + length");
    assert!(!is_exp_ef(&body, 20, 0xF5BE_DD9A), "wrong expected length");
    assert!(!is_exp_ef(&body, 24, 0x0000_0001), "wrong magic");
}
