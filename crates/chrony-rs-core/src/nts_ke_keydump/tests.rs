//! Differential oracle for the `ntskeys` dump codec vs verbatim copies of chrony's
//! `save_keys` / `load_keys` (driven over in-memory `open_memstream` / `fmemopen`;
//! `research/oracle/nts_ke-keydump-c-vectors.txt`).

use super::*;
use crate::util::bytes_to_hex;

fn f<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("missing {key} in: {line}"))
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
/// The oracle's SIV_GetKeyLength: CMAC-256 -> 32, GCM-SIV -> 16, else 0.
fn key_length(alg: i32) -> i32 {
    match alg {
        15 => 32,
        30 => 16,
        _ => 0,
    }
}

#[test]
fn matches_real_c_keydump_vectors() {
    let vectors = include_str!("../../../../research/oracle/nts_ke-keydump-c-vectors.txt");

    // ---- SAVE: the dump text spans multiple lines (between `text=` and `|END`). ----
    let start = vectors.find("text=").unwrap() + "text=".len();
    let end = vectors[start..].find("|END").unwrap() + start;
    let save_text = &vectors[start..end];

    // The generator's key store: id 0x1000+i at store index i, key[j] = 0x40 + j + 0x10*i.
    let keys: Vec<DumpKey> = (0..MAX_SERVER_KEYS)
        .map(|i| DumpKey {
            id: 0x1000 + i as u32,
            siv_algorithm: 15,
            key: (0..32).map(|j| (0x40 + j + 0x10 * i) as u8).collect(),
        })
        .collect();
    let out = format_keydump(0, &keys, 123.4, key_length).expect("dump formatted");
    assert_eq!(out, save_text, "save_keys text");

    // ---- LOAD: replay each case from its input text (hex). ----
    for line in vectors.lines().filter(|l| l.starts_with("LOAD ")) {
        let name = f(line, "name");
        let text = String::from_utf8(unhex(f(line, "intext"))).unwrap();
        let loaded = parse_keydump(&text, key_length);

        let want_ret = f(line, "ret") == "1";
        assert_eq!(loaded.is_some(), want_ret, "LOAD {name} ret");
        if let Some(l) = loaded {
            assert_eq!(format!("{:.1}", l.key_age), f(line, "key_age"), "LOAD {name} key_age");
            assert_eq!(l.current_server_key as i64, f(line, "cur").parse::<i64>().unwrap(), "LOAD {name} cur");
            for (j, k) in l.keys.iter().enumerate() {
                let want = format!(
                    "{:08X}/{}/{}",
                    k.id,
                    k.siv_algorithm,
                    bytes_to_hex(&k.key)
                );
                assert_eq!(want, f(line, &format!("k{j}")), "LOAD {name} k{j}");
            }
        }
    }
}

/// save → load round-trips: formatting a key store and parsing it back recovers the same
/// keys, current index, and age.
#[test]
fn save_load_round_trip() {
    let keys: Vec<DumpKey> = (0..MAX_SERVER_KEYS)
        .map(|i| DumpKey {
            id: 0x9000 + i as u32,
            siv_algorithm: 15,
            key: (0..32).map(|j| (i as u8).wrapping_mul(7).wrapping_add(j as u8)).collect(),
        })
        .collect();

    let text = format_keydump(1, &keys, 42.5, key_length).unwrap();
    let loaded = parse_keydump(&text, key_length).unwrap();

    assert_eq!(loaded.keys, keys, "keys survive the round-trip");
    assert_eq!(format!("{:.1}", loaded.key_age), "42.5");
    // current index = (last placed index - FUTURE_KEYS) mod MAX; the last written key in
    // rotation order from current=1 is index (1 + 3 + 1 + 1) % 4 = 2, so current = 1.
    assert_eq!(loaded.current_server_key, 1);
}
