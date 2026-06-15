//! Tests for the `keys.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `keys.c`** (internal-MD5 build).
//! A C generator loads the committed key file and emits, per key id, the public
//! API results including the MAC bytes; [`matches_real_c_keys_vectors`] replays the
//! exact same key file through this port and asserts every field.
//!
//! **Oracle #2 (independent): the NTP symmetric MAC definition.** The MAC is
//! `MD5(key || message)`; [`mac_is_md5_of_key_then_message`] checks the store's
//! output against the RFC-1321-vectored [`md5`](crate::md5) directly, with no
//! reference to `keys.c`.

use super::*;

const KEYFILE: &str = include_str!("../../../../research/oracle/keys-c-keyfile.txt");
const VECTORS: &str = include_str!("../../../../research/oracle/keys-c-vectors.txt");

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix(&format!("{key}=")) {
            return v;
        }
    }
    panic!("missing field {key} in: {line}");
}

#[test]
fn matches_real_c_keys_vectors() {
    // The data string is carried in the fixture's `DATA` line so the port MACs
    // exactly what the C generator did.
    let data = VECTORS
        .lines()
        .find_map(|l| l.strip_prefix("DATA "))
        .expect("vectors carry the DATA line")
        .as_bytes();

    let mut store = KeyStore::initialise(Some(KEYFILE));
    let mut key_lines = 0;

    for raw in VECTORS.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("KEY ") {
            let id: u32 = field(rest, "id").parse().unwrap();
            let known = field(rest, "known") == "1";
            let authlen: i32 = field(rest, "authlen").parse().unwrap();
            let seclen = field(rest, "seclen") == "1";
            let info = field(rest, "info") == "1";
            let exp_type: i32 = field(rest, "type").parse().unwrap();
            let exp_bits: i32 = field(rest, "bits").parse().unwrap();
            let maclen: usize = field(rest, "maclen").parse().unwrap();
            let mac_hex = field(rest, "mac");

            assert_eq!(store.key_known(id), known, "known id={id}");
            assert_eq!(store.get_auth_length(id), authlen, "authlen id={id}");
            assert_eq!(store.check_key_length(id), seclen, "seclen id={id}");

            match store.get_key_info(id) {
                Some((t, b)) => {
                    assert!(info, "info id={id}: expected None");
                    assert_eq!(t, exp_type, "type id={id}");
                    assert_eq!(b, exp_bits, "bits id={id}");
                }
                None => assert!(!info, "info id={id}: expected Some"),
            }

            let mut auth = [0u8; MAX_HASH_LENGTH];
            let got = store.generate_key_auth(id, data, &mut auth);
            assert_eq!(got, maclen, "maclen id={id}");
            assert_eq!(util::bytes_to_hex(&auth[..got]).to_lowercase(), mac_hex, "mac id={id}");
            key_lines += 1;
        } else if let Some(rest) = line.strip_prefix("CHK ") {
            let id: u32 = field(rest, "id").parse().unwrap();
            let full = field(rest, "full") == "1";
            let bad = field(rest, "bad") == "1";
            // `trunc=N(M)`: M is the truncation/auth length used.
            let trunc_field = field(rest, "trunc");
            let trunc_ok = trunc_field.starts_with('1');
            let trunc_len: usize = trunc_field
                .split('(')
                .nth(1)
                .and_then(|s| s.trim_end_matches(')').parse().ok())
                .unwrap();

            let mut auth = [0u8; MAX_HASH_LENGTH];
            let n = store.generate_key_auth(id, data, &mut auth);

            if n > 0 {
                // full-length check
                assert_eq!(store.check_key_auth(id, data, &auth[..n], 64), full, "chk full id={id}");
                // truncated check
                assert_eq!(
                    store.check_key_auth(id, data, &auth[..trunc_len], trunc_len),
                    trunc_ok,
                    "chk trunc id={id}"
                );
                // corrupted first byte
                let mut corrupt = auth;
                corrupt[0] ^= 0xff;
                assert_eq!(store.check_key_auth(id, data, &corrupt[..n], 64), bad, "chk bad id={id}");
            } else {
                assert!(!full && !bad, "chk id={id}: unknown key must fail all checks");
            }
        }
    }

    assert!(key_lines >= 10, "expected many key probes, got {key_lines}");
}

#[test]
fn mac_is_md5_of_key_then_message() {
    // Independent of keys.c: the NTP symmetric MAC is MD5(key || message). Build a
    // store with one ASCII key and confirm GenerateAuth equals the direct MD5.
    let keyfile = "42 MD5 ASCII:correcthorsebatterystaple\n";
    let mut store = KeyStore::initialise(Some(keyfile));
    let data = b"NTP packet bytes here";

    let mut auth = [0u8; MAX_HASH_LENGTH];
    let n = store.generate_key_auth(42, data, &mut auth);
    assert_eq!(n, 16, "MD5 MAC is 16 bytes");

    let expected = ntp_md5_mac(b"correcthorsebatterystaple", data);
    assert_eq!(&auth[..16], &expected, "store MAC must equal MD5(key||message)");

    // And the full-length verify accepts exactly that MAC.
    assert!(store.check_key_auth(42, data, &expected, 64));
}

#[test]
fn no_keyfile_is_empty_and_unknown() {
    let mut store = KeyStore::initialise(None);
    assert!(store.is_empty());
    assert!(!store.key_known(1));
    assert_eq!(store.get_auth_length(1), 0);
    assert!(!store.check_key_length(1));
    assert_eq!(store.get_key_info(1), None);
}

#[test]
fn decode_key_handles_ascii_hex_and_bare() {
    assert_eq!(decode_key("ASCII:abc"), Some(b"abc".to_vec()));
    assert_eq!(decode_key("HEX:0a0b0c"), Some(vec![0x0a, 0x0b, 0x0c]));
    assert_eq!(decode_key("bareword"), Some(b"bareword".to_vec()));
    // Malformed hex (odd nibble count) is rejected, like chrony's length-0 case.
    assert_eq!(decode_key("HEX:0a0"), None);
}

#[test]
fn unsupported_and_invalid_types_are_rejected_with_warnings() {
    // SHA256 (unsupported hash here), AES128 (no CMAC backend), and a bogus type
    // are all rejected, leaving only the MD5 key loaded.
    let keyfile = "\
1 MD5 ASCII:thiskeyislongenough
2 SHA256 ASCII:rejectedhash
3 AES128 HEX:000102030405060708090a0b0c0d0e0f
4 BOGUS ASCII:rejectedtype
";
    let mut store = KeyStore::initialise(Some(keyfile));
    assert_eq!(store.len(), 1, "only the MD5 key should load");
    assert!(store.key_known(1));
    assert!(!store.key_known(2));
    assert!(!store.key_known(3));
    assert!(!store.key_known(4));
    assert!(store.warnings().iter().any(|w| w.contains("Unsupported hash function in key 2")));
    assert!(store.warnings().iter().any(|w| w.contains("Unsupported cipher in key 3")));
    assert!(store.warnings().iter().any(|w| w.contains("Invalid type in key 4")));
}

#[test]
fn duplicate_id_warns_and_remains_known() {
    let keyfile = "7 MD5 ASCII:firstkeyvalue\n7 MD5 ASCII:secondkeyvalue\n";
    let mut store = KeyStore::initialise(Some(keyfile));
    assert_eq!(store.len(), 2, "both lines load; lookup resolves to one");
    assert!(store.key_known(7));
    assert!(store.warnings().iter().any(|w| w.contains("Detected duplicate key 7")));
}
