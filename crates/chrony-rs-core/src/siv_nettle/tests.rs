//! Tests for the `siv_nettle.c` port.
//!
//! **Oracle #1: the real compiled `siv_nettle.c`** (which `#include`s
//! `siv_nettle_int.c`) over a FIPS-197-verified shim AES. The C generator records
//! the key-length table, instance creation, key setting, the validation results in
//! encrypt/decrypt, a round-trip, tamper rejection, and the no-key refusal
//! (`research/oracle/siv_nettle-c-vectors.txt`); [`matches_real_c_siv_nettle_vectors`]
//! replays the identical script and matches every value.
//!
//! **Oracle #2: composition.** A keyed [`SivInstance`] is a real
//! [`crate::nts_ntp_auth::Siv`], so the NTS authenticator round-trips over genuine
//! AES-SIV-CMAC ([`nts_auth_round_trips_over_real_siv`]).

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Pull `key=value` from a line by key.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

#[test]
fn matches_real_c_siv_nettle_vectors() {
    let vectors = include_str!("../../../../research/oracle/siv_nettle-c-vectors.txt");
    let mut lines = vectors.lines().filter(|l| !l.trim_start().starts_with('#')).map(str::trim);

    // The fixed inputs the generator uses.
    let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let nonce = unhex("00112233445566778899aabbccddeeff");
    let ad = unhex("a0a1a2a3");
    let pt = unhex("0102030405060708090a");

    // KEYLEN
    let l = lines.next().unwrap();
    assert_eq!(get_key_length(SivAlgorithm::AesSivCmac256), field(l, "cmac256").parse::<i32>().unwrap());
    assert_eq!(get_key_length(SivAlgorithm::AesSivCmac384), field(l, "cmac384").parse::<i32>().unwrap());
    assert_eq!(get_key_length(SivAlgorithm::Aes128GcmSiv), field(l, "gcm128").parse::<i32>().unwrap());

    // CREATE gcm_null
    let l = lines.next().unwrap();
    assert_eq!(
        SivInstance::create(SivAlgorithm::Aes128GcmSiv).is_none(),
        field(l, "gcm_null") == "1"
    );

    // CREATE cmac
    let l = lines.next().unwrap();
    let mut s = SivInstance::create(SivAlgorithm::AesSivCmac256).expect("cmac256 supported");
    assert!(field(l, "cmac_ok") == "1");
    assert_eq!(s.min_nonce_length(), field(l, "min").parse::<i32>().unwrap());
    assert_eq!(s.max_nonce_length(), field(l, "max").parse::<i32>().unwrap());
    assert_eq!(s.tag_length(), field(l, "tag").parse::<i32>().unwrap());

    // SETKEY short/ok
    let l = lines.next().unwrap();
    assert_eq!(s.set_key(&key[..16]), field(l, "short") == "1");
    assert_eq!(s.set_key(&key), field(l, "ok") == "1");

    let cl = pt.len() + s.tag_length() as usize;

    // ENC badnonce (empty nonce < min)
    let l = lines.next().unwrap();
    let mut ct = vec![0u8; cl];
    assert_eq!(s.encrypt(&[], &ad, &pt, &mut ct), field(l, "badnonce") == "1");

    // ENC badctlen (ciphertext one byte short)
    let l = lines.next().unwrap();
    let mut ct_short = vec![0u8; cl - 1];
    assert_eq!(s.encrypt(&nonce, &ad, &pt, &mut ct_short), field(l, "badctlen") == "1");

    // ENC ok + CT
    let l = lines.next().unwrap();
    let mut ct = vec![0u8; cl];
    assert_eq!(s.encrypt(&nonce, &ad, &pt, &mut ct), field(l, "ok") == "1");
    assert_eq!(cl as i32, field(l, "cl").parse::<i32>().unwrap());
    let ct_line = lines.next().unwrap().strip_prefix("CT ").unwrap();
    assert_eq!(hex(&ct), ct_line);

    // DEC ok + PT
    let l = lines.next().unwrap();
    let mut out = vec![0u8; pt.len()];
    assert_eq!(s.decrypt(&nonce, &ad, &ct, &mut out), field(l, "ok") == "1");
    let pt_line = lines.next().unwrap().strip_prefix("PT ").unwrap();
    assert_eq!(hex(&out), pt_line);

    // DEC tampered
    let l = lines.next().unwrap();
    let mut bad = ct.clone();
    *bad.last_mut().unwrap() ^= 0xff;
    assert_eq!(s.decrypt(&nonce, &ad, &bad, &mut out), field(l, "tampered") == "1");

    // ENC nokey
    let l = lines.next().unwrap();
    let s2 = SivInstance::create(SivAlgorithm::AesSivCmac256).unwrap();
    let mut ct2 = vec![0u8; cl];
    assert_eq!(s2.encrypt(&nonce, &ad, &pt, &mut ct2), field(l, "nokey") == "1");
}

#[test]
fn nts_auth_round_trips_over_real_siv() {
    use crate::nts_ntp_auth::{decrypt_auth_ef, generate_auth_ef};
    use crate::ntp::ext::{NtpPacketBuf, NtpPacketInfo, NTP_HEADER_LENGTH};

    // A real AES-SIV-CMAC-256 instance, used as the NTS authenticator's cipher.
    let key = unhex("0f0e0d0c0b0a09080706050403020100101112131415161718191a1b1c1d1e1f");
    let mut siv = SivInstance::create(SivAlgorithm::AesSivCmac256).unwrap();
    assert!(siv.set_key(&key));

    let mut pkt = NtpPacketBuf::new();
    {
        let b = pkt.bytes_mut();
        b[0] = 0x23;
        b[1] = 0x02;
    }
    let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, ext_fields: 0 };

    let nonce = [0x5au8; 16];
    let inner = b"encrypted inner extension fields";
    assert!(generate_auth_ef(&mut pkt, &mut info, &mut siv, &nonce, 16, inner, 0));

    let mut out = [0u8; 128];
    let n = decrypt_auth_ef(&pkt, &info, &mut siv, NTP_HEADER_LENGTH, &mut out)
        .expect("auth EF verifies and decrypts under real SIV");
    assert_eq!(&out[..n], inner, "NTS round-trip recovers the inner fields");
}
