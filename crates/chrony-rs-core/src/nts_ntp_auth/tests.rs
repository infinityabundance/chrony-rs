//! Tests for the `nts_ntp_auth.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `nts_ntp_auth.c`** (+ `ntp_ext.c`).
//! A C generator builds a packet, adds the auth EF for several plaintext/nonce/
//! min-length cases, and records the packet bytes plus the decrypt round-trip with a
//! deterministic toy SIV (`research/oracle/nts_ntp_auth-c-vectors.txt`).
//! [`matches_real_c_nts_ntp_auth_vectors`] replays the identical cases with the same
//! toy SIV and asserts identical packet bytes and recovered plaintext.
//!
//! **Oracle #2 (independent): the framing arithmetic + round-trip.** Padding to
//! 4-byte boundaries and a generate→decrypt round-trip are checked directly.

use super::*;
use crate::ntp::ext::{NtpPacketBuf, NtpPacketInfo, NTP_HEADER_LENGTH};

/// The deterministic toy SIV from the C oracle stub, replicated byte-for-byte:
/// tag = 16 bytes, keystream byte i = `nonce[i%nl] ^ i`, tag byte i =
/// `fold(assoc) ^ fold(plaintext) ^ nonce[i%nl] ^ i`.
struct ToySiv;

const TOY_TAG: usize = 16;

fn fold(p: &[u8]) -> u8 {
    p.iter().fold(0u8, |a, &b| a ^ b)
}

fn toy_tag(nonce: &[u8], assoc: &[u8], plaintext: &[u8]) -> [u8; TOY_TAG] {
    let fa = fold(assoc);
    let fp = fold(plaintext);
    let nl = nonce.len();
    let mut tag = [0u8; TOY_TAG];
    for (i, t) in tag.iter_mut().enumerate() {
        let n = if nl != 0 { nonce[i % nl] } else { 0 };
        *t = fa ^ fp ^ n ^ i as u8;
    }
    tag
}

impl Siv for ToySiv {
    fn max_nonce_length(&self) -> i32 {
        16
    }
    fn tag_length(&self) -> i32 {
        TOY_TAG as i32
    }
    fn encrypt(&mut self, nonce: &[u8], assoc: &[u8], plaintext: &[u8], ct: &mut [u8]) -> bool {
        if ct.len() != TOY_TAG + plaintext.len() {
            return false;
        }
        let tag = toy_tag(nonce, assoc, plaintext);
        ct[..TOY_TAG].copy_from_slice(&tag);
        let nl = nonce.len();
        for (i, p) in plaintext.iter().enumerate() {
            let n = if nl != 0 { nonce[i % nl] } else { 0 };
            ct[TOY_TAG + i] = p ^ (n ^ i as u8);
        }
        true
    }
    fn decrypt(&mut self, nonce: &[u8], assoc: &[u8], ct: &[u8], plaintext: &mut [u8]) -> bool {
        if ct.len() != TOY_TAG + plaintext.len() {
            return false;
        }
        let nl = nonce.len();
        for (i, p) in plaintext.iter_mut().enumerate() {
            let n = if nl != 0 { nonce[i % nl] } else { 0 };
            *p = ct[TOY_TAG + i] ^ (n ^ i as u8);
        }
        let tag = toy_tag(nonce, assoc, plaintext);
        tag[..] == ct[..TOY_TAG]
    }
}

/// Build the exact 48-byte NTP header the C generator uses.
fn make_packet() -> NtpPacketBuf {
    let mut pkt = NtpPacketBuf::new();
    let buf = pkt.bytes_mut();
    for (i, b) in buf[..48].iter_mut().enumerate() {
        *b = match i {
            0 => 0x23,
            1 => 0x02,
            2 | 3 => 0,
            _ => (i * 7 + 1) as u8,
        };
    }
    pkt
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn matches_real_c_nts_ntp_auth_vectors() {
    let vectors = include_str!("../../../../research/oracle/nts_ntp_auth-c-vectors.txt");

    // Each case: (plaintext_len, nonce_len, min_ef_length) in the generator's order.
    let cases: &[(i32, i32, i32)] =
        &[(0, 16, 0), (8, 16, 0), (13, 16, 0), (8, 12, 0), (8, 16, 64), (32, 16, 0)];

    // Parse GEN/PKT/DEC/PT lines into per-case expectations (in order).
    struct Exp {
        gen_ok: bool,
        length: i32,
        ext_fields: i32,
        pkt: String,
        dec_ok: bool,
        pt_len: i32,
        pt: String,
    }
    let mut exps: Vec<Exp> = Vec::new();
    let lines: Vec<&str> = vectors.lines().filter(|l| !l.trim_start().starts_with('#')).collect();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim();
        if let Some(rest) = l.strip_prefix("GEN ") {
            let f = |k: &str| -> &str {
                rest.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap()
            };
            let gen_ok = f("ok") == "1";
            let length: i32 = f("length").parse().unwrap();
            let ext_fields: i32 = f("ext_fields").parse().unwrap();
            i += 1;
            let mut pkt = String::new();
            if gen_ok {
                pkt = lines[i].trim().strip_prefix("PKT ").unwrap().to_string();
                i += 1;
            }
            // DEC line
            let dl = lines[i].trim();
            let df = |k: &str| -> &str {
                dl.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap()
            };
            let dec_ok = df("ok") == "1";
            let pt_len: i32 = df("plaintext_length").parse().unwrap();
            i += 1;
            let mut pt = String::new();
            if dec_ok {
                pt = lines[i].trim().strip_prefix("PT ").unwrap_or("").to_string();
                i += 1;
            }
            exps.push(Exp { gen_ok, length, ext_fields, pkt, dec_ok, pt_len, pt });
        } else {
            i += 1;
        }
    }

    assert_eq!(exps.len(), cases.len(), "parsed case count");

    for (idx, (&(pl, nl, min_ef), exp)) in cases.iter().zip(exps.iter()).enumerate() {
        let mut pkt = make_packet();
        let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: 0, ext_fields: 0 };
        let mut siv = ToySiv;

        let nonce: Vec<u8> = (0..nl).map(|i| (0xA0 + i) as u8).collect();
        let plaintext: Vec<u8> = (0..pl).map(|i| (i * 3 + 5) as u8).collect();

        let ok = generate_auth_ef(&mut pkt, &mut info, &mut siv, &nonce, nl, &plaintext, min_ef);
        assert_eq!(ok, exp.gen_ok, "gen ok case {idx}");
        assert_eq!(info.length, exp.length, "info.length case {idx}");
        assert_eq!(info.ext_fields, exp.ext_fields, "ext_fields case {idx}");
        if ok {
            assert_eq!(hex(&pkt.bytes()[..info.length as usize]), exp.pkt, "packet bytes case {idx}");

            let mut out = [0u8; 256];
            let dec = decrypt_auth_ef(&pkt, &info, &mut siv, NTP_HEADER_LENGTH, &mut out);
            assert_eq!(dec.is_some(), exp.dec_ok, "dec ok case {idx}");
            if let Some(n) = dec {
                assert_eq!(n as i32, exp.pt_len, "pt len case {idx}");
                assert_eq!(hex(&out[..n]), exp.pt, "plaintext case {idx}");
            }
        }
    }
}

#[test]
fn independent_round_trip_and_padding() {
    // Padding arithmetic, independent of the C code.
    assert_eq!(get_padding_length(0), 0);
    assert_eq!(get_padding_length(13), 3);
    assert_eq!(get_padding_length(16), 0);
    assert_eq!(get_padded_length(13), 16);

    // A generate→decrypt round-trip recovers the plaintext, and the field lands on
    // a 4-byte boundary.
    let mut pkt = make_packet();
    let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: 0, ext_fields: 0 };
    let mut siv = ToySiv;
    let nonce = [0x11u8; 16];
    let plaintext = b"inner extension fields";

    assert!(generate_auth_ef(&mut pkt, &mut info, &mut siv, &nonce, 16, plaintext, 0));
    assert_eq!(info.length % 4, 0, "packet length stays 4-aligned");
    assert_eq!(info.ext_fields, 1);

    let mut out = [0u8; 256];
    let n = decrypt_auth_ef(&pkt, &info, &mut siv, NTP_HEADER_LENGTH, &mut out).unwrap();
    assert_eq!(&out[..n], plaintext, "round-trip recovers plaintext");
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    let mut pkt = make_packet();
    let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: 0, ext_fields: 0 };
    let mut siv = ToySiv;
    let nonce = [0x22u8; 16];
    assert!(generate_auth_ef(&mut pkt, &mut info, &mut siv, &nonce, 16, b"secret!!", 0));

    // Flip a byte in the last 4 bytes (inside the ciphertext) and expect rejection.
    let n = info.length as usize;
    pkt.bytes_mut()[n - 1] ^= 0xff;

    let mut out = [0u8; 256];
    assert!(decrypt_auth_ef(&pkt, &info, &mut siv, NTP_HEADER_LENGTH, &mut out).is_none());
}
