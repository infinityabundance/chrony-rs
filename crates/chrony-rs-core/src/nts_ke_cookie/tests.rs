//! Differential oracle for the cookie framing vs verbatim copies of chrony's
//! `NKS_GenerateCookie` / `NKS_DecodeCookie` (`nts_ke-cookie-c-vectors.txt`), using a
//! deterministic mock SIV identical to the generator's — so the byte layout, length
//! validations, `key_id` lookup, and key-length⇒algorithm mapping are pinned against the
//! real C. A separate round-trip test exercises the composition over the genuine ported
//! AES-SIV-CMAC-256.

use super::*;
use crate::nts_ke_record::AEAD_AES_SIV_CMAC_256;
use crate::siv_nettle::{SivAlgorithm, SivInstance};

/// The generator's deterministic mock cipher: `ciphertext = tag(16) || (plaintext XOR
/// nonce)`, with `tag[i] = i*3 + sum(plaintext) + nonce[i % nonce_len]` (byte-wrapped).
struct MockSiv;
impl Siv for MockSiv {
    fn max_nonce_length(&self) -> i32 {
        64
    }
    fn tag_length(&self) -> i32 {
        16
    }
    fn encrypt(&mut self, nonce: &[u8], _assoc: &[u8], pt: &[u8], ct: &mut [u8]) -> bool {
        if ct.len() != pt.len() + 16 {
            return false;
        }
        let sum: u32 = pt.iter().map(|&b| b as u32).sum();
        for i in 0..16 {
            ct[i] = (i as u32 * 3 + sum + nonce[i % nonce.len()] as u32) as u8;
        }
        for i in 0..pt.len() {
            ct[16 + i] = pt[i] ^ nonce[i % nonce.len()];
        }
        true
    }
    fn decrypt(&mut self, nonce: &[u8], _assoc: &[u8], ct: &[u8], pt: &mut [u8]) -> bool {
        if ct.len() != pt.len() + 16 {
            return false;
        }
        for i in 0..pt.len() {
            pt[i] = ct[16 + i] ^ nonce[i % nonce.len()];
        }
        let sum: u32 = pt.iter().map(|&b| b as u32).sum();
        for i in 0..16 {
            let t = (i as u32 * 3 + sum + nonce[i % nonce.len()] as u32) as u8;
            if ct[i] != t {
                return false;
            }
        }
        true
    }
}

fn f<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("missing {key} in: {line}"))
}
fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".to_string();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
/// The four server keys the generator uses: id `0x11110000 | index`, nonce length 16.
fn key_store() -> [(u32, usize); 4] {
    [(0x1111_0000, 16), (0x1111_0001, 16), (0x1111_0002, 16), (0x1111_0003, 16)]
}

#[test]
fn matches_real_c_cookie_vectors() {
    let vectors = include_str!("../../../../research/oracle/nts_ke-cookie-c-vectors.txt");
    // The injected nonce (chrony's UTI_GetRandomBytes): nonce[i] = 0x30 + i.
    let nonce: Vec<u8> = (0..64).map(|i| (0x30 + i) as u8).collect();

    // The canonical 32-byte-key cookie the DEC cases decode.
    let c2s32: Vec<u8> = (0..32).map(|i| (0x50 + i) as u8).collect();
    let s2c32: Vec<u8> = (0..32).map(|i| (0x70 + i) as u8).collect();
    let base_cookie = {
        let mut siv = MockSiv;
        let mut k = CookieKey { id: 0x1111_0002, siv: &mut siv, nonce_length: 16 };
        generate_cookie(&mut k, &nonce, &c2s32, &s2c32).expect("base cookie")
    };

    for line in vectors.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let tag = line.split_whitespace().next().unwrap();
        match tag {
            "GEN" => {
                if f(line, "clen") == "mismatch" {
                    let mut siv = MockSiv;
                    let mut k = CookieKey { id: 0x1111_0002, siv: &mut siv, nonce_length: 16 };
                    let c2s = vec![0x50u8; 32];
                    let s2c = vec![0x70u8; 16];
                    assert!(generate_cookie(&mut k, &nonce, &c2s, &s2c).is_none(), "GEN mismatch");
                    continue;
                }
                let clen: usize = f(line, "clen").parse().unwrap();
                let c2s: Vec<u8> = (0..clen).map(|i| (0x50 + i) as u8).collect();
                let s2c: Vec<u8> = (0..clen).map(|i| (0x70 + i) as u8).collect();
                let mut siv = MockSiv;
                let mut k = CookieKey { id: 0x1111_0002, siv: &mut siv, nonce_length: 16 };
                let cookie = generate_cookie(&mut k, &nonce, &c2s, &s2c).expect("cookie built");
                assert_eq!(cookie.len() as i64, f(line, "cklen").parse::<i64>().unwrap(), "GEN len");
                assert_eq!(hex(&cookie), f(line, "cookie"), "GEN cookie bytes");
            }
            "DEC" => {
                let name = f(line, "name");
                let cookie = match name {
                    "valid" => base_cookie.clone(),
                    "unknown_key" => {
                        let mut c = base_cookie.clone();
                        c[0..4].copy_from_slice(&0x2222_0001u32.to_be_bytes());
                        c
                    }
                    "too_short" => {
                        let mut c = vec![0u8; 4];
                        c.copy_from_slice(&0x1111_0002u32.to_be_bytes());
                        c
                    }
                    "corrupt" => {
                        let mut c = base_cookie.clone();
                        *c.last_mut().unwrap() ^= 0xFF;
                        c
                    }
                    "odd_ptlen" => base_cookie[..base_cookie.len() - 1].to_vec(),
                    other => panic!("unknown DEC case {other}"),
                };

                // Build the 4-key store (each with its own mock SIV).
                let store = key_store();
                let (mut s0, mut s1, mut s2, mut s3) = (MockSiv, MockSiv, MockSiv, MockSiv);
                let mut sivs: [&mut dyn Siv; 4] = [&mut s0, &mut s1, &mut s2, &mut s3];
                let mut keys: Vec<CookieKey> = Vec::new();
                for (siv, (id, nl)) in sivs.iter_mut().zip(store.iter()) {
                    // Reborrow each &mut dyn Siv into the CookieKey.
                    keys.push(CookieKey { id: *id, siv: &mut **siv, nonce_length: *nl });
                }
                let ctx = decode_cookie(&cookie, &mut keys);

                let want_ret = f(line, "ret") == "1";
                assert_eq!(ctx.is_some(), want_ret, "DEC {name} ret");
                if let Some(ctx) = ctx {
                    assert_eq!(ctx.algorithm as i64, f(line, "algo").parse::<i64>().unwrap(), "DEC {name} algo");
                    assert_eq!(hex(&ctx.c2s), f(line, "c2s"), "DEC {name} c2s");
                    assert_eq!(hex(&ctx.s2c), f(line, "s2c"), "DEC {name} s2c");
                    assert_eq!(ctx.c2s.len() as i64, f(line, "c2slen").parse::<i64>().unwrap(), "DEC {name} c2slen");
                }
            }
            _ => panic!("unknown tag {tag}"),
        }
    }
    let _ = unhex; // used only if a raw msg field is added later
}

/// The cookie survives a real generate→decode round-trip through the genuine ported
/// AES-SIV-CMAC-256 (not the mock): the recovered context equals the input, and the AEAD
/// algorithm is inferred from the 32-byte key length.
#[test]
fn round_trips_through_real_aes_siv_cmac() {
    let c2s: Vec<u8> = (0..32).map(|i| (0xA0u8).wrapping_add(i)).collect();
    let s2c: Vec<u8> = (0..32).map(|i| (0x10u8).wrapping_add(i)).collect();
    let nonce: Vec<u8> = (0..16).map(|i| (0x01 + i) as u8).collect();

    // key_id 0x1004 routes to store index 0 (0x1004 % 4 == 0).
    let cookie = {
        let mut siv = SivInstance::create(SivAlgorithm::AesSivCmac256).unwrap();
        assert!(siv.set_key(&[0x5Au8; 32]));
        let mut k = CookieKey { id: 0x1004, siv: &mut siv, nonce_length: 16 };
        generate_cookie(&mut k, &nonce, &c2s, &s2c).expect("real cookie")
    };

    let mut siv0 = SivInstance::create(SivAlgorithm::AesSivCmac256).unwrap();
    assert!(siv0.set_key(&[0x5Au8; 32]));
    let (mut d1, mut d2, mut d3) = (MockSiv, MockSiv, MockSiv);
    let mut keys = vec![
        CookieKey { id: 0x1004, siv: &mut siv0, nonce_length: 16 },
        CookieKey { id: 0xFFFF_0001, siv: &mut d1, nonce_length: 16 },
        CookieKey { id: 0xFFFF_0002, siv: &mut d2, nonce_length: 16 },
        CookieKey { id: 0xFFFF_0003, siv: &mut d3, nonce_length: 16 },
    ];
    let ctx = decode_cookie(&cookie, &mut keys).expect("decoded");
    assert_eq!(ctx.algorithm, AEAD_AES_SIV_CMAC_256);
    assert_eq!(ctx.c2s, c2s);
    assert_eq!(ctx.s2c, s2c);

    // A tampered ciphertext fails the real AEAD tag check.
    let mut bad = cookie.clone();
    *bad.last_mut().unwrap() ^= 0x01;
    let mut siv0b = SivInstance::create(SivAlgorithm::AesSivCmac256).unwrap();
    assert!(siv0b.set_key(&[0x5Au8; 32]));
    let (mut e1, mut e2, mut e3) = (MockSiv, MockSiv, MockSiv);
    let mut keys2 = vec![
        CookieKey { id: 0x1004, siv: &mut siv0b, nonce_length: 16 },
        CookieKey { id: 0xFFFF_0001, siv: &mut e1, nonce_length: 16 },
        CookieKey { id: 0xFFFF_0002, siv: &mut e2, nonce_length: 16 },
        CookieKey { id: 0xFFFF_0003, siv: &mut e3, nonce_length: 16 },
    ];
    assert!(decode_cookie(&bad, &mut keys2).is_none(), "tampered cookie must be rejected");
}
