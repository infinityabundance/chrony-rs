//! Tests for the `siv_nettle_int.c` port (AES-SIV-CMAC-256).
//!
//! Three independent oracles:
//! * **FIPS-197** known-answer test for the AES-128 primitive
//!   ([`aes128_fips197_kat`]).
//! * **RFC 5297 §A.1** — the official AES-SIV worked example, asserted directly
//!   ([`rfc5297_a1_worked_example`]) and also present in the differential fixture.
//! * **The real compiled `siv_nettle_int.c`** over a FIPS-197-verified shim AES: a
//!   C generator emits encrypt/decrypt vectors over many shapes
//!   (`research/oracle/siv_nettle_int-c-vectors.txt`);
//!   [`matches_real_c_siv_vectors`] replays every case and matches the ciphertext,
//!   the decrypt verification result, and the recovered plaintext.

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn aes128_fips197_kat() {
    // FIPS-197: AES-128(key = 0^16) of the all-zero block.
    let aes = Aes128::new(&[0u8; 16]);
    assert_eq!(hex(&aes.encrypt_block(&[0u8; 16])), "66e94bd4ef8a2c3b884cfa59ca342b2e");

    // FIPS-197 Appendix B worked example.
    let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
    let pt = unhex("3243f6a8885a308d313198a2e0370734");
    let aes = Aes128::new(key.as_slice().try_into().unwrap());
    assert_eq!(
        hex(&aes.encrypt_block(pt.as_slice().try_into().unwrap())),
        "3925841d02dc09fbdc118597196a0b32"
    );
}

#[test]
fn rfc5297_a1_worked_example() {
    // RFC 5297 Appendix A.1: deterministic AES-SIV (single AD, no nonce).
    let key = unhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let ad = unhex("101112131415161718191a1b1c1d1e1f2021222324252627");
    let pt = unhex("112233445566778899aabbccddee");

    let siv = SivCmacAes128::set_key(key.as_slice().try_into().unwrap());
    let mut ct = vec![0u8; pt.len() + SIV_DIGEST_SIZE];
    siv.encrypt_message(&[], &ad, &mut ct, &pt);
    assert_eq!(hex(&ct), "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");

    let mut out = vec![0u8; pt.len()];
    assert!(siv.decrypt_message(&[], &ad, &mut out, &ct));
    assert_eq!(out, pt);
}

#[test]
fn matches_real_c_siv_vectors() {
    let vectors = include_str!("../../../../research/oracle/siv_nettle_int-c-vectors.txt");

    let lines: Vec<&str> = vectors.lines().filter(|l| !l.trim_start().starts_with('#')).collect();
    let mut i = 0;
    let mut cases = 0;
    while i < lines.len() {
        let l = lines[i].trim();
        if let Some(rest) = l.strip_prefix("AESKAT ") {
            let aes = Aes128::new(&[0u8; 16]);
            assert_eq!(hex(&aes.encrypt_block(&[0u8; 16])), rest, "AES KAT");
            i += 1;
        } else if let Some(rest) = l.strip_prefix("IN ") {
            let field = |k: &str| -> String {
                rest.split_whitespace()
                    .find_map(|t| t.strip_prefix(&format!("{k}=")))
                    .unwrap_or("")
                    .to_string()
            };
            let key = unhex(&field("key"));
            let ad = unhex(&field("ad"));
            let nonce = unhex(&field("nonce"));
            let pt = unhex(&field("pt"));

            // CASE line (lengths) then CT, DEC, PT.
            let ct_line = lines[i + 2].trim().strip_prefix("CT ").unwrap();
            let dec_line = lines[i + 3].trim();
            let dec_ok = dec_line.strip_prefix("DEC ok=").unwrap() == "1";
            let pt_line = lines[i + 4].trim().strip_prefix("PT ").unwrap_or("");

            let siv = SivCmacAes128::set_key(key.as_slice().try_into().unwrap());
            let mut ct = vec![0u8; pt.len() + SIV_DIGEST_SIZE];
            siv.encrypt_message(&nonce, &ad, &mut ct, &pt);
            assert_eq!(hex(&ct), ct_line, "ciphertext case {cases}");

            let expected_ct = unhex(ct_line);
            let mut out = vec![0u8; pt.len()];
            let ok = siv.decrypt_message(&nonce, &ad, &mut out, &expected_ct);
            assert_eq!(ok, dec_ok, "decrypt ok case {cases}");
            assert_eq!(hex(&out), pt_line, "recovered plaintext case {cases}");

            cases += 1;
            i += 5;
        } else {
            i += 1;
        }
    }
    assert!(cases >= 8, "expected many SIV cases, got {cases}");
}

#[test]
fn decrypt_rejects_tampered_input() {
    let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let siv = SivCmacAes128::set_key(key.as_slice().try_into().unwrap());
    let ad = b"associated";
    let nonce = b"0123456789abcdef";
    let pt = b"top secret payload";

    let mut ct = vec![0u8; pt.len() + SIV_DIGEST_SIZE];
    siv.encrypt_message(nonce, ad, &mut ct, pt);

    // Flip a ciphertext byte -> verification must fail.
    let mut bad = ct.clone();
    let n = bad.len();
    bad[n - 1] ^= 0x01;
    let mut out = vec![0u8; pt.len()];
    assert!(!siv.decrypt_message(nonce, ad, &mut out, &bad));

    // Flip the SIV tag -> also fails.
    let mut bad2 = ct.clone();
    bad2[0] ^= 0x01;
    assert!(!siv.decrypt_message(nonce, ad, &mut out, &bad2));

    // Wrong associated data -> fails.
    let mut out2 = vec![0u8; pt.len()];
    assert!(!siv.decrypt_message(nonce, b"different", &mut out2, &ct));
}
