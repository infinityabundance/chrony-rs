//! Tests for the `cmac_nettle.c` port.
//!
//! Three independent oracles:
//! * **RFC 4493 §4** AES-128-CMAC vectors, asserted directly.
//! * **NIST SP 800-38B** AES-256-CMAC vectors (+ FIPS-197 AES-256 KAT), asserted
//!   directly.
//! * **The real compiled `cmac_nettle.c`** over a shim whose CMAC outputs ARE the
//!   RFC/NIST vectors: a C generator records the `CMC_*` API behavior — key-length
//!   table, MAC outputs, create rejection, and `CMC_Hash` truncation/clamping
//!   (`research/oracle/cmac_nettle-c-vectors.txt`); [`matches_real_c_cmac_vectors`]
//!   replays it and matches every value.

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cmac(key_hex: &str, msg_hex: &str) -> String {
    let key = unhex(key_hex);
    let alg = if key.len() == 16 { CmcAlgorithm::Aes128 } else { CmcAlgorithm::Aes256 };
    let mut inst = CmcInstance::create(alg, &key).unwrap();
    let mut out = [0u8; 16];
    let n = inst.hash(&unhex(msg_hex), &mut out);
    hex(&out[..n])
}

#[test]
fn aes256_fips197_kat() {
    // FIPS-197 Appendix C.3: AES-256 of 00112233...ff under key 0001..1f.
    let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let pt = unhex("00112233445566778899aabbccddeeff");
    let aes = Aes256::new(key.as_slice().try_into().unwrap());
    assert_eq!(
        hex(&aes.encrypt_block(pt.as_slice().try_into().unwrap())),
        "8ea2b7ca516745bfeafc49904b496089"
    );
}

#[test]
fn rfc4493_aes128_cmac_vectors() {
    // RFC 4493 §4 — the canonical AES-128-CMAC known answers.
    let k = "2b7e151628aed2a6abf7158809cf4f3c";
    assert_eq!(cmac(k, ""), "bb1d6929e95937287fa37d129b756746");
    assert_eq!(cmac(k, "6bc1bee22e409f96e93d7e117393172a"), "070a16b46b4d4144f79bdd9dd04a287c");
    assert_eq!(
        cmac(k, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
        "dfa66747de9ae63030ca32611497c827"
    );
    assert_eq!(
        cmac(k, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
        "51f0bebf7e3b9d92fc49741779363cfe"
    );
}

#[test]
fn nist_sp800_38b_aes256_cmac_vectors() {
    // NIST SP 800-38B — the AES-256-CMAC example vectors.
    let k = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    assert_eq!(cmac(k, ""), "028962f61b7bf89efc6b551f4667d983");
    assert_eq!(cmac(k, "6bc1bee22e409f96e93d7e117393172a"), "28a7023f452e8f82bd4bf28d8c37c35c");
    assert_eq!(
        cmac(k, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
        "aaf3d8f1de5640c232f5b169b9c911e6"
    );
    assert_eq!(
        cmac(k, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
        "e1992190549f6ed5696a2c056c315410"
    );
}

#[test]
fn matches_real_c_cmac_vectors() {
    let vectors = include_str!("../../../../research/oracle/cmac_nettle-c-vectors.txt");

    // The fixed message inputs the generator MACs, by case name.
    let k128 = "2b7e151628aed2a6abf7158809cf4f3c";
    let k256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    let m16 = "6bc1bee22e409f96e93d7e117393172a";
    let m40 = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411";
    let m64 = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    let lookup = |name: &str| -> (&str, &str) {
        match name {
            "rfc4493_len0" => (k128, ""),
            "rfc4493_len16" => (k128, m16),
            "rfc4493_len40" => (k128, m40),
            "rfc4493_len64" => (k128, m64),
            "nist256_len0" => (k256, ""),
            "nist256_len16" => (k256, m16),
            "nist256_len40" => (k256, m40),
            "nist256_len64" => (k256, m64),
            _ => panic!("unknown case {name}"),
        }
    };

    let mut mac_cases = 0;
    for raw in vectors.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("KEYLEN ") {
            let f = |k: &str| -> i32 {
                rest.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap().parse().unwrap()
            };
            assert_eq!(get_key_length(CmcAlgorithm::Aes128), f("aes128"));
            assert_eq!(get_key_length(CmcAlgorithm::Aes256), f("aes256"));
            assert_eq!(get_key_length(CmcAlgorithm::Invalid), f("inv"));
        } else if let Some(rest) = line.strip_prefix("MAC ") {
            let mut it = rest.split_whitespace();
            let name = it.next().unwrap();
            let expected = it.last().unwrap();
            let (kh, mh) = lookup(name);
            assert_eq!(cmac(kh, mh), expected, "MAC {name}");
            mac_cases += 1;
        } else if let Some(rest) = line.strip_prefix("CREATE badlen=") {
            let key = unhex(k128);
            assert_eq!(CmcInstance::create(CmcAlgorithm::Aes128, &key[..15]).is_none(), rest == "1");
        } else if let Some(rest) = line.strip_prefix("TRUNC ") {
            let exp = rest.split_whitespace().last().unwrap();
            let mut inst = CmcInstance::create(CmcAlgorithm::Aes128, &unhex(k128)).unwrap();
            let mut out = [0u8; 16];
            let n = inst.hash(&unhex(m16), &mut out[..4]);
            assert_eq!(hex(&out[..n]), exp, "truncated MAC");
        } else if let Some(rest) = line.strip_prefix("CLAMP ") {
            let exp = rest.split_whitespace().last().unwrap();
            let mut inst = CmcInstance::create(CmcAlgorithm::Aes128, &unhex(k128)).unwrap();
            let mut out = [0u8; 16];
            let n = inst.hash(&unhex(m16), &mut out);
            assert_eq!(hex(&out[..n]), exp, "clamped MAC");
        }
    }
    assert_eq!(mac_cases, 8, "expected 8 MAC cases");
}
