//! CMAC keyed-MAC instance API — a complete port of chrony 4.5 `cmac_nettle.c`
//! (all 4 functions), the `CMC_*` abstraction used for AES-CMAC authentication keys.
//!
//! # What this module is
//!
//! `cmac_nettle.c` is the instance layer over AES-CMAC (RFC 4493 / NIST SP 800-38B):
//! create a keyed instance for AES-128 or AES-256, report the key length, and
//! compute a (possibly truncated) MAC. In chrony the CMAC itself comes from GNU
//! Nettle; here it is the shared CMAC-128 construction from [`crate::siv_nettle_int`]
//! (already triple-anchored) run over AES-128 ([`crate::siv_nettle_int::Aes128`])
//! and an AES-256 block cipher implemented in this module.
//!
//! # Why this matters
//!
//! This is the backend [`crate::keys`] needs for `AES128`/`AES256` (CMAC) key types,
//! which the internal-MD5 build rejects. With this in place, a CMAC-capable build of
//! the key store is possible.
//!
//! # Oracles
//!
//! * **RFC 4493 §4** — the official AES-128-CMAC test vectors (4 message lengths).
//! * **NIST SP 800-38B** — the AES-256-CMAC example vectors (4 message lengths),
//!   plus the FIPS-197 AES-256 known-answer test.
//! * **The real compiled `cmac_nettle.c`** over a CMAC/AES shim verified by those
//!   vectors: a C generator exercises the key-length table, instance creation, the
//!   truncating `CMC_Hash`, and the create rejections
//!   (`research/oracle/cmac_nettle-c-vectors.txt`). See the tests.

use crate::siv_nettle_int::{Aes128, BlockCipher128, Cmac128};

/// `AES128_KEY_SIZE`.
pub const AES128_KEY_SIZE: i32 = 16;
/// `AES256_KEY_SIZE`.
pub const AES256_KEY_SIZE: i32 = 32;
/// chrony `CMAC128_DIGEST_SIZE`.
pub const CMAC128_DIGEST_SIZE: usize = 16;

/// chrony `CMC_Algorithm` (`cmac.h`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum CmcAlgorithm {
    /// Not a CMAC algorithm.
    Invalid = 0,
    /// AES-128-CMAC.
    Aes128 = 13,
    /// AES-256-CMAC.
    Aes256 = 14,
}

// ===================== AES-256 (FIPS-197) =====================

/// AES S-box (FIPS-197) — shared shape with [`crate::siv_nettle_int`]; kept local so
/// this module is self-contained for the AES-256 schedule.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

/// AES-256 encryption (14 rounds), for AES-256-CMAC.
#[derive(Debug)]
pub struct Aes256 {
    round_keys: [[u8; 16]; 15],
}

impl Aes256 {
    /// FIPS-197 key expansion for a 256-bit key (Nk = 8, Nr = 14).
    pub fn new(key: &[u8; 32]) -> Self {
        let mut w = [[0u8; 4]; 60];
        for i in 0..8 {
            w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        }
        let mut rcon: u8 = 1;
        for i in 8..60 {
            let mut t = w[i - 1];
            if i % 8 == 0 {
                t = [SBOX[t[1] as usize], SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
                t[0] ^= rcon;
                rcon = xtime(rcon);
            } else if i % 8 == 4 {
                t = [SBOX[t[0] as usize], SBOX[t[1] as usize], SBOX[t[2] as usize], SBOX[t[3] as usize]];
            }
            for b in 0..4 {
                w[i][b] = w[i - 8][b] ^ t[b];
            }
        }
        let mut round_keys = [[0u8; 16]; 15];
        for (r, rk) in round_keys.iter_mut().enumerate() {
            for c in 0..4 {
                for b in 0..4 {
                    rk[c * 4 + b] = w[r * 4 + c][b];
                }
            }
        }
        Aes256 { round_keys }
    }

    /// Encrypt one 16-byte block (FIPS-197, 14 rounds).
    pub fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut s = *input;
        add_round_key(&mut s, &self.round_keys[0]);
        for rk in &self.round_keys[1..14] {
            sub_bytes(&mut s);
            shift_rows(&mut s);
            mix_columns(&mut s);
            add_round_key(&mut s, rk);
        }
        sub_bytes(&mut s);
        shift_rows(&mut s);
        add_round_key(&mut s, &self.round_keys[14]);
        s
    }
}

impl BlockCipher128 for Aes256 {
    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        Aes256::encrypt_block(self, block)
    }
}

fn add_round_key(s: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        s[i] ^= rk[i];
    }
}
fn sub_bytes(s: &mut [u8; 16]) {
    for b in s.iter_mut() {
        *b = SBOX[*b as usize];
    }
}
fn shift_rows(s: &mut [u8; 16]) {
    let old = *s;
    for col in 0..4 {
        for row in 0..4 {
            s[col * 4 + row] = old[((col + row) % 4) * 4 + row];
        }
    }
}
fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        s[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        s[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        s[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

// ===================== CMC_* instance API =====================

/// The keyed cipher behind a CMAC instance (chrony's `union` of cmac contexts).
#[derive(Debug)]
enum CmacCipher {
    Aes128(Aes128),
    Aes256(Aes256),
}

/// A keyed CMAC instance (chrony's `CMC_Instance_Record`).
#[derive(Debug)]
pub struct CmcInstance {
    key_length: i32,
    cmac: Cmac128,
    cipher: CmacCipher,
}

/// chrony `CMC_GetKeyLength`: key length (bytes) for an algorithm, or 0 if unknown.
pub fn get_key_length(algorithm: CmcAlgorithm) -> i32 {
    match algorithm {
        CmcAlgorithm::Aes128 => AES128_KEY_SIZE,
        CmcAlgorithm::Aes256 => AES256_KEY_SIZE,
        CmcAlgorithm::Invalid => 0,
    }
}

impl CmcInstance {
    /// chrony `CMC_CreateInstance`: build a keyed instance, or `None` if the key
    /// length is wrong for the algorithm.
    pub fn create(algorithm: CmcAlgorithm, key: &[u8]) -> Option<CmcInstance> {
        let length = key.len() as i32;
        if length <= 0 || length != get_key_length(algorithm) {
            return None;
        }
        let (cmac, cipher) = match length {
            AES128_KEY_SIZE => {
                let c = Aes128::new(key.try_into().expect("len 16"));
                (Cmac128::set_key(&c), CmacCipher::Aes128(c))
            }
            AES256_KEY_SIZE => {
                let c = Aes256::new(key.try_into().expect("len 32"));
                (Cmac128::set_key(&c), CmacCipher::Aes256(c))
            }
            _ => return None,
        };
        Some(CmcInstance { key_length: length, cmac, cipher })
    }

    /// chrony `CMC_Hash`: MAC `input` into `out` (truncated to `out.len()`, capped
    /// at 16). Returns the number of bytes written.
    pub fn hash(&mut self, input: &[u8], out: &mut [u8]) -> usize {
        let out_len = out.len().min(CMAC128_DIGEST_SIZE);
        match &self.cipher {
            CmacCipher::Aes128(c) => {
                self.cmac.update(c, input);
                self.cmac.digest(c, out_len, &mut out[..out_len]);
            }
            CmacCipher::Aes256(c) => {
                self.cmac.update(c, input);
                self.cmac.digest(c, out_len, &mut out[..out_len]);
            }
        }
        out_len
    }

    /// The key length in bytes (16 or 32).
    pub fn key_length(&self) -> i32 {
        self.key_length
    }
}

#[cfg(test)]
mod tests;
