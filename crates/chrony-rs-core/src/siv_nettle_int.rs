//! AES-SIV-CMAC-256 (RFC 5297) — a complete port of chrony 4.5 `siv_nettle_int.c`
//! (all 12 functions), chrony's single-file synthetic-IV authenticated cipher used
//! for NTS.
//!
//! # What this module is
//!
//! `siv_nettle_int.c` is a self-contained implementation of AES-SIV-CMAC-256: the
//! CMAC-128 keyed MAC (RFC 4493), the S2V vectorization (RFC 5297), and SIV
//! encrypt/decrypt that combines S2V (to derive a synthetic IV) with AES-CTR. In
//! chrony it leans on GNU Nettle for exactly one primitive — the **AES-128 block
//! cipher** (and CTR/memxor helpers). The SIV/CMAC/S2V construction itself is
//! chrony's own code, and that is what this port reproduces.
//!
//! # Adaptations (documented, not silent)
//!
//! * **AES is the boundary, reimplemented in pure Rust.** Nettle's `aes128_*` is
//!   replaced by a dependency-free, FIPS-197-vectored AES-128 ([`Aes128`]); CTR mode
//!   and `memxor`/`memeql_sec` are small local helpers — no external crate, and the
//!   code stays entirely in safe Rust. The AES correctness is pinned by the FIPS-197
//!   known-answer test.
//! * **The nettle indirection collapses.** chrony's CMAC is generic over a
//!   `nettle_cipher_func`; AES-128 is the only instantiation, so the port passes a
//!   `&Aes128` directly. The `union nettle_block16` becomes `[u8; 16]`.
//!
//! # Oracles
//!
//! Three independent anchors:
//! 1. **FIPS-197** known-answer test for the AES-128 primitive.
//! 2. **RFC 5297 §A.1** — the official AES-SIV-CMAC deterministic worked example
//!    (authoritative ground truth for the whole construction).
//! 3. **The real compiled `siv_nettle_int.c`** over a nettle-compatible shim whose
//!    AES is itself FIPS-197-verified: a C generator emits encrypt/decrypt vectors
//!    over many lengths and AD/nonce/plaintext shapes
//!    (`research/oracle/siv_nettle_int-c-vectors.txt`); the port must match every
//!    byte and the decrypt verification result. See the tests.

/// SIV block size (chrony `SIV_BLOCK_SIZE`).
const SIV_BLOCK_SIZE: usize = 16;
/// SIV synthetic-IV / tag size (chrony `SIV_DIGEST_SIZE`).
pub const SIV_DIGEST_SIZE: usize = 16;

// ===================== AES-128 (the nettle boundary) =====================

/// AES S-box (FIPS-197).
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

/// Multiply by x in GF(2^8) (the AES field).
#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

/// AES-128 encryption (the only block-cipher operation chrony's SIV needs).
pub struct Aes128 {
    /// 11 round keys, 16 bytes each.
    round_keys: [[u8; 16]; 11],
}

impl Aes128 {
    /// FIPS-197 key expansion for a 128-bit key.
    pub fn new(key: &[u8; 16]) -> Self {
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        }
        let mut rcon: u8 = 1;
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                t = [SBOX[t[1] as usize], SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
                t[0] ^= rcon;
                rcon = xtime(rcon);
            }
            for b in 0..4 {
                w[i][b] = w[i - 4][b] ^ t[b];
            }
        }
        let mut round_keys = [[0u8; 16]; 11];
        for (r, rk) in round_keys.iter_mut().enumerate() {
            for c in 0..4 {
                for b in 0..4 {
                    rk[c * 4 + b] = w[r * 4 + c][b];
                }
            }
        }
        Aes128 { round_keys }
    }

    /// Encrypt one 16-byte block (FIPS-197).
    pub fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut s = *input;
        Self::add_round_key(&mut s, &self.round_keys[0]);
        for rk in &self.round_keys[1..10] {
            Self::sub_bytes(&mut s);
            Self::shift_rows(&mut s);
            Self::mix_columns(&mut s);
            Self::add_round_key(&mut s, rk);
        }
        Self::sub_bytes(&mut s);
        Self::shift_rows(&mut s);
        Self::add_round_key(&mut s, &self.round_keys[10]);
        s
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
        // State is column-major: index = col*4 + row. Row r rotates left by r.
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
}

/// A 128-bit block cipher (the primitive CMAC-128 is built over). Implemented by
/// [`Aes128`] here and by AES-256 in [`crate::cmac_nettle`], so the CMAC code is
/// shared rather than duplicated.
pub(crate) trait BlockCipher128 {
    /// Encrypt one 16-byte block.
    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16];
}

impl BlockCipher128 for Aes128 {
    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        Aes128::encrypt_block(self, block)
    }
}

/// AES-CTR (nettle `ctr_crypt`): `dst = src ^ keystream`, where the keystream is
/// `AES(ctr), AES(ctr+1), …` with the 16-byte counter incremented big-endian.
fn ctr_crypt(cipher: &Aes128, ctr: &mut [u8; 16], src: &[u8], dst: &mut [u8]) {
    let mut off = 0;
    while off < src.len() {
        let ks = cipher.encrypt_block(ctr);
        let n = (src.len() - off).min(SIV_BLOCK_SIZE);
        for i in 0..n {
            dst[off + i] = src[off + i] ^ ks[i];
        }
        // Increment the full 128-bit counter, big-endian.
        for b in ctr.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        off += n;
    }
}

/// Constant-time 16-byte equality (nettle `memeql_sec`).
fn memeql_sec(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

// ===================== CMAC-128 (RFC 4493) =====================

/// chrony `_cmac128_block_mulx`: shift the 128-bit block left by one and, if the
/// high bit was set, XOR the reduction polynomial `0x87` into the low byte.
fn cmac128_block_mulx(src: &[u8; 16]) -> [u8; 16] {
    let b1 = u64::from_be_bytes(src[0..8].try_into().unwrap());
    let b2 = u64::from_be_bytes(src[8..16].try_into().unwrap());
    let n1 = (b1 << 1) | (b2 >> 63);
    let n2 = b2 << 1;
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&n1.to_be_bytes());
    out[8..16].copy_from_slice(&n2.to_be_bytes());
    if src[0] & 0x80 != 0 {
        out[15] ^= 0x87;
    }
    out
}

fn memxor(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}
fn memxor3(dst: &mut [u8], a: &[u8], b: &[u8]) {
    for i in 0..dst.len() {
        dst[i] = a[i] ^ b[i];
    }
}

/// chrony `struct cmac128_ctx`.
pub(crate) struct Cmac128 {
    k1: [u8; 16],
    k2: [u8; 16],
    x: [u8; 16],
    block: [u8; 16],
    index: usize,
}

impl Cmac128 {
    /// chrony `cmac128_set_key`: derive subkeys K1, K2 from the cipher.
    pub(crate) fn set_key<C: BlockCipher128>(cipher: &C) -> Self {
        let l = cipher.encrypt_block(&[0u8; 16]);
        let k1 = cmac128_block_mulx(&l);
        let k2 = cmac128_block_mulx(&k1);
        Cmac128 { k1, k2, x: [0; 16], block: [0; 16], index: 0 }
    }

    /// chrony `cmac128_update`.
    pub(crate) fn update<C: BlockCipher128>(&mut self, cipher: &C, msg: &[u8]) {
        let mut msg = msg;
        if self.index < 16 {
            let len = (16 - self.index).min(msg.len());
            self.block[self.index..self.index + len].copy_from_slice(&msg[..len]);
            msg = &msg[len..];
            self.index += len;
        }
        if msg.is_empty() {
            return;
        }

        let mut y = [0u8; 16];
        memxor3(&mut y, &self.x, &self.block);
        self.x = cipher.encrypt_block(&y);

        while msg.len() > 16 {
            memxor3(&mut y, &self.x, &msg[..16]);
            self.x = cipher.encrypt_block(&y);
            msg = &msg[16..];
        }

        self.block[..msg.len()].copy_from_slice(msg);
        self.index = msg.len();
    }

    /// chrony `cmac128_digest`: finalize into `dst` (length ≤ 16), then reset for
    /// re-use.
    pub(crate) fn digest<C: BlockCipher128>(&mut self, cipher: &C, length: usize, dst: &mut [u8]) {
        for b in self.block[self.index..].iter_mut() {
            *b = 0;
        }
        if self.index < 16 {
            self.block[self.index] = 0x80;
            memxor(&mut self.block, &self.k2);
        } else {
            let k1 = self.k1;
            memxor(&mut self.block, &k1);
        }

        let mut y = [0u8; 16];
        memxor3(&mut y, &self.block, &self.x);

        assert!(length <= 16);
        if length == 16 {
            let out = cipher.encrypt_block(&y);
            dst[..16].copy_from_slice(&out);
        } else {
            self.block = cipher.encrypt_block(&y);
            dst[..length].copy_from_slice(&self.block[..length]);
        }

        self.x = [0; 16];
        self.index = 0;
    }
}

/// chrony's `struct cmac_aes128_ctx` (CMAC over AES-128): the MAC state plus the
/// keyed cipher.
struct CmacAes128 {
    ctx: Cmac128,
    cipher: Aes128,
}

impl CmacAes128 {
    /// chrony `cmac_aes128_set_key`.
    fn set_key(key: &[u8; 16]) -> Self {
        let cipher = Aes128::new(key);
        let ctx = Cmac128::set_key(&cipher);
        CmacAes128 { ctx, cipher }
    }
    /// chrony `cmac_aes128_update`.
    fn update(&mut self, data: &[u8]) {
        self.ctx.update(&self.cipher, data);
    }
    /// chrony `cmac_aes128_digest`.
    fn digest(&mut self, length: usize, dst: &mut [u8]) {
        self.ctx.digest(&self.cipher, length, dst);
    }
}

const CONST_ONE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const CONST_ZERO: [u8; 16] = [0; 16];

/// chrony `_siv_s2v`: the S2V construction (RFC 5297 §2.4) over the associated
/// data, nonce, and plaintext, producing the 16-byte synthetic IV `v`.
fn s2v(s2vk: &[u8; 16], adata: &[u8], nonce: &[u8], pdata: &[u8]) -> [u8; 16] {
    let mut cmac = CmacAes128::set_key(s2vk);
    let mut v = [0u8; 16];

    if nonce.is_empty() && adata.is_empty() {
        cmac.update(&CONST_ONE);
        cmac.digest(16, &mut v);
        return v;
    }

    let mut d = [0u8; 16];
    cmac.update(&CONST_ZERO);
    cmac.digest(16, &mut d);

    // Associated data (chrony's unconditional `if (1)`).
    {
        d = cmac128_block_mulx(&d);
        let mut s = [0u8; 16];
        cmac.update(adata);
        cmac.digest(16, &mut s);
        memxor(&mut d, &s);
    }

    if !nonce.is_empty() {
        d = cmac128_block_mulx(&d);
        let mut s = [0u8; 16];
        cmac.update(nonce);
        cmac.digest(16, &mut s);
        memxor(&mut d, &s);
    }

    // Final block Sn (the plaintext).
    let mut t = [0u8; 16];
    if pdata.len() >= 16 {
        let split = pdata.len() - 16;
        cmac.update(&pdata[..split]);
        memxor3(&mut t, &pdata[split..], &d);
    } else {
        t = cmac128_block_mulx(&d);
        let mut pad = [0u8; 16];
        pad[..pdata.len()].copy_from_slice(pdata);
        pad[pdata.len()] = 0x80;
        memxor(&mut t, &pad);
    }

    cmac.update(&t);
    cmac.digest(16, &mut v);
    v
}

// ===================== AES-SIV-CMAC-256 =====================

/// chrony `struct siv_cmac_aes128_ctx`: the AES-SIV-CMAC-256 cipher (a 32-byte key
/// split into the S2V/CMAC key and the AES-CTR key).
pub struct SivCmacAes128 {
    cipher: Aes128,
    s2vk: [u8; 16],
}

impl SivCmacAes128 {
    /// chrony `siv_cmac_aes128_set_key`: the first 16 bytes key S2V, the next 16 key
    /// the CTR cipher.
    pub fn set_key(key: &[u8; 32]) -> Self {
        let mut s2vk = [0u8; 16];
        s2vk.copy_from_slice(&key[..16]);
        let mut ck = [0u8; 16];
        ck.copy_from_slice(&key[16..]);
        SivCmacAes128 { cipher: Aes128::new(&ck), s2vk }
    }

    /// chrony `siv_cmac_aes128_encrypt_message`: write `SIV || ciphertext` into
    /// `dst` (`dst.len() == SIV_DIGEST_SIZE + plaintext.len()`).
    pub fn encrypt_message(&self, nonce: &[u8], adata: &[u8], dst: &mut [u8], src: &[u8]) {
        assert!(dst.len() >= SIV_DIGEST_SIZE);
        let slength = dst.len() - SIV_DIGEST_SIZE;
        assert_eq!(slength, src.len());

        let siv = s2v(&self.s2vk, adata, nonce, src);
        dst[..SIV_DIGEST_SIZE].copy_from_slice(&siv);

        let mut ctr = siv;
        ctr[8] &= !0x80;
        ctr[12] &= !0x80;

        let (tag, ct) = dst.split_at_mut(SIV_DIGEST_SIZE);
        let _ = tag;
        ctr_crypt(&self.cipher, &mut ctr, src, ct);
    }

    /// chrony `siv_cmac_aes128_decrypt_message`: verify + decrypt `src` (`SIV ||
    /// ciphertext`) into `dst`. Returns whether the tag verified.
    pub fn decrypt_message(&self, nonce: &[u8], adata: &[u8], dst: &mut [u8], src: &[u8]) -> bool {
        assert!(src.len() >= SIV_DIGEST_SIZE);
        let mlength = src.len() - SIV_DIGEST_SIZE;
        assert_eq!(mlength, dst.len());

        let mut ctr = [0u8; 16];
        ctr.copy_from_slice(&src[..SIV_DIGEST_SIZE]);
        ctr[8] &= !0x80;
        ctr[12] &= !0x80;

        ctr_crypt(&self.cipher, &mut ctr, &src[SIV_DIGEST_SIZE..], dst);

        let siv = s2v(&self.s2vk, adata, nonce, dst);
        memeql_sec(&siv, &src[..SIV_DIGEST_SIZE])
    }
}

#[cfg(test)]
mod tests;
