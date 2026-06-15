//! MD5 (RFC 1321) — a complete, dependency-free port of chrony 4.5 `md5.c`.
//!
//! # Why this exists and what it ports
//!
//! chrony's `md5.c` is the RSA Data Security RFC 1321 reference implementation; it
//! is used for NTP symmetric-key (MD5) message authentication. It is a rare chrony
//! translation unit with **zero internal dependencies** (it includes only
//! `md5.h`), which is exactly why it is portable in full: all four of its functions
//! — `MD5Init`, `MD5Update`, `MD5Final`, `Transform` — have direct counterparts
//! here ([`Md5::new`], [`Md5::update`], [`Md5::finalize`], [`Md5::transform`]).
//!
//! # Oracle
//!
//! Because chrony's `md5.c` *is* the RFC 1321 reference algorithm, the official
//! RFC 1321 §A.5 test-suite vectors are an exact behavioral oracle: any conforming
//! MD5 (chrony's included) produces identical digests. The tests below pin every
//! published vector byte-for-byte. This is a restoration, not a transliteration —
//! the table-driven round below is the same algorithm chrony's unrolled
//! `FF/GG/HH/II` macros compute, validated by shared evidence.
//!
//! # Discipline
//!
//! Memory-safe Rust throughout, no escape hatches. MD5's additions are defined
//! modulo 2³², so every add uses [`u32::wrapping_add`] — required here because the
//! workspace builds with `overflow-checks = true` even in release, and an MD5 add
//! is *meant* to wrap.

/// Per-round left-rotation amounts (`S11..S44` in chrony's `Transform`).
const SHIFTS: [[u32; 4]; 4] = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21],
];

/// The 64 sine-derived constants (`floor(2³²·|sin(i+1)|)`), identical to the `ac`
/// arguments of chrony's `FF/GG/HH/II` calls (e.g. step 1 is `0xd76aa478`).
const K: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613,
    0xfd46_9501, 0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193,
    0xa679_438e, 0x49b4_0821, 0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d,
    0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8, 0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
    0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a, 0xfffa_3942, 0x8771_f681, 0x6d9d_6122,
    0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70, 0x289b_7ec6, 0xeaa1_27fa,
    0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665, 0xf429_2244,
    0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb,
    0xeb86_d391,
];

/// Streaming MD5 context — the Rust counterpart of chrony's `MD5_CTX`.
#[derive(Clone)]
pub struct Md5 {
    /// Running state `A,B,C,D` (chrony's `buf[0..4]`).
    state: [u32; 4],
    /// Total message length in bits (chrony's split `i[0]`/`i[1]`).
    bits: u64,
    /// Partial 64-byte block (chrony's `in[]`).
    buffer: [u8; 64],
    /// Bytes currently held in `buffer`.
    buflen: usize,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// `MD5Init`: load the magic initialization constants.
    pub fn new() -> Self {
        Md5 {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            bits: 0,
            buffer: [0u8; 64],
            buflen: 0,
        }
    }

    /// `MD5Update`: fold `data` into the digest, transforming each full 64-byte
    /// block as it completes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.bits = self.bits.wrapping_add((data.len() as u64) << 3);
        while !data.is_empty() {
            let take = (64 - self.buflen).min(data.len());
            self.buffer[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let block = self.buffer;
                self.transform(&block);
                self.buflen = 0;
            }
        }
    }

    /// `MD5Final`: append the `0x80`/zero padding and the 64-bit little-endian bit
    /// length, run the final transform, and emit the 16-byte digest (LE words).
    pub fn finalize(mut self) -> [u8; 16] {
        let bits = self.bits;
        // 0x80 then zeros until the buffer is 56 mod 64, then the 8-byte length.
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let padlen = if self.buflen < 56 {
            56 - self.buflen
        } else {
            120 - self.buflen
        };
        self.update(&pad[..padlen]);
        self.update(&bits.to_le_bytes());
        debug_assert_eq!(self.buflen, 0, "length-padding must land on a block boundary");

        let mut out = [0u8; 16];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// One-shot convenience: `MD5(data)`.
    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut ctx = Md5::new();
        ctx.update(data);
        ctx.finalize()
    }

    /// `Transform`: the basic MD5 compression step over one 64-byte block. The
    /// table-driven round computes exactly what chrony's unrolled `FF/GG/HH/II`
    /// macros do (same constants, same shifts, same message-word schedule).
    fn transform(&mut self, block: &[u8; 64]) {
        // Decode the block into 16 little-endian words (chrony's `in[]` assembly).
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let [mut a, mut b, mut c, mut d] = self.state;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let sum = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(sum.rotate_left(SHIFTS[i / 16][i % 4]));
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: [u8; 16]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfc1321_a5_test_suite_vectors() {
        // The seven official vectors from RFC 1321, Appendix A.5. chrony's md5.c
        // (the RFC reference impl) produces exactly these.
        let cases: &[(&str, &str)] = &[
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(hex(Md5::digest(input.as_bytes())), *want, "MD5({input:?})");
        }
    }

    #[test]
    fn streaming_matches_one_shot_across_block_boundaries() {
        // Feeding in odd-sized chunks must equal a single update, including the
        // 55/56/64-byte padding edge cases.
        for n in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 200] {
            let data: Vec<u8> = (0..n).map(|i| (i * 31 + 7) as u8).collect();
            let one_shot = Md5::digest(&data);
            let mut ctx = Md5::new();
            for chunk in data.chunks(7) {
                ctx.update(chunk);
            }
            assert_eq!(ctx.finalize(), one_shot, "chunked != one-shot at n={n}");
        }
    }

    #[test]
    fn length_padding_edge_cases() {
        // Around the 56-byte boundary the padding switches from `56 - mdi` to
        // `120 - mdi` (a second block). External oracle: independent MD5 digests.
        let want: &[(usize, &str)] = &[
            (55, "ef1772b6dff9a122358552954ad0df65"),
            (56, "3b0c8ac703f828b04c6c197006d17218"),
            (57, "652b906d60af96844ebd21b674f35e93"),
            (64, "014842d480b571495a4a0363793f7367"),
        ];
        for (n, h) in want {
            assert_eq!(hex(Md5::digest(&vec![b'a'; *n])), *h, "MD5(a*{n})");
        }
    }
}
