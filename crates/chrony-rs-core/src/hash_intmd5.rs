//! Internal MD5 hash backend — a complete port of chrony 4.5 `hash_intmd5.c`.
//!
//! chrony abstracts message digests behind an `HSH_*` interface; `hash_intmd5.c`
//! is the dependency-free fallback backend that supports **only MD5** (used for
//! NTP symmetric-key auth and, as `HSH_MD5_NONCRYPTO`, the NTPv4 reference ID). It
//! is a thin wrapper over `md5.c`, which is already ported ([`crate::md5`]), so all
//! three of its functions port directly:
//!
//! | chrony `hash_intmd5.c` | here |
//! |------------------------|------|
//! | `HSH_GetHashId` | [`get_hash_id`] |
//! | `HSH_Hash` | [`hash`] |
//! | `HSH_Finalise` | [`finalise`] |
//!
//! Correctness rides on the ported MD5 (RFC 1321 vectors); the tests here pin the
//! supported-algorithm gate and the `in1 || in2` concatenation/truncation.

use crate::md5::Md5;

/// chrony's `HSH_Algorithm` digest selector. Only the MD5 variants are supported
/// by this backend; the others exist so the gate in [`get_hash_id`] is exact.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
    #[non_exhaustive]
pub enum HshAlgorithm {
    Invalid = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Sha3_224 = 6,
    Sha3_256 = 7,
    Sha3_384 = 8,
    Sha3_512 = 9,
    Tiger = 10,
    Whirlpool = 11,
    /// MD5 used non-cryptographically (NTPv4 reference ID).
    Md5NonCrypto = 10000,
}

/// `HSH_GetHashId`: `Some(0)` for the MD5 algorithms this backend supports, `None`
/// (chrony's `-1`) for anything else.
pub fn get_hash_id(algorithm: HshAlgorithm) -> Option<i32> {
    if algorithm == HshAlgorithm::Md5 || algorithm == HshAlgorithm::Md5NonCrypto {
        Some(0)
    } else {
        None
    }
}

/// `HSH_Hash`: MD5 of `in1` concatenated with `in2`, writing the first
/// `min(out.len(), 16)` digest bytes into `out` and returning that count. (chrony's
/// `id` argument selects the algorithm, but this backend only does MD5, so it is
/// implicit here; the negative-length guard is unrepresentable with slices.)
pub fn hash(in1: &[u8], in2: &[u8], out: &mut [u8]) -> usize {
    let mut ctx = Md5::new();
    ctx.update(in1);
    ctx.update(in2); // an empty in2 adds nothing, matching chrony's NULL check
    let digest = ctx.finalize();
    let n = out.len().min(16);
    out[..n].copy_from_slice(&digest[..n]);
    n
}

/// `HSH_Finalise`: no-op — the internal MD5 backend holds no global resources.
pub fn finalise() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn get_hash_id_only_supports_md5() {
        assert_eq!(get_hash_id(HshAlgorithm::Md5), Some(0));
        assert_eq!(get_hash_id(HshAlgorithm::Md5NonCrypto), Some(0));
        assert_eq!(get_hash_id(HshAlgorithm::Sha256), None);
        assert_eq!(get_hash_id(HshAlgorithm::Invalid), None);
    }

    #[test]
    fn hash_is_md5_of_concatenation() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 (RFC 1321).
        let mut out = [0u8; 16];
        let n = hash(b"abc", b"", &mut out);
        assert_eq!(n, 16);
        assert_eq!(hex(&out), "900150983cd24fb0d6963f7d28e17f72");

        // in1 || in2 must equal hashing the concatenation in one piece.
        let mut split = [0u8; 16];
        hash(b"ab", b"c", &mut split);
        assert_eq!(split, out);
    }

    #[test]
    fn hash_truncates_to_out_len() {
        let mut out = [0u8; 4];
        let n = hash(b"abc", b"", &mut out);
        assert_eq!(n, 4);
        assert_eq!(hex(&out), "90015098"); // first 4 bytes of the MD5
    }

    #[test]
    fn finalise_is_noop() {
        finalise(); // must not panic
    }

    /// Differential oracle vs the REAL compiled `hash_intmd5.c` (`HSH_GetHashId` +
    /// `HSH_Hash`): the concatenation path `MD5(in1 || in2)` and the `out_len`
    /// truncation (capped at 16), driven from the same fixture the md5 sweep uses
    /// (`research/oracle/md5-c-vectors.txt`, `HDR`/`HSH` lines). Covers empty inputs,
    /// concatenations crossing the 56/64-byte block boundary, and out_len of
    /// 0/4/8/16/20 (0 -> return 0, >16 -> 16).
    #[test]
    fn matches_real_c_hash_vectors() {
        let vectors = include_str!("../../../research/oracle/md5-c-vectors.txt");
        fn field(line: &str, key: &str) -> String {
            line.split_whitespace()
                .find_map(|t| t.strip_prefix(&format!("{key}=")))
                .unwrap()
                .to_string()
        }
        fn n(line: &str, key: &str) -> usize {
            field(line, key).parse().unwrap()
        }

        // HDR pins HSH_GetHashId(MD5) == 0, and the unsupported-algorithm rejection.
        let hdr = vectors.lines().find(|l| l.starts_with("HDR ")).unwrap();
        assert_eq!(get_hash_id(HshAlgorithm::Md5), Some(field(hdr, "hashid").parse().unwrap()));
        assert_eq!(get_hash_id(HshAlgorithm::Md5NonCrypto), Some(0));
        assert_eq!(get_hash_id(HshAlgorithm::Sha256), None);

        let mut seen = 0;
        for line in vectors.lines().filter(|l| l.starts_with("HSH ")) {
            let (l1, l2, ol) = (n(line, "i1"), n(line, "i2"), n(line, "out"));
            let want_ret = n(line, "ret");
            let in1: Vec<u8> = (0..l1).map(|i| (i * 7 + 3) as u8).collect();
            let in2: Vec<u8> = (0..l2).map(|i| (i * 11 + 5) as u8).collect();
            let mut out = vec![0xEEu8; ol];
            let ret = hash(&in1, &in2, &mut out);
            assert_eq!(ret, want_ret, "HSH i1={l1} i2={l2} out={ol} ret");
            let got: String = out[..ret].iter().map(|b| format!("{b:02x}")).collect();
            let got = if got.is_empty() { "-".to_string() } else { got };
            assert_eq!(got, field(line, "digest"), "HSH i1={l1} i2={l2} out={ol} digest");
            seen += 1;
        }
        assert_eq!(seen, 14, "expected 14 HSH cases");
    }
}
