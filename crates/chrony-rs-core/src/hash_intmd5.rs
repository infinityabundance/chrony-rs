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
}
