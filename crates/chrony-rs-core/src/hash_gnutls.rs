//! GnuTLS hash backend — a port of chrony 4.5 `hash_gnutls.c`.
//!
//! Chrony supports multiple crypto libraries for hash operations. This is
//! the gnutls backend, which wraps `gnutls_hash_fast`. The same `HSH_*`
//! API is implemented by the nettle, NSS, and tomcrypt backends too.
//! The actual gnutls library is a host boundary; this port injects the hash
//! operation as a closure, composing the algorithm-name resolution from
//! [`crate::util::hash_name_to_algorithm`].

use crate::util::hash_name_to_algorithm;

/// `HSH_GetHashId`: return the hash algorithm id for a given name.
/// Gnutls backend uses gnutls's own algorithm ids.
pub fn hsh_get_hash_id(name: &str) -> i32 {
    hash_name_to_algorithm(name)
}

/// `HSH_Hash`: compute a hash over `in1 || in2` (concatenation) with
/// the algorithm identified by `id`, writing at most `out_len` bytes.
pub fn hsh_hash<F: FnOnce(i32, &[u8]) -> Vec<u8>>(
    id: i32,
    in1: &[u8],
    in2: &[u8],
    out_len: usize,
    hash_fn: F,
) -> Option<Vec<u8>> {
    let mut combined = Vec::with_capacity(in1.len() + in2.len());
    combined.extend_from_slice(in1);
    combined.extend_from_slice(in2);
    let result = hash_fn(id, &combined);
    if out_len == 0 {
        return None;
    }
    let truncated = result.into_iter().take(out_len).collect();
    Some(truncated)
}

/// `HSH_Finalise`: clean up the gnutls hash backend.
pub fn hsh_finalise<F: FnOnce()>(finalise: F) {
    finalise();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_hash_id_works() {
        assert_eq!(hsh_get_hash_id("MD5"), hash_name_to_algorithm("MD5"));
    }
}
