//! Nettle hash backend — a port of chrony 4.5 `hash_nettle.c`.
//!
//! Nettle hash backend wrapping nettle's `nettle_hash` API. The function
//! signatures match `hash_intmd5.c` — they are alternative implementations
//! of the same `HSH_*` interface. The nettle library is the host boundary;
//! this port injects the hash operation as a closure. The primary port
//! of the HSH API for chrony-rs's `internal MD5` build is in
//! [`crate::hash_intmd5`]; this module provides the nettle-shaped wrapper.

use crate::util::hash_name_to_algorithm;

/// `HSH_GetHashId`: return the hash algorithm id (nettle-specific mapping).
pub fn hsh_get_hash_id(name: &str) -> i32 {
    hash_name_to_algorithm(name)
}

/// `HSH_Hash`: compute a hash over `in1 || in2` with the nettle backend.
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

/// `HSH_Finalise`: clean up the nettle hash backend.
pub fn hsh_finalise<F: FnOnce()>(finalise: F) {
    finalise();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_hash_id_works() {
        let id = hsh_get_hash_id("MD5");
        assert_eq!(id, hash_name_to_algorithm("MD5"));
    }
}
