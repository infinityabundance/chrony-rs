//! LibTomCrypt hash backend — a port of chrony 4.5 `hash_tomcrypt.c`.
//!
//! LibTomCrypt hash backend. Host boundary; the hash operation is injected.

use crate::util::hash_name_to_algorithm;

pub fn hsh_get_hash_id(name: &str) -> i32 {
    hash_name_to_algorithm(name)
}

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
    if out_len == 0 { return None; }
    Some(result.into_iter().take(out_len).collect())
}

pub fn hsh_finalise<F: FnOnce()>(finalise: F) { finalise(); }
