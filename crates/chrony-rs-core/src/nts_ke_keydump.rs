//! NTS server key persistence — a port of `save_keys` / `load_keys` from chrony 4.5
//! `nts_ke_server.c`.
//!
//! An NTS server rotates a small ring of server keys (used to encrypt/decrypt cookies) and
//! persists them to an `ntskeys` dump file so cookies issued before a restart stay valid.
//! The dump format (`NKS1`) is:
//!
//! ```text
//! NKS1
//! <key_age>
//! <id:%08X> <key:hex> <algorithm>      (× MAX_SERVER_KEYS, in rotation order)
//! ```
//!
//! (The legacy `NKS0` format carries the algorithm once on the age line and omits it from
//! each key line.) This module ports the pure serialization/parse: the text layout, the
//! rotation ordering, and every `load_keys` validation (identifier, word counts,
//! consecutive-id check, key length ↦ algorithm). The file I/O (`UTI_OpenFile` /
//! `UTI_RenameTempFile`), the CSPRNG key generation, the SIV instances, and the scheduler
//! timing are the host boundary; the caller supplies the key store, the current-key index,
//! and the key age, and receives / provides the dump text.
//!
//! Composes the ported [`crate::util::bytes_to_hex`] / [`crate::util::hex_to_bytes`] /
//! [`crate::util::split_string`].

use crate::util::{bytes_to_hex, hex_to_bytes, split_string};

/// `MAX_SERVER_KEYS` = `1 << KEY_ID_INDEX_BITS`.
pub const MAX_SERVER_KEYS: usize = 4;
/// `FUTURE_KEYS`: how many not-yet-current keys are kept ahead in the ring.
const FUTURE_KEYS: usize = 1;
/// `SIV_MAX_KEY_LENGTH`.
const SIV_MAX_KEY_LENGTH: usize = 32;
const DUMP_IDENTIFIER: &str = "NKS1";
const OLD_DUMP_IDENTIFIER: &str = "NKS0";
const MAX_WORDS: usize = 3;

/// One persisted server key (chrony `ServerKey`, dump-relevant fields).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DumpKey {
    pub id: u32,
    pub siv_algorithm: i32,
    /// The significant key bytes (`SIV_GetKeyLength(algorithm)` of them).
    pub key: Vec<u8>,
}

/// The result of parsing a dump (chrony's loaded state).
#[derive(Clone, Debug, PartialEq)]
pub struct LoadedKeys {
    /// The key store, indexed by `id % MAX_SERVER_KEYS`.
    pub keys: Vec<DumpKey>,
    pub current_server_key: usize,
    pub key_age: f64,
}

/// chrony `save_keys`' formatting: render the `NKS1` dump text for `keys` (indexed by
/// `id % MAX_SERVER_KEYS`) written in rotation order starting after the current key.
/// `key_length(alg)` is `SIV_GetKeyLength`. Returns `None` if a key length exceeds the
/// buffer. The file open/rename and the rotation-disabled / no-dump-dir short-circuits are
/// the caller's.
pub fn format_keydump(
    current_server_key: usize,
    keys: &[DumpKey],
    key_age: f64,
    key_length: impl Fn(i32) -> i32,
) -> Option<String> {
    let mut out = format!("{DUMP_IDENTIFIER}\n{key_age:.1}\n");
    for i in 0..MAX_SERVER_KEYS {
        let index = (current_server_key + i + 1 + FUTURE_KEYS) % MAX_SERVER_KEYS;
        let k = &keys[index];
        let kl = key_length(k.siv_algorithm);
        if kl < 0 || kl as usize > SIV_MAX_KEY_LENGTH || kl as usize > k.key.len() {
            return None;
        }
        let hex = bytes_to_hex(&k.key[..kl as usize]);
        out += &format!("{:08X} {} {}\n", k.id, hex, k.siv_algorithm);
    }
    Some(out)
}

/// chrony `load_keys`' parse: validate and decode the dump `text` (either `NKS1` or the
/// legacy `NKS0`) into the key store, the current-key index, and the key age.
/// `key_length(alg)` is `SIV_GetKeyLength`. Returns `None` on any malformed field, a bad
/// identifier, a wrong word count, non-consecutive key ids, a non-positive key length, or a
/// hex key whose decoded length differs from the algorithm's key length.
///
/// Numeric fields use Rust's strict integer/float parse; chrony's `sscanf` additionally
/// tolerates trailing junk, but the machine-generated dump never produces it (a documented,
/// never-exercised boundary).
pub fn parse_keydump(text: &str, key_length: impl Fn(i32) -> i32) -> Option<LoadedKeys> {
    let mut lines = text.lines();

    let ident = lines.next()?;
    if ident != DUMP_IDENTIFIER && ident != OLD_DUMP_IDENTIFIER {
        return None;
    }
    let old_ver = ident != DUMP_IDENTIFIER;

    // The age line: NKS0 is "<algorithm> <age>", NKS1 is "<age>".
    let (words, count) = split_string(lines.next()?, MAX_WORDS);
    if count != if old_ver { 2 } else { 1 } {
        return None;
    }
    let mut algorithm: i32 = if old_ver { words[0].parse().ok()? } else { 0 };
    let key_age: f64 = words[if old_ver { 1 } else { 0 }].parse().ok()?;

    let mut new_keys: Vec<DumpKey> = Vec::new();
    for i in 0..MAX_SERVER_KEYS {
        let Some(line) = lines.next() else { break };
        let (words, count) = split_string(line, MAX_WORDS);
        if count != if old_ver { 2 } else { 3 } {
            return None;
        }
        let id = u32::from_str_radix(&words[0], 16).ok()?;
        if !old_ver {
            algorithm = words[2].parse().ok()?;
        }
        let kl = key_length(algorithm);

        // Ids must be consecutive mod MAX_SERVER_KEYS (unsigned wrapping, as in C).
        if i > 0 && id.wrapping_sub(new_keys[i - 1].id) % MAX_SERVER_KEYS as u32 != 1 {
            return None;
        }
        if kl <= 0 {
            return None;
        }
        let key = hex_to_bytes(&words[1])?;
        if key.len() != kl as usize {
            return None;
        }
        new_keys.push(DumpKey { id, siv_algorithm: algorithm, key });
    }
    if new_keys.len() < MAX_SERVER_KEYS {
        return None;
    }

    let mut keys = vec![DumpKey::default(); MAX_SERVER_KEYS];
    let mut last_index = 0;
    for k in new_keys {
        let index = (k.id % MAX_SERVER_KEYS as u32) as usize;
        last_index = index;
        keys[index] = k;
    }
    let current_server_key = (last_index + MAX_SERVER_KEYS - FUTURE_KEYS) % MAX_SERVER_KEYS;

    Some(LoadedKeys { keys, current_server_key, key_age })
}

#[cfg(test)]
mod tests;
