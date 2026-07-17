//! Symmetric key store for NTP/command authentication — a complete port of
//! chrony 4.5 `keys.c` (all 17 functions) for chrony's **internal-MD5 build**.
//!
//! # What this module is
//!
//! `keys.c` loads the symmetric key file (`keyfile`), stores one [`Key`] per line
//! sorted by id, and answers the daemon's authentication questions: is a key id
//! known, how long is its MAC, is the key long enough to be secure, and — the core
//! — generate / verify the MAC over a message. It is the direct consumer of the
//! ported [`md5`](crate::md5) / [`hash_intmd5`](crate::hash_intmd5) digest.
//!
//! # Build configuration (and why "Full" is honest here)
//!
//! chrony's MAC can be a keyed hash (`HSH_*`, e.g. MD5/SHA*) or an AES CMAC
//! (`CMC_*`). Which algorithms exist depends on how chrony was *built*: with the
//! internal MD5 hash and **no crypto library**, `HSH_GetHashId` supports only MD5
//! and there is no CMAC backend at all, so SHA/CMAC key lines are rejected at load
//! exactly as this port rejects them. This is the build whose hash this project has
//! already ported byte-for-byte ([`hash_intmd5`](crate::hash_intmd5) `#include`s
//! `md5.c`). Every one of `keys.c`'s 17 functions is ported; the CMAC arms are
//! present (mirroring the C) but, as in a no-crypto chrony, are unreachable because
//! no CMAC key can be stored. AES-CMAC is the documented deferred boundary — a
//! [`CryptoBackend`] implementor can add it without touching this logic.
//!
//! # Adaptations (documented, not silent)
//!
//! * **Host boundary.** chrony reads the key file with `fopen`/`fgets`. The brain
//!   must not touch the filesystem, so [`KeyStore::reload`] takes the key file
//!   *contents* (`Option<&str>`; `None` = no `keyfile` configured). Reading the
//!   file is the daemon's job.
//! * **Crypto injection.** The `HSH_*`/`CMC_*` primitives are behind the
//!   [`CryptoBackend`] trait; [`InternalMd5Backend`] is the default and mirrors the
//!   build above.
//! * **Indices, not pointers.** chrony's `lookup_key`/`get_key` use pointer
//!   arithmetic into the `ARR_Instance`; the port uses a `Vec<Key>` and `usize`
//!   indices, preserving the sorted-array + binary-search + one-entry cache design.
//!
//! # Oracles
//!
//! Differential-tested against the **real compiled `keys.c`** (internal-MD5 build):
//! a C generator loads the committed key file (`research/oracle/keys-c-keyfile.txt`)
//! and emits, per key id, the `KeyKnown`/`GetAuthLength`/`CheckKeyLength`/
//! `GetKeyInfo`/`GenerateAuth` (MAC bytes) and `CheckAuth` results
//! (`research/oracle/keys-c-vectors.txt`); the port replays the same key file and
//! must match every field. A second, independent check verifies the NTP symmetric
//! MAC is `MD5(key || message)` via the RFC-1321-vectored [`md5`](crate::md5)
//! directly. See the tests.

use crate::cmdparse;
use crate::hash_intmd5::{self, HshAlgorithm};
use crate::md5::Md5;
use crate::util;

/// chrony `MIN_SECURE_KEY_LENGTH`: 80 bits (10 bytes) is the floor for a key to be
/// considered secure.
pub const MIN_SECURE_KEY_LENGTH: usize = 10;

/// chrony `MAX_HASH_LENGTH` (`hash.h`): the largest MAC the buffers must hold.
pub const MAX_HASH_LENGTH: usize = 64;

/// chrony `CMC_Algorithm` (`cmac.h`): the AES CMAC ciphers. Recognized by name so
/// the rejection path is faithful, even though the internal-MD5 build supports
/// none of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CmacAlgorithm {
    /// Not a CMAC cipher name.
    Invalid = 0,
    /// AES-128-CMAC.
    Aes128 = 13,
    /// AES-256-CMAC.
    Aes256 = 14,
}

/// The per-class MAC material. chrony keeps a separate `KeyClass` tag (`NTP_MAC` /
/// `CMAC`) alongside a `data` union; in Rust those collapse into one tagged enum —
/// the variant *is* the class, so no separate tag field is needed.
#[derive(Debug)]
enum KeyMac {
    /// A keyed hash: the key bytes plus the hash id returned by the backend.
    NtpMac { value: Vec<u8>, hash_id: i32 },
    /// An AES CMAC key. Never constructed in the internal-MD5 build (no CMAC
    /// backend), but modeled for parity with the C union.
    // Future CMAC authentication support
    #[allow(dead_code)]
    Cmac {
        algorithm: CmacAlgorithm,
        key: Vec<u8>,
    },
}

/// One stored key (chrony's `Key`).
#[derive(Debug)]
struct Key {
    id: u32,
    /// Algorithm enum value (`HSH_*` or `CMC_*`), as chrony stores in `type`.
    type_: i32,
    /// Key length in bytes.
    length: usize,
    mac: KeyMac,
}

/// The crypto primitives `keys.c` calls (`HSH_*` / `CMC_*`). Injecting these keeps
/// the key-store logic independent of which algorithms a build supports.
pub trait CryptoBackend {
    /// chrony `HSH_GetHashId`: a non-negative id if the hash is supported, else -1.
    fn hash_id(&self, algorithm: HshAlgorithm) -> i32;

    /// chrony `HSH_Hash(id, in1, in2, out)`: hash `in1 || in2` into `out`,
    /// returning the number of bytes written (truncated to `out.len()`).
    fn hash(&self, hash_id: i32, in1: &[u8], in2: &[u8], out: &mut [u8]) -> usize;

    /// chrony `CMC_GetKeyLength`: required key length in bytes (0 = unsupported).
    fn cmac_key_length(&self, algorithm: CmacAlgorithm) -> usize;

    /// chrony `CMC_Hash`: AES CMAC of `data` under `key` into `out`. Unreachable in
    /// the internal-MD5 build (no CMAC key can load); a real CMAC backend overrides.
    fn cmac_hash(
        &self,
        _algorithm: CmacAlgorithm,
        _key: &[u8],
        _data: &[u8],
        _out: &mut [u8],
    ) -> usize {
        0
    }
}

/// The default backend: chrony's internal MD5 hash, no crypto library. Supports
/// only MD5 hashing; all CMAC ciphers are unsupported (key length 0), so SHA/CMAC
/// key lines are rejected at load exactly as a no-crypto chrony rejects them.
#[derive(Debug, Default)]
pub struct InternalMd5Backend;

impl CryptoBackend for InternalMd5Backend {
    fn hash_id(&self, algorithm: HshAlgorithm) -> i32 {
        // hash_intmd5: only MD5 (and the non-crypto MD5 refid variant) is supported.
        hash_intmd5::get_hash_id(algorithm).unwrap_or(-1)
    }

    fn hash(&self, _hash_id: i32, in1: &[u8], in2: &[u8], out: &mut [u8]) -> usize {
        // The internal backend has exactly one hash; hash_id is always its id.
        hash_intmd5::hash(in1, in2, out)
    }

    fn cmac_key_length(&self, _algorithm: CmacAlgorithm) -> usize {
        0
    }
}

/// chrony `UTI_HashNameToAlgorithm` (`util.c`): map a key-type name to a hash
/// algorithm (or [`HshAlgorithm::Invalid`]).
pub fn hash_name_to_algorithm(name: &str) -> HshAlgorithm {
    match name {
        "MD5" => HshAlgorithm::Md5,
        "SHA1" => HshAlgorithm::Sha1,
        "SHA256" => HshAlgorithm::Sha256,
        "SHA384" => HshAlgorithm::Sha384,
        "SHA512" => HshAlgorithm::Sha512,
        "SHA3-224" => HshAlgorithm::Sha3_224,
        "SHA3-256" => HshAlgorithm::Sha3_256,
        "SHA3-384" => HshAlgorithm::Sha3_384,
        "SHA3-512" => HshAlgorithm::Sha3_512,
        "TIGER" => HshAlgorithm::Tiger,
        "WHIRLPOOL" => HshAlgorithm::Whirlpool,
        _ => HshAlgorithm::Invalid,
    }
}

/// chrony `UTI_CmacNameToAlgorithm` (`util.c`).
pub fn cmac_name_to_algorithm(name: &str) -> CmacAlgorithm {
    match name {
        "AES128" => CmacAlgorithm::Aes128,
        "AES256" => CmacAlgorithm::Aes256,
        _ => CmacAlgorithm::Invalid,
    }
}

/// chrony `decode_key`: decode an `ASCII:`/`HEX:`-prefixed (or bare ASCII) key into
/// raw bytes. Returns `None` on a malformed `HEX:` value (chrony's length-0 case).
fn decode_key(key: &str) -> Option<Vec<u8>> {
    if let Some(rest) = key.strip_prefix("ASCII:") {
        Some(rest.as_bytes().to_vec())
    } else if let Some(rest) = key.strip_prefix("HEX:") {
        // chrony returns 0 (here: None) when the hex is malformed.
        util::hex_to_bytes(rest).filter(|b| !b.is_empty())
    } else {
        // Assume ASCII.
        Some(key.as_bytes().to_vec())
    }
}

/// The symmetric key store (chrony's `keys.c` module state) over an injected
/// [`CryptoBackend`].
#[derive(Debug)]
pub struct KeyStore<B: CryptoBackend = InternalMd5Backend> {
    keys: Vec<Key>,
    backend: B,
    // chrony's one-entry lookup cache.
    cache_valid: bool,
    cache_key_id: u32,
    cache_key_pos: usize,
    /// Diagnostics emitted during the last [`KeyStore::reload`] (chrony `LOG`s
    /// these as warnings; surfaced here so callers/tests can observe them).
    warnings: Vec<String>,
}

impl KeyStore<InternalMd5Backend> {
    /// chrony `KEY_Initialise` with the default internal-MD5 backend, loading the
    /// given key file contents (`None` = no `keyfile` configured).
    pub fn initialise(keyfile: Option<&str>) -> Self {
        KeyStore::initialise_with_backend(InternalMd5Backend, keyfile)
    }
}

impl<B: CryptoBackend> KeyStore<B> {
    /// chrony `KEY_Initialise` (`KEY_Reload` folded in) with an explicit backend.
    pub fn initialise_with_backend(backend: B, keyfile: Option<&str>) -> Self {
        let mut store = KeyStore {
            keys: Vec::new(),
            backend,
            cache_valid: false,
            cache_key_id: 0,
            cache_key_pos: 0,
            warnings: Vec::new(),
        };
        store.reload(keyfile);
        store
    }

    /// chrony `free_keys`: clear all keys and invalidate the cache.
    fn free_keys(&mut self) {
        self.keys.clear();
        self.cache_valid = false;
    }

    /// chrony `KEY_Reload`: parse the key file contents into the sorted key store.
    pub fn reload(&mut self, keyfile: Option<&str>) {
        self.free_keys();
        self.warnings.clear();

        let Some(contents) = keyfile else {
            return;
        };

        for raw in contents.lines() {
            let line = cmdparse::normalize_line(raw);
            if line.is_empty() {
                continue;
            }

            let Some((id, key_type, key_value)) = cmdparse::parse_key(&line) else {
                self.warnings
                    .push(format!("Could not parse key line: {raw}"));
                continue;
            };

            let Some(decoded) = decode_key(&key_value) else {
                self.warnings.push(format!("Could not decode key {id}"));
                continue;
            };
            if decoded.is_empty() {
                self.warnings.push(format!("Could not decode key {id}"));
                continue;
            }

            let hash_algorithm = hash_name_to_algorithm(&key_type);
            let cmac_algorithm = cmac_name_to_algorithm(&key_type);

            let key = if hash_algorithm != HshAlgorithm::Invalid {
                let hash_id = self.backend.hash_id(hash_algorithm);
                if hash_id < 0 {
                    self.warnings
                        .push(format!("Unsupported hash function in key {id}"));
                    continue;
                }
                Key {
                    id,
                    type_: hash_algorithm as i32,
                    length: decoded.len(),
                    mac: KeyMac::NtpMac {
                        value: decoded,
                        hash_id,
                    },
                }
            } else if cmac_algorithm != CmacAlgorithm::Invalid {
                let cmac_key_length = self.backend.cmac_key_length(cmac_algorithm);
                if cmac_key_length == 0 {
                    self.warnings
                        .push(format!("Unsupported cipher in key {id}"));
                    continue;
                } else if cmac_key_length != decoded.len() {
                    self.warnings.push(format!(
                        "Invalid length of {key_type} key {id} (expected {} bits)",
                        8 * cmac_key_length
                    ));
                    continue;
                }
                Key {
                    id,
                    type_: cmac_algorithm as i32,
                    length: decoded.len(),
                    mac: KeyMac::Cmac {
                        algorithm: cmac_algorithm,
                        key: decoded,
                    },
                }
            } else {
                self.warnings.push(format!("Invalid type in key {id}"));
                continue;
            };

            self.keys.push(key);
        }

        // Sort by id (stable; on a duplicate, which one is used later is arbitrary
        // — chrony says the user should not have created one).
        self.keys.sort_by(|a, b| a.id.cmp(&b.id));

        // Warn on duplicates.
        for i in 1..self.keys.len() {
            if self.keys[i - 1].id == self.keys[i].id {
                self.warnings
                    .push(format!("Detected duplicate key {}", self.keys[i - 1].id));
            }
        }
    }

    /// chrony `lookup_key`: binary search for `id`, returning its index.
    fn lookup_key(&self, id: u32) -> Option<usize> {
        self.keys.binary_search_by(|k| k.id.cmp(&id)).ok()
    }

    /// chrony `get_key_by_id`: cached binary-search lookup. Returns the index.
    fn get_key_by_id(&mut self, key_id: u32) -> Option<usize> {
        if self.cache_valid && key_id == self.cache_key_id {
            return Some(self.cache_key_pos);
        }
        let pos = self.lookup_key(key_id)?;
        self.cache_valid = true;
        self.cache_key_pos = pos;
        self.cache_key_id = key_id;
        Some(pos)
    }

    /// chrony `KEY_KeyKnown`.
    pub fn key_known(&mut self, key_id: u32) -> bool {
        self.get_key_by_id(key_id).is_some()
    }

    /// chrony `KEY_GetAuthLength`: the MAC length the key produces, or 0 if unknown.
    pub fn get_auth_length(&mut self, key_id: u32) -> i32 {
        let Some(idx) = self.get_key_by_id(key_id) else {
            return 0;
        };
        let mut buf = [0u8; MAX_HASH_LENGTH];
        match &self.keys[idx].mac {
            KeyMac::NtpMac { hash_id, .. } => {
                self.backend.hash(*hash_id, &[], &[], &mut buf) as i32
            }
            KeyMac::Cmac { algorithm, key } => {
                self.backend.cmac_hash(*algorithm, key, &[], &mut buf) as i32
            }
        }
    }

    /// chrony `KEY_CheckKeyLength`: whether the key meets the secure-length floor.
    pub fn check_key_length(&mut self, key_id: u32) -> bool {
        match self.get_key_by_id(key_id) {
            None => false,
            Some(idx) => self.keys[idx].length >= MIN_SECURE_KEY_LENGTH,
        }
    }

    /// chrony `KEY_GetKeyInfo`: `(type, bits)` for a known key.
    pub fn get_key_info(&mut self, key_id: u32) -> Option<(i32, i32)> {
        let idx = self.get_key_by_id(key_id)?;
        Some((self.keys[idx].type_, 8 * self.keys[idx].length as i32))
    }

    /// chrony `generate_auth`: write the MAC of `data` into `out`, returning length.
    fn generate_auth(&self, idx: usize, data: &[u8], out: &mut [u8]) -> usize {
        match &self.keys[idx].mac {
            KeyMac::NtpMac { value, hash_id } => self.backend.hash(*hash_id, value, data, out),
            KeyMac::Cmac { algorithm, key } => self.backend.cmac_hash(*algorithm, key, data, out),
        }
    }

    /// chrony `KEY_GenerateAuth`: MAC `data` under `key_id` into `auth` (length, or
    /// 0 if the key is unknown).
    pub fn generate_key_auth(&mut self, key_id: u32, data: &[u8], auth: &mut [u8]) -> usize {
        match self.get_key_by_id(key_id) {
            None => 0,
            Some(idx) => self.generate_auth(idx, data, auth),
        }
    }

    /// chrony `check_auth` / `KEY_CheckAuth`: verify that `auth` is the (possibly
    /// truncated to `trunc_len`) MAC of `data` under `key_id`.
    pub fn check_key_auth(
        &mut self,
        key_id: u32,
        data: &[u8],
        auth: &[u8],
        trunc_len: usize,
    ) -> bool {
        let Some(idx) = self.get_key_by_id(key_id) else {
            return false;
        };
        let mut buf = [0u8; MAX_HASH_LENGTH];
        let hash_len = self.generate_auth(idx, data, &mut buf);
        hash_len.min(trunc_len) == auth.len() && buf[..auth.len()] == *auth
    }

    /// The warnings emitted by the last [`reload`](Self::reload) (chrony's `LOG`s).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Number of loaded keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store has no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Trait for file I/O operations needed by the key store.
/// The brain (core) doesn't touch the filesystem; the IO crate provides
/// the real implementation.
pub trait KeyStoreBackend {
    /// Read the contents of a file. Returns None on error.
    fn read_file(&mut self, name: &str) -> Option<Vec<u8>>;
    /// Estimate of authentication delay for a given message length.
    fn get_auth_delay(&mut self, _len: i32) -> f64;
}

#[allow(non_snake_case)]
/// chrony `KEY_Initialise`: read key file (if configured) and create a KeyStore.
pub fn KEY_Initialise(name: Option<&str>, backend: &mut dyn KeyStoreBackend) -> KeyStore {
    let contents = name.and_then(|n| KEY_ReadFile(n, backend));
    let content_str = contents
        .as_ref()
        .and_then(|c| String::from_utf8(c.clone()).ok());
    KeyStore::initialise(content_str.as_deref())
}

#[allow(non_snake_case)]
/// chrony `KEY_ReadFile`: read a key file from disk via the backend.
pub fn KEY_ReadFile(name: &str, backend: &mut dyn KeyStoreBackend) -> Option<Vec<u8>> {
    backend.read_file(name)
}

#[allow(non_snake_case)]
/// chrony `KEY_Reload`: re-read and reload keys into an existing store.
pub fn KEY_Reload(store: &mut KeyStore, name: Option<&str>, backend: &mut dyn KeyStoreBackend) {
    let contents = name.and_then(|n| KEY_ReadFile(n, backend));
    let content_str = contents
        .as_ref()
        .and_then(|c| String::from_utf8(c.clone()).ok());
    store.reload(content_str.as_deref());
}

/// The NTP symmetric MAC computed directly from the ported MD5, independent of the
/// key store: `MD5(key || message)`. Used by the tests as a second oracle.
#[doc(hidden)]
pub fn ntp_md5_mac(key: &[u8], message: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(key);
    h.update(message);
    h.finalize()
}

#[cfg(test)]
mod tests;
