//! SIV AEAD instance API — a complete port of chrony 4.5 `siv_nettle.c` (all 9
//! functions), the `SIV_*` abstraction NTS uses for authenticated encryption.
//!
//! # What this module is
//!
//! `siv_nettle.c` is the thin instance layer over the SIV ciphers: it creates a
//! keyed instance for a chosen AEAD algorithm, reports the key/nonce/tag lengths,
//! validates inputs, and dispatches encrypt/decrypt. For `AEAD_AES_SIV_CMAC_256`
//! chrony's own [`crate::siv_nettle_int`] does the work (the implementation this
//! project already ports); the AES-GCM-SIV variant needs a newer GNU Nettle.
//!
//! # Build configuration
//!
//! This targets chrony's build **without** `HAVE_NETTLE_SIV_GCM` — the
//! configuration that uses the bundled `siv_nettle_int.c`. As in that build,
//! `AEAD_AES_SIV_CMAC_256` is supported and the GCM-SIV (and CMAC-384/512)
//! algorithms report a key length of 0, so creating an instance for them fails —
//! exactly as a chrony built against that nettle does. All 9 functions are ported.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `siv_nettle.c`** (which
//! `#include`s `siv_nettle_int.c`) over a FIPS-197-verified shim AES: a C generator
//! exercises the key-length table, instance creation, key setting, the nonce/length
//! validation in encrypt/decrypt, a round-trip, tamper rejection, and the no-key
//! refusal (`research/oracle/siv_nettle-c-vectors.txt`). The crypto itself is
//! already triple-anchored in [`crate::siv_nettle_int`] (FIPS-197 + RFC 5297 + real
//! C); this fixture pins the wrapper's API and validation.

use crate::siv_nettle_int::{SivCmacAes128, SIV_DIGEST_SIZE};

/// chrony `SIV_MAX_KEY_LENGTH`.
pub const SIV_MAX_KEY_LENGTH: usize = 32;
/// chrony `SIV_MAX_TAG_LENGTH`.
pub const SIV_MAX_TAG_LENGTH: i32 = 16;
/// chrony `SIV_MIN_NONCE_SIZE` (from `siv_nettle_int.c`).
const SIV_MIN_NONCE_SIZE: i32 = 1;
/// `AES128_KEY_SIZE`.
const AES128_KEY_SIZE: i32 = 16;

/// chrony `SIV_Algorithm`: the AEAD algorithms in the IANA registry chrony names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum SivAlgorithm {
    /// AES-SIV-CMAC-256 (the one this build implements).
    AesSivCmac256 = 15,
    /// AES-SIV-CMAC-384.
    AesSivCmac384 = 16,
    /// AES-SIV-CMAC-512.
    AesSivCmac512 = 17,
    /// AES-128-GCM-SIV.
    Aes128GcmSiv = 30,
    /// AES-256-GCM-SIV.
    Aes256GcmSiv = 31,
}

/// chrony `SIV_GetKeyLength`: the key length (bytes) for an algorithm, or 0 if this
/// build does not support it.
pub fn get_key_length(algorithm: SivAlgorithm) -> i32 {
    debug_assert!(2 * AES128_KEY_SIZE <= SIV_MAX_KEY_LENGTH as i32);
    match algorithm {
        SivAlgorithm::AesSivCmac256 => 2 * AES128_KEY_SIZE,
        // GCM-SIV (and CMAC-384/512) need a different/newer Nettle; unsupported here.
        _ => 0,
    }
}

/// A keyed SIV cipher instance (chrony's `SIV_Instance_Record`).
#[derive(Debug)]
pub struct SivInstance {
    algorithm: SivAlgorithm,
    key_set: bool,
    min_nonce_length: i32,
    max_nonce_length: i32,
    tag_length: i32,
    ctx: Option<SivCmacAes128>,
}

impl SivInstance {
    /// chrony `SIV_CreateInstance`: build an unkeyed instance for `algorithm`, or
    /// `None` if this build does not support it.
    pub fn create(algorithm: SivAlgorithm) -> Option<SivInstance> {
        if get_key_length(algorithm) <= 0 {
            return None;
        }
        let (min_nonce_length, max_nonce_length, tag_length) = match algorithm {
            SivAlgorithm::AesSivCmac256 => (SIV_MIN_NONCE_SIZE, i32::MAX, SIV_DIGEST_SIZE as i32),
            // Only CMAC-256 passes the key-length gate above in this build.
            _ => return None,
        };
        Some(SivInstance {
            algorithm,
            key_set: false,
            min_nonce_length,
            max_nonce_length,
            tag_length,
            ctx: None,
        })
    }

    /// chrony `SIV_SetKey`: key the instance. Returns false on a wrong-length key.
    pub fn set_key(&mut self, key: &[u8]) -> bool {
        if key.len() as i32 != get_key_length(self.algorithm) {
            return false;
        }
        match self.algorithm {
            SivAlgorithm::AesSivCmac256 => {
                let k: &[u8; 32] = key.try_into().expect("checked length 32");
                self.ctx = Some(SivCmacAes128::set_key(k));
            }
            _ => return false,
        }
        self.key_set = true;
        true
    }

    /// chrony `SIV_GetMinNonceLength`.
    pub fn min_nonce_length(&self) -> i32 {
        self.min_nonce_length
    }

    /// chrony `SIV_GetMaxNonceLength`.
    pub fn max_nonce_length(&self) -> i32 {
        self.max_nonce_length
    }

    /// chrony `SIV_GetTagLength`.
    pub fn tag_length(&self) -> i32 {
        assert!(self.tag_length >= 1 && self.tag_length <= SIV_MAX_TAG_LENGTH);
        self.tag_length
    }

    /// Shared input validation for encrypt/decrypt (chrony's identical checks).
    fn validate(&self, nonce_len: i32, assoc_len: i32, plaintext_len: i32, ciphertext_len: i32) -> bool {
        self.key_set
            && nonce_len >= self.min_nonce_length
            && nonce_len <= self.max_nonce_length
            && assoc_len >= 0
            && plaintext_len >= 0
            && plaintext_len <= ciphertext_len
            && plaintext_len + self.tag_length() == ciphertext_len
    }

    /// chrony `SIV_Encrypt`: write `SIV || ciphertext` into `ciphertext`. Returns
    /// false if the key is unset or the lengths are invalid.
    pub fn encrypt(
        &self,
        nonce: &[u8],
        assoc: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> bool {
        if !self.validate(
            nonce.len() as i32,
            assoc.len() as i32,
            plaintext.len() as i32,
            ciphertext.len() as i32,
        ) {
            return false;
        }
        match self.algorithm {
            SivAlgorithm::AesSivCmac256 => {
                self.ctx.as_ref().unwrap().encrypt_message(nonce, assoc, ciphertext, plaintext);
            }
            _ => return false,
        }
        true
    }

    /// chrony `SIV_Decrypt`: verify + decrypt `ciphertext` (`SIV || …`) into
    /// `plaintext`. Returns false on invalid lengths or a failed tag check.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        assoc: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> bool {
        if !self.validate(
            nonce.len() as i32,
            assoc.len() as i32,
            plaintext.len() as i32,
            ciphertext.len() as i32,
        ) {
            return false;
        }
        match self.algorithm {
            SivAlgorithm::AesSivCmac256 => {
                self.ctx.as_ref().unwrap().decrypt_message(nonce, assoc, plaintext, ciphertext)
            }
            _ => return false,
        }
    }
}

/// Bridge: a keyed [`SivInstance`] is a real [`crate::nts_ntp_auth::Siv`], so the
/// NTS authenticator layer can run over genuine AES-SIV-CMAC rather than a test
/// cipher.
impl crate::nts_ntp_auth::Siv for SivInstance {
    fn max_nonce_length(&self) -> i32 {
        SivInstance::max_nonce_length(self)
    }
    fn tag_length(&self) -> i32 {
        SivInstance::tag_length(self)
    }
    fn encrypt(&mut self, nonce: &[u8], assoc: &[u8], plaintext: &[u8], ciphertext: &mut [u8]) -> bool {
        SivInstance::encrypt(self, nonce, assoc, plaintext, ciphertext)
    }
    fn decrypt(&mut self, nonce: &[u8], assoc: &[u8], ciphertext: &[u8], plaintext: &mut [u8]) -> bool {
        SivInstance::decrypt(self, nonce, assoc, ciphertext, plaintext)
    }
}

#[cfg(test)]
mod tests;
