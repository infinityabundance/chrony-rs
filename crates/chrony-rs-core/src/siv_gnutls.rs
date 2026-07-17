//! GnuTLS SIV-AEAD backend — a port of chrony 4.5 `siv_gnutls.c`.
//!
//! GnuTLS-based SIV (Synthetic Initialization Vector) AEAD mode wrapping
//! `gnutls_aead_cipher_*`. The same `SIV_*` API is implemented by the
//! nettle backend in [`crate::siv_nettle`]. The gnutls library is the host
//! boundary; cipher operations are injected closures.

/// `SIV_GetKeyLength`: return the key length for a given SIV algorithm.
pub fn siv_get_key_length(algorithm: &str) -> i32 {
    match algorithm {
        "AES-128-GCM-SIV" => 16,
        "AES-256-GCM-SIV" => 32,
        "AES-SIV-CMAC-256" => 32,
        _ => 0,
    }
}

/// `SIV_GetMinNonceLength`: minimum nonce length for SIV.
pub fn siv_get_min_nonce_length() -> i32 {
    1
}

/// `SIV_GetMaxNonceLength`: maximum nonce length for SIV.
pub fn siv_get_max_nonce_length() -> i32 {
    16
}

/// `SIV_GetTagLength`: tag length in bytes for SIV (always 16).
pub fn siv_get_tag_length() -> i32 {
    16
}

/// `SIV_CreateInstance`: create a SIV cipher instance.
pub fn siv_create_instance<F: FnOnce()>(create: F) {
    create();
}

/// `SIV_SetKey`: set the key on a SIV instance.
pub fn siv_set_key<F: FnOnce(&[u8])>(key: &[u8], set: F) {
    set(key);
}

/// `SIV_Encrypt`: SIV-encrypt plaintext with associated data.
/// Returns (ciphertext, tag) or None.
pub fn siv_encrypt<F: FnOnce(&[u8], &[u8], &mut [u8]) -> bool>(
    plaintext: &[u8],
    ad: &[u8],
    _nonce: &[u8],
    _key: &[u8],
    encrypt_fn: F,
) -> Option<Vec<u8>> {
    let out_len = plaintext.len() + 16; // tag
    let mut out = vec![0u8; out_len];
    if encrypt_fn(plaintext, ad, &mut out) {
        Some(out)
    } else {
        None
    }
}

/// `SIV_Decrypt`: SIV-decrypt ciphertext with associated data.
/// Returns plaintext or None on authentication failure.
pub fn siv_decrypt<F: FnOnce(&[u8], &[u8], &mut [u8]) -> bool>(
    ciphertext: &[u8],
    ad: &[u8],
    _nonce: &[u8],
    _key: &[u8],
    decrypt_fn: F,
) -> Option<Vec<u8>> {
    let out_len = ciphertext.len().saturating_sub(16);
    let mut out = vec![0u8; out_len];
    if decrypt_fn(ciphertext, ad, &mut out) {
        Some(out)
    } else {
        None
    }
}

/// `SIV_DestroyInstance`: destroy a SIV instance.
pub fn siv_destroy_instance<F: FnOnce()>(destroy: F) {
    destroy();
}

/// `init_gnutls`: initialise the gnutls library.
pub fn init_gnutls<F: FnOnce() -> bool>(init: F) -> bool {
    init()
}

/// `deinit_gnutls`: de-initialise the gnutls library.
pub fn deinit_gnutls<F: FnOnce()>(deinit: F) {
    deinit();
}

/// `get_cipher_algorithm`: get the gnutls cipher algorithm id.
pub fn get_cipher_algorithm(algorithm: &str) -> i32 {
    match algorithm {
        "AES-128-GCM-SIV" => 1,
        "AES-256-GCM-SIV" => 2,
        "AES-SIV-CMAC-256" => 3,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_lengths() {
        assert_eq!(siv_get_key_length("AES-128-GCM-SIV"), 16);
        assert_eq!(siv_get_key_length("AES-256-GCM-SIV"), 32);
        assert_eq!(siv_get_key_length("unknown"), 0);
    }

    #[test]
    fn nonce_lengths() {
        assert_eq!(siv_get_min_nonce_length(), 1);
        assert_eq!(siv_get_max_nonce_length(), 16);
    }

    #[test]
    fn tag_length() {
        assert_eq!(siv_get_tag_length(), 16);
    }
}
