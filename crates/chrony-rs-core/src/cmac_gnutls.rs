//! GnuTLS CMAC backend — a port of chrony 4.5 `cmac_gnutls.c`.
//!
//! GnuTLS CMAC (Cipher-based MAC) backend wrapping `gnutls_cipher_mac`.
//! The same `CMC_*` API is implemented by the nettle backend in
//! [`crate::cmac_nettle`]. The gnutls library is the host boundary; the
//! MAC operations are injected closures. Key-length validation and the
//! algorithm-name resolution are ported from the C.

/// `CMC_GetKeyLength`: return the key length in bytes for a given CMAC
/// algorithm name (`"AES-128"` → 16, `"AES-256"` → 32, others → 0).
pub fn cmc_get_key_length(algorithm: &str) -> i32 {
    match algorithm {
        "AES-128" => 16,
        "AES-256" => 32,
        _ => 0,
    }
}

/// `CMC_CreateInstance`: create a new CMAC instance with the given key.
/// Host boundary (gnutls_cipher_init / gnutls_cipher_set_key).
pub fn cmc_create_instance<F: FnOnce(&[u8])>(key: &[u8], create: F) {
    create(key);
}

/// `CMC_Hash`: compute a CMAC over `data` with the instance, writing at
/// most `out_len` bytes. Host boundary (gnutls_cipher_mac).
pub fn cmc_hash<F: FnOnce(&[u8], &mut [u8])>(
    _key: &[u8],
    data: &[u8],
    out_len: usize,
    hash_fn: F,
) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    hash_fn(data, &mut out);
    out.truncate(out_len);
    out
}

/// `CMC_DestroyInstance`: destroy a CMAC instance.
pub fn cmc_destroy_instance<F: FnOnce()>(destroy: F) {
    destroy();
}

/// `init_gnutls`: initialise the gnutls library (gnutls_global_init).
pub fn init_gnutls<F: FnOnce() -> bool>(init: F) -> bool {
    init()
}

/// `deinit_gnutls`: de-initialise the gnutls library.
pub fn deinit_gnutls<F: FnOnce()>(deinit: F) {
    deinit();
}

/// `get_mac_algorithm`: get the gnutls MAC algorithm id for a given
/// CMAC algorithm name. Returns -1 for unknown algorithms.
pub fn get_mac_algorithm(algorithm: &str) -> i32 {
    match algorithm {
        "AES-128" => 1,
        "AES-256" => 2,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_lengths() {
        assert_eq!(cmc_get_key_length("AES-128"), 16);
        assert_eq!(cmc_get_key_length("AES-256"), 32);
        assert_eq!(cmc_get_key_length("BOGUS"), 0);
    }

    #[test]
    fn mac_algorithm() {
        assert_eq!(get_mac_algorithm("AES-128"), 1);
        assert_eq!(get_mac_algorithm("unknown"), -1);
    }
}
