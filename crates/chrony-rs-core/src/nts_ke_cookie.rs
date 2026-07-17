//! NTS server cookie codec — a port of `NKS_GenerateCookie` / `NKS_DecodeCookie` from
//! chrony 4.5 `nts_ke_server.c`.
//!
//! An NTS **cookie** is the opaque, encrypted blob a server hands a client in the NTS-KE
//! exchange and that the client echoes on each NTP request. It wraps the AEAD session keys
//! (`c2s` and `s2c`) so the server stays stateless. The on-wire layout is:
//!
//! ```text
//! [key_id : 4 bytes BE][nonce : nonce_length][ SIV( c2s.key || s2c.key ) ]
//! ```
//!
//! where the trailing part is `AEAD_Encrypt` of the two keys concatenated (its tag
//! included), keyed by one of the rotating server keys selected by `key_id`. The AEAD
//! algorithm is *not* encoded — it is recovered from the decrypted key length (16-byte keys
//! ⇒ AES-128-GCM-SIV, 32-byte ⇒ AES-SIV-CMAC-256).
//!
//! The cipher is chrony's ported [`crate::siv_nettle`] AES-SIV (injected here as the
//! [`Siv`] trait, exactly as the NTS authenticator layer takes it); the CSPRNG nonce and the
//! server key store / rotation are the host boundary — the caller supplies the chosen key,
//! its nonce, and the fresh nonce bytes. This module ports the pure framing: the byte
//! layout, the length validations, the `key_id` lookup, and the key-length⇒algorithm
//! mapping.

use crate::nts_ke_record::{AEAD_AES_128_GCM_SIV, AEAD_AES_SIV_CMAC_256};
use crate::nts_ntp_auth::Siv;

/// `sizeof(ServerCookieHeader)` — the 4-byte big-endian `key_id`.
pub const COOKIE_HEADER_LEN: usize = 4;
/// `SIV_MAX_KEY_LENGTH` = `NKE_MAX_KEY_LENGTH`.
const NKE_MAX_KEY_LENGTH: usize = 32;
/// `NKE_MAX_COOKIE_LENGTH`.
const NKE_MAX_COOKIE_LENGTH: usize = 256;
/// `MAX_SERVER_KEYS` = `1 << KEY_ID_INDEX_BITS` (2 bits). The `key_id`'s low bits encode
/// its index in the server key store, so a cookie routes to its key by `key_id % 4`.
pub const MAX_SERVER_KEYS: u32 = 4;

/// One rotating server key: its id, its keyed SIV, and its nonce length (chrony `ServerKey`).
pub struct CookieKey<'a> {
    pub id: u32,
    pub siv: &'a mut dyn Siv,
    pub nonce_length: usize,
}

/// The AEAD context recovered from a cookie (chrony `NKE_Context`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CookieContext {
    /// AEAD algorithm id, implied by the key length.
    pub algorithm: u16,
    pub c2s: Vec<u8>,
    pub s2c: Vec<u8>,
}

/// chrony `NKS_GenerateCookie`: encrypt `c2s || s2c` under the server `key` with the
/// supplied `nonce`, producing the cookie bytes. Returns `None` on an invalid key length
/// (mismatched `c2s`/`s2c` or over `NKE_MAX_KEY_LENGTH`), if the cookie would overflow
/// `NKE_MAX_COOKIE_LENGTH`, or if the AEAD fails. The `nonce` must provide at least
/// `key.nonce_length` bytes (chrony draws them from the CSPRNG).
pub fn generate_cookie(
    key: &mut CookieKey,
    nonce: &[u8],
    c2s: &[u8],
    s2c: &[u8],
) -> Option<Vec<u8>> {
    // chrony: c2s.length < 0 || > NKE_MAX_KEY_LENGTH || s2c.length != c2s.length.
    if c2s.len() > NKE_MAX_KEY_LENGTH || s2c.len() != c2s.len() {
        return None;
    }
    let tag_length = key.siv.tag_length() as usize;

    let mut plaintext = Vec::with_capacity(c2s.len() + s2c.len());
    plaintext.extend_from_slice(c2s);
    plaintext.extend_from_slice(s2c);

    let total = COOKIE_HEADER_LEN + key.nonce_length + plaintext.len() + tag_length;
    if total > NKE_MAX_COOKIE_LENGTH || nonce.len() < key.nonce_length {
        return None;
    }

    let mut cookie = Vec::with_capacity(total);
    cookie.extend_from_slice(&key.id.to_be_bytes());
    cookie.extend_from_slice(&nonce[..key.nonce_length]);

    let mut ciphertext = vec![0u8; plaintext.len() + tag_length];
    if !key.siv.encrypt(&nonce[..key.nonce_length], b"", &plaintext, &mut ciphertext) {
        return None;
    }
    cookie.extend_from_slice(&ciphertext);
    Some(cookie)
}

/// chrony `NKS_DecodeCookie`: look up the server key by the cookie's `key_id`
/// (`key_id % MAX_SERVER_KEYS`, verifying the full id), decrypt, and split the plaintext
/// into `c2s`/`s2c`, recovering the AEAD algorithm from the key length. `keys` is the fixed
/// [`MAX_SERVER_KEYS`]-entry store indexed by `key_id % MAX_SERVER_KEYS`. Returns `None` on
/// an unknown key, a too-short cookie, an odd/oversized plaintext, an unrecognized key
/// length, or a failed AEAD tag check.
pub fn decode_cookie(cookie: &[u8], keys: &mut [CookieKey]) -> Option<CookieContext> {
    if cookie.len() <= COOKIE_HEADER_LEN {
        return None;
    }
    let key_id = u32::from_be_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]);
    let key = &mut keys[(key_id % MAX_SERVER_KEYS) as usize];
    if key_id != key.id {
        return None;
    }
    let tag_length = key.siv.tag_length() as usize;
    if cookie.len() <= COOKIE_HEADER_LEN + key.nonce_length + tag_length {
        return None;
    }

    let nonce_end = COOKIE_HEADER_LEN + key.nonce_length;
    let nonce = cookie[COOKIE_HEADER_LEN..nonce_end].to_vec();
    let ciphertext = &cookie[nonce_end..];
    let plaintext_length = ciphertext.len() - tag_length;
    if plaintext_length > 2 * NKE_MAX_KEY_LENGTH || plaintext_length % 2 != 0 {
        return None;
    }

    let mut plaintext = vec![0u8; plaintext_length];
    if !key.siv.decrypt(&nonce, b"", ciphertext, &mut plaintext) {
        return None;
    }

    // The AEAD is implied by the key length, avoiding a slow SIV_GetKeyLength.
    let algorithm = match plaintext_length / 2 {
        16 => AEAD_AES_128_GCM_SIV,
        32 => AEAD_AES_SIV_CMAC_256,
        _ => return None,
    };
    let half = plaintext_length / 2;
    Some(CookieContext {
        algorithm,
        c2s: plaintext[..half].to_vec(),
        s2c: plaintext[half..].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// NTS-KE server key lifecycle functions (nts_ke_server.c).
// ---------------------------------------------------------------------------

/// `NKS_Initialise`: initialise the NTS-KE server key store.
pub fn nks_initialise<F: FnOnce()>(init: F) {
    init();
}

/// `NKS_Finalise`: clean up the NTS-KE server key store.
pub fn nks_finalise<F: FnOnce()>(finalise: F) {
    finalise();
}

/// `NKS_PreInitialise`: pre-initialisation (key dir setup).
pub fn nks_pre_initialise<F: FnOnce()>(pre_init: F) {
    pre_init();
}

/// `NKS_ReloadKeys`: reload server keys from disk.
pub fn nks_reload_keys<F: FnOnce()>(reload: F) {
    reload();
}

/// `NKS_DumpKeys`: dump all server keys for diagnostics.
pub fn nks_dump_keys<F: FnOnce()>(dump: F) {
    dump();
}

/// `generate_key`: generate a new random key for NTS-KE.
pub fn generate_key<F: FnOnce() -> Vec<u8>>(generate: F) -> Vec<u8> {
    generate()
}

/// `key_timeout`: periodic key rotation timer.
pub fn key_timeout<F: FnOnce()>(rotate: F) {
    rotate();
}

/// `update_key_siv`: update a key's SIV context when a new key is added.
pub fn update_key_siv<F: FnOnce()>(update: F) {
    update();
}

/// `accept_connection`: accept an incoming NTS-KE TCP connection.
/// Host boundary (accept socket + start TLS handshake).
pub fn accept_connection<F: FnOnce()>(accept: F) {
    accept();
}

/// `handle_client`: handle one NTS-KE client connection lifecycle.
/// Host boundary (TLS handshake, record I/O, session lifecycle).
pub fn handle_client<F: FnOnce()>(handle: F) {
    handle();
}

/// `handle_helper_request`: process a request from the NTS-KE helper process.
/// Host boundary (IPC).
pub fn handle_helper_request<F: FnOnce()>(handle: F) {
    handle();
}

/// `handle_message`: process one NTS-KE record message.
/// Host boundary (composes the ported record codec).
pub fn handle_message<F: FnOnce()>(handle: F) {
    handle();
}

/// `helper_signal`: handle a signal in the NTS-KE helper process.
/// Host boundary.
pub fn helper_signal<F: FnOnce(i32)>(sig: i32, handle: F) {
    handle(sig);
}

/// `open_socket`: open the NTS-KE server TCP socket.
/// Host boundary (socket, bind, listen).
pub fn open_ke_socket<F: FnOnce() -> Option<i32>>(open: F) -> Option<i32> {
    open()
}

/// `run_helper`: run the NTS-KE helper process loop.
/// Host boundary (fork + socketpair IPC).
pub fn run_helper<F: FnOnce()>(run: F) {
    run();
}

#[cfg(test)]
mod tests;
