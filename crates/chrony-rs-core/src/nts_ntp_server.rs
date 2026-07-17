//! Server-side NTS-NTP authentication — a complete port of chrony 4.5
//! `nts_ntp_server.c` (all 4 functions).
//!
//! # What this module is
//!
//! This is the server half of NTS-protected NTP (RFC 8915). For each request it
//! parses the NTS extension fields (unique identifier, cookie, cookie placeholders,
//! and the authenticator), decodes the cookie to recover the per-session keys, keys
//! a SIV cipher with the client-to-server key, verifies + decrypts the
//! authenticator ([`crate::nts_ntp_auth`]), and prepares fresh cookies. The response
//! half copies the unique identifier, adds the new (encrypted) cookies, and appends
//! a server-to-client authenticator sized to match the request.
//!
//! # Adaptations (documented, not silent)
//!
//! * **Composes the ported stack.** Extension-field parsing/formatting is
//!   [`crate::ntp::ext`]; the authenticator EF is [`crate::nts_ntp_auth`]; the AEAD
//!   is a real [`crate::siv_nettle::SivInstance`]. This module is the glue.
//! * **The cookie codec is injected.** Encoding/decoding a cookie (chrony's
//!   `NKS_GenerateCookie` / `NKS_DecodeCookie`, which live in the NTS-KE server and
//!   use the server master key) is the one external boundary — the [`CookieCodec`]
//!   trait. Randomness (the response nonce) is injected too.
//! * **GCM-SIV unsupported.** As in chrony's no-`HAVE_NETTLE_SIV_GCM` build, the
//!   second SIV slot (AES-128-GCM-SIV) is absent; only AES-SIV-CMAC-256 is offered.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `nts_ntp_server.c`** (+
//! `nts_ntp_auth.c`, `ntp_ext.c`, `siv_nettle.c`/`siv_nettle_int.c` over the
//! FIPS-197 shim AES) with a deterministic reversible cookie codec: a C generator
//! builds a client request, runs the check + response, and records the results and
//! the response packet bytes, plus tampered-auth and missing-cookie failures
//! (`research/oracle/nts_ntp_server-c-vectors.txt`). The port replays the identical
//! flow with the same injected codec / real SIV / LCG and matches every byte. See
//! the tests.

use crate::ntp::ext::{
    add_field, parse_field, parse_single_field, set_field, NtpPacketBuf, NtpPacketInfo,
    NTP_HEADER_LENGTH, NTP_MAX_EXTENSIONS_LENGTH,
};
use crate::nts_ntp_auth::{decrypt_auth_ef, generate_auth_ef, NTP_EF_NTS_AUTH_AND_EEF};
use std::fmt;

use crate::siv_nettle::{SivAlgorithm, SivInstance};

/// chrony `NTP_EF_NTS_UNIQUE_IDENTIFIER`.
pub const NTP_EF_NTS_UNIQUE_IDENTIFIER: i32 = 0x0104;
/// chrony `NTP_EF_NTS_COOKIE`.
pub const NTP_EF_NTS_COOKIE: i32 = 0x0204;
/// chrony `NTP_EF_NTS_COOKIE_PLACEHOLDER`.
pub const NTP_EF_NTS_COOKIE_PLACEHOLDER: i32 = 0x0304;
/// chrony `NTP_KOD_NTS_NAK` (kiss-o'-death "NTSN").
pub const NTP_KOD_NTS_NAK: u32 = 0x4e54_534e;
/// chrony `NTS_MAX_COOKIES`.
pub const NTS_MAX_COOKIES: usize = 8;
/// chrony `NKE_MAX_COOKIE_LENGTH`.
pub const NKE_MAX_COOKIE_LENGTH: usize = 256;
/// chrony `NTS_MIN_UNPADDED_NONCE_LENGTH`.
const NONCE_LENGTH: usize = 16;
/// chrony `MODE_CLIENT`.
pub const MODE_CLIENT: i32 = 3;
/// chrony `MODE_SERVER`.
pub const MODE_SERVER: i32 = 4;
/// chrony `MAX_SERVER_SIVS`.
const MAX_SERVER_SIVS: usize = 2;

/// A per-session key (chrony `NKE_Key`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NkeKey {
    /// Key bytes.
    pub key: Vec<u8>,
}

/// The NTS session context carried in a cookie (chrony `NKE_Context`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NkeContext {
    /// AEAD algorithm.
    pub algorithm: SivAlgorithm,
    /// Client-to-server key.
    pub c2s: NkeKey,
    /// Server-to-client key.
    pub s2c: NkeKey,
}

/// An opaque NTS cookie (chrony `NKE_Cookie`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NkeCookie {
    /// Cookie bytes (4-aligned, ≤ [`NKE_MAX_COOKIE_LENGTH`]).
    pub bytes: Vec<u8>,
}

/// The NTS-KE cookie codec (chrony's `NKS_DecodeCookie` / `NKS_GenerateCookie`),
/// injected since it lives in the NTS-KE server and uses the server master key.
pub trait CookieCodec {
    /// Decode a cookie to its session context, or `None` if invalid/expired.
    fn decode_cookie(&mut self, cookie: &NkeCookie) -> Option<NkeContext>;
    /// Generate a fresh cookie carrying `context`, or `None` on failure.
    fn generate_cookie(&mut self, context: &NkeContext) -> Option<NkeCookie>;
}

/// The NTS-NTP server (chrony's `struct NtsServer` + module state).
pub struct NtsServer {
    sivs: [Option<SivInstance>; MAX_SERVER_SIVS],
    siv_algorithms: [SivAlgorithm; MAX_SERVER_SIVS],
    nonce: [u8; NONCE_LENGTH],
    cookies: Vec<NkeCookie>,
    num_cookies: i32,
    siv_index: i32,
    req_tx: [u8; 8],
    codec: Box<dyn CookieCodec>,
    rng: Box<dyn FnMut() -> u8>,
}

impl fmt::Debug for NtsServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtsServer")
            .field("sivs", &self.sivs)
            .field("siv_algorithms", &self.siv_algorithms)
            .field("nonce", &self.nonce)
            .field("cookies", &self.cookies)
            .field("num_cookies", &self.num_cookies)
            .field("siv_index", &self.siv_index)
            .field("req_tx", &self.req_tx)
            .field("codec", &"<CookieCodec>")
            .field("rng", &"<FnMut>")
            .finish()
    }
}

impl NtsServer {
    /// chrony `NNS_Initialise`: create the server with its SIV instances. The
    /// AES-SIV-CMAC-256 instance is required; AES-128-GCM-SIV is absent in this
    /// build (its slot is `None`), exactly as a chrony built without GCM-SIV.
    pub fn new(codec: Box<dyn CookieCodec>, rng: Box<dyn FnMut() -> u8>) -> Self {
        let siv_algorithms = [SivAlgorithm::AesSivCmac256, SivAlgorithm::Aes128GcmSiv];
        let sivs = [
            SivInstance::create(siv_algorithms[0]),
            SivInstance::create(siv_algorithms[1]),
        ];
        assert!(sivs[0].is_some(), "missing AES-SIV-CMAC-256");
        NtsServer {
            sivs,
            siv_algorithms,
            nonce: [0; NONCE_LENGTH],
            cookies: Vec::new(),
            num_cookies: 0,
            siv_index: -1,
            req_tx: [0; 8],
            codec,
            rng,
        }
    }

    fn fill_nonce(&mut self) {
        for i in 0..NONCE_LENGTH {
            self.nonce[i] = (self.rng)();
        }
    }

    /// chrony `NNS_CheckRequestAuth`: verify an NTS request. Returns `(ok, kod)`.
    pub fn check_request_auth(
        &mut self,
        packet: &NtpPacketBuf,
        info: &NtpPacketInfo,
    ) -> (bool, u32) {
        self.num_cookies = 0;
        self.siv_index = -1;
        self.req_tx.copy_from_slice(&packet.bytes()[40..48]);

        if info.ext_fields == 0 || info.mode != MODE_CLIENT {
            return (false, 0);
        }

        let mut requested_cookies = 0;
        let (mut has_uniq_id, mut has_cookie, mut has_auth) = (false, false, false);
        let mut cookie = NkeCookie { bytes: Vec::new() };
        let mut cookie_length: i32 = -1;
        let mut auth_start = 0;

        let mut parsed = NTP_HEADER_LENGTH;
        while parsed < info.length {
            let Some(pf) = parse_field(packet, info.length, parsed) else {
                // Not expected (the packet already passed parsing).
                return (false, 0);
            };
            match pf.field_type {
                NTP_EF_NTS_UNIQUE_IDENTIFIER => has_uniq_id = true,
                NTP_EF_NTS_COOKIE => {
                    if has_cookie || pf.body_length as usize > NKE_MAX_COOKIE_LENGTH {
                        return (false, 0);
                    }
                    cookie.bytes = packet.bytes()
                        [pf.body_offset..pf.body_offset + pf.body_length as usize]
                        .to_vec();
                    has_cookie = true;
                    // Fall through to the placeholder accounting.
                    requested_cookies += 1;
                    if cookie_length >= 0 && cookie_length != pf.body_length {
                        return (false, 0);
                    }
                    cookie_length = pf.body_length;
                }
                NTP_EF_NTS_COOKIE_PLACEHOLDER => {
                    requested_cookies += 1;
                    if cookie_length >= 0 && cookie_length != pf.body_length {
                        return (false, 0);
                    }
                    cookie_length = pf.body_length;
                }
                NTP_EF_NTS_AUTH_AND_EEF => {
                    if parsed + pf.length != info.length {
                        return (false, 0);
                    }
                    auth_start = parsed;
                    has_auth = true;
                }
                _ => {}
            }
            parsed += pf.length;
        }

        if !has_uniq_id || !has_cookie || !has_auth {
            return (false, 0);
        }

        let Some(context) = self.codec.decode_cookie(&cookie) else {
            return (false, NTP_KOD_NTS_NAK);
        };

        // Find the SIV instance for the cookie's algorithm.
        let mut i = 0;
        while i < MAX_SERVER_SIVS && context.algorithm != self.siv_algorithms[i] {
            i += 1;
        }
        if i == MAX_SERVER_SIVS || self.sivs[i].is_none() {
            return (false, 0);
        }
        self.siv_index = i as i32;

        if !self.sivs[i]
            .as_mut()
            .map(|s| s.set_key(&context.c2s.key))
            .unwrap_or(false)
        {
            return (false, 0);
        }

        let mut plaintext = vec![0u8; NTP_MAX_EXTENSIONS_LENGTH as usize];
        let Some(siv) = self.sivs[i].as_mut() else {
            return (false, 0);
        };
        let Some(plaintext_length) = decrypt_auth_ef(packet, info, siv, auth_start, &mut plaintext)
        else {
            return (false, NTP_KOD_NTS_NAK);
        };

        // Count cookie placeholders in the decrypted EFs.
        let mut p = 0i32;
        while p < plaintext_length as i32 {
            let Some(pf) = parse_single_field(&plaintext, plaintext_length as i32, p) else {
                return (false, 0);
            };
            if pf.field_type == NTP_EF_NTS_COOKIE_PLACEHOLDER {
                if cookie_length != pf.body_length {
                    return (false, 0);
                }
                requested_cookies += 1;
            }
            p += pf.length;
        }

        if !self.sivs[i]
            .as_mut()
            .map(|s| s.set_key(&context.s2c.key))
            .unwrap_or(false)
        {
            return (false, 0);
        }

        // Prepare the response material now (minimising work when the TX timestamp
        // is set later).
        self.fill_nonce();

        self.cookies.clear();
        let mut made = 0;
        while made < NTS_MAX_COOKIES && (made as i32) < requested_cookies {
            match self.codec.generate_cookie(&context) {
                Some(c) => self.cookies.push(c),
                None => return (false, 0),
            }
            made += 1;
        }
        self.num_cookies = made as i32;

        (true, 0)
    }

    /// chrony `NNS_GenerateResponseAuth`: build the authenticated response.
    pub fn generate_response_auth(
        &mut self,
        request: &NtpPacketBuf,
        req_info: &NtpPacketInfo,
        response: &mut NtpPacketBuf,
        res_info: &mut NtpPacketInfo,
        kod: u32,
    ) -> bool {
        if req_info.mode != MODE_CLIENT || res_info.mode != MODE_SERVER {
            return false;
        }
        // Must be the response to the request from the last check.
        assert_eq!(
            self.req_tx,
            request.bytes()[40..48],
            "response to a different request"
        );

        // Copy the unique identifier(s) from the request.
        let mut parsed = NTP_HEADER_LENGTH;
        while parsed < req_info.length {
            let Some(pf) = parse_field(request, req_info.length, parsed) else {
                return false;
            };
            if pf.field_type == NTP_EF_NTS_UNIQUE_IDENTIFIER {
                let body = request.bytes()
                    [pf.body_offset..pf.body_offset + pf.body_length as usize]
                    .to_vec();
                if !add_field(response, res_info, pf.field_type, &body) {
                    return false;
                }
            }
            parsed += pf.length;
        }

        // An NTS NAK response carries nothing else.
        if kod != 0 {
            return true;
        }

        // Build the plaintext: the fresh cookies as NTS-cookie EFs.
        let mut plaintext = vec![0u8; NTP_MAX_EXTENSIONS_LENGTH as usize];
        let mut plaintext_length = 0i32;
        for c in &self.cookies {
            match set_field(
                &mut plaintext,
                NTP_MAX_EXTENSIONS_LENGTH,
                plaintext_length,
                NTP_EF_NTS_COOKIE,
                &c.bytes,
            ) {
                Some(ef_length) => plaintext_length += ef_length,
                None => return false,
            }
        }
        self.num_cookies = 0;

        if self.siv_index < 0 {
            return false;
        }

        let nonce = self.nonce;
        let min_ef_length = req_info.length - res_info.length;
        let Some(siv) = self
            .sivs
            .get_mut(self.siv_index as usize)
            .and_then(|s| s.as_mut())
        else {
            return false;
        };
        generate_auth_ef(
            response,
            res_info,
            siv,
            &nonce,
            NONCE_LENGTH as i32,
            &plaintext[..plaintext_length as usize],
            min_ef_length,
        )
    }

    /// Number of cookies prepared by the last [`check_request_auth`](Self::check_request_auth).
    pub fn num_cookies(&self) -> i32 {
        self.num_cookies
    }
}

/// ---------------------------------------------------------------------------
/// Production cookie codec — bridges the nts_ke_cookie framing to the
/// CookieCodec trait that NtsServer expects.
/// ---------------------------------------------------------------------------
use crate::nts_ke_cookie::COOKIE_HEADER_LEN;

/// A production implementation of [`CookieCodec`] that uses real AES-SIV-CMAC
/// via [`SivInstance`] and the wire format from [`crate::nts_ke_cookie`]:
///
/// ```text
/// [key_id : 4 bytes BE][nonce : nonce_length][SIV(c2s || s2c)]
/// ```
///
/// This closes the gap between the ported cookie codec (`nts_ke_cookie`) and the
/// NTS server (`NtsServer`), completing the `KeHandshakeResult` → cookie codec →
/// NTS authenticator chain.
pub struct RealCookieCodec {
    /// Server SIV keys: (key_id, SivInstance, nonce_length).
    keys: Vec<(u32, SivInstance, usize)>,
    #[allow(dead_code)]
    _next_key_id: u32,
    rng: Box<dyn FnMut() -> u8>,
}

impl fmt::Debug for RealCookieCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealCookieCodec")
            .field("keys", &self.keys.len())
            .field("_next_key_id", &self._next_key_id)
            .finish()
    }
}

impl RealCookieCodec {
    /// Create a new codec. Generates one initial server key (AES-SIV-CMAC-256).
    /// `rng` supplies nonce bytes and key material.
    pub fn new(mut rng: Box<dyn FnMut() -> u8>) -> Self {
        let mut key_buf = [0u8; 32];
        for b in &mut key_buf {
            *b = rng();
        }
        let mut siv = SivInstance::create(SivAlgorithm::AesSivCmac256).unwrap();
        siv.set_key(&key_buf);
        RealCookieCodec {
            keys: vec![(0, siv, 16)],
            _next_key_id: 1,
            rng,
        }
    }

    fn fill_nonce(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = (self.rng)();
        }
    }

    fn encode_context(&self, context: &NkeContext) -> Vec<u8> {
        let mut plain = Vec::with_capacity(context.c2s.key.len() + context.s2c.key.len());
        plain.extend_from_slice(&context.c2s.key);
        plain.extend_from_slice(&context.s2c.key);
        plain
    }

    fn decode_context(algorithm: SivAlgorithm, plain: &[u8]) -> Option<NkeContext> {
        let half = plain.len() / 2;
        Some(NkeContext {
            algorithm,
            c2s: NkeKey {
                key: plain[..half].to_vec(),
            },
            s2c: NkeKey {
                key: plain[half..].to_vec(),
            },
        })
    }
}

impl CookieCodec for RealCookieCodec {
    fn decode_cookie(&mut self, cookie: &NkeCookie) -> Option<NkeContext> {
        let bytes = &cookie.bytes;
        if bytes.len() <= COOKIE_HEADER_LEN {
            return None;
        }
        let key_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let (_, siv, nonce_len) = self.keys.iter().find(|(id, _, _)| *id == key_id)?;
        let tag_len = siv.tag_length() as usize;
        if bytes.len() <= COOKIE_HEADER_LEN + nonce_len + tag_len {
            return None;
        }
        let nonce = &bytes[COOKIE_HEADER_LEN..COOKIE_HEADER_LEN + nonce_len];
        let ciphertext = &bytes[COOKIE_HEADER_LEN + nonce_len..];
        let plain_len = ciphertext.len() - tag_len;
        if plain_len > 64 || plain_len % 2 != 0 || plain_len < 2 {
            return None;
        }
        let mut plain = vec![0u8; plain_len];
        if !siv.decrypt(nonce, b"", ciphertext, &mut plain) {
            return None;
        }
        let algorithm = match plain_len / 2 {
            16 => SivAlgorithm::Aes128GcmSiv,
            32 => SivAlgorithm::AesSivCmac256,
            _ => return None,
        };
        Self::decode_context(algorithm, &plain)
    }

    fn generate_cookie(&mut self, context: &NkeContext) -> Option<NkeCookie> {
        let plain = self.encode_context(context);
        // Generate nonce first (needs &mut self) before borrowing keys.
        let nonce_len = self.keys.first().map(|k| k.2).unwrap_or(16);
        let mut nonce = vec![0u8; nonce_len];
        self.fill_nonce(&mut nonce);
        // Now borrow self.keys immutably (no &mut self conflict).
        let (key_id, siv, _) = self.keys.first()?;
        let tag_len = siv.tag_length() as usize;
        let mut ciphertext = vec![0u8; plain.len() + tag_len];
        if !siv.encrypt(&nonce, b"", &plain, &mut ciphertext) {
            return None;
        }
        let mut bytes = Vec::with_capacity(COOKIE_HEADER_LEN + nonce_len + ciphertext.len());
        bytes.extend_from_slice(&key_id.to_be_bytes());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        Some(NkeCookie { bytes })
    }
}

#[cfg(test)]
mod tests;
