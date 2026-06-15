//! Client-side NTS-NTP authentication — a complete port of chrony 4.5
//! `nts_ntp_client.c` (all 17 functions).
//!
//! # What this module is
//!
//! The client half of NTS-protected NTP (RFC 8915). It manages a per-server NTS
//! association: run the NTS-KE handshake to obtain the session keys, an NTP address,
//! and a pool of cookies; for each NTP request pick a cookie, add the NTS extension
//! fields (unique identifier, cookie, cookie placeholders), and append an
//! authenticator under the client-to-server key; on the response, verify the
//! authenticator and unique identifier under the server-to-client key and extract
//! the fresh cookies. It also rate-limits/backs-off NTS-KE attempts and can
//! persist/restore keys+cookies across restarts.
//!
//! # Adaptations (documented, not silent)
//!
//! * **Composes the ported stack.** Extension fields are [`crate::ntp::ext`]; the
//!   authenticator EF is [`crate::nts_ntp_auth`]; the AEAD is a real
//!   [`crate::siv_nettle::SivInstance`]; the NTS types are shared with
//!   [`crate::nts_ntp_server`].
//! * **Boundaries injected.** The NTS-KE TLS handshake (`NKC_*`) is the [`NkeClient`]
//!   trait; the source-address update (`NSR_*`), the monotonic clock
//!   (`SCH_GetLastEventMonoTime`), randomness (`UTI_GetRandomBytes`), the cookie-dump
//!   file I/O (`save_cookies`/`load_cookies`), and the refresh config are injected as
//!   closures. This keeps the brain free of TLS/sockets/host clock while reproducing
//!   chrony's exact request/response bytes and cookie-pool bookkeeping.
//!
//! # Oracle
//!
//! The deterministic auth cycle is differential-tested against the **real compiled
//! `nts_ntp_client.c`** (+ `nts_ntp_auth.c`, `ntp_ext.c`, `siv_nettle.c`/
//! `siv_nettle_int.c` over the FIPS-197 shim AES): with the NTS-KE result injected, a
//! C generator records `PrepareForAuth` → `GenerateRequestAuth` (request bytes) → a
//! crafted valid response → `CheckResponseAuth` → `GetReport`
//! (`research/oracle/nts_ntp_client-c-vectors.txt`). The port replays the identical
//! flow (same injected NKE / clock / LCG / real SIV) and matches the request bytes,
//! the check result, and the report. Cookie save/load is covered by an independent
//! round-trip test. See the tests.

use crate::nts_ntp_auth::{decrypt_auth_ef, generate_auth_ef, NTP_EF_NTS_AUTH_AND_EEF};
use crate::nts_ntp_server::{
    NkeContext, NkeCookie, NTP_EF_NTS_COOKIE, NTP_EF_NTS_COOKIE_PLACEHOLDER,
    NTP_EF_NTS_UNIQUE_IDENTIFIER, NTP_KOD_NTS_NAK, NTS_MAX_COOKIES,
};
use crate::ntp::ext::{
    add_blank_field, add_field, parse_field, parse_single_field, NtpPacketBuf, NtpPacketInfo,
    NTP_HEADER_LENGTH, NTP_MAX_EXTENSIONS_LENGTH, NTP_MAX_V4_MAC_LENGTH, NTP_MIN_EF_LENGTH,
};
use crate::siv_nettle::{get_key_length, SivAlgorithm, SivInstance};
use crate::util;

/// chrony `MODE_CLIENT`.
pub const MODE_CLIENT: i32 = 3;
/// chrony `MODE_SERVER`.
pub const MODE_SERVER: i32 = 4;
/// chrony `NTS_MIN_UNIQ_ID_LENGTH`.
pub const NTS_MIN_UNIQ_ID_LENGTH: usize = 32;
/// chrony `NTS_MIN_UNPADDED_NONCE_LENGTH`.
pub const NONCE_LENGTH: usize = 16;
/// chrony `MAX_TOTAL_COOKIE_LENGTH`.
const MAX_TOTAL_COOKIE_LENGTH: i32 = 8 * 108;
/// chrony `RETRY_INTERVAL_KE_START`.
const RETRY_INTERVAL_KE_START: f64 = 2.0;
/// chrony `NKE_MAX_RETRY_INTERVAL2`.
const NKE_MAX_RETRY_INTERVAL2: i32 = 19;
/// chrony `NTP_INVALID_STRATUM`.
const NTP_INVALID_STRATUM: u8 = 0;
/// chrony `DUMP_IDENTIFIER`.
const DUMP_IDENTIFIER: &str = "NNC0";

/// The injected source-address update (chrony `NSR_UpdateSourceNtpAddress`):
/// `(old, new) -> success`.
pub type UpdateSourceFn = Box<dyn FnMut(&NtpAddress, &NtpAddress) -> bool>;

/// An NTP server address (chrony `NTP_Remote_Address` / `IPSockAddr`, minimal).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NtpAddress {
    /// `None` is `IPADDR_UNSPEC`.
    pub ip: Option<u32>,
    /// UDP port (0 = unset).
    pub port: u16,
}

/// The result of a successful NTS-KE handshake (chrony's `NKC_GetNtsData` outputs).
pub struct NkeData {
    /// Negotiated session context (algorithm + C2S/S2C keys).
    pub context: NkeContext,
    /// Initial cookie pool.
    pub cookies: Vec<NkeCookie>,
    /// Negotiated NTP server address.
    pub ntp_address: NtpAddress,
}

/// The NTS-KE handshake client (chrony's `NKC_*`), injected since it is TLS.
pub trait NkeClient {
    /// `NKC_CreateInstance` + start a session for `address`/`name`/`cert_set`.
    fn create(&mut self, address: &NtpAddress, name: &str, cert_set: u32);
    /// `NKC_Start`: begin the handshake. Returns whether it started.
    fn start(&mut self) -> bool;
    /// `NKC_IsActive`: whether the handshake is still running.
    fn is_active(&mut self) -> bool;
    /// `NKC_GetNtsData`: the result once the session stopped (None on failure).
    fn get_nts_data(&mut self, max_cookies: usize) -> Option<NkeData>;
    /// `NKC_GetRetryFactor`.
    fn get_retry_factor(&mut self) -> i32;
    /// `NKC_DestroyInstance`.
    fn destroy(&mut self);
}

/// chrony's `RPT_AuthReport` (the fields this module fills).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct AuthReport {
    /// Context (key) id.
    pub key_id: u32,
    /// Algorithm enum value.
    pub key_type: i32,
    /// Key length in bits.
    pub key_length: i32,
    /// NTS-KE attempts since the last success.
    pub ke_attempts: i32,
    /// Seconds since the last NTS-KE success (`-1` if never).
    pub last_ke_ago: f64,
    /// Cookies currently held.
    pub cookies: i32,
    /// Length of the next cookie (0 if none).
    pub cookie_length: i32,
    /// Whether the last response was an NTS NAK.
    pub nak: bool,
}

/// The NTS-NTP client association (chrony's `NNC_Instance_Record` + module state).
pub struct NtsClient {
    nts_address: NtpAddress,
    name: String,
    cert_set: u32,
    default_ntp_port: u16,
    ntp_address: NtpAddress,

    has_nke: bool,
    siv: Option<SivInstance>,

    nke_attempts: i32,
    next_nke_attempt: f64,
    last_nke_success: f64,

    context: NkeContext,
    context_id: u32,
    cookies: Vec<NkeCookie>, // ring buffer of NTS_MAX_COOKIES slots
    num_cookies: i32,
    cookie_index: i32,
    auth_ready: bool,
    nak_response: bool,
    ok_response: bool,
    nonce: [u8; NONCE_LENGTH],
    uniq_id: [u8; NTS_MIN_UNIQ_ID_LENGTH],

    // Injected host boundaries.
    nke: Box<dyn NkeClient>,
    mono_time: Box<dyn FnMut() -> f64>,
    rng: Box<dyn FnMut() -> u8>,
    nts_refresh: f64,
    update_source: UpdateSourceFn,
}

fn empty_context() -> NkeContext {
    use crate::nts_ntp_server::NkeKey;
    NkeContext {
        algorithm: SivAlgorithm::AesSivCmac256,
        c2s: NkeKey { key: Vec::new() },
        s2c: NkeKey { key: Vec::new() },
    }
}

impl NtsClient {
    /// chrony `NNC_CreateInstance`. `dump` is the persisted cookie file contents (if
    /// any) to reload; the daemon supplies it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nts_address: NtpAddress,
        name: &str,
        cert_set: u32,
        ntp_port: u16,
        nke: Box<dyn NkeClient>,
        mono_time: Box<dyn FnMut() -> f64>,
        rng: Box<dyn FnMut() -> u8>,
        nts_refresh: f64,
        update_source: UpdateSourceFn,
        dump: Option<&str>,
    ) -> Self {
        let mut inst = NtsClient {
            nts_address,
            name: name.to_string(),
            cert_set,
            default_ntp_port: ntp_port,
            ntp_address: NtpAddress { ip: nts_address.ip, port: ntp_port },
            has_nke: false,
            siv: None,
            nke_attempts: 0,
            next_nke_attempt: 0.0,
            last_nke_success: 0.0,
            context: empty_context(),
            context_id: 0,
            cookies: (0..NTS_MAX_COOKIES).map(|_| NkeCookie { bytes: Vec::new() }).collect(),
            num_cookies: 0,
            cookie_index: 0,
            auth_ready: false,
            nak_response: false,
            ok_response: true,
            nonce: [0; NONCE_LENGTH],
            uniq_id: [0; NTS_MIN_UNIQ_ID_LENGTH],
            nke,
            mono_time,
            rng,
            nts_refresh,
            update_source,
        };
        inst.reset_instance();
        inst.load_cookies(dump);
        inst
    }

    /// chrony `reset_instance`.
    fn reset_instance(&mut self) {
        if self.has_nke {
            self.nke.destroy();
            self.has_nke = false;
        }
        self.siv = None;
        self.nke_attempts = 0;
        self.next_nke_attempt = 0.0;
        self.last_nke_success = 0.0;
        self.context = empty_context();
        self.context_id = 0;
        for c in &mut self.cookies {
            c.bytes.clear();
        }
        self.num_cookies = 0;
        self.cookie_index = 0;
        self.auth_ready = false;
        self.nak_response = false;
        self.ok_response = true;
        self.nonce = [0; NONCE_LENGTH];
        self.uniq_id = [0; NTS_MIN_UNIQ_ID_LENGTH];
    }

    fn mono(&mut self) -> f64 {
        (self.mono_time)()
    }

    /// chrony `check_cookies`: drop the pool if a NAK without a valid response was
    /// seen or the keys need refreshing. Returns whether usable cookies remain.
    fn check_cookies(&mut self) -> bool {
        let now = self.mono();
        if self.num_cookies > 0
            && ((self.nak_response && !self.ok_response)
                || now - self.last_nke_success > self.nts_refresh)
        {
            self.num_cookies = 0;
        }
        self.num_cookies > 0
    }

    /// chrony `set_ntp_address`: adopt the negotiated NTP address (filling defaults),
    /// updating the source if it changed.
    fn set_ntp_address(&mut self, negotiated: &NtpAddress) -> bool {
        let old = self.ntp_address;
        let mut new = *negotiated;
        if new.ip.is_none() {
            new.ip = self.nts_address.ip;
        }
        if new.port == 0 {
            new.port = self.default_ntp_port;
        }
        if old.ip == new.ip && old.port == new.port {
            return true;
        }
        if !(self.update_source)(&old, &new) {
            return false;
        }
        self.ntp_address = new;
        true
    }

    /// chrony `update_next_nke_attempt`: schedule the next NTS-KE attempt (backoff).
    fn update_next_nke_attempt(&mut self, failed_start: bool, now: f64) {
        if failed_start {
            self.next_nke_attempt = now + RETRY_INTERVAL_KE_START;
            return;
        }
        if !self.has_nke {
            return;
        }
        let factor = self.nke.get_retry_factor();
        let interval = (factor + self.nke_attempts - 1).min(NKE_MAX_RETRY_INTERVAL2);
        self.next_nke_attempt = now + util::log2_to_double(interval);
    }

    /// chrony `get_cookies`: run/poll the NTS-KE handshake to obtain a fresh pool.
    fn get_cookies(&mut self) -> bool {
        debug_assert_eq!(self.num_cookies, 0);
        let now = self.mono();

        let mut failed_start = false;
        if !self.has_nke {
            if now < self.next_nke_attempt {
                return false;
            }
            self.nke.create(&self.nts_address, &self.name, self.cert_set);
            self.has_nke = true;
            self.nke_attempts += 1;
            if !self.nke.start() {
                failed_start = true;
            }
        }

        self.update_next_nke_attempt(failed_start, now);

        if self.nke.is_active() {
            return false;
        }

        let data = self.nke.get_nts_data(NTS_MAX_COOKIES);
        self.nke.destroy();
        self.has_nke = false;

        let Some(data) = data else {
            return false;
        };

        self.siv = None;
        self.context_id += 1;

        if !self.set_ntp_address(&data.ntp_address) {
            self.num_cookies = 0;
            return false;
        }

        self.context = data.context;
        let n = data.cookies.len().min(NTS_MAX_COOKIES);
        for (i, c) in data.cookies.into_iter().take(n).enumerate() {
            self.cookies[i] = c;
        }
        self.num_cookies = n as i32;

        self.last_nke_success = now;
        self.cookie_index = 0;
        true
    }

    /// chrony `NNC_PrepareForAuth`: prepare per-request data and the SIV.
    pub fn prepare_for_auth(&mut self) -> bool {
        self.auth_ready = false;

        for b in self.uniq_id.iter_mut() {
            *b = (self.rng)();
        }
        for b in self.nonce.iter_mut() {
            *b = (self.rng)();
        }

        if !self.check_cookies() && !self.get_cookies() {
            return false;
        }

        self.nak_response = false;

        if self.siv.is_none() {
            self.siv = SivInstance::create(self.context.algorithm);
        }
        let ok = match self.siv.as_mut() {
            Some(siv) => siv.set_key(&self.context.c2s.key),
            None => false,
        };
        if !ok {
            return false;
        }

        self.auth_ready = true;
        true
    }

    /// chrony `NNC_GenerateRequestAuth`: add the NTS request EFs + authenticator.
    pub fn generate_request_auth(
        &mut self,
        packet: &mut NtpPacketBuf,
        info: &mut NtpPacketInfo,
    ) -> bool {
        if !self.auth_ready {
            return false;
        }
        self.auth_ready = false;

        if self.num_cookies <= 0 || self.siv.is_none() || info.mode != MODE_CLIENT {
            return false;
        }

        let cookie = self.cookies[self.cookie_index as usize].clone();
        self.num_cookies -= 1;
        self.cookie_index = (self.cookie_index + 1) % NTS_MAX_COOKIES as i32;

        let req_cookies = (NTS_MAX_COOKIES as i32 - self.num_cookies)
            .min(MAX_TOTAL_COOKIE_LENGTH / (cookie.bytes.len() as i32 + 4));

        if !add_field(packet, info, NTP_EF_NTS_UNIQUE_IDENTIFIER, &self.uniq_id) {
            return false;
        }
        if !add_field(packet, info, NTP_EF_NTS_COOKIE, &cookie.bytes) {
            return false;
        }
        for _ in 0..req_cookies - 1 {
            match add_blank_field(packet, info, NTP_EF_NTS_COOKIE_PLACEHOLDER, cookie.bytes.len() as i32) {
                Some(off) => {
                    for b in &mut packet.bytes_mut()[off..off + cookie.bytes.len()] {
                        *b = 0;
                    }
                }
                None => return false,
            }
        }

        let nonce = self.nonce;
        let siv = self.siv.as_mut().unwrap();
        if !generate_auth_ef(packet, info, siv, &nonce, NONCE_LENGTH as i32, &[], NTP_MAX_V4_MAC_LENGTH + 4)
        {
            return false;
        }

        self.ok_response = false;
        true
    }

    /// chrony `parse_encrypted_efs`: validate the decrypted EFs parse cleanly.
    fn parse_encrypted_efs(plaintext: &[u8], length: i32) -> bool {
        let mut parsed = 0i32;
        while parsed < length {
            match parse_single_field(plaintext, length, parsed) {
                Some(pf) => parsed += pf.length,
                None => return false,
            }
        }
        true
    }

    /// chrony `extract_cookies`: store the cookies from the decrypted EFs.
    fn extract_cookies(&mut self, plaintext: &[u8], length: i32) -> bool {
        let mut acceptable = 0;
        let mut parsed = 0i32;
        while parsed < length {
            let Some(pf) = parse_single_field(plaintext, length, parsed) else {
                return false;
            };
            parsed += pf.length;
            if pf.field_type != NTP_EF_NTS_COOKIE {
                continue;
            }
            if pf.length < NTP_MIN_EF_LENGTH
                || pf.body_length as usize > crate::nts_ntp_server::NKE_MAX_COOKIE_LENGTH
            {
                continue;
            }
            acceptable += 1;
            if self.num_cookies >= NTS_MAX_COOKIES as i32 {
                continue;
            }
            let index = ((self.cookie_index + self.num_cookies) % NTS_MAX_COOKIES as i32) as usize;
            self.cookies[index] = NkeCookie {
                bytes: plaintext[pf.body_offset..pf.body_offset + pf.body_length as usize].to_vec(),
            };
            self.num_cookies += 1;
        }
        acceptable > 0
    }

    /// chrony `NNC_CheckResponseAuth`: verify + process an NTS response.
    pub fn check_response_auth(
        &mut self,
        packet: &NtpPacketBuf,
        info: &NtpPacketInfo,
    ) -> bool {
        if info.ext_fields == 0 || info.mode != MODE_SERVER {
            return false;
        }
        // At most one response per request.
        if self.ok_response || self.auth_ready {
            return false;
        }

        let key_ok = match self.siv.as_mut() {
            Some(siv) => siv.set_key(&self.context.s2c.key),
            None => false,
        };
        if !key_ok {
            return false;
        }

        let mut has_valid_uniq_id = false;
        let mut has_valid_auth = false;
        let mut plaintext = vec![0u8; NTP_MAX_EXTENSIONS_LENGTH as usize];
        let mut plaintext_length = 0usize;

        let mut parsed = NTP_HEADER_LENGTH;
        while parsed < info.length {
            let Some(pf) = parse_field(packet, info.length, parsed) else {
                return false;
            };
            match pf.field_type {
                NTP_EF_NTS_UNIQUE_IDENTIFIER => {
                    if pf.body_length as usize != self.uniq_id.len()
                        || packet.bytes()[pf.body_offset..pf.body_offset + pf.body_length as usize]
                            != self.uniq_id
                    {
                        return false;
                    }
                    has_valid_uniq_id = true;
                }
                NTP_EF_NTS_COOKIE => { /* unencrypted cookie: ignore */ }
                NTP_EF_NTS_AUTH_AND_EEF => {
                    if parsed + pf.length != info.length {
                        return false;
                    }
                    let siv = self.siv.as_mut().unwrap();
                    match decrypt_auth_ef(packet, info, siv, parsed, &mut plaintext) {
                        Some(n) => plaintext_length = n,
                        None => return false,
                    }
                    if !Self::parse_encrypted_efs(&plaintext, plaintext_length as i32) {
                        return false;
                    }
                    has_valid_auth = true;
                }
                _ => {}
            }
            parsed += pf.length;
        }

        if !has_valid_uniq_id || !has_valid_auth {
            if has_valid_uniq_id
                && packet.bytes()[1] == NTP_INVALID_STRATUM
                && u32::from_be_bytes(packet.bytes()[12..16].try_into().unwrap()) == NTP_KOD_NTS_NAK
            {
                self.nak_response = true;
                return false;
            }
            return false;
        }

        if !self.extract_cookies(&plaintext, plaintext_length as i32) {
            return false;
        }

        self.ok_response = true;
        self.nke_attempts = 0;
        self.next_nke_attempt = 0.0;
        true
    }

    /// chrony `NNC_ChangeAddress`.
    pub fn change_address(&mut self, address: Option<u32>, dump: Option<&str>) -> Option<String> {
        let saved = self.save_cookies();
        self.nts_address.ip = address;
        self.ntp_address.ip = address;
        self.reset_instance();
        self.load_cookies(dump);
        saved
    }

    /// chrony `save_cookies`: serialise keys+cookies to the dump format (returns the
    /// file contents, or `None` if there is nothing/no real address to save).
    pub fn save_cookies(&self) -> Option<String> {
        if self.num_cookies < 1 || self.nts_address.ip.is_none() {
            return None;
        }
        let mut out = String::new();
        out.push_str(DUMP_IDENTIFIER);
        out.push('\n');
        out.push_str(&self.name);
        out.push('\n');
        // context_time is a real-clock value in chrony; modeled as 0.0 here (the
        // daemon supplies the clock). Format kept identical otherwise.
        out.push_str("0.0\n");
        out.push_str(&format!(
            "{} {}\n",
            ip_to_string(self.ntp_address.ip),
            self.ntp_address.port
        ));
        out.push_str(&format!("{} {} ", self.context_id, self.context.algorithm as i32));
        out.push_str(&util::bytes_to_hex(&self.context.s2c.key).to_lowercase());
        out.push(' ');
        out.push_str(&util::bytes_to_hex(&self.context.c2s.key).to_lowercase());
        out.push('\n');
        for i in 0..self.num_cookies as usize {
            let idx = (self.cookie_index as usize + i) % NTS_MAX_COOKIES;
            out.push_str(&util::bytes_to_hex(&self.cookies[idx].bytes).to_lowercase());
            out.push('\n');
        }
        Some(out)
    }

    /// chrony `load_cookies`: restore keys+cookies from the dump format.
    fn load_cookies(&mut self, dump: Option<&str>) {
        let Some(text) = dump else {
            return;
        };
        self.siv = None;
        if self.load_cookies_inner(text).is_none() {
            self.context = empty_context();
            self.num_cookies = 0;
        }
    }

    fn load_cookies_inner(&mut self, text: &str) -> Option<()> {
        let mut lines = text.lines();
        if lines.next()? != DUMP_IDENTIFIER {
            return None;
        }
        if lines.next()? != self.name {
            return None;
        }
        let _context_time: f64 = lines.next()?.trim().parse().ok()?;
        let addr_line = lines.next()?;
        let mut aw = addr_line.split_whitespace();
        let ip = string_to_ip(aw.next()?)?;
        let port: u16 = aw.next()?.parse().ok()?;
        let ctx_line = lines.next()?;
        let mut cw = ctx_line.split_whitespace();
        let context_id: u32 = cw.next()?.parse().ok()?;
        let algorithm: i32 = cw.next()?.parse().ok()?;
        let s2c = util::hex_to_bytes(cw.next()?)?;
        let c2s = util::hex_to_bytes(cw.next()?)?;

        let alg = algorithm_from_i32(algorithm)?;
        if s2c.len() as i32 != get_key_length(alg) || s2c.is_empty() || c2s.len() != s2c.len() {
            return None;
        }
        use crate::nts_ntp_server::NkeKey;
        self.context = NkeContext {
            algorithm: alg,
            c2s: NkeKey { key: c2s },
            s2c: NkeKey { key: s2c },
        };

        let mut i = 0;
        for line in lines {
            if i >= NTS_MAX_COOKIES {
                break;
            }
            let w = line.split_whitespace().next()?;
            let bytes = util::hex_to_bytes(w)?;
            if bytes.is_empty() {
                return None;
            }
            self.cookies[i] = NkeCookie { bytes };
            i += 1;
        }
        self.num_cookies = i as i32;

        let ntp_addr = NtpAddress { ip: Some(ip), port };
        if !self.set_ntp_address(&ntp_addr) {
            return None;
        }
        self.context_id = context_id;
        Some(())
    }

    /// chrony `NNC_DumpData`.
    pub fn dump_data(&self) -> Option<String> {
        self.save_cookies()
    }

    /// chrony `NNC_GetReport`.
    pub fn get_report(&mut self) -> AuthReport {
        let key_length = 8 * self.context.s2c.key.len() as i32;
        let last_ke_ago = if key_length > 0 {
            self.mono() - self.last_nke_success
        } else {
            -1.0
        };
        AuthReport {
            key_id: self.context_id,
            key_type: self.context.algorithm as i32,
            key_length,
            ke_attempts: self.nke_attempts,
            last_ke_ago,
            cookies: self.num_cookies,
            cookie_length: if self.num_cookies > 0 {
                self.cookies[self.cookie_index as usize].bytes.len() as i32
            } else {
                0
            },
            nak: self.nak_response,
        }
    }
}

fn algorithm_from_i32(v: i32) -> Option<SivAlgorithm> {
    match v {
        15 => Some(SivAlgorithm::AesSivCmac256),
        16 => Some(SivAlgorithm::AesSivCmac384),
        17 => Some(SivAlgorithm::AesSivCmac512),
        30 => Some(SivAlgorithm::Aes128GcmSiv),
        31 => Some(SivAlgorithm::Aes256GcmSiv),
        _ => None,
    }
}

/// Minimal IPv4 dotted-quad rendering for the dump format.
fn ip_to_string(ip: Option<u32>) -> String {
    match ip {
        None => "[UNSPEC]".to_string(),
        Some(v) => {
            let b = v.to_be_bytes();
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }
    }
}

/// Minimal IPv4 dotted-quad parse for the dump format.
fn string_to_ip(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut v = 0u32;
    for p in parts {
        let octet: u8 = p.parse().ok()?;
        v = (v << 8) | octet as u32;
    }
    Some(v)
}

#[cfg(test)]
mod tests;
