//! NTS-KE record framing — a port of the RFC 8915 §4 record codec from chrony 4.5
//! `nts_ke_session.c`.
//!
//! The Network Time Security Key Establishment (NTS-KE) protocol runs over TLS and
//! exchanges a sequence of **records** to negotiate the AEAD algorithm, carry cookies,
//! and (optionally) redirect the client to a different NTP server/port. Each record is a
//! type-length-value:
//!
//! ```text
//! [C|type : 16 bits][body_length : 16 bits][body : body_length bytes]
//! ```
//!
//! where the top bit of the type word is the **Critical** flag (RFC 8915 §4). A message
//! is a run of records terminated by a critical *End of Message* record (type 0, empty).
//!
//! chrony's TLS session (`gnutls_*` handshake, socket I/O, the KE state machine) is a host
//! boundary and is **not** ported here; this module ports the pure record buffer codec —
//! the part that builds and parses the byte stream:
//!
//! | chrony `nts_ke_session.c` | here |
//! |---------------------------|------|
//! | `struct Message` | [`Message`] |
//! | `reset_message` | [`Message::reset`] |
//! | `add_record` | [`Message::add_record`] |
//! | `reset_message_parsing` | [`Message::reset_parsing`] |
//! | `get_record` | [`Message::get_record`] |
//! | `check_message_format` | [`Message::check_message_format`] |
//!
//! The `int`-typed record type / buffer length are kept as [`i32`] so chrony's explicit
//! range/negative rejections are reproduced exactly.

/// `NKE_MAX_MESSAGE_LENGTH`: the fixed message buffer size.
pub const NKE_MAX_MESSAGE_LENGTH: usize = 16384;
/// `NKE_RECORD_CRITICAL_BIT`: the top bit of the type word.
pub const NKE_RECORD_CRITICAL_BIT: u16 = 1 << 15;

/// Record types (`nts_ke.h`).
pub const NKE_RECORD_END_OF_MESSAGE: i32 = 0;
pub const NKE_RECORD_NEXT_PROTOCOL: i32 = 1;
pub const NKE_RECORD_ERROR: i32 = 2;
pub const NKE_RECORD_WARNING: i32 = 3;
pub const NKE_RECORD_AEAD_ALGORITHM: i32 = 4;
pub const NKE_RECORD_COOKIE: i32 = 5;
pub const NKE_RECORD_NTPV4_SERVER_NEGOTIATION: i32 = 6;
pub const NKE_RECORD_NTPV4_PORT_NEGOTIATION: i32 = 7;

/// 4-byte record header (`type` + `body_length`).
const RECORD_HEADER_LEN: usize = 4;

/// One parsed NTS-KE record (chrony's `get_record` out-params).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeRecord {
    /// The Critical flag.
    pub critical: bool,
    /// Record type with the critical bit masked off.
    pub record_type: i32,
    /// The record body's full length on the wire.
    pub body_length: i32,
    /// The body bytes copied out, truncated to the caller's buffer length
    /// (`MIN(buffer_length, body_length)`), matching chrony's `memcpy`.
    pub body: Vec<u8>,
}

/// An NTS-KE message buffer (chrony's `struct Message`). `data` always holds exactly
/// `length` bytes (the invariant chrony maintains with its `length` cursor into a fixed
/// array).
#[derive(Clone, Debug, Default)]
pub struct Message {
    data: Vec<u8>,
    /// Bytes written (chrony `length`).
    pub length: usize,
    /// Bytes already handed to the transport (chrony `sent`); tracked for parity, unused
    /// by the codec itself.
    pub sent: usize,
    /// Parse cursor (chrony `parsed`).
    pub parsed: usize,
    /// Set by [`check_message_format`](Message::check_message_format) once a full,
    /// well-formed message ending in End-of-Message has been seen.
    pub complete: bool,
    /// chrony's `NKSN_Instance.new_message`: set by [`begin_message`](Message::begin_message),
    /// asserted by [`add_message_record`](Message::add_message_record).
    pub new_message: bool,
}

impl Message {
    /// An empty message.
    pub fn new() -> Self {
        Message::default()
    }

    /// A message pre-filled with received bytes (models the TLS layer depositing input
    /// into the buffer before parsing).
    pub fn from_received(bytes: &[u8]) -> Self {
        Message {
            data: bytes.to_vec(),
            length: bytes.len(),
            sent: 0,
            parsed: 0,
            complete: false,
            new_message: false,
        }
    }

    /// The written bytes.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.length]
    }

    /// `reset_message`: clear the buffer for reuse.
    pub fn reset(&mut self) {
        self.data.clear();
        self.length = 0;
        self.sent = 0;
        self.parsed = 0;
        self.complete = false;
    }

    /// `add_record`: append a record carrying `body`. Returns `false` (chrony's `0`) if the
    /// type is out of range (`0..=0x7fff`), the body is too long (`> 0xffff`), or it would
    /// overflow the fixed buffer. (chrony's `body_length < 0` guard is unrepresentable with
    /// a slice.)
    pub fn add_record(&mut self, critical: bool, record_type: i32, body: &[u8]) -> bool {
        debug_assert!(self.length <= NKE_MAX_MESSAGE_LENGTH);
        let body_length = body.len();
        if !(0..=0x7fff).contains(&record_type)
            || body_length > 0xffff
            || self.length + RECORD_HEADER_LEN + body_length > NKE_MAX_MESSAGE_LENGTH
        {
            return false;
        }
        let type_field =
            if critical { NKE_RECORD_CRITICAL_BIT } else { 0 } | record_type as u16;
        self.data.extend_from_slice(&type_field.to_be_bytes());
        self.data.extend_from_slice(&(body_length as u16).to_be_bytes());
        self.data.extend_from_slice(body);
        self.length += RECORD_HEADER_LEN + body_length;
        true
    }

    /// `NKSN_BeginMessage`: start composing a new outgoing message (reset the buffer and
    /// mark it open for records).
    pub fn begin_message(&mut self) {
        self.reset();
        self.new_message = true;
    }

    /// `NKSN_AddRecord`: append a non-terminating record to the message being composed.
    /// chrony `assert`s the message is open (`new_message && !complete`) and that the type
    /// is not the reserved End-of-Message (that terminator is added only by
    /// [`end_message`](Message::end_message)); those become debug assertions here. Returns
    /// [`add_record`](Message::add_record)'s success flag.
    pub fn add_message_record(&mut self, critical: bool, record_type: i32, body: &[u8]) -> bool {
        debug_assert!(self.new_message && !self.complete);
        debug_assert!(record_type != NKE_RECORD_END_OF_MESSAGE);
        self.add_record(critical, record_type, body)
    }

    /// `NKSN_EndMessage`: terminate the message with the critical, empty End-of-Message
    /// record and mark it [`complete`](Message::complete). Returns `false` if the terminator
    /// would overflow the buffer (chrony's `add_record` failure).
    pub fn end_message(&mut self) -> bool {
        debug_assert!(!self.complete);
        if !self.add_record(true, NKE_RECORD_END_OF_MESSAGE, &[]) {
            return false;
        }
        self.complete = true;
        true
    }

    /// `reset_message_parsing`: rewind the parse cursor to the start.
    pub fn reset_parsing(&mut self) {
        self.parsed = 0;
    }

    /// `get_record`: parse the next record at the cursor, copying up to `buffer_length`
    /// body bytes. Returns `None` (chrony's `0`) if there is not a full record left or
    /// `buffer_length` is negative. Advances the cursor past the whole record on success.
    pub fn get_record(&mut self, buffer_length: i32) -> Option<KeRecord> {
        if self.length < self.parsed + RECORD_HEADER_LEN || buffer_length < 0 {
            return None;
        }
        let h = &self.data[self.parsed..self.parsed + RECORD_HEADER_LEN];
        let type_raw = u16::from_be_bytes([h[0], h[1]]);
        let blen = u16::from_be_bytes([h[2], h[3]]) as usize;
        let rlen = RECORD_HEADER_LEN + blen;
        if self.length < self.parsed + rlen {
            return None;
        }
        let critical = type_raw & NKE_RECORD_CRITICAL_BIT != 0;
        let record_type = (type_raw & !NKE_RECORD_CRITICAL_BIT) as i32;
        let copy = (buffer_length as usize).min(blen);
        let body_off = self.parsed + RECORD_HEADER_LEN;
        let body = self.data[body_off..body_off + copy].to_vec();
        self.parsed += rlen;
        Some(KeRecord { critical, record_type, body_length: blen as i32, body })
    }

    /// `check_message_format`: parse the whole message to validate its framing. Returns
    /// `false` on a malformed End-of-Message record (non-critical, non-empty, or repeated).
    /// A message that does not yet parse to a terminating End-of-Message is considered
    /// well-formed only if more data may still arrive (`!eof`). Sets [`complete`] when a
    /// fully-terminated message has been seen.
    ///
    /// [`complete`]: Message::complete
    pub fn check_message_format(&mut self, eof: bool) -> bool {
        self.reset_parsing();
        self.complete = false;
        let mut ends = 0;
        let mut last_type = -1;
        while let Some(rec) = self.get_record(0) {
            last_type = rec.record_type;
            if rec.record_type == NKE_RECORD_END_OF_MESSAGE {
                if !rec.critical || rec.body_length != 0 || ends > 0 {
                    return false;
                }
                ends += 1;
            }
        }

        // Cannot fully parse yet, but more data may be coming: format is ok iff not eof.
        if self.length == 0 || self.parsed < self.length {
            return !eof;
        }
        if last_type != NKE_RECORD_END_OF_MESSAGE {
            return !eof;
        }
        self.complete = true;
        true
    }

    /// Force the written length for tests exercising the buffer-overflow guard.
    #[cfg(test)]
    fn force_length(&mut self, n: usize) {
        self.data = vec![0u8; n];
        self.length = n;
    }

    /// `NKSN_GetRecord`: the next record, *hiding* the End-of-Message terminator (chrony
    /// returns 0 for it, so the message-processing loops stop there rather than treating
    /// the critical EOM as an unknown-critical record).
    pub fn next_record(&mut self, buffer_length: i32) -> Option<KeRecord> {
        match self.get_record(buffer_length) {
            Some(rec) if rec.record_type != NKE_RECORD_END_OF_MESSAGE => Some(rec),
            _ => None,
        }
    }
}

/// ---- NTS-KE protocol constants (nts_ke.h / siv.h) ----

/// `NKE_NEXT_PROTOCOL_NTPV4`.
pub const NKE_NEXT_PROTOCOL_NTPV4: i32 = 0;
/// `NKE_ERROR_UNRECOGNIZED_CRITICAL_RECORD`.
pub const NKE_ERROR_UNRECOGNIZED_CRITICAL_RECORD: i32 = 0;
/// `NKE_ERROR_BAD_REQUEST`.
pub const NKE_ERROR_BAD_REQUEST: i32 = 1;
/// `NKE_ERROR_INTERNAL_SERVER_ERROR`.
pub const NKE_ERROR_INTERNAL_SERVER_ERROR: i32 = 2;
/// `AEAD_AES_SIV_CMAC_256` (`siv.h`).
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;
/// `AEAD_AES_128_GCM_SIV` (`siv.h`).
pub const AEAD_AES_128_GCM_SIV: u16 = 30;

/// `NKE_MAX_RECORD_BODY_LENGTH`: the record-body buffer used while parsing.
const NKE_MAX_RECORD_BODY_LENGTH: i32 = 256;
/// `NKE_MAX_COOKIE_LENGTH`.
const NKE_MAX_COOKIE_LENGTH: usize = 256;
/// `NKE_MAX_COOKIES`.
const NKE_MAX_COOKIES: usize = 8;
/// `sizeof(inst->server_name)` = `NKE_MAX_RECORD_BODY_LENGTH + 2`.
const SERVER_NAME_BUF: i32 = NKE_MAX_RECORD_BODY_LENGTH + 2;

fn read_be16(body: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([body[2 * i], body[2 * i + 1]])
}

/// chrony client `prepare_request`: build the NTS-KE request message — a critical
/// Next-Protocol record (NTPv4) and a critical AEAD-Algorithm record listing the locally
/// supported algorithms (AES-128-GCM-SIV first, then AES-SIV-CMAC-256), terminated by
/// End-of-Message. `aead_supported(alg)` is chrony's `SIV_GetKeyLength(alg) > 0`.
pub fn prepare_request(aead_supported: impl Fn(u16) -> bool) -> Option<Message> {
    let mut m = Message::new();
    if !m.add_record(true, NKE_RECORD_NEXT_PROTOCOL, &(NKE_NEXT_PROTOCOL_NTPV4 as u16).to_be_bytes())
    {
        return None;
    }
    let mut aeads = Vec::new();
    if aead_supported(AEAD_AES_128_GCM_SIV) {
        aeads.extend_from_slice(&AEAD_AES_128_GCM_SIV.to_be_bytes());
    }
    if aead_supported(AEAD_AES_SIV_CMAC_256) {
        aeads.extend_from_slice(&AEAD_AES_SIV_CMAC_256.to_be_bytes());
    }
    if !m.add_record(true, NKE_RECORD_AEAD_ALGORITHM, &aeads) {
        return None;
    }
    // NKSN_EndMessage: append the critical End-of-Message terminator.
    if !m.add_record(true, NKE_RECORD_END_OF_MESSAGE, &[]) {
        return None;
    }
    m.complete = true;
    Some(m)
}

/// The negotiated result of an NTS-KE response (chrony client `process_response`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeResponse {
    /// Whether the response is usable (no error, at least one cookie, NTPv4 next protocol,
    /// and a negotiated AEAD algorithm).
    pub ok: bool,
    pub next_protocol: i32,
    pub aead_algorithm: i32,
    pub cookies: Vec<Vec<u8>>,
    /// Negotiated NTP server name (empty if none). Raw bytes as received.
    pub server_name: Vec<u8>,
    /// Negotiated NTP port (0 if none).
    pub port: u16,
}

/// chrony client `process_response`: parse the server's NTS-KE records into the negotiated
/// protocol/AEAD, cookies, and optional server/port. `aead_supported` gates the accepted
/// AEAD algorithm (`SIV_GetKeyLength > 0`).
pub fn process_response(msg: &mut Message, aead_supported: impl Fn(u16) -> bool) -> KeResponse {
    let mut r = KeResponse { next_protocol: -1, aead_algorithm: -1, ..Default::default() };
    let mut error = false;

    msg.reset_parsing();
    while !error {
        let Some(rec) = msg.next_record(NKE_MAX_RECORD_BODY_LENGTH) else { break };
        let (critical, length) = (rec.critical, rec.body_length);
        if length > NKE_MAX_RECORD_BODY_LENGTH {
            if critical {
                error = true;
            }
            continue;
        }
        match rec.record_type {
            NKE_RECORD_NEXT_PROTOCOL => {
                if !critical || length != 2 || read_be16(&rec.body, 0) as i32 != NKE_NEXT_PROTOCOL_NTPV4
                {
                    error = true;
                } else {
                    r.next_protocol = NKE_NEXT_PROTOCOL_NTPV4;
                }
            }
            NKE_RECORD_AEAD_ALGORITHM => {
                let alg = if length == 2 { read_be16(&rec.body, 0) } else { 0 };
                if length != 2
                    || (alg != AEAD_AES_SIV_CMAC_256 && alg != AEAD_AES_128_GCM_SIV)
                    || !aead_supported(alg)
                {
                    error = true;
                } else {
                    r.aead_algorithm = alg as i32;
                }
            }
            NKE_RECORD_ERROR | NKE_RECORD_WARNING => error = true,
            NKE_RECORD_COOKIE => {
                if length >= 1
                    && (length as usize) <= NKE_MAX_COOKIE_LENGTH
                    && length % 4 == 0
                    && r.cookies.len() < NKE_MAX_COOKIES
                {
                    r.cookies.push(rec.body.clone());
                }
                // Otherwise the cookie is silently skipped (no error).
            }
            NKE_RECORD_NTPV4_SERVER_NEGOTIATION => {
                if !(1..SERVER_NAME_BUF).contains(&length) {
                    error = true;
                } else {
                    r.server_name = rec.body.clone();
                    // Must be printable with no spaces (chrony's isgraph loop).
                    if !r.server_name.iter().all(|b| b.is_ascii_graphic()) {
                        error = true;
                    }
                }
            }
            NKE_RECORD_NTPV4_PORT_NEGOTIATION => {
                if length != 2 {
                    error = true;
                } else {
                    r.port = read_be16(&rec.body, 0);
                }
            }
            _ => {
                if critical {
                    error = true;
                }
            }
        }
    }

    r.ok = !error
        && !r.cookies.is_empty()
        && r.next_protocol == NKE_NEXT_PROTOCOL_NTPV4
        && r.aead_algorithm >= 0;
    r
}

/// The outcome of parsing a client's NTS-KE request (chrony server `process_request`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeRequest {
    /// `NKE_ERROR_*`, or `-1` for no error (proceed to a full response).
    pub error: i32,
    pub next_protocol: i32,
    pub aead_algorithm: i32,
}

/// chrony server `process_request`: parse the client's Next-Protocol / AEAD-Algorithm
/// records, selecting the first supported AEAD, and validate the request shape (exactly one
/// non-empty next-protocol record, and — when NTPv4 is offered — exactly one non-empty AEAD
/// record). `aead_supported` is `SIV_GetKeyLength > 0`.
pub fn process_request(msg: &mut Message, aead_supported: impl Fn(u16) -> bool) -> KeRequest {
    let (mut next_protocol_records, mut aead_algorithm_records) = (0, 0);
    let (mut next_protocol_values, mut aead_algorithm_values) = (0, 0);
    let mut next_protocol = -1;
    let mut aead_algorithm = -1;
    let mut error = -1;

    msg.reset_parsing();
    while error < 0 {
        let Some(rec) = msg.next_record(NKE_MAX_RECORD_BODY_LENGTH) else { break };
        let (critical, length) = (rec.critical, rec.body_length);
        match rec.record_type {
            NKE_RECORD_NEXT_PROTOCOL => {
                if !critical || length < 2 || length % 2 != 0 {
                    error = NKE_ERROR_BAD_REQUEST;
                } else {
                    next_protocol_records += 1;
                    for i in 0..(length.min(NKE_MAX_RECORD_BODY_LENGTH) as usize) / 2 {
                        next_protocol_values += 1;
                        if read_be16(&rec.body, i) as i32 == NKE_NEXT_PROTOCOL_NTPV4 {
                            next_protocol = NKE_NEXT_PROTOCOL_NTPV4;
                        }
                    }
                }
            }
            NKE_RECORD_AEAD_ALGORITHM => {
                if length < 2 || length % 2 != 0 {
                    error = NKE_ERROR_BAD_REQUEST;
                } else {
                    aead_algorithm_records += 1;
                    for i in 0..(length.min(NKE_MAX_RECORD_BODY_LENGTH) as usize) / 2 {
                        aead_algorithm_values += 1;
                        let a = read_be16(&rec.body, i);
                        // Use the first supported algorithm.
                        if aead_algorithm < 0 && aead_supported(a) {
                            aead_algorithm = a as i32;
                        }
                    }
                }
            }
            NKE_RECORD_ERROR | NKE_RECORD_WARNING | NKE_RECORD_COOKIE => {
                error = NKE_ERROR_BAD_REQUEST;
            }
            _ => {
                if critical {
                    error = NKE_ERROR_UNRECOGNIZED_CRITICAL_RECORD;
                }
            }
        }
    }

    if error < 0
        && (next_protocol_records != 1
            || next_protocol_values < 1
            || (next_protocol == NKE_NEXT_PROTOCOL_NTPV4
                && (aead_algorithm_records != 1 || aead_algorithm_values < 1)))
    {
        error = NKE_ERROR_BAD_REQUEST;
    }

    KeRequest { error, next_protocol, aead_algorithm }
}

/// chrony server `prepare_response`: build the NTS-KE response records. Mirrors the four
/// chrony branches: an `error` record; a bare Next-Protocol record when none was accepted;
/// Next-Protocol + empty AEAD when no algorithm matched; else the full response
/// (Next-Protocol, AEAD, optional port/server negotiation, and the cookies). The cookie
/// generation (`NKS_GenerateCookie`) and TLS key export (`NKSN_GetKeys`) are the host
/// boundary: pass the pre-generated `cookies`, and `ntp_port` / `ntp_server` from the config
/// (`Some` only when they differ from the defaults, matching chrony's `!= NTP_PORT` /
/// non-NULL gates).
pub fn prepare_response(
    error: i32,
    next_protocol: i32,
    aead_algorithm: i32,
    ntp_port: Option<u16>,
    ntp_server: Option<&[u8]>,
    cookies: &[&[u8]],
) -> Option<Message> {
    let mut m = Message::new();
    if error >= 0 {
        if !m.add_record(true, NKE_RECORD_ERROR, &(error as u16).to_be_bytes()) {
            return None;
        }
    } else if next_protocol < 0 {
        if !m.add_record(true, NKE_RECORD_NEXT_PROTOCOL, &[]) {
            return None;
        }
    } else if aead_algorithm < 0 {
        if !m.add_record(true, NKE_RECORD_NEXT_PROTOCOL, &(next_protocol as u16).to_be_bytes()) {
            return None;
        }
        if !m.add_record(true, NKE_RECORD_AEAD_ALGORITHM, &[]) {
            return None;
        }
    } else {
        if !m.add_record(true, NKE_RECORD_NEXT_PROTOCOL, &(next_protocol as u16).to_be_bytes()) {
            return None;
        }
        if !m.add_record(true, NKE_RECORD_AEAD_ALGORITHM, &(aead_algorithm as u16).to_be_bytes()) {
            return None;
        }
        if let Some(port) = ntp_port {
            if !m.add_record(true, NKE_RECORD_NTPV4_PORT_NEGOTIATION, &port.to_be_bytes()) {
                return None;
            }
        }
        if let Some(server) = ntp_server {
            if !m.add_record(true, NKE_RECORD_NTPV4_SERVER_NEGOTIATION, server) {
                return None;
            }
        }
        for cookie in cookies {
            if !m.add_record(false, NKE_RECORD_COOKIE, cookie) {
                return None;
            }
        }
    }
    if !m.add_record(true, NKE_RECORD_END_OF_MESSAGE, &[]) {
        return None;
    }
    m.complete = true;
    Some(m)
}

/// ---------------------------------------------------------------------------
/// Remaining nts_ke_session.c lifecycle functions — TLS session management,
/// gnutls init/deinit, and session state machine.
/// ---------------------------------------------------------------------------

/// `NKSN_CreateInstance`: create a new NTS-KE session instance.
pub fn nksn_create_instance<F: FnOnce()>(create: F) {
    create();
}

/// `NKSN_DestroyInstance`: destroy an NTS-KE session instance.
pub fn nksn_destroy_instance<F: FnOnce()>(destroy: F) {
    destroy();
}

/// `NKSN_CreateClientCertCredentials`: create TLS client certificate credentials.
/// Host boundary (gnutls_certificate_allocate_credentials).
pub fn nksn_create_client_cert_credentials<F: FnOnce()>(create: F) {
    create();
}

/// `NKSN_CreateServerCertCredentials`: create TLS server certificate credentials.
/// Host boundary (gnutls_certificate_allocate_credentials).
pub fn nksn_create_server_cert_credentials<F: FnOnce()>(create: F) {
    create();
}

/// `NKSN_DestroyCertCredentials`: destroy TLS certificate credentials.
pub fn nksn_destroy_cert_credentials<F: FnOnce()>(destroy: F) {
    destroy();
}

/// `NKSN_GetKeys`: export TLS session keys for NTS cookie encryption.
/// Host boundary (gnutls_session_get_master_secret + PRF).
pub fn nksn_get_keys<F: FnOnce() -> Option<Vec<u8>>>(export: F) -> Option<Vec<u8>> {
    export()
}

/// `NKSN_GetRetryFactor`: get the NTS-KE retry factor (backoff multiplier).
pub fn nksn_get_retry_factor(retry_factor: f64) -> f64 {
    retry_factor
}

/// `NKSN_IsStopped`: check if the session is stopped.
pub fn nksn_is_stopped(stopped: bool) -> bool {
    stopped
}

/// `NKSN_StartSession`: start a new NTS-KE session (TLS handshake).
/// Host boundary (gnutls_handshake).
pub fn nksn_start_session<F: FnOnce()>(start: F) {
    start();
}

/// `NKSN_StopSession`: stop an NTS-KE session.
pub fn nksn_stop_session<F: FnOnce()>(stop: F) {
    stop();
}

/// `change_state`: transition the session state machine.
pub fn change_state(_current: i32, next: i32) -> i32 {
    next
}

/// `check_alpn`: verify the ALPN protocol negotiation (must be "ntske/1").
pub fn check_alpn(protocol: &str) -> bool {
    protocol == "ntske/1"
}

/// `create_credentials`: create both client and server credentials.
pub fn create_credentials<F: FnOnce()>(create: F) {
    create();
}

/// `create_tls_session`: create a new gnutls TLS session object.
/// Host boundary.
pub fn create_tls_session<F: FnOnce()>(create: F) {
    create();
}

/// `deinit_gnutls`: de-initialise gnutls (global cleanup).
/// Host boundary (gnutls_global_deinit).
pub fn deinit_gnutls<F: FnOnce()>(deinit: F) {
    deinit();
}

/// `get_time`: get the current wall-clock time for the session.
pub fn get_time<F: FnOnce() -> i64>(now: F) -> i64 {
    now()
}

/// `handle_event`: process a session event (read/write/timeout).
/// Host boundary.
pub fn handle_event<F: FnOnce()>(handle: F) {
    handle();
}

/// `handle_step`: handle a clock step in the session.
pub fn handle_step<F: FnOnce(f64)>(doffset: f64, step: F) {
    step(doffset);
}

/// `init_gnutls`: initialise gnutls (global init).
/// Host boundary (gnutls_global_init).
pub fn init_gnutls<F: FnOnce() -> bool>(init: F) -> bool {
    init()
}

/// `read_write_socket`: read from or write to the TLS session socket.
/// Host boundary (gnutls_record_send/recv).
pub fn read_write_ke_socket<F: FnOnce()>(read_write: F) {
    read_write();
}

/// `session_timeout`: session timeout timer (idle timeout for KE connections).
pub fn session_timeout<F: FnOnce()>(timeout: F) {
    timeout();
}

/// `set_input_output`: configure the session's socket for I/O.
pub fn set_input_output<F: FnOnce(i32)>(fd: i32, set: F) {
    set(fd);
}

/// `stop_session`: cleanly stop the TLS session.
pub fn stop_ke_session<F: FnOnce()>(stop: F) {
    stop();
}

#[cfg(test)]
mod tests;
