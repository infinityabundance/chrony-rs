//! Tests for the `ntp_auth.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_auth.c`** (+ `keys.c`,
//! `hash_intmd5.c` which `#include`s `md5.c`, `array.c`). A C generator builds an
//! NTPv4 client request, adds the symmetric MAC (`NAU_GenerateRequestAuth`), checks
//! it (`NAU_CheckRequestAuth`), authenticates a server response
//! (`NAU_GenerateResponseAuth`), checks it (`NAU_CheckResponseAuth`), rejects a
//! tampered packet, and reports the key info (`NAU_GetReport`). The vectors live in
//! `research/oracle/ntp_auth-c-vectors.txt`. [`matches_real_c_ntp_auth_vectors`]
//! replays the identical flow through [`NauInstance`] + the free server functions
//! over the ported [`KeyStore`] and matches every MAC'd byte and result.
//!
//! **Oracle #2 (independent): mode dispatch.** The none / MS-SNTP / NTS branches are
//! exercised against the (separately oracle-backed) NTS modules and an injected
//! MS-SNTP signer, asserting the dispatcher routes to the right primitive.

use super::*;
use crate::keys::KeyStore;
use crate::nts_ntp_auth::generate_auth_ef;
use crate::nts_ntp_client::MODE_CLIENT;
use crate::nts_ntp_server::{
    CookieCodec, NkeContext, NkeCookie, NkeKey, NtsServer, NTP_EF_NTS_COOKIE,
    NTP_EF_NTS_COOKIE_PLACEHOLDER, NTP_EF_NTS_UNIQUE_IDENTIFIER, NTP_KOD_NTS_NAK, MODE_SERVER,
};
use crate::ntp::ext::{add_field, parse_field, NTP_HEADER_LENGTH};
use crate::siv_nettle::{SivAlgorithm, SivInstance};

const KEYFILE: &str = "1 MD5 ASCII:thisisasecretkey";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}

/// Build a packet header with `byte0` set and `bytes[4..48] = f(i)`, info at the
/// bare NTP header length.
fn make_header(byte0: u8, f: impl Fn(usize) -> u8, mode: i32) -> (NtpPacketBuf, NtpPacketInfo) {
    let mut pkt = NtpPacketBuf::new();
    {
        let b = pkt.bytes_mut();
        b[0] = byte0;
        for (i, byte) in b.iter_mut().enumerate().take(NTP_HEADER_LENGTH as usize).skip(4) {
            *byte = f(i);
        }
    }
    let info = NtpPacketInfo {
        length: NTP_HEADER_LENGTH,
        version: 4,
        mode,
        ext_fields: 0,
        ..Default::default()
    };
    (pkt, info)
}

#[test]
fn matches_real_c_ntp_auth_vectors() {
    let vectors = include_str!("../../../../research/oracle/ntp_auth-c-vectors.txt");
    let line = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    let mut keys = KeyStore::initialise(Some(KEYFILE));

    // ---- NAU_GetSuggestedNtpVersion + NAU_IsAuthEnabled ----
    let mut inst = NauInstance::create_symmetric(1);
    assert!(inst.is_auth_enabled());
    let sl = line("SUGGEST");
    assert_eq!(inst.suggested_ntp_version(&mut keys), field(sl, "ver").parse::<i32>().unwrap());

    // ---- NAU_GenerateRequestAuth: NTPv4 client, bytes[4..48] = i*5+3 ----
    let (mut req, mut req_info) = make_header(0x23, |i| (i * 5 + 3) as u8, MODE_CLIENT);
    let gret = inst.generate_request_auth(&mut keys, &mut req, &mut req_info);
    let rl = line("REQ");
    assert_eq!(gret, field(rl, "ret") == "1", "REQ ret");
    assert_eq!(req_info.length, field(rl, "len").parse::<i32>().unwrap(), "REQ len");
    assert_eq!(req_info.mac_start, field(rl, "mac_start").parse::<i32>().unwrap(), "REQ mac_start");
    assert_eq!(req_info.mac_length, field(rl, "mac_len").parse::<i32>().unwrap(), "REQ mac_len");
    assert_eq!(req_info.mac_key_id, field(rl, "mac_key").parse::<u32>().unwrap(), "REQ mac_key");
    assert_eq!(req_info.auth_mode, field(rl, "authmode").parse::<i32>().unwrap(), "REQ authmode");
    let reqpkt = line("REQPKT").strip_prefix("REQPKT ").unwrap();
    assert_eq!(hex(&req.bytes()[..req_info.length as usize]), reqpkt, "request packet bytes");

    // ---- NAU_CheckRequestAuth (server side): the request just generated ----
    let mut server = NtsServer::new(Box::new(NoCodec), Box::new(|| 0u8));
    let (cret, ckod) = check_request_auth(&req, &req_info, &mut keys, &mut server);
    let cl = line("CHECKREQ");
    assert_eq!(cret, field(cl, "ret") == "1", "CHECKREQ ret");
    assert_eq!(ckod, field(cl, "kod").parse::<u32>().unwrap(), "CHECKREQ kod");

    // ---- NAU_GenerateResponseAuth: server, bytes[4..48] = i*7+9 ----
    let (mut resp, mut res_info) = make_header(0x24, |i| (i * 7 + 9) as u8, MODE_SERVER);
    let mut never_called = |_: u32, _: &NtpPacketBuf, _: &NtpPacketInfo| {
        panic!("symmetric path must not call the MS-SNTP signer");
    };
    let signd: SigndFn = &mut never_called;
    let gret = generate_response_auth(
        &req,
        &req_info,
        &mut resp,
        &mut res_info,
        &mut keys,
        &mut server,
        signd,
        0,
    );
    let pl = line("RESP");
    assert_eq!(gret, field(pl, "ret") == "1", "RESP ret");
    assert_eq!(res_info.length, field(pl, "len").parse::<i32>().unwrap(), "RESP len");
    assert_eq!(res_info.auth_mode, field(pl, "authmode").parse::<i32>().unwrap(), "RESP authmode");
    let resppkt = line("RESPPKT").strip_prefix("RESPPKT ").unwrap();
    assert_eq!(hex(&resp.bytes()[..res_info.length as usize]), resppkt, "response packet bytes");

    // ---- NAU_CheckResponseAuth: a client instance verifies the response ----
    let mut client_inst = NauInstance::create_symmetric(1);
    let chret = client_inst.check_response_auth(&mut keys, &resp, &res_info);
    assert_eq!(chret, field(line("CHECKRESP"), "ret") == "1", "CHECKRESP ret");

    // ---- TAMPER: flip a MAC byte, the check must fail ----
    let mut tampered = NtpPacketBuf::new();
    tampered.bytes_mut().copy_from_slice(resp.bytes());
    let n = res_info.length as usize;
    tampered.bytes_mut()[n - 1] ^= 0xff;
    let tret = client_inst.check_response_auth(&mut keys, &tampered, &res_info);
    assert_eq!(tret, field(line("TAMPER"), "ret") == "1", "TAMPER ret");

    // ---- NAU_GetReport ----
    let report = inst.get_report(&mut keys);
    let rep = line("REPORT");
    assert_eq!(report.mode, field(rep, "mode").parse::<i32>().unwrap(), "REPORT mode");
    assert_eq!(report.key_id, field(rep, "key_id").parse::<u32>().unwrap(), "REPORT key_id");
    assert_eq!(report.key_type, field(rep, "key_type").parse::<i32>().unwrap(), "REPORT key_type");
    assert_eq!(
        report.key_length,
        field(rep, "key_length").parse::<i32>().unwrap(),
        "REPORT key_length"
    );
}

#[test]
fn none_mode_is_a_pass_through() {
    // NAU_CreateNoneInstance: generate adds nothing, check accepts, report is empty.
    let mut keys = KeyStore::initialise(None);
    let mut inst = NauInstance::create_none();
    assert!(!inst.is_auth_enabled());

    let (mut req, mut info) = make_header(0x23, |i| i as u8, MODE_CLIENT);
    assert!(inst.generate_request_auth(&mut keys, &mut req, &mut info));
    assert_eq!(info.length, NTP_HEADER_LENGTH, "none mode appends no MAC");
    assert_eq!(info.auth_mode, NtpAuthMode::None as i32);
    assert!(inst.check_response_auth(&mut keys, &req, &info), "none mode accepts unsigned");

    let report = inst.get_report(&mut keys);
    assert_eq!(report.mode, NtpAuthMode::None as i32);
    assert_eq!(report.key_id, 0);
}

#[test]
fn mssntp_response_is_handed_to_the_injected_signer_and_suppressed() {
    // NAU_GenerateResponseAuth for an MS-SNTP request: the original packet is never
    // emitted (returns false), the signer is invoked exactly once with the key id.
    let mut keys = KeyStore::initialise(None);
    let mut server = NtsServer::new(Box::new(NoCodec), Box::new(|| 0u8));

    let (req, mut req_info) = make_header(0x23, |i| i as u8, MODE_CLIENT);
    req_info.auth_mode = NtpAuthMode::Mssntp as i32;
    req_info.mac_key_id = 42;

    let (mut resp, mut res_info) = make_header(0x24, |i| i as u8, MODE_SERVER);

    let mut calls: Vec<u32> = Vec::new();
    let produced = {
        let mut sign = |key_id: u32, _p: &NtpPacketBuf, _i: &NtpPacketInfo| {
            calls.push(key_id);
            true
        };
        let signd: SigndFn = &mut sign;
        generate_response_auth(
            &req,
            &req_info,
            &mut resp,
            &mut res_info,
            &mut keys,
            &mut server,
            signd,
            0,
        )
    };
    assert!(!produced, "MS-SNTP suppresses the synchronous response");
    assert_eq!(calls, vec![42], "the signer is called once with the request key id");
}

/// A trivial reversible cookie codec (the NTS-server oracle's `SerdeCodec`), reused
/// here only to drive the NTS dispatch branch of `ntp_auth`.
struct SerdeCodec;

impl CookieCodec for SerdeCodec {
    fn generate_cookie(&mut self, c: &NkeContext) -> Option<NkeCookie> {
        let mut b = Vec::new();
        b.extend_from_slice(&(c.algorithm as u32).to_be_bytes());
        b.push(c.c2s.key.len() as u8);
        b.extend_from_slice(&c.c2s.key);
        b.push(c.s2c.key.len() as u8);
        b.extend_from_slice(&c.s2c.key);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        Some(NkeCookie { bytes: b })
    }
    fn decode_cookie(&mut self, cookie: &NkeCookie) -> Option<NkeContext> {
        let p = &cookie.bytes;
        if p.len() < 6 {
            return None;
        }
        let algorithm = match u32::from_be_bytes([p[0], p[1], p[2], p[3]]) {
            15 => SivAlgorithm::AesSivCmac256,
            16 => SivAlgorithm::AesSivCmac384,
            17 => SivAlgorithm::AesSivCmac512,
            30 => SivAlgorithm::Aes128GcmSiv,
            31 => SivAlgorithm::Aes256GcmSiv,
            _ => return None,
        };
        let mut n = 4usize;
        let c2s_len = p[n] as usize;
        n += 1;
        if c2s_len > 32 || n + c2s_len > p.len() {
            return None;
        }
        let c2s = p[n..n + c2s_len].to_vec();
        n += c2s_len;
        let s2c_len = p[n] as usize;
        n += 1;
        if s2c_len > 32 || n + s2c_len > p.len() {
            return None;
        }
        let s2c = p[n..n + s2c_len].to_vec();
        Some(NkeContext { algorithm, c2s: NkeKey { key: c2s }, s2c: NkeKey { key: s2c } })
    }
}

/// A codec that never decodes — used where the NTS branch is unreachable, so any
/// cookie traffic would be a routing bug.
struct NoCodec;

impl CookieCodec for NoCodec {
    fn generate_cookie(&mut self, _c: &NkeContext) -> Option<NkeCookie> {
        None
    }
    fn decode_cookie(&mut self, _cookie: &NkeCookie) -> Option<NkeContext> {
        None
    }
}

fn lcg(seed: u64) -> Box<dyn FnMut() -> u8> {
    let mut state = seed;
    Box::new(move || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as u8
    })
}

fn make_context() -> NkeContext {
    NkeContext {
        algorithm: SivAlgorithm::AesSivCmac256,
        c2s: NkeKey { key: (0..32).map(|i| 0x01 + i as u8).collect() },
        s2c: NkeKey { key: (0..32).map(|i| 0x80 + i as u8).collect() },
    }
}

#[test]
fn nts_request_check_and_response_route_through_the_nts_server() {
    // The free server functions must dispatch NTS-mode packets to the NTS server.
    // We reuse the server oracle's reversible codec to build a valid request and
    // confirm check passes (kod=0) and a response is generated, while a tampered
    // auth EF yields the NTS NAK kod.
    let mut keys = KeyStore::initialise(None);
    let ctx = make_context();

    let mut pkt = NtpPacketBuf::new();
    pkt.bytes_mut()[0] = ((4 << 3) | MODE_CLIENT) as u8;
    let mut info =
        NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: MODE_CLIENT, ..Default::default() };
    info.auth_mode = NtpAuthMode::Nts as i32;

    let uniq: Vec<u8> = (0..32).map(|i| 0x10 + i as u8).collect();
    assert!(add_field(&mut pkt, &mut info, NTP_EF_NTS_UNIQUE_IDENTIFIER, &uniq));
    let cookie = SerdeCodec.generate_cookie(&ctx).unwrap();
    assert!(add_field(&mut pkt, &mut info, NTP_EF_NTS_COOKIE, &cookie.bytes));
    let zeros = vec![0u8; cookie.bytes.len()];
    assert!(add_field(&mut pkt, &mut info, NTP_EF_NTS_COOKIE_PLACEHOLDER, &zeros));
    let mut siv = SivInstance::create(SivAlgorithm::AesSivCmac256).unwrap();
    assert!(siv.set_key(&ctx.c2s.key));
    let nonce: Vec<u8> = (0..16).map(|i| 0x70 + i as u8).collect();
    assert!(generate_auth_ef(&mut pkt, &mut info, &mut siv, &nonce, 16, &[], 0));

    let mut server = NtsServer::new(Box::new(SerdeCodec), lcg(0x1234567890abcdef));
    let (ok, kod) = check_request_auth(&pkt, &info, &mut keys, &mut server);
    assert!(ok && kod == 0, "valid NTS request accepted via the dispatcher");

    let mut resp = NtpPacketBuf::new();
    resp.bytes_mut()[0] = ((4 << 3) | MODE_SERVER) as u8;
    let mut res_info = NtpPacketInfo {
        length: NTP_HEADER_LENGTH,
        version: 4,
        mode: MODE_SERVER,
        ..Default::default()
    };
    let mut never = |_: u32, _: &NtpPacketBuf, _: &NtpPacketInfo| panic!("NTS path uses no signer");
    let signd: SigndFn = &mut never;
    let produced = generate_response_auth(
        &pkt,
        &info,
        &mut resp,
        &mut res_info,
        &mut keys,
        &mut server,
        signd,
        0,
    );
    assert!(produced, "NTS response generated via the dispatcher");
    assert_eq!(res_info.auth_mode, NtpAuthMode::Nts as i32);

    // Tampered auth EF => rejected with the NTS NAK kod.
    let mut bad = NtpPacketBuf::new();
    bad.bytes_mut().copy_from_slice(pkt.bytes());
    let n = info.length as usize;
    bad.bytes_mut()[n - 1] ^= 0xff;
    let (tok, tkod) = check_request_auth(&bad, &info, &mut keys, &mut server);
    assert!(!tok, "tampered NTS request rejected");
    assert_eq!(tkod, NTP_KOD_NTS_NAK, "rejection carries the NTS NAK kod");
}

/// Ensure the helper for [`parse_field`] stays referenced (used to scaffold any
/// future EF assertions) without tripping dead-code lints.
#[allow(dead_code)]
fn _uses_parse_field(pkt: &NtpPacketBuf, len: i32, off: i32) {
    let _ = parse_field(pkt, len, off);
}
