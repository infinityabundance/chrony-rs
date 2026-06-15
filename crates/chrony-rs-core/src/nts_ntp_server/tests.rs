//! Tests for the `nts_ntp_server.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `nts_ntp_server.c`** (+
//! `nts_ntp_auth.c`, `ntp_ext.c`, `siv_nettle.c`/`siv_nettle_int.c` over the
//! FIPS-197 shim AES) with a deterministic reversible cookie codec. A C generator
//! builds a client request, runs the check + response, and records the results and
//! the response packet bytes plus tampered-auth and missing-cookie failures
//! (`research/oracle/nts_ntp_server-c-vectors.txt`). [`matches_real_c_nts_server_vectors`]
//! replays the identical flow with the same injected codec / real SIV / LCG and
//! matches every byte.

use super::*;
use crate::ntp::ext::NTP_PACKET_SIZE;

/// The deterministic LCG (`UTI_GetRandomBytes`), one byte per call.
fn lcg(seed: u64) -> Box<dyn FnMut() -> u8> {
    let mut state = seed;
    Box::new(move || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as u8
    })
}

/// The reversible cookie codec from the C oracle stub: serialise the context as
/// `[alg:4 BE][c2s.len:1][c2s.key][s2c.len:1][s2c.key]`, 4-aligned.
struct SerdeCodec;

impl CookieCodec for SerdeCodec {
    fn generate_cookie(&mut self, c: &NkeContext) -> Option<NkeCookie> {
        let alg = c.algorithm as u32;
        let mut b = Vec::new();
        b.extend_from_slice(&alg.to_be_bytes());
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
        let alg = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        let algorithm = match alg {
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
        n += s2c_len;
        if n > p.len() {
            return None;
        }
        Some(NkeContext { algorithm, c2s: NkeKey { key: c2s }, s2c: NkeKey { key: s2c } })
    }
}

fn make_context() -> NkeContext {
    NkeContext {
        algorithm: SivAlgorithm::AesSivCmac256,
        c2s: NkeKey { key: (0..32).map(|i| 0x01 + i as u8).collect() },
        s2c: NkeKey { key: (0..32).map(|i| 0x80 + i as u8).collect() },
    }
}

/// Build the client request (unique-id + cookie + placeholder + auth EF under C2S),
/// exactly as the C generator's `build_request`.
fn build_request(ctx: &NkeContext) -> (NtpPacketBuf, NtpPacketInfo) {
    let mut pkt = NtpPacketBuf::new();
    {
        let b = pkt.bytes_mut();
        b[0] = ((4 << 3) | MODE_CLIENT) as u8; // NTP_LVM(0,4,MODE_CLIENT)
        // transmit_ts (bytes 40..48): hi=0xe5000001, lo=0x40000000 (big-endian)
        b[40..44].copy_from_slice(&0xe5000001u32.to_be_bytes());
        b[44..48].copy_from_slice(&0x40000000u32.to_be_bytes());
    }
    let mut info = NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: MODE_CLIENT, ext_fields: 0 };

    let uniq: Vec<u8> = (0..32).map(|i| 0x10 + i as u8).collect();
    assert!(add_field(&mut pkt, &mut info, NTP_EF_NTS_UNIQUE_IDENTIFIER, &uniq));

    let cookie = SerdeCodec.generate_cookie(ctx).unwrap();
    assert!(add_field(&mut pkt, &mut info, NTP_EF_NTS_COOKIE, &cookie.bytes));
    let zeros = vec![0u8; cookie.bytes.len()];
    assert!(add_field(&mut pkt, &mut info, NTP_EF_NTS_COOKIE_PLACEHOLDER, &zeros));

    // The client's auth EF, generated with the C2S key.
    let mut siv = SivInstance::create(SivAlgorithm::AesSivCmac256).unwrap();
    assert!(siv.set_key(&ctx.c2s.key));
    let nonce: Vec<u8> = (0..16).map(|i| 0x70 + i as u8).collect();
    assert!(generate_auth_ef(&mut pkt, &mut info, &mut siv, &nonce, 16, &[], 0));

    (pkt, info)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}

#[test]
fn matches_real_c_nts_server_vectors() {
    let vectors = include_str!("../../../../research/oracle/nts_ntp_server-c-vectors.txt");
    let line = |prefix: &str| -> String {
        vectors.lines().map(str::trim).find(|l| l.starts_with(prefix)).unwrap().to_string()
    };

    let ctx = make_context();
    let mut server = NtsServer::new(Box::new(SerdeCodec), lcg(0x1234567890abcdef));

    // ---- valid request ----
    let (req, req_info) = build_request(&ctx);
    let (cret, ckod) = server.check_request_auth(&req, &req_info);
    let cl = line("CHECK");
    assert_eq!(cret, field(&cl, "ret") == "1", "CHECK ret");
    assert_eq!(
        format!("0x{ckod:x}"),
        field(&cl, "kod"),
        "CHECK kod"
    );

    // ---- response ----
    let mut resp = NtpPacketBuf::new();
    resp.bytes_mut()[0] = ((4 << 3) | MODE_SERVER) as u8; // NTP_LVM(0,4,MODE_SERVER)
    let mut res_info =
        NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: MODE_SERVER, ext_fields: 0 };
    let gret = server.generate_response_auth(&req, &req_info, &mut resp, &mut res_info, 0);
    let rl = line("RESP");
    assert_eq!(gret, field(&rl, "ret") == "1", "RESP ret");
    assert_eq!(res_info.length, field(&rl, "len").parse::<i32>().unwrap(), "RESP len");
    let pkt_line = line("PKT");
    let expected_pkt = pkt_line.strip_prefix("PKT ").unwrap();
    assert_eq!(hex(&resp.bytes()[..res_info.length as usize]), expected_pkt, "response packet bytes");

    // ---- tampered auth ----
    let (mut req2, req2_info) = build_request(&ctx);
    let n = req2_info.length as usize;
    req2.bytes_mut()[n - 1] ^= 0xff;
    let (tret, tkod) = server.check_request_auth(&req2, &req2_info);
    let tl = line("TAMPER");
    assert_eq!(tret, field(&tl, "ret") == "1", "TAMPER ret");
    assert_eq!(format!("0x{tkod:x}"), field(&tl, "kod"), "TAMPER kod");

    // ---- missing cookie ----
    let mut req3 = NtpPacketBuf::new();
    req3.bytes_mut()[0] = ((4 << 3) | MODE_CLIENT) as u8;
    let mut req3_info =
        NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: MODE_CLIENT, ext_fields: 0 };
    assert!(add_field(&mut req3, &mut req3_info, NTP_EF_NTS_UNIQUE_IDENTIFIER, &[0u8; 32]));
    let (nret, nkod) = server.check_request_auth(&req3, &req3_info);
    let nl = line("NOCOOKIE");
    assert_eq!(nret, field(&nl, "ret") == "1", "NOCOOKIE ret");
    assert_eq!(format!("0x{nkod:x}"), field(&nl, "kod"), "NOCOOKIE kod");
}

#[test]
fn full_nts_round_trip_then_client_uses_returned_cookie() {
    // End-to-end: the server checks a request and emits a response whose auth EF
    // verifies under S2C, and whose cookies decode back to the original context.
    let ctx = make_context();
    let mut server = NtsServer::new(Box::new(SerdeCodec), lcg(42));

    let (req, req_info) = build_request(&ctx);
    let (ok, kod) = server.check_request_auth(&req, &req_info);
    assert!(ok && kod == 0, "valid request accepted");
    assert_eq!(server.num_cookies(), 2, "cookie + placeholder => 2 cookies");

    let mut resp = NtpPacketBuf::new();
    resp.bytes_mut()[0] = ((4 << 3) | MODE_SERVER) as u8;
    let mut res_info =
        NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: MODE_SERVER, ext_fields: 0 };
    assert!(server.generate_response_auth(&req, &req_info, &mut resp, &mut res_info, 0));

    // The client verifies the response auth EF under S2C and recovers the cookies.
    let mut auth_start = None;
    let mut parsed = NTP_HEADER_LENGTH;
    while parsed < res_info.length {
        let pf = parse_field(&resp, res_info.length, parsed).unwrap();
        if pf.field_type == NTP_EF_NTS_AUTH_AND_EEF {
            auth_start = Some(parsed);
        }
        parsed += pf.length;
    }
    let mut s2c = SivInstance::create(SivAlgorithm::AesSivCmac256).unwrap();
    assert!(s2c.set_key(&ctx.s2c.key));
    let mut plaintext = vec![0u8; NTP_PACKET_SIZE as usize];
    let pt_len =
        decrypt_auth_ef(&resp, &res_info, &mut s2c, auth_start.unwrap(), &mut plaintext).unwrap();

    // The decrypted plaintext is two NTS-cookie EFs that decode to the context.
    let mut p = 0i32;
    let mut cookies = 0;
    while p < pt_len as i32 {
        let pf = parse_single_field(&plaintext, pt_len as i32, p).unwrap();
        if pf.field_type == NTP_EF_NTS_COOKIE {
            let c = NkeCookie {
                bytes: plaintext[pf.body_offset..pf.body_offset + pf.body_length as usize].to_vec(),
            };
            assert_eq!(SerdeCodec.decode_cookie(&c).unwrap(), ctx, "returned cookie decodes to context");
            cookies += 1;
        }
        p += pf.length;
    }
    assert_eq!(cookies, 2);
}
