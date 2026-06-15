//! Tests for the `nts_ntp_client.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `nts_ntp_client.c`** (+
//! `nts_ntp_auth.c`, `ntp_ext.c`, `siv_nettle.c`/`siv_nettle_int.c` over the
//! FIPS-197 shim AES), with the NTS-KE result injected. A C generator records the
//! auth cycle (`research/oracle/nts_ntp_client-c-vectors.txt`).
//! [`matches_real_c_nts_client_vectors`] replays the identical flow (same injected
//! NKE / clock / LCG / real SIV) and matches the request bytes, the check result,
//! and the report.
//!
//! **Oracle #2 (independent): the cookie dump round-trip.** `save_cookies` →
//! `load_cookies` restores the keys and cookies ([`cookie_dump_round_trip`]).

use super::*;
use crate::nts_ntp_auth::generate_auth_ef;
use crate::nts_ntp_server::{NkeKey, NTP_EF_NTS_COOKIE};
use crate::ntp::ext::set_field;

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

/// The injected NTS-KE result: context + 2 cookies, returned once (as the C stub).
struct StubNke {
    data: Option<NkeData>,
}
impl NkeClient for StubNke {
    fn create(&mut self, _a: &NtpAddress, _n: &str, _c: u32) {}
    fn start(&mut self) -> bool {
        true
    }
    fn is_active(&mut self) -> bool {
        false
    }
    fn get_nts_data(&mut self, _max: usize) -> Option<NkeData> {
        self.data.take()
    }
    fn get_retry_factor(&mut self) -> i32 {
        2
    }
    fn destroy(&mut self) {}
}

fn injected_data() -> NkeData {
    let cookies = (0..2)
        .map(|c| NkeCookie {
            bytes: (0..100).map(|i| (0xC0 + c * 16 + (i & 0xf)) as u8).collect(),
        })
        .collect();
    NkeData { context: make_context(), cookies, ntp_address: NtpAddress { ip: None, port: 0 } }
}

fn make_client() -> NtsClient {
    NtsClient::new(
        NtpAddress { ip: Some(0x7f000001), port: 4460 },
        "server.example",
        0,
        123,
        Box::new(StubNke { data: Some(injected_data()) }),
        Box::new(|| 1000.0),
        lcg(0x1234567890abcdef),
        1e9,
        Box::new(|_old, _new| true),
        None,
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}

#[test]
fn matches_real_c_nts_client_vectors() {
    let vectors = include_str!("../../../../research/oracle/nts_ntp_client-c-vectors.txt");
    let line = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    let mut client = make_client();

    // PrepareForAuth
    let pret = client.prepare_for_auth();
    assert_eq!(pret, field(line("PREP"), "ret") == "1", "PREP ret");

    // GenerateRequestAuth
    let mut req = NtpPacketBuf::new();
    req.bytes_mut()[0] = ((4 << 3) | MODE_CLIENT) as u8;
    let mut req_info =
        NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: MODE_CLIENT, ext_fields: 0, ..Default::default() };
    let gret = client.generate_request_auth(&mut req, &mut req_info);
    let rl = line("REQ");
    assert_eq!(gret, field(rl, "ret") == "1", "REQ ret");
    assert_eq!(req_info.length, field(rl, "len").parse::<i32>().unwrap(), "REQ len");
    let reqpkt = line("REQPKT").strip_prefix("REQPKT ").unwrap();
    assert_eq!(hex(&req.bytes()[..req_info.length as usize]), reqpkt, "request packet bytes");

    // Extract the client's unique id to echo in the crafted server response.
    let ctx = make_context();
    let mut uniq = Vec::new();
    let mut parsed = NTP_HEADER_LENGTH;
    while parsed < req_info.length {
        let pf = parse_field(&req, req_info.length, parsed).unwrap();
        if pf.field_type == NTP_EF_NTS_UNIQUE_IDENTIFIER {
            uniq = req.bytes()[pf.body_offset..pf.body_offset + pf.body_length as usize].to_vec();
        }
        parsed += pf.length;
    }

    // Craft a valid S2C response carrying 2 new cookies.
    let mut resp = NtpPacketBuf::new();
    resp.bytes_mut()[0] = ((4 << 3) | MODE_SERVER) as u8;
    let mut res_info =
        NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: MODE_SERVER, ext_fields: 0, ..Default::default() };
    add_field(&mut resp, &mut res_info, NTP_EF_NTS_UNIQUE_IDENTIFIER, &uniq);

    let mut plaintext = vec![0u8; 512];
    let mut pl = 0i32;
    for c in 0..2 {
        let nc: Vec<u8> = (0..100).map(|i| (0xD0 + c * 16 + (i & 0xf)) as u8).collect();
        let efl = set_field(&mut plaintext, 512, pl, NTP_EF_NTS_COOKIE, &nc).unwrap();
        pl += efl;
    }
    let mut s2c = SivInstance::create(SivAlgorithm::AesSivCmac256).unwrap();
    assert!(s2c.set_key(&ctx.s2c.key));
    let snonce: Vec<u8> = (0..NONCE_LENGTH).map(|i| 0x90 + i as u8).collect();
    assert!(generate_auth_ef(
        &mut resp,
        &mut res_info,
        &mut s2c,
        &snonce,
        NONCE_LENGTH as i32,
        &plaintext[..pl as usize],
        0
    ));

    let cret = client.check_response_auth(&resp, &res_info);
    assert_eq!(cret, field(line("CHECK"), "ret") == "1", "CHECK ret");

    let rep = client.get_report();
    let rpl = line("REPORT");
    assert_eq!(rep.cookies, field(rpl, "cookies").parse::<i32>().unwrap(), "report cookies");
    assert_eq!(rep.key_length, field(rpl, "key_length").parse::<i32>().unwrap(), "report key_length");
    assert_eq!(rep.key_type, field(rpl, "key_type").parse::<i32>().unwrap(), "report key_type");
    assert_eq!(rep.nak as i32, field(rpl, "nak").parse::<i32>().unwrap(), "report nak");
}

#[test]
fn cookie_dump_round_trip() {
    // Run the auth cycle to populate the cookie pool + context, then save and reload.
    let mut client = make_client();
    assert!(client.prepare_for_auth());

    let mut req = NtpPacketBuf::new();
    req.bytes_mut()[0] = ((4 << 3) | MODE_CLIENT) as u8;
    let mut req_info =
        NtpPacketInfo { length: NTP_HEADER_LENGTH, version: 4, mode: MODE_CLIENT, ext_fields: 0, ..Default::default() };
    assert!(client.generate_request_auth(&mut req, &mut req_info));

    let dump = client.save_cookies().expect("cookies present => a dump is produced");
    assert!(dump.starts_with("NNC0\n"), "dump carries the magic identifier");

    // A fresh client at the same address reloads the dump and recovers the context.
    let reloaded = NtsClient::new(
        NtpAddress { ip: Some(0x7f000001), port: 4460 },
        "server.example",
        0,
        123,
        Box::new(StubNke { data: None }),
        Box::new(|| 1000.0),
        lcg(1),
        1e9,
        Box::new(|_o, _n| true),
        Some(&dump),
    );
    let rep = reloaded.report_snapshot();
    assert_eq!(rep.0, 1, "remaining cookie (one was consumed by the request)");
    assert_eq!(rep.1, make_context().algorithm as i32, "algorithm restored");
    assert_eq!(rep.2, 256, "key length restored (256 bits)");
}

impl NtsClient {
    /// Test helper: `(num_cookies, key_type, key_length_bits)`, read straight from
    /// the private fields (the test submodule has access).
    fn report_snapshot(&self) -> (i32, i32, i32) {
        (self.num_cookies, self.context.algorithm as i32, 8 * self.context.s2c.key.len() as i32)
    }
}
