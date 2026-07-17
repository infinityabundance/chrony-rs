//! Differential oracle for the NTS-KE record codec vs verbatim copies of chrony 4.5
//! `nts_ke_session.c`'s `add_record` / `get_record` / `check_message_format` /
//! `reset_message` bodies (compiled with the real `htons`/`ntohs`/`memcpy`/`MIN`;
//! `research/oracle/nts_ke-record-c-vectors.txt`).

use super::*;
use std::collections::HashMap;

fn f<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("missing {key} in: {line}"))
}
fn n(line: &str, key: &str) -> i64 {
    f(line, key).parse().unwrap()
}
fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".to_string();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}
/// The generator's deterministic body filler: byte `i` is `0x40 + i`.
fn body_rule(len: i64) -> Vec<u8> {
    (0..len.max(0)).map(|i| (0x40 + i) as u8).collect()
}

#[test]
fn matches_real_c_nts_ke_record_vectors() {
    let vectors = include_str!("../../../../research/oracle/nts_ke-record-c-vectors.txt");
    let by_n: HashMap<i64, &str> = vectors
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| (n(l, "n"), l))
        .collect();

    // ---- ADD (n=0..=4): build a real NTS-KE message on a shared buffer. ----
    let mut m = Message::new();
    for k in 0..=4 {
        let line = by_n[&k];
        let (crit, ty, blen) = (n(line, "crit") == 1, n(line, "type") as i32, n(line, "blen"));
        let ret = m.add_record(crit, ty, &body_rule(blen));
        assert_eq!(ret as i64, n(line, "ret"), "ADD n={k} ret");
        assert_eq!(m.length as i64, n(line, "len"), "ADD n={k} len");
        assert_eq!(hex(m.data()), f(line, "data"), "ADD n={k} data");
    }

    // ---- ADD n=5: the buffer-overflow guard near NKE_MAX_MESSAGE_LENGTH. ----
    let mut big = Message::new();
    big.force_length(NKE_MAX_MESSAGE_LENGTH - 3);
    assert!(!big.add_record(false, 7, &body_rule(4)), "ADD n=5 overflow must reject");

    // ---- GET (n=6..=10): sequential parse of the 4-record message. ----
    m.reset_parsing();
    for k in 6..=10 {
        let line = by_n[&k];
        let rec = m.get_record(256);
        assert_eq!(rec.is_some() as i64, n(line, "ret"), "GET n={k} ret");
        assert_eq!(m.parsed as i64, n(line, "parsed"), "GET n={k} parsed");
        if let Some(r) = rec {
            assert_eq!(r.critical as i64, n(line, "crit"), "GET n={k} crit");
            assert_eq!(r.record_type as i64, n(line, "type"), "GET n={k} type");
            assert_eq!(r.body_length as i64, n(line, "blen"), "GET n={k} blen");
            assert_eq!(hex(&r.body), f(line, "body"), "GET n={k} body");
        }
    }

    // ---- GET n=11: buffer_length=1 truncates the copied body (MIN), cursor still
    //      advances by the full record. Skip the first two records first. ----
    m.reset_parsing();
    m.get_record(0);
    m.get_record(0);
    let line = by_n[&11];
    let r = m.get_record(1).expect("record present");
    assert_eq!(r.critical as i64, n(line, "crit"), "GET n=11 crit");
    assert_eq!(r.record_type as i64, n(line, "type"), "GET n=11 type");
    assert_eq!(r.body_length as i64, n(line, "blen"), "GET n=11 blen");
    assert_eq!(hex(&r.body), f(line, "body"), "GET n=11 body");
    assert_eq!(m.parsed as i64, n(line, "parsed"), "GET n=11 parsed");

    // ---- GET n=12: a dangling 2-byte trailer (shorter than a header) parses the first
    //      record then returns None, leaving the cursor at the record boundary. ----
    let mut t = Message::new();
    t.add_record(true, NKE_RECORD_AEAD_ALGORITHM, &body_rule(4));
    let mut raw = t.data().to_vec();
    raw.extend_from_slice(&[0x00, 0x01]);
    let mut t = Message::from_received(&raw);
    t.reset_parsing();
    assert!(t.get_record(0).is_some(), "GET n=12 first record");
    let line = by_n[&12];
    assert_eq!(t.get_record(0).is_some() as i64, n(line, "ret"), "GET n=12 ret");
    assert_eq!(t.parsed as i64, n(line, "parsed"), "GET n=12 parsed");

    // ---- CHECK (n=13..): message-format validation over crafted messages. ----
    for k in 13.. {
        let Some(line) = by_n.get(&k) else { break };
        let mut c = Message::from_received(&unhex(f(line, "msg")));
        let ret = c.check_message_format(n(line, "eof") == 1);
        assert_eq!(ret as i64, n(line, "ret"), "CHECK n={k} ({}) ret", f(line, "name"));
        assert_eq!(c.complete as i64, n(line, "complete"), "CHECK n={k} complete");
    }
}

/// Differential oracle for the client/server NTS-KE message logic vs verbatim copies of
/// chrony's `prepare_request` / `process_response` (client) and `process_request` /
/// `prepare_response` (server), composing the record codec through the EOM-hiding
/// `NKSN_GetRecord` (`research/oracle/nts_ke-protocol-c-vectors.txt`, both AEADs supported).
#[test]
fn matches_real_c_nts_ke_protocol_vectors() {
    let vectors = include_str!("../../../../research/oracle/nts_ke-protocol-c-vectors.txt");
    // The oracle's SIV_GetKeyLength: only the two real AEAD algorithms are supported.
    let supported = |a: u16| a == AEAD_AES_SIV_CMAC_256 || a == AEAD_AES_128_GCM_SIV;

    for line in vectors.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let tag = line.split_whitespace().next().unwrap();
        match tag {
            "PREQ" => {
                let m = prepare_request(supported).expect("request built");
                assert_eq!(hex(m.data()), f(line, "msg"), "prepare_request");
            }
            "RESP" => {
                let mut m = Message::from_received(&unhex(f(line, "msg")));
                let r = process_response(&mut m, supported);
                let name = f(line, "name");
                assert_eq!(r.ok as i64, n(line, "ok"), "RESP {name} ok");
                assert_eq!(r.next_protocol as i64, n(line, "next"), "RESP {name} next");
                assert_eq!(r.aead_algorithm as i64, n(line, "aead"), "RESP {name} aead");
                assert_eq!(r.cookies.len() as i64, n(line, "ncookies"), "RESP {name} ncookies");
                assert_eq!(r.port as i64, n(line, "port"), "RESP {name} port");
                assert_eq!(hex(&r.server_name), f(line, "server"), "RESP {name} server");
                let ck = if r.cookies.is_empty() {
                    "-".to_string()
                } else {
                    r.cookies.iter().map(|c| hex(c)).collect::<Vec<_>>().join(",")
                };
                assert_eq!(ck, f(line, "cookies"), "RESP {name} cookies");
            }
            "REQ" => {
                let mut m = Message::from_received(&unhex(f(line, "msg")));
                let r = process_request(&mut m, supported);
                let name = f(line, "name");
                assert_eq!(r.error as i64, n(line, "error"), "REQ {name} error");
                assert_eq!(r.next_protocol as i64, n(line, "next"), "REQ {name} next");
                assert_eq!(r.aead_algorithm as i64, n(line, "aead"), "REQ {name} aead");
            }
            "PRESP" => {
                // 8 cookies of 4 bytes each: cookie i = [0x10*i, +1, +2, +3].
                let cookie_bufs: Vec<Vec<u8>> =
                    (0..8).map(|i| (0..4).map(|j| (0x10 * i + j) as u8).collect()).collect();
                let cookies: Vec<&[u8]> = cookie_bufs.iter().map(|c| c.as_slice()).collect();
                let name = f(line, "name");
                let m = match name {
                    "error" => prepare_response(NKE_ERROR_BAD_REQUEST, -1, -1, None, None, &cookies),
                    "next_lt0" => prepare_response(-1, -1, -1, None, None, &cookies),
                    "aead_lt0" => {
                        prepare_response(-1, NKE_NEXT_PROTOCOL_NTPV4, -1, None, None, &cookies)
                    }
                    "success" => prepare_response(
                        -1,
                        NKE_NEXT_PROTOCOL_NTPV4,
                        AEAD_AES_SIV_CMAC_256 as i32,
                        None,
                        None,
                        &cookies,
                    ),
                    "success_portsrv" => prepare_response(
                        -1,
                        NKE_NEXT_PROTOCOL_NTPV4,
                        AEAD_AES_SIV_CMAC_256 as i32,
                        Some(4460),
                        Some(b"ntp.x"),
                        &cookies,
                    ),
                    other => panic!("unknown PRESP case {other}"),
                }
                .expect("response built");
                assert_eq!(hex(m.data()), f(line, "msg"), "prepare_response {name}");
            }
            _ => panic!("unknown tag {tag}"),
        }
    }
}

#[test]
fn nksn_begin_add_end_frames_a_message() {
    // NKSN_BeginMessage + NKSN_AddRecord* + NKSN_EndMessage composes the exact record
    // framing the C-verified add_record/get_record/check_message_format primitives accept.
    let mut m = Message::new();
    m.begin_message();
    assert!(m.new_message && !m.complete);
    assert!(m.add_message_record(true, NKE_RECORD_NEXT_PROTOCOL, &(NKE_NEXT_PROTOCOL_NTPV4 as u16).to_be_bytes()));
    assert!(m.add_message_record(true, NKE_RECORD_AEAD_ALGORITHM, &AEAD_AES_SIV_CMAC_256.to_be_bytes()));
    assert!(m.end_message());
    assert!(m.complete);

    // The exact bytes: NP(0x8001,len2,0x0000) AEAD(0x8004,len2,0x000f) EOM(0x8000,len0).
    assert_eq!(hex(m.data()), "80010002000080040002000f80000000");

    // The framing is well-formed and terminates, per the C-verified checker.
    assert!(m.check_message_format(true));
    assert!(m.complete);

    // Round-trip the two payload records back (NKSN_GetRecord hides the EOM terminator).
    m.reset_parsing();
    let r0 = m.next_record(256).expect("next-protocol record");
    assert_eq!((r0.critical, r0.record_type, r0.body), (true, NKE_RECORD_NEXT_PROTOCOL, vec![0x00, 0x00]));
    let r1 = m.next_record(256).expect("aead record");
    assert_eq!((r1.critical, r1.record_type, r1.body_length), (true, NKE_RECORD_AEAD_ALGORITHM, 2));
    assert!(m.next_record(256).is_none(), "EOM terminator is hidden");

    // EndMessage's overflow path: a full buffer leaves no room for the terminator.
    let mut full = Message::new();
    full.begin_message();
    // Fill to within < 4 bytes of the cap so the 4-byte EOM record cannot be added.
    let big = vec![0u8; 0xffff];
    while full.length + 4 + big.len() <= NKE_MAX_MESSAGE_LENGTH {
        assert!(full.add_message_record(false, NKE_RECORD_COOKIE, &big));
    }
    let pad = NKE_MAX_MESSAGE_LENGTH - full.length - 4 + 1; // one byte too many for an EOM header
    if pad <= 0xffff {
        assert!(full.add_message_record(false, NKE_RECORD_WARNING, &vec![0u8; pad.saturating_sub(4)]));
    }
    // If truly no room remains for a 4-byte header, end_message reports failure.
    if full.length + 4 > NKE_MAX_MESSAGE_LENGTH {
        assert!(!full.end_message());
        assert!(!full.complete);
    }
}
