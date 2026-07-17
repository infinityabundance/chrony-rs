//! Differential oracle for the PTP wrap/unwrap framing vs verbatim copies of chrony's
//! `wrap_message` / `NIO_UnwrapMessage` compiled against the real `ptp.h` struct
//! (`research/oracle/ptp-wrap-c-vectors.txt`).

use super::*;

fn f<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("missing {key} in: {line}"))
}
fn n(line: &str, key: &str) -> i64 {
    f(line, key).parse().unwrap()
}
fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".to_string();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}
/// The generator's NTP message filler: byte i = 0x40 + i.
fn ntp_msg(len: usize) -> Vec<u8> {
    (0..len).map(|i| (0x40 + i) as u8).collect()
}

#[test]
fn matches_real_c_ptp_vectors() {
    let vectors = include_str!("../../../../research/oracle/ptp-wrap-c-vectors.txt");

    // Pin the PTP constants against the compiled header.
    let hdr = vectors.lines().find(|l| l.starts_with("HDR ")).unwrap();
    assert_eq!(n(hdr, "PREFIX") as usize, PTP_NTP_PREFIX_LENGTH);
    assert_eq!(n(hdr, "PTPVER") as u8, PTP_VERSION);
    assert_eq!(n(hdr, "DELAYREQ") as u8, PTP_TYPE_DELAY_REQ);
    assert_eq!(n(hdr, "DOMAIN") as u8, PTP_DOMAIN_NTP);
    assert_eq!(n(hdr, "FLAG") as u16, PTP_FLAG_UNICAST);
    assert_eq!(n(hdr, "TLV") as u16, PTP_TLV_NTP);
    assert_eq!(n(hdr, "PKTSIZE") as usize, PTP_MAX_MESSAGE);

    // The generator's static sequence counter: 0 for the first wrap, 1 for the second
    // (the third wrap fails the length check and does not advance it).
    let mut seq: u16 = 0;

    for line in vectors.lines() {
        if let Some(rest) = line.strip_prefix("WRAP ") {
            let ntplen = n(rest, "ntplen") as usize;
            let wrapped = wrap_message(&ntp_msg(ntplen), seq);
            let ret = wrapped.is_some();
            assert_eq!(ret as i64, n(rest, "ret"), "WRAP ntplen={ntplen} ret");
            if let Some(w) = wrapped {
                assert_eq!(w.len() as i64, n(rest, "outlen"), "WRAP ntplen={ntplen} outlen");
                assert_eq!(hex(&w[..PTP_NTP_PREFIX_LENGTH]), f(rest, "prefix"), "WRAP prefix");
                seq += 1;
            }
        } else if let Some(rest) = line.strip_prefix("UNWRAP ") {
            let name = f(rest, "name");
            // Build a valid wrapped 48-byte NTP message (sequence irrelevant to unwrap).
            let mut msg = wrap_message(&ntp_msg(48), 5).unwrap();
            match name {
                "valid" => {
                    // Plant correction = 2^32 (byte 11 = 0x01), as the generator does.
                    msg[8..16].copy_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
                }
                "bad_type" => msg[0] = 9,
                "bad_version" => msg[1] = 1,
                "bad_domain" => msg[4] = 7,
                "bad_flags" => msg[6] = 0xff,
                "bad_tlv_type" => msg[44] = 0xff,
                "bad_length" => msg[2] = 0xff,
                "bad_tlv_length" => msg[46] = 0xff,
                "too_short" => msg = vec![0u8; 48],
                other => panic!("unknown UNWRAP case {other}"),
            }
            let out = unwrap_message(&msg);
            assert_eq!(out.is_some() as i64, n(rest, "ret"), "UNWRAP {name} ret");
            if let Some((ntp, corr)) = out {
                assert_eq!(ntp.len() as i64, n(rest, "ntplen"), "UNWRAP {name} ntplen");
                let want_corr: f64 = f(rest, "corr").parse().unwrap();
                assert!((corr - want_corr).abs() <= 1e-18 + 1e-12 * want_corr.abs(), "UNWRAP {name} corr: {corr} vs {want_corr}");
                assert_eq!(hex(&ntp), f(rest, "ntp"), "UNWRAP {name} ntp");
            }
        }
    }
}
