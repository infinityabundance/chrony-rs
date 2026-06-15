//! Tests for the `refclock_sock.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `refclock_sock.c`.** A C generator
//! builds `sock_sample` datagrams (so the bytes carry the C struct layout), feeds them
//! to the real `read_sample` (captured via the file-handler stub; `recv` returns the
//! crafted bytes), and records the raw datagram bytes plus the `RCL_AddSample` /
//! `RCL_AddPulse` arguments and the rejections
//! (`research/oracle/refclock_sock-c-vectors.txt`). [`matches_real_c_sock_vectors`]
//! feeds the byte-identical datagrams to [`SockDriver::read_sample`] and matches the
//! routing (sample vs pulse) and every timestamp.
//!
//! **Oracle #2 (independent): the length and sanity gates.** A short datagram and an
//! insane offset are rejected.

use super::*;

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}
fn i(line: &str, key: &str) -> i64 {
    field(line, key).parse().unwrap()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn matches_real_c_sock_vectors() {
    let vectors = include_str!("../../../../research/oracle/refclock_sock-c-vectors.txt");
    let line = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    // ---- normal sample (pulse = 0) ----
    let bytes = unhex(line("SAMPLE_BYTES").strip_prefix("SAMPLE_BYTES ").unwrap());
    let l = line("SAMPLE ");
    match SockDriver::read_sample(&bytes) {
        Some(SockOutput::Sample { sys_ts, ref_ts, leap }) => {
            assert_eq!(i(l, "kind"), 1);
            assert_eq!(sys_ts.sec, i(l, "sys_sec"), "sample sys_sec");
            assert_eq!(sys_ts.nsec as i64, i(l, "sys_nsec"), "sample sys_nsec");
            assert_eq!(ref_ts.sec, i(l, "ref_sec"), "sample ref_sec");
            assert_eq!(ref_ts.nsec as i64, i(l, "ref_nsec"), "sample ref_nsec");
            assert_eq!(leap as i64, i(l, "leap"), "sample leap");
        }
        other => panic!("expected Sample, got {other:?}"),
    }

    // ---- pulse sample ----
    let bytes = unhex(line("PULSE_BYTES").strip_prefix("PULSE_BYTES ").unwrap());
    let l = line("PULSE ");
    match SockDriver::read_sample(&bytes) {
        Some(SockOutput::Pulse { sys_ts, offset }) => {
            assert_eq!(i(l, "kind"), 2);
            assert_eq!(sys_ts.sec, i(l, "sys_sec"), "pulse sys_sec");
            assert_eq!(sys_ts.nsec as i64, i(l, "sys_nsec"), "pulse sys_nsec");
            let exp_off: f64 = field(l, "off").parse().unwrap();
            assert_eq!(offset, exp_off, "pulse offset");
        }
        other => panic!("expected Pulse, got {other:?}"),
    }

    // ---- bad magic -> rejected ----
    let bytes = unhex(line("BADMAGIC_BYTES").strip_prefix("BADMAGIC_BYTES ").unwrap());
    assert_eq!(i(line("BADMAGIC "), "kind"), 0);
    assert!(SockDriver::read_sample(&bytes).is_none(), "bad magic rejected");
}

#[test]
fn short_datagram_and_insane_offset_are_rejected() {
    // A datagram that is not exactly sizeof(sock_sample) is rejected (the C BADLEN
    // case delivered sizeof - 4 bytes).
    let short = vec![0u8; SOCK_SAMPLE_SIZE - 4];
    assert!(SockDriver::read_sample(&short).is_none(), "short datagram rejected");
    assert!(SockDriver::parse_sample(&short).is_none());

    // A well-formed datagram with an insane offset is rejected (the C INSANE case).
    let mut buf = vec![0u8; SOCK_SAMPLE_SIZE];
    buf[0..8].copy_from_slice(&2_000_000_000i64.to_ne_bytes()); // tv_sec
    buf[16..24].copy_from_slice(&1e300f64.to_ne_bytes()); // offset
    buf[36..40].copy_from_slice(&SOCK_MAGIC.to_ne_bytes()); // magic
    assert!(SockDriver::read_sample(&buf).is_none(), "insane offset rejected");

    // The same datagram with a sane offset is accepted (sanity gate is the only block).
    buf[16..24].copy_from_slice(&0.001f64.to_ne_bytes());
    assert!(SockDriver::read_sample(&buf).is_some(), "sane offset accepted");
}
