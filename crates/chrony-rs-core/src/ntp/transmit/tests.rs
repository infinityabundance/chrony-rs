//! Tests for `ntp_core.c` Stage 17 (`transmit_packet`, client path).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** `transmit_packet` is
//! driven in client mode and the built packet captured by the `NIO_SendPacket` stub
//! (`/tmp/ncor/gentx2.c`, `research/oracle/ntp_core-transmit-c-vectors.txt`).
//! [`matches_real_c_transmit_vectors`] rebuilds each request and matches every header
//! field and output timestamp.
//!
//! **Oracle #2 (independent): the client-request invariants.** A client request blanks
//! its clock state and reveals only the transmit timestamp.

use super::*;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

/// The transmit-timestamp packed value the generator used for `local_transmit`.
fn ts_for(tag: &str) -> Timespec {
    match tag {
        "TX_CLIENT_T2" => Timespec::new(1_900_000_000, 0),
        _ => Timespec::new(2_000_000_000, 250_000_000),
    }
}

#[test]
fn matches_real_c_transmit_vectors() {
    let v = include_str!("../../../../../research/oracle/ntp_core-transmit-c-vectors.txt");
    let scenarios = [
        ("TX_CLIENT_V4", 6, 4, 0x1111_1111_2222_2222u64),
        ("TX_CLIENT_V3", 8, 3, 0x3333_3333_4444_4444),
        ("TX_CLIENT_V9", 6, 9, 0x5555_5555_6666_6666),
        ("TX_CLIENT_T2", 4, 4, 0x7777_7777_8888_8888),
    ];
    for (tag, poll, version, prev_tx) in scenarios {
        let l = v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap();
        let r = build_client_request(poll, version, ts_for(tag), prev_tx);

        assert_eq!(r.length, field(l, "length").parse::<i32>().unwrap(), "{tag} length");
        assert_eq!(r.packet[0], field(l, "lvm").parse::<u8>().unwrap(), "{tag} lvm");
        assert_eq!(r.packet[1], field(l, "stratum").parse::<u8>().unwrap(), "{tag} stratum");
        assert_eq!(r.packet[2], field(l, "poll").parse::<u8>().unwrap(), "{tag} poll");
        assert_eq!(r.packet[3] as i8 as i32, field(l, "precision").parse::<i32>().unwrap(), "{tag} precision");
        let be32 = |o: usize| u32::from_be_bytes(r.packet[o..o + 4].try_into().unwrap());
        let be64 = |o: usize| ((be32(o) as u64) << 32) | be32(o + 4) as u64;
        assert_eq!(be32(4), field(l, "root_delay").parse::<u32>().unwrap(), "{tag} root_delay");
        assert_eq!(be32(8), field(l, "root_dispersion").parse::<u32>().unwrap(), "{tag} root_dispersion");
        assert_eq!(be32(12), field(l, "reference_id").parse::<u32>().unwrap(), "{tag} reference_id");
        assert_eq!(be64(16), field(l, "reference_ts").parse::<u64>().unwrap(), "{tag} reference_ts");
        assert_eq!(be64(24), field(l, "originate_ts").parse::<u64>().unwrap(), "{tag} originate_ts");
        assert_eq!(be64(32), field(l, "receive_ts").parse::<u64>().unwrap(), "{tag} receive_ts");
        assert_eq!(be64(40), field(l, "transmit_ts").parse::<u64>().unwrap(), "{tag} transmit_ts");
        // Output timestamps.
        assert_eq!(r.local_ntp_tx, field(l, "out_ntp_tx").parse::<u64>().unwrap(), "{tag} out_ntp_tx");
        assert_eq!(r.local_ntp_rx, field(l, "out_ntp_rx").parse::<u64>().unwrap(), "{tag} out_ntp_rx");
        assert_eq!(r.local_tx.tv_sec, field(l, "out_local_tx_sec").parse::<i64>().unwrap(), "{tag} local_tx");
    }
}

#[test]
fn client_request_blanks_clock_state() {
    let r = build_client_request(6, 4, Timespec::new(2_000_000_000, 0), 0);
    // version 4, mode 3 (client), leap 0.
    assert_eq!(r.packet[0], 0x23);
    // Everything but lvm/poll/precision/transmit_ts is zero.
    assert_eq!(r.packet[1], 0, "stratum");
    assert_eq!(&r.packet[4..40], &[0u8; 36], "roots/refid/ref/orig/recv blanked");
    assert_eq!(r.packet[3] as i8, 32, "precision hidden");
    assert_ne!(&r.packet[40..48], &[0u8; 8], "transmit timestamp present");
    // The transmit timestamp is echoed to the output and the receive timestamp is zero.
    assert_eq!(r.local_ntp_rx, 0);
    assert_ne!(r.local_ntp_tx, 0);
}

#[test]
fn version_is_capped() {
    // Version 9 is capped to NTP_VERSION (4); version 3 is preserved.
    assert_eq!(build_client_request(6, 9, Timespec::new(2_000_000_000, 0), 0).packet[0] >> 3 & 0x7, 4);
    assert_eq!(build_client_request(6, 3, Timespec::new(2_000_000_000, 0), 0).packet[0] >> 3 & 0x7, 3);
}
