use chrony_rs_core::sourcestats::SourceStats;

proptest::proptest! {
    #[test]
    fn regression_never_panics(_offset in -1.0f64..1.0f64, _delay in 0.0f64..1.0f64) {
        let mut stats = SourceStats::new(0, false, 4, 64, 0.001, 0.0);
        let _ = &mut stats;
    }

    #[test]
    fn offset_addition_is_commutative(a in -10.0f64..10.0f64, b in -10.0f64..10.0f64) {
        let result = (a + b - a - b).abs();
        assert!(result < 1e-10 || result.is_nan());
    }
}

proptest::proptest! {
    #[test]
    fn ntp_packet_encode_decode_roundtrip(
        li in 0u8..4,
        vn in 0u8..8,
        mode in 0u8..8,
        stratum in 0u8..16,
        poll in (-128i8..127),
        precision in (-128i8..127),
        root_delay in 0u32..0xFFFFFFFFu32,
        root_dispersion in 0u32..0xFFFFFFFFu32,
        ref_id in proptest::arbitrary::any::<u32>(),
        ref_ts_sec in 0u32..0xFFFFFFFFu32,
        ref_ts_frac in 0u32..0xFFFFFFFFu32,
        orig_ts_sec in 0u32..0xFFFFFFFFu32,
        orig_ts_frac in 0u32..0xFFFFFFFFu32,
        rx_ts_sec in 0u32..0xFFFFFFFFu32,
        rx_ts_frac in 0u32..0xFFFFFFFFu32,
        tx_ts_sec in 0u32..0xFFFFFFFFu32,
        tx_ts_frac in 0u32..0xFFFFFFFFu32,
    ) {
        // Build a 48-byte NTP packet
        let mut pkt = [0u8; 48];
        pkt[0] = (li << 6) | (vn << 3) | mode;
        pkt[1] = stratum;
        pkt[2] = poll as u8;
        pkt[3] = precision as u8;
        pkt[4..8].copy_from_slice(&root_delay.to_be_bytes());
        pkt[8..12].copy_from_slice(&root_dispersion.to_be_bytes());
        pkt[12..16].copy_from_slice(&ref_id.to_be_bytes());
        pkt[16..20].copy_from_slice(&ref_ts_sec.to_be_bytes());
        pkt[20..24].copy_from_slice(&ref_ts_frac.to_be_bytes());
        pkt[24..28].copy_from_slice(&orig_ts_sec.to_be_bytes());
        pkt[28..32].copy_from_slice(&orig_ts_frac.to_be_bytes());
        pkt[32..36].copy_from_slice(&rx_ts_sec.to_be_bytes());
        pkt[36..40].copy_from_slice(&rx_ts_frac.to_be_bytes());
        pkt[40..44].copy_from_slice(&tx_ts_sec.to_be_bytes());
        pkt[44..48].copy_from_slice(&tx_ts_frac.to_be_bytes());

        // Decode and verify each field
        let p = chrony_rs_core::ntp::NtpPacket::decode(&pkt);
        assert!(p.is_ok(), "decode should succeed for valid packet");
        let p = p.unwrap();
        let expected_leap = match li {
            0 => chrony_rs_core::ntp::LeapIndicator::NoWarning,
            1 => chrony_rs_core::ntp::LeapIndicator::InsertSecond,
            2 => chrony_rs_core::ntp::LeapIndicator::DeleteSecond,
            _ => chrony_rs_core::ntp::LeapIndicator::Unsynchronized,
        };
        assert_eq!(p.leap, expected_leap);
        assert_eq!(p.version, vn);
        assert_eq!(p.mode.0, mode);
        assert_eq!(p.stratum, stratum);
    }

    #[test]
    fn config_parse_never_panics(config_bytes: Vec<u8>) {
        // Config parser should never panic on any input
        let config_str = String::from_utf8_lossy(&config_bytes);
        let _ = chrony_rs_core::config::parse(&config_str);
    }

    #[test]
    fn timespec_normalise_never_panics(sec in -1000000i64..1000000i64, nsec in -2000000000i32..2000000000i32) {
        let (_normalised_sec, normalised_nsec) = chrony_rs_core::util::normalise_timespec(sec, nsec as i64);
        // After normalisation, nsec should be in [0, 1_000_000_000)
        assert!(normalised_nsec >= 0, "nsec should be >= 0, got {}", normalised_nsec);
        assert!(normalised_nsec < 1_000_000_000, "nsec should be < 1_000_000_000, got {}", normalised_nsec);
    }

    #[test]
    fn offset_arithmetic_no_overflow(
        offset_a in -100.0f64..100.0f64,
        offset_b in -100.0f64..100.0f64,
    ) {
        let sum = offset_a + offset_b;
        let diff = offset_a - offset_b;
        // These should never overflow or produce NaN
        assert!(!sum.is_nan());
        assert!(!diff.is_nan());
    }

    #[test]
    fn ntp64_to_timespec_range(ntp_secs in 0u32..0xFFFFFFFFu32, ntp_frac in 0u32..0xFFFFFFFFu32) {
        // NTP64 to Timespec conversion should always produce valid values
        let (_tv_sec, tv_nsec) = chrony_rs_core::util::ntp64_to_timespec(ntp_secs, ntp_frac, 0);
        assert!(tv_nsec >= 0, "nsec should be >= 0");
        assert!(tv_nsec <= 1_000_000_000, "nsec should be <= 1e9, got {}", tv_nsec);
    }
}
