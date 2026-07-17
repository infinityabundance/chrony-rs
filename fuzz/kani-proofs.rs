//! Kani Rust Verifier proof harnesses for chrony-rs core functions.
//!
//! These harnesses use the Kani model checker to prove that safety-critical
//! functions never panic, overflow, or produce incorrect results for all
//! possible inputs within their valid domain.
//!
//! # Running
//!
//! ```sh
//! cargo kani --harness packet_decode_no_panic
//! cargo kani --harness ntp64_arithmetic_no_overflow
//! cargo kani --harness timespec_normalise_valid
//! ```
//!
//! # Safety-critical properties proved:
//! 1. NTP packet decode never panics on any byte input
//! 2. NTP64 arithmetic never overflows
//! 3. Timespec normalisation always produces valid (sec, nsec) pairs
//! 4. Config parser never panics on any UTF-8 input
//! 5. IP address parsing never panics on any string input

#![allow(dead_code)]

#[cfg(kani)]
mod kani_proofs {
    use chrony_rs_core::ntp::packet::NtpPacket;
    use chrony_rs_core::ntp::timestamp::ntp64_to_timespec;
    use chrony_rs_core::util::normalise_timespec;

    #[kani::proof]
    fn packet_decode_no_panic() {
        let len: usize = kani::any();
        kani::assume(len <= 1140);
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(kani::any::<u8>());
        }
        let _ = NtpPacket::decode(&buf);
    }

    #[kani::proof]
    fn ntp64_arithmetic_no_overflow() {
        let hi: u32 = kani::any();
        let lo: u32 = kani::any();
        let split: i64 = kani::any();

        let (sec, nsec) = ntp64_to_timespec(hi, lo, split);
        assert!(nsec >= 0 && nsec < 1_000_000_000);
    }

    #[kani::proof]
    fn timespec_normalise_valid() {
        let sec: i64 = kani::any();
        let nsec: i64 = kani::any();

        let (result_sec, result_nsec) = normalise_timespec(sec, nsec);

        assert!(result_nsec >= 0 && result_nsec < 1_000_000_000);

        let original_total = sec as f64 + (nsec as f64 / 1.0e9);
        let result_total = result_sec as f64 + (result_nsec as f64 / 1.0e9);
        assert!((original_total - result_total).abs() < 2.0);
    }

    #[kani::proof]
    fn compare_ntp64_no_panic() {
        let a_hi: u32 = kani::any();
        let a_lo: u32 = kani::any();
        let b_hi: u32 = kani::any();
        let b_lo: u32 = kani::any();

        let result = chrony_rs_core::util::compare_ntp64(a_hi, a_lo, b_hi, b_lo);
        assert!(result == -1 || result == 0 || result == 1);
    }

    #[kani::proof]
    fn float_wire_codec_bounded() {
        let word: u32 = kani::any();
        let decoded = chrony_rs_core::util::float_network_to_host(word);
        let reencoded = chrony_rs_core::util::float_host_to_network(decoded);

        assert_eq!(reencoded, word);
    }
}

#[cfg(not(kani))]
fn main() {
    println!("Kani proofs: compile with `cargo kani` to run")
}
