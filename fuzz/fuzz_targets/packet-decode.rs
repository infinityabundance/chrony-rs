#![cfg_attr(any(fuzzing, feature = "fuzz"), no_main)]

use chrony_rs_core::ntp::packet::NtpPacket;

#[cfg(any(fuzzing, feature = "fuzz"))]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = NtpPacket::decode(data);
});

#[cfg(not(any(fuzzing, feature = "fuzz")))]
fn main() {
    println!("fuzz target: build with `cargo fuzz run packet-decode` or `cargo build --features fuzz`")
}
