#![cfg_attr(any(fuzzing, feature = "fuzz"), no_main)]

use chrony_rs_core::ntp::parse::parse_packet;
use chrony_rs_core::ntp::ext::NefContext;

#[cfg(any(fuzzing, feature = "fuzz"))]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut ctx = NefContext::new(data, 48);
    let _ = parse_packet(data, &mut ctx, true);
});

#[cfg(not(any(fuzzing, feature = "fuzz")))]
fn main() {
    println!("fuzz target: build with `cargo fuzz run ntp-header` or `cargo build --features fuzz`")
}
