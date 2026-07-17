#![cfg_attr(any(fuzzing, feature = "fuzz"), no_main)]

use chrony_rs_core::config;

#[cfg(any(fuzzing, feature = "fuzz"))]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = config::parse(s);
    }
});

#[cfg(not(any(fuzzing, feature = "fuzz")))]
fn main() {
    println!("fuzz target: build with `cargo fuzz run config-parse` or `cargo build --features fuzz`")
}
