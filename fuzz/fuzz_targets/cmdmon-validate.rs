#![cfg_attr(any(fuzzing, feature = "fuzz"), no_main)]

use chrony_rs_core::cmdmon::validate_request;

#[cfg(any(fuzzing, feature = "fuzz"))]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() < 7 {
        return;
    }
    let read_len = u16::from_ne_bytes([data[0], data[1]]) as usize;
    let pkt_type = data[2];
    let res1 = data[3];
    let res2 = data[4];
    let version = data[5];
    let command = u16::from_ne_bytes([data[6], data[7]]);
    let _ = validate_request(read_len, pkt_type, res1, res2, version, command);
});

#[cfg(not(any(fuzzing, feature = "fuzz")))]
fn main() {
    println!("fuzz target: build with `cargo fuzz run cmdmon-validate` or `cargo build --features fuzz`")
}
