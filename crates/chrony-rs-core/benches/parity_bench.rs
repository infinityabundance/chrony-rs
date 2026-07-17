//! Micro-benchmarks for chrony-rs-core.
//!
//! These measure the hot-path operations: NTP packet encode/decode,
//! config parsing, and timespec arithmetic. Run with:
//!
//!     cargo bench -p chrony-rs-core

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_ntp_decode(c: &mut Criterion) {
    let pkt = [0u8; 48];
    c.bench_function("ntp_decode_48byte", |b| {
        b.iter(|| {
            let _ = chrony_rs_core::ntp::NtpPacket::decode(black_box(&pkt));
        })
    });
}

fn bench_config_parse(c: &mut Criterion) {
    let config = "server 0.pool.ntp.org iburst\nserver 1.pool.ntp.org iburst\n";
    c.bench_function("config_parse_small", |b| {
        b.iter(|| {
            let _ = chrony_rs_core::config::parse(black_box(config));
        })
    });
}

fn bench_timespec_normalise(c: &mut Criterion) {
    c.bench_function("timespec_normalise", |b| {
        b.iter(|| {
            let result =
                chrony_rs_core::util::normalise_timespec(black_box(1000), black_box(1_500_000_000));
            black_box(result);
        })
    });
}

criterion_group!(
    benches,
    bench_ntp_decode,
    bench_config_parse,
    bench_timespec_normalise
);
criterion_main!(benches);
