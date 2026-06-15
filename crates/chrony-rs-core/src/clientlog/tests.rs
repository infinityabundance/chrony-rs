//! Tests for the `clientlog.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `clientlog.c`.** A C generator
//! (`research/oracle/clientlog-c-vectors.txt`, produced by `/tmp/clg/gen.c` against
//! the genuine chrony 4.5 module with an injected, reproducible random stream)
//! drives the real implementation through five scenarios and records inputs +
//! observable outputs. [`matches_real_c_clientlog_vectors`] replays the same
//! inputs through this port and asserts every output byte-for-byte.
//!
//! **Oracle #2 (independent): behavioral invariants.** The token bucket's defining
//! property — a full bucket allows exactly `burst` responses before it can drop —
//! is checked directly, without reference to the C code's arithmetic.

use super::*;

/// The deterministic random byte source used by the C generator (a PCG-style LCG),
/// replicated so the Rust port consumes an identical stream.
fn lcg_rng(seed: u64) -> Box<dyn FnMut() -> u8> {
    let mut state = seed;
    Box::new(move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u8
    })
}

const CLIENT_IP: ClientIp = ClientIp::V4(0x7f000001);

fn service_from(n: i32) -> Service {
    match n {
        0 => Service::Ntp,
        1 => Service::Ntske,
        _ => Service::Cmdmon,
    }
}

/// Parse `key=value` tokens out of a line into a small lookup.
fn fields(line: &str) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for tok in line.split_whitespace() {
        if let Some((k, v)) = tok.split_once('=') {
            m.insert(k.to_string(), v.to_string());
        }
    }
    m
}

fn geti(m: &std::collections::HashMap<String, String>, k: &str) -> i64 {
    m.get(k).unwrap_or_else(|| panic!("missing field {k}")).parse().unwrap()
}

fn parse_rl(spec: &str, on: bool) -> Option<RateLimit> {
    if !on {
        return None;
    }
    let parts: Vec<i32> = spec.split(',').map(|s| s.parse().unwrap()).collect();
    Some(RateLimit { interval: parts[0], burst: parts[1], leak_rate: parts[2] })
}

#[test]
fn matches_real_c_clientlog_vectors() {
    let data = include_str!("../../../../research/oracle/clientlog-c-vectors.txt");
    let mut clg: Option<ClientLog> = None;
    let mut step_count = 0usize;
    let mut query_count = 0usize;

    for raw in data.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let f = fields(line);

        if line.starts_with("INIT") {
            let cfg = ClientLogConfig {
                ntp_ratelimit: parse_rl(f.get("ntp").unwrap(), geti(&f, "ntp_on") != 0),
                nts_ratelimit: parse_rl(f.get("nts").unwrap(), geti(&f, "nts_on") != 0),
                cmd_ratelimit: parse_rl(f.get("cmd").unwrap(), geti(&f, "cmd_on") != 0),
                no_client_log: geti(&f, "noclientlog") != 0,
                client_log_limit: geti(&f, "loglimit") as u64,
            };
            let seed = f.get("seed").unwrap().parse::<u64>().unwrap();
            clg = Some(ClientLog::new(&cfg, lcg_rng(seed)));
        } else if line.starts_with("STEP") {
            let clg = clg.as_mut().unwrap();
            let svc = service_from(geti(&f, "svc") as i32);
            let now = Timespec::new(geti(&f, "sec"), geti(&f, "nsec"));
            let limit = geti(&f, "limit") != 0;

            let idx = clg.log_service_access(svc, CLIENT_IP, now);
            let drop = if limit && idx >= 0 {
                clg.limit_service_rate(svc, idx as usize)
            } else {
                -1
            };

            let (hits, drops, interval, timeout, last_ago) = if idx >= 0 {
                let r = clg
                    .get_client_access_report_by_index(idx, false, 0, now)
                    .expect("min_hits=0 always reports");
                let (hits, drops, interval) = match svc {
                    Service::Ntp => (r.ntp_hits, r.ntp_drops, r.ntp_interval),
                    Service::Ntske => (r.nke_hits, r.nke_drops, r.nke_interval),
                    Service::Cmdmon => (r.cmd_hits, r.cmd_drops, r.cmd_interval),
                };
                (hits as i64, drops as i64, interval as i64, r.ntp_timeout_interval as i64, r.last_ntp_hit_ago)
            } else {
                (0, 0, 0, 0, 0)
            };

            assert_eq!(idx as i64, geti(&f, "idx"), "idx @ step {step_count}: {line}");
            assert_eq!(drop as i64, geti(&f, "drop"), "drop @ step {step_count}: {line}");
            assert_eq!(hits, geti(&f, "hits"), "hits @ step {step_count}: {line}");
            assert_eq!(drops, geti(&f, "drops"), "drops @ step {step_count}: {line}");
            assert_eq!(interval, geti(&f, "interval"), "interval @ step {step_count}: {line}");
            assert_eq!(timeout, geti(&f, "timeout"), "timeout @ step {step_count}: {line}");
            assert_eq!(last_ago as i64, geti(&f, "last_ago"), "last_ago @ step {step_count}: {line}");
            step_count += 1;
        } else if line.starts_with("SAVE") {
            let clg = clg.as_mut().unwrap();
            let rx = u64::from_str_radix(f.get("rx").unwrap(), 16).unwrap();
            let tx = Timespec::new(geti(&f, "tx_sec"), geti(&f, "tx_nsec"));
            let src = TimestampSource::from_index(geti(&f, "src") as u8);
            clg.save_ntp_timestamps(rx, Some(tx), src);
        } else if line.starts_with("QUERY") {
            let clg = clg.as_mut().unwrap();
            let rx = u64::from_str_radix(f.get("rx").unwrap(), 16).unwrap();
            let got = clg.get_ntp_tx_timestamp(rx);
            let found = if got.is_some() { 1 } else { 0 };
            assert_eq!(found, geti(&f, "found"), "found @ query {query_count}: {line}");
            if let Some((tx, src)) = got {
                assert_eq!(tx.tv_sec, geti(&f, "tx_sec"), "tx_sec @ query {query_count}: {line}");
                assert_eq!(tx.tv_nsec, geti(&f, "tx_nsec"), "tx_nsec @ query {query_count}: {line}");
                assert_eq!(src as i64, geti(&f, "src"), "src @ query {query_count}: {line}");
            }
            query_count += 1;
        } else if line.starts_with("STATS") {
            let clg = clg.as_ref().unwrap();
            let s = clg.get_server_stats_report();
            assert_eq!(s.ntp_hits as i64, geti(&f, "ntp_hits"), "stats ntp_hits: {line}");
            assert_eq!(s.ntp_drops as i64, geti(&f, "ntp_drops"), "stats ntp_drops: {line}");
            assert_eq!(s.nke_hits as i64, geti(&f, "nke_hits"), "stats nke_hits: {line}");
            assert_eq!(s.nke_drops as i64, geti(&f, "nke_drops"), "stats nke_drops: {line}");
            assert_eq!(s.cmd_hits as i64, geti(&f, "cmd_hits"), "stats cmd_hits: {line}");
            assert_eq!(s.cmd_drops as i64, geti(&f, "cmd_drops"), "stats cmd_drops: {line}");
            assert_eq!(s.log_drops as i64, geti(&f, "log_drops"), "stats log_drops: {line}");
            assert_eq!(s.ntp_timestamps as i64, geti(&f, "ntp_timestamps"), "stats ntp_timestamps: {line}");
        }
    }

    // Guard: the fixture must actually have exercised the port.
    assert!(step_count >= 100, "expected many rate-limiter steps, got {step_count}");
    assert_eq!(query_count, 6, "interleaved scenario should issue 6 queries");
}

/// Oracle #2 (independent of the C arithmetic): the defining invariant of the
/// token bucket is that a *full* bucket grants exactly `burst` responses before it
/// can begin dropping. We assert that directly across a sweep of configurations,
/// with no time advancing between responses (so no refill can occur).
#[test]
fn independent_token_bucket_burst_capacity() {
    for &(interval, burst, leak) in &[(3, 8, 2), (-4, 16, 3), (0, 4, 1), (5, 2, 4), (-6, 32, 2)] {
        let cfg = ClientLogConfig {
            ntp_ratelimit: Some(RateLimit { interval, burst, leak_rate: leak }),
            nts_ratelimit: None,
            cmd_ratelimit: None,
            no_client_log: false,
            client_log_limit: 1_000_000,
        };
        let mut clg = ClientLog::new(&cfg, lcg_rng(1));
        let now = Timespec::new(1_700_000_000, 0);
        let idx = clg.log_service_access(Service::Ntp, CLIENT_IP, now);
        assert!(idx >= 0);

        // A fresh record starts with a full bucket: exactly `burst` responses must
        // be allowed before the token path can no longer cover a hit.
        for k in 0..burst {
            let drop = clg.limit_service_rate(Service::Ntp, idx as usize);
            assert_eq!(drop, 0, "response {k} should be allowed from a full bucket (interval={interval}, burst={burst})");
        }
        // The bucket is now dry (capacity = burst * tokens_per_hit spent). The next
        // decision falls to the random leak — i.e. it is no longer guaranteed.
        // Drain a long run; with a dry bucket and no refill, drops must occur.
        let mut drops = 0;
        for _ in 0..1000 {
            drops += clg.limit_service_rate(Service::Ntp, idx as usize);
        }
        assert!(drops > 0, "a dry bucket with no refill must drop some responses (interval={interval}, burst={burst})");
    }
}

#[test]
fn get_interval_maps_invalid_rate_to_127() {
    assert_eq!(ClientLog::get_interval(INVALID_RATE), 127);
    // Rate 0 → 0; positive rates round toward shorter intervals (negative log2).
    assert_eq!(ClientLog::get_interval(0), 0);
    assert!(ClientLog::get_interval(40) < 0);
    assert!(ClientLog::get_interval(-40) > 0);
}

#[test]
fn compare_ts_orders_invalid_as_smallest() {
    assert_eq!(ClientLog::compare_ts(5, 5), 0);
    assert_eq!(ClientLog::compare_ts(5, INVALID_TS), 1);
    assert_eq!(ClientLog::compare_ts(10, 5), 1);
    assert_eq!(ClientLog::compare_ts(5, 10), -1);
}

#[test]
fn set_bucket_params_capacity_is_burst_times_per_hit() {
    // Across the configurable range, max_tokens is always tokens_per_hit * burst
    // (clamped), and tokens_per_hit is non-zero. This is the relationship the
    // burst-capacity invariant relies on.
    for interval in MIN_LIMIT_INTERVAL..=MAX_LIMIT_INTERVAL {
        for &burst in &[1, 2, 4, 8, 16, 64, 255] {
            let (max_tokens, tph, _shift) = ClientLog::set_bucket_params(interval, burst);
            assert!(tph >= 1, "tokens_per_hit must be >= 1");
            // Capacity is always a whole number of hits, and never below the
            // requested burst.
            assert_eq!(max_tokens % tph, 0, "interval={interval} burst={burst}");
            assert!(max_tokens / tph >= burst as u16, "interval={interval} burst={burst}");
            // In the fine-grained branch the requested burst is used verbatim;
            // the coarse branch (interval < -TS_FRAC) may raise it.
            if interval >= -(TS_FRAC as i32) {
                assert_eq!(max_tokens, tph.wrapping_mul(burst as u16), "interval={interval} burst={burst}");
            }
        }
    }
}

#[test]
fn ntp64_to_timespec_zero_is_zero() {
    assert_eq!(ntp64_to_timespec(0), Timespec::default());
    // A non-zero NTP timestamp subtracts the 1900→1970 offset from the seconds.
    let ts = ntp64_to_timespec((JAN_1970 as u64 + 100) << 32);
    assert_eq!(ts.tv_sec, 100);
    assert_eq!(ts.tv_nsec, 0);
}

#[test]
fn inactive_when_noclientlog() {
    let cfg = ClientLogConfig {
        no_client_log: true,
        client_log_limit: 1_000_000,
        ..Default::default()
    };
    let mut clg = ClientLog::new(&cfg, lcg_rng(1));
    assert_eq!(clg.get_number_of_indices(), -1);
    // get_record returns None when inactive, so logging yields -1.
    assert_eq!(clg.log_service_access(Service::Ntp, CLIENT_IP, Timespec::new(1, 0)), -1);
}
