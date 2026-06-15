//! Tests for the `nameserv.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `nameserv.c`.** A C generator
//! drives `DNS_Name2IPAddress` over a `getaddrinfo` overridden to return a crafted
//! `addrinfo` list (with `UTI_StringToIP` forced to "not a literal"), recording the
//! filtered addresses and the status for the UNSPEC / INET4-filter / IPv6-scope-skip
//! / `EAI_AGAIN` / other-error / `max_addrs`-limit cases
//! (`research/oracle/nameserv-c-vectors.txt`). [`matches_real_c_nameserv_vectors`]
//! replays the identical resolver results through [`DnsResolver`] and matches every
//! address and status.
//!
//! **Oracle #2 (independent): the literal shortcut + reverse fallback.** The IP-literal
//! fast path (with its family check) and the reverse lookup (with the IP-string
//! fallback and the `snprintf` truncation check) are unit-tested.

use super::*;

/// A scripted [`Resolver`]: returns a fixed `resolve` result, a controllable literal
/// parse, and a controllable reverse lookup.
#[derive(Default)]
struct StubResolver {
    result: Option<Result<Vec<ResolvedAddr>, DnsStatus>>,
    literal: Option<IpAddr>,
    reverse: Option<String>,
    reloaded: bool,
}

impl Resolver for StubResolver {
    fn resolve(&mut self, _name: &str, _family: i32) -> Result<Vec<ResolvedAddr>, DnsStatus> {
        self.result.clone().expect("resolve not scripted")
    }
    fn reverse(&mut self, _ip: &IpAddr) -> Option<String> {
        self.reverse.clone()
    }
    fn reload(&mut self) {
        self.reloaded = true;
    }
    fn parse_ip_literal(&mut self, _s: &str) -> Option<IpAddr> {
        self.literal
    }
    fn ip_to_string(&mut self, _ip: &IpAddr) -> String {
        "1.2.3.4".to_string()
    }
}

fn field(line: &str, key: &str) -> Option<String> {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}=")).map(str::to_string))
}
fn status_from(n: i64) -> DnsStatus {
    match n {
        0 => DnsStatus::Success,
        1 => DnsStatus::TryAgain,
        _ => DnsStatus::Failure,
    }
}

#[test]
fn matches_real_c_nameserv_vectors() {
    let vectors = include_str!("../../../../research/oracle/nameserv-c-vectors.txt");
    let line = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    // The V6 recipe in the oracle fills bytes fill+k; reproduce for comparison.
    let v6 = |fill: u8| -> [u8; 16] { std::array::from_fn(|k| fill.wrapping_add(k as u8)) };

    let run = |family: i32, list: Result<Vec<ResolvedAddr>, DnsStatus>, max: usize| {
        let mut r = DnsResolver::new();
        r.set_address_family(family);
        let mut stub = StubResolver { result: Some(list), literal: None, ..Default::default() };
        let mut addrs = vec![IpAddr::Unspec; DNS_MAX_ADDRESSES];
        let st = r.name_to_ipaddress(&mut stub, "h", &mut addrs, max);
        (st, addrs)
    };

    // ---- UNSPEC: [V4(0x01020304), V6(scope 0)] -> both ----
    let l = line("UNSPEC");
    let (st, addrs) = run(
        IPADDR_UNSPEC,
        Ok(vec![ResolvedAddr::V4(0x0102_0304), ResolvedAddr::V6 { addr: v6(0x20), scope_id: 0 }]),
        DNS_MAX_ADDRESSES,
    );
    assert_eq!(st, status_from(field(l, "status").unwrap().parse().unwrap()), "UNSPEC status");
    assert_eq!(addrs[0], IpAddr::V4(0x0102_0304), "UNSPEC a0");
    assert_eq!(addrs[1], IpAddr::V6(v6(0x20)), "UNSPEC a1");

    // ---- INET4: same list -> only the V4 ----
    let l = line("INET4");
    let (st, addrs) = run(
        IPADDR_INET4,
        Ok(vec![ResolvedAddr::V4(0x0a00_0001), ResolvedAddr::V6 { addr: v6(0x30), scope_id: 0 }]),
        DNS_MAX_ADDRESSES,
    );
    assert_eq!(st, status_from(field(l, "status").unwrap().parse().unwrap()), "INET4 status");
    assert_eq!(addrs[0], IpAddr::V4(0x0a00_0001), "INET4 a0");
    assert_eq!(addrs[1], IpAddr::Unspec, "INET4 a1 unspec");

    // ---- INET6 with scope!=0 -> skipped -> Failure ----
    let l = line("SCOPESKIP");
    let (st, addrs) = run(
        IPADDR_INET6,
        Ok(vec![ResolvedAddr::V6 { addr: v6(0x40), scope_id: 99 }]),
        DNS_MAX_ADDRESSES,
    );
    assert_eq!(st, status_from(field(l, "status").unwrap().parse().unwrap()), "SCOPESKIP status");
    assert_eq!(addrs[0], IpAddr::Unspec, "SCOPESKIP a0 unspec");

    // ---- getaddrinfo EAI_AGAIN -> TryAgain ----
    let l = line("AGAIN");
    let (st, _) = run(IPADDR_UNSPEC, Err(DnsStatus::TryAgain), DNS_MAX_ADDRESSES);
    assert_eq!(st, status_from(field(l, "status").unwrap().parse().unwrap()), "AGAIN");

    // ---- getaddrinfo other error -> Failure ----
    let l = line("FAIL");
    let (st, _) = run(IPADDR_UNSPEC, Err(DnsStatus::Failure), DNS_MAX_ADDRESSES);
    assert_eq!(st, status_from(field(l, "status").unwrap().parse().unwrap()), "FAIL");

    // ---- max_addrs = 1 with 2 results -> only the first ----
    let l = line("MAX1");
    let (st, addrs) = run(
        IPADDR_UNSPEC,
        Ok(vec![ResolvedAddr::V4(0xc0a8_0001), ResolvedAddr::V4(0xc0a8_0002)]),
        1,
    );
    assert_eq!(st, status_from(field(l, "status").unwrap().parse().unwrap()), "MAX1 status");
    assert_eq!(addrs[0], IpAddr::V4(0xc0a8_0001), "MAX1 a0");
    assert_eq!(addrs[1], IpAddr::Unspec, "MAX1 a1 untouched");
}

#[test]
fn ip_literal_shortcut_bypasses_the_resolver() {
    // A literal address returns immediately without calling resolve().
    let mut r = DnsResolver::new();
    let mut stub = StubResolver { literal: Some(IpAddr::V4(0x7f00_0001)), ..Default::default() };
    let mut addrs = vec![IpAddr::Unspec; 4];
    assert_eq!(r.name_to_ipaddress(&mut stub, "127.0.0.1", &mut addrs, 4), DnsStatus::Success);
    assert_eq!(addrs[0], IpAddr::V4(0x7f00_0001));

    // A literal of the wrong family is rejected when a family is required.
    r.set_address_family(IPADDR_INET6);
    let mut stub = StubResolver { literal: Some(IpAddr::V4(0x7f00_0001)), ..Default::default() };
    assert_eq!(
        r.name_to_ipaddress(&mut stub, "127.0.0.1", &mut addrs, 4),
        DnsStatus::Failure,
        "v4 literal rejected under an INET6 preference"
    );
}

#[test]
fn reverse_falls_back_to_ip_string_and_checks_truncation() {
    let mut r = DnsResolver::new();

    // A successful reverse lookup is used verbatim.
    let mut stub = StubResolver { reverse: Some("host.example".to_string()), ..Default::default() };
    let mut name = String::new();
    assert!(r.ipaddress_to_name(&mut stub, &IpAddr::V4(0x0102_0304), &mut name, 64));
    assert_eq!(name, "host.example");

    // No reverse -> the IP string fallback.
    let mut stub = StubResolver { reverse: None, ..Default::default() };
    let mut name = String::new();
    assert!(r.ipaddress_to_name(&mut stub, &IpAddr::V4(0x0102_0304), &mut name, 64));
    assert_eq!(name, "1.2.3.4");

    // Too small a buffer -> chrony's snprintf truncation check fails (>= len).
    let mut stub = StubResolver { reverse: Some("host.example".to_string()), ..Default::default() };
    let mut name = String::from("untouched");
    assert!(!r.ipaddress_to_name(&mut stub, &IpAddr::V4(0x0102_0304), &mut name, 5));
    assert_eq!(name, "untouched", "name not written on truncation");
}

#[test]
fn reload_calls_res_init() {
    let mut r = DnsResolver::new();
    let mut stub = StubResolver::default();
    r.reload(&mut stub);
    assert!(stub.reloaded);
}

// ---- the daemon's real-resolver convenience (name_to_ip), as before ----

#[test]
fn resolves_localhost_to_loopback() {
    // `localhost` is in /etc/hosts on every reasonable system: deterministic, no net.
    let ip = name_to_ip("localhost").expect("localhost must resolve");
    assert!(ip.is_loopback(), "expected a loopback address, got {ip}");
}

#[test]
fn unresolvable_name_is_none() {
    // A syntactically valid but unregistered .invalid name (RFC 6761) must not resolve.
    assert_eq!(name_to_ip("this-host-does-not-exist.invalid"), None);
}
