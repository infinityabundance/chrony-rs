//! Tests for `ntp_sources.c` source-table internals.
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_sources.c`.** The hash, the slot
//! probing on an 8-slot table (built by the same insert sequence), the sizing rule, the
//! status strings, and the conf-id counter are captured via the `#include` harness with
//! real `array.c` and the random seed pinned to `0x01010101`
//! (`/tmp/nsrc/gents.c`, `research/oracle/ntp_sources-table-c-vectors.txt`).
//!
//! **Oracle #2 (independent): the addressing invariants.** Quadratic probing, the
//! load-factor rule, and IP/port matching are checked directly.

use super::*;

const SEED: u32 = 0x0101_0101;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}
fn lines<'a>(v: &'a str, tag: &str) -> Vec<&'a str> {
    v.lines().map(str::trim).filter(|l| l.starts_with(tag)).collect()
}

/// Rebuild the oracle's 8-slot table with the same insert sequence.
fn built_table() -> SourceTable {
    let mut t = SourceTable::with_size(SEED, 8);
    t.insert(RemoteAddr { ip: IpKey::V4(0x0a00_0001), port: 123 });
    t.insert(RemoteAddr { ip: IpKey::V4(0x0a00_0002), port: 123 });
    t.insert(RemoteAddr { ip: IpKey::V4(0x0a00_0003), port: 200 });
    t.insert(RemoteAddr { ip: IpKey::V4(0xc0a8_0001), port: 123 });
    t
}

#[test]
fn matches_real_c_source_table() {
    let v = include_str!("../../../../research/oracle/ntp_sources-table-c-vectors.txt");

    // Status strings.
    for l in lines(v, "STATUS ") {
        let code: u32 = l.split_whitespace().nth(1).unwrap().split('=').next().unwrap().parse().unwrap();
        let want = l.splitn(2, '=').nth(1).unwrap();
        let status = match code {
            0 => NsrStatus::Success,
            1 => NsrStatus::NoSuchSource,
            2 => NsrStatus::AlreadyInUse,
            3 => NsrStatus::TooManySources,
            4 => NsrStatus::InvalidAf,
            5 => NsrStatus::InvalidName,
            6 => NsrStatus::UnresolvedName,
            other => panic!("status {other}"),
        };
        assert_eq!(status_to_string(status), want, "status {code}");
    }

    // Hashtable sizing.
    for l in lines(v, "HTS ") {
        let ok = check_hashtable_size(field(l, "sources").parse().unwrap(), field(l, "size").parse().unwrap());
        assert_eq!(ok as i32, field(l, "ok").parse::<i32>().unwrap(), "{l}");
    }

    // Conf-id counter (lines are "CONFID i=val").
    let mut alloc = ConfIdAllocator::default();
    for l in lines(v, "CONFID ") {
        let want: u32 = l.rsplit('=').next().unwrap().parse().unwrap();
        assert_eq!(alloc.allocate(), want, "{l}");
    }

    // Seeded hash.
    for l in lines(v, "HASH ") {
        let ip = u32::from_str_radix(field(l, "ip"), 16).unwrap();
        assert_eq!(ip_to_hash(SEED, IpKey::V4(ip)), field(l, "hash").parse::<u32>().unwrap(), "{l}");
    }

    // find_slot on the built table.
    let t = built_table();
    for l in lines(v, "FINDSLOT ") {
        let ip = u32::from_str_radix(field(l, "ip"), 16).unwrap();
        let (found, slot) = t.find_slot(IpKey::V4(ip));
        assert_eq!(found as i32, field(l, "found").parse::<i32>().unwrap(), "{l} found");
        assert_eq!(slot as i32, field(l, "slot").parse::<i32>().unwrap(), "{l} slot");
    }

    // find_slot2 (IP + port).
    for l in lines(v, "FINDSLOT2 ") {
        let ip = u32::from_str_radix(field(l, "ip"), 16).unwrap();
        let port: u16 = field(l, "port").parse().unwrap();
        let (r, slot) = t.find_slot2(RemoteAddr { ip: IpKey::V4(ip), port });
        let r_code = match r {
            Find2::NoMatch => 0,
            Find2::IpOnly => 1,
            Find2::Both => 2,
        };
        assert_eq!(r_code, field(l, "r").parse::<i32>().unwrap(), "{l} r");
        assert_eq!(slot as i32, field(l, "slot").parse::<i32>().unwrap(), "{l} slot");
    }
}

#[test]
fn probing_and_matching_invariants() {
    // Load factor: sources*2 <= size.
    assert!(check_hashtable_size(4, 8));
    assert!(!check_hashtable_size(4, 4));
    assert!(check_hashtable_size(0, 1));

    let mut t = SourceTable::with_size(SEED, 8);
    let a = RemoteAddr { ip: IpKey::V4(0x0a00_0001), port: 123 };
    let s = t.insert(a);
    // Present IP matches; an absent one returns an empty slot.
    assert_eq!(t.find_slot(a.ip), (true, s));
    assert!(!t.find_slot(IpKey::V4(0xdead_beef)).0);
    // Port discrimination.
    assert_eq!(t.find_slot2(a).0, Find2::Both);
    assert_eq!(t.find_slot2(RemoteAddr { ip: a.ip, port: 999 }).0, Find2::IpOnly);
    assert_eq!(t.find_slot2(RemoteAddr { ip: IpKey::V4(0xdead_beef), port: 123 }).0, Find2::NoMatch);
}
