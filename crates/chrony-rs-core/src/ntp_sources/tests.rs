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
        let ok = check_hashtable_size(field(l, "sources").parse::<u32>().unwrap(), field(l, "size").parse().unwrap());
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
fn matches_real_c_rehash() {
    let v = include_str!("../../../../research/oracle/ntp_sources-table-c-vectors.txt");
    // Each REHASH line: "tag size=N slot:iphex slot:iphex ...". Rebuild the same
    // pre-rehash table, rehash on the given n_sources, and match the resulting layout.
    let scenarios: &[(&str, usize, u32, &[u32])] = &[
        ("REHASH_GROW", 8, 5, &[0x0a00_0001, 0x0a00_0002, 0x0a00_0003, 0x0a00_0004]),
        ("REHASH_SAME", 8, 3, &[0x0a00_0001, 0x0a00_0002, 0x0a00_0003]),
        ("REHASH_GROW2", 4, 3, &[0x0a00_0001, 0x0a00_0002]),
    ];
    for (tag, start_size, n_sources, ips) in scenarios {
        let l = lines(v, tag)[0];
        let mut toks = l.split_whitespace();
        toks.next(); // tag
        let want_size: usize = toks.next().unwrap().strip_prefix("size=").unwrap().parse().unwrap();

        let mut t = SourceTable::with_size(SEED, *start_size);
        for &ip in *ips {
            t.insert(RemoteAddr { ip: IpKey::V4(ip), port: 123 });
        }
        t.rehash(*n_sources);

        assert_eq!(t.size(), want_size, "{tag} size");
        // Build the expected slot->ip map from the fixture and compare every slot.
        let mut expected = vec![None; want_size];
        for tok in toks {
            let (slot, ip) = tok.split_once(':').unwrap();
            expected[slot.parse::<usize>().unwrap()] = Some(u32::from_str_radix(ip, 16).unwrap());
        }
        for slot in 0..want_size {
            assert_eq!(t.get(slot).map(|r| match r.ip { IpKey::V4(v) => v, _ => 0 }), expected[slot], "{tag} slot {slot}");
        }
    }
}

#[test]
fn rehash_grows_and_preserves_records() {
    let mut t = SourceTable::with_size(SEED, 4);
    let addrs = [
        RemoteAddr { ip: IpKey::V4(0x0a00_0001), port: 123 },
        RemoteAddr { ip: IpKey::V4(0x0a00_0002), port: 123 },
    ];
    for a in addrs {
        t.insert(a);
    }
    // 5 sources need a 16-slot table (2*5 <= 16, not <= 8).
    t.rehash(5);
    assert_eq!(t.size(), 16);
    // Every record is still findable after the rehash.
    for a in addrs {
        assert!(t.find_slot(a.ip).0, "record survived rehash");
    }
}

fn status_code(s: NsrStatus) -> i32 {
    match s {
        NsrStatus::Success => 0,
        NsrStatus::NoSuchSource => 1,
        NsrStatus::AlreadyInUse => 2,
        NsrStatus::TooManySources => 3,
        NsrStatus::InvalidAf => 4,
        NsrStatus::InvalidName => 5,
        NsrStatus::UnresolvedName => 6,
    }
}

#[test]
fn matches_real_c_add_source() {
    let v = include_str!("../../../../research/oracle/ntp_sources-add-c-vectors.txt");
    let line = |tag: &str| lines(v, tag)[0];

    // Reproduce each scenario and assert status + n_sources + size + slot.
    let check = |t: &mut SourceTable, tag: &str, addr: RemoteAddr, has_name: bool, real: bool| {
        let l = line(tag);
        let s = t.add_source(addr, has_name, real);
        assert_eq!(status_code(s), field(l, "status").parse::<i32>().unwrap(), "{tag} status");
        assert_eq!(t.n_sources(), field(l, "nsources").parse::<u32>().unwrap(), "{tag} nsources");
        assert_eq!(t.size() as u32, field(l, "size").parse::<u32>().unwrap(), "{tag} size");
        let slot = match t.find_slot(addr.ip) {
            (true, s) => s as i32,
            _ => -1,
        };
        assert_eq!(slot, field(l, "slot").parse::<i32>().unwrap(), "{tag} slot");
    };
    let v4 = |ip| RemoteAddr { ip: IpKey::V4(ip), port: 123 };

    // ADD_OK
    let mut t = SourceTable::new(SEED);
    check(&mut t, "ADD_OK", v4(0x0a00_0001), true, true);

    // ADD_FIRST then ADD_DUP on the same table.
    let mut t = SourceTable::new(SEED);
    check(&mut t, "ADD_FIRST", v4(0x0a00_0001), true, true);
    check(&mut t, "ADD_DUP", v4(0x0a00_0001), true, true);

    // ADD_INVALIDNAME: unreal address, no name.
    let mut t = SourceTable::new(SEED);
    check(&mut t, "ADD_INVALIDNAME", v4(0x0a00_0001), false, false);

    // ADD_INVALIDAF: unspecified family, with a name.
    let mut t = SourceTable::new(SEED);
    check(&mut t, "ADD_INVALIDAF", RemoteAddr { ip: IpKey::Unspec, port: 123 }, true, true);

    // ADD_TOOMANY: source count already at the maximum.
    let mut t = SourceTable::new(SEED);
    t.set_n_sources(MAX_SOURCES);
    check(&mut t, "ADD_TOOMANY", v4(0x0a00_0001), true, true);

    // Growth: 5 sources into one table.
    let mut t = SourceTable::new(SEED);
    for (i, ip) in [0x0a00_0001u32, 0x0a00_0002, 0x0a00_0003, 0x0a00_0004, 0x0a00_0005].iter().enumerate() {
        check(&mut t, &format!("ADD_G{i}"), v4(*ip), true, true);
    }

    // NSR_Modify* dispatch: present -> found, absent -> not found (every variant shares
    // this find_slot + NCR_Modify* body, so one dispatch covers them all).
    let mut t = SourceTable::new(SEED);
    t.add_source(v4(0x0a00_0001), true, true);
    assert_eq!(
        t.modify_source(IpKey::V4(0x0a00_0001), |_| {}) as i32,
        field(line("MODIFY_PRESENT"), "ret").parse::<i32>().unwrap(),
        "modify present",
    );
    assert_eq!(
        t.modify_source(IpKey::V4(0x0a00_0001), |_| {}) as i32,
        1,
        "MODIFY_ABSENT line documents the absent path",
    );
    assert_eq!(field(line("MODIFY_ABSENT"), "ret").parse::<i32>().unwrap(), 0);
    // Each NSR_Modify* variant returns found for present, not-found for absent.
    for tag in [
        "MOD_minpoll", "MOD_maxpoll", "MOD_maxdelay", "MOD_maxdelayratio",
        "MOD_maxdelaydevratio", "MOD_minstratum", "MOD_polltarget",
    ] {
        let l = line(tag);
        assert_eq!(t.modify_source(IpKey::V4(0x0a00_0001), |_| {}) as i32, field(l, "p").parse::<i32>().unwrap(), "{tag} present");
        assert_eq!(t.modify_source(IpKey::V4(0x0a00_00ff), |_| {}) as i32, field(l, "x").parse::<i32>().unwrap(), "{tag} absent");
    }
}

#[test]
fn add_source_validation_order() {
    let v4 = |ip| RemoteAddr { ip: IpKey::V4(ip), port: 123 };

    // Duplicate beats every later check.
    let mut t = SourceTable::new(SEED);
    assert_eq!(t.add_source(v4(1), true, true), NsrStatus::Success);
    assert_eq!(t.add_source(v4(1), true, true), NsrStatus::AlreadyInUse);

    // Unreal address without a name is rejected; with a name it is accepted.
    let mut t = SourceTable::new(SEED);
    assert_eq!(t.add_source(v4(2), false, false), NsrStatus::InvalidName);
    assert_eq!(t.add_source(v4(2), true, false), NsrStatus::Success);

    // Invalid family.
    let mut t = SourceTable::new(SEED);
    assert_eq!(t.add_source(RemoteAddr { ip: IpKey::Unspec, port: 0 }, true, true), NsrStatus::InvalidAf);

    // Too many sources (count beats the family check).
    let mut t = SourceTable::new(SEED);
    t.set_n_sources(MAX_SOURCES);
    assert_eq!(t.add_source(v4(3), true, true), NsrStatus::TooManySources);
}

#[test]
fn matches_real_c_removal_and_pools() {
    let v = include_str!("../../../../research/oracle/ntp_sources-rm-c-vectors.txt");
    let line = |tag: &str| lines(v, tag)[0];
    let v4 = |ip| RemoteAddr { ip: IpKey::V4(ip), port: 123 };
    let status_code = |s: NsrStatus| match s {
        NsrStatus::Success => 0,
        NsrStatus::NoSuchSource => 1,
        _ => 99,
    };

    // Table-level removal on a 3-source table.
    let mut t = SourceTable::new(SEED);
    for ip in [0x0a00_0001u32, 0x0a00_0002, 0x0a00_0003] {
        t.add_source(v4(ip), true, true);
    }
    let check_rm = |t: &mut SourceTable, tag: &str, ip: u32| {
        let l = line(tag);
        let s = t.remove_source(IpKey::V4(ip));
        assert_eq!(status_code(s), field(l, "status").parse::<i32>().unwrap(), "{tag} status");
        assert_eq!(t.n_sources(), field(l, "nsources").parse::<u32>().unwrap(), "{tag} nsources");
        assert_eq!(t.size() as u32, field(l, "size").parse::<u32>().unwrap(), "{tag} size");
        let remain: String = (0..t.size())
            .filter_map(|s| t.get(s))
            .map(|r| match r.ip { IpKey::V4(v) => format!("{v:08x},"), _ => String::new() })
            .collect();
        assert_eq!(remain, field(l, "remain"), "{tag} remain");
    };
    check_rm(&mut t, "RM_PRESENT", 0x0a00_0002);
    check_rm(&mut t, "RM_ABSENT", 0x0a00_00ff);
    check_rm(&mut t, "RM_PRESENT2", 0x0a00_0001);
    check_rm(&mut t, "RM_LAST", 0x0a00_0003);

    // Pool-counter bookkeeping (pre-set 5/2/3/5, observe each branch's decrement).
    let pool = || SourcePool { sources: 5, unresolved_sources: 2, confirmed_sources: 3, max_sources: 5 };
    let check_pool = |tag: &str, is_real: bool, tentative: bool, mut p: SourcePool| {
        p.on_remove(is_real, tentative);
        let l = line(tag);
        assert_eq!(p.sources, field(l, "sources").parse::<i32>().unwrap(), "{tag} sources");
        assert_eq!(p.unresolved_sources, field(l, "unresolved").parse::<i32>().unwrap(), "{tag} unresolved");
        assert_eq!(p.confirmed_sources, field(l, "confirmed").parse::<i32>().unwrap(), "{tag} confirmed");
        assert_eq!(p.max_sources, field(l, "max").parse::<i32>().unwrap(), "{tag} max");
    };
    check_pool("POOL_REAL_TENTATIVE", true, true, pool());
    check_pool("POOL_CONFIRMED", true, false, pool());
    check_pool("POOL_UNRESOLVED", false, true, pool());
    check_pool("POOL_NOCLAMP", true, true, SourcePool { max_sources: 2, ..pool() });
}

#[test]
fn remove_round_trip() {
    let mut t = SourceTable::new(SEED);
    let v4 = |ip| RemoteAddr { ip: IpKey::V4(ip), port: 123 };
    for ip in [1u32, 2, 3] {
        t.add_source(v4(ip), true, true);
    }
    assert_eq!(t.n_sources(), 3);
    // Removing an absent source is a no-op error.
    assert_eq!(t.remove_source(IpKey::V4(99)), NsrStatus::NoSuchSource);
    assert_eq!(t.n_sources(), 3);
    // Remove all; the table empties and the remaining stay findable until removed.
    assert_eq!(t.remove_source(IpKey::V4(2)), NsrStatus::Success);
    assert!(t.find_slot(IpKey::V4(1)).0 && t.find_slot(IpKey::V4(3)).0);
    assert!(!t.find_slot(IpKey::V4(2)).0);
    assert_eq!(t.n_sources(), 2);
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
