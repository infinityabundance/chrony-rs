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
fn matches_real_c_iteration_ops() {
    let v = include_str!("../../../../research/oracle/ntp_sources-iter-c-vectors.txt");
    let line = |tag: &str| lines(v, tag)[0];
    let v4 = |ip| RemoteAddr { ip: IpKey::V4(ip), port: 123 };

    // Build the oracle's table (insert order matters for slot layout).
    let mut t = SourceTable::new(SEED);
    for ip in [0x0a00_0001u32, 0x0a00_0002, 0x0a00_00ff, 0xc0a8_0001] {
        t.add_source(v4(ip), true, true);
    }

    // NSR_InitiateSampleBurst selection: matched addresses in slot order + any.
    let check_burst = |tag: &str, address: IpKey, mask: Option<IpKey>| {
        let l = line(tag);
        let (slots, any) = t.select_matching(address, mask);
        assert_eq!(any as i32, field(l, "any").parse::<i32>().unwrap(), "{tag} any");
        let hits: String = slots
            .iter()
            .map(|&s| match t.get(s).unwrap().ip { IpKey::V4(x) => format!("{x:08x},"), _ => String::new() })
            .collect();
        assert_eq!(hits, field(l, "hits"), "{tag} hits");
    };
    check_burst("BURST_ALL", IpKey::Unspec, Some(IpKey::V4(0)));
    check_burst("BURST_ONE", IpKey::V4(0x0a00_0002), Some(IpKey::V4(0xffff_ffff)));
    check_burst("BURST_SUBNET", IpKey::V4(0x0a00_0000), Some(IpKey::V4(0xffff_ff00)));
    check_burst("BURST_NONE", IpKey::V4(0x7f00_0001), Some(IpKey::V4(0xffff_ffff)));

    // NSR_GetLocalRefid: present -> NCR refid, absent -> 0.
    let refid_of = |r: RemoteAddr| match r.ip {
        IpKey::V4(x) => 0xfeed_0000 | (x & 0xff),
        _ => 0,
    };
    assert_eq!(
        t.get_local_refid(IpKey::V4(0x0a00_0002), refid_of),
        u32::from_str_radix(field(line("REFID_PRESENT"), "v"), 16).unwrap(),
        "refid present",
    );
    assert_eq!(
        t.get_local_refid(IpKey::V4(0x7f00_0001), refid_of),
        u32::from_str_radix(field(line("REFID_ABSENT"), "v"), 16).unwrap(),
        "refid absent",
    );

    // NSR_RemoveAllSources: empty table.
    t.remove_all();
    let l = line("REMOVEALL");
    assert_eq!(t.n_sources(), field(l, "nsources").parse::<u32>().unwrap(), "removeall nsources");
    assert_eq!(t.size() as u32, field(l, "size").parse::<u32>().unwrap(), "removeall size");
    assert_eq!(
        (0..t.size()).filter(|&s| t.get(s).is_some()).count() as i32,
        field(l, "occupied").parse::<i32>().unwrap(),
        "removeall occupied",
    );
}

#[test]
fn matches_real_c_set_connectivity() {
    let v = include_str!("../../../../research/oracle/ntp_sources-conn-c-vectors.txt");
    let line = |tag: &str| lines(v, tag)[0];
    let v4 = |ip| RemoteAddr { ip: IpKey::V4(ip), port: 123 };

    let mut t = SourceTable::new(SEED);
    for ip in [0x0a00_0001u32, 0x0a00_0002, 0x0a00_00ff, 0xc0a8_0001] {
        t.add_source(v4(ip), true, true);
    }

    let check = |tag: &str, address: IpKey, mask: Option<IpKey>, conn: SrcConnectivity, syncpeer: u32, unreal: u32| {
        let l = line(tag);
        let is_real = move |r: RemoteAddr| !matches!(r.ip, IpKey::V4(x) if x == unreal && unreal != 0);
        let is_syncpeer = move |r: RemoteAddr| matches!(r.ip, IpKey::V4(x) if x == syncpeer && syncpeer != 0);
        let (slots, any) = t.set_connectivity_order(address, mask, conn, is_real, is_syncpeer);
        assert_eq!(any as i32, field(l, "any").parse::<i32>().unwrap(), "{tag} any");
        let order: String = slots
            .iter()
            .map(|&s| match t.get(s).unwrap().ip { IpKey::V4(x) => format!("{x:08x},"), _ => String::new() })
            .collect();
        assert_eq!(order, field(l, "order"), "{tag} order");
    };
    use SrcConnectivity::*;
    check("SC_ALL", IpKey::Unspec, Some(IpKey::V4(0)), Offline, 0, 0);
    check("SC_SYNC", IpKey::Unspec, Some(IpKey::V4(0)), Offline, 0x0a00_0002, 0);
    check("SC_MAYBE_SKIP", IpKey::Unspec, Some(IpKey::V4(0)), MaybeOnline, 0, 0x0a00_00ff);
    check("SC_MAYBE_ALL", IpKey::Unspec, Some(IpKey::V4(0)), MaybeOnline, 0, 0);
    check("SC_SUBNET_SYNC", IpKey::V4(0x0a00_0000), Some(IpKey::V4(0xffff_ff00)), Offline, 0x0a00_0001, 0);
}

#[test]
fn matches_real_c_pool_and_reports() {
    let v = include_str!("../../../../research/oracle/ntp_sources-pool-c-vectors.txt");
    let line = |tag: &str| lines(v, tag)[0];
    let pool = |sources| SourcePool { sources, ..Default::default() };

    // get_unused_pool_id: first pool with sources == 0 (no pending names).
    let check_pool = |tag: &str, srcs: &[i32]| {
        let pools: Vec<SourcePool> = srcs.iter().map(|&s| pool(s)).collect();
        assert_eq!(get_unused_pool_id(&pools, &[]), field(line(tag), "id").parse::<i32>().unwrap(), "{tag}");
    };
    check_pool("POOLID_0", &[0, 5, 2]);
    check_pool("POOLID_1", &[3, 0, 2]);
    check_pool("POOLID_2", &[3, 5, 0]);
    check_pool("POOLID_NONE", &[1, 2, 3]);
    check_pool("POOLID_EMPTY", &[]);

    // Report fan-outs on a table with one source.
    let mut t = SourceTable::new(SEED);
    t.add_source(RemoteAddr { ip: IpKey::V4(0x0a00_0001), port: 123 }, true, true);
    assert_eq!(t.get_ntp_report(IpKey::V4(0x0a00_0001)) as i32, field(line("NTPREPORT_PRESENT"), "ret").parse::<i32>().unwrap());
    assert_eq!(t.get_ntp_report(IpKey::V4(0x7f00_0001)) as i32, field(line("NTPREPORT_ABSENT"), "ret").parse::<i32>().unwrap());
    // NCR_ReportSource fills poll with the marker 99.
    assert_eq!(t.report_source(IpKey::V4(0x0a00_0001), |_| 99), field(line("REPORTSRC_PRESENT"), "poll").parse::<i32>().unwrap());
    assert_eq!(t.report_source(IpKey::V4(0x7f00_0001), |_| 99), field(line("REPORTSRC_ABSENT"), "poll").parse::<i32>().unwrap());
}

#[test]
fn pool_id_skips_pending() {
    // A pool with no sources but a pending unresolved name is skipped.
    let pools = [SourcePool::default(), SourcePool::default()];
    assert_eq!(get_unused_pool_id(&pools, &[0]), 1, "pool 0 pending -> 1");
    assert_eq!(get_unused_pool_id(&pools, &[0, 1]), INVALID_POOL, "all pending");
    assert_eq!(get_unused_pool_id(&pools, &[]), 0, "none pending -> first");
}

#[test]
fn matches_real_c_is_resolved_and_name() {
    let v = include_str!("../../../../research/oracle/ntp_sources-misc-c-vectors.txt");
    let line = |tag: &str| lines(v, tag)[0];
    let v4 = |ip| RemoteAddr { ip: IpKey::V4(ip), port: 123 };

    let mut t = SourceTable::new(SEED);
    t.add_source(v4(0x0a00_0001), true, true);

    // NSR_GetName: present -> name, absent -> None (the name is supplied by the closure).
    let name_of = |_r: RemoteAddr| "x";
    let present = t.get_name(IpKey::V4(0x0a00_0001), name_of);
    assert_eq!(present.is_some() as i32, field(line("GETNAME_PRESENT"), "found").parse::<i32>().unwrap());
    assert_eq!(present, Some(field(line("GETNAME_PRESENT"), "name")));
    assert_eq!(
        t.get_name(IpKey::V4(0x7f00_0001), name_of).is_some() as i32,
        field(line("GETNAME_ABSENT"), "found").parse::<i32>().unwrap(),
    );

    // is_resolved, pool case (resolved once no unresolved sources remain).
    assert_eq!(is_resolved(0, 2, false) as i32, field(line("RESOLVED_POOL_PENDING"), "r").parse::<i32>().unwrap());
    assert_eq!(is_resolved(0, 0, false) as i32, field(line("RESOLVED_POOL_DONE"), "r").parse::<i32>().unwrap());

    // is_resolved, single-source case (resolved once the address is gone).
    let present = t.address_present(v4(0x0a00_0001));
    let absent = t.address_present(v4(0x7f00_0001));
    assert_eq!(is_resolved(INVALID_POOL, 0, present) as i32, field(line("RESOLVED_ADDR_PRESENT"), "r").parse::<i32>().unwrap());
    assert_eq!(is_resolved(INVALID_POOL, 0, absent) as i32, field(line("RESOLVED_ADDR_ABSENT"), "r").parse::<i32>().unwrap());
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

#[test]
fn process_rx_tx_routing_matches_real_c() {
    // Differential test of NSR_ProcessRx/Tx routing vs the REAL compiled ntp_sources.c
    // (/tmp/nsrc/genrx.c): a packet routes to the Known handler only when the mode gate passes
    // (Rx: not MODE_CLIENT; Tx: not MODE_SERVER) AND the address+port match a source.
    let v = include_str!("../../../../research/oracle/ntp_sources-route-c-vectors.txt");
    let known = "0a000001"; // matches (Both); "unknown_*" tags use a non-present address
    for l in v.lines().filter(|l| l.starts_with("RX ") || l.starts_with("TX ")) {
        let tag = field(l, "tag");
        let mode: u8 = field(l, "mode").parse().unwrap();
        let known_hits: i32 = field(l, "known").parse().unwrap();
        let unknown_hits: i32 = field(l, "unknown").parse().unwrap();
        let matched = tag.starts_with("known_"); // the address column (see genrx.c)
        let _ = known;
        let route = if l.starts_with("RX ") {
            process_rx_route(mode, matched)
        } else {
            process_tx_route(mode, matched)
        };
        // The C fires exactly one of Known/Unknown per call.
        let expected = if known_hits == 1 { RouteTarget::Known } else { RouteTarget::Unknown };
        assert_eq!(known_hits + unknown_hits, 1, "{tag} exactly one handler");
        assert_eq!(route, expected, "{}{tag}", if l.starts_with("RX "){"RX "}else{"TX "});
    }
}

#[test]
fn confirm_tentative_pool_source_bookkeeping() {
    // A tentative pooled source's first good reply confirms it; reaching max_sources signals the
    // pool's remaining tentative sources should be pruned.
    let mut pool = SourcePool { sources: 3, unresolved_sources: 0, confirmed_sources: 0, max_sources: 2 };
    assert!(!confirm_tentative_pool_source(&mut pool)); // 1 < 2
    assert_eq!(pool.confirmed_sources, 1);
    assert!(confirm_tentative_pool_source(&mut pool)); // 2 >= 2 -> prune remaining tentative
    assert_eq!(pool.confirmed_sources, 2);
}

#[test]
fn change_source_address_matches_real_c() {
    // Differential test of change_source_address (table part) vs the REAL compiled ntp_sources.c
    // (/tmp/nsrc/genchg.c): the NoSuchSource / AlreadyInUse validation (incl. the subtle
    // IP-used-by-another-source case) and the address move + rehash. Same insert sequence + seed.
    let v = include_str!("../../../../research/oracle/ntp_sources-change-c-vectors.txt");
    let addr = |ip: u32, port: u16| RemoteAddr { ip: IpKey::V4(ip), port };

    // Build the 8-slot table the oracle had (3 sources -> size 8), same addresses/ports.
    let mut t = SourceTable::with_size(SEED, 8);
    for ip in [0x0a00_0001u32, 0x0a00_0002, 0x0a00_0003] {
        t.insert(addr(ip, 123));
        t.set_n_sources(t.n_sources() + 1);
    }
    let ops: &[(&str, RemoteAddr, RemoteAddr)] = &[
        ("port_change", addr(0x0a00_0001, 123), addr(0x0a00_0001, 456)),
        ("new_addr", addr(0x0a00_0002, 123), addr(0x0c00_0009, 123)),
        ("already_inuse", addr(0x0a00_0003, 123), addr(0x0c00_0009, 123)),
        ("iponly_other", addr(0x0a00_0003, 123), addr(0x0c00_0009, 999)),
        ("no_such", addr(0x0e0e_0e0e, 123), addr(0x0f0f_0f0f, 123)),
    ];
    for (tag, old, new) in ops {
        let status = t.change_source_address(*old, *new);
        let l = v.lines().find(|l| l.starts_with("CHG ") && field(l, "tag") == *tag).unwrap();
        // status is a multi-word string; take everything between "status=" and " old_present=".
        let status_str = l.split("status=").nth(1).unwrap().split(" old_present=").next().unwrap();
        let exp_status = match status_str {
            "Success" => NsrStatus::Success,
            "No such source" => NsrStatus::NoSuchSource,
            "Already in use" => NsrStatus::AlreadyInUse,
            other => panic!("status {other:?}"),
        };
        assert_eq!(status, exp_status, "{tag} status");
        let old_present = t.find_slot2(*old).0 == Find2::Both;
        let new_present = t.find_slot2(*new).0 == Find2::Both;
        assert_eq!(old_present, field(l, "old_present") == "1", "{tag} old_present");
        assert_eq!(new_present, field(l, "new_present") == "1", "{tag} new_present");
    }
}

#[test]
fn change_address_pool_bookkeeping_matches_chrony() {
    // Unreal->real drops unresolved_sources; a previously-confirmed record decrements
    // confirmed_sources (it must re-prove after the address change).
    let mut pool = SourcePool { sources: 3, unresolved_sources: 2, confirmed_sources: 2, max_sources: 3 };
    change_address_pool_bookkeeping(&mut pool, false, true, false);
    assert_eq!((pool.unresolved_sources, pool.confirmed_sources), (1, 1));
    // real->real, still-tentative: no change.
    change_address_pool_bookkeeping(&mut pool, true, true, true);
    assert_eq!((pool.unresolved_sources, pool.confirmed_sources), (1, 1));
}

#[test]
fn update_source_ntp_address_matches_real_c() {
    // Differential test of NSR_UpdateSourceNtpAddress (non-record-locked) vs the REAL compiled
    // ntp_sources.c (/tmp/nsrc/genupd.c): the both-real InvalidAf gate, the find_slot (IP-only)
    // AlreadyInUse pre-check, the same-IP port-change pass-through, and the change dispatch.
    let v = include_str!("../../../../research/oracle/ntp_sources-update-c-vectors.txt");
    let addr = |ip: u32, port: u16| RemoteAddr { ip: IpKey::V4(ip), port };
    let status_of = |l: &str| -> NsrStatus {
        match l.split("status=").nth(1).unwrap().trim() {
            "Success" => NsrStatus::Success,
            "No such source" => NsrStatus::NoSuchSource,
            "Already in use" => NsrStatus::AlreadyInUse,
            "Invalid address" => NsrStatus::InvalidAf,
            other => panic!("status {other:?}"),
        }
    };

    let mut t = SourceTable::with_size(SEED, 8);
    for ip in [0x0a00_0001u32, 0x0a00_0002, 0x0a00_0003] {
        t.insert(addr(ip, 123));
        t.set_n_sources(t.n_sources() + 1);
    }
    // (tag, old, new, old_real, new_real)
    let ops: &[(&str, RemoteAddr, RemoteAddr, bool, bool)] = &[
        ("unreal_old", addr(0x0a00_0001, 123), addr(0x0c00_0009, 123), false, true),
        ("unreal_new", addr(0x0a00_0001, 123), addr(0x0c00_0009, 123), true, false),
        ("new_ip_used", addr(0x0a00_0001, 123), addr(0x0a00_0002, 123), true, true),
        ("port_change", addr(0x0a00_0001, 123), addr(0x0a00_0001, 456), true, true),
        ("new_ip_free", addr(0x0a00_0003, 123), addr(0x0c00_0009, 123), true, true),
        ("no_such", addr(0x0e0e_0e0e, 123), addr(0x0f0f_0f0f, 123), true, true),
    ];
    for (tag, old, new, or, nr) in ops {
        let status = t.update_source_ntp_address(*old, *new, *or, *nr);
        let l = v.lines().find(|l| l.starts_with("UPD ") && field(l, "tag") == *tag).unwrap();
        assert_eq!(status, status_of(l), "{tag}");
    }
}
