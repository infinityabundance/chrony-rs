//! Tests for `ntp_core.c` Stage 5 (`check_sync_loop`, test D).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** The static
//! `check_sync_loop` is reached by `#include`-ing the translation unit into a C
//! generator (`/tmp/ncor/gencsl.c`) with the `REF`/`NIO`/refid inputs made controllable
//! and the small `UTI_*` codecs kept real. Every scenario emits the captured inputs (as
//! this port consumes them) and the C return value
//! (`research/oracle/ntp_core-syncloop-c-vectors.txt`).
//! [`matches_real_c_sync_loop_vectors`] replays the identical inputs and matches the
//! decision in every case.
//!
//! **Oracle #2 (independent): the gate + branch structure.** The serving-time gate and
//! the two loop-detection branches are checked directly at their decision boundaries.

use super::*;

fn u<T: std::str::FromStr>(line: &str, key: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn matches_real_c_sync_loop_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-syncloop-c-vectors.txt");
    for l in vectors.lines().map(str::trim).filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let got = check_sync_loop(
            u::<i32>(l, "socket") != 0,
            u::<i32>(l, "refmode") == 0, // chrony: REF_GetMode() == REF_ModeNormal (0)
            u::<i32>(l, "stratum"),
            u::<u32>(l, "msg_refid"),
            u::<u32>(l, "local_refid"),
            u::<i32>(l, "our_stratum"),
            u::<u32>(l, "our_refid"),
            u::<u32>(l, "msg_rd"),
            u::<u32>(l, "our_rd"),
            u::<u64>(l, "msg_ts"),
            u::<u64>(l, "our_ts"),
        );
        let want = u::<i32>(l, "ret") != 0;
        let tag = l.split_whitespace().next().unwrap();
        assert_eq!(got, want, "{tag}: rust={got} c={want}");
    }
}

#[test]
fn serving_time_gate_and_branches() {
    // Inputs that would otherwise be detected as "it is me".
    let me = |socket, normal| {
        check_sync_loop(socket, normal, 2, 1, 99, 2, 1, 656, 656, 0xdead_beef, 0xdead_beef)
    };
    // Not serving -> always safe regardless of a matching identity.
    assert!(me(false, true), "no socket");
    assert!(me(true, false), "not normal");
    // Serving + exact identity match -> loop (it is us).
    assert!(!me(true, true), "is me");

    // Synced-to-our-address: stratum>1 and refid == local refid.
    assert!(!check_sync_loop(true, true, 3, 42, 42, 9, 7, 0, 0, 0, 0), "synced to us");
    // Stratum 1 with the same refid does NOT trip the address branch.
    assert!(check_sync_loop(true, true, 1, 42, 42, 9, 7, 0, 0, 0, 0), "stratum 1 ok");

    // Identity match but zero reference timestamp -> not us.
    assert!(check_sync_loop(true, true, 2, 1, 99, 2, 1, 656, 656, 0, 0), "zero ts");
    // Identity match but differing reference timestamp -> not us.
    assert!(check_sync_loop(true, true, 2, 1, 99, 2, 1, 656, 656, 0xaa, 0xab), "diff ts");
    // Identity match but differing root delay -> not us.
    assert!(check_sync_loop(true, true, 2, 1, 99, 2, 1, 656, 657, 0xaa, 0xaa), "diff rd");
}
