//! Tests for `sources.c` Stage 1 (the registry / reachability / status machinery).
//!
//! **Oracle #1 (gold standard): the real compiled `sources.c`** (+ the ported
//! `memory.c`, with `SST_*`/`REF_*`/`LCL_*`/`SCH_*`/`NSR_*` stubbed so the triggered
//! `SRC_SelectSource` is a no-op). A C generator drives the registry over a refclock
//! source and records the reachability-register evolution (read back via
//! `SRC_ReportSource`), the bad-source trigger, and the special-mode-end
//! `REF_SetUnsynchronised` trigger (`research/oracle/sources-c-vectors.txt`).
//! [`matches_real_c_sources_stage1_vectors`] replays the identical calls through
//! [`SourceRegistry`] and matches every register value and trigger.
//!
//! **Oracle #2 (independent): the leap-vote majority + the NTP bad-source path.** The
//! `get_leap_status` majority vote and the NTP-only `handle_bad_source` trigger after
//! 8 consecutive misses are unit-tested.

use super::*;

/// A recording [`SourcesHost`].
#[derive(Default)]
struct RecHost {
    leap_close: bool,
    mode_normal: bool,
    precision: f64,
    bad_calls: Vec<usize>,
    unsync_calls: i32,
    select_calls: i32,
    leap_updates: Vec<NtpLeap>,
}

impl SourcesHost for RecHost {
    fn ref_is_leap_second_close(&mut self, _ts: Option<f64>, _offset: f64) -> bool {
        self.leap_close
    }
    fn ref_update_leap_status(&mut self, leap: NtpLeap) {
        self.leap_updates.push(leap);
    }
    fn ref_mode_is_normal(&mut self) -> bool {
        self.mode_normal
    }
    fn ref_set_unsynchronised(&mut self) {
        self.unsync_calls += 1;
    }
    fn nsr_handle_bad_source(&mut self, index: usize) {
        self.bad_calls.push(index);
    }
    fn select_source(&mut self) {
        self.select_calls += 1;
    }
    fn precision(&mut self) -> f64 {
        self.precision
    }
}

impl RecHost {
    fn normal() -> RecHost {
        RecHost { mode_normal: true, ..Default::default() }
    }
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}

fn refclock(reg: &mut SourceRegistry, ref_id: u32) -> usize {
    reg.create_new_instance(ref_id, SrcType::Refclock, false, 0, false, 6, 16, 0.0, 0.0)
}

#[test]
fn matches_real_c_sources_stage1_vectors() {
    let vectors = include_str!("../../../../../research/oracle/sources-c-vectors.txt");
    let lines: Vec<&str> = vectors.lines().map(str::trim).collect();
    let find = |p: &str| *lines.iter().find(|l| l.starts_with(p)).unwrap();

    let mut host = RecHost::normal();
    let mut reg = SourceRegistry::new();
    let s = refclock(&mut reg, 0x5245_4643);
    reg.set_active(s);

    // ---- reachability register evolution ----
    assert_eq!(reg.source(s).reachability, field(find("REACH_START"), "reach").parse::<u32>().unwrap());
    let pattern = [1, 1, 0, 1, 0, 0, 1, 1, 1, 0];
    for (i, &bit) in pattern.iter().enumerate() {
        reg.update_reachability(&mut host, s, bit != 0);
        let l = lines.iter().find(|l| l.starts_with(&format!("REACH i={i} "))).unwrap();
        assert_eq!(
            reg.source(s).reachability,
            field(l, "reach").parse::<u32>().unwrap(),
            "register at step {i}"
        );
    }

    // ---- bad-source trigger: a refclock never calls NSR (NTP-only) ----
    reg.update_reachability(&mut host, s, true);
    host.bad_calls.clear();
    for _ in 0..8 {
        reg.update_reachability(&mut host, s, false);
    }
    let bl = find("BADSRC");
    assert_eq!(host.bad_calls.len() as i32, field(bl, "nsr_bad_calls").parse::<i32>().unwrap());
    assert_eq!(reg.source(s).reachability, field(bl, "reach").parse::<u32>().unwrap());

    // ---- special-mode end -> REF_SetUnsynchronised ----
    let mut host2 = RecHost { mode_normal: false, ..Default::default() };
    let mut reg2 = SourceRegistry::new();
    let a = refclock(&mut reg2, 0x5245_4643);
    let b = refclock(&mut reg2, 0x5245_4344);
    reg2.set_active(a);
    reg2.set_active(b);
    for _ in 0..8 {
        reg2.update_reachability(&mut host2, a, false);
        reg2.update_reachability(&mut host2, b, false);
    }
    let want = field(find("SPECIAL"), "ref_unsync_calls_ge1") == "1";
    assert_eq!(host2.unsync_calls >= 1, want, "special-mode unsync trigger");
}

#[test]
fn leap_vote_majority() {
    // get_leap_status: accept a leap only if more than half of the voting sources agree.
    let mut reg = SourceRegistry::new();
    let ids = [1u32, 2, 3, 4, 5];
    for id in ids {
        refclock(&mut reg, id);
    }

    // Helper to set a source's vote/leap directly (test-only access to fields).
    let set = |reg: &mut SourceRegistry, i: usize, vote: bool, leap: NtpLeap| {
        let s = reg.source_mut(i);
        s.leap_vote = vote;
        s.leap = leap;
    };

    // 3 voters: 2 insert, 1 normal -> 2 > 3/2(=1) -> InsertSecond.
    set(&mut reg, 0, true, NtpLeap::InsertSecond);
    set(&mut reg, 1, true, NtpLeap::InsertSecond);
    set(&mut reg, 2, true, NtpLeap::Normal);
    assert_eq!(reg.leap_status(), NtpLeap::InsertSecond);

    // Add 2 more normal voters: 2 insert of 5 -> 2 > 5/2(=2)? no -> Normal.
    set(&mut reg, 3, true, NtpLeap::Normal);
    set(&mut reg, 4, true, NtpLeap::Normal);
    assert_eq!(reg.leap_status(), NtpLeap::Normal);

    // Delete-second majority.
    set(&mut reg, 0, true, NtpLeap::DeleteSecond);
    set(&mut reg, 1, true, NtpLeap::DeleteSecond);
    set(&mut reg, 2, true, NtpLeap::DeleteSecond);
    set(&mut reg, 3, false, NtpLeap::Normal);
    set(&mut reg, 4, false, NtpLeap::Normal);
    assert_eq!(reg.leap_status(), NtpLeap::DeleteSecond);
}

#[test]
fn ntp_bad_source_fires_after_eight_misses() {
    // An NTP source whose register reaches 0 with a full size triggers NSR exactly once.
    let mut host = RecHost::normal();
    let mut reg = SourceRegistry::new();
    let s = reg.create_new_instance(0x0a00_0001, SrcType::Ntp, false, 0, true, 6, 16, 0.0, 0.0);
    reg.set_active(s);

    // Saturate the register size with reachable, then 8 consecutive misses -> reach 0.
    for _ in 0..8 {
        reg.update_reachability(&mut host, s, true);
    }
    host.bad_calls.clear();
    for _ in 0..8 {
        reg.update_reachability(&mut host, s, false);
    }
    assert_eq!(reg.source(s).reachability, 0);
    assert_eq!(host.bad_calls, vec![s], "NTP bad source handled once at reach==0, size==8");
}

#[test]
fn update_sel_options_applies_authselect_policy() {
    // PREFER: when an authenticated NTP source exists, unauthenticated NTP sources
    // get the NOSELECT option added; authenticated ones are untouched.
    let mut reg = SourceRegistry::new();
    let auth = reg.create_new_instance(1, SrcType::Ntp, true, 0, true, 6, 16, 0.0, 0.0);
    let unauth = reg.create_new_instance(2, SrcType::Ntp, false, 0, true, 6, 16, 0.0, 0.0);
    let refclk = reg.create_new_instance(3, SrcType::Refclock, false, 0, false, 6, 16, 0.0, 0.0);

    let opts = reg.update_sel_options(AuthSelectMode::Prefer);
    assert_eq!(opts[auth], 0, "authenticated NTP unchanged");
    assert_eq!(opts[unauth], SRC_SELECT_NOSELECT, "unauthenticated NTP gets NOSELECT");
    assert_eq!(opts[refclk], 0, "refclock unchanged under PREFER");

    // MIX: with both auth and unauth NTP present, auth NTP + refclocks gain REQUIRE|TRUST.
    let opts = reg.update_sel_options(AuthSelectMode::Mix);
    assert_eq!(opts[auth], SRC_SELECT_REQUIRE | SRC_SELECT_TRUST);
    assert_eq!(opts[unauth], 0, "unauthenticated NTP untouched under MIX");
    assert_eq!(opts[refclk], SRC_SELECT_REQUIRE | SRC_SELECT_TRUST);

    // IGNORE: nothing added.
    let opts = reg.update_sel_options(AuthSelectMode::Ignore);
    assert_eq!(opts, vec![0, 0, 0]);

    // REQUIRE: all unauthenticated NTP get NOSELECT regardless of auth presence.
    let opts = reg.update_sel_options(AuthSelectMode::Require);
    assert_eq!(opts[unauth], SRC_SELECT_NOSELECT);
}

#[test]
fn accumulate_sample_drops_around_leap_and_status_updates_leap() {
    let mut host = RecHost { mode_normal: true, precision: 1.0e-9, ..Default::default() };
    let mut reg = SourceRegistry::new();
    let s = refclock(&mut reg, 0x5245_4643);

    // A sample near a leap second is dropped.
    host.leap_close = true;
    let sample = crate::samplefilt::NtpSample {
        time: 2_000_000_000.0,
        offset: 0.001,
        peer_delay: 0.0,
        peer_dispersion: 0.0,
        root_delay: 0.0,
        root_dispersion: 0.0,
    };
    assert!(!reg.accumulate_sample(&mut host, s, &sample), "dropped near leap");

    // UpdateStatus with leap_vote set propagates a leap-status update.
    reg.source_mut(s).leap_vote = true;
    host.leap_close = false;
    reg.update_status(&mut host, s, 2, NtpLeap::InsertSecond);
    assert_eq!(reg.source(s).stratum, 2);
    assert_eq!(host.leap_updates, vec![NtpLeap::InsertSecond]);
}
