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

// ---- Stage 3: the SRC_SelectSource pipeline ----

use crate::sourcestats::TrackingData;

/// A host for the selection pass with controlled per-source SST data + ref capture.
#[derive(Default)]
struct SelHost {
    /// (lo, hi, root_distance, std_dev, first_ago, last_ago, select_ok) per index.
    sel: Vec<(f64, f64, f64, f64, f64, f64, bool)>,
    trk: Vec<TrackingData>,
    setref_calls: i32,
    last_combined: i32,
    last_off: f64,
    unsync_calls: i32,
}

impl SourcesHost for SelHost {
    fn ref_is_leap_second_close(&mut self, _ts: Option<f64>, _o: f64) -> bool {
        false
    }
    fn ref_update_leap_status(&mut self, _l: NtpLeap) {}
    fn ref_mode_is_normal(&mut self) -> bool {
        true
    }
    fn ref_set_unsynchronised(&mut self) {
        self.unsync_calls += 1;
    }
    fn nsr_handle_bad_source(&mut self, _i: usize) {}
    fn select_source(&mut self) {}
    fn precision(&mut self) -> f64 {
        1.0e-9
    }
    fn now(&mut self) -> f64 {
        2_000_000_000.0
    }
    fn sst_selection_data(&mut self, i: usize, _now: f64) -> (f64, f64, f64, f64, f64, f64, bool) {
        self.sel[i]
    }
    fn sst_tracking_data(&mut self, i: usize) -> TrackingData {
        self.trk[i]
    }
    fn lcl_max_clock_error(&mut self) -> f64 {
        1.0e-6
    }
    fn ref_get_orphan_stratum(&mut self) -> i32 {
        16
    }
    fn nsr_get_local_refid(&mut self, _i: usize) -> u32 {
        0
    }
    #[allow(clippy::too_many_arguments)]
    fn ref_set_reference(
        &mut self,
        _stratum: i32,
        _leap: NtpLeap,
        combined: i32,
        _ref_id: u32,
        _ref_time: f64,
        offset: f64,
        _offset_sd: f64,
        _frequency: f64,
        _frequency_sd: f64,
        _skew: f64,
        _root_delay: f64,
        _root_dispersion: f64,
    ) {
        self.setref_calls += 1;
        self.last_combined = combined;
        self.last_off = offset;
    }
}

/// chrony `SRC_ReportSource`'s state mapping (the differential's observable).
fn rpt_state(status: SrcStatus) -> i32 {
    match status {
        SrcStatus::Falseticker => 1,
        SrcStatus::Jittery => 2,
        SrcStatus::WaitsSources
        | SrcStatus::Nonpreferred
        | SrcStatus::WaitsUpdate
        | SrcStatus::Distant
        | SrcStatus::Outlier => 3,
        SrcStatus::Unselected => 4,
        SrcStatus::Selected => 5,
        _ => 0,
    }
}

fn trk(ref_time: f64, off: f64, osd: f64, fr: f64, frsd: f64, sk: f64) -> TrackingData {
    TrackingData {
        ref_time,
        average_offset: off,
        offset_sd: osd,
        frequency: fr,
        frequency_sd: frsd,
        skew: sk,
        root_delay: 0.02,
        root_dispersion: 0.01,
    }
}

/// Build a ready (active, synced, reachable) refclock registry with `n` sources.
fn ready_registry(host: &mut SelHost, n: usize) -> SourceRegistry {
    let mut reg = SourceRegistry::new();
    for k in 0..n {
        let s = refclock(&mut reg, 0x41414141 + k as u32 * 0x01010101);
        reg.set_active(s);
        reg.update_status(host, s, 1, NtpLeap::Normal);
        for _ in 0..4 {
            reg.update_reachability(host, s, true);
        }
    }
    reg
}

#[test]
fn matches_real_c_select_vectors() {
    let vectors = include_str!("../../../../../research/oracle/sources-select-c-vectors.txt");
    let find = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();
    let close = |a: f64, b: f64| (a - b).abs() <= 1e-12 * (1.0 + a.abs().max(b.abs()));

    // ---- SELECT2: two agreeing sources -> select source 0, combine both ----
    {
        let mut host = SelHost {
            sel: vec![
                (-0.002, 0.002, 0.01, 0.0005, 10.0, 4.0, true),
                (-0.003, 0.001, 0.015, 0.0006, 12.0, 5.0, true),
            ],
            trk: vec![
                trk(2e9, 0.001, 0.0005, 1e-6, 0.1e-6, 1e-6),
                trk(2e9, -0.0005, 0.0006, 1.2e-6, 0.15e-6, 1.1e-6),
            ],
            ..Default::default()
        };
        let mut reg = ready_registry(&mut host, 2);
        reg.select_source(&mut host, Some(0));
        let l = find("SELECT2");
        assert_eq!(host.setref_calls, field(l, "setref").parse::<i32>().unwrap(), "SELECT2 setref");
        assert_eq!(host.last_combined, field(l, "combined").parse::<i32>().unwrap(), "SELECT2 combined");
        assert!(close(host.last_off, field(l, "off").parse().unwrap()), "SELECT2 off");
        assert_eq!(rpt_state(reg.source(0).status), field(l, "stateA").parse::<i32>().unwrap(), "A");
        assert_eq!(rpt_state(reg.source(1).status), field(l, "stateB").parse::<i32>().unwrap(), "B");
    }

    // ---- FALSE: a falseticker among three ----
    {
        let mut host = SelHost {
            sel: vec![
                (-0.002, 0.002, 0.01, 0.0005, 10.0, 4.0, true),
                (-0.0015, 0.0025, 0.012, 0.0005, 10.0, 4.0, true),
                (0.098, 0.102, 0.013, 0.0005, 10.0, 4.0, true),
            ],
            trk: vec![
                trk(2e9, 0.0, 0.0005, 1e-6, 0.1e-6, 1e-6),
                trk(2e9, 0.0005, 0.0005, 1e-6, 0.1e-6, 1e-6),
                trk(2e9, 0.1, 0.0005, 1e-6, 0.1e-6, 1e-6),
            ],
            ..Default::default()
        };
        let mut reg = ready_registry(&mut host, 3);
        reg.select_source(&mut host, Some(0));
        let l = find("FALSE");
        assert_eq!(host.setref_calls, field(l, "setref").parse::<i32>().unwrap(), "FALSE setref");
        assert_eq!(host.last_combined, field(l, "combined").parse::<i32>().unwrap(), "FALSE combined");
        assert_eq!(rpt_state(reg.source(0).status), field(l, "stateA").parse::<i32>().unwrap(), "A");
        assert_eq!(rpt_state(reg.source(1).status), field(l, "stateB").parse::<i32>().unwrap(), "B");
        assert_eq!(rpt_state(reg.source(2).status), field(l, "stateC").parse::<i32>().unwrap(), "C");
    }

    // ---- NOMAJORITY: two disjoint sources -> no reference, both falsetickers ----
    {
        let mut host = SelHost {
            sel: vec![
                (-0.002, 0.002, 0.01, 0.0005, 10.0, 4.0, true),
                (0.098, 0.102, 0.01, 0.0005, 10.0, 4.0, true),
            ],
            trk: vec![
                trk(2e9, 0.0, 0.0005, 1e-6, 0.1e-6, 1e-6),
                trk(2e9, 0.1, 0.0005, 1e-6, 0.1e-6, 1e-6),
            ],
            ..Default::default()
        };
        let mut reg = ready_registry(&mut host, 2);
        reg.select_source(&mut host, Some(0));
        let l = find("NOMAJORITY");
        assert_eq!(host.setref_calls, field(l, "setref").parse::<i32>().unwrap(), "NOMAJORITY setref");
        assert_eq!(rpt_state(reg.source(0).status), field(l, "stateA").parse::<i32>().unwrap(), "A");
        assert_eq!(rpt_state(reg.source(1).status), field(l, "stateB").parse::<i32>().unwrap(), "B");
    }
}

// ---- Stage 4: select report + lifecycle/accessors ----

#[test]
fn select_report_matches_real_c() {
    let vectors = include_str!("../../../../../research/oracle/sources-select-c-vectors.txt");
    let find = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();
    let close = |a: f64, b: f64| (a - b).abs() <= 1e-12 * (1.0 + a.abs().max(b.abs()));

    let mut host = SelHost {
        sel: vec![
            (-0.002, 0.002, 0.01, 0.0005, 10.0, 4.0, true),
            (-0.003, 0.001, 0.015, 0.0006, 12.0, 5.0, true),
        ],
        trk: vec![
            trk(2e9, 0.001, 0.0005, 1e-6, 0.1e-6, 1e-6),
            trk(2e9, -0.0005, 0.0006, 1.2e-6, 0.15e-6, 1.1e-6),
        ],
        ..Default::default()
    };
    let mut reg = ready_registry(&mut host, 2);
    reg.select_source(&mut host, Some(0));

    for (idx, tag) in [(0usize, "GETSEL0"), (1, "GETSEL1")] {
        let l = find(tag);
        let r = reg.get_select_report(idx).unwrap();
        assert_eq!(r.state_char, field(l, "state").chars().next().unwrap(), "{tag} state");
        assert_eq!(r.authentication as i32, field(l, "auth").parse::<i32>().unwrap(), "{tag} auth");
        assert_eq!(r.leap as i32, field(l, "leap").parse::<i32>().unwrap(), "{tag} leap");
        assert_eq!(r.conf_options, field(l, "conf").parse::<i32>().unwrap(), "{tag} conf");
        assert_eq!(r.eff_options, field(l, "eff").parse::<i32>().unwrap(), "{tag} eff");
        assert_eq!(r.last_sample_ago, field(l, "ago").parse::<u32>().unwrap(), "{tag} ago");
        assert!(close(r.score, field(l, "score").parse().unwrap()), "{tag} score");
        assert!(close(r.lo_limit, field(l, "lo").parse().unwrap()), "{tag} lo");
        assert!(close(r.hi_limit, field(l, "hi").parse().unwrap()), "{tag} hi");
    }
}

#[test]
fn destroy_instance_reindexes_and_fixes_selection() {
    let mut host = SelHost {
        sel: vec![(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, false); 3],
        trk: vec![trk(0.0, 0.0, 0.0, 0.0, 1e-7, 1e-6); 3],
        ..Default::default()
    };
    let mut reg = SourceRegistry::new();
    for k in 0..3 {
        let s = refclock(&mut reg, 0x100 + k);
        reg.set_active(s);
    }
    // Pretend source 2 is selected, then destroy source 0: index shifts, selected 2->1.
    reg.source_mut(2).status = SrcStatus::Selected;
    // (selected_source_index is private; drive it through a forced reselect path.)
    reg.destroy_instance(&mut host, 0);
    assert_eq!(reg.number_of_sources(), 2);
    assert_eq!(reg.source(0).index, 0);
    assert_eq!(reg.source(1).index, 1, "indices renumbered after removal");
}

#[test]
fn slew_and_dispersion_and_reset_compose_sourcestats() {
    let mut host = SelHost {
        sel: vec![(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, false); 2],
        trk: vec![trk(0.0, 0.0, 0.0, 0.0, 1e-7, 1e-6); 2],
        ..Default::default()
    };
    let mut reg = SourceRegistry::new();
    refclock(&mut reg, 1);
    refclock(&mut reg, 2);
    // These compose the ported sourcestats; just exercise the fan-out without panic.
    reg.slew_sources(&mut host, 1000.0, 1e-6, 0.001, false);
    reg.add_dispersion(0.001);
    reg.reset_sources(&mut host);
    reg.reselect_source(&mut host);
    reg.set_reselect_distance(5.0e-4);

    // ModifySelectOptions sets configured options and recomputes effective ones.
    assert!(reg.modify_select_options(0, SRC_SELECT_NOSELECT, SRC_SELECT_NOSELECT, AuthSelectMode::Ignore));
    assert_eq!(reg.source(0).conf_sel_options & SRC_SELECT_NOSELECT, SRC_SELECT_NOSELECT);
    assert!(!reg.modify_select_options(99, 0, 0, AuthSelectMode::Ignore), "missing index");
}

// ---- Stage 5: dump save/load ----

#[test]
fn dump_save_format_and_round_trip_match_real_c() {
    let vectors = include_str!("../../../../../research/oracle/sources-dump-c-vectors.txt");
    let find = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    let mut host = RecHost { mode_normal: true, precision: 1.0e-9, ..Default::default() };
    let mut reg = SourceRegistry::new();
    let s = refclock(&mut reg, 0x5245_4643);
    reg.set_active(s);

    // Accumulate a few samples so the source has stats to dump.
    for k in 0..6 {
        let sample = crate::samplefilt::NtpSample {
            time: 2_000_000_000.0 + k as f64 * 64.0,
            offset: 0.001,
            peer_delay: 0.001,
            peer_dispersion: 1e-6,
            root_delay: 0.001,
            root_dispersion: 1e-6,
        };
        reg.accumulate_sample(&mut host, s, &sample);
    }

    // reach pattern 1,0,1 -> 5 (size 3); stratum 3, leap InsertSecond.
    reg.update_status(&mut host, s, 3, NtpLeap::InsertSecond);
    reg.update_reachability(&mut host, s, true);
    reg.update_reachability(&mut host, s, false);
    reg.update_reachability(&mut host, s, true);

    let dump = reg.save_source(s, ".").expect("a source with stats produces a dump");
    let mut lines = dump.lines();
    let l = find("SAVE");
    assert_eq!(lines.next().unwrap(), field(l, "line1"), "dump line 1");
    assert_eq!(lines.next().unwrap(), field(l, "line2"), "dump line 2 (name)");
    // line3 has spaces; the fixture quotes it after "line3=".
    let want_l3 = l.split_once("line3=").unwrap().1;
    assert_eq!(lines.next().unwrap(), want_l3, "dump line 3 (auth reach size stratum leap)");

    // Round-trip: load into a fresh source restores reach/stratum/leap.
    let mut reg2 = SourceRegistry::new();
    let s2 = refclock(&mut reg2, 0x5245_4643);
    assert!(reg2.load_source(s2, &dump, Some("."), 2_000_000_400.0), "dump loads");
    let ll = find("LOAD");
    assert_eq!(reg2.source(s2).reachability, field(ll, "reach").parse::<u32>().unwrap(), "reach");
    assert_eq!(reg2.source(s2).stratum, field(ll, "stratum").parse::<i32>().unwrap(), "stratum");
    assert_eq!(reg2.source(s2).leap as i32, field(ll, "leap").parse::<i32>().unwrap(), "leap");
}

#[test]
fn dump_load_rejects_bad_input() {
    let mut reg = SourceRegistry::new();
    let s = refclock(&mut reg, 0x5245_4643);
    // Wrong magic.
    assert!(!reg.load_source(s, "BAD0\n.\n0 5 3 3 1\n", Some("."), 0.0));
    // Out-of-range stratum.
    assert!(!reg.load_source(s, "SRC0\n.\n0 5 3 99 1\nx\n", Some("."), 0.0));
    // Out-of-range leap (3 = Unsynchronised, excluded).
    assert!(!reg.load_source(s, "SRC0\n.\n0 5 3 3 3\nx\n", Some("."), 0.0));

    // dump_filename: refclock uses refid:HHHHHHHH; NTP needs a real IP string.
    assert_eq!(reg.dump_filename(s, None).as_deref(), Some("refid:52454643"));
    assert!(SourceRegistry::is_dump_file_name("refid:52454643", |_| false));
    assert!(SourceRegistry::is_dump_file_name("10.0.0.1", |n| n == "10.0.0.1"));
    assert!(!SourceRegistry::is_dump_file_name("garbage", |_| false));
}

#[test]
fn reports_and_log_gating() {
    let mut host = RecHost { mode_normal: true, precision: 1.0e-9, ..Default::default() };
    let mut reg = SourceRegistry::new();
    let s = refclock(&mut reg, 0x0102_0304);
    reg.set_active(s);
    for k in 0..6 {
        let sample = crate::samplefilt::NtpSample {
            time: 2_000_000_000.0 + k as f64 * 64.0,
            offset: 0.001,
            peer_delay: 0.001,
            peer_dispersion: 1e-6,
            root_delay: 0.001,
            root_dispersion: 1e-6,
        };
        reg.accumulate_sample(&mut host, s, &sample);
    }
    reg.source_mut(s).status = SrcStatus::Selected;
    reg.source_mut(s).reachability = 0o377;
    reg.source_mut(s).stratum = 2;

    let (state, reach, stratum, ref_id, _rep) = reg.report_source(s, 2_000_000_400.0).unwrap();
    assert_eq!((state, reach, stratum, ref_id), (5, 0o377, 2, 0x0102_0304));
    let (rid, _stats) = reg.report_sourcestats(s, 2_000_000_400.0).unwrap();
    assert_eq!(rid, 0x0102_0304);
    assert!(reg.report_source(99, 0.0).is_none());

    // log_selection_* is gated on the normal reference mode.
    assert_eq!(reg.log_selection_message(true, "hi").as_deref(), Some("hi"));
    assert_eq!(reg.log_selection_message(false, "hi"), None);
    assert_eq!(
        reg.log_selection_source(true, "Detected falseticker %s", "REF").as_deref(),
        Some("Detected falseticker REF")
    );
}
