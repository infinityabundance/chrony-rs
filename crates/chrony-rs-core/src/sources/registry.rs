//! Source registry + reachability + status — the first stage of a faithful port of
//! chrony 4.5 `sources.c` (`SRC_*`), the source-selection brain.
//!
//! # Scope of this stage
//!
//! `sources.c` is the largest, most-entangled translation unit in chrony (48
//! functions, ~1900 lines, with the 517-line `SRC_SelectSource`). It is ported in
//! stages so each lands complete and court-backed rather than rushed:
//!
//! * **Stage 1 (this module): the source registry and the non-selection machinery** —
//!   instance lifecycle, the 8-bit reachability register, status/stratum/leap
//!   bookkeeping, the leap-second vote, sample accumulation (composing the ported
//!   [`crate::sourcestats`]), the special reference-mode end check, and the
//!   accessors. The selection algorithm itself (`SRC_SelectSource` / `combine_sources`
//!   / the classification) is injected here as a *trigger*
//!   ([`SourcesHost::select_source`]) and lands in a later stage.
//! * Later stages: `update_sel_options` + the classification (`mark_source`,
//!   `mark_ok_sources`, the `SelectInfo` computation), `combine_sources`, then
//!   `SRC_SelectSource`, then dump/reload and the reports.
//!
//! The existing simplified [`super::select`] / [`super::Source`] convenience (used by
//! the end-to-end pipeline court) is unrelated and stays as is.
//!
//! # Adaptations (documented, not silent)
//!
//! * **The per-source statistics are the ported [`crate::sourcestats::SourceStats`]**,
//!   composed directly (chrony's `SST_*`).
//! * **`REF_*` / `NSR_*` and the selection trigger are the injected [`SourcesHost`]**;
//!   the per-source IP/refid identity and the address table live with the caller.
//!
//! # Oracle
//!
//! The Stage-1 logic is differential-tested against the **real compiled `sources.c`**
//! (+ the ported `sourcestats.c` / `regress.c`, with `REF_*`/`NSR_*`/`LCL_*`/`SCH_*`
//! stubbed): the reachability register evolution, the leap-second vote majority, the
//! status/reachability select-trigger conditions, and the special-mode-end check
//! (`research/oracle/sources-c-vectors.txt`). The port replays the identical calls and
//! matches every register value, leap verdict, trigger, and check. See the tests.

use crate::reference::NtpLeap;
use crate::samplefilt::NtpSample;
use crate::sourcestats::SourceStats;

/// chrony `SOURCE_REACH_BITS`.
pub const SOURCE_REACH_BITS: u32 = 8;
/// chrony `regress.h` `MIN_SAMPLES_FOR_REGRESS`.
pub const MIN_SAMPLES_FOR_REGRESS: i32 = 3;
/// chrony `BAD_HANDLE_THRESHOLD`.
pub const BAD_HANDLE_THRESHOLD: i32 = 4;
/// chrony `DISTANT_PENALTY`.
pub const DISTANT_PENALTY: i32 = 32;
/// chrony `SCORE_LIMIT`.
pub const SCORE_LIMIT: f64 = 10.0;

/// chrony `SRC_SELECT_*` option bits.
pub const SRC_SELECT_NOSELECT: i32 = 0x1;
pub const SRC_SELECT_PREFER: i32 = 0x2;
pub const SRC_SELECT_TRUST: i32 = 0x4;
pub const SRC_SELECT_REQUIRE: i32 = 0x8;

/// chrony `INVALID_SOURCE`.
pub const INVALID_SOURCE: i32 = -1;
/// chrony `NTP_MAX_STRATUM`.
pub const NTP_MAX_STRATUM: i32 = 16;

/// chrony `SRC_AuthSelectMode` (the `authselectmode` directive).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum AuthSelectMode {
    /// `SRC_AUTHSELECT_IGNORE`.
    Ignore,
    /// `SRC_AUTHSELECT_MIX`.
    Mix,
    /// `SRC_AUTHSELECT_PREFER`.
    Prefer,
    /// `SRC_AUTHSELECT_REQUIRE`.
    Require,
}

/// chrony `SRC_Type`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum SrcType {
    /// `SRC_NTP`.
    Ntp,
    /// `SRC_REFCLOCK`.
    Refclock,
}

/// chrony `SRC_Status` (the source-classification labels).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum SrcStatus {
    Ok,
    Unselectable,
    Unsynchronised,
    BadStats,
    BadDistance,
    Jittery,
    WaitsStats,
    Stale,
    Orphan,
    Untrusted,
    Falseticker,
    WaitsSources,
    Nonpreferred,
    WaitsUpdate,
    Distant,
    Outlier,
    Unselected,
    Selected,
}

/// chrony `RPT_SelectReport` (the `chronyc selectdata` per-source report).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SelectReport {
    pub ref_id: u32,
    pub state_char: char,
    pub authentication: bool,
    pub leap: NtpLeap,
    pub conf_options: i32,
    pub eff_options: i32,
    pub last_sample_ago: u32,
    pub score: f64,
    pub lo_limit: f64,
    pub hi_limit: f64,
}

/// chrony `struct SelectInfo` — the per-source data the selection pass fills.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SelectInfo {
    pub select_ok: bool,
    pub std_dev: f64,
    pub root_distance: f64,
    pub lo_limit: f64,
    pub hi_limit: f64,
    pub last_sample_ago: f64,
}

/// chrony `struct SRC_Instance_Record` (the fields Stage 1 manages; the selection
/// pass adds more in a later stage).
pub struct SrcInstance {
    /// Per-source statistics (chrony `SST_Stats`), the ported module.
    pub stats: SourceStats,
    /// Index back into the registry's table.
    pub index: usize,
    /// Reference ID.
    pub ref_id: u32,
    /// Whether this source has an IP address (NTP) vs a refid (refclock).
    pub has_ip: bool,
    /// Whether the source is updating reachability.
    pub active: bool,
    /// Reachability register.
    pub reachability: u32,
    /// Number of set bits tracked in the register.
    pub reachability_size: i32,
    /// Updates since the last reference update.
    pub updates: i32,
    /// Updates left before allowing combining.
    pub distant: i32,
    /// Updates with a status requiring source replacement.
    pub bad: i32,
    /// Classification status.
    pub status: SrcStatus,
    /// Source type.
    pub type_: SrcType,
    /// Whether the source is authenticated.
    pub authenticated: bool,
    /// Configured selection options.
    pub conf_sel_options: i32,
    /// Effective selection options.
    pub sel_options: i32,
    /// Score against the currently selected source.
    pub sel_score: f64,
    /// Current stratum.
    pub stratum: i32,
    /// Current leap status.
    pub leap: NtpLeap,
    /// Whether the source has a leap-second vote.
    pub leap_vote: bool,
    /// Whether already reported as a falseticker since the last selection change.
    pub reported_falseticker: bool,
    /// The selection pass's per-source data.
    pub sel_info: SelectInfo,
}

/// The host boundary: `REF_*` / `NSR_*` and the selection-algorithm trigger that
/// Stage 1 calls but does not yet implement.
pub trait SourcesHost {
    /// `REF_IsLeapSecondClose(ts, offset)` (a `None` ts is chrony's `NULL`).
    fn ref_is_leap_second_close(&mut self, ts: Option<f64>, offset: f64) -> bool;
    /// `REF_UpdateLeapStatus(leap)`.
    fn ref_update_leap_status(&mut self, leap: NtpLeap);
    /// `REF_GetMode() == REF_ModeNormal`.
    fn ref_mode_is_normal(&mut self) -> bool;
    /// `REF_SetUnsynchronised()`.
    fn ref_set_unsynchronised(&mut self);
    /// `NSR_HandleBadSource(inst->ip_addr)` — keyed by source index here.
    fn nsr_handle_bad_source(&mut self, index: usize);
    /// `SRC_SelectSource(...)` — the selection pass (a later stage); recorded as a
    /// trigger for now.
    fn select_source(&mut self);
    /// `LCL_GetSysPrecisionAsQuantum`-derived precision for `SST_DoNewRegression`.
    fn precision(&mut self) -> f64;

    // ---- selection-pass boundaries (Stage 3) ----
    /// `SCH_GetLastEventTime` cooked seconds.
    fn now(&mut self) -> f64 {
        0.0
    }
    /// `SST_GetSelectionData(stats, now)` for source `index`: returns
    /// `(lo, hi, root_distance, std_dev, first_sample_ago, last_sample_ago, select_ok)`.
    #[allow(clippy::type_complexity)]
    fn sst_selection_data(
        &mut self,
        _index: usize,
        _now: f64,
    ) -> (f64, f64, f64, f64, f64, f64, bool) {
        (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, false)
    }
    /// `SST_GetTrackingData(stats)` for source `index`.
    fn sst_tracking_data(&mut self, _index: usize) -> crate::sourcestats::TrackingData {
        crate::sourcestats::TrackingData {
            ref_time: 0.0,
            average_offset: 0.0,
            offset_sd: 0.0,
            frequency: 0.0,
            frequency_sd: 0.0,
            skew: 0.0,
            root_delay: 0.0,
            root_dispersion: 0.0,
        }
    }
    /// `LCL_GetMaxClockError`.
    fn lcl_max_clock_error(&mut self) -> f64 {
        0.0
    }
    /// `REF_GetOrphanStratum`.
    fn ref_get_orphan_stratum(&mut self) -> i32 {
        16
    }
    /// `NSR_GetLocalRefid(inst->ip_addr)` for source `index`.
    fn nsr_get_local_refid(&mut self, _index: usize) -> u32 {
        0
    }
    /// `REF_SetReference(...)`: the selected reference + combined sources.
    #[allow(clippy::too_many_arguments)]
    fn ref_set_reference(
        &mut self,
        _stratum: i32,
        _leap: NtpLeap,
        _combined: i32,
        _ref_id: u32,
        _ref_time: f64,
        _offset: f64,
        _offset_sd: f64,
        _frequency: f64,
        _frequency_sd: f64,
        _skew: f64,
        _root_delay: f64,
        _root_dispersion: f64,
    ) {
    }
}

/// chrony's selection-tuning configuration (the `CNF_Get*` knobs read at init).
#[derive(Clone, Copy, Debug)]
pub struct SourcesConfig {
    pub max_distance: f64,
    pub max_jitter: f64,
    pub reselect_distance: f64,
    pub stratum_weight: f64,
    pub combine_limit: f64,
    pub min_sources: i32,
}

impl Default for SourcesConfig {
    fn default() -> SourcesConfig {
        // chrony's documented defaults.
        SourcesConfig {
            max_distance: 3.0,
            max_jitter: 1.0,
            reselect_distance: 1.0e-4,
            stratum_weight: 1.0e-3,
            combine_limit: 3.0,
            min_sources: 1,
        }
    }
}

/// chrony's `sources.c` module state: the table of sources + the selected index.
#[derive(Default)]
pub struct SourceRegistry {
    sources: Vec<SrcInstance>,
    selected_source_index: i32,
    /// chrony `report_selection_loss`.
    report_selection_loss: bool,
    /// chrony `reported_no_majority`.
    reported_no_majority: bool,
    /// chrony `last_updated_inst` index (`INVALID_SOURCE` if none).
    last_updated_inst: i32,
    cfg: SourcesConfig,
}

impl SourceRegistry {
    /// chrony `SRC_Initialise` (default selection config).
    pub fn new() -> SourceRegistry {
        SourceRegistry::with_config(SourcesConfig::default())
    }

    /// chrony `SRC_Initialise` with explicit selection config.
    pub fn with_config(cfg: SourcesConfig) -> SourceRegistry {
        SourceRegistry {
            sources: Vec::new(),
            selected_source_index: INVALID_SOURCE,
            report_selection_loss: false,
            reported_no_majority: false,
            last_updated_inst: INVALID_SOURCE,
            cfg,
        }
    }

    /// chrony `SRC_ReadNumberOfSources`.
    pub fn number_of_sources(&self) -> i32 {
        self.sources.len() as i32
    }
    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
    /// chrony `SRC_ActiveSources`.
    pub fn active_sources(&self) -> i32 {
        self.sources.iter().filter(|s| s.active).count() as i32
    }
    /// The selected source index (`INVALID_SOURCE` if none).
    pub fn selected_index(&self) -> i32 {
        self.selected_source_index
    }
    /// Borrow a source.
    pub fn source(&self, index: usize) -> &SrcInstance {
        &self.sources[index]
    }
    /// Mutably borrow a source (the selection stage and tests set the vote/leap fields).
    pub fn source_mut(&mut self, index: usize) -> &mut SrcInstance {
        &mut self.sources[index]
    }
    /// chrony `SRC_GetSourcestats`.
    pub fn get_sourcestats(&mut self, index: usize) -> &mut SourceStats {
        &mut self.sources[index].stats
    }
    /// chrony `SRC_GetType`.
    pub fn get_type(&self, index: usize) -> SrcType {
        self.sources[index].type_
    }
    /// chrony `SRC_IsReachable`.
    pub fn is_reachable(&self, index: usize) -> bool {
        self.sources[index].reachability != 0
    }
    /// chrony `SRC_IsSyncPeer`.
    pub fn is_sync_peer(&self, index: usize) -> bool {
        self.selected_source_index == index as i32
    }

    /// chrony `SRC_CreateNewInstance`: register a new source, returning its index.
    #[allow(clippy::too_many_arguments)]
    pub fn create_new_instance(
        &mut self,
        ref_id: u32,
        type_: SrcType,
        authenticated: bool,
        sel_options: i32,
        has_ip: bool,
        min_samples: i32,
        max_samples: i32,
        min_delay: f64,
        asymmetry: f64,
    ) -> usize {
        let index = self.sources.len();
        let stats = SourceStats::new(ref_id, has_ip, min_samples, max_samples, min_delay, asymmetry);
        let mut inst = SrcInstance {
            stats,
            index,
            ref_id,
            has_ip,
            active: false,
            reachability: 0,
            reachability_size: 0,
            updates: 0,
            distant: 0,
            bad: 0,
            status: SrcStatus::BadStats,
            type_,
            authenticated,
            conf_sel_options: sel_options,
            sel_options,
            sel_score: 1.0,
            stratum: 0,
            leap: NtpLeap::Unsynchronised,
            leap_vote: false,
            reported_falseticker: false,
            sel_info: SelectInfo::default(),
        };
        inst.set_refid(ref_id, has_ip);
        self.sources.push(inst);
        // chrony resets the instance and updates sel options + selects here; the
        // selection pass is a later stage.
        self.reset_instance_fields(index);
        index
    }

    /// chrony `SRC_SetRefid`.
    pub fn set_refid(&mut self, index: usize, ref_id: u32, has_ip: bool) {
        self.sources[index].set_refid(ref_id, has_ip);
    }

    /// chrony `SRC_ResetInstance` (the field reset; the select trigger is the host's).
    pub fn reset_instance(&mut self, host: &mut dyn SourcesHost, index: usize) {
        self.reset_instance_fields(index);
        if self.selected_source_index == index as i32 {
            host.select_source();
        }
    }

    fn reset_instance_fields(&mut self, index: usize) {
        let inst = &mut self.sources[index];
        inst.updates = 0;
        inst.reachability = 0;
        inst.reachability_size = 0;
        inst.distant = 0;
        inst.bad = 0;
        inst.status = SrcStatus::BadStats;
        inst.sel_score = 1.0;
        inst.stratum = 0;
        inst.leap = NtpLeap::Unsynchronised;
        inst.leap_vote = false;
        inst.reported_falseticker = false;
        inst.sel_info = SelectInfo::default();
        inst.stats.reset();
    }

    /// chrony `get_leap_status`: accept a leap if more than half the voting sources
    /// agree.
    pub fn leap_status(&self) -> NtpLeap {
        let mut votes = 0;
        let mut ins = 0;
        let mut del = 0;
        for s in &self.sources {
            if !s.leap_vote {
                continue;
            }
            votes += 1;
            match s.leap {
                NtpLeap::InsertSecond => ins += 1,
                NtpLeap::DeleteSecond => del += 1,
                _ => {}
            }
        }
        if ins > votes / 2 {
            NtpLeap::InsertSecond
        } else if del > votes / 2 {
            NtpLeap::DeleteSecond
        } else {
            NtpLeap::Normal
        }
    }

    /// chrony `SRC_UpdateStatus`.
    pub fn update_status(
        &mut self,
        host: &mut dyn SourcesHost,
        index: usize,
        stratum: i32,
        leap: NtpLeap,
    ) {
        self.sources[index].stratum = stratum;

        if host.ref_is_leap_second_close(None, 0.0) {
            return;
        }
        self.sources[index].leap = leap;

        if self.sources[index].leap_vote {
            let ls = self.leap_status();
            host.ref_update_leap_status(ls);
        }
    }

    /// chrony `SRC_AccumulateSample`.
    pub fn accumulate_sample(
        &mut self,
        host: &mut dyn SourcesHost,
        index: usize,
        sample: &NtpSample,
    ) -> bool {
        if host.ref_is_leap_second_close(Some(sample.time), sample.offset) {
            // chrony logs and drops the sample around a leap second.
            return false;
        }
        let precision = host.precision();
        let inst = &mut self.sources[index];
        inst.stats.accumulate_sample(sample);
        inst.stats.do_new_regression(precision);
        true
    }

    /// chrony `SRC_SetActive`.
    pub fn set_active(&mut self, index: usize) {
        self.sources[index].active = true;
    }
    /// chrony `SRC_UnsetActive`.
    pub fn unset_active(&mut self, index: usize) {
        self.sources[index].active = false;
    }

    /// chrony `special_mode_end`: whether no active source can still gather enough
    /// samples to become selectable.
    pub fn special_mode_end(&self) -> bool {
        for s in &self.sources {
            if !s.active {
                continue;
            }
            if s.reachability_size >= SOURCE_REACH_BITS as i32 - 1 {
                continue;
            }
            if SOURCE_REACH_BITS as i32 - 1 - s.reachability_size + s.stats.samples()
                >= MIN_SAMPLES_FOR_REGRESS
            {
                return false;
            }
        }
        true
    }

    /// chrony `handle_bad_source` (NTP sources only).
    fn handle_bad_source(&mut self, host: &mut dyn SourcesHost, index: usize) {
        if self.sources[index].type_ == SrcType::Ntp {
            host.nsr_handle_bad_source(index);
        }
    }

    /// chrony `SRC_UpdateReachability`.
    pub fn update_reachability(
        &mut self,
        host: &mut dyn SourcesHost,
        index: usize,
        reachable: bool,
    ) {
        {
            let inst = &mut self.sources[index];
            inst.reachability <<= 1;
            inst.reachability |= reachable as u32;
            inst.reachability %= 1u32 << SOURCE_REACH_BITS;
            if inst.reachability_size < SOURCE_REACH_BITS as i32 {
                inst.reachability_size += 1;
            }
        }

        if !reachable && index as i32 == self.selected_source_index {
            host.select_source();
        }

        // Check if special reference update mode failed.
        if !host.ref_mode_is_normal() && self.special_mode_end() {
            host.ref_set_unsynchronised();
        }

        // Try to replace unreachable NTP sources.
        let inst = &self.sources[index];
        if inst.reachability == 0 && inst.reachability_size == SOURCE_REACH_BITS as i32 {
            self.handle_bad_source(host, index);
        }
    }

    /// chrony `SRC_ResetReachability`.
    pub fn reset_reachability(&mut self, host: &mut dyn SourcesHost, index: usize) {
        self.sources[index].reachability = 0;
        self.sources[index].reachability_size = 0;
        self.update_reachability(host, index, false);
    }

    /// chrony `update_sel_options`: recompute every source's effective `sel_options`
    /// from the configured options and the `authselectmode` policy. Returns the new
    /// effective options per source (the registry is updated in place).
    pub fn update_sel_options(&mut self, mode: AuthSelectMode) -> Vec<i32> {
        let mut auth_ntp_sources = 0;
        let mut unauth_ntp_sources = 0;
        for s in &self.sources {
            if s.conf_sel_options & SRC_SELECT_NOSELECT != 0 {
                continue;
            }
            if s.type_ != SrcType::Ntp {
                continue;
            }
            if s.authenticated {
                auth_ntp_sources += 1;
            } else {
                unauth_ntp_sources += 1;
            }
        }

        let (mut auth_ntp_options, mut unauth_ntp_options, mut refclk_options) = (0, 0, 0);
        match mode {
            AuthSelectMode::Ignore => {}
            AuthSelectMode::Mix => {
                if auth_ntp_sources > 0 && unauth_ntp_sources > 0 {
                    auth_ntp_options = SRC_SELECT_REQUIRE | SRC_SELECT_TRUST;
                    refclk_options = SRC_SELECT_REQUIRE | SRC_SELECT_TRUST;
                }
            }
            AuthSelectMode::Prefer => {
                if auth_ntp_sources > 0 {
                    unauth_ntp_options = SRC_SELECT_NOSELECT;
                }
            }
            AuthSelectMode::Require => {
                // If no authenticated sources exist, fall back to IGNORE to avoid
                // marking all sources as NOSELECT (which would make zero sources selectable).
                if auth_ntp_sources == 0 {
                    unauth_ntp_options = 0;
                } else {
                    unauth_ntp_options = SRC_SELECT_NOSELECT;
                }
            }
        }

        for s in &mut self.sources {
            let mut options = s.conf_sel_options;
            if options & SRC_SELECT_NOSELECT == 0 {
                options |= match s.type_ {
                    SrcType::Ntp => {
                        if s.authenticated {
                            auth_ntp_options
                        } else {
                            unauth_ntp_options
                        }
                    }
                    SrcType::Refclock => refclk_options,
                };
            }
            s.sel_options = options;
        }

        self.sources.iter().map(|s| s.sel_options).collect()
    }

    /// chrony `mark_source`: set the status and maintain the bad-source counter.
    fn mark_source(&mut self, host: &mut dyn SourcesHost, i: usize, status: SrcStatus) {
        self.sources[i].status = status;
        if self.last_updated_inst == i as i32 {
            let bad = {
                let s = &mut self.sources[i];
                if s.bad < i32::MAX
                    && matches!(
                        status,
                        SrcStatus::Falseticker | SrcStatus::BadDistance | SrcStatus::Jittery
                    )
                {
                    s.bad += 1;
                } else {
                    s.bad = 0;
                }
                s.bad
            };
            if bad >= BAD_HANDLE_THRESHOLD {
                self.handle_bad_source(host, i);
            }
        }
    }

    /// chrony `mark_ok_sources`.
    fn mark_ok_sources(&mut self, host: &mut dyn SourcesHost, status: SrcStatus) {
        for i in 0..self.sources.len() {
            if self.sources[i].status == SrcStatus::Ok {
                self.mark_source(host, i, status);
            }
        }
    }

    /// chrony `unselect_selected_source`. `message` present means a non-transient loss.
    fn unselect_selected_source(&mut self, message: bool) {
        if self.selected_source_index != INVALID_SOURCE {
            self.selected_source_index = INVALID_SOURCE;
            self.report_selection_loss = true;
        }
        if self.report_selection_loss && message {
            self.report_selection_loss = false;
        }
    }

    /// chrony `SRC_SelectSource`: select the reference source from the pool and update
    /// the local reference (via [`SourcesHost::ref_set_reference`]). `updated_inst` is
    /// the source that just got a sample (`None` = chrony's `NULL`).
    pub fn select_source(&mut self, host: &mut dyn SourcesHost, updated_inst: Option<usize>) {
        use super::combine::{
            combine_sources, compare_sort_elements, CombineEntry, CombineMark, EndpointTag,
            SortElement,
        };

        if let Some(u) = updated_inst {
            self.sources[u].updates += 1;
            self.last_updated_inst = u as i32;
        }

        let n = self.sources.len();
        if n == 0 {
            self.unselect_selected_source(true);
            return;
        }

        let now = host.now();

        // ---- Step 1: classify each source, build sel_info for candidates ----
        let mut max_sel_reach = 0u32;
        let mut max_badstat_reach = 0u32;
        let mut max_sel_reach_size = 0i32;
        let mut max_reach_sample_ago = 0.0f64;
        let mut n_badstats_sources = 0;
        let mut sel_req_source = false;

        for i in 0..n {
            self.sources[i].leap_vote = false;
            if self.sources[i].sel_options & SRC_SELECT_REQUIRE != 0 {
                sel_req_source = true;
            }
            if self.sources[i].sel_options & SRC_SELECT_NOSELECT != 0 {
                self.mark_source(host, i, SrcStatus::Unselectable);
                continue;
            }
            if self.sources[i].leap == NtpLeap::Unsynchronised {
                self.mark_source(host, i, SrcStatus::Unsynchronised);
                continue;
            }

            let (lo, hi, root_distance, std_dev, first_ago, last_ago, ok) =
                host.sst_selection_data(i, now);
            {
                let si = &mut self.sources[i].sel_info;
                si.lo_limit = lo;
                si.hi_limit = hi;
                si.root_distance = root_distance;
                si.std_dev = std_dev;
                si.last_sample_ago = last_ago;
                si.select_ok = ok;
            }
            if !ok {
                n_badstats_sources += 1;
                self.mark_source(host, i, SrcStatus::BadStats);
                if max_badstat_reach < self.sources[i].reachability {
                    max_badstat_reach = self.sources[i].reachability;
                }
                continue;
            }

            // Extra dispersion when the last sample is older than the sample span.
            if first_ago < 2.0 * last_ago {
                let extra = host.lcl_max_clock_error() * (2.0 * last_ago - first_ago);
                let si = &mut self.sources[i].sel_info;
                si.root_distance += extra;
                si.lo_limit -= extra;
                si.hi_limit += extra;
            }

            let si = self.sources[i].sel_info;
            if !(si.root_distance <= self.cfg.max_distance && si.lo_limit <= si.hi_limit) {
                self.mark_source(host, i, SrcStatus::BadDistance);
                continue;
            }
            if si.std_dev > self.cfg.max_jitter {
                self.mark_source(host, i, SrcStatus::Jittery);
                continue;
            }

            self.sources[i].status = SrcStatus::Ok;

            if self.sources[i].reachability != 0 && max_reach_sample_ago < first_ago {
                max_reach_sample_ago = first_ago;
            }
            if max_sel_reach < self.sources[i].reachability {
                max_sel_reach = self.sources[i].reachability;
            }
            if max_sel_reach_size < self.sources[i].reachability_size {
                max_sel_reach_size = self.sources[i].reachability_size;
            }
        }

        // ---- orphan handling + stale check ----
        let orphan_stratum = host.ref_get_orphan_stratum();
        let mut orphan_source = INVALID_SOURCE;
        let mut n_sel_sources = 0;

        for i in 0..n {
            if self.sources[i].status != SrcStatus::Ok {
                continue;
            }
            let last_ago = self.sources[i].sel_info.last_sample_ago;
            if self.sources[i].reachability == 0 && max_reach_sample_ago < last_ago {
                self.mark_source(host, i, SrcStatus::Stale);
                continue;
            }
            if self.sources[i].stratum >= orphan_stratum && self.sources[i].type_ == SrcType::Ntp {
                self.mark_source(host, i, SrcStatus::Orphan);
                if self.sources[i].stratum == orphan_stratum
                    && self.sources[i].reachability != 0
                    && (orphan_source == INVALID_SOURCE
                        || self.sources[i].ref_id < self.sources[orphan_source as usize].ref_id)
                {
                    orphan_source = i as i32;
                }
                continue;
            }
            n_sel_sources += 1;
        }

        if n_sel_sources == 0 && orphan_source != INVALID_SOURCE {
            let os = orphan_source as usize;
            let local_ref_id = host.nsr_get_local_refid(os);
            if local_ref_id != 0 && self.sources[os].ref_id < local_ref_id {
                self.sources[os].status = SrcStatus::Ok;
                n_sel_sources = 1;
            }
        }

        // ---- build endpoint list + count trust sources ----
        let mut sort_list: Vec<SortElement> = Vec::new();
        let mut n_sel_trust_sources = 0;
        for i in 0..n {
            if self.sources[i].status != SrcStatus::Ok {
                continue;
            }
            if self.sources[i].sel_options & SRC_SELECT_TRUST != 0 {
                n_sel_trust_sources += 1;
            }
            let si = self.sources[i].sel_info;
            sort_list.push(SortElement { index: i, offset: si.lo_limit, tag: EndpointTag::Low });
            sort_list.push(SortElement { index: i, offset: si.hi_limit, tag: EndpointTag::High });
        }
        let n_endpoints = sort_list.len();

        // Wait for stats on start when a bad-stats source shares the polling interval.
        if n_badstats_sources > 0
            && n_sel_sources > 0
            && self.selected_source_index == INVALID_SOURCE
            && max_sel_reach_size < SOURCE_REACH_BITS as i32
            && max_sel_reach >> 1 == max_badstat_reach
        {
            self.mark_ok_sources(host, SrcStatus::WaitsStats);
            self.unselect_selected_source(false);
            return;
        }

        if n_endpoints == 0 {
            self.unselect_selected_source(true);
            return;
        }

        sort_list.sort_by(compare_sort_elements);

        // ---- falseticker intersection (depth / trust-depth search) ----
        let mut trust_depth = 0;
        let mut best_trust_depth = 0;
        let mut depth = 0;
        let mut best_depth = 0;
        let (mut best_lo, mut best_hi, mut best_trust_lo, mut best_trust_hi) = (0.0, 0.0, 0.0, 0.0);

        for e in &sort_list {
            let trusted = self.sources[e.index].sel_options & SRC_SELECT_TRUST != 0;
            match e.tag {
                EndpointTag::Low => {
                    depth += 1;
                    if trusted {
                        trust_depth += 1;
                    }
                    if trust_depth > best_trust_depth
                        || (trust_depth == best_trust_depth && depth > best_depth)
                    {
                        if trust_depth > best_trust_depth {
                            best_trust_depth = trust_depth;
                            best_trust_lo = e.offset;
                        }
                        best_depth = depth;
                        best_lo = e.offset;
                    }
                }
                EndpointTag::High => {
                    if trust_depth == best_trust_depth {
                        if depth == best_depth {
                            best_hi = e.offset;
                        }
                        best_trust_hi = e.offset;
                    }
                    if trusted {
                        trust_depth -= 1;
                    }
                    depth -= 1;
                }
            }
        }

        if (best_trust_depth == 0 && best_depth <= n_sel_sources / 2)
            || (best_trust_depth > 0 && best_trust_depth <= n_sel_trust_sources / 2)
        {
            if !self.reported_no_majority {
                self.reported_no_majority = true;
                self.report_selection_loss = false;
            }
            if self.selected_source_index != INVALID_SOURCE {
                host.ref_set_unsynchronised();
                self.selected_source_index = INVALID_SOURCE;
            }
            self.mark_ok_sources(host, SrcStatus::Falseticker);
            return;
        }

        // ---- build admissible source list (in the best interval) ----
        let mut sel_sources: Vec<usize> = Vec::new();
        for i in 0..n {
            if self.sources[i].status != SrcStatus::Ok {
                continue;
            }
            let si = self.sources[i].sel_info;
            let contains_or_within = (si.lo_limit <= best_lo && si.hi_limit >= best_hi)
                || (si.lo_limit >= best_lo && si.hi_limit <= best_hi);
            if contains_or_within {
                let trusted = self.sources[i].sel_options & SRC_SELECT_TRUST != 0;
                if !(best_trust_depth == 0
                    || trusted
                    || (si.lo_limit >= best_trust_lo && si.hi_limit <= best_trust_hi))
                {
                    self.mark_source(host, i, SrcStatus::Untrusted);
                    continue;
                }
                sel_sources.push(i);
                if self.sources[i].sel_options & SRC_SELECT_REQUIRE != 0 {
                    sel_req_source = false;
                }
            } else {
                self.mark_source(host, i, SrcStatus::Falseticker);
                self.sources[i].reported_falseticker = true;
            }
        }

        if sel_sources.is_empty()
            || sel_req_source
            || (sel_sources.len() as i32) < self.cfg.min_sources
        {
            self.unselect_selected_source(true);
            self.mark_ok_sources(host, SrcStatus::WaitsSources);
            return;
        }

        // ---- enable leap voting ----
        for &index in &sel_sources {
            if best_trust_depth != 0 && self.sources[index].sel_options & SRC_SELECT_TRUST == 0 {
                continue;
            }
            self.sources[index].leap_vote = true;
        }

        // ---- prefer reduction ----
        let any_prefer =
            sel_sources.iter().any(|&i| self.sources[i].sel_options & SRC_SELECT_PREFER != 0);
        let sel_prefer = any_prefer;
        if any_prefer {
            let mut kept = Vec::new();
            for &i in &sel_sources {
                if self.sources[i].sel_options & SRC_SELECT_PREFER == 0 {
                    self.mark_source(host, i, SrcStatus::Nonpreferred);
                } else {
                    kept.push(i);
                }
            }
            sel_sources = kept;
        }

        // ---- minimum stratum ----
        let min_stratum =
            sel_sources.iter().map(|&i| self.sources[i].stratum).min().unwrap();

        // ---- score update + max-score selection ----
        let mut max_score_index = INVALID_SOURCE;
        let mut max_score = 0.0;
        let sel_src_distance = if self.selected_source_index != INVALID_SOURCE {
            let s = &self.sources[self.selected_source_index as usize];
            s.sel_info.root_distance + (s.stratum - min_stratum) as f64 * self.cfg.stratum_weight
        } else {
            0.0
        };

        for i in 0..n {
            if self.sources[i].status != SrcStatus::Ok
                || (sel_prefer && self.sources[i].sel_options & SRC_SELECT_PREFER == 0)
            {
                self.sources[i].sel_score = 1.0;
                self.sources[i].distant = DISTANT_PENALTY;
                continue;
            }
            let mut distance = self.sources[i].sel_info.root_distance
                + (self.sources[i].stratum - min_stratum) as f64 * self.cfg.stratum_weight;
            if self.sources[i].type_ == SrcType::Ntp {
                distance += self.cfg.reselect_distance;
            }

            if self.selected_source_index != INVALID_SOURCE {
                if Some(i) == updated_inst
                    || self.selected_source_index == updated_inst.map_or(INVALID_SOURCE, |u| u as i32)
                {
                    self.sources[i].sel_score *= sel_src_distance / distance;
                    if self.sources[i].sel_score < 1.0 {
                        self.sources[i].sel_score = 1.0;
                    }
                }
            } else {
                self.sources[i].sel_score = 1.0 / distance;
            }

            if max_score < self.sources[i].sel_score {
                max_score = self.sources[i].sel_score;
                max_score_index = i as i32;
            }
        }

        // ---- selection change (hysteresis) ----
        if self.selected_source_index == INVALID_SOURCE
            || self.sources[self.selected_source_index as usize].status != SrcStatus::Ok
            || (max_score_index != self.selected_source_index && max_score > SCORE_LIMIT)
        {
            if self.sources[max_score_index as usize].updates == 0 {
                self.unselect_selected_source(false);
                self.mark_ok_sources(host, SrcStatus::WaitsUpdate);
                return;
            }
            self.selected_source_index = max_score_index;
            for s in &mut self.sources {
                s.sel_score = 1.0;
                s.distant = 0;
                s.reported_falseticker = false;
            }
            self.reported_no_majority = false;
            self.report_selection_loss = false;
        }

        let selected = self.selected_source_index as usize;
        self.mark_source(host, selected, SrcStatus::Selected);

        // ---- don't update the reference with no new samples ----
        if self.sources[selected].updates == 0 {
            for &index in &sel_sources {
                if self.sources[index].status == SrcStatus::Ok {
                    let st = if self.sources[index].distant != 0 {
                        SrcStatus::Distant
                    } else {
                        SrcStatus::Unselected
                    };
                    self.mark_source(host, index, st);
                }
            }
            return;
        }

        for s in &mut self.sources {
            s.updates = 0;
        }
        let leap_status = self.leap_status();

        // ---- combine + REF_SetReference ----
        let init = host.sst_tracking_data(selected);
        let mut entries: Vec<CombineEntry> = sel_sources
            .iter()
            .map(|&index| CombineEntry {
                root_distance: self.sources[index].sel_info.root_distance,
                distant: self.sources[index].distant,
                reachability_size: self.sources[index].reachability_size,
                is_selected: index == selected,
                is_ntp: self.sources[index].type_ == SrcType::Ntp,
                status_ok: self.sources[index].status == SrcStatus::Ok,
                tracking: host.sst_tracking_data(index),
            })
            .collect();

        let (result, marks) = combine_sources(
            &mut entries,
            init.ref_time,
            init.average_offset,
            init.offset_sd,
            init.frequency,
            init.frequency_sd,
            init.skew,
            self.cfg.combine_limit,
            self.cfg.reselect_distance,
            host.lcl_max_clock_error(),
        );

        // Apply combine's per-source effects (distant counter + status marks).
        for (k, &index) in sel_sources.iter().enumerate() {
            self.sources[index].distant = entries[k].distant;
            match marks[k] {
                CombineMark::Distant => self.mark_source(host, index, SrcStatus::Distant),
                CombineMark::Unselected => self.mark_source(host, index, SrcStatus::Unselected),
                CombineMark::Combined => {}
            }
        }

        host.ref_set_reference(
            self.sources[selected].stratum,
            leap_status,
            result.combined,
            self.sources[selected].ref_id,
            init.ref_time,
            result.offset,
            result.offset_sd,
            result.frequency,
            result.frequency_sd,
            result.skew,
            init.root_delay,
            init.root_dispersion,
        );
    }

    /// chrony `find_source`: by IP (NTP) or refid (refclock).
    pub fn find_source(&self, has_ip: bool, ip_key: u32, ref_id: u32) -> Option<usize> {
        self.sources.iter().position(|s| {
            (has_ip && s.type_ == SrcType::Ntp && s.has_ip && s.ref_id == ip_key)
                || (!has_ip && s.type_ == SrcType::Refclock && ref_id == s.ref_id)
        })
    }

    // ---- Stage 4: lifecycle, slew/dispersion handlers, reports, accessors ----

    /// chrony `SRC_Finalise`.
    pub fn finalise(&mut self) {
        self.sources.clear();
        self.selected_source_index = INVALID_SOURCE;
    }

    /// chrony `SRC_DestroyInstance`: remove a source, reindex, and fix up the selected
    /// index (re-selecting if the reference or a falseticker contributor was removed).
    pub fn destroy_instance(&mut self, host: &mut dyn SourcesHost, index: usize) {
        if self.last_updated_inst == index as i32 {
            self.last_updated_inst = INVALID_SOURCE;
        }
        self.sources.remove(index);
        for (i, s) in self.sources.iter_mut().enumerate() {
            s.index = i;
        }
        let dead = index as i32;
        if self.selected_source_index > dead {
            self.selected_source_index -= 1;
        } else if self.selected_source_index == dead {
            self.unselect_selected_source(false);
        }
        self.select_source(host, None);
    }

    /// chrony `SRC_ReselectSource`: force re-selection of the best source.
    pub fn reselect_source(&mut self, host: &mut dyn SourcesHost) {
        self.selected_source_index = INVALID_SOURCE;
        self.select_source(host, None);
    }

    /// chrony `SRC_SetReselectDistance`.
    pub fn set_reselect_distance(&mut self, distance: f64) {
        self.cfg.reselect_distance = distance;
    }

    /// chrony `SRC_ResetSources`.
    pub fn reset_sources(&mut self, host: &mut dyn SourcesHost) {
        for i in 0..self.sources.len() {
            self.reset_instance(host, i);
        }
    }

    /// chrony `SRC_ModifySelectOptions`: change a source's configured options.
    /// Returns whether the source was found.
    pub fn modify_select_options(
        &mut self,
        index: usize,
        options: i32,
        mask: i32,
        mode: AuthSelectMode,
    ) -> bool {
        if index >= self.sources.len() {
            return false;
        }
        if self.sources[index].conf_sel_options & mask == options {
            return true;
        }
        self.sources[index].conf_sel_options =
            (self.sources[index].conf_sel_options & !mask) | options;
        self.update_sel_options(mode);
        true
    }

    /// chrony `slew_sources`: adjust every source's statistics for a clock change
    /// (composing the ported `sourcestats`). `unknown_step` resets instead of slewing.
    pub fn slew_sources(
        &mut self,
        host: &mut dyn SourcesHost,
        cooked: f64,
        dfreq: f64,
        doffset: f64,
        unknown_step: bool,
    ) {
        for s in &mut self.sources {
            if unknown_step {
                s.stats.reset();
            } else {
                s.stats.slew_samples(cooked, dfreq, doffset);
            }
        }
        if unknown_step {
            self.select_source(host, None);
        }
    }

    /// chrony `add_dispersion`: add an indeterminate dispersion to every source.
    pub fn add_dispersion(&mut self, dispersion: f64) {
        for s in &mut self.sources {
            s.stats.add_dispersion(dispersion);
        }
    }

    /// chrony `SRC_GetSelectReport`: the per-source selection report.
    pub fn get_select_report(&self, index: usize) -> Option<SelectReport> {
        let s = self.sources.get(index)?;
        Some(SelectReport {
            ref_id: s.ref_id,
            state_char: super::combine::get_status_char(s.status),
            authentication: s.authenticated,
            leap: s.leap,
            conf_options: s.conf_sel_options,
            eff_options: s.sel_options,
            // chrony assigns the double last_sample_ago to a uint32 field (truncation).
            last_sample_ago: s.sel_info.last_sample_ago as u32,
            score: s.sel_score,
            lo_limit: s.sel_info.lo_limit,
            hi_limit: s.sel_info.hi_limit,
        })
    }

    /// chrony `SRC_ReportSource`'s `report->state` mapping (the `RPT_*` source state).
    pub fn report_state(&self, index: usize) -> i32 {
        match self.sources[index].status {
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

    /// chrony `source_to_string`: the refid string for a refclock; for an NTP source
    /// the caller supplies its IP string (chrony's `UTI_IPToString`).
    pub fn source_to_string(&self, index: usize, ntp_ip: Option<&str>) -> String {
        match self.sources[index].type_ {
            SrcType::Refclock => crate::util::refid_to_string(self.sources[index].ref_id),
            SrcType::Ntp => ntp_ip.unwrap_or("").to_string(),
        }
    }

    /// chrony `get_dumpfile`: the dump filename for a source. Refclocks use
    /// `refid:HHHHHHHH`; NTP sources use their IP string (supplied, must be real).
    pub fn dump_filename(&self, index: usize, ntp_ip: Option<&str>) -> Option<String> {
        match self.sources[index].type_ {
            SrcType::Refclock => Some(format!("refid:{:08x}", self.sources[index].ref_id)),
            SrcType::Ntp => ntp_ip.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        }
    }

    /// chrony `SRC_RemoveDumpFiles`'s per-file gate: whether a `.dat` base name looks
    /// like an actual dump file (`refid:` prefix or a valid IP literal).
    pub fn is_dump_file_name(name: &str, is_ip: impl Fn(&str) -> bool) -> bool {
        name.starts_with("refid:") || is_ip(name)
    }

    /// chrony `save_source`: serialise a source's dump (the `SRC0` header + the ported
    /// sourcestats dump). `ntp_name` is the resolved server name (`"."` for refclocks).
    pub fn save_source(&self, index: usize, ntp_name: &str) -> Option<String> {
        let s = &self.sources[index];
        let sst = s.stats.save_to_string()?;
        Some(format!(
            "SRC0\n{}\n{} {:o} {} {} {}\n{}",
            ntp_name,
            s.authenticated as i32,
            s.reachability,
            s.reachability_size,
            s.stratum,
            s.leap as i32,
            sst,
        ))
    }

    /// chrony `load_source`: restore a source from its dump `content`. For NTP sources
    /// the saved name must match `ntp_name`. Returns whether the dump loaded.
    pub fn load_source(
        &mut self,
        index: usize,
        content: &str,
        ntp_name: Option<&str>,
        now: f64,
    ) -> bool {
        let mut parts = content.splitn(4, '\n');
        let (Some(l1), Some(l2), Some(l3), sst) =
            (parts.next(), parts.next(), parts.next(), parts.next().unwrap_or(""))
        else {
            return false;
        };
        if l1 != "SRC0" {
            return false;
        }
        // chrony splits line 2 to one word (the saved name).
        let name_word = l2.split_whitespace().next().unwrap_or("");
        if self.sources[index].type_ == SrcType::Ntp
            && !matches!(ntp_name, Some(n) if n == name_word)
        {
            return false;
        }
        // line 3: "auth reach(octal) reach_size stratum leap".
        let mut it = l3.split_whitespace();
        let parse_i32 = |o: Option<&str>| o.and_then(|w| w.parse::<i32>().ok());
        let auth = parse_i32(it.next());
        let reach = it.next().and_then(|w| u32::from_str_radix(w, 8).ok());
        let reach_size = parse_i32(it.next());
        let stratum = parse_i32(it.next());
        let leap = parse_i32(it.next());
        let (Some(auth), Some(reach), Some(reach_size), Some(stratum), Some(leap)) =
            (auth, reach, reach_size, stratum, leap)
        else {
            return false;
        };

        if (auth == 0 && self.sources[index].authenticated)
            || !(0..NTP_MAX_STRATUM).contains(&stratum)
            || !(0..3).contains(&leap)
            || !self.sources[index].stats.load_from_string(sst, now)
        {
            return false;
        }

        let s = &mut self.sources[index];
        s.reachability = reach & ((1u32 << SOURCE_REACH_BITS) - 1);
        s.reachability_size = reach_size.clamp(0, SOURCE_REACH_BITS as i32);
        s.stratum = stratum;
        s.leap = match leap {
            1 => NtpLeap::InsertSecond,
            2 => NtpLeap::DeleteSecond,
            _ => NtpLeap::Normal,
        };
        true
    }

    /// chrony `SRC_ReportSource`: the source-level report fields (state + reachability
    /// + stratum + ref_id) merged with the ported sourcestats source report.
    pub fn report_source(
        &self,
        index: usize,
        now: f64,
    ) -> Option<(i32, u32, i32, u32, crate::sourcestats::SourceReport)> {
        let s = self.sources.get(index)?;
        Some((
            self.report_state(index),
            s.reachability,
            s.stratum,
            s.ref_id,
            s.stats.source_report(now),
        ))
    }

    /// chrony `SRC_ReportSourcestats`: ref_id + the ported sourcestats statistics report.
    pub fn report_sourcestats(
        &self,
        index: usize,
        now: f64,
    ) -> Option<(u32, crate::sourcestats::SourcestatsReport)> {
        let s = self.sources.get(index)?;
        Some((s.ref_id, s.stats.sourcestats_report(now)))
    }

    /// chrony `log_selection_message`: only emitted in the normal reference mode.
    pub fn log_selection_message(&self, mode_is_normal: bool, message: &str) -> Option<String> {
        if !mode_is_normal {
            return None;
        }
        Some(message.to_string())
    }

    /// chrony `log_selection_source`: format a source identity into a selection log
    /// message (mode-gated). `name` is the source string (refid or IP[+name]).
    pub fn log_selection_source(
        &self,
        mode_is_normal: bool,
        format: &str,
        name: &str,
    ) -> Option<String> {
        self.log_selection_message(mode_is_normal, &format.replace("%s", name))
    }

    /// chrony `SRC_DumpSources`: serialise every source via `save`, keyed by index.
    pub fn dump_sources(&self, mut save: impl FnMut(usize, String)) {
        for i in 0..self.sources.len() {
            // The NTP name is the daemon's; refclocks use ".".
            if self.sources[i].type_ == SrcType::Refclock {
                if let Some(dump) = self.save_source(i, ".") {
                    save(i, dump);
                }
            }
        }
    }

    /// chrony `SRC_ReloadSources`: restore every source via `load`, then allow an
    /// immediate reference update and re-select.
    pub fn reload_sources(
        &mut self,
        host: &mut dyn SourcesHost,
        now: f64,
        mut load: impl FnMut(usize) -> Option<String>,
    ) {
        for i in 0..self.sources.len() {
            if let Some(content) = load(i) {
                let name = if self.sources[i].type_ == SrcType::Refclock { Some(".") } else { None };
                self.load_source(i, &content, name, now);
            }
            self.sources[i].updates += 1;
        }
        self.select_source(host, None);
    }
}

impl SrcInstance {
    fn set_refid(&mut self, ref_id: u32, has_ip: bool) {
        self.ref_id = ref_id;
        self.has_ip = has_ip;
        self.stats.set_refid(ref_id, has_ip);
    }
}

#[cfg(test)]
mod tests;
