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

/// chrony `SRC_Type`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SrcType {
    /// `SRC_NTP`.
    Ntp,
    /// `SRC_REFCLOCK`.
    Refclock,
}

/// chrony `SRC_Status` (the source-classification labels).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

/// chrony `struct SelectInfo` — the per-source data the selection pass fills.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SelectInfo {
    pub stratum: i32,
    pub leap: i32,
    pub root_distance: f64,
    pub std_dev: f64,
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
}

/// chrony's `sources.c` module state: the table of sources + the selected index.
#[derive(Default)]
pub struct SourceRegistry {
    sources: Vec<SrcInstance>,
    selected_source_index: i32,
    /// chrony `report_selection_loss`: set when selection is lost; consumed by the
    /// selection stage's `unselect_selected_source` (a later stage).
    #[allow(dead_code)]
    report_selection_loss: bool,
}

impl SourceRegistry {
    /// chrony `SRC_Initialise`.
    pub fn new() -> SourceRegistry {
        SourceRegistry {
            sources: Vec::new(),
            selected_source_index: INVALID_SOURCE,
            report_selection_loss: false,
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

    /// chrony `find_source`: by IP (NTP) or refid (refclock).
    pub fn find_source(&self, has_ip: bool, ip_key: u32, ref_id: u32) -> Option<usize> {
        self.sources.iter().position(|s| {
            (has_ip && s.type_ == SrcType::Ntp && s.has_ip && s.ref_id == ip_key)
                || (!has_ip && s.type_ == SrcType::Refclock && ref_id == s.ref_id)
        })
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
