//! Source combining + selection helpers — Stage 2 of the staged `sources.c` port.
//!
//! This stage ports the *numeric combine* (`combine_sources`) and the small selection
//! helpers (`compare_sort_elements`, `get_status_char`). `combine_sources` is the
//! weighted blend of the selectable sources' offsets and frequencies that chrony
//! feeds to `REF_SetReference` — the heart of the combine step. The full
//! `SRC_SelectSource` classification/intersection pipeline that *calls* it lands in
//! Stage 3 ([`crate::sources::registry::SourceRegistry`] gains the selector then).
//!
//! # Oracle
//!
//! `combine_sources` is differential-tested against the **real compiled `sources.c`**:
//! the C generator drives `SRC_SelectSource` over two controlled, agreeing sources
//! (controlled `SST_GetSelectionData` / `SST_GetTrackingData`), so the selector
//! classifies, intersects, selects, and combines for real, and captures the combined
//! `REF_SetReference` result (`research/oracle/sources-combine-c-vectors.txt`). This
//! port replays the identical per-source tracking data through [`combine_sources`] and
//! matches the combined offset / offset-sd / frequency / frequency-sd / skew. The
//! distant-penalty path and the status-char/sort helpers are unit-tested.

use crate::sourcestats::TrackingData;
use super::registry::{SrcStatus, DISTANT_PENALTY, SOURCE_REACH_BITS};

fn square(x: f64) -> f64 {
    x * x
}

/// chrony `get_status_char`: the single-character status code used in reports/logs.
pub fn get_status_char(status: SrcStatus) -> char {
    match status {
        SrcStatus::Unselectable => 'N',
        SrcStatus::Unsynchronised => 's',
        SrcStatus::BadStats => 'M',
        SrcStatus::BadDistance => 'd',
        SrcStatus::Jittery => '~',
        SrcStatus::WaitsStats => 'w',
        SrcStatus::Stale => 'S',
        SrcStatus::Orphan => 'O',
        SrcStatus::Untrusted => 'T',
        SrcStatus::Falseticker => 'x',
        SrcStatus::WaitsSources => 'W',
        SrcStatus::Nonpreferred => 'P',
        SrcStatus::WaitsUpdate => 'U',
        SrcStatus::Distant => 'D',
        SrcStatus::Outlier => 'L',
        SrcStatus::Unselected => '+',
        SrcStatus::Selected => '*',
        // SRC_OK and any other -> default.
        SrcStatus::Ok => '?',
    }
}

/// chrony `Sort_Element` tag (an interval endpoint).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum EndpointTag {
    /// `LOW` (= -1).
    Low,
    /// `HIGH` (= +1).
    High,
}

impl EndpointTag {
    fn order(self) -> i32 {
        match self {
            EndpointTag::Low => -1,
            EndpointTag::High => 1,
        }
    }
}

/// chrony `struct Sort_Element`.
#[derive(Clone, Copy, Debug)]
pub struct SortElement {
    pub index: usize,
    pub offset: f64,
    pub tag: EndpointTag,
}

/// chrony `compare_sort_elements`: order by offset, then by tag (LOW before HIGH).
pub fn compare_sort_elements(u: &SortElement, v: &SortElement) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if u.offset < v.offset {
        Ordering::Less
    } else if u.offset > v.offset {
        Ordering::Greater
    } else {
        u.tag.order().cmp(&v.tag.order())
    }
}

/// One selectable source for [`combine_sources`] (a `sel_sources` entry).
#[derive(Clone, Copy, Debug)]
pub struct CombineEntry {
    /// `sel_info.root_distance`.
    pub root_distance: f64,
    /// `distant` counter (in/out).
    pub distant: i32,
    /// `reachability_size`.
    pub reachability_size: i32,
    /// Whether this is the currently selected source (`index == selected_source_index`).
    pub is_selected: bool,
    /// Whether this is an NTP source (adds `reselect_distance` to the selected distance).
    pub is_ntp: bool,
    /// Whether `status == SRC_OK` on entry (marked `SRC_UNSELECTED` when combined).
    pub status_ok: bool,
    /// `SST_GetTrackingData` for this source.
    pub tracking: TrackingData,
}

/// What [`combine_sources`] decided per entry (the side-effects chrony applies via
/// `mark_source`): the updated `distant` counter and the new status.
#[derive(Clone, Copy, Debug, PartialEq)]
    #[non_exhaustive]
pub enum CombineMark {
    /// Marked `SRC_DISTANT` (and skipped).
    Distant,
    /// Marked `SRC_UNSELECTED` (combined).
    Unselected,
    /// Left as-is (combined; was not `SRC_OK`, e.g. the selected source).
    Combined,
}

/// The combined reference (chrony's in/out offset/frequency/skew + `combined` count).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CombineResult {
    pub combined: i32,
    pub offset: f64,
    pub offset_sd: f64,
    pub frequency: f64,
    pub frequency_sd: f64,
    pub skew: f64,
}

/// chrony `combine_sources`. `ref_time` and the initial offset/frequency/skew are the
/// selected source's tracking data (chrony fills them before the call); `entries` are
/// the `sel_sources` (including the selected one). Returns the combined result and the
/// per-entry mark decisions (the `distant` counters in `entries` are updated in place).
#[allow(clippy::too_many_arguments)]
pub fn combine_sources(
    entries: &mut [CombineEntry],
    ref_time: f64,
    init_offset: f64,
    init_offset_sd: f64,
    init_frequency: f64,
    init_frequency_sd: f64,
    init_skew: f64,
    combine_limit: f64,
    reselect_distance: f64,
    max_clock_error: f64,
) -> (CombineResult, Vec<CombineMark>) {
    let mut marks = vec![CombineMark::Combined; entries.len()];

    // chrony short-circuits a single source (the selected one).
    if entries.len() == 1 {
        return (
            CombineResult {
                combined: 1,
                offset: init_offset,
                offset_sd: init_offset_sd,
                frequency: init_frequency,
                frequency_sd: init_frequency_sd,
                skew: init_skew,
            },
            marks,
        );
    }

    // The selected source's distance (NTP adds reselect_distance).
    let sel = entries.iter().find(|e| e.is_selected).expect("a selected source");
    let mut sel_src_distance = sel.root_distance;
    if sel.is_ntp {
        sel_src_distance += reselect_distance;
    }

    let mut sum_offset_weight = 0.0;
    let mut sum_offset = 0.0;
    let mut sum2_offset_sd = 0.0;
    let mut sum_frequency_weight = 0.0;
    let mut sum_frequency = 0.0;
    let mut inv_sum2_frequency_sd = 0.0;
    let mut inv_sum2_skew = 0.0;
    let mut combined = 0;

    for (i, e) in entries.iter_mut().enumerate() {
        let t = e.tracking;

        // Distant check (uses the selected source's initial frequency/skew).
        if !e.is_selected
            && (e.root_distance > combine_limit * sel_src_distance
                || (init_frequency - t.frequency).abs()
                    > combine_limit * (init_skew + t.skew + max_clock_error))
        {
            e.distant = if e.reachability_size >= SOURCE_REACH_BITS as i32 {
                DISTANT_PENALTY
            } else {
                1
            };
        } else if e.distant != 0 {
            e.distant -= 1;
        }

        if e.distant != 0 {
            marks[i] = CombineMark::Distant;
            continue;
        }

        if e.status_ok {
            marks[i] = CombineMark::Unselected;
        }

        let elapsed = ref_time - t.ref_time;
        let src_offset = t.average_offset + elapsed * t.frequency;
        let src_offset_sd = t.offset_sd + elapsed * t.frequency_sd;
        let offset_weight = 1.0 / e.root_distance;
        let frequency_weight = 1.0 / square(t.frequency_sd);

        sum_offset_weight += offset_weight;
        sum_offset += offset_weight * src_offset;
        sum2_offset_sd += offset_weight * (square(src_offset_sd) + square(src_offset - init_offset));

        sum_frequency_weight += frequency_weight;
        sum_frequency += frequency_weight * t.frequency;
        inv_sum2_frequency_sd += 1.0 / square(t.frequency_sd);
        inv_sum2_skew += 1.0 / square(t.skew);

        combined += 1;
    }

    let result = CombineResult {
        combined,
        offset: sum_offset / sum_offset_weight,
        offset_sd: (sum2_offset_sd / sum_offset_weight).sqrt(),
        frequency: sum_frequency / sum_frequency_weight,
        frequency_sd: 1.0 / inv_sum2_frequency_sd.sqrt(),
        skew: 1.0 / inv_sum2_skew.sqrt(),
    };
    (result, marks)
}

#[cfg(test)]
mod tests;
