//! Tests for `sources.c` Stage 2 (combine + selection helpers).
//!
//! **Oracle #1 (gold standard): the real compiled `sources.c`.** A C generator drives
//! `SRC_SelectSource` over two controlled, agreeing sources (controlled
//! `SST_GetSelectionData` / `SST_GetTrackingData`), so chrony classifies, intersects,
//! selects, and combines for real, and captures the combined `REF_SetReference` result
//! (`research/oracle/sources-combine-c-vectors.txt`).
//! [`matches_real_c_combine_vectors`] replays the identical per-source tracking data
//! through [`combine_sources`] and matches the combined offset / offset-sd / frequency
//! / frequency-sd / skew.
//!
//! **Oracle #2 (independent): the distant penalty + the status-char/sort helpers.**

use super::*;
use crate::sourcestats::TrackingData;

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}
fn close(a: f64, b: f64, what: &str) {
    let tol = 1e-12 * (1.0 + a.abs().max(b.abs()));
    assert!((a - b).abs() <= tol, "{what}: rust={a:.17e} c={b:.17e}");
}

#[test]
fn matches_real_c_combine_vectors() {
    let vectors = include_str!("../../../../../research/oracle/sources-combine-c-vectors.txt");
    let l = vectors.lines().map(str::trim).find(|l| l.starts_with("COMBINE")).unwrap();

    // The two sources the C generator configured (source 0 is selected by score).
    let s0 = TrackingData {
        ref_time: 2_000_000_000.0,
        average_offset: 0.001,
        offset_sd: 0.0005,
        frequency: 1.0e-6,
        frequency_sd: 0.1e-6,
        skew: 1.0e-6,
        root_delay: 0.02,
        root_dispersion: 0.01,
    };
    let s1 = TrackingData {
        ref_time: 2_000_000_000.0,
        average_offset: -0.0005,
        offset_sd: 0.0006,
        frequency: 1.2e-6,
        frequency_sd: 0.15e-6,
        skew: 1.1e-6,
        root_delay: 0.025,
        root_dispersion: 0.012,
    };

    // sel_sources = [selected s0, s1]; init from the selected source's tracking.
    let mut entries = vec![
        CombineEntry {
            root_distance: 0.01,
            distant: 0,
            reachability_size: 8,
            is_selected: true,
            is_ntp: false,
            status_ok: false, // s0 is SRC_SELECTED by the time combine runs
            tracking: s0,
        },
        CombineEntry {
            root_distance: 0.015,
            distant: 0,
            reachability_size: 8,
            is_selected: false,
            is_ntp: false,
            status_ok: true, // s1 is SRC_OK -> marked UNSELECTED
            tracking: s1,
        },
    ];

    let (res, marks) = combine_sources(
        &mut entries,
        s0.ref_time,
        s0.average_offset,
        s0.offset_sd,
        s0.frequency,
        s0.frequency_sd,
        s0.skew,
        3.0,   // combine_limit
        1.0e-4, // reselect_distance (unused: refclock)
        1.0e-6, // max_clock_error
    );

    assert_eq!(res.combined, field(l, "combined").parse::<i32>().unwrap(), "combined count");
    close(res.offset, field(l, "off").parse().unwrap(), "combined offset");
    close(res.offset_sd, field(l, "osd").parse().unwrap(), "combined offset_sd");
    close(res.frequency, field(l, "fr").parse().unwrap(), "combined frequency");
    close(res.frequency_sd, field(l, "frsd").parse().unwrap(), "combined frequency_sd");
    close(res.skew, field(l, "sk").parse().unwrap(), "combined skew");

    // s1 (SRC_OK) is marked UNSELECTED; s0 (already SELECTED) is just combined.
    assert_eq!(marks, vec![CombineMark::Combined, CombineMark::Unselected]);
}

#[test]
fn distant_source_is_penalised_and_excluded() {
    let near = TrackingData {
        ref_time: 0.0,
        average_offset: 0.0,
        offset_sd: 0.001,
        frequency: 0.0,
        frequency_sd: 1.0e-7,
        skew: 1.0e-6,
        root_delay: 0.0,
        root_dispersion: 0.0,
    };
    // A source whose root distance is far beyond combine_limit * selected distance.
    let far = TrackingData { frequency: 0.0, ..near };
    let mut entries = vec![
        CombineEntry {
            root_distance: 0.01,
            distant: 0,
            reachability_size: 8,
            is_selected: true,
            is_ntp: false,
            status_ok: false,
            tracking: near,
        },
        CombineEntry {
            root_distance: 100.0, // >> 3 * 0.01
            distant: 0,
            reachability_size: 8,
            is_selected: false,
            is_ntp: false,
            status_ok: true,
            tracking: far,
        },
    ];
    let (res, marks) = combine_sources(
        &mut entries, 0.0, 0.0, 0.001, 0.0, 1.0e-7, 1.0e-6, 3.0, 1.0e-4, 1.0e-6,
    );
    assert_eq!(res.combined, 1, "only the near source combined");
    assert_eq!(marks[1], CombineMark::Distant, "far source marked distant");
    // A fully-reached distant source gets the full penalty.
    assert_eq!(entries[1].distant, DISTANT_PENALTY);
}

#[test]
fn single_source_short_circuits() {
    let t = TrackingData {
        ref_time: 0.0,
        average_offset: 0.5,
        offset_sd: 0.01,
        frequency: 2.0e-6,
        frequency_sd: 1.0e-7,
        skew: 1.0e-6,
        root_delay: 0.0,
        root_dispersion: 0.0,
    };
    let mut entries = vec![CombineEntry {
        root_distance: 0.01,
        distant: 0,
        reachability_size: 8,
        is_selected: true,
        is_ntp: false,
        status_ok: false,
        tracking: t,
    }];
    let (res, _) =
        combine_sources(&mut entries, 0.0, 0.5, 0.01, 2.0e-6, 1.0e-7, 1.0e-6, 3.0, 1.0e-4, 1.0e-6);
    assert_eq!(res.combined, 1);
    assert_eq!(res.offset, 0.5, "single source passes its offset through unchanged");
    assert_eq!(res.frequency, 2.0e-6);
}

#[test]
fn status_char_matches_chrony() {
    use crate::sources::registry::SrcStatus::*;
    assert_eq!(get_status_char(Unselectable), 'N');
    assert_eq!(get_status_char(Unsynchronised), 's');
    assert_eq!(get_status_char(BadStats), 'M');
    assert_eq!(get_status_char(BadDistance), 'd');
    assert_eq!(get_status_char(Jittery), '~');
    assert_eq!(get_status_char(Stale), 'S');
    assert_eq!(get_status_char(Falseticker), 'x');
    assert_eq!(get_status_char(Distant), 'D');
    assert_eq!(get_status_char(Outlier), 'L');
    assert_eq!(get_status_char(Unselected), '+');
    assert_eq!(get_status_char(Selected), '*');
}

#[test]
fn sort_orders_by_offset_then_low_before_high() {
    use std::cmp::Ordering;
    let lo = SortElement { index: 0, offset: 1.0, tag: EndpointTag::Low };
    let hi = SortElement { index: 0, offset: 1.0, tag: EndpointTag::High };
    let bigger = SortElement { index: 1, offset: 2.0, tag: EndpointTag::Low };
    assert_eq!(compare_sort_elements(&lo, &hi), Ordering::Less, "LOW sorts before HIGH at equal offset");
    assert_eq!(compare_sort_elements(&lo, &bigger), Ordering::Less);
    assert_eq!(compare_sort_elements(&bigger, &hi), Ordering::Greater);
}
