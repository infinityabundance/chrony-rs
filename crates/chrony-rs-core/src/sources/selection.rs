//! Source selection: falseticker rejection by interval intersection.
//!
//! # What this reproduces, and what it does NOT (read before claiming parity)
//!
//! chrony decides which sources are trustworthy by treating each as a confidence
//! interval `[offset ± root_distance]` and finding the largest set that mutually
//! overlap — the *majority clique* of "truechimers". Sources whose interval falls
//! outside that agreement are *falsetickers* and are rejected. This module
//! reconstructs that **core idea**: a maximum-overlap sweep over interval
//! endpoints, a majority requirement, and falseticker labelling.
//!
//! It deliberately does **not** reproduce, and must not be claimed to:
//!
//!   * chrony's exact falseticker-count loop (incrementally tolerating `f`
//!     falsetickers with a midpoint refinement, RFC 5905 §11.2.1 style),
//!   * chrony's clustering/combining stage (jitter-weighted trimming),
//!   * chrony's precise tie-breaking, `prefer`/`trust` bias, and reselection
//!     hysteresis (`reselectdist`).
//!
//! Consequently `selected` here is "the truechimer with the smallest root
//! distance" — a transparent, documented stand-in for chrony's cluster pick, NOT
//! its output. The exact decision is an oracle court (CHRONY.FILTER.8–.11) that
//! requires a captured chronyd run; until then this is an *algorithmic* court,
//! not an oracle-witnessed one. See `docs/filtering-atlas.md`.

use super::source::Source;

/// The result of running selection over a set of sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionOutcome {
    /// Sources in the majority clique (ids), sorted for deterministic output.
    pub truechimers: Vec<String>,
    /// Selectable sources rejected as falsetickers (outside the clique).
    pub falsetickers: Vec<String>,
    /// Sources excluded before the interval math (offline/unreachable/no sample/
    /// bad stratum). See [`Source::is_selectable`].
    pub unselectable: Vec<String>,
    /// The chosen source id, or `None` if no majority clique exists. This is the
    /// documented stand-in (min root distance among truechimers), not chrony's
    /// cluster output.
    pub selected: Option<String>,
    /// Whether a strict majority clique was found. Without one, chrony cannot tell
    /// truechimers from falsetickers, so `selected` is `None` and no source is
    /// blamed as a falseticker.
    pub majority: bool,
}

/// An interval endpoint for the sweep.
struct Endpoint {
    edge: f64,
    /// +1 at a lower edge (interval opens), -1 at an upper edge (interval closes).
    delta: i32,
}

/// Run selection over `sources`.
pub fn select(sources: &[Source]) -> SelectionOutcome {
    let mut unselectable = Vec::new();
    let mut candidates: Vec<(&Source, (f64, f64))> = Vec::new();
    for s in sources {
        match s.selection_interval() {
            Some(iv) => candidates.push((s, iv)),
            None => unselectable.push(s.id.clone()),
        }
    }
    unselectable.sort();

    if candidates.is_empty() {
        return SelectionOutcome {
            truechimers: Vec::new(),
            falsetickers: Vec::new(),
            unselectable,
            selected: None,
            majority: false,
        };
    }

    let best_point = max_overlap_point(&candidates);

    // The clique is every candidate whose closed interval contains best_point.
    let mut clique: Vec<&Source> = Vec::new();
    let mut outside: Vec<&Source> = Vec::new();
    for (s, (lo, hi)) in &candidates {
        if *lo <= best_point && best_point <= *hi {
            clique.push(s);
        } else {
            outside.push(s);
        }
    }

    // Majority: the agreeing set must be strictly more than half of the selectable
    // sources. Otherwise we cannot distinguish truth from error and refuse to pick
    // or to blame (chrony likewise will not sync without a majority).
    let majority = clique.len() * 2 > candidates.len();

    if !majority {
        return SelectionOutcome {
            truechimers: Vec::new(),
            falsetickers: Vec::new(),
            unselectable,
            selected: None,
            majority: false,
        };
    }

    // Stand-in pick: smallest root distance, ties broken by id for determinism.
    let selected = clique
        .iter()
        .min_by(|a, b| {
            let da = a.last_sample.map(|s| s.root_distance()).unwrap_or(f64::INFINITY);
            let db = b.last_sample.map(|s| s.root_distance()).unwrap_or(f64::INFINITY);
            da.partial_cmp(&db)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        })
        .map(|s| s.id.clone());

    let mut truechimers: Vec<String> = clique.iter().map(|s| s.id.clone()).collect();
    let mut falsetickers: Vec<String> = outside.iter().map(|s| s.id.clone()).collect();
    truechimers.sort();
    falsetickers.sort();

    SelectionOutcome {
        truechimers,
        falsetickers,
        unselectable,
        selected,
        majority: true,
    }
}

/// Find a coordinate covered by the maximum number of intervals (Marzullo-style
/// sweep). Closed intervals that merely touch (one's `hi` equals another's `lo`)
/// are treated as overlapping, achieved by processing opening edges before closing
/// edges at the same coordinate.
fn max_overlap_point(candidates: &[(&Source, (f64, f64))]) -> f64 {
    let mut events: Vec<Endpoint> = Vec::with_capacity(candidates.len() * 2);
    for (_, (lo, hi)) in candidates {
        events.push(Endpoint { edge: *lo, delta: 1 });
        events.push(Endpoint { edge: *hi, delta: -1 });
    }
    events.sort_by(|a, b| {
        a.edge
            .partial_cmp(&b.edge)
            .unwrap_or(std::cmp::Ordering::Equal)
            // At equal coordinate, opens (+1) before closes (-1).
            .then_with(|| b.delta.cmp(&a.delta))
    });

    let mut cur = 0i32;
    let mut best = -1i32;
    let mut best_point = candidates[0].1 .0;
    for e in &events {
        cur += e.delta;
        if cur > best {
            best = cur;
            best_point = e.edge;
        }
    }
    best_point
}

#[cfg(test)]
mod tests {
    use super::super::source::{SampleSummary, Source};
    use super::*;

    fn src(id: &str, offset: f64, dist: f64) -> Source {
        let mut s = Source::new(id);
        s.stratum = 2;
        s.reach.register(true);
        s.last_sample = Some(SampleSummary {
            offset,
            root_delay: 0.0,
            root_dispersion: dist,
        });
        s
    }

    #[test]
    fn three_agree_one_disagrees_marks_the_outlier() {
        // CHRONY.FILTER.8 — a clear falseticker among agreeing sources.
        let sources = vec![
            src("a", 0.100, 0.010), // [0.090, 0.110]
            src("b", 0.105, 0.010), // [0.095, 0.115]
            src("c", 0.098, 0.010), // [0.088, 0.108]
            src("d", 0.500, 0.010), // [0.490, 0.510] — disjoint
        ];
        let out = select(&sources);
        assert!(out.majority);
        assert_eq!(out.truechimers, vec!["a", "b", "c"]);
        assert_eq!(out.falsetickers, vec!["d"]);
        // d is the outlier; the pick is among the agreeing three.
        assert!(matches!(out.selected.as_deref(), Some("a" | "b" | "c")));
    }

    #[test]
    fn min_root_distance_wins_among_truechimers() {
        let sources = vec![
            src("wide", 0.100, 0.050),   // big interval, big distance
            src("narrow", 0.101, 0.005), // tight interval, small distance
            src("mid", 0.099, 0.020),
        ];
        let out = select(&sources);
        assert!(out.majority);
        assert_eq!(out.selected.as_deref(), Some("narrow"));
    }

    #[test]
    fn no_majority_picks_nothing_and_blames_no_one() {
        // Two sources that disagree: cannot tell which is the falseticker.
        let sources = vec![src("a", 0.0, 0.010), src("b", 1.0, 0.010)];
        let out = select(&sources);
        assert!(!out.majority);
        assert_eq!(out.selected, None);
        assert!(out.falsetickers.is_empty(), "no blame without a majority");
    }

    #[test]
    fn unselectable_sources_are_partitioned_out() {
        // CHRONY.SOURCE.6/.7 — offline/unreachable/bad-stratum never reach the math.
        let mut offline = src("off", 0.1, 0.01);
        offline.status = super::super::source::SourceStatus::Offline;
        let mut bad_stratum = src("bad", 0.1, 0.01);
        bad_stratum.stratum = 16;
        let sources = vec![src("a", 0.1, 0.01), src("b", 0.1, 0.01), offline, bad_stratum];
        let out = select(&sources);
        assert_eq!(out.unselectable, vec!["bad", "off"]);
        assert_eq!(out.truechimers, vec!["a", "b"]);
    }

    #[test]
    fn empty_input_is_safe() {
        let out = select(&[]);
        assert!(!out.majority);
        assert_eq!(out.selected, None);
    }

    #[test]
    fn touching_intervals_count_as_overlapping() {
        // a:[0.00,0.10], b:[0.10,0.20], c:[0.05,0.15] all share the point 0.10.
        let sources = vec![
            src("a", 0.05, 0.05),
            src("b", 0.15, 0.05),
            src("c", 0.10, 0.05),
        ];
        let out = select(&sources);
        assert!(out.majority);
        assert_eq!(out.truechimers, vec!["a", "b", "c"]);
    }
}
