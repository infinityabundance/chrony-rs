//! Per-source state — a deliberately reduced cousin of chrony's `SRC_Instance`.
//!
//! chrony's real source instance carries a great deal (the full sample history,
//! regression estimator, asymmetry handling, NTP-vs-refclock specialization). We
//! model only what the *selection* court needs and label this honestly as a
//! reduction, not a clone. Promoting a field here requires a court that exercises
//! it.
//!
//! # Root distance (the load-bearing definition)
//!
//! Selection turns each source into a confidence interval around its offset. The
//! half-width is the *root distance*: how far the true time could be given delay
//! and dispersion accumulated from the reference down to us. chrony's synchro-
//! nisation distance is
//!
//! ```text
//!   root_distance = root_dispersion + |root_delay| / 2
//! ```
//!
//! (sample dispersion folds into `root_dispersion` upstream). The interval is then
//! `[offset - root_distance, offset + root_distance]`. A source is a *falseticker*
//! when its interval cannot be reconciled with the majority — see `selection.rs`.

use super::reachability::Reachability;

/// Online/offline status, as set by `online`/`offline` directives and commands.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
    #[non_exhaustive]
pub enum SourceStatus {
    #[default]
    Online,
    Offline,
}

/// The most recent measurement summary we keep for a source. All fields are in
/// seconds, sign conventions matching chrony: positive `offset` means the source's
/// clock reads ahead of ours.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct SampleSummary {
    pub offset: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
}

impl SampleSummary {
    /// chrony's root/synchronisation distance: `root_dispersion + |root_delay|/2`.
    pub fn root_distance(&self) -> f64 {
        self.root_dispersion + self.root_delay.abs() / 2.0
    }
}

/// A time source as the selector sees it.
#[derive(Clone, Debug)]
pub struct Source {
    /// Stable identity (address or refclock name) — used as the selection key.
    pub id: String,
    pub status: SourceStatus,
    pub reach: Reachability,
    /// Last advertised stratum. 0 or 16 are not usable as a sync source.
    pub stratum: u8,
    /// Most recent measurement, if any.
    pub last_sample: Option<SampleSummary>,
    /// `prefer`-style flag (chrony's preferred source bias). Modeled but not yet
    /// used by selection — recorded so config can round-trip into it later.
    pub preferred: bool,
}

impl Source {
    pub fn new(id: impl Into<String>) -> Self {
        Source {
            id: id.into(),
            status: SourceStatus::Online,
            reach: Reachability::new(),
            stratum: 0,
            last_sample: None,
            preferred: false,
        }
    }

    /// Whether this source is eligible to participate in selection at all. chrony
    /// excludes sources that are offline, unreachable, have no sample, or advertise
    /// an unusable stratum (0 = kiss/unspec, 16 = unsynchronised). Excluding these
    /// *before* the interval math is important: a stratum-16 server must not drag
    /// the intersection around (this is why the check lives here, not later — moving
    /// it would change which sources reach the clique, re-run CHRONY.SOURCE.7/.8).
    pub fn is_selectable(&self) -> bool {
        self.status == SourceStatus::Online
            && self.reach.is_reachable()
            && self.stratum != 0
            && self.stratum < 16
            && self.last_sample.is_some()
    }

    /// The selection interval `[offset - root_distance, offset + root_distance]`,
    /// or `None` if the source is not selectable.
    pub fn selection_interval(&self) -> Option<(f64, f64)> {
        if !self.is_selectable() {
            return None;
        }
        let s = self.last_sample?;
        let d = s.root_distance();
        Some((s.offset - d, s.offset + d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reachable_source(id: &str, offset: f64, dist: f64, stratum: u8) -> Source {
        let mut s = Source::new(id);
        s.stratum = stratum;
        s.reach.register(true);
        // Put all the distance into dispersion so root_distance == dist exactly.
        s.last_sample = Some(SampleSummary {
            offset,
            root_delay: 0.0,
            root_dispersion: dist,
        });
        s
    }

    #[test]
    fn root_distance_uses_half_delay() {
        let s = SampleSummary {
            offset: 0.0,
            root_delay: 0.010,
            root_dispersion: 0.002,
        };
        // 0.002 + 0.010/2 = 0.007
        assert!((s.root_distance() - 0.007).abs() < 1e-12);
    }

    #[test]
    fn selectable_requires_reach_online_sample_and_stratum() {
        // CHRONY.SOURCE.1/.6/.7
        let mut s = Source::new("a");
        assert!(!s.is_selectable(), "no reach/sample/stratum");
        s.reach.register(true);
        s.stratum = 2;
        assert!(!s.is_selectable(), "still no sample");
        s.last_sample = Some(SampleSummary { offset: 0.0, root_delay: 0.0, root_dispersion: 0.001 });
        assert!(s.is_selectable());
        s.status = SourceStatus::Offline;
        assert!(!s.is_selectable(), "offline excludes");
    }

    #[test]
    fn bad_stratum_is_not_selectable() {
        // CHRONY.SOURCE.7 — stratum 0 (kiss/unspec) and 16 (unsynchronised).
        let mut s = reachable_source("a", 0.0, 0.001, 0);
        assert!(!s.is_selectable(), "stratum 0 excluded");
        s.stratum = 16;
        assert!(!s.is_selectable(), "stratum 16 excluded");
        s.stratum = 15;
        assert!(s.is_selectable(), "stratum 15 ok");
    }

    #[test]
    fn interval_is_offset_plus_minus_distance() {
        let s = reachable_source("a", 0.100, 0.005, 2);
        let (lo, hi) = s.selection_interval().unwrap();
        assert!((lo - 0.095).abs() < 1e-12);
        assert!((hi - 0.105).abs() < 1e-12);
    }
}
