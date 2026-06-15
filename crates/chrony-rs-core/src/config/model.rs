//! Typed model of an (admitted-subset) chrony configuration.
//!
//! Only directives with an oracle case are given typed structure. Everything else
//! is kept as [`Directive::Unmodeled`] — recognized, line-preserved, but not
//! interpreted. This is the difference between "we read the file the way chrony
//! does" (true now) and "we implement this directive's behavior" (true only per
//! `docs/config-atlas.md`).

use serde::{Deserialize, Serialize};

/// Whether a time source was declared as a single `server`, a `pool` of servers,
/// or a symmetric `peer`. These differ in chrony's source handling, not just
/// syntax, which is why the distinction is carried in the type rather than a flag.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ServerKind {
    Server,
    Pool,
    Peer,
}

/// A `server` / `pool` / `peer` directive with the options chrony-rs currently
/// models. Unmodeled options on the line are kept in [`raw_options`] so nothing
/// is lost and so a future court can promote them without a re-parse.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SourceDirective {
    pub kind: ServerKind,
    /// Hostname or address as written. Not resolved here — name resolution is a
    /// daemon-time, OS-boundary concern and must not happen in the parser.
    pub address: String,
    pub iburst: bool,
    pub burst: bool,
    /// `minpoll N` / `maxpoll N` as log2 seconds, if present.
    pub minpoll: Option<i32>,
    pub maxpoll: Option<i32>,
    /// Options we recognized on the line but do not yet model (e.g. `key`,
    /// `nts`, `xleave`). Preserved verbatim, in order.
    pub raw_options: Vec<String>,
}

/// A modeled directive, or an unmodeled-but-preserved one.
///
/// Note: only `PartialEq` (not `Eq`) because `MakeStep.threshold` is an `f64`.
/// Config comparison in tests is by value equality, which is what we want; we do
/// not key collections on `Directive`, so the missing `Eq` costs nothing.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Directive {
    Source(SourceDirective),
    /// `driftfile <path>`.
    DriftFile { path: String },
    /// `makestep <threshold> <limit>`. `limit` of -1 means "always", which chrony
    /// encodes specially; we keep it as the literal integer and defer that policy
    /// to the discipline campaign rather than reinterpreting it here.
    MakeStep { threshold: f64, limit: i32 },
    /// `rtcsync` — a bare flag directive.
    RtcSync,
    /// A recognized keyword whose semantics chrony-rs does not yet model. The full
    /// original token line is retained.
    Unmodeled {
        keyword: String,
        args: Vec<String>,
    },
}

/// A parsed configuration: the ordered directives plus the line each came from.
/// Order is preserved because chrony's behavior can depend on directive order
/// (e.g. later `driftfile` wins), and discarding order would lose that.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub directives: Vec<(usize, Directive)>,
}

impl Config {
    /// All declared sources, in declaration order.
    pub fn sources(&self) -> impl Iterator<Item = &SourceDirective> {
        self.directives.iter().filter_map(|(_, d)| match d {
            Directive::Source(s) => Some(s),
            _ => None,
        })
    }

    /// The effective drift file path (last `driftfile` wins, matching chrony's
    /// last-assignment-wins behavior for single-valued directives).
    pub fn drift_file(&self) -> Option<&str> {
        self.directives
            .iter()
            .rev()
            .find_map(|(_, d)| match d {
                Directive::DriftFile { path } => Some(path.as_str()),
                _ => None,
            })
    }
}
