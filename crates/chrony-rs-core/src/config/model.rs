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

/// `leapsecmode` value (chrony `REF_LeapMode`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LeapSecMode {
    System,
    Slew,
    Step,
    Ignore,
}

/// `authselectmode` value (chrony `SRC_AuthSelectMode`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AuthSelectMode {
    Require,
    Prefer,
    Mix,
    Ignore,
}

/// A `log` flag (chrony's `parse_log` keywords, matched case-sensitively). `RawMeasurements`
/// additionally implies measurement logging in chrony.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LogFlag {
    RawMeasurements,
    Measurements,
    Selection,
    Statistics,
    Tracking,
    Rtc,
    Refclocks,
    Tempcomp,
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
    /// A single-integer directive (e.g. `cmdport 0`), parsed with chrony's lenient
    /// `sscanf("%d")` semantics. The keyword is kept lowercased.
    ScalarInt { keyword: String, value: i32 },
    /// A single-double directive (e.g. `maxupdateskew 100.0`), parsed with chrony's
    /// lenient `sscanf("%lf")` semantics.
    ScalarDouble { keyword: String, value: f64 },
    /// A single-unsigned directive (e.g. `clientloglimit 1048576`), parsed with chrony's
    /// `sscanf("%lu")` semantics (a leading `-` wraps).
    ScalarUint { keyword: String, value: u64 },
    /// A single-string directive (e.g. `pidfile /run/chronyd.pid`). chrony's `parse_string`
    /// requires exactly one argument and stores it verbatim.
    ScalarString { keyword: String, value: String },
    /// `maxchange <threshold> <delay> <ignore>` — chrony reads all three with one
    /// `sscanf("%lf %d %d")`, so a malformed earlier field fails the whole directive.
    MaxChange { threshold: f64, delay: i32, ignore: i32 },
    /// `leapsecmode <mode>`.
    LeapSecMode(LeapSecMode),
    /// `authselectmode <mode>`.
    AuthSelectMode(AuthSelectMode),
    /// `log <flag>...` — the enabled logging categories, in declaration order.
    Log(Vec<LogFlag>),
    /// `allow` / `deny` / `cmdallow` / `cmddeny` — an access-control restriction. `allow`
    /// is the allow/deny sense; `cmd` selects the command (vs NTP) restriction table. The
    /// `spec` is chrony's parsed `CPS_ParseAllowDeny` output (feed into the addrfilt table).
    AccessRestriction { allow: bool, cmd: bool, spec: crate::cmdparse::AllowDeny },
    /// `fallbackdrift <min> <max>` — the min/max log2-second fallback drift intervals
    /// (read with one `sscanf("%d %d")`, so both must parse).
    FallbackDrift { min: i32, max: i32 },
    /// `smoothtime <max-freq> <max-wander> [leaponly]` — the time-smoothing parameters
    /// (`sscanf("%lf %lf")`) plus the optional `leaponly` flag.
    SmoothTime { max_freq: f64, max_wander: f64, leap_only: bool },
    /// `initstepslew <threshold> [source]...` — the step threshold and the source
    /// host strings (resolution is a daemon-time boundary, deferred). Ignored at runtime
    /// when chronyd was started with `-R`, which is not a parse concern.
    InitStepSlew { threshold: f64, sources: Vec<String> },
    /// `local [stratum N] [orphan] [distance D]` — the local-reference options (chrony's
    /// `CPS_ParseLocal`). The directive's presence enables local mode.
    Local(crate::cmdparse::LocalOpts),
    /// `sourcedir <dir>` — a directory scanned for `*.sources` files. chrony stores the
    /// rest of the line verbatim (no tokenization or arity check).
    SourceDir { path: String },
    /// `confdir <dir>...` — 1..=10 directories scanned for `*.conf` files (the file
    /// reading/globbing is a daemon-time boundary, deferred).
    ConfDir { dirs: Vec<String> },
    /// `include <pattern>` — a glob pattern of config files to include (the glob expansion
    /// and file reading are a daemon-time boundary, deferred).
    Include { pattern: String },
    /// `ratelimit` / `cmdratelimit` / `ntsratelimit` `[interval N] [burst N] [leak N]`.
    /// The directive's presence enables it; each option is optional and may appear in any
    /// order. chrony reads the value of each option with `sscanf("%d%n")`, advancing past
    /// only the digits, so a value's trailing junk becomes a (bad) option key.
    RateLimit {
        keyword: String,
        interval: Option<i32>,
        burst: Option<i32>,
        leak: Option<i32>,
    },
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
