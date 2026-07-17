//! Rendering of chrony control-tool reports (currently `tracking`).
//!
//! This is an *output byte-parity* surface: `chronyc tracking` prints a fixed,
//! label-aligned block, and operators and scripts depend on that exact layout.
//! We reproduce the layout here, driven by a structured [`TrackingReport`] so the
//! renderer is testable offline without a live daemon or control socket.
//!
//! # Parity status (do not overclaim)
//!
//! The *label column layout* (16-char left-justified label, then `": "`) is
//! admitted and byte-tested below. The *numeric formatting and phrasing* of each
//! value (sign conventions, "fast/slow of NTP time", ppm wording) is reconstructed
//! from observed chrony output but is only claimed exact for values witnessed
//! against the oracle in `docs/chronyc-parity.md`. Where a numeric format has not
//! yet been witnessed, it is marked normalized there, not claimed as exact.
//!
//! The live control-socket transport (connecting to a running daemon) is a
//! deferred negative capability — see `docs/negative-capabilities.md`. This
//! renderer formats a report you already hold; it does not fetch one.

use serde::{Deserialize, Serialize};

/// Leap status as reported by `chronyc tracking`. The exact strings match
/// chrony's `leap_status` rendering and must not be paraphrased.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
    #[non_exhaustive]
pub enum LeapStatus {
    Normal,
    InsertSecond,
    DeleteSecond,
    NotSynchronised,
}

impl LeapStatus {
    fn as_chrony_str(self) -> &'static str {
        match self {
            LeapStatus::Normal => "Normal",
            LeapStatus::InsertSecond => "Insert second",
            LeapStatus::DeleteSecond => "Delete second",
            // British spelling is intentional: chrony prints "Not synchronised".
            LeapStatus::NotSynchronised => "Not synchronised",
        }
    }
}

/// Structured `tracking` data. Field names mirror chrony's report lines. Times in
/// seconds, frequencies in ppm, as chrony renders them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrackingReport {
    /// Reference ID as a 32-bit value, rendered uppercase hex (e.g. `0A000001`).
    pub reference_id: u32,
    /// Optional resolved name shown in parentheses after the hex refid.
    #[serde(default)]
    pub reference_name: Option<String>,
    pub stratum: u32,
    /// Reference time, formatted by the caller (we keep it as a preformatted
    /// string because date formatting/locale is its own court and must not be
    /// reinvented inside the renderer).
    pub ref_time_utc: String,
    /// System time offset in seconds. Positive means the system clock is *fast*
    /// of NTP time; chrony phrases the sign as "fast"/"slow of NTP time".
    pub system_time_offset: f64,
    pub last_offset: f64,
    pub rms_offset: f64,
    /// Frequency error in ppm. Positive = clock runs fast.
    pub frequency_ppm: f64,
    pub residual_freq_ppm: f64,
    pub skew_ppm: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub update_interval: f64,
    pub leap_status: LeapStatus,
}

impl TrackingReport {
    /// Render exactly as `chronyc tracking` would print. Returns the full block
    /// including the trailing newline on the last line.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let refid = match &self.reference_name {
            Some(name) => format!("{:08X} ({name})", self.reference_id),
            None => format!("{:08X} ()", self.reference_id),
        };
        line(&mut s, "Reference ID", &refid);
        line(&mut s, "Stratum", &self.stratum.to_string());
        line(&mut s, "Ref time (UTC)", &self.ref_time_utc);
        line(
            &mut s,
            "System time",
            &format!(
                "{:.9} seconds {} of NTP time",
                self.system_time_offset.abs(),
                fast_slow(self.system_time_offset),
            ),
        );
        line(&mut s, "Last offset", &format!("{:+.9} seconds", self.last_offset));
        line(&mut s, "RMS offset", &format!("{:.9} seconds", self.rms_offset));
        line(
            &mut s,
            "Frequency",
            &format!("{:.3} ppm {}", self.frequency_ppm.abs(), fast_slow(self.frequency_ppm)),
        );
        line(&mut s, "Residual freq", &format!("{:+.3} ppm", self.residual_freq_ppm));
        line(&mut s, "Skew", &format!("{:.3} ppm", self.skew_ppm));
        line(&mut s, "Root delay", &format!("{:.9} seconds", self.root_delay));
        line(&mut s, "Root dispersion", &format!("{:.9} seconds", self.root_dispersion));
        line(&mut s, "Update interval", &format!("{:.1} seconds", self.update_interval));
        line(&mut s, "Leap status", self.leap_status.as_chrony_str());
        s
    }
}

// ---------------------------------------------------------------------------
// `chronyc sources` (CHRONYC.2)
//
// Ported from chrony 4.5 `client.c::process_cmd_sources` and its `print_report`
// custom format engine. The header and verbose legend are *live-witnessed* against
// real chrony 4.5 output (`reports/oracle/chronyc-live/sources*.raw.out`); the data
// rows are byte-derived from the C format string
//   "%c%c %-27s  %2d  %2d   %3o  %I  %+S[%+S] +/- %S\n"
// and its `%I`/`%S` helpers (`print_seconds`, `print_(signed_)nanoseconds`).
// ---------------------------------------------------------------------------

/// The `sources` table header. Exactly chrony's literal (79 chars); the `=` rule
/// chrony prints under it is `'=' * header.len()` (see `print_header`).
const SOURCES_HEADER: &str =
    "MS Name/IP address         Stratum Poll Reach LastRx Last sample               ";

/// The `-v` legend block, printed before the header. Byte-identical to chrony's
/// nine `printf` lines (`process_cmd_sources`); the leading empty line and the
/// trailing `\` continuation lines are part of the real output.
const SOURCES_LEGEND_LINES: &[&str] = &[
    "",
    "  .-- Source mode  '^' = server, '=' = peer, '#' = local clock.",
    " / .- Source state '*' = current best, '+' = combined, '-' = not combined,",
    "| /             'x' = may be in error, '~' = too variable, '?' = unusable.",
    "||                                                 .- xxxx [ yyyy ] +/- zzzz",
    "||      Reachability register (octal) -.           |  xxxx = adjusted offset,",
    "||      Log2(Polling interval) --.      |          |  yyyy = measured offset,",
    "||                                \\     |          |  zzzz = estimated error.",
    "||                                 |    |           \\",
];

/// Source mode glyph (first column char), from `RPY_SD_MD_*` in chrony.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
    #[non_exhaustive]
pub enum SourceMode {
    /// `^` — a server we poll as a client.
    Server,
    /// `=` — a symmetric peer.
    Peer,
    /// `#` — a local reference clock.
    RefClock,
}

impl From<crate::cmdmon::SourceMode> for SourceMode {
    fn from(m: crate::cmdmon::SourceMode) -> Self {
        match m {
            crate::cmdmon::SourceMode::NtpClient => SourceMode::Server,
            crate::cmdmon::SourceMode::NtpPeer => SourceMode::Peer,
            crate::cmdmon::SourceMode::LocalReference => SourceMode::RefClock,
        }
    }
}

impl SourceMode {
    pub fn glyph(self) -> char {
        match self {
            SourceMode::Server => '^',
            SourceMode::Peer => '=',
            SourceMode::RefClock => '#',
        }
    }
}

/// Source selection state glyph (second column char), from `RPY_SD_ST_*`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
    #[non_exhaustive]
pub enum SourceState {
    /// `*` — current synced/best source (`RPY_SD_ST_SELECTED`).
    Selected,
    /// `+` — acceptable, combined (`RPY_SD_ST_UNSELECTED`).
    Combined,
    /// `-` — acceptable, not combined (`RPY_SD_ST_SELECTABLE`).
    NotCombined,
    /// `?` — unreachable/unusable (`RPY_SD_ST_NONSELECTABLE`).
    Unusable,
    /// `x` — falseticker (`RPY_SD_ST_FALSETICKER`).
    Falseticker,
    /// `~` — too variable (`RPY_SD_ST_JITTERY`).
    Jittery,
}

impl From<crate::cmdmon::SourceState> for SourceState {
    fn from(s: crate::cmdmon::SourceState) -> Self {
        match s {
            crate::cmdmon::SourceState::Selected => SourceState::Selected,
            crate::cmdmon::SourceState::Unselected => SourceState::Combined,
            crate::cmdmon::SourceState::Selectable => SourceState::NotCombined,
            crate::cmdmon::SourceState::Nonselectable => SourceState::Unusable,
            crate::cmdmon::SourceState::Falseticker => SourceState::Falseticker,
            crate::cmdmon::SourceState::Jittery => SourceState::Jittery,
        }
    }
}

impl SourceState {
    pub fn glyph(self) -> char {
        match self {
            SourceState::Selected => '*',
            SourceState::Combined => '+',
            SourceState::NotCombined => '-',
            SourceState::Unusable => '?',
            SourceState::Falseticker => 'x',
            SourceState::Jittery => '~',
        }
    }
}

/// One `sources` row. Field meanings and units mirror `RPY_SourceData`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceEntry {
    pub mode: SourceMode,
    pub state: SourceState,
    /// Display name/IP, already resolved (chrony formats this to ≤25 chars).
    pub name: String,
    pub stratum: u16,
    /// Log2 of the polling interval; signed (`int16_t` in chrony).
    pub poll: i16,
    /// 8-bit reachability register, shown octal.
    pub reach: u16,
    /// Seconds since the last sample (`LastRx`); `u32::MAX` renders as `-`.
    pub since_sample: u32,
    /// Adjusted offset (`latest_meas`), seconds.
    pub adjusted_offset: f64,
    /// Measured offset (`orig_latest_meas`), seconds.
    pub measured_offset: f64,
    /// Estimated error (`latest_meas_err`), seconds.
    pub error: f64,
}

impl SourceEntry {
    /// Render one row exactly as `print_report`'s format string would.
    pub fn render_row(&self) -> String {
        format!(
            "{}{} {:<27}  {:2}  {:2}   {:3o}  {}  {}[{}] +/- {}\n",
            self.mode.glyph(),
            self.state.glyph(),
            self.name,
            self.stratum,
            self.poll,
            self.reach,
            fmt_seconds(self.since_sample),
            fmt_signed_nanoseconds(self.adjusted_offset),
            fmt_signed_nanoseconds(self.measured_offset),
            fmt_nanoseconds(self.error),
        )
    }
}

/// A full `sources` report (zero or more rows).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SourcesReport {
    #[serde(default)]
    pub sources: Vec<SourceEntry>,
}

impl SourcesReport {
    /// Render as `chronyc sources` (`verbose` = the `-v` legend). Includes the
    /// trailing newline on the last row.
    pub fn render(&self, verbose: bool) -> String {
        let mut s = String::new();
        if verbose {
            s.push_str(&SOURCES_LEGEND_LINES.join("\n"));
            s.push('\n');
        }
        s.push_str(SOURCES_HEADER);
        s.push('\n');
        s.push_str(&"=".repeat(SOURCES_HEADER.len()));
        s.push('\n');
        for src in &self.sources {
            s.push_str(&src.render_row());
        }
        s
    }
}

/// `print_seconds`: a `LastRx`-style interval with a unit suffix, 4-char field.
fn fmt_seconds(s: u32) -> String {
    if s == u32::MAX {
        "   -".to_string()
    } else if s < 1200 {
        format!("{s:4}")
    } else if s < 36000 {
        format!("{:3}m", s / 60)
    } else if s < 345_600 {
        format!("{:3}h", s / 3600)
    } else {
        let d = s / 86400;
        if d > 999 {
            format!("{:3}y", d / 365)
        } else {
            format!("{d:3}d")
        }
    }
}

/// `print_nanoseconds`: an unsigned magnitude with an auto-scaled unit.
fn fmt_nanoseconds(s: f64) -> String {
    let s = s.abs();
    if s < 9999.5e-9 {
        format!("{:4.0}ns", s * 1e9)
    } else if s < 9999.5e-6 {
        format!("{:4.0}us", s * 1e6)
    } else if s < 9999.5e-3 {
        format!("{:4.0}ms", s * 1e3)
    } else if s < 999.5 {
        format!("{s:5.1}s")
    } else if s < 99999.5 {
        format!("{s:5.0}s")
    } else if s < 99999.5 * 60.0 {
        format!("{:5.0}m", s / 60.0)
    } else if s < 99999.5 * 3600.0 {
        format!("{:5.0}h", s / 3600.0)
    } else if s < 99999.5 * 3600.0 * 24.0 {
        format!("{:5.0}d", s / (3600.0 * 24.0))
    } else {
        format!("{:5.0}y", s / (3600.0 * 24.0 * 365.0))
    }
}

/// `print_signed_nanoseconds`: like [`fmt_nanoseconds`] but always signed; the
/// unit branch is chosen on the magnitude, the printed value keeps its sign.
fn fmt_signed_nanoseconds(s: f64) -> String {
    let x = s.abs();
    if x < 9999.5e-9 {
        format!("{:+5.0}ns", s * 1e9)
    } else if x < 9999.5e-6 {
        format!("{:+5.0}us", s * 1e6)
    } else if x < 9999.5e-3 {
        format!("{:+5.0}ms", s * 1e3)
    } else if x < 999.5 {
        format!("{s:+6.1}s")
    } else if x < 99999.5 {
        format!("{s:+6.0}s")
    } else if x < 99999.5 * 60.0 {
        format!("{:+6.0}m", s / 60.0)
    } else if x < 99999.5 * 3600.0 {
        format!("{:+6.0}h", s / 3600.0)
    } else if x < 99999.5 * 3600.0 * 24.0 {
        format!("{:+6.0}d", s / (3600.0 * 24.0))
    } else {
        format!("{:+6.0}y", s / (3600.0 * 24.0 * 365.0))
    }
}

// ---------------------------------------------------------------------------
// `chronyc sourcestats` (CHRONYC.3)
//
// Ported from chrony 4.5 `client.c::process_cmd_sourcestats`. Header and `-v`
// legend are live-witnessed against real chrony 4.5
// (`reports/oracle/chronyc-live/sourcestats*.raw.out`); data rows are byte-derived
// from the format string "%-25s %3U %3U  %I %+P %P  %+S  %S\n" and its helpers.
// ---------------------------------------------------------------------------

/// The `sourcestats` table header (78 chars; the `=` rule is `'=' * len`).
const SOURCESTATS_HEADER: &str =
    "Name/IP Address            NP  NR  Span  Frequency  Freq Skew  Offset  Std Dev";

/// The `-v` legend block (chrony's nine `printf` lines; no leading blank line,
/// unlike `sources`).
const SOURCESTATS_LEGEND_LINES: &[&str] = &[
    "                             .- Number of sample points in measurement set.",
    "                            /    .- Number of residual runs with same sign.",
    "                           |    /    .- Length of measurement set (time).",
    "                           |   |    /      .- Est. clock freq error (ppm).",
    "                           |   |   |      /           .- Est. error in freq.",
    "                           |   |   |     |           /         .- Est. offset.",
    "                           |   |   |     |          |          |   On the -.",
    "                           |   |   |     |          |          |   samples. \\",
    "                           |   |   |     |          |          |             |",
];

/// One `sourcestats` row (fields mirror `RPY_Sourcestats`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourcestatsEntry {
    pub name: String,
    /// Number of sample points (`NP`).
    pub n_samples: u32,
    /// Number of residual runs with the same sign (`NR`).
    pub n_runs: u32,
    /// Length of the measurement set in seconds (`Span`; `u32::MAX` → `-`).
    pub span_seconds: u32,
    /// Estimated residual frequency error, ppm (`Frequency`).
    pub resid_freq_ppm: f64,
    /// Estimated error in the frequency, ppm (`Freq Skew`).
    pub skew_ppm: f64,
    /// Estimated offset, seconds (`Offset`).
    pub est_offset: f64,
    /// Standard deviation of the offset, seconds (`Std Dev`).
    pub std_dev: f64,
}

impl SourcestatsEntry {
    pub fn render_row(&self) -> String {
        format!(
            "{:<25} {:3} {:3}  {} {} {}  {}  {}\n",
            self.name,
            self.n_samples,
            self.n_runs,
            fmt_seconds(self.span_seconds),
            fmt_signed_freq_ppm(self.resid_freq_ppm),
            fmt_freq_ppm(self.skew_ppm),
            fmt_signed_nanoseconds(self.est_offset),
            fmt_nanoseconds(self.std_dev),
        )
    }
}

/// A full `sourcestats` report (zero or more rows).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SourcestatsReport {
    #[serde(default)]
    pub sources: Vec<SourcestatsEntry>,
}

impl SourcestatsReport {
    /// Render as `chronyc sourcestats` (`verbose` = the `-v` legend).
    pub fn render(&self, verbose: bool) -> String {
        let mut s = String::new();
        if verbose {
            s.push_str(&SOURCESTATS_LEGEND_LINES.join("\n"));
            s.push('\n');
        }
        s.push_str(SOURCESTATS_HEADER);
        s.push('\n');
        s.push_str(&"=".repeat(SOURCESTATS_HEADER.len()));
        s.push('\n');
        for src in &self.sources {
            s.push_str(&src.render_row());
        }
        s
    }
}

/// `print_freq_ppm`: an unsigned ppm frequency, `%10.3f` (or `%10.0f` if huge).
fn fmt_freq_ppm(f: f64) -> String {
    if f.abs() < 99999.5 {
        format!("{f:10.3}")
    } else {
        format!("{f:10.0}")
    }
}

/// `print_signed_freq_ppm`: signed ppm frequency, `%+10.3f` (or `%+10.0f`).
fn fmt_signed_freq_ppm(f: f64) -> String {
    if f.abs() < 99999.5 {
        format!("{f:+10.3}")
    } else {
        format!("{f:+10.0}")
    }
}

/// `print_clientlog_interval`: a log2 request-rate/interval shown as `%2d`, but a saturated
/// rate (`>= 127`) renders as `" -"` (chrony's `clients`/`serverstats` "unknown" marker).
fn fmt_clientlog_interval(rate: i32) -> String {
    if rate >= 127 {
        " -".to_string()
    } else {
        format!("{rate:2}")
    }
}

// ---------------------------------------------------------------------------
// `print_report`: chrony's custom mini-printf that drives every chronyc report.
//
// Ported from chrony 4.5 `client.c::print_report`. The format grammar is
// printf-like but with chrony-specific specifiers (see `ReportSpec` below) and a
// CSV mode that drops literal text, comma-joins fields, remaps a few specifiers,
// and appends a trailing newline. Differential-tested vs the VERBATIM print_report
// engine (linked against the real util.c) over both modes.
// ---------------------------------------------------------------------------

/// A typed argument consumed by [`print_report`], mirroring the C `va_arg` types each
/// specifier reads (the C engine trusts the caller to pass the right type per specifier).
#[derive(Clone, Debug, PartialEq)]
    #[non_exhaustive]
pub enum ReportArg {
    /// A signed `int` (`%B`, `%C`, `%L`, `%M`, `%N`, `%c`, `%d`).
    Int(i32),
    /// A `uint32_t` (`%I`, `%R`, `%U`).
    U32(u32),
    /// A `uint64_t` (`%Q`).
    U64(u64),
    /// An `unsigned int` (`%b`, `%o`, `%u`).
    Uint(u32),
    /// A `double` (`%F`, `%O`, `%P`, `%S`, `%f`).
    Double(f64),
    /// A `const char *` (`%s`).
    Str(String),
    /// A `struct timespec *` (`%V`; `%T` is not modeled — see [`print_report`]).
    Timespec(i64, i64),
}

/// Whether [`print_report`] renders human-readable text or CSV (the `-c` mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum ReportMode {
    Human,
    Csv,
}

/// chrony's `print_report` engine (`client.c`): format `format` against `args`, returning the
/// exact bytes chronyc would print. The grammar between `%` specifiers is literal text
/// (emitted only in [`ReportMode::Human`]); a specifier is `%[+|-][width][.prec]C` where the
/// sign flag, decimal `width` (default 0), and `.prec` (default 5) drive the chrony-specific
/// conversions. In [`ReportMode::Csv`] the sign/width are cleared, fields are comma-joined, a
/// few specifiers are remapped (`C→d`, `F/P→f.3`, `O/S→f.9`, `I→U`, `T→V`), and a trailing
/// newline is appended.
///
/// The `%T` specifier renders the timespec's seconds as `strftime("%a %b %d %T %Y")` UTC via
/// [`crate::util::gmtime_report_string`] (the nanoseconds are unused, as in chrony); `%V` renders
/// the full `seconds.nanoseconds` form. Every specifier is reproduced exactly.
pub fn print_report(format: &str, args: &[ReportArg], mode: ReportMode) -> String {
    let csv = mode == ReportMode::Csv;
    let fmt: Vec<char> = format.chars().collect();
    let mut out = String::new();
    let mut ai = 0usize; // next argument index
    let mut next_arg = || {
        let a = args[ai].clone();
        ai += 1;
        a
    };
    let mut pos = 0usize;
    let mut field = 0i32;
    loop {
        // Copy literal text up to the next '%' or end.
        let mut lit = String::new();
        while pos < fmt.len() && fmt[pos] != '%' {
            lit.push(fmt[pos]);
            pos += 1;
        }
        if !csv {
            out.push_str(&lit);
        }
        // Stop on end-of-format or a trailing bare '%'.
        if pos >= fmt.len() || pos + 1 >= fmt.len() {
            break;
        }
        pos += 1; // consume '%'

        // Parse [+|-] sign flag, [width], [.prec].
        let mut sign = false;
        let mut width = 0usize;
        let mut prec = 5usize;
        if fmt[pos] == '+' || fmt[pos] == '-' {
            sign = true;
            pos += 1;
        }
        if fmt[pos].is_ascii_digit() {
            let start = pos;
            while pos < fmt.len() && fmt[pos].is_ascii_digit() {
                pos += 1;
            }
            width = fmt[start..pos].iter().collect::<String>().parse().unwrap();
        }
        if pos < fmt.len() && fmt[pos] == '.' {
            pos += 1;
            let start = pos;
            while pos < fmt.len() && fmt[pos].is_ascii_digit() {
                pos += 1;
            }
            prec = fmt[start..pos].iter().collect::<String>().parse().unwrap_or(0);
        }
        let mut spec = fmt[pos];
        pos += 1;

        // CSV mode: clear sign/width, comma-join, and remap a few specifiers.
        if csv {
            sign = false;
            width = 0;
            if field > 0 {
                out.push(',');
            }
            match spec {
                'C' => spec = 'd',
                'F' | 'P' => {
                    prec = 3;
                    spec = 'f';
                }
                'O' | 'S' => {
                    prec = 9;
                    spec = 'f';
                }
                'I' => spec = 'U',
                'T' => spec = 'V',
                _ => {}
            }
        }

        match spec {
            'B' => {
                let v = as_int(next_arg());
                out.push_str(if v != 0 { "Yes" } else { "No" });
            }
            'C' => out.push_str(&fmt_clientlog_interval(as_int(next_arg()))),
            'F' | 'O' => {
                let dbl = as_double(next_arg());
                let unit = if spec == 'O' { "seconds" } else { "ppm" };
                // (dbl > 0) XOR (spec != 'O') ? "slow" : "fast"
                let slow = (dbl > 0.0) ^ (spec != 'O');
                out.push_str(&format!(
                    "{} {} {}",
                    fmt_fixed(dbl.abs(), width, prec, false),
                    unit,
                    if slow { "slow" } else { "fast" }
                ));
            }
            'I' => out.push_str(&fmt_seconds(as_u32(next_arg()))),
            'L' => {
                let v = as_int(next_arg());
                out.push_str(leap_string(v, width));
            }
            'M' => {
                let v = as_int(next_arg());
                out.push_str(match v {
                    1 => "Symmetric active",
                    2 => "Symmetric passive",
                    4 => "Server",
                    _ => "Invalid",
                });
            }
            'N' => {
                let v = as_int(next_arg());
                out.push_str(match v {
                    b if b == b'D' as i32 => "Daemon",
                    b if b == b'K' as i32 => "Kernel",
                    b if b == b'H' as i32 => "Hardware",
                    _ => "Invalid",
                });
            }
            'P' => {
                let dbl = as_double(next_arg());
                out.push_str(&if sign { fmt_signed_freq_ppm(dbl) } else { fmt_freq_ppm(dbl) });
            }
            'R' => out.push_str(&format!("{:08X}", as_u32(next_arg()))),
            'S' => {
                let dbl = as_double(next_arg());
                out.push_str(&if sign { fmt_signed_nanoseconds(dbl) } else { fmt_nanoseconds(dbl) });
            }
            'U' => out.push_str(&fmt_uint_width(as_u32(next_arg()) as u64, width)),
            'T' => {
                if let ReportArg::Timespec(sec, _nsec) = next_arg() {
                    out.push_str(&crate::util::gmtime_report_string(sec));
                }
            }
            'V' => {
                if let ReportArg::Timespec(sec, nsec) = next_arg() {
                    out.push_str(&crate::util::timespec_to_string(sec, nsec));
                }
            }
            'Q' => out.push_str(&fmt_uint_width(as_u64(next_arg()), width)),
            'b' => {
                let v = as_uint(next_arg());
                for i in (0..prec as i32).rev() {
                    out.push(if v & (1u32 << i) != 0 { '1' } else { '0' });
                }
            }
            'c' => out.push(as_int(next_arg()) as u8 as char),
            'd' => out.push_str(&fmt_int_width(as_int(next_arg()), width)),
            'f' => out.push_str(&fmt_fixed(as_double(next_arg()), width, prec, sign)),
            'o' => out.push_str(&fmt_oct_width(as_uint(next_arg()), width)),
            's' => {
                let s = as_str(next_arg());
                out.push_str(&fmt_str_width(&s, width, sign));
            }
            'u' => out.push_str(&fmt_uint_width(as_uint(next_arg()) as u64, width)),
            _ => {}
        }
        field += 1;
    }
    if csv {
        out.push('\n');
    }
    out
}

/// `%L` leap-status text: the single-char glyph when `width == 1`, else the full phrase.
fn leap_string(v: i32, width: usize) -> &'static str {
    match v {
        0 => if width != 1 { "Normal" } else { "N" },
        1 => if width != 1 { "Insert second" } else { "+" },
        2 => if width != 1 { "Delete second" } else { "-" },
        3 => if width != 1 { "Not synchronised" } else { "?" },
        _ => if width != 1 { "Invalid" } else { "?" },
    }
}

// C `printf` field-width helpers (right-justified min-width; `%-*s` is left-justified).
fn fmt_int_width(v: i32, width: usize) -> String {
    format!("{v:>width$}")
}
fn fmt_uint_width(v: u64, width: usize) -> String {
    format!("{v:>width$}")
}
fn fmt_oct_width(v: u32, width: usize) -> String {
    format!("{v:>width$o}")
}
fn fmt_str_width(s: &str, width: usize, left: bool) -> String {
    if left {
        format!("{s:<width$}")
    } else {
        format!("{s:>width$}")
    }
}
/// C `%*.*f` / `%+*.*f`: fixed-point with a min field width and precision.
fn fmt_fixed(v: f64, width: usize, prec: usize, sign: bool) -> String {
    if sign {
        format!("{v:>+width$.prec$}")
    } else {
        format!("{v:>width$.prec$}")
    }
}

fn as_int(a: ReportArg) -> i32 {
    match a {
        ReportArg::Int(v) => v,
        _ => 0,
    }
}
fn as_u32(a: ReportArg) -> u32 {
    match a {
        ReportArg::U32(v) => v,
        _ => 0,
    }
}
fn as_u64(a: ReportArg) -> u64 {
    match a {
        ReportArg::U64(v) => v,
        _ => 0,
    }
}
fn as_uint(a: ReportArg) -> u32 {
    match a {
        ReportArg::Uint(v) => v,
        _ => 0,
    }
}
fn as_double(a: ReportArg) -> f64 {
    match a {
        ReportArg::Double(v) => v,
        _ => 0.0,
    }
}
fn as_str(a: ReportArg) -> String {
    match a {
        ReportArg::Str(v) => v,
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Report renderers built on the print_report engine (client.c process_cmd_*).
//
// Each reproduces a chronyc report's exact format string + argument assembly,
// composing the ported wire decoders (cmdmon report structs). The display `name`
// column (chrony's format_name of refid/IP) and name resolution are a host
// boundary supplied by the caller. Headers and -v legends are the verbatim text.
// ---------------------------------------------------------------------------

use crate::cmdmon::{AuthMode, AuthReport, ClientAccessReport, ManualSampleReport, SelectReport};

/// `chronyc clients` column header (`process_cmd_clients`). The sixth column is `Cmd` normally
/// or `NTS-KE` with `-k`; chrony builds it with `snprintf("%6s", ...)`, so `Cmd` is right-padded
/// to width 6 (`"   Cmd"`) while `NTS-KE` fills it exactly.
pub fn clients_header(nke: bool) -> String {
    let col = if nke { "NTS-KE" } else { "Cmd" };
    format!("Hostname                      NTP   Drop Int IntL Last  {col:>6}   Drop Int  Last")
}

/// `chronyc clients` per-client row (`process_cmd_clients`). `name` is the pre-formatted display
/// name. With `nke`, the second counter group is the NTS-KE columns; otherwise the command
/// columns. The `%C` interval columns are the raw signed log2 intervals (clientlog-interval
/// formatting), and the `%I` columns are seconds-since (unit-scaled).
pub fn render_clients_row(name: &str, r: &ClientAccessReport, nke: bool, mode: ReportMode) -> String {
    let (hits2, drops2, interval2, last2) = if nke {
        (r.nke_hits, r.nke_drops, r.nke_interval, r.last_nke_hit_ago)
    } else {
        (r.cmd_hits, r.cmd_drops, r.cmd_interval, r.last_cmd_hit_ago)
    };
    let args = [
        ReportArg::Str(name.to_string()),
        ReportArg::U32(r.ntp_hits),
        ReportArg::U32(r.ntp_drops),
        ReportArg::Int(r.ntp_interval as i32),
        ReportArg::Int(r.ntp_timeout_interval as i32),
        ReportArg::U32(r.last_ntp_hit_ago),
        ReportArg::U32(hits2),
        ReportArg::U32(drops2),
        ReportArg::Int(interval2 as i32),
        ReportArg::U32(last2),
    ];
    print_report("%-25s  %6U  %5U  %C  %C  %I  %6U  %5U  %C  %I\n", &args, mode)
}

/// `chronyc manual list` column header (`process_cmd_manual_list`).
pub const MANUAL_LIST_HEADER: &str = "#    Date     Time(UTC)    Slewed   Original   Residual";

/// `chronyc manual list`'s `210 n_samples = N` info line (printed before the table via
/// `print_info_field`, which is suppressed in CSV mode).
pub fn manual_list_info_line(n_samples: u32) -> String {
    format!("210 n_samples = {n_samples}\n")
}

/// `chronyc manual list` per-sample row (`process_cmd_manual_list`): the index (`%2d`), the
/// sample time as `UTI_TimeToLogForm` (`%s`, `"%Y-%m-%d %H:%M:%S"` UTC), and the slewed/original/
/// residual offsets (`%10.2f`). Consumes a decoded [`ManualSampleReport`].
pub fn render_manual_list_row(index: i32, r: &ManualSampleReport, mode: ReportMode) -> String {
    let args = [
        ReportArg::Int(index),
        ReportArg::Str(crate::util::time_to_log_form(r.when_sec)),
        ReportArg::Double(r.slewed_offset),
        ReportArg::Double(r.orig_offset),
        ReportArg::Double(r.residual),
    ];
    print_report("%2d %s %10.2f %10.2f %10.2f\n", &args, mode)
}

/// `chronyc authdata` column header (`process_cmd_authdata`).
pub const AUTHDATA_HEADER: &str =
    "Name/IP address             Mode KeyID Type KLen Last Atmp  NAK Cook CLen";

/// `chronyc authdata -v` legend (the five verbatim `printf` lines).
pub const AUTHDATA_LEGEND_LINES: &[&str] = &[
    "                             .- Auth. mechanism (NTS, SK - symmetric key)",
    "                            |   Key length -.  Cookie length (bytes) -.",
    "                            |       (bits)  |  Num. of cookies --.    |",
    "                            |               |  Key est. attempts  |   |",
    "                            |               |           |         |   |",
];

/// `chronyc authdata` per-source row. `name` is the pre-formatted display name (chrony's
/// `format_name`, ≤25 chars, right-padded to 27 by the `%-27s`). The auth mode renders as
/// `-`/`SK`/`NTS`/`?` (`RPY_AD_MD_*`). Format string and argument order are exactly
/// `process_cmd_authdata`'s.
pub fn render_authdata_row(name: &str, r: &AuthReport, mode: ReportMode) -> String {
    let mode_str = match r.mode {
        AuthMode::None => "-",
        AuthMode::Symmetric => "SK",
        AuthMode::Nts => "NTS",
    };
    let args = [
        ReportArg::Str(name.to_string()),
        ReportArg::Str(mode_str.to_string()),
        ReportArg::U32(r.key_id),
        ReportArg::Int(r.key_type as i32),
        ReportArg::Int(r.key_length as i32),
        ReportArg::U32(r.last_ke_ago),
        ReportArg::Int(r.ke_attempts as i32),
        ReportArg::Int(r.nak as i32),
        ReportArg::Int(r.cookies as i32),
        ReportArg::Int(r.cookie_length as i32),
    ];
    print_report("%-27s %4s %5U %4d %4d %I %4d %4d %4d %4d\n", &args, mode)
}

/// `chronyc selectdata` column header (`process_cmd_selectdata`).
pub const SELECTDATA_HEADER: &str =
    "S Name/IP Address        Auth COpts EOpts Last Score     Interval  Leap";

/// `chronyc selectdata -v` legend (the eight verbatim `printf` lines).
pub const SELECTDATA_LEGEND_LINES: &[&str] = &[
    "  . State: N - noselect, s - unsynchronised, M - missing samples,",
    " /         d/D - large distance, ~ - jittery, w/W - waits for others,",
    "|          S - stale, O - orphan, T - not trusted, P - not preferred,",
    "|          U - waits for update,, x - falseticker, + - combined, * - best.",
    "|   Effective options   ---------.  (N - noselect, P - prefer",
    "|   Configured options  ----.     \\  T - trust, R - require)",
    "|   Auth. enabled (Y/N) -.   \\     \\     Offset interval --.",
    "|                        |    |     |                       |",
];

const SD_OPTION_NOSELECT: i32 = 0x1;
const SD_OPTION_PREFER: i32 = 0x2;
const SD_OPTION_TRUST: i32 = 0x4;
const SD_OPTION_REQUIRE: i32 = 0x8;

/// The five-character option group chrony prints for `COpts`/`EOpts`: noselect/prefer/trust/
/// require glyphs then a trailing literal `-`.
fn option_chars(opts: i32) -> [char; 5] {
    [
        if opts & SD_OPTION_NOSELECT != 0 { 'N' } else { '-' },
        if opts & SD_OPTION_PREFER != 0 { 'P' } else { '-' },
        if opts & SD_OPTION_TRUST != 0 { 'T' } else { '-' },
        if opts & SD_OPTION_REQUIRE != 0 { 'R' } else { '-' },
        '-',
    ]
}

/// `chronyc selectdata` per-source row. `name` is the pre-formatted display name. The option
/// masks are the `SRC_SELECT_*`/`RPY_SD_OPTION_*` bits (values coincide). Format string and
/// argument order are exactly `process_cmd_selectdata`'s.
pub fn render_selectdata_row(name: &str, r: &SelectReport, mode: ReportMode) -> String {
    let conf = option_chars(r.conf_options);
    let eff = option_chars(r.eff_options);
    let auth = if r.authentication != 0 { 'Y' } else { 'N' };
    let args = [
        ReportArg::Int(r.state_char as i32),
        ReportArg::Str(name.to_string()),
        ReportArg::Int(auth as i32),
        ReportArg::Int(conf[0] as i32),
        ReportArg::Int(conf[1] as i32),
        ReportArg::Int(conf[2] as i32),
        ReportArg::Int(conf[3] as i32),
        ReportArg::Int(conf[4] as i32),
        ReportArg::Int(eff[0] as i32),
        ReportArg::Int(eff[1] as i32),
        ReportArg::Int(eff[2] as i32),
        ReportArg::Int(eff[3] as i32),
        ReportArg::Int(eff[4] as i32),
        ReportArg::U32(r.last_sample_ago),
        ReportArg::Double(r.score),
        ReportArg::Double(r.lo_limit),
        ReportArg::Double(r.hi_limit),
        ReportArg::Int(r.leap as i32),
    ];
    print_report("%c %-25s %c %c%c%c%c%c %c%c%c%c%c %I %5.1f %+S %+S  %1L\n", &args, mode)
}

/// The mapping from `serverstats` **display** position to the wire-counter index in
/// `ServerStatsReport::counters` (`RPY_ServerStats` order). chrony's `process_cmd_serverstats`
/// prints the counters in a different order than they appear on the wire — e.g. the NTS-KE
/// counters (wire idx 1/4) are shown after the command/log counters. Used to feed the existing
/// [`ServerstatsReport`] (which holds display-order values) from a wire-order decode.
pub const SERVERSTATS_DISPLAY_TO_WIRE: [usize; 17] =
    [0, 3, 2, 5, 6, 1, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

/// Reorder the 17 wire counters (`RPY_ServerStats` order, as decoded by
/// [`crate::cmdmon`]) into the `serverstats` display order used by [`ServerstatsReport`].
pub fn serverstats_wire_to_display(counters: &[u64; 17]) -> Vec<u64> {
    SERVERSTATS_DISPLAY_TO_WIRE.iter().map(|&w| counters[w]).collect()
}

/// `chronyc tracking` (`process_cmd_tracking`), driven by the [`print_report`] engine over the
/// exact 13-line format string. `name` is the pre-formatted reference display name (chrony's
/// `format_name` of the ref-id/IP), which the caller supplies (name resolution is a host
/// boundary). Consumes a wire-decoded [`crate::cmdmon::TrackingReport`]. In CSV mode the labels
/// are dropped, `%T` falls back to `%V` (the `seconds.nanoseconds` form), and the fields are
/// comma-joined.
pub fn render_tracking(r: &crate::cmdmon::TrackingReport, name: &str, mode: ReportMode) -> String {
    let args = [
        ReportArg::U32(r.ref_id),
        ReportArg::Str(name.to_string()),
        ReportArg::Uint(r.stratum as u32),
        ReportArg::Timespec(r.ref_time_sec, r.ref_time_nsec),
        ReportArg::Double(r.current_correction),
        ReportArg::Double(r.last_offset),
        ReportArg::Double(r.rms_offset),
        ReportArg::Double(r.freq_ppm),
        ReportArg::Double(r.resid_freq_ppm),
        ReportArg::Double(r.skew_ppm),
        ReportArg::Double(r.root_delay),
        ReportArg::Double(r.root_dispersion),
        ReportArg::Double(r.last_update_interval),
        ReportArg::Int(r.leap_status as i32),
    ];
    print_report(
        "Reference ID    : %R (%s)\n\
         Stratum         : %u\n\
         Ref time (UTC)  : %T\n\
         System time     : %.9O of NTP time\n\
         Last offset     : %+.9f seconds\n\
         RMS offset      : %.9f seconds\n\
         Frequency       : %.3F\n\
         Residual freq   : %+.3f ppm\n\
         Skew            : %.3f ppm\n\
         Root delay      : %.9f seconds\n\
         Root dispersion : %.9f seconds\n\
         Update interval : %.1f seconds\n\
         Leap status     : %L\n",
        &args,
        mode,
    )
}

/// `chronyc ntpdata` (`process_cmd_ntpdata`), driven by the [`print_report`] engine over the
/// exact 28-line format string. Consumes a wire-decoded [`crate::ntp::ntp_report::NtpReport`]
/// plus the exchange's `remote_addr`/`remote_port` (which the reply carries alongside the
/// report). Composes the ported `UTI_IPToString`/`UTI_IPToRefid` for the address+refid columns,
/// `UTI_RefidToString` for the stratum-≤1 reference name, and `UTI_Log2ToDouble` for the
/// poll/precision seconds. The `NTP tests` line shows the 10 test bits grouped 3-3-4 (the
/// interleaved/authenticated flag bits sit above bit 9 and do not appear there).
pub fn render_ntpdata(
    r: &crate::ntp::ntp_report::NtpReport,
    remote_addr: &crate::util::IpAddr,
    remote_port: u16,
    mode: ReportMode,
) -> String {
    use crate::util::{ip_to_refid, ip_to_string, log2_to_double, refid_to_string};
    let ref_name = if r.stratum <= 1 { refid_to_string(r.ref_id) } else { String::new() };
    let tests = r.tests as u32;
    let args = [
        ReportArg::Str(ip_to_string(remote_addr)),
        ReportArg::U32(ip_to_refid(remote_addr)),
        ReportArg::Uint(remote_port as u32),
        ReportArg::Str(ip_to_string(&r.local_addr)),
        ReportArg::U32(ip_to_refid(&r.local_addr)),
        ReportArg::Int(r.leap as i32),
        ReportArg::Uint(r.version as u32),
        ReportArg::Int(r.mode as i32),
        ReportArg::Uint(r.stratum as u32),
        ReportArg::Int(r.poll as i32),
        ReportArg::Double(log2_to_double(r.poll as i32)),
        ReportArg::Int(r.precision as i32),
        ReportArg::Double(log2_to_double(r.precision as i32)),
        ReportArg::Double(r.root_delay),
        ReportArg::Double(r.root_dispersion),
        ReportArg::U32(r.ref_id),
        ReportArg::Str(ref_name),
        ReportArg::Timespec(r.ref_time.tv_sec, r.ref_time.tv_nsec),
        ReportArg::Double(r.offset),
        ReportArg::Double(r.peer_delay),
        ReportArg::Double(r.peer_dispersion),
        ReportArg::Double(r.response_time),
        ReportArg::Double(r.jitter_asymmetry),
        // The three %b test-bit groups: (tests>>7)[2:0], (tests>>4)[2:0], tests[3:0].
        ReportArg::Uint(tests >> 7),
        ReportArg::Uint(tests >> 4),
        ReportArg::Uint(tests),
        ReportArg::Int(r.interleaved as i32),
        ReportArg::Int(r.authenticated as i32),
        ReportArg::Int(r.tx_tss_char as i32),
        ReportArg::Int(r.rx_tss_char as i32),
        ReportArg::U32(r.total_tx_count),
        ReportArg::U32(r.total_rx_count),
        ReportArg::U32(r.total_valid_count),
        ReportArg::U32(r.total_good_count),
    ];
    print_report(
        "Remote address  : %s (%R)\n\
         Remote port     : %u\n\
         Local address   : %s (%R)\n\
         Leap status     : %L\n\
         Version         : %u\n\
         Mode            : %M\n\
         Stratum         : %u\n\
         Poll interval   : %d (%.0f seconds)\n\
         Precision       : %d (%.9f seconds)\n\
         Root delay      : %.6f seconds\n\
         Root dispersion : %.6f seconds\n\
         Reference ID    : %R (%s)\n\
         Reference time  : %T\n\
         Offset          : %+.9f seconds\n\
         Peer delay      : %.9f seconds\n\
         Peer dispersion : %.9f seconds\n\
         Response time   : %.9f seconds\n\
         Jitter asymmetry: %+.2f\n\
         NTP tests       : %.3b %.3b %.4b\n\
         Interleaved     : %B\n\
         Authenticated   : %B\n\
         TX timestamping : %N\n\
         RX timestamping : %N\n\
         Total TX        : %U\n\
         Total RX        : %U\n\
         Total valid RX  : %U\n\
         Total good RX   : %U\n",
        &args,
        mode,
    )
}

/// `chronyc rtcdata` (`process_cmd_rtcreport`), driven by the [`print_report`] engine over the
/// exact 6-line format string. Consumes a wire-decoded [`crate::cmdmon::RtcReport`].
pub fn render_rtcdata(r: &crate::cmdmon::RtcReport, mode: ReportMode) -> String {
    let args = [
        ReportArg::Timespec(r.ref_time_sec, r.ref_time_nsec),
        ReportArg::Uint(r.n_samples as u32),
        ReportArg::Uint(r.n_runs as u32),
        ReportArg::U32(r.span_seconds),
        ReportArg::Double(r.rtc_seconds_fast),
        ReportArg::Double(r.rtc_gain_rate_ppm),
    ];
    print_report(
        "RTC ref time (UTC) : %T\n\
         Number of samples  : %u\n\
         Number of runs     : %u\n\
         Sample span period : %I\n\
         RTC is fast by     : %12.6f seconds\n\
         RTC gains time at  : %9.3f ppm\n",
        &args,
        mode,
    )
}

// ---------------------------------------------------------------------------
// `chronyc activity` (CHRONYC.4) and `chronyc serverstats` (CHRONYC.5)
//
// Ported from chrony 4.5 `client.c::process_cmd_activity` /
// `process_cmd_serverstats`. Both are live-witnessed against real chrony 4.5
// (`reports/oracle/chronyc-live/{activity,serverstats}.raw.out`).
// ---------------------------------------------------------------------------

/// `chronyc activity`: counts of sources by online/offline/burst state. chrony
/// prints a leading `200 OK` (via `print_info_field`, non-CSV mode) then five
/// `%U sources ...` lines.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ActivityReport {
    pub online: u32,
    pub offline: u32,
    pub burst_online: u32,
    pub burst_offline: u32,
    pub unknown: u32,
}

impl ActivityReport {
    pub fn render(&self) -> String {
        format!(
            "200 OK\n\
             {} sources online\n\
             {} sources offline\n\
             {} sources doing burst (return to online)\n\
             {} sources doing burst (return to offline)\n\
             {} sources with unknown address\n",
            self.online, self.offline, self.burst_online, self.burst_offline, self.unknown,
        )
    }
}

/// The 17 `serverstats` labels, in chrony's order. Rendered left-justified to 27
/// columns then `": "`, matching `client.c`'s baked-in format literals.
const SERVERSTATS_LABELS: [&str; 17] = [
    "NTP packets received",
    "NTP packets dropped",
    "Command packets received",
    "Command packets dropped",
    "Client log records dropped",
    "NTS-KE connections accepted",
    "NTS-KE connections dropped",
    "Authenticated NTP packets",
    "Interleaved NTP packets",
    "NTP timestamps held",
    "NTP timestamp span",
    "NTP daemon RX timestamps",
    "NTP daemon TX timestamps",
    "NTP kernel RX timestamps",
    "NTP kernel TX timestamps",
    "NTP hardware RX timestamps",
    "NTP hardware TX timestamps",
];

/// `chronyc serverstats`: 17 unsigned 64-bit counters, label-aligned.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServerstatsReport {
    /// The 17 counters in [`SERVERSTATS_LABELS`] order.
    pub values: Vec<u64>,
}

impl ServerstatsReport {
    /// Render the label-aligned block. Missing trailing values render as 0 so a
    /// short fixture still produces all 17 lines.
    pub fn render(&self) -> String {
        let mut s = String::new();
        for (i, label) in SERVERSTATS_LABELS.iter().enumerate() {
            let v = self.values.get(i).copied().unwrap_or(0);
            // chrony's labels are left-justified to 27 columns, then ": " then %Q.
            s.push_str(&format!("{label:<27}: {v}\n"));
        }
        s
    }
}

/// chrony's directional wording for a signed quantity. Note: zero renders as
/// "slow" in chrony because the comparison is `> 0.0`; we match that rather than
/// inventing a "exact" case.
fn fast_slow(v: f64) -> &'static str {
    if v > 0.0 {
        "fast"
    } else {
        "slow"
    }
}

/// Emit one `"<label padded to 16>: <value>\n"` line.
fn line(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!("{label:<16}: {value}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TrackingReport {
        TrackingReport {
            reference_id: 0x0A00_0001,
            reference_name: Some("ntp.example.com".to_string()),
            stratum: 2,
            ref_time_utc: "Wed May 25 10:20:30 2022".to_string(),
            system_time_offset: 0.000_020_390,
            last_offset: 0.000_001_234,
            rms_offset: 0.000_005_678,
            frequency_ppm: 12.345,
            residual_freq_ppm: 0.001,
            skew_ppm: 0.234,
            root_delay: 0.001_234_567,
            root_dispersion: 0.000_456_789,
            update_interval: 64.5,
            leap_status: LeapStatus::Normal,
        }
    }

    #[test]
    fn tracking_layout_is_byte_stable() {
        // CHRONYC.1 — the label-aligned block. Compared byte-for-byte.
        let expected = "\
Reference ID    : 0A000001 (ntp.example.com)
Stratum         : 2
Ref time (UTC)  : Wed May 25 10:20:30 2022
System time     : 0.000020390 seconds fast of NTP time
Last offset     : +0.000001234 seconds
RMS offset      : 0.000005678 seconds
Frequency       : 12.345 ppm fast
Residual freq   : +0.001 ppm
Skew            : 0.234 ppm
Root delay      : 0.001234567 seconds
Root dispersion : 0.000456789 seconds
Update interval : 64.5 seconds
Leap status     : Normal
";
        assert_eq!(sample().render(), expected);
    }

    #[test]
    fn negative_offset_renders_slow() {
        let mut r = sample();
        r.system_time_offset = -0.000_000_007;
        r.frequency_ppm = -1.5;
        let out = r.render();
        assert!(out.contains("0.000000007 seconds slow of NTP time"));
        assert!(out.contains("1.500 ppm slow"));
    }

    // The real chrony 4.5 captures, embedded at compile time as golden oracles.
    // Path: src/report.rs -> ../../../ -> repo root.
    const ORACLE_SOURCES: &str =
        include_str!("../../../reports/oracle/chronyc-live/sources.raw.out");
    const ORACLE_SOURCES_V: &str =
        include_str!("../../../reports/oracle/chronyc-live/sources-v.raw.out");

    #[test]
    fn sources_header_and_rule_match_live_chrony_4_5() {
        // CHRONYC.2 — header + `=` rule, byte-compared to real `chronyc sources`.
        let empty = SourcesReport::default();
        assert_eq!(empty.render(false), ORACLE_SOURCES);
    }

    #[test]
    fn sources_verbose_legend_matches_live_chrony_4_5() {
        // CHRONYC.2 — the `-v` legend block, byte-compared to real `chronyc sources -v`.
        let empty = SourcesReport::default();
        assert_eq!(empty.render(true), ORACLE_SOURCES_V);
    }

    #[test]
    fn sources_row_is_byte_exact_to_client_c_format() {
        // Golden derived from `client.c` print_report spec (a populated row is not
        // live-witnessed in this sandbox; the formatters are ported byte-for-byte).
        let r = SourcesReport {
            sources: vec![SourceEntry {
                mode: SourceMode::Server,
                state: SourceState::Selected,
                name: "ntp1.example.com".to_string(),
                stratum: 2,
                poll: 6,
                reach: 0o377,
                since_sample: 21,
                adjusted_offset: 0.000_123,
                measured_offset: 0.000_456,
                error: 0.000_012,
            }],
        };
        let out = r.render(false);
        let row = out.lines().last().unwrap();
        assert_eq!(
            row,
            "^* ntp1.example.com              2   6   377    21   +123us[ +456us] +/-   12us"
        );
        // The data row must align under the header columns: same width.
        assert_eq!(row.len(), SOURCES_HEADER.len());
    }

    const ORACLE_ACTIVITY: &str =
        include_str!("../../../reports/oracle/chronyc-live/activity.raw.out");
    const ORACLE_SERVERSTATS: &str =
        include_str!("../../../reports/oracle/chronyc-live/serverstats.raw.out");

    #[test]
    fn activity_matches_live_chrony_4_5() {
        // CHRONYC.4 — all-zero activity (a local-only daemon) byte-compared to real
        // `chronyc activity`, including the leading `200 OK`.
        assert_eq!(ActivityReport::default().render(), ORACLE_ACTIVITY);
    }

    #[test]
    fn serverstats_labels_match_live_chrony_4_5() {
        // CHRONYC.5 — the 17 labels/alignment are witnessed against real
        // `chronyc serverstats` (values are volatile, so we check the label+":" +
        // padding prefix of each captured line, not the counts).
        let captured: Vec<&str> = ORACLE_SERVERSTATS.lines().collect();
        let rendered = ServerstatsReport::default(); // all-zero -> all 17 lines
        let mine: Vec<String> = rendered.render().lines().map(|l| l.to_string()).collect();
        assert_eq!(captured.len(), 17);
        assert_eq!(mine.len(), 17);
        for (cap, label) in captured.iter().zip(SERVERSTATS_LABELS.iter()) {
            let prefix = format!("{label:<27}: ");
            assert!(cap.starts_with(&prefix), "label mismatch: {cap:?} vs prefix {prefix:?}");
        }
    }

    const ORACLE_SOURCESTATS: &str =
        include_str!("../../../reports/oracle/chronyc-live/sourcestats.raw.out");
    const ORACLE_SOURCESTATS_V: &str =
        include_str!("../../../reports/oracle/chronyc-live/sourcestats-v.raw.out");

    #[test]
    fn sourcestats_header_and_legend_match_live_chrony_4_5() {
        // CHRONYC.3 — header + `=` rule and the `-v` legend, byte-compared to real
        // `chronyc sourcestats` / `... -v`.
        let empty = SourcestatsReport::default();
        assert_eq!(empty.render(false), ORACLE_SOURCESTATS);
        assert_eq!(empty.render(true), ORACLE_SOURCESTATS_V);
    }

    #[test]
    fn sourcestats_row_is_byte_exact_to_client_c_format() {
        let r = SourcestatsReport {
            sources: vec![SourcestatsEntry {
                name: "ntp1.example.com".to_string(),
                n_samples: 12,
                n_runs: 7,
                span_seconds: 600,
                resid_freq_ppm: -0.123,
                skew_ppm: 0.456,
                est_offset: 0.000_089,
                std_dev: 0.000_034,
            }],
        };
        let row = r.render(false);
        let last = row.lines().last().unwrap();
        assert_eq!(
            last,
            "ntp1.example.com           12   7   600     -0.123      0.456    +89us    34us"
        );
        assert_eq!(last.len(), SOURCESTATS_HEADER.len());
    }

    #[test]
    fn freq_ppm_formatters_match_c_helpers() {
        assert_eq!(fmt_freq_ppm(0.456), "     0.456");
        assert_eq!(fmt_signed_freq_ppm(-0.123), "    -0.123");
        assert_eq!(fmt_signed_freq_ppm(1.5), "    +1.500");
        // huge magnitude drops to %.0f width 10
        assert_eq!(fmt_freq_ppm(123456.0), "    123456");
    }

    #[test]
    fn sources_formatters_match_c_helpers() {
        // print_seconds branches
        assert_eq!(fmt_seconds(21), "  21");
        assert_eq!(fmt_seconds(1000), "1000");
        assert_eq!(fmt_seconds(1200), " 20m");
        assert_eq!(fmt_seconds(36000), " 10h");
        assert_eq!(fmt_seconds(u32::MAX), "   -");
        // print_signed_nanoseconds / print_nanoseconds unit scaling
        assert_eq!(fmt_signed_nanoseconds(0.000_123), " +123us");
        assert_eq!(fmt_signed_nanoseconds(-0.0034), "-3400us");
        assert_eq!(fmt_nanoseconds(0.000_012), "  12us");
        assert_eq!(fmt_nanoseconds(0.000_000_030), "  30ns");
    }

    #[test]
    fn print_formatters_match_real_c_over_battery() {
        // A large adversarial battery captured from the VERBATIM client.c print_* helpers
        // (/tmp/nfmt/genfmt.c) covering every unit threshold, rounding half-point, sign edge,
        // and negative zero. This upgrades the value formatters from live-witnessed to
        // compiled-oracle-verified across their full domain.
        let v = include_str!("../../../research/oracle/chronyc-fmt-c-vectors.txt");
        for l in v.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
            // Format: "TAG v=<value> |<output>|"
            let (head, rest) = l.split_once('|').expect("marker");
            let out = rest.strip_suffix('|').expect("closing marker");
            let mut it = head.split_whitespace();
            let tag = it.next().unwrap();
            let val = it.next().unwrap().strip_prefix("v=").unwrap();
            let got = match tag {
                "SEC" => fmt_seconds(val.parse::<u32>().unwrap()),
                "NS" => fmt_nanoseconds(val.parse::<f64>().unwrap()),
                "SNS" => fmt_signed_nanoseconds(val.parse::<f64>().unwrap()),
                "FQ" => fmt_freq_ppm(val.parse::<f64>().unwrap()),
                "SFQ" => fmt_signed_freq_ppm(val.parse::<f64>().unwrap()),
                "CLI" => fmt_clientlog_interval(val.parse::<i32>().unwrap()),
                other => panic!("unknown tag {other}"),
            };
            assert_eq!(got, out, "tag={tag} value={val}");
        }
    }

    #[test]
    fn print_report_engine_matches_real_c() {
        use ReportArg::*;
        // The (format, args) for each fixture id, driven identically in Human and CSV mode.
        // Mirrors the calls in the verbatim-engine oracle (/tmp/nutil/genreport.c).
        let cases: &[(&str, &str, Vec<ReportArg>)] = &[
            ("bool", "a=%B b=%B", vec![Int(1), Int(0)]),
            ("cli", "%C %C %C", vec![Int(5), Int(127), Int(200)]),
            ("fo", "f=%F o=%O", vec![Double(12.5), Double(-0.003)]),
            ("fo2", "f=%F o=%O", vec![Double(-12.5), Double(0.003)]),
            ("ivl", "%I|%I", vec![U32(1500), U32(4294967295)]),
            ("leap", "%L/%L/%L/%L/%L", vec![Int(0), Int(1), Int(2), Int(3), Int(9)]),
            ("leap1", "%1L%1L%1L%1L", vec![Int(0), Int(1), Int(2), Int(3)]),
            ("mode", "%M/%M/%M/%M", vec![Int(1), Int(2), Int(4), Int(7)]),
            ("tss", "%N/%N/%N/%N", vec![Int(b'D' as i32), Int(b'K' as i32), Int(b'H' as i32), Int(b'x' as i32)]),
            ("ppm", "%P|%+P", vec![Double(1.25), Double(-0.5)]),
            ("refid", "%R", vec![U32(0x0a01_0203)]),
            ("soff", "%S|%+S", vec![Double(0.000123), Double(-0.0034)]),
            ("u32", "[%8U][%U]", vec![U32(42), U32(7)]),
            ("u64", "[%10Q]", vec![U64(1_099_511_627_776)]),
            ("bin", "%b %.3b", vec![Uint(10), Uint(5)]),
            ("chr", "%c%c", vec![Int(65), Int(66)]),
            ("dec", "[%5d][%d]", vec![Int(-3), Int(7)]),
            ("dbl", "[%8.2f][%+.3f]", vec![Double(3.14159), Double(-2.5)]),
            ("oct", "[%4o]", vec![Uint(255)]),
            ("str", "[%10s][%-10s]", vec![Str("hi".into()), Str("yo".into())]),
            ("usr", "[%5u]", vec![Uint(12345)]),
            ("vts", "t=%V", vec![Timespec(1_700_000_000, 123_456_789)]),
            ("mix", "Ref %R str %2d leap %L end", vec![U32(0xdead_beef), Int(3), Int(0)]),
        ];

        let v = include_str!("../../../research/oracle/chronyc-print-report-c-vectors.txt");
        // Fixture line: "R id=<id> mode=<HUM|CSV> |<output-with-\n-escaped>|"
        let expected = |id: &str, mode: &str| -> String {
            let l = v
                .lines()
                .find(|l| {
                    l.contains(&format!("id={id} ")) && l.contains(&format!("mode={mode} "))
                })
                .unwrap_or_else(|| panic!("no fixture for id={id} mode={mode}"));
            let start = l.find(" |").unwrap() + 2;
            let end = l.rfind('|').unwrap();
            l[start..end].replace("\\n", "\n")
        };

        for (id, fmt, args) in cases {
            assert_eq!(&print_report(fmt, args, ReportMode::Human), &expected(id, "HUM"), "HUM id={id}");
            assert_eq!(&print_report(fmt, args, ReportMode::Csv), &expected(id, "CSV"), "CSV id={id}");
        }
    }

    #[test]
    fn report_renderers_match_real_c() {
        use crate::cmdmon::{AuthMode, AuthReport, SelectReport};
        let v = include_str!("../../../research/oracle/chronyc-renderers-c-vectors.txt");
        let expected = |id: &str, mode: &str| -> String {
            let l = v
                .lines()
                .find(|l| l.contains(&format!("id={id} ")) && l.contains(&format!("mode={mode} ")))
                .unwrap();
            let start = l.find(" |").unwrap() + 2;
            let end = l.rfind('|').unwrap();
            l[start..end].replace("\\n", "\n")
        };

        // authdata row (mode SK = Symmetric).
        let ad = AuthReport {
            mode: AuthMode::Symmetric,
            key_type: 1,
            key_id: 42,
            key_length: 128,
            ke_attempts: 3,
            last_ke_ago: 100,
            cookies: 8,
            cookie_length: 100,
            nak: 1,
        };
        assert_eq!(render_authdata_row("ntp.example.org", &ad, ReportMode::Human), expected("authrow", "HUM"));
        assert_eq!(render_authdata_row("ntp.example.org", &ad, ReportMode::Csv), expected("authrow", "CSV"));

        // selectdata row (state '*', conf PREFER|TRUST, eff PREFER).
        let sel = SelectReport {
            ref_id: 0,
            ip_addr: crate::util::IpAddr::Unspec,
            state_char: '*',
            authentication: 1,
            leap: 0,
            conf_options: SD_OPTION_PREFER | SD_OPTION_TRUST,
            eff_options: SD_OPTION_PREFER,
            last_sample_ago: 17,
            score: 1.2,
            lo_limit: -0.5,
            hi_limit: 0.5,
        };
        assert_eq!(render_selectdata_row("192.168.1.5", &sel, ReportMode::Human), expected("selrow", "HUM"));
        assert_eq!(render_selectdata_row("192.168.1.5", &sel, ReportMode::Csv), expected("selrow", "CSV"));

        // serverstats: counters in WIRE order (RPY_ServerStats), reordered to the display order
        // the existing ServerstatsReport renderer expects. This upgrades that renderer from
        // live-witnessed to compiled-oracle-verified, and pins the wire->display reorder.
        // wire: [ntp_hits, nke_hits, cmd_hits, ntp_drops, nke_drops, cmd_drops, log_drops,
        //        ntp_auth, interleaved, timestamps, span, drx, dtx, krx, ktx, hrx, htx]
        let wire = [1000u64, 50, 200, 3, 4, 5, 7, 900, 80, 111, 3600, 11, 12, 13, 14, 15, 16];
        let ss = ServerstatsReport { values: serverstats_wire_to_display(&wire) };
        assert_eq!(ss.render(), expected("srvstats", "HUM"));

        // Header/legend text parity (operational-knowledge; exact strings).
        assert_eq!(AUTHDATA_HEADER.len(), 73);
        assert_eq!(AUTHDATA_LEGEND_LINES.len(), 5);
        assert_eq!(SELECTDATA_LEGEND_LINES.len(), 8);
    }

    #[test]
    fn list_row_renderers_match_real_c() {
        use crate::cmdmon::{ClientAccessReport, ManualSampleReport};
        let v = include_str!("../../../research/oracle/chronyc-list-rows-c-vectors.txt");
        let expected = |id: &str, mode: &str| -> String {
            let l = v
                .lines()
                .find(|l| l.contains(&format!("id={id} ")) && l.contains(&format!("mode={mode} ")))
                .unwrap();
            let start = l.find(" |").unwrap() + 2;
            let end = l.rfind('|').unwrap();
            l[start..end].replace("\\n", "\n")
        };

        // clients row: ntp group + a cmd/nke second group (interval fields are raw signed bytes).
        let client = ClientAccessReport {
            ip_addr: crate::util::string_to_ip("203.0.113.9").unwrap(),
            ntp_hits: 1000,
            nke_hits: 5,
            cmd_hits: 2,
            ntp_drops: 3,
            nke_drops: 1,
            cmd_drops: 0,
            ntp_interval: 6,
            nke_interval: -4,
            cmd_interval: 8,
            ntp_timeout_interval: -2,
            last_ntp_hit_ago: 30,
            last_nke_hit_ago: 3600,
            last_cmd_hit_ago: 0,
        };
        assert_eq!(render_clients_row("host.example", &client, false, ReportMode::Human), expected("clirow", "HUM"));
        assert_eq!(render_clients_row("host.example", &client, false, ReportMode::Csv), expected("clirow", "CSV"));
        assert_eq!(render_clients_row("host.example", &client, true, ReportMode::Human), expected("clirownke", "HUM"));
        assert_eq!(render_clients_row("host.example", &client, true, ReportMode::Csv), expected("clirownke", "CSV"));

        // manual list row.
        let sample = ManualSampleReport {
            when_sec: 1_600_000_000,
            when_nsec: 0,
            slewed_offset: 0.01,
            orig_offset: 0.02,
            residual: -0.005,
        };
        assert_eq!(render_manual_list_row(3, &sample, ReportMode::Human), expected("mlrow", "HUM"));
        assert_eq!(render_manual_list_row(3, &sample, ReportMode::Csv), expected("mlrow", "CSV"));

        // Header/info text.
        assert_eq!(clients_header(false), "Hostname                      NTP   Drop Int IntL Last     Cmd   Drop Int  Last");
        assert_eq!(clients_header(true), "Hostname                      NTP   Drop Int IntL Last  NTS-KE   Drop Int  Last");
        assert_eq!(manual_list_info_line(5), "210 n_samples = 5\n");
    }

    #[test]
    fn ntpdata_renderer_matches_real_c() {
        use crate::ntp::ntp_report::NtpReport;
        use crate::sys_generic::Timespec;
        let v = include_str!("../../../research/oracle/chronyc-ntpdata-c-vectors.txt");
        let expected = |mode: &str| -> String {
            let l = v.lines().find(|l| l.contains(&format!("mode={mode} "))).unwrap();
            let start = l.find(" |").unwrap() + 2;
            let end = l.rfind('|').unwrap();
            l[start..end].replace("\\n", "\n")
        };
        let report = NtpReport {
            local_addr: crate::util::string_to_ip("192.168.1.10").unwrap(),
            leap: 1,
            version: 4,
            mode: 4,
            stratum: 1,
            poll: 6,
            precision: -24,
            root_delay: 0.01,
            root_dispersion: 0.02,
            ref_id: 0x4750_5300, // "GPS\0"
            ref_time: Timespec::new(1_700_000_000, 500_000_000),
            offset: -0.00015,
            peer_delay: 0.001,
            peer_dispersion: 2e-6,
            response_time: 1e-5,
            jitter_asymmetry: 0.25,
            tests: 0x2aa,
            interleaved: true,
            authenticated: true,
            tx_tss_char: 'K',
            rx_tss_char: 'H',
            total_valid_count: 98,
            total_good_count: 97,
            total_tx_count: 100,
            total_rx_count: 99,
        };
        let remote = crate::util::string_to_ip("203.0.113.9").unwrap();
        assert_eq!(render_ntpdata(&report, &remote, 123, ReportMode::Human), expected("HUM"));
        assert_eq!(render_ntpdata(&report, &remote, 123, ReportMode::Csv), expected("CSV"));
    }

    #[test]
    fn gmtime_report_string_matches_real_strftime() {
        let v = include_str!("../../../research/oracle/gmtime-report-c-vectors.txt");
        for l in v.lines().filter(|l| l.starts_with("T ")) {
            let sec: i64 = l
                .split_whitespace()
                .find_map(|t| t.strip_prefix("sec="))
                .unwrap()
                .parse()
                .unwrap();
            let start = l.find(" |").unwrap() + 2;
            let end = l.rfind('|').unwrap();
            assert_eq!(crate::util::gmtime_report_string(sec), &l[start..end], "sec={sec}");
        }
    }

    #[test]
    fn tracking_and_rtcdata_renderers_match_real_c() {
        use crate::cmdmon::{RtcReport, TrackingReport};
        let v = include_str!("../../../research/oracle/chronyc-tracking-rtc-c-vectors.txt");
        let expected = |id: &str, mode: &str| -> String {
            let l = v
                .lines()
                .find(|l| l.contains(&format!("id={id} ")) && l.contains(&format!("mode={mode} ")))
                .unwrap();
            let start = l.find(" |").unwrap() + 2;
            let end = l.rfind('|').unwrap();
            l[start..end].replace("\\n", "\n")
        };

        let trk = TrackingReport {
            ref_id: 0x0a01_0203,
            ip_addr: crate::util::IpAddr::Inet4(0xc0a8_0105),
            stratum: 3,
            leap_status: 0,
            ref_time_sec: 1_700_000_000,
            ref_time_nsec: 123_456_789,
            current_correction: 0.0015,
            last_offset: -0.00025,
            rms_offset: 0.0003,
            freq_ppm: -12.5,
            resid_freq_ppm: 0.05,
            skew_ppm: 0.2,
            root_delay: 0.01,
            root_dispersion: 0.02,
            last_update_interval: 64.0,
        };
        assert_eq!(render_tracking(&trk, "foo.example", ReportMode::Human), expected("track", "HUM"));
        assert_eq!(render_tracking(&trk, "foo.example", ReportMode::Csv), expected("track", "CSV"));

        let rtc = RtcReport {
            ref_time_sec: 1_700_000_000,
            ref_time_nsec: 123_456_789,
            n_samples: 40,
            n_runs: 8,
            span_seconds: 7200,
            rtc_seconds_fast: 0.125,
            rtc_gain_rate_ppm: -1.5,
        };
        assert_eq!(render_rtcdata(&rtc, ReportMode::Human), expected("rtc", "HUM"));
        assert_eq!(render_rtcdata(&rtc, ReportMode::Csv), expected("rtc", "CSV"));
    }

    #[test]
    fn every_label_aligns_to_16_columns() {
        // Guard the alignment invariant directly, independent of the golden block.
        for l in sample().render().lines() {
            let colon = l.find(':').expect("each line has a colon");
            assert_eq!(&l[colon..colon + 2], ": ", "expected ': ' at column 16 in {l:?}");
            assert_eq!(colon, 16, "label column must be 16 wide in {l:?}");
        }
    }
}
