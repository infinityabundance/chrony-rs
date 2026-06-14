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
pub enum SourceMode {
    /// `^` — a server we poll as a client.
    Server,
    /// `=` — a symmetric peer.
    Peer,
    /// `#` — a local reference clock.
    RefClock,
}

impl SourceMode {
    fn glyph(self) -> char {
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

impl SourceState {
    fn glyph(self) -> char {
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
    fn render_row(&self) -> String {
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
    fn render_row(&self) -> String {
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
    fn every_label_aligns_to_16_columns() {
        // Guard the alignment invariant directly, independent of the golden block.
        for l in sample().render().lines() {
            let colon = l.find(':').expect("each line has a colon");
            assert_eq!(&l[colon..colon + 2], ": ", "expected ': ' at column 16 in {l:?}");
            assert_eq!(colon, 16, "label column must be 16 wide in {l:?}");
        }
    }
}
