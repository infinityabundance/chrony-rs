//! Directive parser: token lines → typed [`Config`] plus [`Diagnostic`]s.
//!
//! Two distinct failure modes are kept separate, because chrony keeps them
//! separate and a future engineer must not collapse them:
//!
//!   * **Unknown directive** — a keyword chrony does not recognize at all. chrony
//!     fatally rejects the file. We emit `CFG_UNKNOWN_DIRECTIVE` (error).
//!   * **Recognized-but-unmodeled directive** — a real chrony keyword whose
//!     *semantics* chrony-rs hasn't modeled yet. This is **not** an error: a valid
//!     chrony file must still pass `--check-config`. We keep it as
//!     [`Directive::Unmodeled`] with no diagnostic.
//!
//! Argument-level errors (wrong arity, non-numeric where a number is required)
//! are emitted for *modeled* directives only; for unmodeled directives we cannot
//! validate arguments without modeling them, so we don't pretend to.

use super::diagnostics::Diagnostic;
use super::lexer::{tokenize, TokenLine};
use super::model::{
    AuthSelectMode, Config, Directive, LeapSecMode, LogFlag, ServerKind, SourceDirective,
    TempCompCurve,
};

/// Result of parsing: the (best-effort) config and any diagnostics.
#[derive(Clone, Debug, Default)]
pub struct ParseOutput {
    pub config: Config,
    pub diagnostics: Vec<Diagnostic>,
}

impl ParseOutput {
    /// True if any diagnostic is an error. `--check-config` exits non-zero exactly
    /// when this is true.
    pub fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(Diagnostic::is_error)
    }
}

/// The set of directive keywords chrony recognizes. This list governs
/// *recognition* only — being on it does not imply chrony-rs models the
/// directive's behavior.
///
/// **Extracted from chrony 4.5 `conf.c`** (the complete `strcasecmp(command, …)`
/// dispatch, 93 entries) and cross-checked with `chronyd -p` via
/// `tools/oracle/directive-recognition.sh`. The witnessed count is pinned by a
/// test below. The set was built in two passes the oracle/source archaeology
/// drove: first the oracle caught five *fabricated* entries (guessed NTS names,
/// `open_commands`, `ntpcache`); then doxygen-style extraction of `conf.c` found
/// eleven *missing* ones (the `bind*device`, `linux_*`, `commandkey`/
/// `generatecommandkey` compat directives, `ptpport`, etc.). Measured, not
/// guessed. Adding a keyword is a version-anchored change tied to
/// `docs/version-lineage.md` and `docs/source-archaeology.md`, and must be
/// re-witnessed.
const KNOWN_DIRECTIVES: &[&str] = &[
    "acquisitionport", "allow", "authselectmode", "bindacqaddress", "bindacqdevice", "bindaddress",
    "bindcmdaddress", "bindcmddevice", "binddevice", "broadcast", "clientloglimit", "clockprecision",
    "cmdallow", "cmddeny", "cmdport", "cmdratelimit", "combinelimit", "commandkey",
    "confdir", "corrtimeratio", "deny", "driftfile", "dscp", "dumpdir",
    "dumponexit", "fallbackdrift", "generatecommandkey", "hwclockfile", "hwtimestamp", "hwtstimeout",
    "include", "initstepslew", "keyfile", "leapsecmode", "leapsectz", "linux_freq_scale",
    "linux_hz", "local", "lock_all", "log", "logbanner", "logchange",
    "logdir", "mailonchange", "makestep", "manual", "maxchange", "maxclockerror",
    "maxdistance", "maxdrift", "maxjitter", "maxntsconnections", "maxsamples", "maxslewrate",
    "maxupdateskew", "minsamples", "minsources", "nocerttimecheck", "noclientlog", "nosystemcert",
    "ntpsigndsocket", "ntscachedir", "ntsdumpdir", "ntsntpserver", "ntsport", "ntsprocesses",
    "ntsratelimit", "ntsrefresh", "ntsrotate", "ntsservercert", "ntsserverkey", "ntstrustedcerts",
    "peer", "pidfile", "pool", "port", "ptpport", "ratelimit",
    "refclock", "refresh", "reselectdist", "rtcautotrim", "rtcdevice", "rtcfile",
    "rtconutc", "rtcsync", "sched_priority", "server", "smoothtime", "sourcedir",
    "stratumweight", "tempcomp", "user",
];

fn is_known_directive(keyword: &str) -> bool {
    KNOWN_DIRECTIVES.contains(&keyword)
}

/// The oracle-anchored directive recognition set (chrony 4.5). Exposed so the
/// doc generator (`xtask`) renders the list from the *source of truth*, making it
/// impossible for the documented set to drift from the code.
pub fn known_directives() -> &'static [&'static str] {
    KNOWN_DIRECTIVES
}

/// Source (`server`/`pool`/`peer`) options that take no value. See `parse_source`.
pub fn source_flag_options() -> &'static [&'static str] {
    SOURCE_FLAG_OPTS
}

/// Source options that consume one value argument. See `parse_source`.
pub fn source_value_options() -> &'static [&'static str] {
    SOURCE_VALUE_OPTS
}

/// Parse a full chrony config file.
pub fn parse(input: &str) -> ParseOutput {
    let mut out = ParseOutput::default();
    for line in tokenize(input) {
        parse_line(line, &mut out);
    }
    out
}

fn parse_line(line: TokenLine, out: &mut ParseOutput) {
    let TokenLine {
        line_no,
        keyword,
        keyword_raw,
        args,
    } = line;

    match keyword.as_str() {
        "server" => parse_source(ServerKind::Server, line_no, args, out),
        "pool" => parse_source(ServerKind::Pool, line_no, args, out),
        "peer" => parse_source(ServerKind::Peer, line_no, args, out),
        "driftfile" => parse_driftfile(line_no, args, out),
        "makestep" => parse_makestep(line_no, args, out),
        "maxchange" => parse_maxchange(line_no, args, out),
        "clientloglimit" => parse_clientloglimit(line_no, args, out),
        "leapsecmode" => parse_leapsecmode(line_no, args, out),
        "authselectmode" => parse_authselectmode(line_no, args, out),
        "log" => parse_log(line_no, args, out),
        "ratelimit" | "cmdratelimit" | "ntsratelimit" => {
            parse_ratelimit(keyword.as_str(), line_no, args, out)
        }
        "allow" => parse_access(line_no, true, false, args, out),
        "deny" => parse_access(line_no, false, false, args, out),
        "cmdallow" => parse_access(line_no, true, true, args, out),
        "cmddeny" => parse_access(line_no, false, true, args, out),
        "initstepslew" => parse_initstepslew(line_no, args, out),
        "fallbackdrift" => parse_fallbackdrift(line_no, args, out),
        "smoothtime" => parse_smoothtime(line_no, args, out),
        "local" => parse_local(line_no, args, out),
        "sourcedir" => out.config.directives.push((line_no, Directive::SourceDir { path: args.join(" ") })),
        "confdir" => parse_confdir(line_no, args, out),
        "include" => parse_include(line_no, args, out),
        "broadcast" => parse_broadcast(line_no, args, out),
        "mailonchange" => parse_mailonchange(line_no, args, out),
        "tempcomp" => parse_tempcomp(line_no, args, out),
        "rtcsync" => {
            // A bare flag. chrony tolerates trailing tokens on some flag
            // directives, but `rtcsync` takes none; extra args are a diagnostic.
            if !args.is_empty() {
                out.diagnostics.push(
                    Diagnostic::error(
                        line_no,
                        "CFG_UNEXPECTED_ARGS",
                        format!("rtcsync takes no arguments, found {}", args.len()),
                    )
                    .for_directive("rtcsync"),
                );
            }
            out.config.directives.push((line_no, Directive::RtcSync));
        }
        other if SCALAR_INT_DIRECTIVES.contains(&other) => {
            parse_scalar_int(other, keyword_raw, line_no, args, out)
        }
        other if SCALAR_DOUBLE_DIRECTIVES.contains(&other) => {
            parse_scalar_double(other, keyword_raw, line_no, args, out)
        }
        other if SCALAR_STRING_DIRECTIVES.contains(&other) => {
            parse_scalar_string(other, keyword_raw, line_no, args, out)
        }
        other if is_known_directive(other) => {
            // Recognized chrony keyword we have not modeled. Preserve it; do NOT
            // emit a diagnostic — a valid chrony file must still check-config clean.
            out.config.directives.push((
                line_no,
                Directive::Unmodeled {
                    keyword: keyword_raw,
                    args,
                },
            ));
        }
        _ => {
            out.diagnostics.push(Diagnostic::error(
                line_no,
                "CFG_UNKNOWN_DIRECTIVE",
                format!("unknown directive '{keyword_raw}'"),
            ));
        }
    }
}

/// Source options that take **no** value. Extracted verbatim from chrony 4.5
/// `cmdparse.c::CPS_ParseNTPSourceAdd` (the boolean branches) plus the select
/// options from `CPS_GetSelectOption`. See `docs/source-archaeology.md`.
const SOURCE_FLAG_OPTS: &[&str] = &[
    "auto_offline", "burst", "copy", "iburst", "offline", "nts", "xleave",
    // select options (CPS_GetSelectOption):
    "noselect", "prefer", "require", "trust",
];

/// Source options that consume exactly **one** value argument. Extracted from the
/// `cmdparse.c::CPS_ParseNTPSourceAdd` branches that read a following word and
/// `return 0` (error) when it is missing.
const SOURCE_VALUE_OPTS: &[&str] = &[
    "certset", "key", "asymmetry", "extfield", "filter", "maxdelay", "maxdelayratio",
    "maxdelaydevratio", "maxdelayquant", "maxpoll", "maxsamples", "maxsources", "mindelay",
    "minpoll", "minsamples", "minstratum", "ntsport", "offset", "port", "polltarget",
    "presend", "version",
];

fn parse_source(kind: ServerKind, line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    let kw = match kind {
        ServerKind::Server => "server",
        ServerKind::Pool => "pool",
        ServerKind::Peer => "peer",
    };
    let mut iter = args.into_iter();
    let Some(address) = iter.next() else {
        out.diagnostics.push(
            Diagnostic::error(
                line_no,
                "CFG_MISSING_ADDRESS",
                format!("{kw} directive requires a hostname or address"),
            )
            .for_directive(kw),
        );
        return;
    };

    let mut src = SourceDirective {
        kind,
        address,
        iburst: false,
        burst: false,
        minpoll: None,
        maxpoll: None,
        raw_options: Vec::new(),
    };

    // Validate options exactly as chrony does: a flag option consumes nothing, a
    // value option consumes one following word, and ANY unrecognized option (or a
    // value option missing its value) makes chrony's parser `return 0`, which
    // conf.c reports as "Could not parse <kw> directive". We reproduce that — an
    // earlier version silently kept unknown options, which the oracle flagged as a
    // divergence (`server host iburst # primary` must be rejected, not accepted).
    while let Some(opt) = iter.next() {
        let lc = opt.to_ascii_lowercase();
        if SOURCE_FLAG_OPTS.contains(&lc.as_str()) {
            match lc.as_str() {
                "iburst" => src.iburst = true,
                "burst" => src.burst = true,
                _ => src.raw_options.push(opt), // recognized flag, not yet modeled
            }
        } else if SOURCE_VALUE_OPTS.contains(&lc.as_str()) {
            let Some(value) = iter.next() else {
                // chrony: missing value → return 0 → "Could not parse <kw> directive".
                out.diagnostics
                    .push(source_parse_error(line_no, kw, format!("{opt} requires a value")));
                return;
            };
            // minpoll/maxpoll are modeled as integers; chrony also rejects a
            // non-integer here (its number parse fails → return 0).
            match lc.as_str() {
                "minpoll" | "maxpoll" => match value.parse::<i32>() {
                    Ok(n) => {
                        if lc == "minpoll" {
                            src.minpoll = Some(n);
                        } else {
                            src.maxpoll = Some(n);
                        }
                    }
                    Err(_) => {
                        out.diagnostics.push(source_parse_error(
                            line_no,
                            kw,
                            format!("{opt} expects an integer, found '{value}'"),
                        ));
                        return;
                    }
                },
                _ => {
                    // recognized value option, not yet modeled: preserve both tokens.
                    src.raw_options.push(opt);
                    src.raw_options.push(value);
                }
            }
        } else {
            // Unknown option — chrony rejects the whole directive here.
            out.diagnostics
                .push(source_parse_error(line_no, kw, format!("unknown option '{opt}'")));
            return;
        }
    }

    out.config.directives.push((line_no, Directive::Source(src)));
}

/// Build the diagnostic chrony emits for any failure inside a source directive.
/// chrony has a single message for all of them — "Could not parse <kw> directive"
/// — so the code is uniform (`CFG_BAD_NUMBER` keeps `chrony_message()` mapping to
/// that exact wording).
fn source_parse_error(line_no: usize, kw: &str, detail: String) -> Diagnostic {
    Diagnostic::error(line_no, "CFG_BAD_NUMBER", format!("{kw}: {detail}")).for_directive(kw)
}

fn parse_driftfile(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    match args.len() {
        0 => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_MISSING_PATH", "driftfile requires a path")
                .for_directive("driftfile"),
        ),
        1 => out.config.directives.push((
            line_no,
            Directive::DriftFile {
                path: args.into_iter().next().unwrap(),
            },
        )),
        _ => out.diagnostics.push(
            Diagnostic::error(
                line_no,
                "CFG_UNEXPECTED_ARGS",
                "driftfile takes a single path argument",
            )
            .for_directive("driftfile"),
        ),
    }
}

/// Single-value `int` directives (chrony `conf.c`: `parse_int(p, &global)`). Each takes
/// exactly one argument parsed with `sscanf("%d")` (see [`crate::config::scan::scan_int`]).
const SCALAR_INT_DIRECTIVES: &[&str] = &[
    "cmdport", "ntpport", "ptpport", "maxsamples", "minsamples", "minsources",
];

/// Single-value `double` directives (chrony `conf.c`: `parse_double(p, &global)`).
const SCALAR_DOUBLE_DIRECTIVES: &[&str] = &[
    "clockprecision", "combinelimit", "corrtimeratio", "maxclockerror", "maxdistance",
    "maxdrift", "maxjitter", "maxslewrate", "maxupdateskew", "reselectdistance", "stratumweight",
];

/// Single-value string directives (chrony `conf.c`: `parse_string(p, &global)`). Each takes
/// exactly one argument, stored verbatim. (`driftfile` is modeled separately for its
/// last-wins accessor.)
const SCALAR_STRING_DIRECTIVES: &[&str] = &[
    "bindacqdevice", "bindcmddevice", "binddevice", "dumpdir", "hwclockfile", "keyfile",
    "leapsectz", "logdir", "ntpsigndsocket", "ntsdumpdir", "pidfile", "rtcdevice", "rtcfile",
    "user",
];

/// Emit chrony's `check_number_of_args` arity diagnostic (`Missing`/`Too many`) when
/// `args.len() != want`. Returns `true` if the arity is wrong (caller should stop).
fn arity_error(keyword: &str, keyword_raw: &str, want: usize, line_no: usize, args: &[String], out: &mut ParseOutput) -> bool {
    if args.len() == want {
        return false;
    }
    let (code, what) = if args.len() < want {
        ("CFG_MISSING_VALUE", "Missing")
    } else {
        ("CFG_UNEXPECTED_ARGS", "Too many")
    };
    out.diagnostics.push(
        Diagnostic::error(line_no, code,
            format!("{what} arguments for {keyword}: expected {want}, found {}", args.len()))
            .for_directive(keyword_raw),
    );
    true
}

/// chrony `parse_string`: exactly one argument, stored verbatim.
fn parse_scalar_string(keyword: &str, keyword_raw: String, line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    if arity_error(keyword, &keyword_raw, 1, line_no, &args, out) {
        return;
    }
    let value = args.into_iter().next().unwrap();
    out.config.directives.push((line_no, Directive::ScalarString { keyword: keyword.to_string(), value }));
}

/// chrony `parse_clientloglimit`: exactly one argument, read with `sscanf("%lu")`.
fn parse_clientloglimit(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    if arity_error("clientloglimit", "clientloglimit", 1, line_no, &args, out) {
        return;
    }
    match crate::config::scan::scan_uint(&args[0]) {
        Some(value) => out.config.directives.push((
            line_no,
            Directive::ScalarUint { keyword: "clientloglimit".into(), value },
        )),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER",
                format!("clientloglimit value must be an unsigned integer, found '{}'", args[0]))
                .for_directive("clientloglimit"),
        ),
    }
}

/// chrony `parse_maxchange`: `maxchange <threshold> <delay> <ignore>` read with one
/// `sscanf("%lf %d %d")` over the line, so a malformed earlier field fails the whole thing.
fn parse_maxchange(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    if arity_error("maxchange", "maxchange", 3, line_no, &args, out) {
        return;
    }
    match crate::config::scan::scan_maxchange(&args.join(" ")) {
        Some((threshold, delay, ignore)) => out.config.directives.push((
            line_no,
            Directive::MaxChange { threshold, delay, ignore },
        )),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER",
                format!("maxchange expects '<threshold> <delay> <ignore>', found '{}'", args.join(" ")))
                .for_directive("maxchange"),
        ),
    }
}

/// chrony `parse_leapsecmode`: a single keyword matched case-insensitively against the whole
/// value (so extra tokens never match → parse error). chrony emits `command_parse_error`
/// for any non-match (including wrong arity), so this is never an arity diagnostic.
fn parse_leapsecmode(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    let mode = match args.join(" ").to_ascii_lowercase().as_str() {
        "system" => Some(LeapSecMode::System),
        "slew" => Some(LeapSecMode::Slew),
        "step" => Some(LeapSecMode::Step),
        "ignore" => Some(LeapSecMode::Ignore),
        _ => None,
    };
    match mode {
        Some(m) => out.config.directives.push((line_no, Directive::LeapSecMode(m))),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER", "invalid leapsecmode".to_string())
                .for_directive("leapsecmode"),
        ),
    }
}

/// chrony `parse_authselectmode`: a single keyword (case-insensitive over the whole value).
fn parse_authselectmode(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    let mode = match args.join(" ").to_ascii_lowercase().as_str() {
        "require" => Some(AuthSelectMode::Require),
        "prefer" => Some(AuthSelectMode::Prefer),
        "mix" => Some(AuthSelectMode::Mix),
        "ignore" => Some(AuthSelectMode::Ignore),
        _ => None,
    };
    match mode {
        Some(m) => out.config.directives.push((line_no, Directive::AuthSelectMode(m))),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER", "invalid authselectmode".to_string())
                .for_directive("authselectmode"),
        ),
    }
}

/// chrony `parse_log`: a list of logging-category flags, matched **case-sensitively**
/// (`strcmp`). A bare `log` enables nothing. An unrecognized flag is chrony's
/// `other_parse_error("Invalid log parameter")` and stops parsing the line; the flags read
/// before it are still kept (chrony has already set them).
fn parse_log(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    let mut flags = Vec::new();
    for arg in &args {
        let flag = match arg.as_str() {
            "rawmeasurements" => LogFlag::RawMeasurements,
            "measurements" => LogFlag::Measurements,
            "selection" => LogFlag::Selection,
            "statistics" => LogFlag::Statistics,
            "tracking" => LogFlag::Tracking,
            "rtc" => LogFlag::Rtc,
            "refclocks" => LogFlag::Refclocks,
            "tempcomp" => LogFlag::Tempcomp,
            _ => {
                out.diagnostics.push(
                    Diagnostic::error(line_no, "CFG_INVALID_LOG_PARAM", format!("invalid log parameter '{arg}'"))
                        .for_directive("log"),
                );
                break;
            }
        };
        flags.push(flag);
    }
    out.config.directives.push((line_no, Directive::Log(flags)));
}

/// chrony `parse_tempcomp`: the form is chosen by argument count — 3 args is the
/// `<sensor-file> <interval> <points-file>` form, otherwise exactly 6 for the
/// `<sensor-file> <interval> <T0> <k0> <k1> <k2>` form (its five doubles read with one
/// `sscanf("%lf %lf %lf %lf %lf")`). A non-numeric value is `command_parse_error`.
fn parse_tempcomp(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    let point_form = args.len() == 3;
    if !point_form && args.len() != 6 {
        let (code, what) = if args.len() < 6 {
            ("CFG_MISSING_VALUE", "Missing")
        } else {
            ("CFG_UNEXPECTED_ARGS", "Too many")
        };
        out.diagnostics.push(
            Diagnostic::error(line_no, code,
                format!("{what} arguments for tempcomp: expected 3 or 6, found {}", args.len()))
                .for_directive("tempcomp"),
        );
        return;
    }
    let bad = |out: &mut ParseOutput| {
        out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER", "could not parse tempcomp".to_string())
                .for_directive("tempcomp"),
        );
    };
    let sensor_file = args[0].clone();
    if point_form {
        let Some(interval) = crate::config::scan::scan_double(&args[1]) else {
            return bad(out);
        };
        out.config.directives.push((line_no, Directive::TempComp {
            sensor_file,
            interval,
            curve: TempCompCurve::PointFile(args[2].clone()),
        }));
    } else {
        let Some(v) = crate::config::scan::scan_doubles(&args[1..].join(" "), 5) else {
            return bad(out);
        };
        out.config.directives.push((line_no, Directive::TempComp {
            sensor_file,
            interval: v[0],
            curve: TempCompCurve::Coefficients { t0: v[1], k0: v[2], k1: v[3], k2: v[4] },
        }));
    }
}

/// chrony `parse_broadcast`: `<interval> <address> [port]`. The interval is `sscanf("%d")`
/// on the first word; the address must parse as an IP (`UTI_StringToIP` →
/// [`crate::util::string_to_ip`]); the optional third word is the port (`sscanf("%d")`),
/// defaulting to `NTP_PORT` (123). A 4th word, a bad interval/port, or an unparseable
/// address is `command_parse_error`.
fn parse_broadcast(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    let err = |out: &mut ParseOutput| {
        out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER", "could not parse broadcast".to_string())
                .for_directive("broadcast"),
        );
    };
    let Some(interval) = args.first().and_then(|s| crate::config::scan::scan_int(s)) else {
        return err(out);
    };
    let Some(address) = args.get(1).filter(|s| crate::util::string_to_ip(s).is_some()).cloned() else {
        return err(out);
    };
    let port = match args.get(2) {
        None => 123, // NTP_PORT
        Some(s) => match crate::config::scan::scan_int(s) {
            Some(p) if args.len() == 3 => p,
            _ => return err(out),
        },
    };
    out.config.directives.push((line_no, Directive::Broadcast { interval, address, port }));
}

/// chrony `parse_mailonchange`: exactly two args — the email address and the step threshold
/// (`sscanf("%lf")`).
fn parse_mailonchange(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    if arity_error("mailonchange", "mailonchange", 2, line_no, &args, out) {
        return;
    }
    match crate::config::scan::scan_double(&args[1]) {
        Some(threshold) => out.config.directives.push((
            line_no,
            Directive::MailOnChange { address: args[0].clone(), threshold },
        )),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER",
                format!("mailonchange threshold must be a number, found '{}'", args[1]))
                .for_directive("mailonchange"),
        ),
    }
}

/// chrony `parse_local`: the `[stratum N] [orphan] [distance D]` options via the ported
/// `CPS_ParseLocal` ([`crate::cmdparse::parse_local`]). The directive's presence enables
/// local mode; a malformed option is `command_parse_error`.
fn parse_local(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    match crate::cmdparse::parse_local(&args.join(" ")) {
        Some(opts) => out.config.directives.push((line_no, Directive::Local(opts))),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER", "could not parse local options".to_string())
                .for_directive("local"),
        ),
    }
}

/// chrony `parse_confdir` → `search_dirs`: `UTI_SplitString` the line into 1..=`MAX_CONF_DIRS`
/// (10) directories (the `*.conf` globbing and file reading are a daemon-time boundary,
/// deferred). Zero directories or more than 10 is `command_parse_error`.
fn parse_confdir(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    // chrony MAX_CONF_DIRS.
    if args.is_empty() || args.len() > 10 {
        out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER",
                format!("confdir expects 1..=10 directories, found {}", args.len()))
                .for_directive("confdir"),
        );
        return;
    }
    out.config.directives.push((line_no, Directive::ConfDir { dirs: args }));
}

/// chrony `parse_include`: exactly one glob pattern argument (the glob expansion and file
/// reading are a daemon-time boundary, deferred).
fn parse_include(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    if arity_error("include", "include", 1, line_no, &args, out) {
        return;
    }
    out.config.directives.push((line_no, Directive::Include { pattern: args.into_iter().next().unwrap() }));
}

/// chrony `parse_fallbackdrift`: exactly two ints read with one `sscanf("%d %d")`.
fn parse_fallbackdrift(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    if arity_error("fallbackdrift", "fallbackdrift", 2, line_no, &args, out) {
        return;
    }
    match crate::config::scan::scan_two_int(&args.join(" ")) {
        Some((min, max)) => out.config.directives.push((line_no, Directive::FallbackDrift { min, max })),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER",
                format!("fallbackdrift expects '<min> <max>', found '{}'", args.join(" ")))
                .for_directive("fallbackdrift"),
        ),
    }
}

/// chrony `parse_smoothtime`: `<max-freq> <max-wander> [leaponly]`. Valid arity is 2 or 3
/// (chrony only enforces exactly-2 when there isn't a 3rd arg). The two doubles are read
/// with `sscanf("%lf %lf")`; a present 3rd token must be `leaponly` (case-insensitive).
fn parse_smoothtime(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    if args.len() < 2 {
        out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_MISSING_VALUE",
                format!("Missing arguments for smoothtime: expected 2, found {}", args.len()))
                .for_directive("smoothtime"),
        );
        return;
    }
    if args.len() > 3 {
        out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_UNEXPECTED_ARGS",
                format!("Too many arguments for smoothtime: expected 2, found {}", args.len()))
                .for_directive("smoothtime"),
        );
        return;
    }
    let (max_freq, max_wander) = match crate::config::scan::scan_two_double(&args.join(" ")) {
        Some(v) => v,
        None => {
            out.diagnostics.push(
                Diagnostic::error(line_no, "CFG_BAD_NUMBER",
                    format!("smoothtime expects '<max-freq> <max-wander>', found '{}'", args.join(" ")))
                    .for_directive("smoothtime"),
            );
            return;
        }
    };
    let mut leap_only = false;
    if let Some(third) = args.get(2) {
        if third.eq_ignore_ascii_case("leaponly") {
            leap_only = true;
        } else {
            out.diagnostics.push(
                Diagnostic::error(line_no, "CFG_BAD_NUMBER",
                    format!("smoothtime third argument must be 'leaponly', found '{third}'"))
                    .for_directive("smoothtime"),
            );
            return;
        }
    }
    out.config.directives.push((line_no, Directive::SmoothTime { max_freq, max_wander, leap_only }));
}

/// chrony `parse_allow_deny`: parse the access spec via the ported `CPS_ParseAllowDeny`
/// ([`crate::cmdparse::parse_allow_deny`]) and record an [`Directive::AccessRestriction`].
/// `allow` is the allow/deny sense; `cmd` selects the command table. A malformed spec is
/// chrony's `command_parse_error`. (A bare hostname resolves at daemon time in chrony; the
/// ported parser defers DNS, so an unresolved hostname reads as a parse failure here.)
fn parse_access(line_no: usize, allow: bool, cmd: bool, args: Vec<String>, out: &mut ParseOutput) {
    let keyword = match (allow, cmd) {
        (true, false) => "allow",
        (false, false) => "deny",
        (true, true) => "cmdallow",
        (false, true) => "cmddeny",
    };
    match crate::cmdparse::parse_allow_deny(&args.join(" ")) {
        Some(spec) => out
            .config
            .directives
            .push((line_no, Directive::AccessRestriction { allow, cmd, spec })),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER", format!("could not parse {keyword} spec"))
                .for_directive(keyword),
        ),
    }
}

/// chrony `parse_initstepslew`: the first word is the step threshold (`sscanf("%lf")`); the
/// remaining words are source host strings (chrony resolves them via DNS — deferred here,
/// so they are kept verbatim). An empty line (no threshold) is `command_parse_error`.
fn parse_initstepslew(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    let Some((threshold_tok, sources)) = args.split_first() else {
        out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER", "initstepslew needs a threshold".to_string())
                .for_directive("initstepslew"),
        );
        return;
    };
    match crate::config::scan::scan_double(threshold_tok) {
        Some(threshold) => out.config.directives.push((
            line_no,
            Directive::InitStepSlew { threshold, sources: sources.to_vec() },
        )),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER",
                format!("initstepslew threshold must be a number, found '{threshold_tok}'"))
                .for_directive("initstepslew"),
        ),
    }
}

/// chrony `parse_ratelimit`: the `[interval N] [burst N] [leak N]` key-value loop. The
/// directive's presence enables it. Each iteration reads an option word
/// (`CPS_SplitWord` → [`crate::cmdparse::split_word`]) and its value with `sscanf("%d%n")`,
/// advancing by *only* the consumed digits — so a value's trailing junk (`5x`) re-tokenizes
/// into a bad option key on the next pass. An unknown key or a missing/non-numeric value is
/// chrony's `command_parse_error`; values applied before the error are kept (chrony would
/// already have stored them).
fn parse_ratelimit(keyword: &str, line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    let line = args.join(" ");
    let mut rest = line.as_str();
    let (mut interval, mut burst, mut leak) = (None, None, None);
    let mut err = false;
    while !rest.is_empty() {
        let (opt, after) = crate::cmdparse::split_word(rest);
        if opt.is_empty() {
            break;
        }
        match crate::config::scan::scan_int_at(after) {
            Some((val, consumed)) => {
                rest = &after[consumed..];
                match opt.to_ascii_lowercase().as_str() {
                    "interval" => interval = Some(val),
                    "burst" => burst = Some(val),
                    "leak" => leak = Some(val),
                    _ => {
                        err = true;
                        break;
                    }
                }
            }
            None => {
                err = true;
                break;
            }
        }
    }
    if err {
        out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER", format!("could not parse {keyword} options"))
                .for_directive(keyword),
        );
    }
    out.config.directives.push((
        line_no,
        Directive::RateLimit { keyword: keyword.to_string(), interval, burst, leak },
    ));
}

/// chrony `parse_int`: exactly one argument, read with lenient `sscanf("%d")`. Wrong arity
/// or a non-numeric value is fatal in chrony; here it is a recoverable diagnostic.
fn parse_scalar_int(keyword: &str, keyword_raw: String, line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    if args.len() != 1 {
        // chrony check_number_of_args: too few -> "Missing", too many -> "Too many".
        let (code, what) = if args.is_empty() {
            ("CFG_MISSING_VALUE", "Missing")
        } else {
            ("CFG_UNEXPECTED_ARGS", "Too many")
        };
        out.diagnostics.push(
            Diagnostic::error(line_no, code,
                format!("{what} arguments for {keyword}: expected 1, found {}", args.len()))
                .for_directive(&keyword_raw),
        );
        return;
    }
    match crate::config::scan::scan_int(&args[0]) {
        Some(value) => out.config.directives.push((
            line_no,
            Directive::ScalarInt { keyword: keyword.to_string(), value },
        )),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER",
                format!("{keyword} value must be an integer, found '{}'", args[0]))
                .for_directive(&keyword_raw),
        ),
    }
}

/// chrony `parse_double`: exactly one argument, read with lenient `sscanf("%lf")`.
fn parse_scalar_double(keyword: &str, keyword_raw: String, line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    if args.len() != 1 {
        // chrony check_number_of_args: too few -> "Missing", too many -> "Too many".
        let (code, what) = if args.is_empty() {
            ("CFG_MISSING_VALUE", "Missing")
        } else {
            ("CFG_UNEXPECTED_ARGS", "Too many")
        };
        out.diagnostics.push(
            Diagnostic::error(line_no, code,
                format!("{what} arguments for {keyword}: expected 1, found {}", args.len()))
                .for_directive(&keyword_raw),
        );
        return;
    }
    match crate::config::scan::scan_double(&args[0]) {
        Some(value) => out.config.directives.push((
            line_no,
            Directive::ScalarDouble { keyword: keyword.to_string(), value },
        )),
        None => out.diagnostics.push(
            Diagnostic::error(line_no, "CFG_BAD_NUMBER",
                format!("{keyword} value must be a number, found '{}'", args[0]))
                .for_directive(&keyword_raw),
        ),
    }
}

fn parse_makestep(line_no: usize, args: Vec<String>, out: &mut ParseOutput) {
    // chrony: `makestep <threshold-seconds> <limit-updates>`. A bare `makestep`
    // with no args is also accepted by chrony and means "step once" — but to keep
    // the admitted court honest we currently require the two-argument form and
    // defer the zero-arg form to CHRONY.CONFIG.7 with an explicit oracle case.
    if args.len() != 2 {
        out.diagnostics.push(
            Diagnostic::error(
                line_no,
                "CFG_BAD_ARITY",
                format!("makestep expects 2 arguments (threshold limit), found {}", args.len()),
            )
            .for_directive("makestep"),
        );
        return;
    }
    let threshold = match args[0].parse::<f64>() {
        Ok(v) => v,
        Err(_) => {
            out.diagnostics.push(
                Diagnostic::error(
                    line_no,
                    "CFG_BAD_NUMBER",
                    format!("makestep threshold must be a number, found '{}'", args[0]),
                )
                .for_directive("makestep"),
            );
            return;
        }
    };
    let limit = match args[1].parse::<i32>() {
        Ok(v) => v,
        Err(_) => {
            out.diagnostics.push(
                Diagnostic::error(
                    line_no,
                    "CFG_BAD_NUMBER",
                    format!("makestep limit must be an integer, found '{}'", args[1]),
                )
                .for_directive("makestep"),
            );
            return;
        }
    };
    out.config
        .directives
        .push((line_no, Directive::MakeStep { threshold, limit }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_minimal_config() {
        // CHRONY.CONFIG.3 / .8 / .7 — a realistic distro-shaped fragment.
        let cfg = "\
# minimal
pool 2.pool.ntp.org iburst
server time.example.org minpoll 4 maxpoll 8
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
";
        let out = parse(cfg);
        assert!(!out.has_errors(), "valid config must not error: {:?}", out.diagnostics);
        let sources: Vec<_> = out.config.sources().collect();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].kind, ServerKind::Pool);
        assert!(sources[0].iburst);
        assert_eq!(sources[1].minpoll, Some(4));
        assert_eq!(sources[1].maxpoll, Some(8));
        assert_eq!(out.config.drift_file(), Some("/var/lib/chrony/drift"));
    }

    #[test]
    fn unknown_directive_is_an_error() {
        // CHRONY.CONFIG.12
        let out = parse("frobnicate 5\n");
        assert!(out.has_errors());
        assert_eq!(out.diagnostics[0].code, "CFG_UNKNOWN_DIRECTIVE");
    }

    #[test]
    fn recognized_but_unmodeled_directive_is_not_an_error() {
        // `hwtimestamp` is a real chrony directive we don't model yet. A file
        // using it must still pass check-config.
        let out = parse("hwtimestamp *\n");
        assert!(!out.has_errors(), "{:?}", out.diagnostics);
        assert!(matches!(
            out.config.directives[0].1,
            Directive::Unmodeled { .. }
        ));
    }

    #[test]
    fn known_directive_set_is_oracle_anchored_to_chrony_4_5() {
        // The recognition set was measured, not guessed: every entry is recognized
        // by `chronyd -p` in chrony 4.5 (tools/oracle/directive-recognition.sh).
        // Pin the count and a few entries the oracle specifically corrected, so a
        // regression toward fabricated directives is caught.
        assert_eq!(KNOWN_DIRECTIVES.len(), 93, "full chrony 4.5 conf.c directive count");
        // Previously-fabricated names that chrony 4.5 rejects must NOT reappear.
        for bogus in ["ntsca", "ntscert", "ntskey", "ntpcache", "open_commands"] {
            assert!(!is_known_directive(bogus), "{bogus} is not a chrony 4.5 directive");
        }
        // Names the oracle taught us (correct NTS names, sourcedir) must be present.
        for real in ["ntsservercert", "ntsserverkey", "ntstrustedcerts", "sourcedir", "cmdratelimit"] {
            assert!(is_known_directive(real), "{real} is a real chrony 4.5 directive");
        }
    }

    #[test]
    fn server_without_address_errors() {
        let out = parse("server\n");
        assert!(out.has_errors());
        assert_eq!(out.diagnostics[0].code, "CFG_MISSING_ADDRESS");
    }

    #[test]
    fn makestep_bad_number_errors() {
        let out = parse("makestep fast 3\n");
        assert!(out.has_errors());
        assert_eq!(out.diagnostics[0].code, "CFG_BAD_NUMBER");
    }

    #[test]
    fn unmodeled_source_options_are_preserved() {
        let out = parse("server host key 5 xleave\n");
        let s = out.config.sources().next().unwrap();
        assert_eq!(s.raw_options, vec!["key", "5", "xleave"]);
    }

    /// Witnessed against real chrony 4.5 via `tools/oracle/capture-config.sh`.
    /// Each `chrony_message()` must equal the normalized `chronyd -p` diagnostic
    /// recorded under `reports/oracle/config/`. This is the config court's
    /// promotion from "normalized" to "oracle-witnessed message text".
    #[test]
    fn diagnostics_match_witnessed_chrony_4_5_messages() {
        let cases = [
            ("frobnicate 5\n", "Fatal error : Invalid directive at line 1 in file <FILE>"),
            ("server\n", "Fatal error : Could not parse server directive at line 1 in file <FILE>"),
            ("makestep fast 3\n", "Fatal error : Could not parse makestep directive at line 1 in file <FILE>"),
            ("driftfile\n", "Fatal error : Missing arguments for driftfile directive at line 1 in file <FILE>"),
            ("rtcsync foo\n", "Fatal error : Too many arguments for rtcsync directive at line 1 in file <FILE>"),
        ];
        for (input, expected) in cases {
            let out = parse(input);
            let diag = out
                .diagnostics
                .first()
                .unwrap_or_else(|| panic!("expected a diagnostic for {input:?}"));
            assert_eq!(
                diag.chrony_message().as_deref(),
                Some(expected),
                "chrony-message mismatch for input {input:?}"
            );
        }
    }

    #[test]
    fn scalar_directives_parse_with_sscanf_semantics() {
        // Single-double directive, modeled and clean.
        let out = parse("maxupdateskew 100.0\n");
        assert!(!out.has_errors(), "{:?}", out.diagnostics);
        assert_eq!(
            out.config.directives,
            vec![(1, Directive::ScalarDouble { keyword: "maxupdateskew".into(), value: 100.0 })]
        );

        // Single-int directive.
        let out = parse("cmdport 0\n");
        assert_eq!(
            out.config.directives,
            vec![(1, Directive::ScalarInt { keyword: "cmdport".into(), value: 0 })]
        );

        // chrony's lenient sscanf: trailing junk on a double is dropped (accepted as the
        // leading number), where Rust's strict parse would have rejected it.
        let out = parse("maxdrift 2.5x\n");
        assert!(!out.has_errors());
        assert_eq!(
            out.config.directives,
            vec![(1, Directive::ScalarDouble { keyword: "maxdrift".into(), value: 2.5 })]
        );
        // ...and an int directive truncates a decimal (sscanf %d on "3.14" -> 3).
        let out = parse("minsources 3.14\n");
        assert_eq!(
            out.config.directives,
            vec![(1, Directive::ScalarInt { keyword: "minsources".into(), value: 3 })]
        );

        // A value with no leading number is a parse failure ("Could not parse").
        let out = parse("maxclockerror abc\n");
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Could not parse maxclockerror directive at line 1 in file <FILE>")
        );

        // Wrong arity distinguishes Missing vs Too many, like check_number_of_args.
        let out = parse("stratumweight\n");
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Missing arguments for stratumweight directive at line 1 in file <FILE>")
        );
        let out = parse("cmdport 1 2\n");
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Too many arguments for cmdport directive at line 1 in file <FILE>")
        );
    }

    #[test]
    fn string_uint_and_maxchange_directives() {
        // String directive: one argument, stored verbatim.
        let out = parse("pidfile /run/chronyd.pid\n");
        assert!(!out.has_errors(), "{:?}", out.diagnostics);
        assert_eq!(
            out.config.directives,
            vec![(1, Directive::ScalarString { keyword: "pidfile".into(), value: "/run/chronyd.pid".into() })]
        );
        // A string directive with a space-containing value is "too many args" in chrony
        // (no quoting), so two tokens is an arity error, not a two-word path.
        let out = parse("user chrony extra\n");
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Too many arguments for user directive at line 1 in file <FILE>")
        );

        // clientloglimit: %lu, lenient trailing junk.
        let out = parse("clientloglimit 1048576\n");
        assert_eq!(
            out.config.directives,
            vec![(1, Directive::ScalarUint { keyword: "clientloglimit".into(), value: 1048576 })]
        );

        // maxchange: all three fields parse.
        let out = parse("maxchange 1.0 30 2\n");
        assert!(!out.has_errors());
        assert_eq!(
            out.config.directives,
            vec![(1, Directive::MaxChange { threshold: 1.0, delay: 30, ignore: 2 })]
        );
        // Trailing junk on the first field makes the second sscanf conversion fail, so the
        // whole directive fails (a per-token parse would have wrongly accepted it).
        let out = parse("maxchange 1.0x 30 2\n");
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Could not parse maxchange directive at line 1 in file <FILE>")
        );
        // Wrong arity for the 3-arg form.
        let out = parse("maxchange 1.0 30\n");
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Missing arguments for maxchange directive at line 1 in file <FILE>")
        );
    }

    #[test]
    fn enum_and_log_directives() {
        // leapsecmode: case-insensitive keyword.
        assert_eq!(
            parse("leapsecmode slew\n").config.directives,
            vec![(1, Directive::LeapSecMode(LeapSecMode::Slew))]
        );
        assert_eq!(
            parse("leapsecmode IGNORE\n").config.directives,
            vec![(1, Directive::LeapSecMode(LeapSecMode::Ignore))]
        );
        // chrony matches the whole value, so an extra token never matches -> parse error.
        let out = parse("leapsecmode slew extra\n");
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Could not parse leapsecmode directive at line 1 in file <FILE>")
        );
        // Unknown keyword -> parse error.
        assert!(parse("leapsecmode bogus\n").has_errors());

        // authselectmode.
        assert_eq!(
            parse("authselectmode require\n").config.directives,
            vec![(1, Directive::AuthSelectMode(AuthSelectMode::Require))]
        );

        // log: a list of flags, in order; a bare `log` enables nothing.
        assert_eq!(
            parse("log measurements statistics tracking\n").config.directives,
            vec![(1, Directive::Log(vec![LogFlag::Measurements, LogFlag::Statistics, LogFlag::Tracking]))]
        );
        assert_eq!(parse("log\n").config.directives, vec![(1, Directive::Log(vec![]))]);
        // log flags are case-SENSITIVE (chrony uses strcmp, not strcasecmp).
        let out = parse("log Measurements\n");
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Invalid log parameter at line 1 in file <FILE>")
        );
        // An unknown flag stops parsing but keeps the flags read before it.
        let out = parse("log tracking bogus rtc\n");
        assert_eq!(
            out.config.directives,
            vec![(1, Directive::Log(vec![LogFlag::Tracking]))]
        );
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Invalid log parameter at line 1 in file <FILE>")
        );
    }

    #[test]
    fn matches_real_c_ratelimit() {
        let v = include_str!("../../../../research/oracle/config-ratelimit-c-vectors.txt");
        let line = |tag: &str| {
            v.lines()
                .find(|l| l.split_whitespace().any(|t| t == format!("tag={tag}")))
                .unwrap()
        };
        let f = |l: &str, k: &str| -> i32 {
            l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap().parse().unwrap()
        };
        // -1 in the oracle is the "unset" sentinel (no test sets a value to -1).
        let opt = |l: &str, k: &str| {
            let n = f(l, k);
            if n == -1 { None } else { Some(n) }
        };
        let cases = [
            ("BARE", "ratelimit\n"),
            ("FULL", "ratelimit interval 5 burst 10 leak 2\n"),
            ("ONE", "ratelimit interval 3\n"),
            ("REORDER", "ratelimit leak 4 interval 6\n"),
            ("CASE", "ratelimit INTERVAL 7\n"),
            ("NOVAL", "ratelimit interval\n"),
            ("BADKEY", "ratelimit frequency 5\n"),
            ("JUNKVAL", "ratelimit interval 5x burst 10\n"),
            ("NEG", "ratelimit interval -3\n"),
        ];
        for (tag, input) in cases {
            let l = line(tag);
            let out = parse(input);
            assert_eq!(out.has_errors() as i32, f(l, "err"), "{tag} err");
            let rl = out
                .config
                .directives
                .iter()
                .find_map(|(_, d)| match d {
                    Directive::RateLimit { interval, burst, leak, .. } => Some((*interval, *burst, *leak)),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{tag}: no RateLimit directive"));
            assert_eq!(rl.0, opt(l, "interval"), "{tag} interval");
            assert_eq!(rl.1, opt(l, "burst"), "{tag} burst");
            assert_eq!(rl.2, opt(l, "leak"), "{tag} leak");
        }
    }

    #[test]
    fn access_restriction_directives() {
        use crate::addrfilt::Subnet;
        use crate::cmdparse::AllowDeny;
        let v4 = |s: &str| Subnet::V4(s.parse().unwrap());

        // Bare `allow` = all addresses; keyword sets allow/cmd flags.
        assert_eq!(
            parse("allow\n").config.directives,
            vec![(1, Directive::AccessRestriction {
                allow: true, cmd: false,
                spec: AllowDeny { all: false, subnet: Subnet::Unspec, subnet_bits: 0 },
            })]
        );
        // `deny all`.
        assert_eq!(
            parse("deny all\n").config.directives,
            vec![(1, Directive::AccessRestriction {
                allow: false, cmd: false,
                spec: AllowDeny { all: true, subnet: Subnet::Unspec, subnet_bits: 0 },
            })]
        );
        // Full subnet, command table.
        assert_eq!(
            parse("cmdallow 10.0.0.0/8\n").config.directives,
            vec![(1, Directive::AccessRestriction {
                allow: true, cmd: true,
                spec: AllowDeny { all: false, subnet: v4("10.0.0.0"), subnet_bits: 8 },
            })]
        );
        // Shortened IPv4 notation (192.168 = 192.168.0.0/16), deny + command table.
        assert_eq!(
            parse("cmddeny 192.168\n").config.directives,
            vec![(1, Directive::AccessRestriction {
                allow: false, cmd: true,
                spec: AllowDeny { all: false, subnet: v4("192.168.0.0"), subnet_bits: 16 },
            })]
        );
        // Malformed spec -> command_parse_error.
        let out = parse("allow 1.2.3.4/bogus\n");
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Could not parse allow directive at line 1 in file <FILE>")
        );
    }

    #[test]
    fn initstepslew_directive() {
        // Threshold + source host strings (resolution deferred, kept verbatim).
        assert_eq!(
            parse("initstepslew 30 ntp1.example ntp2.example\n").config.directives,
            vec![(1, Directive::InitStepSlew {
                threshold: 30.0,
                sources: vec!["ntp1.example".into(), "ntp2.example".into()],
            })]
        );
        // Threshold only, no sources.
        assert_eq!(
            parse("initstepslew 5.5\n").config.directives,
            vec![(1, Directive::InitStepSlew { threshold: 5.5, sources: vec![] })]
        );
        // No threshold -> parse error.
        let out = parse("initstepslew\n");
        assert_eq!(
            out.diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Could not parse initstepslew directive at line 1 in file <FILE>")
        );
        // Non-numeric threshold -> parse error.
        assert!(parse("initstepslew foo ntp1\n").has_errors());
    }

    #[test]
    fn fallbackdrift_and_smoothtime_directives() {
        // fallbackdrift: two ints.
        assert_eq!(
            parse("fallbackdrift 16 19\n").config.directives,
            vec![(1, Directive::FallbackDrift { min: 16, max: 19 })]
        );
        // Wrong arity (only 1) -> Missing.
        assert_eq!(
            parse("fallbackdrift 16\n").diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Missing arguments for fallbackdrift directive at line 1 in file <FILE>")
        );

        // smoothtime: two doubles, no flag.
        assert_eq!(
            parse("smoothtime 400 0.001\n").config.directives,
            vec![(1, Directive::SmoothTime { max_freq: 400.0, max_wander: 0.001, leap_only: false })]
        );
        // ...with the optional leaponly flag (case-insensitive).
        assert_eq!(
            parse("smoothtime 400 0.001 LeapOnly\n").config.directives,
            vec![(1, Directive::SmoothTime { max_freq: 400.0, max_wander: 0.001, leap_only: true })]
        );
        // A bad 3rd token (not leaponly) -> parse error.
        assert_eq!(
            parse("smoothtime 400 0.001 bogus\n").diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Could not parse smoothtime directive at line 1 in file <FILE>")
        );
        // Too few args -> Missing; too many -> Too many.
        assert_eq!(
            parse("smoothtime 400\n").diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Missing arguments for smoothtime directive at line 1 in file <FILE>")
        );
        assert_eq!(
            parse("smoothtime 400 0.001 leaponly extra\n").diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Too many arguments for smoothtime directive at line 1 in file <FILE>")
        );
    }

    #[test]
    fn local_dir_and_include_directives() {
        use crate::cmdparse::LocalOpts;
        // local: options via the ported CPS_ParseLocal (defaults when bare).
        assert_eq!(
            parse("local\n").config.directives,
            vec![(1, Directive::Local(LocalOpts { stratum: 10, orphan: false, distance: 1.0 }))]
        );
        assert_eq!(
            parse("local stratum 5 orphan distance 0.5\n").config.directives,
            vec![(1, Directive::Local(LocalOpts { stratum: 5, orphan: true, distance: 0.5 }))]
        );
        // Malformed local option -> parse error.
        assert!(parse("local stratum 99\n").has_errors()); // stratum >= NTP_MAX_STRATUM

        // sourcedir: the rest of the line, verbatim, no arity check.
        assert_eq!(
            parse("sourcedir /etc/chrony/sources.d\n").config.directives,
            vec![(1, Directive::SourceDir { path: "/etc/chrony/sources.d".into() })]
        );

        // confdir: 1..=10 directories.
        assert_eq!(
            parse("confdir /etc/chrony/conf.d /run/chrony.d\n").config.directives,
            vec![(1, Directive::ConfDir { dirs: vec!["/etc/chrony/conf.d".into(), "/run/chrony.d".into()] })]
        );
        // Empty confdir -> parse error.
        assert!(parse("confdir\n").has_errors());

        // include: one glob pattern.
        assert_eq!(
            parse("include /etc/chrony/conf.d/*.conf\n").config.directives,
            vec![(1, Directive::Include { pattern: "/etc/chrony/conf.d/*.conf".into() })]
        );
        // Wrong arity -> Too many.
        assert_eq!(
            parse("include a b\n").diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Too many arguments for include directive at line 1 in file <FILE>")
        );
    }

    #[test]
    fn broadcast_and_mailonchange_directives() {
        // broadcast: interval + address, default port 123.
        assert_eq!(
            parse("broadcast 60 192.168.1.255\n").config.directives,
            vec![(1, Directive::Broadcast { interval: 60, address: "192.168.1.255".into(), port: 123 })]
        );
        // ...with an explicit port.
        assert_eq!(
            parse("broadcast 60 192.168.1.255 1123\n").config.directives,
            vec![(1, Directive::Broadcast { interval: 60, address: "192.168.1.255".into(), port: 1123 })]
        );
        // Unparseable address -> error.
        assert!(parse("broadcast 60 not-an-ip\n").has_errors());
        // A 4th word -> error.
        assert!(parse("broadcast 60 192.168.1.255 1123 extra\n").has_errors());
        // Missing address -> error.
        assert!(parse("broadcast 60\n").has_errors());

        // mailonchange: address + threshold.
        assert_eq!(
            parse("mailonchange root@localhost 0.5\n").config.directives,
            vec![(1, Directive::MailOnChange { address: "root@localhost".into(), threshold: 0.5 })]
        );
        // Wrong arity -> Missing/Too many.
        assert_eq!(
            parse("mailonchange root@localhost\n").diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Missing arguments for mailonchange directive at line 1 in file <FILE>")
        );
        // Non-numeric threshold -> Could not parse.
        assert_eq!(
            parse("mailonchange root@localhost soon\n").diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Could not parse mailonchange directive at line 1 in file <FILE>")
        );
    }

    #[test]
    fn tempcomp_both_forms() {
        use crate::config::model::TempCompCurve;
        // 3-arg points-file form.
        assert_eq!(
            parse("tempcomp /sys/temp 30 /etc/chrony/comp.points\n").config.directives,
            vec![(1, Directive::TempComp {
                sensor_file: "/sys/temp".into(),
                interval: 30.0,
                curve: TempCompCurve::PointFile("/etc/chrony/comp.points".into()),
            })]
        );
        // 6-arg coefficient form (the five doubles via one sscanf).
        assert_eq!(
            parse("tempcomp /sys/temp 30 20.0 1.0 0.1 0.01\n").config.directives,
            vec![(1, Directive::TempComp {
                sensor_file: "/sys/temp".into(),
                interval: 30.0,
                curve: TempCompCurve::Coefficients { t0: 20.0, k0: 1.0, k1: 0.1, k2: 0.01 },
            })]
        );
        // Junk on a non-final coefficient fails the whole sscanf.
        assert_eq!(
            parse("tempcomp /sys/temp 30 20.0 1.0x 0.1 0.01\n").diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Could not parse tempcomp directive at line 1 in file <FILE>")
        );
        // Wrong arity: 4 or 5 args is neither the 3-arg nor 6-arg form -> Missing; >6 -> Too many.
        assert_eq!(
            parse("tempcomp /sys/temp 30 20.0 1.0\n").diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Missing arguments for tempcomp directive at line 1 in file <FILE>")
        );
        assert_eq!(
            parse("tempcomp /sys/temp 30 20.0 1.0 0.1 0.01 extra\n").diagnostics.first().and_then(|d| d.chrony_message()).as_deref(),
            Some("Fatal error : Too many arguments for tempcomp directive at line 1 in file <FILE>")
        );
    }
}
