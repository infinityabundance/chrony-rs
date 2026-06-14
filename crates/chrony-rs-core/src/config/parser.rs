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
use super::model::{Config, Directive, ServerKind, SourceDirective};

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
}
