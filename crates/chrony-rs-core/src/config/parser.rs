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
/// **Oracle-anchored to chrony 4.5.** Every entry was verified to be recognized
/// by `chronyd -p` via `tools/oracle/directive-recognition.sh`; the witnessed
/// count is pinned by a test below. The oracle previously caught five *fabricated*
/// entries here (guessed NTS names + a nonexistent `open_commands`/`ntpcache`),
/// which is exactly why the set is measured, not guessed. Adding a keyword is a
/// version-anchored change tied to `docs/version-lineage.md` and must be
/// re-witnessed.
const KNOWN_DIRECTIVES: &[&str] = &[
    "acquisitionport", "allow", "authselectmode", "bindacqaddress", "bindaddress", "bindcmdaddress",
    "broadcast", "clientloglimit", "cmdallow", "cmddeny", "cmdport", "cmdratelimit",
    "combinelimit", "confdir", "corrtimeratio", "deny", "driftfile", "dscp",
    "dumpdir", "dumponexit", "fallbackdrift", "hwclockfile", "hwtimestamp", "include",
    "initstepslew", "keyfile", "leapsecmode", "leapsectz", "local", "lock_all",
    "log", "logbanner", "logchange", "logdir", "mailonchange", "makestep",
    "manual", "maxchange", "maxclockerror", "maxdistance", "maxdrift", "maxjitter",
    "maxntsconnections", "maxsamples", "maxslewrate", "maxupdateskew", "minsamples", "minsources",
    "nocerttimecheck", "noclientlog", "ntpsigndsocket", "ntscachedir", "ntsdumpdir", "ntsntpserver",
    "ntsport", "ntsprocesses", "ntsratelimit", "ntsrefresh", "ntsrotate", "ntsservercert",
    "ntsserverkey", "ntstrustedcerts", "peer", "pidfile", "pool", "port",
    "ratelimit", "refclock", "refresh", "reselectdist", "rtcautotrim", "rtcdevice",
    "rtcfile", "rtconutc", "rtcsync", "sched_priority", "server", "smoothtime",
    "sourcedir", "stratumweight", "tempcomp", "user",
];

fn is_known_directive(keyword: &str) -> bool {
    KNOWN_DIRECTIVES.contains(&keyword)
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

    // chrony options are a flat list of flags and key/value pairs after the
    // address. We model the common, well-understood ones and preserve the rest.
    while let Some(opt) = iter.next() {
        match opt.as_str() {
            "iburst" => src.iburst = true,
            "burst" => src.burst = true,
            "minpoll" => parse_poll_opt(line_no, "minpoll", &mut iter, &mut src.minpoll, out),
            "maxpoll" => parse_poll_opt(line_no, "maxpoll", &mut iter, &mut src.maxpoll, out),
            _ => src.raw_options.push(opt),
        }
    }

    out.config.directives.push((line_no, Directive::Source(src)));
}

fn parse_poll_opt(
    line_no: usize,
    name: &str,
    iter: &mut std::vec::IntoIter<String>,
    slot: &mut Option<i32>,
    out: &mut ParseOutput,
) {
    match iter.next() {
        Some(v) => match v.parse::<i32>() {
            Ok(n) => *slot = Some(n),
            Err(_) => out.diagnostics.push(Diagnostic::error(
                line_no,
                "CFG_BAD_NUMBER",
                format!("{name} expects an integer, found '{v}'"),
            )),
        },
        None => out.diagnostics.push(Diagnostic::error(
            line_no,
            "CFG_MISSING_VALUE",
            format!("{name} requires a value"),
        )),
    }
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
        assert_eq!(KNOWN_DIRECTIVES.len(), 82, "witnessed chrony 4.5 directive count");
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
