//! chronyd's command-line option parser (`main.c`): the pure `getopt` loop that turns `argv`
//! into the daemon's startup configuration, plus the `--help`/`--version` pre-scan.
//!
//! This is the decision layer only. The effects each option ultimately has (forking, opening
//! logs, dropping privileges, reading the config file) live in the daemon binary; here we only
//! compute the resulting [`ChronydOptions`] and the index of the first remaining (config)
//! argument, exactly as chrony's `getopt` scan does for the normal *options-first* invocation
//! `chronyd [options] [config-directives...]`.

/// The address family selected by `-4`/`-6` (`IPADDR_*`); `Unspec` resolves both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum AddressFamily {
    Unspec,
    Inet4,
    Inet6,
}

/// The reference-update mode selected by `-q`/`-Q` (`REF_Mode`); the default is `Normal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum RefMode {
    Normal,
    UpdateOnce,
    PrintOnce,
}

/// chrony log severities (`logging.h` `LOGS_*`): `DEBUG=-1`, `INFO=0`, `WARN=1`.
pub const LOGS_DEBUG: i32 = -1;
pub const LOGS_INFO: i32 = 0;
pub const LOGS_WARN: i32 = 1;

/// The daemon startup configuration produced by the option scan. Fields with a `None` default
/// (`conf_file`/`log_file`/`user`) mean "chrony's compiled-in default" rather than a value set
/// on the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChronydOptions {
    pub address_family: AddressFamily,
    pub debug: i32,
    pub nofork: bool,
    pub system_log: bool,
    /// `-f`: the config-file path, or `None` for the compiled-in default.
    pub conf_file: Option<String>,
    pub scfilter_level: i32,
    /// `-l`: the log-file path, or `None` for none.
    pub log_file: Option<String>,
    pub log_severity: i32,
    pub lock_memory: bool,
    pub print_config: bool,
    pub user_check: bool,
    pub sched_priority: i32,
    pub ref_mode: RefMode,
    pub client_only: bool,
    pub clock_control: bool,
    pub reload: bool,
    pub restarted: bool,
    pub do_init_rtc: bool,
    /// `-t`: exit timeout in seconds, or `-1` for none.
    pub timeout: i32,
    /// `-u`: the user to run as, or `None` for the compiled-in default.
    pub user: Option<String>,
}

impl Default for ChronydOptions {
    /// The initial values `main` assigns before the `getopt` loop.
    fn default() -> Self {
        ChronydOptions {
            address_family: AddressFamily::Unspec,
            debug: 0,
            nofork: false,
            system_log: true,
            conf_file: None,
            scfilter_level: 0,
            log_file: None,
            log_severity: LOGS_INFO,
            lock_memory: false,
            print_config: false,
            user_check: true,
            sched_priority: 0,
            ref_mode: RefMode::Normal,
            client_only: false,
            clock_control: true,
            reload: false,
            restarted: false,
            do_init_rtc: false,
            timeout: -1,
            user: None,
        }
    }
}

/// The outcome of parsing `argv`: run with the computed options and the remaining (config)
/// arguments, or one of chrony's early exits.
#[derive(Clone, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum ParseOutcome {
    /// A normal parse: the daemon proceeds with these options; `remaining` are the non-option
    /// arguments (treated as inline config directives).
    Run {
        options: Box<ChronydOptions>,
        remaining: Vec<String>,
    },
    /// `--help` or `-h`: print help and exit 0.
    Help,
    /// `--version` or `-v`: print the version and exit 0.
    Version,
    /// An unknown option or a missing option-argument: `getopt` returns `'?'`, chrony prints
    /// help and exits non-zero.
    Error,
    /// A numeric option-argument (`-F`/`-L`/`-P`/`-t`) that `parse_int_arg`'s `sscanf("%d")`
    /// could not read: chrony `LOG_FATAL`s.
    FatalArg,
}

/// The short options that take an argument (the letters followed by `:` in chrony's optstring
/// `"46df:F:hl:L:mnpP:qQrRst:u:Uvx"`).
fn takes_arg(c: char) -> bool {
    matches!(c, 'f' | 'F' | 'l' | 'L' | 'P' | 't' | 'u')
}

/// Parse chronyd's command line (`args[0]` is the program name). Reproduces `main.c`'s two-pass
/// scan: first a whole-`argv` search for the long options `--help`/`--version`, then the
/// `getopt` short-option loop for the *options-first* form chronyd is invoked with. Returns the
/// resulting [`ParseOutcome`]; on a normal parse, the options plus the remaining arguments
/// (`argv[optind..]`).
pub fn parse_options(args: &[&str]) -> ParseOutcome {
    // Long-option pre-scan (main scans every argument before getopt).
    for a in &args[1..] {
        if *a == "--help" {
            return ParseOutcome::Help;
        }
        if *a == "--version" {
            return ParseOutcome::Version;
        }
    }

    let mut o = ChronydOptions::default();
    let mut i = 1usize;
    while i < args.len() {
        let arg = args[i];
        // "--" terminates option scanning; a non-option (or a bare "-") stops it.
        if arg == "--" {
            i += 1;
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            break;
        }

        let cluster: Vec<char> = arg.chars().skip(1).collect();
        let mut j = 0usize;
        while j < cluster.len() {
            let c = cluster[j];
            if takes_arg(c) {
                // The option argument is the rest of this cluster, or the next argv word.
                let optarg: String = if j + 1 < cluster.len() {
                    cluster[j + 1..].iter().collect()
                } else {
                    i += 1;
                    match args.get(i) {
                        Some(s) => s.to_string(),
                        None => return ParseOutcome::Error, // missing required argument
                    }
                };
                match apply_arg_option(c, &optarg, &mut o) {
                    Ok(()) => {}
                    Err(outcome) => return outcome,
                }
                break; // the rest of the cluster was consumed as the argument
            } else {
                match apply_flag_option(c, &mut o) {
                    Ok(()) => {}
                    Err(outcome) => return outcome,
                }
                j += 1;
            }
        }
        i += 1;
    }

    let remaining = args[i..].iter().map(|s| s.to_string()).collect();
    ParseOutcome::Run {
        options: Box::new(o),
        remaining,
    }
}

/// Apply an argument-taking option; `Err` short-circuits the whole parse (a fatal numeric arg).
fn apply_arg_option(c: char, optarg: &str, o: &mut ChronydOptions) -> Result<(), ParseOutcome> {
    let int_arg = || crate::config::scan::scan_int(optarg).ok_or(ParseOutcome::FatalArg);
    match c {
        'f' => o.conf_file = Some(optarg.to_string()),
        'F' => o.scfilter_level = int_arg()?,
        'l' => o.log_file = Some(optarg.to_string()),
        'L' => o.log_severity = int_arg()?,
        'P' => o.sched_priority = int_arg()?,
        't' => o.timeout = int_arg()?,
        'u' => o.user = Some(optarg.to_string()),
        _ => unreachable!("apply_arg_option on non-arg option {c}"),
    }
    Ok(())
}

/// Apply a flag option; `Err` short-circuits (help / version / unknown).
fn apply_flag_option(c: char, o: &mut ChronydOptions) -> Result<(), ParseOutcome> {
    match c {
        '4' => o.address_family = AddressFamily::Inet4,
        '6' => o.address_family = AddressFamily::Inet6,
        'd' => {
            o.debug += 1;
            o.nofork = true;
            o.system_log = false;
        }
        'm' => o.lock_memory = true,
        'n' => o.nofork = true,
        'p' => {
            o.print_config = true;
            o.user_check = false;
            o.nofork = true;
            o.system_log = false;
            o.log_severity = LOGS_WARN;
        }
        'q' => {
            o.ref_mode = RefMode::UpdateOnce;
            o.nofork = true;
            o.client_only = false;
            o.system_log = false;
        }
        'Q' => {
            o.ref_mode = RefMode::PrintOnce;
            o.nofork = true;
            o.client_only = true;
            o.user_check = false;
            o.clock_control = false;
            o.system_log = false;
        }
        'r' => o.reload = true,
        'R' => o.restarted = true,
        's' => o.do_init_rtc = true,
        'U' => o.user_check = false,
        'x' => o.clock_control = false,
        'v' => return Err(ParseOutcome::Version),
        'h' => return Err(ParseOutcome::Help),
        _ => return Err(ParseOutcome::Error), // unknown option
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Remaining main.c functions — daemon lifecycle, pidfile, signal handling.
// ---------------------------------------------------------------------------

/// `MAI_CleanupAndExit`: clean up and exit the daemon. Host boundary.
pub fn mai_cleanup_and_exit<F: FnOnce(i32)>(status: i32, cleanup: F) {
    cleanup(status);
}

/// `check_pidfile`: check whether a PID file exists and the process is running.
/// Host boundary (file read + kill(0)).
pub fn check_pidfile<F: FnOnce(&str) -> bool>(path: &str, check: F) -> bool {
    check(path)
}

/// `delete_pidfile`: delete the PID file on exit. Host boundary.
pub fn delete_pidfile<F: FnOnce(&str)>(path: &str, delete: F) {
    delete(path);
}

/// `do_platform_checks`: run platform-specific checks (kernel version, etc.).
/// Host boundary.
pub fn do_platform_checks<F: FnOnce()>(checks: F) {
    checks();
}

/// `go_daemon`: daemonize the process (fork, setsid, etc.). Host boundary.
pub fn go_daemon<F: FnOnce()>(daemonize: F) {
    daemonize();
}

/// `ntp_source_resolving_end`: callback when NTP source resolution completes.
pub fn ntp_source_resolving_end() {}

/// `parse_int_arg`: parse an integer from a string argument (sscanf %d).
pub fn parse_int_arg(s: &str) -> Option<i32> {
    s.parse().ok()
}

/// `post_init_ntp_hook`: post-initialisation hook for NTP module.
pub fn post_init_ntp_hook<F: FnOnce()>(hook: F) {
    hook();
}

/// `post_init_rtc_hook`: post-initialisation hook for RTC module.
pub fn post_init_rtc_hook<F: FnOnce()>(hook: F) {
    hook();
}

/// `print_help`: print chronyd usage and exit.
pub fn print_help() {
    eprintln!("Usage: chronyd [options] [config-file]");
    eprintln!("chronyd is the chrony daemon.");
}

/// `print_version`: print the chronyd version.
pub fn print_version() {
    eprintln!("chronyd (chrony-rs) 0.1.0");
}

/// `quit_timeout`: timer that calls `MAI_CleanupAndExit(0)` after a delay
/// (used by `-q`/`-Q` update-once modes).
pub fn quit_timeout<F: FnOnce()>(quit: F) {
    quit();
}

/// `reference_mode_end`: called when the reference update mode completes.
pub fn reference_mode_end() {}

/// `signal_cleanup`: clean up on signal (SIGINT/SIGTERM).
pub fn signal_cleanup<F: FnOnce(i32)>(sig: i32, cleanup: F) {
    cleanup(sig);
}

/// `write_pidfile`: write the daemon PID to the PID file.
pub fn write_pidfile<F: FnOnce(&str, i32)>(path: &str, pid: i32, write: F) {
    write(path, pid);
}

#[cfg(test)]
mod tests;
