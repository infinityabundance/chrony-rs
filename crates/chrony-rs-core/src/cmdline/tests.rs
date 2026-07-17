//! Differential tests for chronyd's option parser vs the REAL `getopt` loop
//! (`/tmp/nopt/genopts.c`, `research/oracle/chronyd-getopt-c-vectors.txt`).

use super::*;

/// The argv for each fixture id (mirroring the C oracle's `C(id, ...)` cases). `args[0]` is the
/// program name, as in `main`.
fn argv_for(id: &str) -> Vec<&'static str> {
    let rest: Vec<&str> = match id {
        "none" => vec![],
        "d" => vec!["-d"],
        "dd" => vec!["-d", "-d"],
        "cluster" => vec!["-dn"],
        "f_sep" => vec!["-f", "/etc/chrony.conf"],
        "f_attached" => vec!["-f/etc/chrony.conf"],
        "F" => vec!["-F", "1"],
        "L" => vec!["-L", "-1"],
        "p" => vec!["-p"],
        "q" => vec!["-q"],
        "Q" => vec!["-Q"],
        "x" => vec!["-x"],
        "u" => vec!["-u", "chrony"],
        "t" => vec!["-t", "30"],
        "many" => vec!["-4", "-d", "-m", "-r", "-R", "-s", "-U", "-P", "5"],
        "46combo" => vec!["-6"],
        "help_long" => vec!["--help"],
        "version_long" => vec!["--version"],
        "v" => vec!["-v"],
        "h" => vec!["-h"],
        "unknown" => vec!["-z"],
        "dashdash" => vec!["--", "extra"],
        "configargs" => vec!["-d", "server", "pool.ntp.org"],
        "attached_L" => vec!["-L2"],
        "q_and_conf" => vec!["-q", "server 1.2.3.4 iburst"],
        other => panic!("unknown case {other}"),
    };
    let mut v = vec!["chronyd"];
    v.extend(rest);
    v
}

fn field<'a>(l: &'a str, k: &str) -> &'a str {
    l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap()
}

#[test]
fn parse_options_matches_real_getopt() {
    let v = include_str!("../../../../research/oracle/chronyd-getopt-c-vectors.txt");
    for l in v.lines().filter(|l| l.starts_with("OPT ")) {
        let id = field(l, "id");
        let argv = argv_for(id);
        let got = parse_options(&argv);
        let action: i32 = field(l, "action").parse().unwrap();

        match action {
            1 => {
                assert_eq!(got, ParseOutcome::Help, "{id}");
                continue;
            }
            2 => {
                assert_eq!(got, ParseOutcome::Version, "{id}");
                continue;
            }
            3 => {
                assert_eq!(got, ParseOutcome::Error, "{id}");
                continue;
            }
            4 => {
                assert_eq!(got, ParseOutcome::FatalArg, "{id}");
                continue;
            }
            _ => {}
        }

        let (options, remaining) = match got {
            ParseOutcome::Run { options, remaining } => (options, remaining),
            other => panic!("{id}: expected Run, got {other:?}"),
        };

        let af = match field(l, "af") {
            "0" => AddressFamily::Unspec,
            "1" => AddressFamily::Inet4,
            "2" => AddressFamily::Inet6,
            x => panic!("af {x}"),
        };
        let refmode = match field(l, "refmode") {
            "0" => RefMode::Normal,
            "2" => RefMode::UpdateOnce,
            "3" => RefMode::PrintOnce,
            x => panic!("refmode {x}"),
        };
        let conf_file = match field(l, "conffile") {
            "DEFAULT" => None,
            p => Some(p.to_string()),
        };
        let log_file = match field(l, "logfile") {
            "NULL" => None,
            p => Some(p.to_string()),
        };
        let user = match field(l, "user") {
            "NULL" => None,
            p => Some(p.to_string()),
        };
        let b = |k: &str| field(l, k) == "1";

        let expected = ChronydOptions {
            address_family: af,
            debug: field(l, "debug").parse().unwrap(),
            nofork: b("nofork"),
            system_log: b("syslog"),
            conf_file,
            scfilter_level: field(l, "scf").parse().unwrap(),
            log_file,
            log_severity: field(l, "logsev").parse().unwrap(),
            lock_memory: b("lockmem"),
            print_config: b("printcfg"),
            user_check: b("usercheck"),
            sched_priority: field(l, "schedprio").parse().unwrap(),
            ref_mode: refmode,
            client_only: b("clientonly"),
            clock_control: b("clockctl"),
            reload: b("reload"),
            restarted: b("restarted"),
            do_init_rtc: b("initrtc"),
            timeout: field(l, "timeout").parse().unwrap(),
            user,
        };
        assert_eq!(*options, expected, "{id} options");

        // Remaining args: the oracle comma-joins them at the END of the line (an individual arg
        // may itself contain spaces, so take everything after "remaining=" to end-of-line).
        let rem = l.split("remaining=").nth(1).unwrap();
        let exp_remaining: Vec<String> = if rem.is_empty() {
            vec![]
        } else {
            rem.split(',').map(|s| s.to_string()).collect()
        };
        assert_eq!(remaining, exp_remaining, "{id} remaining");
    }
}

#[test]
fn defaults_match_main_initialisers() {
    let d = ChronydOptions::default();
    assert_eq!(d.address_family, AddressFamily::Unspec);
    assert_eq!(d.log_severity, LOGS_INFO);
    assert_eq!(d.timeout, -1);
    assert!(d.system_log && d.user_check && d.clock_control);
    assert!(!d.nofork && !d.client_only);
    assert_eq!(d.ref_mode, RefMode::Normal);
}
