//! Differential tests for the `CNF_Get*` accessor port.
//!
//! The expected values come from `research/oracle/conf-accessors-c-vectors.txt`, which is the
//! output of the real chrony `conf.c` `CNF_ParseLine` + `CNF_GetX` pipeline (see that file's
//! header). Each scenario's *input* config lines are embedded here; the *expected* values are
//! read from the oracle, so nothing is hand-transcribed.

use super::*;
use crate::config::parse;
use std::collections::HashMap;

const VECTORS: &str = include_str!("../../../../../research/oracle/conf-accessors-c-vectors.txt");

/// Parse the oracle file into `tag -> { key -> value }`. Each scenario is delimited by
/// `SCEN <tag>` .. `END <tag>`; body lines are whitespace-separated `key=value` pairs.
fn load() -> HashMap<String, HashMap<String, String>> {
    let mut out: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut cur: Option<String> = None;
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(tag) = line.strip_prefix("SCEN ") {
            cur = Some(tag.to_string());
            out.entry(tag.to_string()).or_default();
        } else if line.starts_with("END ") {
            cur = None;
        } else if let Some(tag) = &cur {
            let m = out.get_mut(tag).unwrap();
            for pair in line.split_whitespace() {
                if let Some((k, val)) = pair.split_once('=') {
                    m.insert(k.to_string(), val.to_string());
                }
            }
        }
    }
    out
}

/// Build a `tag -> { key -> value }` map from a resolved [`ConfigValues`], using the exact
/// same keys and formatting the C oracle's `dump()` emits, so the two are directly comparable.
fn dump(v: &ConfigValues) -> HashMap<String, String> {
    fn g17(x: f64) -> String {
        // The oracle prints %.17g; format!("{:.17e}") differs textually, so compare numerically
        // instead (see `check`). Here we just store the f64's shortest round-trip and re-parse.
        format!("{x:?}")
    }
    fn b(x: bool) -> String {
        (if x { 1 } else { 0 }).to_string()
    }
    fn s(x: Option<&str>) -> String {
        x.unwrap_or("(null)").to_string()
    }
    let mut m = HashMap::new();
    let mut put = |k: &str, val: String| {
        m.insert(k.to_string(), val);
    };
    put("ntpport", v.ntp_port().to_string());
    put("acqport", v.acquisition_port().to_string());
    put("cmdport", v.command_port().to_string());
    put("ptpport", v.ptp_port().to_string());
    put("dscp", v.ntp_dscp().to_string());
    put("logbanner", v.log_banner().to_string());
    put("manual", b(v.manual_enabled()));
    put("rtconutc", b(v.rtc_on_utc()));
    put("rtcsync", b(v.rtc_sync()));
    put("noclientlog", b(v.no_client_log()));
    put("schedprio", v.sched_priority().to_string());
    put("lockmem", b(v.lock_memory()));
    put("maxsamples", v.max_samples().to_string());
    put("minsamples", v.min_samples().to_string());
    put("minsources", v.min_sources().to_string());
    put("refresh", v.refresh().to_string());
    put("ntsport", v.nts_server_port().to_string());
    put("ntsproc", v.nts_server_processes().to_string());
    put("ntsconn", v.nts_server_connections().to_string());
    put("ntsrefresh", v.nts_refresh().to_string());
    put("ntsrotate", v.nts_rotate().to_string());
    put("nosystemcert", b(v.no_system_cert()));
    put("nocerttimecheck", v.no_cert_time_check().to_string());
    put("clientloglimit", v.client_log_limit().to_string());
    put("maxupdateskew", g17(v.max_update_skew()));
    put("maxdrift", g17(v.max_drift()));
    put("maxclockerror", g17(v.max_clock_error()));
    put("corrtimeratio", g17(v.correction_time_ratio()));
    put("maxslewrate", g17(v.max_slew_rate()));
    put("clockprecision", g17(v.clock_precision()));
    put("maxdistance", g17(v.max_distance()));
    put("maxjitter", g17(v.max_jitter()));
    put("reselectdist", g17(v.reselect_distance()));
    put("stratumweight", g17(v.stratum_weight()));
    put("combinelimit", g17(v.combine_limit()));
    put("rtcautotrim", g17(v.rtc_autotrim()));
    put("logchange", g17(v.log_change()));
    put("initstepthr", g17(v.init_step_threshold()));
    put("hwtstimeout", g17(v.hwts_timeout()));
    put("authselect", (v.auth_select_mode() as i32).to_string());
    put("leapsecmode", (v.leap_sec_mode() as i32).to_string());
    put("driftfile", s(v.drift_file()));
    put("logdir", s(v.log_dir()));
    put("dumpdir", s(v.dump_dir()));
    put("keysfile", s(v.keys_file()));
    put("rtcfile", s(v.rtc_file()));
    put("rtcdevice", s(v.rtc_device()));
    put("hwclockfile", s(v.hwclock_file()));
    put("pidfile", s(v.pid_file()));
    put("leapsectz", s(v.leap_sec_timezone()));
    put("ntpsignd", s(v.ntp_signd_socket()));
    put("user", s(v.user()));
    put("ntsdumpdir", s(v.nts_dump_dir()));
    put("ntsntpserver", s(v.nts_ntp_server()));
    put("bindntpif", s(v.bind_ntp_interface()));
    put("bindacqif", s(v.bind_acquisition_interface()));
    put("bindcmdif", s(v.bind_command_interface()));
    put("bindcmdpath", s(v.bind_command_path()));
    let (limit, thr) = v.make_step();
    put("makestep_limit", limit.to_string());
    put("makestep_thr", g17(thr));
    let (delay, ignore, off) = v.max_change();
    put("maxchange_delay", delay.to_string());
    put("maxchange_ignore", ignore.to_string());
    put("maxchange_off", g17(off));
    let (mn, mx) = v.fallback_drifts();
    put("fbdrift_min", mn.to_string());
    put("fbdrift_max", mx.to_string());
    let (mf, mw, lo) = v.smooth();
    put("smooth_maxfreq", g17(mf));
    put("smooth_maxwander", g17(mw));
    put("smooth_leaponly", b(lo));
    let (men, mthr, muser) = v.mail_on_change();
    put("mail_enabled", b(men));
    put("mail_thr", g17(mthr));
    put("mail_user", s(muser));
    let (lm, raw) = v.log_measurements();
    put("logmeas", b(lm));
    put("raw", b(raw));
    put("logsel", b(v.log_selection()));
    put("logstat", b(v.log_statistics()));
    put("logtrk", b(v.log_tracking()));
    put("logrtc", b(v.log_rtc()));
    put("logrefc", b(v.log_refclocks()));
    put("logtmp", b(v.log_temp_comp()));
    let n = v.ntp_rate_limit();
    put("ntprl_en", b(n.enabled));
    put("ntprl_iv", n.interval.to_string());
    put("ntprl_bu", n.burst.to_string());
    put("ntprl_lk", n.leak.to_string());
    let n = v.nts_rate_limit();
    put("ntsrl_en", b(n.enabled));
    put("ntsrl_iv", n.interval.to_string());
    put("ntsrl_bu", n.burst.to_string());
    put("ntsrl_lk", n.leak.to_string());
    let c = v.command_rate_limit();
    put("cmdrl_en", b(c.enabled));
    put("cmdrl_iv", c.interval.to_string());
    put("cmdrl_bu", c.burst.to_string());
    put("cmdrl_lk", c.leak.to_string());
    m
}

/// Numeric keys whose textual form differs between Rust `{:?}` and C `%.17g` but which
/// round-trip to the same `f64`; compared by value, not string.
fn is_float_key(k: &str) -> bool {
    matches!(
        k,
        "maxupdateskew" | "maxdrift" | "maxclockerror" | "corrtimeratio" | "maxslewrate"
            | "clockprecision" | "maxdistance" | "maxjitter" | "reselectdist" | "stratumweight"
            | "combinelimit" | "rtcautotrim" | "logchange" | "initstepthr" | "hwtstimeout"
            | "makestep_thr" | "maxchange_off" | "smooth_maxfreq" | "smooth_maxwander"
            | "mail_thr"
    )
}

/// Compare every oracle key for one scenario against the resolved values.
fn check(tag: &str, cfg_lines: &str) {
    let vectors = load();
    let expected = vectors
        .get(tag)
        .unwrap_or_else(|| panic!("scenario {tag} missing from oracle vectors"));
    let cfg = parse(cfg_lines).config;
    let values = ConfigValues::resolve(&cfg);
    let got = dump(&values);

    for (k, exp) in expected {
        let actual = got
            .get(k)
            .unwrap_or_else(|| panic!("[{tag}] key {k} not produced by the Rust accessor dump"));
        if is_float_key(k) {
            let ef: f64 = exp.parse().unwrap_or_else(|_| panic!("[{tag}] bad float {k}={exp}"));
            let af: f64 = actual.parse().unwrap();
            assert_eq!(
                af, ef,
                "[{tag}] float accessor {k}: rust={af:?} oracle={ef:?}"
            );
        } else {
            assert_eq!(actual, exp, "[{tag}] accessor {k}: rust={actual} oracle={exp}");
        }
    }
}

#[test]
fn defaults_match_chrony() {
    check("DEFAULTS", "");
}

#[test]
fn client_only_forces_ports_and_paths_off() {
    check("CLIENT_ONLY", "");
}

#[test]
fn broad_override_matches_chrony() {
    let lines = "\
port 1123
acquisitionport 1234
cmdport 0
ptpport 319
dscp 46
logbanner 10
manual
rtconutc
rtcsync
noclientlog
sched_priority 50
lock_all
maxsamples 12
minsamples 3
minsources 2
refresh 600
ntsport 5000
ntsprocesses 4
maxntsconnections 50
ntsrefresh 100
ntsrotate 200
nosystemcert
nocerttimecheck 5
clientloglimit 1048576
maxupdateskew 5.5
maxdrift 100.0
maxclockerror 2.0
corrtimeratio 1.5
maxslewrate 83333.0
clockprecision 1e-6
maxdistance 6.0
maxjitter 0.2
reselectdist 1e-3
stratumweight 0.5
combinelimit 4.0
rtcautotrim 30.0
logchange 0.5
hwtstimeout 0.01
authselectmode require
leapsecmode slew
driftfile /var/lib/chrony/drift
logdir /var/log/chrony
dumpdir /var/lib/chrony
keyfile /etc/chrony.keys
rtcfile /var/lib/chrony/rtc
rtcdevice /dev/rtc1
hwclockfile /etc/adjtime
pidfile /run/chronyd.pid
leapsectz right/UTC
ntpsigndsocket /var/run/samba/ntp_signd/socket
user chrony
ntsdumpdir /var/lib/chrony/nts
ntsntpserver ntp.example.com
binddevice eth0
bindacqdevice eth1
bindcmddevice lo
makestep 0.1 3
maxchange 1000 1 2
fallbackdrift 10 16
smoothtime 400 0.01 leaponly
mailonchange root@localhost 0.5
log measurements statistics tracking rtc refclocks tempcomp selection rawmeasurements
ratelimit interval 4 burst 16 leak 3
ntsratelimit interval 5 burst 12 leak 1
cmdratelimit interval -2 burst 4 leak 2
initstepslew 30
";
    check("OVERRIDE", lines);
}

#[test]
fn bind_addresses_default_and_override() {
    use crate::util::IpAddr;

    // Defaults (CNF_Initialise): wildcard for server/acquisition, loopback for command.
    let d = ConfigValues::resolve(&parse("").config);
    assert_eq!(d.bind_address(1), IpAddr::Inet4(0));
    assert_eq!(d.bind_address(2), IpAddr::Inet6([0; 16]));
    assert_eq!(d.bind_acquisition_address(1), IpAddr::Inet4(0));
    assert_eq!(d.bind_command_address(1), IpAddr::Inet4(0x7f00_0001));
    let mut v6lo = [0u8; 16];
    v6lo[15] = 1;
    assert_eq!(d.bind_command_address(2), IpAddr::Inet6(v6lo));
    assert_eq!(d.bind_address(0), IpAddr::Unspec);

    // Overrides: each bind*address sets the slot matching the parsed family.
    let cfg = parse(
        "bindaddress 192.168.1.5\n\
         bindaddress 2001:db8::1\n\
         bindacqaddress 10.0.0.7\n\
         bindcmdaddress 127.0.0.9\n",
    )
    .config;
    let v = ConfigValues::resolve(&cfg);
    assert_eq!(v.bind_address(1), IpAddr::Inet4(0xc0a8_0105));
    assert!(matches!(v.bind_address(2), IpAddr::Inet6(_)));
    assert_eq!(v.bind_acquisition_address(1), IpAddr::Inet4(0x0a00_0007));
    assert_eq!(v.bind_command_address(1), IpAddr::Inet4(0x7f00_0009));
    // v6 acquisition/command untouched -> still the defaults.
    assert_eq!(v.bind_acquisition_address(2), IpAddr::Inet6([0; 16]));

    // bindcmdaddress with a /path sets the command socket path; a lone "/" disables it.
    let p = ConfigValues::resolve(&parse("bindcmdaddress /run/chrony/x.sock\n").config);
    assert_eq!(p.bind_command_path(), Some("/run/chrony/x.sock"));
    let off = ConfigValues::resolve(&parse("bindcmdaddress /\n").config);
    assert_eq!(off.bind_command_path(), None);
}

#[test]
fn array_and_optional_accessors_resolve() {
    use crate::config::model::TempCompCurve;

    // Defaults: everything empty/absent.
    let d = ConfigValues::resolve(&parse("").config);
    assert_eq!(d.allow_local_reference(), None);
    assert_eq!(d.temp_comp(), None);
    assert_eq!(d.init_sources(), 0);
    assert_eq!(d.hw_ts_interface(0), None);
    assert_eq!(d.nts_server_cert_and_key_files(), Some((&[][..], &[][..])));
    assert!(d.nts_trusted_certs_paths().is_empty());

    let cfg = parse(
        "local stratum 5 orphan distance 0.1\n\
         tempcomp /sys/temp 30.0 /etc/points\n\
         initstepslew 30 10.0.0.1 10.0.0.2\n\
         hwtimestamp eth0 minpoll 2\n\
         ntsservercert /a.pem\n\
         ntsserverkey /a.key\n\
         ntsservercert /b.pem\n\
         ntsserverkey /b.key\n\
         ntstrustedcerts 3 /trusted.pem\n",
    )
    .config;
    let v = ConfigValues::resolve(&cfg);

    let lr = v.allow_local_reference().expect("local enabled");
    assert_eq!((lr.stratum, lr.orphan, lr.distance), (5, true, 0.1));

    let tc = v.temp_comp().expect("tempcomp set");
    assert_eq!(tc.sensor_file, "/sys/temp");
    assert_eq!(tc.interval, 30.0);
    assert_eq!(tc.curve, TempCompCurve::PointFile("/etc/points".to_string()));

    assert_eq!(v.init_sources(), 2);

    let hw = v.hw_ts_interface(0).expect("hwts iface");
    assert_eq!(hw.name, "eth0");
    assert_eq!(hw.minpoll, 2);
    assert_eq!(hw.maxpoll, 3); // minpoll + 1 default
    assert_eq!(v.hw_ts_interface(1), None);

    let (certs, keys) = v.nts_server_cert_and_key_files().expect("even cert/key count");
    assert_eq!(certs, &["/a.pem".to_string(), "/b.pem".to_string()]);
    assert_eq!(keys, &["/a.key".to_string(), "/b.key".to_string()]);

    assert_eq!(v.nts_trusted_certs_paths(), &[(3u32, "/trusted.pem".to_string())]);

    // An uneven cert/key count is chrony's fatal case -> None here.
    let uneven = ConfigValues::resolve(&parse("ntsservercert /only.pem\n").config);
    assert_eq!(uneven.nts_server_cert_and_key_files(), None);
}

#[test]
fn last_directive_wins() {
    let lines = "\
maxupdateskew 1.0
maxupdateskew 2.0
maxupdateskew 3.0
driftfile /a
driftfile /b
";
    check("LAST_WINS", lines);
}
