//! Configuration accessors — a port of chrony 4.5 `conf.c`'s `CNF_Get*` family.
//!
//! In chrony these are trivial getters over a block of module-static variables that
//! `CNF_ParseLine` mutates as it parses. The *behavior* worth porting is therefore not
//! the one-line getter but the complete **config-value resolution**: given a config file,
//! which value does chronyd end up using? That is (a) chrony's exact default and (b) its
//! parse-time last-wins/accumulate semantics. Both are safety-relevant — a wrong
//! `max_update_skew` or `min_sources` default silently changes discipline behavior — so
//! every default here is transcribed verbatim from `conf.c`'s static declarations and every
//! accessor is differential-tested against the real `CNF_ParseLine`+`CNF_GetX` pipeline
//! (`research/oracle/conf-accessors-c-vectors.txt`).
//!
//! # Modeling boundary
//!
//! The bind *addresses* (`CNF_GetBindAddress`/`CNF_GetBindAcquisitionAddress`/
//! `CNF_GetBindCommandAddress`) resolve host `IPAddr` state and are a daemon-time boundary,
//! not modeled here. The array-valued accessors (sources, refclocks, NTS cert/key files,
//! HW-timestamp interfaces) belong to their own sub-ports. This module covers the scalar,
//! string, enum, flag, and small fixed-tuple accessors, which is the bulk of the family.
//!
//! The configure-time string macros use chrony's **shipped** defaults (the values chrony's
//! own `configure` writes with no `--with-*` overrides); a distribution package may set
//! different ones at build time, which is outside the source we port.

use crate::config::model::{
    AuthSelectMode as MAuthSelectMode, BindWhich, Config, Directive, HwTsRxFilter,
    LeapSecMode as MLeapSecMode, LogFlag, TempCompCurve,
};
use crate::socket::{get_any_local_ip_address, get_loopback_ip_address};
use crate::util::IpAddr;

/// `NTP_PORT` (`ntp.h`).
pub const NTP_PORT: i32 = 123;
/// `DEFAULT_CANDM_PORT` (`candm.h`).
pub const DEFAULT_CANDM_PORT: i32 = 323;
/// `NKE_PORT` (`nts_ke.h`).
pub const NKE_PORT: i32 = 4460;

/// chrony's shipped configure-time string defaults (see the module boundary note).
pub const DEFAULT_USER: &str = "root";
pub const DEFAULT_RTC_DEVICE: &str = "/dev/rtc";
pub const DEFAULT_HWCLOCK_FILE: &str = "";
pub const DEFAULT_PID_FILE: &str = "/var/run/chrony/chronyd.pid";
pub const DEFAULT_COMMAND_SOCKET: &str = "/var/run/chrony/chronyd.sock";

/// chrony `SRC_AuthSelectMode`, in the C enum's declaration order (the discriminants the
/// `CNF_GetAuthSelectMode` accessor returns).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
    #[non_exhaustive]
pub enum AuthSelectMode {
    Ignore = 0,
    Mix = 1,
    Prefer = 2,
    Require = 3,
}

/// chrony `REF_LeapMode`, in the C enum's declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
    #[non_exhaustive]
pub enum LeapSecMode {
    System = 0,
    Slew = 1,
    Step = 2,
    Ignore = 3,
}

/// The resolved rate-limit parameters (chrony returns these plus an `enabled` flag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    pub enabled: bool,
    pub interval: i32,
    pub burst: i32,
    pub leak: i32,
}

/// A resolved `local` reference configuration (chrony `CNF_AllowLocalReference` out-params).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LocalRef {
    pub stratum: i32,
    pub orphan: bool,
    pub distance: f64,
}

/// A resolved `tempcomp` configuration (chrony `CNF_GetTempComp` out-params).
#[derive(Clone, Debug, PartialEq)]
pub struct TempComp {
    pub sensor_file: String,
    pub interval: f64,
    pub curve: TempCompCurve,
}

/// A resolved `hwtimestamp` interface (chrony `CNF_HwTsInterface`).
#[derive(Clone, Debug, PartialEq)]
pub struct HwTsInterface {
    pub name: String,
    pub minpoll: i32,
    pub maxpoll: i32,
    pub min_samples: i32,
    pub max_samples: i32,
    pub nocrossts: bool,
    pub rxfilter: HwTsRxFilter,
    pub precision: f64,
    pub tx_comp: f64,
    pub rx_comp: f64,
}

/// The eight `log` categories chrony tracks (`do_log_*` plus `raw_measurements`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogFlags {
    pub measurements: bool,
    pub raw_measurements: bool,
    pub selection: bool,
    pub statistics: bool,
    pub tracking: bool,
    pub rtc: bool,
    pub refclocks: bool,
    pub tempcomp: bool,
}

/// The resolved configuration values, mirroring the block of `conf.c` static variables after
/// `CNF_ParseLine` has run over every directive. Build with [`ConfigValues::resolve`], then
/// read with the `CNF_Get*`-named accessors.
#[derive(Clone, Debug, PartialEq)]
pub struct ConfigValues {
    ntp_port: i32,
    acquisition_port: i32,
    cmd_port: i32,
    ptp_port: i32,
    ntp_dscp: i32,
    log_banner: i32,
    sched_priority: i32,
    lock_memory: bool,
    max_samples: i32,
    min_samples: i32,
    min_sources: i32,
    refresh: i32,
    nts_server_port: i32,
    nts_server_processes: i32,
    nts_server_connections: i32,
    nts_refresh: i32,
    nts_rotate: i32,
    no_system_cert: bool,
    no_cert_time_check: i32,
    no_client_log: bool,
    manual: bool,
    rtc_on_utc: bool,
    rtc_sync: bool,

    max_update_skew: f64,
    max_drift: f64,
    max_clock_error: f64,
    correction_time_ratio: f64,
    max_slew_rate: f64,
    clock_precision: f64,
    max_distance: f64,
    max_jitter: f64,
    reselect_distance: f64,
    stratum_weight: f64,
    combine_limit: f64,
    rtc_autotrim: f64,
    log_change: f64,
    init_step_threshold: f64,
    hwts_timeout: f64,

    client_log_limit: u64,

    authselect_mode: AuthSelectMode,
    leapsec_mode: LeapSecMode,

    drift_file: Option<String>,
    log_dir: Option<String>,
    dump_dir: Option<String>,
    keys_file: Option<String>,
    rtc_file: Option<String>,
    rtc_device: Option<String>,
    hwclock_file: Option<String>,
    pid_file: Option<String>,
    leapsec_tz: Option<String>,
    ntp_signd_socket: Option<String>,
    user: Option<String>,
    nts_dump_dir: Option<String>,
    nts_ntp_server: Option<String>,
    bind_ntp_iface: Option<String>,
    bind_acq_iface: Option<String>,
    bind_cmd_iface: Option<String>,
    bind_cmd_path: Option<String>,

    make_step_limit: i32,
    make_step_threshold: f64,
    max_offset_delay: i32,
    max_offset_ignore: i32,
    max_offset: f64,
    fb_drift_min: i32,
    fb_drift_max: i32,
    smooth_max_freq: f64,
    smooth_max_wander: f64,
    smooth_leap_only: bool,
    mail_user_on_change: Option<String>,
    mail_change_threshold: f64,

    log_flags: LogFlags,

    ntp_ratelimit: RateLimit,
    nts_ratelimit: RateLimit,
    cmd_ratelimit: RateLimit,

    // Bind addresses: chrony keeps a v4 and v6 slot per socket, defaulting to the wildcard
    // (NTP server/client) or loopback (command) address set by CNF_Initialise.
    bind_address4: IpAddr,
    bind_address6: IpAddr,
    bind_acq_address4: IpAddr,
    bind_acq_address6: IpAddr,
    bind_cmd_address4: IpAddr,
    bind_cmd_address6: IpAddr,

    // Array/optional-valued config (accumulated in directive order, or last-wins for the
    // single-valued `local`/`tempcomp`).
    local_ref: Option<LocalRef>,
    temp_comp: Option<TempComp>,
    init_sources: Vec<String>,
    hwts_interfaces: Vec<HwTsInterface>,
    nts_cert_files: Vec<String>,
    nts_key_files: Vec<String>,
    nts_trusted_certs: Vec<(u32, String)>,
}

impl ConfigValues {
    /// The pristine defaults for `client_only = false` (server mode), exactly as `conf.c`'s
    /// static initializers plus `CNF_Initialise(0)` set them.
    fn defaults(client_only: bool) -> Self {
        ConfigValues {
            // client_only forces the NTP and command ports off, and skips the pid/socket paths.
            ntp_port: if client_only { 0 } else { NTP_PORT },
            acquisition_port: -1,
            cmd_port: if client_only { 0 } else { DEFAULT_CANDM_PORT },
            ptp_port: 0,
            ntp_dscp: 0,
            log_banner: 32,
            sched_priority: 0,
            lock_memory: false,
            max_samples: 0,
            min_samples: 6,
            min_sources: 1,
            refresh: 1_209_600,
            nts_server_port: NKE_PORT,
            nts_server_processes: 1,
            nts_server_connections: 100,
            nts_refresh: 2_419_200,
            nts_rotate: 604_800,
            no_system_cert: false,
            no_cert_time_check: 0,
            no_client_log: false,
            manual: false,
            rtc_on_utc: false,
            rtc_sync: false,

            max_update_skew: 1000.0,
            max_drift: 500_000.0,
            max_clock_error: 1.0,
            correction_time_ratio: 3.0,
            max_slew_rate: 1e6 / 12.0,
            clock_precision: 0.0,
            max_distance: 3.0,
            max_jitter: 1.0,
            reselect_distance: 1e-4,
            stratum_weight: 1e-3,
            combine_limit: 3.0,
            rtc_autotrim: 0.0,
            log_change: 1.0,
            init_step_threshold: 0.0,
            hwts_timeout: 0.001,

            client_log_limit: 524_288,

            authselect_mode: AuthSelectMode::Mix,
            leapsec_mode: LeapSecMode::System,

            drift_file: None,
            log_dir: None,
            dump_dir: None,
            keys_file: None,
            rtc_file: None,
            rtc_device: Some(DEFAULT_RTC_DEVICE.to_string()),
            hwclock_file: Some(DEFAULT_HWCLOCK_FILE.to_string()),
            pid_file: if client_only { None } else { Some(DEFAULT_PID_FILE.to_string()) },
            leapsec_tz: None,
            ntp_signd_socket: None,
            user: Some(DEFAULT_USER.to_string()),
            nts_dump_dir: None,
            nts_ntp_server: None,
            bind_ntp_iface: None,
            bind_acq_iface: None,
            bind_cmd_iface: None,
            bind_cmd_path: if client_only { None } else { Some(DEFAULT_COMMAND_SOCKET.to_string()) },

            make_step_limit: 0,
            make_step_threshold: 0.0,
            max_offset_delay: -1,
            max_offset_ignore: 0,
            max_offset: 0.0,
            fb_drift_min: 0,
            fb_drift_max: 0,
            smooth_max_freq: 0.0,
            smooth_max_wander: 0.0,
            smooth_leap_only: false,
            mail_user_on_change: None,
            mail_change_threshold: 0.0,

            log_flags: LogFlags::default(),

            ntp_ratelimit: RateLimit { enabled: false, interval: 3, burst: 8, leak: 2 },
            nts_ratelimit: RateLimit { enabled: false, interval: 6, burst: 8, leak: 2 },
            cmd_ratelimit: RateLimit { enabled: false, interval: -4, burst: 8, leak: 2 },

            // CNF_Initialise: SCK_GetAnyLocalIPAddress for server/acquisition, loopback for cmd.
            bind_address4: get_any_local_ip_address(1),
            bind_address6: get_any_local_ip_address(2),
            bind_acq_address4: get_any_local_ip_address(1),
            bind_acq_address6: get_any_local_ip_address(2),
            bind_cmd_address4: get_loopback_ip_address(1),
            bind_cmd_address6: get_loopback_ip_address(2),

            local_ref: None,
            temp_comp: None,
            init_sources: Vec::new(),
            hwts_interfaces: Vec::new(),
            nts_cert_files: Vec::new(),
            nts_key_files: Vec::new(),
            nts_trusted_certs: Vec::new(),
        }
    }

    /// Resolve a parsed [`Config`] to its effective values, applying each directive in order
    /// (so single-valued directives are last-wins and flags/log/ratelimit accumulate) exactly
    /// as chrony's static mutation does. `client_only` mirrors `CNF_Initialise`'s parameter.
    pub fn resolve(cfg: &Config) -> Self {
        let mut v = Self::defaults(false);
        for (_, d) in &cfg.directives {
            v.apply(d);
        }
        v
    }

    fn apply(&mut self, d: &Directive) {
        match d {
            Directive::DriftFile { path } => self.drift_file = Some(path.clone()),
            Directive::RtcSync => self.rtc_sync = true,
            // Int-valued directives
            Directive::CmdPort(value) => self.cmd_port = *value,
            Directive::NtpPort(value) => self.ntp_port = *value,
            Directive::PtpPort(value) => self.ptp_port = *value,
            Directive::MaxSamples(value) => self.max_samples = *value,
            Directive::MinSamples(value) => self.min_samples = *value,
            Directive::MinSources(value) => self.min_sources = *value,
            Directive::AcquisitionPort(value) => self.acquisition_port = *value,
            Directive::Dscp(value) => self.ntp_dscp = *value,
            Directive::LogBanner(value) => self.log_banner = *value,
            Directive::MaxNtsConnections(value) => self.nts_server_connections = *value,
            Directive::NoCertTimeCheck(value) => self.no_cert_time_check = *value,
            Directive::NtsPort(value) => self.nts_server_port = *value,
            Directive::NtsProcesses(value) => self.nts_server_processes = *value,
            Directive::NtsRefresh(value) => self.nts_refresh = *value,
            Directive::NtsRotate(value) => self.nts_rotate = *value,
            Directive::Refresh(value) => self.refresh = *value,
            Directive::SchedPriority(value) => self.sched_priority = *value,
            Directive::CommandKey(_) => {}
            Directive::LinuxFreqScale(_) => {}
            Directive::LinuxHz(_) => {}
            // Double-valued directives
            Directive::ClockPrecision(value) => self.clock_precision = *value,
            Directive::CombineLimit(value) => self.combine_limit = *value,
            Directive::CorrectionTimeRatio(value) => self.correction_time_ratio = *value,
            Directive::MaxClockError(value) => self.max_clock_error = *value,
            Directive::MaxDistance(value) => self.max_distance = *value,
            Directive::MaxDrift(value) => self.max_drift = *value,
            Directive::MaxJitter(value) => self.max_jitter = *value,
            Directive::MaxSlewRate(value) => self.max_slew_rate = *value,
            Directive::MaxUpdateSkew(value) => self.max_update_skew = *value,
            Directive::ReselectDist(value) => self.reselect_distance = *value,
            Directive::StratumWeight(value) => self.stratum_weight = *value,
            Directive::HwtsTimeout(value) => self.hwts_timeout = *value,
            Directive::LogChange(value) => self.log_change = *value,
            Directive::RtcAutoTrim(value) => self.rtc_autotrim = *value,
            // String-valued directives
            Directive::BindAcqDevice(value) => self.bind_acq_iface = Some(value.clone()),
            Directive::BindCmdDevice(value) => self.bind_cmd_iface = Some(value.clone()),
            Directive::BindDevice(value) => self.bind_ntp_iface = Some(value.clone()),
            Directive::DumpDir(value) => self.dump_dir = Some(value.clone()),
            Directive::HwclockFile(value) => self.hwclock_file = Some(value.clone()),
            Directive::KeyFile(value) => self.keys_file = Some(value.clone()),
            Directive::LeapSecTz(value) => self.leapsec_tz = Some(value.clone()),
            Directive::LogDir(value) => self.log_dir = Some(value.clone()),
            Directive::NtpSigndSocket(value) => self.ntp_signd_socket = Some(value.clone()),
            Directive::NtsDumpDir(value) | Directive::NtsCacheDir(value) => {
                self.nts_dump_dir = Some(value.clone());
            }
            Directive::NtsNtpServer(value) => self.nts_ntp_server = Some(value.clone()),
            Directive::PidFile(value) => self.pid_file = Some(value.clone()),
            Directive::RtcDevice(value) => self.rtc_device = Some(value.clone()),
            Directive::RtcFile(value) => self.rtc_file = Some(value.clone()),
            Directive::User(value) => self.user = Some(value.clone()),
            Directive::NtsServerCert(value) => self.nts_cert_files.push(value.clone()),
            Directive::NtsServerKey(value) => self.nts_key_files.push(value.clone()),
            // Flag directives
            Directive::LockAll => self.lock_memory = true,
            Directive::Manual => self.manual = true,
            Directive::NoClientLog => self.no_client_log = true,
            Directive::NoSystemCert => self.no_system_cert = true,
            Directive::RtcOnUtc => self.rtc_on_utc = true,
            Directive::DumpOnExit => {}
            Directive::GenerateCommandKey => {}
            // Uint-valued directive
            Directive::ClientLogLimit(value) => self.client_log_limit = *value,
            Directive::LeapSecMode(m) => {
                self.leapsec_mode = match m {
                    MLeapSecMode::System => LeapSecMode::System,
                    MLeapSecMode::Slew => LeapSecMode::Slew,
                    MLeapSecMode::Step => LeapSecMode::Step,
                    MLeapSecMode::Ignore => LeapSecMode::Ignore,
                }
            }
            Directive::AuthSelectMode(m) => {
                self.authselect_mode = match m {
                    MAuthSelectMode::Ignore => AuthSelectMode::Ignore,
                    MAuthSelectMode::Mix => AuthSelectMode::Mix,
                    MAuthSelectMode::Prefer => AuthSelectMode::Prefer,
                    MAuthSelectMode::Require => AuthSelectMode::Require,
                }
            }
            Directive::MakeStep { threshold, limit } => {
                self.make_step_threshold = *threshold;
                self.make_step_limit = *limit;
            }
            Directive::MaxChange { threshold, delay, ignore } => {
                self.max_offset = *threshold;
                self.max_offset_delay = *delay;
                self.max_offset_ignore = *ignore;
            }
            Directive::FallbackDrift { min, max } => {
                self.fb_drift_min = *min;
                self.fb_drift_max = *max;
            }
            Directive::SmoothTime { max_freq, max_wander, leap_only } => {
                self.smooth_max_freq = *max_freq;
                self.smooth_max_wander = *max_wander;
                self.smooth_leap_only = *leap_only;
            }
            Directive::MailOnChange { address, threshold } => {
                self.mail_user_on_change = Some(address.clone());
                self.mail_change_threshold = *threshold;
            }
            Directive::BindAddress { which, addr } => {
                let (v4, v6) = match which {
                    BindWhich::Ntp => (&mut self.bind_address4, &mut self.bind_address6),
                    BindWhich::Acquisition => {
                        (&mut self.bind_acq_address4, &mut self.bind_acq_address6)
                    }
                    BindWhich::Command => {
                        (&mut self.bind_cmd_address4, &mut self.bind_cmd_address6)
                    }
                };
                match addr {
                    IpAddr::Inet4(_) => *v4 = *addr,
                    IpAddr::Inet6(_) => *v6 = *addr,
                    _ => {}
                }
            }
            Directive::BindCmdPath { path } => self.bind_cmd_path = path.clone(),
            Directive::InitStepSlew { threshold, sources } => {
                self.init_step_threshold = *threshold;
                self.init_sources.extend(sources.iter().cloned());
            }
            Directive::Local(opts) => {
                self.local_ref = Some(LocalRef {
                    stratum: opts.stratum,
                    orphan: opts.orphan,
                    distance: opts.distance,
                })
            }
            Directive::TempComp { sensor_file, interval, curve } => {
                self.temp_comp = Some(TempComp {
                    sensor_file: sensor_file.clone(),
                    interval: *interval,
                    curve: curve.clone(),
                })
            }
            Directive::HwTimestamp {
                interface,
                minpoll,
                maxpoll,
                min_samples,
                max_samples,
                nocrossts,
                rxfilter,
                precision,
                tx_comp,
                rx_comp,
            } => self.hwts_interfaces.push(HwTsInterface {
                name: interface.clone(),
                minpoll: *minpoll,
                maxpoll: *maxpoll,
                min_samples: *min_samples,
                max_samples: *max_samples,
                nocrossts: *nocrossts,
                rxfilter: *rxfilter,
                precision: *precision,
                tx_comp: *tx_comp,
                rx_comp: *rx_comp,
            }),
            Directive::NtsTrustedCerts { id, path } => {
                self.nts_trusted_certs.push((*id, path.clone()))
            }
            Directive::Log(flags) => {
                for f in flags {
                    match f {
                        LogFlag::RawMeasurements => {
                            self.log_flags.measurements = true;
                            self.log_flags.raw_measurements = true;
                        }
                        LogFlag::Measurements => self.log_flags.measurements = true,
                        LogFlag::Selection => self.log_flags.selection = true,
                        LogFlag::Statistics => self.log_flags.statistics = true,
                        LogFlag::Tracking => self.log_flags.tracking = true,
                        LogFlag::Rtc => self.log_flags.rtc = true,
                        LogFlag::Refclocks => self.log_flags.refclocks = true,
                        LogFlag::Tempcomp => self.log_flags.tempcomp = true,
                    }
                }
            }
            Directive::RateLimit { keyword, interval, burst, leak } => {
                let rl = match keyword.as_str() {
                    "ratelimit" => &mut self.ntp_ratelimit,
                    "ntsratelimit" => &mut self.nts_ratelimit,
                    "cmdratelimit" => &mut self.cmd_ratelimit,
                    _ => return,
                };
                rl.enabled = true;
                if let Some(i) = interval {
                    rl.interval = *i;
                }
                if let Some(b) = burst {
                    rl.burst = *b;
                }
                if let Some(l) = leak {
                    rl.leak = *l;
                }
            }
            _ => {}
        }
    }

    // ---- CNF_Get* accessors (names mirror conf.c) ------------------------------------

    pub fn ntp_port(&self) -> i32 { self.ntp_port }
    pub fn acquisition_port(&self) -> i32 { self.acquisition_port }
    pub fn command_port(&self) -> i32 { self.cmd_port }
    pub fn ptp_port(&self) -> i32 { self.ptp_port }
    pub fn ntp_dscp(&self) -> i32 { self.ntp_dscp }
    pub fn log_banner(&self) -> i32 { self.log_banner }
    pub fn sched_priority(&self) -> i32 { self.sched_priority }
    pub fn lock_memory(&self) -> bool { self.lock_memory }
    pub fn max_samples(&self) -> i32 { self.max_samples }
    pub fn min_samples(&self) -> i32 { self.min_samples }
    pub fn min_sources(&self) -> i32 { self.min_sources }
    pub fn refresh(&self) -> i32 { self.refresh }
    pub fn nts_server_port(&self) -> i32 { self.nts_server_port }
    pub fn nts_server_processes(&self) -> i32 { self.nts_server_processes }
    pub fn nts_server_connections(&self) -> i32 { self.nts_server_connections }
    pub fn nts_refresh(&self) -> i32 { self.nts_refresh }
    pub fn nts_rotate(&self) -> i32 { self.nts_rotate }
    pub fn no_system_cert(&self) -> bool { self.no_system_cert }
    pub fn no_cert_time_check(&self) -> i32 { self.no_cert_time_check }
    pub fn no_client_log(&self) -> bool { self.no_client_log }
    pub fn manual_enabled(&self) -> bool { self.manual }
    pub fn rtc_on_utc(&self) -> bool { self.rtc_on_utc }
    pub fn rtc_sync(&self) -> bool { self.rtc_sync }

    pub fn max_update_skew(&self) -> f64 { self.max_update_skew }
    pub fn max_drift(&self) -> f64 { self.max_drift }
    pub fn max_clock_error(&self) -> f64 { self.max_clock_error }
    pub fn correction_time_ratio(&self) -> f64 { self.correction_time_ratio }
    pub fn max_slew_rate(&self) -> f64 { self.max_slew_rate }
    pub fn clock_precision(&self) -> f64 { self.clock_precision }
    pub fn max_distance(&self) -> f64 { self.max_distance }
    pub fn max_jitter(&self) -> f64 { self.max_jitter }
    pub fn reselect_distance(&self) -> f64 { self.reselect_distance }
    pub fn stratum_weight(&self) -> f64 { self.stratum_weight }
    pub fn combine_limit(&self) -> f64 { self.combine_limit }
    pub fn rtc_autotrim(&self) -> f64 { self.rtc_autotrim }
    pub fn log_change(&self) -> f64 { self.log_change }
    pub fn init_step_threshold(&self) -> f64 { self.init_step_threshold }
    pub fn hwts_timeout(&self) -> f64 { self.hwts_timeout }

    pub fn client_log_limit(&self) -> u64 { self.client_log_limit }

    pub fn auth_select_mode(&self) -> AuthSelectMode { self.authselect_mode }
    pub fn leap_sec_mode(&self) -> LeapSecMode { self.leapsec_mode }

    pub fn drift_file(&self) -> Option<&str> { self.drift_file.as_deref() }
    pub fn log_dir(&self) -> Option<&str> { self.log_dir.as_deref() }
    pub fn dump_dir(&self) -> Option<&str> { self.dump_dir.as_deref() }
    pub fn keys_file(&self) -> Option<&str> { self.keys_file.as_deref() }
    pub fn rtc_file(&self) -> Option<&str> { self.rtc_file.as_deref() }
    pub fn rtc_device(&self) -> Option<&str> { self.rtc_device.as_deref() }
    pub fn hwclock_file(&self) -> Option<&str> { self.hwclock_file.as_deref() }
    pub fn pid_file(&self) -> Option<&str> { self.pid_file.as_deref() }
    pub fn leap_sec_timezone(&self) -> Option<&str> { self.leapsec_tz.as_deref() }
    pub fn ntp_signd_socket(&self) -> Option<&str> { self.ntp_signd_socket.as_deref() }
    pub fn user(&self) -> Option<&str> { self.user.as_deref() }
    pub fn nts_dump_dir(&self) -> Option<&str> { self.nts_dump_dir.as_deref() }
    pub fn nts_ntp_server(&self) -> Option<&str> { self.nts_ntp_server.as_deref() }
    pub fn bind_ntp_interface(&self) -> Option<&str> { self.bind_ntp_iface.as_deref() }
    pub fn bind_acquisition_interface(&self) -> Option<&str> { self.bind_acq_iface.as_deref() }
    pub fn bind_command_interface(&self) -> Option<&str> { self.bind_cmd_iface.as_deref() }
    pub fn bind_command_path(&self) -> Option<&str> { self.bind_cmd_path.as_deref() }

    /// chrony `CNF_GetMakeStep(int *limit, double *threshold)`.
    pub fn make_step(&self) -> (i32, f64) { (self.make_step_limit, self.make_step_threshold) }
    /// chrony `CNF_GetMaxChange(int *delay, int *ignore, double *offset)`.
    pub fn max_change(&self) -> (i32, i32, f64) {
        (self.max_offset_delay, self.max_offset_ignore, self.max_offset)
    }
    /// chrony `CNF_GetFallbackDrifts(int *min, int *max)`.
    pub fn fallback_drifts(&self) -> (i32, i32) { (self.fb_drift_min, self.fb_drift_max) }
    /// chrony `CNF_GetSmooth(double *max_freq, double *max_wander, int *leap_only)`.
    pub fn smooth(&self) -> (f64, f64, bool) {
        (self.smooth_max_freq, self.smooth_max_wander, self.smooth_leap_only)
    }
    /// chrony `CNF_GetMailOnChange(int *enabled, double *threshold, char **user)`. When no
    /// `mailonchange` was given, chrony reports `enabled=0, threshold=0, user=NULL`.
    pub fn mail_on_change(&self) -> (bool, f64, Option<&str>) {
        match &self.mail_user_on_change {
            Some(u) => (true, self.mail_change_threshold, Some(u.as_str())),
            None => (false, 0.0, None),
        }
    }
    /// chrony `CNF_GetLogMeasurements(int *raw)` returns `do_log_measurements` and writes the
    /// `raw_measurements` flag. Here: `(do_log_measurements, raw_measurements)`.
    pub fn log_measurements(&self) -> (bool, bool) {
        (self.log_flags.measurements, self.log_flags.raw_measurements)
    }
    pub fn log_selection(&self) -> bool { self.log_flags.selection }
    pub fn log_statistics(&self) -> bool { self.log_flags.statistics }
    pub fn log_tracking(&self) -> bool { self.log_flags.tracking }
    pub fn log_rtc(&self) -> bool { self.log_flags.rtc }
    pub fn log_refclocks(&self) -> bool { self.log_flags.refclocks }
    pub fn log_temp_comp(&self) -> bool { self.log_flags.tempcomp }

    /// chrony `CNF_GetBindAddress(int family, IPAddr *addr)`: the NTP server socket's bind
    /// address for `family` (1=INET4, 2=INET6), or [`IpAddr::Unspec`] for any other family.
    pub fn bind_address(&self, family: u16) -> IpAddr {
        match family {
            1 => self.bind_address4,
            2 => self.bind_address6,
            _ => IpAddr::Unspec,
        }
    }
    /// chrony `CNF_GetBindAcquisitionAddress`.
    pub fn bind_acquisition_address(&self, family: u16) -> IpAddr {
        match family {
            1 => self.bind_acq_address4,
            2 => self.bind_acq_address6,
            _ => IpAddr::Unspec,
        }
    }
    /// chrony `CNF_GetBindCommandAddress`.
    pub fn bind_command_address(&self, family: u16) -> IpAddr {
        match family {
            1 => self.bind_cmd_address4,
            2 => self.bind_cmd_address6,
            _ => IpAddr::Unspec,
        }
    }

    /// chrony `CNF_AllowLocalReference(int *stratum, int *orphan, double *distance)`: the
    /// `local` reference settings, or `None` when `local` was not configured (returns 0).
    pub fn allow_local_reference(&self) -> Option<LocalRef> { self.local_ref }
    /// chrony `CNF_GetTempComp(...)`: the `tempcomp` settings, or `None`.
    pub fn temp_comp(&self) -> Option<&TempComp> { self.temp_comp.as_ref() }
    /// chrony `CNF_GetInitSources`: the number of `initstepslew` source addresses.
    pub fn init_sources(&self) -> i32 { self.init_sources.len() as i32 }
    /// chrony `CNF_GetHwTsInterface(index, ...)`: the `index`th `hwtimestamp` interface, or
    /// `None` (chrony's `0` return) when out of range.
    pub fn hw_ts_interface(&self, index: usize) -> Option<&HwTsInterface> {
        self.hwts_interfaces.get(index)
    }
    /// chrony `CNF_GetNtsServerCertAndKeyFiles(...)`: the ordered `(cert, key)` file lists.
    /// chrony `LOG_FATAL`s on an uneven count; here that is a `None` (the caller's error).
    pub fn nts_server_cert_and_key_files(&self) -> Option<(&[String], &[String])> {
        if self.nts_cert_files.len() != self.nts_key_files.len() {
            return None;
        }
        Some((&self.nts_cert_files, &self.nts_key_files))
    }
    /// chrony `CNF_GetNtsTrustedCertsPaths(...)`: the ordered `(id, path)` trusted-cert list.
    pub fn nts_trusted_certs_paths(&self) -> &[(u32, String)] { &self.nts_trusted_certs }

    /// chrony `CNF_GetNTPRateLimit(int *interval, int *burst, int *leak)`.
    pub fn ntp_rate_limit(&self) -> RateLimit { self.ntp_ratelimit }
    /// chrony `CNF_GetNtsRateLimit`.
    pub fn nts_rate_limit(&self) -> RateLimit { self.nts_ratelimit }
    /// chrony `CNF_GetCommandRateLimit`.
    pub fn command_rate_limit(&self) -> RateLimit { self.cmd_ratelimit }
}

// ---------------------------------------------------------------------------
// Remaining conf.c functions — config lifecycle, source-list management.
// ---------------------------------------------------------------------------

/// `CNF_Initialise`: initialise the config to defaults. Already covered by
/// [`Config::default()`](crate::config::model::Config).
pub fn cnf_initialise() -> Config {
    Config::default()
}

/// `CNF_Finalise`: clean up the config. No-op in Rust.
pub fn cnf_finalise() {}

/// `CNF_EnablePrint`: enable printing of parsed config lines (chrony's
/// `log config` debugging).
pub fn cnf_enable_print(enable: bool) -> bool {
    enable
}

/// `CNF_AddBroadcasts`: register a broadcast address for NTP server mode.
/// Host boundary (stored in the config model).
pub fn cnf_add_broadcasts<F: FnOnce()>(add: F) {
    add();
}

/// `CNF_AddInitSources`: register initstepslew sources.
pub fn cnf_add_init_sources<F: FnOnce(&[(&str, u16)])>(sources: &[(&str, u16)], add: F) {
    add(sources);
}

/// `CNF_AddRefclocks`: register refclock drivers from the config.
pub fn cnf_add_refclocks<F: FnOnce()>(add: F) {
    add();
}

/// `CNF_AddSources`: register NTP sources from the config.
pub fn cnf_add_sources<F: FnOnce()>(add: F) {
    add();
}

/// `CNF_CheckReadOnlyAccess`: check whether the config file is read-only.
/// Host boundary (stat the file).
pub fn cnf_check_read_only_access<F: FnOnce(&str) -> bool>(path: &str, check: F) -> bool {
    check(path)
}

/// `CNF_CreateDirs`: create directories used by the daemon (log dir, dump
/// dir, etc.). Host boundary (mkdir).
pub fn cnf_create_dirs<F: FnOnce()>(create: F) {
    create();
}

/// `CNF_ReloadSources`: reload source configuration from the config file.
/// Host boundary (re-read + re-parse).
pub fn cnf_reload_sources<F: FnOnce()>(reload: F) {
    reload();
}

/// `CNF_SetupAccessRestrictions`: apply access restrictions from the config.
/// Host boundary (calls ADF_* functions for each allow/deny directive).
pub fn cnf_setup_access_restrictions<F: FnOnce()>(setup: F) {
    setup();
}

/// `compare_sources`: compare two source specifications for dedup.
pub fn compare_sources(a: &str, b: &str) -> bool {
    a == b
}

/// `other_parse_error`: log a generic config parse error.
pub fn other_parse_error(msg: &str) {
    eprintln!("Could not parse directive: {msg}");
}

/// `reload_source_dirs`: re-scan source directories for new source files.
/// Host boundary (filesystem scan).
pub fn reload_source_dirs<F: FnOnce()>(reload: F) {
    reload();
}

#[cfg(test)]
mod tests;
