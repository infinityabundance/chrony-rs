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
    #[non_exhaustive]
pub enum ServerKind {
    Server,
    Pool,
    Peer,
}

/// A `server` / `pool` / `peer` directive. The options are parsed in full by the
/// oracle-backed [`crate::cmdparse::parse_ntp_source_add`], so [`params`] carries every
/// `SourceParameters` field (not just a modeled subset). `params.name` is the hostname/address
/// as written — name resolution is a daemon-time OS boundary and does not happen in the parser.
///
/// Only `PartialEq` (not `Eq`) because [`crate::cmdparse::CpsNtpSource`] holds `f64` fields.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SourceDirective {
    pub kind: ServerKind,
    pub params: crate::cmdparse::CpsNtpSource,
}

/// `leapsecmode` value (chrony `REF_LeapMode`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    #[non_exhaustive]
pub enum LeapSecMode {
    System,
    Slew,
    Step,
    Ignore,
}

/// `authselectmode` value (chrony `SRC_AuthSelectMode`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    #[non_exhaustive]
pub enum AuthSelectMode {
    Require,
    Prefer,
    Mix,
    Ignore,
}

/// A `log` flag (chrony's `parse_log` keywords, matched case-sensitively). `RawMeasurements`
/// additionally implies measurement logging in chrony.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    #[non_exhaustive]
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

/// `tempcomp`'s compensation curve: either a points file or inline coefficients.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
    #[non_exhaustive]
pub enum TempCompCurve {
    /// 3-arg form: a file of `(temperature, compensation)` points.
    PointFile(String),
    /// 6-arg form: the inline `T0 k0 k1 k2` quadratic coefficients.
    Coefficients { t0: f64, k0: f64, k1: f64, k2: f64 },
}

/// `hwtimestamp`'s `rxfilter` option (chrony `CNF_HWTS_RXFILTER_*`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    #[non_exhaustive]
pub enum HwTsRxFilter {
    Any,
    None,
    Ntp,
    Ptp,
    All,
}

/// Parsed `refclock` parameters (chrony's `RefclockParameters`). `sel_options` is a bitmask
/// of `SRC_SELECT_*` (noselect=1, prefer=2, trust=4, require=8).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RefclockParams {
    pub driver_name: String,
    pub driver_parameter: String,
    pub poll: i32,
    pub driver_poll: i32,
    pub filter_length: i32,
    pub local: bool,
    pub pps_forced: bool,
    pub pps_rate: i32,
    pub min_samples: i32,
    pub max_samples: i32,
    pub sel_options: i32,
    pub stratum: i32,
    pub tai: bool,
    pub max_lock_age: i32,
    pub ref_id: u32,
    pub lock_ref_id: u32,
    pub offset: f64,
    pub delay: f64,
    pub precision: f64,
    pub max_dispersion: f64,
    pub pulse_width: f64,
}

/// Which socket a `bind*address` directive targets (chrony keeps three separate
/// `bind_*_address4/6` pairs).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    #[non_exhaustive]
pub enum BindWhich {
    /// `bindaddress` — the NTP server socket.
    Ntp,
    /// `bindacqaddress` — the NTP client (acquisition) socket.
    Acquisition,
    /// `bindcmdaddress` — the command socket.
    Command,
}

/// A modeled directive, or an unmodeled-but-preserved one.
///
/// Note: only `PartialEq` (not `Eq`) because `MakeStep.threshold` is an `f64`.
/// Config comparison in tests is by value equality, which is what we want; we do
/// not key collections on `Directive`, so the missing `Eq` costs nothing.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
    #[non_exhaustive]
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
    // Flags (chrony `parse_null` — exactly zero arguments)
    /// `lock_all` — lock process memory to avoid swapping.
    LockAll,
    /// `manual` — enable manual time input mode.
    Manual,
    /// `noclientlog` — disable client log.
    NoClientLog,
    /// `nosystemcert` — do not load system certificates for NTS.
    NoSystemCert,
    /// `rtconutc` — RTC keeps UTC (not local time).
    RtcOnUtc,
    /// `dumponexit` — write dump files on exit (chrony silently ignores this).
    DumpOnExit,
    /// `generatecommandkey` — auto-generate a command key (compat, ignored).
    GenerateCommandKey,

    // Int-valued directives (chrony `parse_int`)
    /// `cmdport <port>` — command port number (0 disables).
    CmdPort(i32),
    /// `port <port>` — NTP port number.
    NtpPort(i32),
    /// `ptpport <port>` — PTP port number.
    PtpPort(i32),
    /// `maxsamples <n>` — maximum samples per source.
    MaxSamples(i32),
    /// `minsamples <n>` — minimum samples per source.
    MinSamples(i32),
    /// `minsources <n>` — minimum sources to synchronize.
    MinSources(i32),
    /// `acquisitionport <port>` — acquisition port number.
    AcquisitionPort(i32),
    /// `dscp <dscp>` — DSCP marking for NTP packets.
    Dscp(i32),
    /// `logbanner <n>` — interval between log banners (in log lines).
    LogBanner(i32),
    /// `maxntsconnections <n>` — max simultaneous NTS-KE connections.
    MaxNtsConnections(i32),
    /// `nocerttimecheck <n>` — disable certificate time check (seconds).
    NoCertTimeCheck(i32),
    /// `ntsport <port>` — NTS-KE server port.
    NtsPort(i32),
    /// `ntsprocesses <n>` — NTS-KE helper processes.
    NtsProcesses(i32),
    /// `ntsrefresh <n>` — NTS key refresh interval.
    NtsRefresh(i32),
    /// `ntsrotate <n>` — NTS key rotation interval.
    NtsRotate(i32),
    /// `refresh <n>` — refresh interval for source resolution.
    Refresh(i32),
    /// `sched_priority <n>` — scheduler priority.
    SchedPriority(i32),
    /// `commandkey <id>` — command key ID (compat).
    CommandKey(i32),
    /// `linux_freq_scale <n>` — Linux frequency scale (platform).
    LinuxFreqScale(i32),
    /// `linux_hz <n>` — Linux kernel tick rate (platform).
    LinuxHz(i32),

    // Double-valued directives (chrony `parse_double`)
    /// `clockprecision <sec>` — expected clock read precision.
    ClockPrecision(f64),
    /// `combinelimit <n>` — min surviving sources to combine.
    CombineLimit(f64),
    /// `corrtimeratio <ratio>` — correction time ratio.
    CorrectionTimeRatio(f64),
    /// `maxclockerror <ppm>` — maximum clock error.
    MaxClockError(f64),
    /// `maxdistance <sec>` — maximum root distance.
    MaxDistance(f64),
    /// `maxdrift <ppm>` — maximum drift rate.
    MaxDrift(f64),
    /// `maxjitter <sec>` — maximum jitter.
    MaxJitter(f64),
    /// `maxslewrate <ppm>` — maximum slew rate.
    MaxSlewRate(f64),
    /// `maxupdateskew <ppm>` — maximum skew for clock updates.
    MaxUpdateSkew(f64),
    /// `reselectdist <sec>` — reselect distance.
    ReselectDist(f64),
    /// `stratumweight <sec>` — stratum weight.
    StratumWeight(f64),
    /// `hwtstimeout <sec>` — hardware timestamp timeout.
    HwtsTimeout(f64),
    /// `logchange <threshold>` — log a message when clock changes by threshold.
    LogChange(f64),
    /// `rtcautotrim <interval>` — RTC auto-trim interval.
    RtcAutoTrim(f64),

    // String-valued directives (chrony `parse_string` — one verbatim arg)
    /// `bindacqdevice <dev>` — bind acquisition socket to interface.
    BindAcqDevice(String),
    /// `bindcmddevice <dev>` — bind command socket to interface.
    BindCmdDevice(String),
    /// `binddevice <dev>` — bind NTP socket to interface.
    BindDevice(String),
    /// `dumpdir <dir>` — dump file directory.
    DumpDir(String),
    /// `hwclockfile <path>` — hwclock correction file.
    HwclockFile(String),
    /// `keyfile <path>` — key file path.
    KeyFile(String),
    /// `leapsectz <tz>` — leap second timezone.
    LeapSecTz(String),
    /// `logdir <dir>` — log file directory.
    LogDir(String),
    /// `ntpsigndsocket <path>` — ntpsignd socket path.
    NtpSigndSocket(String),
    /// `ntsdumpdir <dir>` — NTS dump directory.
    NtsDumpDir(String),
    /// `ntscachedir <dir>` — NTS cache directory (alias for ntsdumpdir).
    NtsCacheDir(String),
    /// `ntsntpserver <host>` — NTS NTP server hostname.
    NtsNtpServer(String),
    /// `pidfile <path>` — PID file path.
    PidFile(String),
    /// `rtcdevice <dev>` — RTC device path.
    RtcDevice(String),
    /// `rtcfile <path>` — RTC save file.
    RtcFile(String),
    /// `user <name>` — daemon user name.
    User(String),
    /// `ntsservercert <path>` — NTS server certificate file.
    NtsServerCert(String),
    /// `ntsserverkey <path>` — NTS server key file.
    NtsServerKey(String),

    // Uint-valued
    /// `clientloglimit <n>` — client log memory limit (bytes).
    ClientLogLimit(u64),

    // Complex typed directives
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
    /// `broadcast <interval> <address> [port]` — a broadcast destination. `address` is the
    /// verbatim arg (validated to parse as an IP); `port` defaults to 123 (`NTP_PORT`).
    Broadcast { interval: i32, address: String, port: i32 },
    /// `mailonchange <address> <threshold>` — email a user when the offset on a clock step
    /// exceeds `threshold` seconds.
    MailOnChange { address: String, threshold: f64 },
    /// `tempcomp <sensor-file> <interval> (<points-file> | <T0> <k0> <k1> <k2>)` —
    /// temperature compensation. The form is chosen by argument count (3 = points file,
    /// 6 = inline coefficients).
    TempComp { sensor_file: String, interval: f64, curve: TempCompCurve },
    /// `hwtimestamp <interface> [option...]` — hardware-timestamping settings for an
    /// interface. The options are a key-value loop (`maxsamples`/`minpoll`/`maxpoll`/
    /// `minsamples` ints, `precision`/`rxcomp`/`txcomp` doubles, `rxfilter` enum,
    /// `nocrossts` flag). `maxpoll` defaults to `minpoll + 1` when not given.
    HwTimestamp {
        interface: String,
        minpoll: i32,
        maxpoll: i32,
        min_samples: i32,
        max_samples: i32,
        nocrossts: bool,
        rxfilter: HwTsRxFilter,
        precision: f64,
        tx_comp: f64,
        rx_comp: f64,
    },
    /// `refclock <driver> <parameter> [option...]` — a reference clock source and its
    /// driver-specific option loop.
    Refclock(RefclockParams),
    /// `ntstrustedcerts [<id>] <path>` — a trusted-certs file, optionally tagged with a
    /// numeric server id (1-arg form uses id 0).
    NtsTrustedCerts { id: u32, path: String },
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
    /// `bindaddress` / `bindacqaddress` / `bindcmdaddress <ip>` — the local IP a socket binds
    /// to, parsed by [`crate::util::string_to_ip`] and stored by its family (chrony keeps a
    /// v4 and a v6 slot per socket).
    BindAddress { which: BindWhich, addr: crate::util::IpAddr },
    /// `bindcmdaddress /path` — the command Unix-socket path (chrony's `/`-prefixed form). A
    /// lone `/` disables the socket, modeled as `None`.
    BindCmdPath { path: Option<String> },
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

    /// All access restrictions (`allow`, `deny`, `cmdallow`, `cmddeny`), in declaration order.
    pub fn access_restrictions(&self) -> impl Iterator<Item = (bool, bool, &crate::cmdparse::AllowDeny)> {
        self.directives.iter().filter_map(|(_, d)| match d {
            Directive::AccessRestriction { allow, cmd, spec } => Some((*allow, *cmd, spec)),
            _ => None,
        })
    }

    /// All refclock declarations, in order.
    pub fn refclocks(&self) -> impl Iterator<Item = &RefclockParams> {
        self.directives.iter().filter_map(|(_, d)| match d {
            Directive::Refclock(p) => Some(p),
            _ => None,
        })
    }

    /// All broadcast destinations, in order.
    pub fn broadcasts(&self) -> impl Iterator<Item = (i32, &str, i32)> {
        self.directives.iter().filter_map(|(_, d)| match d {
            Directive::Broadcast { interval, address, port } => Some((*interval, address.as_str(), *port)),
            _ => None,
        })
    }

    /// All source directories (`sourcedir`), in order.
    pub fn source_dirs(&self) -> impl Iterator<Item = &str> {
        self.directives.iter().filter_map(|(_, d)| match d {
            Directive::SourceDir { path } => Some(path.as_str()),
            _ => None,
        })
    }

    /// All config directories (`confdir`), in order.
    pub fn conf_dirs(&self) -> impl Iterator<Item = &[String]> {
        self.directives.iter().filter_map(|(_, d)| match d {
            Directive::ConfDir { dirs } => Some(dirs.as_slice()),
            _ => None,
        })
    }

    /// All include patterns, in order.
    pub fn includes(&self) -> impl Iterator<Item = &str> {
        self.directives.iter().filter_map(|(_, d)| match d {
            Directive::Include { pattern } => Some(pattern.as_str()),
            _ => None,
        })
    }
}
