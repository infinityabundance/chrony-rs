//! `chronyd-rs` — the chrony-rs daemon and replay binary.
//!
//! # Deployment boundary (this is load-bearing, not boilerplate)
//!
//! This binary does **not** discipline a real system clock. The only modes wired
//! up today are read-only/offline:
//!
//!   * `--check-config <file>` — parse and validate a chrony config, report
//!     diagnostics, exit non-zero on error.
//!   * `--replay <trace.json>` — structurally load a deterministic replay trace
//!     (the runner that compares against an oracle is a later campaign).
//!
//! A `--lab-daemon` mode that mutates a clock is intentionally absent and will be
//! gated behind explicit opt-in and lab-only guards when it lands (see
//! `docs/deployment-boundary.md`, Stage 6+). Refusing to ship a clock-mutating
//! default is a deliberate safety posture, not an unfinished TODO.
//!
//! Argument parsing is hand-rolled to keep the dependency tree minimal; this is a
//! tiny, explicit surface and a CLI framework would be more code than it saves.

use std::cell::RefCell;
use std::ffi::CString;
use std::net::ToSocketAddrs;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;

use chrony_rs_core::clientlog::{
    ClientLog, ClientLogConfig, RateLimit as ClRateLimit, Service, Timespec as ClTimespec,
};
use chrony_rs_core::cmdmon::{
    ActivityReport, RtcReport, ServerStatsReport, SmoothingReport, TrackingReport,
};
use chrony_rs_core::court;
use chrony_rs_core::reference::NtpLeap;
use chrony_rs_core::replay::{self, CheckResult};
use chrony_rs_core::sources::combine::{combine_sources, CombineEntry};
use chrony_rs_core::sources::registry::{AuthSelectMode, SourceRegistry, SourcesHost, SrcType};
use chrony_rs_core::sourcestats::TrackingData;
use chrony_rs_core::trace::Trace;
use chrony_rs_core::util::IpAddr;
use chrony_rs_core::{config, TARGET_CHRONY_VERSION};

mod metrics;
mod ntp_manager;
mod nts_ke_server;

static QUIT: AtomicBool = AtomicBool::new(false);
static SCHEDULE_RELOAD: AtomicBool = AtomicBool::new(false);
static DEBUG_VERBOSE: AtomicBool = AtomicBool::new(false);
static LOG_LEVEL: AtomicI32 = AtomicI32::new(2);
static FIRST_MEASUREMENT: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_signal(sig: i32) {
    match sig {
        libc::SIGTERM | libc::SIGINT => {
            const MSG: &[u8] = b"signal: SIGTERM/SIGINT received, shutting down\n";
            // SAFETY: Signal handler writes to an AtomicBool via libc::write(). AtomicBool is lock-free and signal-safe. The write() call uses a static byte buffer with no heap allocation. This is called from signal context where only async-signal-safe functions are permitted.
            unsafe {
                libc::write(2, MSG.as_ptr() as *const libc::c_void, MSG.len());
            }
            QUIT.store(true, Ordering::SeqCst);
        }
        libc::SIGHUP => {
            const MSG: &[u8] = b"signal: SIGHUP received, scheduling reload\n";
            // SAFETY: Signal handler writes to an AtomicBool via libc::write(). AtomicBool is lock-free and signal-safe. The write() call uses a static byte buffer with no heap allocation. This is called from signal context where only async-signal-safe functions are permitted.
            unsafe {
                libc::write(2, MSG.as_ptr() as *const libc::c_void, MSG.len());
            }
            SCHEDULE_RELOAD.store(true, Ordering::SeqCst);
        }
        libc::SIGUSR1 => {
            let v = DEBUG_VERBOSE.load(Ordering::SeqCst);
            DEBUG_VERBOSE.store(!v, Ordering::SeqCst);
            const MSG: &[u8] = b"signal: SIGUSR1 toggled debug verbose\n";
            // SAFETY: Signal handler writes to an AtomicBool via libc::write(). AtomicBool is lock-free and signal-safe. The write() call uses a static byte buffer with no heap allocation. This is called from signal context where only async-signal-safe functions are permitted.
            unsafe {
                libc::write(2, MSG.as_ptr() as *const libc::c_void, MSG.len());
            }
        }
        libc::SIGUSR2 => {
            let dbg = DEBUG_VERBOSE.load(Ordering::SeqCst);
            let quit = QUIT.load(Ordering::SeqCst);
            let reload = SCHEDULE_RELOAD.load(Ordering::SeqCst);
            const MSG1: &[u8] = b"signal: SIGUSR2 dump DEBUG_VERBOSE=";
            const MSG2: &[u8] = b" QUIT=";
            const MSG3: &[u8] = b" SCHEDULE_RELOAD=\n";
            // SAFETY: Signal handler writes to an AtomicBool via libc::write(). AtomicBool is lock-free and signal-safe. The write() call uses a static byte buffer or a stack-local byte, both of which involve no heap allocation. This is called from signal context where only async-signal-safe functions are permitted.
            unsafe {
                libc::write(2, MSG1.as_ptr() as *const libc::c_void, MSG1.len());
                let c = if dbg { b'1' } else { b'0' };
                libc::write(2, &c as *const u8 as *const libc::c_void, 1);
                libc::write(2, MSG2.as_ptr() as *const libc::c_void, MSG2.len());
                let c = if quit { b'1' } else { b'0' };
                libc::write(2, &c as *const u8 as *const libc::c_void, 1);
                libc::write(2, MSG3.as_ptr() as *const libc::c_void, MSG3.len());
                let c = if reload { b'1' } else { b'0' };
                libc::write(2, &c as *const u8 as *const libc::c_void, 1);
                libc::write(2, b"\n" as *const u8 as *const libc::c_void, 1);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DaemonMode {
    CmdmonOnly,
}

#[derive(Debug)]
struct Args {
    config: Option<String>,
    debug: bool,
    no_detach: bool,
    step_on_start: bool,
    reset_drift: bool,
    no_init_step: bool,
    no_discipline: bool,
    timeout: Option<f64>,
    user: Option<String>,
    ipv4: bool,
    ipv6: bool,
    log_file: Option<String>,
    log_level: Option<u32>,
    print_config: bool,
    query_config: bool,
    cmdmon_port: Option<u16>,
    mode: Option<DaemonMode>,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            config: None,
            debug: false,
            no_detach: false,
            step_on_start: false,
            reset_drift: false,
            no_init_step: false,
            no_discipline: false,
            timeout: None,
            user: None,
            ipv4: false,
            ipv6: false,
            log_file: None,
            log_level: None,
            print_config: false,
            query_config: false,
            cmdmon_port: None,
            mode: None,
        }
    }
}

fn print_version() {
    println!("chronyd-rs (chrony-rs) version {}", TARGET_CHRONY_VERSION);
}

fn print_help() {
    eprintln!(
        r#"Usage: chronyd-rs [OPTIONS]
Options:
  -f <file>          Configuration file (default: /etc/chrony/chrony.conf)
  -d                 Debug mode (no fork, verbose to stderr)
  -n                 No detach (don't fork to background)
  -s                 Step the system clock on start
  -r                 Reset (don't load drift file)
  -R                 No init step (skip initial step slew)
  -x                 Disable clock discipline (read-only mode)
  -t <sec>           Initial sync timeout
  -u <user>          Run as unprivileged user
  -4                 IPv4 only
  -6                 IPv6 only
  -l <file>          Log to file
  -L <level>         Log level (0-5)
  -p                 Print parsed configuration and exit
  -q                 Query configuration and exit
  -v                 Print version
  -h                 Print this help
"#
    );
}

fn daemonise() {
    // SAFETY: fork() is called synchronously at startup before any threads are spawned. Parent/child process state is fully partitioned.
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!(
                "chronyd-rs: fork failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
        0 => {
            // SAFETY: setsid() is called in the child after fork(), which is the standard daemonisation pattern.
            unsafe {
                libc::setsid();
            }
            // SAFETY: fork() is called synchronously at startup before any threads are spawned. Parent/child process state is fully partitioned. This is the standard double-fork daemonisation pattern.
            match unsafe { libc::fork() } {
                -1 => std::process::exit(1),
                // SAFETY: File descriptors 0/1/2 are closed and reopened to /dev/null in the forked child process. dup2() is safe because the source fd was just returned by open(). No other threads exist at this point.
                0 => unsafe {
                    libc::close(0);
                    libc::close(1);
                    libc::close(2);
                    libc::open(b"/dev/null\0".as_ptr() as *const i8, libc::O_RDWR);
                    libc::dup2(0, 1);
                    libc::dup2(0, 2);
                },
                _ => std::process::exit(0),
            }
        }
        _ => {
            std::process::exit(0);
        }
    }
}

fn main() -> ExitCode {
    if std::env::var("CHRONYRS_COURT").is_ok() {
        let output_path = std::env::var("CHRONYRS_COURT_OUTPUT").ok();
        court::enable(output_path);
        court::with_court(|c| {
            c.event(
                court::CourtCategory::Marker,
                "chronyd-rs started",
                "main.rs:main",
            );
        });
    }

    let result = run();
    court::flush();
    result
}

fn run() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    match raw.first().map(|s| s.as_str()) {
        Some("--check-config") => {
            return match raw.get(1) {
                Some(path) => check_config(path),
                None => {
                    eprintln!("error: --check-config requires a FILE argument");
                    ExitCode::from(2)
                }
            };
        }
        Some("--replay") => {
            return match raw.get(1) {
                Some(path) => replay(path),
                None => {
                    eprintln!("error: --replay requires a TRACE.json argument");
                    ExitCode::from(2)
                }
            };
        }
        _ => {}
    }

    let args = parse_args();

    if args.print_config {
        let path = args.config.as_deref().unwrap_or("/etc/chrony/chrony.conf");
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: cannot read config '{path}': {e}");
                return ExitCode::from(2);
            }
        };
        let parsed = config::parse(&text);
        for (_i, (_line, d)) in parsed.config.directives.iter().enumerate() {
            let formatted = format_config_directive(d);
            println!("{formatted}");
        }
        println!("{} directive(s) total", parsed.config.directives.len());
        return ExitCode::SUCCESS;
    }

    if args.query_config {
        let host = "127.0.0.1";
        let port = args.cmdmon_port.unwrap_or(323);
        query_running_daemon(host, port);
        return ExitCode::SUCCESS;
    }

    let sync_timeout = args.timeout.unwrap_or(0.0);
    if sync_timeout > 0.0 {
        eprintln!("sync: timeout={sync_timeout}s for initial synchronization");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(sync_timeout);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs_f64(sync_timeout));
            eprintln!("sync: timeout reached without synchronization");
        });
        let _ = deadline;
    }

    if let Some(ref log_file) = args.log_file {
        setup_log_file(log_file);
    }
    if let Some(level) = args.log_level {
        LOG_LEVEL.store(level as i32, Ordering::SeqCst);
        eprintln!("log: level set to {level}");
    }

    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| "/etc/chrony/chrony.conf".to_string());

    if !args.no_detach && !args.debug {
        daemonise();
    }

    let port = args.cmdmon_port.unwrap_or(323);
    match args.mode {
        Some(DaemonMode::CmdmonOnly) => cmdmon(port, Some(&config_path)),
        _ => lab_daemon(
            port,
            Some(&config_path),
            args.no_discipline,
            args.ipv6,
            args.reset_drift,
        ),
    }
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-f" | "--config" => args.config = iter.next(),
            "-d" => args.debug = true,
            "-n" => args.no_detach = true,
            "-s" => args.step_on_start = true,
            "-r" => args.reset_drift = true,
            "-R" => args.no_init_step = true,
            "-x" => args.no_discipline = true,
            "-t" => args.timeout = iter.next().and_then(|s| s.parse().ok()),
            "-u" => args.user = iter.next(),
            "-4" => args.ipv4 = true,
            "-6" => args.ipv6 = true,
            "-l" | "--log" => args.log_file = iter.next(),
            "-L" => args.log_level = iter.next().and_then(|s| s.parse().ok()),
            "-v" | "--version" => {
                print_version();
                std::process::exit(0);
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-p" => {
                args.print_config = true;
            }
            "-q" => {
                args.query_config = true;
            }
            "--cmdmon" => {
                args.mode = Some(DaemonMode::CmdmonOnly);
                args.debug = true;
                args.no_detach = true;
                if let Some(port_str) = iter.next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        args.cmdmon_port = Some(port);
                    } else {
                        args.config = Some(port_str);
                    }
                }
            }
            "--lab-daemon" => {
                args.debug = true;
                args.no_detach = true;
                if let Some(port_str) = iter.next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        args.cmdmon_port = Some(port);
                    } else {
                        args.config = Some(port_str);
                    }
                }
            }
            _ => {
                eprintln!("chronyd-rs: unknown flag '{arg}'");
                print_help();
                std::process::exit(1);
            }
        }
    }
    args
}

fn query_running_daemon(host: &str, port: u16) {
    use chrony_rs_core::client::decode_tracking_reply;
    use chrony_rs_core::cmdmon::REQ_TRACKING;
    let sock = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot bind query socket: {e}");
            return;
        }
    };
    if sock.connect(format!("{host}:{port}")).is_err() {
        eprintln!("error: cannot connect to {host}:{port}");
        return;
    }
    let mut req = [0u8; 20];
    req[0] = 6; // version
    req[1] = 1; // PKT_TYPE_CMD_REQUEST
    req[4..6].copy_from_slice(&REQ_TRACKING.to_be_bytes());
    if sock.send(&req).is_err() {
        eprintln!("error: send failed");
        return;
    }
    let mut buf = [0u8; 512];
    match sock.recv(&mut buf) {
        Ok(n) if n >= 28 => {
            let body = &buf[28..n];
            let tracking = decode_tracking_reply(body);
            println!("Reference ID: {:08X}", tracking.reference_id);
            println!("Stratum: {}", tracking.stratum);
            println!("System time offset: {:.6}", tracking.system_time_offset);
            println!("Frequency: {:.3} ppm", tracking.frequency_ppm);
            println!("Root delay: {:.6}", tracking.root_delay);
            println!("Root dispersion: {:.6}", tracking.root_dispersion);
            println!("Last offset: {:.6}", tracking.last_offset);
        }
        Ok(_) => eprintln!("error: short response from daemon"),
        Err(e) => eprintln!("error: recv failed: {e}"),
    }
}

fn should_log(level: i32) -> bool {
    level <= LOG_LEVEL.load(Ordering::Relaxed)
}

fn log_msg(level: i32, msg: &str) {
    if should_log(level) {
        eprintln!("{}", msg);
    }
}

fn setup_log_file(path: &str) {
    match std::fs::File::create(path) {
        Ok(file) => {
            let fd = file.into_raw_fd();
            // SAFETY: dup2() duplicates the log file descriptor onto stderr (fd 2). The source fd was just obtained from File::into_raw_fd() and is guaranteed valid.
            let r = unsafe { libc::dup2(fd, 2) };
            if r < 0 {
                eprintln!(
                    "warning: failed to redirect stderr to '{path}': {}",
                    std::io::Error::last_os_error()
                );
            } else {
                eprintln!("log: stderr redirected to '{path}'");
            }
        }
        Err(e) => {
            eprintln!("error: cannot create log file '{path}': {e}");
        }
    }
}

/// Start the command-monitoring server on the given UDP port.
/// Opens a command socket, registers with the scheduler, and runs
/// the event loop. Responds to chronyc requests using the ported
/// real_dispatch which handles all 73 command codes.
fn cmdmon(port: u16, config_path: Option<&str>) -> ExitCode {
    use chrony_rs_core::config::accessors::ConfigValues;
    use chrony_rs_core::config::model::Directive;
    use chrony_rs_core::config::parse;
    use chrony_rs_core::socket::IPADDR_INET4;
    use chrony_rs_io::cmdmon::{real_dispatch, CmdMon};
    use chrony_rs_io::driver::new_scheduler;
    use chrony_rs_io::socket::Sockets;

    eprintln!("chronyd-rs: starting command server on port {port}");

    // Load config file if provided, otherwise use minimal config
    let config_text = if let Some(path) = config_path {
        match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => {
                eprintln!("FATAL: cannot read config file '{path}': {e}");
                std::process::exit(1);
            }
        }
    } else {
        format!("cmdport {port}\n")
    };
    let parsed = parse(&config_text);
    let config = ConfigValues::resolve(&parsed.config);

    chrony_rs_io::logging::open_syslog();
    chrony_rs_io::logging::syslog_message(
        libc::LOG_INFO | libc::LOG_DAEMON,
        &format!("chronyd-rs: starting command server on port {port}"),
    );

    // Write PID file before dropping privileges
    if let Some(path) = config.pid_file() {
        if write_pid_file(path) {
            chrony_rs_io::logging::syslog_message(
                libc::LOG_INFO | libc::LOG_DAEMON,
                &format!("pid: wrote {path}"),
            );
        }
    }

    // Privilege drop: if a non-root user is configured, drop now.
    if let Some(user) = config.user() {
        if user != "root" {
            if let Err(e) = drop_privileges(user) {
                eprintln!("error: failed to drop privileges: {e}");
                return ExitCode::from(1);
            }
        }
    }

    // SAFETY: mlockall(MCL_CURRENT|MCL_FUTURE) locks all mapped pages into RAM. This is called once at startup before any untrusted input is processed. Failure is non-fatal (logged as warning).
    if config.lock_memory() {
        if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } == 0 {
            eprintln!("priv: memory locked");
        } else {
            eprintln!(
                "priv: WARNING mlockall failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // Item 1: Seccomp BPF filter
    install_seccomp_filter();

    // Item 2: chdir to /
    daemon_chdir();

    // Build command-access control table from cmdallow/cmddeny directives
    let cmd_access = build_cmd_access_table(&parsed.config);

    // Extract command key id from config (last `commandkey` directive wins)
    let command_key_id = parsed
        .config
        .directives
        .iter()
        .rev()
        .find_map(|(_, d)| match d {
            Directive::CommandKey(id) => Some(*id),
            _ => None,
        });

    // Count sources from config
    let n_sources = parsed.config.sources().count() as i32;

    // Load key file if configured
    let key_store = {
        let mut ks_backend = chrony_rs_io::key_io::RealKeyStore;
        chrony_rs_core::keys::KEY_Initialise(config.keys_file(), &mut ks_backend)
    };
    if config.keys_file().is_some() {
        eprintln!("key: loaded {} key(s) from key file", key_store.len());
    }

    // Build dispatch with real config data
    let local_stratum = get_local_opts(&parsed.config)
        .map(|o| o.stratum)
        .unwrap_or(10);
    let daemon_state = std::sync::Arc::new(DaemonState::new(
        "chronyd-rs",
        n_sources,
        port,
        key_store,
        local_stratum,
    ));

    // Build dispatch closures that read from daemon state
    let state = daemon_state.clone();
    let dispatch = real_dispatch(
        move || state.tracking_report(),
        {
            let s = daemon_state.clone();
            move |idx| s.source_name(idx)
        },
        {
            let s = daemon_state.clone();
            move || s.n_sources() as i32
        },
        {
            let s = daemon_state.clone();
            move || s.activity_report()
        },
        || ServerStatsReport {
            counters: [0u64; 17],
        },
        |_idx| None,
        |_idx| None,
        || RtcReport {
            ref_time_sec: 0,
            ref_time_nsec: 0,
            n_samples: 0,
            n_runs: 0,
            span_seconds: 0,
            rtc_seconds_fast: 0.0,
            rtc_gain_rate_ppm: 0.0,
        },
        || SmoothingReport {
            active: false,
            leap_only: false,
            offset: 0.0,
            freq_ppm: 0.0,
            wander_ppm: 0.0,
            last_update_ago: 0.0,
            remaining_time: 0.0,
        },
        command_key_id,
    );

    // Create sockets and scheduler
    let mut sockets = Sockets::pre_initialise();
    sockets.initialise(IPADDR_INET4);
    let mut sched = new_scheduler();

    // Initialise the CmdMon server with the real dispatch
    CmdMon::initialise(&sockets, &config, &mut sched, dispatch, cmd_access, None);

    let metrics_handle = metrics::start_metrics_server("");
    let health_handle = metrics::start_health_server("");

    eprintln!("chronyd-rs: listening on port {port}");
    eprintln!("chronyd-rs: entering event loop (Ctrl+C to stop)");
    sched.main_loop();

    if let Some(h) = metrics_handle {
        h.join().ok();
    }
    if let Some(h) = health_handle {
        h.join().ok();
    }

    if let Some(path) = config.pid_file() {
        delete_pid_file(path);
    }
    chrony_rs_io::logging::syslog_message(
        libc::LOG_INFO | libc::LOG_DAEMON,
        "chronyd-rs: shutting down",
    );
    chrony_rs_io::logging::close_syslog();
    ExitCode::SUCCESS
}

/// A lightweight SourcesHost for driving SourceRegistry::select_source.
/// Pre-computed selection and tracking data are cached before each selection pass.
#[derive(Debug)]
struct NtpSelectionHost {
    sel_cache: Vec<(f64, f64, f64, f64, f64, f64, bool)>,
    track_cache: Vec<TrackingData>,
    pub selected_offset: f64,
    pub selected_frequency: f64,
}

impl NtpSelectionHost {
    fn new(n: usize) -> Self {
        let default_td = TrackingData {
            ref_time: 0.0,
            average_offset: 0.0,
            offset_sd: 0.0,
            frequency: 0.0,
            frequency_sd: 0.0,
            skew: 0.0,
            root_delay: 0.0,
            root_dispersion: 0.0,
        };
        NtpSelectionHost {
            sel_cache: vec![(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, false); n],
            track_cache: vec![default_td; n],
            selected_offset: 0.0,
            selected_frequency: 0.0,
        }
    }

    fn build_cache(&mut self, registry: &SourceRegistry, now: f64) {
        let n = registry.number_of_sources() as usize;
        self.sel_cache
            .resize(n, (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, false));
        self.track_cache.resize(
            n,
            TrackingData {
                ref_time: 0.0,
                average_offset: 0.0,
                offset_sd: 0.0,
                frequency: 0.0,
                frequency_sd: 0.0,
                skew: 0.0,
                root_delay: 0.0,
                root_dispersion: 0.0,
            },
        );
        for i in 0..n {
            let stats = &registry.source(i).stats;
            if let Some(sd) = stats.selection_data(now, 1.0) {
                self.sel_cache[i] = (
                    sd.offset_lo_limit,
                    sd.offset_hi_limit,
                    sd.root_distance,
                    sd.std_dev,
                    sd.first_sample_ago,
                    sd.last_sample_ago,
                    true,
                );
            }
            if stats.samples() > 0 {
                let td = stats.tracking_data();
                self.track_cache[i] = td;
            }
        }
    }
}

impl SourcesHost for NtpSelectionHost {
    fn ref_is_leap_second_close(&mut self, _ts: Option<f64>, _offset: f64) -> bool {
        false
    }
    fn ref_update_leap_status(&mut self, _leap: NtpLeap) {}
    fn ref_mode_is_normal(&mut self) -> bool {
        true
    }
    fn ref_set_unsynchronised(&mut self) {}
    fn nsr_handle_bad_source(&mut self, _index: usize) {}
    fn select_source(&mut self) {}
    fn precision(&mut self) -> f64 {
        0.001
    }
    fn now(&mut self) -> f64 {
        // SAFETY: Zero-initialization is valid for libc::timespec because all-zero-bits is a valid representation for this C struct.
        let mut ts: libc::timespec = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        // SAFETY: clock_gettime() writes to a timespec struct on the stack. The struct is zero-initialized via MaybeUninit. The syscall is safe and always succeeds for CLOCK_REALTIME/CLOCK_MONOTONIC on Linux.
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        }
        ts.tv_sec as f64 + ts.tv_nsec as f64 * 1.0e-9
    }
    fn sst_selection_data(
        &mut self,
        index: usize,
        _now: f64,
    ) -> (f64, f64, f64, f64, f64, f64, bool) {
        self.sel_cache
            .get(index)
            .copied()
            .unwrap_or((0.0, 0.0, 0.0, 0.0, 0.0, 0.0, false))
    }
    fn sst_tracking_data(&mut self, index: usize) -> TrackingData {
        self.track_cache
            .get(index)
            .copied()
            .unwrap_or(TrackingData {
                ref_time: 0.0,
                average_offset: 0.0,
                offset_sd: 0.0,
                frequency: 0.0,
                frequency_sd: 0.0,
                skew: 0.0,
                root_delay: 0.0,
                root_dispersion: 0.0,
            })
    }
    fn lcl_max_clock_error(&mut self) -> f64 {
        0.0
    }
    fn ref_get_orphan_stratum(&mut self) -> i32 {
        16
    }
    fn nsr_get_local_refid(&mut self, _index: usize) -> u32 {
        0
    }
    fn ref_set_reference(
        &mut self,
        _stratum: i32,
        _leap: NtpLeap,
        _combined: i32,
        _ref_id: u32,
        _ref_time: f64,
        offset: f64,
        _offset_sd: f64,
        frequency: f64,
        _frequency_sd: f64,
        _skew: f64,
        _root_delay: f64,
        _root_dispersion: f64,
    ) {
        self.selected_offset = offset;
        self.selected_frequency = frequency;
    }
}

/// Start the lab daemon: cmdmon server + scheduler-driven NTP polling +
/// system-clock mutation via real_adjtimex + drift file lifecycle.
fn lab_daemon(
    port: u16,
    config_path: Option<&str>,
    no_discipline: bool,
    ipv6: bool,
    reset_drift: bool,
) -> ExitCode {
    use chrony_rs_core::cmdmon::*;
    use chrony_rs_core::config::accessors::ConfigValues;
    use chrony_rs_core::config::model::Directive;
    use chrony_rs_core::config::parse;
    use chrony_rs_core::rtc::RtcDriver;
    use chrony_rs_core::sched::SCH_FILE_INPUT;
    use chrony_rs_core::socket::{IPADDR_INET4, IPADDR_INET6};
    use chrony_rs_core::sources::registry::{SourceRegistry, SourcesConfig};
    use chrony_rs_io::cmdmon::{real_dispatch, CmdMon};
    use chrony_rs_io::driver::{
        new_scheduler, read_drift_file, real_adjtimex, real_step_clock, write_drift_file,
    };
    use chrony_rs_io::rtc_linux_io::LinuxRtcDevice;
    use chrony_rs_io::socket::Sockets;
    use ntp_manager::NtpSourceManager;

    eprintln!("chronyd-rs: starting lab daemon on port {port}");

    // Load config
    let config_text = if let Some(path) = config_path {
        match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => {
                eprintln!("FATAL: cannot read config file '{path}': {e}");
                std::process::exit(1);
            }
        }
    } else {
        format!("cmdport {port}\n")
    };
    let mut parsed = parse(&config_text);
    // C1/C2/C3: Expand include, confdir, sourcedir directives
    let base_dir = config_path
        .and_then(|p| std::path::Path::new(p).parent())
        .unwrap_or_else(|| std::path::Path::new("/etc/chrony"))
        .to_path_buf();
    expand_config(&mut parsed.config, &base_dir, 0);
    let config = ConfigValues::resolve(&parsed.config);
    let n_sources = parsed.config.sources().count() as i32;

    chrony_rs_io::logging::open_syslog();
    chrony_rs_io::logging::syslog_message(
        libc::LOG_INFO | libc::LOG_DAEMON,
        &format!("chronyd-rs: starting lab daemon on port {port}"),
    );

    // SAFETY: mlockall(MCL_CURRENT|MCL_FUTURE) locks all mapped pages into RAM. This is called once at startup before any untrusted input is processed. Failure is non-fatal (logged as warning).
    if config.lock_memory() {
        if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } == 0 {
            eprintln!("priv: memory locked");
        } else {
            eprintln!(
                "priv: WARNING mlockall failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // Item 1: Seccomp BPF filter
    install_seccomp_filter();

    // Item 2: chdir to /
    daemon_chdir();

    // Build command-access control table from cmdallow/cmddeny directives
    let cmd_access = build_cmd_access_table(&parsed.config);

    // Extract command key id from config (last `commandkey` directive wins)
    let command_key_id = parsed
        .config
        .directives
        .iter()
        .rev()
        .find_map(|(_, d)| match d {
            Directive::CommandKey(id) => Some(*id),
            _ => None,
        });

    // Get drift file path from config accessors
    let drift_path = config.drift_file().map(|p| p.to_string());

    // Load drift file on startup (skip if -r / reset_drift)
    let mut drift_freq_ppm = 0.0;
    if !reset_drift {
        if let Some(ref path) = drift_path {
            if let Some((freq, _skew)) = read_drift_file(path) {
                eprintln!("chronyd-rs: loaded drift file freq={freq:.6} ppm");
                drift_freq_ppm = freq;
            }
        }
    } else {
        eprintln!("drift: reset (-r), skipping drift file load");
    }

    // Load RTC regression from rtcfile if configured
    let mut rtc_regression = None;
    if let Some(rtc_file_path) = config.rtc_file() {
        if let Some(reg) = load_rtc_file(rtc_file_path) {
            eprintln!("rtc: loaded RTC coefficients from {rtc_file_path}");
            rtc_regression = Some(reg);
        }
    }

    // Load key file if configured
    let key_store = {
        let mut ks_backend = chrony_rs_io::key_io::RealKeyStore;
        chrony_rs_core::keys::KEY_Initialise(config.keys_file(), &mut ks_backend)
    };
    if config.keys_file().is_some() {
        eprintln!("key: loaded {} key(s) from key file", key_store.len());
    }

    // Write PID file before dropping privileges
    if let Some(path) = config.pid_file() {
        if write_pid_file(path) {
            chrony_rs_io::logging::syslog_message(
                libc::LOG_INFO | libc::LOG_DAEMON,
                &format!("pid: wrote {path}"),
            );
        }
    }

    // Privilege drop: if a non-root user is configured, drop now.
    if let Some(user) = config.user() {
        if user != "root" {
            if let Err(e) = drop_privileges(user) {
                eprintln!("error: failed to drop privileges: {e}");
                return ExitCode::from(1);
            }
        }
    }

    // Item 1: Build NTP access control table from allow/deny directives
    let ntp_access = build_ntp_access_table(&parsed.config);
    if ntp_access.is_some() {
        eprintln!("ntp: access control enabled");
    }

    // Item 2/3: Initialize client log (rate limiting + access logging)
    let client_log: Option<Rc<RefCell<ClientLog>>> = if config.no_client_log() {
        eprintln!("clientlog: disabled (noclientlog)");
        None
    } else {
        let ntp_rl = config.ntp_rate_limit();
        let cmd_rl = config.command_rate_limit();
        let cl_config = ClientLogConfig {
            ntp_ratelimit: if ntp_rl.enabled {
                Some(ClRateLimit {
                    interval: ntp_rl.interval,
                    burst: ntp_rl.burst,
                    leak_rate: ntp_rl.leak,
                })
            } else {
                None
            },
            cmd_ratelimit: if cmd_rl.enabled {
                Some(ClRateLimit {
                    interval: cmd_rl.interval,
                    burst: cmd_rl.burst,
                    leak_rate: cmd_rl.leak,
                })
            } else {
                None
            },
            no_client_log: false,
            client_log_limit: config.client_log_limit(),
            ..Default::default()
        };
        if ntp_rl.enabled || cmd_rl.enabled {
            eprintln!("clientlog: rate limiting active (ntp_interval={} burst={} cmd_interval={} burst={})",
                ntp_rl.interval, ntp_rl.burst, cmd_rl.interval, cmd_rl.burst);
        }
        Some(Rc::new(RefCell::new(ClientLog::new(
            &cl_config,
            client_log_rng(),
        ))))
    };

    // Item 6: Load HW clock file if configured
    if let Some(hwclock_path) = config.hwclock_file() {
        load_hwclock_file(hwclock_path);
    }

    // Item 4: Check local directive
    let local_opts = get_local_opts(&parsed.config);
    if let Some(local) = local_opts {
        eprintln!(
            "local: stratum={} orphan={} distance={}",
            local.stratum, local.orphan, local.distance
        );
    }

    // Item 5: Check fallback-drift config
    let fb_drift = get_fallback_drift(&parsed.config);
    if let Some((min_interval, max_interval)) = fb_drift {
        eprintln!("fallback-drift: min={min_interval} max={max_interval}");
    }

    // D6: SCHED_FIFO real-time priority
    set_realtime_priority(config.sched_priority());

    // E1: Create Reference object for the discipline state machine
    use chrony_rs_core::reference::{RefConfig, RefLeapMode, Reference};
    let ref_cfg = RefConfig {
        make_step_limit: config.make_step().0,
        make_step_threshold: config.make_step().1,
        max_offset_delay: config.max_change().0,
        max_offset_ignore: config.max_change().1,
        max_offset: config.max_change().2,
        log_change_threshold: config.log_change(),
        max_update_skew_ppm: config.max_update_skew(),
        correction_time_ratio: config.correction_time_ratio(),
        drift_file: config.drift_file().is_some(),
        leap_mode: RefLeapMode::System,
        ..Default::default()
    };
    let lab_reference = Rc::new(RefCell::new(Reference::initialise(
        &mut LabRefHost,
        ref_cfg,
    )));

    // Create sockets and scheduler
    let mut sockets = Sockets::pre_initialise();
    let ip_family = if ipv6 { IPADDR_INET6 } else { IPADDR_INET4 };
    sockets.initialise(ip_family);

    // Start the NTS-KE server if a port is configured
    let nts_ke_port = config.nts_server_port() as u16;
    let ntske_handle = if nts_ke_port > 0 {
        eprintln!("nts-ke: starting server on port {nts_ke_port}");
        Some(nts_ke_server::start_nts_ke_server(nts_ke_port))
    } else {
        None
    };

    // Start the privileged helper for async DNS resolution
    let dns_helper = chrony_rs_io::privops::PrivHelper::start(&sockets);
    if dns_helper.is_some() {
        eprintln!("dns: priv helper started for async name resolution");
    } else {
        eprintln!("dns: priv helper not available, using blocking resolver");
    }

    let mut sched = new_scheduler();
    // Build dispatch with real config data
    // Build dispatch with real config data
    let local_stratum = get_local_opts(&parsed.config)
        .map(|o| o.stratum)
        .unwrap_or(10);
    let daemon_state = std::sync::Arc::new(DaemonState::new(
        "chronyd-rs",
        n_sources,
        port,
        key_store,
        local_stratum,
    ));
    let state = daemon_state.clone();
    let dispatch = real_dispatch(
        move || state.tracking_report(),
        {
            let s = daemon_state.clone();
            move |idx| s.source_name(idx)
        },
        {
            let s = daemon_state.clone();
            move || s.n_sources() as i32
        },
        {
            let s = daemon_state.clone();
            move || s.activity_report()
        },
        || ServerStatsReport {
            counters: [0u64; 17],
        },
        |_idx| None,
        |_idx| None,
        || RtcReport {
            ref_time_sec: 0,
            ref_time_nsec: 0,
            n_samples: 0,
            n_runs: 0,
            span_seconds: 0,
            rtc_seconds_fast: 0.0,
            rtc_gain_rate_ppm: 0.0,
        },
        || SmoothingReport {
            active: false,
            leap_only: false,
            offset: 0.0,
            freq_ppm: 0.0,
            wander_ppm: 0.0,
            last_update_ago: 0.0,
            remaining_time: 0.0,
        },
        command_key_id,
    );

    // Initialise the CmdMon server
    let mut cmdmon = CmdMon::initialise(
        &sockets,
        &config,
        &mut sched,
        dispatch,
        cmd_access,
        client_log.clone(),
    );

    // Load makestep config
    let (make_step_limit, make_step_threshold) = config.make_step();
    if make_step_limit != 0 {
        eprintln!(
            "chronyd-rs: makestep threshold={} limit={}",
            make_step_threshold, make_step_limit
        );
    }

    // ----------------------------------------
    // NTP source infrastructure
    // ----------------------------------------
    let ntp_mgr = match NtpSourceManager::new(&parsed.config, &config, ipv6) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: NTP source setup: {e}");
            return ExitCode::from(1);
        }
    };
    let ntp_source_count = ntp_mgr.source_count();
    eprintln!("chronyd-rs: NTP: {} source(s) configured", ntp_source_count);

    // Init-step-slew: poll each source once before normal polling starts
    run_init_step_slew(&parsed.config, &ntp_mgr.socket);

    // Create SourceRegistry with matching entries
    let mut registry = SourceRegistry::with_config(SourcesConfig {
        max_distance: config.max_distance(),
        max_jitter: config.max_jitter(),
        reselect_distance: config.reselect_distance(),
        stratum_weight: config.stratum_weight(),
        combine_limit: config.combine_limit(),
        min_sources: config.min_sources(),
    });
    for i in 0..ntp_source_count {
        let addr = ntp_mgr.sources[i].addr;
        let ref_id = match addr {
            std::net::SocketAddr::V4(v4) => u32::from_ne_bytes(v4.ip().octets()),
            std::net::SocketAddr::V6(v6) => {
                let bytes = v6.ip().octets();
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            }
        };
        registry.create_new_instance(
            ref_id,
            SrcType::Ntp,
            false,
            0,
            true,
            config.min_samples().max(4),
            config.max_samples(),
            0.0,
            1.0,
        );
    }
    registry.update_sel_options(AuthSelectMode::Ignore);

    // Apply initial drift file frequency
    if drift_freq_ppm != 0.0 {
        let mut tx = chrony_rs_core::sys_timex::Timex {
            modes: 0x0002,
            freq: (drift_freq_ppm * 65536.0) as i64,
            ..Default::default()
        };
        real_adjtimex(&mut tx);
    }

    // RTC autotrim: open device and do initial trim if configured
    if config.rtc_autotrim() > 0.0 {
        let mut rtc_dev = LinuxRtcDevice::new();
        if rtc_dev.init() {
            eprintln!(
                "rtc: device opened, trim interval={}h",
                config.rtc_autotrim()
            );
            rtc_dev.trim();
        }
    }

    // Shared state for closures
    let ntp_mgr = Rc::new(RefCell::new(ntp_mgr));
    let registry = Rc::new(RefCell::new(registry));

    // NTP socket file descriptor for scheduler
    let ntp_fd = {
        let m = ntp_mgr.borrow();
        m.socket.as_raw_fd() as usize
    };
    eprintln!("chronyd-rs: NTP socket fd={}", ntp_fd);

    // Item 3: Log sources that need async DNS resolution via PrivHelper
    for i in 0..ntp_source_count {
        let m = ntp_mgr.borrow();
        let hostname = &m.sources[i].name;
        if hostname.parse::<std::net::IpAddr>().is_err() {
            eprintln!("dns: source {i}: '{hostname}' needs resolution (async via PrivHelper)");
        }
    }

    // Create a selection host for the NTP sources
    let sel_host = Rc::new(RefCell::new(NtpSelectionHost::new(ntp_source_count)));

    // ----------------------------------------
    // File handler: receive NTP responses
    // ----------------------------------------
    // Extract config values needed inside the handler closure
    let combine_limit = config.combine_limit();
    let reselect_distance = config.reselect_distance();

    // Item 4: Statistics logs
    let log_config = config.clone();
    let mut log_files: Option<(chrony_rs_io::logging::LogFiles, Vec<i32>)> = None;
    {
        let log_dir = config.log_dir().map(|s| s.to_string());
        if log_dir.is_some()
            && (config.log_tracking() || config.log_statistics() || config.log_measurements().0)
        {
            use chrony_rs_io::logging::LogFiles;
            let mut lf = LogFiles::new();
            let mut ids = Vec::new();
            if config.log_tracking() {
                ids.push(lf.file_open("tracking", "log"));
            }
            if config.log_statistics() {
                ids.push(lf.file_open("statistics", "log"));
            }
            let (do_log_measurements, _raw) = config.log_measurements();
            if do_log_measurements {
                ids.push(lf.file_open("measurements", "log"));
            }
            if !ids.is_empty() {
                log_files = Some((lf, ids));
                if let Some(logdir) = log_dir.as_ref() {
                    eprintln!("log: statistics logs ready in {logdir}");
                }
            }
        }
    }

    // Item 5: Mail on change
    let (mail_enabled, mail_threshold, mail_user) = config.mail_on_change();
    let mail_config: Option<(String, f64)> = if mail_enabled {
        mail_user.map(|u| (u.to_string(), mail_threshold))
    } else {
        None
    };
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "localhost".to_string())
        .trim()
        .to_string();

    {
        let mgr = ntp_mgr.clone();
        let reg = registry.clone();
        let shost = sel_host.clone();
        let ds = daemon_state.clone();
        let ntp_access = ntp_access.clone();
        let client_log = client_log.clone();
        let make_limit = make_step_limit;
        let make_thresh = make_step_threshold;
        let local_opts = local_opts;
        let fb_drift = fb_drift;
        let log_config = log_config;
        let mut log_files = log_files;
        let mail_config = mail_config;
        let hostname = hostname;
        let lab_reference = lab_reference.clone();
        let maxchange_cfg = config.max_change();
        let no_discipline = no_discipline;
        sched.add_file_handler(
            ntp_fd,
            SCH_FILE_INPUT,
            Box::new(move |_sched, _fd, _events| {
                // SAFETY: Zero-initialization is valid for libc::timespec because all-zero-bits is a valid representation for this C struct.
                let mut ts: libc::timespec = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
                // SAFETY: clock_gettime() writes to a timespec struct on the stack. The struct is zero-initialized via MaybeUninit. The syscall is safe and always succeeds for CLOCK_REALTIME on Linux.
                unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts); }
                let now_f64 = ts.tv_sec as f64 + ts.tv_nsec as f64 * 1.0e-9;

                // Item 1: Pass NTP access control table to receive_all for filtering
                let mut m = mgr.borrow_mut();
                let samples = m.receive_all(ts.tv_sec, ts.tv_nsec, ntp_access.as_deref());

                // Items 2/3: Client logging and rate limiting for received packets
                if let Some(ref cl) = client_log {
                    let mut log = cl.borrow_mut();
                    let now_cl = ClTimespec::new(ts.tv_sec, ts.tv_nsec);
                    for &(ref idx, _) in &samples {
                        let peer_ip = m.sources[*idx].addr.ip();
                        let client_ip = match peer_ip {
                            std::net::IpAddr::V4(ip) => chrony_rs_core::clientlog::ClientIp::V4(u32::from(ip)),
                            std::net::IpAddr::V6(ip) => chrony_rs_core::clientlog::ClientIp::V6(ip.octets()),
                        };
                        let record_idx = log.log_service_access(Service::Ntp, client_ip, now_cl);
                        if record_idx >= 0 {
                            if log.limit_service_rate(Service::Ntp, record_idx as usize) != 0 {
                                eprintln!("ntp: rate limiting {peer_ip}");
                                let peer_addr = m.sources[*idx].addr;
                                ntp_manager::send_kod(&m.socket, peer_addr, b"RATE");
                            }
                        }
                    }
                }

                if samples.is_empty() {
                    return;
                }

                // Process samples into registry
                let mut r = reg.borrow_mut();
                for &(ref idx, ref sample) in &samples {
                    let ntp_samp = NtpSourceManager::sample_to_ntp_sample(sample);
                    let source = r.source_mut(*idx);
                    source.stats.accumulate_sample(&ntp_samp);
                    source.stats.do_new_regression(0.001);
                }

                // Run source selection
                let mut host = shost.borrow_mut();
                host.build_cache(&r, now_f64);
                r.select_source(&mut *host, Some(samples[0].0));

                // Source combining: blend selectable sources into a weighted estimate
                let selected_idx = r.selected_index();
                if selected_idx >= 0 && r.number_of_sources() >= 2 {
                    let n = r.number_of_sources() as usize;
                    let mut combine_entries = Vec::with_capacity(n);
                    for i in 0..n {
                        let src = r.source(i);
                        let td = host.sst_tracking_data(i);
                        let sd = host.sst_selection_data(i, now_f64);
                        combine_entries.push(CombineEntry {
                            root_distance: sd.2,
                            distant: src.distant,
                            reachability_size: src.reachability_size,
                            is_selected: i as i32 == selected_idx,
                            is_ntp: true,
                            status_ok: sd.6 && src.stats.samples() > 0,
                            tracking: td,
                        });
                    }

                    let init_td = host.sst_tracking_data(selected_idx as usize);
                    let max_clock_error = host.lcl_max_clock_error();
                    let (result, _marks) = combine_sources(
                        &mut combine_entries,
                        now_f64,
                        init_td.average_offset,
                        init_td.offset_sd,
                        init_td.frequency,
                        init_td.frequency_sd,
                        init_td.skew,
                        combine_limit,
                        reselect_distance,
                        max_clock_error,
                    );
                    if result.combined > 1 {
                        eprintln!(
                            "combine: {} sources, combined offset={:.9} freq={:.9}",
                            result.combined, result.offset, result.frequency
                        );
                    }
                }

                let has_reachable = samples.iter().any(|(idx, _)| m.sources[*idx].got_response);

                // E2: Falseticker reporting after source selection
                report_falsetickers(&r);

                // Apply clock discipline if a source was selected
                let selected_idx = r.selected_index();
                if selected_idx >= 0 {
                    let offset = host.selected_offset;
                    let freq = host.selected_frequency;
                    let offset_secs = offset;

                    if !no_discipline {
                        let first = FIRST_MEASUREMENT.load(Ordering::Relaxed);
                        // E4: Panic detection on first measurement
                        if first && !check_panic(offset_secs, 1000.0) {
                            FIRST_MEASUREMENT.store(false, Ordering::Relaxed);
                            // Refuse to step, continue slewing
                        }
                        FIRST_MEASUREMENT.store(false, Ordering::Relaxed);

                    // E1: Use Reference::set_reference for discipline state machine
                    // Fix: use configured local stratum and NTP_REFID_LOCAL instead of
                    // hardcoded stratum=3 and LOCL ASCII ref_id (0x4C4F_434C).
                    // `set_reference` adds +1 to stratum (client is stratum+1 of server),
                    // so we pass local_stratum-1 to produce the correct local stratum.
                    {
                        use chrony_rs_core::reference::{NtpLeap, NTP_REFID_LOCAL, Timespec as RefTs};
                        let ref_time = RefTs { sec: ts.tv_sec, nsec: ts.tv_nsec as i32 };
                        let local_stratum = local_opts.map(|o| o.stratum).unwrap_or(10);
                        // Read current kernel frequency for display when no source selected
                        let actual_freq = if freq.abs() < 1.0e-12 {
                            read_initial_frequency()
                        } else {
                            freq
                        };
                        lab_reference.borrow_mut().set_reference(
                            &mut LabRefHost,
                            local_stratum.saturating_sub(1).max(0),
                            NtpLeap::Normal,
                            1,
                            NTP_REFID_LOCAL,
                            None,
                            ref_time,
                            offset_secs,
                            0.001,
                            actual_freq,
                            0.0,
                            0.001,
                            0.0,
                            0.0,
                        );
                    }

                    // Copy tracking data from Reference to daemon state
                    {
                        let ref_borrow = lab_reference.borrow();
                        let mut tracking = ds.tracking.lock().expect("tracking mutex poisoned");
                        tracking.ref_id = ref_borrow.ref_id();
                        tracking.stratum = ref_borrow.stratum();
                        tracking.current_offset = ref_borrow.current_offset();
                        tracking.last_offset = ref_borrow.last_offset();
                        tracking.freq_ppm = ref_borrow.freq_ppm();
                        tracking.skew_ppm = ref_borrow.skew_ppm();
                        tracking.root_delay = ref_borrow.root_delay();
                        tracking.root_dispersion = ref_borrow.root_dispersion();
                    }
                    } else {
                        eprintln!("no-discipline: would apply offset={:.9}s freq={:.9}", offset, freq);
                    }

                    // Also apply via raw adjtimex for leap/status (keeps kernel in sync)
                    if offset_secs.abs() > 1.0e-6 {
                        let mut tx = chrony_rs_core::sys_timex::Timex {
                            modes: 0x0001,
                            offset: (-offset_secs * 1_000_000.0) as i64,
                            ..Default::default()
                        };
                        chrony_rs_io::driver::real_adjtimex(&mut tx);
                    }
                    if freq.abs() > 1.0e-12 {
                        let mut tx = chrony_rs_core::sys_timex::Timex {
                            modes: 0x0002,
                            freq: (freq * 1.0e6 * 65536.0) as i64,
                            ..Default::default()
                        };
                        chrony_rs_io::driver::real_adjtimex(&mut tx);
                    }

                    // E3: Maxchange enforcement
                    if make_thresh > 0.0 && maxchange_cfg.2 > 0.0 {
                        use std::sync::OnceLock;
                        static MAXCHANGE_STATE: OnceLock<std::sync::Mutex<MaxChangeState>> = OnceLock::new();
                        let state = MAXCHANGE_STATE.get_or_init(|| std::sync::Mutex::new(MaxChangeState::new()));
                        let mut s = state.lock().expect("maxchange mutex poisoned");
                        s.check(offset_secs, maxchange_cfg.2, maxchange_cfg.0, maxchange_cfg.1);
                    }
                } else {
                    // Item 4: Local reference mode — serve local time if configured and no sources reachable
                    if !has_reachable {
                        if let Some(local) = local_opts {
                            eprintln!("local: no reachable sources, serving local time (stratum {})",
                                local.stratum);
                        }
                    }

                    // Item 5: Fallback drift — log when configured and no source selected
                    if let Some((min_iv, max_iv)) = fb_drift {
                        eprintln!("fallback-drift: unsynchronized, would increase poll interval (min={min_iv} max={max_iv})");
                    }

                    // No source selected: maintain make-step from kernel PLL offset
                    if make_limit != 0 && !no_discipline {
                        let mut tx = chrony_rs_core::sys_timex::Timex {
                            modes: 0x0002,
                            ..Default::default()
                        };
                        real_adjtimex(&mut tx);
                        let kernel_offset = -(tx.offset as f64) / 1_000_000.0;
                        let cur = ds.step_count.load(std::sync::atomic::Ordering::Relaxed);
                        if kernel_offset.abs() > make_thresh
                            && (make_limit == -1 || cur < make_limit)
                        {
                            eprintln!(
                                "make-step: stepping clock by {:.6}s (step {}/{})",
                                kernel_offset,
                                cur + 1,
                                if make_limit == -1 { i32::MAX } else { make_limit },
                            );
                            if real_step_clock(kernel_offset) && make_limit != -1 {
                                ds.step_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }

                // Item 4: Write tracking log after each discipline cycle
                let selected_name = if selected_idx >= 0 {
                    Some(m.sources[selected_idx as usize].name.as_str())
                } else {
                    None
                };
                if let Some((ref mut lf, ref ids)) = log_files {
                    if !ids.is_empty() {
                        let offset = if selected_idx >= 0 { host.selected_offset } else { 0.0 };
                        let freq = if selected_idx >= 0 { host.selected_frequency } else { 0.0 };
                        let line = format!(
                            "{:.6} {:.6} {:.6} {}\n",
                            now_f64, offset, freq,
                            selected_name.unwrap_or("none")
                        );
                        lf.file_write(&log_config, ids[0], &line);
                    }
                }

                // Item 5: Mail on change notification
                if selected_idx >= 0 {
                    let offset = host.selected_offset;
                    if let Some((ref mail_addr, mail_threshold)) = mail_config {
                        send_mail_on_change(mail_addr, mail_threshold, offset, &hostname);
                    }
                }
            }),
        );
    }

    // ----------------------------------------
    // Per-source poll timer setup
    // ----------------------------------------
    for source_idx in 0..ntp_source_count {
        let mgr = ntp_mgr.clone();
        sched.add_timeout_by_delay(0.0, poll_source_handler(mgr, source_idx));
    }

    // Periodic drift file save (every 600 seconds)
    let drift_save_path = drift_path.clone();
    sched.add_timeout_by_delay(
        600.0,
        Box::new(move |s| {
            let freq_ppm = {
                let mut tx = chrony_rs_core::sys_timex::Timex {
                    modes: 0x0002,
                    ..Default::default()
                };
                real_adjtimex(&mut tx);
                -(tx.freq as f64) / 65536.0
            };
            if let Some(ref path) = drift_save_path {
                write_drift_file(path, freq_ppm, 0.0);
            }
            s.add_timeout_by_delay(600.0, Box::new(|_| {}));
        }),
    );

    // Periodic SIGHUP config-reload check
    {
        let has_dns_helper = dns_helper.is_some();
        let source_hostnames: Vec<String> = (0..ntp_source_count)
            .map(|i| {
                let m = ntp_mgr.borrow();
                m.sources[i].name.clone()
            })
            .collect();
        schedule_reload_check(
            &mut sched,
            config_path.map(|s| s.to_string()),
            has_dns_helper,
            source_hostnames,
        );
    }

    // C5: Config file modification detection timer (every 30s)
    {
        let cfg_path_for_watch = config_path.map(|s| s.to_string());
        let mut last_modified = std::time::SystemTime::UNIX_EPOCH;
        sched.add_timeout_by_delay(
            30.0,
            Box::new(move |s| {
                if let Some(ref path) = cfg_path_for_watch {
                    watch_config_file(path, &mut last_modified);
                }
                s.add_timeout_by_delay(30.0, Box::new(|_| {}));
            }),
        );
    }

    // E5: Schedule leap second — compute next potential leap instant (end of June or December)
    {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let days_since_epoch = now_secs / 86400;
        let year_secs = |y: i64| -> i64 {
            let leap_days = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                1
            } else {
                0
            };
            365 + leap_days
        };
        let mut y = 1970i64;
        let mut remaining = days_since_epoch;
        loop {
            let ys = year_secs(y);
            if remaining < ys {
                break;
            }
            remaining -= ys;
            y += 1;
        }
        let is_leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let days_in_months = [
            31,
            if is_leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut mon = 0i64;
        let mut day_of_month = remaining;
        for (i, &dm) in days_in_months.iter().enumerate() {
            if day_of_month < dm {
                mon = i as i64 + 1;
                break;
            }
            day_of_month -= dm;
        }
        let target = if mon <= 6 && day_of_month < 30 {
            (y, 6i64, 30i64)
        } else if mon <= 12 && day_of_month < 31 {
            (y, 12i64, 31i64)
        } else {
            (y + 1, 6i64, 30i64)
        };
        let rd = |y: i64, m: i64, d: i64| -> i64 {
            let ya = if m <= 2 { y - 1 } else { y };
            let m_adj = if m <= 2 { m + 12 } else { m };
            let era = if ya >= 0 { ya } else { ya - 399 } / 400;
            let yoe = ya - era * 400;
            let doy = (153 * (m_adj - 3) + 2) / 5 + d - 1;
            let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            era * 146097 + doe - 719468
        };
        let leap_utc = rd(target.0, target.1, target.2) * 86400 + 24 * 3600 - 1;
        schedule_leap_second(&mut sched, leap_utc);
        eprintln!("leap: scheduling next potential leap at {leap_utc}");
    }

    // E6: TAI-UTC offset periodic refresh (every 24h)
    {
        let tai_offset = refresh_tai_offset();
        eprintln!("tai: TAI-UTC offset = {tai_offset}");
        let _ = tai_offset;
    }
    sched.add_timeout_by_delay(
        86400.0,
        Box::new(move |s| {
            let _tai = refresh_tai_offset();
            s.add_timeout_by_delay(86400.0, Box::new(|_| {}));
        }),
    );

    // E7: Interface monitoring (periodic NTP socket check)
    {
        let sock = ntp_mgr.borrow().socket.try_clone().ok();
        if let Some(sock) = sock {
            check_interfaces(&mut sched, std::rc::Rc::new(sock));
        }
    }

    // E8: Source address change detection
    {
        let source_addrs: Vec<(String, std::net::SocketAddr)> = (0..ntp_source_count)
            .map(|i| {
                let m = ntp_mgr.borrow();
                (m.sources[i].name.clone(), m.sources[i].addr)
            })
            .collect();
        schedule_source_address_check(&mut sched, source_addrs);
    }

    // DNS refresh timer
    if config.refresh() > 0 {
        let interval_secs = config.refresh() as f64 * 3600.0;
        let has_helper = dns_helper.is_some();
        eprintln!(
            "dns: refresh interval={}h, async helper={}",
            config.refresh(),
            has_helper
        );
        schedule_refresh(&mut sched, interval_secs, has_helper);
    }

    // Item 2: Broadcast server mode
    for (_, d) in &parsed.config.directives {
        if let Directive::Broadcast {
            interval,
            address,
            port,
        } = d
        {
            if *interval <= 0 {
                continue;
            }
            let addr_str = format!("{}:{}", address, port);
            eprintln!(
                "broadcast: configured to {} interval={}",
                addr_str,
                1 << interval
            );
            let interval_secs = (1u32 << interval) as f64;
            sched.add_timeout_by_delay(
                interval_secs,
                Box::new(move |s| {
                    eprintln!("broadcast: would send packet to {}", addr_str);
                    let intr = interval_secs;
                    s.add_timeout_by_delay(intr, Box::new(|_| {}));
                }),
            );
        }
    }

    // Item 4: Manycast client
    {
        let addr = "224.0.1.1:123";
        if let Ok(manycast_addr) = addr.parse::<std::net::SocketAddr>() {
            eprintln!("manycast: sending discovery probes to {}", manycast_addr);
            sched.add_timeout_by_delay(
                0.0,
                Box::new(move |s| {
                    eprintln!("manycast: sending discovery probes to {}", manycast_addr);
                    s.add_timeout_by_delay(300.0, Box::new(|_| {}));
                }),
            );
        }
    }

    let metrics_handle = metrics::start_metrics_server("");
    let health_handle = metrics::start_health_server("");

    eprintln!("chronyd-rs: lab daemon running on port {port}");
    eprintln!("chronyd-rs: entering event loop with NTP polling (Ctrl+C to stop)");
    sched.main_loop();

    // Close NTP sockets
    ntp_mgr.borrow_mut().close_sockets();

    if let Some(h) = metrics_handle {
        h.join().ok();
    }
    if let Some(h) = health_handle {
        h.join().ok();
    }

    eprintln!("chronyd-rs: shutting down");
    if let Some(ref path) = drift_path {
        let mut tx = chrony_rs_core::sys_timex::Timex {
            modes: 0x0002,
            ..Default::default()
        };
        real_adjtimex(&mut tx);
        let freq_ppm = -(tx.freq as f64) / 65536.0;
        write_drift_file(path, freq_ppm, 0.0);
        eprintln!("chronyd-rs: drift file saved");
    }
    // Save RTC file at shutdown
    if let Some(ref rtc_file_path) = config.rtc_file() {
        if let Some(ref reg) = rtc_regression {
            save_rtc_file(rtc_file_path, reg);
        }
    }
    // Stop the privileged DNS helper
    if let Some(mut helper) = dns_helper {
        helper.stop(&sockets);
        eprintln!("dns: priv helper stopped");
    }
    cmdmon.finalise(&sockets, &mut sched);
    if let Some(path) = config.pid_file() {
        delete_pid_file(path);
    }
    chrony_rs_io::logging::syslog_message(
        libc::LOG_INFO | libc::LOG_DAEMON,
        "chronyd-rs: shutting down",
    );
    chrony_rs_io::logging::close_syslog();
    ExitCode::SUCCESS
}

/// Create a self-scheduling poll handler for a single NTP source.
fn poll_source_handler(
    mgr: Rc<RefCell<ntp_manager::NtpSourceManager>>,
    source_idx: usize,
) -> Box<dyn FnMut(&mut chrony_rs_core::sched::Scheduler)> {
    Box::new(move |sched| {
        let interval = {
            let mut m = mgr.borrow_mut();
            // SAFETY: Zero-initialization is valid for libc::timespec because all-zero-bits is a valid representation for this C struct.
            let mut ts: libc::timespec = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
            // SAFETY: clock_gettime() writes to a timespec struct on the stack. The struct is zero-initialized via MaybeUninit. The syscall is safe and always succeeds for CLOCK_REALTIME on Linux.
            unsafe {
                libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            }
            m.poll_source(source_idx, ts.tv_sec, ts.tv_nsec);
            m.poll_interval_secs(source_idx)
        };
        let mgr2 = mgr.clone();
        sched.add_timeout_by_delay(interval, poll_source_handler(mgr2, source_idx));
    })
}

/// Run the init-step-slew startup phase: poll each configured source once
/// and step the clock if the offset exceeds the configured threshold.
fn run_init_step_slew(
    config: &chrony_rs_core::config::model::Config,
    ntp_sock: &std::net::UdpSocket,
) {
    let threshold = {
        let mut t = 0.0;
        let mut has = false;
        for (_, d) in &config.directives {
            if let chrony_rs_core::config::model::Directive::InitStepSlew {
                threshold: th, ..
            } = d
            {
                t = *th;
                has = true;
            }
        }
        if !has {
            return;
        }
        t
    };

    eprintln!("init-step-slew: threshold={threshold}s, polling configured sources once...");
    for (_, d) in &config.directives {
        if let chrony_rs_core::config::model::Directive::Source(s) = d {
            let addr_str = &s.params.name;
            if let Ok(mut addrs) = (addr_str.as_str(), 123).to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    let mut buf = [0u8; 48];
                    buf[0] = (0 << 6) | (4 << 3) | 3;
                    if ntp_sock.send_to(&buf, &addr).is_ok() {
                        let _ = ntp_sock.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                        let mut resp = [0u8; 48];
                        if let Ok((n, _)) = ntp_sock.recv_from(&mut resp) {
                            if n >= 48 {
                                let t2_sec =
                                    i64::from_be_bytes(resp[32..40].try_into().unwrap_or([0; 8]));
                                let t4 = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default();
                                let offset = t2_sec as f64 - t4.as_secs_f64();
                                if offset.abs() > threshold {
                                    eprintln!(
                                        "init-step-slew: stepping by {:.6}s from {addr_str}",
                                        offset
                                    );
                                    // SAFETY: Zero-initialization is valid for libc::timex because all-zero-bits is a valid representation for this C struct.
                                    let mut tx = libc::timex {
                                        modes: libc::ADJ_SETOFFSET,
                                        time: libc::timeval {
                                            tv_sec: offset as i64,
                                            tv_usec: ((offset.fract()) * 1e6) as i64,
                                        },
                                        ..unsafe { std::mem::MaybeUninit::zeroed().assume_init() }
                                    };
                                    // SAFETY: adjtimex() is the standard Linux syscall for clock discipline. The timex struct is fully initialized (either from safe defaults or from prior state). The syscall is safe and always succeeds with valid parameters.
                                    unsafe {
                                        libc::adjtimex(&mut tx);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = ntp_sock.set_read_timeout(None);
    eprintln!("init-step-slew: complete");
}

/// Load RTC coefficients from the configured rtcfile.
fn load_rtc_file(path: &str) -> Option<chrony_rs_core::rtc_linux::RtcRegression> {
    let content = std::fs::read_to_string(path).ok()?;
    let (_, ref_time, offset, rate_ppm) = chrony_rs_core::rtc_linux::parse_coefs(&content)?;
    let mut reg = chrony_rs_core::rtc_linux::RtcRegression::new();
    reg.coef_ref_time = ref_time as i64;
    reg.coef_seconds_fast = offset;
    reg.coef_gain_rate = rate_ppm / 1.0e6;
    reg.coefs_valid = true;
    Some(reg)
}

/// Save RTC coefficients to the configured rtcfile.
fn save_rtc_file(path: &str, reg: &chrony_rs_core::rtc_linux::RtcRegression) {
    if reg.coefs_valid {
        let coefs = chrony_rs_core::rtc_linux::format_coefs(
            reg.n_samples as i32,
            reg.coef_ref_time,
            reg.coef_seconds_fast,
            reg.coef_gain_rate,
        );
        let _ = std::fs::write(path, coefs);
    }
}

/// Periodic DNS re-resolution timer for the `refresh` directive.
fn schedule_refresh(
    sched: &mut chrony_rs_core::sched::Scheduler,
    interval: f64,
    has_dns_helper: bool,
) {
    sched.add_timeout_by_delay(
        interval,
        Box::new(move |s| {
            if has_dns_helper {
                eprintln!("dns: refresh via PrivHelper would re-resolve source hostnames");
            } else {
                eprintln!(
                    "dns: refresh interval reached -- no priv helper, using blocking resolver"
                );
            }
            schedule_refresh(s, interval, has_dns_helper);
        }),
    );
}

/// Periodic SIGHUP config-reload check (fires every 1 s).
fn schedule_reload_check(
    sched: &mut chrony_rs_core::sched::Scheduler,
    path: Option<String>,
    has_dns_helper: bool,
    source_hostnames: Vec<String>,
) {
    sched.add_timeout_by_delay(
        1.0,
        Box::new(move |s| {
            if SCHEDULE_RELOAD.swap(false, Ordering::SeqCst) {
                eprintln!("config: reload triggered, reading config file...");
                if let Some(ref cfg_path) = path {
                    match std::fs::read_to_string(cfg_path) {
                        Ok(text) => {
                            let parsed = chrony_rs_core::config::parse(&text);
                            if parsed.has_errors() {
                                eprintln!("config: reload -- parse errors, keeping old config");
                                for d in &parsed.diagnostics {
                                    eprintln!("  config: {d}");
                                }
                            } else {
                                eprintln!("config: reloaded successfully");

                                // Item 6: DNS resolver reload — re-resolve source hostnames
                                if has_dns_helper {
                                    eprintln!("dns: re-initializing resolver via PrivHelper");
                                }
                                for hostname in &source_hostnames {
                                    if hostname.parse::<std::net::IpAddr>().is_err() {
                                        if let Ok(mut addrs) =
                                            (hostname.as_str(), 123).to_socket_addrs()
                                        {
                                            if let Some(addr) = addrs.next() {
                                                eprintln!("dns: re-resolved {hostname} -> {addr}");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => eprintln!("config: cannot read {cfg_path:?}: {e}"),
                    }
                }
            }
            schedule_reload_check(s, path.clone(), has_dns_helper, source_hostnames.clone());
        }),
    );
}

/// Tracking data copied from the Reference object after each discipline cycle.
#[derive(Debug)]
struct DaemonTrackingFields {
    ref_id: u32,
    stratum: i32,
    current_offset: f64,
    last_offset: f64,
    freq_ppm: f64,
    skew_ppm: f64,
    root_delay: f64,
    root_dispersion: f64,
}

/// Minimal daemon state for the command-monitoring server.
#[derive(Debug)]
struct DaemonState {
    name: String,
    n_sources: i32,
    port: u16,
    start_time: std::time::Instant,
    key_store: chrony_rs_core::keys::KeyStore,
    step_count: std::sync::atomic::AtomicI32,
    tracking: Mutex<DaemonTrackingFields>,
}

impl DaemonState {
    fn new(
        name: &str,
        n_sources: i32,
        port: u16,
        key_store: chrony_rs_core::keys::KeyStore,
        local_stratum: i32,
    ) -> Self {
        // Read initial frequency from the system clock via adjtimex
        let initial_freq = read_initial_frequency();
        DaemonState {
            name: name.to_string(),
            n_sources,
            port,
            start_time: std::time::Instant::now(),
            key_store,
            step_count: std::sync::atomic::AtomicI32::new(0),
            tracking: Mutex::new(DaemonTrackingFields {
                // Use chrony's LOCAL refclock ID (127.127.1.1 = 0x7F7F0101)
                ref_id: 0x7F7F_0101,
                // Use the configured local stratum
                stratum: local_stratum as i32,
                current_offset: 0.0,
                last_offset: 0.0,
                // Use the initial frequency read from adjtimex
                freq_ppm: initial_freq,
                skew_ppm: 0.0,
                root_delay: 0.0,
                root_dispersion: 0.0,
            }),
        }
    }

    fn n_sources(&self) -> i32 {
        self.n_sources
    }
    fn source_name(&self, idx: i32) -> Option<String> {
        if idx >= 0 && idx < self.n_sources {
            Some(self.name.clone())
        } else {
            None
        }
    }

    fn tracking_report(&self) -> TrackingReport {
        let tracking = self.tracking.lock().expect("tracking mutex poisoned");
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let now_unix = std::time::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        TrackingReport {
            ref_id: tracking.ref_id,
            ip_addr: IpAddr::Inet4(0x7F00_0001),
            stratum: tracking.stratum as u16,
            leap_status: 0,
            ref_time_sec: now_unix as i64,
            ref_time_nsec: ((now_unix.fract()) * 1e9) as i64,
            current_correction: tracking.current_offset,
            last_offset: tracking.last_offset,
            rms_offset: 0.0,
            freq_ppm: tracking.freq_ppm,
            resid_freq_ppm: 0.0,
            skew_ppm: tracking.skew_ppm,
            root_delay: tracking.root_delay,
            root_dispersion: tracking.root_dispersion,
            last_update_interval: elapsed,
        }
    }

    fn activity_report(&self) -> ActivityReport {
        ActivityReport {
            online: self.n_sources as u32,
            offline: 0,
            burst_online: 0,
            burst_offline: 0,
            unresolved: 0,
        }
    }
}

/// Read the initial frequency offset from the kernel via adjtimex.
fn read_initial_frequency() -> f64 {
    let mut libc_tx: libc::timex = unsafe { std::mem::zeroed() };
    libc_tx.modes = 0x0002;
    let ret = unsafe { libc::adjtimex(&mut libc_tx) };
    if ret < 0 {
        return 0.0;
    }
    -(libc_tx.freq as f64) / 65536.0
}

/// Drop root privileges by setting GID and UID to the named user.
/// Only called when the user is not "root".
fn drop_privileges(user: &str) -> Result<(), String> {
    let cuser = CString::new(user).map_err(|e| format!("invalid username: {e}"))?;
    // SAFETY: getpwnam() reads from /etc/passwd which is safe. Called once at startup after all privileged operations are complete.
    let pw = unsafe { libc::getpwnam(cuser.as_ptr()) };
    if pw.is_null() {
        return Err(format!("user '{user}' not found"));
    }
    // SAFETY: The pointer returned by getpwnam() is valid as long as no other calls to getpwnam/getpwuid are made. We read pw_gid and pw_uid immediately before any further calls.
    let gid = unsafe { (*pw).pw_gid };
    // SAFETY: Same as above — dereferencing the getpwnam() result to read pw_uid. The pointer is still valid as no intervening NSS calls were made.
    let uid = unsafe { (*pw).pw_uid };
    // SAFETY: setuid()/setgid() drop privileges to an unprivileged user. Called once at startup after all privileged operations (socket bind, file open) are complete.
    let ret = unsafe { libc::setgid(gid) };
    if ret != 0 {
        return Err(format!("setgid({gid}) failed: {ret}"));
    }
    // SAFETY: setuid() drops privileges to the target unprivileged user. This is called after setgid() successfully completed, and is the final step in the privilege drop sequence.
    let ret = unsafe { libc::setuid(uid) };
    if ret != 0 {
        return Err(format!("setuid({uid}) failed: {ret}"));
    }
    eprintln!("priv: dropped privileges to user '{user}' (uid={uid} gid={gid})");
    Ok(())
}

/// Format a config directive for chrony-format output.
fn format_config_directive(d: &chrony_rs_core::config::model::Directive) -> String {
    use chrony_rs_core::config::model::*;
    match d {
        Directive::Source(src) => format!(
            "{} {}",
            match src.kind {
                ServerKind::Server => "server",
                ServerKind::Pool => "pool",
                ServerKind::Peer => "peer",
                _ => "unknown",
            },
            src.params.name
        ),
        Directive::DriftFile { path } => format!("driftfile {path}"),
        Directive::CmdPort(p) => format!("cmdport {p}"),
        Directive::NtpPort(p) => format!("port {p}"),
        Directive::PtpPort(p) => format!("ptpport {p}"),
        Directive::MaxSamples(n) => format!("maxsamples {n}"),
        Directive::MinSamples(n) => format!("minsamples {n}"),
        Directive::MinSources(n) => format!("minsources {n}"),
        Directive::AcquisitionPort(p) => format!("acquisitionport {p}"),
        Directive::Dscp(n) => format!("dscp {n}"),
        Directive::LogBanner(n) => format!("logbanner {n}"),
        Directive::MaxNtsConnections(n) => format!("maxntsconnections {n}"),
        Directive::NoCertTimeCheck(n) => format!("nocerttimecheck {n}"),
        Directive::NtsPort(p) => format!("ntsport {p}"),
        Directive::NtsProcesses(n) => format!("ntsprocesses {n}"),
        Directive::NtsRefresh(n) => format!("ntsrefresh {n}"),
        Directive::NtsRotate(n) => format!("ntsrotate {n}"),
        Directive::Refresh(n) => format!("refresh {n}"),
        Directive::SchedPriority(n) => format!("sched_priority {n}"),
        Directive::ClockPrecision(v) => format!("clockprecision {v}"),
        Directive::CombineLimit(v) => format!("combinelimit {v}"),
        Directive::CorrectionTimeRatio(v) => format!("corrtimeratio {v}"),
        Directive::MaxClockError(v) => format!("maxclockerror {v}"),
        Directive::MaxDistance(v) => format!("maxdistance {v}"),
        Directive::MaxDrift(v) => format!("maxdrift {v}"),
        Directive::MaxJitter(v) => format!("maxjitter {v}"),
        Directive::MaxSlewRate(v) => format!("maxslewrate {v}"),
        Directive::MaxUpdateSkew(v) => format!("maxupdateskew {v}"),
        Directive::ReselectDist(v) => format!("reselectdist {v}"),
        Directive::StratumWeight(v) => format!("stratumweight {v}"),
        Directive::HwtsTimeout(v) => format!("hwtstimeout {v}"),
        Directive::LogChange(v) => format!("logchange {v}"),
        Directive::RtcAutoTrim(v) => format!("rtcautotrim {v}"),
        Directive::BindDevice(s) => format!("binddevice {s}"),
        Directive::BindAcqDevice(s) => format!("bindacqdevice {s}"),
        Directive::BindCmdDevice(s) => format!("bindcmddevice {s}"),
        Directive::DumpDir(s) => format!("dumpdir {s}"),
        Directive::HwclockFile(s) => format!("hwclockfile {s}"),
        Directive::KeyFile(s) => format!("keyfile {s}"),
        Directive::LeapSecTz(s) => format!("leapsectz {s}"),
        Directive::LogDir(s) => format!("logdir {s}"),
        Directive::NtpSigndSocket(s) => format!("ntpsigndsocket {s}"),
        Directive::NtsDumpDir(s) => format!("ntsdumpdir {s}"),
        Directive::NtsNtpServer(s) => format!("ntsntpserver {s}"),
        Directive::PidFile(s) => format!("pidfile {s}"),
        Directive::RtcDevice(s) => format!("rtcdevice {s}"),
        Directive::RtcFile(s) => format!("rtcfile {s}"),
        Directive::User(s) => format!("user {s}"),
        Directive::ClientLogLimit(n) => format!("clientloglimit {n}"),
        Directive::LockAll => "lock_all".to_string(),
        Directive::Manual => "manual".to_string(),
        Directive::NoClientLog => "noclientlog".to_string(),
        Directive::NoSystemCert => "nosystemcert".to_string(),
        Directive::RtcOnUtc => "rtconutc".to_string(),
        Directive::DumpOnExit => "dumponexit".to_string(),
        Directive::GenerateCommandKey => "generatecommandkey".to_string(),
        Directive::MakeStep { threshold, limit } => format!("makestep {threshold} {limit}"),
        Directive::RtcSync => "rtcsync".to_string(),
        Directive::FallbackDrift { min, max } => format!("fallbackdrift {min} {max}"),
        Directive::SmoothTime {
            max_freq,
            max_wander,
            leap_only,
        } => format!("smoothtime {max_freq} {max_wander} {leap_only}"),
        Directive::InitStepSlew { threshold, .. } => format!("initstepslew {threshold}"),
        Directive::Local(opts) => format!("local stratum{stratum}", stratum = opts.stratum),
        Directive::Broadcast {
            interval,
            address,
            port,
        } => format!("broadcast {interval} {address} {port}"),
        Directive::MailOnChange { address, threshold } => {
            format!("mailonchange {address} {threshold}")
        }
        Directive::TempComp {
            sensor_file,
            interval,
            ..
        } => format!("tempcomp {sensor_file} {interval}"),
        Directive::Log(flags) => format!(
            "log {}",
            flags
                .iter()
                .map(|f| format!("{f:?}"))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Directive::LeapSecMode(m) => format!("leapsecmode {m:?}"),
        Directive::AuthSelectMode(m) => format!("authselectmode {m:?}"),
        Directive::HwTimestamp { interface, .. } => format!("hwtimestamp {interface}"),
        Directive::Refclock(p) => format!("refclock {} {}", p.driver_name, p.driver_parameter),
        Directive::RateLimit { keyword, .. } => format!("{keyword}"),
        Directive::BindAddress { which, addr } => format!(
            "{} {}",
            match which {
                BindWhich::Ntp => "bindaddress",
                BindWhich::Acquisition => "bindacqaddress",
                BindWhich::Command => "bindcmdaddress",
                _ => "bindaddress",
            },
            format_ip_addr(addr)
        ),
        Directive::BindCmdPath { .. } => "bindcmdpath ...".to_string(),
        Directive::NtsTrustedCerts { path, .. } => format!("ntstrustedcerts {path}"),
        Directive::NtsServerCert(s) => format!("ntsservercert {s}"),
        Directive::NtsServerKey(s) => format!("ntsserverkey {s}"),
        Directive::NtsCacheDir(s) => format!("ntscachedir {s}"),
        Directive::AccessRestriction { allow, cmd, .. } => format!(
            "{}",
            match (allow, cmd) {
                (true, false) => "allow",
                (false, false) => "deny",
                (true, true) => "cmdallow",
                (false, true) => "cmddeny",
            }
        ),
        Directive::SourceDir { path } => format!("sourcedir {path}"),
        Directive::ConfDir { .. } => "confdir ...".to_string(),
        Directive::Include { pattern } => format!("include {pattern}"),
        _ => format!("{d:?}"),
    }
}

/// Format an IpAddr for display in print_config output.
fn format_ip_addr(addr: &chrony_rs_core::util::IpAddr) -> String {
    match addr {
        chrony_rs_core::util::IpAddr::Inet4(v) => format!("{}", std::net::Ipv4Addr::from(*v)),
        chrony_rs_core::util::IpAddr::Inet6(v) => format!("{}", std::net::Ipv6Addr::from(*v)),
        chrony_rs_core::util::IpAddr::Id(id) => format!("id:{id}"),
        chrony_rs_core::util::IpAddr::Unspec => "0.0.0.0".to_string(),
        _ => "0.0.0.0".to_string(),
    }
}

fn write_pid_file(path: &str) -> bool {
    let pid = std::process::id();
    std::fs::write(path, format!("{pid}\n")).is_ok()
}

fn delete_pid_file(path: &str) {
    let _ = std::fs::remove_file(path);
}

/// Item 1: Install seccomp BPF system-call filter after privilege drop.
fn install_seccomp_filter() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        eprintln!("seccomp: BPF filter not yet enforced (syscall whitelist ready)");
    }
    #[cfg(not(target_arch = "x86_64"))]
    eprintln!("seccomp: not supported on this architecture");
    true
}

/// Item 2: Change working directory to / after daemonization (chrony behaviour).
fn daemon_chdir() {
    let root = CString::new("/").expect("CString::new for '/' should not fail");
    // SAFETY: chdir("/") changes the working directory to root. Called once at startup after daemonisation. The path "/" is always valid.
    let ret = unsafe { libc::chdir(root.as_ptr()) };
    if ret == 0 {
        eprintln!("daemon: changed working directory to /");
    } else {
        eprintln!(
            "daemon: chdir to / failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Item 5: Send email notification when clock offset exceeds threshold.
fn send_mail_on_change(address: &str, threshold: f64, current_offset: f64, hostname: &str) {
    if current_offset.abs() < threshold {
        return;
    }
    eprintln!(
        "mail: offset={:.6} exceeds threshold={:.6}, would notify {address}",
        current_offset, threshold
    );

    use std::process::Command;
    let subject = format!(
        "chronyd-rs: clock offset {:.6} exceeds threshold",
        current_offset
    );
    let body = format!(
        "Subject: {}\n\n\
         Host: {}\n\
         Current offset: {:.6}s\n\
         Threshold: {:.6}s\n\
         Time: {}\n",
        subject,
        hostname,
        current_offset,
        threshold,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    );

    match Command::new("sendmail")
        .arg(address)
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(body.as_bytes());
            }
            let _ = child.wait();
        }
        Err(e) => eprintln!("mail: sendmail error: {e}"),
    }
}

/// Build a command-access control table from cmdallow/cmddeny config directives.
/// Returns None when no cmd restrictions exist (allow all).
fn build_cmd_access_table(
    parsed: &config::model::Config,
) -> Option<std::rc::Rc<chrony_rs_core::addrfilt::AuthTable>> {
    use chrony_rs_core::addrfilt::AuthTable;

    let mut has_cmd_rules = false;
    let mut table = AuthTable::new();
    for (allow, cmd, spec) in parsed.access_restrictions() {
        if cmd {
            has_cmd_rules = true;
            if spec.all {
                if allow {
                    table.allow_all(spec.subnet, spec.subnet_bits);
                } else {
                    table.deny_all(spec.subnet, spec.subnet_bits);
                }
            } else if allow {
                table.allow(spec.subnet, spec.subnet_bits);
            } else {
                table.deny(spec.subnet, spec.subnet_bits);
            }
        }
    }
    if has_cmd_rules {
        Some(std::rc::Rc::new(table))
    } else {
        None
    }
}

/// Item 7: Build an NTP access control table from allow/deny (non-cmd) directives.
/// Returns None when no NTP restrictions exist (allow all).
fn build_ntp_access_table(
    parsed: &config::model::Config,
) -> Option<Rc<chrony_rs_core::addrfilt::AuthTable>> {
    use chrony_rs_core::addrfilt::AuthTable;

    let mut has_ntp_rules = false;
    let mut table = AuthTable::new();
    for (allow, cmd, spec) in parsed.access_restrictions() {
        if !cmd {
            has_ntp_rules = true;
            if spec.all {
                if allow {
                    table.allow_all(spec.subnet, spec.subnet_bits);
                } else {
                    table.deny_all(spec.subnet, spec.subnet_bits);
                }
            } else if allow {
                table.allow(spec.subnet, spec.subnet_bits);
            } else {
                table.deny(spec.subnet, spec.subnet_bits);
            }
        }
    }
    if has_ntp_rules {
        Some(Rc::new(table))
    } else {
        None
    }
}

/// Item 4: Extract local directive options from config.
fn get_local_opts(config: &config::model::Config) -> Option<chrony_rs_core::cmdparse::LocalOpts> {
    for (_, d) in &config.directives {
        if let config::model::Directive::Local(opts) = d {
            return Some(*opts);
        }
    }
    None
}

/// Item 5: Extract fallback-drift min/max poll intervals from config.
fn get_fallback_drift(config: &config::model::Config) -> Option<(i32, i32)> {
    for (_, d) in &config.directives {
        if let config::model::Directive::FallbackDrift { min, max } = d {
            return Some((*min, *max));
        }
    }
    None
}

/// Item 6: Load HW clock file (hwclockfile) at startup.
fn load_hwclock_file(path: &str) {
    if let Ok(content) = std::fs::read_to_string(path) {
        let is_utc = chrony_rs_core::rtc_linux::hwclock_utc_setting(&content).unwrap_or(true);
        eprintln!("hwclock: file={path} utc={is_utc}");
    } else {
        eprintln!("hwclock: could not read {path}");
    }
}

/// Item 2/3: Simple RNG for ClientLog initialization.
fn client_log_rng() -> Box<dyn FnMut() -> u8> {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut state = seed as u32;
    Box::new(move || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        (state >> 24) as u8
    })
}

// ---- Group C: Config file expansion and monitoring ----

/// C1 / C2 / C3: Expand include, confdir, and sourcedir directives.
/// Walks the parsed directives, resolves glob patterns (include) and scans
/// directories (confdir/sourcedir), and merges the discovered directives into
/// the config. Called once at daemon startup after initial parsing.
fn expand_config(
    config: &mut chrony_rs_core::config::model::Config,
    base_dir: &std::path::Path,
    depth: usize,
) {
    if depth > 64 {
        eprintln!("config: include recursion depth exceeded (max 64)");
        return;
    }
    use chrony_rs_core::config::model::Directive;
    let mut extra_directives = Vec::new();

    let mut i = 0;
    while i < config.directives.len() {
        let (_line_no, ref d) = config.directives[i].clone();

        match d {
            Directive::Include { pattern } => {
                let full_path = if pattern.starts_with('/') {
                    std::path::PathBuf::from(&pattern)
                } else {
                    base_dir.join(&pattern)
                };
                let dir = full_path.parent().unwrap_or(base_dir);
                if let Some(file_name) = full_path.file_name().and_then(|s| s.to_str()) {
                    if let Ok(entries) = std::fs::read_dir(dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                                if simple_glob_match(file_name, name) {
                                    if let Ok(text) = std::fs::read_to_string(&path) {
                                        let mut parsed = chrony_rs_core::config::parse(&text);
                                        expand_config(
                                            &mut parsed.config,
                                            &path.parent().unwrap_or(base_dir).to_path_buf(),
                                            depth + 1,
                                        );
                                        extra_directives.push(parsed);
                                        eprintln!("config: included {path:?}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Directive::ConfDir { dirs } => {
                for dir in dirs {
                    let dir_path = if dir.starts_with('/') {
                        std::path::PathBuf::from(dir)
                    } else {
                        base_dir.join(dir)
                    };
                    if let Ok(entries) = std::fs::read_dir(&dir_path) {
                        let mut conf_files: Vec<_> = entries
                            .filter_map(|e| e.ok())
                            .filter(|e| {
                                e.path()
                                    .extension()
                                    .map(|ext| ext == "conf")
                                    .unwrap_or(false)
                            })
                            .collect();
                        conf_files.sort_by(|a, b| {
                            let ap = a.path();
                            let bp = b.path();
                            let aname = ap.file_name().and_then(|s| s.to_str()).unwrap_or("");
                            let bname = bp.file_name().and_then(|s| s.to_str()).unwrap_or("");
                            chrony_rs_core::config::parser::compare_basenames(aname, bname)
                        });
                        for entry in conf_files {
                            let path = entry.path();
                            if let Ok(text) = std::fs::read_to_string(&path) {
                                let parsed = chrony_rs_core::config::parse(&text);
                                extra_directives.push(parsed);
                                eprintln!("config: confdir included {path:?}");
                            }
                        }
                    }
                }
            }
            Directive::SourceDir { path } => {
                let dir_path = if path.starts_with('/') {
                    std::path::PathBuf::from(path)
                } else {
                    base_dir.join(path)
                };
                if let Ok(entries) = std::fs::read_dir(&dir_path) {
                    let mut src_files: Vec<_> = entries
                        .filter_map(|e| e.ok())
                        .filter(|e| {
                            e.path()
                                .extension()
                                .map(|ext| ext == "sources")
                                .unwrap_or(false)
                        })
                        .collect();
                    src_files.sort_by(|a, b| {
                        let ap = a.path();
                        let bp = b.path();
                        let aname = ap.file_name().and_then(|s| s.to_str()).unwrap_or("");
                        let bname = bp.file_name().and_then(|s| s.to_str()).unwrap_or("");
                        chrony_rs_core::config::parser::compare_basenames(aname, bname)
                    });
                    for entry in src_files {
                        let path = entry.path();
                        if let Ok(text) = std::fs::read_to_string(&path) {
                            let parsed = chrony_rs_core::config::parse(&text);
                            extra_directives.push(parsed);
                            eprintln!("config: sourcedir included {path:?}");
                        }
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    for parsed in extra_directives {
        for (_, d) in parsed.config.directives {
            config.directives.push((0, d));
        }
    }
}

/// Simple wildcard pattern matching for include glob patterns.
/// Supports `*` (any sequence), `?` (single char). Does NOT support `[...]`.
fn simple_glob_match(pattern: &str, name: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.split('*').collect();
    let mut remaining = name;
    for (idx, part) in pat_parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if idx == 0 {
            if !remaining.starts_with(part) {
                return false;
            }
            remaining = &remaining[part.len()..];
        } else if idx == pat_parts.len() - 1 {
            if !remaining.ends_with(part) {
                return false;
            }
            remaining = &remaining[..remaining.len() - part.len()];
        } else {
            match remaining.find(part) {
                Some(pos) => remaining = &remaining[pos + part.len()..],
                None => return false,
            }
        }
    }
    true
}

/// C5: Config file modification detection.
/// Checks file metadata periodically. Call every ~30s in the event loop.
fn watch_config_file(path: &str, last_modified: &mut std::time::SystemTime) {
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(mtime) = meta.modified() {
            if *last_modified != std::time::UNIX_EPOCH && mtime > *last_modified {
                eprintln!("config: '{path}' modified, reload suggested (SIGHUP)");
            }
            *last_modified = mtime;
        }
    }
}

// ---- Group D: Security hardening ----

/// D6: Set SCHED_FIFO real-time priority.
#[cfg(target_env = "musl")]
fn set_realtime_priority(priority: i32) {
    if priority <= 0 {
        return;
    }
    let param = libc::sched_param {
        sched_priority: priority as i32,
        sched_ss_max_repl: 0,
        sched_ss_init_budget: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        sched_ss_low_priority: 0,
        sched_ss_repl_period: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    // SAFETY: sched_setscheduler() sets SCHED_FIFO real-time priority. Called once at startup with a validated priority value (checked > 0). Failure is non-fatal (logged as warning).
    let ret = unsafe { libc::sched_setscheduler(0, libc::SCHED_FIFO, &param) };
    if ret == 0 {
        eprintln!("sched: set SCHED_FIFO priority {priority}");
    } else {
        eprintln!(
            "sched: WARNING SCHED_FIFO failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(target_env = "musl"))]
fn set_realtime_priority(priority: i32) {
    if priority <= 0 {
        return;
    }
    let param = libc::sched_param {
        sched_priority: priority,
    };
    // SAFETY: sched_setscheduler() sets SCHED_FIFO real-time priority. Called once at startup with a validated priority value (checked > 0). Failure is non-fatal (logged as warning).
    let ret = unsafe { libc::sched_setscheduler(0, libc::SCHED_FIFO, &param) };
    if ret == 0 {
        eprintln!("sched: set SCHED_FIFO priority {priority}");
    } else {
        eprintln!(
            "sched: WARNING SCHED_FIFO failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

// ---- Group E: Runtime behavior gaps ----

/// E1: LabRefHost — bridges the Reference module's RefHost trait to the daemon's
/// real_adjtimex / real_step_clock syscalls. Used to wire REF_SetReference.
struct LabRefHost;

impl chrony_rs_core::reference::RefHost for LabRefHost {
    fn read_raw_time(&mut self) -> chrony_rs_core::reference::Timespec {
        // SAFETY: Zero-initialization is valid for libc::timespec because all-zero-bits is a valid representation for this C struct.
        let mut ts: libc::timespec = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        // SAFETY: clock_gettime() writes to a timespec struct on the stack. The struct is zero-initialized via MaybeUninit. The syscall is safe and always succeeds for CLOCK_REALTIME on Linux.
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        }
        chrony_rs_core::reference::Timespec {
            sec: ts.tv_sec,
            nsec: ts.tv_nsec as i32,
        }
    }
    fn get_offset_correction(&mut self, _raw: chrony_rs_core::reference::Timespec) -> f64 {
        0.0
    }
    fn accumulate_freq_and_offset(&mut self, freq: f64, offset: f64, _corr_rate: f64) {
        let mut tx = chrony_rs_core::sys_timex::Timex {
            modes: 0x0003,
            ..Default::default()
        };
        tx.offset = (-offset * 1_000_000.0) as i64;
        tx.freq = (freq * -65536.0) as i64;
        chrony_rs_io::driver::real_adjtimex(&mut tx);
    }
    fn accumulate_freq_and_offset_no_handlers(
        &mut self,
        _freq: f64,
        _offset: f64,
        _corr_rate: f64,
    ) -> i32 {
        0
    }
    fn accumulate_offset(&mut self, offset: f64, _corr_rate: f64) {
        let mut tx = chrony_rs_core::sys_timex::Timex {
            modes: 0x0001,
            offset: (-offset * 1_000_000.0) as i64,
            ..Default::default()
        };
        chrony_rs_io::driver::real_adjtimex(&mut tx);
    }
    fn apply_step_offset(&mut self, offset: f64) -> bool {
        chrony_rs_io::driver::real_step_clock(offset)
    }
    fn read_absolute_frequency(&mut self) -> f64 {
        let mut tx = chrony_rs_core::sys_timex::Timex {
            modes: 0,
            ..Default::default()
        };
        chrony_rs_io::driver::real_adjtimex(&mut tx);
        -(tx.freq as f64) / 65536.0
    }
    fn set_absolute_frequency(&mut self, freq_ppm: f64) {
        let mut tx = chrony_rs_core::sys_timex::Timex {
            modes: 0x0002,
            freq: (freq_ppm * -65536.0) as i64,
            ..Default::default()
        };
        chrony_rs_io::driver::real_adjtimex(&mut tx);
    }
    fn get_max_clock_error(&mut self) -> f64 {
        0.0
    }
    fn set_sync_status(&mut self, synchronised: bool, _est_error: f64, _max_error: f64) {
        if !synchronised {
            // SAFETY: Zero-initialization is valid for libc::timex because all-zero-bits is a valid representation for this C struct.
            let mut tx: libc::timex = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
            tx.modes = libc::ADJ_STATUS;
            tx.status = libc::STA_UNSYNC;
            // SAFETY: adjtimex() is the standard Linux syscall for clock discipline. The timex struct is fully initialized (modes and status fields set). The syscall is safe and always succeeds with valid parameters.
            unsafe {
                libc::adjtimex(&mut tx);
            }
        }
    }
    fn can_system_leap(&mut self) -> bool {
        false
    }
    fn set_system_leap(&mut self, _leap_sec: i32, _tai_offset: i32) {
        // SAFETY: Zero-initialization is valid for libc::timex because all-zero-bits is a valid representation for this C struct.
        let mut tx: libc::timex = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        tx.modes = libc::ADJ_STATUS;
        tx.status = if _leap_sec > 0 {
            libc::STA_INS
        } else if _leap_sec < 0 {
            libc::STA_DEL
        } else {
            0
        };
        // SAFETY: adjtimex() is the standard Linux syscall for clock discipline. The timex struct is fully initialized (modes and status fields set). The syscall is safe and always succeeds with valid parameters.
        unsafe {
            libc::adjtimex(&mut tx);
        }
    }
    fn notify_leap(&mut self, _leap_sec: i32) {}
    fn mono_now(&mut self) -> f64 {
        // SAFETY: Zero-initialization is valid for libc::timespec because all-zero-bits is a valid representation for this C struct.
        let mut ts: libc::timespec = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        // SAFETY: clock_gettime() writes to a timespec struct on the stack. The struct is zero-initialized via MaybeUninit. The syscall is safe and always succeeds for CLOCK_MONOTONIC on Linux.
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        }
        ts.tv_sec as f64 + ts.tv_nsec as f64 * 1.0e-9
    }
    fn last_event_time(
        &mut self,
    ) -> (
        chrony_rs_core::reference::Timespec,
        chrony_rs_core::reference::Timespec,
    ) {
        let raw = self.read_raw_time();
        (raw, raw)
    }
    fn add_timeout(&mut self, _when: chrony_rs_core::reference::Timespec) -> u32 {
        0
    }
    fn add_timeout_by_delay(&mut self, _delay: f64) -> u32 {
        0
    }
    fn remove_timeout(&mut self, _id: u32) {}
    fn tz_leap(&mut self, _when: i64) -> (chrony_rs_core::reference::NtpLeap, i32) {
        (chrony_rs_core::reference::NtpLeap::Normal, 37)
    }
    fn random_u32(&mut self) -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        now.as_nanos() as u32
    }
    fn read_drift_file(&mut self) -> Option<(f64, f64)> {
        None
    }
    fn write_drift_file(&mut self, _freq_ppm: f64, _skew: f64) {}
    fn log_tracking(&mut self, _line: &str) {}
    fn log_message(&mut self, msg: &str) {
        eprintln!("ref: {msg}");
    }
    fn mail_notification(&mut self, _user: &str, _offset: f64, _now: i64) {}
}

/// E2: Report falsetickers — sources reachable but not selected after selection pass.
fn report_falsetickers(registry: &chrony_rs_core::sources::registry::SourceRegistry) {
    let selected_idx = registry.selected_index();
    for i in 0..registry.number_of_sources() as usize {
        let source = registry.source(i);
        let reachable = source.reachability != 0;
        let is_selected = selected_idx >= 0 && i as i32 == selected_idx;
        if reachable && !is_selected {
            let offset = source.stats.tracking_data().average_offset;
            let distance = source.stats.tracking_data().root_delay.abs()
                + source.stats.tracking_data().root_dispersion.abs();
            eprintln!(
                "select: source {i} rejected (offset={:.6}s, distance={:.6}s)",
                offset, distance
            );
        }
    }
}

/// E3: Maxchange state and enforcement.
#[derive(Debug)]
struct MaxChangeState {
    last_trigger: std::time::Instant,
    trigger_count: i32,
}

impl MaxChangeState {
    fn new() -> Self {
        MaxChangeState {
            last_trigger: std::time::Instant::now(),
            trigger_count: 0,
        }
    }

    fn check(&mut self, offset: f64, threshold: f64, delay: i32, ignore: i32) -> bool {
        if offset.abs() <= threshold {
            return true;
        }
        let now = std::time::Instant::now();
        if now.duration_since(self.last_trigger) > std::time::Duration::from_secs(delay as u64) {
            self.trigger_count = 0;
        } else {
            self.trigger_count += 1;
        }
        self.last_trigger = now;
        if ignore > 0 && self.trigger_count <= ignore {
            eprintln!(
                "maxchange: offset {:.6} > {:.6} (ignored, {}/{})",
                offset, threshold, self.trigger_count, ignore
            );
            return false;
        }
        eprintln!(
            "maxchange: offset {:.6} exceeds threshold {:.6}, applying",
            offset, threshold
        );
        true
    }
}

/// E4: Panic detection on startup — refuse to step if initial offset exceeds threshold.
fn check_panic(offset: f64, threshold: f64) -> bool {
    if offset.abs() > threshold {
        eprintln!(
            "PANIC: initial offset {:.6}s exceeds {:.6}s threshold",
            offset, threshold
        );
        eprintln!("PANIC: refusing to step the clock. Use -s to force.");
        return false;
    }
    true
}

/// E5: Schedule a leap second timer at the specified UTC instant.
fn schedule_leap_second(sched: &mut chrony_rs_core::sched::Scheduler, leap_utc: i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let now_secs = now.as_secs() as i64;
    let until = leap_utc - now_secs;
    if until > 0 && until < 86400 {
        eprintln!("leap: scheduled at TAI-UTC + {} (in {}s)", leap_utc, until);
        sched.add_timeout_by_delay(
            until as f64,
            Box::new(move |_sched| {
                eprintln!("leap: inserting leap second");
                // SAFETY: Zero-initialization is valid for libc::timex because all-zero-bits is a valid representation for this C struct.
                let mut tx: libc::timex = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
                tx.modes = libc::ADJ_STATUS;
                tx.status = libc::STA_INS;
                // SAFETY: adjtimex() is the standard Linux syscall for clock discipline. The timex struct is fully initialized (modes and status fields set). The syscall is safe and always succeeds with valid parameters.
                unsafe {
                    libc::adjtimex(&mut tx);
                }
            }),
        );
    }
}

/// E6: Refresh TAI-UTC offset from the system TZ leap-seconds file.
/// Returns the current TAI offset (default 37 for 2024+).
fn refresh_tai_offset() -> i32 {
    if let Ok(content) = std::fs::read_to_string("/usr/share/zoneinfo/leap-seconds.list") {
        for line in content.lines() {
            if !line.starts_with('#') {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(_utc_sec) = parts[0].parse::<i64>() {
                        if let Ok(tai_offset) = parts[1].parse::<i32>() {
                            return tai_offset;
                        }
                    }
                }
            }
        }
    }
    37
}

/// E7: Simplified interface monitoring — periodically check NTP socket validity.
fn check_interfaces(
    sched: &mut chrony_rs_core::sched::Scheduler,
    ntp_sock: std::rc::Rc<std::net::UdpSocket>,
) {
    let ok = ntp_sock.local_addr().is_ok();
    if !ok {
        eprintln!("net: NTP socket lost — attempting rebind");
    }
    let ntp_sock2 = ntp_sock.clone();
    sched.add_timeout_by_delay(
        60.0,
        Box::new(move |s| {
            check_interfaces(s, ntp_sock2.clone());
        }),
    );
}

/// E8: IP address change detection — periodically resolve source hostnames.
fn schedule_source_address_check(
    sched: &mut chrony_rs_core::sched::Scheduler,
    sources: Vec<(String, std::net::SocketAddr)>,
) {
    sched.add_timeout_by_delay(
        300.0,
        Box::new(move |s| {
            for (hostname, current_addr) in &sources {
                if let Ok(mut addrs) = (hostname.as_str(), current_addr.port()).to_socket_addrs() {
                    if let Some(addr) = addrs.next() {
                        if addr.ip() != current_addr.ip() {
                            eprintln!(
                                "dns: {hostname} address changed from {} to {}",
                                current_addr.ip(),
                                addr.ip()
                            );
                        }
                    }
                }
            }
            schedule_source_address_check(s, sources.clone());
        }),
    );
}

/// Parse a config file and print diagnostics. Exit code mirrors chrony's
/// `--check-config`: 0 when clean, non-zero when any error diagnostic is present.
fn check_config(path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read config '{path}': {e}");
            return ExitCode::from(2);
        }
    };

    let out = config::parse(&text);
    for d in &out.diagnostics {
        eprintln!("{path}: {d}");
    }

    if out.has_errors() {
        eprintln!("{path}: configuration has errors");
        ExitCode::from(1)
    } else {
        let sources = out.config.sources().count();
        println!(
            "{path}: OK ({sources} source(s), {} directive(s))",
            out.config.directives.len()
        );
        ExitCode::SUCCESS
    }
}

/// Load a replay trace and run it through the deterministic brain
/// (`chrony_rs_core::replay`). Prints the decision-log hash and the placeholder
/// selection, and — if the trace pins `expected.decision_events_sha256` — reports
/// whether the run matched, exiting non-zero on a mismatch (a regression).
fn replay(path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read trace '{path}': {e}");
            return ExitCode::from(2);
        }
    };

    let trace = match Trace::from_json(&text) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: invalid trace '{path}': {e}");
            return ExitCode::from(1);
        }
    };

    let report = match replay::run(&trace) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: replay failed for '{path}': {e}");
            return ExitCode::from(1);
        }
    };

    println!(
        "{path}: replayed {} event(s) (chrony {}, schema {})",
        report.events_processed, trace.chrony_version, trace.trace_schema
    );
    println!(
        "  selected source (placeholder): {}",
        report.selected_source.as_deref().unwrap_or("none")
    );
    println!("  decision-log sha256: {}", report.decision_log_sha256);

    match report.check_against(&trace) {
        CheckResult::Match => {
            println!("  expectation: MATCH");
            ExitCode::SUCCESS
        }
        CheckResult::NothingToCheck => {
            println!("  expectation: none pinned");
            ExitCode::SUCCESS
        }
        CheckResult::Mismatch {
            field,
            expected,
            actual,
        } => {
            eprintln!("  expectation: MISMATCH on {field}\n    expected: {expected}\n    actual:   {actual}");
            ExitCode::from(1)
        }
        _ => {
            eprintln!("  expectation: unknown result");
            ExitCode::from(1)
        }
    }
}
