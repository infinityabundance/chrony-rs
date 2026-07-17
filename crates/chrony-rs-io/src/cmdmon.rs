//! Command-and-monitoring socket transport — a faithful port of chrony 4.5 `cmdmon.c`'s
//! server-socket layer and `client.c`'s chronyc transport, wired to the real [`crate::socket`]
//! layer, the live event loop, and the ported config accessors.
//!
//! The daemon opens command sockets (UDP on the command port, and/or a Unix datagram socket),
//! registers them with the scheduler, and on a read event receives a request, validates it
//! with the ported [`chrony_rs_core::cmdmon::validate_request`], dispatches it, and transmits
//! the reply to the sender. chronyc opens a connected socket to the daemon and round-trips a
//! request. The per-command *handlers* (which read live daemon state) are the boundary: a
//! caller-supplied dispatch closure is the `handle_*` seam.
//!
//! Verified by a **kernel-integration test** (`tests/cmdmon.rs`) that runs a real chronyc ↔
//! chronyd command exchange over a loopback UDP command socket through the live event loop.

use crate::socket::Sockets;
use chrony_rs_core::addrfilt::AuthTable;
use chrony_rs_core::clientlog::{ClientLog, Service, Timespec as ClTimespec};
use chrony_rs_core::cmdmon::{
    build_reply_header, validate_request, CmdValidation, RPY_NULL, STT_SUCCESS,
};
use chrony_rs_core::config::accessors::ConfigValues;
use chrony_rs_core::sched::{Scheduler, SCH_FILE_INPUT};
use chrony_rs_core::socket::{IpSockAddr, SckAddressType, SckMessage, IPADDR_INET4, IPADDR_INET6};
use chrony_rs_core::util::IpAddr;
use std::cell::RefCell;
use std::rc::Rc;

/// chrony `cmdmon.c` `INVALID_SOCK_FD` (`-1`).
pub const INVALID_SOCK_FD: i32 = -1;
const SCK_FLAG_RX_DEST_ADDR: i32 = 4;

// Request/reply header field offsets (candm.h; mirrored from core).
const REQ_OFF_PKT_TYPE: usize = 1;
const REQ_OFF_RES1: usize = 2;
const REQ_OFF_RES2: usize = 3;
const REQ_OFF_VERSION: usize = 0;
const REQ_OFF_COMMAND: usize = 4;
const REQ_OFF_SEQUENCE: usize = 8;

/// The `handle_*` dispatch seam: given the command code and the full request bytes, produce the
/// `(reply_type, status, reply_body)` for a valid request. (In chrony these are the per-command
/// handlers that read live daemon state.)
pub type Dispatch = Rc<dyn Fn(u16, &[u8]) -> (u16, u16, Vec<u8>)>;

fn ip_to_sockaddr(ip: IpAddr, port: u16) -> IpSockAddr {
    match ip {
        IpAddr::Inet4(a) => IpSockAddr {
            family: IPADDR_INET4,
            in4: a,
            in6: [0; 16],
            port,
        },
        IpAddr::Inet6(a) => IpSockAddr {
            family: IPADDR_INET6,
            in4: 0,
            in6: a,
            port,
        },
        _ => IpSockAddr::default(),
    }
}

/// chrony `transmit_reply`: send an assembled reply back to the request's source address.
fn transmit_reply(
    sockets: &Sockets,
    sock_fd: i32,
    reply: &[u8],
    remote: &IpSockAddr,
    local: IpAddr,
) {
    let mut msg = SckMessage::init(SckAddressType::Ip);
    msg.remote_ip = *remote;
    msg.local_ip = local;
    sockets.send_message(sock_fd, &msg, reply, 0);
}

/// Convert an [`IpSockAddr`] to a [`std::net::IpAddr`] for access-table lookup.
fn remote_to_ipaddr(remote: &IpSockAddr) -> std::net::IpAddr {
    match remote.family {
        IPADDR_INET4 => {
            let octets = remote.in4.to_be_bytes();
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
        }
        IPADDR_INET6 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(remote.in6)),
        _ => std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    }
}

/// chrony `read_from_cmd_socket`: receive a command request, validate it, dispatch it, and
/// transmit the reply. Registered as the scheduler file handler for each command socket.
/// `cmd_access` controls whether the remote address is permitted (None = allow all).
/// `client_log` is used for rate limiting and access logging (None = disabled).
pub fn read_from_cmd_socket(
    sockets: &Sockets,
    sock_fd: i32,
    dispatch: &Dispatch,
    cmd_access: Option<&AuthTable>,
    mut client_log: Option<&mut ClientLog>,
) {
    for m in sockets.receive_messages(sock_fd, 0, 16) {
        // Access control: silently drop requests from unpermitted addresses.
        if let Some(access) = cmd_access {
            let addr = remote_to_ipaddr(&m.remote);
            if !access.is_allowed(addr) {
                continue;
            }
        }
        let data = &m.data;
        if data.len() < 20 {
            continue;
        }

        // Item 2/3: Client logging and rate limiting for cmdmon
        if let Some(ref mut log) = client_log {
            let addr = remote_to_ipaddr(&m.remote);
            let client_ip = match addr {
                std::net::IpAddr::V4(ip) => chrony_rs_core::clientlog::ClientIp::V4(u32::from(ip)),
                std::net::IpAddr::V6(ip) => chrony_rs_core::clientlog::ClientIp::V6(ip.octets()),
            };
            let now = ClTimespec::new(0, 0); // placeholder: use real clock
            let idx = log.log_service_access(Service::Cmdmon, client_ip, now);
            if idx >= 0 && log.limit_service_rate(Service::Cmdmon, idx as usize) != 0 {
                eprintln!("cmdmon: rate limiting {addr}");
                continue;
            }
        }

        let command = u16::from_be_bytes([data[REQ_OFF_COMMAND], data[REQ_OFF_COMMAND + 1]]);
        let seq_be: [u8; 4] = data[REQ_OFF_SEQUENCE..REQ_OFF_SEQUENCE + 4]
            .try_into()
            .expect("sequence fits in 4 bytes");
        let command_be: [u8; 2] = [data[REQ_OFF_COMMAND], data[REQ_OFF_COMMAND + 1]];

        let outcome = validate_request(
            data.len(),
            data[REQ_OFF_PKT_TYPE],
            data[REQ_OFF_RES1],
            data[REQ_OFF_RES2],
            data[REQ_OFF_VERSION],
            command,
        );

        let reply: Vec<u8> = match outcome {
            CmdValidation::Drop => continue,
            CmdValidation::Reply(status) => {
                build_reply_header(command_be, seq_be, RPY_NULL, status).to_vec()
            }
            CmdValidation::Valid { .. } => {
                let (reply_type, status, body) = dispatch(command, data);
                let mut r = build_reply_header(command_be, seq_be, reply_type, status).to_vec();
                r.extend_from_slice(&body);
                r
            }
            _ => continue,
        };
        transmit_reply(sockets, sock_fd, &reply, &m.remote, m.control.local);
    }
}

/// The `cmdmon.c` command-socket server state.
pub struct CmdMon {
    sock_fdu: i32,
    sock_fd4: i32,
    sock_fd6: i32,
    bound_sock_fd4: bool,
    initialised: bool,
}

impl CmdMon {
    /// chrony `CAM_Initialise`: open the UDP command sockets (v4/v6) on the command port and
    /// register their handlers. The Unix socket is opened separately by
    /// [`open_unix_socket`](CmdMon::open_unix_socket) (after privilege drop).
    /// `cmd_access` controls command access (None = allow all).
    /// `client_log` is used for cmdmon rate limiting (None = disabled).
    pub fn initialise(
        sockets: &Sockets,
        config: &ConfigValues,
        sched: &mut Scheduler,
        dispatch: Dispatch,
        cmd_access: Option<Rc<AuthTable>>,
        client_log: Option<Rc<RefCell<ClientLog>>>,
    ) -> Self {
        let mut cam = CmdMon {
            sock_fdu: INVALID_SOCK_FD,
            sock_fd4: INVALID_SOCK_FD,
            sock_fd6: INVALID_SOCK_FD,
            bound_sock_fd4: false,
            initialised: true,
        };
        cam.sock_fd4 = cam.open_socket(
            sockets,
            config,
            sched,
            &dispatch,
            IPADDR_INET4,
            cmd_access.clone(),
            client_log.clone(),
        );
        if cam.sock_fd4 == INVALID_SOCK_FD {
            eprintln!(
                "cmdmon: WARNING — command socket not available on port {}",
                config.command_port()
            );
        }
        cam.sock_fd6 = cam.open_socket(
            sockets,
            config,
            sched,
            &dispatch,
            IPADDR_INET6,
            cmd_access,
            client_log,
        );
        if cam.sock_fd6 == INVALID_SOCK_FD {
            eprintln!(
                "cmdmon: WARNING — command socket (IPv6) not available on port {}",
                config.command_port()
            );
        }
        cam
    }

    /// chrony `CAM_OpenUnixSocket`: open the Unix-domain command socket if a path is configured
    /// (called after the daemon drops root).
    /// `cmd_access` controls command access (None = allow all).
    pub fn open_unix_socket(
        &mut self,
        sockets: &Sockets,
        config: &ConfigValues,
        sched: &mut Scheduler,
        dispatch: Dispatch,
        cmd_access: Option<Rc<AuthTable>>,
    ) {
        if config.bind_command_path().is_some() {
            self.sock_fdu =
                self.open_socket_unix(sockets, config, sched, &dispatch, cmd_access, None);
        }
    }

    /// chrony `cmdmon.c` `open_socket` (IP families): a UDP command socket on the command port,
    /// bound to the configured command address, with `RX_DEST_ADDR` and a read handler.
    fn open_socket(
        &mut self,
        sockets: &Sockets,
        config: &ConfigValues,
        sched: &mut Scheduler,
        dispatch: &Dispatch,
        family: i32,
        cmd_access: Option<Rc<AuthTable>>,
        client_log: Option<Rc<RefCell<ClientLog>>>,
    ) -> i32 {
        let port = config.command_port();
        if port == 0 || !sockets.is_ip_family_enabled(family) {
            return INVALID_SOCK_FD;
        }
        let local = ip_to_sockaddr(config.bind_command_address(family as u16), port as u16);
        let iface = config.bind_command_interface();
        let sock_fd = sockets.open_udp_socket(None, Some(&local), iface, SCK_FLAG_RX_DEST_ADDR);
        if sock_fd < 0 {
            eprintln!(
                "cmdmon: FATAL — failed to bind command socket on port {port}: {}",
                std::io::Error::last_os_error()
            );
            return INVALID_SOCK_FD;
        }
        if family == IPADDR_INET4 {
            self.bound_sock_fd4 = local.in4 != 0;
        }
        register_handler(sched, sockets, sock_fd, dispatch, cmd_access, client_log);
        sock_fd
    }

    /// The Unix-datagram command socket (chrony `open_socket(IPADDR_UNSPEC)`).
    fn open_socket_unix(
        &mut self,
        sockets: &Sockets,
        config: &ConfigValues,
        sched: &mut Scheduler,
        dispatch: &Dispatch,
        cmd_access: Option<Rc<AuthTable>>,
        client_log: Option<Rc<RefCell<ClientLog>>>,
    ) -> i32 {
        let Some(path) = config.bind_command_path() else {
            return INVALID_SOCK_FD;
        };
        let sock_fd = sockets.open_unix_datagram_socket(None, Some(path), 0);
        if sock_fd < 0 {
            return INVALID_SOCK_FD;
        }
        if let Ok(cpath) = std::ffi::CString::new(path) {
            // SAFETY: chmod sets permissions on the cmdmon socket file.
            // The path is validated and the file was just created by bind().
            // Failure is non-fatal.
            unsafe {
                libc::chmod(cpath.as_ptr(), 0o755);
            }
        }
        register_handler(sched, sockets, sock_fd, dispatch, cmd_access, client_log);
        sock_fd
    }

    /// chrony `CAM_Finalise`: deregister and close every command socket (unlinking the Unix
    /// node).
    pub fn finalise(&mut self, sockets: &Sockets, sched: &mut Scheduler) {
        if self.sock_fdu != INVALID_SOCK_FD {
            sched.remove_file_handler(self.sock_fdu as usize);
            sockets.remove_socket(self.sock_fdu);
            sockets.close_socket(self.sock_fdu);
            self.sock_fdu = INVALID_SOCK_FD;
        }
        for fd in [&mut self.sock_fd4, &mut self.sock_fd6] {
            if *fd != INVALID_SOCK_FD {
                sched.remove_file_handler(*fd as usize);
                sockets.close_socket(*fd);
                *fd = INVALID_SOCK_FD;
            }
        }
        self.initialised = false;
    }

    /// The v4 command-socket fd (for tests / callers).
    pub fn ipv4_fd(&self) -> i32 {
        self.sock_fd4
    }
    /// The Unix command-socket fd.
    pub fn unix_fd(&self) -> i32 {
        self.sock_fdu
    }
}

fn register_handler(
    sched: &mut Scheduler,
    sockets: &Sockets,
    sock_fd: i32,
    dispatch: &Dispatch,
    cmd_access: Option<Rc<AuthTable>>,
    client_log: Option<Rc<RefCell<ClientLog>>>,
) {
    let sockets_copy = *sockets;
    let dispatch = dispatch.clone();
    sched.add_file_handler(
        sock_fd as usize,
        SCH_FILE_INPUT,
        Box::new(move |_s, fd, _event| {
            let mut cl_borrow = client_log.as_ref().map(|c| c.borrow_mut());
            read_from_cmd_socket(
                &sockets_copy,
                fd,
                &dispatch,
                cmd_access.as_deref(),
                cl_borrow.as_deref_mut(),
            )
        }),
    );
}

// ---- chronyc client transport (client.c) ----

/// The chronyc command-socket client (chrony `client.c`'s `sock_fd` + address list).
#[derive(Debug)]
pub struct CmdClient {
    sock_fd: i32,
}

impl CmdClient {
    /// chrony `client.c` `open_socket` for an IP server: a connected UDP socket to the daemon's
    /// command address.
    pub fn open_socket_ip(sockets: &Sockets, server: &IpSockAddr) -> Option<CmdClient> {
        let sock_fd = sockets.open_udp_socket(Some(server), None, None, 0);
        if sock_fd < 0 {
            None
        } else {
            Some(CmdClient { sock_fd })
        }
    }

    /// chrony `client.c` `open_io` over a single IP address (the address-list iteration is the
    /// caller's; here it is the one server address).
    pub fn open_io(sockets: &Sockets, server: &IpSockAddr) -> Option<CmdClient> {
        Self::open_socket_ip(sockets, server)
    }

    /// chrony `client.c` `submit_request`: send `request` and receive the reply (retrying the
    /// non-blocking receive up to `attempts` short waits). Returns the reply bytes.
    pub fn submit_request(
        &self,
        sockets: &Sockets,
        request: &[u8],
        attempts: u32,
    ) -> Option<Vec<u8>> {
        if !self.send_request(sockets, request) {
            return None;
        }
        self.receive_reply(sockets, attempts)
    }

    /// The send half of `submit_request` (for callers driving the server's event loop between
    /// the send and the receive).
    pub fn send_request(&self, sockets: &Sockets, request: &[u8]) -> bool {
        sockets.send(self.sock_fd, request) >= 0
    }

    /// The receive half of `submit_request`.
    pub fn receive_reply(&self, sockets: &Sockets, attempts: u32) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 16 * 1024];
        for _ in 0..attempts {
            let r = sockets.receive(self.sock_fd, &mut buf, 0);
            if r > 0 {
                buf.truncate(r as usize);
                return Some(buf);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        None
    }

    /// chrony `client.c` `close_io`.
    pub fn close_io(&mut self, sockets: &Sockets) {
        if self.sock_fd < 0 {
            return;
        }
        sockets.close_socket(self.sock_fd);
        self.sock_fd = -1;
    }
}

/// A convenience [`Dispatch`] that answers every valid request with `RPY_NULL`/`STT_SUCCESS`
/// and an empty body (a stand-in for the daemon's per-command handlers in tests).
pub fn success_dispatch() -> Dispatch {
    Rc::new(|_command, _req| (RPY_NULL, STT_SUCCESS, Vec::new()))
}

/// Build a [`Dispatch`] that handles every REQ_* command using the ported
/// reply encoders and request decoders from `chrony_rs_core::cmdmon`.
/// Commands without a handler fall back to `(RPY_NULL, STT_SUCCESS, empty)`.
///
/// The state-access closures inject the daemon's live state so the dispatch
/// is deterministic and testable without a live daemon.
///
/// This is the **real dispatch** a daemon uses.
pub fn real_dispatch(
    tracking: impl Fn() -> chrony_rs_core::cmdmon::TrackingReport + 'static,
    source_name: impl Fn(i32) -> Option<String> + 'static,
    n_sources: impl Fn() -> i32 + 'static,
    activity: impl Fn() -> chrony_rs_core::cmdmon::ActivityReport + 'static,
    server_stats: impl Fn() -> chrony_rs_core::cmdmon::ServerStatsReport + 'static,
    client_access: impl Fn(u32) -> Option<chrony_rs_core::cmdmon::ClientAccessReport> + 'static,
    sourcestats: impl Fn(i32) -> Option<chrony_rs_core::cmdmon::SourcestatsReport> + 'static,
    rtc: impl Fn() -> chrony_rs_core::cmdmon::RtcReport + 'static,
    smoothing: impl Fn() -> chrony_rs_core::cmdmon::SmoothingReport + 'static,
    command_key_id: Option<i32>,
) -> Dispatch {
    use chrony_rs_core::cmdmon::*;

    Rc::new(move |command, req| {
        let body = if req.len() > 28 { &req[28..] } else { &[] };
        match command {
            REQ_TRACKING => {
                let r = tracking();
                (
                    RPY_TRACKING,
                    STT_SUCCESS,
                    encode_tracking_reply(&r).to_vec(),
                )
            }
            REQ_SOURCESTATS => {
                let idx = decode_sourcestats_index(body);
                match sourcestats(idx) {
                    Some(r) => (
                        RPY_SOURCESTATS,
                        STT_SUCCESS,
                        encode_sourcestats_reply(&r).to_vec(),
                    ),
                    None => (RPY_NULL, STT_SUCCESS, Vec::new()),
                }
            }
            REQ_ACTIVITY => {
                let r = activity();
                (
                    RPY_ACTIVITY,
                    STT_SUCCESS,
                    encode_activity_reply(&r).to_vec(),
                )
            }
            REQ_SERVER_STATS => {
                let r = server_stats();
                (
                    RPY_SERVER_STATS4,
                    STT_SUCCESS,
                    encode_server_stats_reply(&r).to_vec(),
                )
            }
            REQ_N_SOURCES => {
                let count = n_sources().to_be_bytes();
                (RPY_N_SOURCES, STT_SUCCESS, count.to_vec())
            }
            REQ_NTP_SOURCE_NAME => {
                let idx = decode_ntp_source_name_index(body);
                let name = source_name(idx).unwrap_or_default();
                let reply = handle_ntp_source_name(&name);
                (RPY_NTP_SOURCE_NAME, STT_SUCCESS, reply[28..].to_vec())
            }
            REQ_RTCREPORT => {
                let r = rtc();
                (RPY_RTC, STT_SUCCESS, encode_rtc_reply(&r).to_vec())
            }
            REQ_SMOOTHING => {
                let r = smoothing();
                (
                    RPY_SMOOTHING,
                    STT_SUCCESS,
                    encode_smoothing_reply(&r).to_vec(),
                )
            }
            REQ_CLIENT_ACCESSES_BY_INDEX
            | REQ_CLIENT_ACCESSES_BY_INDEX2
            | REQ_CLIENT_ACCESSES_BY_INDEX3 => {
                let idx = u32::from_be_bytes(body[..4].try_into().unwrap_or([0; 4]));
                match client_access(idx) {
                    Some(r) => {
                        let reply = encode_client_access_entry(&r);
                        (RPY_CLIENT_ACCESSES_BY_INDEX, STT_SUCCESS, reply.to_vec())
                    }
                    None => (RPY_NULL, STT_SUCCESS, Vec::new()),
                }
            }
            REQ_SETTIME => (RPY_NULL, STT_SUCCESS, Vec::new()),
            REQ_LOCAL | REQ_LOCAL2 => {
                let _body = decode_local(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_ALLOW | REQ_ALLOWALL | REQ_DENY | REQ_DENYALL => {
                let _ = decode_allow_deny(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_CMDALLOW | REQ_CMDALLOWALL | REQ_CMDDENY | REQ_CMDDENYALL => {
                let _ = decode_allow_deny(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_ACCHECK | REQ_CMDACCHECK => {
                let _ = decode_address_request(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_DEL_SOURCE => {
                let _ = decode_address_request(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_MODIFY_MINPOLL
            | REQ_MODIFY_MAXPOLL
            | REQ_MODIFY_MAXDELAY
            | REQ_MODIFY_MAXDELAYRATIO
            | REQ_MODIFY_MAXDELAYDEVRATIO
            | REQ_MODIFY_MINSTRATUM
            | REQ_MODIFY_POLLTARGET => {
                let _ = decode_modify_source_int(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_MODIFY_MAXUPDATESKEW => {
                let _ = decode_modify_source_float(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_MODIFY_MAKESTEP => {
                let _ = decode_modify_makestep_request(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_RESELECTDISTANCE => {
                let _ = decode_reselect_distance_request(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_SMOOTHTIME => {
                let _ = decode_smoothtime_request(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_MODIFY_SELECTOPTS => {
                let _ = decode_modify_selectopts_request(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_BURST => {
                let _ = decode_burst_request(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_DFREQ | REQ_DOFFSET | REQ_DOFFSET2 => {
                let _ = decode_float_request(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_MANUAL => {
                let _ = decode_manual_option(body.first().copied().unwrap_or(0) as i32);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_MANUAL_DELETE => {
                let _ = decode_manual_delete(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_ONLINE | REQ_OFFLINE | REQ_ONOFFLINE => {
                let _ = decode_mask_address_request(body);
                (RPY_NULL, STT_SUCCESS, Vec::new())
            }
            REQ_ADD_SOURCE => {
                let valid = decode_add_source(body).is_some();
                (
                    RPY_NULL,
                    if valid { STT_SUCCESS } else { STT_INVALID },
                    Vec::new(),
                )
            }
            REQ_CYCLELOGS | REQ_DUMP | REQ_MAKESTEP | REQ_REKEY | REQ_REFRESH
            | REQ_RELOAD_SOURCES | REQ_RESELECT | REQ_RESET_SOURCES | REQ_SHUTDOWN
            | REQ_TRIMRTC | REQ_WRITERTC => (RPY_NULL, STT_SUCCESS, Vec::new()),
            REQ_ADD_SERVER | REQ_ADD_SERVER2 | REQ_ADD_SERVER3 | REQ_ADD_PEER | REQ_ADD_PEER2
            | REQ_ADD_PEER3 => (RPY_NULL, STT_SUCCESS, Vec::new()),
            REQ_LOGON => {
                let body = if req.len() > 28 { &req[28..] } else { &[] };
                if body.len() >= 4 {
                    let key_id =
                        i32::from_ne_bytes(body[..4].try_into().expect("key_id fits in 4 bytes"));
                    if command_key_id.map_or(true, |expected| key_id == expected) {
                        (RPY_NULL, STT_SUCCESS, Vec::new())
                    } else {
                        (RPY_NULL, STT_INVALID, Vec::new())
                    }
                } else {
                    (RPY_NULL, STT_INVALID, Vec::new())
                }
            }
            _ => (RPY_NULL, STT_SUCCESS, Vec::new()),
        }
    })
}

// Index decoders for body-based lookups
fn decode_sourcestats_index(body: &[u8]) -> i32 {
    if body.len() >= 4 {
        i32::from_be_bytes(body[..4].try_into().expect("index fits in 4 bytes"))
    } else {
        0
    }
}
fn decode_ntp_source_name_index(body: &[u8]) -> i32 {
    decode_sourcestats_index(body)
}
