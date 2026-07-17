//! NTP socket I/O — a faithful port of chrony 4.5 `ntp_io.c` (the non-Linux-timestamping
//! path), wiring the real socket layer ([`crate::socket`]), the live event loop
//! ([`crate::driver`]) and the ported config accessors together.
//!
//! `ntp_io.c` owns the daemon's NTP server/client sockets: opening them with the configured
//! bind address / port / DSCP, registering them with the scheduler, and, on a read event,
//! decoding each datagram and handing it to `NSR_ProcessRx`. The NTP source-processing engine
//! (`NSR_ProcessRx`) and the clock's timestamp cooking (`LCL_CookTime`) are the boundaries:
//! received packets are delivered to a caller-supplied sink (the `NSR_ProcessRx` seam), and
//! the RX timestamp is the scheduler's daemon time (kernel/HW timestamping is a separate
//! Linux-only path, not ported here).
//!
//! Verified by a **kernel-integration test** (`tests/ntp_io.rs`) that opens a real server
//! socket, sends a genuine NTP datagram over loopback, and drives the real event loop until
//! the packet is decoded and delivered.

use crate::socket::{Sockets, SCK_FLAG_BLOCK};
use chrony_rs_core::config::accessors::ConfigValues;
use chrony_rs_core::sched::{Scheduler, SCH_FILE_INPUT};
use chrony_rs_core::socket::{IpSockAddr, IPADDR_INET4, IPADDR_INET6, IPADDR_UNSPEC};
use chrony_rs_core::util::IpAddr;
use std::cell::RefCell;
use std::rc::Rc;

/// chrony `ntp_io.c` `INVALID_SOCK_FD` (note: `-1`, distinct from `socket.c`'s `-4`).
pub const INVALID_SOCK_FD: i32 = -1;
/// `SCK_FLAG_RX_DEST_ADDR` / `SCK_FLAG_PRIV_BIND` / `SCK_FLAG_BROADCAST` (ntp_io open flags).
const SCK_FLAG_RX_DEST_ADDR: i32 = 4;
const SCK_FLAG_BROADCAST: i32 = 2;
const SCK_FLAG_PRIV_BIND: i32 = 16;

const NTP_HEADER_LENGTH: usize = 48;
/// `sizeof(NTP_Packet)` for chrony 4.5 (compiled probe).
const NTP_PACKET_SIZE: usize = 1140;

/// A decoded received NTP packet as handed to `NSR_ProcessRx`: the source and (from
/// `IP_PKTINFO`) destination addresses, receiving interface, socket, packet bytes, and
/// kernel/hardware RX timestamp (if available from `SCM_TIMESTAMPING`).
#[derive(Clone, Debug, PartialEq)]
pub struct ReceivedNtp {
    pub remote: IpSockAddr,
    pub local_ip: IpAddr,
    pub if_index: i32,
    pub sock_fd: i32,
    pub data: Vec<u8>,
    /// Kernel RX timestamp `(sec, nsec)` from `SCM_TIMESTAMPING` or `SCM_TIMESTAMP`,
    /// or `None` if timestamping is not enabled/available.
    pub rx_timestamp: Option<(i64, i64)>,
}

/// The `NSR_ProcessRx` seam: received, validated NTP packets are pushed here. Shared so the
/// scheduler-owned read handler and the caller both see it.
pub type PacketSink = Rc<RefCell<Vec<ReceivedNtp>>>;

fn ip_to_sockaddr(ip: IpAddr, port: u16) -> IpSockAddr {
    match ip {
        IpAddr::Inet4(a) => IpSockAddr { family: IPADDR_INET4, in4: a, in6: [0; 16], port },
        IpAddr::Inet6(a) => IpSockAddr { family: IPADDR_INET6, in4: 0, in6: a, port },
        _ => IpSockAddr { family: IPADDR_UNSPEC, in4: 0, in6: [0; 16], port },
    }
}

fn ipsockaddr_to_ip(a: &IpSockAddr) -> IpAddr {
    match a.family {
        IPADDR_INET4 => IpAddr::Inet4(a.in4),
        IPADDR_INET6 => IpAddr::Inet6(a.in6),
        _ => IpAddr::Unspec,
    }
}

/// chrony `process_message` (non-HW-timestamping path): validate one received message and, if
/// it is a well-formed NTP packet, deliver it to the `NSR_ProcessRx` sink. `is_ptp` selects the
/// PTP-unwrap branch of `NIO_UnwrapMessage`. Returns whether a packet was delivered.
///
/// Performs basic auth-mode validation before accepting the packet:
/// packets with unsupported auth modes are rejected early.
///
/// Extracts the kernel/hardware RX timestamp (`SCM_TIMESTAMPING` / `SCM_TIMESTAMP`) from the
/// message's ancillary data and passes it through to the sink.
pub fn process_message(
    msg: &crate::socket::ReceivedMessage,
    sock_fd: i32,
    is_ptp: bool,
    sink: &PacketSink,
) -> bool {
    // The address type is always IP for these UDP sockets (chrony rejects others).
    let mut data = msg.data.clone();

    // NIO_UnwrapMessage: pass-through on a normal socket; PTP prefix strip on a PTP socket.
    if is_ptp {
        match chrony_rs_core::ptp::unwrap_message(&data) {
            Some((inner, _corr)) => data = inner,
            None => return false,
        }
    }

    // Ignore packets that are not of a recognized NTP length.
    if data.len() < NTP_HEADER_LENGTH || data.len() > NTP_PACKET_SIZE {
        return false;
    }

    // Basic auth-mode check: parse the packet to verify auth mode is recognized.
    // The per-source full auth verification happens in SourceInstance::handle_response().
    let mut buf = chrony_rs_core::ntp::ext::NtpPacketBuf::new();
    let copy_len = data.len().min(buf.bytes().len());
    buf.bytes_mut()[..copy_len].copy_from_slice(&data[..copy_len]);
    if let Some(info) = chrony_rs_core::ntp::parse::parse_packet(&buf, data.len() as i32) {
        // Reject packets with auth modes that are definitively unsupported
        if info.auth_mode < 0 || info.auth_mode > 4 {
            return false;
        }
    }

    // Extract the best available RX timestamp from the control data.
    // Priority: hardware timestamp > kernel timestamp > software timestamp > None.
    let rx_timestamp = {
        let ctrl = &msg.control;
        if ctrl.hw_ts != (0, 0) {
            Some(ctrl.hw_ts)
        } else if ctrl.kernel_ts != (0, 0) {
            Some(ctrl.kernel_ts)
        } else {
            None
        }
    };

    sink.borrow_mut().push(ReceivedNtp {
        remote: msg.remote,
        local_ip: msg.control.local,
        if_index: msg.control.if_index,
        sock_fd,
        data,
        rx_timestamp,
    });
    true
}

/// Build and transmit a server response to a client request.
/// Returns `true` if the response was sent.
/// Uses live reference state from `ref_params` instead of hardcoded values.
/// If `nts_server` is provided and the request contains NTS extension fields,
/// authenticates the request and appends NTS authenticator + cookie EFs.
pub fn transmit_server_response(
    sockets: &crate::socket::Sockets,
    sock_fd: i32,
    request_data: &[u8],
    remote: &chrony_rs_core::socket::IpSockAddr,
    local_ip: chrony_rs_core::util::IpAddr,
    _now: chrony_rs_core::sys_generic::Timespec,
    ref_params: &chrony_rs_core::ntp::transmit::ReferenceParams,
    mut nts_server: Option<&mut chrony_rs_core::nts_ntp_server::NtsServer>,
) -> bool {
    use chrony_rs_core::ntp::transmit::{build_server_response, ntp64_to_timespec};
    use chrony_rs_core::ntp::ext::{NtpPacketBuf, NtpPacketInfo};
    use chrony_rs_core::ntp::parse::parse_packet;

    if request_data.len() < 48 {
        return false;
    }

    let local_receive = ntp64_to_timespec(ref_params.rx_ts);
    let cooked_transmit = ntp64_to_timespec(ref_params.tx_ts);

    let response = build_server_response(
        6, 4, ref_params, ref_params.origin_ts, local_receive, cooked_transmit, -6,
    );

    let mut packet = response.packet.to_vec();

    // NTS extension fields
    if let Some(ref mut nts) = nts_server {
        // Parse the request into NtpPacketBuf / NtpPacketInfo for NTS processing
        let mut req_buf = NtpPacketBuf::new();
        let copy_len = request_data.len().min(req_buf.bytes().len());
        req_buf.bytes_mut()[..copy_len].copy_from_slice(&request_data[..copy_len]);
        if let Some(req_info) = parse_packet(&req_buf, request_data.len() as i32) {
            if req_info.ext_fields > 0 {
                let (ok, _kod) = nts.check_request_auth(&req_buf, &req_info);
                if ok {
                    let mut resp_buf = NtpPacketBuf::new();
                    resp_buf.bytes_mut()[..packet.len()].copy_from_slice(&packet);
                    let mut resp_info = NtpPacketInfo {
                        length: packet.len() as i32,
                        version: 4,
                        mode: chrony_rs_core::nts_ntp_server::MODE_SERVER,
                        ..Default::default()
                    };
                    if nts.generate_response_auth(&req_buf, &req_info, &mut resp_buf, &mut resp_info, 0) {
                        let nts_length = resp_info.length;
                        packet = resp_buf.bytes()[..nts_length as usize].to_vec();
                    }
                }
            }
        }
    }

    // Check amplification margin before sending
    if !chrony_rs_core::ntp::transmit::check_amplification_margin(request_data.len(), packet.len()) {
        eprintln!("ntp: dropping oversized response (amplification mitigation)");
        return false;
    }

    // Send the response
    let mut msg = chrony_rs_core::socket::SckMessage::init(
        chrony_rs_core::socket::SckAddressType::Ip
    );
    msg.remote_ip = *remote;
    msg.local_ip = local_ip;
    sockets.send_message(sock_fd, &msg, &packet, 0) >= 0
}

/// chrony `read_from_socket`: drain all pending datagrams on `sock_fd` (a single `recvmmsg`
/// batch) and process each. The scheduler invokes this as the file handler.
pub fn read_from_socket(
    sockets: &Sockets,
    sock_fd: i32,
    event: i32,
    is_ptp: bool,
    sink: &PacketSink,
) {
    // On an exception event chrony reads the error queue (Linux timestamping only).
    let flags = if event == chrony_rs_core::sched::SCH_FILE_EXCEPTION {
        crate::socket::SCK_FLAG_MSG_ERRQUEUE
    } else {
        0
    };
    for m in sockets.receive_messages(sock_fd, flags, 16) {
        process_message(&m, sock_fd, is_ptp, sink);
    }
}

/// The `ntp_io.c` module state (server/client/PTP socket fds and their reference counts, plus
/// the mode flags derived from the config). Held by the daemon; methods take the socket layer,
/// config, and scheduler explicitly.
#[derive(Debug)]
pub struct NtpIo {
    server_sock_fd4: i32,
    server_sock_fd6: i32,
    client_sock_fd4: i32,
    client_sock_fd6: i32,
    server_sock_ref4: i32,
    server_sock_ref6: i32,
    separate_client_sockets: bool,
    permanent_server_sockets: bool,
    ptp_port: i32,
    ptp_sock_fd4: i32,
    ptp_sock_fd6: i32,
    ptp_seq: u16,
    initialised: bool,
}

impl NtpIo {
    /// chrony `NIO_Initialise`: derive the socket-sharing mode from the NTP/acquisition ports
    /// and open the permanent server/client sockets. `sink` receives decoded packets.
    pub fn initialise(
        sockets: &Sockets,
        config: &ConfigValues,
        sched: &mut Scheduler,
        sink: &PacketSink,
    ) -> Self {
        let server_port = config.ntp_port();
        let mut client_port = config.acquisition_port();

        let separate_client_sockets = client_port < 0;
        if client_port < 0 {
            client_port = 0;
        }
        let permanent_server_sockets =
            server_port == 0 || (!separate_client_sockets && client_port == server_port);

        let mut io = NtpIo {
            server_sock_fd4: INVALID_SOCK_FD,
            server_sock_fd6: INVALID_SOCK_FD,
            client_sock_fd4: INVALID_SOCK_FD,
            client_sock_fd6: INVALID_SOCK_FD,
            server_sock_ref4: 0,
            server_sock_ref6: 0,
            separate_client_sockets,
            permanent_server_sockets,
            ptp_port: config.ptp_port(),
            ptp_sock_fd4: INVALID_SOCK_FD,
            ptp_sock_fd6: INVALID_SOCK_FD,
            ptp_seq: 0,
            initialised: true,
        };

        if permanent_server_sockets && server_port != 0 {
            io.server_sock_fd4 =
                io.open_socket(sockets, config, sched, sink, IPADDR_INET4, server_port, false, None);
            io.server_sock_fd6 =
                io.open_socket(sockets, config, sched, sink, IPADDR_INET6, server_port, false, None);
        }

        if !separate_client_sockets {
            if client_port != server_port || server_port == 0 {
                io.client_sock_fd4 =
                    io.open_socket(sockets, config, sched, sink, IPADDR_INET4, client_port, true, None);
                io.client_sock_fd6 =
                    io.open_socket(sockets, config, sched, sink, IPADDR_INET6, client_port, true, None);
            } else {
                io.client_sock_fd4 = io.server_sock_fd4;
                io.client_sock_fd6 = io.server_sock_fd6;
            }
        }
        io
    }

    /// chrony `ntp_io.c` `open_socket`: open a UDP socket for `family` bound to `local_port`
    /// with the configured bind address / interface / DSCP, and register its read handler.
    /// Retries up to 3 times on failure with a 1-second delay.
    #[allow(clippy::too_many_arguments)]
    fn open_socket(
        &self,
        sockets: &Sockets,
        config: &ConfigValues,
        sched: &mut Scheduler,
        sink: &PacketSink,
        family: i32,
        local_port: i32,
        client_only: bool,
        remote: Option<&IpSockAddr>,
    ) -> i32 {
        if !sockets.is_ip_family_enabled(family) {
            return INVALID_SOCK_FD;
        }
        let (bind_ip, iface) = if client_only {
            (config.bind_acquisition_address(family as u16), config.bind_acquisition_interface())
        } else {
            (config.bind_address(family as u16), config.bind_ntp_interface())
        };
        let local = ip_to_sockaddr(bind_ip, local_port as u16);

        let mut flags = SCK_FLAG_RX_DEST_ADDR | SCK_FLAG_PRIV_BIND;
        if !client_only {
            flags |= SCK_FLAG_BROADCAST;
        }
        // PRIV_BIND has no effect without a priv-bind helper; mask it (we bind directly).
        flags &= !SCK_FLAG_PRIV_BIND;
        let _ = SCK_FLAG_BLOCK; // (documenting the flag set; blocking mode not used)

        let max_retries = 3;
        let retry_delay = std::time::Duration::from_secs(1);
        let sock_fd = {
            let mut fd = INVALID_SOCK_FD;
            for attempt in 1..=max_retries {
                fd = sockets.open_udp_socket(remote, Some(&local), iface, flags);
                if fd >= 0 {
                    break;
                }
                if attempt < max_retries {
                    eprintln!("net: failed to bind NTP socket (attempt {}/{})", attempt, max_retries);
                    std::thread::sleep(retry_delay);
                }
            }
            if fd < 0 {
                eprintln!("net: FATAL — failed to bind NTP socket after {} attempts", max_retries);
            }
            fd
        };
        if sock_fd < 0 {
            return INVALID_SOCK_FD;
        }

        // DSCP (IP_TOS / IPV6_TCLASS), best-effort like chrony.
        let dscp = config.ntp_dscp();
        if dscp > 0 && dscp < 64 {
            const IP_TOS: i32 = 1;
            const IPV6_TCLASS: i32 = 67;
            if family == IPADDR_INET4 {
                let _ = sockets.set_int_option(sock_fd, chrony_rs_core::socket::IPPROTO_IP, IP_TOS, dscp << 2);
            } else {
                let _ = sockets.set_int_option(sock_fd, chrony_rs_core::socket::IPPROTO_IPV6, IPV6_TCLASS, dscp << 2);
            }
        }

        // Enable HW timestamping if any hwtimestamp interfaces are configured.
        if config.hw_ts_interface(0).is_some() {
            sockets.enable_kernel_rx_timestamping(sock_fd);
            sockets.enable_kernel_tx_timestamping(sock_fd);
        }

        // Register the read handler on the scheduler (the live event loop drives it).
        let is_ptp = self.ptp_port > 0 && local_port == self.ptp_port;
        let sockets_copy = *sockets;
        let sink_clone = sink.clone();
        sched.add_file_handler(
            sock_fd as usize,
            SCH_FILE_INPUT,
            Box::new(move |_s, fd, event| {
                read_from_socket(&sockets_copy, fd, event, is_ptp, &sink_clone);
            }),
        );
        sock_fd
    }

    /// chrony `NIO_OpenServerSocket`: the (ref-counted) server socket for a remote's family.
    pub fn open_server_socket(
        &mut self,
        sockets: &Sockets,
        config: &ConfigValues,
        sched: &mut Scheduler,
        sink: &PacketSink,
        family: i32,
    ) -> i32 {
        match family {
            IPADDR_INET4 => {
                if self.permanent_server_sockets {
                    return self.server_sock_fd4;
                }
                if self.server_sock_fd4 == INVALID_SOCK_FD {
                    self.server_sock_fd4 = self.open_socket(
                        sockets, config, sched, sink, IPADDR_INET4, config.ntp_port(), false, None,
                    );
                }
                if self.server_sock_fd4 != INVALID_SOCK_FD {
                    self.server_sock_ref4 += 1;
                }
                self.server_sock_fd4
            }
            IPADDR_INET6 => {
                if self.permanent_server_sockets {
                    return self.server_sock_fd6;
                }
                if self.server_sock_fd6 == INVALID_SOCK_FD {
                    self.server_sock_fd6 = self.open_socket(
                        sockets, config, sched, sink, IPADDR_INET6, config.ntp_port(), false, None,
                    );
                }
                if self.server_sock_fd6 != INVALID_SOCK_FD {
                    self.server_sock_ref6 += 1;
                }
                self.server_sock_fd6
            }
            _ => INVALID_SOCK_FD,
        }
    }

    /// chrony `NIO_CloseServerSocket`: drop a server-socket reference, closing it at zero.
    pub fn close_server_socket(&mut self, sockets: &Sockets, sched: &mut Scheduler, sock_fd: i32) {
        if self.permanent_server_sockets || sock_fd == INVALID_SOCK_FD || self.is_ptp_socket(sock_fd)
        {
            return;
        }
        if sock_fd == self.server_sock_fd4 {
            self.server_sock_ref4 -= 1;
            if self.server_sock_ref4 <= 0 {
                close_socket(sockets, sched, self.server_sock_fd4);
                self.server_sock_fd4 = INVALID_SOCK_FD;
            }
        } else if sock_fd == self.server_sock_fd6 {
            self.server_sock_ref6 -= 1;
            if self.server_sock_ref6 <= 0 {
                close_socket(sockets, sched, self.server_sock_fd6);
                self.server_sock_fd6 = INVALID_SOCK_FD;
            }
        }
    }

    /// chrony `is_ptp_socket`.
    pub fn is_ptp_socket(&self, sock_fd: i32) -> bool {
        self.ptp_port > 0
            && sock_fd != INVALID_SOCK_FD
            && (sock_fd == self.ptp_sock_fd4 || sock_fd == self.ptp_sock_fd6)
    }

    /// chrony `NIO_IsServerSocket`.
    pub fn is_server_socket(&self, sock_fd: i32) -> bool {
        sock_fd != INVALID_SOCK_FD
            && (sock_fd == self.server_sock_fd4
                || sock_fd == self.server_sock_fd6
                || self.is_ptp_socket(sock_fd))
    }

    /// chrony `NIO_IsServerSocketOpen`.
    pub fn is_server_socket_open(&self) -> bool {
        self.server_sock_fd4 != INVALID_SOCK_FD
            || self.server_sock_fd6 != INVALID_SOCK_FD
            || self.ptp_sock_fd4 != INVALID_SOCK_FD
            || self.ptp_sock_fd6 != INVALID_SOCK_FD
    }

    /// chrony `open_separate_client_socket`: a fresh connected client socket for `remote`.
    fn open_separate_client_socket(
        &self,
        sockets: &Sockets,
        config: &ConfigValues,
        sched: &mut Scheduler,
        sink: &PacketSink,
        remote: &IpSockAddr,
    ) -> i32 {
        self.open_socket(sockets, config, sched, sink, remote.family, 0, true, Some(remote))
    }

    /// chrony `NIO_OpenClientSocket`: a client socket for `remote` — a fresh connected socket
    /// per source when `separate_client_sockets`, else the shared client socket.
    pub fn open_client_socket(
        &self,
        sockets: &Sockets,
        config: &ConfigValues,
        sched: &mut Scheduler,
        sink: &PacketSink,
        remote: &IpSockAddr,
    ) -> i32 {
        match remote.family {
            IPADDR_INET4 => {
                if self.ptp_port > 0 && remote.port as i32 == self.ptp_port {
                    return self.ptp_sock_fd4;
                }
                if self.separate_client_sockets {
                    self.open_separate_client_socket(sockets, config, sched, sink, remote)
                } else {
                    self.client_sock_fd4
                }
            }
            IPADDR_INET6 => {
                if self.ptp_port > 0 && remote.port as i32 == self.ptp_port {
                    return self.ptp_sock_fd6;
                }
                if self.separate_client_sockets {
                    self.open_separate_client_socket(sockets, config, sched, sink, remote)
                } else {
                    self.client_sock_fd6
                }
            }
            _ => INVALID_SOCK_FD,
        }
    }

    /// chrony `NIO_CloseClientSocket`: close a per-source client socket (shared ones persist).
    pub fn close_client_socket(&self, sockets: &Sockets, sched: &mut Scheduler, sock_fd: i32) {
        if self.is_ptp_socket(sock_fd) {
            return;
        }
        if self.separate_client_sockets {
            close_socket(sockets, sched, sock_fd);
        }
    }

    /// chrony `NIO_IsServerConnectable`: whether a client socket to `remote` can be opened
    /// (open a throwaway one and close it).
    pub fn is_server_connectable(
        &self,
        sockets: &Sockets,
        config: &ConfigValues,
        sched: &mut Scheduler,
        sink: &PacketSink,
        remote: &IpSockAddr,
    ) -> bool {
        let sock_fd = self.open_separate_client_socket(sockets, config, sched, sink, remote);
        if sock_fd == INVALID_SOCK_FD {
            return false;
        }
        close_socket(sockets, sched, sock_fd);
        true
    }

    /// chrony `NIO_SendPacket`: send `packet` to `remote` from the socket in `local`
    /// (`local_ip`/`local_if_index`/`sock_fd`). On a PTP socket the packet is PTP-wrapped
    /// (`wrap_message`); on a connected client socket the remote address is left unset (the
    /// kernel routes to the connected peer). The interface is pinned only for a link-local
    /// destination. `process_tx` (HW TX timestamping) is a Linux boundary and ignored here.
    /// Returns whether the send succeeded.
    #[allow(clippy::too_many_arguments)]
    pub fn send_packet(
        &mut self,
        sockets: &Sockets,
        packet: &[u8],
        remote: &IpSockAddr,
        local_ip: IpAddr,
        local_if_index: i32,
        sock_fd: i32,
        _process_tx: bool,
    ) -> bool {
        if sock_fd == INVALID_SOCK_FD {
            return false;
        }
        // wrap_message: PTP prefix on a PTP socket, otherwise pass-through.
        let data = if self.is_ptp_socket(sock_fd) {
            let seq = self.ptp_seq;
            self.ptp_seq = self.ptp_seq.wrapping_add(1);
            match chrony_rs_core::ptp::wrap_message(packet, seq) {
                Some(w) => w,
                None => return false,
            }
        } else {
            packet.to_vec()
        };

        let mut msg = chrony_rs_core::socket::SckMessage::init(chrony_rs_core::socket::SckAddressType::Ip);
        // Specify the remote address only on an unconnected socket (server / shared client).
        if self.is_server_socket(sock_fd) || !self.separate_client_sockets {
            msg.remote_ip = *remote;
        }
        msg.local_ip = local_ip;
        // Don't pin the interface for a non-link-local destination.
        let remote_ip = ipsockaddr_to_ip(remote);
        msg.if_index = if chrony_rs_core::socket::is_link_local_ip_address(&remote_ip) {
            local_if_index
        } else {
            chrony_rs_core::socket::INVALID_IF_INDEX
        };

        sockets.send_message(sock_fd, &msg, &data, 0) >= 0
    }

    /// chrony `NIO_Finalise`: close all sockets and reset the module state.
    pub fn finalise(&mut self, sockets: &Sockets, sched: &mut Scheduler) {
        if self.server_sock_fd4 != self.client_sock_fd4 {
            close_socket(sockets, sched, self.client_sock_fd4);
        }
        close_socket(sockets, sched, self.server_sock_fd4);
        self.server_sock_fd4 = INVALID_SOCK_FD;
        self.client_sock_fd4 = INVALID_SOCK_FD;

        if self.server_sock_fd6 != self.client_sock_fd6 {
            close_socket(sockets, sched, self.client_sock_fd6);
        }
        close_socket(sockets, sched, self.server_sock_fd6);
        self.server_sock_fd6 = INVALID_SOCK_FD;
        self.client_sock_fd6 = INVALID_SOCK_FD;

        close_socket(sockets, sched, self.ptp_sock_fd4);
        close_socket(sockets, sched, self.ptp_sock_fd6);
        self.ptp_sock_fd4 = INVALID_SOCK_FD;
        self.ptp_sock_fd6 = INVALID_SOCK_FD;
        self.initialised = false;
    }
}

/// chrony `close_socket`: deregister the fd from the scheduler and close it.
pub fn close_socket(sockets: &Sockets, sched: &mut Scheduler, sock_fd: i32) {
    if sock_fd == INVALID_SOCK_FD {
        return;
    }
    sched.remove_file_handler(sock_fd as usize);
    sockets.close_socket(sock_fd);
}
