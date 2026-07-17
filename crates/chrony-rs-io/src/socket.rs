//! Real OS socket layer — a faithful port of chrony 4.5 `socket.c`'s UDP path.
//!
//! Unlike the pure byte codecs in `chrony-rs-core::socket` (sockaddr marshalling, cmsg
//! parse/build — all differential-tested against compiled C), this module makes the actual
//! `socket`/`bind`/`connect`/`sendmsg`/`recvmsg` syscalls, reproducing chrony's exact option
//! and flag sequences. It therefore cannot be differential-unit-tested against C; it is
//! verified by **kernel-integration tests** (see `tests/udp.rs`) that open real loopback
//! sockets and observe end-to-end behaviour.
//!
//! # Scope and boundaries
//!
//! This is the UDP client/server path the NTP engine uses: open (with chrony's socket/IP
//! options), send/receive datagrams and messages (with `IP_PKTINFO` ancillary data), and
//! close. Deliberately **not** ported yet (documented boundaries, not credited):
//! - the systemd `LISTEN_FDS` reusable-socket inheritance/pool (`get_reusable_socket`,
//!   `SCK_CloseReusableSockets`) — `SCK_PreInitialise` parses `LISTEN_FDS` but the pool is
//!   inert, so on a normal (non-systemd) start every path matches chrony exactly;
//! - TCP and Unix-domain sockets, `recvmmsg` batching (only the single-message path), the
//!   Linux HW/SW TX-timestamp control messages, and the `privops` privileged bind helper.
//!
//! The byte-level work (sockaddr layout, PKTINFO cmsg) is delegated to the already-tested
//! `chrony-rs-core::socket` codecs, so this layer only owns the syscalls and control flow.

use chrony_rs_core::socket as codec;
use chrony_rs_core::socket::{IpSockAddr, SckAddressType, SckMessage};
use chrony_rs_core::util::IpAddr;
use std::os::raw::c_int;

pub use chrony_rs_core::socket::{INVALID_SOCK_FD, SCK_FLAG_BLOCK, SCK_FLAG_MSG_ERRQUEUE};

/// chrony `SCK_FLAG_BROADCAST` / `SCK_FLAG_RX_DEST_ADDR` / `SCK_FLAG_PRIV_BIND` (open flags).
pub const SCK_FLAG_BROADCAST: i32 = 2;
pub const SCK_FLAG_RX_DEST_ADDR: i32 = 4;
pub const SCK_FLAG_PRIV_BIND: i32 = 16;

const IPADDR_INET4: i32 = codec::IPADDR_INET4;
const IPADDR_INET6: i32 = codec::IPADDR_INET6;
const IPADDR_UNSPEC: i32 = codec::IPADDR_UNSPEC;

/// The socket-layer state chrony keeps in module statics (`ip4_enabled`, `ip6_enabled`,
/// `supported_socket_flags`, the reusable-fd window). Held by the daemon and passed to the
/// `SCK_*` operations, replacing C's globals.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sockets {
    ip4_enabled: bool,
    ip6_enabled: bool,
    supported_socket_flags: c_int,
    first_reusable_fd: c_int,
    reusable_fds: c_int,
    initialised: bool,
}

/// `check_socket_flag`: probe whether the kernel accepts a `socket()` creation flag and sets
/// the expected fd/status flag — chrony's runtime capability test for `SOCK_CLOEXEC` /
/// `SOCK_NONBLOCK`. Opens a throwaway `AF_INET`/`SOCK_DGRAM` socket, checks `F_GETFD`/`F_GETFL`,
/// and closes it.
pub fn check_socket_flag(sock_flag: c_int, fd_flag: c_int, fs_flag: c_int) -> bool {
    // SAFETY: standard socket()/fcntl()/close() over a locally-created fd.
    unsafe {
        let sock_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | sock_flag, 0);
        if sock_fd < 0 {
            return false;
        }
        let fd_flags = libc::fcntl(sock_fd, libc::F_GETFD);
        let fs_flags = libc::fcntl(sock_fd, libc::F_GETFL);
        libc::close(sock_fd);
        fd_flags != -1
            && (fd_flags & fd_flag) == fd_flag
            && fs_flags != -1
            && (fs_flags & fs_flag) == fs_flag
    }
}

impl Sockets {
    /// `SCK_PreInitialise`: read the systemd `LISTEN_FDS` window (the inherited fds start at 3).
    /// The pool itself is not populated (a documented boundary), so on a normal start this
    /// leaves `reusable_fds == 0` and every later path matches chrony's non-systemd behaviour.
    pub fn pre_initialise() -> Self {
        // chrony: inherited fds start at 3; parse LISTEN_FDS, rejecting trailing junk/negative.
        let reusable_fds = std::env::var("LISTEN_FDS")
            .ok()
            .and_then(|v| v.parse::<c_int>().ok())
            .filter(|n| *n >= 0)
            .unwrap_or(0);
        Sockets { first_reusable_fd: 3, reusable_fds, ..Sockets::default() }
    }

    /// `SCK_Initialise`: enable the requested address families and probe the supported
    /// `socket()` creation flags (`SOCK_CLOEXEC`/`SOCK_NONBLOCK`).
    pub fn initialise(&mut self, family: i32) {
        self.ip4_enabled = family == IPADDR_INET4 || family == IPADDR_UNSPEC;
        self.ip6_enabled = family == IPADDR_INET6 || family == IPADDR_UNSPEC;

        self.supported_socket_flags = 0;
        if check_socket_flag(libc::SOCK_CLOEXEC, libc::FD_CLOEXEC, 0) {
            self.supported_socket_flags |= libc::SOCK_CLOEXEC;
        }
        if check_socket_flag(libc::SOCK_NONBLOCK, 0, libc::O_NONBLOCK) {
            self.supported_socket_flags |= libc::SOCK_NONBLOCK;
        }
        self.initialised = true;
    }

    /// `SCK_Finalise`.
    pub fn finalise(&mut self) {
        self.initialised = false;
    }

    /// `SCK_IsIpFamilyEnabled`.
    pub fn is_ip_family_enabled(&self, family: i32) -> bool {
        match family {
            IPADDR_INET4 => self.ip4_enabled,
            IPADDR_INET6 => self.ip6_enabled,
            _ => false,
        }
    }

    /// `SCK_IsReusable`: whether `sock_fd` is in the inherited (systemd) reusable window.
    fn is_reusable(&self, sock_fd: c_int) -> bool {
        sock_fd >= self.first_reusable_fd && sock_fd < self.first_reusable_fd + self.reusable_fds
    }

    /// `get_ip_socket`: reuse a matching pre-inherited (systemd) socket if the pool has one,
    /// else open a fresh socket. With no inherited sockets (`reusable_fds == 0`, the normal
    /// case) this always opens a new one, matching chrony exactly.
    fn get_ip_socket(&self, domain: c_int, sock_type: c_int, flags: i32) -> c_int {
        // get_reusable_socket over an empty pool yields none.
        if self.reusable_fds == 0 {
            return self.open_socket(domain, sock_type, flags);
        }
        // A populated pool is a documented boundary (systemd LISTEN_FDS); fall back to opening.
        self.open_socket(domain, sock_type, flags)
    }

    /// `open_socket`: `socket(domain, type | get_open_flags(flags))` then apply the fd flags.
    fn open_socket(&self, domain: c_int, sock_type: c_int, flags: i32) -> c_int {
        let open_flags = codec::get_open_flags(self.supported_socket_flags, flags);
        // SAFETY: socket() with computed flags; fd closed on the failure path.
        let sock_fd = unsafe { libc::socket(domain, sock_type | open_flags, 0) };
        if sock_fd < 0 {
            return INVALID_SOCK_FD;
        }
        if !self.set_socket_flags(sock_fd, flags) {
            unsafe { libc::close(sock_fd) };
            return INVALID_SOCK_FD;
        }
        sock_fd
    }

    /// `set_socket_flags`: set `FD_CLOEXEC` (unless the socket was created with `SOCK_CLOEXEC`)
    /// and non-blocking mode (unless blocking was requested or `SOCK_NONBLOCK` was used).
    fn set_socket_flags(&self, sock_fd: c_int, flags: i32) -> bool {
        if !self.is_reusable(sock_fd)
            && self.supported_socket_flags & libc::SOCK_CLOEXEC == 0
            && !fd_set_cloexec(sock_fd)
        {
            return false;
        }
        if flags & SCK_FLAG_BLOCK == 0
            && (self.is_reusable(sock_fd) || self.supported_socket_flags & libc::SOCK_NONBLOCK == 0)
            && !set_socket_nonblock(sock_fd)
        {
            return false;
        }
        true
    }

    /// `set_socket_options`: `SO_BROADCAST` if requested (best-effort, like chrony).
    fn set_socket_options(&self, sock_fd: c_int, flags: i32) -> bool {
        if flags & SCK_FLAG_BROADCAST != 0 {
            let _ = self.set_int_option(sock_fd, libc::SOL_SOCKET, libc::SO_BROADCAST, 1);
        }
        true
    }

    /// `set_ip_options`: `IPV6_V6ONLY` on v6 sockets, and `IP_PKTINFO`/`IPV6_RECVPKTINFO` when
    /// the caller wants received packets' destination address. Best-effort like chrony except
    /// the mandatory `IPV6_V6ONLY`.
    fn set_ip_options(&self, sock_fd: c_int, family: i32, flags: i32) -> bool {
        if family == IPADDR_INET6
            && !self.is_reusable(sock_fd)
            && !self.set_int_option(sock_fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)
        {
            return false;
        }
        if flags & SCK_FLAG_RX_DEST_ADDR != 0 {
            if family == IPADDR_INET4 {
                let _ = self.set_int_option(sock_fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1);
            } else if family == IPADDR_INET6 {
                let _ =
                    self.set_int_option(sock_fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1);
            }
        }
        true
    }

    /// `bind_device`: `SO_BINDTODEVICE` to `iface`.
    fn bind_device(&self, sock_fd: c_int, iface: &str) -> bool {
        let bytes = iface.as_bytes();
        // SAFETY: setsockopt with a byte buffer of the interface name.
        let r = unsafe {
            libc::setsockopt(
                sock_fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len() as libc::socklen_t,
            )
        };
        r >= 0
    }

    /// `bind_ip_address`: set the reuse/freebind options for a fixed port, then `bind()` to the
    /// marshalled sockaddr.
    fn bind_ip_address(&self, sock_fd: c_int, addr: &IpSockAddr, _flags: i32) -> bool {
        if addr.port > 0 {
            let _ = self.set_int_option(sock_fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1);
            let _ = self.set_int_option(sock_fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1);
        }
        // IP_FREEBIND (Linux): allow binding to a not-yet-configured address. Best-effort.
        const IP_FREEBIND: c_int = 15;
        let _ = self.set_int_option(sock_fd, libc::IPPROTO_IP, IP_FREEBIND, 1);

        if self.is_reusable(sock_fd) {
            return true;
        }
        let mut sa = [0u8; codec::SIZEOF_SOCKADDR_IN6];
        let cap = sa.len();
        let len = codec::ip_sockaddr_to_sockaddr(addr, &mut sa, cap);
        if len == 0 {
            return false;
        }
        // SAFETY: sa holds a valid sockaddr of `len` bytes produced by the tested codec.
        let r = unsafe {
            libc::bind(sock_fd, sa.as_ptr() as *const libc::sockaddr, len as libc::socklen_t)
        };
        r >= 0
    }

    /// `connect_ip_address`: `connect()` to the marshalled sockaddr (`EINPROGRESS` on a
    /// non-blocking socket is success).
    fn connect_ip_address(&self, sock_fd: c_int, addr: &IpSockAddr) -> bool {
        let mut sa = [0u8; codec::SIZEOF_SOCKADDR_IN6];
        let cap = sa.len();
        let len = codec::ip_sockaddr_to_sockaddr(addr, &mut sa, cap);
        if len == 0 {
            return false;
        }
        // SAFETY: sa holds a valid sockaddr of `len` bytes.
        let r = unsafe {
            libc::connect(sock_fd, sa.as_ptr() as *const libc::sockaddr, len as libc::socklen_t)
        };
        r >= 0 || last_errno() == libc::EINPROGRESS
    }

    /// `open_ip_socket`: the full open sequence — pick the domain from the local/remote family,
    /// create the socket, apply socket/IP options, optionally bind the device and local
    /// address, and connect the remote address.
    fn open_ip_socket(
        &self,
        remote: Option<&IpSockAddr>,
        local: Option<&IpSockAddr>,
        iface: Option<&str>,
        sock_type: c_int,
        flags: i32,
    ) -> c_int {
        let family = if let Some(l) = local {
            l.family
        } else if let Some(r) = remote {
            r.family
        } else {
            IPADDR_INET4
        };
        let domain = match family {
            IPADDR_INET4 => {
                if !self.ip4_enabled {
                    return INVALID_SOCK_FD;
                }
                libc::AF_INET
            }
            IPADDR_INET6 => {
                if !self.ip6_enabled {
                    return INVALID_SOCK_FD;
                }
                libc::AF_INET6
            }
            _ => return INVALID_SOCK_FD,
        };

        let sock_fd = self.get_ip_socket(domain, sock_type, flags);
        if sock_fd < 0 {
            return INVALID_SOCK_FD;
        }

        let fail = |s: &Sockets| -> c_int {
            s.close_socket(sock_fd);
            INVALID_SOCK_FD
        };

        if !self.set_socket_options(sock_fd, flags) {
            return fail(self);
        }
        if !self.set_ip_options(sock_fd, family, flags) {
            return fail(self);
        }
        if let Some(i) = iface {
            if !self.bind_device(sock_fd, i) {
                return fail(self);
            }
        }
        if let Some(l) = local {
            let any = l.family != IPADDR_UNSPEC
                && (l.port != 0 || !is_any_ipsockaddr(l))
                && !self.bind_ip_address(sock_fd, l, flags);
            if any {
                return fail(self);
            }
        }
        if let Some(r) = remote {
            if r.family != IPADDR_UNSPEC && !self.connect_ip_address(sock_fd, r) {
                return fail(self);
            }
        }
        sock_fd
    }

    /// `SCK_OpenUdpSocket`.
    pub fn open_udp_socket(
        &self,
        remote: Option<&IpSockAddr>,
        local: Option<&IpSockAddr>,
        iface: Option<&str>,
        flags: i32,
    ) -> c_int {
        self.open_ip_socket(remote, local, iface, libc::SOCK_DGRAM, flags)
    }

    /// `SCK_OpenTcpSocket`.
    pub fn open_tcp_socket(
        &self,
        remote: Option<&IpSockAddr>,
        local: Option<&IpSockAddr>,
        iface: Option<&str>,
        flags: i32,
    ) -> c_int {
        self.open_ip_socket(remote, local, iface, libc::SOCK_STREAM, flags)
    }

    /// `SCK_ListenOnSocket`: `listen(backlog)` (reusable sockets are already listening).
    pub fn listen_on_socket(&self, sock_fd: c_int, backlog: c_int) -> bool {
        if self.is_reusable(sock_fd) {
            return true;
        }
        // SAFETY: listen on an owned fd.
        unsafe { libc::listen(sock_fd, backlog) >= 0 }
    }

    /// `SCK_AcceptConnection`: `accept()` a connection, set close-on-exec + non-blocking on the
    /// new fd, and decode the peer address. Returns `(conn_fd, remote)` or `INVALID_SOCK_FD`.
    pub fn accept_connection(&self, sock_fd: c_int) -> (c_int, IpSockAddr) {
        let mut sa = [0u8; codec::SIZEOF_SOCKADDR_IN6];
        let mut saddr_len = sa.len() as libc::socklen_t;
        // SAFETY: accept into a sockaddr buffer with its length.
        let conn_fd =
            unsafe { libc::accept(sock_fd, sa.as_mut_ptr() as *mut libc::sockaddr, &mut saddr_len) };
        if conn_fd < 0 {
            return (INVALID_SOCK_FD, IpSockAddr::default());
        }
        if !fd_set_cloexec(conn_fd) || !set_socket_nonblock(conn_fd) {
            // SAFETY: close the fd we just accepted.
            unsafe { libc::close(conn_fd) };
            return (INVALID_SOCK_FD, IpSockAddr::default());
        }
        let remote = codec::sockaddr_to_ip_sockaddr(&sa, saddr_len as usize);
        (conn_fd, remote)
    }

    /// `SCK_ShutdownConnection`: `shutdown(SHUT_RDWR)`.
    pub fn shutdown_connection(&self, sock_fd: c_int) -> bool {
        // SAFETY: shutdown on an owned fd.
        unsafe { libc::shutdown(sock_fd, libc::SHUT_RDWR) >= 0 }
    }

    /// `bind_unix_address`: bind an `AF_UNIX` socket to `addr` (unlinking any stale node first),
    /// optionally `chmod 0666` for `SCK_FLAG_ALL_PERMISSIONS`.
    fn bind_unix_address(&self, sock_fd: c_int, addr: &str, flags: i32) -> bool {
        let (saddr, len) = match fill_sockaddr_un(addr) {
            Some(v) => v,
            None => return false,
        };
        // Best-effort remove of a stale socket node (chrony logs but does not fail on error).
        let _ = std::fs::remove_file(addr);
        // SAFETY: bind with a fully-initialised sockaddr_un of `len` bytes.
        let r = unsafe {
            libc::bind(sock_fd, &saddr as *const libc::sockaddr_un as *const libc::sockaddr, len)
        };
        if r < 0 {
            return false;
        }
        const SCK_FLAG_ALL_PERMISSIONS: i32 = 8;
        if flags & SCK_FLAG_ALL_PERMISSIONS != 0 {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::set_permissions(addr, std::fs::Permissions::from_mode(0o666)).is_err() {
                return false;
            }
        }
        true
    }

    /// `connect_unix_address`: connect an `AF_UNIX` socket to `addr`.
    fn connect_unix_address(&self, sock_fd: c_int, addr: &str) -> bool {
        let (saddr, len) = match fill_sockaddr_un(addr) {
            Some(v) => v,
            None => return false,
        };
        // SAFETY: connect with a fully-initialised sockaddr_un of `len` bytes.
        let r = unsafe {
            libc::connect(sock_fd, &saddr as *const libc::sockaddr_un as *const libc::sockaddr, len)
        };
        r >= 0
    }

    /// `open_unix_socket`: open an `AF_UNIX` socket of `type`, apply options, and optionally
    /// bind a local path / connect a remote path.
    fn open_unix_socket(
        &self,
        remote: Option<&str>,
        local: Option<&str>,
        sock_type: c_int,
        flags: i32,
    ) -> c_int {
        let sock_fd = self.open_socket(libc::AF_UNIX, sock_type, flags);
        if sock_fd < 0 {
            return INVALID_SOCK_FD;
        }
        let fail = |s: &Sockets| -> c_int {
            s.remove_socket(sock_fd);
            s.close_socket(sock_fd);
            INVALID_SOCK_FD
        };
        if !self.set_socket_options(sock_fd, flags) {
            return fail(self);
        }
        if let Some(l) = local {
            if !self.bind_unix_address(sock_fd, l, flags) {
                return fail(self);
            }
        }
        if let Some(r) = remote {
            if !self.connect_unix_address(sock_fd, r) {
                return fail(self);
            }
        }
        sock_fd
    }

    /// `SCK_OpenUnixStreamSocket`.
    pub fn open_unix_stream_socket(
        &self,
        remote: Option<&str>,
        local: Option<&str>,
        flags: i32,
    ) -> c_int {
        self.open_unix_socket(remote, local, libc::SOCK_STREAM, flags)
    }

    /// `SCK_OpenUnixDatagramSocket`.
    pub fn open_unix_datagram_socket(
        &self,
        remote: Option<&str>,
        local: Option<&str>,
        flags: i32,
    ) -> c_int {
        self.open_unix_socket(remote, local, libc::SOCK_DGRAM, flags)
    }

    /// `open_socket_pair`: `socketpair()` of `type` with both ends' fd flags applied. Returns
    /// `(fd0, fd1)` or `INVALID_SOCK_FD`.
    fn open_socket_pair(&self, domain: c_int, sock_type: c_int, flags: i32) -> (c_int, c_int) {
        let open_flags = codec::get_open_flags(self.supported_socket_flags, flags);
        let mut fds = [0 as c_int; 2];
        // SAFETY: socketpair fills the two-element fd array.
        let r = unsafe { libc::socketpair(domain, sock_type | open_flags, 0, fds.as_mut_ptr()) };
        if r < 0 {
            return (INVALID_SOCK_FD, INVALID_SOCK_FD);
        }
        if !self.set_socket_flags(fds[0], flags) || !self.set_socket_flags(fds[1], flags) {
            // SAFETY: close both fds of the pair.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return (INVALID_SOCK_FD, INVALID_SOCK_FD);
        }
        (fds[0], fds[1])
    }

    /// `SCK_OpenUnixSocketPair`: a connected `AF_UNIX` pair, preferring `SOCK_SEQPACKET` (so a
    /// closed peer yields a zero-length EOF message) and falling back to `SOCK_DGRAM`.
    pub fn open_unix_socket_pair(&self, flags: i32) -> Option<(c_int, c_int)> {
        let pair = self.open_socket_pair(libc::AF_UNIX, libc::SOCK_SEQPACKET, flags);
        let pair = if pair.0 < 0 {
            self.open_socket_pair(libc::AF_UNIX, libc::SOCK_DGRAM, flags)
        } else {
            pair
        };
        if pair.0 < 0 {
            None
        } else {
            Some(pair)
        }
    }

    /// `SCK_RemoveSocket`: unlink the filesystem node of a bound `AF_UNIX` socket (found via
    /// `getsockname`). A no-op for non-Unix sockets.
    pub fn remove_socket(&self, sock_fd: c_int) -> bool {
        let mut saddr: libc::sockaddr_un = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        let mut len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        // SAFETY: getsockname into a sockaddr_un with its length.
        let r = unsafe {
            libc::getsockname(sock_fd, &mut saddr as *mut libc::sockaddr_un as *mut libc::sockaddr, &mut len)
        };
        if r < 0 {
            return false;
        }
        let fam_len = std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t;
        if len as usize > std::mem::size_of::<libc::sockaddr_un>()
            || len <= fam_len
            || saddr.sun_family != libc::AF_UNIX as libc::sa_family_t
        {
            return false;
        }
        let path = sun_path_to_str(&saddr);
        if path.is_empty() {
            return false;
        }
        std::fs::remove_file(&path).is_ok()
    }

    /// `SCK_SetIntOption`: `setsockopt(level, name, (int)value)`.
    pub fn set_int_option(&self, sock_fd: c_int, level: c_int, name: c_int, value: c_int) -> bool {
        // SAFETY: setsockopt of a single int.
        let r = unsafe {
            libc::setsockopt(
                sock_fd,
                level,
                name,
                &value as *const c_int as *const libc::c_void,
                std::mem::size_of::<c_int>() as libc::socklen_t,
            )
        };
        r >= 0
    }

    /// `SCK_GetIntOption`: `getsockopt(level, name) -> int`.
    pub fn get_int_option(&self, sock_fd: c_int, level: c_int, name: c_int) -> Option<c_int> {
        let mut value: c_int = 0;
        let mut len = std::mem::size_of::<c_int>() as libc::socklen_t;
        // SAFETY: getsockopt into a single int with its length.
        let r = unsafe {
            libc::getsockopt(
                sock_fd,
                level,
                name,
                &mut value as *mut c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if r >= 0 {
            Some(value)
        } else {
            None
        }
    }

    /// `SCK_Send`: `send(buffer, length, 0)` (chrony asserts `flags == 0`).
    pub fn send(&self, sock_fd: c_int, buffer: &[u8]) -> isize {
        // SAFETY: send from a valid slice.
        unsafe {
            libc::send(sock_fd, buffer.as_ptr() as *const libc::c_void, buffer.len(), 0)
        }
    }

    /// `SCK_Receive`: `recv(buffer, length, get_recv_flags(flags))`.
    pub fn receive(&self, sock_fd: c_int, buffer: &mut [u8], flags: i32) -> isize {
        let recv_flags = codec::get_recv_flags(flags);
        // SAFETY: recv into a valid mutable slice.
        unsafe {
            libc::recv(
                sock_fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                recv_flags,
            )
        }
    }

    /// `SCK_EnableKernelRxTimestamping`: request kernel software RX timestamps on the socket
    /// (`SO_TIMESTAMPNS`, falling back to `SO_TIMESTAMP`). Returns whether either succeeded.
    /// (The BSD-only `SO_TS_CLOCK`/`SO_TS_REALTIME` refinement is not part of the Linux path.)
    pub fn enable_kernel_rx_timestamping(&self, sock_fd: c_int) -> bool {
        if self.set_int_option(sock_fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, 1) {
            return true;
        }
        self.set_int_option(sock_fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP, 1)
    }

    /// Enable kernel TX hardware and software timestamping on the socket via
    /// `SO_TIMESTAMPING` with `SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_TX_SOFTWARE`.
    /// Also enables RX hardware/software and raw hardware for completeness.
    pub fn enable_kernel_tx_timestamping(&self, sock_fd: c_int) -> bool {
        const SOF_TIMESTAMPING_TX_HARDWARE: i32 = 1 << 0;
        const SOF_TIMESTAMPING_TX_SOFTWARE: i32 = 1 << 1;
        const SOF_TIMESTAMPING_RX_HARDWARE: i32 = 1 << 2;
        const SOF_TIMESTAMPING_RX_SOFTWARE: i32 = 1 << 3;
        const SOF_TIMESTAMPING_RAW_HARDWARE: i32 = 1 << 4;
        let val: i32 = SOF_TIMESTAMPING_TX_HARDWARE
            | SOF_TIMESTAMPING_TX_SOFTWARE
            | SOF_TIMESTAMPING_RX_HARDWARE
            | SOF_TIMESTAMPING_RX_SOFTWARE
            | SOF_TIMESTAMPING_RAW_HARDWARE;
        // SAFETY: setsockopt of a single int.
        unsafe {
            libc::setsockopt(
                sock_fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                &val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            ) >= 0
        }
    }

    /// `SCK_CloseSocket`: `close()` (reusable sockets are closed at finalisation).
    pub fn close_socket(&self, sock_fd: c_int) {
        if self.is_reusable(sock_fd) {
            return;
        }
        // SAFETY: close of an fd this layer owns.
        unsafe {
            libc::close(sock_fd);
        }
    }

    /// `SCK_SendMessage` / `send_message`: `sendmsg()` with the remote address and the local
    /// address's `IP_PKTINFO` control message (built by the tested core codec). `data` is the
    /// message payload (chrony's `message->data`/`length`). Returns the number of bytes sent,
    /// or `-1`.
    pub fn send_message(
        &self,
        sock_fd: c_int,
        message: &SckMessage,
        data: &[u8],
        _flags: i32,
    ) -> isize {
        // Remote address.
        let mut sa = [0u8; codec::SIZEOF_SOCKADDR_IN6];
        let saddr_len = match message.addr_type {
            SckAddressType::Ip => {
                let cap = sa.len();
                codec::ip_sockaddr_to_sockaddr(&message.remote_ip, &mut sa, cap)
            }
            _ => 0,
        };

        // Control (PKTINFO for the source address), reusing the tested builder.
        let control = if message.addr_type == SckAddressType::Ip {
            codec::build_pktinfo_control(message.local_ip, message.if_index, codec::CMSG_BUF_SIZE)
        } else {
            None
        };
        let ctrl_bytes: &[u8] = control.as_ref().map(|c| c.bytes()).unwrap_or(&[]);

        let mut iov = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        // SAFETY: msghdr is fully initialised below; all pointers reference live buffers for
        // the duration of the sendmsg call.
        let mut msg: libc::msghdr = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        if saddr_len > 0 {
            msg.msg_name = sa.as_mut_ptr() as *mut libc::c_void;
            msg.msg_namelen = saddr_len as libc::socklen_t;
        }
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !ctrl_bytes.is_empty() {
            msg.msg_control = ctrl_bytes.as_ptr() as *mut libc::c_void;
            msg.msg_controllen = ctrl_bytes.len() as _;
        }
        // SAFETY: msg references buffers that outlive this call.
        unsafe { libc::sendmsg(sock_fd, &msg, 0) }
    }

    /// `SCK_ReceiveMessage`: the single-message path — `receive_messages` capped at one, taking
    /// the first result. Returns the received payload + extracted [`codec::ControlData`] +
    /// source address, or `None` on error/empty.
    pub fn receive_message(&self, sock_fd: c_int, flags: i32) -> Option<ReceivedMessage> {
        self.receive_messages(sock_fd, flags, 1).into_iter().next()
    }

    /// `receive_messages` / `SCK_ReceiveMessages`: batch-receive up to `max_messages` datagrams
    /// with a single `recvmmsg()`, decoding each one's ancillary data (destination/interface/
    /// timestamps) via the tested core cmsg parser and its source address via the tested
    /// sockaddr parser. Returns the successfully-decoded messages (chrony caps
    /// `SCK_ReceiveMessages` at `MAX_RECV_MESSAGES`).
    pub fn receive_messages(&self, sock_fd: c_int, flags: i32, max_messages: usize) -> Vec<ReceivedMessage> {
        if max_messages < 1 {
            return Vec::new();
        }
        let n = max_messages.min(MAX_RECV_MESSAGES);

        // Persistent-per-call buffers (chrony reuses module arrays; a fresh set per call is
        // behaviourally identical). prepare_buffers wires the iovec/msghdr to them.
        let mut names = vec![[0u8; codec::SIZEOF_SOCKADDR_IN6]; n];
        let mut ctrls = vec![[0u8; codec::CMSG_BUF_SIZE]; n];
        let mut datas: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; RECV_BUF_SIZE]).collect();
        let mut iovs = vec![libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; n];
        // SAFETY: mmsghdr is POD; every pointer field is set by prepare_buffers below.
        let mut hdrs: Vec<libc::mmsghdr> = (0..n).map(|_| unsafe { std::mem::MaybeUninit::zeroed().assume_init() }).collect();

        prepare_buffers(&mut hdrs, &mut iovs, &mut names, &mut ctrls, &mut datas);

        let recv_flags = codec::get_recv_flags(flags);
        // SAFETY: recvmmsg fills hdrs[..n], each pointing at the live buffers above.
        let ret = unsafe {
            libc::recvmmsg(sock_fd, hdrs.as_mut_ptr(), n as _, recv_flags as _, std::ptr::null_mut())
        };
        if ret < 0 {
            self.handle_recv_error(sock_fd, flags);
            return Vec::new();
        }
        let received = ret as usize;

        let mut out = Vec::with_capacity(received);
        for i in 0..received {
            let msg_len = hdrs[i].msg_len as usize;
            let controllen = (hdrs[i].msg_hdr.msg_controllen as usize).min(ctrls[i].len());
            let namelen = hdrs[i].msg_hdr.msg_namelen as usize;
            let control = codec::parse_control_data(&ctrls[i][..(controllen as usize)]);
            let remote = codec::sockaddr_to_ip_sockaddr(&names[i], namelen);
            let data = datas[i][..msg_len.min(RECV_BUF_SIZE)].to_vec();
            out.push(ReceivedMessage { data, control, remote });
        }
        out
    }

    /// `handle_recv_error`: when an error-queue read fails, the pending event is a socket
    /// error; read and clear `SO_ERROR` (setting `errno`) so the daemon's `select()` loop does
    /// not busy-spin on the same exception. Returns the cleared error value (chrony stores it
    /// in `errno`; we return it so the caller/test can observe it).
    pub fn handle_recv_error(&self, sock_fd: c_int, flags: i32) -> c_int {
        if flags & SCK_FLAG_MSG_ERRQUEUE != 0 {
            if let Some(error) = self.get_int_option(sock_fd, libc::SOL_SOCKET, libc::SO_ERROR) {
                set_errno(error);
                return error;
            }
        }
        0
    }
}

/// A received message: the payload plus the destination/interface metadata from the ancillary
/// data and the source address.
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    pub data: Vec<u8>,
    pub control: codec::ControlData,
    pub remote: IpSockAddr,
}

/// `MAX_RECV_MESSAGES` (`socket.c`): the `recvmmsg` batch size.
const MAX_RECV_MESSAGES: usize = 16;
/// Per-message receive buffer (chrony's `msg_buf`, sized for a jumbo NTP/cmd datagram).
const RECV_BUF_SIZE: usize = 16 * 1024;

/// `prepare_buffers`: wire each `mmsghdr` to its name/iovec/control buffers before a
/// `recvmmsg` (chrony resets the reused module buffers here). One `iovec` per message.
fn prepare_buffers(
    hdrs: &mut [libc::mmsghdr],
    iovs: &mut [libc::iovec],
    names: &mut [[u8; codec::SIZEOF_SOCKADDR_IN6]],
    ctrls: &mut [[u8; codec::CMSG_BUF_SIZE]],
    datas: &mut [Vec<u8>],
) {
    for i in 0..hdrs.len() {
        iovs[i].iov_base = datas[i].as_mut_ptr() as *mut libc::c_void;
        iovs[i].iov_len = datas[i].len();
        hdrs[i].msg_hdr.msg_name = names[i].as_mut_ptr() as *mut libc::c_void;
        hdrs[i].msg_hdr.msg_namelen = names[i].len() as libc::socklen_t;
        hdrs[i].msg_hdr.msg_iov = &mut iovs[i];
        hdrs[i].msg_hdr.msg_iovlen = 1;
        hdrs[i].msg_hdr.msg_control = ctrls[i].as_mut_ptr() as *mut libc::c_void;
        hdrs[i].msg_hdr.msg_controllen = ctrls[i].len() as _;
        hdrs[i].msg_hdr.msg_flags = 0;
        hdrs[i].msg_len = 0;
    }
}

/// `UTI_FdSetCloexec`: set the close-on-exec fd flag.
fn fd_set_cloexec(sock_fd: c_int) -> bool {
    // SAFETY: fcntl on an owned fd.
    unsafe {
        let flags = libc::fcntl(sock_fd, libc::F_GETFD);
        if flags < 0 {
            return false;
        }
        libc::fcntl(sock_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) >= 0
    }
}

/// `set_socket_nonblock`: `fcntl(F_SETFL, O_NONBLOCK)`.
fn set_socket_nonblock(sock_fd: c_int) -> bool {
    // SAFETY: fcntl on an owned fd.
    unsafe { libc::fcntl(sock_fd, libc::F_SETFL, libc::O_NONBLOCK) >= 0 }
}

fn last_errno() -> c_int {
    // SAFETY: __errno_location returns a valid pointer to thread-local errno.
    unsafe { *libc::__errno_location() }
}

fn set_errno(value: c_int) {
    // SAFETY: __errno_location returns a valid pointer to thread-local errno.
    unsafe { *libc::__errno_location() = value }
}

/// Build a `sockaddr_un` for `path` (chrony's `snprintf(sun_path, ...) >= size` rejection for
/// an over-long path). Returns the struct and the `sizeof(sockaddr_un)` length chrony passes.
fn fill_sockaddr_un(path: &str) -> Option<(libc::sockaddr_un, libc::socklen_t)> {
    // SAFETY: zeroed POD; fields set below.
    let mut saddr: libc::sockaddr_un = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    let bytes = path.as_bytes();
    // sun_path must hold the path plus a NUL terminator (chrony's snprintf contract).
    if bytes.len() + 1 > saddr.sun_path.len() {
        return None;
    }
    saddr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, &b) in saddr.sun_path.iter_mut().zip(bytes) {
        *dst = b as libc::c_char;
    }
    Some((saddr, std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t))
}

/// The NUL-terminated path out of a `sockaddr_un` (as a `String`, lossily).
fn sun_path_to_str(saddr: &libc::sockaddr_un) -> String {
    let mut out = Vec::new();
    for &c in saddr.sun_path.iter() {
        if c == 0 {
            break;
        }
        out.push(c as u8);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether an `IpSockAddr` carries the wildcard/any address (composing the core predicate).
fn is_any_ipsockaddr(a: &IpSockAddr) -> bool {
    let ip = match a.family {
        IPADDR_INET4 => IpAddr::Inet4(a.in4),
        IPADDR_INET6 => IpAddr::Inet6(a.in6),
        _ => IpAddr::Unspec,
    };
    codec::is_any_address(&ip)
}

