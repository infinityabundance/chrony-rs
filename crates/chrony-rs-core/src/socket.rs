//! Socket address marshalling — a port of the `IPSockAddr` ⇄ `struct sockaddr` conversions
//! from chrony 4.5 `socket.c` (`SCK_IPSockAddrToSockaddr` / `SCK_SockaddrToIPSockAddr`).
//!
//! These translate between chrony's compact `IPSockAddr` (family + address + port) and the
//! OS `struct sockaddr_in` / `sockaddr_in6` the kernel exchanges on every send/recv. They are
//! pure byte/struct serialization; the socket syscalls, buffer management, and the rest of
//! `socket.c` are the host boundary.
//!
//! The `struct sockaddr` layout here is the **little-endian Linux ABI** the oracle observes
//! (`AF_INET = 2`, `AF_INET6 = 10`; `sockaddr_in` = 16 bytes, `sockaddr_in6` = 28): the
//! `sa_family` field is a native-order `u16`, while the port and address are network order.

/// chrony `IPADDR_*` families.
pub const IPADDR_UNSPEC: i32 = 0;
pub const IPADDR_INET4: i32 = 1;
pub const IPADDR_INET6: i32 = 2;

/// Linux socket address families.
pub const AF_UNSPEC: u16 = 0;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Linux `struct sockaddr*` sizes.
pub const SIZEOF_SOCKADDR: usize = 16;
pub const SIZEOF_SOCKADDR_IN: usize = 16;
pub const SIZEOF_SOCKADDR_IN6: usize = 28;

/// chrony's `IPSockAddr` (an `IPAddr` plus a port).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpSockAddr {
    /// `IPADDR_UNSPEC` / `IPADDR_INET4` / `IPADDR_INET6`.
    pub family: i32,
    /// IPv4 address in host order.
    pub in4: u32,
    /// IPv6 address bytes (network order).
    pub in6: [u8; 16],
    pub port: u16,
}

/// `SCK_IPSockAddrToSockaddr`: serialize `ip` into the `sa` buffer as a `struct sockaddr_in`
/// / `sockaddr_in6`, zeroing the struct first. Returns the number of bytes written, or 0 for
/// an unspecified family or a buffer smaller than `sa_length` requires. (`sa_length` is the
/// caller's declared capacity, mirroring the C signature; `sa` must hold that many bytes.)
pub fn ip_sockaddr_to_sockaddr(ip: &IpSockAddr, sa: &mut [u8], sa_length: usize) -> usize {
    match ip.family {
        IPADDR_INET4 => {
            if sa_length < SIZEOF_SOCKADDR_IN {
                return 0;
            }
            sa[..SIZEOF_SOCKADDR_IN].fill(0);
            sa[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            sa[2..4].copy_from_slice(&ip.port.to_be_bytes()); // sin_port
            sa[4..8].copy_from_slice(&ip.in4.to_be_bytes()); // sin_addr (htonl)
            SIZEOF_SOCKADDR_IN
        }
        IPADDR_INET6 => {
            if sa_length < SIZEOF_SOCKADDR_IN6 {
                return 0;
            }
            sa[..SIZEOF_SOCKADDR_IN6].fill(0);
            sa[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            sa[2..4].copy_from_slice(&ip.port.to_be_bytes()); // sin6_port
            // sin6_flowinfo (4..8) stays zero; sin6_addr at 8..24; sin6_scope_id (24..28) zero.
            sa[8..24].copy_from_slice(&ip.in6);
            SIZEOF_SOCKADDR_IN6
        }
        _ => {
            if sa_length < SIZEOF_SOCKADDR {
                return 0;
            }
            sa[..SIZEOF_SOCKADDR].fill(0);
            sa[0..2].copy_from_slice(&AF_UNSPEC.to_ne_bytes());
            0
        }
    }
}

/// `SCK_SockaddrToIPSockAddr`: parse the `sa` buffer (declared length `sa_length`) into an
/// `IpSockAddr`. An unknown family, or a buffer too short for the family's struct, yields
/// `IPADDR_UNSPEC` with port 0 (chrony leaves the address field untouched in that case; here
/// it is the `Default` zero).
pub fn sockaddr_to_ip_sockaddr(sa: &[u8], sa_length: usize) -> IpSockAddr {
    let mut ip = IpSockAddr::default();
    if sa.len() < 2 {
        return ip;
    }
    match u16::from_ne_bytes([sa[0], sa[1]]) {
        AF_INET => {
            if sa_length < SIZEOF_SOCKADDR_IN {
                return ip;
            }
            ip.family = IPADDR_INET4;
            ip.in4 = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);
            ip.port = u16::from_be_bytes([sa[2], sa[3]]);
        }
        AF_INET6 => {
            if sa_length < SIZEOF_SOCKADDR_IN6 {
                return ip;
            }
            ip.family = IPADDR_INET6;
            ip.in6.copy_from_slice(&sa[8..24]);
            ip.port = u16::from_be_bytes([sa[2], sa[3]]);
        }
        _ => {}
    }
    ip
}

/// `AF_UNIX` (Linux).
pub const AF_UNIX: u16 = 1;

/// chrony `domain_to_string`: a human label for a socket domain (`AF_*`).
pub fn domain_to_string(domain: u16) -> &'static str {
    match domain {
        AF_INET => "IPv4",
        AF_INET6 => "IPv6",
        AF_UNIX => "Unix",
        AF_UNSPEC => "UNSPEC",
        _ => "?",
    }
}

/// `SCK_GetAnyLocalIPAddress`: the wildcard ("any") address for a family (`INADDR_ANY` /
/// `in6addr_any`). `family` is a chrony `IPADDR_*` tag.
pub fn get_any_local_ip_address(family: u16) -> crate::util::IpAddr {
    use crate::util::IpAddr;
    match family as i32 {
        IPADDR_INET4 => IpAddr::Inet4(0),
        IPADDR_INET6 => IpAddr::Inet6([0u8; 16]),
        _ => IpAddr::Unspec,
    }
}

/// `SCK_GetLoopbackIPAddress`: the loopback address for a family (`127.0.0.1` / `::1`).
pub fn get_loopback_ip_address(family: u16) -> crate::util::IpAddr {
    use crate::util::IpAddr;
    match family as i32 {
        IPADDR_INET4 => IpAddr::Inet4(0x7f00_0001), // INADDR_LOOPBACK (host order)
        IPADDR_INET6 => {
            let mut a = [0u8; 16];
            a[15] = 1;
            IpAddr::Inet6(a)
        }
        _ => IpAddr::Unspec,
    }
}

/// chrony `is_any_address`: whether `addr` is the wildcard address for its family.
pub fn is_any_address(addr: &crate::util::IpAddr) -> bool {
    crate::util::compare_ips(&get_any_local_ip_address(addr.family()), addr, None) == 0
}

/// `SCK_IsLinkLocalIPAddress`: whether `addr` is IPv4 link-local (`169.254.0.0/16`) or IPv6
/// link-local (`fe80::/10`).
pub fn is_link_local_ip_address(addr: &crate::util::IpAddr) -> bool {
    use crate::util::IpAddr;
    match addr {
        IpAddr::Inet4(a) => (a & 0xffff_0000) == 0xa9fe_0000,
        IpAddr::Inet6(b) => b[0] == 0xfe && (b[1] & 0xc0) == 0x80,
        _ => false,
    }
}

// ---- Received control-message (cmsg) parsing (process_header's loop) ----

use crate::util::IpAddr;

/// cmsg levels / types (Linux ABI values).
pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_IPV6: i32 = 41;
pub const SOL_SOCKET: i32 = 1;
pub const IP_PKTINFO: i32 = 8;
pub const IPV6_PKTINFO: i32 = 50;
pub const SCM_TIMESTAMP: i32 = 29;
pub const SCM_TIMESTAMPING: i32 = 37;
pub const SCM_TIMESTAMPING_PKTINFO: i32 = 58;

/// `sizeof(struct cmsghdr)` on 64-bit Linux (`cmsg_len` size_t + two ints).
const CMSG_HDR_LEN: usize = 16;

/// `CMSG_ALIGN`: round up to the `size_t` alignment (8 bytes).
fn cmsg_align(x: usize) -> usize {
    (x + 7) & !7
}

/// The control data chrony extracts from a received message's ancillary data (a subset of
/// `SCK_Message` / `NTP_Local_Timestamp`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ControlData {
    /// Destination address (`IP_PKTINFO` / `IPV6_PKTINFO`), or `Unspec`.
    pub local: IpAddr,
    /// Receiving interface index.
    pub if_index: i32,
    /// Layer-2 length (`SCM_TIMESTAMPING_PKTINFO`).
    pub l2_length: i32,
    /// Kernel software timestamp `(sec, nsec)`.
    pub kernel_ts: (i64, i64),
    /// Hardware timestamp `(sec, nsec)`.
    pub hw_ts: (i64, i64),
}

impl Default for ControlData {
    fn default() -> Self {
        ControlData {
            local: IpAddr::Unspec,
            if_index: 0,
            l2_length: 0,
            kernel_ts: (0, 0),
            hw_ts: (0, 0),
        }
    }
}

/// chrony `process_header`'s ancillary-data loop: walk the received control buffer's
/// `cmsghdr`s and extract the destination address, interface index, layer-2 length, and
/// kernel/hardware timestamps. Reproduces the Linux `CMSG_*` iteration (16-byte header,
/// 8-byte alignment) over the raw control bytes. The `SCM_RIGHTS` fd-passing, `IP_RECVERR`
/// error-queue validation, and the socket recv itself are the host boundary.
pub fn parse_control_data(control: &[u8]) -> ControlData {
    let mut cd = ControlData::default();
    let end = control.len();
    if end < CMSG_HDR_LEN {
        return cd;
    }

    let le64 = |o: usize| i64::from_le_bytes(control[o..o + 8].try_into().unwrap());
    let le32 = |o: usize| i32::from_le_bytes(control[o..o + 4].try_into().unwrap());
    let be32 = |o: usize| u32::from_be_bytes(control[o..o + 4].try_into().unwrap());

    let mut off = 0usize;
    loop {
        let len = u64::from_le_bytes(control[off..off + 8].try_into().unwrap()) as usize;
        let level = le32(off + 8);
        let ctype = le32(off + 12);
        // A complete cmsg must fit; a truncated/over-claiming one ends the walk.
        if len < CMSG_HDR_LEN || off + cmsg_align(len) > end {
            break;
        }
        let d = off + CMSG_HDR_LEN;
        let matches = |wl: i32, wt: i32, wdl: usize| {
            ctype == wt && level == wl && (wdl == 0 || len == CMSG_HDR_LEN + wdl)
        };

        if matches(IPPROTO_IP, IP_PKTINFO, 12) {
            cd.if_index = le32(d); // ipi_ifindex
            cd.local = IpAddr::Inet4(be32(d + 8)); // ntohl(ipi_addr)
        } else if matches(IPPROTO_IPV6, IPV6_PKTINFO, 20) {
            cd.local = IpAddr::Inet6(control[d..d + 16].try_into().unwrap());
            cd.if_index = le32(d + 16); // ipi6_ifindex
        } else if matches(SOL_SOCKET, SCM_TIMESTAMP, 16) {
            cd.kernel_ts = (le64(d), le64(d + 8) * 1000); // timeval: usec -> nsec
        } else if matches(SOL_SOCKET, SCM_TIMESTAMPING_PKTINFO, 16) {
            cd.if_index = le32(d); // scm_ts_pktinfo.if_index (u32)
            cd.l2_length = le32(d + 4); // pkt_length
        } else if matches(SOL_SOCKET, SCM_TIMESTAMPING, 48) {
            cd.kernel_ts = (le64(d), le64(d + 8)); // ts[0]
            cd.hw_ts = (le64(d + 32), le64(d + 40)); // ts[2]
        }

        // CMSG_NXTHDR.
        let next = off + cmsg_align(len);
        if next + CMSG_HDR_LEN > end {
            break;
        }
        let next_len = u64::from_le_bytes(control[next..next + 8].try_into().unwrap()) as usize;
        if next + cmsg_align(next_len) > end {
            break;
        }
        off = next;
    }
    cd
}

// ---- Transmit-side message construction (SCK_Message init + send_message's cmsg build) ----

/// `INVALID_IF_INDEX` (`addressing.h`).
pub const INVALID_IF_INDEX: i32 = -1;
/// `INVALID_SOCK_FD` (`socket.c`).
pub const INVALID_SOCK_FD: i32 = -4;
/// `CMSG_BUF_SIZE` (`socket.c`): the fixed control-buffer size for a transmitted message.
pub const CMSG_BUF_SIZE: usize = 256;

/// `SCK_FLAG_BLOCK` (`socket.h`, open flags).
pub const SCK_FLAG_BLOCK: i32 = 1;
/// `SCK_FLAG_MSG_ERRQUEUE` (`socket.h`, message flags).
pub const SCK_FLAG_MSG_ERRQUEUE: i32 = 1;
/// Linux `SOCK_NONBLOCK` / `MSG_ERRQUEUE` (the kernel flag bits chrony maps to).
pub const SOCK_NONBLOCK: i32 = 0x800;
pub const MSG_ERRQUEUE: i32 = 0x2000;

/// `SCK_AddressType` (`socket.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum SckAddressType {
    Unspec,
    Ip,
    Unix,
}

/// The host-independent fields of chrony's `SCK_Message`. The `data` pointer and socket
/// `descriptor` are modeled as an owned length / fd int; the raw send/recv syscalls that
/// consume this are the host boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct SckMessage {
    pub addr_type: SckAddressType,
    pub length: i32,
    pub if_index: i32,
    pub remote_ip: IpSockAddr,
    pub remote_path: Option<String>,
    pub local_ip: IpAddr,
    pub ts_kernel: (i64, i64),
    pub ts_hw: (i64, i64),
    pub ts_if_index: i32,
    pub ts_l2_length: i32,
    pub ts_tx_flags: i32,
    pub descriptor: i32,
}

impl SckMessage {
    /// `init_message_addresses`: set the address type and clear the address fields it selects
    /// (chrony leaves the other union arm untouched).
    fn init_addresses(&mut self, addr_type: SckAddressType) {
        self.addr_type = addr_type;
        match addr_type {
            SckAddressType::Unspec => {}
            SckAddressType::Ip => {
                self.remote_ip = IpSockAddr::default();
                self.local_ip = IpAddr::Unspec;
            }
            SckAddressType::Unix => {
                self.remote_path = None;
            }
        }
    }

    /// `init_message_nonaddress`: clear the data/length, interface index, timestamps, and
    /// descriptor to their sentinel defaults.
    fn init_nonaddress(&mut self) {
        self.length = 0;
        self.if_index = INVALID_IF_INDEX;
        self.ts_kernel = (0, 0);
        self.ts_hw = (0, 0);
        self.ts_if_index = INVALID_IF_INDEX;
        self.ts_l2_length = 0;
        self.ts_tx_flags = 0;
        self.descriptor = INVALID_SOCK_FD;
    }

    /// `SCK_InitMessage`: a freshly-initialised message of the given address type.
    pub fn init(addr_type: SckAddressType) -> Self {
        let mut m = SckMessage {
            addr_type: SckAddressType::Unspec,
            length: 0,
            if_index: INVALID_IF_INDEX,
            remote_ip: IpSockAddr::default(),
            remote_path: None,
            local_ip: IpAddr::Unspec,
            ts_kernel: (0, 0),
            ts_hw: (0, 0),
            ts_if_index: INVALID_IF_INDEX,
            ts_l2_length: 0,
            ts_tx_flags: 0,
            descriptor: INVALID_SOCK_FD,
        };
        m.init_addresses(addr_type);
        m.init_nonaddress();
        m
    }
}

/// `get_open_flags`: the socket-creation flags — the runtime-probed `supported_socket_flags`
/// with `SOCK_NONBLOCK` cleared when the caller requested blocking mode. `supported` is
/// chrony's probed global (the host boundary), passed in explicitly.
pub fn get_open_flags(supported: i32, flags: i32) -> i32 {
    let mut r = supported;
    if flags & SCK_FLAG_BLOCK != 0 {
        r &= !SOCK_NONBLOCK;
    }
    r
}

/// `get_recv_flags`: the `recvmsg` flags — `MSG_ERRQUEUE` iff the error-queue read was
/// requested.
pub fn get_recv_flags(flags: i32) -> i32 {
    let mut recv_flags = 0;
    if flags & SCK_FLAG_MSG_ERRQUEUE != 0 {
        recv_flags |= MSG_ERRQUEUE;
    }
    recv_flags
}

/// `CMSG_LEN`: header + data (no trailing alignment).
fn cmsg_len(data_len: usize) -> usize {
    CMSG_HDR_LEN + data_len
}
/// `CMSG_SPACE`: header + data rounded up to the alignment.
fn cmsg_space(data_len: usize) -> usize {
    cmsg_align(CMSG_HDR_LEN + data_len)
}

/// A `msghdr` control buffer under construction — chrony's `cmsg_buf` array plus the growing
/// `msg_controllen`.
#[derive(Clone, Debug)]
pub struct ControlBuffer {
    buf: Vec<u8>,
    controllen: usize,
}

impl ControlBuffer {
    /// A zeroed buffer of `capacity` bytes (chrony sizes it `CMSG_BUF_SIZE`).
    pub fn new(capacity: usize) -> Self {
        ControlBuffer { buf: vec![0u8; capacity], controllen: 0 }
    }

    /// The control bytes written so far (`msg_control[..msg_controllen]`).
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.controllen]
    }

    /// `msg_controllen`.
    pub fn controllen(&self) -> usize {
        self.controllen
    }

    /// chrony `add_control_message`: append a `cmsghdr` (`level`/`type`/`CMSG_LEN(length)`)
    /// with `length` zeroed data bytes. Returns the offset of `CMSG_DATA` for the caller to
    /// fill, or `None` (chrony's `NULL`) when the message would overflow the buffer. Mirrors
    /// chrony's non-`CMSG_NXTHDR` manual advance and the `length > buf_length` /
    /// `controllen + CMSG_SPACE > buf_length` guards.
    pub fn add_control_message(&mut self, level: i32, ctype: i32, length: usize) -> Option<usize> {
        let cap = self.buf.len();
        let space = cmsg_space(length);
        if length > cap || self.controllen + space > cap {
            return None;
        }
        let base = self.controllen;
        for b in &mut self.buf[base..base + space] {
            *b = 0;
        }
        self.buf[base..base + 8].copy_from_slice(&(cmsg_len(length) as u64).to_le_bytes());
        self.buf[base + 8..base + 12].copy_from_slice(&level.to_le_bytes());
        self.buf[base + 12..base + 16].copy_from_slice(&ctype.to_le_bytes());
        self.controllen += space;
        Some(base + CMSG_HDR_LEN)
    }

    fn write(&mut self, off: usize, bytes: &[u8]) {
        self.buf[off..off + bytes.len()].copy_from_slice(bytes);
    }
}

/// chrony `send_message`'s local-address control-message assembly: build the `IP_PKTINFO`
/// (v4) / `IPV6_PKTINFO` (v6) ancillary data that pins the source address (and interface,
/// unless [`INVALID_IF_INDEX`]) of a transmitted packet. Returns the populated control
/// buffer, or `None` if a cmsg would overflow. A non-IP `local` yields an empty buffer (no
/// control message). This is the exact transmit-side inverse of [`parse_control_data`]; the
/// terminal `sendmsg` and the `HAVE_LINUX_TIMESTAMPING` TX-timestamp cmsg are host boundaries.
pub fn build_pktinfo_control(local: IpAddr, if_index: i32, capacity: usize) -> Option<ControlBuffer> {
    let mut cb = ControlBuffer::new(capacity);
    match local {
        IpAddr::Inet4(a) => {
            // struct in_pktinfo { int ipi_ifindex; struct in_addr ipi_spec_dst; struct in_addr ipi_addr; }
            let d = cb.add_control_message(IPPROTO_IP, IP_PKTINFO, 12)?;
            // ipi_spec_dst = htonl(addr) — network-order bytes at offset +4.
            cb.write(d + 4, &a.to_be_bytes());
            if if_index != INVALID_IF_INDEX {
                cb.write(d, &if_index.to_le_bytes());
            }
        }
        IpAddr::Inet6(a) => {
            // struct in6_pktinfo { struct in6_addr ipi6_addr; unsigned int ipi6_ifindex; }
            let d = cb.add_control_message(IPPROTO_IPV6, IPV6_PKTINFO, 20)?;
            cb.write(d, &a);
            if if_index != INVALID_IF_INDEX {
                cb.write(d + 16, &if_index.to_le_bytes());
            }
        }
        _ => {}
    }
    Some(cb)
}

// ---------------------------------------------------------------------------
// Remaining socket.c functions — reusable socket management, privilege bind,
// device bind, and message logging.
// ---------------------------------------------------------------------------

/// `SCK_CloseReusableSockets`: close all sockets that were opened as reusable
/// (shared across multiple bindings). Host boundary.
pub fn sck_close_reusable_sockets<F: FnOnce()>(close: F) {
    close();
}

/// `SCK_SetPrivBind`: enable or disable privileged binding (binding to ports
/// below 1024). On Linux this calls setsockopt with IP_FREEBIND or similar.
/// Host boundary.
pub fn sck_set_priv_bind<F: FnOnce(bool)>(enable: bool, set: F) {
    set(enable);
}

/// `bind_device`: bind a socket to a specific network device (SO_BINDTODEVICE).
/// Host boundary (setsockopt).
pub fn bind_device<F: FnOnce(i32, &str)>(fd: i32, device: &str, bind: F) {
    bind(fd, device);
}

/// `get_reusable_socket`: look up a reusable socket by address and port.
/// Returns the socket fd if one exists.
pub fn get_reusable_socket<F: FnOnce() -> Option<i32>>(lookup: F) -> Option<i32> {
    lookup()
}

/// `log_message`: log a socket-related message (e.g., a bind failure or
/// option-setting error). Host boundary (delegates to the logging subsystem).
pub fn log_message<F: FnOnce(&str)>(msg: &str, log: F) {
    log(msg);
}

#[cfg(test)]
mod tests;
