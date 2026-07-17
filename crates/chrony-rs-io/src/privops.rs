//! Privileged-operation helper — a faithful port of chrony 4.5 `privops.c` (the Linux
//! `NAME2IPADDRESS`/`RELOADDNS` configuration, i.e. the seccomp build where DNS resolution is
//! delegated to an unfiltered helper process).
//!
//! chrony's seccomp-filtered main thread cannot call `getaddrinfo`, so at startup it forks a
//! small helper connected by a Unix socketpair; the daemon sends resolution requests and the
//! helper replies with the addresses. This module reproduces that: the fork + socketpair setup
//! ([`PrivHelper::start`]), the request/response IPC ([`submit_request`]-style round trip over
//! the [`crate::socket`] layer), the helper loop ([`helper_main`]), and the DNS operations
//! (`do_name_to_ipaddress` / `do_reload_dns`).
//!
//! The IPC is entirely internal (daemon ↔ its own fork), so a faithful port reproduces the
//! request/response *protocol and behaviour*, not chrony's private C-struct memcpy layout.
//! Verified by a **kernel-integration test** (`tests/privops.rs`) that forks a real helper and
//! round-trips a resolution request over the real socketpair.
//!
//! The privileged clock operations (`ADJUSTTIMEX`/`SETTIME`/`BINDSOCKET`) belong to other
//! `configure` profiles (NetBSD `clockctl`, etc.) and are not part of this Linux path.

use crate::socket::{Sockets, SCK_FLAG_BLOCK};
use chrony_rs_core::util::{string_to_ip, IpAddr};
use std::os::raw::c_int;

/// Operation codes (`privops.c`).
const OP_NAME2IPADDRESS: u32 = 1028;
const OP_RELOADDNS: u32 = 1029;
const OP_QUIT: u32 = 1099;

/// `DNS_MAX_ADDRESSES`.
const DNS_MAX_ADDRESSES: usize = 16;
/// `sizeof(ReqName2IPAddress.name)`.
const NAME_LEN: usize = 256;

/// `DNS_Status` integer values (`nameserv.h`).
pub const DNS_SUCCESS: i32 = 0;
pub const DNS_TRY_AGAIN: i32 = 1;
pub const DNS_FAILURE: i32 = 2;

// ---- Wire framing (internal protocol; message-boundary-preserving SEQPACKET/DGRAM) ----

fn encode_request(op: u32, name: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + NAME_LEN);
    buf.extend_from_slice(&op.to_le_bytes());
    let mut namebuf = [0u8; NAME_LEN];
    let n = name.len().min(NAME_LEN - 1);
    namebuf[..n].copy_from_slice(&name.as_bytes()[..n]);
    buf.extend_from_slice(&namebuf);
    buf
}

fn decode_request(buf: &[u8]) -> Option<(u32, String)> {
    if buf.len() < 4 {
        return None;
    }
    let op = u32::from_le_bytes(buf[0..4].try_into().expect("op fits in 4 bytes"));
    let name = if buf.len() >= 4 + NAME_LEN {
        let raw = &buf[4..4 + NAME_LEN];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    } else {
        String::new()
    };
    Some((op, name))
}

fn encode_response(rc: i32, addrs: &[IpAddr]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&rc.to_le_bytes());
    let n = addrs.len().min(DNS_MAX_ADDRESSES) as u32;
    buf.extend_from_slice(&n.to_le_bytes());
    for a in addrs.iter().take(DNS_MAX_ADDRESSES) {
        match a {
            IpAddr::Inet4(v) => {
                buf.push(1);
                buf.extend_from_slice(&v.to_be_bytes());
                buf.extend_from_slice(&[0u8; 12]);
            }
            IpAddr::Inet6(v) => {
                buf.push(2);
                buf.extend_from_slice(v);
            }
            _ => {
                buf.push(0);
                buf.extend_from_slice(&[0u8; 16]);
            }
        }
    }
    buf
}

fn decode_response(buf: &[u8]) -> (i32, Vec<IpAddr>) {
    if buf.len() < 8 {
        return (DNS_FAILURE, Vec::new());
    }
    let rc = i32::from_le_bytes(buf[0..4].try_into().expect("rc fits in 4 bytes"));
    let n = u32::from_le_bytes(buf[4..8].try_into().expect("n fits in 4 bytes")) as usize;
    let mut addrs = Vec::new();
    let mut off = 8;
    for _ in 0..n.min(DNS_MAX_ADDRESSES) {
        if off + 17 > buf.len() {
            break;
        }
        let fam = buf[off];
        let body = &buf[off + 1..off + 17];
        addrs.push(match fam {
            1 => IpAddr::Inet4(u32::from_be_bytes(body[..4].try_into().expect("addr fits in 4 bytes"))),
            2 => IpAddr::Inet6(body.try_into().expect("addr6 fits in 16 bytes")),
            _ => IpAddr::Unspec,
        });
        off += 17;
    }
    (rc, addrs)
}

/// chrony `do_name_to_ipaddress`: resolve `name` (the ported `DNS_Name2IPAddress` behaviour —
/// an IP literal is returned directly; otherwise `getaddrinfo` via `std::net`). Returns the
/// `DNS_Status` code and the resolved addresses.
pub fn do_name_to_ipaddress(name: &str) -> (i32, Vec<IpAddr>) {
    // IP-literal fast path (no getaddrinfo), matching DNS_Name2IPAddress.
    if let Some(ip) = string_to_ip(name) {
        return (DNS_SUCCESS, vec![ip]);
    }
    match (name, 0u16).to_socket_addrs_lenient() {
        Ok(list) if !list.is_empty() => (DNS_SUCCESS, list),
        Ok(_) => (DNS_FAILURE, Vec::new()),
        Err(again) => (if again { DNS_TRY_AGAIN } else { DNS_FAILURE }, Vec::new()),
    }
}

/// `do_reload_dns`: reset the resolver (`DNS_Reload`/`res_init`). A no-op with `std::net`'s
/// resolver; `rc = 0`.
pub fn do_reload_dns() -> i32 {
    0
}

/// chrony `send_request`: send a request (op + name) to the helper.
pub fn send_request(sockets: &Sockets, fd: c_int, op: u32, name: &str) -> bool {
    sockets.send(fd, &encode_request(op, name)) >= 0
}

/// chrony `receive_from_daemon`: read the next request on the helper's socket. Returns the
/// `(op, name)`, or `None` when the daemon closed the connection.
pub fn receive_from_daemon(sockets: &Sockets, fd: c_int) -> Option<(u32, String)> {
    let mut buf = vec![0u8; 4 + NAME_LEN];
    let r = sockets.receive(fd, &mut buf, 0);
    if r <= 0 {
        return None;
    }
    decode_request(&buf[..r as usize])
}

/// chrony `send_response`: send a response (status + addresses) back to the daemon.
pub fn send_response(sockets: &Sockets, fd: c_int, rc: i32, addrs: &[IpAddr]) -> bool {
    sockets.send(fd, &encode_response(rc, addrs)) >= 0
}

/// chrony `receive_response`: read the helper's response on the daemon's socket.
pub fn receive_response(sockets: &Sockets, fd: c_int) -> (i32, Vec<IpAddr>) {
    let mut buf = vec![0u8; 8 + DNS_MAX_ADDRESSES * 17];
    let r = sockets.receive(fd, &mut buf, 0);
    if r <= 0 {
        return (DNS_FAILURE, Vec::new());
    }
    decode_response(&buf[..r as usize])
}

/// chrony `submit_request`: `send_request` then `receive_response`.
pub fn submit_request(sockets: &Sockets, fd: c_int, op: u32, name: &str) -> (i32, Vec<IpAddr>) {
    send_request(sockets, fd, op, name);
    receive_response(sockets, fd)
}

/// chrony `helper_main`/`run_helper`: the child's serve loop — receive a request, dispatch it,
/// send the response, until `OP_QUIT` (or the daemon closes the socket). Runs in the forked
/// child on `helper_fd`.
pub fn helper_main(sockets: &Sockets, helper_fd: c_int) {
    while let Some((op, name)) = receive_from_daemon(sockets, helper_fd) {
        match op {
            OP_NAME2IPADDRESS => {
                let (rc, addrs) = do_name_to_ipaddress(&name);
                send_response(sockets, helper_fd, rc, &addrs);
            }
            OP_RELOADDNS => {
                send_response(sockets, helper_fd, do_reload_dns(), &[]);
            }
            _ => break, // OP_QUIT or unknown
        }
    }
}

/// The daemon-side handle to the privileged helper (chrony's `helper_fd`/`helper_pid`).
#[derive(Debug)]
pub struct PrivHelper {
    helper_fd: c_int,
    helper_pid: libc::pid_t,
}

impl PrivHelper {
    /// chrony `PRV_StartHelper`: open a Unix socketpair and `fork()` the helper, which runs
    /// [`helper_main`] on its end and exits on `OP_QUIT`. Returns `None` if the socketpair or
    /// fork fails.
    pub fn start(sockets: &Sockets) -> Option<PrivHelper> {
        let (sock_fd1, sock_fd2) = sockets.open_unix_socket_pair(SCK_FLAG_BLOCK)?;
        // SAFETY: fork(); the child path only performs async-safe socket I/O and _exit.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            sockets.close_socket(sock_fd1);
            sockets.close_socket(sock_fd2);
            return None;
        }
        if pid == 0 {
            // Child: close the parent end, serve requests, then exit without running the
            // parent's atexit/test teardown.
            sockets.close_socket(sock_fd1);
            helper_main(sockets, sock_fd2);
            // SAFETY: terminate the child immediately.
            unsafe { libc::_exit(0) };
        }
        // Parent.
        sockets.close_socket(sock_fd2);
        Some(PrivHelper { helper_fd: sock_fd1, helper_pid: pid })
    }

    /// chrony `have_helper`.
    pub fn have_helper(&self) -> bool {
        self.helper_fd >= 0
    }

    /// `submit_request` for `OP_NAME2IPADDRESS` (`PRV_Name2IPAddress`'s helper path): send the
    /// name, receive the resolved addresses and status.
    pub fn name_to_ipaddress(&self, sockets: &Sockets, name: &str) -> (i32, Vec<IpAddr>) {
        if name.len() >= NAME_LEN {
            return (DNS_FAILURE, Vec::new());
        }
        submit_request(sockets, self.helper_fd, OP_NAME2IPADDRESS, name)
    }

    /// `submit_request` for `OP_RELOADDNS` (`PRV_ReloadDNS`'s helper path).
    pub fn reload_dns(&self, sockets: &Sockets) -> i32 {
        submit_request(sockets, self.helper_fd, OP_RELOADDNS, "").0
    }

    /// chrony `stop_helper`: send `OP_QUIT` and reap the child.
    pub fn stop(&mut self, sockets: &Sockets) {
        if !self.have_helper() {
            return;
        }
        sockets.send(self.helper_fd, &encode_request(OP_QUIT, ""));
        // SAFETY: reap the known child pid.
        let mut status: c_int = 0;
        unsafe {
            libc::waitpid(self.helper_pid, &mut status, 0);
        }
        sockets.close_socket(self.helper_fd);
        self.helper_fd = -1;
    }
}

/// A small `getaddrinfo` wrapper distinguishing "try again" from a hard failure, mirroring
/// chrony's `EAI_AGAIN → DNS_TryAgain` mapping. `Err(true)` means retryable.
trait ToSocketAddrsLenient {
    fn to_socket_addrs_lenient(&self) -> Result<Vec<IpAddr>, bool>;
}

impl ToSocketAddrsLenient for (&str, u16) {
    fn to_socket_addrs_lenient(&self) -> Result<Vec<IpAddr>, bool> {
        use std::net::ToSocketAddrs;
        match self.to_socket_addrs() {
            Ok(iter) => Ok(iter
                .map(|sa| match sa.ip() {
                    std::net::IpAddr::V4(v) => IpAddr::Inet4(u32::from(v)),
                    std::net::IpAddr::V6(v) => IpAddr::Inet6(v.octets()),
                })
                .collect()),
            // std does not surface EAI_AGAIN distinctly; treat all as hard failure.
            Err(_) => Err(false),
        }
    }
}
