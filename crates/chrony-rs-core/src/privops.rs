//! Privilege separation — a complete port of chrony 4.5 `privops.c`.
//!
//! # What this module is
//!
//! chronyd drops root early but still needs a few privileged operations
//! (`adjtime`, `ntp_adjtime`, `settimeofday`, binding a low port, DNS resolution).
//! Before dropping privileges it forks a small **helper** that keeps them; the
//! daemon then asks the helper to perform those operations over a Unix-domain
//! socketpair. `privops.c` is both ends of that protocol: the daemon-side `PRV_*`
//! request senders and the helper-side dispatch loop.
//!
//! # Adaptations (documented, not silent)
//!
//! * **The fork/socketpair transport is the host's.** chrony forks in
//!   `PRV_StartHelper` and marshals C structs over the socket; here the daemon side
//!   is [`PrivClient`] with an injected transport closure, and the helper side is
//!   [`dispatch`]. The privileged operations themselves (`adjtime`, …) are the
//!   injected [`PrivBackend`]; the wire marshalling of the C structs (which carries
//!   platform-specific `struct timex`/`sockaddr` layouts and an `SCM_RIGHTS` file
//!   descriptor for the bind) stays the host transport's concern.
//! * **`receive_from_daemon`'s descriptor handling** (the bind op carries the socket
//!   fd as an out-of-band control message; any other op must not) is modelled by the
//!   transport delivering the fd alongside the [`PrivRequest::BindSocket`].
//!
//! # What is faithfully ported here
//!
//! The protocol *logic*: the daemon-side direct-vs-helper routing of every `PRV_*`
//! call, the helper-side op dispatch, the bind port-validation security gate, the
//! `res_fatal` path for an unknown op, and the response assembly (`rc`/`errno`/data,
//! with `errno` recorded only on the per-op failure condition chrony uses).
//!
//! # Oracle
//!
//! The helper dispatch + response assembly is differential-tested against the **real
//! compiled `privops.c`** driven end-to-end through its actual `fork()` +
//! socketpair: a C generator starts the real helper and issues `PRV_AdjustTime` /
//! `PRV_SetTime` (errno path) / `PRV_Name2IPAddress` / `PRV_ReloadDNS` with the
//! privileged ops overridden by recording stubs, capturing each response
//! (`research/oracle/privops-c-vectors.txt`). [`tests`] replays the identical ops
//! through [`dispatch`] over a matching backend and gets the same responses; the
//! bind port-validation gate and the client direct-vs-helper routing are
//! unit-tested.

/// A `struct timeval`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    pub sec: i64,
    pub usec: i64,
}

/// The kernel `struct timex`, forwarded verbatim by chrony (opaque to `privops`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Timex(pub Vec<u8>);

/// A socket address, opaque except for the bytes handed to `bind`. The port is
/// extracted by the backend (`SCK_SockaddrToIPSockAddr`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SockAddr(pub Vec<u8>);

/// chrony's operation codes (`OP_*`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivRequest {
    /// `OP_ADJUSTTIME`.
    AdjustTime(Timeval),
    /// `OP_ADJUSTTIMEX`.
    AdjustTimex(Timex),
    /// `OP_SETTIME`.
    SetTime(Timeval),
    /// `OP_BINDSOCKET` (the socket fd travels out of band; `sock` is its value).
    BindSocket { sock: i32, addr: SockAddr },
    /// `OP_NAME2IPADDRESS`.
    Name2IpAddress(String),
    /// `OP_RELOADDNS`.
    ReloadDns,
    /// `OP_QUIT`.
    Quit,
    /// Any unrecognised op code (the `default` arm).
    Unknown(i32),
}

/// chrony's numeric op codes.
pub mod op {
    pub const ADJUSTTIME: i32 = 1024;
    pub const ADJUSTTIMEX: i32 = 1025;
    pub const SETTIME: i32 = 1026;
    pub const BINDSOCKET: i32 = 1027;
    pub const NAME2IPADDRESS: i32 = 1028;
    pub const RELOADDNS: i32 = 1029;
    pub const QUIT: i32 = 1099;
}

impl PrivRequest {
    /// The op code chrony would tag this request with.
    pub fn op_code(&self) -> i32 {
        match self {
            PrivRequest::AdjustTime(_) => op::ADJUSTTIME,
            PrivRequest::AdjustTimex(_) => op::ADJUSTTIMEX,
            PrivRequest::SetTime(_) => op::SETTIME,
            PrivRequest::BindSocket { .. } => op::BINDSOCKET,
            PrivRequest::Name2IpAddress(_) => op::NAME2IPADDRESS,
            PrivRequest::ReloadDns => op::RELOADDNS,
            PrivRequest::Quit => op::QUIT,
            PrivRequest::Unknown(o) => *o,
        }
    }
}

/// `DNS_MAX_ADDRESSES`.
pub const DNS_MAX_ADDRESSES: usize = 16;

/// The per-op response payload (chrony's `PrvResponse.data` union, used part).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ResponseData {
    /// No payload.
    #[default]
    None,
    /// `ResAdjustTime` (the old delta).
    AdjustTime(Timeval),
    /// `ResAdjustTimex` (the mutated timex).
    AdjustTimex(Timex),
    /// `ResName2IPAddress` (resolved addresses).
    Name2IpAddress(Vec<u32>),
}

/// chrony's `PrvResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivResponse {
    /// `fatal_error`.
    pub fatal_error: bool,
    /// `fatal_msg.msg` (only when `fatal_error`).
    pub fatal_msg: String,
    /// `rc` — the return code of the privileged operation.
    pub rc: i32,
    /// `res_errno` — `errno` captured on failure.
    pub res_errno: i32,
    /// The op payload.
    pub data: ResponseData,
}

impl PrivResponse {
    /// chrony `res_fatal`.
    fn fatal(msg: String) -> PrivResponse {
        PrivResponse { fatal_error: true, fatal_msg: msg, ..Default::default() }
    }
}

/// The privileged operations the helper actually performs (`do_*`), plus the bind
/// port-validation inputs. All of these are real syscalls / other modules in chrony.
pub trait PrivBackend {
    /// `adjtime(delta)` -> `(rc, errno, olddelta)`.
    fn adjust_time(&mut self, delta: Timeval) -> (i32, i32, Timeval);
    /// `ntp_adjtime(tmx)` -> `(rc, errno, mutated tmx)`.
    fn adjust_timex(&mut self, tmx: Timex) -> (i32, i32, Timex);
    /// `settimeofday(tv)` -> `(rc, errno)`.
    fn set_time(&mut self, tv: Timeval) -> (i32, i32);
    /// `bind(sock, addr)` -> `(rc, errno)`.
    fn bind_socket(&mut self, sock: i32, addr: &SockAddr) -> (i32, i32);
    /// `DNS_Name2IPAddress(name)` -> `(rc, addresses)`.
    fn name_to_ipaddress(&mut self, name: &str) -> (i32, Vec<u32>);
    /// `DNS_Reload()`.
    fn reload_dns(&mut self);
    /// `SCK_SockaddrToIPSockAddr(addr).port`.
    fn sockaddr_port(&mut self, addr: &SockAddr) -> u16;
    /// `(CNF_GetNTPPort(), CNF_GetAcquisitionPort(), CNF_GetPtpPort())`.
    fn allowed_ports(&mut self) -> (u16, u16, u16);
    /// `SCK_CloseSocket` for the bind op (the helper closes its copy of the fd).
    fn close_socket(&mut self, sock: i32);
}

/// chrony `do_bind_socket`: validate the port, then bind. Closes the helper's fd.
fn do_bind_socket(backend: &mut dyn PrivBackend, sock: i32, addr: &SockAddr) -> PrivResponse {
    let port = backend.sockaddr_port(addr);
    let (ntp, acq, ptp) = backend.allowed_ports();
    if port != 0 && port != ntp && port != acq && port != ptp {
        backend.close_socket(sock);
        return PrivResponse::fatal(format!("Invalid port {port}"));
    }
    let (rc, errno) = backend.bind_socket(sock, addr);
    let mut res = PrivResponse { rc, ..Default::default() };
    if rc != 0 {
        res.res_errno = errno;
    }
    backend.close_socket(sock);
    res
}

/// chrony's `helper_main` body for one request: dispatch and assemble the response.
/// Returns `(response, quit)`; `quit` is set for `OP_QUIT` (no response is sent).
pub fn dispatch(req: &PrivRequest, backend: &mut dyn PrivBackend) -> (PrivResponse, bool) {
    let mut res = PrivResponse::default();
    match req {
        PrivRequest::AdjustTime(delta) => {
            let (rc, errno, old) = backend.adjust_time(*delta);
            res.rc = rc;
            if rc != 0 {
                res.res_errno = errno;
            }
            res.data = ResponseData::AdjustTime(old);
        }
        PrivRequest::AdjustTimex(tmx) => {
            let (rc, errno, mutated) = backend.adjust_timex(tmx.clone());
            res.rc = rc;
            // chrony records errno when rc < 0 for ntp_adjtime.
            if rc < 0 {
                res.res_errno = errno;
            }
            res.data = ResponseData::AdjustTimex(mutated);
        }
        PrivRequest::SetTime(tv) => {
            let (rc, errno) = backend.set_time(*tv);
            res.rc = rc;
            if rc != 0 {
                res.res_errno = errno;
            }
        }
        PrivRequest::BindSocket { sock, addr } => {
            res = do_bind_socket(backend, *sock, addr);
        }
        PrivRequest::Name2IpAddress(name) => {
            let (rc, addrs) = backend.name_to_ipaddress(name);
            res.rc = rc;
            res.data = ResponseData::Name2IpAddress(addrs);
        }
        PrivRequest::ReloadDns => {
            backend.reload_dns();
            res.rc = 0;
        }
        PrivRequest::Quit => return (res, true),
        PrivRequest::Unknown(o) => {
            res = PrivResponse::fatal(format!("Unexpected operator {o}"));
        }
    }
    (res, false)
}

/// The daemon side (`PRV_*`): routes each privileged call to the helper if one is
/// running, or performs it directly otherwise.
pub struct PrivClient {
    has_helper: bool,
}

/// A transport delivering a request to the helper and returning its response
/// (chrony's `submit_request` over the socketpair).
pub type Transport<'a> = &'a mut dyn FnMut(PrivRequest) -> PrivResponse;

impl PrivClient {
    /// chrony `PRV_Initialise` (no helper yet).
    pub fn new() -> PrivClient {
        PrivClient { has_helper: false }
    }

    /// Whether a helper is running (`have_helper`). Set after `PRV_StartHelper`.
    pub fn has_helper(&self) -> bool {
        self.has_helper
    }
    /// Mark the helper as started (chrony `PRV_StartHelper`; the fork is the host's).
    pub fn set_helper_started(&mut self) {
        self.has_helper = true;
    }
    /// chrony `PRV_Finalise` / `stop_helper`: the helper is gone.
    pub fn finalise(&mut self) {
        self.has_helper = false;
    }

    /// chrony `PRV_AdjustTime`. A `None` delta (a read-only query) is always done
    /// directly, as chrony does. Returns `(rc, olddelta)`.
    pub fn adjust_time(
        &self,
        transport: Transport,
        backend: &mut dyn PrivBackend,
        delta: Option<Timeval>,
    ) -> (i32, Timeval) {
        if !self.has_helper || delta.is_none() {
            let (rc, _errno, old) = backend.adjust_time(delta.unwrap_or_default());
            return (rc, old);
        }
        let res = transport(PrivRequest::AdjustTime(delta.unwrap()));
        let old = match res.data {
            ResponseData::AdjustTime(old) => old,
            _ => Timeval::default(),
        };
        (res.rc, old)
    }

    /// chrony `PRV_AdjustTimex`: returns `(rc, mutated timex)`.
    pub fn adjust_timex(
        &self,
        transport: Transport,
        backend: &mut dyn PrivBackend,
        tmx: Timex,
    ) -> (i32, Timex) {
        if !self.has_helper {
            let (rc, _errno, mutated) = backend.adjust_timex(tmx);
            return (rc, mutated);
        }
        let res = transport(PrivRequest::AdjustTimex(tmx.clone()));
        let mutated = match res.data {
            ResponseData::AdjustTimex(t) => t,
            _ => tmx,
        };
        (res.rc, mutated)
    }

    /// chrony `PRV_SetTime`: returns `rc`.
    pub fn set_time(&self, transport: Transport, backend: &mut dyn PrivBackend, tv: Timeval) -> i32 {
        if !self.has_helper {
            return backend.set_time(tv).0;
        }
        transport(PrivRequest::SetTime(tv)).rc
    }

    /// chrony `PRV_BindSocket`: returns `rc`. chrony asserts the port is allowed on
    /// the daemon side too; that gate is surfaced as `Err(port)`.
    pub fn bind_socket(
        &self,
        transport: Transport,
        backend: &mut dyn PrivBackend,
        sock: i32,
        addr: SockAddr,
    ) -> Result<i32, u16> {
        let port = backend.sockaddr_port(&addr);
        let (ntp, acq, ptp) = backend.allowed_ports();
        if port != 0 && port != ntp && port != acq && port != ptp {
            return Err(port);
        }
        if !self.has_helper {
            return Ok(backend.bind_socket(sock, &addr).0);
        }
        Ok(transport(PrivRequest::BindSocket { sock, addr }).rc)
    }

    /// chrony `PRV_ReloadDNS`.
    pub fn reload_dns(&self, transport: Transport, backend: &mut dyn PrivBackend) {
        if !self.has_helper {
            backend.reload_dns();
            return;
        }
        let _ = transport(PrivRequest::ReloadDns);
    }

    /// chrony `PRV_Name2IPAddress`: returns `(rc, addresses)`.
    pub fn name_to_ipaddress(
        &self,
        transport: Transport,
        backend: &mut dyn PrivBackend,
        name: &str,
        max_addrs: usize,
    ) -> (i32, Vec<u32>) {
        if !self.has_helper {
            return backend.name_to_ipaddress(name);
        }
        let res = transport(PrivRequest::Name2IpAddress(name.to_string()));
        let addrs = match res.data {
            ResponseData::Name2IpAddress(a) => {
                a.into_iter().take(max_addrs.min(DNS_MAX_ADDRESSES)).collect()
            }
            _ => Vec::new(),
        };
        (res.rc, addrs)
    }
}

impl Default for PrivClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
