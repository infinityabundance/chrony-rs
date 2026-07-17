//! NTP server access control — `ntp_core.c` Stage 10 (`NCR_AddAccessRestriction`,
//! `NCR_CheckAccessRestriction`).
//!
//! These are chrony's NTP-server `allow`/`deny` surface (the `allow`/`deny` config
//! directives and the `chronyc allow`/`deny` commands). They operate on the access
//! authorisation table — the already-ported address filter ([`crate::addrfilt`],
//! chrony's `addrfilt.c`):
//!
//! * [`add_access_restriction`] dispatches an `(allow, all)` request to the matching
//!   `ADF_*` table operation and reports whether it succeeded,
//! * [`check_access_restriction`] answers whether an address is permitted.
//!
//! # Adaptation (documented, not silent)
//!
//! chrony's `NCR_AddAccessRestriction` also opens/closes the server sockets as the set
//! of allowed addresses changes (`NIO_OpenServerSocket` / `NIO_CloseServerSocket`).
//! Sockets are a host boundary in this reconstruction, so that I/O is **not** performed
//! here; the function returns whether the restriction was applied and the caller drives
//! the socket lifecycle from the table state ([`crate::addrfilt::AuthTable::is_any_allowed`]).
//!
//! # Oracle
//!
//! The `(allow, all)` → `ADF_*` dispatch and the status→return mapping are
//! differential-tested against the **real compiled `ntp_core.c`** via the `#include`
//! harness with recording ADF stubs (`research/oracle/ntp_core-access-c-vectors.txt`).
//! The end-to-end allow/deny behaviour is independently checked against the ported ADF
//! table (itself courted against `addrfilt.c`). See the tests.

use crate::addrfilt::{AdfStatus, AuthTable, Subnet};
use std::net::IpAddr;

/// The `ADF_*` table operation selected by an `(allow, all)` request — chrony's 2×2
/// dispatch in `NCR_AddAccessRestriction`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum AccessOp {
    Allow,
    AllowAll,
    Deny,
    DenyAll,
}

/// chrony's `(allow, all)` → `ADF_*` selection.
pub fn select_access_op(allow: bool, all: bool) -> AccessOp {
    match (allow, all) {
        (true, false) => AccessOp::Allow,
        (true, true) => AccessOp::AllowAll,
        (false, false) => AccessOp::Deny,
        (false, true) => AccessOp::DenyAll,
    }
}

/// chrony `NCR_AddAccessRestriction`: apply an `allow`/`deny` (optionally `all`)
/// restriction for `subnet`/`subnet_bits` to the access table. Returns `true` on success
/// (chrony's `1`), `false` if the table rejected the subnet (chrony's `0`).
///
/// The server-socket open/close side effect is a host-boundary concern (see the module
/// docs) and is not performed here.
pub fn add_access_restriction(
    table: &mut AuthTable,
    subnet: Subnet,
    subnet_bits: i32,
    allow: bool,
    all: bool,
) -> bool {
    let status = match select_access_op(allow, all) {
        AccessOp::Allow => table.allow(subnet, subnet_bits),
        AccessOp::AllowAll => table.allow_all(subnet, subnet_bits),
        AccessOp::Deny => table.deny(subnet, subnet_bits),
        AccessOp::DenyAll => table.deny_all(subnet, subnet_bits),
    };
    status == AdfStatus::Success
}

/// chrony `NCR_CheckAccessRestriction`: whether `ip` is permitted by the access table.
pub fn check_access_restriction(table: &AuthTable, ip: IpAddr) -> bool {
    table.is_allowed(ip)
}

#[cfg(test)]
mod tests;
