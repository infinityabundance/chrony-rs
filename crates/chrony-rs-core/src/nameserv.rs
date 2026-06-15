//! Hostname resolution — a complete port of chrony 4.5 `nameserv.c` (all 4
//! functions).
//!
//! # What this module is
//!
//! `nameserv.c` is chrony's **one** name-resolution entry point: forward resolution
//! (`DNS_Name2IPAddress`), reverse resolution (`DNS_IPAddress2Name`), the
//! address-family preference (`DNS_SetAddressFamily`), and a resolver reload
//! (`DNS_Reload`). It is the one place the core may touch the network, so it stays
//! isolated and clearly labelled; everything else in `chrony-rs-core` is
//! deterministic.
//!
//! # Two surfaces
//!
//! * [`name_to_ip`] is the daemon's convenience that resolves a name to its first
//!   address through the **real** system resolver (used by [`crate::cmdparse`] for
//!   `allow`/`deny` host rules, live-witnessed vs `chronyc accheck`). It is not
//!   deterministic and not court-backed — by nature.
//! * [`DnsResolver`] is the **faithful, court-backed port**: it reproduces chrony's
//!   exact resolution *logic* (the IP-literal shortcut, the address-family filtering,
//!   the IPv4 host-order / IPv6 scope-id handling, the result-array fill, the status
//!   mapping, and the reverse fallback) over an injected [`Resolver`] so the logic is
//!   testable without the network.
//!
//! # Adaptations (documented, not silent)
//!
//! * **`getaddrinfo`/`getnameinfo`/`res_init` are the injected [`Resolver`]**, as are
//!   the IP-literal parse (`UTI_StringToIP`) and format (`UTI_IPToString`) — those are
//!   `util.c`'s concern, reached through the same boundary here.
//! * IPv4 addresses are carried in **host order** (chrony's `ntohl` is applied by the
//!   resolver boundary that reads the `sockaddr`).
//!
//! # Oracle
//!
//! `DNS_Name2IPAddress`'s result processing is differential-tested against the **real
//! compiled `nameserv.c`** with `getaddrinfo` overridden to return a crafted
//! `addrinfo` list (`research/oracle/nameserv-c-vectors.txt`): the family filter, the
//! IPv4 extraction, the IPv6 scope-id skip, the `max_addrs` limit, and the
//! Success/TryAgain/Failure status mapping. The port replays the identical resolver
//! results and matches every address and status; the literal shortcut and the reverse
//! fallback are unit-tested. See the tests.

use std::net::ToSocketAddrs;

/// `DNS_Name2IPAddress` (first address): resolve `name` through the system resolver,
/// returning the first address or `None`. The daemon's convenience; not deterministic.
pub fn name_to_ip(name: &str) -> Option<std::net::IpAddr> {
    (name, 0u16).to_socket_addrs().ok()?.next().map(|sa| sa.ip())
}

/// chrony `DNS_MAX_ADDRESSES`.
pub const DNS_MAX_ADDRESSES: usize = 16;

/// chrony address-family markers (`IPADDR_*`).
pub const IPADDR_UNSPEC: i32 = 0;
pub const IPADDR_INET4: i32 = 1;
pub const IPADDR_INET6: i32 = 2;

/// chrony `DNS_Status`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DnsStatus {
    /// `DNS_Success`.
    Success,
    /// `DNS_TryAgain`.
    TryAgain,
    /// `DNS_Failure`.
    Failure,
}

/// An `IPAddr` (the subset `nameserv` produces). IPv4 is host-order.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum IpAddr {
    /// `IPADDR_UNSPEC`.
    #[default]
    Unspec,
    /// `IPADDR_INET4` (host order).
    V4(u32),
    /// `IPADDR_INET6`.
    V6([u8; 16]),
}

impl IpAddr {
    /// The `IPADDR_*` family marker.
    pub fn family(&self) -> i32 {
        match self {
            IpAddr::Unspec => IPADDR_UNSPEC,
            IpAddr::V4(_) => IPADDR_INET4,
            IpAddr::V6(_) => IPADDR_INET6,
        }
    }
}

/// One address returned by the resolver (a `getaddrinfo` `addrinfo` node). IPv4 is
/// host order; IPv6 carries its scope id so the scope-loss skip can be reproduced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResolvedAddr {
    /// `AF_INET` -> host-order address.
    V4(u32),
    /// `AF_INET6` -> 16 bytes + scope id.
    V6 { addr: [u8; 16], scope_id: u32 },
}

/// The host boundary: `getaddrinfo`/`getnameinfo`/`res_init` plus the IP-literal
/// parse/format that `nameserv.c` reaches through `util.c`.
pub trait Resolver {
    /// `getaddrinfo(name)` with the family hint, returning the address list or the
    /// mapped failure status (`TryAgain` on `EAI_AGAIN`, else `Failure`).
    fn resolve(&mut self, name: &str, family: i32) -> Result<Vec<ResolvedAddr>, DnsStatus>;
    /// `getnameinfo(ip)` reverse lookup, `None` if it fails.
    fn reverse(&mut self, ip: &IpAddr) -> Option<String>;
    /// `res_init()`.
    fn reload(&mut self);
    /// `UTI_StringToIP(s)`: parse an IP literal, `None` if `s` is not one.
    fn parse_ip_literal(&mut self, s: &str) -> Option<IpAddr>;
    /// `UTI_IPToString(ip)`.
    fn ip_to_string(&mut self, ip: &IpAddr) -> String;
}

/// The resolver state (chrony's `nameserv.c` module global `address_family`).
#[derive(Default)]
pub struct DnsResolver {
    address_family: i32,
}

impl DnsResolver {
    /// A resolver with no family preference.
    pub fn new() -> DnsResolver {
        DnsResolver { address_family: IPADDR_UNSPEC }
    }

    /// chrony `DNS_SetAddressFamily`.
    pub fn set_address_family(&mut self, family: i32) {
        self.address_family = family;
    }

    /// chrony `DNS_Name2IPAddress`: resolve `name` into `ip_addrs` (capped at
    /// `DNS_MAX_ADDRESSES`), returning the status.
    pub fn name_to_ipaddress(
        &mut self,
        resolver: &mut dyn Resolver,
        name: &str,
        ip_addrs: &mut [IpAddr],
        max_addrs: usize,
    ) -> DnsStatus {
        let max_addrs = max_addrs.min(DNS_MAX_ADDRESSES).min(ip_addrs.len());

        for ip in ip_addrs.iter_mut().take(max_addrs) {
            *ip = IpAddr::Unspec;
        }

        // Avoid calling getaddrinfo() if the name is an IP address.
        if let Some(ip) = resolver.parse_ip_literal(name) {
            if self.address_family != IPADDR_UNSPEC && ip.family() != self.address_family {
                return DnsStatus::Failure;
            }
            if max_addrs >= 1 {
                ip_addrs[0] = ip;
            }
            return DnsStatus::Success;
        }

        let list = match resolver.resolve(name, self.address_family) {
            Ok(list) => list,
            Err(status) => return status,
        };

        let mut i = 0;
        for a in list {
            if i >= max_addrs {
                break;
            }
            match a {
                ResolvedAddr::V4(v) => {
                    if self.address_family != IPADDR_UNSPEC && self.address_family != IPADDR_INET4 {
                        continue;
                    }
                    ip_addrs[i] = IpAddr::V4(v);
                    i += 1;
                }
                ResolvedAddr::V6 { addr, scope_id } => {
                    if self.address_family != IPADDR_UNSPEC && self.address_family != IPADDR_INET6 {
                        continue;
                    }
                    // Don't return an address that would lose a scope ID.
                    if scope_id != 0 {
                        continue;
                    }
                    ip_addrs[i] = IpAddr::V6(addr);
                    i += 1;
                }
            }
        }

        if max_addrs == 0 || ip_addrs[0] != IpAddr::Unspec {
            DnsStatus::Success
        } else {
            DnsStatus::Failure
        }
    }

    /// chrony `DNS_IPAddress2Name`: reverse-resolve `ip` into `name` (`len` bytes).
    /// Returns whether the name fit (chrony's `snprintf` truncation check).
    pub fn ipaddress_to_name(
        &mut self,
        resolver: &mut dyn Resolver,
        ip: &IpAddr,
        name: &mut String,
        len: usize,
    ) -> bool {
        let result = resolver.reverse(ip).unwrap_or_else(|| resolver.ip_to_string(ip));
        // snprintf(name, len, "%s", result) >= len  =>  truncated.
        if result.len() >= len {
            return false;
        }
        *name = result;
        true
    }

    /// chrony `DNS_Reload`.
    pub fn reload(&mut self, resolver: &mut dyn Resolver) {
        resolver.reload();
    }
}

#[cfg(test)]
mod tests;
