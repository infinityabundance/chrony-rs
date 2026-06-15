//! Hostname resolution — a port of the resolver entry point of chrony 4.5
//! `nameserv.c` (`DNS_Name2IPAddress`).
//!
//! # Boundary note (read this)
//!
//! This module is the **one place** in `chrony-rs-core` that performs name
//! resolution, and therefore the one place that may touch the network. Everywhere
//! else the core is side-effect-free and deterministic; resolution is not (it
//! depends on `/etc/hosts`, `nsswitch`, and DNS). It lives here, isolated and
//! clearly labelled, rather than being smeared through the config parser, so the
//! boundary stays auditable. Callers that must stay pure simply do not call it.
//!
//! chrony's `DNS_Name2IPAddress(name, addrs, 1)` resolves a name to its first
//! address; [`name_to_ip`] is that, via the system resolver (`getaddrinfo`).

use std::net::{IpAddr, ToSocketAddrs};

/// `DNS_Name2IPAddress` (first address): resolve `name` to an [`IpAddr`] using the
/// system resolver, returning the first address (chrony's `max = 1` behaviour) or
/// `None` if the name does not resolve. The port number is irrelevant — only
/// address resolution is wanted — so 0 is used.
pub fn name_to_ip(name: &str) -> Option<IpAddr> {
    (name, 0u16).to_socket_addrs().ok()?.next().map(|sa| sa.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_localhost_to_loopback() {
        // `localhost` is in /etc/hosts on every reasonable system, so this is
        // deterministic and needs no network.
        let ip = name_to_ip("localhost").expect("localhost must resolve");
        assert!(ip.is_loopback(), "expected a loopback address, got {ip}");
    }

    #[test]
    fn unresolvable_name_is_none() {
        // A syntactically valid but unregistered .invalid name (RFC 6761) must not
        // resolve.
        assert_eq!(name_to_ip("this-host-does-not-exist.invalid"), None);
    }
}
