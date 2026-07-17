//! Kernel-integration test for the privileged DNS helper: fork a real helper over a Unix
//! socketpair and round-trip resolution + reload requests.
//!
//! Resolution uses an IP *literal* ("127.0.0.1"), which `DNS_Name2IPAddress`/
//! `do_name_to_ipaddress` answer without calling `getaddrinfo` — keeping the forked child on
//! the async-safe fast path (no allocator-heavy resolver call after `fork`).

use chrony_rs_core::util::IpAddr;
use chrony_rs_io::privops::{PrivHelper, DNS_SUCCESS};
use chrony_rs_io::socket::Sockets;

#[test]
fn helper_resolves_literal_and_reloads() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(chrony_rs_core::socket::IPADDR_INET4);

    let mut helper = PrivHelper::start(&sck).expect("fork helper");
    assert!(helper.have_helper());

    // NAME2IPADDRESS over the socketpair: an IP literal resolves to itself.
    let (rc, addrs) = helper.name_to_ipaddress(&sck, "127.0.0.1");
    assert_eq!(rc, DNS_SUCCESS);
    assert_eq!(addrs, vec![IpAddr::Inet4(0x7f00_0001)]);

    // A second request on the same helper (v6 literal).
    let (rc6, addrs6) = helper.name_to_ipaddress(&sck, "::1");
    assert_eq!(rc6, DNS_SUCCESS);
    let mut v6 = [0u8; 16];
    v6[15] = 1;
    assert_eq!(addrs6, vec![IpAddr::Inet6(v6)]);

    // RELOADDNS round-trips with rc = 0.
    assert_eq!(helper.reload_dns(&sck), 0);

    // OP_QUIT + waitpid.
    helper.stop(&sck);
    assert!(!helper.have_helper());
}
