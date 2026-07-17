//! Differential oracle for the sockaddr codec vs verbatim copies of chrony's
//! `SCK_IPSockAddrToSockaddr` / `SCK_SockaddrToIPSockAddr`, compiled against the real OS
//! `struct sockaddr_in` / `sockaddr_in6` (`research/oracle/socket-sockaddr-c-vectors.txt`).

use super::*;
use crate::util::IpAddr;

fn f<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("missing {key} in: {line}"))
}
fn n(line: &str, key: &str) -> i64 {
    f(line, key).parse().unwrap()
}
fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".to_string();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn matches_real_c_sockaddr_vectors() {
    let vectors = include_str!("../../../../research/oracle/socket-sockaddr-c-vectors.txt");

    // Pin the ABI constants against the compiled struct sizes.
    let hdr = vectors.lines().find(|l| l.starts_with("HDR ")).unwrap();
    assert_eq!(n(hdr, "AF_INET") as u16, AF_INET, "AF_INET");
    assert_eq!(n(hdr, "AF_INET6") as u16, AF_INET6, "AF_INET6");
    assert_eq!(n(hdr, "szin") as usize, SIZEOF_SOCKADDR_IN, "sizeof sockaddr_in");
    assert_eq!(n(hdr, "szin6") as usize, SIZEOF_SOCKADDR_IN6, "sizeof sockaddr_in6");
    assert_eq!(n(hdr, "szsa") as usize, SIZEOF_SOCKADDR, "sizeof sockaddr");

    // The inputs the generator used, keyed by case name.
    let v6_2x = |base: u8| -> [u8; 16] { std::array::from_fn(|i| base + i as u8) };
    let tosa_input = |name: &str| -> (IpSockAddr, usize) {
        match name {
            "v4" => (IpSockAddr { family: IPADDR_INET4, in4: 0xc000_0207, port: 4460, ..Default::default() }, 64),
            "v6" => (IpSockAddr { family: IPADDR_INET6, in6: v6_2x(0x20), port: 123, ..Default::default() }, 64),
            "unspec" => (IpSockAddr::default(), 64),
            "v4_short" => (IpSockAddr { family: IPADDR_INET4, in4: 0x0808_0808, port: 53, ..Default::default() }, 4),
            "v6_short" => (IpSockAddr { family: IPADDR_INET6, port: 1, ..Default::default() }, 20),
            other => panic!("unknown TOSA case {other}"),
        }
    };

    for line in vectors.lines() {
        if let Some(rest) = line.strip_prefix("TOSA ") {
            let name = f(rest, "name");
            let (ip, sa_length) = tosa_input(name);
            let mut sa = vec![0xEEu8; 64];
            let ret = ip_sockaddr_to_sockaddr(&ip, &mut sa, sa_length);
            assert_eq!(ret as i64, n(rest, "ret"), "TOSA {name} ret");
            if f(rest, "bytes") != "-" {
                // The written struct is compared byte-for-byte (native little-endian ABI).
                let want = unhex(f(rest, "bytes"));
                assert_eq!(hex(&sa[..want.len()]), hex(&want), "TOSA {name} bytes");
            }
        } else if let Some(rest) = line.strip_prefix("TOIP ") {
            let name = f(rest, "name");
            // Reproduce the generator: build a sockaddr (build direction is pinned by TOSA
            // above), then parse it back — or a hand-built AF_UNIX sockaddr.
            let (sa, sa_length) = match name {
                "v4" => {
                    let ip = IpSockAddr { family: IPADDR_INET4, in4: 0xac10_0009, port: 443, ..Default::default() };
                    let mut b = vec![0u8; 64];
                    let l = ip_sockaddr_to_sockaddr(&ip, &mut b, 64);
                    (b, l)
                }
                "v6" => {
                    let ip = IpSockAddr { family: IPADDR_INET6, in6: v6_2x(0x30), port: 8080, ..Default::default() };
                    let mut b = vec![0u8; 64];
                    let l = ip_sockaddr_to_sockaddr(&ip, &mut b, 64);
                    (b, l)
                }
                "v4_short" => {
                    let ip = IpSockAddr { family: IPADDR_INET4, in4: 0x7f00_0001, port: 22, ..Default::default() };
                    let mut b = vec![0u8; 64];
                    ip_sockaddr_to_sockaddr(&ip, &mut b, 64);
                    (b, 4) // parse with a too-short declared length
                }
                "unix" => {
                    let mut b = vec![0u8; 16];
                    b[0..2].copy_from_slice(&1u16.to_ne_bytes()); // AF_UNIX
                    (b, 16)
                }
                other => panic!("unknown TOIP case {other}"),
            };
            let out = sockaddr_to_ip_sockaddr(&sa, sa_length);
            assert_eq!(out.family as i64, n(rest, "fam"), "TOIP {name} fam");
            assert_eq!(out.port as i64, n(rest, "port"), "TOIP {name} port");
            // The address is only defined for a recognized family (chrony leaves it
            // untouched otherwise — the oracle prints uninitialized bytes there).
            if out.family == IPADDR_INET4 {
                assert_eq!(format!("{:08x}", out.in4), f(rest, "addr"), "TOIP {name} addr");
            } else if out.family == IPADDR_INET6 {
                assert_eq!(hex(&out.in6), f(rest, "addr"), "TOIP {name} addr");
            }
        }
    }
}

/// Differential oracle for the socket address utilities (domain_to_string, the wildcard /
/// loopback addresses, is_any_address, and SCK_IsLinkLocalIPAddress) vs verbatim copies
/// using the real OS INADDR_*/in6addr_* constants
/// (`research/oracle/socket-addrutil-c-vectors.txt`).
#[test]
fn matches_real_c_addrutil_vectors() {
    let vectors = include_str!("../../../../research/oracle/socket-addrutil-c-vectors.txt");
    fn v6(h: &str) -> IpAddr {
        let b: Vec<u8> =
            (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect();
        IpAddr::Inet6(b.try_into().unwrap())
    }
    let named_addr = |name: &str| -> IpAddr {
        match name {
            "v4_zero" => IpAddr::Inet4(0),
            "v4_nonzero" => IpAddr::Inet4(0x0102_0304),
            "v6_zero" => v6("00000000000000000000000000000000"),
            "v6_one" => v6("00000000000000000000000000000001"),
            "v4_ll" => IpAddr::Inet4(0xa9fe_0101),
            "v4_not" => IpAddr::Inet4(0xa9fd_0101),
            "v4_pub" => IpAddr::Inet4(0x0808_0808),
            "v6_ll" => v6("fe800000000000000000000000000000"),
            "v6_ll2" => v6("febf0000000000000000000000000001"),
            "v6_fec0" => v6("fec00000000000000000000000000000"),
            "v6_pub" => v6("20010db8000000000000000000000001"),
            other => panic!("unknown addr {other}"),
        }
    };

    for line in vectors.lines() {
        if let Some(rest) = line.strip_prefix("HDR ") {
            assert_eq!(n(rest, "AF_INET") as u16, AF_INET);
            assert_eq!(n(rest, "AF_INET6") as u16, AF_INET6);
            assert_eq!(n(rest, "AF_UNIX") as u16, AF_UNIX);
            assert_eq!(n(rest, "AF_UNSPEC") as u16, AF_UNSPEC);
        } else if let Some(rest) = line.strip_prefix("DOM ") {
            assert_eq!(domain_to_string(n(rest, "dom") as u16), f(rest, "s"), "DOM {}", f(rest, "dom"));
        } else if let Some(rest) = line.strip_prefix("ANY ") {
            let a = get_any_local_ip_address(n(rest, "fam") as u16);
            match a {
                IpAddr::Inet4(v) => assert_eq!(format!("{v:08x}"), f(rest, "in4"), "ANY in4"),
                IpAddr::Inet6(b) => assert_eq!(hex(&b), f(rest, "in6"), "ANY in6"),
                _ => panic!("ANY unexpected"),
            }
        } else if let Some(rest) = line.strip_prefix("LOOP ") {
            let a = get_loopback_ip_address(n(rest, "fam") as u16);
            match a {
                IpAddr::Inet4(v) => assert_eq!(format!("{v:08x}"), f(rest, "in4"), "LOOP in4"),
                IpAddr::Inet6(b) => assert_eq!(hex(&b), f(rest, "in6"), "LOOP in6"),
                _ => panic!("LOOP unexpected"),
            }
        } else if let Some(rest) = line.strip_prefix("ISANY ") {
            let a = named_addr(f(rest, "name"));
            assert_eq!(is_any_address(&a) as i64, n(rest, "r"), "ISANY {}", f(rest, "name"));
        } else if let Some(rest) = line.strip_prefix("LL ") {
            let a = named_addr(f(rest, "name"));
            assert_eq!(is_link_local_ip_address(&a) as i64, n(rest, "r"), "LL {}", f(rest, "name"));
        }
    }
}

/// Differential oracle for the received-cmsg parser vs a verbatim copy of chrony's
/// `process_header` ancillary-data loop, compiled against the real Linux `CMSG_*` macros and
/// `in_pktinfo`/`scm_timestamping`/`scm_ts_pktinfo` structs
/// (`research/oracle/socket-cmsg-c-vectors.txt`).
#[test]
fn matches_real_c_cmsg_vectors() {
    let vectors = include_str!("../../../../research/oracle/socket-cmsg-c-vectors.txt");

    // Pin the ABI constants against the compiled values.
    let hdr = vectors.lines().find(|l| l.starts_with("HDR ")).unwrap();
    assert_eq!(n(hdr, "CMSGHDR") as usize, 16, "sizeof cmsghdr");
    assert_eq!(n(hdr, "ALIGN"), 8, "CMSG_ALIGN unit");
    assert_eq!(n(hdr, "IP_PKTINFO") as i32, IP_PKTINFO);
    assert_eq!(n(hdr, "IPV6_PKTINFO") as i32, IPV6_PKTINFO);
    assert_eq!(n(hdr, "SCM_TS") as i32, SCM_TIMESTAMPING);
    assert_eq!(n(hdr, "SCM_TSPKT") as i32, SCM_TIMESTAMPING_PKTINFO);
    assert_eq!(n(hdr, "SCM_STAMP") as i32, SCM_TIMESTAMP);
    assert_eq!(n(hdr, "SOL_SOCKET") as i32, SOL_SOCKET);
    assert_eq!(n(hdr, "IPPROTO_IP") as i32, IPPROTO_IP);
    assert_eq!(n(hdr, "IPPROTO_IPV6") as i32, IPPROTO_IPV6);

    fn ts(line: &str, key: &str) -> (i64, i64) {
        let v = f(line, key);
        let (s, ns) = v.split_once('.').unwrap();
        (s.parse().unwrap(), ns.parse().unwrap())
    }

    for line in vectors.lines().filter(|l| l.starts_with("CMSG ")) {
        let name = f(line, "name");
        let ctrl = unhex(f(line, "ctrl"));
        let cd = parse_control_data(&ctrl);

        let want_fam = n(line, "fam");
        match cd.local {
            IpAddr::Inet4(v) => {
                assert_eq!(want_fam, 1, "{name} fam");
                assert_eq!(format!("{v:08x}"), f(line, "in4"), "{name} in4");
            }
            IpAddr::Inet6(b) => {
                assert_eq!(want_fam, 2, "{name} fam");
                assert_eq!(hex(&b), f(line, "in6"), "{name} in6");
            }
            _ => assert_eq!(want_fam, 0, "{name} fam"),
        }
        assert_eq!(cd.if_index as i64, n(line, "if"), "{name} if");
        assert_eq!(cd.l2_length as i64, n(line, "l2"), "{name} l2");
        assert_eq!(cd.kernel_ts, ts(line, "k"), "{name} kernel_ts");
        assert_eq!(cd.hw_ts, ts(line, "hw"), "{name} hw_ts");
    }
}

#[test]
fn build_pktinfo_control_matches_real_c() {
    // Differential vs the verbatim add_control_message + send_message PKTINFO assembly using
    // the real CMSG_* macros (socket-control-msg oracle).
    let v = include_str!("../../../../research/oracle/socket-control-msg-c-vectors.txt");
    let field = |l: &str, k: &str| -> Option<String> {
        l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}=")).map(str::to_string))
    };
    // Pin the ABI constants the oracle reports.
    let cline = v.lines().find(|l| l.contains("cmsghdr_len=")).unwrap();
    assert_eq!(field(cline, "cmsghdr_len").unwrap(), "16");
    assert_eq!(field(cline, "cmsg_space_ip4").unwrap(), "32");
    assert_eq!(field(cline, "cmsg_space_ip6").unwrap(), "40");

    let a6: [u8; 16] = std::array::from_fn(|i| (0x20 + i) as u8);
    let case = |tag: &str, local: IpAddr, if_index: i32| {
        let line = v.lines().find(|l| l.split_whitespace().next() == Some(tag)).unwrap();
        let cb = build_pktinfo_control(local, if_index, CMSG_BUF_SIZE).expect("built");
        assert_eq!(
            cb.controllen().to_string(),
            field(line, "controllen").unwrap(),
            "{tag} controllen"
        );
        let got: String = cb.bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, field(line, "buf").unwrap(), "{tag} bytes");
    };
    case("V4_IDX", IpAddr::Inet4(0xc0a8_0101), 5);
    case("V4_NOIDX", IpAddr::Inet4(0x0a00_0001), INVALID_IF_INDEX);
    case("V4_ZERO", IpAddr::Inet4(0), 0);
    case("V6_IDX", IpAddr::Inet6(a6), 7);
    case("V6_NOIDX", IpAddr::Inet6(a6), INVALID_IF_INDEX);
}

#[test]
fn add_control_message_overflow_and_flags() {
    // add_control_message rejects a cmsg that would overflow the buffer (chrony returns NULL).
    let mut cb = ControlBuffer::new(16); // room for a header but no aligned data
    assert!(cb.add_control_message(IPPROTO_IP, IP_PKTINFO, 12).is_none());
    // A non-IP local address yields no control message.
    let cb = build_pktinfo_control(IpAddr::Unspec, 3, CMSG_BUF_SIZE).unwrap();
    assert_eq!(cb.controllen(), 0);

    // get_open_flags clears SOCK_NONBLOCK only when BLOCK is requested.
    let supported = SOCK_NONBLOCK | 0x8_0000; // NONBLOCK | CLOEXEC (a typical probe)
    assert_eq!(get_open_flags(supported, 0), supported);
    assert_eq!(get_open_flags(supported, SCK_FLAG_BLOCK), supported & !SOCK_NONBLOCK);
    // get_recv_flags maps the error-queue request bit.
    assert_eq!(get_recv_flags(0), 0);
    assert_eq!(get_recv_flags(SCK_FLAG_MSG_ERRQUEUE), MSG_ERRQUEUE);
}

#[test]
fn sck_init_message_sets_sentinels() {
    // SCK_InitMessage: address fields cleared per type; timestamps zeroed; if_index/descriptor
    // at their INVALID sentinels.
    let m = SckMessage::init(SckAddressType::Ip);
    assert_eq!(m.addr_type, SckAddressType::Ip);
    assert_eq!(m.remote_ip, IpSockAddr::default());
    assert_eq!(m.local_ip, IpAddr::Unspec);
    assert_eq!((m.length, m.if_index), (0, INVALID_IF_INDEX));
    assert_eq!((m.ts_kernel, m.ts_hw), ((0, 0), (0, 0)));
    assert_eq!((m.ts_if_index, m.ts_l2_length, m.ts_tx_flags), (INVALID_IF_INDEX, 0, 0));
    assert_eq!(m.descriptor, INVALID_SOCK_FD);

    let u = SckMessage::init(SckAddressType::Unix);
    assert_eq!(u.addr_type, SckAddressType::Unix);
    assert_eq!(u.remote_path, None);
}
