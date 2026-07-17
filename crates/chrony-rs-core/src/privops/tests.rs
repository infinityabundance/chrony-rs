//! Tests for the `privops.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `privops.c`, driven end-to-end
//! through its actual `fork()` + Unix socketpair.** A C generator starts the real
//! helper and issues `PRV_AdjustTime` / `PRV_SetTime` (errno path) /
//! `PRV_Name2IPAddress` / `PRV_ReloadDNS` with the privileged ops overridden by
//! recording stubs, capturing each response
//! (`research/oracle/privops-c-vectors.txt`). [`matches_real_c_privops_vectors`]
//! drives the identical ops through [`dispatch`] over a backend returning the same
//! overridden values and matches every response field.
//!
//! **Oracle #2 (independent): the protocol invariants.** The bind port-validation
//! gate, the unknown-op `res_fatal` path, the `OP_QUIT` signal, and the client's
//! direct-vs-helper routing are unit-tested.

use super::*;

/// A backend mirroring the C oracle's overridden privileged ops.
struct OracleBackend {
    closed: Vec<i32>,
    bind_port: u16,
    bind_rc: i32,
    bind_errno: i32,
}

impl OracleBackend {
    fn new() -> OracleBackend {
        OracleBackend { closed: Vec::new(), bind_port: 123, bind_rc: 0, bind_errno: 0 }
    }
}

impl PrivBackend for OracleBackend {
    fn adjust_time(&mut self, _delta: Timeval) -> (i32, i32, Timeval) {
        // adjtime: old = {77, 88}, rc = 0.
        (0, 0, Timeval { sec: 77, usec: 88 })
    }
    fn adjust_timex(&mut self, tmx: Timex) -> (i32, i32, Timex) {
        (2, 0, tmx)
    }
    fn set_time(&mut self, _tv: Timeval) -> (i32, i32) {
        // settimeofday: errno = 13, rc = -1.
        (-1, 13)
    }
    fn bind_socket(&mut self, _sock: i32, _addr: &SockAddr) -> (i32, i32) {
        (self.bind_rc, self.bind_errno)
    }
    fn name_to_ipaddress(&mut self, _name: &str) -> (i32, Vec<u32>) {
        // DNS_Name2IPAddress: addresses[0] = 0x01020304, rc = DNS_Success(0).
        (0, vec![0x0102_0304])
    }
    fn reload_dns(&mut self) {}
    fn sockaddr_port(&mut self, _addr: &SockAddr) -> u16 {
        self.bind_port
    }
    fn allowed_ports(&mut self) -> (u16, u16, u16) {
        (123, 0, 319)
    }
    fn close_socket(&mut self, sock: i32) {
        self.closed.push(sock);
    }
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}

#[test]
fn matches_real_c_privops_vectors() {
    let vectors = include_str!("../../../../research/oracle/privops-c-vectors.txt");
    let line = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    let mut be = OracleBackend::new();

    // ---- ADJUSTTIME ----
    let (res, quit) = dispatch(&PrivRequest::AdjustTime(Timeval { sec: 1, usec: 2 }), &mut be);
    assert!(!quit);
    let l = line("ADJUSTTIME");
    assert_eq!(res.rc, field(l, "rc").parse::<i32>().unwrap(), "ADJUSTTIME rc");
    match res.data {
        ResponseData::AdjustTime(old) => {
            assert_eq!(old.sec, field(l, "old_sec").parse::<i64>().unwrap(), "old sec");
            assert_eq!(old.usec, field(l, "old_usec").parse::<i64>().unwrap(), "old usec");
        }
        _ => panic!("expected AdjustTime payload"),
    }

    // ---- SETTIME (errno path) ----
    let (res, _) = dispatch(&PrivRequest::SetTime(Timeval { sec: 1000, usec: 0 }), &mut be);
    let l = line("SETTIME");
    assert_eq!(res.rc, field(l, "rc").parse::<i32>().unwrap(), "SETTIME rc");
    // The daemon sets errno from res_errno on a non-zero rc.
    assert_eq!(res.res_errno, field(l, "errno").parse::<i32>().unwrap(), "SETTIME errno");

    // ---- NAME2IPADDRESS ----
    let (res, _) = dispatch(&PrivRequest::Name2IpAddress("host.example".into()), &mut be);
    let l = line("NAME2IP");
    assert_eq!(res.rc, field(l, "rc").parse::<i32>().unwrap(), "NAME2IP rc");
    let expected = u32::from_str_radix(field(l, "addr0_in4").trim_start_matches("0x"), 16).unwrap();
    match res.data {
        ResponseData::Name2IpAddress(addrs) => assert_eq!(addrs[0], expected, "addr0"),
        _ => panic!("expected Name2IpAddress payload"),
    }

    // ---- RELOADDNS ----
    let (res, _) = dispatch(&PrivRequest::ReloadDns, &mut be);
    assert_eq!(res.rc, 0, "RELOADDNS rc");
    assert!(line("RELOADDNS").contains("done=1"));
}

#[test]
fn bind_port_validation_gate() {
    let mut be = OracleBackend::new();

    // An allowed port (NTP = 123) binds; the helper closes its copy of the fd.
    be.bind_port = 123;
    let (res, _) = dispatch(&PrivRequest::BindSocket { sock: 7, addr: SockAddr(vec![]) }, &mut be);
    assert!(!res.fatal_error, "allowed port binds");
    assert_eq!(res.rc, 0);
    assert_eq!(be.closed, vec![7], "fd closed after bind");

    // Port 0 (let the OS choose) is allowed.
    let (res, _) = dispatch(&PrivRequest::BindSocket { sock: 8, addr: SockAddr(vec![]) }, &mut {
        let mut b = OracleBackend::new();
        b.bind_port = 0;
        b
    });
    assert!(!res.fatal_error, "port 0 allowed");

    // A disallowed port is rejected with a fatal error and the fd is closed.
    let mut be2 = OracleBackend::new();
    be2.bind_port = 9999;
    let (res, _) = dispatch(&PrivRequest::BindSocket { sock: 9, addr: SockAddr(vec![]) }, &mut be2);
    assert!(res.fatal_error, "disallowed port rejected");
    assert_eq!(res.fatal_msg, "Invalid port 9999");
    assert_eq!(be2.closed, vec![9], "fd closed on rejection");
}

#[test]
fn unknown_op_is_fatal_and_quit_signals() {
    let mut be = OracleBackend::new();

    let (res, quit) = dispatch(&PrivRequest::Unknown(9999), &mut be);
    assert!(!quit);
    assert!(res.fatal_error);
    assert_eq!(res.fatal_msg, "Unexpected operator 9999");

    let (_res, quit) = dispatch(&PrivRequest::Quit, &mut be);
    assert!(quit, "OP_QUIT signals the helper loop to stop");
}

#[test]
fn client_routes_direct_or_to_helper() {
    // Without a helper, PRV_* perform the op directly via the backend.
    let mut client = PrivClient::new();
    assert!(!client.has_helper());
    let mut be = OracleBackend::new();
    let mut never = |_req: PrivRequest| -> PrivResponse {
        panic!("no helper: must not use the transport");
    };
    let (rc, old) = client.adjust_time(&mut never, &mut be, Some(Timeval { sec: 1, usec: 2 }));
    assert_eq!((rc, old.sec, old.usec), (0, 77, 88), "direct adjtime");
    assert_eq!(client.set_time(&mut never, &mut be, Timeval { sec: 5, usec: 0 }), -1, "direct settime");

    // A read-only adjtime query (delta = None) is always direct, even with a helper.
    client.set_helper_started();
    assert!(client.has_helper());
    let (rc, _) = client.adjust_time(&mut never, &mut be, None);
    assert_eq!(rc, 0, "None delta queried directly");

    // With a helper, a real adjustment goes through the transport.
    let mut transport = |req: PrivRequest| -> PrivResponse {
        assert_eq!(req, PrivRequest::SetTime(Timeval { sec: 9, usec: 0 }));
        PrivResponse { rc: 42, ..Default::default() }
    };
    assert_eq!(client.set_time(&mut transport, &mut be, Timeval { sec: 9, usec: 0 }), 42, "delegated");

    client.finalise();
    assert!(!client.has_helper());
}
