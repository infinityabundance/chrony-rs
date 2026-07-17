//! Kernel-integration tests for the TCP + Unix-domain + socketpair socket paths.

use chrony_rs_core::socket::{IpSockAddr, IPADDR_INET4};
use chrony_rs_io::socket::Sockets;

fn loopback_v4(port: u16) -> IpSockAddr {
    IpSockAddr { family: IPADDR_INET4, in4: 0x7f00_0001, in6: [0; 16], port }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn tmp_path(tag: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("chrony-rs-io-{}-{}.sock", std::process::id(), tag));
    p.to_string_lossy().into_owned()
}

#[test]
fn tcp_listen_accept_connect_roundtrip() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);

    let port = free_port();
    let addr = loopback_v4(port);

    // Server: bound + listening TCP socket.
    let server = sck.open_tcp_socket(None, Some(&addr), None, 0);
    assert!(server >= 0, "server open failed: {server}");
    assert!(sck.listen_on_socket(server, 5));

    // Client: connect to the server (non-blocking → EINPROGRESS is success).
    let client = sck.open_tcp_socket(Some(&addr), None, None, 0);
    assert!(client >= 0, "client open failed: {client}");

    // Accept on the server, retrying while the non-blocking connect completes.
    let mut conn = -1;
    let mut peer = IpSockAddr::default();
    for _ in 0..500 {
        let (c, p) = sck.accept_connection(server);
        if c >= 0 {
            conn = c;
            peer = p;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(conn >= 0, "accept never succeeded");
    assert_eq!(peer.family, IPADDR_INET4);
    assert_eq!(peer.in4, 0x7f00_0001);

    // Server -> client.
    let msg = b"tcp hello";
    for _ in 0..500 {
        if sck.send(conn, msg) == msg.len() as isize {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let mut buf = [0u8; 64];
    let mut got = -1;
    for _ in 0..500 {
        let r = sck.receive(client, &mut buf, 0);
        if r > 0 {
            got = r;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(got, msg.len() as isize);
    assert_eq!(&buf[..msg.len()], msg);

    assert!(sck.shutdown_connection(conn));
    sck.close_socket(conn);
    sck.close_socket(client);
    sck.close_socket(server);
}

#[test]
fn unix_stream_bind_connect_roundtrip() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);

    let path = tmp_path("stream");
    let _ = std::fs::remove_file(&path);

    let server = sck.open_unix_stream_socket(None, Some(&path), 0);
    assert!(server >= 0, "unix server open failed: {server}");
    assert!(sck.listen_on_socket(server, 5));
    assert!(std::path::Path::new(&path).exists(), "socket node should exist");

    let client = sck.open_unix_stream_socket(Some(&path), None, 0);
    assert!(client >= 0, "unix client open failed: {client}");

    let mut conn = -1;
    for _ in 0..500 {
        let (c, _) = sck.accept_connection(server);
        if c >= 0 {
            conn = c;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(conn >= 0, "unix accept never succeeded");

    let msg = b"unix stream";
    for _ in 0..500 {
        if sck.send(client, msg) == msg.len() as isize {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let mut buf = [0u8; 64];
    let mut got = -1;
    for _ in 0..500 {
        let r = sck.receive(conn, &mut buf, 0);
        if r > 0 {
            got = r;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(got, msg.len() as isize);
    assert_eq!(&buf[..msg.len()], msg);

    sck.close_socket(conn);
    sck.close_socket(client);
    // SCK_RemoveSocket unlinks the bound node.
    assert!(sck.remove_socket(server), "remove_socket should unlink the node");
    assert!(!std::path::Path::new(&path).exists(), "node should be gone");
    sck.close_socket(server);
}

#[test]
fn unix_socket_pair_roundtrip() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);

    let (a, b) = sck.open_unix_socket_pair(0).expect("socketpair");
    assert!(a >= 0 && b >= 0);

    let msg = b"pair message";
    assert_eq!(sck.send(a, msg), msg.len() as isize);
    let mut buf = [0u8; 64];
    let mut got = -1;
    for _ in 0..500 {
        let r = sck.receive(b, &mut buf, 0);
        if r > 0 {
            got = r;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(got, msg.len() as isize);
    assert_eq!(&buf[..msg.len()], msg);

    sck.close_socket(a);
    sck.close_socket(b);
}

#[test]
fn unix_datagram_bind_connect_roundtrip() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);

    let spath = tmp_path("dgram-srv");
    let _ = std::fs::remove_file(&spath);
    let server = sck.open_unix_datagram_socket(None, Some(&spath), 0);
    assert!(server >= 0);

    // Datagram client connected to the server path.
    let client = sck.open_unix_datagram_socket(Some(&spath), None, 0);
    assert!(client >= 0);

    let msg = b"unix dgram";
    assert_eq!(sck.send(client, msg), msg.len() as isize);
    let mut buf = [0u8; 64];
    let mut got = -1;
    for _ in 0..500 {
        let r = sck.receive(server, &mut buf, 0);
        if r > 0 {
            got = r;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(got, msg.len() as isize);
    assert_eq!(&buf[..msg.len()], msg);

    sck.close_socket(client);
    let _ = sck.remove_socket(server);
    sck.close_socket(server);
}
