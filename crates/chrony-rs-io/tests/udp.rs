//! Kernel-integration tests for the real UDP socket path (`chrony-rs-io::socket`).
//!
//! These open genuine loopback sockets and exercise chrony's open/bind/connect/send/recv
//! sequence end-to-end — the verification contract for the syscall layer (which cannot be
//! differential-unit-tested against C). They require only loopback networking.

use chrony_rs_core::socket::{IpSockAddr, SckAddressType, SckMessage, IPADDR_INET4};
use chrony_rs_io::socket::{Sockets, SCK_FLAG_RX_DEST_ADDR};

fn loopback_v4(port: u16) -> IpSockAddr {
    IpSockAddr { family: IPADDR_INET4, in4: 0x7f00_0001, in6: [0; 16], port }
}

/// Read back the local port a socket was bound to (SO-less: via getsockname through a
/// received packet's source, since we send from it). Here we bind to an ephemeral port and
/// discover it by having the peer receive from us — simpler: bind server to a fixed-free port.
fn free_port() -> u16 {
    // Ask the kernel for an ephemeral port by binding a throwaway std socket.
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

#[test]
fn open_bind_send_receive_datagram() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);
    assert!(sck.is_ip_family_enabled(IPADDR_INET4));

    let server_port = free_port();
    let server_addr = loopback_v4(server_port);

    // Server: bound UDP socket on the chosen port.
    let server = sck.open_udp_socket(None, Some(&server_addr), None, 0);
    assert!(server >= 0, "server open failed: {server}");

    // Client: connected to the server.
    let client = sck.open_udp_socket(Some(&server_addr), None, None, 0);
    assert!(client >= 0, "client open failed: {client}");

    // Send a datagram from the connected client.
    let payload = b"chrony-rs udp integration";
    let sent = sck.send(client, payload);
    assert_eq!(sent, payload.len() as isize, "send returned {sent}");

    // Receive it on the server (retry briefly for the non-blocking socket).
    let mut buf = [0u8; 128];
    let mut got = -1isize;
    for _ in 0..200 {
        let r = sck.receive(server, &mut buf, 0);
        if r >= 0 {
            got = r;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(got, payload.len() as isize, "receive returned {got}");
    assert_eq!(&buf[..payload.len()], payload);

    sck.close_socket(client);
    sck.close_socket(server);
}

#[test]
fn set_and_get_int_option_roundtrip() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);
    let fd = sck.open_udp_socket(None, Some(&loopback_v4(free_port())), None, 0);
    assert!(fd >= 0);
    // Set SO_REUSEADDR and read it back (getsockopt reports it enabled).
    assert!(sck.set_int_option(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1));
    let v = sck.get_int_option(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR);
    assert!(v.is_some() && v.unwrap() != 0, "SO_REUSEADDR should read back enabled, got {v:?}");
    sck.close_socket(fd);
}

#[test]
fn send_message_delivers_payload_and_dest_address() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);

    let server_port = free_port();
    let server_addr = loopback_v4(server_port);

    // Server requests the destination address of received packets (IP_PKTINFO).
    let server = sck.open_udp_socket(None, Some(&server_addr), None, SCK_FLAG_RX_DEST_ADDR);
    assert!(server >= 0);
    // Unconnected client socket so we can address the message explicitly.
    let client = sck.open_udp_socket(None, None, None, 0);
    assert!(client >= 0);

    // Build an SCK_Message addressed to the server, with no explicit source (any).
    let mut msg = SckMessage::init(SckAddressType::Ip);
    msg.remote_ip = server_addr;
    let payload = b"pktinfo probe";
    let sent = sck.send_message(client, &msg, payload, 0);
    assert_eq!(sent, payload.len() as isize, "send_message returned {sent}");

    let mut rm = None;
    for _ in 0..200 {
        if let Some(m) = sck.receive_message(server, 0) {
            rm = Some(m);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let rm = rm.expect("no message received");
    assert_eq!(rm.data, payload);
    // The destination address recovered from IP_PKTINFO is the loopback server address.
    match rm.control.local {
        chrony_rs_core::util::IpAddr::Inet4(a) => assert_eq!(a, 0x7f00_0001),
        other => panic!("expected v4 dest addr, got {other:?}"),
    }
    // The source is the client's loopback address.
    assert_eq!(rm.remote.family, IPADDR_INET4);
    assert_eq!(rm.remote.in4, 0x7f00_0001);

    sck.close_socket(client);
    sck.close_socket(server);
}

#[test]
fn receive_messages_batches_multiple_datagrams() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);
    let server_port = free_port();
    let server_addr = loopback_v4(server_port);
    let server = sck.open_udp_socket(None, Some(&server_addr), None, 0);
    assert!(server >= 0);
    let client = sck.open_udp_socket(Some(&server_addr), None, None, 0);
    assert!(client >= 0);

    // Send three datagrams.
    for i in 0..3u8 {
        let payload = [b'A' + i, b'B' + i, b'C' + i];
        assert_eq!(sck.send(client, &payload), 3);
    }

    // Batch-receive; collect until we've seen all three (retry for delivery).
    let mut all = Vec::new();
    for _ in 0..300 {
        let batch = sck.receive_messages(server, 0, 16);
        for m in batch {
            all.push(m.data);
        }
        if all.len() >= 3 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(all.len(), 3, "expected 3 datagrams, got {}", all.len());
    all.sort();
    assert_eq!(all, vec![vec![b'A', b'B', b'C'], vec![b'B', b'C', b'D'], vec![b'C', b'D', b'E']]);

    sck.close_socket(client);
    sck.close_socket(server);
}

#[test]
fn broadcast_flag_sets_so_broadcast() {
    // Opening with SCK_FLAG_BROADCAST runs set_socket_options -> SO_BROADCAST; verify it stuck.
    use chrony_rs_io::socket::SCK_FLAG_BROADCAST;
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);
    let fd = sck.open_udp_socket(None, Some(&loopback_v4(free_port())), None, SCK_FLAG_BROADCAST);
    assert!(fd >= 0);
    let v = sck.get_int_option(fd, libc::SOL_SOCKET, libc::SO_BROADCAST);
    assert!(v.is_some() && v.unwrap() != 0, "SO_BROADCAST should be enabled, got {v:?}");
    sck.close_socket(fd);
}

#[test]
fn enable_kernel_rx_timestamping_succeeds() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);
    let fd = sck.open_udp_socket(None, Some(&loopback_v4(free_port())), None, 0);
    assert!(fd >= 0);
    // SO_TIMESTAMPNS is available on Linux, so this enables kernel RX timestamping.
    assert!(sck.enable_kernel_rx_timestamping(fd), "kernel RX timestamping should enable");
    let v = sck.get_int_option(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS);
    assert!(v.is_some() && v.unwrap() != 0);
    sck.close_socket(fd);
}

#[test]
fn handle_recv_error_reads_so_error() {
    // On a healthy socket with no pending error, handle_recv_error reads SO_ERROR and finds 0
    // (exercising the getsockopt SO_ERROR clear path chrony uses to avoid a select() busy-loop).
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);
    let fd = sck.open_udp_socket(None, Some(&loopback_v4(free_port())), None, 0);
    assert!(fd >= 0);
    let err = sck.handle_recv_error(fd, chrony_rs_io::socket::SCK_FLAG_MSG_ERRQUEUE);
    assert_eq!(err, 0, "no error should be pending");
    sck.close_socket(fd);
}

#[test]
fn open_rejects_disabled_family() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4); // v6 disabled
    let v6 = IpSockAddr {
        family: chrony_rs_core::socket::IPADDR_INET6,
        in4: 0,
        in6: [0; 16],
        port: 0,
    };
    // A v6 local address on a v4-only stack is refused (INVALID_SOCK_FD).
    let fd = sck.open_udp_socket(None, Some(&v6), None, 0);
    assert!(fd < 0, "v6 open should be refused when v6 disabled");
}
