//! Kernel-integration test for the real NTP socket I/O path: open a server socket, deliver a
//! genuine NTP datagram over loopback, drive the live event loop, and observe the decoded
//! packet arrive at the NSR_ProcessRx seam.

use chrony_rs_core::config::accessors::ConfigValues;
use chrony_rs_core::config::parse;
use chrony_rs_core::socket::IPADDR_INET4;
use chrony_rs_io::driver::new_scheduler;
use chrony_rs_io::ntp_io::{NtpIo, PacketSink};
use chrony_rs_io::socket::Sockets;
use std::cell::RefCell;
use std::rc::Rc;

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A minimal but well-formed 48-byte NTP client request (LI=0, VN=4, Mode=3).
fn ntp_client_packet() -> [u8; 48] {
    let mut p = [0u8; 48];
    p[0] = 0x23; // LI=0, VN=4, Mode=3 (client)
    p[1] = 0; // stratum
    p[2] = 4; // poll
    p[3] = 0xEC; // precision
    p
}

#[test]
fn server_socket_receives_ntp_packet_through_event_loop() {
    let port = free_udp_port();
    let cfg: ConfigValues =
        ConfigValues::resolve(&parse(&format!("port {port}\n")).config);

    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);

    let mut sched = new_scheduler();
    let sink: PacketSink = Rc::new(RefCell::new(Vec::new()));

    // NIO_Initialise: with the default acquisition port (-1) the server socket is opened on
    // demand, so this opens nothing yet.
    let mut nio = NtpIo::initialise(&sck, &cfg, &mut sched, &sink);
    assert!(!nio.is_server_socket_open());

    // Open the v4 server socket (binds 0.0.0.0:<port>, registers the read handler).
    let server_fd = nio.open_server_socket(&sck, &cfg, &mut sched, &sink, IPADDR_INET4);
    assert!(server_fd >= 0, "server socket open failed: {server_fd}");
    assert!(nio.is_server_socket_open());
    assert!(nio.is_server_socket(server_fd));

    // Send a genuine NTP datagram to the server from an ordinary client socket.
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let pkt = ntp_client_packet();
    client.send_to(&pkt, ("127.0.0.1", port)).unwrap();

    // Bound the event loop: quit shortly after so the test can't hang if delivery is lost.
    sched.add_timeout_by_delay(2.0, Box::new(|s| s.quit_program()));

    // Drive the real event loop: select() wakes on the server fd, read_from_socket decodes the
    // datagram and pushes it to the sink; then the timeout quits.
    sched.main_loop();

    let received = sink.borrow();
    assert_eq!(received.len(), 1, "expected exactly one NTP packet, got {}", received.len());
    let r = &received[0];
    assert_eq!(r.data, pkt.to_vec(), "packet bytes must round-trip");
    assert_eq!(r.sock_fd, server_fd);
    assert_eq!(r.remote.family, IPADDR_INET4);
    assert_eq!(r.remote.in4, 0x7f00_0001, "source is loopback");
    // The RX_DEST_ADDR option means the destination (loopback) is recovered via IP_PKTINFO.
    match r.local_ip {
        chrony_rs_core::util::IpAddr::Inet4(a) => assert_eq!(a, 0x7f00_0001),
        other => panic!("expected v4 dest addr, got {other:?}"),
    }

    // Close-down path.
    nio.close_server_socket(&sck, &mut sched, server_fd);
    nio.finalise(&sck, &mut sched);
    assert!(!nio.is_server_socket_open());
}

#[test]
fn send_packet_delivers_over_loopback() {
    let port = free_udp_port();
    let cfg = ConfigValues::resolve(&parse(&format!("port {port}\n")).config);
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);
    let mut sched = new_scheduler();
    let sink: PacketSink = Rc::new(RefCell::new(Vec::new()));

    let mut nio = NtpIo::initialise(&sck, &cfg, &mut sched, &sink);

    // Receiver: the server socket bound to the port.
    let server_fd = nio.open_server_socket(&sck, &cfg, &mut sched, &sink, IPADDR_INET4);
    assert!(server_fd >= 0);

    // Sender: a connected client socket toward the server.
    let remote = chrony_rs_core::socket::IpSockAddr {
        family: IPADDR_INET4,
        in4: 0x7f00_0001,
        in6: [0; 16],
        port,
    };
    let client_fd = nio.open_client_socket(&sck, &cfg, &mut sched, &sink, &remote);
    assert!(client_fd >= 0);

    // NIO_SendPacket from the connected client (local address unspecified, if_index invalid).
    let pkt = ntp_client_packet();
    let ok = nio.send_packet(
        &sck,
        &pkt,
        &remote,
        chrony_rs_core::util::IpAddr::Unspec,
        chrony_rs_core::socket::INVALID_IF_INDEX,
        client_fd,
        false,
    );
    assert!(ok, "NIO_SendPacket failed");

    sched.add_timeout_by_delay(2.0, Box::new(|s| s.quit_program()));
    sched.main_loop();

    let received = sink.borrow();
    assert_eq!(received.len(), 1, "server should receive exactly one packet");
    assert_eq!(received[0].data, pkt.to_vec());
    assert_eq!(received[0].sock_fd, server_fd);
}

#[test]
fn client_sockets_connect_and_close() {
    // A server on a free port to connect toward.
    let port = free_udp_port();
    let cfg = ConfigValues::resolve(&parse("").config);
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);
    let mut sched = new_scheduler();
    let sink: PacketSink = Rc::new(RefCell::new(Vec::new()));

    // Default acquisition port (-1) -> separate connected client sockets.
    let nio = NtpIo::initialise(&sck, &cfg, &mut sched, &sink);

    let remote = chrony_rs_core::socket::IpSockAddr {
        family: IPADDR_INET4,
        in4: 0x7f00_0001,
        in6: [0; 16],
        port,
    };

    // NIO_IsServerConnectable opens a throwaway connected socket and closes it.
    assert!(nio.is_server_connectable(&sck, &cfg, &mut sched, &sink, &remote));

    // NIO_OpenClientSocket returns a fresh connected socket (separate_client_sockets); it can
    // send to the peer.
    let client_fd = nio.open_client_socket(&sck, &cfg, &mut sched, &sink, &remote);
    assert!(client_fd >= 0, "client socket open failed: {client_fd}");
    assert_eq!(sck.send(client_fd, b"probe"), 5);
    nio.close_client_socket(&sck, &mut sched, client_fd);
}
