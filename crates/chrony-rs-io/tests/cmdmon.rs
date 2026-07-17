//! Kernel-integration test: a real chronyc ↔ chronyd command exchange over a loopback UDP
//! command socket, driven through the live event loop.

use chrony_rs_core::client::build_request_header;
use chrony_rs_core::cmdmon::{PROTO_VERSION_NUMBER, STT_SUCCESS};
use chrony_rs_core::config::accessors::ConfigValues;
use chrony_rs_core::config::parse;
use chrony_rs_core::socket::{IpSockAddr, IPADDR_INET4};
use chrony_rs_io::cmdmon::{CmdClient, CmdMon, Dispatch};
use chrony_rs_io::driver::new_scheduler;
use chrony_rs_io::socket::Sockets;
use std::rc::Rc;

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

// Reply/request header field offsets (candm.h).
const RPY_OFF_STATUS: usize = 8;
const REQ_N_SOURCES: u16 = 14; // an arbitrary valid command code for the exchange

#[test]
fn chronyc_chronyd_command_exchange() {
    let port = free_udp_port();
    let cfg: ConfigValues = ConfigValues::resolve(&parse(&format!("cmdport {port}\n")).config);

    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);
    let mut sched = new_scheduler();

    // Server dispatch: echo back the command code as a 2-byte body with STT_SUCCESS.
    let dispatch: Dispatch = Rc::new(|command, _req| {
        (chrony_rs_core::cmdmon::RPY_NULL, STT_SUCCESS, command.to_be_bytes().to_vec())
    });

    // CAM_Initialise: opens the v4 command socket on 127.0.0.1:<port> and registers its handler.
    let mut cam = CmdMon::initialise(&sck, &cfg, &mut sched, dispatch, None, None);
    assert!(cam.ipv4_fd() >= 0, "command socket should open");

    // chronyc: connect to the command socket.
    let server = IpSockAddr { family: IPADDR_INET4, in4: 0x7f00_0001, in6: [0; 16], port };
    let client = CmdClient::open_io(&sck, &server).expect("client open");

    // Build and send a request (build_request_header is the ported chronyc encoder). Pad it to
    // the command's expected length (and at least the 28-byte reply-data offset, chrony's
    // anti-amplification floor) so validate_request accepts it.
    let seq = [0x11, 0x22, 0x33, 0x44];
    let expected = chrony_rs_core::pktlength::command_length(PROTO_VERSION_NUMBER, REQ_N_SOURCES);
    let len = (expected.max(28)) as usize;
    let mut request = build_request_header(REQ_N_SOURCES, 0, seq, PROTO_VERSION_NUMBER).to_vec();
    request.resize(len, 0);
    assert!(client.send_request(&sck, &request));

    // Drive the server's event loop: it receives, validates, dispatches, and replies.
    sched.add_timeout_by_delay(2.0, Box::new(|s| s.quit_program()));
    sched.main_loop();

    // chronyc receives the reply.
    let reply = client.receive_reply(&sck, 500).expect("no reply received");
    assert!(reply.len() >= 28, "reply shorter than a CMD_Reply header: {}", reply.len());

    // The status is SUCCESS and the sequence echoes the request's.
    let status = u16::from_be_bytes([reply[RPY_OFF_STATUS], reply[RPY_OFF_STATUS + 1]]);
    assert_eq!(status, STT_SUCCESS, "reply status");
    assert_eq!(&reply[16..20], &seq, "reply sequence echo");
    // The dispatch body (the command code) follows the 28-byte header.
    assert_eq!(&reply[28..30], &REQ_N_SOURCES.to_be_bytes(), "reply body");

    cam.finalise(&sck, &mut sched);
}

#[test]
fn cam_open_unix_socket_binds_the_command_path() {
    // A configured bindcmdaddress /path makes CAM_OpenUnixSocket bind the Unix command socket.
    let mut p = std::env::temp_dir();
    p.push(format!("chrony-rs-cmd-{}.sock", std::process::id()));
    let path = p.to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&path);

    // cmdport 0 disables the UDP sockets; the Unix socket is opened by CAM_OpenUnixSocket.
    let cfg = ConfigValues::resolve(
        &parse(&format!("cmdport 0\nbindcmdaddress {path}\n")).config,
    );
    let mut sck = Sockets::pre_initialise();
    sck.initialise(IPADDR_INET4);
    let mut sched = new_scheduler();

    let mut cam = CmdMon::initialise(&sck, &cfg, &mut sched, chrony_rs_io::cmdmon::success_dispatch(), None, None);
    assert_eq!(cam.ipv4_fd(), -1, "cmdport 0 leaves the UDP socket closed");
    cam.open_unix_socket(&sck, &cfg, &mut sched, chrony_rs_io::cmdmon::success_dispatch(), None);
    assert!(cam.unix_fd() >= 0, "unix command socket should open");
    assert!(std::path::Path::new(&path).exists(), "socket node should exist");

    cam.finalise(&sck, &mut sched);
    assert!(!std::path::Path::new(&path).exists(), "node unlinked on finalise");
}
