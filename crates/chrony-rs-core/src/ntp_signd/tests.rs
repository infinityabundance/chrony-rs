//! Tests for the `ntp_signd.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_signd.c`** (+ `array.c`,
//! `memory.c`). A C generator drives `NSD_SignAndSendPacket` and the static
//! `read_write_socket` event handler (captured via the `SCH_AddFileHandler` stub)
//! and records the exact `SigndRequest` wire bytes, the emitted signed packet, and
//! the rejection of a bad `packet_id` / a non-success op / an over-short response
//! length (`research/oracle/ntp_signd-c-vectors.txt`).
//! [`matches_real_c_ntp_signd_vectors`] replays the identical flow through
//! [`SigndBridge`] over a recording [`SigndIo`] and matches every byte and decision.
//!
//! **Oracle #2 (independent): the queue / partial-IO invariants.** A short-write
//! socket must not advance until the whole request is flushed, the ring buffer holds
//! exactly `MAX_QUEUE_LENGTH - 1` packets, and a closed socket empties the queue.

use super::*;

/// A scripted, recording [`SigndIo`]: captures everything sent, replays a queued
/// response on the next `receive`, and lets a test inject short writes / failures.
#[derive(Default)]
struct RecordingIo {
    open_ok: bool,
    is_open: bool,
    output_enabled: Option<bool>,
    /// All bytes handed to `send`, concatenated.
    sent: Vec<u8>,
    /// At most this many bytes per `send` (0 = no limit).
    send_chunk: usize,
    /// `send` returns this error once, then resumes (negative => error).
    send_error: bool,
    /// Bytes `receive` will yield, and how far we've drained them.
    recv: Vec<u8>,
    recv_pos: usize,
    /// At most this many bytes per `receive` (0 = no limit).
    recv_chunk: usize,
    is_server: bool,
    /// Captured `send_packet` calls: (packet bytes, remote, local).
    sent_packets: Vec<(Vec<u8>, u64, u64)>,
    close_count: usize,
}

impl SigndIo for RecordingIo {
    fn open_socket(&mut self) -> bool {
        if self.open_ok {
            self.is_open = true;
        }
        self.open_ok
    }
    fn close_socket(&mut self) {
        self.is_open = false;
        self.close_count += 1;
    }
    fn set_output_event(&mut self, enable: bool) {
        self.output_enabled = Some(enable);
    }
    fn send(&mut self, data: &[u8]) -> i32 {
        if self.send_error {
            self.send_error = false;
            return -1;
        }
        let mut n = data.len();
        if self.send_chunk > 0 {
            n = n.min(self.send_chunk);
        }
        self.sent.extend_from_slice(&data[..n]);
        n as i32
    }
    fn receive(&mut self, buf: &mut [u8]) -> i32 {
        let avail = self.recv.len() - self.recv_pos;
        let mut n = buf.len().min(avail);
        if self.recv_chunk > 0 {
            n = n.min(self.recv_chunk);
        }
        if n == 0 {
            return 0;
        }
        buf[..n].copy_from_slice(&self.recv[self.recv_pos..self.recv_pos + n]);
        self.recv_pos += n;
        n as i32
    }
    fn is_server_socket(&mut self, _local_fd: i32) -> bool {
        self.is_server
    }
    fn send_packet(&mut self, packet: &[u8], remote: u64, local: u64) {
        self.sent_packets.push((packet.to_vec(), remote, local));
    }
}

impl RecordingIo {
    fn fresh() -> RecordingIo {
        RecordingIo { open_ok: true, is_server: true, ..Default::default() }
    }
    /// Load a crafted `SigndResponse` to be replayed by `receive`.
    fn set_response(&mut self, op: u32, packet_id: u32, signed_packet: &[u8]) {
        let length = (RESPONSE_HEADER - 4 + signed_packet.len()) as u32;
        let mut r = Vec::new();
        r.extend_from_slice(&length.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes()); // version
        r.extend_from_slice(&op.to_be_bytes());
        r.extend_from_slice(&packet_id.to_be_bytes());
        r.extend_from_slice(signed_packet);
        self.recv = r;
        self.recv_pos = 0;
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}

#[test]
fn matches_real_c_ntp_signd_vectors() {
    let vectors = include_str!("../../../../research/oracle/ntp_signd-c-vectors.txt");
    let line = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    let mut bridge = SigndBridge::new(true);
    let mut io = RecordingIo::fresh();

    // NTP packet[i] = i, key_id = 0x01020304.
    let packet: Vec<u8> = (0..NTP_HEADER_LENGTH as u8).collect();
    let key_id = 0x0102_0304u32;

    // ---- enqueue + flush: the SigndRequest wire bytes ----
    let r = bridge.sign_and_send_packet(&mut io, key_id, &packet, NTP_HEADER_LENGTH, 0, 0, 9);
    let sl = line("SIGN");
    assert_eq!(r, field(sl, "ret") == "1", "SIGN ret");
    assert_eq!(io.output_enabled, Some(true), "output enabled on first enqueue");
    assert_eq!(io.output_enabled.unwrap() as i32, field(sl, "output_enabled").parse::<i32>().unwrap());

    bridge.on_socket_event(&mut io, SocketEvent::Output);
    let reqlen: usize = line("REQLEN").trim_start_matches("REQLEN").trim().parse().unwrap();
    assert_eq!(io.sent.len(), reqlen, "request length");
    assert_eq!(hex(&io.sent), line("REQ ").strip_prefix("REQ ").unwrap(), "request wire bytes");
    assert_eq!(io.output_enabled, Some(false), "output disabled after full send");

    // ---- successful response: the signed packet is emitted ----
    let signed: Vec<u8> = (0..NTP_HEADER_LENGTH).map(|i| (200 - i) as u8).collect();
    io.set_response(SigndOp::SigningSuccess as u32, 0, &signed);
    bridge.on_socket_event(&mut io, SocketEvent::Input);
    let sent_len: i32 =
        if io.sent_packets.is_empty() { -1 } else { io.sent_packets[0].0.len() as i32 };
    let exp_sentlen: i32 = line("SENTLEN").trim_start_matches("SENTLEN").trim().parse().unwrap();
    assert_eq!(sent_len, exp_sentlen, "emitted signed-packet length");
    assert_eq!(hex(&io.sent_packets[0].0), line("SENT ").strip_prefix("SENT ").unwrap(), "signed packet bytes");

    // ---- bad packet id: enqueue again (slot 1), respond with the wrong id ----
    io.sent.clear();
    io.sent_packets.clear();
    assert!(bridge.sign_and_send_packet(&mut io, key_id, &packet, NTP_HEADER_LENGTH, 0, 0, 9));
    bridge.on_socket_event(&mut io, SocketEvent::Output);
    io.set_response(SigndOp::SigningSuccess as u32, 999, &signed);
    bridge.on_socket_event(&mut io, SocketEvent::Input);
    let badid = if io.sent_packets.is_empty() { -1 } else { io.sent_packets[0].0.len() as i32 };
    assert_eq!(badid, field(line("BADID"), "sentlen").parse::<i32>().unwrap(), "bad id => no send");

    // ---- non-success op ----
    io.sent.clear();
    io.sent_packets.clear();
    assert!(bridge.sign_and_send_packet(&mut io, key_id, &packet, NTP_HEADER_LENGTH, 0, 0, 9));
    bridge.on_socket_event(&mut io, SocketEvent::Output);
    io.set_response(SigndOp::SigningFailure as u32, 2, &signed);
    bridge.on_socket_event(&mut io, SocketEvent::Input);
    let failop = if io.sent_packets.is_empty() { -1 } else { io.sent_packets[0].0.len() as i32 };
    assert_eq!(failop, field(line("FAILOP"), "sentlen").parse::<i32>().unwrap(), "fail op => no send");

    // ---- over-short response length closes the socket ----
    io.sent.clear();
    io.sent_packets.clear();
    assert!(bridge.sign_and_send_packet(&mut io, key_id, &packet, NTP_HEADER_LENGTH, 0, 0, 9));
    bridge.on_socket_event(&mut io, SocketEvent::Output);
    io.recv = 4u32.to_be_bytes().to_vec(); // response_length = 4 + 4 = 8 < RESPONSE_HEADER
    io.recv.extend_from_slice(&[0u8; 4]);
    io.recv_pos = 0;
    let closes_before = io.close_count;
    bridge.on_socket_event(&mut io, SocketEvent::Input);
    let badlen = if io.sent_packets.is_empty() { -1 } else { io.sent_packets[0].0.len() as i32 };
    assert_eq!(badlen, field(line("BADLEN"), "sentlen").parse::<i32>().unwrap(), "bad len => no send");
    assert_eq!(io.close_count, closes_before + 1, "over-short length closes the socket");

    // ---- a request with the wrong NTP length is rejected outright ----
    let bad = bridge.sign_and_send_packet(&mut io, key_id, &packet, NTP_HEADER_LENGTH + 4, 0, 0, 9);
    assert_eq!(bad, field(line("BADREQLEN"), "ret") == "1", "bad request length rejected");
}

#[test]
fn disabled_bridge_never_signs() {
    let mut bridge = SigndBridge::new(false);
    let mut io = RecordingIo::fresh();
    let packet = vec![0u8; NTP_HEADER_LENGTH as usize];
    assert!(!bridge.is_enabled());
    assert!(!bridge.sign_and_send_packet(&mut io, 1, &packet, NTP_HEADER_LENGTH, 0, 0, 0));
    assert!(io.sent.is_empty(), "nothing is queued when disabled");
}

#[test]
fn partial_writes_do_not_advance_until_the_request_is_flushed() {
    // A socket that accepts only 10 bytes per send must take several OUTPUT events to
    // flush the 68-byte request, and only then disable output.
    let mut bridge = SigndBridge::new(true);
    let mut io = RecordingIo::fresh();
    io.send_chunk = 10;
    let packet: Vec<u8> = (0..NTP_HEADER_LENGTH as u8).collect();
    assert!(bridge.sign_and_send_packet(&mut io, 7, &packet, NTP_HEADER_LENGTH, 0, 0, 9));

    let request_len = (REQUEST_HEADER + NTP_HEADER_LENGTH as usize) as i32;
    io.output_enabled = Some(true);
    let mut events = 0;
    while (io.sent.len() as i32) < request_len {
        bridge.on_socket_event(&mut io, SocketEvent::Output);
        events += 1;
        if events < (request_len + 9) / 10 {
            assert_eq!(io.output_enabled, Some(true), "output stays enabled mid-send");
        }
    }
    assert_eq!(io.sent.len() as i32, request_len, "the whole request is flushed");
    assert_eq!(io.output_enabled, Some(false), "output disabled once complete");
}

#[test]
fn queue_holds_at_most_max_queue_length_minus_one() {
    let mut bridge = SigndBridge::new(true);
    let mut io = RecordingIo::fresh();
    let packet: Vec<u8> = (0..NTP_HEADER_LENGTH as u8).collect();
    // The ring reserves one slot to distinguish empty from full.
    for i in 0..MAX_QUEUE_LENGTH - 1 {
        assert!(
            bridge.sign_and_send_packet(&mut io, i as u32, &packet, NTP_HEADER_LENGTH, 0, 0, 9),
            "slot {i} accepted"
        );
    }
    assert!(
        !bridge.sign_and_send_packet(&mut io, 99, &packet, NTP_HEADER_LENGTH, 0, 0, 9),
        "the queue is full at MAX_QUEUE_LENGTH - 1"
    );
}
