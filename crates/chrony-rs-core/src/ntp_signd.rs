//! MS-SNTP signing-daemon bridge — a complete port of chrony 4.5 `ntp_signd.c`
//! (all 7 functions). The other half of the MS-SNTP authentication path.
//!
//! # What this module is
//!
//! Microsoft's MS-SNTP variant authenticates server responses by handing the
//! packet to an external Samba `ntp_signd` daemon over a Unix-domain stream socket;
//! the daemon signs it with the client's machine-account key and chrony forwards the
//! signed packet. `ntp_signd.c` is the asynchronous client of that protocol: it
//! serialises a `SigndRequest` (the Samba `ntp_signd` IDL), queues it (bursts are not
//! lost), pushes it out as the socket becomes writable, reads back the `SigndResponse`,
//! and emits the signed NTP packet.
//!
//! This is the counterpart to [`crate::ntp_auth`], which injects the signing step
//! (`NSD_SignAndSendPacket`) as a closure on the MS-SNTP response path — this module
//! *is* that step.
//!
//! # The wire format (Samba `source4/librpc/idl/ntp_signd.idl`)
//!
//! Request (`SigndRequest`), all integers big-endian (`htonl`/`htons`):
//!
//! ```text
//! length:u32  version:u32  op:u32  packet_id:u16  _pad:u16  key_id:u32  packet[..]
//! ```
//!
//! `length` excludes itself; `version` = `SIGND_VERSION` (0); `op` = `SIGN_TO_CLIENT`
//! (0); `packet_id` echoes the queue slot. The response is
//! `length:u32 version:u32 op:u32 packet_id:u32 signed_packet[..]`; a `SIGNING_SUCCESS`
//! op whose `packet_id` matches the request causes the signed packet to be sent.
//!
//! # Adaptations (documented, not silent)
//!
//! * **All host boundaries are injected via [`SigndIo`].** chrony reaches the socket
//!   layer (`SCK_*`), the scheduler's file-handler events (`SCH_*`), and the NTP send
//!   path (`NIO_*`) through module globals; here they are one trait. The static
//!   `read_write_socket` event handler becomes [`SigndBridge::on_socket_event`],
//!   which the daemon's scheduler drives.
//! * **The fixed queue is a `Vec` of `MAX_QUEUE_LENGTH` reused slots**, indexed by
//!   the same head/tail ring arithmetic as chrony's `ARR_Instance`.
//! * **The request timestamp / delay are dropped.** chrony records them only for a
//!   `DEBUG_LOG`; they have no effect on the bytes sent, so the monotonic clock is
//!   not threaded here.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `ntp_signd.c`** (+ `array.c`,
//! `memory.c`): a C generator drives `NSD_SignAndSendPacket` and the static
//! `read_write_socket` (captured via the file-handler stub) and records the exact
//! `SigndRequest` bytes, the emitted signed packet, and the rejection of a bad
//! `packet_id` / a non-success op / an over-short length
//! (`research/oracle/ntp_signd-c-vectors.txt`). This port replays the identical flow
//! and matches every byte. See the tests.

use crate::ntp::ext::{NTP_HEADER_LENGTH, NTP_PACKET_SIZE};

/// chrony `SIGND_VERSION`.
const SIGND_VERSION: u32 = 0;

/// chrony `SigndOp` (the Samba `ntp_signd` operation codes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum SigndOp {
    /// `SIGN_TO_CLIENT`.
    SignToClient = 0,
    /// `ASK_SERVER_TO_SIGN`.
    AskServerToSign = 1,
    /// `CHECK_SERVER_SIGNATURE`.
    CheckServerSignature = 2,
    /// `SIGNING_SUCCESS`.
    SigningSuccess = 3,
    /// `SIGNING_FAILURE`.
    SigningFailure = 4,
}

/// chrony `MAX_QUEUE_LENGTH`.
const MAX_QUEUE_LENGTH: usize = 16;

/// `offsetof(SigndRequest, packet_to_sign)` — the request header preceding the NTP
/// packet: `length(4) version(4) op(4) packet_id(2) _pad(2) key_id(4)`.
const REQUEST_HEADER: usize = 4 + 4 + 4 + 2 + 2 + 4;

/// `offsetof(SigndResponse, signed_packet)` — `length(4) version(4) op(4) packet_id(4)`.
const RESPONSE_HEADER: usize = 4 + 4 + 4 + 4;

/// `sizeof(SigndResponse)` = header + `sizeof(NTP_Packet)`; the receive-buffer bound.
const RESPONSE_SIZE: usize = RESPONSE_HEADER + NTP_PACKET_SIZE as usize;

/// The host boundary chrony reaches through `SCK_*` / `SCH_*` / `NIO_*` globals.
///
/// Every method corresponds to a chrony call: [`open_socket`](SigndIo::open_socket)
/// (`SCK_OpenUnixStreamSocket` + `SCH_AddFileHandler`),
/// [`close_socket`](SigndIo::close_socket) (`SCH_RemoveFileHandler` +
/// `SCK_CloseSocket`), [`set_output_event`](SigndIo::set_output_event)
/// (`SCH_SetFileHandlerEvent` for `SCH_FILE_OUTPUT`), [`send`](SigndIo::send) /
/// [`receive`](SigndIo::receive) (`SCK_Send` / `SCK_Receive`, partial transfers
/// allowed), [`is_server_socket`](SigndIo::is_server_socket) (`NIO_IsServerSocket`),
/// and [`send_packet`](SigndIo::send_packet) (`NIO_SendPacket`).
pub trait SigndIo {
    /// Open the Unix-domain stream socket to `ntp_signd` and register its file
    /// handler. Returns whether a socket was obtained.
    fn open_socket(&mut self) -> bool;
    /// Remove the file handler and close the socket.
    fn close_socket(&mut self);
    /// Enable/disable the writable (`SCH_FILE_OUTPUT`) event.
    fn set_output_event(&mut self, enable: bool);
    /// Send up to `data.len()` bytes; returns bytes sent (`<0` on error), allowing
    /// short writes as `SCK_Send` does.
    fn send(&mut self, data: &[u8]) -> i32;
    /// Receive into `buf`; returns bytes read (`<=0` ends the exchange), allowing
    /// short reads as `SCK_Receive` does.
    fn receive(&mut self, buf: &mut [u8]) -> i32;
    /// Whether the original request's local NTP socket is still a server socket
    /// (`NIO_IsServerSocket`).
    fn is_server_socket(&mut self, local_fd: i32) -> bool;
    /// Send the signed NTP packet back to the client (`NIO_SendPacket`).
    fn send_packet(&mut self, packet: &[u8], remote: u64, local: u64);
}

/// A file-handler event, mirroring chrony's `SCH_FILE_OUTPUT` / `SCH_FILE_INPUT`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[non_exhaustive]
pub enum SocketEvent {
    /// The socket is writable.
    Output,
    /// The socket is readable.
    Input,
}

/// chrony's `SignInstance`: one queued signing exchange.
#[derive(Clone, Default)]
struct SignInstance {
    /// Opaque token for the client's remote address (`NIO_SendPacket` routing).
    remote: u64,
    /// Opaque token for the local address (`NIO_SendPacket` routing).
    local: u64,
    /// `local_addr.sock_fd` checked by `NIO_IsServerSocket`.
    local_fd: i32,
    /// Bytes of the request already sent.
    sent: usize,
    /// Bytes of the response already received.
    received: usize,
    /// Total request length (header + NTP packet).
    request_length: usize,
    /// The serialised `SigndRequest`.
    request: Vec<u8>,
    /// The accumulating `SigndResponse` buffer.
    response: Vec<u8>,
}

/// The MS-SNTP signing bridge (chrony's `ntp_signd` module state).
pub struct SigndBridge {
    enabled: bool,
    sock_open: bool,
    queue: Vec<SignInstance>,
    head: usize,
    tail: usize,
}

impl SigndBridge {
    /// chrony `NSD_Initialise`. `enabled` mirrors `CNF_GetNtpSigndSocket()` being
    /// configured non-empty.
    pub fn new(enabled: bool) -> SigndBridge {
        SigndBridge {
            enabled,
            sock_open: false,
            queue: vec![SignInstance::default(); MAX_QUEUE_LENGTH],
            head: 0,
            tail: 0,
        }
    }

    /// Whether MS-SNTP signing is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// chrony `NEXT_QUEUE_INDEX`.
    fn next_index(index: usize) -> usize {
        (index + 1) % MAX_QUEUE_LENGTH
    }

    /// chrony `IS_QUEUE_EMPTY`.
    fn is_queue_empty(&self) -> bool {
        self.head == self.tail
    }

    /// chrony `open_socket`.
    fn open_socket(&mut self, io: &mut dyn SigndIo) -> bool {
        if self.sock_open {
            return true;
        }
        if io.open_socket() {
            self.sock_open = true;
            true
        } else {
            false
        }
    }

    /// chrony `close_socket`: drop the socket and empty the queue.
    fn close_socket(&mut self, io: &mut dyn SigndIo) {
        io.close_socket();
        self.sock_open = false;
        self.head = 0;
        self.tail = 0;
    }

    /// chrony `NSD_SignAndSendPacket`: serialise + enqueue a packet for signing.
    /// `packet` is the NTP packet bytes and `info_length` its length (which must be
    /// exactly the NTP header length). Returns whether it was queued.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_and_send_packet(
        &mut self,
        io: &mut dyn SigndIo,
        key_id: u32,
        packet: &[u8],
        info_length: i32,
        remote: u64,
        local: u64,
        local_fd: i32,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        // Queue full (the tail would catch the head).
        if self.head == Self::next_index(self.tail) {
            return false;
        }
        if info_length != NTP_HEADER_LENGTH {
            return false;
        }
        if !self.open_socket(io) {
            return false;
        }

        let info_length = info_length as usize;
        let request_length = REQUEST_HEADER + info_length;
        let tail = self.tail;

        let mut request = vec![0u8; request_length];
        // The length field doesn't include itself.
        request[0..4].copy_from_slice(&((request_length - 4) as u32).to_be_bytes());
        request[4..8].copy_from_slice(&SIGND_VERSION.to_be_bytes());
        request[8..12].copy_from_slice(&(SigndOp::SignToClient as u32).to_be_bytes());
        request[12..14].copy_from_slice(&(tail as u16).to_be_bytes());
        // request[14..16] is the pad, already zero.
        request[16..20].copy_from_slice(&key_id.to_be_bytes());
        request[20..20 + info_length].copy_from_slice(&packet[..info_length]);

        let inst = &mut self.queue[tail];
        inst.remote = remote;
        inst.local = local;
        inst.local_fd = local_fd;
        inst.sent = 0;
        inst.received = 0;
        inst.request_length = request_length;
        inst.request = request;
        inst.response = vec![0u8; RESPONSE_SIZE];

        // Enable output if there was no pending request.
        if self.is_queue_empty() {
            io.set_output_event(true);
        }
        self.tail = Self::next_index(self.tail);
        true
    }

    /// chrony `read_write_socket`: drive the send/receive state machine for one
    /// file-handler event.
    pub fn on_socket_event(&mut self, io: &mut dyn SigndIo, event: SocketEvent) {
        match event {
            SocketEvent::Output => {
                let head = self.head;
                let (request_length, sent, send_res) = {
                    let inst = &mut self.queue[head];
                    let s = io.send(&inst.request[inst.sent..inst.request_length]);
                    if s >= 0 {
                        inst.sent += s as usize;
                    }
                    (inst.request_length, inst.sent, s)
                };
                if send_res < 0 {
                    self.close_socket(io);
                    return;
                }
                // Try again later if the request is not complete yet.
                if sent < request_length {
                    return;
                }
                // Disable output and wait for a response.
                io.set_output_event(false);
            }
            SocketEvent::Input => {
                if self.is_queue_empty() {
                    self.close_socket(io);
                    return;
                }
                let head = self.head;
                let recv_res = {
                    let inst = &mut self.queue[head];
                    let start = inst.received;
                    let s = io.receive(&mut inst.response[start..]);
                    if s > 0 {
                        inst.received += s as usize;
                    }
                    s
                };
                if recv_res <= 0 {
                    self.close_socket(io);
                    return;
                }
                let received = self.queue[head].received;
                if received < 4 {
                    return;
                }
                let length_field =
                    u32::from_be_bytes(self.queue[head].response[0..4].try_into().unwrap());
                let response_length = length_field as usize + 4;
                // chrony: response_length < offsetof(signed_packet) || > sizeof(SigndResponse).
                if !(RESPONSE_HEADER..=RESPONSE_SIZE).contains(&response_length) {
                    self.close_socket(io);
                    return;
                }
                // Wait for more data if not complete yet.
                if received < response_length {
                    return;
                }

                self.process_response(io, head, response_length);

                // Move the head and enable output for the next packet.
                self.head = Self::next_index(self.head);
                if !self.is_queue_empty() {
                    io.set_output_event(true);
                }
            }
        }
    }

    /// chrony `process_response`: validate the signed response and emit the packet.
    fn process_response(&mut self, io: &mut dyn SigndIo, head: usize, response_length: usize) {
        let inst = &self.queue[head];

        // packet_id: request is 16-bit (htons), response is 32-bit (htonl).
        let request_id = u16::from_be_bytes([inst.request[12], inst.request[13]]) as u32;
        let response_id = u32::from_be_bytes(inst.response[12..16].try_into().unwrap());
        if request_id != response_id {
            return;
        }

        let op = u32::from_be_bytes(inst.response[8..12].try_into().unwrap());
        if op != SigndOp::SigningSuccess as u32 {
            return;
        }

        if !io.is_server_socket(inst.local_fd) {
            return;
        }

        // NIO_SendPacket length = response_length - offsetof(signed_packet).
        let signed_len = response_length - RESPONSE_HEADER;
        let packet = inst.response[RESPONSE_HEADER..RESPONSE_HEADER + signed_len].to_vec();
        let (remote, local) = (inst.remote, inst.local);
        io.send_packet(&packet, remote, local);
    }
}

#[cfg(test)]
mod tests;
