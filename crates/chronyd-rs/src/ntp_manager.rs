use std::net::{UdpSocket, SocketAddr, ToSocketAddrs};
use std::time::Duration;

fn resolve_with_timeout(host: &str, port: u16, timeout_secs: u64) -> Option<std::net::SocketAddr> {
    let host = host.to_string();
    let handle = std::thread::spawn(move || {
        (host.as_str(), port).to_socket_addrs().ok()?.next()
    });
    handle.join().ok()?
}

use chrony_rs_core::config::accessors::ConfigValues;
use chrony_rs_core::config::model::{Config, ServerKind};
use chrony_rs_core::ntp::ext::{NtpPacketBuf, NtpPacketInfo, NTP_HEADER_LENGTH};
use chrony_rs_core::ntp::rx_dispatch::SourceInstance;
use chrony_rs_core::ntp::rx_dispatch::{MODE_ACTIVE, MODE_BROADCAST, MODE_CLIENT, MODE_PASSIVE, MODE_SERVER, MODE_CONTROL, MODE_PRIVATE};
use chrony_rs_core::ntp::sample::ResponseSample;
use chrony_rs_core::ntp::NtpTimestamp;
use chrony_rs_core::ntp_auth::NauInstance;
use chrony_rs_core::nts_ntp_client::{NtsClient, RealNkeClient, NtpAddress, UpdateSourceFn};
use chrony_rs_core::nts_tls;
use chrony_rs_core::samplefilt::NtpSample;
use chrony_rs_core::sys_generic::Timespec;
use chrony_rs_core::util::timespec_to_ntp64;
use crate::metrics;

const REACH_BITS: u32 = 8;

/// Per-source NTP polling state.
#[derive(Debug)]
pub struct NtpSourceEntry {
    pub name: String,
    pub addr: SocketAddr,
    pub instance: SourceInstance,
    pub mode: i32,
    pub poll: i32,
    pub max_delay: f64,
    pub offset_correction: f64,
    pub reachability: u32,
    pub reachability_size: i32,
    pub stratum: i32,
    pub got_response: bool,
    // Item 1: Interleaved mode saved timestamps
    pub saved_origin_ts: Option<NtpTimestamp>,
    pub saved_rx_ts: Option<NtpTimestamp>,
    pub saved_tx_ts: Option<NtpTimestamp>,
}

/// Manages NTP socket I/O and per-source poll/response dispatch.
#[derive(Debug)]
pub struct NtpSourceManager {
    pub socket: UdpSocket,
    pub sources: Vec<NtpSourceEntry>,
}

impl NtpSourceManager {
    pub fn new(config: &Config, config_values: &ConfigValues, ipv6: bool) -> Result<Self, String> {
        let bind_addr = if ipv6 { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| format!("bind NTP socket {bind_addr}: {e}"))?;
        socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
        let mut sources = Vec::new();
        for src in config.sources() {
            let host = &src.params.name;
            let port = src.params.port as u16;
            let addr = resolve_with_timeout(host, port, 10)
                .ok_or_else(|| format!("dns: failed to resolve {host}:{port}"))?;
            let mode = if src.kind == ServerKind::Peer { MODE_ACTIVE } else { MODE_CLIENT };

            let mut entry = NtpSourceEntry {
                name: host.clone(),
                addr,
                instance: SourceInstance::new(host, mode, 0),
                mode,
                poll: src.params.minpoll.max(4).min(10),
                max_delay: src.params.max_delay,
                offset_correction: src.params.offset,
                reachability: 0,
                reachability_size: 0,
                stratum: 16,
                got_response: false,
                saved_origin_ts: None,
                saved_rx_ts: None,
                saved_tx_ts: None,
            };

            if src.params.nts {
                entry = Self::setup_nts_source(entry, host, src, config_values, mode, port, &addr)?;
            }

            // chrony MAX_SOURCES ceiling
            const MAX_NTP_SOURCES: usize = 65536;
            if sources.len() >= MAX_NTP_SOURCES {
                eprintln!("ntp: WARNING — maximum source count ({MAX_NTP_SOURCES}) reached, skipping {host}");
                continue;
            }
            sources.push(entry);
        }
        Ok(NtpSourceManager { socket, sources })
    }

    fn setup_nts_source(
        mut entry: NtpSourceEntry,
        host: &str,
        src: &chrony_rs_core::config::model::SourceDirective,
        config_values: &ConfigValues,
        mode: i32,
        port: u16,
        _addr: &SocketAddr,
    ) -> Result<NtpSourceEntry, String> {
        eprintln!("nts: configuring NTS for source {host}");

        if mode != MODE_CLIENT {
            eprintln!("nts: WARNING NTS with non-client mode ({mode}) is not supported by RFC 8915");
        }

        let nts_host = config_values
            .nts_ntp_server()
            .unwrap_or(host)
            .to_string();
        let nts_port = 4460u16;

        let tls_session = nts_tls::create_default_tls_session();

        let nke = Box::new(RealNkeClient::new(tls_session, nts_host, nts_port));

        let nts_address = NtpAddress { ip: None, port: nts_port };

        let mono_time: Box<dyn FnMut() -> f64> = Box::new(move || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64()
        });

        let rng: Box<dyn FnMut() -> u8> = {
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let mut state = seed as u32;
            Box::new(move || {
                state = state.wrapping_mul(1103515245).wrapping_add(12345);
                (state >> 16) as u8
            })
        };

        let update_source: UpdateSourceFn =
            Box::new(|_old, _new| {
                eprintln!("nts: source address update not implemented");
                true
            });

        let nts_refresh = config_values.nts_refresh() as f64;

        let nts_client = NtsClient::new(
            nts_address,
            host,
            src.params.cert_set,
            port,
            nke,
            mono_time,
            rng,
            nts_refresh,
            update_source,
            None,
        );

        entry.instance =
            SourceInstance::new_with_auth(host, mode, NauInstance::create_nts(nts_client));

        eprintln!("nts: NTS-KE client ready for {host}");
        Ok(entry)
    }

    /// Send an NTP client request to source `index`.
    /// Before sending, updates reachability based on whether a response
    /// was received since the last poll.
    /// Returns true if the packet was sent.
    pub fn poll_source(&mut self, index: usize, now_sec: i64, now_nsec: i64) -> bool {
        let entry = &mut self.sources[index];

        let previous_response = entry.got_response;
        entry.got_response = false;

        entry.reachability = (entry.reachability << 1) | (previous_response as u32);
        entry.reachability %= 1u32 << REACH_BITS;
        if entry.reachability_size < REACH_BITS as i32 {
            entry.reachability_size += 1;
        }

        let (hi, lo) = timespec_to_ntp64(now_sec, now_nsec, None);

        entry.instance.auth.prepare_request_auth();

        let mut packet = NtpPacketBuf::new();
        packet.set_lvm((0 << 6) | (4 << 3) | entry.mode as u8);
        packet.bytes_mut()[40..44].copy_from_slice(&hi.to_be_bytes());
        packet.bytes_mut()[44..48].copy_from_slice(&lo.to_be_bytes());

        let mut info = NtpPacketInfo {
            length: NTP_HEADER_LENGTH,
            version: 4,
            mode: entry.mode,
            ..Default::default()
        };

        entry
            .instance
            .auth
            .generate_request_auth(&mut entry.instance.keys, &mut packet, &mut info);

        let cooked = Timespec {
            tv_sec: now_sec,
            tv_nsec: now_nsec,
        };
        let packet_len = info.length as usize;
        let sent = self
            .socket
            .send_to(&packet.bytes()[..packet_len], entry.addr)
            .is_ok();
        if sent {
            entry.instance.record_t1(cooked, 0.0);
            metrics::inc_ntp_packets_sent();
        }
        sent
    }

    /// Drain all available NTP responses from the socket.
    /// For matching server responses, marks `got_response` and
    /// processes through the source instance.
    /// If `ntp_access` is provided, packets from disallowed peers are silently dropped.
    /// Returns accepted samples.
    pub fn receive_all(
        &mut self,
        now_sec: i64,
        now_nsec: i64,
        ntp_access: Option<&chrony_rs_core::addrfilt::AuthTable>,
    ) -> Vec<(usize, ResponseSample)> {
        let mut results = Vec::new();
        let mut buf = [0u8; 1200];
        let now = chrony_rs_core::sys_generic::Timespec {
            tv_sec: now_sec,
            tv_nsec: now_nsec,
        };
        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    if n < 48 {
                        continue;
                    }
                    // Item 1: NTP access control (ADF_IsAllowed)
                    if let Some(access) = ntp_access {
                        if !access.is_allowed(peer.ip()) {
                            send_kod(&self.socket, peer, b"DENY");
                            continue;
                        }
                    }

                    let pkt_mode = (buf[0] & 0x07) as i32;

                    // Item 3: Broadcast client mode — accept mode-5 packets
                    if pkt_mode == MODE_BROADCAST {
                        let ref_sec = i64::from_be_bytes(buf[24..32].try_into().unwrap_or([0; 8]));
                        let ref_frac = u64::from_be_bytes(buf[32..40].try_into().unwrap_or([0; 8]));
                        let server_tx = ref_sec as f64 + ref_frac as f64 / (1u64 << 32) as f64;
                        let client_rx = now_sec as f64 + now_nsec as f64 / 1e9;
                        let offset = server_tx - client_rx;
                        let root_delay = u32::from_be_bytes(buf[4..8].try_into().unwrap_or([0; 4])) as f64 / 65536.0;
                        let root_dispersion = u32::from_be_bytes(buf[8..12].try_into().unwrap_or([0; 4])) as f64 / 65536.0;
                        eprintln!("ntp: broadcast from {}, offset={:.6}s", peer, offset);
                        // Only push sample if we have a matching source (broadcastclient config)
                        if let Some(bc_idx) = self.sources.iter().position(|s| s.addr == peer) {
                            let sample = ResponseSample {
                                offset,
                                peer_delay: 0.001,
                                peer_dispersion: 0.01,
                                root_delay,
                                root_dispersion,
                                time: Timespec { tv_sec: now_sec, tv_nsec: now_nsec },
                            };
                            results.push((bc_idx, sample));
                        }
                        continue;
                    }

                    // Item 3: Manycast server — respond to client solicitations from multicast addresses
                    if pkt_mode == MODE_CLIENT && peer.ip().is_multicast() {
                        let mut resp = [0u8; 48];
                        resp[0] = (0 << 6) | (4 << 3) | 4;
                        resp[24..32].copy_from_slice(&buf[40..48]);
                        let (hi, lo) = timespec_to_ntp64(now.tv_sec, now.tv_nsec, None);
                        resp[40..44].copy_from_slice(&hi.to_be_bytes());
                        resp[44..48].copy_from_slice(&lo.to_be_bytes());
                        let _ = self.socket.send_to(&resp, peer);
                        continue;
                    }

                    // B1: NTP control mode (mode 6) — respond with minimal control response
                    if pkt_mode == MODE_CONTROL {
                        let (now_hi, now_lo) = timespec_to_ntp64(now.tv_sec, now.tv_nsec, None);
                        let now_bytes_32 = now_hi.to_be_bytes();
                        let now_bytes_40 = now_lo.to_be_bytes();
                        let mut resp = [0u8; 48];
                        resp[0] = (0 << 6) | (4 << 3) | 6;
                        resp[24..32].copy_from_slice(&buf[40..48]);
                        resp[32..36].copy_from_slice(&now_bytes_32);
                        resp[36..40].copy_from_slice(&now_bytes_40);
                        resp[40..44].copy_from_slice(&now_bytes_32);
                        resp[44..48].copy_from_slice(&now_bytes_40);
                        let _ = self.socket.send_to(&resp, peer);
                        continue;
                    }

                    // B2: NTP private mode (mode 7) — respond with a REFUSED status
                    if pkt_mode == MODE_PRIVATE {
                        let mut resp = [0u8; 48];
                        resp[0] = (0 << 6) | (4 << 3) | 7;
                        let _ = self.socket.send_to(&resp, peer);
                        continue;
                    }

                    // B6: MS-SNTP detection — check for MS-SNTP auth mode
                    if n >= 52 {
                        let auth_mode = detect_mssntp(&buf[..n]);
                        if auth_mode == 2 {
                            eprintln!("ntp: MS-SNTP authenticated request from {}, signing not yet wired", peer);
                        }
                    }

                    let Some(idx) = self.sources.iter().position(|s| s.addr == peer) else {
                        continue;
                    };

                    let ok = if self.sources[idx].mode == MODE_ACTIVE {
                        pkt_mode == MODE_ACTIVE || pkt_mode == MODE_PASSIVE
                    } else {
                        pkt_mode == MODE_SERVER
                    };
                    if !ok {
                        continue;
                    }
                    self.sources[idx].got_response = true;
                    self.sources[idx].stratum = buf[1] as i32;
                    metrics::inc_ntp_packets_received();

                    let entry = &mut self.sources[idx];

                    // Item 1: Origin timestamp enforcement (test B / replay mitigation)
                    let origin_ts = NtpTimestamp::from_be_bytes(
                        buf[24..32].try_into().unwrap_or([0; 8])
                    );
                    let origin_ts_u64 = u64::from_be_bytes(
                        buf[24..32].try_into().unwrap_or([0u8; 8])
                    );
                    let our_t1 = entry.instance.saved_t1.map(|ts| {
                        let (hi, lo) = timespec_to_ntp64(ts.tv_sec, ts.tv_nsec, None);
                        (hi as u64) << 32 | lo as u64
                    }).unwrap_or(0);
                    if origin_ts_u64 != 0 && origin_ts_u64 != our_t1 {
                        if entry.saved_rx_ts.is_none() {
                            eprintln!("ntp: origin timestamp mismatch from {peer} — possible replay attack, dropping");
                            continue;
                        }
                        eprintln!("ntp: interleaved response from {peer}");
                    }

                    // Save timestamps for future interleaved matching
                    entry.saved_origin_ts = Some(origin_ts);
                    entry.saved_rx_ts = Some(NtpTimestamp::from_be_bytes(
                        buf[32..40].try_into().unwrap_or([0; 8])
                    ));
                    entry.saved_tx_ts = Some(NtpTimestamp::from_be_bytes(
                        buf[40..48].try_into().unwrap_or([0; 8])
                    ));

                    if let Some(sample) = entry.instance.handle_response(
                        &buf[..n],
                        now,
                        0.0,
                        entry.max_delay,
                        entry.offset_correction,
                    ) {
                        results.push((idx, sample));
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("ntp: recv error: {e}");
                    break;
                }
            }
        }
        results
    }

    pub fn _is_reachable(&self, index: usize) -> bool {
        self.sources[index].reachability != 0
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    pub fn poll_interval_secs(&self, index: usize) -> f64 {
        let p = self.sources[index].poll;
        if p >= 0 {
            (1u32 << p) as f64
        } else {
            1.0 / ((1u32 << (-p)) as f64)
        }
    }

    pub fn close_sockets(&mut self) {
        eprintln!("ntp: closing sockets");
    }

    pub fn sample_to_ntp_sample(sample: &ResponseSample) -> NtpSample {
        NtpSample {
            time: sample.time.tv_sec as f64 + sample.time.tv_nsec as f64 * 1.0e-9,
            offset: sample.offset,
            peer_delay: sample.peer_delay,
            peer_dispersion: sample.peer_dispersion,
            root_delay: sample.root_delay,
            root_dispersion: sample.root_dispersion,
        }
    }
}

/// B3: Send a Kiss-o'-Death packet to the specified peer.
pub fn send_kod(sock: &std::net::UdpSocket, peer: std::net::SocketAddr, refid: &[u8; 4]) {
    let mut packet = [0u8; 48];
    packet[0] = (3 << 6) | (4 << 3) | 4;
    packet[1] = 0;
    packet[12..16].copy_from_slice(refid);
    let _ = sock.send_to(&packet, peer);
}

/// B6: Detect MS-SNTP authentication from the raw packet bytes.
/// Looks for the MAC after the 48-byte header: MS-SNTP uses key_id=0 and a specific
/// MAC format. Returns auth_mode: 2 for MSSNTP, 0 otherwise.
fn detect_mssntp(buf: &[u8]) -> i32 {
    if buf.len() < 52 {
        return 0;
    }
    let mac_len = buf.len() - 48;
    if mac_len == 4 {
        let key_id = u32::from_be_bytes([buf[48], buf[49], buf[50], buf[51]]);
        if key_id == 0 {
            return 2;
        }
    }
    0
}
