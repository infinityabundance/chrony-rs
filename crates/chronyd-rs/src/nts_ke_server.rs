//! Minimal NTS-KE server — RFC 8915 Key Establishment.
//!
//! Listens on a TCP port (default 4460) and performs the NTS-KE exchange:
//! parsing the client's request, selecting an AEAD algorithm, generating
//! fresh session keys and cookies, and responding.
//!
//! ## Limitations
//!
//! - No TLS 1.3 handshake (required by RFC 8915). The server accepts plain
//!   TCP connections, which is suitable for testing but not production.
//!   When the `nts-tls` feature is enabled (see Cargo.toml), this should
//!   wrap the stream in a TLS session before reading NTS-KE records.
//! - Single server key with no rotation.
//! - No NTPv4 server/port negotiation.

use chrony_rs_core::nts_ke_record;
use chrony_rs_core::nts_ke_record::{
    KeRequest, Message, AEAD_AES_SIV_CMAC_256, NKE_MAX_MESSAGE_LENGTH,
    NKE_NEXT_PROTOCOL_NTPV4,
};
use chrony_rs_core::nts_ntp_server::{CookieCodec, NkeContext, NkeKey, RealCookieCodec};
use chrony_rs_core::siv_nettle::{get_key_length, SivAlgorithm};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;

/// NTS-KE rate limiter: token-bucket — at most 10 connections per second.
fn random_bytes(buf: &mut [u8]) {
    #[cfg(target_os = "linux")]
    {
        use std::fs::File;
        use std::io::Read;
        if let Ok(mut f) = File::open("/dev/urandom") {
            let _ = f.read_exact(buf);
            return;
        }
    }
    unsafe {
        libc::syscall(libc::SYS_getrandom, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
    }
}

fn ntske_last_accept() -> &'static Mutex<std::time::Instant> {
    static NTSKE_LAST_ACCEPT: std::sync::OnceLock<Mutex<std::time::Instant>> = std::sync::OnceLock::new();
    NTSKE_LAST_ACCEPT.get_or_init(|| Mutex::new(std::time::Instant::now()))
}

fn rate_limit_ntske() -> bool {
    let mut last = ntske_last_accept().lock().expect("ntske mutex poisoned");
    let now = std::time::Instant::now();
    if now.duration_since(*last).as_millis() < 100 {
        return false;
    }
    *last = now;
    true
}

/// Start the NTS-KE server on the given port.
/// Spawns a daemon thread and returns a JoinHandle.
pub fn start_nts_ke_server(port: u16) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
    let addr = format!("127.0.0.1:{port}");
    match TcpListener::bind(&addr) {
        Ok(listener) => {
            eprintln!("nts-ke: server listening on {addr}");
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        if !rate_limit_ntske() {
                            eprintln!("nts-ke: rate limit exceeded, dropping connection");
                            continue;
                        }
                        if let Err(e) = handle_client(stream) {
                            eprintln!("nts-ke: client error: {e}");
                        }
                    }
                    Err(e) => eprintln!("nts-ke: accept error: {e}"),
                }
            }
        }
        Err(e) => eprintln!("nts-ke: cannot bind {addr}: {e}"),
    }
    })
}

fn handle_client(mut stream: TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| format!("set timeout: {e}"))?;

    let peer = stream.peer_addr().map_err(|e| format!("peer addr: {e}"))?;
    let ip = peer.ip();
    if !ip.is_loopback() {
        return Err(format!("connection from {ip} rejected (not yet supported)"));
    }
    eprintln!("nts-ke: connection from {peer}");

    // In production a TLS 1.3 handshake would happen here.
    // When the nts-tls feature is enabled, wrap stream in a TLS session:
    //   #[cfg(feature = "nts-tls")] { ... }

    let mut buf = [0u8; NKE_MAX_MESSAGE_LENGTH];
    let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
    if n == 0 {
        return Err("empty request".into());
    }

    let mut msg = Message::from_received(&buf[..n]);

    if !msg.check_message_format(true) {
        return Err("malformed message".into());
    }

    let aead_supported = |alg: u16| -> bool {
        match alg {
            a if a == AEAD_AES_SIV_CMAC_256 as u16 => {
                get_key_length(SivAlgorithm::AesSivCmac256) > 0
            }
            _ => false,
        }
    };

    let req: KeRequest = nts_ke_record::process_request(&mut msg, aead_supported);

    if req.error >= 0 {
        let resp = nts_ke_record::prepare_response(req.error, -1, -1, None, None, &[])
            .ok_or("prepare error response")?;
        stream
            .write_all(resp.data())
            .map_err(|e| format!("write: {e}"))?;
        eprintln!("nts-ke: sent error {} to {peer}", req.error);
        return Ok(());
    }

    if req.aead_algorithm < 0 {
        let resp =
            nts_ke_record::prepare_response(-1, NKE_NEXT_PROTOCOL_NTPV4, -1, None, None, &[])
                .ok_or("prepare no-AEAD response")?;
        stream
            .write_all(resp.data())
            .map_err(|e| format!("write: {e}"))?;
        eprintln!("nts-ke: no common AEAD for {peer}");
        return Ok(());
    }

    let key_len = match req.aead_algorithm as u16 {
        AEAD_AES_SIV_CMAC_256 => 32,
        _ => return Err("unsupported AEAD algorithm".into()),
    };

    let mut c2s_key = vec![0u8; key_len];
    let mut s2c_key = vec![0u8; key_len];
    random_bytes(&mut c2s_key);
    random_bytes(&mut s2c_key);

    let context = NkeContext {
        algorithm: SivAlgorithm::AesSivCmac256,
        c2s: NkeKey { key: c2s_key },
        s2c: NkeKey { key: s2c_key },
    };

    let mut codec = RealCookieCodec::new(Box::new(|| {
        let mut b = [0u8; 1];
        random_bytes(&mut b);
        b[0]
    }));
    let mut cookies = Vec::new();
    for _ in 0..8 {
        if let Some(cookie) = codec.generate_cookie(&context) {
            cookies.push(cookie.bytes);
        }
    }
    if cookies.is_empty() {
        return Err("cookie generation failed".into());
    }

    let cookie_refs: Vec<&[u8]> = cookies.iter().map(|c| c.as_slice()).collect();

    let resp = nts_ke_record::prepare_response(
        -1,
        NKE_NEXT_PROTOCOL_NTPV4,
        req.aead_algorithm,
        None,
        None,
        &cookie_refs,
    )
    .ok_or("prepare response")?;

    stream
        .write_all(resp.data())
        .map_err(|e| format!("write: {e}"))?;
    eprintln!(
        "nts-ke: responded to {peer} with {} cookie(s)",
        cookies.len()
    );
    Ok(())
}


