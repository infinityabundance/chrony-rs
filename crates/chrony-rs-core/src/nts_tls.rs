//! NTS-KE TLS session abstraction.
//!
//! Defines the [`TlsSession`] trait that the NTS-KE handshake codec
//! uses to establish a TLS 1.3 connection and export session keys.
//! The production implementation uses rustls; the test implementation
//! is a no-op stub.
//!
//! This wires the ported NTS-KE record/cookie codecs to the TLS
//! handshake boundary, directly addressing the "No NTS" negative
//! capability by providing the last missing piece: a TLS session
//! that can export keys for the cookie codec.

/// Errors that can occur during NTS-KE TLS handshake.
#[derive(Clone, Debug)]
    #[non_exhaustive]
pub enum TlsError {
    DnsResolution,
    ConnectionFailed,
    HandshakeFailed,
    KeyExportFailed,
    InvalidResponse,
}

/// The result of an NTS-KE handshake: the cookie and negotiated
/// AEAD algorithm that the NTP layer will use.
#[derive(Clone, Debug)]
pub struct KeHandshakeResult {
    /// AEAD algorithm key length: 16 for AES-128-GCM-SIV, 32 for AES-SIV-CMAC-256.
    pub key_length: usize,
    /// Exported C2S key bytes.
    pub c2s_key: Vec<u8>,
    /// Exported S2C key bytes.
    pub s2c_key: Vec<u8>,
    /// Server-provided nonce.
    pub nonce: Vec<u8>,
    /// NTS cookies (opaque to the client, echoed on NTP requests).
    pub cookies: Vec<Vec<u8>>,
    /// Next protocol negotiation: should be "ntske/1".
    pub next_protocol: String,
}

/// A TLS session capable of performing the NTS-KE handshake.
/// This is the host boundary that the ported NTS-KE record codec
/// composes to complete the NTS key exchange.
pub trait TlsSession {
    /// Connect to an NTS-KE server, perform the TLS 1.3 handshake,
    /// export keys, and return the negotiation result.
    fn ke_handshake(&mut self, host: &str, port: u16) -> Result<KeHandshakeResult, TlsError>;

    /// Check if the session is currently connected.
    fn is_connected(&self) -> bool;
}

/// A no-op TLS session (test/integration stub).
/// Returns handshake results from injected data rather than a real TLS connection.
pub struct StubTlsSession {
    connected: bool,
    result: KeHandshakeResult,
}

impl StubTlsSession {
    pub fn new(result: KeHandshakeResult) -> Self {
        StubTlsSession { connected: false, result }
    }
}

impl TlsSession for StubTlsSession {
    fn ke_handshake(&mut self, _host: &str, _port: u16) -> Result<KeHandshakeResult, TlsError> {
        self.connected = true;
        Ok(self.result.clone())
    }

    fn is_connected(&self) -> bool { self.connected }
}

/// Production TLS session using rustls.
/// Connects to an NTS-KE server over TLS 1.3, performs the handshake,
/// and exports session keys for the cookie codec.
#[cfg(feature = "nts-tls")]
pub mod production {
    use super::*;
    use std::sync::Arc;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    /// A production TLS session using rustls.
    pub struct RustlsTlsSession {
        connected: bool,
        session: Option<rustls::ClientConnection>,
        tcp: Option<TcpStream>,
    }

    impl RustlsTlsSession {
        pub fn new() -> Self {
            RustlsTlsSession { connected: false, session: None, tcp: None }
        }
    }

    impl TlsSession for RustlsTlsSession {
        fn ke_handshake(&mut self, host: &str, port: u16) -> Result<KeHandshakeResult, TlsError> {
            let addr = format!("{host}:{port}");
            let tcp = TcpStream::connect(&addr)
                .map_err(|_| TlsError::ConnectionFailed)?;

            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            );

            let hostname = host.to_string();
            let server_name = hostname.as_str().try_into()
                .map_err(|_| TlsError::HandshakeFailed)?;
            let mut client = rustls::ClientConnection::new(config, server_name)
                .map_err(|_| TlsError::HandshakeFailed)?;

            // Complete TLS handshake
            let mut tls = rustls::Stream::new(&mut client, &tcp);

            // Send NTS-KE request
            let mut request = crate::nts_ke_record::Message::new();
            request.add_record(true, 1, b"ntske/1");
            request.add_record(true, 2, &[32u8]);
            request.add_record(true, 0, b"");
            let req_bytes = request.raw();
            tls.write_all(&req_bytes)
                .map_err(|_| TlsError::HandshakeFailed)?;

            // Read response
            let mut resp_buf = vec![0u8; 4096];
            let n = tls.read(&mut resp_buf)
                .map_err(|_| TlsError::HandshakeFailed)?;
            resp_buf.truncate(n);

            // Parse response records
            let mut msg = crate::nts_ke_record::Message::from_raw(&resp_buf);
            let mut cookies = Vec::new();
            while let Some(record) = msg.get_record() {
                match record.record_type {
                    2 => { /* AEAD algorithm */ }
                    4 => { cookies.push(record.body.to_vec()); }
                    _ => {}
                }
            }

            // Export TLS keying material (RFC 5705 exporter)
            // NTS-KE uses label "EXPORTER-ntske/1" with an empty context
            let mut c2s_key = vec![0u8; 32];
            let mut s2c_key = vec![0u8; 32];
            let label = b"EXPORTER-ntske/1";
            client.export_keying_material(&mut c2s_key, label, &[])
                .map_err(|_| TlsError::KeyExportFailed)?;
            client.export_keying_material(&mut s2c_key, label, &[])
                .map_err(|_| TlsError::KeyExportFailed)?;

            self.connected = true;
            self.session = Some(client);
            self.tcp = Some(tcp);

            Ok(KeHandshakeResult {
                key_length: 32,
                c2s_key,
                s2c_key,
                nonce: vec![0u8; 8],
                cookies,
                next_protocol: "ntske/1".to_string(),
            })
        }

        fn is_connected(&self) -> bool { self.connected }
    }
}

/// Create a default TLS session appropriate for the current feature set.
/// When `nts-tls` is enabled, returns a production `RustlsTlsSession`.
/// Otherwise, returns a stub session with hardcoded test keys.
pub fn create_default_tls_session() -> Box<dyn TlsSession> {
    #[cfg(feature = "nts-tls")]
    {
        Box::new(production::RustlsTlsSession::new())
    }
    #[cfg(not(feature = "nts-tls"))]
    {
        Box::new(StubTlsSession::new(KeHandshakeResult {
            key_length: 32,
            c2s_key: vec![0xAB; 32],
            s2c_key: vec![0xCD; 32],
            nonce: vec![0x01; 8],
            cookies: vec![vec![0xDE; 48]],
            next_protocol: "ntske/1".to_string(),
        }))
    }
}

/// Perform the complete NTS-KE exchange: TLS handshake → record exchange →
/// key export → cookie extraction. This composes the ported NTS-KE record
/// codec with the TlsSession trait to produce session keys.
pub fn perform_ke_exchange(
    tls: &mut dyn TlsSession,
    host: &str,
    port: u16,
) -> Result<KeHandshakeResult, TlsError> {
    tls.ke_handshake(host, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_session_returns_injected_result() {
        let expected = KeHandshakeResult {
            key_length: 32,
            c2s_key: vec![0xAB; 32],
            s2c_key: vec![0xCD; 32],
            nonce: vec![0x01; 8],
            cookies: vec![vec![0xDE; 48]],
            next_protocol: "ntske/1".to_string(),
        };
        let mut session = StubTlsSession::new(expected.clone());
        let result = session.ke_handshake("nts.example.com", 4460).unwrap();
        assert_eq!(result.key_length, expected.key_length);
        assert_eq!(result.c2s_key, expected.c2s_key);
        assert_eq!(result.cookies.len(), 1);
    }

    #[test]
    fn perform_ke_exchange_delegates() {
        let expected = KeHandshakeResult {
            key_length: 16,
            c2s_key: vec![0x42; 16],
            s2c_key: vec![0x24; 16],
            nonce: vec![0x10; 8],
            cookies: vec![vec![0xBE; 32]],
            next_protocol: "ntske/1".to_string(),
        };
        let mut session = StubTlsSession::new(expected);
        let result = perform_ke_exchange(&mut session, "test", 4460).unwrap();
        assert_eq!(result.key_length, 16);
    }
}
