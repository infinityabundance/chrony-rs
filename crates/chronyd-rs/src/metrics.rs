use std::sync::atomic::{AtomicI64, Ordering};

static NTP_PACKETS_RECEIVED: AtomicI64 = AtomicI64::new(0);
static NTP_PACKETS_SENT: AtomicI64 = AtomicI64::new(0);
static CMDMON_REQUESTS: AtomicI64 = AtomicI64::new(0);
static CURRENT_OFFSET: AtomicI64 = AtomicI64::new(0);
static SELECTED_SOURCE_STRATUM: AtomicI64 = AtomicI64::new(0);

pub fn inc_ntp_packets_received() {
    NTP_PACKETS_RECEIVED.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_ntp_packets_sent() {
    NTP_PACKETS_SENT.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_cmdmon_requests() {
    CMDMON_REQUESTS.fetch_add(1, Ordering::Relaxed);
}
pub fn set_current_offset(offset_nanos: i64) {
    CURRENT_OFFSET.store(offset_nanos, Ordering::Relaxed);
}
pub fn set_selected_source_stratum(stratum: i64) {
    SELECTED_SOURCE_STRATUM.store(stratum, Ordering::Relaxed);
}

pub fn start_metrics_server(bind_addr: &str) -> Option<std::thread::JoinHandle<()>> {
    let addr = format!("{}:{}", if bind_addr.is_empty() { "127.0.0.1" } else { bind_addr }, 8080);
    Some(std::thread::spawn(move || {
        use std::io::Write;
        let listener = match std::net::TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("metrics: WARNING — cannot bind to {addr}: {e}");
                return;
            }
        };
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n\
                     # HELP chronyd_ntp_packets_received NTP packets received\n\
                     # TYPE chronyd_ntp_packets_received counter\n\
                     chronyd_ntp_packets_received {}\n\
                     # HELP chronyd_ntp_packets_sent NTP packets sent\n\
                     # TYPE chronyd_ntp_packets_sent counter\n\
                     chronyd_ntp_packets_sent {}\n\
                     # HELP chronyd_cmdmon_requests cmdmon requests processed\n\
                     # TYPE chronyd_cmdmon_requests counter\n\
                     chronyd_cmdmon_requests {}\n\
                     # HELP chronyd_current_offset_seconds Current clock offset\n\
                     # TYPE chronyd_current_offset_seconds gauge\n\
                     chronyd_current_offset_seconds {:.9}\n\
                     # HELP chronyd_selected_source_stratum Selected source stratum\n\
                     # TYPE chronyd_selected_source_stratum gauge\n\
                     chronyd_selected_source_stratum {}\n",
                    NTP_PACKETS_RECEIVED.load(Ordering::Relaxed),
                    NTP_PACKETS_SENT.load(Ordering::Relaxed),
                    CMDMON_REQUESTS.load(Ordering::Relaxed),
                    CURRENT_OFFSET.load(Ordering::Relaxed) as f64 / 1e9,
                    SELECTED_SOURCE_STRATUM.load(Ordering::Relaxed),
                );
                let _ = s.write_all(response.as_bytes());
            }
        }
    }))
}

pub fn start_health_server(bind_addr: &str) -> Option<std::thread::JoinHandle<()>> {
    let addr = format!("{}:{}", if bind_addr.is_empty() { "127.0.0.1" } else { bind_addr }, 8081);
    Some(std::thread::spawn(move || {
        let listener = match std::net::TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("metrics: WARNING — cannot bind to {addr}: {e}");
                return;
            }
        };
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK\n";
                let _ = std::io::Write::write_all(&mut s, response.as_bytes());
            }
        }
    }))
}
