use std::net::UdpSocket;
use std::process::ExitCode;

use chrony_rs_core::client::build_request_header;
use chrony_rs_core::cmdmon::{self, ClientAccessReport, ManualSampleReport};
use chrony_rs_core::court;
use chrony_rs_core::court_event;
use chrony_rs_core::report::{
    clients_header, manual_list_info_line, render_authdata_row, render_clients_row,
    render_manual_list_row, render_ntpdata, render_rtcdata, render_selectdata_row, render_tracking,
    serverstats_wire_to_display, ReportMode, ServerstatsReport, SourceEntry, SourcestatsEntry,
    AUTHDATA_HEADER, MANUAL_LIST_HEADER, SELECTDATA_HEADER,
};
use chrony_rs_core::util::{
    self, float_network_to_host, ip_network_to_host, timespec_network_to_host,
};

const PROTO_VERSION: u8 = 6;

fn main() -> ExitCode {
    if std::env::var("CHRONYRS_COURT").is_ok() {
        let output_path = std::env::var("CHRONYRS_COURT_OUTPUT").ok();
        court::enable(output_path);
        court_event!(court::CourtCategory::Marker, "chronyc-rs started");
    }

    let raw_args: Vec<String> = std::env::args().collect();
    let mut host = String::from("127.0.0.1");
    let mut port = 323u16;
    let mut csv_mode = false;
    let mut no_dns = false;
    let mut verbose = false;

    let mut i = 1;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "-c" => csv_mode = true,
            "-h" => {
                i += 1;
                if i < raw_args.len() {
                    host = raw_args[i].clone();
                }
            }
            "-p" => {
                i += 1;
                if i < raw_args.len() {
                    port = raw_args[i].parse().unwrap_or(323);
                }
            }
            "-n" => no_dns = true,
            "-d" => verbose = true,
            "-v" => {
                println!(
                    "chronyc-rs (chrony-rs) version {}",
                    chrony_rs_core::TARGET_CHRONY_VERSION
                );
                return ExitCode::SUCCESS;
            }
            _ => break,
        }
        i += 1;
    }

    let command = raw_args.get(i).map(|s| s.as_str());
    let sub_args: Vec<String> = raw_args.iter().skip(i + 1).cloned().collect();

    let result = match command {
        None => {
            eprintln!("{}", USAGE);
            return ExitCode::from(2);
        }
        Some(cmd) => run(cmd, &sub_args, &host, port, csv_mode, no_dns, verbose),
    };

    court::flush();
    match result {
        Ok(out) => {
            print!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(
    command: &str,
    args: &[String],
    host: &str,
    port: u16,
    csv: bool,
    _no_dns: bool,
    _verbose: bool,
) -> Result<String, String> {
    match command {
        "--help" | "-h" | "help" => Ok(format!("{}", USAGE)),
        "--version" | "-v" | "version" => Ok(format!(
            "chronyc-rs (chrony-rs) version {}\n",
            chrony_rs_core::TARGET_CHRONY_VERSION
        )),

        "tracking" => do_tracking(host, port, csv),
        "activity" => do_activity(host, port, csv),
        "sources" => do_sources(host, port, csv),
        "sourcestats" => do_sourcestats(host, port, csv),
        "serverstats" => do_serverstats(host, port, csv),
        "n_sources" => do_n_sources(host, port),

        "ntpdata" => do_ntpdata(host, port, csv, args),
        "clients" => do_clients(host, port, csv, args),
        "manual" => do_manual(host, port, csv, args),
        "rtc" | "rtcdata" => do_rtcdata(host, port, csv),
        "authdata" => do_authdata(host, port, csv, args),
        "smooth" | "smoothing" => do_smoothing(host, port, csv),
        "select" | "selectdata" => do_selectdata(host, port, csv, args),

        "reselect" => send_simple(host, port, cmdmon::REQ_RESELECT, "reselect"),
        "settime" => do_settime(host, port, csv, args),
        "local" => do_local(host, port, args),
        "makesource" | "addserver" => do_add_source(host, port, args),
        "deletesource" => do_delete_source(host, port, args),
        "burst" => do_burst(host, port, args),
        "dns" => send_simple(host, port, cmdmon::REQ_REFRESH, "dns"),
        "cyclelogs" => send_simple(host, port, cmdmon::REQ_CYCLELOGS, "cyclelogs"),
        "reload" => send_simple(host, port, cmdmon::REQ_RELOAD_SOURCES, "reload"),
        "rekey" => send_simple(host, port, cmdmon::REQ_REKEY, "rekey"),
        "password" => do_password(host, port, args),
        "shutdown" => send_simple(host, port, cmdmon::REQ_SHUTDOWN, "shutdown"),
        "dump" => send_simple(host, port, cmdmon::REQ_DUMP, "dump"),
        "writertc" => send_simple(host, port, cmdmon::REQ_WRITERTC, "writertc"),
        "trimrtc" => send_simple(host, port, cmdmon::REQ_TRIMRTC, "trimrtc"),
        "makestep" => do_makestep(host, port, args),
        "refresh" => send_simple(host, port, cmdmon::REQ_REFRESH, "refresh"),
        "reset" => send_simple(host, port, cmdmon::REQ_RESET_SOURCES, "reset"),
        "smoothtime" => do_smoothtime(host, port, args),
        "online" => do_online_offline(host, port, cmdmon::REQ_ONLINE, args),
        "offline" => do_online_offline(host, port, cmdmon::REQ_OFFLINE, args),
        "allow" => do_allow_deny(host, port, cmdmon::REQ_ALLOW, args),
        "deny" => do_allow_deny(host, port, cmdmon::REQ_DENY, args),
        "cmdallow" => do_allow_deny(host, port, cmdmon::REQ_CMDALLOW, args),
        "cmddeny" => do_allow_deny(host, port, cmdmon::REQ_CMDDENY, args),
        "accheck" => do_accheck(host, port, args, false),
        "cmdaccheck" => do_accheck(host, port, args, true),

        _ => Err(format!("unknown command '{command}'")),
    }
}

// ---------------------------------------------------------------------------
// Report command handlers
// ---------------------------------------------------------------------------

fn do_tracking(host: &str, port: u16, csv: bool) -> Result<String, String> {
    let bytes = query_daemon_raw(host, port, cmdmon::REQ_TRACKING, &[])?;
    let tr = chrony_rs_core::client::decode_tracking_reply_cmdmon(&bytes);
    let name = util::ip_to_string(&tr.ip_addr);
    let mode = if csv {
        ReportMode::Csv
    } else {
        ReportMode::Human
    };
    Ok(render_tracking(&tr, &name, mode))
}

fn do_activity(host: &str, port: u16, csv: bool) -> Result<String, String> {
    let bytes = query_daemon_raw(host, port, cmdmon::REQ_ACTIVITY, &[])?;
    let r = chrony_rs_core::client::decode_activity_reply(&bytes);
    if csv {
        Ok(format!(
            "{},{},{},{},{}\n",
            r.online, r.offline, r.burst_online, r.burst_offline, r.unknown
        ))
    } else {
        Ok(r.render())
    }
}

fn do_sources(host: &str, port: u16, csv: bool) -> Result<String, String> {
    let n_bytes = query_daemon_raw(host, port, cmdmon::REQ_N_SOURCES, &[])?;
    let n = u32::from_be_bytes(n_bytes[..4].try_into().unwrap()) as usize;

    let header = "MS Name/IP address         Stratum Poll Reach LastRx Last sample               ";
    let sep = "===============================================================================";
    let mut out = if csv {
        String::new()
    } else {
        format!("{header}\n{sep}\n")
    };

    for i in 0..n {
        let body = chrony_rs_core::client::encode_word_request(i as i32);
        let data_bytes = query_daemon_raw(host, port, cmdmon::REQ_SOURCE_DATA, &body)?;
        if let Some(sd) = chrony_rs_core::client::decode_source_data_reply(&data_bytes) {
            let name = util::ip_to_string(&sd.ip_addr);
            let entry = SourceEntry {
                mode: sd.mode.into(),
                state: sd.state.into(),
                name,
                stratum: sd.stratum,
                poll: sd.poll,
                reach: sd.reachability,
                since_sample: sd.latest_meas_ago,
                adjusted_offset: sd.latest_meas,
                measured_offset: sd.orig_latest_meas,
                error: sd.latest_meas_err,
            };
            if csv {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{}\n",
                    entry.mode.glyph(),
                    entry.state.glyph(),
                    entry.name,
                    entry.stratum,
                    entry.poll,
                    entry.reach,
                    entry.since_sample,
                    entry.adjusted_offset,
                    entry.measured_offset,
                    entry.error,
                ));
            } else {
                out.push_str(&entry.render_row());
            }
        }
    }
    Ok(out)
}

fn do_sourcestats(host: &str, port: u16, csv: bool) -> Result<String, String> {
    let n_bytes = query_daemon_raw(host, port, cmdmon::REQ_N_SOURCES, &[])?;
    let n = u32::from_be_bytes(n_bytes[..4].try_into().unwrap()) as usize;

    let header = "Name/IP Address            NP  NR  Span  Frequency  Freq Skew  Offset  Std Dev";
    let sep = "===============================================================================";
    let mut out = if csv {
        String::new()
    } else {
        format!("{header}\n{sep}\n")
    };

    for i in 0..n {
        let body = chrony_rs_core::client::encode_word_request(i as i32);
        let data_bytes = query_daemon_raw(host, port, cmdmon::REQ_SOURCESTATS, &body)?;
        let flat = chrony_rs_core::client::decode_sourcestats_reply(&data_bytes);
        let name = util::ip_to_string(&flat.ip_addr);
        let entry = SourcestatsEntry {
            name,
            n_samples: flat.n_samples,
            n_runs: flat.n_runs,
            span_seconds: flat.span_seconds,
            resid_freq_ppm: flat.resid_freq_ppm,
            skew_ppm: flat.skew_ppm,
            est_offset: flat.est_offset,
            std_dev: flat.sd,
        };
        if csv {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                entry.name,
                entry.n_samples,
                entry.n_runs,
                entry.span_seconds,
                entry.resid_freq_ppm,
                entry.skew_ppm,
                entry.est_offset,
                entry.std_dev,
            ));
        } else {
            out.push_str(&entry.render_row());
        }
    }
    Ok(out)
}

fn do_serverstats(host: &str, port: u16, csv: bool) -> Result<String, String> {
    let bytes = query_daemon_raw(host, port, cmdmon::REQ_SERVER_STATS, &[])?;
    let wire = chrony_rs_core::client::decode_serverstats_reply(&bytes);
    let display = serverstats_wire_to_display(&wire.counters);
    let report = ServerstatsReport { values: display };
    if csv {
        let v = &report.values;
        Ok(v.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",")
            + "\n")
    } else {
        Ok(report.render())
    }
}

fn do_n_sources(host: &str, port: u16) -> Result<String, String> {
    let bytes = query_daemon_raw(host, port, cmdmon::REQ_N_SOURCES, &[])?;
    let count = u32::from_be_bytes(bytes[..4].try_into().unwrap());
    Ok(format!("{count} source(s)\n"))
}

// ---------------------------------------------------------------------------
// New report commands
// ---------------------------------------------------------------------------

fn do_ntpdata(host: &str, port: u16, csv: bool, args: &[String]) -> Result<String, String> {
    let n_bytes = query_daemon_raw(host, port, cmdmon::REQ_N_SOURCES, &[])?;
    let n = u32::from_be_bytes(n_bytes[..4].try_into().unwrap()) as usize;
    let mode = if csv {
        ReportMode::Csv
    } else {
        ReportMode::Human
    };
    let mut out = String::new();

    for i in 0..n {
        let body = chrony_rs_core::client::encode_word_request(i as i32);
        let data_bytes = match query_daemon_raw(host, port, cmdmon::REQ_NTP_DATA, &body) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let (report, remote_addr, remote_port) =
            chrony_rs_core::client::decode_ntp_data_reply(&data_bytes);
        if args.is_empty()
            || args
                .iter()
                .any(|a| util::ip_to_string(&remote_addr).contains(a))
        {
            out.push_str(&render_ntpdata(&report, &remote_addr, remote_port, mode));
            if !csv && i + 1 < n {
                out.push('\n');
            }
        }
    }
    if out.is_empty() {
        out.push_str("No matching NTP data found\n");
    }
    Ok(out)
}

fn do_clients(host: &str, port: u16, csv: bool, _args: &[String]) -> Result<String, String> {
    let count_bytes = query_daemon_raw(host, port, cmdmon::REQ_CLIENT_ACCESSES, &[])?;
    if count_bytes.len() < 4 {
        return Err("short clients reply".to_string());
    }
    let n = u32::from_be_bytes(count_bytes[..4].try_into().unwrap()) as usize;
    let mode = if csv {
        ReportMode::Csv
    } else {
        ReportMode::Human
    };
    let mut out = if csv {
        String::new()
    } else {
        clients_header(false) + "\n"
    };

    for i in 0..n {
        let body = chrony_rs_core::client::encode_word_request(i as i32);
        let data = query_daemon_raw(host, port, cmdmon::REQ_CLIENT_ACCESSES_BY_INDEX, &body)?;
        if data.len() < 60 {
            return Err("short client record".to_string());
        }
        let client = decode_client_access_entry(&data);
        let name = util::ip_to_string(&client.ip_addr);
        out.push_str(&render_clients_row(&name, &client, false, mode));
    }
    Ok(out)
}

fn do_manual(host: &str, port: u16, csv: bool, args: &[String]) -> Result<String, String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    match sub {
        "list" => {
            let bytes = query_daemon_raw(host, port, cmdmon::REQ_MANUAL_LIST, &[])?;
            if bytes.len() < 4 {
                return Err("short manual list reply".to_string());
            }
            let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            let mode = if csv {
                ReportMode::Csv
            } else {
                ReportMode::Human
            };
            let mut out = if csv {
                String::new()
            } else {
                manual_list_info_line(n as u32) + MANUAL_LIST_HEADER + "\n"
            };
            for i in 0..n {
                let off = 4 + i * 24;
                if off + 24 > bytes.len() {
                    break;
                }
                let sample = decode_manual_list_sample(&bytes[off..off + 24]);
                out.push_str(&render_manual_list_row(i as i32, &sample, mode));
            }
            Ok(out)
        }
        "delete" => {
            let idx = args
                .get(1)
                .and_then(|s| s.parse::<i32>().ok())
                .ok_or_else(|| "usage: manual delete <index>".to_string())?;
            let body = chrony_rs_core::client::encode_word_request(idx);
            let _ = query_daemon_raw(host, port, cmdmon::REQ_MANUAL_DELETE, &body)?;
            Ok("200 OK\n".to_string())
        }
        "on" | "enable" => {
            let body = chrony_rs_core::client::encode_word_request(1);
            let _ = query_daemon_raw(host, port, cmdmon::REQ_MANUAL, &body)?;
            Ok("200 OK\n".to_string())
        }
        "off" | "disable" => {
            let body = chrony_rs_core::client::encode_word_request(0);
            let _ = query_daemon_raw(host, port, cmdmon::REQ_MANUAL, &body)?;
            Ok("200 OK\n".to_string())
        }
        "reset" => {
            let body = chrony_rs_core::client::encode_word_request(2);
            let _ = query_daemon_raw(host, port, cmdmon::REQ_MANUAL, &body)?;
            Ok("200 OK\n".to_string())
        }
        _ => {
            // bare "manual" -> show help
            Ok("manual commands: list, on/off/enable/disable, reset, delete <index>\n".to_string())
        }
    }
}

fn do_rtcdata(host: &str, port: u16, csv: bool) -> Result<String, String> {
    let bytes = query_daemon_raw(host, port, cmdmon::REQ_RTCREPORT, &[])?;
    let rtc = chrony_rs_core::client::decode_rtc_reply(&bytes);
    let mode = if csv {
        ReportMode::Csv
    } else {
        ReportMode::Human
    };
    Ok(render_rtcdata(&rtc, mode))
}

fn do_authdata(host: &str, port: u16, csv: bool, args: &[String]) -> Result<String, String> {
    let n_bytes = query_daemon_raw(host, port, cmdmon::REQ_N_SOURCES, &[])?;
    let n = u32::from_be_bytes(n_bytes[..4].try_into().unwrap()) as usize;
    let mode = if csv {
        ReportMode::Csv
    } else {
        ReportMode::Human
    };
    let filter = args.first().map(|s| s.as_str());
    let mut out = if csv {
        String::new()
    } else {
        AUTHDATA_HEADER.to_string() + "\n"
    };

    for i in 0..n {
        let idx_body = chrony_rs_core::client::encode_word_request(i as i32);
        let name = match query_daemon_raw(host, port, cmdmon::REQ_NTP_SOURCE_NAME, &idx_body) {
            Ok(nb) => {
                let nul = nb.iter().position(|&c| c == 0).unwrap_or(nb.len());
                String::from_utf8_lossy(&nb[..nul]).into_owned()
            }
            Err(_) => format!("#{i}"),
        };
        let auth_bytes = match query_daemon_raw(host, port, cmdmon::REQ_AUTH_DATA, &idx_body) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Some(auth) = chrony_rs_core::client::decode_auth_data_reply(&auth_bytes) {
            if filter.map_or(true, |f| name.contains(f)) {
                out.push_str(&render_authdata_row(&name, &auth, mode));
            }
        }
    }
    Ok(out)
}

fn do_smoothing(host: &str, port: u16, csv: bool) -> Result<String, String> {
    let bytes = query_daemon_raw(host, port, cmdmon::REQ_SMOOTHING, &[])?;
    let sm = chrony_rs_core::client::decode_smoothing_reply(&bytes);
    if csv {
        Ok(format!(
            "{},{},{},{},{},{},{}\n",
            sm.active as u8,
            sm.leap_only as u8,
            sm.offset,
            sm.freq_ppm,
            sm.wander_ppm,
            sm.last_update_ago,
            sm.remaining_time,
        ))
    } else {
        Ok(format!(
            "Active           : {}\n\
             Offset           : {:.9} seconds\n\
             Frequency        : {:.3} ppm\n\
             Leap only        : {}\n\
             Wander           : {:.3} ppm\n\
             Last update      : {:.1} seconds ago\n\
             Remaining time   : {:.1} seconds\n",
            if sm.active { "Yes" } else { "No" },
            sm.offset,
            sm.freq_ppm.abs(),
            if sm.leap_only { "Yes" } else { "No" },
            sm.wander_ppm,
            sm.last_update_ago,
            sm.remaining_time,
        ))
    }
}

fn do_selectdata(host: &str, port: u16, csv: bool, args: &[String]) -> Result<String, String> {
    let n_bytes = query_daemon_raw(host, port, cmdmon::REQ_N_SOURCES, &[])?;
    let n = u32::from_be_bytes(n_bytes[..4].try_into().unwrap()) as usize;
    let mode = if csv {
        ReportMode::Csv
    } else {
        ReportMode::Human
    };
    let filter = args.first().map(|s| s.as_str());
    let mut out = if csv {
        String::new()
    } else {
        SELECTDATA_HEADER.to_string() + "\n"
    };

    for i in 0..n {
        let body = chrony_rs_core::client::encode_word_request(i as i32);
        let data = match query_daemon_raw(host, port, cmdmon::REQ_SELECT_DATA, &body) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let sel = chrony_rs_core::client::decode_select_data_reply(&data);
        let name = util::ip_to_string(&sel.ip_addr);
        if filter.map_or(true, |f| name.contains(f)) {
            out.push_str(&render_selectdata_row(&name, &sel, mode));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Action command handlers
// ---------------------------------------------------------------------------

fn do_settime(host: &str, port: u16, csv: bool, args: &[String]) -> Result<String, String> {
    let t = if args.is_empty() {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
    } else {
        let secs: u64 = args[0]
            .parse()
            .map_err(|_| "usage: settime [<seconds>]".to_string())?;
        std::time::Duration::from_secs(secs)
    };
    let body =
        chrony_rs_core::client::encode_settime_request(t.as_secs() as i64, t.subsec_nanos() as i64);
    let bytes = query_daemon_raw(host, port, cmdmon::REQ_SETTIME, &body)?;
    if !csv && bytes.len() >= 12 {
        let (offset, dfreq, newfreq) =
            chrony_rs_core::client::decode_manual_timestamp_reply(&bytes);
        Ok(format!(
            "200 OK\n\
             Offset     : {:.9} seconds\n\
             Dfreq      : {:.3} ppm\n\
             New freq   : {:.3} ppm\n",
            offset, dfreq, newfreq
        ))
    } else {
        Ok("200 OK\n".to_string())
    }
}

fn do_local(host: &str, port: u16, args: &[String]) -> Result<String, String> {
    // local [on|off] [stratum] [distance] [orphan]
    let on_off = match args.first().map(|s| s.as_str()) {
        Some("on" | "enable") => 1,
        Some("off" | "disable") => 0,
        Some(s) => i32::from_be_bytes(
            s.parse::<i32>()
                .map_err(|_| "usage: local [on|off] [stratum] [distance] [orphan]".to_string())?
                .to_be_bytes(),
        ),
        None => 1,
    };
    let stratum: i32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let distance: f64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let orphan: i32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = chrony_rs_core::client::encode_local_request(on_off, stratum, distance, orphan);
    let _ = query_daemon_raw(host, port, cmdmon::REQ_LOCAL2, &body)?;
    Ok("200 OK\n".to_string())
}

fn do_add_source(host: &str, port: u16, args: &[String]) -> Result<String, String> {
    let name = args
        .first()
        .ok_or_else(|| "usage: addserver <hostname> [port]".to_string())?;
    let port_num: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(123);
    let params = chrony_rs_core::client::AddSourceParams {
        source_type: chrony_rs_core::cmdmon::AddSourceType::Server,
        name: name.clone(),
        port: port_num,
        minpoll: 6,
        maxpoll: 10,
        presend_minpoll: 0,
        min_stratum: 0,
        poll_target: 8,
        version: 4,
        max_sources: 4,
        min_samples: 4,
        max_samples: 8,
        authkey: 0,
        nts_port: 0,
        max_delay: 0.0,
        max_delay_ratio: 0.0,
        max_delay_dev_ratio: 0.0,
        min_delay: 0.0,
        asymmetry: 1.0,
        offset: 0.0,
        filter_length: 4,
        cert_set: 0,
        max_delay_quant: 0.0,
        connectivity_online: true,
        auto_offline: false,
        iburst: false,
        interleaved: false,
        burst: false,
        nts: false,
        copy: false,
        ext_fields: 0,
        sel_options: 0,
    };
    let body = chrony_rs_core::client::encode_add_source_request(&params)
        .ok_or_else(|| "failed to encode add source request".to_string())?;
    let _ = query_daemon_raw(host, port, cmdmon::REQ_ADD_SOURCE, &body)?;
    Ok(format!("200 OK\nadded source {name}\n"))
}

fn do_delete_source(host: &str, port: u16, args: &[String]) -> Result<String, String> {
    let addr = args
        .first()
        .ok_or_else(|| "usage: deletesource <address>".to_string())?;
    let ip = util::string_to_ip(addr).ok_or_else(|| format!("cannot parse address '{addr}'"))?;
    let body = chrony_rs_core::client::encode_address_request(&ip);
    let _ = query_daemon_raw(host, port, cmdmon::REQ_DEL_SOURCE, &body)?;
    Ok(format!("200 OK\ndeleted source {addr}\n"))
}

fn do_burst(host: &str, port: u16, args: &[String]) -> Result<String, String> {
    let n_good: i32 = args.first().and_then(|s| s.parse().ok()).unwrap_or(2);
    let n_total: i32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let mask_str = args.get(2).map(|s| s.as_str()).unwrap_or("0.0.0.0/0");
    let addr_str = args.get(3).map(|s| s.as_str()).unwrap_or("0.0.0.0");
    let mask = util::string_to_ip(mask_str).unwrap_or(util::IpAddr::Inet4(0));
    let addr = util::string_to_ip(addr_str).unwrap_or(util::IpAddr::Inet4(0));
    let body = chrony_rs_core::client::encode_burst_request(&mask, &addr, n_good, n_total);
    let _ = query_daemon_raw(host, port, cmdmon::REQ_BURST, &body)?;
    Ok(format!("200 OK\nburst {n_good}/{n_total}\n"))
}

fn do_password(host: &str, port: u16, args: &[String]) -> Result<String, String> {
    let pw = args
        .first()
        .ok_or_else(|| "usage: password <passwd>".to_string())?;
    let body = pw.as_bytes();
    let _ = query_daemon_raw(host, port, cmdmon::REQ_LOGON, body)?;
    Ok("200 OK\n".to_string())
}

fn do_makestep(host: &str, port: u16, args: &[String]) -> Result<String, String> {
    if args.is_empty() {
        let _ = query_daemon_raw(host, port, cmdmon::REQ_MAKESTEP, &[])?;
        Ok("200 OK\n".to_string())
    } else {
        let limit: i32 = args[0]
            .parse()
            .map_err(|_| "usage: makestep <limit> <threshold>".to_string())?;
        let threshold: f64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let body = chrony_rs_core::client::encode_modify_makestep_request(limit, threshold);
        let _ = query_daemon_raw(host, port, cmdmon::REQ_MODIFY_MAKESTEP, &body)?;
        Ok(format!("200 OK\nmakestep {limit} {threshold}\n"))
    }
}

fn do_smoothtime(host: &str, port: u16, args: &[String]) -> Result<String, String> {
    let option = match args.first().map(|s| s.as_str()) {
        Some("reset") => 0,
        Some("activate") | None => 1,
        Some(s) => s
            .parse::<i32>()
            .map_err(|_| "usage: smoothtime [reset|activate]".to_string())?,
    };
    let body = chrony_rs_core::client::encode_smoothtime_request(option);
    let _ = query_daemon_raw(host, port, cmdmon::REQ_SMOOTHTIME, &body)?;
    Ok("200 OK\n".to_string())
}

fn do_online_offline(host: &str, port: u16, code: u16, args: &[String]) -> Result<String, String> {
    if args.is_empty() {
        let _ = query_daemon_raw(host, port, code, &[])?;
    } else {
        let addr_str = &args[0];
        let mask_str = args.get(1).map(|s| s.as_str()).unwrap_or("255.255.255.255");
        let addr = util::string_to_ip(addr_str)
            .ok_or_else(|| format!("cannot parse address '{addr_str}'"))?;
        let mask = util::string_to_ip(mask_str)
            .ok_or_else(|| format!("cannot parse mask '{mask_str}'"))?;
        let body = chrony_rs_core::client::encode_mask_address_request(&mask, &addr);
        let _ = query_daemon_raw(host, port, code, &body)?;
    }
    Ok("200 OK\n".to_string())
}

fn do_allow_deny(host: &str, port: u16, code: u16, args: &[String]) -> Result<String, String> {
    let (addr_str, subnet_str) = match args.first() {
        Some(s) if s == "all" => {
            // *ALL variant
            let all_code = match code {
                17 => cmdmon::REQ_ALLOWALL,
                19 => cmdmon::REQ_DENYALL,
                21 => cmdmon::REQ_CMDALLOWALL,
                23 => cmdmon::REQ_CMDDENYALL,
                _ => code,
            };
            let _ = query_daemon_raw(host, port, all_code, &[])?;
            return Ok("200 OK\n".to_string());
        }
        Some(s) => (s.clone(), args.get(1).cloned().unwrap_or_default()),
        None => return Err("usage: allow|deny <address> [subnet_bits]".to_string()),
    };
    let ip = util::string_to_ip(&addr_str)
        .ok_or_else(|| format!("cannot parse address '{addr_str}'"))?;
    let subnet_bits: i32 = if subnet_str.is_empty() {
        if util::string_to_ip(&addr_str).map_or(false, |a| matches!(a, util::IpAddr::Inet4(_))) {
            32
        } else {
            128
        }
    } else {
        subnet_str
            .parse()
            .map_err(|_| format!("invalid subnet bits '{subnet_str}'"))?
    };
    let body = chrony_rs_core::client::encode_allow_deny_request(&ip, subnet_bits);
    let _ = query_daemon_raw(host, port, code, &body)?;
    Ok("200 OK\n".to_string())
}

fn do_accheck(host: &str, port: u16, args: &[String], cmd: bool) -> Result<String, String> {
    let addr_str = args
        .first()
        .ok_or_else(|| "usage: accheck <address>".to_string())?;
    let ip =
        util::string_to_ip(addr_str).ok_or_else(|| format!("cannot parse address '{addr_str}'"))?;
    let code = if cmd {
        cmdmon::REQ_CMDACCHECK
    } else {
        cmdmon::REQ_ACCHECK
    };
    let body = chrony_rs_core::client::encode_address_request(&ip);
    let bytes = query_daemon_raw(host, port, code, &body)?;
    if bytes.len() >= 4 {
        let result = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        Ok(format!(
            "200 OK\n{} access {}\n",
            if cmd { "command" } else { "NTP" },
            if result != 0 { "allowed" } else { "denied" }
        ))
    } else {
        Ok("200 OK\n".to_string())
    }
}

fn send_simple(host: &str, port: u16, code: u16, label: &str) -> Result<String, String> {
    let _ = query_daemon_raw(host, port, code, &[])?;
    Ok(format!("200 OK\n{label} successful\n"))
}

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------

fn query_daemon_raw(host: &str, port: u16, command: u16, body: &[u8]) -> Result<Vec<u8>, String> {
    let addr = format!("{host}:{port}");
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("cannot create socket: {e}"))?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok();

    let seq: u32 = 42;
    let header = build_request_header(command, 0, seq.to_be_bytes(), PROTO_VERSION);
    let mut request = Vec::with_capacity(20 + body.len());
    request.extend_from_slice(&header);
    request.extend_from_slice(body);

    // Pad the request to the expected command length (at least CMD_REPLY_DATA_OFFSET)
    // so the server's validate_request accepts it. Without padding, a 20-byte header-only
    // request fails the read_length < CMD_REPLY_DATA_OFFSET (28) check.
    let expected = chrony_rs_core::pktlength::command_length(PROTO_VERSION as u8, command);
    let min_len = expected.max(chrony_rs_core::cmdmon::CMD_REPLY_DATA_OFFSET as i32) as usize;
    request.resize(min_len.max(request.len()), 0);

    sock.send_to(&request, &addr)
        .map_err(|e| format!("cannot send to {addr}: {e}"))?;

    let mut buf = [0u8; 1024];
    let (n, _src) = sock
        .recv_from(&mut buf)
        .map_err(|e| format!("no reply from {addr}: {e}"))?;

    if n < 28 {
        return Err(format!("short reply ({n} bytes)"));
    }
    let status = u16::from_be_bytes([buf[8], buf[9]]);
    if status != 0 {
        let msg = chrony_rs_core::client::status_message(status);
        return Err(format!("daemon returned status {status}: {msg}"));
    }
    Ok(buf[28..n].to_vec())
}

// ---------------------------------------------------------------------------
// Decode helpers for types without existing decoders
// ---------------------------------------------------------------------------

fn decode_client_access_entry(body: &[u8]) -> ClientAccessReport {
    ClientAccessReport {
        ip_addr: ip_network_to_host(body[0..20].try_into().unwrap()),
        ntp_hits: u32::from_be_bytes(body[20..24].try_into().unwrap()),
        nke_hits: u32::from_be_bytes(body[24..28].try_into().unwrap()),
        cmd_hits: u32::from_be_bytes(body[28..32].try_into().unwrap()),
        ntp_drops: u32::from_be_bytes(body[32..36].try_into().unwrap()),
        nke_drops: u32::from_be_bytes(body[36..40].try_into().unwrap()),
        cmd_drops: u32::from_be_bytes(body[40..44].try_into().unwrap()),
        ntp_interval: body[44] as i8,
        nke_interval: body[45] as i8,
        cmd_interval: body[46] as i8,
        ntp_timeout_interval: body[47] as i8,
        last_ntp_hit_ago: u32::from_be_bytes(body[48..52].try_into().unwrap()),
        last_nke_hit_ago: u32::from_be_bytes(body[52..56].try_into().unwrap()),
        last_cmd_hit_ago: u32::from_be_bytes(body[56..60].try_into().unwrap()),
    }
}

fn decode_manual_list_sample(body: &[u8]) -> ManualSampleReport {
    let (sec, nsec) = timespec_network_to_host(
        u32::from_be_bytes(body[0..4].try_into().unwrap()),
        u32::from_be_bytes(body[4..8].try_into().unwrap()),
        u32::from_be_bytes(body[8..12].try_into().unwrap()),
    );
    ManualSampleReport {
        when_sec: sec,
        when_nsec: nsec,
        slewed_offset: float_network_to_host(u32::from_be_bytes(body[12..16].try_into().unwrap())),
        orig_offset: float_network_to_host(u32::from_be_bytes(body[16..20].try_into().unwrap())),
        residual: float_network_to_host(u32::from_be_bytes(body[20..24].try_into().unwrap())),
    }
}

// ---------------------------------------------------------------------------
// Render helpers (offline JSON rendering)
// ---------------------------------------------------------------------------

const USAGE: &str = "\
chronyc-rs -- chrony-rs control client

USAGE:
    chronyc-rs [-c] [-h <host>] [-p <port>] [-n] [-d] <command> [args...]

COMMANDS:
    tracking          Query daemon tracking
    activity          Query daemon activity
    sources           Query daemon sources
    sourcestats       Query daemon sourcestats
    serverstats       Query daemon server stats
    n_sources         Query number of sources
    ntpdata           Query NTP data for sources
    clients           Query client accesses
    manual            Manual time input (list|delete|on|off|reset)
    rtcdata           Query RTC parameters
    authdata          Query authentication data
    smoothing         Query time smoothing
    selectdata        Query source selection data
    help              Print this help
    version           Print version

  (Action commands)
    reselect          Force source reselection
    settime           Set daemon time
    local             Configure local reference mode
    addserver         Add a new NTP server
    deletesource      Remove a source
    burst             Burst measurements
    online            Set sources online
    offline           Set sources offline
    allow             Allow NTP access
    deny              Deny NTP access
    cmdallow          Allow command access
    cmddeny           Deny command access
    accheck           Check NTP access
    cmdaccheck        Check command access
    rekey             Re-read key file
    reload            Reload sources
    refresh           Refresh DNS
    reset             Reset sources
    smoothtime        Activate or reset smoothing
    makestep          Step clock or configure makestep
    dump              Dump measurement data
    shutdown          Shut down daemon
    writertc          Write RTC file
    trimrtc           Trim RTC
    cyclelogs         Cycle log files
    dns               Trigger DNS re-resolution
    password          Authenticate with daemon

OPTIONS:
    -c               CSV output mode
    -h <host>        Hostname or IP of daemon (default: 127.0.0.1)
    -p <port>        Command port (default: 323)
    -n               No DNS resolution (print IP addresses)
    -d               Debug/verbose output
    -v               Print version";
