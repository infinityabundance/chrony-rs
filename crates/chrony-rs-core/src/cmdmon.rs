//! Command/monitoring protocol (chronyc ↔ chronyd) — a partial port of `cmdmon.c`.
//!
//! `cmdmon.c` is the daemon's control-socket server: it is mostly host-bound (UDP/Unix
//! sockets, rate limiting, and per-command handlers that read live daemon state). This
//! module ports the **pure protocol-framing** core of `read_from_cmd_socket`: the
//! request-validation state machine that decides, from a received packet's header and
//! length, whether to drop it silently or reply with a specific error status before any
//! command is dispatched. It builds on the ported [`crate::pktlength`] length tables.
//!
//! # Oracle
//!
//! Differential-tested against a verbatim copy of `read_from_cmd_socket`'s validation using
//! the **real** `PKL_CommandLength` (`/tmp/ncmd/gencmdval.c`,
//! `research/oracle/cmdmon-validate-c-vectors.txt`). See the tests.

/// chrony `PROTO_VERSION_NUMBER`: the current command-protocol version.
pub const PROTO_VERSION_NUMBER: u8 = 6;
/// chrony `PROTO_VERSION_MISMATCH_COMPAT_SERVER`: the lowest version a server still replies
/// to (with a version-mismatch status) rather than dropping.
pub const PROTO_VERSION_MISMATCH_COMPAT_SERVER: u8 = 5;
/// chrony `PKT_TYPE_CMD_REQUEST` / `PKT_TYPE_CMD_REPLY`.
pub const PKT_TYPE_CMD_REQUEST: u8 = 1;
pub const PKT_TYPE_CMD_REPLY: u8 = 2;
/// chrony `N_REQUEST_TYPES`: the number of defined request commands.
pub const N_REQUEST_TYPES: u16 = 73;
/// chrony `N_REPLY_TYPES`: the number of defined reply types (codes start at 1).
pub const N_REPLY_TYPES: u16 = 26;
/// chrony `MAX_PADDING_LENGTH` (`candm.h`).
pub const MAX_PADDING_LENGTH: i32 = 484;

/// `offsetof(CMD_Request, data)` / `offsetof(CMD_Reply, data)` / `sizeof(CMD_Request)` /
/// `sizeof(CMD_Reply)` for chrony 4.5 (extracted from a compiled `candm.h` probe).
pub const CMD_REQUEST_DATA_OFFSET: usize = 20;
pub const CMD_REPLY_DATA_OFFSET: usize = 28;
pub const CMD_REQUEST_SIZE: usize = 860;
pub const CMD_REPLY_SIZE: usize = 524;

/// Reply status codes (chrony `STT_*`).
pub const STT_SUCCESS: u16 = 0;
pub const STT_INVALID: u16 = 3;
pub const STT_BADPKTVERSION: u16 = 18;
pub const STT_BADPKTLENGTH: u16 = 19;
/// chrony `RPY_NULL`: the reply type stamped before a command sets its own.
pub const RPY_NULL: u16 = 1;

/// Reply type constants — from chrony 4.5 candm.h (NOT REQ_XXX + 1).
pub const RPY_N_SOURCES: u16 = 2;
pub const RPY_SOURCE_DATA: u16 = 3;
pub const RPY_MANUAL_TIMESTAMP: u16 = 4;
pub const RPY_TRACKING: u16 = 5;
pub const RPY_SOURCESTATS: u16 = 6;
pub const RPY_RTC: u16 = 7;
pub const RPY_SUBNETS_ACCESSED: u16 = 8;
pub const RPY_CLIENT_ACCESSES: u16 = 9;
pub const RPY_CLIENT_ACCESSES_BY_INDEX: u16 = 10;
pub const RPY_MANUAL_LIST: u16 = 11;
pub const RPY_ACTIVITY: u16 = 12;
pub const RPY_SMOOTHING: u16 = 13;
pub const RPY_SERVER_STATS: u16 = 14;
pub const RPY_CLIENT_ACCESSES_BY_INDEX2: u16 = 15;
pub const RPY_NTP_DATA: u16 = 16;
pub const RPY_MANUAL_TIMESTAMP2: u16 = 17;
pub const RPY_MANUAL_LIST2: u16 = 18;
pub const RPY_NTP_SOURCE_NAME: u16 = 19;
pub const RPY_AUTH_DATA: u16 = 20;
pub const RPY_CLIENT_ACCESSES_BY_INDEX3: u16 = 21;
pub const RPY_SERVER_STATS2: u16 = 22;
pub const RPY_SELECT_DATA: u16 = 23;
pub const RPY_SERVER_STATS3: u16 = 24;
pub const RPY_SERVER_STATS4: u16 = 25;

/// Command code constants (chrony `REQ_*` from `candm.h`).
pub const REQ_NULL: u16 = 0;
pub const REQ_ONLINE: u16 = 1;
pub const REQ_OFFLINE: u16 = 2;
pub const REQ_BURST: u16 = 3;
pub const REQ_MODIFY_MINPOLL: u16 = 4;
pub const REQ_MODIFY_MAXPOLL: u16 = 5;
pub const REQ_DUMP: u16 = 6;
pub const REQ_MODIFY_MAXDELAY: u16 = 7;
pub const REQ_MODIFY_MAXDELAYRATIO: u16 = 8;
pub const REQ_MODIFY_MAXUPDATESKEW: u16 = 9;
pub const REQ_LOGON: u16 = 10;
pub const REQ_SETTIME: u16 = 11;
pub const REQ_LOCAL: u16 = 12;
pub const REQ_MANUAL: u16 = 13;
pub const REQ_N_SOURCES: u16 = 14;
pub const REQ_SOURCE_DATA: u16 = 15;
pub const REQ_REKEY: u16 = 16;
pub const REQ_ALLOW: u16 = 17;
pub const REQ_ALLOWALL: u16 = 18;
pub const REQ_DENY: u16 = 19;
pub const REQ_DENYALL: u16 = 20;
pub const REQ_CMDALLOW: u16 = 21;
pub const REQ_CMDALLOWALL: u16 = 22;
pub const REQ_CMDDENY: u16 = 23;
pub const REQ_CMDDENYALL: u16 = 24;
pub const REQ_ACCHECK: u16 = 25;
pub const REQ_CMDACCHECK: u16 = 26;
pub const REQ_ADD_SERVER: u16 = 27;
pub const REQ_ADD_PEER: u16 = 28;
pub const REQ_DEL_SOURCE: u16 = 29;
pub const REQ_WRITERTC: u16 = 30;
pub const REQ_DFREQ: u16 = 31;
pub const REQ_DOFFSET: u16 = 32;
pub const REQ_TRACKING: u16 = 33;
pub const REQ_SOURCESTATS: u16 = 34;
pub const REQ_RTCREPORT: u16 = 35;
pub const REQ_TRIMRTC: u16 = 36;
pub const REQ_CYCLELOGS: u16 = 37;
pub const REQ_SUBNETS_ACCESSED: u16 = 38;
pub const REQ_CLIENT_ACCESSES: u16 = 39;
pub const REQ_CLIENT_ACCESSES_BY_INDEX: u16 = 40;
pub const REQ_MANUAL_LIST: u16 = 41;
pub const REQ_MANUAL_DELETE: u16 = 42;
pub const REQ_MAKESTEP: u16 = 43;
pub const REQ_ACTIVITY: u16 = 44;
pub const REQ_MODIFY_MINSTRATUM: u16 = 45;
pub const REQ_MODIFY_POLLTARGET: u16 = 46;
pub const REQ_MODIFY_MAXDELAYDEVRATIO: u16 = 47;
pub const REQ_RESELECT: u16 = 48;
pub const REQ_RESELECTDISTANCE: u16 = 49;
pub const REQ_MODIFY_MAKESTEP: u16 = 50;
pub const REQ_SMOOTHING: u16 = 51;
pub const REQ_SMOOTHTIME: u16 = 52;
pub const REQ_REFRESH: u16 = 53;
pub const REQ_SERVER_STATS: u16 = 54;
pub const REQ_CLIENT_ACCESSES_BY_INDEX2: u16 = 55;
pub const REQ_LOCAL2: u16 = 56;
pub const REQ_NTP_DATA: u16 = 57;
pub const REQ_ADD_SERVER2: u16 = 58;
pub const REQ_ADD_PEER2: u16 = 59;
pub const REQ_ADD_SERVER3: u16 = 60;
pub const REQ_ADD_PEER3: u16 = 61;
pub const REQ_SHUTDOWN: u16 = 62;
pub const REQ_ONOFFLINE: u16 = 63;
pub const REQ_ADD_SOURCE: u16 = 64;
pub const REQ_NTP_SOURCE_NAME: u16 = 65;
pub const REQ_RESET_SOURCES: u16 = 66;
pub const REQ_AUTH_DATA: u16 = 67;
pub const REQ_CLIENT_ACCESSES_BY_INDEX3: u16 = 68;
pub const REQ_SELECT_DATA: u16 = 69;
pub const REQ_RELOAD_SOURCES: u16 = 70;
pub const REQ_DOFFSET2: u16 = 71;
pub const REQ_MODIFY_SELECTOPTS: u16 = 72;

/// The outcome of validating a received command request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CmdValidation {
    /// Drop silently — no reply (malformed length, wrong packet type/reserved fields, or a
    /// version mismatch below the compat-server threshold).
    Drop,
    /// Reply with an error `status` (the reply header is version [`PROTO_VERSION_NUMBER`],
    /// type [`PKT_TYPE_CMD_REPLY`], reply [`RPY_NULL`], with the request's command and
    /// sequence echoed).
    Reply(u16),
    /// A valid request to dispatch; `expected_length` is `PKL_CommandLength`.
    Valid { expected_length: i32 },
}

/// `read_from_cmd_socket`'s pre-dispatch validation: given the received `read_length` and
/// the request header fields (`pkt_type`, the two reserved bytes, `version`, and the
/// host-order `command`), decide the framing outcome. Rate limiting and access logging are
/// host boundaries handled by the caller.
pub fn validate_request(
    read_length: usize,
    pkt_type: u8,
    res1: u8,
    res2: u8,
    version: u8,
    command: u16,
) -> CmdValidation {
    // An error reply must not be larger than the request, and the request must fit. The two
    // separate `< offset` checks mirror chrony's `read_length < offsetof(CMD_Request,data)
    // || read_length < offsetof(CMD_Reply,data)` (the second dominates) — kept verbatim.
    #[allow(clippy::manual_range_contains)]
    if read_length < CMD_REQUEST_DATA_OFFSET
        || read_length < CMD_REPLY_DATA_OFFSET
        || read_length > CMD_REQUEST_SIZE
    {
        return CmdValidation::Drop;
    }
    if pkt_type != PKT_TYPE_CMD_REQUEST || res1 != 0 || res2 != 0 {
        return CmdValidation::Drop;
    }

    let expected = crate::pktlength::command_length(version, command);

    if version != PROTO_VERSION_NUMBER {
        return if version >= PROTO_VERSION_MISMATCH_COMPAT_SERVER {
            CmdValidation::Reply(STT_BADPKTVERSION)
        } else {
            CmdValidation::Drop
        };
    }
    if command >= N_REQUEST_TYPES || expected < CMD_REQUEST_DATA_OFFSET as i32 {
        return CmdValidation::Reply(STT_INVALID);
    }
    if (read_length as i32) < expected {
        return CmdValidation::Reply(STT_BADPKTLENGTH);
    }
    CmdValidation::Valid {
        expected_length: expected,
    }
}

/// chrony `cmdmon.c` `do_size_checks`: the startup invariant that every command's
/// `PKL_CommandLength`/`PKL_CommandPaddingLength` and every reply's `PKL_ReplyLength` stay
/// within the fixed `CMD_Request`/`CMD_Reply` envelope. chrony `assert`s each bound at
/// startup; this returns whether they all hold (a wrong length table would silently corrupt
/// the control protocol). Reproduces the exact bounds over the ported [`crate::pktlength`]
/// tables at [`PROTO_VERSION_NUMBER`] with `STT_SUCCESS` replies.
pub fn do_size_checks() -> bool {
    if CMD_REQUEST_DATA_OFFSET != 20 || CMD_REPLY_DATA_OFFSET != 28 {
        return false;
    }
    for command in 0..N_REQUEST_TYPES {
        let request_length = crate::pktlength::command_length(PROTO_VERSION_NUMBER, command);
        let padding_length =
            crate::pktlength::command_padding_length(PROTO_VERSION_NUMBER, command);
        if padding_length > MAX_PADDING_LENGTH
            || padding_length > request_length
            || request_length > CMD_REQUEST_SIZE as i32
            || (request_length != 0 && request_length < CMD_REQUEST_DATA_OFFSET as i32)
        {
            return false;
        }
    }
    for reply in 1..N_REPLY_TYPES {
        let reply_length = crate::pktlength::reply_length(reply);
        if (reply_length != 0 && reply_length < CMD_REPLY_DATA_OFFSET as i32)
            || reply_length > CMD_REPLY_SIZE as i32
        {
            return false;
        }
    }
    true
}

/// chrony's `RPT_TrackingReport`, the subset `handle_tracking` serializes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TrackingReport {
    pub ref_id: u32,
    pub ip_addr: crate::util::IpAddr,
    pub stratum: u16,
    pub leap_status: u16,
    pub ref_time_sec: i64,
    pub ref_time_nsec: i64,
    pub current_correction: f64,
    pub last_offset: f64,
    pub rms_offset: f64,
    pub freq_ppm: f64,
    pub resid_freq_ppm: f64,
    pub skew_ppm: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub last_update_interval: f64,
}

/// `handle_tracking`'s serialization of a tracking report into the 80-byte `RPY_Tracking`
/// body (chrony 4.5 field offsets). Composes the ported wire encoders — `htonl`/`htons`,
/// [`crate::util::ip_host_to_network`], [`crate::util::timespec_host_to_network`] (the
/// `HAVE_LONG_TIME_T` split), and [`crate::util::float_host_to_network`] (chrony's custom
/// 32-bit wire float). The tracking report itself comes from `REF_GetTrackingReport`, a host
/// boundary supplied by the caller.
pub fn encode_tracking_reply(r: &TrackingReport) -> [u8; 80] {
    use crate::util::{float_host_to_network, ip_host_to_network, timespec_host_to_network};
    let mut b = [0u8; 80];
    b[0..4].copy_from_slice(&r.ref_id.to_be_bytes());
    b[4..24].copy_from_slice(&ip_host_to_network(&r.ip_addr));
    b[24..26].copy_from_slice(&r.stratum.to_be_bytes());
    b[26..28].copy_from_slice(&r.leap_status.to_be_bytes());
    let (high, low, nsec) = timespec_host_to_network(r.ref_time_sec, r.ref_time_nsec);
    b[28..32].copy_from_slice(&high.to_be_bytes());
    b[32..36].copy_from_slice(&low.to_be_bytes());
    b[36..40].copy_from_slice(&nsec.to_be_bytes());
    // The nine Float fields (custom 32-bit wire float, network order = big-endian of the
    // host-order encoded word).
    for (off, x) in [
        (40, r.current_correction),
        (44, r.last_offset),
        (48, r.rms_offset),
        (52, r.freq_ppm),
        (56, r.resid_freq_ppm),
        (60, r.skew_ppm),
        (64, r.root_delay),
        (68, r.root_dispersion),
        (72, r.last_update_interval),
    ] {
        b[off..off + 4].copy_from_slice(&float_host_to_network(x).to_be_bytes());
    }
    b
}

/// chrony's `RPT_SourcestatsReport`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SourcestatsReport {
    pub ref_id: u32,
    pub ip_addr: crate::util::IpAddr,
    pub n_samples: u32,
    pub n_runs: u32,
    pub span_seconds: u32,
    pub resid_freq_ppm: f64,
    pub skew_ppm: f64,
    pub sd: f64,
    pub est_offset: f64,
    pub est_offset_err: f64,
}

/// `handle_sourcestats`'s serialization into the 60-byte `RPY_Sourcestats` body. Note the
/// wire order places `sd` (offset 36) *before* `resid_freq_ppm` (40), unlike the C's
/// assignment order.
pub fn encode_sourcestats_reply(r: &SourcestatsReport) -> [u8; 60] {
    use crate::util::{float_host_to_network, ip_host_to_network};
    let mut b = [0u8; 60];
    b[0..4].copy_from_slice(&r.ref_id.to_be_bytes());
    b[4..24].copy_from_slice(&ip_host_to_network(&r.ip_addr));
    b[24..28].copy_from_slice(&r.n_samples.to_be_bytes());
    b[28..32].copy_from_slice(&r.n_runs.to_be_bytes());
    b[32..36].copy_from_slice(&r.span_seconds.to_be_bytes());
    let flt = |b: &mut [u8; 60], off: usize, x: f64| {
        b[off..off + 4].copy_from_slice(&float_host_to_network(x).to_be_bytes());
    };
    flt(&mut b, 36, r.sd);
    flt(&mut b, 40, r.resid_freq_ppm);
    flt(&mut b, 44, r.skew_ppm);
    flt(&mut b, 48, r.est_offset);
    flt(&mut b, 52, r.est_offset_err);
    b
}

/// chrony's `RPT_SourceReport` selection state — mapped to the wire `RPY_SD_ST_*` codes,
/// which are *not* in the same order (e.g. `Selected` → 0, `Nonselectable` → 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceState {
    Nonselectable,
    Falseticker,
    Jittery,
    Selectable,
    Unselected,
    Selected,
}

impl SourceState {
    /// The wire `RPY_SD_ST_*` code.
    pub fn wire(self) -> u16 {
        match self {
            SourceState::Selected => 0,
            SourceState::Nonselectable => 1,
            SourceState::Falseticker => 2,
            SourceState::Jittery => 3,
            SourceState::Unselected => 4,
            SourceState::Selectable => 5,
        }
    }

    /// The inverse of [`Self::wire`]: the state for a wire `RPY_SD_ST_*` code, or [`None`] for
    /// an unrecognized code.
    pub fn from_wire(code: u16) -> Option<Self> {
        Some(match code {
            0 => SourceState::Selected,
            1 => SourceState::Nonselectable,
            2 => SourceState::Falseticker,
            3 => SourceState::Jittery,
            4 => SourceState::Unselected,
            5 => SourceState::Selectable,
            _ => return None,
        })
    }
}

/// chrony's `RPT_SourceReport` mode — mapped to the wire `RPY_SD_MD_*` codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceMode {
    NtpClient,
    NtpPeer,
    LocalReference,
}

impl SourceMode {
    /// The wire `RPY_SD_MD_*` code.
    pub fn wire(self) -> u16 {
        match self {
            SourceMode::NtpClient => 0,
            SourceMode::NtpPeer => 1,
            SourceMode::LocalReference => 2,
        }
    }

    /// The inverse of [`Self::wire`]: the mode for a wire `RPY_SD_MD_*` code, or [`None`] for an
    /// unrecognized code.
    pub fn from_wire(code: u16) -> Option<Self> {
        Some(match code {
            0 => SourceMode::NtpClient,
            1 => SourceMode::NtpPeer,
            2 => SourceMode::LocalReference,
            _ => return None,
        })
    }
}

/// chrony's `RPT_SourceReport`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SourceDataReport {
    pub ip_addr: crate::util::IpAddr,
    pub poll: i16,
    pub stratum: u16,
    pub state: SourceState,
    pub mode: SourceMode,
    pub reachability: u16,
    pub latest_meas_ago: u32,
    pub orig_latest_meas: f64,
    pub latest_meas: f64,
    pub latest_meas_err: f64,
}

/// `handle_source_data`'s serialization into the 52-byte `RPY_Source_Data` body. `flags` is
/// always 0.
pub fn encode_source_data_reply(r: &SourceDataReport) -> [u8; 52] {
    use crate::util::{float_host_to_network, ip_host_to_network};
    let mut b = [0u8; 52];
    b[0..20].copy_from_slice(&ip_host_to_network(&r.ip_addr));
    b[20..22].copy_from_slice(&r.poll.to_be_bytes());
    b[22..24].copy_from_slice(&r.stratum.to_be_bytes());
    b[24..26].copy_from_slice(&r.state.wire().to_be_bytes());
    b[26..28].copy_from_slice(&r.mode.wire().to_be_bytes());
    b[28..30].copy_from_slice(&0u16.to_be_bytes()); // flags
    b[30..32].copy_from_slice(&r.reachability.to_be_bytes());
    b[32..36].copy_from_slice(&r.latest_meas_ago.to_be_bytes());
    b[36..40].copy_from_slice(&float_host_to_network(r.orig_latest_meas).to_be_bytes());
    b[40..44].copy_from_slice(&float_host_to_network(r.latest_meas).to_be_bytes());
    b[44..48].copy_from_slice(&float_host_to_network(r.latest_meas_err).to_be_bytes());
    b
}

/// chrony's `RPT_ActivityReport`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivityReport {
    pub online: u32,
    pub offline: u32,
    pub burst_online: u32,
    pub burst_offline: u32,
    pub unresolved: u32,
}

/// `handle_activity`'s serialization into the 24-byte `RPY_Activity` body (five `htonl`
/// counters).
pub fn encode_activity_reply(r: &ActivityReport) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0..4].copy_from_slice(&r.online.to_be_bytes());
    b[4..8].copy_from_slice(&r.offline.to_be_bytes());
    b[8..12].copy_from_slice(&r.burst_online.to_be_bytes());
    b[12..16].copy_from_slice(&r.burst_offline.to_be_bytes());
    b[16..20].copy_from_slice(&r.unresolved.to_be_bytes());
    b
}

/// chrony's `RPT_ServerStatsReport` — seventeen 64-bit counters, in wire order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerStatsReport {
    pub counters: [u64; 17],
}

/// `handle_server_stats`'s serialization into the 172-byte `RPY_ServerStats` body: the
/// seventeen counters as chrony wire `Integer64`s ([`crate::util::integer64_host_to_network`]),
/// then 36 reserved `0xff` bytes.
pub fn encode_server_stats_reply(r: &ServerStatsReport) -> [u8; 172] {
    let mut b = [0u8; 172];
    for (i, &v) in r.counters.iter().enumerate() {
        let (high, low) = crate::util::integer64_host_to_network(v);
        b[i * 8..i * 8 + 4].copy_from_slice(&high.to_be_bytes());
        b[i * 8 + 4..i * 8 + 8].copy_from_slice(&low.to_be_bytes());
    }
    // reserved is 32 bytes @136..168 (chrony memsets sizeof(reserved)); 168..172 is trailing
    // struct padding, left zero.
    b[136..168].fill(0xff);
    b
}

/// chrony `RPY_NTP_FLAGS_TESTS` / `RPY_NTP_FLAG_INTERLEAVED` / `RPY_NTP_FLAG_AUTHENTICATED`.
const RPY_NTP_FLAGS_TESTS: u16 = 0x3ff;
const RPY_NTP_FLAG_INTERLEAVED: u16 = 0x4000;
const RPY_NTP_FLAG_AUTHENTICATED: u16 = 0x8000;

/// `handle_ntp_data`'s serialization into the 128-byte `RPY_NTPData` body. Reuses the
/// [`crate::ntp::ntp_report::NtpReport`] (the ntpdata report already ported in `ntp_core`),
/// plus the `remote_addr`/`remote_port` set at instance-creation time (supplied here). The
/// `flags` field packs the low-10 test bits with the interleaved/authenticated flags.
pub fn encode_ntp_data_reply(
    report: &crate::ntp::ntp_report::NtpReport,
    remote_addr: &crate::util::IpAddr,
    remote_port: u16,
) -> [u8; 128] {
    use crate::util::{float_host_to_network, ip_host_to_network, timespec_host_to_network};
    let mut b = [0u8; 128];
    b[0..20].copy_from_slice(&ip_host_to_network(remote_addr));
    b[20..40].copy_from_slice(&ip_host_to_network(&report.local_addr));
    b[40..42].copy_from_slice(&remote_port.to_be_bytes());
    b[42] = report.leap;
    b[43] = report.version;
    b[44] = report.mode;
    b[45] = report.stratum;
    b[46] = report.poll as u8;
    b[47] = report.precision as u8;
    b[48..52].copy_from_slice(&float_host_to_network(report.root_delay).to_be_bytes());
    b[52..56].copy_from_slice(&float_host_to_network(report.root_dispersion).to_be_bytes());
    b[56..60].copy_from_slice(&report.ref_id.to_be_bytes());
    let (high, low, nsec) =
        timespec_host_to_network(report.ref_time.tv_sec, report.ref_time.tv_nsec);
    b[60..64].copy_from_slice(&high.to_be_bytes());
    b[64..68].copy_from_slice(&low.to_be_bytes());
    b[68..72].copy_from_slice(&nsec.to_be_bytes());
    b[72..76].copy_from_slice(&float_host_to_network(report.offset).to_be_bytes());
    b[76..80].copy_from_slice(&float_host_to_network(report.peer_delay).to_be_bytes());
    b[80..84].copy_from_slice(&float_host_to_network(report.peer_dispersion).to_be_bytes());
    b[84..88].copy_from_slice(&float_host_to_network(report.response_time).to_be_bytes());
    b[88..92].copy_from_slice(&float_host_to_network(report.jitter_asymmetry).to_be_bytes());
    let flags = (report.tests & RPY_NTP_FLAGS_TESTS)
        | if report.interleaved {
            RPY_NTP_FLAG_INTERLEAVED
        } else {
            0
        }
        | if report.authenticated {
            RPY_NTP_FLAG_AUTHENTICATED
        } else {
            0
        };
    b[92..94].copy_from_slice(&flags.to_be_bytes());
    b[94] = report.tx_tss_char as u8;
    b[95] = report.rx_tss_char as u8;
    b[96..100].copy_from_slice(&report.total_tx_count.to_be_bytes());
    b[100..104].copy_from_slice(&report.total_rx_count.to_be_bytes());
    b[104..108].copy_from_slice(&report.total_valid_count.to_be_bytes());
    b[108..112].copy_from_slice(&report.total_good_count.to_be_bytes());
    b[112..124].fill(0xff); // reserved is 12 bytes; 124..128 is trailing padding, left zero
    b
}

/// chrony's `RPT_RTC_Report`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RtcReport {
    pub ref_time_sec: i64,
    pub ref_time_nsec: i64,
    pub n_samples: u16,
    pub n_runs: u16,
    pub span_seconds: u32,
    pub rtc_seconds_fast: f64,
    pub rtc_gain_rate_ppm: f64,
}

/// `handle_rtcreport`'s serialization into the 32-byte `RPY_Rtc` body.
pub fn encode_rtc_reply(r: &RtcReport) -> [u8; 32] {
    use crate::util::{float_host_to_network, timespec_host_to_network};
    let mut b = [0u8; 32];
    let (high, low, nsec) = timespec_host_to_network(r.ref_time_sec, r.ref_time_nsec);
    b[0..4].copy_from_slice(&high.to_be_bytes());
    b[4..8].copy_from_slice(&low.to_be_bytes());
    b[8..12].copy_from_slice(&nsec.to_be_bytes());
    b[12..14].copy_from_slice(&r.n_samples.to_be_bytes());
    b[14..16].copy_from_slice(&r.n_runs.to_be_bytes());
    b[16..20].copy_from_slice(&r.span_seconds.to_be_bytes());
    b[20..24].copy_from_slice(&float_host_to_network(r.rtc_seconds_fast).to_be_bytes());
    b[24..28].copy_from_slice(&float_host_to_network(r.rtc_gain_rate_ppm).to_be_bytes());
    b
}

/// chrony `RPY_SMT_FLAG_ACTIVE` / `RPY_SMT_FLAG_LEAPONLY`.
const RPY_SMT_FLAG_ACTIVE: u32 = 0x1;
const RPY_SMT_FLAG_LEAPONLY: u32 = 0x2;

/// chrony's `RPT_SmoothingReport`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SmoothingReport {
    pub active: bool,
    pub leap_only: bool,
    pub offset: f64,
    pub freq_ppm: f64,
    pub wander_ppm: f64,
    pub last_update_ago: f64,
    pub remaining_time: f64,
}

/// `handle_smoothing`'s serialization into the 28-byte `RPY_Smoothing` body: an
/// active/leap-only flags word (`htonl`) then five Floats.
pub fn encode_smoothing_reply(r: &SmoothingReport) -> [u8; 28] {
    use crate::util::float_host_to_network;
    let mut b = [0u8; 28];
    let flags = if r.active { RPY_SMT_FLAG_ACTIVE } else { 0 }
        | if r.leap_only {
            RPY_SMT_FLAG_LEAPONLY
        } else {
            0
        };
    b[0..4].copy_from_slice(&flags.to_be_bytes());
    b[4..8].copy_from_slice(&float_host_to_network(r.offset).to_be_bytes());
    b[8..12].copy_from_slice(&float_host_to_network(r.freq_ppm).to_be_bytes());
    b[12..16].copy_from_slice(&float_host_to_network(r.wander_ppm).to_be_bytes());
    b[16..20].copy_from_slice(&float_host_to_network(r.last_update_ago).to_be_bytes());
    b[20..24].copy_from_slice(&float_host_to_network(r.remaining_time).to_be_bytes());
    b
}

/// chrony's `NTP_AUTH` mode of a source, mapped to the wire `RPY_AD_MD_*` codes (which
/// share the same values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMode {
    None,
    Symmetric,
    Nts,
}

impl AuthMode {
    /// The wire `RPY_AD_MD_*` code.
    pub fn wire(self) -> u16 {
        match self {
            AuthMode::None => 0,
            AuthMode::Symmetric => 1,
            AuthMode::Nts => 2,
        }
    }

    /// The inverse of [`Self::wire`]: the mode for a wire `RPY_AD_MD_*` code, or [`None`] for an
    /// unrecognized code.
    pub fn from_wire(code: u16) -> Option<Self> {
        Some(match code {
            0 => AuthMode::None,
            1 => AuthMode::Symmetric,
            2 => AuthMode::Nts,
            _ => return None,
        })
    }
}

/// chrony's `RPT_AuthReport`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthReport {
    pub mode: AuthMode,
    pub key_type: u16,
    pub key_id: u32,
    pub key_length: u16,
    pub ke_attempts: u16,
    pub last_ke_ago: u32,
    pub cookies: u16,
    pub cookie_length: u16,
    pub nak: u16,
}

/// `handle_auth_data`'s serialization into the 28-byte `RPY_AuthData` body.
pub fn encode_auth_data_reply(r: &AuthReport) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..2].copy_from_slice(&r.mode.wire().to_be_bytes());
    b[2..4].copy_from_slice(&r.key_type.to_be_bytes());
    b[4..8].copy_from_slice(&r.key_id.to_be_bytes());
    b[8..10].copy_from_slice(&r.key_length.to_be_bytes());
    b[10..12].copy_from_slice(&r.ke_attempts.to_be_bytes());
    b[12..16].copy_from_slice(&r.last_ke_ago.to_be_bytes());
    b[16..18].copy_from_slice(&r.cookies.to_be_bytes());
    b[18..20].copy_from_slice(&r.cookie_length.to_be_bytes());
    b[20..22].copy_from_slice(&r.nak.to_be_bytes());
    b
}

/// `convert_sd_sel_options`: map a `SRC_SELECT_*` option bitmask to the wire
/// `RPY_SD_OPTION_*` bitmask (bit values coincide, but the mapping is explicit as in chrony).
pub fn convert_sd_sel_options(options: i32) -> u16 {
    let mut r = 0u16;
    if options & 0x2 != 0 {
        r |= 0x2;
    } // SRC_SELECT_PREFER -> RPY_SD_OPTION_PREFER
    if options & 0x1 != 0 {
        r |= 0x1;
    } // SRC_SELECT_NOSELECT -> RPY_SD_OPTION_NOSELECT
    if options & 0x4 != 0 {
        r |= 0x4;
    } // SRC_SELECT_TRUST -> RPY_SD_OPTION_TRUST
    if options & 0x8 != 0 {
        r |= 0x8;
    } // SRC_SELECT_REQUIRE -> RPY_SD_OPTION_REQUIRE
    r
}

/// chrony's `RPT_SelectReport`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SelectReport {
    pub ref_id: u32,
    pub ip_addr: crate::util::IpAddr,
    pub state_char: char,
    pub authentication: u8,
    pub leap: u8,
    pub conf_options: i32,
    pub eff_options: i32,
    pub last_sample_ago: u32,
    pub score: f64,
    pub lo_limit: f64,
    pub hi_limit: f64,
}

/// `handle_select_data`'s serialization into the 52-byte `RPY_SelectData` body. The wire
/// order places `lo_limit` (offset 40) before `hi_limit` (44), unlike the C's assignment
/// order.
pub fn encode_select_data_reply(r: &SelectReport) -> [u8; 52] {
    use crate::util::{float_host_to_network, ip_host_to_network};
    let mut b = [0u8; 52];
    b[0..4].copy_from_slice(&r.ref_id.to_be_bytes());
    b[4..24].copy_from_slice(&ip_host_to_network(&r.ip_addr));
    b[24] = r.state_char as u8;
    b[25] = r.authentication;
    b[26] = r.leap;
    b[28..30].copy_from_slice(&convert_sd_sel_options(r.conf_options).to_be_bytes());
    b[30..32].copy_from_slice(&convert_sd_sel_options(r.eff_options).to_be_bytes());
    b[32..36].copy_from_slice(&r.last_sample_ago.to_be_bytes());
    b[36..40].copy_from_slice(&float_host_to_network(r.score).to_be_bytes());
    b[40..44].copy_from_slice(&float_host_to_network(r.lo_limit).to_be_bytes());
    b[44..48].copy_from_slice(&float_host_to_network(r.hi_limit).to_be_bytes());
    b
}

/// `handle_modify_{minpoll,maxpoll,minstratum,polltarget}`'s request decode: the source
/// address (`UTI_IPNetworkToHost`) and the new integer value (`ntohl`). The 28-byte
/// `REQ_Modify_*` body places the address at offset 0 and the value at 20. The decoded
/// `(address, value)` is fed to the ported `NCR_Modify*` / `NSR_Modify*`.
pub fn decode_modify_source_int(body: &[u8]) -> (crate::util::IpAddr, i32) {
    let addr = crate::util::ip_network_to_host(body[0..20].try_into().unwrap());
    let value = i32::from_be_bytes(body[20..24].try_into().unwrap());
    (addr, value)
}

/// `handle_modify_{maxdelay,maxdelayratio,maxdelaydevratio}`'s request decode: the source
/// address and the new float value (`UTI_FloatNetworkToHost`).
pub fn decode_modify_source_float(body: &[u8]) -> (crate::util::IpAddr, f64) {
    let addr = crate::util::ip_network_to_host(body[0..20].try_into().unwrap());
    let value =
        crate::util::float_network_to_host(u32::from_be_bytes(body[20..24].try_into().unwrap()));
    (addr, value)
}

/// `handle_local`'s request decode: the `REQ_Local` body — `on_off`/`stratum`/`orphan`
/// (`ntohl`) and `distance` ([`crate::util::float_network_to_host`]). A non-zero `on_off`
/// enables local reference (`REF_EnableLocal(stratum, distance, orphan)`); zero disables it.
/// Fields are at offsets 0/4/8/12.
pub fn decode_local(body: &[u8]) -> (i32, i32, f64, i32) {
    let on_off = i32::from_be_bytes(body[0..4].try_into().unwrap());
    let stratum = i32::from_be_bytes(body[4..8].try_into().unwrap());
    let distance =
        crate::util::float_network_to_host(u32::from_be_bytes(body[8..12].try_into().unwrap()));
    let orphan = i32::from_be_bytes(body[12..16].try_into().unwrap());
    (on_off, stratum, distance, orphan)
}

/// `handle_allowdeny`/`handle_cmdallowdeny`'s request decode: the `REQ_Allow_Deny` body — the
/// 20-byte wire address ([`crate::util::ip_network_to_host`]) at offset 0 and `subnet_bits`
/// (`ntohl`) at offset 20. The decoded `(ip, subnet_bits)` feeds `NCR_AddAccessRestriction` /
/// `CAM_AddAccessRestriction`.
pub fn decode_allow_deny(body: &[u8]) -> (crate::util::IpAddr, i32) {
    let ip = crate::util::ip_network_to_host(body[0..20].try_into().unwrap());
    let subnet_bits = i32::from_be_bytes(body[20..24].try_into().unwrap());
    (ip, subnet_bits)
}

/// Decode a request whose body is a single 20-byte wire address at offset 0 — the shape shared
/// by `handle_accheck`/`handle_cmdaccheck` (`REQ_Ac_Check`) and `handle_del_source`
/// (`REQ_Del_Source`).
pub fn decode_address_request(body: &[u8]) -> crate::util::IpAddr {
    crate::util::ip_network_to_host(body[0..20].try_into().unwrap())
}

/// Decode a request whose body is a single wire `Float` at offset 0 — the shape shared by
/// `handle_dfreq` (`REQ_Dfreq`) and `handle_doffset` (`REQ_Doffset`).
pub fn decode_float_request(body: &[u8]) -> f64 {
    crate::util::float_network_to_host(u32::from_be_bytes(body[0..4].try_into().unwrap()))
}

/// `handle_manual_delete`'s request decode: the sample `index` (`ntohl`) at offset 0.
pub fn decode_manual_delete(body: &[u8]) -> i32 {
    i32::from_be_bytes(body[0..4].try_into().unwrap())
}

/// `handle_online`/`handle_offline`'s request decode: the `REQ_Online`/`REQ_Offline` body — a
/// 20-byte wire `mask` at offset 0 and a 20-byte wire `address` at offset 20. The decoded
/// `(mask, address)` selects which sources `NSR_SetConnectivity` moves online/offline.
pub fn decode_mask_address_request(body: &[u8]) -> (crate::util::IpAddr, crate::util::IpAddr) {
    let mask = crate::util::ip_network_to_host(body[0..20].try_into().unwrap());
    let address = crate::util::ip_network_to_host(body[20..40].try_into().unwrap());
    (mask, address)
}

/// `handle_burst`'s request decode: the `REQ_Burst` body — `mask`@0 and `address`@20 (20-byte
/// wire addresses), then `n_good_samples`@40 and `n_total_samples`@44 (`ntohl`).
pub fn decode_burst_request(body: &[u8]) -> (crate::util::IpAddr, crate::util::IpAddr, i32, i32) {
    let mask = crate::util::ip_network_to_host(body[0..20].try_into().unwrap());
    let address = crate::util::ip_network_to_host(body[20..40].try_into().unwrap());
    let n_good = i32::from_be_bytes(body[40..44].try_into().unwrap());
    let n_total = i32::from_be_bytes(body[44..48].try_into().unwrap());
    (mask, address, n_good, n_total)
}

/// `handle_modify_makestep`'s request decode: the `REQ_Modify_Makestep` body — `limit`@0
/// (`ntohl`) and `threshold`@4 ([`crate::util::float_network_to_host`]).
pub fn decode_modify_makestep_request(body: &[u8]) -> (i32, f64) {
    let limit = i32::from_be_bytes(body[0..4].try_into().unwrap());
    let threshold =
        crate::util::float_network_to_host(u32::from_be_bytes(body[4..8].try_into().unwrap()));
    (limit, threshold)
}

/// `handle_reselect_distance`'s request decode: the `REQ_ReselectDistance` body — a single wire
/// `Float` `distance` at offset 0.
pub fn decode_reselect_distance_request(body: &[u8]) -> f64 {
    crate::util::float_network_to_host(u32::from_be_bytes(body[0..4].try_into().unwrap()))
}

/// `handle_smoothtime`'s request decode: the `REQ_SmoothTime` body — the `option`
/// (`REQ_SMOOTHTIME_RESET=0` / `REQ_SMOOTHTIME_ACTIVATE=1`, `ntohl`) at offset 0.
pub fn decode_smoothtime_request(body: &[u8]) -> i32 {
    i32::from_be_bytes(body[0..4].try_into().unwrap())
}

/// `handle_modify_selectopts`'s request decode: the `REQ_Modify_SelectOpts` body — `address`@0
/// (20-byte wire), `ref_id`@20 (`ntohl`), `mask`@24 (`ntohl`, raw `SRC_SELECT_*` bits), and
/// `options`@28 (`ntohl` then `convert_addsrc_select_options` back to `SRC_SELECT_*` bits). The
/// decoded values feed `SRC_ModifySelectOptions`.
pub fn decode_modify_selectopts_request(body: &[u8]) -> (crate::util::IpAddr, u32, i32, i32) {
    let address = crate::util::ip_network_to_host(body[0..20].try_into().unwrap());
    let ref_id = u32::from_be_bytes(body[20..24].try_into().unwrap());
    let mask = i32::from_be_bytes(body[24..28].try_into().unwrap());
    let options =
        convert_addsrc_select_options(u32::from_be_bytes(body[28..32].try_into().unwrap()));
    (address, ref_id, mask, options)
}

/// `handle_settime`'s request decode: the `REQ_Settime` body's wire `Timespec`
/// ([`crate::util::timespec_network_to_host`]) at offset 0, yielding `(tv_sec, tv_nsec)`.
pub fn decode_settime(body: &[u8]) -> (i64, i64) {
    let high = u32::from_be_bytes(body[0..4].try_into().unwrap());
    let low = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let nsec = u32::from_be_bytes(body[8..12].try_into().unwrap());
    crate::util::timespec_network_to_host(high, low, nsec)
}

/// The three `handle_manual` options; an out-of-range option is [`None`] and maps to
/// [`STT_INVALID`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManualOption {
    Disable,
    Enable,
    Reset,
}

/// `handle_manual`'s option validation: `option` 0/1/2 select disable/enable/reset; anything
/// else is invalid.
pub fn decode_manual_option(option: i32) -> Option<ManualOption> {
    match option {
        0 => Some(ManualOption::Disable),
        1 => Some(ManualOption::Enable),
        2 => Some(ManualOption::Reset),
        _ => None,
    }
}

/// chrony `REQ_ADDSRC_*` source-type codes.
pub const REQ_ADDSRC_SERVER: u32 = 1;
pub const REQ_ADDSRC_PEER: u32 = 2;
pub const REQ_ADDSRC_POOL: u32 = 3;

/// chrony `REQ_ADDSRC_*` flag bits (`add source`/`add peer`/`add pool` request flags).
pub const REQ_ADDSRC_ONLINE: u32 = 0x1;
pub const REQ_ADDSRC_AUTOOFFLINE: u32 = 0x2;
pub const REQ_ADDSRC_IBURST: u32 = 0x4;
pub const REQ_ADDSRC_PREFER: u32 = 0x8;
pub const REQ_ADDSRC_NOSELECT: u32 = 0x10;
pub const REQ_ADDSRC_TRUST: u32 = 0x20;
pub const REQ_ADDSRC_REQUIRE: u32 = 0x40;
pub const REQ_ADDSRC_INTERLEAVED: u32 = 0x80;
pub const REQ_ADDSRC_BURST: u32 = 0x100;
pub const REQ_ADDSRC_NTS: u32 = 0x200;
pub const REQ_ADDSRC_COPY: u32 = 0x400;
pub const REQ_ADDSRC_EF_EXP_MONO_ROOT: u32 = 0x800;
pub const REQ_ADDSRC_EF_EXP_NET_CORRECTION: u32 = 0x1000;

/// `convert_addsrc_select_options`: map the `REQ_ADDSRC_*` prefer/noselect/trust/require flag
/// bits to a `SRC_SELECT_*` option bitmask (`NOSELECT=0x1`, `PREFER=0x2`, `TRUST=0x4`,
/// `REQUIRE=0x8`). Kept in chrony's explicit-mapping form even though only the bit positions
/// differ.
pub fn convert_addsrc_select_options(flags: u32) -> i32 {
    let mut r = 0i32;
    if flags & REQ_ADDSRC_PREFER != 0 {
        r |= 0x2;
    }
    if flags & REQ_ADDSRC_NOSELECT != 0 {
        r |= 0x1;
    }
    if flags & REQ_ADDSRC_TRUST != 0 {
        r |= 0x4;
    }
    if flags & REQ_ADDSRC_REQUIRE != 0 {
        r |= 0x8;
    }
    r
}

/// The decoded `handle_add_source` request: the source type/name/port plus the full
/// `SourceParameters` set and the derived boolean flags. The name is the NUL-terminated string
/// from the 256-byte `name` field; a name not terminated within that field is an error
/// ([`None`], mapping to `STT_INVALIDNAME`), as is an unrecognized `type` (mapping to
/// [`STT_INVALID`], surfaced here as [`AddSourceType`] being absent).
#[derive(Clone, Debug, PartialEq)]
pub struct AddSourceRequest {
    /// `NTP_SERVER`/`NTP_PEER` with the `pool` flag folded in via [`AddSourceType`].
    pub source_type: AddSourceType,
    pub name: String,
    pub port: u32,
    pub minpoll: i32,
    pub maxpoll: i32,
    pub presend_minpoll: i32,
    pub min_stratum: u32,
    pub poll_target: u32,
    pub version: u32,
    pub max_sources: u32,
    pub min_samples: i32,
    pub max_samples: i32,
    pub authkey: u32,
    pub nts_port: u32,
    pub max_delay: f64,
    pub max_delay_ratio: f64,
    pub max_delay_dev_ratio: f64,
    pub min_delay: f64,
    pub asymmetry: f64,
    pub offset: f64,
    pub filter_length: i32,
    pub cert_set: u32,
    pub max_delay_quant: f64,
    pub flags: u32,
    pub connectivity_online: bool,
    pub auto_offline: bool,
    pub iburst: bool,
    pub interleaved: bool,
    pub burst: bool,
    pub nts: bool,
    pub copy: bool,
    pub ext_fields: u32,
    pub sel_options: i32,
}

/// The source flavor selected by `REQ_ADDSRC_{SERVER,PEER,POOL}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddSourceType {
    Server,
    Peer,
    Pool,
}

/// chrony `NTP_EF_FLAG_*` external-field flags, mapped from the corresponding `REQ_ADDSRC_EF_*`
/// request flags.
const NTP_EF_FLAG_EXP_MONO_ROOT: u32 = 0x2;
const NTP_EF_FLAG_EXP_NET_CORRECTION: u32 = 0x4;

const REQ_NTP_SOURCE_NAME_LEN: usize = 256;

/// `handle_add_source`'s request decode: the 356-byte `REQ_NTP_Source` body. Returns [`None`]
/// for an unrecognized type or an unterminated name (chrony replies `STT_INVALID` /
/// `STT_INVALIDNAME` respectively). The decoded request feeds `NSR_AddSourceByName`.
pub fn decode_add_source(body: &[u8]) -> Option<AddSourceRequest> {
    let u32_at = |o: usize| u32::from_be_bytes(body[o..o + 4].try_into().unwrap());
    let i32_at = |o: usize| i32::from_be_bytes(body[o..o + 4].try_into().unwrap());
    let flt_at = |o: usize| crate::util::float_network_to_host(u32_at(o));

    let source_type = match u32_at(0) {
        REQ_ADDSRC_SERVER => AddSourceType::Server,
        REQ_ADDSRC_PEER => AddSourceType::Peer,
        REQ_ADDSRC_POOL => AddSourceType::Pool,
        _ => return None,
    };

    // The name field must be NUL-terminated within its 256 bytes (chrony checks the final byte).
    let name_field = &body[4..4 + REQ_NTP_SOURCE_NAME_LEN];
    if name_field[REQ_NTP_SOURCE_NAME_LEN - 1] != 0 {
        return None;
    }
    let nul = name_field.iter().position(|&c| c == 0).unwrap();
    let name = String::from_utf8_lossy(&name_field[..nul]).into_owned();

    let flags = u32_at(332);
    let ext_fields = if flags & REQ_ADDSRC_EF_EXP_MONO_ROOT != 0 {
        NTP_EF_FLAG_EXP_MONO_ROOT
    } else {
        0
    } | if flags & REQ_ADDSRC_EF_EXP_NET_CORRECTION != 0 {
        NTP_EF_FLAG_EXP_NET_CORRECTION
    } else {
        0
    };

    Some(AddSourceRequest {
        source_type,
        name,
        port: u32_at(260),
        minpoll: i32_at(264),
        maxpoll: i32_at(268),
        presend_minpoll: i32_at(272),
        min_stratum: u32_at(276),
        poll_target: u32_at(280),
        version: u32_at(284),
        max_sources: u32_at(288),
        min_samples: i32_at(292),
        max_samples: i32_at(296),
        authkey: u32_at(300),
        nts_port: u32_at(304),
        max_delay: flt_at(308),
        max_delay_ratio: flt_at(312),
        max_delay_dev_ratio: flt_at(316),
        min_delay: flt_at(320),
        asymmetry: flt_at(324),
        offset: flt_at(328),
        flags,
        filter_length: i32_at(336),
        cert_set: u32_at(340),
        max_delay_quant: flt_at(344),
        connectivity_online: flags & REQ_ADDSRC_ONLINE != 0,
        auto_offline: flags & REQ_ADDSRC_AUTOOFFLINE != 0,
        iburst: flags & REQ_ADDSRC_IBURST != 0,
        interleaved: flags & REQ_ADDSRC_INTERLEAVED != 0,
        burst: flags & REQ_ADDSRC_BURST != 0,
        nts: flags & REQ_ADDSRC_NTS != 0,
        copy: flags & REQ_ADDSRC_COPY != 0,
        ext_fields,
        sel_options: convert_addsrc_select_options(flags),
    })
}

/// `handle_settime`'s reply serialization into the 12-byte `RPY_ManualTimestamp` body (offset,
/// dfreq_ppm, new_afreq_ppm — three Floats). The measured values come from `MNL_AcceptTimestamp`,
/// a host boundary supplied by the caller.
pub fn encode_manual_timestamp(offset: f64, dfreq_ppm: f64, new_afreq_ppm: f64) -> [u8; 12] {
    use crate::util::float_host_to_network;
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&float_host_to_network(offset).to_be_bytes());
    b[4..8].copy_from_slice(&float_host_to_network(dfreq_ppm).to_be_bytes());
    b[8..12].copy_from_slice(&float_host_to_network(new_afreq_ppm).to_be_bytes());
    b
}

/// chrony's `RPT_ClientAccessByIndex_Report`, the per-client row `handle_client_accesses_by_index`
/// serializes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAccessReport {
    pub ip_addr: crate::util::IpAddr,
    pub ntp_hits: u32,
    pub nke_hits: u32,
    pub cmd_hits: u32,
    pub ntp_drops: u32,
    pub nke_drops: u32,
    pub cmd_drops: u32,
    pub ntp_interval: i8,
    pub nke_interval: i8,
    pub cmd_interval: i8,
    pub ntp_timeout_interval: i8,
    pub last_ntp_hit_ago: u32,
    pub last_nke_hit_ago: u32,
    pub last_cmd_hit_ago: u32,
}

/// `handle_client_accesses_by_index`'s serialization of one client row into the 60-byte
/// `RPY_ClientAccesses_Client` body. The four `*_interval` fields are raw signed bytes (log2
/// intervals), copied without byte-swapping; every other counter is `htonl`.
pub fn encode_client_access_entry(r: &ClientAccessReport) -> [u8; 60] {
    use crate::util::ip_host_to_network;
    let mut b = [0u8; 60];
    b[0..20].copy_from_slice(&ip_host_to_network(&r.ip_addr));
    b[20..24].copy_from_slice(&r.ntp_hits.to_be_bytes());
    b[24..28].copy_from_slice(&r.nke_hits.to_be_bytes());
    b[28..32].copy_from_slice(&r.cmd_hits.to_be_bytes());
    b[32..36].copy_from_slice(&r.ntp_drops.to_be_bytes());
    b[36..40].copy_from_slice(&r.nke_drops.to_be_bytes());
    b[40..44].copy_from_slice(&r.cmd_drops.to_be_bytes());
    b[44] = r.ntp_interval as u8;
    b[45] = r.nke_interval as u8;
    b[46] = r.cmd_interval as u8;
    b[47] = r.ntp_timeout_interval as u8;
    b[48..52].copy_from_slice(&r.last_ntp_hit_ago.to_be_bytes());
    b[52..56].copy_from_slice(&r.last_nke_hit_ago.to_be_bytes());
    b[56..60].copy_from_slice(&r.last_cmd_hit_ago.to_be_bytes());
    b
}

/// chrony's `RPT_ManualSamplesReport`, one row of the `manual list` reply.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ManualSampleReport {
    pub when_sec: i64,
    pub when_nsec: i64,
    pub slewed_offset: f64,
    pub orig_offset: f64,
    pub residual: f64,
}

/// `handle_manual_list`'s serialization of one sample into the 24-byte `RPY_ManualListSample`
/// body: the wire `Timespec` then three Floats.
pub fn encode_manual_list_sample(r: &ManualSampleReport) -> [u8; 24] {
    use crate::util::{float_host_to_network, timespec_host_to_network};
    let mut b = [0u8; 24];
    let (high, low, nsec) = timespec_host_to_network(r.when_sec, r.when_nsec);
    b[0..4].copy_from_slice(&high.to_be_bytes());
    b[4..8].copy_from_slice(&low.to_be_bytes());
    b[8..12].copy_from_slice(&nsec.to_be_bytes());
    b[12..16].copy_from_slice(&float_host_to_network(r.slewed_offset).to_be_bytes());
    b[16..20].copy_from_slice(&float_host_to_network(r.orig_offset).to_be_bytes());
    b[20..24].copy_from_slice(&float_host_to_network(r.residual).to_be_bytes());
    b
}

/// `offsetof(CMD_Reply, ...)` field offsets in the 28-byte reply header (chrony 4.5, from a
/// compiled `candm.h` probe): version@0, pkt_type@1, res1@2, res2@3, command@4, reply@6,
/// status@8, pad1@10, pad2@12, pad3@14, sequence@16, pad4@20, pad5@24, data@28.
const RPY_OFF_VERSION: usize = 0;
const RPY_OFF_PKT_TYPE: usize = 1;
const RPY_OFF_COMMAND: usize = 4;
const RPY_OFF_REPLY: usize = 6;
const RPY_OFF_STATUS: usize = 8;
const RPY_OFF_SEQUENCE: usize = 16;

/// `read_from_cmd_socket`'s reply-header initialization. The `CMD_Reply` is zeroed (so `res*`
/// and all `pad*` stay 0), then `version`/`pkt_type` are stamped, the request's `command` and
/// `sequence` are echoed **verbatim in network order** (the raw request bytes), and `reply` /
/// `status` are set (the default dispatch uses `RPY_NULL` / `STT_SUCCESS`; an error path
/// overrides `status` and leaves `reply` at `RPY_NULL`). `command_be`/`sequence_be` are the
/// request's on-wire bytes at `CMD_Request` offsets 4 and 8.
pub fn build_reply_header(
    command_be: [u8; 2],
    sequence_be: [u8; 4],
    reply: u16,
    status: u16,
) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[RPY_OFF_VERSION] = PROTO_VERSION_NUMBER;
    b[RPY_OFF_PKT_TYPE] = PKT_TYPE_CMD_REPLY;
    b[RPY_OFF_COMMAND..RPY_OFF_COMMAND + 2].copy_from_slice(&command_be);
    b[RPY_OFF_REPLY..RPY_OFF_REPLY + 2].copy_from_slice(&reply.to_be_bytes());
    b[RPY_OFF_STATUS..RPY_OFF_STATUS + 2].copy_from_slice(&status.to_be_bytes());
    b[RPY_OFF_SEQUENCE..RPY_OFF_SEQUENCE + 4].copy_from_slice(&sequence_be);
    b
}

/// chrony's per-command `permissions[]` levels (`candm.h` `PERMIT_*`): the authority required to
/// issue a command over an IP command socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Permit {
    /// `PERMIT_OPEN` (0): allowed from any host that passed the access-allow table.
    Open,
    /// `PERMIT_LOCAL` (1): allowed only from the loopback address.
    Local,
    /// `PERMIT_AUTH` (2): allowed only over the Unix-domain socket (root/chrony-owned); never
    /// over an IP socket in this build (there is no per-command network authentication).
    Auth,
}

impl Permit {
    /// The `candm.h` `PERMIT_*` numeric value.
    pub fn value(self) -> u8 {
        match self {
            Permit::Open => 0,
            Permit::Local => 1,
            Permit::Auth => 2,
        }
    }
}

/// chrony's `permissions[]` table (`cmdmon.c`): one entry per request command, in command-code
/// order, giving the authority level required. This is operational-knowledge parity — the exact
/// set of commands that are readable by any allowed host (`Open`) versus write/control commands
/// restricted to the Unix socket (`Auth`). Transcribed from the 4.5 source and pinned against an
/// awk-extracted copy of the real array in the tests.
pub static PERMISSIONS: [Permit; N_REQUEST_TYPES as usize] = {
    use Permit::{Auth, Open};
    [
        Open, /* 0  NULL */
        Auth, /* 1  ONLINE */
        Auth, /* 2  OFFLINE */
        Auth, /* 3  BURST */
        Auth, /* 4  MODIFY_MINPOLL */
        Auth, /* 5  MODIFY_MAXPOLL */
        Auth, /* 6  DUMP */
        Auth, /* 7  MODIFY_MAXDELAY */
        Auth, /* 8  MODIFY_MAXDELAYRATIO */
        Auth, /* 9  MODIFY_MAXUPDATESKEW */
        Open, /* 10 LOGON */
        Auth, /* 11 SETTIME */
        Auth, /* 12 LOCAL */
        Auth, /* 13 MANUAL */
        Open, /* 14 N_SOURCES */
        Open, /* 15 SOURCE_DATA */
        Auth, /* 16 REKEY */
        Auth, /* 17 ALLOW */
        Auth, /* 18 ALLOWALL */
        Auth, /* 19 DENY */
        Auth, /* 20 DENYALL */
        Auth, /* 21 CMDALLOW */
        Auth, /* 22 CMDALLOWALL */
        Auth, /* 23 CMDDENY */
        Auth, /* 24 CMDDENYALL */
        Auth, /* 25 ACCHECK */
        Auth, /* 26 CMDACCHECK */
        Auth, /* 27 ADD_SERVER */
        Auth, /* 28 ADD_PEER */
        Auth, /* 29 DEL_SOURCE */
        Auth, /* 30 WRITERTC */
        Auth, /* 31 DFREQ */
        Auth, /* 32 DOFFSET */
        Open, /* 33 TRACKING */
        Open, /* 34 SOURCESTATS */
        Open, /* 35 RTCREPORT */
        Auth, /* 36 TRIMRTC */
        Auth, /* 37 CYCLELOGS */
        Auth, /* 38 SUBNETS_ACCESSED */
        Auth, /* 39 CLIENT_ACCESSES (by subnet) */
        Auth, /* 40 CLIENT_ACCESSES_BY_INDEX */
        Open, /* 41 MANUAL_LIST */
        Auth, /* 42 MANUAL_DELETE */
        Auth, /* 43 MAKESTEP */
        Open, /* 44 ACTIVITY */
        Auth, /* 45 MODIFY_MINSTRATUM */
        Auth, /* 46 MODIFY_POLLTARGET */
        Auth, /* 47 MODIFY_MAXDELAYDEVRATIO */
        Auth, /* 48 RESELECT */
        Auth, /* 49 RESELECTDISTANCE */
        Auth, /* 50 MODIFY_MAKESTEP */
        Open, /* 51 SMOOTHING */
        Auth, /* 52 SMOOTHTIME */
        Auth, /* 53 REFRESH */
        Auth, /* 54 SERVER_STATS */
        Auth, /* 55 CLIENT_ACCESSES_BY_INDEX2 */
        Auth, /* 56 LOCAL2 */
        Auth, /* 57 NTP_DATA */
        Auth, /* 58 ADD_SERVER2 */
        Auth, /* 59 ADD_PEER2 */
        Auth, /* 60 ADD_SERVER3 */
        Auth, /* 61 ADD_PEER3 */
        Auth, /* 62 SHUTDOWN */
        Auth, /* 63 ONOFFLINE */
        Auth, /* 64 ADD_SOURCE */
        Open, /* 65 NTP_SOURCE_NAME */
        Auth, /* 66 RESET_SOURCES */
        Auth, /* 67 AUTH_DATA */
        Auth, /* 68 CLIENT_ACCESSES_BY_INDEX3 */
        Auth, /* 69 SELECT_DATA */
        Auth, /* 70 RELOAD_SOURCES */
        Auth, /* 71 DOFFSET2 */
        Auth, /* 72 MODIFY_SELECTOPTS */
    ]
};

/// The authority level required for `command` (its `permissions[]` entry). `command` must be a
/// valid request code (`< N_REQUEST_TYPES`); callers gate that earlier via [`validate_request`].
pub fn command_permission(command: u16) -> Permit {
    PERMISSIONS[command as usize]
}

/// `read_from_cmd_socket`'s authority check: whether a validated command may be dispatched.
/// Requests over the Unix-domain socket (`from_unix_socket`) are always allowed (the socket is
/// owned by root/chrony). Over IP, [`Permit::Open`] is always allowed, [`Permit::Local`] only
/// from the loopback address, and [`Permit::Auth`] never.
pub fn is_command_allowed(command: u16, from_unix_socket: bool, localhost: bool) -> bool {
    if from_unix_socket {
        return true;
    }
    match command_permission(command) {
        Permit::Open => true,
        Permit::Local => localhost,
        Permit::Auth => false,
    }
}

/// `transmit_reply`'s length gate: a reply is sent only if it is no larger than the request that
/// prompted it (`request_length >= reply_length`, where `reply_length` is `PKL_ReplyLength`).
/// Returns whether the reply fits and should be transmitted.
pub fn reply_fits(request_length: i32, reply_length: i32) -> bool {
    request_length >= reply_length
}

// ---------------------------------------------------------------------------
// Remaining handle_* command dispatchers — cmdmon.c cyclelogs/dump/make_step/
// n_sources/ntp_source_name/onoffline/refresh/rekey/reload_sources/reselect/
// reset_sources/shutdown/trimrtc/writertc.
//
// These are the simple (void-arg or single-field) command handlers that either
// act on daemon state (host-boundary) or return a trivial reply. Each is a pure
// function that encodes the reply bytes, composes the ported encoder primitives.
// ---------------------------------------------------------------------------

/// Build a minimal valid reply buffer with header fields pre-populated.
/// version, pkt_type, reply type (RPY_NULL), and status (STT_SUCCESS) are set.
/// The command (offset 4) and sequence (offset 16) are left as 0 — the dispatch
/// overwrites them via `build_reply_header` when a request context is available.
fn reply_header_null() -> [u8; CMD_REPLY_SIZE] {
    let mut reply = [0u8; CMD_REPLY_SIZE];
    reply[RPY_OFF_VERSION] = PROTO_VERSION_NUMBER;
    reply[RPY_OFF_PKT_TYPE] = PKT_TYPE_CMD_REPLY;
    reply[RPY_OFF_REPLY..RPY_OFF_REPLY + 2].copy_from_slice(&RPY_NULL.to_be_bytes());
    reply[RPY_OFF_STATUS..RPY_OFF_STATUS + 2].copy_from_slice(&STT_SUCCESS.to_be_bytes());
    reply
}

/// `handle_cyclelogs` (REQ_CYCLELOGS): close and re-open all log files.
/// Returns the RPY_NULL reply header + body (no additional data).
pub fn handle_cyclelogs() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_dump` (REQ_DUMP): dump all source measurements to files.
/// Returns the RPY_NULL reply header + body.
pub fn handle_dump() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_make_step` (REQ_MAKESTEP): immediately step the clock.
/// Returns the RPY_NULL reply header + body.
pub fn handle_make_step() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_n_sources` (REQ_N_SOURCES): report the number of known sources.
/// Encodes a 4-byte big-endian count at the reply data offset.
pub fn handle_n_sources(n_sources: i32) -> [u8; CMD_REPLY_SIZE] {
    let mut reply = reply_header_null();
    let count = n_sources.to_be_bytes();
    reply[CMD_REPLY_DATA_OFFSET..CMD_REPLY_DATA_OFFSET + 4].copy_from_slice(&count);
    reply[RPY_OFF_REPLY..RPY_OFF_REPLY + 2].copy_from_slice(&RPY_N_SOURCES.to_be_bytes());
    reply
}

/// `handle_ntp_source_name` (REQ_NTP_SOURCE_NAME): report the name of
/// a source given its index. Returns the source name as a null-terminated
/// string, or an empty name if no source at that index.
pub fn handle_ntp_source_name(name: &str) -> [u8; CMD_REPLY_SIZE] {
    let mut reply = reply_header_null();
    let max_len = CMD_REPLY_SIZE - CMD_REPLY_DATA_OFFSET - 1;
    let bytes = name.as_bytes();
    let len = bytes.len().min(max_len);
    reply[CMD_REPLY_DATA_OFFSET..CMD_REPLY_DATA_OFFSET + len].copy_from_slice(&bytes[..len]);
    reply[RPY_OFF_REPLY..RPY_OFF_REPLY + 2].copy_from_slice(&RPY_NTP_SOURCE_NAME.to_be_bytes());
    reply
}

/// `handle_onoffline` (REQ_ONOFFLINE): cycle online/offline for all sources.
/// Returns the RPY_NULL reply header + body.
pub fn handle_onoffline() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_refresh` (REQ_REFRESH): refresh source addresses.
/// Returns the RPY_NULL reply header + body.
pub fn handle_refresh() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_rekey` (REQ_REKEY): re-read key files.
/// Returns the RPY_NULL reply header + body.
pub fn handle_rekey() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_reload_sources` (REQ_RELOAD_SOURCES): reload the source
/// configuration (re-read config file sources).
/// Returns the RPY_NULL reply header + body.
pub fn handle_reload_sources() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_reselect` (REQ_RESELECT): force re-selection of the synchronisation
/// source. Returns the RPY_NULL reply header + body.
pub fn handle_reselect() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_reset_sources` (REQ_RESET_SOURCES): reset all sources (drop all
/// measurements). Returns the RPY_NULL reply header + body.
pub fn handle_reset_sources() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_shutdown` (REQ_SHUTDOWN): shut down the daemon.
/// Returns the RPY_NULL reply header + body.
pub fn handle_shutdown() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_trimrtc` (REQ_TRIMRTC): trim the RTC.
/// Returns the RPY_NULL reply header + body.
pub fn handle_trimrtc() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

/// `handle_writertc` (REQ_WRITERTC): write RTC parameters to file.
/// Returns the RPY_NULL reply header + body.
pub fn handle_writertc() -> [u8; CMD_REPLY_SIZE] {
    reply_header_null()
}

#[cfg(test)]
mod tests;
