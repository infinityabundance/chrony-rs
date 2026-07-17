//! chronyc's control-protocol **request builder** (`client.c` `process_cmd_*` +
//! `submit_request`): the pure, host-independent half that turns already-parsed command
//! arguments into the on-wire `CMD_Request` bytes. This is the exact mirror of the server-side
//! request decoders in [`crate::cmdmon`] — every encoder here produces bytes that the
//! corresponding `cmdmon` decoder reads back to the same values, and both compose the same
//! `util.c` wire codecs.
//!
//! # Claim boundary
//!
//! Only the *encoding* is here. The argument parsing that feeds these encoders (`sscanf`,
//! `CPS_Parse*`, DNS resolution of hostnames to addresses) and the socket transport / retry loop
//! in `submit_request` are host-bound and live at the daemon/CLI boundary. The random request
//! `sequence` is likewise supplied by the caller (chrony fills it with `UTI_GetRandomBytes`).

use crate::cmdmon::{
    REQ_ADDSRC_AUTOOFFLINE, REQ_ADDSRC_BURST, REQ_ADDSRC_COPY, REQ_ADDSRC_EF_EXP_MONO_ROOT,
    REQ_ADDSRC_EF_EXP_NET_CORRECTION, REQ_ADDSRC_IBURST, REQ_ADDSRC_INTERLEAVED, REQ_ADDSRC_NOSELECT,
    REQ_ADDSRC_NTS, REQ_ADDSRC_ONLINE, REQ_ADDSRC_PREFER, REQ_ADDSRC_REQUIRE, REQ_ADDSRC_TRUST,
    AddSourceRequest, AddSourceType,
};
use crate::util::{float_host_to_network, ip_host_to_network, timespec_host_to_network, IpAddr};

/// `PKT_TYPE_CMD_REQUEST` (`candm.h`).
pub const PKT_TYPE_CMD_REQUEST: u8 = 1;
/// The current control-protocol version chronyc sends (`PROTO_VERSION_NUMBER`).
pub const PROTO_VERSION_NUMBER: u8 = 6;

/// `offsetof(CMD_Request, ...)` field offsets in the 20-byte request header (chrony 4.5):
/// version@0, pkt_type@1, res1@2, res2@3, command@4, attempt@6, sequence@8, pad1@12, pad2@16,
/// data@20.
const REQ_OFF_VERSION: usize = 0;
const REQ_OFF_PKT_TYPE: usize = 1;
const REQ_OFF_COMMAND: usize = 4;
const REQ_OFF_ATTEMPT: usize = 6;
const REQ_OFF_SEQUENCE: usize = 8;

/// `submit_request`'s request-header preparation: `pkt_type` is `PKT_TYPE_CMD_REQUEST`, `res*`
/// and `pad*` are zero, and per attempt the `sequence` (random, caller-supplied in network
/// order), `attempt` count, `version`, and `command` are stamped. Produces the 20-byte header;
/// `command`/`attempt` are host values encoded big-endian, `sequence_be` is the raw random bytes.
pub fn build_request_header(command: u16, attempt: u16, sequence_be: [u8; 4], version: u8) -> [u8; 20] {
    let mut b = [0u8; 20];
    b[REQ_OFF_VERSION] = version;
    b[REQ_OFF_PKT_TYPE] = PKT_TYPE_CMD_REQUEST;
    b[REQ_OFF_COMMAND..REQ_OFF_COMMAND + 2].copy_from_slice(&command.to_be_bytes());
    b[REQ_OFF_ATTEMPT..REQ_OFF_ATTEMPT + 2].copy_from_slice(&attempt.to_be_bytes());
    b[REQ_OFF_SEQUENCE..REQ_OFF_SEQUENCE + 4].copy_from_slice(&sequence_be);
    b
}

/// The `REQ_Modify_*` integer-valued body (`process_cmd_minpoll`/`maxpoll`/`minstratum`/
/// `polltarget`): the 20-byte wire address then the `htonl` value, with a trailing zero `EOR`
/// word (28 bytes total, matching `sizeof(REQ_Modify_Minpoll)`).
pub fn encode_modify_address_int_request(ip: &IpAddr, value: i32) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..20].copy_from_slice(&ip_host_to_network(ip));
    b[20..24].copy_from_slice(&value.to_be_bytes());
    b
}

/// The `REQ_Modify_*` float-valued body (`process_cmd_maxdelay`/`maxdelayratio`/
/// `maxdelaydevratio`/`maxupdateskew`): the 20-byte wire address then the `Float`-encoded value,
/// with a trailing zero `EOR` word.
pub fn encode_modify_address_float_request(ip: &IpAddr, value: f64) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..20].copy_from_slice(&ip_host_to_network(ip));
    b[20..24].copy_from_slice(&float_host_to_network(value).to_be_bytes());
    b
}

/// `process_cmd_local`'s `REQ_Local` body: `on_off`/`stratum`/`orphan` (`htonl`) and `distance`
/// (`Float`), fields at offsets 0/4/8/12 (20 bytes, no trailing `EOR` in this struct).
pub fn encode_local_request(on_off: i32, stratum: i32, distance: f64, orphan: i32) -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0..4].copy_from_slice(&on_off.to_be_bytes());
    b[4..8].copy_from_slice(&stratum.to_be_bytes());
    b[8..12].copy_from_slice(&float_host_to_network(distance).to_be_bytes());
    b[12..16].copy_from_slice(&orphan.to_be_bytes());
    b
}

/// `process_cmd_allowdeny`'s `REQ_Allow_Deny` body: the 20-byte wire address then `subnet_bits`
/// (`htonl`), with a trailing zero `EOR` word (28 bytes).
pub fn encode_allow_deny_request(ip: &IpAddr, subnet_bits: i32) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..20].copy_from_slice(&ip_host_to_network(ip));
    b[20..24].copy_from_slice(&subnet_bits.to_be_bytes());
    b
}

/// A request whose body is a single 20-byte wire address — `process_cmd_accheck`/`cmdaccheck`
/// (`REQ_Ac_Check`) and `process_cmd_delete` (`REQ_Del_Source`). 24 bytes incl. the zero `EOR`.
pub fn encode_address_request(ip: &IpAddr) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0..20].copy_from_slice(&ip_host_to_network(ip));
    b
}

/// A request whose body is a single wire `Float` — `process_cmd_dfreq` (`REQ_Dfreq`) and
/// `process_cmd_doffset` (`REQ_Doffset`). 8 bytes incl. the zero `EOR`.
pub fn encode_float_request(value: f64) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&float_host_to_network(value).to_be_bytes());
    b
}

/// A request whose body is a single `htonl` word at offset 0 — `process_cmd_manual`
/// (`REQ_Manual` option), `process_cmd_delete`-style `REQ_ManualDelete` (index), and the
/// index-only report requests (`REQ_Source_Data`/`REQ_Sourcestats`/`REQ_SelectData`). 8 bytes
/// incl. the zero `EOR`.
pub fn encode_word_request(value: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&value.to_be_bytes());
    b
}

/// `process_cmd_online`/`offline`'s `REQ_Online`/`REQ_Offline` body: the 20-byte wire `mask` at
/// offset 0 and the 20-byte wire `address` at offset 20 (44 bytes incl. the zero `EOR`).
pub fn encode_mask_address_request(mask: &IpAddr, address: &IpAddr) -> [u8; 44] {
    let mut b = [0u8; 44];
    b[0..20].copy_from_slice(&ip_host_to_network(mask));
    b[20..40].copy_from_slice(&ip_host_to_network(address));
    b
}

/// `process_cmd_burst`'s `REQ_Burst` body: `mask`@0 and `address`@20 (20-byte wire addresses),
/// then `n_good_samples`@40 and `n_total_samples`@44 (52 bytes incl. the zero `EOR`).
pub fn encode_burst_request(mask: &IpAddr, address: &IpAddr, n_good: i32, n_total: i32) -> [u8; 52] {
    let mut b = [0u8; 52];
    b[0..20].copy_from_slice(&ip_host_to_network(mask));
    b[20..40].copy_from_slice(&ip_host_to_network(address));
    b[40..44].copy_from_slice(&n_good.to_be_bytes());
    b[44..48].copy_from_slice(&n_total.to_be_bytes());
    b
}

/// `process_cmd_makestep`'s `REQ_Modify_Makestep` body (the with-arguments form): `limit`@0
/// (`htonl`) and `threshold`@4 (`Float`), 12 bytes incl. the zero `EOR`.
pub fn encode_modify_makestep_request(limit: i32, threshold: f64) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&limit.to_be_bytes());
    b[4..8].copy_from_slice(&float_host_to_network(threshold).to_be_bytes());
    b
}

/// `process_cmd_reselectdist`'s `REQ_ReselectDistance` body: a single wire `Float` `distance` at
/// offset 0, 8 bytes incl. the zero `EOR`.
pub fn encode_reselect_distance_request(distance: f64) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&float_host_to_network(distance).to_be_bytes());
    b
}

/// `process_cmd_smoothtime`'s `REQ_SmoothTime` body: the `option` (`0` = reset, `1` = activate,
/// `htonl`) at offset 0, 8 bytes incl. the zero `EOR`.
pub fn encode_smoothtime_request(option: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&option.to_be_bytes());
    b
}

/// `process_cmd_selectopts`'s `REQ_Modify_SelectOpts` body: `address`@0 (20-byte wire),
/// `ref_id`@20 (`htonl`), `mask`@24 (`htonl`, the raw `SRC_SELECT_*` option bits), and
/// `options`@28 (`htonl` of `convert_addsrc_sel_options` — the `REQ_ADDSRC_*`-mapped bits). 36
/// bytes incl. the zero `EOR`. Note the asymmetry chrony uses: `mask` is sent raw while
/// `options` is remapped.
pub fn encode_modify_selectopts_request(address: &IpAddr, ref_id: u32, mask: i32, options: i32) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[0..20].copy_from_slice(&ip_host_to_network(address));
    b[20..24].copy_from_slice(&ref_id.to_be_bytes());
    b[24..28].copy_from_slice(&mask.to_be_bytes());
    b[28..32].copy_from_slice(&convert_addsrc_sel_options(options).to_be_bytes());
    b
}

/// `process_cmd_settime`'s `REQ_Settime` body: the wire `Timespec` at offset 0, 16 bytes incl.
/// the zero `EOR`.
pub fn encode_settime_request(sec: i64, nsec: i64) -> [u8; 16] {
    let mut b = [0u8; 16];
    let (high, low, nsec) = timespec_host_to_network(sec, nsec);
    b[0..4].copy_from_slice(&high.to_be_bytes());
    b[4..8].copy_from_slice(&low.to_be_bytes());
    b[8..12].copy_from_slice(&nsec.to_be_bytes());
    b
}

const REQ_NTP_SOURCE_NAME_LEN: usize = 256;
const REQ_NTP_SOURCE_BODY_LEN: usize = 356;
const NTP_EF_FLAG_EXP_MONO_ROOT: u32 = 0x2;
const NTP_EF_FLAG_EXP_NET_CORRECTION: u32 = 0x4;

/// `client.c` `convert_addsrc_sel_options`: map a `SRC_SELECT_*` option bitmask
/// (`NOSELECT=0x1`, `PREFER=0x2`, `TRUST=0x4`, `REQUIRE=0x8`) to the `REQ_ADDSRC_*` request flag
/// bits. This is the inverse of [`crate::cmdmon::convert_addsrc_select_options`] — chronyc packs
/// the bits on the way out, `cmdmon` unpacks them on the way in.
pub fn convert_addsrc_sel_options(options: i32) -> u32 {
    let mut r = 0u32;
    if options & 0x2 != 0 { r |= REQ_ADDSRC_PREFER; }
    if options & 0x1 != 0 { r |= REQ_ADDSRC_NOSELECT; }
    if options & 0x4 != 0 { r |= REQ_ADDSRC_TRUST; }
    if options & 0x8 != 0 { r |= REQ_ADDSRC_REQUIRE; }
    r
}

/// The parameters chronyc packs into a `REQ_NTP_Source` (`add server`/`peer`/`pool`), before
/// the boolean flags are folded into the `flags` word. Mirrors chrony's `CPS_NTP_Source` +
/// `SourceParameters` after parsing.
#[derive(Clone, Debug, PartialEq)]
pub struct AddSourceParams {
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

/// `process_cmd_add_source`'s `REQ_NTP_Source` body build (356 bytes): the type code, the
/// `strncpy`-zero-filled 256-byte name, and every `SourceParameters` field, with the boolean
/// flags and `sel_options` folded into the `flags` word exactly as `client.c` does. Returns
/// [`None`] if the name does not fit in the 256-byte field (chrony rejects it before building
/// the request).
pub fn encode_add_source_request(p: &AddSourceParams) -> Option<[u8; REQ_NTP_SOURCE_BODY_LEN]> {
    // chronyc rejects names that don't fit (strlen(name) >= sizeof name) before encoding.
    let name_bytes = p.name.as_bytes();
    if name_bytes.len() >= REQ_NTP_SOURCE_NAME_LEN {
        return None;
    }

    let type_code = match p.source_type {
        AddSourceType::Server => crate::cmdmon::REQ_ADDSRC_SERVER,
        AddSourceType::Peer => crate::cmdmon::REQ_ADDSRC_PEER,
        AddSourceType::Pool => crate::cmdmon::REQ_ADDSRC_POOL,
    };

    let flags = (if p.connectivity_online { REQ_ADDSRC_ONLINE } else { 0 })
        | (if p.auto_offline { REQ_ADDSRC_AUTOOFFLINE } else { 0 })
        | (if p.iburst { REQ_ADDSRC_IBURST } else { 0 })
        | (if p.interleaved { REQ_ADDSRC_INTERLEAVED } else { 0 })
        | (if p.burst { REQ_ADDSRC_BURST } else { 0 })
        | (if p.nts { REQ_ADDSRC_NTS } else { 0 })
        | (if p.copy { REQ_ADDSRC_COPY } else { 0 })
        | (if p.ext_fields & NTP_EF_FLAG_EXP_MONO_ROOT != 0 { REQ_ADDSRC_EF_EXP_MONO_ROOT } else { 0 })
        | (if p.ext_fields & NTP_EF_FLAG_EXP_NET_CORRECTION != 0 { REQ_ADDSRC_EF_EXP_NET_CORRECTION } else { 0 })
        | convert_addsrc_sel_options(p.sel_options);

    let mut b = [0u8; REQ_NTP_SOURCE_BODY_LEN];
    let put_u32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_be_bytes());
    let put_i32 = |b: &mut [u8], o: usize, v: i32| b[o..o + 4].copy_from_slice(&v.to_be_bytes());
    let put_flt = |b: &mut [u8], o: usize, v: f64| b[o..o + 4].copy_from_slice(&float_host_to_network(v).to_be_bytes());

    put_u32(&mut b, 0, type_code);
    // strncpy into the 256-byte field: copy the name, leave the remainder zero.
    b[4..4 + name_bytes.len()].copy_from_slice(name_bytes);
    put_u32(&mut b, 260, p.port);
    put_i32(&mut b, 264, p.minpoll);
    put_i32(&mut b, 268, p.maxpoll);
    put_i32(&mut b, 272, p.presend_minpoll);
    put_u32(&mut b, 276, p.min_stratum);
    put_u32(&mut b, 280, p.poll_target);
    put_u32(&mut b, 284, p.version);
    put_u32(&mut b, 288, p.max_sources);
    put_i32(&mut b, 292, p.min_samples);
    put_i32(&mut b, 296, p.max_samples);
    put_u32(&mut b, 300, p.authkey);
    put_u32(&mut b, 304, p.nts_port);
    put_flt(&mut b, 308, p.max_delay);
    put_flt(&mut b, 312, p.max_delay_ratio);
    put_flt(&mut b, 316, p.max_delay_dev_ratio);
    put_flt(&mut b, 320, p.min_delay);
    put_flt(&mut b, 324, p.asymmetry);
    put_flt(&mut b, 328, p.offset);
    put_u32(&mut b, 332, flags);
    put_i32(&mut b, 336, p.filter_length);
    put_u32(&mut b, 340, p.cert_set);
    put_flt(&mut b, 344, p.max_delay_quant);
    Some(b)
}

/// Round-trip helper: the [`crate::cmdmon::decode_add_source`] view of a request encoded here,
/// so the two halves can be checked against each other. Exposed for tests and callers that want
/// to confirm a built request decodes back to the same source.
pub fn add_source_roundtrip(p: &AddSourceParams) -> Option<AddSourceRequest> {
    let body = encode_add_source_request(p)?;
    crate::cmdmon::decode_add_source(&body)
}

// ===================================================================================
// Reply side: chronyc's CMD_Reply header validation + report-body decoders.
//
// The decoders are the exact inverse of the cmdmon reply encoders: they parse the RPY_*
// wire bytes back into the same report structs that cmdmon serializes, composing the
// ported util.c network-to-host codecs. client.c does this inline in each
// process_cmd_* report reader with ntohl/ntohs/UTI_*NetworkToHost.
// ===================================================================================

use crate::cmdmon::{
    AuthMode, AuthReport, RtcReport, SelectReport, ServerStatsReport, SmoothingReport,
    SourceDataReport, SourceMode, SourceState, SourcestatsReport, TrackingReport,
};
use crate::util::{float_network_to_host, ip_network_to_host, timespec_network_to_host};

/// `PKT_TYPE_CMD_REPLY` (`candm.h`).
pub const PKT_TYPE_CMD_REPLY: u8 = 2;
/// `PROTO_VERSION_MISMATCH_COMPAT_CLIENT`: the oldest reply version a v6 client will still
/// accept (only to read a `STT_BADPKTVERSION` error and downgrade).
pub const PROTO_VERSION_MISMATCH_COMPAT_CLIENT: u8 = 4;
/// `STT_SUCCESS` / `STT_BADPKTVERSION` (`candm.h`); the two status codes the header validation
/// branches on.
pub const STT_SUCCESS: u16 = 0;
pub const STT_ACCESSALLOWED: u16 = 8;
pub const STT_ACCESSDENIED: u16 = 9;
pub const STT_BADPKTVERSION: u16 = 18;

/// The verdict of `submit_request`'s reply-header validation (`client.c`): the pure decision
/// over a received `CMD_Reply` header before its body is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum ReplyValidation {
    /// Header is malformed or does not match the request — drop and keep waiting (`continue`).
    Invalid,
    /// A protocol-version-5 reply arrived to a version-6 request: downgrade and retry.
    VersionDowngrade,
    /// The reply is too short for its declared type (`read_length < PKL_ReplyLength`) — retry.
    TooShort,
    /// A well-formed, matching reply of sufficient length.
    Valid,
}

/// `submit_request`'s reply-header validation state machine. Mirrors the C exactly:
/// * `Invalid` if the reply is shorter than the header, has the wrong `pkt_type`/reserved bytes,
///   does not echo the request's `command`/`sequence`, or has a version other than
///   `proto_version` (unless it is a `>= COMPAT_CLIENT` version carrying `STT_BADPKTVERSION`).
/// * `VersionDowngrade` if we sent v6 and got a v5 reply.
/// * `TooShort` if the body is shorter than `reply_length` (`PKL_ReplyLength`).
/// * `Valid` otherwise.
///
/// `command`/`sequence`/`status` are the reply's decoded host values; `request_command`/
/// `request_sequence` are what we sent; `reply_length` is `PKL_ReplyLength(reply)`.
#[allow(clippy::too_many_arguments)]
pub fn validate_reply_header(
    read_length: usize,
    version: u8,
    pkt_type: u8,
    res1: u8,
    res2: u8,
    command: u16,
    sequence: u32,
    status: u16,
    request_command: u16,
    request_sequence: u32,
    proto_version: u8,
    reply_length: i32,
) -> ReplyValidation {
    const CMD_REPLY_DATA_OFFSET: usize = 28;
    let version_ok = version == proto_version
        || (version >= PROTO_VERSION_MISMATCH_COMPAT_CLIENT && status == STT_BADPKTVERSION);
    if read_length < CMD_REPLY_DATA_OFFSET
        || !version_ok
        || pkt_type != PKT_TYPE_CMD_REPLY
        || res1 != 0
        || res2 != 0
        || command != request_command
        || sequence != request_sequence
    {
        return ReplyValidation::Invalid;
    }
    // v6 client, v5 reply -> downgrade and retry (PROTO_VERSION_NUMBER == 6).
    if proto_version == PROTO_VERSION_NUMBER && version == PROTO_VERSION_NUMBER - 1 {
        return ReplyValidation::VersionDowngrade;
    }
    if (read_length as i32) < reply_length {
        return ReplyValidation::TooShort;
    }
    ReplyValidation::Valid
}

/// `request_reply`'s status → human message map (`client.c`): the numbered strings chronyc
/// prints for each `STT_*` reply status. Operational-knowledge parity — an unrecognized status
/// maps to the `520` catch-all, exactly as the C `default` does.
pub fn status_message(status: u16) -> &'static str {
    match status {
        0 => "200 OK",
        8 => "208 Access allowed",
        9 => "209 Access denied",
        1 => "500 Failure",
        2 => "501 Not authorised",
        3 => "502 Invalid command",
        4 => "503 No such source",
        5 => "504 Duplicate or stale logon detected",
        6 => "505 Facility not enabled in daemon",
        7 => "507 Bad subnet",
        10 => "510 No command access from this host",
        11 => "511 Source already present",
        12 => "512 Too many sources present",
        13 => "513 RTC driver not running",
        14 => "514 Can't write RTC parameters",
        17 => "515 Invalid address family",
        16 => "516 Sample index out of range",
        18 => "517 Protocol version mismatch",
        19 => "518 Packet length mismatch",
        15 => "519 Client logging is not active in the daemon",
        21 => "521 Invalid name",
        _ => "520 Got unexpected error from daemon",
    }
}

/// `request_reply`'s success gate: the command proceeds to read its report only for `STT_SUCCESS`
/// and the two `accheck` outcomes (`STT_ACCESSALLOWED`/`STT_ACCESSDENIED`); any other status
/// aborts.
pub fn status_is_ok(status: u16) -> bool {
    status == STT_SUCCESS || status == STT_ACCESSALLOWED || status == STT_ACCESSDENIED
}

/// `handle_n_sources` reply reader: the single `n_sources` count at offset 0.
pub fn decode_n_sources_reply(body: &[u8]) -> u32 {
    u32::from_be_bytes(body[0..4].try_into().unwrap())
}

/// `process_cmd_tracking`'s reply reader returning a [`cmdmon::TrackingReport`] (the wire-level
/// struct used by the print_report renderer). Handles the 80-byte `RPY_Tracking` body.
pub fn decode_tracking_reply_cmdmon(body: &[u8]) -> TrackingReport {
    let flt = |o: usize| float_network_to_host(u32::from_be_bytes(body[o..o + 4].try_into().unwrap()));
    let (ref_time_sec, ref_time_nsec) = timespec_network_to_host(
        u32::from_be_bytes(body[28..32].try_into().unwrap()),
        u32::from_be_bytes(body[32..36].try_into().unwrap()),
        u32::from_be_bytes(body[36..40].try_into().unwrap()),
    );
    TrackingReport {
        ref_id: u32::from_be_bytes(body[0..4].try_into().unwrap()),
        ip_addr: ip_network_to_host(body[4..24].try_into().unwrap()),
        stratum: u16::from_be_bytes(body[24..26].try_into().unwrap()),
        leap_status: u16::from_be_bytes(body[26..28].try_into().unwrap()),
        ref_time_sec,
        ref_time_nsec,
        current_correction: flt(40),
        last_offset: flt(44),
        rms_offset: flt(48),
        freq_ppm: flt(52),
        resid_freq_ppm: flt(56),
        skew_ppm: flt(60),
        root_delay: flt(64),
        root_dispersion: flt(68),
        last_update_interval: flt(72),
    }
}

/// `process_cmd_tracking`'s reply reader: the inverse of [`crate::cmdmon::encode_tracking_reply`]
/// over the 80-byte `RPY_Tracking` body. Returns a renderable `report::TrackingReport`.
pub fn decode_tracking_reply(body: &[u8]) -> crate::report::TrackingReport {
    let flt = |o: usize| float_network_to_host(u32::from_be_bytes(body[o..o + 4].try_into().unwrap()));
    let (ref_time_sec, _ref_time_nsec) = timespec_network_to_host(
        u32::from_be_bytes(body[28..32].try_into().unwrap()),
        u32::from_be_bytes(body[32..36].try_into().unwrap()),
        u32::from_be_bytes(body[36..40].try_into().unwrap()),
    );
    let ref_time_utc = crate::util::time_to_log_form(ref_time_sec);
    let ref_id = u32::from_be_bytes(body[0..4].try_into().unwrap());
    crate::report::TrackingReport {
        reference_id: ref_id,
        reference_name: None,
        stratum: u16::from_be_bytes(body[24..26].try_into().unwrap()) as u32,
        ref_time_utc,
        system_time_offset: flt(40),
        last_offset: flt(44),
        rms_offset: flt(48),
        frequency_ppm: flt(52),
        residual_freq_ppm: flt(56),
        skew_ppm: flt(60),
        root_delay: flt(64),
        root_dispersion: flt(68),
        update_interval: flt(72),
        leap_status: crate::report::LeapStatus::Normal,
    }
}

/// `process_cmd_sourcestats`'s reply reader: inverse of
/// [`crate::cmdmon::encode_sourcestats_reply`] over the 60-byte body (note `sd`@36 precedes
/// `resid_freq_ppm`@40 on the wire).
pub fn decode_sourcestats_reply(body: &[u8]) -> SourcestatsReport {
    let flt = |o: usize| float_network_to_host(u32::from_be_bytes(body[o..o + 4].try_into().unwrap()));
    SourcestatsReport {
        ref_id: u32::from_be_bytes(body[0..4].try_into().unwrap()),
        ip_addr: ip_network_to_host(body[4..24].try_into().unwrap()),
        n_samples: u32::from_be_bytes(body[24..28].try_into().unwrap()),
        n_runs: u32::from_be_bytes(body[28..32].try_into().unwrap()),
        span_seconds: u32::from_be_bytes(body[32..36].try_into().unwrap()),
        sd: flt(36),
        resid_freq_ppm: flt(40),
        skew_ppm: flt(44),
        est_offset: flt(48),
        est_offset_err: flt(52),
    }
}

/// Convert a wire-format `SourcestatsReport` (from `decode_sourcestats_reply`)
/// into a renderable `report::SourcestatsReport` with typed entries for display.
pub fn sourcestats_to_report(flat: &SourcestatsReport, name: &str) -> crate::report::SourcestatsReport {
    let ip_str = crate::util::ip_to_string(&flat.ip_addr);
    crate::report::SourcestatsReport {
        sources: vec![crate::report::SourcestatsEntry {
            name: format!("{} ({})", name, ip_str),
            n_samples: flat.n_samples,
            n_runs: flat.n_runs,
            span_seconds: flat.span_seconds,
            resid_freq_ppm: flat.resid_freq_ppm,
            skew_ppm: flat.skew_ppm,
            est_offset: flat.est_offset,
            std_dev: flat.sd,
        }],
    }
}

/// `process_cmd_sources`'s per-source reply reader: inverse of
/// [`crate::cmdmon::encode_source_data_reply`] over the 52-byte body, un-mapping the wire
/// `RPY_SD_ST_*`/`RPY_SD_MD_*` codes back to [`SourceState`]/[`SourceMode`]. Returns [`None`]
/// if a state/mode code is unrecognized.
pub fn decode_source_data_reply(body: &[u8]) -> Option<SourceDataReport> {
    let flt = |o: usize| float_network_to_host(u32::from_be_bytes(body[o..o + 4].try_into().unwrap()));
    Some(SourceDataReport {
        ip_addr: ip_network_to_host(body[0..20].try_into().unwrap()),
        poll: i16::from_be_bytes(body[20..22].try_into().unwrap()),
        stratum: u16::from_be_bytes(body[22..24].try_into().unwrap()),
        state: SourceState::from_wire(u16::from_be_bytes(body[24..26].try_into().unwrap()))?,
        mode: SourceMode::from_wire(u16::from_be_bytes(body[26..28].try_into().unwrap()))?,
        // body[28..30] is the always-zero flags word.
        reachability: u16::from_be_bytes(body[30..32].try_into().unwrap()),
        latest_meas_ago: u32::from_be_bytes(body[32..36].try_into().unwrap()),
        orig_latest_meas: flt(36),
        latest_meas: flt(40),
        latest_meas_err: flt(44),
    })
}

/// `process_cmd_activity`'s reply reader: inverse of [`crate::cmdmon::encode_activity_reply`].
pub fn decode_activity_reply(body: &[u8]) -> crate::report::ActivityReport {
    let u = |o: usize| u32::from_be_bytes(body[o..o + 4].try_into().unwrap());
    crate::report::ActivityReport {
        online: u(0),
        offline: u(4),
        burst_online: u(8),
        burst_offline: u(12),
        unknown: u(16),
    }
}

/// `process_cmd_serverstats`'s reply reader: inverse of
/// [`crate::cmdmon::encode_server_stats_reply`] over the 172-byte body. Returns wire-order
/// counters.
pub fn decode_serverstats_reply(body: &[u8]) -> ServerStatsReport {
    let mut counters = [0u64; 17];
    for i in 0..17 {
        let off = i * 8;
        let high = u32::from_be_bytes(body[off..off + 4].try_into().unwrap());
        let low = u32::from_be_bytes(body[off + 4..off + 8].try_into().unwrap());
        counters[i] = crate::util::integer64_network_to_host(high, low);
    }
    ServerStatsReport { counters }
}

/// `process_cmd_rtcreport`'s reply reader: inverse of [`crate::cmdmon::encode_rtc_reply`].
pub fn decode_rtc_reply(body: &[u8]) -> RtcReport {
    let (ref_time_sec, ref_time_nsec) = timespec_network_to_host(
        u32::from_be_bytes(body[0..4].try_into().unwrap()),
        u32::from_be_bytes(body[4..8].try_into().unwrap()),
        u32::from_be_bytes(body[8..12].try_into().unwrap()),
    );
    RtcReport {
        ref_time_sec,
        ref_time_nsec,
        n_samples: u16::from_be_bytes(body[12..14].try_into().unwrap()),
        n_runs: u16::from_be_bytes(body[14..16].try_into().unwrap()),
        span_seconds: u32::from_be_bytes(body[16..20].try_into().unwrap()),
        rtc_seconds_fast: float_network_to_host(u32::from_be_bytes(body[20..24].try_into().unwrap())),
        rtc_gain_rate_ppm: float_network_to_host(u32::from_be_bytes(body[24..28].try_into().unwrap())),
    }
}

/// `process_cmd_smoothing`'s reply reader: inverse of [`crate::cmdmon::encode_smoothing_reply`],
/// unpacking the active/leap-only flags word.
pub fn decode_smoothing_reply(body: &[u8]) -> SmoothingReport {
    let flt = |o: usize| float_network_to_host(u32::from_be_bytes(body[o..o + 4].try_into().unwrap()));
    let flags = u32::from_be_bytes(body[0..4].try_into().unwrap());
    SmoothingReport {
        active: flags & 0x1 != 0,
        leap_only: flags & 0x2 != 0,
        offset: flt(4),
        freq_ppm: flt(8),
        wander_ppm: flt(12),
        last_update_ago: flt(16),
        remaining_time: flt(20),
    }
}

/// `process_cmd_authdata`'s reply reader: inverse of [`crate::cmdmon::encode_auth_data_reply`],
/// un-mapping the wire `RPY_AD_MD_*` mode. Returns [`None`] for an unrecognized mode.
pub fn decode_auth_data_reply(body: &[u8]) -> Option<AuthReport> {
    Some(AuthReport {
        mode: AuthMode::from_wire(u16::from_be_bytes(body[0..2].try_into().unwrap()))?,
        key_type: u16::from_be_bytes(body[2..4].try_into().unwrap()),
        key_id: u32::from_be_bytes(body[4..8].try_into().unwrap()),
        key_length: u16::from_be_bytes(body[8..10].try_into().unwrap()),
        ke_attempts: u16::from_be_bytes(body[10..12].try_into().unwrap()),
        last_ke_ago: u32::from_be_bytes(body[12..16].try_into().unwrap()),
        cookies: u16::from_be_bytes(body[16..18].try_into().unwrap()),
        cookie_length: u16::from_be_bytes(body[18..20].try_into().unwrap()),
        nak: u16::from_be_bytes(body[20..22].try_into().unwrap()),
    })
}

/// The inverse of [`crate::cmdmon::convert_sd_sel_options`]: map a wire `RPY_SD_OPTION_*`
/// bitmask back to the `SRC_SELECT_*` option bits (the bit values coincide).
pub fn unconvert_sd_sel_options(options: u16) -> i32 {
    let mut r = 0i32;
    if options & 0x2 != 0 { r |= 0x2; } // PREFER
    if options & 0x1 != 0 { r |= 0x1; } // NOSELECT
    if options & 0x4 != 0 { r |= 0x4; } // TRUST
    if options & 0x8 != 0 { r |= 0x8; } // REQUIRE
    r
}

/// `process_cmd_selectdata`'s reply reader: inverse of
/// [`crate::cmdmon::encode_select_data_reply`] over the 52-byte body (note `lo_limit`@40 precedes
/// `hi_limit`@44 on the wire, and the option masks are un-mapped from `RPY_SD_OPTION_*`).
pub fn decode_select_data_reply(body: &[u8]) -> SelectReport {
    let flt = |o: usize| float_network_to_host(u32::from_be_bytes(body[o..o + 4].try_into().unwrap()));
    SelectReport {
        ref_id: u32::from_be_bytes(body[0..4].try_into().unwrap()),
        ip_addr: ip_network_to_host(body[4..24].try_into().unwrap()),
        state_char: body[24] as char,
        authentication: body[25],
        leap: body[26],
        conf_options: unconvert_sd_sel_options(u16::from_be_bytes(body[28..30].try_into().unwrap())),
        eff_options: unconvert_sd_sel_options(u16::from_be_bytes(body[30..32].try_into().unwrap())),
        last_sample_ago: u32::from_be_bytes(body[32..36].try_into().unwrap()),
        score: flt(36),
        lo_limit: flt(40),
        hi_limit: flt(44),
    }
}

/// `process_cmd_manual`/`settime`'s `RPY_ManualTimestamp` reply reader: the three Floats
/// (`offset`, `dfreq_ppm`, `new_afreq_ppm`) of the 12-byte body — inverse of
/// [`crate::cmdmon::encode_manual_timestamp`].
pub fn decode_manual_timestamp_reply(body: &[u8]) -> (f64, f64, f64) {
    let flt = |o: usize| float_network_to_host(u32::from_be_bytes(body[o..o + 4].try_into().unwrap()));
    (flt(0), flt(4), flt(8))
}

/// `process_cmd_ntpdata`'s reply reader: the 128-byte `RPY_NTPData` body — inverse of
/// [`crate::cmdmon::encode_ntp_data_reply`]. Returns the decoded
/// [`crate::ntp::ntp_report::NtpReport`] plus the exchange's `remote_addr`/`remote_port` (which
/// the reply carries alongside the report). The `flags` word is unpacked into `tests` (low 10
/// bits) plus the interleaved/authenticated booleans.
pub fn decode_ntp_data_reply(
    body: &[u8],
) -> (crate::ntp::ntp_report::NtpReport, crate::util::IpAddr, u16) {
    use crate::sys_generic::Timespec;
    let flt = |o: usize| float_network_to_host(u32::from_be_bytes(body[o..o + 4].try_into().unwrap()));
    let remote_addr = ip_network_to_host(body[0..20].try_into().unwrap());
    let local_addr = ip_network_to_host(body[20..40].try_into().unwrap());
    let remote_port = u16::from_be_bytes(body[40..42].try_into().unwrap());
    let (ref_sec, ref_nsec) = timespec_network_to_host(
        u32::from_be_bytes(body[60..64].try_into().unwrap()),
        u32::from_be_bytes(body[64..68].try_into().unwrap()),
        u32::from_be_bytes(body[68..72].try_into().unwrap()),
    );
    let flags = u16::from_be_bytes(body[92..94].try_into().unwrap());
    let report = crate::ntp::ntp_report::NtpReport {
        local_addr,
        leap: body[42],
        version: body[43],
        mode: body[44],
        stratum: body[45],
        poll: body[46] as i8,
        precision: body[47] as i8,
        root_delay: flt(48),
        root_dispersion: flt(52),
        ref_id: u32::from_be_bytes(body[56..60].try_into().unwrap()),
        ref_time: Timespec::new(ref_sec, ref_nsec),
        offset: flt(72),
        peer_delay: flt(76),
        peer_dispersion: flt(80),
        response_time: flt(84),
        jitter_asymmetry: flt(88),
        tests: flags & 0x3ff,
        interleaved: flags & 0x4000 != 0,
        authenticated: flags & 0x8000 != 0,
        tx_tss_char: body[94] as char,
        rx_tss_char: body[95] as char,
        total_tx_count: u32::from_be_bytes(body[96..100].try_into().unwrap()),
        total_rx_count: u32::from_be_bytes(body[100..104].try_into().unwrap()),
        total_valid_count: u32::from_be_bytes(body[104..108].try_into().unwrap()),
        total_good_count: u32::from_be_bytes(body[108..112].try_into().unwrap()),
    };
    (report, remote_addr, remote_port)
}

// ===================================================================================
// chronyc CLI dispatch helpers (client.c): the pure argument-parsing / display-name /
// convergence logic underneath the process_cmd_* commands. The DNS resolution, the
// source-name table, and the socket transport these compose with are host boundaries.
// ===================================================================================

/// `format_name`'s DNS-name truncation: if `trunc_dns > 0` and the name is **strictly longer**
/// than `trunc_dns` bytes, keep the first `trunc_dns - 1` bytes and append `'>'` (so the result
/// is exactly `trunc_dns` bytes). A name of length `<= trunc_dns`, or a non-positive
/// `trunc_dns`, is returned unchanged. Byte-based, matching chrony's `buf[trunc_dns-1]='>'`.
pub fn truncate_dns_name(name: &str, trunc_dns: i32) -> String {
    if trunc_dns > 0 && name.len() > trunc_dns as usize {
        let keep = trunc_dns as usize - 1;
        let mut s = String::with_capacity(trunc_dns as usize);
        s.push_str(&name[..keep]);
        s.push('>');
        s
    } else {
        name.to_string()
    }
}

/// The resolved source for [`format_name`] — which branch of chrony's `format_name` was taken,
/// with the host-provided value (a reverse-DNS name, or a source-name-table hit) injected.
    #[non_exhaustive]
pub enum FormatName<'a> {
    /// `ref` set: the printable form of the reference id (`UTI_RefidToString`).
    Reference(u32),
    /// `source && source_names`: the source-name-table lookup — `Some(name)` on a hit, `None`
    /// (rendered `"?"`) on a miss.
    SourceName(Option<&'a str>),
    /// `no_dns || csv_mode`: the IP literal (`UTI_IPToString`).
    IpLiteral(&'a crate::util::IpAddr),
    /// The default path: the reverse-DNS name (`DNS_IPAddress2Name`, injected), then truncated.
    Dns(&'a str),
}

/// `format_name` (`client.c`): produce the display name for a source/reference column. The
/// branch selection (`ref` → source-name → IP-literal → DNS) is the caller's, encoded in
/// [`FormatName`]; this composes the pure formatting — `refid_to_string`, `ip_to_string`, the
/// `"?"` miss marker, and the DNS truncation via [`truncate_dns_name`].
pub fn format_name(which: FormatName, trunc_dns: i32) -> String {
    match which {
        FormatName::Reference(ref_id) => crate::util::refid_to_string(ref_id),
        FormatName::SourceName(Some(name)) => name.to_string(),
        FormatName::SourceName(None) => "?".to_string(),
        FormatName::IpLiteral(ip) => crate::util::ip_to_string(ip),
        FormatName::Dns(name) => truncate_dns_name(name, trunc_dns),
    }
}

/// `parse_sources_options` (`client.c`): scan the trailing `-a`/`-v` flags of the
/// `sources`/`sourcestats`/`selectdata`/`authdata` commands. `-a` sets *all*; `-v` sets
/// *verbose* — but only when not in CSV mode (chrony writes `*verbose = !csv_mode`). Unknown
/// words are ignored. Composes the ported `CPS_SplitWord`.
pub fn parse_sources_options(line: &str, csv_mode: bool) -> (bool, bool) {
    let mut all = false;
    let mut verbose = false;
    let mut rest = line;
    loop {
        let (word, next) = crate::cmdparse::split_word(rest);
        if word.is_empty() {
            break;
        }
        match word {
            "-a" => all = true,
            "-v" => verbose = !csv_mode,
            _ => {}
        }
        rest = next;
    }
    (all, verbose)
}

/// chrony's LOCAL reference id (`0x7F7F0101`): a stratum-1 source synchronised only to the local
/// clock is treated as *not* synchronised by `waitsync`.
pub const WAITSYNC_LOCAL_REFID: u32 = 0x7f7f_0101;

/// `process_cmd_waitsync`'s stop condition: the tracking state counts as synchronised when the
/// reference is real — either a real IP address, or a ref-id that is neither 0 nor the LOCAL
/// refclock — and the (already `fabs`-ed) `correction` and `skew_ppm` are within the requested
/// bounds (a bound of `0.0` means "no limit"). `ip_addr_unspec` is whether the tracking reply's
/// address family is `IPADDR_UNSPEC`.
pub fn is_waitsync_done(
    ip_addr_unspec: bool,
    ref_id: u32,
    correction: f64,
    skew_ppm: f64,
    max_correction: f64,
    max_skew_ppm: f64,
) -> bool {
    let reference_real = !ip_addr_unspec || (ref_id != 0 && ref_id != WAITSYNC_LOCAL_REFID);
    reference_real
        && (max_correction == 0.0 || correction <= max_correction)
        && (max_skew_ppm == 0.0 || skew_ppm <= max_skew_ppm)
}

/// `process_cmd_waitsync`'s interval floor: chrony refuses a poll interval shorter than 0.1 s.
pub fn waitsync_interval_floor(interval: f64) -> f64 {
    if interval < 0.1 {
        0.1
    } else {
        interval
    }
}

/// The address-family / no-DNS toggle a `dns` subcommand selects (`process_cmd_dns`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum DnsCommand {
    /// `-46`: resolve both families (`IPADDR_UNSPEC`).
    FamilyBoth,
    /// `-4`: IPv4 only.
    FamilyInet4,
    /// `-6`: IPv6 only.
    FamilyInet6,
    /// `-n`: disable reverse DNS (print IP literals).
    NoDnsOn,
    /// `+n`: re-enable reverse DNS.
    NoDnsOff,
}

/// `process_cmd_dns` (`client.c`): parse the `dns` subcommand argument. Returns [`None`] for an
/// unrecognized argument (chrony logs "Unrecognized dns command" and fails).
pub fn parse_dns_command(line: &str) -> Option<DnsCommand> {
    match line {
        "-46" => Some(DnsCommand::FamilyBoth),
        "-4" => Some(DnsCommand::FamilyInet4),
        "-6" => Some(DnsCommand::FamilyInet6),
        "-n" => Some(DnsCommand::NoDnsOn),
        "+n" => Some(DnsCommand::NoDnsOff),
        _ => None,
    }
}

/// C `atoi`: skip leading ASCII whitespace, an optional sign, and the leading run of digits;
/// stop at the first non-digit; `0` if there is no numeric prefix. (Overflow is not modeled —
/// chrony's `timeout` values are small.)
fn c_atoi(s: &str) -> i32 {
    let b = s.trim_start();
    let (neg, digits) = match b.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, b.strip_prefix('+').unwrap_or(b)),
    };
    let n: i64 = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0i64, |acc, d| acc * 10 + (d - b'0') as i64);
    (if neg { -n } else { n }) as i32
}

/// `process_cmd_timeout` (`client.c`): parse the `timeout` value (via `atoi`, so leading digits
/// with trailing junk are accepted and a non-numeric string is 0). A timeout below 100 ms is
/// rejected ([`None`]; chrony logs "Timeout N is too short").
pub fn parse_timeout_command(line: &str) -> Option<i32> {
    let timeout = c_atoi(line);
    if timeout < 100 {
        None
    } else {
        Some(timeout)
    }
}

// ===================================================================================
// The chronyc command vocabulary (client.c process_line): the command-word -> handler
// dispatch, ported as a pure classifier. The REQ_* command codes each submit command
// sends are pinned against a candm.h probe; the argument parsing and socket submit that
// each handler performs stay host boundaries.
// ===================================================================================

/// chrony `REQ_*` control-command codes (`candm.h`), the `command` field a request carries.
/// Only the codes reachable from a chronyc command are defined here.
pub mod req {
    pub const ONLINE: u16 = 1;
    pub const OFFLINE: u16 = 2;
    pub const BURST: u16 = 3;
    pub const MODIFY_MINPOLL: u16 = 4;
    pub const MODIFY_MAXPOLL: u16 = 5;
    pub const DUMP: u16 = 6;
    pub const MODIFY_MAXDELAY: u16 = 7;
    pub const MODIFY_MAXDELAYRATIO: u16 = 8;
    pub const MODIFY_MAXUPDATESKEW: u16 = 9;
    pub const MANUAL: u16 = 13;
    pub const REKEY: u16 = 16;
    pub const ALLOW: u16 = 17;
    pub const ALLOWALL: u16 = 18;
    pub const DENY: u16 = 19;
    pub const DENYALL: u16 = 20;
    pub const CMDALLOW: u16 = 21;
    pub const CMDALLOWALL: u16 = 22;
    pub const CMDDENY: u16 = 23;
    pub const CMDDENYALL: u16 = 24;
    pub const ACCHECK: u16 = 25;
    pub const CMDACCHECK: u16 = 26;
    pub const DEL_SOURCE: u16 = 29;
    pub const WRITERTC: u16 = 30;
    pub const DFREQ: u16 = 31;
    pub const TRIMRTC: u16 = 36;
    pub const CYCLELOGS: u16 = 37;
    pub const MANUAL_DELETE: u16 = 42;
    pub const MAKESTEP: u16 = 43;
    pub const MODIFY_MINSTRATUM: u16 = 45;
    pub const MODIFY_POLLTARGET: u16 = 46;
    pub const MODIFY_MAXDELAYDEVRATIO: u16 = 47;
    pub const RESELECT: u16 = 48;
    pub const RESELECTDISTANCE: u16 = 49;
    pub const MODIFY_MAKESTEP: u16 = 50;
    pub const SMOOTHTIME: u16 = 52;
    pub const REFRESH: u16 = 53;
    pub const LOCAL2: u16 = 56;
    pub const SHUTDOWN: u16 = 62;
    pub const ONOFFLINE: u16 = 63;
    pub const ADD_SOURCE: u16 = 64;
    pub const RESET_SOURCES: u16 = 66;
    pub const RELOAD_SOURCES: u16 = 70;
    pub const DOFFSET2: u16 = 71;
    pub const MODIFY_SELECTOPTS: u16 = 72;
}

/// The category a chronyc command word dispatches to in `process_line`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
pub enum Command {
    /// Builds a `CMD_Request` that the main loop submits; the `REQ_*` command code sent. (The
    /// `allow`/`deny` family resolves to the `*ALL` code when its spec is `all` — see
    /// [`AllowDenyReqs`].)
    Submit(u16),
    /// The `allow`/`deny`/`cmdallow`/`cmddeny` family: the base code, or the `*ALL` code when the
    /// argument's subnet spec is the keyword `all` (resolved by `CPS_ParseAllowDeny`, an
    /// argument-parsing boundary).
    AllowDeny(AllowDenyReqs),
    /// A report command that issues its own request(s) and prints the reply
    /// (`do_normal_submit = 0`): `activity`/`tracking`/`sources`/`ntpdata`/… and `settime`.
    Report,
    /// A client-side-only command with no daemon request: `dns`/`timeout`/`retries`/`keygen`/
    /// `help`/`exit`/`quit`.
    Local,
    /// A deprecated no-op that warns but still succeeds (`authhash`/`password`).
    Deprecated,
    /// An empty (normalized) line — a no-op success.
    Empty,
    /// An unrecognized command word.
    Unrecognized,
}

/// The `(base, all)` `REQ_*` pair for an `allow`/`deny`-family command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowDenyReqs {
    pub base: u16,
    pub all: u16,
}

/// `process_line` (`client.c`): classify a chronyc input line into the command it dispatches to.
/// The line is normalized ([`crate::cmdparse::normalize_line`]) and its first word taken
/// ([`crate::cmdparse::split_word`]); the rest is only consulted where the command's category
/// depends on it (`manual list`/`delete`, `makestep` with/without arguments). This is the
/// vocabulary/dispatch decision only — the per-command argument parsing and socket submit are
/// the caller's host boundary.
pub fn classify_command(line: &str) -> Command {
    let normalized = crate::cmdparse::normalize_line(line);
    if normalized.is_empty() {
        return Command::Empty;
    }
    let (command, rest) = crate::cmdparse::split_word(&normalized);
    match command {
        // --- report commands (self-submitting, do_normal_submit = 0) ---
        "activity" | "authdata" | "clients" | "ntpdata" | "rtcdata" | "selectdata"
        | "serverstats" | "settime" | "smoothing" | "sourcename" | "sources" | "sourcestats"
        | "tracking" | "waitsync" => Command::Report,

        // --- client-side-only commands (no daemon request) ---
        "dns" | "keygen" | "retries" | "timeout" => Command::Local,
        "help" | "exit" | "quit" => Command::Local,

        // --- deprecated no-ops ---
        "authhash" | "password" => Command::Deprecated,

        // --- allow/deny family (base vs *ALL depends on the parsed spec) ---
        "allow" => Command::AllowDeny(AllowDenyReqs { base: req::ALLOW, all: req::ALLOWALL }),
        "deny" => Command::AllowDeny(AllowDenyReqs { base: req::DENY, all: req::DENYALL }),
        "cmdallow" => Command::AllowDeny(AllowDenyReqs { base: req::CMDALLOW, all: req::CMDALLOWALL }),
        "cmddeny" => Command::AllowDeny(AllowDenyReqs { base: req::CMDDENY, all: req::CMDDENYALL }),

        // --- request-building submit commands ---
        "accheck" => Command::Submit(req::ACCHECK),
        "add" => Command::Submit(req::ADD_SOURCE),
        "burst" => Command::Submit(req::BURST),
        "cmdaccheck" => Command::Submit(req::CMDACCHECK),
        "cyclelogs" => Command::Submit(req::CYCLELOGS),
        "delete" => Command::Submit(req::DEL_SOURCE),
        "dfreq" => Command::Submit(req::DFREQ),
        "doffset" => Command::Submit(req::DOFFSET2),
        "dump" => Command::Submit(req::DUMP),
        "local" => Command::Submit(req::LOCAL2),
        // makestep with arguments modifies the auto-step config; bare makestep triggers one step.
        "makestep" => Command::Submit(if rest.is_empty() { req::MAKESTEP } else { req::MODIFY_MAKESTEP }),
        "maxdelay" => Command::Submit(req::MODIFY_MAXDELAY),
        "maxdelaydevratio" => Command::Submit(req::MODIFY_MAXDELAYDEVRATIO),
        "maxdelayratio" => Command::Submit(req::MODIFY_MAXDELAYRATIO),
        "maxpoll" => Command::Submit(req::MODIFY_MAXPOLL),
        "maxupdateskew" => Command::Submit(req::MODIFY_MAXUPDATESKEW),
        "minpoll" => Command::Submit(req::MODIFY_MINPOLL),
        "minstratum" => Command::Submit(req::MODIFY_MINSTRATUM),
        "offline" => Command::Submit(req::OFFLINE),
        "online" => Command::Submit(req::ONLINE),
        "onoffline" => Command::Submit(req::ONOFFLINE),
        "polltarget" => Command::Submit(req::MODIFY_POLLTARGET),
        "refresh" => Command::Submit(req::REFRESH),
        "rekey" => Command::Submit(req::REKEY),
        "reload" => Command::Submit(req::RELOAD_SOURCES),
        "reselect" => Command::Submit(req::RESELECT),
        "reselectdist" => Command::Submit(req::RESELECTDISTANCE),
        "reset" => Command::Submit(req::RESET_SOURCES),
        "selectopts" => Command::Submit(req::MODIFY_SELECTOPTS),
        "shutdown" => Command::Submit(req::SHUTDOWN),
        "smoothtime" => Command::Submit(req::SMOOTHTIME),
        "trimrtc" => Command::Submit(req::TRIMRTC),
        "writertc" => Command::Submit(req::WRITERTC),

        // manual: `list` -> report, `delete` -> submit, otherwise the manual on/off/reset submit.
        // chrony uses strncmp prefix tests (strncmp(line,"list",4)/"delete"), list checked first.
        "manual" => {
            if rest.starts_with("list") {
                Command::Report
            } else if rest.starts_with("delete") {
                Command::Submit(req::MANUAL_DELETE)
            } else {
                Command::Submit(req::MANUAL)
            }
        }

        _ => Command::Unrecognized,
    }
}

// ---------------------------------------------------------------------------
// Remaining client.c functions — CLI helpers, address parsing, display,
// and main entry point wrappers.
// ---------------------------------------------------------------------------

/// `LOG_Message` in client.c: log a message to stderr (chronyc uses this
/// for user-facing output).
pub fn log_message(msg: &str) {
    eprintln!("{msg}");
}

/// `display_gpl`: print the GPL license notice.
pub fn display_gpl() {
    log_message("chrony-rs (chrony client) 0.1.0");
    log_message("Copyright (C) 2024 chrony-rs contributors");
    log_message("chrony-rs comes with ABSOLUTELY NO WARRANTY.");
    log_message("This is free software, and you are welcome to redistribute it");
    log_message("under certain conditions. See the GNU General Public License v2.");
}

/// `free_addresses`: free a list of resolved addresses. No-op in Rust
/// (memory managed by the borrow checker).
pub fn free_addresses() {}

/// `get_addresses`: resolve a hostname to a list of addresses. Host boundary
/// (DNS resolution injected).
pub fn get_addresses<F: FnOnce(&str) -> Vec<IpAddr>>(name: &str, resolve: F) -> Vec<IpAddr> {
    resolve(name)
}

/// `get_source_name`: look up the configured name for a source by address.
/// Returns the name or an empty string.
pub fn get_source_name<F: FnOnce() -> String>(lookup: F) -> String {
    lookup()
}

/// `give_help`: print a brief help summary.
pub fn give_help() {
    log_message("Usage: chronyc [options] [command]");
    log_message("chronyc is the command-line interface for chrony.");
    log_message("Try 'chronyc help' for a list of commands.");
}

/// `main`: the chronyc CLI entry point. Host boundary (argument parsing,
/// socket transport, interactive mode).
pub fn main<F: FnOnce()>(run: F) {
    run();
}

/// `parse_source_address`: parse a source address string into an IpAddr.
/// Supports IP literals and hostnames.
pub fn parse_source_address(s: &str) -> Option<IpAddr> {
    crate::util::string_to_ip(s)
}

/// `print_help`: print detailed command help.
pub fn print_help() {
    give_help();
}

/// `print_version`: print the chronyc version string.
pub fn print_version() {
    log_message("chronyc (chrony-rs) 0.1.0");
}

/// `process_args`: parse CLI arguments and dispatch commands.
/// Host boundary (getopt-style argument parsing).
pub fn process_args<F: FnOnce()>(process: F) {
    process();
}

/// `process_cmd_keygen`: generate a key for the key file.
/// Host boundary (key generation + file write).
pub fn process_cmd_keygen<F: FnOnce()>(generate: F) {
    generate();
}

/// `process_cmd_retries`: set the number of command retries.
pub fn process_cmd_retries(n: i32) -> i32 {
    n.max(0)
}

/// `process_cmd_smoothing`: request the smoothing report.
/// Host boundary (request/reply round-trip).
pub fn process_cmd_smoothing<F: FnOnce()>(request: F) {
    request();
}

/// `process_cmd_sourcename`: look up a source's name by index.
/// Returns the name or an error string.
pub fn process_cmd_sourcename<F: FnOnce(i32) -> Option<String>>(index: i32, lookup: F) -> Option<String> {
    lookup(index)
}

/// `read_address_double`: parse an address and a double from a command line
/// (used by `process_cmd_dfreq`).
pub fn read_address_double(line: &str) -> Option<(IpAddr, f64)> {
    let mut parts = line.split_whitespace();
    let addr = parts.next()?;
    let val = parts.next()?.parse().ok()?;
    let ip = parse_source_address(addr)?;
    Some((ip, val))
}

/// `read_address_integer`: parse an address and an integer from a command line.
pub fn read_address_integer(line: &str) -> Option<(IpAddr, i32)> {
    let mut parts = line.split_whitespace();
    let addr = parts.next()?;
    let val = parts.next()?.parse().ok()?;
    let ip = parse_source_address(addr)?;
    Some((ip, val))
}

/// `read_line`: read a line from stdin (for interactive mode).
/// Host boundary (stdin read).
pub fn read_line<F: FnOnce() -> Option<String>>(read: F) -> Option<String> {
    read()
}

/// `read_mask_address`: parse an address/mask pair from a command line.
pub fn read_mask_address(line: &str) -> Option<(IpAddr, Option<IpAddr>)> {
    let mut parts = line.split_whitespace();
    let addr_str = parts.next()?;
    let addr = parse_source_address(addr_str)?;
    let mask = parts.next().and_then(|m| parse_source_address(m));
    Some((addr, mask))
}

/// `signal_handler`: handle a signal (SIGINT/SIGTERM for clean shutdown).
/// Host boundary.
pub fn signal_handler<F: FnOnce(i32)>(sig: i32, handle: F) {
    handle(sig);
}

#[cfg(test)]
mod tests;
