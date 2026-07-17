//! chrony command/config line parsing — a dependency-free subset of chrony 4.5
//! `cmdparse.c` (`CPS_*`).
//!
//! `cmdparse.c` turns config/command words into structured values. This module
//! ports its pure, dependency-free helpers (the source-line option parser
//! `CPS_ParseNTPSourceAdd`/`CPS_GetSelectOption` lives with the config parser in
//! [`crate::config`]):
//!
//! | chrony `cmdparse.c` | here |
//! |---------------------|------|
//! | `CPS_SplitWord` | [`split_word`] |
//! | `CPS_NormalizeLine` | [`normalize_line`] |
//! | `CPS_ParseRefid` | [`parse_refid`] |
//! | `CPS_ParseKey` | [`parse_key`] |
//!
//! | `CPS_ParseAllowDeny` | [`parse_allow_deny`] |
//! | `CPS_ParseLocal` | [`parse_local`] |
//!
//! `parse_allow_deny` ports every branch, including chrony's final hostname case:
//! a name with no `/bits` is resolved through [`crate::nameserv`] (the system
//! resolver). `parse_local` ports the `stratum`/`orphan`/`distance` option parser,
//! including chrony's leading-number `sscanf` consumption (exotic float literals
//! like `inf`/`nan`/hex are not replicated). cmdparse.c is fully ported.

use crate::addrfilt::Subnet;
use std::net::{IpAddr, Ipv4Addr};

/// C `isspace` for the C locale: space, tab, newline, vertical tab, form feed,
/// carriage return. (Rust's `is_ascii_whitespace` omits vertical tab.)
fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `CPS_SplitWord`: split off the first whitespace-delimited word. Returns
/// `(word, rest)` where `rest` already has its leading whitespace stripped (so
/// repeated calls walk the words). chrony does this in place on a mutable buffer;
/// here it is a pure slice split.
pub fn split_word(line: &str) -> (&str, &str) {
    let b = line.as_bytes();
    let mut q = 0;
    while q < b.len() && is_c_space(b[q]) {
        q += 1;
    }
    let start = q;
    while q < b.len() && !is_c_space(b[q]) {
        q += 1;
    }
    let end = q;
    while q < b.len() && is_c_space(b[q]) {
        q += 1;
    }
    (&line[start..end], &line[q..])
}

/// `CPS_NormalizeLine`: trim, collapse internal whitespace runs to a single space,
/// strip a trailing space, and drop a line whose first non-space char is a comment
/// char (`! ; # %`).
pub fn normalize_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut space = true;
    let mut first = true;
    for &p in line.as_bytes() {
        if is_c_space(p) {
            if !space {
                out.push(' ');
            }
            space = true;
            continue;
        }
        if first && matches!(p, b'!' | b';' | b'#' | b'%') {
            break;
        }
        out.push(p as char);
        space = false;
        first = false;
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// `CPS_ParseRefid`: pack up to four leading non-space chars into a big-endian
/// reference ID (first char in the most-significant byte). Returns `None` if the
/// token is empty or longer than four characters (chrony returns 0 in both cases).
pub fn parse_refid(s: &str) -> Option<u32> {
    let mut refid = 0u32;
    let mut i = 0u32;
    for &b in s.as_bytes() {
        if is_c_space(b) {
            break;
        }
        if i >= 4 {
            return None;
        }
        refid |= (b as u32) << (24 - i * 8);
        i += 1;
    }
    if i == 0 {
        None
    } else {
        Some(refid)
    }
}

/// Leading-unsigned scan matching `sscanf("%u")`: read the leading ASCII digit
/// run, ignoring any trailing characters (chrony's id parse is this lenient).
fn scan_leading_u32(s: &str) -> Option<u32> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u32>().ok()
}

/// `CPS_ParseKey`: parse a key spec `"<id> [<type>] <key>"`. With two words the
/// type defaults to `"MD5"`; three words give an explicit type. Returns
/// `(id, type, key)` or `None` if there are fewer than two / more than three words
/// or the id is not a number.
pub fn parse_key(line: &str) -> Option<(u32, String, String)> {
    let (w1, r1) = split_word(line);
    let (w2, r2) = split_word(r1);
    let (w3, r3) = split_word(r2);
    let (w4, _) = split_word(r3);

    // Require two or three words (chrony: `!*s2 || *s4`).
    if w2.is_empty() || !w4.is_empty() {
        return None;
    }
    let id = scan_leading_u32(w1)?;
    let (typ, key) = if !w3.is_empty() {
        (w2.to_string(), w3.to_string())
    } else {
        ("MD5".to_string(), w2.to_string())
    };
    Some((id, typ, key))
}

/// chrony's `NTP_MAX_STRATUM`: a `local stratum` must be in `1..NTP_MAX_STRATUM`.
const NTP_MAX_STRATUM: i32 = 16;

/// Parsed `local` directive options (chrony's `CPS_ParseLocal` outputs), with
/// chrony's defaults: stratum 10, no orphan mode, distance 1.0.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LocalOpts {
    pub stratum: i32,
    pub orphan: bool,
    pub distance: f64,
}

/// `CPS_ParseLocal`: parse the options of a `local` directive — any of
/// `stratum <n>`, `orphan`, `distance <d>` in any order. Returns `None` on an
/// unknown keyword, a missing/!valid number, or a stratum outside `1..16`.
pub fn parse_local(line: &str) -> Option<LocalOpts> {
    let mut opts = LocalOpts { stratum: 10, orphan: false, distance: 1.0 };
    let mut rest = line;
    while !rest.is_empty() {
        let (cmd, after) = split_word(rest);
        if cmd.is_empty() {
            break; // only trailing whitespace remained
        }
        rest = after;
        // chrony uses strcasecmp.
        if cmd.eq_ignore_ascii_case("stratum") {
            let (val, n) = scan_leading_i32(rest)?;
            if val >= NTP_MAX_STRATUM || val <= 0 {
                return None;
            }
            opts.stratum = val;
            rest = &rest[n..];
        } else if cmd.eq_ignore_ascii_case("orphan") {
            opts.orphan = true; // consumes no number (chrony's n = 0)
        } else if cmd.eq_ignore_ascii_case("distance") {
            let (val, n) = scan_leading_f64(rest)?;
            opts.distance = val;
            rest = &rest[n..];
        } else {
            return None;
        }
    }
    Some(opts)
}

/// Scan a leading optional-signed integer like `sscanf("%d%n")`: returns
/// `(value, bytes_consumed)` or `None` if no integer is present.
fn scan_leading_i32(s: &str) -> Option<(i32, usize)> {
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let start_digits = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == start_digits {
        return None; // no digits -> no conversion
    }
    s[..i].parse::<i32>().ok().map(|v| (v, i))
}

/// Scan a leading floating-point number like `sscanf("%lf%n")` for the common
/// decimal/scientific grammar: returns `(value, bytes_consumed)` or `None`.
fn scan_leading_f64(s: &str) -> Option<(f64, usize)> {
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let mut saw_digit = false;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
        saw_digit = true;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
            saw_digit = true;
        }
    }
    if !saw_digit {
        return None;
    }
    // Optional exponent, consumed only if it has at least one digit.
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        let exp_start = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > exp_start {
            i = j;
        }
    }
    s[..i].parse::<f64>().ok().map(|v| (v, i))
}

/// A parsed `allow`/`deny` subnet specification (chrony's `CPS_ParseAllowDeny`
/// outputs). `all` selects the prune (`*All`) variant; feed these straight into
/// [`crate::addrfilt::AuthTable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AllowDeny {
    /// The `all` keyword was present (use the `AllowAll`/`DenyAll` prune variant).
    pub all: bool,
    pub subnet: Subnet,
    pub subnet_bits: i32,
}

/// Parse the argument of an `allow`/`deny` line into an [`AllowDeny`]. Handles the
/// optional leading `all`, an empty spec (all addresses), a full IPv4/IPv6 address
/// with optional `/bits`, and chrony's shortened IPv4 notation (1–3 dotted
/// numbers, e.g. `10` = `10.0.0.0/8`, `192.168` = `192.168.0.0/16`). Returns `None`
/// on malformed input or a hostname (DNS resolution is deferred — see module docs).
pub fn parse_allow_deny(line: &str) -> Option<AllowDeny> {
    let (first, rest) = split_word(line);
    let (all, net, after) = if first == "all" {
        let (net, after) = split_word(rest);
        (true, net, after)
    } else {
        (false, first, rest)
    };
    // No further arguments are allowed.
    if !after.is_empty() {
        return None;
    }
    // No address/network means all IPv4 and IPv6 addresses.
    if net.is_empty() {
        return Some(AllowDeny { all, subnet: Subnet::Unspec, subnet_bits: 0 });
    }

    // Optional `/bits` suffix (non-negative decimal, consuming the rest).
    let (net, bits) = match net.split_once('/') {
        Some((n, b)) => {
            if b.is_empty() || !b.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            (n, b.parse::<i32>().ok()?)
        }
        None => (net, -1),
    };

    // A full IPv4/IPv6 literal.
    if let Ok(ip) = net.parse::<IpAddr>() {
        let (subnet, default_bits) = match ip {
            IpAddr::V4(a) => (Subnet::V4(a), 32),
            IpAddr::V6(a) => (Subnet::V6(a), 128),
        };
        return Some(AllowDeny {
            all,
            subnet,
            subnet_bits: if bits >= 0 { bits } else { default_bits },
        });
    }

    // Shortened IPv4 (1–3 decimal numbers).
    if let Some((addr, n)) = parse_shortened_ipv4(net) {
        return Some(AllowDeny {
            all,
            subnet: Subnet::V4(Ipv4Addr::from(addr)),
            subnet_bits: if bits >= 0 { bits } else { n * 8 },
        });
    }

    // The remaining possibility is a hostname, resolved via the system resolver.
    // chrony only attempts this when no `/bits` was given (`bits < 0`).
    if bits < 0 {
        if let Some(ip) = crate::nameserv::name_to_ip(net) {
            let (subnet, default_bits) = match ip {
                IpAddr::V4(a) => (Subnet::V4(a), 32),
                IpAddr::V6(a) => (Subnet::V6(a), 128),
            };
            return Some(AllowDeny { all, subnet, subnet_bits: default_bits });
        }
    }
    None
}

/// chrony's shortened IPv4: 1–3 dot-separated decimals (each ≤255) packed into the
/// high bytes of an address; returns `(addr, count)` or `None`. The whole string
/// must be consumed (matching chrony's `!net[len]` check).
fn parse_shortened_ipv4(net: &str) -> Option<(u32, i32)> {
    let parts: Vec<&str> = net.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let mut vals = [0u32; 3];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let v = p.parse::<u32>().ok()?;
        if v > 255 {
            return None;
        }
        vals[i] = v;
    }
    let addr = (vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8);
    Some((addr, parts.len() as i32))
}

/// `CPS_GetSelectOption` (`cmdparse.c`): map a source/refclock select-option keyword to its
/// `SRC_SELECT_*` bit (`NOSELECT=0x1`, `PREFER=0x2`, `TRUST=0x4`, `REQUIRE=0x8`), case-
/// insensitively; `0` for anything else.
pub fn get_select_option(option: &str) -> i32 {
    match option.to_ascii_lowercase().as_str() {
        "noselect" => 0x1,
        "prefer" => 0x2,
        "require" => 0x8,
        "trust" => 0x4,
        _ => 0,
    }
}

/// chrony's `SourceParameters` as produced by [`parse_ntp_source_add`] — the `server`/`pool`/
/// `peer` directive's options after parsing. Field types mirror `srcparams.h`; the `SRC_ONLINE`
/// default is `connectivity_online = true`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CpsNtpSource {
    pub name: String,
    pub port: i32,
    pub minpoll: i32,
    pub maxpoll: i32,
    pub presend_minpoll: i32,
    pub min_stratum: u32,
    pub poll_target: u32,
    pub version: i32,
    pub max_sources: u32,
    pub min_samples: i32,
    pub max_samples: i32,
    pub filter_length: i32,
    pub authkey: u32,
    pub cert_set: u32,
    pub nts_port: i32,
    pub sel_options: i32,
    pub ext_fields: u32,
    pub connectivity_online: bool,
    pub auto_offline: bool,
    pub burst: bool,
    pub iburst: bool,
    pub interleaved: bool,
    pub nts: bool,
    pub copy: bool,
    pub max_delay: f64,
    pub max_delay_ratio: f64,
    pub max_delay_dev_ratio: f64,
    pub max_delay_quant: f64,
    pub min_delay: f64,
    pub asymmetry: f64,
    pub offset: f64,
}

impl CpsNtpSource {
    /// The `SRC_DEFAULT_*` / `INACTIVE_AUTHKEY` initial values `CPS_ParseNTPSourceAdd` assigns
    /// before parsing options (`srcparams.h`).
    fn defaults(name: String) -> Self {
        CpsNtpSource {
            name,
            port: 123,
            minpoll: 6,
            maxpoll: 10,
            presend_minpoll: 100,
            min_stratum: 0,
            poll_target: 8,
            version: 0,
            max_sources: 4,
            min_samples: -1,
            max_samples: -1,
            filter_length: 0,
            authkey: 0, // INACTIVE_AUTHKEY
            cert_set: 0,
            nts_port: 4460,
            sel_options: 0,
            ext_fields: 0,
            connectivity_online: true, // SRC_ONLINE
            auto_offline: false,
            burst: false,
            iburst: false,
            interleaved: false,
            nts: false,
            copy: false,
            max_delay: 3.0,
            max_delay_ratio: 0.0,
            max_delay_dev_ratio: 10.0,
            max_delay_quant: 0.0,
            min_delay: 0.0,
            asymmetry: 1.0,
            offset: 0.0,
        }
    }
}

const NTP_EF_EXP_MONO_ROOT: u32 = 0xF323;
const NTP_EF_EXP_NET_CORRECTION: u32 = 0xF324;
const NTP_EF_FLAG_EXP_MONO_ROOT: u32 = 0x1;
const NTP_EF_FLAG_EXP_NET_CORRECTION: u32 = 0x2;

/// `CPS_ParseNTPSourceAdd` (`cmdparse.c`): parse a `server`/`pool`/`peer` directive's hostname
/// and options into a [`CpsNtpSource`], or [`None`] on any error (chrony's `return 0`, which the
/// caller reports as "Could not parse \<directive\>").
///
/// Faithfully reproduces chrony's option loop, including the `sscanf("%d%n"/"%lf%n"/"%u%n"/
/// "%x%n")` value scans that advance only past the consumed characters — so trailing junk on a
/// value **re-tokenizes** into the next option word (e.g. `minpoll 6iburst` reads `6` then parses
/// `iburst` as a flag, while `minpoll 4x` leaves a stray `x` that is an unknown option and
/// rejects). The `key` value must be non-zero (`!= INACTIVE_AUTHKEY`), and `extfield` accepts
/// only the two experimental EF type codes.
pub fn parse_ntp_source_add(line: &str) -> Option<CpsNtpSource> {
    use crate::config::scan::{scan_double_at, scan_hex_at, scan_int_at, scan_uint_at};

    let (hostname, mut line) = split_word(line);
    if hostname.is_empty() {
        return None;
    }
    let mut src = CpsNtpSource::defaults(hostname.to_string());

    // Loop while there is another word; each value option advances `line` by only the characters
    // its scan consumed (chrony's `line += n`), so leftovers re-tokenize.
    while {
        let (cmd, after_cmd) = split_word(line);
        line = after_cmd;
        if cmd.is_empty() {
            false
        } else {
            // Returns Some(consumed) to continue, or None to reject.
            let consumed: Option<usize> = (|| {
                let lc = cmd.to_ascii_lowercase();
                // %d value scan.
                let int_at = |dst: &mut i32| scan_int_at(line).map(|(v, n)| { *dst = v; n });
                let uint_at = |dst: &mut u32| scan_uint_at(line).map(|(v, n)| { *dst = v as u32; n });
                let dbl_at = |dst: &mut f64| scan_double_at(line).map(|(v, n)| { *dst = v; n });
                // %d into a u32 field (chrony scans min_stratum/max_sources/poll_target with %d).
                let int_at_u = |dst: &mut u32| scan_int_at(line).map(|(v, n)| { *dst = v as u32; n });

                match lc.as_str() {
                    "auto_offline" => { src.auto_offline = true; Some(0) }
                    "burst" => { src.burst = true; Some(0) }
                    "copy" => { src.copy = true; Some(0) }
                    "iburst" => { src.iburst = true; Some(0) }
                    "offline" => { src.connectivity_online = false; Some(0) }
                    "nts" => { src.nts = true; Some(0) }
                    "xleave" => { src.interleaved = true; Some(0) }
                    "certset" => uint_at(&mut src.cert_set),
                    "key" => {
                        let (v, n) = scan_uint_at(line)?;
                        if v as u32 == 0 { return None; } // INACTIVE_AUTHKEY rejected
                        src.authkey = v as u32;
                        Some(n)
                    }
                    "asymmetry" => dbl_at(&mut src.asymmetry),
                    "extfield" => {
                        let (ef, n) = scan_hex_at(line)?;
                        match ef {
                            NTP_EF_EXP_MONO_ROOT => src.ext_fields |= NTP_EF_FLAG_EXP_MONO_ROOT,
                            NTP_EF_EXP_NET_CORRECTION => src.ext_fields |= NTP_EF_FLAG_EXP_NET_CORRECTION,
                            _ => return None,
                        }
                        Some(n)
                    }
                    "filter" => int_at(&mut src.filter_length),
                    "maxdelay" => dbl_at(&mut src.max_delay),
                    "maxdelayratio" => dbl_at(&mut src.max_delay_ratio),
                    "maxdelaydevratio" => dbl_at(&mut src.max_delay_dev_ratio),
                    "maxdelayquant" => dbl_at(&mut src.max_delay_quant),
                    "maxpoll" => int_at(&mut src.maxpoll),
                    "maxsamples" => int_at(&mut src.max_samples),
                    "maxsources" => int_at_u(&mut src.max_sources),
                    "mindelay" => dbl_at(&mut src.min_delay),
                    "minpoll" => int_at(&mut src.minpoll),
                    "minsamples" => int_at(&mut src.min_samples),
                    "minstratum" => int_at_u(&mut src.min_stratum),
                    "ntsport" => int_at(&mut src.nts_port),
                    "offset" => dbl_at(&mut src.offset),
                    "port" => int_at(&mut src.port),
                    "polltarget" => int_at_u(&mut src.poll_target),
                    "presend" => int_at(&mut src.presend_minpoll),
                    "version" => int_at(&mut src.version),
                    _ => {
                        let bit = get_select_option(&lc);
                        if bit != 0 {
                            src.sel_options |= bit;
                            Some(0)
                        } else {
                            None
                        }
                    }
                }
            })();
            match consumed {
                Some(n) => {
                    line = &line[n..];
                    true
                }
                None => return None,
            }
        }
    } {}

    Some(src)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cps_parsers_match_real_c() {
        // Differential test of CPS_ParseRefid / ParseKey / ParseLocal / ParseAllowDeny vs the
        // REAL compiled cmdparse.c (/tmp/nutil/gencps2.c + cmdparse.c + util.c). The DNS-hostname
        // branch of allow/deny is a resolver boundary and is not exercised (IP-literal +
        // shortened-IPv4 + subnet forms only).
        let v = include_str!("../../../research/oracle/cps-parsers-c-vectors.txt");
        let f = |l: &str, k: &str| l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap().to_string();
        // key/allow-deny values can be checked directly; refid/local packed values compared numerically.

        // --- REFID (id -> input) ---
        let refids: &[(&str, &str)] = &[
            ("gps", "GPS"), ("gps1", "GPS1"), ("one", "1"), ("abcd", "ABCD"),
            ("abcde", "ABCDE"), ("empty", ""), ("spc", "AB CD"), ("pps", "PPS"),
        ];
        for (id, input) in refids {
            let l = v.lines().find(|l| l.starts_with("REFID ") && f(l, "id") == *id).unwrap();
            let got = parse_refid(input);
            if f(&l, "ret") == "0" {
                assert!(got.is_none(), "refid {id} expected None");
            } else {
                assert_eq!(got, Some(f(&l, "refid").parse::<u32>().unwrap()), "refid {id}");
            }
        }

        // --- KEY ---
        let keys: &[(&str, &str)] = &[
            ("two", "5 mysecret"), ("three", "7 SHA256 deadbeef"), ("one_word", "5"),
            ("four", "1 A B C"), ("bad_id", "x mysecret"), ("id_junk", "42x mysecret"),
        ];
        for (id, input) in keys {
            let l = v.lines().find(|l| l.starts_with("KEY ") && f(l, "id") == *id).unwrap();
            let got = parse_key(input);
            if f(&l, "ret") == "0" {
                assert!(got.is_none(), "key {id} expected None");
            } else {
                let (kid, typ, key) = got.unwrap();
                assert_eq!(kid, f(&l, "kid").parse::<u32>().unwrap(), "key {id} id");
                assert_eq!(typ, f(&l, "type"), "key {id} type");
                assert_eq!(key, f(&l, "key"), "key {id} key");
            }
        }

        // --- LOCAL ---
        let locals: &[(&str, &str)] = &[
            ("defaults", ""), ("stratum", "stratum 5"), ("orphan", "orphan"),
            ("distance", "distance 0.5"), ("combo", "stratum 3 orphan distance 2.5"),
            ("bad_stratum0", "stratum 0"), ("bad_stratum16", "stratum 16"),
            ("stratum15", "stratum 15"), ("badopt", "frobnicate"), ("stratum_junk", "stratum 5orphan"),
        ];
        for (id, input) in locals {
            let l = v.lines().find(|l| l.starts_with("LOCAL ") && f(l, "id") == *id).unwrap();
            let got = parse_local(input);
            if f(&l, "ret") == "0" {
                assert!(got.is_none(), "local {id} expected None");
            } else {
                let o = got.unwrap();
                assert_eq!(o.stratum, f(&l, "stratum").parse::<i32>().unwrap(), "local {id} stratum");
                assert_eq!(o.orphan, f(&l, "orphan") == "1", "local {id} orphan");
                assert_eq!(o.distance, f(&l, "distance").parse::<f64>().unwrap(), "local {id} distance");
            }
        }

        // --- ALLOW/DENY (IP-literal + shortened forms) ---
        let ads: &[(&str, &str)] = &[
            ("ipv4", "192.168.1.0/24"), ("ipv4_nobits", "10.0.0.1"), ("all", "all 172.16.0.0/12"),
            ("empty", ""), ("all_empty", "all"), ("short1", "10"), ("short2", "192.168"),
            ("short3", "192.168.1"), ("short_bits", "10/8"), ("ipv6", "2001:db8::/32"),
            ("ipv6_nobits", "2001:db8::1"), ("bad_bits", "10.0.0.0/x"), ("extra", "1.2.3.4 extra"),
            ("bad_octet", "300.1"), ("neg_bits", "10.0.0.0/-1"),
        ];
        for (id, input) in ads {
            let l = v.lines().find(|l| l.starts_with("AD ") && f(l, "id") == *id).unwrap();
            let got = parse_allow_deny(input);
            if f(&l, "ret") == "0" {
                assert!(got.is_none(), "ad {id} expected None");
            } else {
                let a = got.unwrap();
                assert_eq!(a.all, f(&l, "all") == "1", "ad {id} all");
                assert_eq!(a.subnet_bits, f(&l, "bits").parse::<i32>().unwrap(), "ad {id} bits");
                let ip_str = match a.subnet {
                    crate::addrfilt::Subnet::V4(v4) => v4.to_string(),
                    crate::addrfilt::Subnet::V6(v6) => v6.to_string(),
                    crate::addrfilt::Subnet::Unspec => "unspec".to_string(),
                };
                assert_eq!(ip_str, f(&l, "ip"), "ad {id} ip");
            }
        }
    }

    #[test]
    fn parse_ntp_source_add_matches_real_c() {
        // Differential test vs the REAL compiled CPS_ParseNTPSourceAdd (/tmp/nutil/gencps.c +
        // cmdparse.c + util.c), including the sscanf %n re-tokenization behavior.
        let v = include_str!("../../../research/oracle/cps-source-add-c-vectors.txt");
        // The battery lines, keyed by id (mirroring the C oracle's dump() calls).
        let lines: &[(&str, &str)] = &[
            ("defaults", "host.example"),
            ("common", "host minpoll 4 maxpoll 8 iburst prefer"),
            ("valopts", "host key 5 version 3 port 1234 maxdelay 0.5 asymmetry 0.25"),
            ("lenient_minpoll", "host minpoll 4x maxpoll 9"),
            ("key0", "host key 0"),
            ("key_bad", "host key abc"),
            ("ef_mono", "host extfield F323"),
            ("ef_net", "host extfield f324"),
            ("ef_bad", "host extfield 9999"),
            ("badopt", "host frobnicate"),
            ("selopts", "host trust require noselect prefer"),
            ("flags", "host xleave nts ntsport 1234 copy auto_offline offline burst"),
            ("allvals", "host maxsources 2 minsamples 6 maxsamples 12 filter 4 presend 8 polltarget 16 minstratum 1 mindelay 1e-5 maxdelayratio 3 maxdelaydevratio 5 maxdelayquant 0.1 offset -0.001 certset 2"),
            ("empty", ""),
            ("case_insens", "host IBURST Prefer MinPoll 5"),
        ];
        let f = |l: &str, k: &str| l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{k}="))).unwrap().to_string();
        let fi = |l: &str, k: &str| f(l, k).parse::<i64>().unwrap();
        let ff = |l: &str, k: &str| f(l, k).parse::<f64>().unwrap();
        let fb = |l: &str, k: &str| f(l, k) == "1";

        for (id, input) in lines {
            let oracle = v.lines().find(|l| l.split_whitespace().nth(1) == Some(&format!("id={id}"))).unwrap();
            let got = parse_ntp_source_add(input);
            if f(oracle, "ret") == "0" {
                assert!(got.is_none(), "{id} expected reject, got {got:?}");
                continue;
            }
            let s = got.unwrap_or_else(|| panic!("{id} expected accept, got None"));
            assert_eq!(s.name, f(oracle, "name"), "{id} name");
            assert_eq!(s.port as i64, fi(oracle, "port"), "{id} port");
            assert_eq!(s.minpoll as i64, fi(oracle, "minpoll"), "{id} minpoll");
            assert_eq!(s.maxpoll as i64, fi(oracle, "maxpoll"), "{id} maxpoll");
            assert_eq!(s.presend_minpoll as i64, fi(oracle, "presend"), "{id} presend");
            assert_eq!(s.min_stratum as i64, fi(oracle, "min_stratum"), "{id} min_stratum");
            assert_eq!(s.poll_target as i64, fi(oracle, "poll_target"), "{id} poll_target");
            assert_eq!(s.version as i64, fi(oracle, "version"), "{id} version");
            assert_eq!(s.max_sources as i64, fi(oracle, "max_sources"), "{id} max_sources");
            assert_eq!(s.min_samples as i64, fi(oracle, "min_samples"), "{id} min_samples");
            assert_eq!(s.max_samples as i64, fi(oracle, "max_samples"), "{id} max_samples");
            assert_eq!(s.filter_length as i64, fi(oracle, "filter"), "{id} filter");
            assert_eq!(s.authkey as i64, fi(oracle, "authkey"), "{id} authkey");
            assert_eq!(s.cert_set as i64, fi(oracle, "cert_set"), "{id} cert_set");
            assert_eq!(s.nts_port as i64, fi(oracle, "nts_port"), "{id} nts_port");
            assert_eq!(s.sel_options as i64, fi(oracle, "sel_options"), "{id} sel_options");
            assert_eq!(s.ext_fields as i64, fi(oracle, "ext_fields"), "{id} ext_fields");
            assert_eq!(s.connectivity_online, fi(oracle, "connectivity") == 1, "{id} connectivity");
            assert_eq!(s.auto_offline, fb(oracle, "auto_offline"), "{id} auto_offline");
            assert_eq!(s.burst, fb(oracle, "burst"), "{id} burst");
            assert_eq!(s.iburst, fb(oracle, "iburst"), "{id} iburst");
            assert_eq!(s.interleaved, fb(oracle, "interleaved"), "{id} interleaved");
            assert_eq!(s.nts, fb(oracle, "nts"), "{id} nts");
            assert_eq!(s.copy, fb(oracle, "copy"), "{id} copy");
            assert_eq!(s.max_delay, ff(oracle, "max_delay"), "{id} max_delay");
            assert_eq!(s.max_delay_ratio, ff(oracle, "max_delay_ratio"), "{id} max_delay_ratio");
            assert_eq!(s.max_delay_dev_ratio, ff(oracle, "max_delay_dev_ratio"), "{id} max_delay_dev_ratio");
            assert_eq!(s.max_delay_quant, ff(oracle, "max_delay_quant"), "{id} max_delay_quant");
            assert_eq!(s.min_delay, ff(oracle, "min_delay"), "{id} min_delay");
            assert_eq!(s.asymmetry, ff(oracle, "asymmetry"), "{id} asymmetry");
            assert_eq!(s.offset, ff(oracle, "offset"), "{id} offset");
        }

        // The %n re-tokenization: `minpoll 6iburst` reads 6 then parses `iburst` as a flag.
        let s = parse_ntp_source_add("host minpoll 6iburst").unwrap();
        assert_eq!((s.minpoll, s.iburst), (6, true));
    }

    #[test]
    fn split_word_walks_words() {
        let (w, r) = split_word("  server  pool.ntp.org   iburst ");
        assert_eq!(w, "server");
        assert_eq!(r, "pool.ntp.org   iburst ");
        let (w, r) = split_word(r);
        assert_eq!(w, "pool.ntp.org");
        let (w, r) = split_word(r);
        assert_eq!(w, "iburst");
        // Exhausted -> empty word, empty rest.
        let (w, r) = split_word(r);
        assert_eq!(w, "");
        assert_eq!(r, "");
    }

    #[test]
    fn normalize_line_collapses_and_strips_comments() {
        assert_eq!(normalize_line("   server   foo   "), "server foo");
        assert_eq!(normalize_line("\tpool\tbar\t"), "pool bar");
        // line-start comment chars discard the whole line
        assert_eq!(normalize_line("  # a comment"), "");
        assert_eq!(normalize_line("! bang"), "");
        // a comment char mid-line is kept (not at the first column)
        assert_eq!(normalize_line("x # y"), "x # y");
        assert_eq!(normalize_line(""), "");
    }

    #[test]
    fn parse_refid_packs_big_endian() {
        assert_eq!(parse_refid("GPS"), Some(0x4750_5300));
        assert_eq!(parse_refid("PPS"), Some(0x5050_5300));
        assert_eq!(parse_refid("ABCD"), Some(0x4142_4344));
        assert_eq!(parse_refid("AB CD"), Some(0x4142_0000)); // stops at space
        assert_eq!(parse_refid("ABCDE"), None); // > 4 chars
        assert_eq!(parse_refid(""), None); // empty
    }

    #[test]
    fn parse_local_options() {
        // defaults
        assert_eq!(parse_local(""), Some(LocalOpts { stratum: 10, orphan: false, distance: 1.0 }));
        // all three, any order
        assert_eq!(
            parse_local("stratum 5 orphan distance 0.5"),
            Some(LocalOpts { stratum: 5, orphan: true, distance: 0.5 })
        );
        assert_eq!(
            parse_local("DISTANCE 1e3 STRATUM 1"),
            Some(LocalOpts { stratum: 1, orphan: false, distance: 1000.0 })
        );
        // chrony's sscanf-adjacency quirk: a number directly followed by the next
        // keyword (no space) is consumed as the number, then the keyword.
        assert_eq!(
            parse_local("stratum 5orphan"),
            Some(LocalOpts { stratum: 5, orphan: true, distance: 1.0 })
        );
        // rejects: unknown keyword, out-of-range stratum, missing number
        assert_eq!(parse_local("badkeyword"), None);
        assert_eq!(parse_local("stratum 0"), None);
        assert_eq!(parse_local("stratum 16"), None);
        assert_eq!(parse_local("stratum"), None);
        assert_eq!(parse_local("distance"), None);
    }

    #[test]
    fn parse_allow_deny_forms() {
        let v4 = |s: &str| Subnet::V4(s.parse().unwrap());
        // full IP with /bits
        assert_eq!(
            parse_allow_deny("10.0.0.0/8"),
            Some(AllowDeny { all: false, subnet: v4("10.0.0.0"), subnet_bits: 8 })
        );
        // full IP, no /bits -> host (/32)
        assert_eq!(
            parse_allow_deny("192.168.1.1"),
            Some(AllowDeny { all: false, subnet: v4("192.168.1.1"), subnet_bits: 32 })
        );
        // `all` keyword selects the prune variant
        assert_eq!(
            parse_allow_deny("all 10.1.2.128/25"),
            Some(AllowDeny { all: true, subnet: v4("10.1.2.128"), subnet_bits: 25 })
        );
        // empty -> every address
        assert_eq!(
            parse_allow_deny(""),
            Some(AllowDeny { all: false, subnet: Subnet::Unspec, subnet_bits: 0 })
        );
        // shortened IPv4: 1/2/3 numbers default to /8, /16, /24
        assert_eq!(
            parse_allow_deny("10"),
            Some(AllowDeny { all: false, subnet: v4("10.0.0.0"), subnet_bits: 8 })
        );
        assert_eq!(
            parse_allow_deny("192.168"),
            Some(AllowDeny { all: false, subnet: v4("192.168.0.0"), subnet_bits: 16 })
        );
        // a v6 literal
        assert_eq!(
            parse_allow_deny("2001:db8::/32"),
            Some(AllowDeny { all: false, subnet: Subnet::V6("2001:db8::".parse().unwrap()), subnet_bits: 32 })
        );
        // a hostname is resolved via the system resolver (localhost -> loopback)
        let host = parse_allow_deny("localhost").expect("localhost resolves");
        assert!(!host.all);
        assert_eq!(host.subnet_bits, 32); // 127.0.0.1 -> /32
        assert!(matches!(host.subnet, Subnet::V4(a) if a.is_loopback()));
        // a hostname with explicit /bits is NOT resolved (chrony only tries DNS
        // when no width is given) -> rejected
        assert_eq!(parse_allow_deny("localhost/24"), None);

        // rejects: extra arg, bad octet, unresolvable name, bad bits
        assert_eq!(parse_allow_deny("10.0.0.0/8 extra"), None);
        assert_eq!(parse_allow_deny("10.0.0.999"), None);
        assert_eq!(parse_allow_deny("no-such-host.invalid"), None);
        assert_eq!(parse_allow_deny("10.0.0.0/-1"), None);
    }

    #[test]
    fn allow_deny_parsing_reproduces_accheck_oracle() {
        // End-to-end: parse the same config rule strings fed to chrony 4.5, drive
        // an addrfilt table, and reproduce the live `chronyc accheck` verdicts
        // (reports/oracle/chronyc-live/accheck.raw.out). Ties cmdparse -> addrfilt.
        use crate::addrfilt::AuthTable;
        let rules: &[(&str, &str)] = &[
            ("allow", "10.0.0.0/8"),
            ("deny", "10.1.0.0/16"),
            ("allow", "192.168.0.0/17"),
            ("deny", "10.1.2.0/24"),
            ("allow", "10.1.2.128/25"),
        ];
        let mut t = AuthTable::new();
        for (dir, spec) in rules {
            let ad = parse_allow_deny(spec).expect("parse rule");
            match (*dir, ad.all) {
                ("allow", false) => t.allow(ad.subnet, ad.subnet_bits),
                ("allow", true) => t.allow_all(ad.subnet, ad.subnet_bits),
                ("deny", false) => t.deny(ad.subnet, ad.subnet_bits),
                ("deny", true) => t.deny_all(ad.subnet, ad.subnet_bits),
                _ => {
                    eprintln!("cmdparse: unexpected allow/deny pair '{}' all={}", dir, ad.all);
                    continue;
                },
            };
        }
        let oracle: &[(&str, bool)] = &[
            ("10.0.0.1", true),
            ("10.1.2.3", false),
            ("10.1.2.200", true),
            ("10.2.3.4", true),
            ("11.0.0.1", false),
            ("192.168.0.1", true),
            ("192.168.127.255", true),
            ("192.168.128.1", false),
            ("8.8.8.8", false),
        ];
        for (ip, allowed) in oracle {
            assert_eq!(t.is_allowed(ip.parse().unwrap()), *allowed, "accheck for {ip}");
        }
    }

    #[test]
    fn parse_key_two_and_three_words() {
        assert_eq!(
            parse_key("1 mykey"),
            Some((1, "MD5".to_string(), "mykey".to_string()))
        );
        assert_eq!(
            parse_key("42 SHA256 deadbeef"),
            Some((42, "SHA256".to_string(), "deadbeef".to_string()))
        );
        // leading-digit id leniency (sscanf %u)
        assert_eq!(parse_key("7x key"), Some((7, "MD5".to_string(), "key".to_string())));
        // too few / too many words, or non-numeric id
        assert_eq!(parse_key("1"), None);
        assert_eq!(parse_key("1 a b c"), None);
        assert_eq!(parse_key("x key"), None);
    }
}
