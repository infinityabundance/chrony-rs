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
#[derive(Clone, Copy, Debug, PartialEq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
                _ => unreachable!(),
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
