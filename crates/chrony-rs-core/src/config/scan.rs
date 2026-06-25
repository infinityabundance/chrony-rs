//! Faithful `sscanf` scalar parsing for config directives.
//!
//! chrony's `conf.c` reads scalar directive values with `sscanf("%d")` / `sscanf("%lf")` /
//! `sscanf("%lu")`, and multi-value directives with a single `sscanf("%lf %d %d", line)`
//! over the whole line. These are **lenient about trailing junk** — `sscanf("%d")` on
//! `"42abc"` yields `42` — and for the multi-field form, trailing junk on a non-final
//! field makes the *next* conversion fail (so `sscanf("%lf %d %d", "1.0x 30 2")` parses
//! only the first field). Rust's `str::parse` is strict, so it would reject inputs chrony
//! accepts; per-token parsing would also miss the multi-field coupling. These functions
//! reproduce `sscanf`'s behavior.
//!
//! Scope: the **decimal** domain real configs use. `sscanf("%lf")` also accepts hex floats
//! and `%d` has implementation-defined overflow wrapping; neither occurs in a config, so
//! they are out of scope (documented, not silently handled).
//!
//! # Oracle
//!
//! Differential-tested against the real `sscanf` (`/tmp/genscan.c`,
//! `research/oracle/config-scan-c-vectors.txt`). See the tests.

/// Skip C `isspace` whitespace (space, tab, newline, vtab, formfeed, CR) from `i`.
fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    i
}

/// `sscanf("%d")` at the start of `s`: skip leading whitespace, parse the base-10 integer
/// (optional sign), and return `(value, end_index)` — the index just past the consumed
/// digits. `None` when no digit is present.
fn scan_int_at(s: &str) -> Option<(i32, usize)> {
    let b = s.as_bytes();
    let start = skip_ws(b, 0);
    let mut i = start;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let digits = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == digits {
        return None;
    }
    Some((s[start..i].parse::<i32>().ok()?, i))
}

/// `sscanf("%lf")` at the start of `s`: skip leading whitespace, parse the decimal float
/// (sign, fraction, exponent, `inf`/`infinity`/`nan`), and return `(value, end_index)`.
fn scan_double_at(s: &str) -> Option<(f64, usize)> {
    let b = s.as_bytes();
    let start = skip_ws(b, 0);
    let mut i = start;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let rest = s[i..].to_ascii_lowercase();
    if rest.starts_with("infinity") {
        return Some((s[start..i + 8].parse::<f64>().ok()?, i + 8));
    }
    if rest.starts_with("inf") {
        return Some((s[start..i + 3].parse::<f64>().ok()?, i + 3));
    }
    if rest.starts_with("nan") {
        return Some((s[start..i + 3].parse::<f64>().ok()?, i + 3));
    }
    let mut digits = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
        digits += 1;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        return None;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        let exp_digits = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > exp_digits {
            i = j;
        }
    }
    // Rust rejects a trailing bare '.', which sscanf accepts ("3." -> 3.0); drop it.
    let lexeme = s[start..i].strip_suffix('.').unwrap_or(&s[start..i]);
    Some((lexeme.parse::<f64>().ok()?, i))
}

/// `sscanf("%lu")` at the start of `s`: skip leading whitespace, parse a base-10 unsigned
/// long (`u64`), with a leading `-` wrapping like C's `strtoul` (`"-1"` → `u64::MAX`).
fn scan_uint_at(s: &str) -> Option<(u64, usize)> {
    let b = s.as_bytes();
    let start = skip_ws(b, 0);
    let mut i = start;
    let neg = i < b.len() && b[i] == b'-';
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let digits = i;
    let mut v: u64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((b[i] - b'0') as u64);
        i += 1;
    }
    if i == digits {
        return None;
    }
    Some((if neg { v.wrapping_neg() } else { v }, i))
}

/// `sscanf("%d", token)` — the value of a single trimmed argument, trailing junk ignored.
pub fn scan_int(s: &str) -> Option<i32> {
    scan_int_at(s).map(|(v, _)| v)
}

/// `sscanf("%lf", token)` — the value of a single trimmed argument.
pub fn scan_double(s: &str) -> Option<f64> {
    scan_double_at(s).map(|(v, _)| v)
}

/// `sscanf("%lu", token)` — the value of a single trimmed argument.
pub fn scan_uint(s: &str) -> Option<u64> {
    scan_uint_at(s).map(|(v, _)| v)
}

/// `parse_maxchange`'s `sscanf("%lf %d %d", line)` over the whole (space-normalized) line:
/// all three fields must convert from one left-to-right pass (a non-final field's trailing
/// junk makes the next conversion fail). Returns `(threshold, delay, ignore)` only when all
/// three parse.
pub fn scan_maxchange(line: &str) -> Option<(f64, i32, i32)> {
    let (a, i) = scan_double_at(line)?;
    let (b, j) = scan_int_at(&line[i..])?;
    let (c, _) = scan_int_at(&line[i + j..])?;
    Some((a, b, c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_real_c_sscanf() {
        let v = include_str!("../../../../research/oracle/config-scan-c-vectors.txt");
        for l in v.lines().map(str::trim).filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f = |key: &str| l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap();
            if l.starts_with("INT ") {
                let got = scan_int(f("in"));
                assert_eq!(got.is_some() as i32, f("ret").parse::<i32>().unwrap(), "INT {} ret", f("in"));
                if got.is_some() {
                    assert_eq!(got.unwrap(), f("val").parse::<i32>().unwrap(), "INT {} val", f("in"));
                }
            } else if l.starts_with("DBL ") {
                let got = scan_double(f("in"));
                assert_eq!(got.is_some() as i32, f("ret").parse::<i32>().unwrap(), "DBL {} ret", f("in"));
                if got.is_some() {
                    let want = f("val").parse::<f64>().unwrap();
                    if want.is_nan() {
                        assert!(got.unwrap().is_nan(), "DBL {} nan", f("in"));
                    } else {
                        assert_eq!(got.unwrap(), want, "DBL {} val", f("in"));
                    }
                }
            } else if l.starts_with("UINT ") {
                let got = scan_uint(f("in"));
                assert_eq!(got.is_some() as i32, f("ret").parse::<i32>().unwrap(), "UINT {} ret", f("in"));
                if got.is_some() {
                    assert_eq!(got.unwrap(), f("val").parse::<u64>().unwrap(), "UINT {} val", f("in"));
                }
            }
        }
    }

    #[test]
    fn matches_real_c_maxchange() {
        // (tag, line, expected ret count from the oracle).
        let cases = [
            ("OK", "1.0 30 2", 3, Some((1.0, 30, 2))),
            ("FRAC", "0.5 300 1", 3, Some((0.5, 300, 1))),
            ("JUNK0", "1.0x 30 2", 1, None),
            ("JUNK1", "1.0 30x 2", 2, None),
            ("SHORT", "1.0 30", 2, None),
            ("EXTRASPACE", "1.0   30   2", 3, Some((1.0, 30, 2))),
        ];
        for (tag, line, ret, expected) in cases {
            let got = scan_maxchange(line);
            // The directive succeeds iff the oracle's conversion count is 3.
            assert_eq!(got.is_some(), ret == 3, "{tag} success");
            assert_eq!(got, expected, "{tag} value");
        }
    }
}
