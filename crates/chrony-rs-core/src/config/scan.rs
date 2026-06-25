//! Faithful `sscanf("%d")` / `sscanf("%lf")` scalar parsing for config directives.
//!
//! chrony's `conf.c` reads scalar directive values with `sscanf("%d", …)` /
//! `sscanf("%lf", …)`, which is **lenient about trailing junk** — `sscanf("%d")` on
//! `"42abc"` yields `42` and succeeds, and `"3.14"` parsed as an int yields `3`. Rust's
//! `str::parse` is strict (it rejects any trailing characters), so using it would reject
//! inputs chrony accepts. These functions reproduce `sscanf`'s behavior by consuming the
//! leading numeric token and parsing that.
//!
//! Scope: the **decimal** domain that real configs use. `sscanf("%lf")` also accepts hex
//! floats (`0x1f` → 31) and `sscanf("%d")` has implementation-defined overflow wrapping;
//! neither occurs in a chrony config, so they are out of scope (documented, not silently
//! handled). Inputs here are already-tokenized args, so no leading-whitespace skipping is
//! needed (the tokenizer trims).
//!
//! # Oracle
//!
//! Differential-tested against the real `sscanf` (`/tmp/genscan.c`,
//! `research/oracle/config-scan-c-vectors.txt`). See the tests.

/// `sscanf("%d", s)`: parse the leading base-10 integer (optional sign), ignoring any
/// trailing characters. `None` when no digit is present (chrony's parse failure, which it
/// treats as fatal). Out-of-`i32`-range inputs return `None` (out of scope; configs stay
/// in range).
pub fn scan_int(s: &str) -> Option<i32> {
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let digit_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == digit_start {
        return None; // no digits
    }
    s[..i].parse::<i32>().ok()
}

/// `sscanf("%lf", s)`: parse the leading decimal floating-point number (optional sign,
/// optional fraction, optional exponent, plus `inf`/`infinity`/`nan`), ignoring any
/// trailing characters. `None` when no numeric lexeme is present.
pub fn scan_double(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }

    // inf / infinity / nan (case-insensitive, as C's strtod accepts).
    let rest = s[i..].to_ascii_lowercase();
    if rest.starts_with("infinity") {
        return s[..i + 8].parse::<f64>().ok();
    }
    if rest.starts_with("inf") {
        return s[..i + 3].parse::<f64>().ok();
    }
    if rest.starts_with("nan") {
        return s[..i + 3].parse::<f64>().ok();
    }

    // Mantissa: digits, optional '.', optional digits — but at least one digit overall.
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
    // Optional exponent — only consumed if it has at least one digit.
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
    let lexeme = s[..i].strip_suffix('.').unwrap_or(&s[..i]);
    lexeme.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_real_c_sscanf() {
        let v = include_str!("../../../../research/oracle/config-scan-c-vectors.txt");
        for l in v.lines().map(str::trim).filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f = |key: &str| l.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap();
            let input = f("in");
            let ret: i32 = f("ret").parse().unwrap();
            if let Some(kind) = l.strip_prefix("INT ") {
                let _ = kind;
                let got = scan_int(input);
                assert_eq!(got.is_some() as i32, ret, "INT {input} ret");
                if ret == 1 {
                    assert_eq!(got.unwrap(), f("val").parse::<i32>().unwrap(), "INT {input} val");
                }
            } else if l.starts_with("DBL ") {
                let got = scan_double(input);
                assert_eq!(got.is_some() as i32, ret, "DBL {input} ret");
                if ret == 1 {
                    let want = f("val").parse::<f64>().unwrap();
                    if want.is_nan() {
                        assert!(got.unwrap().is_nan(), "DBL {input} nan");
                    } else {
                        assert_eq!(got.unwrap(), want, "DBL {input} val");
                    }
                }
            }
        }
    }
}
