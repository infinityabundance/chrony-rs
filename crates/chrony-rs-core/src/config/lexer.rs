//! Line/token splitting for chrony config files.
//!
//! chrony tokenizes a line by splitting on runs of spaces and tabs (the
//! `CPS_SplitCommand`/`get_next_token` path in chrony's `conf.c`/`cmdparse.c`).
//!
//! # Comment rule (witnessed against chrony 4.5 — do not "improve" this)
//!
//! A line is a comment **only** when its first non-whitespace character is one of
//! `# % ! ;` ([`COMMENT_CHARS`]). chrony does **not** treat these as comments
//! mid-line. Verified with `chronyd -p`:
//!
//!   * `server host iburst # primary` → *error* ("Could not parse server
//!     directive") — the `#` is parsed as an argument, not a comment.
//!   * `   # indented` → comment (leading whitespace allowed before the marker).
//!   * `! ...`, `; ...`, `% ...` at line start → comments too.
//!   * `server host#1` → `#1` stays attached to the token (not at line start).
//!
//! An earlier version of this lexer stripped `#` at any token boundary, which
//! silently *accepted* configs chrony rejects. The oracle caught it. Mid-line
//! comment markers must therefore flow through as ordinary tokens so the parser
//! errors exactly where chrony does.
//!
//! Line numbers are 1-based and preserved on every token line so diagnostics can
//! point at the offending source line exactly as chrony does.

/// One source line split into its keyword and remaining arguments, with the
/// original 1-based line number retained for diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenLine {
    pub line_no: usize,
    /// The directive keyword, lowercased for matching. chrony matches directive
    /// names case-insensitively (`CPS_*` compares with `strcasecmp`), so we fold
    /// case here — but we keep the original spelling in [`keyword_raw`] because
    /// some diagnostics echo the user's text.
    ///
    /// [`keyword_raw`]: TokenLine::keyword_raw
    pub keyword: String,
    pub keyword_raw: String,
    /// Argument tokens after the keyword, in order, original case preserved.
    pub args: Vec<String>,
}

/// Characters that introduce a whole-line comment when they are the first
/// non-whitespace character of the line. Witnessed set for chrony 4.5.
pub const COMMENT_CHARS: [char; 4] = ['#', '%', '!', ';'];

/// Split a full config file into token lines, skipping blank and comment-only
/// lines. Never fails: an unparseable *directive* is a diagnostic produced later,
/// not a tokenizer error.
pub fn tokenize(input: &str) -> Vec<TokenLine> {
    let input = if input.as_bytes().starts_with(&[0xEF, 0xBB, 0xBF]) {
        &input[3..]
    } else {
        input
    };
    let mut out = Vec::new();
    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;

        // Comment/blank detection happens on the line as a whole, before any
        // tokenization, because the comment markers are only special at the start.
        let trimmed = raw_line.trim_start();
        if trimmed.is_empty() {
            continue; // blank line
        }
        if let Some(first) = trimmed.chars().next() {
            if COMMENT_CHARS.contains(&first) {
                continue; // whole-line comment
            }
        }

        // Not a comment: split on whitespace and keep every token verbatim. A
        // mid-line `#`/`;`/etc. is NOT a comment and flows through as an argument,
        // matching chrony (and letting the parser reject it where chrony does).
        let mut tokens: Vec<String> = raw_line.split_whitespace().map(str::to_string).collect();
        if tokens.is_empty() {
            continue;
        }
        let keyword_raw = tokens.remove(0);
        out.push(TokenLine {
            line_no,
            keyword: keyword_raw.to_ascii_lowercase(),
            keyword_raw,
            args: tokens,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_and_comment_lines_are_dropped() {
        // CHRONY.CONFIG.2 — witnessed: all four comment markers, with leading
        // whitespace allowed before the marker.
        let lines = tokenize("\n   \n# hash\n\t! bang\n  ; semi\n% percent\n");
        assert!(lines.is_empty(), "got: {lines:?}");
    }

    #[test]
    fn keyword_is_case_folded_but_raw_kept() {
        let lines = tokenize("MakeStep 1.0 3");
        assert_eq!(lines[0].keyword, "makestep");
        assert_eq!(lines[0].keyword_raw, "MakeStep");
        assert_eq!(lines[0].args, vec!["1.0", "3"]);
    }

    #[test]
    fn midline_comment_marker_is_not_a_comment() {
        // Witnessed against chrony 4.5: `# primary` flows through as arguments
        // (chrony then errors "Could not parse server directive"). The lexer must
        // NOT strip it — that was the original bug the oracle caught.
        let lines = tokenize("server time.example.org iburst # primary");
        assert_eq!(
            lines[0].args,
            vec!["time.example.org", "iburst", "#", "primary"]
        );
    }

    #[test]
    fn hash_inside_a_word_is_not_a_comment() {
        // chrony keeps `#1` attached to the host token (the `#` is not at line start).
        let lines = tokenize("server pool.ntp.org#1");
        assert_eq!(lines[0].args, vec!["pool.ntp.org#1"]);
    }

    #[test]
    fn comment_marker_only_special_at_line_start() {
        // A line that *starts* with a marker is a comment; the same marker later is
        // not. Each of the four markers behaves identically.
        for c in ['#', '%', '!', ';'] {
            assert!(tokenize(&format!("{c} a comment")).is_empty(), "{c} at start");
            let line = tokenize(&format!("server host{c}suffix"));
            assert_eq!(line[0].args, vec![format!("host{c}suffix")], "{c} mid-token");
        }
    }
}
