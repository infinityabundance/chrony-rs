//! Line/token splitting for chrony config files.
//!
//! chrony tokenizes a line by splitting on runs of spaces and tabs (see
//! `CPS_SplitCommand` / the `getword`-style splitting in chrony's `conf.c` and
//! `cmdparse.c`). Two traps to preserve:
//!
//!   * A `#` begins a comment **only** when it starts a token. chrony does not
//!     strip `#` from the middle of a word, so `server pool.ntp.org#1` keeps the
//!     `#1`. We reproduce that: comments are recognized at token boundaries, not
//!     by a naive "find first #".
//!   * Leading whitespace is insignificant; a line that is empty or comment-only
//!     yields no directive.
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

/// Split a full config file into token lines, skipping blank and comment-only
/// lines. Never fails: an unparseable *directive* is a diagnostic produced later,
/// not a tokenizer error.
pub fn tokenize(input: &str) -> Vec<TokenLine> {
    let mut out = Vec::new();
    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let mut tokens = split_tokens(raw_line);
        if tokens.is_empty() {
            continue; // blank or comment-only line
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

/// Split one line on whitespace, stopping at a token that *starts* with `#`
/// (a comment). chrony also treats `;` as a comment introducer in some contexts;
/// we match the `#` behavior here and track `;` as an explicit later court rather
/// than guessing.
fn split_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for tok in line.split_whitespace() {
        if tok.starts_with('#') {
            break; // comment to end of line
        }
        tokens.push(tok.to_string());
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_and_comment_lines_are_dropped() {
        // CHRONY.CONFIG.2
        let lines = tokenize("\n   \n# a comment\n\t# indented comment\n");
        assert!(lines.is_empty());
    }

    #[test]
    fn keyword_is_case_folded_but_raw_kept() {
        let lines = tokenize("MakeStep 1.0 3");
        assert_eq!(lines[0].keyword, "makestep");
        assert_eq!(lines[0].keyword_raw, "MakeStep");
        assert_eq!(lines[0].args, vec!["1.0", "3"]);
    }

    #[test]
    fn trailing_comment_is_stripped_at_token_boundary() {
        let lines = tokenize("server time.example.org iburst  # primary");
        assert_eq!(lines[0].args, vec!["time.example.org", "iburst"]);
    }

    #[test]
    fn hash_inside_a_word_is_not_a_comment() {
        // The trap: chrony keeps `#1` attached to the host token.
        let lines = tokenize("server pool.ntp.org#1");
        assert_eq!(lines[0].args, vec!["pool.ntp.org#1"]);
    }
}
