//! Config-file loading — the file-reading half of chrony 4.5 `conf.c` (`CNF_ReadFile`,
//! `load_source_file`, `search_dirs`, `CNF_CreateDirs`) over safe `std::fs`.
//!
//! The line grammar and per-directive parsing are the (differential-tested) responsibility of
//! `chrony_rs_core::config`; this module does the actual disk reads that the core parser
//! defers: reading the main config file, recursively processing `include` directives (with the
//! `MAX_INCLUDE_LEVEL` guard), loading `*.sources` files, and the `sourcedir`/`confdir`
//! directory scan with chrony's basename-dedup + directive-order preference.
//!
//! Verified by integration tests over real temp files/directories; all safe `std::fs` (no FFI).

use chrony_rs_core::config::model::Directive;
use chrony_rs_core::config::{parse, Config, Diagnostic};
use std::path::{Path, PathBuf};

/// `MAX_INCLUDE_LEVEL` (`conf.c`).
const MAX_INCLUDE_LEVEL: u32 = 10;
/// `MAX_LINE_LENGTH` (`conf.c`): chrony's line buffer; longer lines are diagnosed.
const MAX_LINE_LENGTH: usize = 2047;

/// The result of loading a config tree: the merged directives (in read order, includes
/// expanded in place) and any diagnostics.
#[derive(Debug, Default)]
pub struct LoadedConfig {
    pub config: Config,
    pub diagnostics: Vec<Diagnostic>,
    /// The files read, in order (the main file then each included file).
    pub files_read: Vec<String>,
}

/// chrony `CNF_ReadFile`: read `filename` line by line, parse each line, and expand any
/// `include <pattern>` directives by recursively reading the matched files in glob order. The
/// `MAX_INCLUDE_LEVEL` guard prevents runaway recursion (chrony `LOG_FATAL`s; here the include
/// is skipped with a diagnostic). A file that cannot be opened yields a diagnostic.
pub fn read_file(filename: &str) -> LoadedConfig {
    let mut out = LoadedConfig::default();
    read_file_at(filename, 1, &mut out);
    out
}

fn read_file_at(filename: &str, level: u32, out: &mut LoadedConfig) {
    if level > MAX_INCLUDE_LEVEL {
        out.diagnostics.push(Diagnostic::error(
            0,
            "CFG_INCLUDE_DEPTH",
            format!("Maximum include level reached at {filename}"),
        ));
        return;
    }
    let text = match std::fs::read_to_string(filename) {
        Ok(t) => t,
        Err(_) => {
            out.diagnostics.push(Diagnostic::error(
                0,
                "CFG_OPEN",
                format!("Could not open configuration file {filename}"),
            ));
            return;
        }
    };
    out.files_read.push(filename.to_string());

    // Parse line by line (matching CNF_ReadFile's fgets loop), so a truncated line is diagnosed
    // exactly where chrony does and the line numbers line up.
    for (i, line) in text.lines().enumerate() {
        let line_no = i + 1;
        if line.len() > MAX_LINE_LENGTH {
            out.diagnostics.push(
                Diagnostic::error(line_no, "CFG_LINE_TOO_LONG", "String too long".to_string()),
            );
            continue;
        }
        let mut parsed = parse(line);
        // Renumber the single-line parse's diagnostics/directives to the real line number.
        for (ln, d) in parsed.config.directives.drain(..) {
            let _ = ln;
            // Expand includes in place; keep everything else.
            if let Directive::Include { pattern } = &d {
                for path in glob_paths(pattern, filename) {
                    read_file_at(&path, level + 1, out);
                }
            } else {
                out.config.directives.push((line_no, d));
            }
        }
        for mut diag in parsed.diagnostics {
            diag.line_no = line_no;
            out.diagnostics.push(diag);
        }
    }
}

/// chrony `load_source_file`: read a `*.sources` file, parsing each `server`/`pool`/`peer`
/// line. chrony requires every line to be newline-terminated and stops at the first line that
/// is not (a truncated final line is ignored). Returns the source directives in file order.
pub fn load_source_file(filename: &str) -> Vec<Directive> {
    let text = match std::fs::read_to_string(filename) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut sources = Vec::new();
    // chrony breaks at the first line whose fgets buffer did not end in '\n' (i.e. a final line
    // without a trailing newline). `str::lines()` drops the terminator, so detect it explicitly.
    let terminated_prefix = match text.rfind('\n') {
        Some(pos) => &text[..=pos],
        None => "", // no complete line at all
    };
    for line in terminated_prefix.lines() {
        let parsed = parse(line);
        for (_, d) in parsed.config.directives {
            if matches!(d, Directive::Source(_)) {
                sources.push(d);
            }
        }
    }
    sources
}

/// chrony `search_dirs`: across `dirs` (in directive order), find every file ending in
/// `suffix`, then for each distinct basename read the file from the earliest-listed directory
/// that has it (chrony's later-dir-does-not-override + basename-sorted iteration). Returns the
/// chosen paths in basename order.
pub fn search_dirs(dirs: &[&str], suffix: &str) -> Vec<PathBuf> {
    // (basename -> the path from the earliest dir that has it)
    let mut chosen: Vec<(String, PathBuf)> = Vec::new();
    for dir in dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) if n.ends_with(suffix) => n.to_string(),
                _ => continue,
            };
            // Earliest dir wins: only insert if this basename is unseen.
            if !chosen.iter().any(|(b, _)| *b == name) {
                chosen.push((name, path));
            }
        }
    }
    // chrony sorts the collected paths by basename before reading.
    chosen.sort_by(|a, b| a.0.cmp(&b.0));
    chosen.into_iter().map(|(_, p)| p).collect()
}

/// chrony `CNF_CreateDirs`' directory creation: create `dir` and its parents with `mode`
/// (`UTI_CreateDirAndParents`). Ownership (`uid`/`gid`) is a privileged operation left to the
/// caller. Returns whether the directory exists afterward.
pub fn create_dir_and_parents(dir: &str, mode: u32) -> bool {
    use std::os::unix::fs::DirBuilderExt;
    if Path::new(dir).is_dir() {
        return true;
    }
    std::fs::DirBuilder::new().recursive(true).mode(mode).create(dir).is_ok()
}

/// Expand a glob `pattern` (chrony's `include`/`confdir` use `glob(3)`). Relative patterns are
/// resolved against the including file's directory, as chrony does. Returns matched paths
/// sorted (chrony sorts include matches).
fn glob_paths(pattern: &str, relative_to: &str) -> Vec<String> {
    // Resolve a relative pattern against the including file's directory.
    let full = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        let dir = Path::new(relative_to).parent().map(|p| p.to_path_buf()).unwrap_or_default();
        dir.join(pattern).to_string_lossy().into_owned()
    };
    // Only the trailing-component `*<suffix>` form is supported here (chrony's include patterns
    // are simple globs); an exact path with no wildcard matches itself.
    let path = Path::new(&full);
    if !full.contains('*') {
        return if path.exists() { vec![full] } else { Vec::new() };
    }
    let (dir, file_glob) = match path.parent().zip(path.file_name().and_then(|n| n.to_str())) {
        Some((d, f)) => (d.to_path_buf(), f.to_string()),
        None => return Vec::new(),
    };
    let (prefix, suffix) = match file_glob.split_once('*') {
        Some(ps) => ps,
        None => return Vec::new(),
    };
    let mut matches = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                if name.starts_with(prefix) && name.ends_with(suffix) {
                    matches.push(e.path().to_string_lossy().into_owned());
                }
            }
        }
    }
    matches.sort();
    matches
}
