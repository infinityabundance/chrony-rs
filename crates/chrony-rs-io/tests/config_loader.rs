//! Integration tests for config-file loading over real files/directories.

use chrony_rs_core::config::model::Directive;
use chrony_rs_io::config_loader::{
    create_dir_and_parents, load_source_file, read_file, search_dirs,
};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("chrony-rs-cfg-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn read_file_expands_includes_in_order() {
    let dir = tmpdir("include");
    let inc = dir.join("extra.conf");
    std::fs::write(&inc, "minsources 3\nmaxdrift 100.0\n").unwrap();
    let main = dir.join("chrony.conf");
    std::fs::write(
        &main,
        format!("port 1123\ninclude {}\nlogbanner 8\n", inc.display()),
    )
    .unwrap();

    let loaded = read_file(main.to_str().unwrap());
    assert!(loaded.diagnostics.is_empty(), "unexpected diagnostics: {:?}", loaded.diagnostics);
    // Two files read: the main file, then the included one.
    assert_eq!(loaded.files_read.len(), 2);
    assert!(loaded.files_read[1].ends_with("extra.conf"));

    // The included directives are present, expanded in place (order: port, [minsources,
    // maxdrift from the include], logbanner).
    let ds = &loaded.config.directives;
    let keywords: Vec<&str> = ds
        .iter()
        .filter_map(|(_, d)| match d {
            Directive::NtpPort(_) => Some("port"),
            Directive::MinSources(_) => Some("minsources"),
            Directive::MaxDrift(_) => Some("maxdrift"),
            Directive::LogBanner(_) => Some("logbanner"),
            _ => None,
        })
        .collect();
    assert_eq!(keywords, vec!["port", "minsources", "maxdrift", "logbanner"]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn read_file_missing_include_and_depth() {
    let dir = tmpdir("missing");
    let main = dir.join("c.conf");
    std::fs::write(&main, format!("include {}/nope.conf\n", dir.display())).unwrap();
    let loaded = read_file(main.to_str().unwrap());
    // A missing literal include is a glob no-match: nothing read, no panic, no extra directives.
    assert_eq!(loaded.files_read.len(), 1, "only the main file was read");
    assert!(loaded.config.directives.is_empty());

    // A missing top-level file diagnoses cleanly (a direct open, not a glob).
    let missing = read_file("/definitely/not/here.conf");
    assert!(missing.diagnostics.iter().any(|d| d.code == "CFG_OPEN"));
    assert!(missing.files_read.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_source_file_parses_terminated_lines_only() {
    let dir = tmpdir("sources");
    let f = dir.join("pool.sources");
    // Two complete server lines, then a final line with NO trailing newline (chrony ignores it).
    std::fs::write(&f, "server a.example.com iburst\nserver b.example.com\nserver c.truncated").unwrap();
    let sources = load_source_file(f.to_str().unwrap());
    assert_eq!(sources.len(), 2, "the unterminated final line must be ignored");
    for d in &sources {
        assert!(matches!(d, Directive::Source(_)));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn search_dirs_dedups_by_basename_earliest_dir_wins() {
    let base = tmpdir("srchdirs");
    let d1 = base.join("d1");
    let d2 = base.join("d2");
    std::fs::create_dir_all(&d1).unwrap();
    std::fs::create_dir_all(&d2).unwrap();
    // d1 has a.sources + b.sources; d2 has a.sources (shadowed) + c.sources.
    std::fs::write(d1.join("a.sources"), "server d1a\n").unwrap();
    std::fs::write(d1.join("b.sources"), "server d1b\n").unwrap();
    std::fs::write(d2.join("a.sources"), "server d2a\n").unwrap();
    std::fs::write(d2.join("c.sources"), "server d2c\n").unwrap();
    // A non-matching file is ignored.
    std::fs::write(d1.join("ignore.txt"), "x\n").unwrap();

    let chosen = search_dirs(&[d1.to_str().unwrap(), d2.to_str().unwrap()], ".sources");
    let names: Vec<String> =
        chosen.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
    // Basename-sorted: a, b, c.
    assert_eq!(names, vec!["a.sources", "b.sources", "c.sources"]);
    // a.sources resolves to d1 (earliest dir wins).
    assert!(chosen[0].starts_with(&d1), "a.sources should come from d1, got {:?}", chosen[0]);
    assert!(chosen[2].starts_with(&d2), "c.sources should come from d2");

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn create_dir_and_parents_makes_nested() {
    let base = tmpdir("mkdir");
    let nested = base.join("a/b/c");
    assert!(create_dir_and_parents(nested.to_str().unwrap(), 0o750));
    assert!(nested.is_dir());
    // Idempotent on an existing directory.
    assert!(create_dir_and_parents(nested.to_str().unwrap(), 0o750));
    let _ = std::fs::remove_dir_all(&base);
}
