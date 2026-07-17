//! Integration test for file logging: write real statistics-log records and verify the banner
//! cadence and content on disk.

use chrony_rs_core::config::accessors::ConfigValues;
use chrony_rs_core::config::parse;
use chrony_rs_io::logging::LogFiles;

#[test]
fn file_write_emits_banner_and_records() {
    // A temp logdir + logbanner 3 (a banner every third write).
    let mut dir = std::env::temp_dir();
    dir.push(format!("chrony-rs-log-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let logdir = dir.to_string_lossy().into_owned();

    let cfg: ConfigValues =
        ConfigValues::resolve(&parse(&format!("logdir {logdir}\nlogbanner 3\n")).config);

    let mut logs = LogFiles::new();
    let id = logs.file_open("tracking", "Date  Time  Value");
    assert_eq!(id, 0);

    // Five records; banners precede writes 0 and 3.
    for i in 0..5 {
        logs.file_write(&cfg, id, &format!("record {i}"));
    }

    let path = dir.join("tracking.log");
    let content = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Expected: [banner x3] record0 record1 record2 [banner x3] record3 record4
    assert_eq!(lines[0], "=================");
    assert_eq!(lines[1], "Date  Time  Value");
    assert_eq!(lines[2], "=================");
    assert_eq!(lines[3], "record 0");
    assert_eq!(lines[4], "record 1");
    assert_eq!(lines[5], "record 2");
    assert_eq!(lines[6], "================="); // banner before the 4th write (writes % 3 == 0)
    assert_eq!(lines[7], "Date  Time  Value");
    assert_eq!(lines[8], "=================");
    assert_eq!(lines[9], "record 3");
    assert_eq!(lines[10], "record 4");

    // Cycle closes the file; a further write reopens (append) and continues.
    logs.cycle_log_files();
    logs.file_write(&cfg, id, "record 5");
    let content2 = std::fs::read_to_string(&path).unwrap();
    assert!(content2.ends_with("record 5\n"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_file_log_appends_to_the_message_log() {
    use std::io::Write;
    let mut p = std::env::temp_dir();
    p.push(format!("chrony-rs-msglog-{}.log", std::process::id()));
    let path = p.to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&path);

    // LOG_OpenFileLog(path) opens the message log in append mode.
    let mut f = chrony_rs_io::logging::open_file_log(Some(&path)).expect("open");
    writeln!(f, "2023-11-14T22:13:20Z started").unwrap();
    drop(f);
    // Reopening appends rather than truncating.
    let mut f2 = chrony_rs_io::logging::open_file_log(Some(&path)).expect("reopen");
    writeln!(f2, "2023-11-14T22:13:21Z again").unwrap();
    drop(f2);

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("started") && content.contains("again"));
    assert_eq!(content.lines().count(), 2, "append, not truncate");
    // A None log file selects stderr in chrony; here it yields None.
    assert!(chrony_rs_io::logging::open_file_log(None).is_none());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_write_without_logdir_is_disabled() {
    // No logdir configured -> the first write disables the log (no panic, no file).
    let cfg = ConfigValues::resolve(&parse("").config);
    let mut logs = LogFiles::new();
    let id = logs.file_open("stats", "banner");
    logs.file_write(&cfg, id, "should be dropped");
    // A second write is a no-op (name cleared); still no panic.
    logs.file_write(&cfg, id, "also dropped");
    assert_eq!(logs.len(), 1);
}
