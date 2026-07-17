//! Tests for the `rtc.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `rtc.c`** (`-DLINUX -DFEAT_RTC`,
//! its `RTC_Linux_*` driver replaced by recording stubs). A C generator drives the
//! initialise decision tree and the forwarded lifecycle/measurement calls, recording
//! the driver/clock call log and return codes
//! (`research/oracle/rtc-c-vectors.txt`). [`matches_real_c_rtc_vectors`] replays the
//! same scenarios and matches the log; [`rtcfile_with_rtcsync_is_fatal`] covers the
//! fatal case.

use super::*;
use std::cell::RefCell;
use std::rc::Rc;

type Log = Rc<RefCell<Vec<String>>>;

/// A recording RTC driver mirroring the C oracle's `RTC_Linux_*` stubs.
struct RecDriver {
    log: Log,
    init_ret: bool,
    preinit_ret: bool,
    write_ret: i32,
    trim_ret: i32,
}

impl RtcDriver for RecDriver {
    fn init(&mut self) -> bool {
        self.log.borrow_mut().push(format!("INIT ret={}", self.init_ret as i32));
        self.init_ret
    }
    fn finalise(&mut self) {
        self.log.borrow_mut().push("FINI".into());
    }
    fn time_pre_init(&mut self, t: i64) -> bool {
        self.log.borrow_mut().push(format!("PREINIT t={t} ret={}", self.preinit_ret as i32));
        self.preinit_ret
    }
    fn time_init(&mut self, mut after_hook: Box<dyn FnMut()>) {
        self.log.borrow_mut().push("TIMEINIT".into());
        after_hook();
    }
    fn start_measurements(&mut self) {
        self.log.borrow_mut().push("START".into());
    }
    fn write_parameters(&mut self) -> i32 {
        self.log.borrow_mut().push(format!("WRITE ret={}", self.write_ret));
        self.write_ret
    }
    fn get_report(&mut self) -> Option<RtcReport> {
        self.log.borrow_mut().push("GETREPORT".into());
        Some(RtcReport::default())
    }
    fn trim(&mut self) -> i32 {
        self.log.borrow_mut().push(format!("TRIM ret={}", self.trim_ret));
        self.trim_ret
    }
}

/// Build a manager matching the C generator: drift-file mtime 1700000100, cooked
/// time 1700000000, `apply_step` logs and succeeds.
fn make_manager(log: Log, rtc_sync: bool, preinit_ret: bool) -> RtcManager {
    let driver = RecDriver {
        log: log.clone(),
        init_ret: true,
        preinit_ret,
        write_ret: 0,
        trim_ret: 0,
    };
    let step_log = log.clone();
    RtcManager::new(
        Some(Box::new(driver)),
        Some("/rtcfile".to_string()),
        rtc_sync,
        Box::new(|| 1_700_000_100),
        Box::new(|| 1_700_000_000),
        Box::new(move |off| {
            step_log.borrow_mut().push(format!("STEP off={off:.1}"));
            true
        }),
    )
}

/// Drive scenario 0 or 1 and return the call log.
fn run_scenario(sc: u32) -> Vec<String> {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let preinit = sc == 0; // sc0: pre-init ok; sc1: pre-init fails
    let mut rtc = make_manager(log.clone(), false, preinit);

    rtc.initialise(true);
    {
        let hook_log = log.clone();
        rtc.time_init(Box::new(move || hook_log.borrow_mut().push("HOOK".into())));
    }
    rtc.start_measurements();
    let t = rtc.trim();
    log.borrow_mut().push(format!("TRIMRET={t}"));
    let w = rtc.write_parameters();
    log.borrow_mut().push(format!("WRITERET={w}"));
    let g = rtc.get_report();
    log.borrow_mut().push(format!("GETRET={}", g.is_some() as i32));
    rtc.finalise();

    let out = log.borrow().clone();
    out
}

/// Parse the fixture into `scenario -> Vec<line>` (excluding the SCENARIO header).
fn parse_scenarios() -> Vec<Vec<String>> {
    let text = include_str!("../../../../research/oracle/rtc-c-vectors.txt");
    let mut scs: Vec<Vec<String>> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("SCENARIO") {
            scs.push(Vec::new());
        } else {
            scs.last_mut().unwrap().push(line.to_string());
        }
    }
    scs
}

#[test]
fn matches_real_c_rtc_vectors() {
    let scs = parse_scenarios();
    assert_eq!(scs.len(), 3, "three scenarios");

    assert_eq!(run_scenario(0), scs[0], "scenario 0 (pre-init ok) call log");
    assert_eq!(run_scenario(1), scs[1], "scenario 1 (pre-init fail -> drift step) call log");
}

#[test]
fn rtcfile_with_rtcsync_is_fatal() {
    // Scenario 2: rtcfile + rtcsync -> chrony LOG_FATAL (a panic here).
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut rtc = make_manager(log.clone(), true, true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rtc.initialise(true)));
    assert!(result.is_err(), "rtcfile + rtcsync must be fatal");
    // The pre-init ran (and logged) before the fatal rtcfile/rtcsync check.
    assert_eq!(log.borrow()[0], "PREINIT t=1700000100 ret=1");
}

#[test]
fn no_driver_forwards_to_safe_defaults() {
    // chrony's all-NULL driver table: no driver loaded, dispatch returns safe values.
    let mut rtc = RtcManager::new(
        None,
        None, // no rtcfile -> driver not loaded
        false,
        Box::new(|| 0),
        Box::new(|| 1_700_000_000),
        Box::new(|_| false),
    );
    rtc.initialise(true);
    assert_eq!(rtc.write_parameters(), RTC_ST_NODRV, "no driver -> RTC_ST_NODRV");
    assert_eq!(rtc.trim(), 0);
    assert_eq!(rtc.get_report(), None);
    // time_init with no usable driver calls the hook directly.
    let called = Rc::new(RefCell::new(false));
    let c = called.clone();
    rtc.time_init(Box::new(move || *c.borrow_mut() = true));
    assert!(*called.borrow(), "after_hook called directly when no driver");
}
