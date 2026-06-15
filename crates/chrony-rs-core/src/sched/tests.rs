//! Tests for the `sched.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `sched.c`.** A C generator drives
//! the real timer queue through `SCH_MainLoop` with a clock-advancing stubbed
//! `select`, recording the dispatch order and fire times
//! (`research/oracle/sched-c-vectors.txt`). [`matches_real_c_sched_vectors`] replays
//! the identical scenarios (same injected clock/select/LCG) and matches every fired
//! tag and time, including the class-separation spacing, the random in-class delay,
//! and the clock-step shift.
//!
//! **Oracle #2 (independent): file-handler dispatch.** A registered descriptor
//! handler fires for the event the injected `select` reports
//! ([`file_handler_dispatch`]).

use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// The deterministic LCG `UTI_GetRandomBytes` uses, returning a `u32` assembled
/// little-endian from four successive bytes (matching the C stub byte-for-byte).
fn lcg(seed: u64) -> Box<dyn FnMut() -> u32> {
    let mut state = seed;
    Box::new(move || {
        let mut b = [0u8; 4];
        for x in &mut b {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *x = (state >> 33) as u8;
        }
        u32::from_le_bytes(b)
    })
}

/// Build a scheduler whose raw clock and `select` share a clock cell. The clock is
/// a `Timespec` (nanosecond-quantized on every set, exactly as the C stub's
/// `clk_set`/`clk_get` round-trip through `struct timespec`), and `select` advances
/// it to the next deadline (min 1µs, mirroring forward-moving real time).
fn make_sched(clock: Rc<Cell<Timespec>>) -> Scheduler {
    let raw_clock = {
        let c = clock.clone();
        Box::new(move || c.get()) as Box<dyn FnMut() -> Timespec>
    };
    let cook = Box::new(|raw: Timespec| (raw, 0.0)) as Box<dyn FnMut(Timespec) -> (Timespec, f64)>;
    let select_fn = {
        let c = clock.clone();
        Box::new(move |timeout: Option<f64>, _r: &[usize], _w: &[usize], _e: &[usize]| {
            if let Some(d) = timeout {
                let d = if d < 1e-6 { 1e-6 } else { d };
                c.set(Timespec::from_seconds(c.get().as_seconds() + d));
            }
            SelectResult { status: 0, ready_read: vec![], ready_write: vec![], ready_except: vec![] }
        }) as SelectFn
    };
    Scheduler::new(raw_clock, cook, lcg(0x1234567890abcdef), select_fn)
}

/// A recording, self-quitting timeout handler.
fn rec_handler(
    tag: i64,
    log: Rc<RefCell<Vec<(i64, f64)>>>,
    remaining: Rc<Cell<i32>>,
) -> Box<dyn FnMut(&mut Scheduler)> {
    Box::new(move |s: &mut Scheduler| {
        let t = s.now_seconds();
        log.borrow_mut().push((tag, t));
        remaining.set(remaining.get() - 1);
        if remaining.get() <= 0 {
            s.quit_program();
        }
    })
}

/// Parse the fixture into `scenario -> Vec<(tag, time)>`.
fn parse_vectors() -> Vec<Vec<(i64, f64)>> {
    let text = include_str!("../../../../research/oracle/sched-c-vectors.txt");
    let mut scenarios: Vec<Vec<(i64, f64)>> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("SCENARIO") {
            scenarios.push(Vec::new());
        } else if let Some(rest) = line.strip_prefix("FIRE ") {
            let tag: i64 =
                rest.split_whitespace().find_map(|t| t.strip_prefix("tag=")).unwrap().parse().unwrap();
            let t: f64 =
                rest.split_whitespace().find_map(|t| t.strip_prefix("t=")).unwrap().parse().unwrap();
            scenarios.last_mut().unwrap().push((tag, t));
        }
    }
    scenarios
}

#[test]
fn matches_real_c_sched_vectors() {
    let expected = parse_vectors();
    assert_eq!(expected.len(), 2, "two scenarios");

    // ----- Scenario 0: ordering / by-delay / in-class / remove -----
    {
        let base = 1000.0;
        let clock = Rc::new(Cell::new(Timespec::from_seconds(base)));
        let mut s = make_sched(clock);
        let log = Rc::new(RefCell::new(Vec::new()));
        let remaining = Rc::new(Cell::new(7));

        s.add_timeout(Timespec::new(1003, 0), rec_handler(3, log.clone(), remaining.clone()));
        s.add_timeout(Timespec::new(1001, 0), rec_handler(1, log.clone(), remaining.clone()));
        s.add_timeout(Timespec::new(1001, 0), rec_handler(11, log.clone(), remaining.clone()));
        let d = s.add_timeout(Timespec::new(1005, 0), rec_handler(5, log.clone(), remaining.clone()));
        s.add_timeout_by_delay(2.0, rec_handler(2, log.clone(), remaining.clone()));
        s.add_timeout_in_class(0.5, 1.0, 0.0, TimeoutClass::NtpClient, rec_handler(100, log.clone(), remaining.clone()));
        s.add_timeout_in_class(0.5, 1.0, 0.0, TimeoutClass::NtpClient, rec_handler(101, log.clone(), remaining.clone()));
        s.add_timeout_in_class(1.0, 0.5, 0.5, TimeoutClass::NtpPeer, rec_handler(200, log.clone(), remaining.clone()));
        s.remove_timeout(d);

        s.main_loop();
        s.finalise();

        let got = log.borrow();
        assert_eq!(got.len(), expected[0].len(), "scenario 0 fire count");
        for (i, ((gt, gtime), (et, etime))) in got.iter().zip(expected[0].iter()).enumerate() {
            assert_eq!(gt, et, "scenario 0 tag #{i}");
            assert!((gtime - etime).abs() < 1e-9, "scenario 0 time #{i}: {gtime} vs {etime}");
        }
    }

    // ----- Scenario 1: clock step shifts pending timers -----
    {
        let base = 1000.0;
        let clock = Rc::new(Cell::new(Timespec::from_seconds(base)));
        let mut s = make_sched(clock);
        let log = Rc::new(RefCell::new(Vec::new()));
        let remaining = Rc::new(Cell::new(2));

        s.add_timeout(Timespec::new(1002, 0), rec_handler(20, log.clone(), remaining.clone()));
        s.add_timeout(Timespec::new(1004, 0), rec_handler(40, log.clone(), remaining.clone()));
        // handle_slew step: raw=cooked=base, doffset=1.0 -> shift timers by -1.
        s.handle_slew(Timespec::new(1000, 0), 0.0, 1.0, ChangeType::Step);

        s.main_loop();
        s.finalise();

        let got = log.borrow();
        assert_eq!(got.len(), expected[1].len(), "scenario 1 fire count");
        for (i, ((gt, gtime), (et, etime))) in got.iter().zip(expected[1].iter()).enumerate() {
            assert_eq!(gt, et, "scenario 1 tag #{i}");
            assert!((gtime - etime).abs() < 1e-9, "scenario 1 time #{i}: {gtime} vs {etime}");
        }
    }
}

#[test]
fn file_handler_dispatch() {
    // No timers; one descriptor. The injected select reports fd 5 readable once.
    let clock = Rc::new(Cell::new(1000.0));
    let raw_clock = {
        let c = clock.clone();
        Box::new(move || Timespec::from_seconds(c.get())) as Box<dyn FnMut() -> Timespec>
    };
    let cook = Box::new(|raw: Timespec| (raw, 0.0)) as Box<dyn FnMut(Timespec) -> (Timespec, f64)>;
    let fired_once = Rc::new(Cell::new(false));
    let select_fn = {
        let fired_once = fired_once.clone();
        Box::new(move |_t: Option<f64>, rd: &[usize], _w: &[usize], _e: &[usize]| {
            if !fired_once.get() && rd.contains(&5) {
                fired_once.set(true);
                SelectResult { status: 1, ready_read: vec![5], ready_write: vec![], ready_except: vec![] }
            } else {
                SelectResult { status: 0, ready_read: vec![], ready_write: vec![], ready_except: vec![] }
            }
        }) as SelectFn
    };
    let mut s = Scheduler::new(raw_clock, cook, lcg(1), select_fn);

    let events: Rc<RefCell<Vec<(i32, i32)>>> = Rc::new(RefCell::new(Vec::new()));
    let ev = events.clone();
    s.add_file_handler(
        5,
        SCH_FILE_INPUT,
        Box::new(move |sched: &mut Scheduler, fd: i32, event: i32| {
            ev.borrow_mut().push((fd, event));
            sched.quit_program();
        }),
    );

    s.main_loop();
    s.finalise();

    assert_eq!(*events.borrow(), vec![(5, SCH_FILE_INPUT)], "fd 5 read handler fired once");
}

#[test]
fn remove_timeout_and_reentrant_add() {
    // A handler that re-entrantly adds another timeout (re-entrancy must work).
    let clock = Rc::new(Cell::new(Timespec::from_seconds(1000.0)));
    let mut s = make_sched(clock);
    let log = Rc::new(RefCell::new(Vec::new()));

    let log2 = log.clone();
    s.add_timeout(
        Timespec::new(1001, 0),
        Box::new(move |sched: &mut Scheduler| {
            log2.borrow_mut().push(1i64);
            // add a follow-up timeout 1s later from inside the handler
            let log3 = log2.clone();
            sched.add_timeout(
                Timespec::new(1002, 0),
                Box::new(move |s2: &mut Scheduler| {
                    log3.borrow_mut().push(2i64);
                    s2.quit_program();
                }),
            );
        }),
    );

    s.main_loop();
    s.finalise();
    assert_eq!(*log.borrow(), vec![1, 2], "re-entrantly added timeout fires");
}
