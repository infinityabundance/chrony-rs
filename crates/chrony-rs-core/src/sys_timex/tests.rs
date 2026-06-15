//! Tests for the `sys_timex.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `sys_timex.c`** (+ `sys_generic.c`,
//! `-DLINUX`). A C generator replaces `adjtimex` with a recording stub modeling a
//! kernel frequency register and captures every submitted `struct timex` across an
//! initialise / set-frequency / set-sync-status / set-leap sequence
//! (`research/oracle/sys_timex-c-vectors.txt`). [`matches_real_c_sys_timex_vectors`]
//! drives the identical sequence and asserts every submitted `timex` (masked by
//! `modes`, exactly what the kernel reads) matches.
//!
//! **Oracle #2 (independent): the ppm⇄kernel-freq scaling.** `freq = ppm·-2^16` and
//! `ppm = -freq/2^16`, checked directly.

use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// One submitted `timex`, masked to the fields the kernel reads for `modes` (the
/// same masking the C stub applies, so the comparison is field-for-field).
#[derive(Debug, PartialEq, Eq)]
struct Submission {
    modes: u32,
    freq: i64,
    status: i32,
    offset: i64,
    esterror: i64,
    maxerror: i64,
    constant: i64,
}

fn mask(txc: &Timex) -> Submission {
    let m = txc.modes;
    Submission {
        modes: m,
        freq: if m & MOD_FREQUENCY != 0 { txc.freq } else { 0 },
        status: if m & MOD_STATUS != 0 { txc.status } else { 0 },
        offset: if m & MOD_OFFSET != 0 { txc.offset } else { 0 },
        esterror: if m & MOD_ESTERROR != 0 { txc.esterror } else { 0 },
        maxerror: if m & MOD_MAXERROR != 0 { txc.maxerror } else { 0 },
        constant: if m & (MOD_TIMECONST | MOD_TAI) != 0 { txc.constant } else { 0 },
    }
}

fn parse_vectors() -> (Vec<Submission>, f64) {
    let text = include_str!("../../../../research/oracle/sys_timex-c-vectors.txt");
    let mut subs = Vec::new();
    let mut base = f64::NAN;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("BASE") {
            base = line.split("base_freq=").nth(1).unwrap().parse().unwrap();
        } else if line.starts_with("TMX") {
            let get = |k: &str| -> &str {
                line.split_whitespace()
                    .find_map(|t| t.strip_prefix(&format!("{k}=")))
                    .unwrap()
            };
            let h = |s: &str| i64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
            subs.push(Submission {
                modes: h(get("modes")) as u32,
                freq: get("freq").parse().unwrap(),
                status: h(get("status")) as i32,
                offset: get("offset").parse().unwrap(),
                esterror: get("esterror").parse().unwrap(),
                maxerror: get("maxerror").parse().unwrap(),
                constant: get("constant").parse().unwrap(),
            });
        }
    }
    (subs, base)
}

#[test]
fn matches_real_c_sys_timex_vectors() {
    let (expected, base_freq) = parse_vectors();

    // The recording adjtimex stub: model a kernel frequency register, capture each
    // masked submission, write the frequency back, return TIME_OK.
    let log: Rc<RefCell<Vec<Submission>>> = Rc::new(RefCell::new(Vec::new()));
    let kernel_freq = Rc::new(Cell::new(0i64));
    let adjtimex = {
        let log = log.clone();
        let kernel_freq = kernel_freq.clone();
        Box::new(move |txc: &mut Timex| -> i32 {
            if txc.modes & MOD_FREQUENCY != 0 {
                kernel_freq.set(txc.freq);
            }
            log.borrow_mut().push(mask(txc));
            txc.freq = kernel_freq.get();
            TIME_OK
        }) as Box<dyn FnMut(&mut Timex) -> i32>
    };

    // Drive the exact sequence the C generator runs (directly on the driver — for
    // set_frequency the value reaching the driver equals the requested ppm, so the
    // submitted timex is identical to going through sys_generic).
    let mut t = SysTimex::new(adjtimex, true); // initialise_timex: submits #1, #2
    let read_base = t.read_frequency(); // submit #3 (modes 0)
    assert_eq!(read_base, base_freq, "read_frequency after init == BASE");

    assert_eq!(t.set_frequency(50.0), 50.0, "set_frequency echoes 50 ppm"); // #4
    assert_eq!(t.set_frequency(-123.5), -123.5, "set_frequency echoes -123.5 ppm"); // #5

    t.set_sync_status(true, 0.001, 0.005); // #6
    t.set_sync_status(true, 0.001, 20.0); // #7
    t.set_sync_status(false, 0.0, 0.0); // #8

    t.set_leap(1, 37); // #9, #10
    t.set_leap(-1, 37); // #11, #12
    t.set_leap(0, 37); // #13, #14

    t.set_frequency(-123.5); // #15 (finalise sets clamp(base_freq))

    let got = log.borrow();
    assert_eq!(got.len(), expected.len(), "submission count");
    for (i, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
        assert_eq!(g, e, "submission #{i}");
    }
}

#[test]
fn independent_ppm_to_kernel_freq_scaling() {
    // freq = ppm * -2^16; ppm = -freq / 2^16. Checked without the C arithmetic.
    let log: Rc<RefCell<Vec<i64>>> = Rc::new(RefCell::new(Vec::new()));
    let kernel_freq = Rc::new(Cell::new(0i64));
    let adjtimex = {
        let log = log.clone();
        let kernel_freq = kernel_freq.clone();
        Box::new(move |txc: &mut Timex| -> i32 {
            if txc.modes & MOD_FREQUENCY != 0 {
                kernel_freq.set(txc.freq);
                log.borrow_mut().push(txc.freq);
            }
            txc.freq = kernel_freq.get();
            TIME_OK
        }) as Box<dyn FnMut(&mut Timex) -> i32>
    };
    let mut t = SysTimex::new(adjtimex, true);

    for &ppm in &[0.0, 1.0, -1.0, 50.0, -123.5, 500.0] {
        let echoed = t.set_frequency(ppm);
        let submitted = *log.borrow().last().unwrap();
        assert_eq!(submitted, (ppm * -65536.0) as i64, "kernel freq for {ppm} ppm");
        assert!((echoed - ppm).abs() < 1e-9, "round-trip ppm for {ppm}: got {echoed}");
    }
}

#[test]
fn composition_with_sys_generic_routes_set_frequency() {
    // SYS_Timex_InitialiseWithFunctions builds a working SysGeneric; setting the
    // frequency through the generic layer reaches the kernel as ppm·-2^16.
    let last_kernel_freq = Rc::new(Cell::new(i64::MIN));
    let kernel_freq = Rc::new(Cell::new(0i64));
    let adjtimex = {
        let last = last_kernel_freq.clone();
        let kernel_freq = kernel_freq.clone();
        Box::new(move |txc: &mut Timex| -> i32 {
            if txc.modes & MOD_FREQUENCY != 0 {
                kernel_freq.set(txc.freq);
                last.set(txc.freq);
            }
            txc.freq = kernel_freq.get();
            TIME_OK
        }) as Box<dyn FnMut(&mut Timex) -> i32>
    };

    let now = Rc::new(Cell::new(1_700_000_000.0_f64));
    let raw_clock = {
        let now = now.clone();
        Box::new(move || Timespec::from_seconds(now.get())) as Box<dyn FnMut() -> Timespec>
    };

    let mut sg = SysTimex::initialise(
        adjtimex,
        true,
        83333.333,
        raw_clock,
        Box::new(|_| {}),
        None,
    );

    // No outstanding offset, so the generic layer sets exactly the base frequency.
    sg.set_frequency(42.0);
    assert_eq!(last_kernel_freq.get(), (42.0 * -65536.0) as i64, "42 ppm reached the kernel");
}
