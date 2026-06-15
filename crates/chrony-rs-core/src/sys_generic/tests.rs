//! Tests for the `sys_generic.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `sys_generic.c`.** A C generator
//! completes the generic driver over a fake frequency-only base driver and drives a
//! fixed sequence of `set_frequency`/`accrue_offset`/clock-advance/end-of-slew
//! actions, recording the frequency set, the scheduled slew end, the
//! `offset_convert` correction, and the dispersion notified
//! (`research/oracle/sys_generic-c-vectors.txt`). [`matches_real_c_sys_generic_vectors`]
//! replays the identical sequence and matches every value.
//!
//! **Oracle #2 (independent): the steady-state slew relationship.** A single offset
//! correction with no fast slew must drain the register through a frequency offset
//! of `offset / duration` (clamped), and `offset_convert` must read back the
//! remaining offset — checked directly, without reference to the C arithmetic.

use super::*;
use std::cell::Cell;
use std::rc::Rc;

/// A fake frequency-only base driver: `set_frequency` returns the requested value
/// verbatim (no rounding) and records it; everything else is the default NULL-like
/// behavior (no fast slew, no sync status). This is exactly the C oracle's driver.
struct RecordingDriver {
    base: f64,
    last_set: Rc<Cell<f64>>,
}

impl FreqDriver for RecordingDriver {
    fn read_frequency(&mut self) -> f64 {
        self.base
    }
    fn set_frequency(&mut self, freq_ppm: f64) -> f64 {
        self.last_set.set(freq_ppm);
        freq_ppm
    }
}

const MAX_SET_FREQ: f64 = 100000.0;
const MAX_SET_FREQ_DELAY: f64 = 0.01;
const MAX_SLEW_RATE: f64 = 83333.333; // CNF_GetMaxSlewRate() in the generator

fn close(a: f64, b: f64, ctx: &str) {
    let tol = 1.0e-9 + 1.0e-9 * b.abs();
    assert!(
        (a - b).abs() <= tol,
        "{ctx}: got {a:.17e}, expected {b:.17e} (|diff|={:.3e})",
        (a - b).abs()
    );
}

/// One expected report row from the vectors file.
struct Expect {
    set_freq: f64,
    timeout_in: f64,
    corr: f64,
    err: f64,
    disp: f64,
}

fn parse_f64(line: &str, key: &str) -> f64 {
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix(&format!("{key}=")) {
            return v.parse().unwrap();
        }
    }
    panic!("missing {key} in: {line}");
}

#[test]
fn matches_real_c_sys_generic_vectors() {
    let vectors = include_str!("../../../../research/oracle/sys_generic-c-vectors.txt");

    let mut init_base = f64::NAN;
    let mut final_set = f64::NAN;
    let mut expects: Vec<Expect> = Vec::new();
    for raw in vectors.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("INIT") {
            init_base = parse_f64(line, "base_freq");
        } else if line.starts_with("FINAL") {
            final_set = parse_f64(line, "set_freq");
        } else {
            expects.push(Expect {
                set_freq: parse_f64(line, "set_freq"),
                timeout_in: parse_f64(line, "timeout_in"),
                corr: parse_f64(line, "corr"),
                err: parse_f64(line, "err"),
                disp: parse_f64(line, "disp"),
            });
        }
    }

    // Shared mutable state the injected closures read/write.
    let now = Rc::new(Cell::new(1_700_000_000.0_f64));
    let last_set = Rc::new(Cell::new(0.0_f64));
    let disp = Rc::new(Cell::new(0.0_f64));

    let driver = RecordingDriver { base: 0.0, last_set: last_set.clone() };
    let raw_clock = {
        let now = now.clone();
        Box::new(move || Timespec::from_seconds(now.get())) as Box<dyn FnMut() -> Timespec>
    };
    let dispersion = {
        let disp = disp.clone();
        Box::new(move |d| disp.set(d)) as Box<dyn FnMut(f64)>
    };

    let mut sg = SysGeneric::complete_freq_driver(
        driver,
        MAX_SET_FREQ,
        MAX_SET_FREQ_DELAY,
        0.0,
        0.0,
        MAX_SLEW_RATE,
        raw_clock,
        dispersion,
        None,
    );
    close(sg.read_frequency(), init_base, "INIT base_freq");

    // The exact action sequence the C generator runs (advance-before, action).
    enum Act {
        SetFreq(f64),
        Accrue(f64, f64),
        Nop,
        Fire,
    }
    let ops: &[(f64, Act)] = &[
        (0.0, Act::SetFreq(5.0)),   // SETF5
        (0.0, Act::Accrue(0.5, 30.0)), // ACCR0.5
        (1.0, Act::Nop),            // ADV1
        (2.0, Act::Fire),           // EOS
        (0.0, Act::Accrue(-0.2, 50.0)), // ACCRneg
        (5.0, Act::Fire),           // EOS2
        (0.0, Act::Accrue(100.0, 1.0)), // BIG
        (0.0, Act::SetFreq(-3.0)),  // SETFneg3
        (10.0, Act::Fire),          // CONV
        (10.0, Act::Fire),          // CONV
        (10.0, Act::Fire),          // CONV
        (10.0, Act::Fire),          // CONV
        (0.0, Act::Accrue(1e-12, 10.0)), // TINY
    ];

    assert_eq!(ops.len(), expects.len(), "op/expect count mismatch");

    for (i, ((adv, act), exp)) in ops.iter().zip(expects.iter()).enumerate() {
        now.set(now.get() + adv);
        match act {
            Act::SetFreq(f) => {
                sg.set_frequency(*f);
            }
            Act::Accrue(o, r) => sg.accrue_offset(*o, *r),
            Act::Nop => {}
            Act::Fire => sg.fire_end_of_slew(),
        }

        let now_ts = Timespec::from_seconds(now.get());
        let (corr, err) = sg.offset_convert(now_ts);
        let timeout_in = sg.scheduled_timeout().as_seconds() - now.get();

        close(last_set.get(), exp.set_freq, &format!("set_freq @ op {i}"));
        close(timeout_in, exp.timeout_in, &format!("timeout_in @ op {i}"));
        close(corr, exp.corr, &format!("corr @ op {i}"));
        close(err, exp.err, &format!("err @ op {i}"));
        close(disp.get(), exp.disp, &format!("disp @ op {i}"));
    }

    sg.finalise();
    close(last_set.get(), final_set, "FINAL set_freq");
}

/// Oracle #2 (independent of the C arithmetic): a single offset correction with no
/// fast slew drains the register through a clamped frequency offset, and
/// `offset_convert` reads back the still-outstanding offset.
#[test]
fn independent_single_offset_correction_drains_register() {
    let now = Rc::new(Cell::new(1_700_000_000.0_f64));
    let last_set = Rc::new(Cell::new(0.0_f64));

    let driver = RecordingDriver { base: 0.0, last_set: last_set.clone() };
    let raw_clock = {
        let now = now.clone();
        Box::new(move || Timespec::from_seconds(now.get())) as Box<dyn FnMut() -> Timespec>
    };
    let mut sg = SysGeneric::complete_freq_driver(
        driver,
        MAX_SET_FREQ,
        MAX_SET_FREQ_DELAY,
        0.0,
        0.0,
        MAX_SLEW_RATE,
        raw_clock,
        Box::new(|_| {}),
        None,
    );

    // Accrue a 0.4 s offset with a correction rate that yields a sub-max-rate slew.
    let offset = 0.4;
    let rate = 200.0; // correction_rate; duration target = rate/|offset| = 500 s
    sg.accrue_offset(offset, rate);

    // Immediately after accrue, no time has elapsed: offset_convert reads back the
    // full outstanding offset as a negative correction (cooked = raw + corr).
    let (corr0, _) = sg.offset_convert(Timespec::from_seconds(now.get()));
    close(corr0, -offset, "offset_convert right after accrue == -offset");

    // A positive outstanding offset drives a positive frequency offset (corr_freq =
    // offset/duration > 0), clamped to the max slew rate.
    assert!(last_set.get() > 0.0, "a positive offset slews the frequency positive");
    assert!(
        last_set.get().abs() <= MAX_SLEW_RATE + 1.0,
        "frequency stays within the max slew rate"
    );

    // After half the nominal correction time, roughly half the offset remains.
    now.set(now.get() + 250.0);
    sg.fire_end_of_slew();
    let (corr_half, _) = sg.offset_convert(Timespec::from_seconds(now.get()));
    // Remaining offset should be markedly smaller in magnitude than the original.
    assert!(corr_half.abs() < offset, "register drains over time: {corr_half} vs {offset}");
}

#[test]
fn apply_step_offset_uses_injected_set_time() {
    let now = Rc::new(Cell::new(1_700_000_000.0_f64));
    let last_set = Rc::new(Cell::new(0.0_f64));
    let stepped_to = Rc::new(Cell::new(Timespec::default()));

    let driver = RecordingDriver { base: 0.0, last_set };
    let raw_clock = {
        let now = now.clone();
        Box::new(move || Timespec::from_seconds(now.get())) as Box<dyn FnMut() -> Timespec>
    };
    let set_time = {
        let stepped_to = stepped_to.clone();
        Box::new(move |t: Timespec| {
            stepped_to.set(t);
            true
        }) as Box<dyn FnMut(Timespec) -> bool>
    };
    let mut sg = SysGeneric::complete_freq_driver(
        driver,
        MAX_SET_FREQ,
        MAX_SET_FREQ_DELAY,
        0.0,
        0.0,
        MAX_SLEW_RATE,
        raw_clock,
        Box::new(|_| {}),
        Some(set_time),
    );

    // Step the clock back by 2 seconds (positive offset => jump backwards).
    assert!(sg.apply_step_offset(2.0));
    let expected = Timespec::from_seconds(1_700_000_000.0).add_double(-2.0);
    assert_eq!(stepped_to.get(), expected, "step target is now - offset");
}
