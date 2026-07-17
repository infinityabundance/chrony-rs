//! Tests for the `refclock.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `refclock.c`** (+ `array.c`,
//! `memory.c`). A C generator registers an SHM and a PPS refclock, then drives
//! `RCL_AddSample` (accepted + stale-time rejected) and `RCL_AddCookedPulse`
//! (PPS-interval folding in both directions + unsynchronised-reference rejection)
//! over recording `SPF_*`/`SRC_*`/`REF_*`/`LCL_*` stubs, capturing the exact offset
//! and dispersion handed to the sample filter and the accept/reject decision
//! (`research/oracle/refclock-c-vectors.txt`). [`matches_real_c_refclock_vectors`]
//! replays the identical inputs through [`RefclockManager`] over a recording
//! [`RefclockHost`] and matches every value.
//!
//! **Oracle #2 (independent): the driver-option parser and refid derivation.** The
//! `':'`-separated option lookup and the auto-generated refid are unit-tested.

use super::*;

/// A recording host mirroring the C oracle's stubs.
#[derive(Default)]
struct RecHost {
    correction: f64,
    disp: f64,
    cooked: Timespec,
    ref_params: RefParams,
    tai_offset: i32,
    next_id: u32,
    acc_n: i32,
    acc_off: f64,
    acc_disp: f64,
    dropped: i32,
}

impl RefclockHost for RecHost {
    fn spf_accumulate_sample(&mut self, _idx: usize, sample: &Sample) -> bool {
        self.acc_off = sample.offset;
        self.acc_disp = sample.peer_dispersion;
        self.acc_n += 1;
        true
    }
    fn spf_get_last_sample(&mut self, _idx: usize) -> Option<Sample> {
        None
    }
    fn spf_get_avg_sample_dispersion(&mut self, _idx: usize) -> f64 {
        0.0
    }
    fn spf_drop_samples(&mut self, _idx: usize) {
        self.dropped += 1;
    }
    fn spf_get_filtered_sample(&mut self, _idx: usize) -> Option<Sample> {
        None
    }
    fn spf_slew_samples(&mut self, _idx: usize, _now: Timespec, _dfreq: f64, _doffset: f64) {}
    fn spf_correct_offset(&mut self, _idx: usize, _correction: f64) {}
    fn spf_add_dispersion(&mut self, _idx: usize, _dispersion: f64) {}

    fn src_accumulate_sample(&mut self, _idx: usize, _sample: &Sample) {}
    fn src_reset_instance(&mut self, _idx: usize) {}
    fn src_update_reachability(&mut self, _idx: usize, _reachable: bool) {}
    fn src_update_status(&mut self, _idx: usize, _stratum: i32, _leap: i32) {}
    fn src_select_source(&mut self, _idx: usize) {}
    fn src_set_active(&mut self, _idx: usize) {}
    fn src_get_tracking_data(&mut self, _idx: usize) -> Option<TrackingData> {
        None
    }

    fn ref_get_reference_params(&mut self, _ts: Timespec) -> RefParams {
        self.ref_params
    }
    fn ref_get_tai_offset(&mut self, _ts: Timespec) -> i32 {
        self.tai_offset
    }
    fn ref_adjust_reference(&mut self, _doffset: f64, _dfreq: f64) -> bool {
        true
    }

    fn lcl_get_offset_correction(&mut self, _ts: Timespec) -> (f64, f64) {
        (self.correction, self.disp)
    }
    fn lcl_read_cooked_time(&mut self) -> Timespec {
        self.cooked
    }
    fn lcl_sys_precision(&mut self) -> f64 {
        1.0e-9
    }

    fn sch_add_timeout_by_delay(&mut self, _delay: f64) -> u32 {
        self.next_id += 1;
        self.next_id
    }
    fn log_sample(&mut self, _line: &str) {}
    fn log_message(&mut self, _msg: &str) {}
}

/// A driver with `init` only (no `poll`), like the oracle's SHM/PPS stubs.
struct InitDriver;
impl RefclockDriver for InitDriver {
    fn has_init(&self) -> bool {
        true
    }
}

fn base(name: &str, ref_id: u32) -> RefclockParameters {
    RefclockParameters {
        driver_name: name.to_string(),
        driver_parameter: String::new(),
        driver_poll: 4,
        poll: 4,
        filter_length: 64,
        pps_rate: 1,
        offset: 0.0,
        delay: 1.0e-3,
        precision: 1.0e-6,
        stratum: 0,
        max_dispersion: 1.0,
        max_samples: 16,
        ref_id,
        ..Default::default()
    }
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}
fn close(a: f64, b: f64, what: &str) {
    let tol = 1e-12 * (1.0 + a.abs().max(b.abs()));
    assert!((a - b).abs() <= tol, "{what}: rust={a:.17e} c={b:.17e}");
}

#[test]
fn matches_real_c_refclock_vectors() {
    let vectors = include_str!("../../../../research/oracle/refclock-c-vectors.txt");
    let line = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    let mut host = RecHost::new_defaults();
    let mut mgr = RefclockManager::new(false);
    let shm = mgr.add_refclock(&mut host, Box::new(InitDriver), base("SHM", 0x4750_5300));
    let pps = mgr.add_refclock(&mut host, Box::new(InitDriver), base("PPS", 0x5050_5300));
    mgr.start_refclocks(&mut host);
    assert_eq!((shm, pps), (0, 1));

    // ---- AddSample: raw_offset = +0.01, correction 0.0005, disp 1e-7 ----
    host.correction = 0.0005;
    host.disp = 1.0e-7;
    host.cooked = Timespec { sec: 2_000_000_001, nsec: 0 };
    let st = Timespec { sec: 2_000_000_000, nsec: 0 };
    let rt = Timespec { sec: 2_000_000_000, nsec: 10_000_000 };
    host.acc_n = 0;
    let r = mgr.add_sample(&mut host, shm, st, rt, LEAP_NORMAL);
    let l = line("SAMPLE");
    assert_eq!(r as i32, field(l, "ret").parse::<i32>().unwrap(), "SAMPLE ret");
    assert_eq!(host.acc_n, field(l, "acc_n").parse::<i32>().unwrap(), "SAMPLE acc_n");
    close(host.acc_off, field(l, "off").parse().unwrap(), "SAMPLE off");
    close(host.acc_disp, field(l, "disp").parse().unwrap(), "SAMPLE disp");

    // ---- AddSample rejected: cooked time far ahead (stale) ----
    host.cooked = Timespec { sec: 2_000_001_000, nsec: 0 };
    host.acc_n = 0;
    let r = mgr.add_sample(&mut host, shm, st, rt, LEAP_NORMAL);
    let l = line("SAMPLE_STALE");
    assert_eq!(r as i32, field(l, "ret").parse::<i32>().unwrap(), "STALE ret");
    assert_eq!(host.acc_n, field(l, "acc_n").parse::<i32>().unwrap(), "STALE acc_n");

    // ---- AddCookedPulse (PPS, lock_ref=-1, synchronised): fold 0.2 -> -0.2 ----
    host.cooked = Timespec { sec: 2_000_000_001, nsec: 0 };
    host.ref_params =
        RefParams { is_synchronised: true, leap: LEAP_NORMAL, root_delay: 0.0, root_dispersion: 0.0, ..Default::default() };
    let ct = Timespec { sec: 2_000_000_000, nsec: 200_000_000 };
    host.acc_n = 0;
    let r = mgr.add_cooked_pulse(&mut host, pps, ct, 0.2, 1.0e-7, 0.0);
    let l = line("PULSE");
    assert_eq!(r as i32, field(l, "ret").parse::<i32>().unwrap(), "PULSE ret");
    close(host.acc_off, field(l, "off").parse().unwrap(), "PULSE off");
    close(host.acc_disp, field(l, "disp").parse().unwrap(), "PULSE disp");

    // ---- fold 0.7 -> 0.3 ----
    host.acc_n = 0;
    let r = mgr.add_cooked_pulse(&mut host, pps, ct, 0.7, 1.0e-7, 0.0);
    let l = line("PULSE2");
    assert_eq!(r as i32, field(l, "ret").parse::<i32>().unwrap(), "PULSE2 ret");
    close(host.acc_off, field(l, "off").parse().unwrap(), "PULSE2 off");

    // ---- rejected: unsynchronised reference ----
    host.ref_params.leap = LEAP_UNSYNCHRONISED;
    host.acc_n = 0;
    let r = mgr.add_cooked_pulse(&mut host, pps, ct, 0.2, 1.0e-7, 0.0);
    let l = line("PULSE_UNSYNC");
    assert_eq!(r as i32, field(l, "ret").parse::<i32>().unwrap(), "UNSYNC ret");
    assert_eq!(host.acc_n, field(l, "acc_n").parse::<i32>().unwrap(), "UNSYNC acc_n");
}

#[test]
fn auto_refid_derived_from_driver_name_and_index() {
    let mut host = RecHost::new_defaults();
    let mut mgr = RefclockManager::new(false);
    // No ref_id => derived from "SHM" + index 0 => 'S','H','M','0'.
    let mut p = base("SHM", 0);
    p.ref_id = 0;
    let i0 = mgr.add_refclock(&mut host, Box::new(InitDriver), p);
    assert_eq!(i0, 0);
    let expected = (b'S' as u32) << 24 | (b'H' as u32) << 16 | (b'M' as u32) << 8 | b'0' as u32;
    assert_eq!(mgr.refclock_refid(i0), expected);
}

#[test]
fn driver_option_lookup() {
    let mut host = RecHost::new_defaults();
    let mut mgr = RefclockManager::new(false);
    let mut p = base("SOCK", 0x534f_434b);
    // First segment is the driver parameter; the rest are options.
    p.driver_parameter = "/dev/sock:baud=9600:noselect".to_string();
    let i = mgr.add_refclock(&mut host, Box::new(InitDriver), p);

    assert_eq!(mgr.driver_parameter(i), Some("/dev/sock"));
    assert_eq!(mgr.driver_option(i, "baud"), Some("9600"));
    assert_eq!(mgr.driver_option(i, "noselect"), Some("")); // present, no value
    assert_eq!(mgr.driver_option(i, "missing"), None);

    assert_eq!(mgr.check_driver_options(i, &["baud", "noselect"]), None);
    assert_eq!(mgr.check_driver_options(i, &["baud"]), Some("noselect".to_string()));
}

impl RecHost {
    fn new_defaults() -> RecHost {
        RecHost { next_id: 49, ..Default::default() }
    }
}

impl RefclockManager {
    /// Test accessor for the derived refid.
    fn refclock_refid(&self, idx: usize) -> u32 {
        self.refclocks[idx].ref_id
    }
}
