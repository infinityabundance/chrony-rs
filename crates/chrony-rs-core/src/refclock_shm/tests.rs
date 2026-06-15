//! Tests for the `refclock_shm.c` port.
//!
//! **Oracle #1 (gold standard): the real compiled `refclock_shm.c`.** A C generator
//! drives the real `RCL_SHM_driver.poll` over a controlled `shmTime` segment (stubbed
//! `shmget`/`shmat`) and records the `(receive_ts, clock_ts, leap)` handed to a
//! stubbed `RCL_AddSample`, plus the validity rejections
//! (`research/oracle/refclock_shm-c-vectors.txt`). [`matches_real_c_shm_vectors`]
//! replays the identical segment snapshots through [`ShmDriver::poll`] and matches
//! every field and decision, including that `valid` is cleared on acceptance.
//!
//! **Oracle #2 (independent): the mode-1 writer race + the key/permission parser.**
//! A mode-1 sample whose `count` changed during the read is rejected; the `SHMKEY +
//! unit` segment key and the octal `perm` option are unit-tested.

use super::*;

/// A controllable [`ShmSource`]: hands out a fixed snapshot, a separately
/// controllable re-read `count` (to model a concurrent writer), and records the
/// `clear_valid` call.
struct StubShm {
    snap: ShmTime,
    reread_count: i32,
    cleared: bool,
}

impl ShmSource for StubShm {
    fn snapshot(&mut self) -> ShmTime {
        self.snap
    }
    fn current_count(&mut self) -> i32 {
        self.reread_count
    }
    fn clear_valid(&mut self) {
        self.cleared = true;
    }
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap().to_string()
}
fn i(line: &str, key: &str) -> i64 {
    field(line, key).parse().unwrap()
}

#[test]
fn matches_real_c_shm_vectors() {
    let vectors = include_str!("../../../../research/oracle/refclock_shm-c-vectors.txt");
    let line = |p: &str| vectors.lines().map(str::trim).find(|l| l.starts_with(p)).unwrap();

    let check = |tag: &str, snap: ShmTime| {
        let l = line(tag);
        let mut shm = StubShm { snap, reread_count: snap.count, cleared: false };
        let out = ShmDriver.poll(&mut shm);
        match out {
            Some((recv, clock, leap)) => {
                assert_eq!(i(l, "ret"), 1, "{tag}: expected accept");
                assert_eq!(i(l, "acc_n"), 1, "{tag} acc_n");
                assert_eq!(recv.sec, i(l, "recv_sec"), "{tag} recv_sec");
                assert_eq!(recv.nsec as i64, i(l, "recv_nsec"), "{tag} recv_nsec");
                assert_eq!(clock.sec, i(l, "clock_sec"), "{tag} clock_sec");
                assert_eq!(clock.nsec as i64, i(l, "clock_nsec"), "{tag} clock_nsec");
                assert_eq!(leap as i64, i(l, "leap"), "{tag} leap");
                assert!(shm.cleared, "{tag}: valid must be cleared on acceptance");
            }
            None => {
                assert_eq!(i(l, "ret"), 0, "{tag}: expected reject");
                assert_eq!(i(l, "acc_n"), 0, "{tag} acc_n");
                assert!(!shm.cleared, "{tag}: valid not cleared on rejection");
            }
        }
    };

    // NSEC: mode 0, nsec consistent with usec -> uses nsec; leap 1.
    check(
        "NSEC",
        ShmTime {
            mode: 0,
            valid: 1,
            leap: 1,
            recv_sec: 2_000_000_000,
            recv_usec: 123_456,
            recv_nsec: 123_456_789,
            clock_sec: 2_000_000_000,
            clock_usec: 654_321,
            clock_nsec: 654_321_987,
            ..Default::default()
        },
    );

    // USEC: nsec NOT consistent -> falls back to usec*1000.
    check(
        "USEC",
        ShmTime {
            mode: 0,
            valid: 1,
            leap: 0,
            recv_sec: 2_000_000_005,
            recv_usec: 222_222,
            recv_nsec: 999_999_999,
            clock_sec: 2_000_000_005,
            clock_usec: 111_111,
            clock_nsec: 0,
            ..Default::default()
        },
    );

    // MODE1_OK: mode 1, count stable -> accepted; leap 2.
    check(
        "MODE1_OK",
        ShmTime {
            mode: 1,
            count: 7,
            valid: 1,
            leap: 2,
            recv_sec: 2_000_000_010,
            recv_usec: 500_000,
            recv_nsec: 500_000_000,
            clock_sec: 2_000_000_010,
            clock_usec: 400_000,
            clock_nsec: 400_000_000,
            ..Default::default()
        },
    );

    // INVALID: valid = 0 -> reject.
    check("INVALID", ShmTime { mode: 0, valid: 0, ..Default::default() });

    // BADMODE: mode = 2 -> reject.
    check("BADMODE", ShmTime { mode: 2, valid: 1, ..Default::default() });
}

#[test]
fn mode1_rejects_a_concurrent_writer() {
    // mode 1 with the re-read count differing from the snapshot (a writer raced) is
    // rejected and `valid` is not cleared.
    let snap = ShmTime { mode: 1, count: 7, valid: 1, ..Default::default() };
    let mut shm = StubShm { snap, reread_count: 8, cleared: false };
    assert!(ShmDriver.poll(&mut shm).is_none(), "raced mode-1 sample is rejected");
    assert!(!shm.cleared);

    // Same snapshot but a stable count is accepted.
    let mut shm = StubShm { snap, reread_count: 7, cleared: false };
    assert!(ShmDriver.poll(&mut shm).is_some(), "stable mode-1 sample is accepted");
    assert!(shm.cleared);
}

#[test]
fn config_parses_unit_key_and_octal_perm() {
    // Default unit 0, default perm 0600.
    assert_eq!(ShmDriver::config("0", None), (SHMKEY, 0o600));
    // Unit 2 shifts the key; explicit octal perm masked to 0777.
    assert_eq!(ShmDriver::config("2", Some("644")), (SHMKEY + 2, 0o644));
    assert_eq!(ShmDriver::config("1", Some("777")), (SHMKEY + 1, 0o777));
    // Garbage perm -> 0; non-numeric unit -> 0 (atoi semantics).
    assert_eq!(ShmDriver::config("xyz", Some("zzz")), (SHMKEY, 0));
}
