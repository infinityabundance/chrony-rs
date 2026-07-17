//! POSIX shared-memory I/O for the SHM refclock driver.
//!
//! Wraps `shmget()`, `shmat()`, `shmdt()` and implements the
//! [`chrony_rs_core::refclock_shm::ShmSource`] trait for real shared-memory
//! segments used by gpsd and other NTP reference clock sources.
//!
//! Integration tests check if a SHM segment exists at the default chrony key
//! (SHMKEY=0x4e545030 = "NTP0") and skip otherwise.

use chrony_rs_core::refclock_shm::ShmSource;
use chrony_rs_core::refclock_shm::ShmTime;

/// The chrony default SHM key prefix (`0x4e545030` = `"NTP0"` as ASCII).
const CHRONY_SHM_KEY: i32 = 0x4e545030;

/// A real POSIX shared-memory segment for the SHM refclock.
#[derive(Debug)]
pub struct ShmSegment {
    _shmid: i32,
    ptr: *mut ShmTime,
    _key: i32,
}

// SAFETY: The shared-memory segment is accessed from a single thread
// (the chrony event loop), so Send+Sync are safe. The pointer is valid
// for the lifetime of the struct (until drop).
unsafe impl Send for ShmSegment {}
unsafe impl Sync for ShmSegment {}

impl ShmSegment {
    /// Open (or create) the SHM segment for the given unit number.
    /// Unit 0 = `SHMKEY + 0`, unit 1 = `SHMKEY + 1`, etc.
    pub fn open(unit: i32) -> Option<Self> {
        let key = CHRONY_SHM_KEY + unit;
        // Try to get existing segment first (IPC_CREAT not set)
        // SAFETY: shmget() return value (shmid) is checked for < 0
        // immediately after. key is a valid IPC key. The size matches
        // the ShmTime struct layout.
        let shmid = unsafe { libc::shmget(key, std::mem::size_of::<ShmTime>(), 0o666) };
        if shmid < 0 {
            return None;
        }
        // SAFETY: shmat() return value is checked against MAP_FAILED
        // immediately after. shmid is a valid segment id from the
        // preceding shmget() call. The address hint (NULL) lets the
        // kernel choose the mapping.
        let ptr = unsafe { libc::shmat(shmid, std::ptr::null(), 0) };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        Some(ShmSegment {
            _shmid: shmid,
            ptr: ptr as *mut ShmTime,
            _key: key,
        })
    }

    /// Create a new SHM segment (used for testing).
    pub fn create(unit: i32) -> Option<Self> {
        let key = CHRONY_SHM_KEY + unit;
        // SAFETY: shmget() return value (shmid) is checked for < 0
        // immediately after. key is a valid IPC key. IPC_CREAT|IPC_EXCL
        // ensures we create a new segment. Size matches ShmTime layout.
        let shmid = unsafe {
            libc::shmget(
                key,
                std::mem::size_of::<ShmTime>(),
                libc::IPC_CREAT | libc::IPC_EXCL | 0o666,
            )
        };
        if shmid < 0 {
            return None;
        }
        // SAFETY: shmat() return value is checked against MAP_FAILED
        // immediately after. shmid is a valid segment id from the
        // preceding shmget() call.
        let ptr = unsafe { libc::shmat(shmid, std::ptr::null(), 0) };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        // Zero-initialize the segment
        // SAFETY: ptr is non-null (checked against MAP_FAILED above)
        // and points to a valid SHM segment of at least size_of::<ShmTime>()
        // bytes. The segment was just created so no concurrent access.
        unsafe {
            std::ptr::write_bytes(ptr as *mut u8, 0, std::mem::size_of::<ShmTime>());
        }
        Some(ShmSegment {
            _shmid: shmid,
            ptr: ptr as *mut ShmTime,
            _key: key,
        })
    }
}

impl ShmSource for ShmSegment {
    fn snapshot(&mut self) -> ShmTime {
        if self.ptr.is_null() {
            return ShmTime::default();
        }
        // SAFETY: self.ptr is verified non-null above and points to a valid
        // shared-memory segment. read_volatile ensures the compiler does not
        // optimize away the read, which is necessary for memory shared with
        // another process (gpsd/chrony).
        unsafe { std::ptr::read_volatile(self.ptr) }
    }

    fn current_count(&mut self) -> i32 {
        if self.ptr.is_null() {
            return 0;
        }
        // SAFETY: self.ptr is verified non-null above. addr_of!() creates a
        // raw pointer to the count field without creating a reference.
        // read_volatile ensures we read the latest value written by the
        // producing process (gpsd/chrony).
        unsafe { std::ptr::read_volatile(std::ptr::addr_of!((*self.ptr).count)) }
    }

    fn clear_valid(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: self.ptr is verified non-null and points to a valid
            // shared-memory segment. Writing to the valid field via raw
            // pointer avoids undefined behavior from creating a dangling
            // reference to shared memory.
            unsafe {
                (*self.ptr).valid = 0;
            }
        }
    }
}

impl Drop for ShmSegment {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: _shmid is the valid IPC identifier returned by
            // shmget(). IPC_RMID marks the segment for removal after
            // the last detach.
            unsafe {
                libc::shmctl(self._shmid, libc::IPC_RMID, std::ptr::null_mut());
            }
            // SAFETY: self.ptr is a non-null pointer returned by shmat(),
            // which owns the attachment to the SHM segment. shmdt() detaches
            // it. This is called at most once per successful shmat().
            unsafe {
                libc::shmdt(self.ptr as *mut libc::c_void);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shm_available() -> bool {
        // Try to open unit 0; if no gpsd/chrony running, the segment won't exist.
        ShmSegment::open(0).is_some()
    }

    #[test]
    fn shm_create_and_read() {
        let mut seg = ShmSegment::create(99).expect("create SHM segment (may need CAP_IPC_OWNER)");
        let snap = seg.snapshot();
        assert_eq!(snap.valid, 0);
        seg.clear_valid();
    }

    #[test]
    fn shm_open_existing() {
        if !shm_available() {
            eprintln!("skipping: no SHM segment at key {:#x}", CHRONY_SHM_KEY);
            return;
        }
        let mut seg = ShmSegment::open(0).expect("open existing SHM segment");
        let count = seg.current_count();
        eprintln!("SHM unit 0: count={count}");
    }
}
