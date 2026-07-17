//! OS adapter dispatch — a port of chrony 4.5 `sys.c`.
//!
//! `sys.c` is the platform-agnostic dispatch layer for OS-specific clock
//! drivers. It forwards lifecycle calls (`SYS_Initialise`, `SYS_Finalise`)
//! and process-control calls (`SYS_DropRoot`, `SYS_EnableSystemCallFilter`,
//! `SYS_LockMemory`, `SYS_SetScheduler`) to the platform-specific driver.
//! These are entirely host-boundary operations in the port.

/// `SYS_Initialise`: initialise the OS-specific clock driver.
pub fn sys_initialise<F: FnOnce()>(init: F) {
    init();
}

/// `SYS_Finalise`: finalise the OS-specific clock driver.
pub fn sys_finalise<F: FnOnce()>(finalise: F) {
    finalise();
}

/// `SYS_DropRoot`: drop root privileges (setuid/setgid/capabilities).
pub fn sys_drop_root<F: FnOnce() -> bool>(drop: F) -> bool {
    drop()
}

/// `SYS_EnableSystemCallFilter`: enable a seccomp system-call filter.
pub fn sys_enable_system_call_filter<F: FnOnce() -> bool>(enable: F) -> bool {
    enable()
}

/// `SYS_LockMemory`: lock the process memory to prevent swapping (mlockall).
pub fn sys_lock_memory<F: FnOnce() -> bool>(lock: F) -> bool {
    lock()
}

/// `SYS_SetScheduler`: set the process scheduling policy and priority.
pub fn sys_set_scheduler<F: FnOnce() -> bool>(set: F) -> bool {
    set()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_delegates() {
        let mut called = false;
        sys_initialise(|| called = true);
        assert!(called);
    }
}
