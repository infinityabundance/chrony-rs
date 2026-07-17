//! Solaris clock-adapter stubs — a port of chrony 4.5 `sys_solaris.c`.
//!
//! Solaris uses its own clock API (`dosynctodr`, `ntp_adjtime`). This
//! module ports the lifecycle and time-of-day control as injected wrappers.

/// `SYS_Solaris_Initialise`: initialise the Solaris clock driver.
pub fn sys_solaris_initialise<F: FnOnce()>(init: F) {
    init();
}

/// `SYS_Solaris_Finalise`: finalise the Solaris clock driver.
pub fn sys_solaris_finalise<F: FnOnce()>(finalise: F) {
    finalise();
}

/// `set_dosynctodr`: enable or disable the kernel's time-of-day
/// synchronisation (do_sync_to_date). On Solaris, chrony disables
/// the kernel's built-in time-of-day sync while it disciplines the clock.
pub fn set_dosynctodr<F: FnOnce(bool)>(enable: bool, set: F) {
    set(enable);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_dispatch() {
        let mut called = false;
        sys_solaris_initialise(|| called = true);
        assert!(called);
    }
}
