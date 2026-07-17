//! NetBSD clock-adapter stubs — a port of chrony 4.5 `sys_netbsd.c`.
//!
//! NetBSD uses a different clock API than Linux. This module ports the
//! lifecycle and offset-correction functions as trait-injected wrappers.

/// `SYS_NetBSD_Initialise`: initialise the NetBSD clock driver.
pub fn sys_netbsd_initialise<F: FnOnce()>(init: F) {
    init();
}

/// `SYS_NetBSD_Finalise`: finalise the NetBSD clock driver.
pub fn sys_netbsd_finalise<F: FnOnce()>(finalise: F) {
    finalise();
}

/// `accrue_offset`: apply an accumulated offset to the NetBSD clock.
/// NetBSD uses `ntp_adjtime` for frequency control.
pub fn accrue_offset<F: FnOnce(f64)>(offset: f64, apply: F) {
    apply(offset);
}

/// `get_offset_correction`: read back the outstanding offset correction
/// from the NetBSD kernel.
pub fn get_offset_correction<F: FnOnce() -> f64>(read: F) -> f64 {
    read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_works() {
        let mut v = 0.0;
        accrue_offset(1.5, |o| v = o);
        assert!((v - 1.5).abs() < 1e-12);
    }
}
