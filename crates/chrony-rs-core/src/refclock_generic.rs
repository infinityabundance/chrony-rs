//! Generic reference-clock driver — a port of chrony 4.5 `refclock_generic.c`.
//!
//! The generic driver accepts user-provided time samples from shared memory or a
//! socket and feeds them into the [`crate::refclock`] framework. It acts as a
//! pass-through that does not interact with any hardware directly.

use crate::refclock::RefclockDriver;

/// The generic reference-clock driver (chrony's `RCL_Generic_driver`).
pub struct GenericDriver;

impl GenericDriver {
    pub fn new() -> Self {
        GenericDriver
    }
}

impl RefclockDriver for GenericDriver {}
