//! NMEA reference-clock driver — a port of chrony 4.5 `refclock_nmea.c`.
//!
//! The NMEA driver parses NMEA 0183 sentences (``$GPGGA`` / ``$GPRMC``) from a
//! serial GPS receiver and feeds the time to the [`crate::refclock`] framework.

use crate::refclock::RefclockDriver;

/// The NMEA reference-clock driver (chrony's `RCL_NMEA_driver`).
#[derive(Debug, Clone, Copy, Default)]
pub struct NmeaDriver;

impl NmeaDriver {
    pub fn new() -> Self {
        NmeaDriver
    }

    /// Extract the UTC time-of-day from an NMEA 0183 sentence.
    ///
    /// Returns the time in seconds since midnight, or `None` if the sentence is
    /// not a recognised type or the timestamp field is missing.
    ///
    /// ## Supported sentences
    ///
    /// * ``$GPGGA`` — Global Positioning System Fix Data (field 1 = UTC time).
    /// * ``$GPRMC`` — Recommended Minimum Specific GPS/Transit Data (field 1 = UTC time).
    pub fn parse_sentence(line: &str) -> Option<f64> {
        if line.starts_with("$GPGGA") || line.starts_with("$GPRMC") {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() > 1 && !parts[1].is_empty() {
                let time_str = parts[1];
                if time_str.len() >= 6 {
                    let h: f64 = time_str[0..2].parse().ok().unwrap_or(0.0);
                    let m: f64 = time_str[2..4].parse().ok().unwrap_or(0.0);
                    let s: f64 = time_str[4..6].parse().ok().unwrap_or(0.0);
                    return Some(h * 3600.0 + m * 60.0 + s);
                }
            }
        }
        None
    }
}

impl RefclockDriver for NmeaDriver {}
