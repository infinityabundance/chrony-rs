//! Rendering of chrony control-tool reports (currently `tracking`).
//!
//! This is an *output byte-parity* surface: `chronyc tracking` prints a fixed,
//! label-aligned block, and operators and scripts depend on that exact layout.
//! We reproduce the layout here, driven by a structured [`TrackingReport`] so the
//! renderer is testable offline without a live daemon or control socket.
//!
//! # Parity status (do not overclaim)
//!
//! The *label column layout* (16-char left-justified label, then `": "`) is
//! admitted and byte-tested below. The *numeric formatting and phrasing* of each
//! value (sign conventions, "fast/slow of NTP time", ppm wording) is reconstructed
//! from observed chrony output but is only claimed exact for values witnessed
//! against the oracle in `docs/chronyc-parity.md`. Where a numeric format has not
//! yet been witnessed, it is marked normalized there, not claimed as exact.
//!
//! The live control-socket transport (connecting to a running daemon) is a
//! deferred negative capability — see `docs/negative-capabilities.md`. This
//! renderer formats a report you already hold; it does not fetch one.

use serde::{Deserialize, Serialize};

/// Leap status as reported by `chronyc tracking`. The exact strings match
/// chrony's `leap_status` rendering and must not be paraphrased.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeapStatus {
    Normal,
    InsertSecond,
    DeleteSecond,
    NotSynchronised,
}

impl LeapStatus {
    fn as_chrony_str(self) -> &'static str {
        match self {
            LeapStatus::Normal => "Normal",
            LeapStatus::InsertSecond => "Insert second",
            LeapStatus::DeleteSecond => "Delete second",
            // British spelling is intentional: chrony prints "Not synchronised".
            LeapStatus::NotSynchronised => "Not synchronised",
        }
    }
}

/// Structured `tracking` data. Field names mirror chrony's report lines. Times in
/// seconds, frequencies in ppm, as chrony renders them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrackingReport {
    /// Reference ID as a 32-bit value, rendered uppercase hex (e.g. `0A000001`).
    pub reference_id: u32,
    /// Optional resolved name shown in parentheses after the hex refid.
    #[serde(default)]
    pub reference_name: Option<String>,
    pub stratum: u32,
    /// Reference time, formatted by the caller (we keep it as a preformatted
    /// string because date formatting/locale is its own court and must not be
    /// reinvented inside the renderer).
    pub ref_time_utc: String,
    /// System time offset in seconds. Positive means the system clock is *fast*
    /// of NTP time; chrony phrases the sign as "fast"/"slow of NTP time".
    pub system_time_offset: f64,
    pub last_offset: f64,
    pub rms_offset: f64,
    /// Frequency error in ppm. Positive = clock runs fast.
    pub frequency_ppm: f64,
    pub residual_freq_ppm: f64,
    pub skew_ppm: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub update_interval: f64,
    pub leap_status: LeapStatus,
}

impl TrackingReport {
    /// Render exactly as `chronyc tracking` would print. Returns the full block
    /// including the trailing newline on the last line.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let refid = match &self.reference_name {
            Some(name) => format!("{:08X} ({name})", self.reference_id),
            None => format!("{:08X} ()", self.reference_id),
        };
        line(&mut s, "Reference ID", &refid);
        line(&mut s, "Stratum", &self.stratum.to_string());
        line(&mut s, "Ref time (UTC)", &self.ref_time_utc);
        line(
            &mut s,
            "System time",
            &format!(
                "{:.9} seconds {} of NTP time",
                self.system_time_offset.abs(),
                fast_slow(self.system_time_offset),
            ),
        );
        line(&mut s, "Last offset", &format!("{:+.9} seconds", self.last_offset));
        line(&mut s, "RMS offset", &format!("{:.9} seconds", self.rms_offset));
        line(
            &mut s,
            "Frequency",
            &format!("{:.3} ppm {}", self.frequency_ppm.abs(), fast_slow(self.frequency_ppm)),
        );
        line(&mut s, "Residual freq", &format!("{:+.3} ppm", self.residual_freq_ppm));
        line(&mut s, "Skew", &format!("{:.3} ppm", self.skew_ppm));
        line(&mut s, "Root delay", &format!("{:.9} seconds", self.root_delay));
        line(&mut s, "Root dispersion", &format!("{:.9} seconds", self.root_dispersion));
        line(&mut s, "Update interval", &format!("{:.1} seconds", self.update_interval));
        line(&mut s, "Leap status", self.leap_status.as_chrony_str());
        s
    }
}

/// chrony's directional wording for a signed quantity. Note: zero renders as
/// "slow" in chrony because the comparison is `> 0.0`; we match that rather than
/// inventing a "exact" case.
fn fast_slow(v: f64) -> &'static str {
    if v > 0.0 {
        "fast"
    } else {
        "slow"
    }
}

/// Emit one `"<label padded to 16>: <value>\n"` line.
fn line(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!("{label:<16}: {value}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TrackingReport {
        TrackingReport {
            reference_id: 0x0A00_0001,
            reference_name: Some("ntp.example.com".to_string()),
            stratum: 2,
            ref_time_utc: "Wed May 25 10:20:30 2022".to_string(),
            system_time_offset: 0.000_020_390,
            last_offset: 0.000_001_234,
            rms_offset: 0.000_005_678,
            frequency_ppm: 12.345,
            residual_freq_ppm: 0.001,
            skew_ppm: 0.234,
            root_delay: 0.001_234_567,
            root_dispersion: 0.000_456_789,
            update_interval: 64.5,
            leap_status: LeapStatus::Normal,
        }
    }

    #[test]
    fn tracking_layout_is_byte_stable() {
        // CHRONYC.1 — the label-aligned block. Compared byte-for-byte.
        let expected = "\
Reference ID    : 0A000001 (ntp.example.com)
Stratum         : 2
Ref time (UTC)  : Wed May 25 10:20:30 2022
System time     : 0.000020390 seconds fast of NTP time
Last offset     : +0.000001234 seconds
RMS offset      : 0.000005678 seconds
Frequency       : 12.345 ppm fast
Residual freq   : +0.001 ppm
Skew            : 0.234 ppm
Root delay      : 0.001234567 seconds
Root dispersion : 0.000456789 seconds
Update interval : 64.5 seconds
Leap status     : Normal
";
        assert_eq!(sample().render(), expected);
    }

    #[test]
    fn negative_offset_renders_slow() {
        let mut r = sample();
        r.system_time_offset = -0.000_000_007;
        r.frequency_ppm = -1.5;
        let out = r.render();
        assert!(out.contains("0.000000007 seconds slow of NTP time"));
        assert!(out.contains("1.500 ppm slow"));
    }

    #[test]
    fn every_label_aligns_to_16_columns() {
        // Guard the alignment invariant directly, independent of the golden block.
        for l in sample().render().lines() {
            let colon = l.find(':').expect("each line has a colon");
            assert_eq!(&l[colon..colon + 2], ": ", "expected ': ' at column 16 in {l:?}");
            assert_eq!(colon, 16, "label column must be 16 wide in {l:?}");
        }
    }
}
