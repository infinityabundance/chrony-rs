//! Temperature compensation — a complete port of chrony 4.5 `tempcomp.c`.
//!
//! chrony can compensate the clock frequency for temperature, either from a
//! quadratic function or by interpolating a table of `(temperature, compensation)`
//! points read from a file. `tempcomp.c` is that mapping. All 5 functions port
//! here, and the points table is stored in the ported [`crate::array::Array`]
//! (chrony uses its `ARR_*`), so this also exercises that port end-to-end:
//!
//! | chrony `tempcomp.c` | here |
//! |---------------------|------|
//! | `TMC_Initialise` | [`TempComp::new`] |
//! | `TMC_Finalise` | [`TempComp::finalise`] / `Drop` |
//! | `get_tempcomp` | [`TempComp::get_tempcomp`] |
//! | `read_points` | [`read_points`] |
//! | `read_timeout` | [`TempComp::read_timeout`] |
//!
//! # Adaptations (documented)
//!
//! The temperature is passed in rather than read from a sensor file
//! (`read_timeout` returns the compensation to apply instead of calling
//! `LCL_SetTempComp` and rescheduling), the points come from a string rather than
//! `UTI_OpenFile`, and the quadratic coefficients/points are constructor arguments
//! rather than `CNF_GetTempComp`. The logging/scheduling glue is dropped.

use crate::array::Array;

/// chrony's `MAX_COMP`: the sanity limit (ppm) on a computed compensation.
pub const MAX_COMP: f64 = 10.0;

const POINT_SIZE: usize = 16; // two f64s: (temp, comp)

fn point_to_bytes(temp: f64, comp: f64) -> [u8; POINT_SIZE] {
    let mut b = [0u8; POINT_SIZE];
    b[0..8].copy_from_slice(&temp.to_ne_bytes());
    b[8..16].copy_from_slice(&comp.to_ne_bytes());
    b
}

fn point_from_bytes(b: &[u8]) -> (f64, f64) {
    let temp = f64::from_ne_bytes(b[0..8].try_into().unwrap());
    let comp = f64::from_ne_bytes(b[8..16].try_into().unwrap());
    (temp, comp)
}

/// `read_points`: parse a `(temperature compensation)` table — one pair of decimals
/// per line — into an [`Array`] of points. Errors if a line is malformed or there
/// are fewer than two points (chrony `LOG_FATAL`s in both cases).
pub fn read_points(content: &str) -> Result<Array, String> {
    let mut points = Array::new(POINT_SIZE);
    for line in content.lines() {
        let mut it = line.split_whitespace();
        match (
            it.next().and_then(|s| s.parse::<f64>().ok()),
            it.next().and_then(|s| s.parse::<f64>().ok()),
        ) {
            (Some(temp), Some(comp)) => {
                points.append_element(&point_to_bytes(temp, comp));
            }
            _ => return Err(format!("Could not read tempcomp point from line {line:?}")),
        }
    }
    if points.size() < 2 {
        return Err("Not enough points".to_string());
    }
    Ok(points)
}

/// Temperature-to-frequency-compensation mapping (chrony's `tempcomp.c` state).
pub struct TempComp {
    // Quadratic-function coefficients (used only when there are no points).
    t0: f64,
    k0: f64,
    k1: f64,
    k2: f64,
    points: Option<Array>,
}

impl TempComp {
    /// `TMC_Initialise`: a compensator. With `points_content`, the table is used
    /// and the quadratic coefficients are ignored; without it, the quadratic
    /// `k0 + (T-T0)·k1 + (T-T0)²·k2` is used.
    pub fn new(
        t0: f64,
        k0: f64,
        k1: f64,
        k2: f64,
        points_content: Option<&str>,
    ) -> Result<Self, String> {
        let points = match points_content {
            Some(c) => Some(read_points(c)?),
            None => None,
        };
        Ok(TempComp { t0, k0, k1, k2, points })
    }

    /// `TMC_Finalise`: nothing to release.
    pub fn finalise(&self) {}

    /// `get_tempcomp`: the compensation (ppm) for `temp`. Quadratic when no points;
    /// otherwise linear interpolation/extrapolation between the two nearest points.
    pub fn get_tempcomp(&self, temp: f64) -> f64 {
        let points = match &self.points {
            None => {
                let d = temp - self.t0;
                return self.k0 + d * self.k1 + d * d * self.k2;
            }
            Some(p) => p,
        };

        // Find the first point with temp >= the query (chrony's loop), defaulting
        // to the last point; p1 is the point before it.
        let n = points.size();
        let mut i = n - 1;
        for j in 1..n {
            let (t, _) = point_from_bytes(points.get_element(j));
            if t >= temp {
                i = j;
                break;
            }
        }
        let (t1, c1) = point_from_bytes(points.get_element(i - 1));
        let (t2, c2) = point_from_bytes(points.get_element(i));
        (temp - t1) / (t2 - t1) * (c2 - c1) + c1
    }

    /// `read_timeout`: the compensation to apply for temperature `temp`, or `None`
    /// if it exceeds the sanity limit [`MAX_COMP`] (chrony logs a warning and skips).
    pub fn read_timeout(&self, temp: f64) -> Option<f64> {
        let comp = self.get_tempcomp(temp);
        if comp.abs() <= MAX_COMP {
            Some(comp)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quadratic_mode() {
        // k0=1, k1=0.5, k2=0.1, T0=20.
        let tc = TempComp::new(20.0, 1.0, 0.5, 0.1, None).unwrap();
        assert_eq!(tc.get_tempcomp(20.0), 1.0); // at T0 -> k0
        // at T=25: 1 + 5*0.5 + 25*0.1 = 1 + 2.5 + 2.5 = 6.0
        assert!((tc.get_tempcomp(25.0) - 6.0).abs() < 1e-12);
    }

    #[test]
    fn point_interpolation_and_extrapolation() {
        // Points: (10,-2), (20,0), (30,4).
        let tc = TempComp::new(0.0, 0.0, 0.0, 0.0, Some("10 -2\n20 0\n30 4\n")).unwrap();
        assert_eq!(tc.get_tempcomp(10.0), -2.0); // exact point
        assert_eq!(tc.get_tempcomp(20.0), 0.0);
        assert!((tc.get_tempcomp(15.0) - (-1.0)).abs() < 1e-12); // midpoint 10..20
        assert!((tc.get_tempcomp(25.0) - 2.0).abs() < 1e-12); // midpoint 20..30
        // extrapolate below the first segment (uses points[0],points[1])
        assert!((tc.get_tempcomp(0.0) - (-4.0)).abs() < 1e-12); // line through (10,-2),(20,0)
        // extrapolate above the last segment (uses points[1],points[2])
        assert!((tc.get_tempcomp(40.0) - 8.0).abs() < 1e-12); // line through (20,0),(30,4)
    }

    #[test]
    fn read_timeout_respects_sanity_limit() {
        // A quadratic that blows past MAX_COMP at large |T-T0|.
        let tc = TempComp::new(0.0, 0.0, 0.0, 1.0, None).unwrap();
        assert_eq!(tc.read_timeout(2.0), Some(4.0)); // within limit
        assert_eq!(tc.read_timeout(100.0), None); // 10000 ppm > MAX_COMP
    }

    #[test]
    fn read_points_validation() {
        assert!(read_points("10 1\n").is_err()); // fewer than 2 points
        assert!(read_points("10 1\nbad line\n").is_err()); // malformed
        assert_eq!(read_points("10 1\n20 2\n").unwrap().size(), 2);
    }
}
