//! Robust-regression statistical primitives — a dependency-free subset of chrony
//! 4.5 `regress.c`.
//!
//! # Scope (honest)
//!
//! `regress.c` has 11 functions. This module ports the **pure, exactly-verifiable,
//! dependency-free** ones — the two critical-value tables and the order-statistic
//! median — because they have no chrony global state and an independent oracle:
//!
//! | chrony `regress.c` | here |
//! |--------------------|------|
//! | `RGR_GetTCoef`     | [`t_coef`] |
//! | `RGR_GetChi2Coef`  | [`chi2_coef`] |
//! | `RGR_FindMedian`   | [`find_median`] |
//! | `find_median` (static) | [`median_in_place`] |
//! | `find_ordered_entry_with_flags` (static) | [`select_ordered`] |
//!
//! The weighted/robust regressions themselves (`RGR_WeightedRegression`,
//! `RGR_FindBestRobustRegression`, …) are **not** ported here — they carry chrony's
//! outlier-pruning policy and want a behavioral oracle, so they stay a gap rather
//! than a guessed transliteration. See `docs/generated/port-parity-functions.md`.
//!
//! # Bit-exactness
//!
//! chrony's coefficient tables are C `float` literals promoted to `double` at the
//! return. We store them as [`f32`] and cast to [`f64`] so the promoted value is
//! identical to chrony's, not the (different) value of an `f64` literal.

/// chrony's `MAX_POINTS`: the largest sample count the selection handles.
pub const MAX_POINTS: usize = 64;

/// `RGR_GetTCoef`: 99.95% Student-t critical value for `dof` degrees of freedom
/// (1-based, as chrony calls it). Above 40 dof chrony returns a flat `3.5`.
pub fn t_coef(dof: i32) -> f64 {
    // 99.95% quantile table, dof = 1..=40 (chrony's `coefs`).
    const COEFS: [f32; 40] = [
        636.6, 31.6, 12.92, 8.61, 6.869, 5.959, 5.408, 5.041, 4.781, 4.587, 4.437, 4.318, 4.221,
        4.140, 4.073, 4.015, 3.965, 3.922, 3.883, 3.850, 3.819, 3.792, 3.768, 3.745, 3.725, 3.707,
        3.690, 3.674, 3.659, 3.646, 3.633, 3.622, 3.611, 3.601, 3.591, 3.582, 3.574, 3.566, 3.558,
        3.551,
    ];
    if (1..=40).contains(&dof) {
        COEFS[(dof - 1) as usize] as f64
    } else {
        3.5
    }
}

/// `RGR_GetChi2Coef`: chi-squared critical value for `dof` degrees of freedom
/// (1-based). Above 64 dof chrony returns `1.2 * dof`.
pub fn chi2_coef(dof: i32) -> f64 {
    const COEFS: [f32; 64] = [
        2.706, 4.605, 6.251, 7.779, 9.236, 10.645, 12.017, 13.362, 14.684, 15.987, 17.275, 18.549,
        19.812, 21.064, 22.307, 23.542, 24.769, 25.989, 27.204, 28.412, 29.615, 30.813, 32.007,
        33.196, 34.382, 35.563, 36.741, 37.916, 39.087, 40.256, 41.422, 42.585, 43.745, 44.903,
        46.059, 47.212, 48.363, 49.513, 50.660, 51.805, 52.949, 54.090, 55.230, 56.369, 57.505,
        58.641, 59.774, 60.907, 62.038, 63.167, 64.295, 65.422, 66.548, 67.673, 68.796, 69.919,
        71.040, 72.160, 73.279, 74.397, 75.514, 76.630, 77.745, 78.860,
    ];
    if (1..=64).contains(&dof) {
        COEFS[(dof - 1) as usize] as f64
    } else {
        1.2 * dof as f64
    }
}

/// Result of a weighted linear regression (chrony's `RGR_WeightedRegression`
/// out-parameters).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Regression {
    /// `b0` — estimated y-axis intercept.
    pub intercept: f64,
    /// `b1` — estimated slope.
    pub slope: f64,
    /// `s2` — estimated (weighted-average) variance of the data points.
    pub variance: f64,
    /// `sb0` — estimated standard deviation of the intercept.
    pub sd_intercept: f64,
    /// `sb1` — estimated standard deviation of the slope.
    pub sd_slope: f64,
}

/// `RGR_MultipleRegress`: two-variable linear regression `y ~ x1 + x2`, returning
/// the estimated **second** slope `b2` (chrony only needs that one) via Cramer's
/// rule on the normal equations. Returns `None` if `n < 4` or the system is too
/// ill-conditioned for a numerically stable solution (chrony's `|V|·1e10` test).
pub fn multiple_regress(x1: &[f64], x2: &[f64], y: &[f64]) -> Option<f64> {
    let n = x1.len();
    assert!(x2.len() == n && y.len() == n);
    if n < 4 {
        return None;
    }
    let (mut sx1, mut sx2, mut sx1x1, mut sx1x2, mut sx2x2, mut sx1y, mut sx2y, mut sy) =
        (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    for i in 0..n {
        sx1 += x1[i];
        sx2 += x2[i];
        sx1x1 += x1[i] * x1[i];
        sx1x2 += x1[i] * x2[i];
        sx2x2 += x2[i] * x2[i];
        sx1y += x1[i] * y[i];
        sx2y += x2[i] * y[i];
        sy += y[i];
    }
    let nf = n as f64;
    let u = nf * (sx1x2 * sx1y - sx1x1 * sx2y) + sx1 * sx1 * sx2y - sx1 * sx2 * sx1y
        + sy * (sx2 * sx1x1 - sx1 * sx1x2);
    let v1 = nf * (sx1x2 * sx1x2 - sx1x1 * sx2x2);
    let v2 = sx1 * sx1 * sx2x2 + sx2 * sx2 * sx1x1;
    let v3 = -2.0 * sx1 * sx2 * sx1x2;
    let v = v1 + v2 + v3;
    // Numerical-stability guard (chrony's exact comparison).
    if v.abs() * 1.0e10 <= -v1 + v2 + v3.abs() {
        return None;
    }
    Some(u / v)
}

/// `eval_robust_residual`: for a candidate slope `b`, the intercept `a` is the
/// median of `y - b*x`; the returned `rr` is `Σ sign(y-a-b*x)·x`, whose root (in
/// `b`) gives the robust (median-based) line fit. Returns `(a, rr)`.
fn eval_robust_residual(x: &[f64], y: &[f64], b: f64) -> (f64, f64) {
    let mut d: Vec<f64> = (0..x.len()).map(|i| y[i] - b * x[i]).collect();
    let a = median_in_place(&mut d);
    let mut res = 0.0;
    for i in 0..x.len() {
        let del = y[i] - a - b * x[i];
        if del > 0.0 {
            res += x[i];
        } else if del < 0.0 {
            res -= x[i];
        }
    }
    (a, res)
}

/// Result of [`find_best_robust_regression`] (chrony's
/// `RGR_FindBestRobustRegression` outputs).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RobustRegression {
    pub intercept: f64,
    pub slope: f64,
    pub n_runs: i32,
    pub best_start: usize,
}

/// `RGR_FindBestRobustRegression`: a median-based robust line fit tolerant of
/// outliers. The slope is found by bisecting [`eval_robust_residual`] to its root,
/// and the oldest samples are dropped until the residuals pass the runs test.
/// `tol` is the slope tolerance. Returns `None` if `n < 2` or the root bracket
/// grows beyond chrony's limit (it returns 0 in both cases).
pub fn find_best_robust_regression(x: &[f64], y: &[f64], tol: f64) -> Option<RobustRegression> {
    let n = x.len();
    assert!(y.len() == n && n <= MAX_POINTS);
    if n < 2 {
        return None;
    }
    if n == 2 {
        let slope = (y[1] - y[0]) / (x[1] - x[0]);
        return Some(RobustRegression {
            intercept: y[0] - slope * x[0],
            slope,
            n_runs: 0,
            best_start: 0,
        });
    }

    let mut start = 0usize;
    let mut nruns = 0i32;
    // Assigned every iteration before any break (definite via the `loop`).
    let mut intercept: f64;
    let mut slope: f64;

    loop {
        let np = n - start;
        // Ordinary least squares for a starting estimate.
        let (mut p, mut u_sum) = (0.0, 0.0);
        for i in start..n {
            p += y[i];
            u_sum += x[i];
        }
        let w = np as f64;
        let (my, mx) = (p / w, u_sum / w);
        let (mut xx, mut v) = (0.0, 0.0);
        for i in start..n {
            xx += (y[i] - my) * (x[i] - mx);
            v += (x[i] - mx) * (x[i] - mx);
        }
        let b = xx / v;
        let mut a = my - b * mx;
        let mut s2 = 0.0;
        for i in start..n {
            let r = y[i] - a - b * x[i];
            s2 += r * r;
        }

        // Expand a symmetric interval about b until it brackets the residual root.
        let mut incr = (s2 * w / v).sqrt().max(tol);
        let (mut blo, mut bhi, mut rlo, mut rhi);
        loop {
            incr *= 2.0;
            if incr > 100.0 {
                return None; // interval too large; give up
            }
            let (lo, hi) = (b - incr, b + incr);
            let (_, rl) = eval_robust_residual(&x[start..n], &y[start..n], lo);
            let (av, rh) = eval_robust_residual(&x[start..n], &y[start..n], hi);
            a = av;
            blo = lo;
            bhi = hi;
            rlo = rl;
            rhi = rh;
            if rlo * rhi < 0.0 {
                break;
            }
        }

        // Bisect to the root.
        let mut bmid;
        loop {
            bmid = 0.5 * (blo + bhi);
            if !(blo < bmid && bmid < bhi) {
                break;
            }
            let (av, rmid) = eval_robust_residual(&x[start..n], &y[start..n], bmid);
            a = av;
            if rmid == 0.0 {
                break;
            } else if rmid * rlo > 0.0 {
                blo = bmid;
                rlo = rmid;
            } else if rmid * rhi > 0.0 {
                bhi = bmid;
                rhi = rmid;
            } else {
                unreachable!("residual root sign invariant");
            }
            if bhi - blo <= tol {
                break;
            }
        }

        intercept = a;
        slope = bmid;

        // Runs test, unless we are already at the minimum sample count.
        if np == MIN_SAMPLES_FOR_REGRESS {
            break;
        }
        let resids: Vec<f64> = (start..n).map(|i| y[i] - a - bmid * x[i]).collect();
        nruns = runs_count(&resids);
        if nruns > CRITICAL_RUNS[np] {
            break;
        }
        start += 1;
    }

    Some(RobustRegression { intercept, slope, n_runs: nruns, best_start: start })
}

/// `RGR_WeightedRegression`: closed-form weighted least-squares line fit. `w[i]`
/// are chrony's weightings where *larger means less reliable* (the effective
/// weight is `1/w[i]`). Requires `n >= 3` and equal-length slices, matching
/// chrony's `assert(n >= 3)`.
pub fn weighted_regression(x: &[f64], y: &[f64], w: &[f64]) -> Regression {
    let n = x.len();
    assert!(n >= 3 && y.len() == n && w.len() == n, "need >=3 equal-length points");

    // Weighted mean of x: u = (Σ x/w) / (Σ 1/w).
    let mut big_w = 0.0;
    let mut u_sum = 0.0;
    for i in 0..n {
        u_sum += x[i] / w[i];
        big_w += 1.0 / w[i];
    }
    let u = u_sum / big_w;

    let (mut p, mut q, mut v) = (0.0, 0.0, 0.0);
    for i in 0..n {
        let ui = x[i] - u;
        p += y[i] / w[i];
        q += y[i] * ui / w[i];
        v += ui * ui / w[i];
    }

    let b1 = q / v;
    let b0 = p / big_w - b1 * u;

    let mut s2 = 0.0;
    for i in 0..n {
        let diff = y[i] - b0 - b1 * x[i];
        s2 += diff * diff / w[i];
    }
    s2 /= (n - 2) as f64;

    // Standard deviations use s2 *before* the final rescale (chrony's order).
    let sb1 = (s2 / v).sqrt();
    let aa = u * sb1;
    let sb0 = (s2 / big_w + aa * aa).sqrt();
    s2 *= n as f64 / big_w; // weighted average of variances

    Regression { intercept: b0, slope: b1, variance: s2, sd_intercept: sb0, sd_slope: sb1 }
}

/// `REGRESS_RUNS_RATIO` / `MIN_SAMPLES_FOR_REGRESS` (chrony's `regress.h`).
pub const REGRESS_RUNS_RATIO: usize = 2;
const MIN_SAMPLES_FOR_REGRESS: usize = 3;

/// Critical number of residual sign-runs (chrony's `critical_runs[]`): the runs
/// test passes when the count *exceeds* this, indexed by sample count.
const CRITICAL_RUNS: [i32; 130] = [
    0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 7, 7, 7, 8, 8, 9, 9, 9, 10, 10, 11,
    11, 11, 12, 12, 13, 13, 14, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 18, 19, 19, 20, 20, 21, 21,
    21, 22, 22, 23, 23, 24, 24, 25, 25, 26, 26, 26, 27, 27, 28, 28, 29, 29, 30, 30, 30, 31, 31, 32,
    32, 33, 33, 34, 34, 35, 35, 35, 36, 36, 37, 37, 38, 38, 39, 39, 40, 40, 40, 41, 41, 42, 42, 43,
    43, 44, 44, 45, 45, 46, 46, 46, 47, 47, 48, 48, 49, 49, 50, 50, 51, 51, 52, 52, 52, 53, 53, 54,
    54, 55, 55, 56,
];

/// `n_runs_from_residuals`: count runs of same-signed residuals (a zero residual
/// breaks a run, as in chrony). Always at least 1.
fn runs_count(resid: &[f64]) -> i32 {
    let mut nruns = 1;
    for i in 1..resid.len() {
        let same = (resid[i - 1] < 0.0 && resid[i] < 0.0)
            || (resid[i - 1] > 0.0 && resid[i] > 0.0);
        if !same {
            nruns += 1;
        }
    }
    nruns
}

/// Result of [`find_best_regression`] (chrony's `RGR_FindBestRegression` outputs).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BestRegression {
    pub intercept: f64,
    pub slope: f64,
    pub variance: f64,
    pub sd_intercept: f64,
    pub sd_slope: f64,
    /// New starting index (relative to the main data): how many oldest samples
    /// were dropped to make the residuals pass the runs test.
    pub new_start: usize,
    pub n_runs: i32,
    /// Degrees of freedom (`npoints - 2`).
    pub dof: usize,
}

/// `RGR_FindBestRegression`: weighted line fit that drops the oldest samples until
/// the residuals pass a runs test (robustness against an out-of-trend start).
///
/// `x`/`y`/`w` hold `m` extra (older) samples followed by the `n` main samples —
/// length `m + n` — so the main data is `x[m..]` and the extra samples (used only
/// to extend the runs test) are `x[..m]`. This is the slice-based equivalent of
/// chrony's negative-index pointer arithmetic. Returns `None` if `n` is below
/// `MIN_SAMPLES_FOR_REGRESS` (chrony returns 0).
pub fn find_best_regression(
    x: &[f64],
    y: &[f64],
    w: &[f64],
    n: usize,
    m: usize,
    min_samples: usize,
) -> Option<BestRegression> {
    assert!(x.len() == m + n && y.len() == m + n && w.len() == m + n);
    assert!(n <= MAX_POINTS);
    assert!(n * REGRESS_RUNS_RATIO < CRITICAL_RUNS.len());
    if n < MIN_SAMPLES_FOR_REGRESS {
        return None;
    }

    let mi = m as i64;
    let ni = n as i64;
    // C index i in -m..n maps to buffer index (i + m).
    let buf = |i: i64| (i + mi) as usize;

    let mut resid = vec![0.0f64; m + n];
    let mut start: i64 = 0;
    // Values from the final iteration that the post-loop statistics need. The
    // `loop` always runs and assigns these before any `break`, so they are left
    // uninitialized here (no dead initial store) but reassigned each iteration.
    let mut big_w: f64;
    let mut u: f64;
    let mut v: f64;
    let mut b: f64;
    let mut a: f64;
    let mut resid_start: i64;
    let mut nruns: i32;

    loop {
        big_w = 0.0;
        let mut big_u = 0.0;
        for i in start..ni {
            let bi = buf(i);
            big_u += x[bi] / w[bi];
            big_w += 1.0 / w[bi];
        }
        u = big_u / big_w;

        let (mut p, mut q) = (0.0, 0.0);
        v = 0.0;
        for i in start..ni {
            let bi = buf(i);
            let ui = x[bi] - u;
            p += y[bi] / w[bi];
            q += y[bi] * ui / w[bi];
            v += ui * ui / w[bi];
        }
        b = q / v;
        a = p / big_w - b * u;

        // Residuals, extended back over the extra samples.
        resid_start = ni - (ni - start) * REGRESS_RUNS_RATIO as i64;
        if resid_start < -mi {
            resid_start = -mi;
        }
        for i in resid_start..ni {
            let bi = buf(i);
            resid[(i - resid_start) as usize] = y[bi] - a - b * x[bi];
        }

        let count = (ni - resid_start) as usize;
        nruns = runs_count(&resid[..count]);
        if nruns > CRITICAL_RUNS[count]
            || (ni - start) as usize <= MIN_SAMPLES_FOR_REGRESS
            || (ni - start) as usize <= min_samples
        {
            if start != resid_start {
                // Report runs over the kept samples only (ignore the extras).
                let off = (start - resid_start) as usize;
                nruns = runs_count(&resid[off..off + (ni - start) as usize]);
            }
            break;
        }
        start += 1;
    }

    let mut ss = 0.0;
    for i in start..ni {
        let bi = buf(i);
        let r = resid[(i - resid_start) as usize];
        ss += r * r / w[bi];
    }
    let npoints = (ni - start) as f64;
    ss /= npoints - 2.0;
    let sb1 = (ss / v).sqrt();
    let aa = u * sb1;
    let sb0 = (ss / big_w + aa * aa).sqrt();
    let s2 = ss * npoints / big_w;

    Some(BestRegression {
        intercept: a,
        slope: b,
        variance: s2,
        sd_intercept: sb0,
        sd_slope: sb1,
        new_start: start as usize,
        n_runs: nruns,
        dof: (ni - start) as usize - 2,
    })
}

/// `find_ordered_entry_with_flags`: return the `index`-th smallest value (0-based)
/// of `x`, partially sorting `x` in place and memoizing finished positions in
/// `flags`. A faithful port of chrony's memoized quickselect.
fn select_ordered(x: &mut [f64], n: usize, index: usize, flags: &mut [bool]) -> f64 {
    debug_assert!(index < n);

    // Already pinned by a previous call.
    if flags[index] {
        return x[index];
    }

    // i64 index arithmetic mirrors chrony's `int` math without usize underflow.
    let idx = index as i64;
    // Subrange [u, v] bounded by the nearest pinned positions.
    let mut u = idx;
    let mut v = idx;
    while u > 0 && !flags[u as usize] {
        u -= 1;
    }
    if flags[u as usize] {
        u += 1;
    }
    while v < (n as i64 - 1) && !flags[v as usize] {
        v += 1;
    }
    if flags[v as usize] {
        v -= 1;
    }

    loop {
        if v - u < 2 {
            if x[v as usize] < x[u as usize] {
                x.swap(u as usize, v as usize);
            }
            flags[v as usize] = true;
            flags[u as usize] = true;
            return x[index];
        }
        let pivind = (u + v) >> 1;
        x.swap(u as usize, pivind as usize);
        let piv = x[u as usize];
        let mut l = u + 1;
        let mut r = v;
        loop {
            while l < v && x[l as usize] < piv {
                l += 1;
            }
            while x[r as usize] > piv {
                r -= 1;
            }
            if r <= l {
                break;
            }
            x.swap(l as usize, r as usize);
            l += 1;
            r -= 1;
        }
        x.swap(u as usize, r as usize);
        flags[r as usize] = true; // pivot now in its final place
        match idx.cmp(&r) {
            std::cmp::Ordering::Equal => return x[r as usize],
            std::cmp::Ordering::Less => v = r - 1,
            std::cmp::Ordering::Greater => u = l,
        }
    }
}

/// `find_median` (static): median of `x`, partially sorting it in place. For an
/// even count, averages the two central order statistics, exactly as chrony does.
pub fn median_in_place(x: &mut [f64]) -> f64 {
    let n = x.len();
    assert!(n > 0 && n <= MAX_POINTS, "n must be in 1..={MAX_POINTS}");
    let mut flags = [false; MAX_POINTS];
    let k = n >> 1;
    if n & 1 == 1 {
        select_ordered(x, n, k, &mut flags[..n])
    } else {
        0.5 * (select_ordered(x, n, k, &mut flags[..n])
            + select_ordered(x, n, k - 1, &mut flags[..n]))
    }
}

/// `RGR_FindMedian`: median of `x` without disturbing the caller's slice (chrony
/// copies into a scratch buffer first).
pub fn find_median(x: &[f64]) -> f64 {
    let mut tmp: Vec<f64> = x.to_vec();
    median_in_place(&mut tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_and_chi2_tables_are_exact() {
        // Spot-check published table entries (as float→double, chrony's promotion).
        assert_eq!(t_coef(1), 636.6_f32 as f64);
        assert_eq!(t_coef(40), 3.551_f32 as f64);
        assert_eq!(t_coef(41), 3.5); // flat fallback above 40
        assert_eq!(t_coef(0), 3.5); // out of range → fallback
        assert_eq!(chi2_coef(1), 2.706_f32 as f64);
        assert_eq!(chi2_coef(64), 78.860_f32 as f64);
        assert_eq!(chi2_coef(65), 1.2 * 65.0); // dof>64 → 1.2*dof
    }

    /// Independent oracle: a sort-based median.
    fn naive_median(x: &[f64]) -> f64 {
        let mut s = x.to_vec();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = s.len();
        if n & 1 == 1 {
            s[n / 2]
        } else {
            0.5 * (s[n / 2] + s[n / 2 - 1])
        }
    }

    #[test]
    fn weighted_regression_recovers_perfect_line_exactly() {
        // A perfect line y = b0 + b1*x has zero residuals, so it is recovered
        // exactly for ANY positive weights — a truly independent check.
        let x = [0.0, 1.0, 2.0, 3.0, 4.0];
        let (b0, b1) = (5.0, -2.0);
        let y: Vec<f64> = x.iter().map(|&xi| b0 + b1 * xi).collect();
        let w = [1.0, 2.0, 0.5, 3.0, 1.5];
        let r = weighted_regression(&x, &y, &w);
        assert!((r.slope - b1).abs() < 1e-12, "slope {}", r.slope);
        assert!((r.intercept - b0).abs() < 1e-12, "intercept {}", r.intercept);
        assert!(r.variance.abs() < 1e-12);
        assert!(r.sd_slope.abs() < 1e-12 && r.sd_intercept.abs() < 1e-12);
    }

    #[test]
    fn weighted_regression_matches_reference_noisy_case() {
        // Reference values from an independent computation of chrony's formulas.
        let x = [1.0, 2.0, 3.0, 4.0, 5.0];
        let y = [2.1, 3.9, 6.2, 7.8, 10.1];
        let w = [1.0, 1.0, 2.0, 1.0, 0.5];
        let r = weighted_regression(&x, &y, &w);
        assert!((r.intercept - 0.002054794520548242).abs() < 1e-12);
        assert!((r.slope - 2.0047945205479447).abs() < 1e-12);
        assert!((r.variance - 0.02965960979659611).abs() < 1e-12);
        assert!((r.sd_intercept - 0.1836923646860035).abs() < 1e-12);
        assert!((r.sd_slope - 0.049579138242772824).abs() < 1e-12);
    }

    #[test]
    fn robust_regression_tolerates_an_outlier() {
        // Clean line y = 3 + 2x: recovered exactly (matches reference).
        let x: Vec<f64> = (0..8).map(|i| i as f64).collect();
        let y: Vec<f64> = (0..8).map(|i| 3.0 + 2.0 * i as f64).collect();
        let r = find_best_robust_regression(&x, &y, 1e-9).unwrap();
        assert!((r.intercept - 3.0).abs() < 1e-6, "b0 {}", r.intercept);
        assert!((r.slope - 2.0).abs() < 1e-6, "b1 {}", r.slope);
        assert_eq!(r.best_start, 0);
        assert_eq!(r.n_runs, 8);

        // Same line with a +10 outlier at index 5: the median fit still recovers
        // ~(3, 2), dropping one oldest sample (matches reference impl).
        let mut yo = y.clone();
        yo[5] += 10.0;
        let r = find_best_robust_regression(&x, &yo, 1e-9).unwrap();
        assert!((r.intercept - 3.0).abs() < 1e-6, "b0 {}", r.intercept);
        assert!((r.slope - 2.0).abs() < 1e-6, "b1 {}", r.slope);
        assert_eq!(r.best_start, 1);
        assert_eq!(r.n_runs, 3);

        // Two points -> exact straight line.
        let r = find_best_robust_regression(&[0.0, 2.0], &[1.0, 5.0], 1e-9).unwrap();
        assert_eq!(r.slope, 2.0);
        assert_eq!(r.intercept, 1.0);
    }

    #[test]
    fn multiple_regress_recovers_second_slope() {
        // y = 1 + 2*x1 + 3*x2 exactly -> b2 = 3.
        let x1 = [1.0, 2.0, 3.0, 4.0, 5.0];
        let x2 = [2.0, 1.0, 4.0, 3.0, 6.0];
        let y: Vec<f64> = (0..5).map(|i| 1.0 + 2.0 * x1[i] + 3.0 * x2[i]).collect();
        let b2 = multiple_regress(&x1, &x2, &y).unwrap();
        assert!((b2 - 3.0).abs() < 1e-9, "b2 = {b2}");

        // Fewer than 4 points -> None.
        assert!(multiple_regress(&x1[..3], &x2[..3], &y[..3]).is_none());
    }

    /// Differential test against the REAL chrony 4.5 `regress.c`: the committed
    /// vectors are inputs + outputs captured from the compiled C (see the file
    /// header). This is a genuine *second* oracle — independent of the Rust port
    /// and of the hand-written reference above, so a shared misunderstanding cannot
    /// pass both.
    #[test]
    fn matches_real_c_regress_vectors() {
        const VEC: &str = include_str!("../../../research/oracle/regress-c-vectors.txt");
        let mut lines = VEC.lines().filter(|l| !l.starts_with('#'));

        let close = |got: f64, c: f64, what: &str| {
            assert!(
                (got - c).abs() <= 1e-9 * (1.0 + c.abs()),
                "{what}: rust {got} vs C {c}"
            );
        };

        // WREG: weighted_regression.
        let hdr = lines.next().unwrap();
        let wc: usize = hdr.strip_prefix("WREG ").unwrap().parse().unwrap();
        for _ in 0..wc {
            let line = lines.next().unwrap();
            let (ins, outs) = line.split_once('|').unwrap();
            let nums: Vec<f64> = ins.split_whitespace().map(|s| s.parse().unwrap()).collect();
            let n = nums[0] as usize;
            let (mut x, mut y, mut w) = (vec![], vec![], vec![]);
            for i in 0..n {
                x.push(nums[1 + i * 3]);
                y.push(nums[2 + i * 3]);
                w.push(nums[3 + i * 3]);
            }
            let o: Vec<f64> = outs.split_whitespace().map(|s| s.parse().unwrap()).collect();
            let r = weighted_regression(&x, &y, &w);
            close(r.intercept, o[0], "wreg b0");
            close(r.slope, o[1], "wreg b1");
            close(r.variance, o[2], "wreg s2");
            close(r.sd_intercept, o[3], "wreg sb0");
            close(r.sd_slope, o[4], "wreg sb1");
        }

        // FBREG: find_best_regression.
        let hdr = lines.next().unwrap();
        let fc: usize = hdr.strip_prefix("FBREG ").unwrap().parse().unwrap();
        for _ in 0..fc {
            let line = lines.next().unwrap();
            let (ins, outs) = line.split_once('|').unwrap();
            let nums: Vec<f64> = ins.split_whitespace().map(|s| s.parse().unwrap()).collect();
            let n = nums[0] as usize;
            let m = nums[1] as usize;
            let min_s = nums[2] as usize;
            let total = m + n;
            let mut x = vec![];
            let mut y = vec![];
            for i in 0..total {
                x.push(nums[3 + i * 2]);
                y.push(nums[4 + i * 2]);
            }
            // C passes weights of length n (main only); our API wants length m+n.
            let woff = 3 + total * 2;
            let mut wfull = vec![0.0f64; m];
            for i in 0..n {
                wfull.push(nums[woff + i]);
            }
            let o: Vec<f64> = outs.split_whitespace().map(|s| s.parse().unwrap()).collect();
            let ok = o[0] as i32 == 1;
            let r = find_best_regression(&x, &y, &wfull, n, m, min_s);
            assert_eq!(r.is_some(), ok, "fbreg ok");
            if let Some(r) = r {
                close(r.intercept, o[1], "fbreg b0");
                close(r.slope, o[2], "fbreg b1");
                close(r.variance, o[3], "fbreg s2");
                close(r.sd_intercept, o[4], "fbreg sb0");
                close(r.sd_slope, o[5], "fbreg sb1");
                assert_eq!(r.new_start, o[6] as usize, "fbreg best_start");
                assert_eq!(r.n_runs, o[7] as i32, "fbreg n_runs");
                assert_eq!(r.dof, o[8] as usize, "fbreg dof");
            }
        }
    }

    #[test]
    fn runs_count_basic() {
        assert_eq!(runs_count(&[]), 1);
        assert_eq!(runs_count(&[1.0]), 1);
        assert_eq!(runs_count(&[1.0, 2.0, 3.0]), 1); // all positive -> 1 run
        assert_eq!(runs_count(&[1.0, -1.0, 1.0, -1.0]), 4); // alternating
        assert_eq!(runs_count(&[1.0, 1.0, -1.0, -1.0, 1.0]), 3);
        assert_eq!(runs_count(&[1.0, 0.0, 1.0]), 3); // zero breaks the run
    }

    fn close(got: &BestRegression, want: &BestRegression) {
        assert!((got.intercept - want.intercept).abs() < 1e-9, "b0 {} vs {}", got.intercept, want.intercept);
        assert!((got.slope - want.slope).abs() < 1e-9, "b1 {} vs {}", got.slope, want.slope);
        assert!((got.variance - want.variance).abs() < 1e-9, "s2");
        assert!((got.sd_intercept - want.sd_intercept).abs() < 1e-9, "sb0");
        assert!((got.sd_slope - want.sd_slope).abs() < 1e-9, "sb1");
        assert_eq!(got.new_start, want.new_start);
        assert_eq!(got.n_runs, want.n_runs);
        assert_eq!(got.dof, want.dof);
    }

    #[test]
    fn find_best_regression_matches_reference() {
        // Goldens from an independent reference implementation of chrony's
        // RGR_FindBestRegression (Python port of the same algorithm).

        // Case A: clean alternating residuals, no extra samples, no drop.
        let xa: Vec<f64> = (0..10).map(|i| i as f64).collect();
        let ya: Vec<f64> = (0..10).map(|i| 1.0 + 0.5 * i as f64 + if i % 2 == 1 { 0.1 } else { -0.1 }).collect();
        let wa = vec![1.0; 10];
        close(
            &find_best_regression(&xa, &ya, &wa, 10, 0, 4).unwrap(),
            &BestRegression {
                intercept: 0.9727272727272727,
                slope: 0.5060606060606061,
                variance: 0.012121212121212113,
                sd_intercept: 0.0647095651638261,
                sd_slope: 0.012121212121212118,
                new_start: 0,
                n_runs: 10,
                dof: 8,
            },
        );

        // Case C: a parabola forces dropping the 5 oldest samples (start=5).
        let xc: Vec<f64> = (0..12).map(|i| i as f64).collect();
        let yc: Vec<f64> = (0..12).map(|i| (i as f64 - 5.5).powi(2)).collect();
        let wc = vec![1.0; 12];
        close(
            &find_best_regression(&xc, &yc, &wc, 12, 0, 3).unwrap(),
            &BestRegression {
                intercept: -29.75,
                slope: 5.0,
                variance: 16.8,
                sd_intercept: 6.3874877690685254,
                sd_slope: 0.7745966692414834,
                new_start: 5,
                n_runs: 5,
                dof: 5,
            },
        );

        // Too few samples -> None.
        assert!(find_best_regression(&[0.0, 1.0], &[0.0, 1.0], &[1.0, 1.0], 2, 0, 1).is_none());
    }

    #[test]
    fn find_best_regression_with_extra_samples() {
        // Case B: m=2 extra (older) samples extend the runs test; no drop.
        let xb: Vec<f64> = (-2..12).map(|i| i as f64).collect();
        let yb: Vec<f64> = (-2..12)
            .enumerate()
            .map(|(k, i)| 2.0 - 1.0 * i as f64 + if k % 2 == 1 { 0.2 } else { -0.2 })
            .collect();
        let wb = vec![1.0; 14];
        let r = find_best_regression(&xb, &yb, &wb, 12, 2, 4).unwrap();
        assert_eq!(r.new_start, 0);
        assert_eq!(r.n_runs, 12);
        assert!((r.intercept - 1.953846153846154).abs() < 1e-9);
        assert!((r.slope - (-0.9916083916083916)).abs() < 1e-9);
        assert!((r.variance - 0.04699300699300694).abs() < 1e-9);
    }

    #[test]
    fn median_matches_sort_oracle_and_preserves_input() {
        // Deterministic LCG so the test is reproducible without an rng dependency.
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((state >> 33) as f64 / (1u64 << 31) as f64) - 1.0
        };
        for n in 1..=MAX_POINTS {
            for _ in 0..20 {
                let data: Vec<f64> = (0..n).map(|_| next()).collect();
                assert_eq!(find_median(&data), naive_median(&data), "n={n}");
            }
        }
    }

    #[test]
    fn median_handles_duplicates_and_small_sets() {
        assert_eq!(find_median(&[5.0]), 5.0);
        assert_eq!(find_median(&[2.0, 2.0, 2.0, 2.0]), 2.0);
        assert_eq!(find_median(&[3.0, 1.0]), 2.0);
        assert_eq!(find_median(&[1.0, 2.0, 3.0]), 2.0);
        assert_eq!(find_median(&[4.0, 1.0, 3.0, 2.0]), 2.5);
    }
}
