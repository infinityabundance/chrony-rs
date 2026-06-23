//! Tests for `ntp_core.c` Stage 16 (protocol support helpers).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** The slew/step offset
//! tracking, the saved-response predicate, and the quantile comparison are captured via
//! the `#include` harness (`/tmp/ncor/genaux.c`,
//! `research/oracle/ntp_core-support-c-vectors.txt`). [`matches_real_c_support_vectors`]
//! replays them and matches every value.
//!
//! **Oracle #2 (independent): boundaries.** The accumulate/reset transition and the
//! quantile/timeout boundaries are checked directly.

use super::*;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}
fn line<'a>(v: &'a str, tag: &str) -> &'a str {
    v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap()
}

#[test]
fn matches_real_c_support_vectors() {
    let v = include_str!("../../../../../research/oracle/ntp_core-support-c-vectors.txt");

    // handle_slew: start offset 2.0, doffset 0.5.
    let chk_slew = |tag: &str, ct: ChangeType| {
        let l = line(v, tag);
        let r = handle_slew(2.0, ct, 0.5);
        assert_eq!(r.mono_offset, field(l, "offset").parse::<f64>().unwrap(), "{tag} offset");
        assert_eq!(r.reseed_epoch as i32, field(l, "reseed").parse::<i32>().unwrap(), "{tag} reseed");
    };
    chk_slew("SLEW_ADJUST", ChangeType::Adjust);
    chk_slew("SLEW_STEP", ChangeType::Step);
    chk_slew("SLEW_UNKNOWN", ChangeType::UnknownStep);

    // has_saved_response.
    assert_eq!(has_saved_response(false, 0) as i32, field(line(v, "HSR_NONE"), "ret").parse::<i32>().unwrap());
    assert_eq!(has_saved_response(true, 0) as i32, field(line(v, "HSR_ZERO_TIMEOUT"), "ret").parse::<i32>().unwrap());
    assert_eq!(has_saved_response(true, 5) as i32, field(line(v, "HSR_ACTIVE"), "ret").parse::<i32>().unwrap());

    // check_delay_quant: quantile 0.05.
    assert_eq!(check_delay_quant(0.05, 0.02) as i32, field(line(v, "CDQ_UNDER"), "ret").parse::<i32>().unwrap());
    assert_eq!(check_delay_quant(0.05, 0.05) as i32, field(line(v, "CDQ_EQUAL"), "ret").parse::<i32>().unwrap());
    assert_eq!(check_delay_quant(0.05, 0.5) as i32, field(line(v, "CDQ_OVER"), "ret").parse::<i32>().unwrap());
}

#[test]
fn slew_accumulates_step_resets() {
    // Successive slews accumulate.
    let a = handle_slew(0.0, ChangeType::Adjust, 0.1);
    let b = handle_slew(a.mono_offset, ChangeType::Adjust, 0.2);
    assert!((b.mono_offset - 0.3).abs() < 1e-12);
    assert!(!a.reseed_epoch && !b.reseed_epoch);
    // A step wipes the accumulated offset and reseeds.
    let s = handle_slew(b.mono_offset, ChangeType::Step, 0.9);
    assert_eq!(s.mono_offset, 0.0);
    assert!(s.reseed_epoch);
}

#[test]
fn predicate_and_quantile_boundaries() {
    assert!(!has_saved_response(true, 0), "timeout must be > 0");
    assert!(!has_saved_response(false, 5), "must have a saved response");
    assert!(has_saved_response(true, 1), "active");
    assert!(check_delay_quant(0.1, 0.1), "delay == quantile accepted");
    assert!(!check_delay_quant(0.1, 0.10001), "just over rejected");
}
