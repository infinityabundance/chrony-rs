//! Tests for monotonic-root sample selection (`ntp_core.c` mono-root handling).
//!
//! Oracle: the real compiled `ntp_core.c`. `process_response` is driven with/without a
//! real `add_ef_mono_root`-built extension field (`/tmp/ncor/genmono.c`,
//! `research/oracle/ntp_core-monoroot-c-vectors.txt`), capturing the selected root
//! delay/dispersion, the offset handed to `SST_CorrectOffset`, and the instance's
//! monotonic state.

use super::*;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

#[test]
fn matches_real_c_mono_root() {
    let v = include_str!("../../../../../research/oracle/ntp_core-monoroot-c-vectors.txt");
    let line = |tag: &str| v.lines().map(str::trim).find(|l| l.starts_with(tag)).unwrap();

    // The generator's fixed monotonic epoch and prior-state inputs.
    const SERVER_EPOCH: u32 = 0xABCD1234;

    // (tag, epoch_match) — MONO_MISMATCH stored a different prior epoch.
    for (tag, epoch_match) in [("MONO_PRESENT", true), ("MONO_MISMATCH", false), ("MONO_ABSENT", true)] {
        let l = line(tag);
        let fd = |k: &str| field(l, k).parse::<f64>().unwrap();
        let u = |k: &str| field(l, k).parse::<u64>().unwrap();
        let u32f = |k: &str| field(l, k).parse::<u32>().unwrap();
        let ef_present = field(l, "ef_present") == "1";

        // select_root.
        let ef = ef_present.then(|| (u32f("ef_rd_raw"), u32f("ef_rdsp_raw")));
        let (rd, rdsp) = select_root(ef, u32f("hdr_rd"), u32f("hdr_rdsp"));
        assert_eq!(rd, fd("root_delay"), "{tag} root_delay");
        assert_eq!(rdsp, fd("root_dispersion"), "{tag} root_dispersion");

        // compute_mono_doffset (the value handed to SST_CorrectOffset, applied only when
        // non-zero -> correct_calls reflects whether it ran).
        let doffset = compute_mono_doffset(
            ef_present,
            epoch_match,
            u("ef_monorx"),
            u("prior_monorx"),
            u("msg_rx"),
            u("prior_rx"),
        );
        let correct_calls: i32 = field(l, "correct_calls").parse().unwrap();
        if correct_calls == 1 {
            assert_eq!(doffset, fd("corrected_offset"), "{tag} mono_doffset");
            assert!(doffset != 0.0, "{tag} nonzero offset implies a correction call");
        } else {
            // No correction call -> the computed offset was zero.
            assert_eq!(doffset, 0.0, "{tag} mono_doffset zero");
        }

        // update_mono_state (prior accumulator was zeroed before the call).
        let st = update_mono_state(ef_present, u("ef_monorx"), SERVER_EPOCH, doffset, 0.0);
        assert_eq!(st.remote_mono_epoch, u32f("remote_mono_epoch"), "{tag} remote_mono_epoch");
        assert_eq!(st.remote_ntp_monorx, u("remote_ntp_monorx"), "{tag} remote_ntp_monorx");
    }
}

#[test]
fn mono_doffset_clamps_out_of_range() {
    // A huge monotonic step (> MAX_MONO_DOFFSET) is rejected to 0. Build two ntp64 a
    // full ~100 s apart in the monotonic series but ~0 in the real series.
    let sec = |s: u64| s << 32;
    let big = compute_mono_doffset(true, true, sec(2_000_000_100), sec(2_000_000_000), sec(2_000_000_000), sec(2_000_000_000));
    assert_eq!(big, 0.0);
    // Absent / epoch-mismatch / zero-timestamp all yield 0.
    assert_eq!(compute_mono_doffset(false, true, sec(2), sec(1), sec(2), sec(1)), 0.0);
    assert_eq!(compute_mono_doffset(true, false, sec(2), sec(1), sec(2), sec(1)), 0.0);
    assert_eq!(compute_mono_doffset(true, true, 0, sec(1), sec(2), sec(1)), 0.0);
}
