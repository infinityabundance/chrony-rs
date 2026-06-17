//! Tests for `ntp_core.c` Stage 13 (`NCR_CreateInstance` parameter mapping).
//!
//! **Oracle #1 (gold standard): the real compiled `ntp_core.c`.** An instance is built
//! from each parameter set via the `#include` harness and the mapped fields captured
//! (`/tmp/ncor/genci.c`, `research/oracle/ntp_core-create-c-vectors.txt`).
//! [`matches_real_c_create_vectors`] reproduces each scenario and matches every field.
//!
//! **Oracle #2 (independent): the default/clamp/version invariants.** The poll defaults,
//! the peer copy/presend rules, and the version selection are checked directly.

use super::*;

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}="))).unwrap()
}

/// The generator's default parameter set (`defp()` in genci.c).
fn defp() -> SourceParameters {
    SourceParameters {
        minpoll: 4,
        maxpoll: 10,
        min_stratum: 1,
        presend_minpoll: 100,
        poll_target: 6,
        version: 0,
        interleaved: false,
        ext_fields: 0,
        copy: true,
        iburst: true,
        burst: false,
        auto_offline: true,
        max_delay: 0.3,
        max_delay_ratio: 3.0,
        max_delay_dev_ratio: 1.5,
        offset: 0.001,
    }
}

/// Reproduce a scenario tag exactly as genci.c sets it up.
fn scenario(tag: &str) -> InstanceConfig {
    let (ty, suggested, p) = match tag {
        "CI_SERVER" => (SourceType::Server, 4, defp()),
        "CI_PEER" => (SourceType::Peer, 4, defp()),
        "CI_PEER_PRESEND" => (SourceType::Peer, 4, SourceParameters { presend_minpoll: 6, ..defp() }),
        "CI_POLL_DEFAULTS" => (SourceType::Server, 4, SourceParameters { minpoll: -100, maxpoll: -100, ..defp() }),
        "CI_POLL_HI" => (SourceType::Server, 4, SourceParameters { minpoll: 99, maxpoll: 99, ..defp() }),
        "CI_MAXLTMIN" => (SourceType::Server, 4, SourceParameters { minpoll: 8, maxpoll: 5, ..defp() }),
        "CI_STRATUM_CLAMP" => (SourceType::Server, 4, SourceParameters { min_stratum: 20, ..defp() }),
        "CI_DELAY_CLAMP" => (SourceType::Server, 4, SourceParameters { max_delay: -1.0, max_delay_ratio: 1e9, max_delay_dev_ratio: 1e9, ..defp() }),
        "CI_POLLTARGET" => (SourceType::Server, 4, SourceParameters { poll_target: 0, ..defp() }),
        "CI_VER_SUGGESTED" => (SourceType::Server, 3, defp()),
        "CI_VER_INTERLEAVED" => (SourceType::Server, 3, SourceParameters { interleaved: true, ..defp() }),
        "CI_VER_EXT" => (SourceType::Server, 3, SourceParameters { ext_fields: 1, ..defp() }),
        "CI_VER_EXPLICIT_HI" => (SourceType::Server, 4, SourceParameters { version: 9, ..defp() }),
        "CI_VER_EXPLICIT_LO" => (SourceType::Server, 4, SourceParameters { version: -5, ..defp() }),
        other => panic!("unknown scenario {other}"),
    };
    create_instance_config(ty, &p, suggested)
}

#[test]
fn matches_real_c_create_vectors() {
    let vectors = include_str!("../../../../../research/oracle/ntp_core-create-c-vectors.txt");
    for l in vectors.lines().map(str::trim).filter(|l| l.starts_with("CI_")) {
        let tag = l.split_whitespace().next().unwrap();
        let c = scenario(tag);
        let i = |k| field(l, k).parse::<i32>().unwrap();
        let d = |k| field(l, k).parse::<f64>().unwrap();
        let b = |k| field(l, k) == "1";
        assert_eq!(c.mode, i("mode"), "{tag} mode");
        assert_eq!(c.interleaved, b("interleaved"), "{tag} interleaved");
        assert_eq!(c.minpoll, i("minpoll"), "{tag} minpoll");
        assert_eq!(c.maxpoll, i("maxpoll"), "{tag} maxpoll");
        assert_eq!(c.min_stratum, i("min_stratum"), "{tag} min_stratum");
        assert_eq!(c.presend_minpoll, i("presend_minpoll"), "{tag} presend_minpoll");
        assert_eq!(c.max_delay, d("max_delay"), "{tag} max_delay");
        assert_eq!(c.max_delay_ratio, d("max_delay_ratio"), "{tag} max_delay_ratio");
        assert_eq!(c.max_delay_dev_ratio, d("max_delay_dev_ratio"), "{tag} max_delay_dev_ratio");
        assert_eq!(c.offset_correction, d("offset_correction"), "{tag} offset_correction");
        assert_eq!(c.auto_iburst, b("auto_iburst"), "{tag} auto_iburst");
        assert_eq!(c.auto_burst, b("auto_burst"), "{tag} auto_burst");
        assert_eq!(c.auto_offline, b("auto_offline"), "{tag} auto_offline");
        assert_eq!(c.copy, b("copy"), "{tag} copy");
        assert_eq!(c.poll_target, i("poll_target"), "{tag} poll_target");
        assert_eq!(c.ext_field_flags, i("ext_field_flags"), "{tag} ext_field_flags");
        assert_eq!(c.version, i("version"), "{tag} version");
    }
}

#[test]
fn defaults_clamps_and_version() {
    // Peer: active mode, copy forced off, presend disabled when within range.
    let peer = create_instance_config(SourceType::Peer, &SourceParameters { copy: true, presend_minpoll: 6, ..defp() }, 4);
    assert_eq!(peer.mode, 1);
    assert!(!peer.copy, "copy only for clients");
    assert_eq!(peer.presend_minpoll, MAX_POLL + 1, "presend disabled for peers");

    // Below-range poll values fall back to the source defaults.
    let d = create_instance_config(SourceType::Server, &SourceParameters { minpoll: -100, maxpoll: -100, ..defp() }, 4);
    assert_eq!((d.minpoll, d.maxpoll), (SRC_DEFAULT_MINPOLL, SRC_DEFAULT_MAXPOLL));

    // maxpoll is never below minpoll.
    let m = create_instance_config(SourceType::Server, &SourceParameters { minpoll: 8, maxpoll: 5, ..defp() }, 4);
    assert_eq!(m.maxpoll, 8);

    // Version: interleaved/ext force NTP_VERSION; explicit clamps; else suggested.
    assert_eq!(create_instance_config(SourceType::Server, &defp(), 3).version, 3);
    assert_eq!(create_instance_config(SourceType::Server, &SourceParameters { interleaved: true, ..defp() }, 3).version, NTP_VERSION);
    assert_eq!(create_instance_config(SourceType::Server, &SourceParameters { version: 9, ..defp() }, 4).version, NTP_VERSION);
    assert_eq!(create_instance_config(SourceType::Server, &SourceParameters { version: -5, ..defp() }, 4).version, NTP_MIN_COMPAT_VERSION);
}
