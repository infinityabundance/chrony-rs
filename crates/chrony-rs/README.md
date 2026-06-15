# chrony-rs

A forensic Rust reconstruction of chrony time-discipline behavior.

This is the umbrella crate; it re-exports the deterministic core
[`chrony-rs-core`](https://crates.io/crates/chrony-rs-core). The `chronyd-rs`
(daemon/replay) and `chronyc-rs` (control client) binaries are separate crates
in the same workspace.

**chrony-rs is a forensic reconstruction, not a production NTP daemon.** See the
project repository for the full claim boundary and negative-capabilities
register.

`0.0.1` is a placeholder release that establishes the crate.
