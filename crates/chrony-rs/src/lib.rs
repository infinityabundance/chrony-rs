//! # chrony-rs
//!
//! Umbrella crate for **chrony-rs** — a forensic Rust reconstruction of chrony's
//! time-discipline behavior. This crate re-exports the deterministic, host-free
//! core ([`chrony_rs_core`]); the `chronyd-rs` (daemon/replay) and `chronyc-rs`
//! (control client) binaries are separate crates in the same workspace.
//!
//! `chrony-rs` is a forensic reconstruction, **not** a production NTP daemon. See
//! the workspace `README.md`, `docs/deployment-boundary.md`, and
//! `docs/negative-capabilities.md` for the claim boundary.
//!
//! This is a `0.0.1` placeholder release that establishes the crate; the public
//! surface will stabilize in later versions.
#![forbid(unsafe_code)]

#[doc(inline)]
pub use chrony_rs_core as core;
