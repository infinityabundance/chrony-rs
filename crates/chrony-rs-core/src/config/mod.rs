//! chrony configuration parsing — the first behavior-parity surface.
//!
//! chrony's config grammar is line-oriented: each non-blank, non-comment line is
//! a *directive* (a keyword) followed by directive-specific arguments, separated
//! by arbitrary runs of spaces and tabs. There is no block structure and no
//! statement terminator. This module reproduces that grammar and, just as
//! importantly, chrony's *diagnostics* for malformed input — the exact set of
//! complaints `chronyd -p` / `chronyd --check-config` produces is a court
//! (`CHRONY.CONFIG.12`, `CHRONY.CONFIG.14`).
//!
//! # Scope (read the negative-capability ledger before extending)
//!
//! Only an admitted subset of directives is *modeled* (turned into typed
//! structure). Every other directive is still *recognized* and preserved as a
//! [`model::Directive::Unmodeled`] so that:
//!
//!   * `--check-config` does not falsely reject a valid chrony file just because
//!     we haven't modeled a directive yet, and
//!   * we never silently drop a line.
//!
//! Claiming a directive is "supported" requires an oracle case in
//! `docs/config-atlas.md`. Recognizing the keyword is not the same as admitting
//! its semantics, and the two must not be conflated.

pub mod diagnostics;
pub mod lexer;
pub mod model;
pub mod parser;

pub use diagnostics::{Diagnostic, Severity};
pub use model::{Config, Directive, ServerKind, SourceDirective};
pub use parser::{
    known_directives, parse, source_flag_options, source_value_options, ParseOutput,
};
