//! Source model, reachability, and selection (Stage 4).
//!
//! This is the first module where `chrony-rs` reconstructs *chrony policy* rather
//! than wire format or plumbing, so the honesty bar is highest here. Two distinct
//! confidence levels coexist and are labelled per item:
//!
//!   * [`reachability`] — exactly specified chrony behavior (the 8-bit shift
//!     register), reconstructed precisely.
//!   * [`selection`] — the *core idea* of chrony's falseticker intersection,
//!     reconstructed from the published algorithm but NOT byte/decision-identical
//!     to chrony's full selector (no cluster/combine, no `f`-loop refinement, no
//!     reselection hysteresis). This is an algorithmic court pending an oracle
//!     capture, not an oracle-witnessed parity claim.
//!
//! See `docs/source-selection-atlas.md` and `docs/filtering-atlas.md`.

pub mod reachability;
pub mod registry;
pub mod selection;
pub mod source;

pub use reachability::Reachability;
pub use selection::{select, SelectionOutcome};
pub use source::{SampleSummary, Source, SourceStatus};
