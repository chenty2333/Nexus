#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Trace conformance between `specs/cser/Cser.tla` and the `cser-model` oracle.
//!
//! This crate replays TLC counterexample behaviors of the baseline CSER
//! specification against the independent Rust reference model, so the
//! correspondence between the two artifacts is machine-checked for the
//! replayed behaviors rather than asserted in prose.
//!
//! What the lane establishes, and what it does not, is stated in this crate's
//! `README.md`. In short: it is a *checked trace-conformance witness* for the
//! behaviors the listed witnesses produce. It is not a refinement proof, and
//! it covers two of the fourteen specification families in `specs/cser/`.
//!
//! Each family owns a module here holding its action catalog, its projection,
//! its replay engine, and its witness set. [`trace`], [`value`], [`tlc`],
//! [`report`], and [`sha256`] are the shared harness.

use std::path::{Path, PathBuf};

pub mod cser;
pub mod production_identity;
pub mod report;
pub mod sha256;
pub mod tlc;
pub mod trace;
pub mod value;

/// Returns the repository root as resolved from this crate's manifest.
#[must_use]
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

/// Returns the path of a specification family's module.
#[must_use]
pub fn spec_path(module: &str) -> PathBuf {
    repo_root().join("specs/cser").join(format!("{module}.tla"))
}
