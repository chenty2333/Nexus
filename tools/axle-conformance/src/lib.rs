#![forbid(unsafe_code)]

//! Axle conformance runner core.
//!
//! This crate loads declarative scenarios/profiles and executes them as
//! reproducible command-based conformance cases.

pub mod gc;
pub mod model;
pub mod report;
pub mod runner;
pub mod selection;
pub mod test_id;

pub use model::{ProfileSpec, ScenarioSpec};
pub use report::{CaseReport, CaseStatus, Manifest, RunSummary};
pub use runner::{RunConfig, run_conformance};
