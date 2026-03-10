#![forbid(unsafe_code)]

//! Axle conformance runner core.
//!
//! This crate loads declarative scenarios and executes them as
//! reproducible command-based conformance cases.

pub mod contracts;
pub mod elf;
pub mod gc;
pub mod model;
pub mod report;
pub mod runner;
pub mod selection;
pub mod test_id;

pub use model::ScenarioSpec;
pub use report::{CaseReport, CaseStatus, GroupReport, Manifest, RunSummary};
pub use runner::{RunConfig, run_conformance};
