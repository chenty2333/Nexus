use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::elf::ElfCheckReport;

/// Status of a single conformance case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Pass,
    Fail,
}

/// Detailed per-case outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseReport {
    pub scenario_id: String,
    pub status: CaseStatus,
    pub attempts: u32,
    pub duration_ms: u128,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub reason: Option<String>,
    pub missing_expect: Vec<String>,
    pub matched_forbid: Vec<String>,
    pub parsed_metrics: BTreeMap<String, i64>,
    pub assertion_mismatches: Vec<String>,
    pub elf_check: Option<ElfCheckReport>,
    pub case_dir: String,
}

/// Run manifest for reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub test_id: String,
    pub selected_scenarios: Vec<String>,
    pub scenario_filters: Vec<String>,
    pub tag_filters: Vec<String>,
    pub started_unix_ms: u128,
}

/// Top-level run summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub test_id: String,
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub flaky_pass: usize,
    pub duration_ms: u128,
    pub report_path: String,
    pub cases: Vec<CaseReport>,
}
