use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const OVERLAY_PATH: &str = "evaluation/production-identity/causal-evidence-overlay.toml";
const OVERLAY_SCHEMA: &str = "nexus.research.production-identity.causal-evidence-overlay.v2";
const OVERLAY_REVISION: usize = 1;
const OVERLAY_AS_OF: &str = "2026-07-20";
const PROMOTION_POLICY: &str = "locked-empty-until-structured-v3";
const RFC_PATH: &str = "docs/rfcs/0003-causal-coverage-closure.md";
const BASE_COVERAGE_PATH: &str = "evaluation/production-identity/causal-coverage.toml";
const BASE_COVERAGE_SHA256: &str =
    "5f2d71fadf0275217f0e28ede923551fb84b5a7530c832a81930e9ce24c54bbe";
const BASE_MATRIX_PATH: &str = "evaluation/production-identity/causal-fault-matrix.toml";
const BASE_MATRIX_SHA256: &str = "9813ee8d26a2d72b383d8c4a7fbf7b193d8b0b1aa84e0fe49d4645fdd9ad818e";
const BASE_MATRIX_SEMANTIC_SHA256: &str =
    "fdd636526fde6c77d17d3a1acd9e4cb88a030230c4aeaa9f2cdf9245d5d05075";
const BASE_CELL_COUNT: usize = 66;
const BASE_STATE: &str = "planned";
const STATUS_EMPTY: &str = "incomplete-no-promotions";
const ROOT_OWNED_OBLIGATION: &str = "root-owned-obligation";
const CLASSIFICATIONS: &[&str] = &[
    "tracked-effect",
    "root-owned-publication",
    ROOT_OWNED_OBLIGATION,
    "kernel-tcb-infrastructure",
    "uncovered-gap",
];
const EVIDENCE_STATES: &[&str] = &["planned", "source-mapped", "observed"];

#[derive(Debug)]
pub(crate) struct Summary {
    pub(crate) cells: usize,
    pub(crate) promotions: usize,
    pub(crate) planned: usize,
    pub(crate) source_mapped: usize,
    pub(crate) observed: usize,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Overlay {
    schema: String,
    overlay_revision: usize,
    as_of: String,
    rfc: String,
    base_coverage: String,
    base_coverage_sha256: String,
    base_matrix: String,
    base_matrix_sha256: String,
    base_matrix_semantic_sha256: String,
    base_cell_count: usize,
    base_state: String,
    promotion_policy: String,
    status: String,
    complete: bool,
    allowed_classifications: Vec<String>,
    allowed_evidence_states: Vec<String>,
    promotion_count: usize,
    planned_count: usize,
    source_mapped_count: usize,
    observed_count: usize,
    #[serde(default)]
    promotion: Vec<toml::Value>,
}

pub(crate) fn validate(root: &Path) -> Result<Summary, String> {
    let matrix_summary = super::causal_fault_matrix::validate(root)
        .map_err(|error| format!("base v1 matrix: {error}"))?;
    if matrix_summary.cells != BASE_CELL_COUNT
        || matrix_summary.planned != BASE_CELL_COUNT
        || matrix_summary.source_mapped != 0
        || matrix_summary.observed != 0
        || matrix_summary.canonical_sha256 != BASE_MATRIX_SEMANTIC_SHA256
    {
        return Err("base v1 matrix semantic population drifted".into());
    }

    let coverage = read_regular_bytes(root, BASE_COVERAGE_PATH)?;
    require_digest(BASE_COVERAGE_PATH, &coverage, BASE_COVERAGE_SHA256)?;
    let matrix = read_regular_bytes(root, BASE_MATRIX_PATH)?;
    require_digest(BASE_MATRIX_PATH, &matrix, BASE_MATRIX_SHA256)?;

    let bytes = read_regular_bytes(root, OVERLAY_PATH)?;
    let overlay: Overlay = toml::from_str(
        std::str::from_utf8(&bytes)
            .map_err(|error| format!("{OVERLAY_PATH} is not UTF-8: {error}"))?,
    )
    .map_err(|error| format!("parse {OVERLAY_PATH}: {error}"))?;
    validate_document(&overlay)
}

fn validate_document(overlay: &Overlay) -> Result<Summary, String> {
    require_eq("schema", &overlay.schema, OVERLAY_SCHEMA)?;
    if overlay.overlay_revision != OVERLAY_REVISION {
        return Err(format!(
            "overlay_revision must remain {OVERLAY_REVISION} while v2 is locked empty"
        ));
    }
    require_eq("as_of", &overlay.as_of, OVERLAY_AS_OF)?;
    require_eq("rfc", &overlay.rfc, RFC_PATH)?;
    require_eq("base_coverage", &overlay.base_coverage, BASE_COVERAGE_PATH)?;
    require_eq(
        "base_coverage_sha256",
        &overlay.base_coverage_sha256,
        BASE_COVERAGE_SHA256,
    )?;
    require_eq("base_matrix", &overlay.base_matrix, BASE_MATRIX_PATH)?;
    require_eq(
        "base_matrix_sha256",
        &overlay.base_matrix_sha256,
        BASE_MATRIX_SHA256,
    )?;
    require_eq(
        "base_matrix_semantic_sha256",
        &overlay.base_matrix_semantic_sha256,
        BASE_MATRIX_SEMANTIC_SHA256,
    )?;
    if overlay.base_cell_count != BASE_CELL_COUNT {
        return Err(format!(
            "overlay base must remain the exact {BASE_CELL_COUNT}-cell v1 population"
        ));
    }
    require_eq("base_state", &overlay.base_state, BASE_STATE)?;
    require_eq(
        "promotion_policy",
        &overlay.promotion_policy,
        PROMOTION_POLICY,
    )?;

    // v2 deliberately has no promotion semantics. Reject a non-empty log before
    // inspecting any row so no syntactic source or receipt heuristic can be
    // mistaken for evidence. Opening the log requires a separately reviewed v3.
    if !overlay.promotion.is_empty() {
        return Err(format!(
            "causal evidence overlay v2 is locked empty by promotion_policy={PROMOTION_POLICY}; any promotion requires a structured v3 schema and validator"
        ));
    }

    require_eq("status", &overlay.status, STATUS_EMPTY)?;
    if overlay.complete {
        return Err("causal evidence overlay complete must remain false".into());
    }
    require_exact_list(
        "allowed_classifications",
        &overlay.allowed_classifications,
        CLASSIFICATIONS,
    )?;
    require_exact_list(
        "allowed_evidence_states",
        &overlay.allowed_evidence_states,
        EVIDENCE_STATES,
    )?;
    if overlay.promotion_count != 0
        || overlay.planned_count != BASE_CELL_COUNT
        || overlay.source_mapped_count != 0
        || overlay.observed_count != 0
    {
        return Err(format!(
            "locked-empty overlay counts must remain promotions=0 planned={BASE_CELL_COUNT} source-mapped=0 observed=0"
        ));
    }

    Ok(Summary {
        cells: BASE_CELL_COUNT,
        promotions: 0,
        planned: BASE_CELL_COUNT,
        source_mapped: 0,
        observed: 0,
        complete: false,
    })
}

fn read_regular_bytes(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    let path = root.join(relative);
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| format!("inspect {relative}: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "path must be a regular non-symlink file: {relative}"
        ));
    }
    fs::read(&path).map_err(|error| format!("read {relative}: {error}"))
}

fn require_digest(field: &str, bytes: &[u8], expected: &str) -> Result<(), String> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected {
        return Err(format!(
            "{field} byte digest drifted: expected {expected}, found {actual}"
        ));
    }
    Ok(())
}

fn require_eq(field: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} must be {expected}, found {actual}"))
    }
}

fn require_exact_list(field: &str, actual: &[String], expected: &[&str]) -> Result<(), String> {
    if actual.len() != expected.len()
        || actual
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual != expected)
    {
        return Err(format!("{field} must equal {expected:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn fixture() -> Overlay {
        let overlay = fs::read_to_string(root().join(OVERLAY_PATH)).unwrap();
        toml::from_str(&overlay).unwrap()
    }

    #[test]
    fn repository_overlay_is_locked_empty_and_byte_freezes_both_v1_inputs() {
        let summary = validate(&root()).unwrap();
        assert_eq!(summary.cells, 66);
        assert_eq!(summary.promotions, 0);
        assert_eq!(summary.planned, 66);
        assert_eq!(summary.source_mapped, 0);
        assert_eq!(summary.observed, 0);
        assert!(!summary.complete);

        let coverage = fs::read(root().join(BASE_COVERAGE_PATH)).unwrap();
        require_digest(BASE_COVERAGE_PATH, &coverage, BASE_COVERAGE_SHA256).unwrap();
        let matrix = fs::read(root().join(BASE_MATRIX_PATH)).unwrap();
        require_digest(BASE_MATRIX_PATH, &matrix, BASE_MATRIX_SHA256).unwrap();
    }

    #[test]
    fn rejects_any_nonempty_promotion_before_interpreting_rows() {
        let mut overlay = fixture();
        overlay
            .promotion
            .push(toml::Value::String("intentionally-uninterpreted".into()));
        let error = validate_document(&overlay).unwrap_err();
        assert!(error.contains("locked empty"));
        assert!(error.contains("structured v3"));
    }

    #[test]
    fn rejects_policy_status_count_and_completion_drift() {
        let mut policy = fixture();
        policy.promotion_policy = "open".into();
        assert!(
            validate_document(&policy)
                .unwrap_err()
                .contains("promotion_policy")
        );

        let mut status = fixture();
        status.status = "incomplete-promotions-recorded".into();
        assert!(validate_document(&status).unwrap_err().contains("status"));

        let mut counts = fixture();
        counts.promotion_count = 1;
        assert!(validate_document(&counts).unwrap_err().contains("counts"));

        let mut complete = fixture();
        complete.complete = true;
        assert!(
            validate_document(&complete)
                .unwrap_err()
                .contains("complete")
        );
    }
}
