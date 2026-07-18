use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

const LEDGER_PATH: &str = "evaluation/production-identity/causal-coverage.toml";
const LEDGER_SCHEMA: &str = "nexus.production-identity.causal-coverage.v1";
const WORKLOAD: &str = "linux-runtime-fs-smoke-first-executable-pread64";
const SCOPE: &str = "bounded-same-boot-single-vcpu-polling-checkpoint";
const CLAIM: &str = "machine-readable-audited-inventory-not-runtime-coverage-gate-or-phase-closure";
const INCOMPLETE_STATUS: &str = "incomplete-explicit-gaps";
const VALIDATOR_LIMITATION: &str = "freezes-declared-inventory-and-regular-source-files-but-cannot-discover-undeclared-runtime-or-source-boundaries";
const TCB_POLICY: &str = "request-derived-authority-must-join-the-root-unless-a-reviewed-row-records-why-kernel-infrastructure-cannot-retain-or-publish-it";
const CLASSIFICATIONS: [&str; 4] = [
    "tracked-effect",
    "root-owned-publication",
    "kernel-tcb-infrastructure",
    "uncovered-gap",
];
const EXPECTED_BOUNDARIES: [(&str, &str); 20] = [
    ("task-admission", "uncovered-gap"),
    ("service-death", "root-owned-publication"),
    ("page-fault", "uncovered-gap"),
    ("syscall-root-admission", "tracked-effect"),
    ("filesystem-child", "tracked-effect"),
    ("block-request", "tracked-effect"),
    ("filesystem-service-request-queue", "uncovered-gap"),
    ("queue-dma-preparation", "uncovered-gap"),
    ("guest-waiter", "uncovered-gap"),
    ("guest-waker", "uncovered-gap"),
    ("timer-deadline", "uncovered-gap"),
    ("virtio-queue-publication", "root-owned-publication"),
    ("dma-queue-owner-a", "tracked-effect"),
    ("dma-queue-owner-b", "tracked-effect"),
    ("dma-request-owner", "tracked-effect"),
    ("device-completion", "root-owned-publication"),
    ("device-reset", "root-owned-publication"),
    ("iotlb-invalidation", "root-owned-publication"),
    ("backend-data-publication", "root-owned-publication"),
    ("guest-reply", "uncovered-gap"),
];

#[derive(Debug)]
pub(crate) struct Summary {
    pub(crate) boundaries: usize,
    pub(crate) tracked_effects: usize,
    pub(crate) root_owned_publications: usize,
    pub(crate) kernel_tcb_infrastructure: usize,
    pub(crate) uncovered_gaps: usize,
    pub(crate) overall_status: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: String,
    ledger_revision: u32,
    as_of: String,
    workload: String,
    scope: String,
    claim: String,
    overall_status: String,
    complete: bool,
    runtime_boundary_gate: bool,
    source_symbol_gate: bool,
    validator_limitation: String,
    boundary_count: usize,
    allowed_classifications: Vec<String>,
    tcb_policy: String,
    summary: CoverageSummary,
    boundary: Vec<Boundary>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageSummary {
    tracked_effect: usize,
    root_owned_publication: usize,
    kernel_tcb_infrastructure: usize,
    uncovered_gap: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundary {
    id: String,
    classification: String,
    owner: String,
    parent: Option<String>,
    tcb_rationale: Option<String>,
    creation_admission: String,
    commit_publication: String,
    cancel_recovery: String,
    terminal_closure: String,
    credit: String,
    source_paths: Vec<String>,
}

pub(crate) fn validate(root: &Path) -> Result<Summary, String> {
    let path = root.join(LEDGER_PATH);
    let source =
        fs::read_to_string(&path).map_err(|error| format!("read {LEDGER_PATH}: {error}"))?;
    let ledger: Ledger =
        toml::from_str(&source).map_err(|error| format!("parse {LEDGER_PATH}: {error}"))?;
    validate_document(root, &ledger)
}

fn validate_document(root: &Path, ledger: &Ledger) -> Result<Summary, String> {
    require_eq("schema", &ledger.schema, LEDGER_SCHEMA)?;
    if ledger.ledger_revision != 1 {
        return Err("ledger_revision must be 1".into());
    }
    require_date("as_of", &ledger.as_of)?;
    require_eq("workload", &ledger.workload, WORKLOAD)?;
    require_eq("scope", &ledger.scope, SCOPE)?;
    require_eq("claim", &ledger.claim, CLAIM)?;
    require_eq("overall_status", &ledger.overall_status, INCOMPLETE_STATUS)?;
    if ledger.complete {
        return Err("complete must remain false while uncovered gaps exist".into());
    }
    if ledger.runtime_boundary_gate || ledger.source_symbol_gate {
        return Err(
            "this tranche validates the audited inventory and regular source files, not runtime boundary discovery or source symbols"
                .into(),
        );
    }
    require_eq(
        "validator_limitation",
        &ledger.validator_limitation,
        VALIDATOR_LIMITATION,
    )?;
    require_eq("tcb_policy", &ledger.tcb_policy, TCB_POLICY)?;
    require_exact_list(
        "allowed_classifications",
        &ledger.allowed_classifications,
        &CLASSIFICATIONS,
    )?;
    if ledger.boundary_count != EXPECTED_BOUNDARIES.len()
        || ledger.boundary_count != ledger.boundary.len()
    {
        return Err(format!(
            "boundary_count must equal the frozen {}-row inventory",
            EXPECTED_BOUNDARIES.len()
        ));
    }

    let known_ids = EXPECTED_BOUNDARIES
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    let mut seen_ids = BTreeSet::new();
    let mut counts = [0_usize; CLASSIFICATIONS.len()];

    for (index, (boundary, (expected_id, expected_classification))) in ledger
        .boundary
        .iter()
        .zip(EXPECTED_BOUNDARIES.iter())
        .enumerate()
    {
        if boundary.id != *expected_id || boundary.classification != *expected_classification {
            return Err(format!(
                "boundary[{index}] must be {expected_id}:{expected_classification}, found {}:{}",
                boundary.id, boundary.classification
            ));
        }
        if !seen_ids.insert(boundary.id.as_str()) {
            return Err(format!("duplicate boundary id: {}", boundary.id));
        }
        let classification_index = CLASSIFICATIONS
            .iter()
            .position(|classification| *classification == boundary.classification)
            .ok_or_else(|| {
                format!(
                    "boundary {} has unsupported classification {}",
                    boundary.id, boundary.classification
                )
            })?;
        counts[classification_index] += 1;
        validate_boundary(root, boundary, &known_ids)?;
    }
    validate_parent_graph(&ledger.boundary)?;

    let recorded_counts = [
        ledger.summary.tracked_effect,
        ledger.summary.root_owned_publication,
        ledger.summary.kernel_tcb_infrastructure,
        ledger.summary.uncovered_gap,
    ];
    if recorded_counts != counts {
        return Err(format!(
            "summary counts {recorded_counts:?} do not match boundary counts {counts:?}"
        ));
    }
    if counts[3] == 0 {
        return Err("this checkpoint must not claim complete causal coverage".into());
    }

    Ok(Summary {
        boundaries: ledger.boundary.len(),
        tracked_effects: counts[0],
        root_owned_publications: counts[1],
        kernel_tcb_infrastructure: counts[2],
        uncovered_gaps: counts[3],
        overall_status: ledger.overall_status.clone(),
    })
}

fn validate_parent_graph(boundaries: &[Boundary]) -> Result<(), String> {
    let by_id = boundaries
        .iter()
        .map(|boundary| (boundary.id.as_str(), boundary))
        .collect::<BTreeMap<_, _>>();
    for boundary in boundaries {
        if boundary.classification == "kernel-tcb-infrastructure" {
            continue;
        }
        let mut path = BTreeSet::new();
        let mut current = boundary.id.as_str();
        loop {
            if !path.insert(current) {
                return Err(format!(
                    "boundary {} parent graph contains a cycle at {current}",
                    boundary.id
                ));
            }
            let record = by_id
                .get(current)
                .ok_or_else(|| format!("boundary {} parent graph lost {current}", boundary.id))?;
            match record.parent.as_deref() {
                Some("root" | "unresolved") => break,
                Some(parent) => current = parent,
                None => {
                    return Err(format!(
                        "boundary {} parent graph terminates at non-rooted {}",
                        boundary.id, record.id
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_boundary(
    root: &Path,
    boundary: &Boundary,
    known_ids: &BTreeSet<&str>,
) -> Result<(), String> {
    for (field, value) in [
        ("owner", &boundary.owner),
        ("creation_admission", &boundary.creation_admission),
        ("commit_publication", &boundary.commit_publication),
        ("cancel_recovery", &boundary.cancel_recovery),
        ("terminal_closure", &boundary.terminal_closure),
        ("credit", &boundary.credit),
    ] {
        require_nonempty(&format!("boundary {} {field}", boundary.id), value)?;
    }

    match boundary.classification.as_str() {
        "kernel-tcb-infrastructure" => {
            if boundary.parent.is_some() {
                return Err(format!(
                    "boundary {} is TCB infrastructure and must not name a root parent",
                    boundary.id
                ));
            }
            require_optional_nonempty(
                &format!("boundary {} tcb_rationale", boundary.id),
                boundary.tcb_rationale.as_deref(),
            )?;
        }
        _ => {
            if boundary.tcb_rationale.is_some() {
                return Err(format!(
                    "boundary {} may only carry tcb_rationale when classified as kernel-tcb-infrastructure",
                    boundary.id
                ));
            }
            let parent = require_optional_nonempty(
                &format!("boundary {} parent", boundary.id),
                boundary.parent.as_deref(),
            )?;
            if parent == boundary.id {
                return Err(format!("boundary {} cannot parent itself", boundary.id));
            }
            if parent == "unresolved" {
                if boundary.classification != "uncovered-gap" {
                    return Err(format!(
                        "only an uncovered gap may use unresolved as its parent: {}",
                        boundary.id
                    ));
                }
            } else if parent != "root" && !known_ids.contains(parent) {
                return Err(format!(
                    "boundary {} names unknown parent {parent}",
                    boundary.id
                ));
            }
        }
    }

    let credit_prefix = match boundary.classification.as_str() {
        "tracked-effect" => "reserved:",
        "root-owned-publication" => "inherits:",
        "kernel-tcb-infrastructure" => "tcb-owned:",
        "uncovered-gap" => "missing:",
        other => return Err(format!("unsupported classification: {other}")),
    };
    if !boundary.credit.starts_with(credit_prefix) {
        return Err(format!(
            "boundary {} credit must start with {credit_prefix} for classification {}",
            boundary.id, boundary.classification
        ));
    }

    if boundary.source_paths.is_empty() {
        return Err(format!(
            "boundary {} must name at least one source path",
            boundary.id
        ));
    }
    let mut source_paths = BTreeSet::new();
    for source in &boundary.source_paths {
        require_nonempty(&format!("boundary {} source path", boundary.id), source)?;
        if !source_paths.insert(source.as_str()) {
            return Err(format!(
                "boundary {} repeats source path {source}",
                boundary.id
            ));
        }
        validate_source_path(root, &boundary.id, source)?;
    }

    Ok(())
}

fn validate_source_path(root: &Path, boundary_id: &str, source: &str) -> Result<(), String> {
    let relative = Path::new(source);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "boundary {boundary_id} source path must be a normalized repository-relative path: {source}"
        ));
    }
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("boundary {boundary_id} source path {source}: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "boundary {boundary_id} source path is not a regular file: {source}"
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
            .zip(expected.iter())
            .any(|(actual, expected)| actual != expected)
    {
        return Err(format!("{field} must equal {expected:?}"));
    }
    Ok(())
}

fn require_nonempty(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.trim() != value {
        Err(format!("{field} must be nonempty and trimmed"))
    } else {
        Ok(())
    }
}

fn require_optional_nonempty<'a>(field: &str, value: Option<&'a str>) -> Result<&'a str, String> {
    let value = value.ok_or_else(|| format!("{field} is required"))?;
    require_nonempty(field, value)?;
    Ok(value)
}

fn require_date(field: &str, value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return Err(format!("{field} must be YYYY-MM-DD"));
    }
    let year = value[0..4].parse::<u32>().unwrap_or(0);
    let month = value[5..7].parse::<u32>().unwrap_or(0);
    let day = value[8..10].parse::<u32>().unwrap_or(0);
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days_in_month {
        return Err(format!("{field} is not a valid date"));
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

    fn fixture() -> Ledger {
        let source = fs::read_to_string(root().join(LEDGER_PATH)).unwrap();
        toml::from_str(&source).unwrap()
    }

    #[test]
    fn repository_coverage_ledger_is_valid_and_incomplete() {
        let summary = validate(&root()).unwrap();
        assert_eq!(summary.boundaries, EXPECTED_BOUNDARIES.len());
        assert_eq!(summary.tracked_effects, 6);
        assert_eq!(summary.root_owned_publications, 6);
        assert_eq!(summary.kernel_tcb_infrastructure, 0);
        assert_eq!(summary.uncovered_gaps, 8);
        assert_eq!(summary.overall_status, INCOMPLETE_STATUS);
    }

    #[test]
    fn inventory_order_is_frozen() {
        let mut ledger = fixture();
        ledger.boundary.swap(0, 1);
        let error = validate_document(&root(), &ledger).unwrap_err();
        assert!(error.contains("boundary[0] must be task-admission:uncovered-gap"));
    }

    #[test]
    fn summary_and_incomplete_status_must_match_explicit_gaps() {
        let mut ledger = fixture();
        ledger.summary.uncovered_gap -= 1;
        let error = validate_document(&root(), &ledger).unwrap_err();
        assert!(error.contains("summary counts"));

        let mut ledger = fixture();
        ledger.complete = true;
        let error = validate_document(&root(), &ledger).unwrap_err();
        assert!(error.contains("complete must remain false"));

        let mut ledger = fixture();
        ledger.runtime_boundary_gate = true;
        let error = validate_document(&root(), &ledger).unwrap_err();
        assert!(error.contains("not runtime boundary discovery"));
    }

    #[test]
    fn tracked_effects_require_parent_and_reserved_credit() {
        let mut ledger = fixture();
        let tracked = ledger
            .boundary
            .iter_mut()
            .find(|boundary| boundary.id == "filesystem-child")
            .unwrap();
        tracked.parent = None;
        let error = validate_document(&root(), &ledger).unwrap_err();
        assert!(error.contains("filesystem-child parent is required"));

        let mut ledger = fixture();
        let tracked = ledger
            .boundary
            .iter_mut()
            .find(|boundary| boundary.id == "filesystem-child")
            .unwrap();
        tracked.credit = "missing:credit".into();
        let error = validate_document(&root(), &ledger).unwrap_err();
        assert!(error.contains("credit must start with reserved:"));
    }

    #[test]
    fn tcb_classification_requires_rationale_instead_of_parent() {
        let mut boundary = fixture().boundary.remove(0);
        boundary.classification = "kernel-tcb-infrastructure".into();
        boundary.credit = "tcb-owned:no-root-credit".into();
        let known_ids = EXPECTED_BOUNDARIES
            .iter()
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>();
        let error = validate_boundary(&root(), &boundary, &known_ids).unwrap_err();
        assert!(error.contains("must not name a root parent"));

        boundary.parent = None;
        let error = validate_boundary(&root(), &boundary, &known_ids).unwrap_err();
        assert!(error.contains("tcb_rationale is required"));
    }

    #[test]
    fn source_paths_must_be_normalized_regular_files() {
        let mut ledger = fixture();
        ledger.boundary[0].source_paths[0] = "evaluation/production-identity".into();
        let error = validate_document(&root(), &ledger).unwrap_err();
        assert!(error.contains("is not a regular file"));

        let mut ledger = fixture();
        ledger.boundary[0].source_paths[0] = "../outside".into();
        let error = validate_document(&root(), &ledger).unwrap_err();
        assert!(error.contains("normalized repository-relative path"));
    }

    #[test]
    fn parent_graph_must_be_acyclic_and_rooted() {
        let mut ledger = fixture();
        let syscall = ledger
            .boundary
            .iter_mut()
            .find(|boundary| boundary.id == "syscall-root-admission")
            .unwrap();
        syscall.parent = Some("filesystem-child".into());
        let error = validate_document(&root(), &ledger).unwrap_err();
        assert!(error.contains("parent graph contains a cycle"));

        let mut ledger = fixture();
        let task = ledger
            .boundary
            .iter_mut()
            .find(|boundary| boundary.id == "task-admission")
            .unwrap();
        task.parent = Some("service-death".into());
        let service_death = ledger
            .boundary
            .iter_mut()
            .find(|boundary| boundary.id == "service-death")
            .unwrap();
        service_death.parent = None;
        let error = validate_parent_graph(&ledger.boundary).unwrap_err();
        assert!(error.contains("terminates at non-rooted service-death"));
    }
}
