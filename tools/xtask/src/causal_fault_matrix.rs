use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

const MATRIX_PATH: &str = "evaluation/production-identity/causal-fault-matrix.toml";
const MATRIX_SCHEMA: &str = "nexus.research.production-identity.causal-fault-matrix.v1";
const RFC_PATH: &str = "docs/rfcs/0003-causal-coverage-closure.md";
const LEGACY_MATRIX_PATH: &str = "evaluation/production-identity/fault-matrix.toml";
const LEGACY_MATRIX_SHA256: &str =
    "09ee81d198cb7501057884308b041d81a757005c927ce23bcb15bea0d035a13e";
const LEGACY_MATRIX_CELLS: usize = 35;
const CONTRACT_STATUS: &str = "prospective-no-runtime-evidence";
const IDENTITY_BASE: &str = "complete-obligation-identity-v1";
const CURRENT_BOUNDARY: &str = "planned-contract-no-production-hook";
const TARGET_INJECTION_PREFIX: &str = "prospective-hook:";
const CONTINUATION_PHASES: &[&str] = &[
    "absent",
    "reserved",
    "armed",
    "consumed",
    "armed-or-consumed",
];
// SHA-256 over serde_json's deterministic struct/sequence serialization of the
// parsed Matrix. The digest is deliberately kept outside Matrix, so the
// semantic contract has no self-reference. Updating it requires an explicit
// review of every row; TOML comments and layout remain free to improve.
const MATRIX_CANONICAL_SHA256: &str =
    "fdd636526fde6c77d17d3a1acd9e4cb88a030230c4aeaa9f2cdf9245d5d05075";

const EVIDENCE_STATES: &[&str] = &["planned", "source-mapped"];
const TRANCHES: &[&str] = &[
    "queue-dma-preparation",
    "task-admission",
    "filesystem-service-queue",
    "guest-continuation",
    "guest-reply",
    "deadline-retry-generation",
    "request-derived-page-fault",
];
const BOUNDARIES: &[&str] = &[
    "queue-dma-preparation",
    "task-admission",
    "filesystem-service-request-queue",
    "guest-waiter",
    "guest-waker",
    "guest-reply",
    "timer-deadline",
    "page-fault",
];
const PROJECTION_FIELDS: &[&str] = &[
    "root",
    "obligation",
    "reverse-index",
    "publication",
    "terminal",
    "typed-credit",
];
const IDENTITY_FIELDS: &[&str] = &[
    "registry-instance",
    "scope-id",
    "scope-generation",
    "root-effect",
    "immutable-parent",
    "obligation-id",
    "obligation-generation",
    "obligation-kind",
    "authority-epoch",
    "domain-id",
    "binding-epoch",
    "nonce",
];
const CPU_REQUIREMENTS: &[&str] = &[
    "single-production-actor",
    "ordered-one-vcpu-plus-smp-refinement",
    "controlled-two-and-four-vcpu-race",
    "service-supervisor-recovery-actors",
];
const IRQ_REQUIREMENTS: &[&str] = &[
    "task-context-irqs-enabled",
    "task-context-irqs-disabled",
    "raw-irq-tcb-ticket-match-required",
    "crosses-task-and-irq-context",
    "not-applicable",
];
const RETAINED_DISPOSITIONS: &[&str] = &[
    "not-allowed-before-external-mutation",
    "required-on-uncertain-external-mutation",
    "required-until-explicit-reconciliation",
    "typed-rejection-projection-unchanged",
    "terminal-or-retained-single-winner",
];

const EXPECTED_CELLS: &[(&str, &str, &str)] = &[
    (
        "qdp-reservation-failure-before-hardware",
        "queue-dma-preparation",
        "queue-dma-preparation",
    ),
    (
        "qdp-revoke-or-crash-after-reservation",
        "queue-dma-preparation",
        "queue-dma-preparation",
    ),
    (
        "qdp-hardware-failure-before-materialization",
        "queue-dma-preparation",
        "queue-dma-preparation",
    ),
    (
        "qdp-crash-after-hardware-before-materialization",
        "queue-dma-preparation",
        "queue-dma-preparation",
    ),
    (
        "qdp-materialization-validation-or-allocation-failure",
        "queue-dma-preparation",
        "queue-dma-preparation",
    ),
    (
        "qdp-cancellation-uncertain-quiescence",
        "queue-dma-preparation",
        "queue-dma-preparation",
    ),
    (
        "qdp-duplicate-materialize-or-cancel",
        "queue-dma-preparation",
        "queue-dma-preparation",
    ),
    (
        "qdp-wrong-preparation-identity",
        "queue-dma-preparation",
        "queue-dma-preparation",
    ),
    (
        "task-reserved-before-construction-failure",
        "task-admission",
        "task-admission",
    ),
    (
        "task-constructed-before-runnable-failure",
        "task-admission",
        "task-admission",
    ),
    (
        "task-crash-immediately-after-runnable",
        "task-admission",
        "task-admission",
    ),
    (
        "task-exit-before-terminal-ack",
        "task-admission",
        "task-admission",
    ),
    (
        "task-root-revoke-vs-admission",
        "task-admission",
        "task-admission",
    ),
    (
        "task-stale-binding-admission",
        "task-admission",
        "task-admission",
    ),
    (
        "task-repeated-replacement-crash",
        "task-admission",
        "task-admission",
    ),
    (
        "task-generation-substitution",
        "task-admission",
        "task-admission",
    ),
    (
        "svc-reserved-before-queue-write-crash",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "svc-queue-written-before-arm-crash",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "svc-dequeued-before-claim-crash",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "svc-claim-validation-before-child-publication",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "svc-claim-before-delayed-command-installation",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "svc-command-before-rebind",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "svc-command-after-rebind",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "svc-stale-command-delivery",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "svc-duplicate-dequeue-claim-or-delivery",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "svc-coordinator-exit",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "svc-root-revoke-queued-or-claimed",
        "filesystem-service-queue",
        "filesystem-service-request-queue",
    ),
    (
        "cont-guest-exit-before-park",
        "guest-continuation",
        "guest-waiter",
    ),
    (
        "cont-revoke-before-park",
        "guest-continuation",
        "guest-waiter",
    ),
    (
        "cont-service-crash-before-stage",
        "guest-continuation",
        "guest-waker",
    ),
    (
        "cont-crash-after-stage-before-raw-wake",
        "guest-continuation",
        "guest-waker",
    ),
    (
        "cont-crash-after-raw-wake-before-ack",
        "guest-continuation",
        "guest-waker",
    ),
    (
        "cont-duplicate-wake-or-ack",
        "guest-continuation",
        "guest-waker",
    ),
    ("cont-stale-binding", "guest-continuation", "guest-waker"),
    (
        "cont-wrong-task-or-vm-generation",
        "guest-continuation",
        "guest-waiter",
    ),
    (
        "cont-replacement-retry",
        "guest-continuation",
        "guest-waker",
    ),
    (
        "reply-service-crash-after-device-commit",
        "guest-reply",
        "guest-reply",
    ),
    (
        "reply-crash-after-outcome-before-create",
        "guest-reply",
        "guest-reply",
    ),
    (
        "reply-crash-after-create-before-guest-mutation",
        "guest-reply",
        "guest-reply",
    ),
    (
        "reply-crash-after-guest-mutation-before-ack",
        "guest-reply",
        "guest-reply",
    ),
    ("reply-stale-service-binding", "guest-reply", "guest-reply"),
    ("reply-wrong-backend-receipt", "guest-reply", "guest-reply"),
    (
        "reply-guest-remap-or-vm-generation",
        "guest-reply",
        "guest-reply",
    ),
    ("reply-duplicate-publication", "guest-reply", "guest-reply"),
    ("reply-vs-root-revoke", "guest-reply", "guest-reply"),
    (
        "reply-vs-replacement-isolation",
        "guest-reply",
        "guest-reply",
    ),
    (
        "deadline-arm-failure",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "deadline-success-vs-expiry",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "deadline-cancel-vs-expiry",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "deadline-lost-or-duplicate-callback",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "deadline-late-old-generation-callback",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "deadline-crash-before-expiry-ack",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "deadline-replacement-retry",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "deadline-revoke-active-generation",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "deadline-attempt-exhaustion",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "deadline-counter-exhaustion",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "deadline-retained-pressure-backoff",
        "deadline-retry-generation",
        "timer-deadline",
    ),
    (
        "fault-event-reservation-failure",
        "request-derived-page-fault",
        "page-fault",
    ),
    (
        "fault-wrong-task-binding-or-vm",
        "request-derived-page-fault",
        "page-fault",
    ),
    (
        "fault-duplicate-exception",
        "request-derived-page-fault",
        "page-fault",
    ),
    (
        "fault-crash-after-capture-before-disposition",
        "request-derived-page-fault",
        "page-fault",
    ),
    (
        "fault-revoke-vs-disposition",
        "request-derived-page-fault",
        "page-fault",
    ),
    (
        "fault-stale-replacement",
        "request-derived-page-fault",
        "page-fault",
    ),
    (
        "fault-nested-or-unexpected-exception",
        "request-derived-page-fault",
        "page-fault",
    ),
    (
        "fault-counter-exhaustion",
        "request-derived-page-fault",
        "page-fault",
    ),
    (
        "fault-supervisor-replay-consumed-receipt",
        "request-derived-page-fault",
        "page-fault",
    ),
];

const QUEUE_DMA_SOURCES: &[&str] = &[
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
    "kernel/nexus-ostd/src/cser/device_flight.rs",
    "kernel/nexus-ostd/src/personality/linux_fs.rs",
    "crates/nexus-ostd-virtio/src/production.rs",
    "crates/nexus-ostd-virtio/src/dma.rs",
];
const TASK_SOURCES: &[&str] = &[
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
    "kernel/nexus-ostd/src/lib.rs",
    "kernel/nexus-ostd/src/personality/linux_fs.rs",
    "patches/ostd-0.18.0-cser.patch",
];
const SERVICE_QUEUE_SOURCES: &[&str] = &[
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
    "kernel/nexus-ostd/src/personality/linux_fs.rs",
    "kernel/nexus-ostd/src/cser/effect.rs",
];
const CONTINUATION_SOURCES: &[&str] = &[
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
    "kernel/nexus-ostd/src/cser/effect.rs",
    "kernel/nexus-ostd/src/personality/linux_fs.rs",
    "patches/ostd-0.18.0-cser.patch",
];
const REPLY_SOURCES: &[&str] = &[
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
    "kernel/nexus-ostd/src/cser/effect.rs",
    "kernel/nexus-ostd/src/personality/linux_fs.rs",
];
const DEADLINE_SOURCES: &[&str] = &[
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
    "kernel/nexus-ostd/src/cser/effect.rs",
    "kernel/nexus-ostd/src/personality/linux_fs.rs",
    "patches/ostd-0.18.0-cser.patch",
];
const PAGE_FAULT_SOURCES: &[&str] = &[
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
    "kernel/nexus-ostd/src/lib.rs",
    "kernel/nexus-ostd/src/personality/linux_fs.rs",
    "patches/ostd-0.18.0-cser.patch",
];

#[derive(Debug)]
pub(crate) struct Summary {
    pub(crate) cells: usize,
    pub(crate) planned: usize,
    pub(crate) source_mapped: usize,
    pub(crate) observed: usize,
    pub(crate) legacy_cells: usize,
    pub(crate) canonical_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    schema: String,
    rfc: String,
    legacy_fault_matrix: String,
    legacy_fault_matrix_sha256: String,
    legacy_expected_count: usize,
    contract_status: String,
    expected_count: usize,
    allowed_evidence_states: Vec<String>,
    planned_count: usize,
    source_mapped_count: usize,
    observed_count: usize,
    production_execution_observed: bool,
    one_vcpu_observed: bool,
    two_vcpu_observed: bool,
    four_vcpu_observed: bool,
    real_irq_observed: bool,
    required_tranches: Vec<String>,
    required_boundaries: Vec<String>,
    required_projection_fields: Vec<String>,
    required_identity_fields: Vec<String>,
    allowed_cpu_requirements: Vec<String>,
    allowed_irq_requirements: Vec<String>,
    allowed_retained_dispositions: Vec<String>,
    cell: Vec<Cell>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cell {
    id: String,
    tranche: String,
    boundary: String,
    failure_window: String,
    evidence: String,
    current_boundary: String,
    target_injection_point: String,
    production_symbols: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continuation_phase: Option<String>,
    identity_base: String,
    identity_extensions: Vec<String>,
    cpu_requirement: String,
    irq_requirement: String,
    retained_disposition: String,
    expected_disposition: String,
    before: Projection,
    after: Projection,
    source_paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Projection {
    root: String,
    obligation: String,
    reverse_index: String,
    publication: String,
    terminal: String,
    typed_credit: String,
}

#[derive(Deserialize)]
struct LegacyMatrixProbe {
    expected_count: usize,
    cell: Vec<toml::Value>,
}

pub(crate) fn validate(root: &Path) -> Result<Summary, String> {
    let legacy = read_regular_bytes(root, LEGACY_MATRIX_PATH)?;
    validate_legacy_matrix_bytes(&legacy)?;

    let bytes = read_regular_bytes(root, MATRIX_PATH)?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|error| format!("{MATRIX_PATH} is not UTF-8: {error}"))?;
    let matrix: Matrix =
        toml::from_str(source).map_err(|error| format!("parse {MATRIX_PATH}: {error}"))?;
    validate_document(root, &matrix)?;
    let canonical_sha256 = canonical_matrix_sha256(&matrix)?;

    Ok(Summary {
        cells: matrix.cell.len(),
        planned: matrix.planned_count,
        source_mapped: matrix.source_mapped_count,
        observed: matrix.observed_count,
        legacy_cells: LEGACY_MATRIX_CELLS,
        canonical_sha256,
    })
}

fn validate_legacy_matrix_bytes(bytes: &[u8]) -> Result<(), String> {
    let digest = format!("{:x}", Sha256::digest(bytes));
    if digest != LEGACY_MATRIX_SHA256 {
        return Err(format!(
            "legacy 35-cell fault matrix byte digest drifted: expected {LEGACY_MATRIX_SHA256}, found {digest}"
        ));
    }
    let source = std::str::from_utf8(bytes)
        .map_err(|error| format!("legacy fault matrix is not UTF-8: {error}"))?;
    let legacy: LegacyMatrixProbe =
        toml::from_str(source).map_err(|error| format!("parse legacy fault matrix: {error}"))?;
    if legacy.expected_count != LEGACY_MATRIX_CELLS || legacy.cell.len() != LEGACY_MATRIX_CELLS {
        return Err(format!(
            "legacy fault matrix must remain exactly {LEGACY_MATRIX_CELLS} cells"
        ));
    }
    Ok(())
}

fn validate_document(root: &Path, matrix: &Matrix) -> Result<(), String> {
    require_eq("schema", &matrix.schema, MATRIX_SCHEMA)?;
    require_eq("rfc", &matrix.rfc, RFC_PATH)?;
    require_eq(
        "legacy_fault_matrix",
        &matrix.legacy_fault_matrix,
        LEGACY_MATRIX_PATH,
    )?;
    require_eq(
        "legacy_fault_matrix_sha256",
        &matrix.legacy_fault_matrix_sha256,
        LEGACY_MATRIX_SHA256,
    )?;
    if matrix.legacy_expected_count != LEGACY_MATRIX_CELLS {
        return Err(format!(
            "legacy_expected_count must remain {LEGACY_MATRIX_CELLS}"
        ));
    }
    require_eq("contract_status", &matrix.contract_status, CONTRACT_STATUS)?;
    if matrix.expected_count != EXPECTED_CELLS.len() || matrix.cell.len() != EXPECTED_CELLS.len() {
        return Err(format!(
            "causal matrix must contain the exact ordered {}-cell RFC 0003 population",
            EXPECTED_CELLS.len()
        ));
    }
    require_exact_list(
        "allowed_evidence_states",
        &matrix.allowed_evidence_states,
        EVIDENCE_STATES,
    )?;
    require_exact_list("required_tranches", &matrix.required_tranches, TRANCHES)?;
    require_exact_list(
        "required_boundaries",
        &matrix.required_boundaries,
        BOUNDARIES,
    )?;
    require_exact_list(
        "required_projection_fields",
        &matrix.required_projection_fields,
        PROJECTION_FIELDS,
    )?;
    require_exact_list(
        "required_identity_fields",
        &matrix.required_identity_fields,
        IDENTITY_FIELDS,
    )?;
    require_exact_list(
        "allowed_cpu_requirements",
        &matrix.allowed_cpu_requirements,
        CPU_REQUIREMENTS,
    )?;
    require_exact_list(
        "allowed_irq_requirements",
        &matrix.allowed_irq_requirements,
        IRQ_REQUIREMENTS,
    )?;
    require_exact_list(
        "allowed_retained_dispositions",
        &matrix.allowed_retained_dispositions,
        RETAINED_DISPOSITIONS,
    )?;
    if matrix.observed_count != 0
        || matrix.production_execution_observed
        || matrix.one_vcpu_observed
        || matrix.two_vcpu_observed
        || matrix.four_vcpu_observed
        || matrix.real_irq_observed
    {
        return Err("prospective causal matrix must not claim runtime or observed evidence".into());
    }

    let mut planned = 0;
    let mut source_mapped = 0;
    let mut seen = BTreeSet::new();
    for (index, (cell, expected)) in matrix.cell.iter().zip(EXPECTED_CELLS).enumerate() {
        let (expected_id, expected_tranche, expected_boundary) = *expected;
        if cell.id != expected_id
            || cell.tranche != expected_tranche
            || cell.boundary != expected_boundary
        {
            return Err(format!(
                "causal cell[{index}] must be {expected_id}:{expected_tranche}:{expected_boundary}, found {}:{}:{}",
                cell.id, cell.tranche, cell.boundary
            ));
        }
        if !seen.insert(cell.id.as_str()) {
            return Err(format!("duplicate causal cell id: {}", cell.id));
        }
        match cell.evidence.as_str() {
            "planned" => planned += 1,
            "source-mapped" => source_mapped += 1,
            other => {
                return Err(format!(
                    "causal cell {} has forbidden evidence state {other}",
                    cell.id
                ));
            }
        }
        validate_cell(root, cell)?;
    }
    if (planned, source_mapped, matrix.observed_count)
        != (
            matrix.planned_count,
            matrix.source_mapped_count,
            matrix.observed_count,
        )
    {
        return Err(format!(
            "causal evidence population differs: matrix planned={} source-mapped={} observed={}, rows planned={planned} source-mapped={source_mapped} observed=0",
            matrix.planned_count, matrix.source_mapped_count, matrix.observed_count
        ));
    }
    if matrix.planned_count != EXPECTED_CELLS.len() || matrix.source_mapped_count != 0 {
        return Err(
            "initial RFC 0003 contract must remain fully planned until a separate source-mapping change is reviewed"
                .into(),
        );
    }
    let canonical_sha256 = canonical_matrix_sha256(matrix)?;
    if canonical_sha256 != MATRIX_CANONICAL_SHA256 {
        return Err(format!(
            "causal matrix canonical semantic digest drifted: expected {MATRIX_CANONICAL_SHA256}, found {canonical_sha256}"
        ));
    }
    Ok(())
}

fn validate_cell(root: &Path, cell: &Cell) -> Result<(), String> {
    require_nonempty(
        &format!("cell {} failure_window", cell.id),
        &cell.failure_window,
    )?;
    require_nonempty(
        &format!("cell {} expected_disposition", cell.id),
        &cell.expected_disposition,
    )?;
    require_eq(
        &format!("cell {} current_boundary", cell.id),
        &cell.current_boundary,
        CURRENT_BOUNDARY,
    )?;
    let expected_injection = format!("{TARGET_INJECTION_PREFIX}{}", cell.id);
    require_eq(
        &format!("cell {} target_injection_point", cell.id),
        &cell.target_injection_point,
        &expected_injection,
    )?;
    if cell.production_symbols.is_empty() {
        return Err(format!(
            "cell {} must name at least one prospective production symbol",
            cell.id
        ));
    }
    let mut production_symbols = BTreeSet::new();
    for symbol in &cell.production_symbols {
        validate_production_symbol(root, cell, symbol)?;
        if !production_symbols.insert(symbol.as_str()) {
            return Err(format!(
                "cell {} repeats prospective production symbol {symbol}",
                cell.id
            ));
        }
    }
    if cell.tranche == "filesystem-service-queue" {
        let phase = cell.continuation_phase.as_deref().ok_or_else(|| {
            format!(
                "cell {} must declare its exact response-continuation phase",
                cell.id
            )
        })?;
        require_allowed(
            &format!("cell {} continuation_phase", cell.id),
            phase,
            CONTINUATION_PHASES,
        )?;
    } else if cell.continuation_phase.is_some() {
        return Err(format!(
            "non-service cell {} must not declare a service continuation phase",
            cell.id
        ));
    }
    require_eq(
        &format!("cell {} identity_base", cell.id),
        &cell.identity_base,
        IDENTITY_BASE,
    )?;
    if cell.identity_extensions.is_empty() {
        return Err(format!(
            "cell {} must bind workload-specific identity extensions",
            cell.id
        ));
    }
    let mut identity_extensions = BTreeSet::new();
    for extension in &cell.identity_extensions {
        require_token(&format!("cell {} identity extension", cell.id), extension)?;
        if !identity_extensions.insert(extension.as_str()) {
            return Err(format!(
                "cell {} repeats identity extension {extension}",
                cell.id
            ));
        }
    }
    require_allowed(
        &format!("cell {} cpu_requirement", cell.id),
        &cell.cpu_requirement,
        CPU_REQUIREMENTS,
    )?;
    require_allowed(
        &format!("cell {} irq_requirement", cell.id),
        &cell.irq_requirement,
        IRQ_REQUIREMENTS,
    )?;
    require_allowed(
        &format!("cell {} retained_disposition", cell.id),
        &cell.retained_disposition,
        RETAINED_DISPOSITIONS,
    )?;
    validate_projection(&cell.id, "before", &cell.before)?;
    validate_projection(&cell.id, "after", &cell.after)?;

    let expected_sources = sources_for_tranche(&cell.tranche)?;
    if cell.source_paths.len() != expected_sources.len()
        || cell
            .source_paths
            .iter()
            .zip(expected_sources)
            .any(|(actual, expected)| actual != expected)
    {
        return Err(format!(
            "cell {} source paths drifted from the exact {} mapping",
            cell.id, cell.tranche
        ));
    }
    for source in &cell.source_paths {
        validate_source_path(root, &cell.id, source)?;
    }
    Ok(())
}

fn validate_projection(cell: &str, side: &str, projection: &Projection) -> Result<(), String> {
    for (field, value, prefix) in [
        ("root", &projection.root, "root:"),
        ("obligation", &projection.obligation, "obligation:"),
        ("reverse-index", &projection.reverse_index, "reverse-index:"),
        ("publication", &projection.publication, "publication:"),
        ("terminal", &projection.terminal, "terminal:"),
        ("typed-credit", &projection.typed_credit, "typed-credit:"),
    ] {
        require_nonempty(&format!("cell {cell} {side}.{field}"), value)?;
        if !value.starts_with(prefix) {
            return Err(format!(
                "cell {cell} {side}.{field} must start with {prefix}"
            ));
        }
    }
    if !projection.typed_credit.contains('=') {
        return Err(format!(
            "cell {cell} {side}.typed-credit must name at least one typed class and quantity"
        ));
    }
    Ok(())
}

fn sources_for_tranche(tranche: &str) -> Result<&'static [&'static str], String> {
    match tranche {
        "queue-dma-preparation" => Ok(QUEUE_DMA_SOURCES),
        "task-admission" => Ok(TASK_SOURCES),
        "filesystem-service-queue" => Ok(SERVICE_QUEUE_SOURCES),
        "guest-continuation" => Ok(CONTINUATION_SOURCES),
        "guest-reply" => Ok(REPLY_SOURCES),
        "deadline-retry-generation" => Ok(DEADLINE_SOURCES),
        "request-derived-page-fault" => Ok(PAGE_FAULT_SOURCES),
        other => Err(format!("unknown causal tranche {other}")),
    }
}

fn validate_source_path(root: &Path, cell: &str, source: &str) -> Result<(), String> {
    let relative = Path::new(source);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "cell {cell} source path must be normalized and repository-relative: {source}"
        ));
    }
    let absolute = root.join(relative);
    let metadata = fs::symlink_metadata(&absolute)
        .map_err(|error| format!("cell {cell} source path {source}: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "cell {cell} source path must be a regular non-symlink file: {source}"
        ));
    }
    Ok(())
}

fn validate_production_symbol(root: &Path, cell: &Cell, symbol: &str) -> Result<(), String> {
    require_nonempty(
        &format!("cell {} prospective production symbol", cell.id),
        symbol,
    )?;
    let (source, symbol_path) = symbol.split_once("::").ok_or_else(|| {
        format!(
            "cell {} prospective production symbol must be path::symbol: {symbol}",
            cell.id
        )
    })?;
    if symbol_path.is_empty()
        || symbol_path
            .split("::")
            .any(|component| component.is_empty() || !is_rust_identifier(component))
    {
        return Err(format!(
            "cell {} prospective production symbol has an invalid symbol path: {symbol}",
            cell.id
        ));
    }
    if !cell
        .source_paths
        .iter()
        .any(|candidate| candidate == source)
    {
        return Err(format!(
            "cell {} prospective production symbol is outside source_paths: {symbol}",
            cell.id
        ));
    }
    validate_source_path(root, &cell.id, source)
}

fn is_rust_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn canonical_matrix_sha256(matrix: &Matrix) -> Result<String, String> {
    let canonical = serde_json::to_vec(matrix)
        .map_err(|error| format!("serialize canonical causal matrix: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

fn read_regular_bytes(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    let path = root.join(relative);
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| format!("inspect {relative}: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "contract must be a regular non-symlink file: {relative}"
        ));
    }
    let first = fs::read(&path).map_err(|error| format!("read {relative}: {error}"))?;
    let second = fs::read(&path).map_err(|error| format!("reread {relative}: {error}"))?;
    if first != second {
        return Err(format!("contract changed while reading: {relative}"));
    }
    Ok(first)
}

fn require_eq(field: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} must be {expected}, found {actual}"))
    }
}

fn require_nonempty(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.trim() != value {
        Err(format!("{field} must be nonempty and trimmed"))
    } else {
        Ok(())
    }
}

fn require_token(field: &str, value: &str) -> Result<(), String> {
    require_nonempty(field, value)?;
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
    {
        return Err(format!("{field} must be a lowercase kebab token"));
    }
    Ok(())
}

fn require_allowed(field: &str, value: &str, allowed: &[&str]) -> Result<(), String> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("{field} has unsupported value {value}"))
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
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn fixture() -> Matrix {
        let bytes = read_regular_bytes(&root(), MATRIX_PATH).unwrap();
        toml::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap()
    }

    #[test]
    fn repository_causal_matrix_is_exactly_planned_and_freezes_legacy_bytes() {
        let summary = validate(&root()).unwrap();
        assert_eq!(summary.cells, 66);
        assert_eq!(summary.planned, 66);
        assert_eq!(summary.source_mapped, 0);
        assert_eq!(summary.observed, 0);
        assert_eq!(summary.legacy_cells, 35);
        assert_eq!(summary.canonical_sha256, MATRIX_CANONICAL_SHA256);

        let matrix = fixture();
        let reply = matrix
            .cell
            .iter()
            .find(|cell| cell.id == "reply-crash-after-create-before-guest-mutation")
            .unwrap();
        for field in ["result-digest", "byte-range", "destination"] {
            assert!(reply.identity_extensions.iter().any(|value| value == field));
        }
        let deadline = matrix
            .cell
            .iter()
            .find(|cell| cell.id == "deadline-arm-failure")
            .unwrap();
        assert!(
            deadline
                .identity_extensions
                .iter()
                .any(|value| value == "deadline-bound")
        );
        let post_hardware = matrix
            .cell
            .iter()
            .find(|cell| cell.id == "qdp-crash-after-hardware-before-materialization")
            .unwrap();
        for field in ["operation-digest", "descriptor-token", "device-session"] {
            assert!(
                post_hardware
                    .identity_extensions
                    .iter()
                    .any(|value| value == field)
            );
        }
    }

    #[test]
    fn all_service_rows_bind_the_exact_continuation_phase_identity() {
        let matrix = fixture();
        let expected = [
            ("svc-reserved-before-queue-write-crash", "reserved", false),
            ("svc-queue-written-before-arm-crash", "reserved", false),
            ("svc-dequeued-before-claim-crash", "armed", true),
            (
                "svc-claim-validation-before-child-publication",
                "armed",
                true,
            ),
            (
                "svc-claim-before-delayed-command-installation",
                "armed",
                true,
            ),
            ("svc-command-before-rebind", "armed", true),
            ("svc-command-after-rebind", "armed", true),
            ("svc-stale-command-delivery", "armed", true),
            (
                "svc-duplicate-dequeue-claim-or-delivery",
                "armed-or-consumed",
                true,
            ),
            ("svc-coordinator-exit", "armed", true),
            ("svc-root-revoke-queued-or-claimed", "armed", true),
        ];
        let rows = matrix
            .cell
            .iter()
            .filter(|cell| cell.tranche == "filesystem-service-queue")
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), expected.len());
        for ((expected_id, expected_phase, has_selected_obligation), cell) in
            expected.iter().zip(rows)
        {
            assert_eq!(&cell.id, expected_id);
            assert_eq!(cell.continuation_phase.as_deref(), Some(*expected_phase));
            assert!(has_extension(cell, "continuation-slot"));
            assert_eq!(
                has_extension(cell, "continuation-selector"),
                *has_selected_obligation,
                "{} selector phase",
                cell.id
            );
            assert_eq!(
                has_extension(cell, "continuation-obligation"),
                *has_selected_obligation,
                "{} obligation phase",
                cell.id
            );
        }
    }

    #[test]
    fn all_deadline_rows_bind_series_limit_and_exact_active_callback_phase() {
        let matrix = fixture();
        let callback_rows = BTreeSet::from([
            "deadline-success-vs-expiry",
            "deadline-cancel-vs-expiry",
            "deadline-lost-or-duplicate-callback",
            "deadline-late-old-generation-callback",
            "deadline-crash-before-expiry-ack",
            "deadline-replacement-retry",
            "deadline-revoke-active-generation",
        ]);
        let rows = matrix
            .cell
            .iter()
            .filter(|cell| cell.tranche == "deadline-retry-generation")
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 11);
        for cell in rows {
            for required in [
                "deadline-purpose",
                "attempt-limit",
                "deadline-generation",
                "clock-basis",
                "deadline-bound",
                "attempt",
            ] {
                assert!(
                    has_extension(cell, required),
                    "{} lacks {required}",
                    cell.id
                );
            }
            assert_eq!(
                has_extension(cell, "callback-ticket"),
                callback_rows.contains(cell.id.as_str()),
                "{} callback-ticket phase",
                cell.id
            );
        }
    }

    #[test]
    fn rejects_missing_extra_reordered_renamed_and_duplicate_cells() {
        let repository = root();

        let mut missing = fixture();
        missing.cell.pop();
        assert!(validate_document(&repository, &missing).is_err());

        let mut extra = fixture();
        let mut fabricated = extra.cell[0].clone();
        fabricated.id = "fabricated-extra-cell".into();
        extra.cell.push(fabricated);
        assert!(validate_document(&repository, &extra).is_err());

        let mut reordered = fixture();
        reordered.cell.swap(0, 1);
        assert!(validate_document(&repository, &reordered).is_err());

        let mut renamed = fixture();
        renamed.cell[0].id.push_str("-renamed");
        assert!(validate_document(&repository, &renamed).is_err());

        let mut duplicate = fixture();
        duplicate.cell[1].id = duplicate.cell[0].id.clone();
        assert!(validate_document(&repository, &duplicate).is_err());
    }

    #[test]
    fn rejects_unknown_boundary_and_any_observed_claim() {
        let repository = root();
        let mut unknown = fixture();
        unknown.cell[0].boundary = "unknown-boundary".into();
        assert!(validate_document(&repository, &unknown).is_err());

        let mut observed = fixture();
        observed.cell[0].evidence = "observed".into();
        assert!(validate_document(&repository, &observed).is_err());

        let mut flag = fixture();
        flag.one_vcpu_observed = true;
        assert!(validate_document(&repository, &flag).is_err());
    }

    #[test]
    fn rejects_missing_or_untyped_projection_and_identity_drift() {
        let repository = root();
        let mut missing = fixture();
        missing.cell[0].before.root.clear();
        assert!(validate_document(&repository, &missing).is_err());

        let mut untyped = fixture();
        untyped.cell[0].after.typed_credit = "typed-credit:population".into();
        assert!(validate_document(&repository, &untyped).is_err());

        let mut identity = fixture();
        identity.cell[0].identity_base = "copied-integers".into();
        assert!(validate_document(&repository, &identity).is_err());

        let mut continuation = fixture();
        let service = continuation
            .cell
            .iter_mut()
            .find(|cell| cell.id == "svc-dequeued-before-claim-crash")
            .unwrap();
        service
            .identity_extensions
            .retain(|field| field != "continuation-selector");
        assert_canonical_drift(&repository, &continuation);

        let mut deadline = fixture();
        let expiry = deadline
            .cell
            .iter_mut()
            .find(|cell| cell.id == "deadline-success-vs-expiry")
            .unwrap();
        expiry
            .identity_extensions
            .retain(|field| field != "callback-ticket");
        assert_canonical_drift(&repository, &deadline);

        let mut deadline_limit = fixture();
        let arm = deadline_limit
            .cell
            .iter_mut()
            .find(|cell| cell.id == "deadline-arm-failure")
            .unwrap();
        arm.identity_extensions
            .retain(|field| field != "attempt-limit");
        assert_canonical_drift(&repository, &deadline_limit);
    }

    #[test]
    fn rejects_well_formed_semantic_projection_and_policy_drift() {
        let repository = root();

        let mut projection = fixture();
        projection.cell[0].before.root = "root:semantically-weakened".into();
        assert_canonical_drift(&repository, &projection);

        let mut identity = fixture();
        identity.cell[0]
            .identity_extensions
            .retain(|field| field != "operation-digest");
        assert_canonical_drift(&repository, &identity);

        let mut cpu = fixture();
        cpu.cell[0].cpu_requirement = "single-production-actor".into();
        assert_canonical_drift(&repository, &cpu);

        let mut irq = fixture();
        irq.cell[0].irq_requirement = "not-applicable".into();
        assert_canonical_drift(&repository, &irq);

        let mut retained = fixture();
        retained.cell[0].retained_disposition = "typed-rejection-projection-unchanged".into();
        assert_canonical_drift(&repository, &retained);
    }

    #[test]
    fn rejects_failure_disposition_and_prospective_target_drift() {
        let repository = root();

        let mut failure = fixture();
        failure.cell[0].failure_window.push_str(" weakened");
        assert_canonical_drift(&repository, &failure);

        let mut disposition = fixture();
        disposition.cell[0]
            .expected_disposition
            .push_str(" weakened");
        assert_canonical_drift(&repository, &disposition);

        let mut symbol = fixture();
        symbol.cell[0].production_symbols[0] = concat!(
            "kernel/nexus-ostd/src/cser/effect_registry.rs",
            "::EffectRegistry::fabricated_but_well_formed"
        )
        .into();
        assert_canonical_drift(&repository, &symbol);

        let mut injection = fixture();
        injection.cell[0].target_injection_point =
            "prospective-hook:qdp-fabricated-boundary".into();
        assert!(validate_document(&repository, &injection).is_err());

        let mut current = fixture();
        current.cell[0].current_boundary = "source-mapped-by-file-existence".into();
        assert!(validate_document(&repository, &current).is_err());
    }

    #[test]
    fn rejects_source_path_drift_and_symlinks() {
        let repository = root();
        let mut drift = fixture();
        drift.cell[0].source_paths[0] = "kernel/nexus-ostd/src/lib.rs".into();
        assert!(validate_document(&repository, &drift).is_err());

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temporary = std::env::temp_dir().join(format!(
            "nexus-causal-fault-matrix-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&temporary).unwrap();
        fs::write(temporary.join("real.rs"), "fn real() {}\n").unwrap();
        symlink("real.rs", temporary.join("link.rs")).unwrap();
        let error = validate_source_path(&temporary, "symlink-test", "link.rs").unwrap_err();
        assert!(error.contains("regular non-symlink"));
        fs::remove_dir_all(temporary).unwrap();
    }

    #[test]
    fn legacy_fault_matrix_is_byte_and_count_frozen() {
        let bytes = read_regular_bytes(&root(), LEGACY_MATRIX_PATH).unwrap();
        validate_legacy_matrix_bytes(&bytes).unwrap();

        let mut mutated = bytes;
        let byte = mutated.iter_mut().find(|byte| **byte == b'3').unwrap();
        *byte = b'4';
        let error = validate_legacy_matrix_bytes(&mutated).unwrap_err();
        assert!(error.contains("byte digest drifted"));
    }

    #[test]
    fn raw_contract_rejects_unknown_or_missing_projection_fields() {
        let bytes = read_regular_bytes(&root(), MATRIX_PATH).unwrap();
        let source = std::str::from_utf8(&bytes).unwrap();
        assert!(toml::from_str::<Matrix>(&format!("{source}\nunknown = true\n")).is_err());

        let missing = source.replacen("root = \"root:", "missing-root = \"root:", 1);
        assert!(toml::from_str::<Matrix>(&missing).is_err());
    }

    fn assert_canonical_drift(repository: &Path, matrix: &Matrix) {
        let error = validate_document(repository, matrix).unwrap_err();
        assert!(
            error.contains("canonical semantic digest drifted"),
            "unexpected validation error: {error}"
        );
    }

    fn has_extension(cell: &Cell, expected: &str) -> bool {
        cell.identity_extensions
            .iter()
            .any(|extension| extension == expected)
    }
}
