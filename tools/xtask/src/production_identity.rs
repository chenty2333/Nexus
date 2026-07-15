use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Component, Path};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const SCHEMA: &str = "nexus.research.production-identity.v2";
const SUMMARY_SCHEMA: &str = "nexus.research.production-identity.summary.v2";
const COMMAND: &str = "./x research production-identity";
const SPEC: &str = "ProductionIdentityCser";
const OUTPUT_DIRECTORY: &str = "target/research/production-identity";
const PLUSCAL_LOG: &str = "target/research/production-identity/pluscal.log";
const TLC_LOG: &str = "target/research/production-identity/tlc.log";
const RUST_LOG: &str = "target/research/production-identity/rust-oracle.log";
const SUMMARY_PATH: &str = "target/research/production-identity/summary.txt";
const RECEIPT_PATH: &str = "target/research/production-identity/receipt.json";
const TRANSITION_MAP_PATH: &str = "evaluation/production-identity/transition-map.toml";
const FAULT_MATRIX_PATH: &str = "evaluation/production-identity/fault-matrix.toml";
const TRANSITION_MAP_SHA256: &str =
    "6ddaf74045ffe8cacc6ffc56ee4e8399d19fad6a70e44283b18b4677821cf609";
const FAULT_MATRIX_SHA256: &str =
    "09ee81d198cb7501057884308b041d81a757005c927ce23bcb15bea0d035a13e";
const ACTOR_BOUNDARY: &str = "abstract 2/4-CPU Service/Kernel/IRQ identities";
const BOUNDEDNESS_STATEMENT: &str = "Abstract 2/4-CPU actor identities only; not OSTD SpinLock, IRQ delivery, memory-ordering, or real SMP evidence.";

const FROZEN_V0_1_SPECS: [&str; 12] = [
    "Cser",
    "PagerCser",
    "IoCser",
    "PersonalityCser",
    "PersonalityFutexCser",
    "PersonalityFutexRequeueCser",
    "PersonalityReadinessCser",
    "PersonalityExecCser",
    "RuntimeFsCser",
    "RuntimeNetCser",
    "CompositionCser",
    "LinuxIoCompositionCser",
];

const SOURCE_FILES: &[&str] = &[
    "x",
    "Dockerfile",
    ".cargo/config.toml",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "crates/cser-model/Cargo.toml",
    "crates/cser-model/src/lib.rs",
    "crates/cser-model/src/production_identity.rs",
    "crates/cser-model/tests/production_identity_support/mod.rs",
    "crates/cser-model/tests/production_identity_sequences.rs",
    "crates/cser-model/tests/production_identity_properties.rs",
    "crates/cser-model/tests/production_identity_loom.rs",
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
    "evaluation/production-identity/transition-map.toml",
    "evaluation/production-identity/fault-matrix.toml",
    "evaluation/production-identity/README.md",
    "tools/xtask/Cargo.toml",
    "tools/xtask/Cargo.lock",
    "tools/xtask/src/main.rs",
    "tools/xtask/src/production_identity.rs",
    "specs/cser/check.sh",
    "specs/cser/ProductionIdentityCser.tla",
    "specs/cser/ProductionIdentityCserSafetyMC.cfg",
    "specs/cser/ProductionIdentityCserSmp4SafetyMC.cfg",
    "specs/cser/ProductionIdentityCserActionMC.cfg",
    "specs/cser/ProductionIdentityCserProgressMC.cfg",
    "specs/cser/PRODUCTION_IDENTITY.md",
    "specs/cser/README.md",
    "docs/rfcs/0001-production-identity.md",
];

const EVIDENCE_STATES: &[&str] = &["checked", "observed", "planned"];

const SEQUENCE_TESTS: &[&str] = &[
    "normal_read_preserves_one_tree_through_device_and_one_shot_guest_reply",
    "crash_snapshot_ready_rebind_adopt_changes_only_current_binding",
    "reset_timeout_is_indeterminate_until_same_identity_retry_and_iotlb_ack",
    "revoke_winner_aborts_the_complete_tree_in_leaf_first_order",
    "wrong_parent_registration_rejects_the_complete_projection",
];

const PROPERTY_TESTS: &[&str] = &[
    "substituted_registry_root_generations_and_parent_reject_atomically",
    "arbitrary_domain_recovery_preserves_every_immutable_effect_identity",
    "foreign_root_tokens_never_mutate_registration_or_revoke",
];

const LOOM_TESTS: &[&str] = &[
    "loom_block_commit_and_root_revoke_have_one_gate_winner",
    "loom_domain_crash_fences_or_follows_device_commit_without_identity_replacement",
    "loom_retry_iotlb_ack_and_old_completion_cannot_double_publish",
];

const TRANSITION_IDS: &[&str] = &[
    "derive-register",
    "prepare-effect",
    "crash-domain",
    "snapshot-domain",
    "ready-domain",
    "rebind-domain",
    "adopt-effect",
    "device-commit",
    "revoke-begin",
    "backend-completion",
    "normal-iotlb-ack",
    "guest-reply-publication",
    "reset-timeout-retain",
    "reset-retry-ack",
    "iotlb-timeout-retain",
    "iotlb-retry",
    "iotlb-retry-ack",
    "stale-identity-rejection",
    "leaf-first-revoke-next",
    "revoke-complete",
    "production-irq-completion",
    "production-smp-gate",
];

const REQUIRED_FAULT_FAMILIES: &[&str] = &[
    "derive-register-vs-root-revoke",
    "multi-object-pretransition-failure",
    "crash-before-device-commit",
    "crash-after-device-commit-before-backend",
    "crash-after-backend-before-reply",
    "stale-old-binding-operations",
    "adopt-vs-kernel-abort",
    "duplicate-replayed-receipts",
    "device-completion-vs-reset-ack",
    "reset-timeout-retry",
    "iommu-timeout-late-ack-retry",
    "repeated-service-crash",
    "root-revoke-vs-cross-cpu-irq",
    "wrong-presented-identity",
    "retained-credit-pressure",
];

const REQUIRED_OBSERVATION_FIELDS: &[&str] = &[
    "injection_point",
    "cpu",
    "presented_identity",
    "expected_result",
    "observed_result",
    "semantic_projection_before",
    "semantic_projection_after",
    "terminalization_count",
    "publication_count",
    "credits_before",
    "credits_after",
    "retained_owners",
    "final_root_state",
    "honest_non_success_timeout",
];

const FAULT_CELL_IDS: &[&str] = &[
    "derive-register-vs-root-revoke",
    "multi-object-allocation-failure",
    "multi-object-validation-failure",
    "crash-before-device-commit",
    "crash-after-device-commit-before-backend",
    "crash-after-backend-before-reply",
    "stale-binding-prepare",
    "stale-binding-commit",
    "stale-binding-completion",
    "stale-binding-reply",
    "stale-binding-adopt",
    "adopt-vs-kernel-abort",
    "duplicate-commit-receipt",
    "duplicate-publication-receipt",
    "duplicate-completion-receipt",
    "duplicate-reset-receipt",
    "duplicate-iommu-receipt",
    "duplicate-closure-receipt",
    "device-completion-vs-reset-ack",
    "reset-timeout-then-retry",
    "iommu-timeout-then-retry",
    "iommu-late-ack-after-timeout",
    "repeated-crash-before-rebind",
    "repeated-crash-after-rebind",
    "root-revoke-vs-cross-cpu-irq",
    "wrong-registry-instance",
    "wrong-root",
    "wrong-effect",
    "wrong-queue",
    "wrong-device-session",
    "wrong-device-generation",
    "wrong-ancestry",
    "queue-credit-pressure-with-tombstone",
    "dma-credit-pressure-with-tombstone",
    "frame-credit-pressure-with-tombstone",
];

#[derive(Clone, Copy)]
struct ConfigurationExpectation {
    config: &'static str,
    heading: &'static str,
    generated: u64,
    distinct: u64,
    depth: u64,
    property_mode: &'static str,
}

const CONFIGURATIONS: [ConfigurationExpectation; 4] = [
    ConfigurationExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        heading: "ProductionIdentityCser 2-CPU-actor safety graph",
        generated: 4_793,
        distinct: 3_396,
        depth: 33,
        property_mode: "safety",
    },
    ConfigurationExpectation {
        config: "ProductionIdentityCserSmp4SafetyMC.cfg",
        heading: "ProductionIdentityCser 4-CPU-actor safety graph",
        generated: 4_793,
        distinct: 3_396,
        depth: 33,
        property_mode: "safety",
    },
    ConfigurationExpectation {
        config: "ProductionIdentityCserActionMC.cfg",
        heading: "ProductionIdentityCser action properties",
        generated: 4_793,
        distinct: 3_396,
        depth: 33,
        property_mode: "action-properties",
    },
    ConfigurationExpectation {
        config: "ProductionIdentityCserProgressMC.cfg",
        heading: "ProductionIdentityCser conditional kernel progress",
        generated: 3_356,
        distinct: 2_670,
        depth: 32,
        property_mode: "conditional-progress-5-temporal-branches",
    },
];

#[derive(Clone, Copy)]
struct WitnessExpectation {
    config: &'static str,
    invariant: &'static str,
    description: &'static str,
}

const WITNESSES: [WitnessExpectation; 8] = [
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "IdentityPreservingReadAbsent",
        description: "workload-created identities survive one same-effect block read and root closure",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "FilesystemCrashAdoptAbsent",
        description: "filesystem crash/rebind/adopt changes only the current domain binding",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "CommitWinsRevokeRaceAbsent",
        description: "device batch commit wins the shared root gate before revocation",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "RevokeWinsCommitRaceAbsent",
        description: "root revocation wins the shared gate and aborts every uncommitted descendant",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "ResetIotlbSameEffectAbsent",
        description: "reset and IOTLB timeouts retain the same effect through retry and closure",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "CrossRegistryGenerationRejectAbsent",
        description: "foreign-registry and stale-device-generation inputs reject without semantic mutation",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSafetyMC.cfg",
        invariant: "ActorSeparationAbsent",
        description: "2-CPU abstract service/kernel/IRQ roles retain one identity chain",
    },
    WitnessExpectation {
        config: "ProductionIdentityCserSmp4SafetyMC.cfg",
        invariant: "ActorSeparationAbsent",
        description: "4-CPU abstract service/kernel/IRQ roles retain one identity chain",
    },
];

#[derive(Clone, Copy)]
enum ExpectedSection {
    Configuration(usize),
    Witness(usize),
}

const SECTION_ORDER: [ExpectedSection; 12] = [
    ExpectedSection::Configuration(0),
    ExpectedSection::Configuration(1),
    ExpectedSection::Witness(0),
    ExpectedSection::Witness(1),
    ExpectedSection::Witness(2),
    ExpectedSection::Witness(3),
    ExpectedSection::Witness(4),
    ExpectedSection::Witness(5),
    ExpectedSection::Witness(6),
    ExpectedSection::Witness(7),
    ExpectedSection::Configuration(2),
    ExpectedSection::Configuration(3),
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct TransitionMap {
    schema: String,
    rfc: String,
    abstract_specification: String,
    rust_oracle: String,
    production_registry: String,
    expected_count: usize,
    allowed_evidence_states: Vec<String>,
    checked_count: usize,
    observed_count: usize,
    planned_count: usize,
    transition: Vec<TransitionMapping>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct TransitionMapping {
    id: String,
    abstract_action: String,
    rust_oracle_source: String,
    rust_tests: Vec<String>,
    production_sources: Vec<String>,
    evidence: String,
    boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FaultMatrix {
    schema: String,
    rfc: String,
    transition_map: String,
    expected_count: usize,
    allowed_evidence_states: Vec<String>,
    checked_count: usize,
    observed_count: usize,
    planned_count: usize,
    shared_production_registry_execution_observed: bool,
    real_user_service_crash_observed: bool,
    real_irq_observed: bool,
    two_vcpu_observed: bool,
    four_vcpu_observed: bool,
    required_families: Vec<String>,
    required_observation_fields: Vec<String>,
    cell: Vec<FaultCell>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FaultCell {
    id: String,
    family: String,
    phase: String,
    injection_point: String,
    cpu_requirement: String,
    presented_identity: String,
    expected_result: String,
    evidence: String,
    oracle_tests: Vec<String>,
    production_sources: Vec<String>,
    boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationReceipt {
    config: String,
    status: String,
    generated: u64,
    distinct: u64,
    depth: u64,
    states_left_on_queue: u64,
    property_mode: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WitnessReceipt {
    config: String,
    invariant: String,
    description: String,
    status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBoundary {
    accepted_release: String,
    accepted_specifications: usize,
    successor_in_v0_1_catalog: bool,
    successor_artifacts_in_v0_1_manifest: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RustOracleReceipt {
    independent_from_production_registry: bool,
    sequence_tests: usize,
    property_tests: usize,
    loom_tests: usize,
    total_tests: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionMapReceipt {
    path: String,
    sha256: String,
    entries: usize,
    checked: usize,
    observed: usize,
    planned: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FaultContractReceipt {
    path: String,
    sha256: String,
    cells: usize,
    families: usize,
    checked: usize,
    observed: usize,
    planned: usize,
    required_observation_fields: usize,
    shared_production_registry_execution_observed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Logs {
    pluscal_translation: String,
    tlc: String,
    rust_oracle: String,
    summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Digests {
    pluscal_translation_sha256: String,
    tlc_sha256: String,
    rust_oracle_sha256: String,
    summary_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    status: String,
    prospective: bool,
    command: String,
    revision: String,
    worktree_dirty: bool,
    source_fingerprint: String,
    source_files: Vec<String>,
    translation_current: bool,
    full_configurations: usize,
    configurations: Vec<ConfigurationReceipt>,
    reachability_witnesses: usize,
    witnesses: Vec<WitnessReceipt>,
    rust_oracle: RustOracleReceipt,
    transition_map: TransitionMapReceipt,
    fault_contract: FaultContractReceipt,
    actor_boundary: String,
    boundedness_statement: String,
    real_ostd_smp_claimed: bool,
    release_boundary: ReleaseBoundary,
    generated_unix_seconds: u64,
    logs: Logs,
    digests: Digests,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GraphStats {
    generated: u64,
    distinct: u64,
    left_on_queue: u64,
    depth: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct LogSummary {
    configurations: Vec<ConfigurationReceipt>,
    witnesses: Vec<WitnessReceipt>,
}

pub(crate) fn run(root: &Path, release_specs: &[&str]) -> Result<()> {
    validate_release_boundary(release_specs)?;
    let transition_map = validate_transition_map(root)?;
    let fault_matrix = validate_fault_matrix(root)?;

    let output = root.join(OUTPUT_DIRECTORY);
    let output_parent = output
        .parent()
        .ok_or("production-identity output has no parent")?;
    fs::create_dir_all(output_parent)?;
    let _lock = super::SpecRunLock::acquire(&output_parent.join(".production-identity.lock"))?;
    fs::create_dir_all(&output)?;
    clear_previous_outputs(root)?;

    let revision_before = git_text(root, &["rev-parse", "HEAD"])?;
    let source_before = fingerprint_paths(root, SOURCE_FILES)?;
    let jar = super::tla2tools_jar()?;
    let source_cser_dir = root.join("specs/cser");
    let workspace = super::IsolatedSpecWorkspace::create(&source_cser_dir)?;

    super::pluscal_translation_is_current(
        &source_cser_dir,
        workspace.cser_dir(),
        &jar,
        SPEC,
        &root.join(PLUSCAL_LOG),
    )?;

    super::section("run prospective ProductionIdentityCser research gate");
    let mut command = Command::new("sh");
    command
        .current_dir(workspace.cser_dir())
        .env("TLA2TOOLS_JAR", &jar)
        .env("TMPDIR", workspace.temp_dir())
        .arg(workspace.cser_dir().join("check.sh"))
        .arg(SPEC);
    super::run_bounded_logged_quiet(
        &mut command,
        &root.join(TLC_LOG),
        Duration::from_secs(900),
        16 * 1024 * 1024,
    )?;

    let transcript = fs::read_to_string(root.join(TLC_LOG))?;
    let log_summary = validate_tlc_log(&transcript)?;
    run_rust_oracle(root)?;
    validate_rust_log(&fs::read_to_string(root.join(RUST_LOG))?)?;
    let revision_after = git_text(root, &["rev-parse", "HEAD"])?;
    let source_after = fingerprint_paths(root, SOURCE_FILES)?;
    if revision_before != revision_after || source_before != source_after {
        return Err(format!(
            "production-identity sources changed during verification: revision {revision_before}->{revision_after}, fingerprint {source_before}->{source_after}"
        )
        .into());
    }

    let worktree_dirty = !git_bytes(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?
    .is_empty();
    let summary = summary_text(&revision_after, &source_after, worktree_dirty);
    atomic_write(&root.join(SUMMARY_PATH), summary.as_bytes())?;

    let receipt = Receipt {
        schema: String::from(SCHEMA),
        status: String::from("passed"),
        prospective: true,
        command: String::from(COMMAND),
        revision: revision_after,
        worktree_dirty,
        source_fingerprint: source_after,
        source_files: SOURCE_FILES
            .iter()
            .map(|path| String::from(*path))
            .collect(),
        translation_current: true,
        full_configurations: log_summary.configurations.len(),
        configurations: log_summary.configurations,
        reachability_witnesses: log_summary.witnesses.len(),
        witnesses: log_summary.witnesses,
        rust_oracle: RustOracleReceipt {
            independent_from_production_registry: true,
            sequence_tests: SEQUENCE_TESTS.len(),
            property_tests: PROPERTY_TESTS.len(),
            loom_tests: LOOM_TESTS.len(),
            total_tests: SEQUENCE_TESTS.len() + PROPERTY_TESTS.len() + LOOM_TESTS.len(),
        },
        transition_map: TransitionMapReceipt {
            path: String::from(TRANSITION_MAP_PATH),
            sha256: String::from(TRANSITION_MAP_SHA256),
            entries: transition_map.transition.len(),
            checked: transition_map.checked_count,
            observed: transition_map.observed_count,
            planned: transition_map.planned_count,
        },
        fault_contract: FaultContractReceipt {
            path: String::from(FAULT_MATRIX_PATH),
            sha256: String::from(FAULT_MATRIX_SHA256),
            cells: fault_matrix.cell.len(),
            families: fault_matrix.required_families.len(),
            checked: fault_matrix.checked_count,
            observed: fault_matrix.observed_count,
            planned: fault_matrix.planned_count,
            required_observation_fields: fault_matrix.required_observation_fields.len(),
            shared_production_registry_execution_observed: false,
        },
        actor_boundary: String::from(ACTOR_BOUNDARY),
        boundedness_statement: String::from(BOUNDEDNESS_STATEMENT),
        real_ostd_smp_claimed: false,
        release_boundary: ReleaseBoundary {
            accepted_release: String::from("v0.1.0"),
            accepted_specifications: release_specs.len(),
            successor_in_v0_1_catalog: false,
            successor_artifacts_in_v0_1_manifest: false,
        },
        generated_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        logs: Logs {
            pluscal_translation: String::from(PLUSCAL_LOG),
            tlc: String::from(TLC_LOG),
            rust_oracle: String::from(RUST_LOG),
            summary: String::from(SUMMARY_PATH),
        },
        digests: Digests {
            pluscal_translation_sha256: sha256_file(&root.join(PLUSCAL_LOG))?,
            tlc_sha256: sha256_file(&root.join(TLC_LOG))?,
            rust_oracle_sha256: sha256_file(&root.join(RUST_LOG))?,
            summary_sha256: sha256_file(&root.join(SUMMARY_PATH))?,
        },
    };
    validate_receipt(&receipt)?;
    let mut encoded = serde_json::to_vec_pretty(&receipt)?;
    encoded.push(b'\n');
    atomic_write(&root.join(RECEIPT_PATH), &encoded)?;

    println!(
        "PRODUCTION IDENTITY RESEARCH PASS configurations={} witnesses={} rust_tests={} transitions={} fault_cells={} receipt={}",
        receipt.full_configurations,
        receipt.reachability_witnesses,
        receipt.rust_oracle.total_tests,
        receipt.transition_map.entries,
        receipt.fault_contract.cells,
        RECEIPT_PATH
    );
    println!("{BOUNDEDNESS_STATEMENT}");
    Ok(())
}

pub(crate) fn validate_release_boundary(release_specs: &[&str]) -> Result<()> {
    if release_specs != FROZEN_V0_1_SPECS {
        return Err(format!(
            "the accepted v0.1.0 specification catalog changed: expected {:?}, found {release_specs:?}",
            FROZEN_V0_1_SPECS
        )
        .into());
    }
    if release_specs.contains(&SPEC) {
        return Err(
            "ProductionIdentityCser must remain outside the accepted v0.1.0 catalog".into(),
        );
    }
    Ok(())
}

fn validate_transition_map(root: &Path) -> Result<TransitionMap> {
    let contents = read_regular_contract(root, TRANSITION_MAP_PATH)?;
    if sha256_bytes(contents.as_bytes()) != TRANSITION_MAP_SHA256 {
        return Err(format!(
            "production-identity transition map digest drifted: expected {TRANSITION_MAP_SHA256}"
        )
        .into());
    }
    let map: TransitionMap = toml::from_str(&contents)?;
    validate_transition_map_contract(root, &map)?;
    Ok(map)
}

fn validate_transition_map_contract(root: &Path, map: &TransitionMap) -> Result<()> {
    if map.schema != "nexus.research.production-identity.transition-map.v1"
        || map.rfc != "docs/rfcs/0001-production-identity.md"
        || map.abstract_specification != "specs/cser/ProductionIdentityCser.tla"
        || map.rust_oracle != "crates/cser-model/src/production_identity.rs"
        || map.production_registry != "kernel/nexus-ostd/src/cser/effect_registry.rs"
        || map.expected_count != TRANSITION_IDS.len()
        || map.allowed_evidence_states != string_vec(EVIDENCE_STATES)
        || map.checked_count != 20
        || map.observed_count != 0
        || map.planned_count != 2
    {
        return Err("production-identity transition map changed its Phase 1 boundary".into());
    }
    let ids: Vec<_> = map
        .transition
        .iter()
        .map(|transition| transition.id.as_str())
        .collect();
    if ids != TRANSITION_IDS || map.transition.len() != map.expected_count {
        return Err("production-identity transition population or order differs".into());
    }
    if ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err("production-identity transition IDs are not unique".into());
    }
    validate_evidence_population(
        map.transition
            .iter()
            .map(|transition| transition.evidence.as_str()),
        map.checked_count,
        map.observed_count,
        map.planned_count,
        "transition map",
    )?;

    let known_tests = known_rust_tests();
    for (index, transition) in map.transition.iter().enumerate() {
        if transition.abstract_action.is_empty()
            || transition.rust_oracle_source.is_empty()
            || transition.production_sources.is_empty()
            || transition.boundary.is_empty()
        {
            return Err(format!(
                "transition {} contains an empty contract field",
                transition.id
            )
            .into());
        }
        let expected_evidence = if index < 20 { "checked" } else { "planned" };
        if transition.evidence != expected_evidence {
            return Err(format!(
                "transition {} evidence changed: expected {expected_evidence}",
                transition.id
            )
            .into());
        }
        if transition.evidence == "checked" && transition.rust_tests.is_empty() {
            return Err(format!("checked transition {} lacks Rust tests", transition.id).into());
        }
        validate_test_references(&transition.rust_tests, &known_tests, &transition.id)?;
        validate_source_reference(root, &transition.rust_oracle_source)?;
        for source in &transition.production_sources {
            validate_source_reference(root, source)?;
        }
    }
    Ok(())
}

fn validate_fault_matrix(root: &Path) -> Result<FaultMatrix> {
    let contents = read_regular_contract(root, FAULT_MATRIX_PATH)?;
    if sha256_bytes(contents.as_bytes()) != FAULT_MATRIX_SHA256 {
        return Err(format!(
            "production-identity fault matrix digest drifted: expected {FAULT_MATRIX_SHA256}"
        )
        .into());
    }
    let matrix: FaultMatrix = toml::from_str(&contents)?;
    validate_fault_matrix_contract(root, &matrix)?;
    Ok(matrix)
}

fn validate_fault_matrix_contract(root: &Path, matrix: &FaultMatrix) -> Result<()> {
    if matrix.schema != "nexus.research.production-identity.fault-matrix.v1"
        || matrix.rfc != "docs/rfcs/0001-production-identity.md"
        || matrix.transition_map != TRANSITION_MAP_PATH
        || matrix.expected_count != FAULT_CELL_IDS.len()
        || matrix.allowed_evidence_states != string_vec(EVIDENCE_STATES)
        || matrix.checked_count != 12
        || matrix.observed_count != 0
        || matrix.planned_count != 23
        || matrix.shared_production_registry_execution_observed
        || matrix.real_user_service_crash_observed
        || matrix.real_irq_observed
        || matrix.two_vcpu_observed
        || matrix.four_vcpu_observed
    {
        return Err("production-identity fault matrix changed its Phase 1 boundary".into());
    }
    if matrix.required_families != string_vec(REQUIRED_FAULT_FAMILIES)
        || matrix.required_observation_fields != string_vec(REQUIRED_OBSERVATION_FIELDS)
    {
        return Err(
            "production-identity fault matrix lost a required RFC 0001 family or observation field"
                .into(),
        );
    }
    let ids: Vec<_> = matrix.cell.iter().map(|cell| cell.id.as_str()).collect();
    if ids != FAULT_CELL_IDS || matrix.cell.len() != matrix.expected_count {
        return Err("production-identity fault cell population or order differs".into());
    }
    if ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err("production-identity fault cell IDs are not unique".into());
    }
    validate_evidence_population(
        matrix.cell.iter().map(|cell| cell.evidence.as_str()),
        matrix.checked_count,
        matrix.observed_count,
        matrix.planned_count,
        "fault matrix",
    )?;

    let known_tests = known_rust_tests();
    let mut represented_families = BTreeSet::new();
    for cell in &matrix.cell {
        if !REQUIRED_FAULT_FAMILIES.contains(&cell.family.as_str()) {
            return Err(format!("fault cell {} has an unknown family", cell.id).into());
        }
        represented_families.insert(cell.family.as_str());
        if !matches!(
            cell.phase.as_str(),
            "phase-1" | "phase-2" | "phase-3" | "phase-4"
        ) || cell.injection_point.is_empty()
            || cell.cpu_requirement.is_empty()
            || cell.presented_identity.is_empty()
            || cell.expected_result.is_empty()
            || cell.production_sources.is_empty()
            || cell.boundary.is_empty()
        {
            return Err(format!(
                "fault cell {} contains an invalid or empty contract field",
                cell.id
            )
            .into());
        }
        match cell.evidence.as_str() {
            "checked" if cell.phase == "phase-1" && !cell.oracle_tests.is_empty() => {}
            "planned" if cell.oracle_tests.is_empty() => {}
            _ => {
                return Err(format!(
                    "fault cell {} evidence does not match its Phase 1 oracle population",
                    cell.id
                )
                .into());
            }
        }
        validate_test_references(&cell.oracle_tests, &known_tests, &cell.id)?;
        for source in &cell.production_sources {
            validate_source_reference(root, source)?;
        }
    }
    if represented_families
        != REQUIRED_FAULT_FAMILIES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    {
        return Err("production-identity fault cells do not cover every required family".into());
    }
    Ok(())
}

fn validate_evidence_population<'a>(
    evidence: impl Iterator<Item = &'a str>,
    expected_checked: usize,
    expected_observed: usize,
    expected_planned: usize,
    context: &str,
) -> Result<()> {
    let mut checked = 0;
    let mut observed = 0;
    let mut planned = 0;
    for state in evidence {
        match state {
            "checked" => checked += 1,
            "observed" => observed += 1,
            "planned" => planned += 1,
            other => return Err(format!("{context} uses unknown evidence state {other}").into()),
        }
    }
    if (checked, observed, planned) != (expected_checked, expected_observed, expected_planned) {
        return Err(format!(
            "{context} evidence population differs: expected checked={expected_checked} observed={expected_observed} planned={expected_planned}, found checked={checked} observed={observed} planned={planned}"
        )
        .into());
    }
    Ok(())
}

fn known_rust_tests() -> BTreeSet<&'static str> {
    SEQUENCE_TESTS
        .iter()
        .chain(PROPERTY_TESTS)
        .chain(LOOM_TESTS)
        .copied()
        .collect()
}

fn validate_test_references(
    tests: &[String],
    known_tests: &BTreeSet<&str>,
    context: &str,
) -> Result<()> {
    if tests.iter().collect::<BTreeSet<_>>().len() != tests.len() {
        return Err(format!("{context} repeats a Rust oracle test").into());
    }
    for test in tests {
        if !known_tests.contains(test.as_str()) {
            return Err(format!("{context} references unknown Rust oracle test {test}").into());
        }
    }
    Ok(())
}

fn validate_source_reference(root: &Path, reference: &str) -> Result<()> {
    let (relative, symbol) = match reference.split_once(".rs::") {
        Some((path, symbol)) => (format!("{path}.rs"), Some(symbol)),
        None if reference.ends_with(".rs") => (String::from(reference), None),
        None => return Err(format!("source reference lacks a Rust path: {reference}").into()),
    };
    let path = Path::new(&relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!("source reference escapes repository: {reference}").into());
    }
    let absolute = root.join(path);
    let metadata = fs::symlink_metadata(&absolute)
        .map_err(|error| format!("source reference {reference}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("source reference is not a regular file: {reference}").into());
    }
    if let Some(symbol) = symbol {
        let name = symbol
            .rsplit("::")
            .next()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("source reference has an empty symbol: {reference}"))?;
        let source = fs::read_to_string(&absolute)?;
        if !source.contains(&format!("fn {name}")) {
            return Err(format!("source reference symbol is absent: {reference}").into());
        }
    }
    Ok(())
}

fn read_regular_contract(root: &Path, relative: &str) -> Result<String> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("contract must be a regular non-symlink file: {relative}").into());
    }
    let first = fs::read_to_string(&path)?;
    let second = fs::read_to_string(&path)?;
    if first != second {
        return Err(format!("contract changed while reading: {relative}").into());
    }
    Ok(first)
}

fn string_vec(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| String::from(*value)).collect()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn clear_previous_outputs(root: &Path) -> Result<()> {
    for relative in [PLUSCAL_LOG, TLC_LOG, RUST_LOG, SUMMARY_PATH, RECEIPT_PATH] {
        match fs::remove_file(root.join(relative)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "remove stale production-identity artifact {relative}: {error}"
                )
                .into());
            }
        }
    }
    Ok(())
}

fn validate_tlc_log(log: &str) -> Result<LogSummary> {
    let lines: Vec<_> = log.lines().collect();
    let starts: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("==> ProductionIdentityCser "))
        .map(|(index, line)| (index, *line))
        .collect();
    let expected_headings: Vec<_> = SECTION_ORDER.iter().map(expected_heading).collect();
    let actual_headings: Vec<_> = starts
        .iter()
        .map(|(_, heading)| String::from(*heading))
        .collect();
    if actual_headings != expected_headings {
        return Err(format!(
            "ProductionIdentityCser section population or order differs: expected {expected_headings:?}, found {actual_headings:?}"
        )
        .into());
    }

    let expected_coverage: Vec<_> = WITNESSES
        .iter()
        .map(|witness| format!("COVERAGE_RESULT PASS {}", witness.description))
        .collect();
    let actual_coverage: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("COVERAGE_RESULT "))
        .map(|line| String::from(*line))
        .collect();
    if actual_coverage != expected_coverage {
        return Err(format!(
            "ProductionIdentityCser coverage population or order differs: expected {expected_coverage:?}, found {actual_coverage:?}"
        )
        .into());
    }

    let completion_marker = "Model checking completed. No error has been found.";
    let completion_count = lines
        .iter()
        .filter(|line| **line == completion_marker)
        .count();
    if completion_count != CONFIGURATIONS.len() {
        return Err(format!(
            "ProductionIdentityCser has {completion_count} complete TLC markers; expected {}",
            CONFIGURATIONS.len()
        )
        .into());
    }

    let mut configurations = Vec::with_capacity(CONFIGURATIONS.len());
    let mut witnesses = Vec::with_capacity(WITNESSES.len());
    for (position, section) in SECTION_ORDER.iter().enumerate() {
        let start = starts[position].0;
        let end = starts
            .get(position + 1)
            .map(|(index, _)| *index)
            .unwrap_or(lines.len());
        let block = &lines[start..end];
        match section {
            ExpectedSection::Configuration(index) => {
                let expected = CONFIGURATIONS[*index];
                configurations.push(validate_configuration_block(expected, block)?);
            }
            ExpectedSection::Witness(index) => {
                let expected = WITNESSES[*index];
                witnesses.push(validate_witness_block(expected, block)?);
            }
        }
    }

    let expected_configurations: Vec<_> =
        CONFIGURATIONS.iter().map(configuration_receipt).collect();
    if configurations != expected_configurations {
        return Err("ProductionIdentityCser configuration receipts differ from the frozen four-graph contract".into());
    }
    let expected_witnesses: Vec<_> = WITNESSES.iter().map(witness_receipt).collect();
    if witnesses != expected_witnesses {
        return Err(
            "ProductionIdentityCser witness receipts differ from the frozen eight-witness contract"
                .into(),
        );
    }

    Ok(LogSummary {
        configurations,
        witnesses,
    })
}

fn run_rust_oracle(root: &Path) -> Result<()> {
    super::section("run independent production-identity safe-Rust oracle");
    let script = r#"
set -eu
echo '==> production-identity sequence oracle'
cargo test --locked -p cser-model --test production_identity_sequences
echo '==> production-identity property oracle'
cargo test --locked -p cser-model --test production_identity_properties
echo '==> production-identity Loom oracle'
cargo test --locked -p cser-model --test production_identity_loom
"#;
    let mut command = Command::new("sh");
    command.current_dir(root).arg("-c").arg(script);
    super::run_bounded_logged_quiet(
        &mut command,
        &root.join(RUST_LOG),
        Duration::from_secs(600),
        8 * 1024 * 1024,
    )
}

fn validate_rust_log(log: &str) -> Result<()> {
    let suites = [
        ("==> production-identity sequence oracle", SEQUENCE_TESTS),
        ("==> production-identity property oracle", PROPERTY_TESTS),
        ("==> production-identity Loom oracle", LOOM_TESTS),
    ];
    let lines: Vec<_> = log.lines().collect();
    let headings: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("==> production-identity "))
        .map(|(index, line)| (index, *line))
        .collect();
    if headings.iter().map(|(_, line)| *line).collect::<Vec<_>>()
        != suites
            .iter()
            .map(|(heading, _)| *heading)
            .collect::<Vec<_>>()
    {
        return Err("production-identity Rust suite population or order differs".into());
    }
    for (index, (_, tests)) in suites.iter().enumerate() {
        let start = headings[index].0;
        let end = headings
            .get(index + 1)
            .map(|(position, _)| *position)
            .unwrap_or(lines.len());
        let block = &lines[start..end];
        for test in *tests {
            let marker = format!("test {test} ... ok");
            if block.iter().filter(|line| **line == marker).count() != 1 {
                return Err(format!("Rust oracle test marker differs: {test}").into());
            }
        }
        let result = format!(
            "test result: ok. {} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
            tests.len()
        );
        if block
            .iter()
            .filter(|line| line.starts_with(&result))
            .count()
            != 1
        {
            return Err(format!(
                "production-identity Rust oracle suite lacks exact pass count: {}",
                tests.len()
            )
            .into());
        }
    }
    Ok(())
}

fn expected_heading(section: &ExpectedSection) -> String {
    match section {
        ExpectedSection::Configuration(index) => {
            format!("==> {}", CONFIGURATIONS[*index].heading)
        }
        ExpectedSection::Witness(index) => {
            format!("==> {SPEC} reachability: {}", WITNESSES[*index].description)
        }
    }
}

fn validate_configuration_block(
    expected: ConfigurationExpectation,
    block: &[&str],
) -> Result<ConfigurationReceipt> {
    let completion_marker = "Model checking completed. No error has been found.";
    let completions = block
        .iter()
        .filter(|line| **line == completion_marker)
        .count();
    if completions != 1 {
        return Err(format!(
            "{} has {completions} complete TLC markers; expected one",
            expected.config
        )
        .into());
    }
    if block
        .iter()
        .any(|line| line.starts_with("COVERAGE_RESULT "))
    {
        return Err(format!("{} contains a fabricated coverage marker", expected.config).into());
    }

    let state_lines: Vec<_> = block
        .iter()
        .filter(|line| {
            line.as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_digit())
                && line.contains(" states generated, ")
                && line.contains(" states left on queue.")
        })
        .collect();
    if state_lines.len() != 1 {
        return Err(format!(
            "{} has {} final state-population lines; expected one",
            expected.config,
            state_lines.len()
        )
        .into());
    }
    let (generated, distinct, left_on_queue) = parse_state_population(state_lines[0])?;
    let depth_lines: Vec<_> = block
        .iter()
        .filter(|line| line.starts_with("The depth of the complete state graph search is "))
        .collect();
    if depth_lines.len() != 1 {
        return Err(format!(
            "{} has {} complete-depth lines; expected one",
            expected.config,
            depth_lines.len()
        )
        .into());
    }
    let depth = parse_depth(depth_lines[0])?;
    let observed = GraphStats {
        generated,
        distinct,
        left_on_queue,
        depth,
    };
    let required = GraphStats {
        generated: expected.generated,
        distinct: expected.distinct,
        left_on_queue: 0,
        depth: expected.depth,
    };
    if observed != required {
        return Err(format!(
            "{} graph population differs: expected {required:?}, found {observed:?}",
            expected.config
        )
        .into());
    }
    if expected.config == "ProductionIdentityCserProgressMC.cfg" {
        let temporal_branches = block
            .iter()
            .filter(|line| {
                **line == "Implied-temporal checking--satisfiability problem has 5 branches."
            })
            .count();
        if temporal_branches != 1 {
            return Err(format!(
                "{} has {temporal_branches} five-branch temporal markers; expected one",
                expected.config
            )
            .into());
        }
    }
    Ok(configuration_receipt(&expected))
}

fn validate_witness_block(expected: WitnessExpectation, block: &[&str]) -> Result<WitnessReceipt> {
    let coverage = format!("COVERAGE_RESULT PASS {}", expected.description);
    let coverage_count = block
        .iter()
        .filter(|line| **line == coverage.as_str())
        .count();
    if coverage_count != 1 {
        return Err(format!(
            "witness {} has {coverage_count} exact coverage markers; expected one",
            expected.invariant
        )
        .into());
    }
    let invariant_marker = format!("Invariant {} is violated", expected.invariant);
    let invariant_count = block
        .iter()
        .filter(|line| line.contains(&invariant_marker))
        .count();
    if invariant_count != 1 {
        return Err(format!(
            "witness {} has {invariant_count} expected invariant violations; expected one",
            expected.invariant
        )
        .into());
    }
    if block.contains(&"Model checking completed. No error has been found.") {
        return Err(format!(
            "witness {} was mislabeled as a successful invariant graph",
            expected.invariant
        )
        .into());
    }
    Ok(witness_receipt(&expected))
}

fn parse_state_population(line: &str) -> Result<(u64, u64, u64)> {
    let (generated, remainder) = line
        .split_once(" states generated, ")
        .ok_or_else(|| format!("malformed TLC state population: {line}"))?;
    let (distinct, remainder) = remainder
        .split_once(" distinct states found, ")
        .ok_or_else(|| format!("malformed TLC distinct population: {line}"))?;
    let left = remainder
        .strip_suffix(" states left on queue.")
        .ok_or_else(|| format!("malformed TLC queue population: {line}"))?;
    Ok((
        parse_formatted_u64(generated)?,
        parse_formatted_u64(distinct)?,
        parse_formatted_u64(left)?,
    ))
}

fn parse_depth(line: &str) -> Result<u64> {
    let value = line
        .strip_prefix("The depth of the complete state graph search is ")
        .and_then(|value| value.strip_suffix('.'))
        .ok_or_else(|| format!("malformed TLC complete depth: {line}"))?;
    parse_formatted_u64(value)
}

fn parse_formatted_u64(value: &str) -> Result<u64> {
    Ok(value.replace(',', "").parse()?)
}

fn configuration_receipt(expected: &ConfigurationExpectation) -> ConfigurationReceipt {
    ConfigurationReceipt {
        config: String::from(expected.config),
        status: String::from("complete"),
        generated: expected.generated,
        distinct: expected.distinct,
        depth: expected.depth,
        states_left_on_queue: 0,
        property_mode: String::from(expected.property_mode),
    }
}

fn witness_receipt(expected: &WitnessExpectation) -> WitnessReceipt {
    WitnessReceipt {
        config: String::from(expected.config),
        invariant: String::from(expected.invariant),
        description: String::from(expected.description),
        status: String::from("reachable"),
    }
}

fn validate_receipt(receipt: &Receipt) -> Result<()> {
    if receipt.schema != SCHEMA
        || receipt.status != "passed"
        || !receipt.prospective
        || receipt.command != COMMAND
        || !receipt.translation_current
    {
        return Err(
            "production-identity receipt has an invalid identity or status boundary".into(),
        );
    }
    if receipt.actor_boundary != ACTOR_BOUNDARY
        || receipt.boundedness_statement != BOUNDEDNESS_STATEMENT
        || receipt.real_ostd_smp_claimed
    {
        return Err(
            "production-identity receipt overstates its abstract CPU-actor boundary".into(),
        );
    }
    if receipt.release_boundary
        != (ReleaseBoundary {
            accepted_release: String::from("v0.1.0"),
            accepted_specifications: FROZEN_V0_1_SPECS.len(),
            successor_in_v0_1_catalog: false,
            successor_artifacts_in_v0_1_manifest: false,
        })
    {
        return Err("production-identity receipt changed the accepted v0.1.0 boundary".into());
    }
    let configurations: Vec<_> = CONFIGURATIONS.iter().map(configuration_receipt).collect();
    if receipt.full_configurations != CONFIGURATIONS.len()
        || receipt.configurations != configurations
    {
        return Err(
            "production-identity receipt lacks the exact four complete configurations".into(),
        );
    }
    let witnesses: Vec<_> = WITNESSES.iter().map(witness_receipt).collect();
    if receipt.reachability_witnesses != WITNESSES.len() || receipt.witnesses != witnesses {
        return Err(
            "production-identity receipt lacks the exact eight reachability witnesses".into(),
        );
    }
    if receipt.rust_oracle
        != (RustOracleReceipt {
            independent_from_production_registry: true,
            sequence_tests: SEQUENCE_TESTS.len(),
            property_tests: PROPERTY_TESTS.len(),
            loom_tests: LOOM_TESTS.len(),
            total_tests: SEQUENCE_TESTS.len() + PROPERTY_TESTS.len() + LOOM_TESTS.len(),
        })
    {
        return Err("production-identity receipt lacks the exact 5 + 3 + 3 Rust oracle".into());
    }
    if receipt.transition_map
        != (TransitionMapReceipt {
            path: String::from(TRANSITION_MAP_PATH),
            sha256: String::from(TRANSITION_MAP_SHA256),
            entries: TRANSITION_IDS.len(),
            checked: 20,
            observed: 0,
            planned: 2,
        })
    {
        return Err("production-identity receipt changed the transition-map contract".into());
    }
    if receipt.fault_contract
        != (FaultContractReceipt {
            path: String::from(FAULT_MATRIX_PATH),
            sha256: String::from(FAULT_MATRIX_SHA256),
            cells: FAULT_CELL_IDS.len(),
            families: REQUIRED_FAULT_FAMILIES.len(),
            checked: 12,
            observed: 0,
            planned: 23,
            required_observation_fields: REQUIRED_OBSERVATION_FIELDS.len(),
            shared_production_registry_execution_observed: false,
        })
    {
        return Err("production-identity receipt changed the fault-matrix contract".into());
    }
    let source_files: Vec<_> = SOURCE_FILES
        .iter()
        .map(|path| String::from(*path))
        .collect();
    if receipt.source_files != source_files
        || !is_sha256(&receipt.source_fingerprint)
        || receipt.revision.is_empty()
    {
        return Err("production-identity receipt is not bound to the expected source set".into());
    }
    if receipt.logs
        != (Logs {
            pluscal_translation: String::from(PLUSCAL_LOG),
            tlc: String::from(TLC_LOG),
            rust_oracle: String::from(RUST_LOG),
            summary: String::from(SUMMARY_PATH),
        })
        || !is_sha256(&receipt.digests.pluscal_translation_sha256)
        || !is_sha256(&receipt.digests.tlc_sha256)
        || !is_sha256(&receipt.digests.rust_oracle_sha256)
        || !is_sha256(&receipt.digests.summary_sha256)
    {
        return Err("production-identity receipt has an invalid artifact binding".into());
    }
    Ok(())
}

fn summary_text(revision: &str, source_fingerprint: &str, worktree_dirty: bool) -> String {
    format!(
        "schema={SUMMARY_SCHEMA}\nstatus=passed\nprospective=true\ncommand={COMMAND}\nrevision={revision}\nworktree_dirty={worktree_dirty}\nsource_fingerprint={source_fingerprint}\ntranslation_current=true\nfull_configurations={}\nreachability_witnesses={}\nrust_sequence_tests={}\nrust_property_tests={}\nrust_loom_tests={}\ntransition_map_entries={}\ntransition_checked=20\ntransition_observed=0\ntransition_planned=2\nfault_cells={}\nfault_families={}\nfault_checked=12\nfault_observed=0\nfault_planned=23\nshared_production_registry_execution_observed=false\naccepted_v0_1_specifications={}\nsuccessor_in_v0_1_catalog=false\nsuccessor_artifacts_in_v0_1_manifest=false\nactor_boundary={ACTOR_BOUNDARY}\nboundedness_statement={BOUNDEDNESS_STATEMENT}\nreal_ostd_smp_claimed=false\nreceipt={RECEIPT_PATH}\n",
        CONFIGURATIONS.len(),
        WITNESSES.len(),
        SEQUENCE_TESTS.len(),
        PROPERTY_TESTS.len(),
        LOOM_TESTS.len(),
        TRANSITION_IDS.len(),
        FAULT_CELL_IDS.len(),
        REQUIRED_FAULT_FAMILIES.len(),
        FROZEN_V0_1_SPECS.len(),
    )
}

fn fingerprint_paths(root: &Path, paths: &[&str]) -> Result<String> {
    let mut digest = Sha256::new();
    for relative in paths {
        let path = Path::new(relative);
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(
                format!("source fingerprint path escapes the repository: {relative}").into(),
            );
        }
        let absolute = root.join(path);
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("source fingerprint input {relative}: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(
                format!("source fingerprint input is not a regular file: {relative}").into(),
            );
        }
        let first = fs::read(&absolute)?;
        let second = fs::read(&absolute)?;
        if first != second {
            return Err(
                format!("source fingerprint input changed while reading: {relative}").into(),
            );
        }
        digest_field(&mut digest, relative.as_bytes());
        digest_field(&mut digest, &first);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn digest_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    let bytes = git_bytes(root, args)?;
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git").current_dir(root).args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "git command failed with {}: git {}",
            output.status,
            args.join(" ")
        )
        .into());
    }
    Ok(output.stdout)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("artifact path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("artifact path has no UTF-8 file name: {}", path.display()))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    fs::write(&temporary, bytes)?;
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("xtask repository root")
            .to_path_buf()
    }

    fn synthetic_log() -> String {
        let mut log = String::new();
        for section in SECTION_ORDER {
            log.push_str(&expected_heading(&section));
            log.push('\n');
            match section {
                ExpectedSection::Configuration(index) => {
                    let expected = CONFIGURATIONS[index];
                    if expected.config == "ProductionIdentityCserProgressMC.cfg" {
                        log.push_str(
                            "Implied-temporal checking--satisfiability problem has 5 branches.\n",
                        );
                        log.push_str(&format!(
                            "Progress(32): {} states generated, {} distinct states found, 0 states left on queue.\n",
                            expected.generated, expected.distinct
                        ));
                    }
                    log.push_str("Model checking completed. No error has been found.\n");
                    log.push_str(&format!(
                        "{} states generated, {} distinct states found, 0 states left on queue.\n",
                        expected.generated, expected.distinct
                    ));
                    log.push_str(&format!(
                        "The depth of the complete state graph search is {}.\n",
                        expected.depth
                    ));
                }
                ExpectedSection::Witness(index) => {
                    let expected = WITNESSES[index];
                    log.push_str(&format!(
                        "Error: Invariant {} is violated.\n",
                        expected.invariant
                    ));
                    log.push_str(&format!("COVERAGE_RESULT PASS {}\n", expected.description));
                }
            }
        }
        log
    }

    fn synthetic_rust_log() -> String {
        let suites = [
            ("==> production-identity sequence oracle", SEQUENCE_TESTS),
            ("==> production-identity property oracle", PROPERTY_TESTS),
            ("==> production-identity Loom oracle", LOOM_TESTS),
        ];
        let mut log = String::new();
        for (heading, tests) in suites {
            log.push_str(heading);
            log.push('\n');
            for test in tests {
                log.push_str(&format!("test {test} ... ok\n"));
            }
            log.push_str(&format!(
                "test result: ok. {} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
                tests.len()
            ));
        }
        log
    }

    #[test]
    fn accepts_exact_four_configurations_and_eight_witnesses() {
        let summary = validate_tlc_log(&synthetic_log()).expect("valid research log");
        assert_eq!(summary.configurations.len(), 4);
        assert_eq!(summary.witnesses.len(), 8);
    }

    #[test]
    fn accepts_exact_five_three_three_rust_oracle_population() {
        validate_rust_log(&synthetic_rust_log()).expect("valid Rust oracle log");

        let missing =
            synthetic_rust_log().replacen(&format!("test {} ... ok\n", SEQUENCE_TESTS[0]), "", 1);
        assert!(validate_rust_log(&missing).is_err());

        let wrong_count = synthetic_rust_log().replacen("5 passed", "6 passed", 1);
        assert!(validate_rust_log(&wrong_count).is_err());

        let reordered = synthetic_rust_log()
            .replacen(
                "==> production-identity sequence oracle",
                "TEMPORARY_HEADING",
                1,
            )
            .replacen(
                "==> production-identity property oracle",
                "==> production-identity sequence oracle",
                1,
            )
            .replacen(
                "TEMPORARY_HEADING",
                "==> production-identity property oracle",
                1,
            );
        assert!(validate_rust_log(&reordered).is_err());
    }

    #[test]
    fn checked_in_transition_map_is_exact_and_rejects_contract_drift() {
        let root = root();
        let map = validate_transition_map(&root).expect("valid transition map");
        assert_eq!(map.transition.len(), 22);
        assert_eq!(
            (map.checked_count, map.observed_count, map.planned_count),
            (20, 0, 2)
        );

        let mut reordered = map.clone();
        reordered.transition.swap(0, 1);
        assert!(validate_transition_map_contract(&root, &reordered).is_err());

        let mut overstated = map.clone();
        overstated.transition[0].evidence = String::from("observed");
        assert!(validate_transition_map_contract(&root, &overstated).is_err());

        let mut remapped = map;
        remapped.transition[0].production_sources[0] = String::from(
            "kernel/nexus-ostd/src/cser/effect_registry.rs::EffectRegistry::missing_mapping",
        );
        assert!(validate_transition_map_contract(&root, &remapped).is_err());
    }

    #[test]
    fn checked_in_fault_matrix_is_exact_and_rejects_contract_drift() {
        let root = root();
        let matrix = validate_fault_matrix(&root).expect("valid fault matrix");
        assert_eq!(matrix.cell.len(), 35);
        assert_eq!(
            (
                matrix.checked_count,
                matrix.observed_count,
                matrix.planned_count
            ),
            (12, 0, 23)
        );

        let mut reordered = matrix.clone();
        reordered.cell.swap(0, 1);
        assert!(validate_fault_matrix_contract(&root, &reordered).is_err());

        let mut overstated = matrix.clone();
        overstated.cell[0].evidence = String::from("observed");
        assert!(validate_fault_matrix_contract(&root, &overstated).is_err());

        let mut remapped = matrix.clone();
        remapped.cell[0].production_sources[0] = String::from(
            "kernel/nexus-ostd/src/cser/effect_registry.rs::EffectRegistry::missing_mapping",
        );
        assert!(validate_fault_matrix_contract(&root, &remapped).is_err());

        let mut missing_family = matrix;
        missing_family.required_families.pop();
        assert!(validate_fault_matrix_contract(&root, &missing_family).is_err());
    }

    #[test]
    fn machine_readable_contracts_deny_unknown_fields_and_raw_drift() {
        let root = root();
        let transition =
            read_regular_contract(&root, TRANSITION_MAP_PATH).expect("checked-in transition map");
        let matrix =
            read_regular_contract(&root, FAULT_MATRIX_PATH).expect("checked-in fault matrix");
        assert!(
            toml::from_str::<TransitionMap>(&format!("{transition}\nunknown = true\n")).is_err()
        );
        assert!(toml::from_str::<FaultMatrix>(&format!("{matrix}\nunknown = true\n")).is_err());
        assert_ne!(
            sha256_bytes(
                transition
                    .replacen("derive-register", "derive-renamed", 1)
                    .as_bytes()
            ),
            TRANSITION_MAP_SHA256
        );
        assert_ne!(
            sha256_bytes(
                matrix
                    .replacen("wrong-root", "wrong-root-renamed", 1)
                    .as_bytes()
            ),
            FAULT_MATRIX_SHA256
        );
    }

    #[test]
    fn rejects_missing_duplicated_and_fabricated_witness_markers() {
        let marker = format!("COVERAGE_RESULT PASS {}", WITNESSES[0].description);

        let missing = synthetic_log().replacen(&format!("{marker}\n"), "", 1);
        assert!(validate_tlc_log(&missing).is_err());

        let duplicated = format!("{}{}\n", synthetic_log(), marker);
        assert!(validate_tlc_log(&duplicated).is_err());

        let fabricated = synthetic_log().replacen(
            &marker,
            "COVERAGE_RESULT PASS fabricated successor evidence",
            1,
        );
        assert!(validate_tlc_log(&fabricated).is_err());
    }

    #[test]
    fn rejects_reordered_sections_and_inexact_graph_populations() {
        let first = expected_heading(&ExpectedSection::Configuration(0));
        let second = expected_heading(&ExpectedSection::Configuration(1));
        let reordered = synthetic_log()
            .replacen(&first, "TEMPORARY_HEADING", 1)
            .replacen(&second, &first, 1)
            .replacen("TEMPORARY_HEADING", &second, 1);
        assert!(validate_tlc_log(&reordered).is_err());

        let population = synthetic_log().replacen(
            "4793 states generated, 3396 distinct states found",
            "4794 states generated, 3396 distinct states found",
            1,
        );
        assert!(validate_tlc_log(&population).is_err());
    }

    #[test]
    fn freezes_the_v0_1_catalog_outside_the_successor() {
        validate_release_boundary(&FROZEN_V0_1_SPECS).expect("frozen catalog");
        let mut widened = FROZEN_V0_1_SPECS.to_vec();
        widened.push(SPEC);
        assert!(validate_release_boundary(&widened).is_err());
        assert_eq!(FROZEN_V0_1_SPECS.len(), 12);
    }

    #[test]
    fn receipt_contract_forbids_real_ostd_smp_claims() {
        let configurations = CONFIGURATIONS
            .iter()
            .map(configuration_receipt)
            .collect::<Vec<_>>();
        let witnesses = WITNESSES.iter().map(witness_receipt).collect::<Vec<_>>();
        let mut receipt = Receipt {
            schema: String::from(SCHEMA),
            status: String::from("passed"),
            prospective: true,
            command: String::from(COMMAND),
            revision: String::from("revision"),
            worktree_dirty: true,
            source_fingerprint: "a".repeat(64),
            source_files: SOURCE_FILES
                .iter()
                .map(|path| String::from(*path))
                .collect(),
            translation_current: true,
            full_configurations: configurations.len(),
            configurations,
            reachability_witnesses: witnesses.len(),
            witnesses,
            rust_oracle: RustOracleReceipt {
                independent_from_production_registry: true,
                sequence_tests: SEQUENCE_TESTS.len(),
                property_tests: PROPERTY_TESTS.len(),
                loom_tests: LOOM_TESTS.len(),
                total_tests: SEQUENCE_TESTS.len() + PROPERTY_TESTS.len() + LOOM_TESTS.len(),
            },
            transition_map: TransitionMapReceipt {
                path: String::from(TRANSITION_MAP_PATH),
                sha256: String::from(TRANSITION_MAP_SHA256),
                entries: TRANSITION_IDS.len(),
                checked: 20,
                observed: 0,
                planned: 2,
            },
            fault_contract: FaultContractReceipt {
                path: String::from(FAULT_MATRIX_PATH),
                sha256: String::from(FAULT_MATRIX_SHA256),
                cells: FAULT_CELL_IDS.len(),
                families: REQUIRED_FAULT_FAMILIES.len(),
                checked: 12,
                observed: 0,
                planned: 23,
                required_observation_fields: REQUIRED_OBSERVATION_FIELDS.len(),
                shared_production_registry_execution_observed: false,
            },
            actor_boundary: String::from(ACTOR_BOUNDARY),
            boundedness_statement: String::from(BOUNDEDNESS_STATEMENT),
            real_ostd_smp_claimed: false,
            release_boundary: ReleaseBoundary {
                accepted_release: String::from("v0.1.0"),
                accepted_specifications: 12,
                successor_in_v0_1_catalog: false,
                successor_artifacts_in_v0_1_manifest: false,
            },
            generated_unix_seconds: 1,
            logs: Logs {
                pluscal_translation: String::from(PLUSCAL_LOG),
                tlc: String::from(TLC_LOG),
                rust_oracle: String::from(RUST_LOG),
                summary: String::from(SUMMARY_PATH),
            },
            digests: Digests {
                pluscal_translation_sha256: "b".repeat(64),
                tlc_sha256: "c".repeat(64),
                rust_oracle_sha256: "d".repeat(64),
                summary_sha256: "e".repeat(64),
            },
        };
        validate_receipt(&receipt).expect("bounded prospective receipt");

        receipt.real_ostd_smp_claimed = true;
        assert!(validate_receipt(&receipt).is_err());
        receipt.real_ostd_smp_claimed = false;
        receipt.boundedness_statement = String::from("real SMP evidence");
        assert!(validate_receipt(&receipt).is_err());
    }
}
