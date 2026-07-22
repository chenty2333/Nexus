use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::Result;

const SPEC: &str = "HandoffAdmissionCser";
const SCHEMA: &str = "nexus.research.handoff-admission.v2";
const SUMMARY_SCHEMA: &str = "nexus.research.handoff-admission.summary.v2";
const COMMAND: &str = "./x research handoff-admission";
const OUTPUT_DIRECTORY: &str = "target/research/handoff-admission";
const TLA_LOG: &str = "target/research/handoff-admission/tla.log";
const RUST_LOG: &str = "target/research/handoff-admission/rust-oracle.log";
const SUMMARY_PATH: &str = "target/research/handoff-admission/summary.txt";
const RECEIPT_PATH: &str = "target/research/handoff-admission/receipt.json";
const MATRIX_PATH: &str = "evaluation/handoff-admission/fault-matrix.toml";
const PRODUCTION_REGISTRY: &str = "kernel/nexus-ostd/src/cser/effect_registry.rs";

const SOURCE_FILES: &[&str] = &[
    "x",
    "Dockerfile",
    ".cargo/config.toml",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "third_party/tlaplus/1.8.0-227f61b/tla2tools-227f61b.jar",
    "third_party/tlaplus/1.8.0-227f61b/PROVENANCE.json",
    "third_party/tlaplus/1.8.0-227f61b/SHA256SUMS",
    "third_party/tlaplus/1.8.0-227f61b/LICENSE.upstream",
    "crates/cser-model/Cargo.toml",
    "crates/cser-model/src/lib.rs",
    "crates/cser-model/src/handoff_admission.rs",
    "crates/cser-model/tests/handoff_admission_support/mod.rs",
    "crates/cser-model/tests/handoff_admission_sequences.rs",
    "crates/cser-model/tests/handoff_admission_properties.rs",
    "crates/cser-model/tests/handoff_admission_loom.rs",
    "crates/cser-model/README.md",
    "crates/cser-transition-gates/Cargo.toml",
    "crates/cser-transition-gates/src/lib.rs",
    "crates/cser-transition-gates/src/handoff.rs",
    "crates/cser-transition-gates/tests/handoff_loom.rs",
    "crates/cser-transition-gates/tests/production_handoff_registry.rs",
    "crates/nexus-effect-peer-wire/Cargo.toml",
    "crates/nexus-effect-peer-wire/PROVENANCE.md",
    "crates/nexus-effect-peer-wire/README.md",
    "crates/nexus-effect-peer-wire/contract/effect-peer-native-v1.json",
    "crates/nexus-effect-peer-wire/src/frozen_v1.rs",
    "crates/nexus-effect-peer-wire/src/lib.rs",
    "crates/nexus-effect-peer-wire/tests/frozen_v1.rs",
    "crates/nexus-effect-peer/Cargo.toml",
    "crates/nexus-effect-peer/README.md",
    "crates/nexus-effect-peer/src/lib.rs",
    "crates/nexus-effect-peer/src/main.rs",
    "crates/nexus-effect-peer/src/peer.rs",
    "crates/nexus-effect-peer/src/peer_tests.rs",
    "crates/nexus-effect-peer/tests/stdio.rs",
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
    "specs/cser/check.sh",
    "specs/cser/HandoffAdmissionCser.tla",
    "specs/cser/HandoffAdmissionCserSafetyMC.cfg",
    "specs/cser/HandoffAdmissionCserProgressMC.cfg",
    "specs/cser/HANDOFF_ADMISSION.md",
    "specs/cser/README.md",
    "docs/rfcs/0002-handoff-admission-profile.md",
    "evaluation/handoff-admission/fault-matrix.toml",
    "evaluation/handoff-admission/README.md",
    "README.md",
    "ARCHITECTURE.md",
    "CONTRIBUTING.md",
    "tools/xtask/Cargo.toml",
    "tools/xtask/Cargo.lock",
    "tools/xtask/src/main.rs",
    "tools/xtask/src/evidence.rs",
    "tools/xtask/src/handoff_admission.rs",
    "tools/xtask/src/production_identity.rs",
];

const REQUIRED_INVARIANTS: &[&str] = &[
    "AtMostOneExecutionAuthority",
    "NoPostFreezeUntrackedEffect",
    "AbortImpliesNoDestinationAuthority",
    "CommitDecisionImpliesSourcePrincipalFenced",
    "PostCommitPublicationImpliesPreFreezeCommittedAndClosureOwned",
    "UnknownDecisionImpliesRemainFrozen",
    "DestinationActivationRequiresSourceClosure",
    "EveryReceiptBindsOneDecisionAndOneCohort",
    "StaleBindingCannotPublish",
    "TombstoneCannotBeInterpretedAsClosure",
];

const NEGATIVE_MUTATIONS: &[&str] = &[
    "drop-cell",
    "duplicate-cell",
    "reorder-cell",
    "rename-witness",
    "rename-rust-test",
    "allow-freeze-without-intent",
    "allow-first-commit-after-freeze",
    "accept-untyped-abort",
    "accept-conflicting-decision",
    "activate-before-closure",
    "treat-tombstone-as-closure",
];

#[derive(Clone, Copy)]
struct ConfigurationExpectation {
    config: &'static str,
    heading: &'static str,
    generated: u64,
    distinct: u64,
    depth: u64,
    property_mode: &'static str,
    temporal_branches: Option<u64>,
}

const CONFIGURATIONS: &[ConfigurationExpectation] = &[
    ConfigurationExpectation {
        config: "HandoffAdmissionCserSafetyMC.cfg",
        heading: "HandoffAdmissionCser complete local safety graph",
        generated: 100_118,
        distinct: 32_438,
        depth: 25,
        property_mode: "safety-with-postcommit-retention",
        temporal_branches: None,
    },
    ConfigurationExpectation {
        config: "HandoffAdmissionCserProgressMC.cfg",
        heading: "HandoffAdmissionCser conditional local closure progress",
        generated: 72_470,
        distinct: 26_390,
        depth: 25,
        property_mode: "conditional-progress-2-temporal-branches",
        temporal_branches: Some(2),
    },
];

#[derive(Clone, Copy)]
struct WitnessExpectation {
    invariant: &'static str,
    description: &'static str,
}

const WITNESSES: &[WitnessExpectation] = &[
    WitnessExpectation {
        invariant: "IntentCrashBeforeFreezeAbsent",
        description: "intent crash before freeze leaves source authority active",
    },
    WitnessExpectation {
        invariant: "FreezeBeforeCommitAbsent",
        description: "freeze wins before first commit and rejects it atomically",
    },
    WitnessExpectation {
        invariant: "CommitBeforeFreezeAbsent",
        description: "first commit wins before freeze and joins the drain cohort",
    },
    WitnessExpectation {
        invariant: "PredecisionTombstoneBlockedAbsent",
        description: "predecision retained tombstone blocks ownership commit",
    },
    WitnessExpectation {
        invariant: "TypedAbortRequiredAbsent",
        description: "untyped abort rejects before the typed abort thaws source",
    },
    WitnessExpectation {
        invariant: "CommitAckLossReplayAbsent",
        description: "lost commit acknowledgement replays one decision",
    },
    WitnessExpectation {
        invariant: "SourceCrashStaleBindingAbsent",
        description: "source crash rejects the old binding while decision is unknown",
    },
    WitnessExpectation {
        invariant: "DuplicateCommitCloseAbsent",
        description: "duplicate commit-close replays one closure",
    },
    WitnessExpectation {
        invariant: "ConflictingDecisionRejectedAbsent",
        description: "conflicting abort after commit rejects without mutation",
    },
    WitnessExpectation {
        invariant: "PostcommitRetainedRecoveryAbsent",
        description: "postcommit retained effect blocks activation without ownership rollback",
    },
];

const SEQUENCE_TESTS: &[&str] = &[
    "intent_crash_before_freeze_leaves_source_active",
    "freeze_before_first_commit_rejects_commit_atomically",
    "first_commit_before_freeze_is_classified_for_drain",
    "predecision_tombstone_blocks_ownership_commit",
    "typed_abort_receipt_is_required_to_thaw",
    "lost_commit_ack_replays_the_same_decision",
    "source_crash_rejects_old_binding_while_frozen",
    "duplicate_commit_close_returns_the_same_closure",
    "conflicting_abort_after_commit_is_rejected_atomically",
    "postcommit_retained_effect_blocks_activation_without_rollback",
];

const PROPERTY_TESTS: &[&str] = &[
    "decision_identity_substitutions_reject_without_mutation",
    "arbitrary_pre_freeze_effect_population_preserves_all_invariants",
    "exact_commit_replay_never_advances_authority_twice",
];

const LOOM_TESTS: &[&str] = &[
    "freeze_and_first_commit_have_one_serialized_winner",
    "abort_and_commit_decisions_cannot_both_win",
    "duplicate_close_replays_one_receipt",
];

const SUBSTRATE_LOOM_TESTS: &[&str] = &[
    "freeze_and_source_mutation_have_one_outer_lock_winner",
    "abort_and_commit_cannot_both_win",
];

const PRODUCTION_REGISTRY_TESTS: &[&str] = &[
    "production_freeze_abort_ack_and_thaw_reopen_exact_admission",
    "ordinary_revoke_remains_valid_after_an_aborted_handoff",
    "abort_thaw_preserves_the_same_precommit_effect",
    "partial_abort_returns_publication_tickets_until_committed_children_drain",
    "partial_abort_returns_prior_ticket_before_a_later_terminal_overflow",
    "production_commit_reuses_irreversible_revoke_and_mints_one_closure",
    "empty_handoff_close_preflights_terminal_revision_before_commit",
    "frozen_source_crash_preserves_cohort_and_abort_requires_recovery",
    "ownership_decision_cannot_replay_across_registry_or_cohort_identity",
    "precommit_device_roots_reject_freeze_without_mutation",
    "retained_tombstones_block_or_delay_but_never_fabricate_closure",
];

#[derive(Clone, Copy)]
struct CellExpectation {
    id: &'static str,
    events: &'static [&'static str],
    expected: &'static str,
    witness: &'static str,
    rust_test: &'static str,
    kill_condition: &'static str,
}

const CELLS: &[CellExpectation] = &[
    CellExpectation {
        id: "intent-crash-before-freeze",
        events: &["PrepareIntent", "CoordinatorCrash", "RecoverIntent"],
        expected: "source remains active because no local freeze linearized",
        witness: "IntentCrashBeforeFreezeAbsent",
        rust_test: "intent_crash_before_freeze_leaves_source_active",
        kill_condition: "intent alone freezes or fences source execution",
    },
    CellExpectation {
        id: "freeze-before-first-commit",
        events: &["PrepareIntent", "FreezeAdmission", "FirstCommitProbe"],
        expected: "first commit rejects without cohort or effect mutation",
        witness: "FreezeBeforeCommitAbsent",
        rust_test: "freeze_before_first_commit_rejects_commit_atomically",
        kill_condition: "an uncommitted effect crosses commit after freeze",
    },
    CellExpectation {
        id: "first-commit-before-freeze",
        events: &["PrepareIntent", "FirstCommit", "FreezeAdmission"],
        expected: "the committed effect is classified in the frozen cohort and may drain",
        witness: "CommitBeforeFreezeAbsent",
        rust_test: "first_commit_before_freeze_is_classified_for_drain",
        kill_condition: "freeze omits the already committed effect",
    },
    CellExpectation {
        id: "predecision-tombstone-blocks-commit",
        events: &[
            "FirstCommit",
            "Retain",
            "PrepareIntent",
            "FreezeAdmission",
            "CommitProbe",
        ],
        expected: "freeze returns Blocked and ownership commit rejects",
        witness: "PredecisionTombstoneBlockedAbsent",
        rust_test: "predecision_tombstone_blocks_ownership_commit",
        kill_condition: "a retained tombstone is accepted as ReadyToCommit or closure",
    },
    CellExpectation {
        id: "typed-abort-required-to-thaw",
        events: &[
            "PrepareIntent",
            "FreezeAdmission",
            "UntypedAbortProbe",
            "TypedAbort",
        ],
        expected: "only the matching authoritative abort receipt opens the gate",
        witness: "TypedAbortRequiredAbsent",
        rust_test: "typed_abort_receipt_is_required_to_thaw",
        kill_condition: "phase-only or untyped evidence resumes source execution",
    },
    CellExpectation {
        id: "commit-ack-loss-replay",
        events: &[
            "PrepareIntent",
            "FreezeAdmission",
            "AbortUncommitted",
            "CommitDecision",
            "LoseAck",
            "CommitReplay",
        ],
        expected: "the exact commit receipt replays one decision and one close progress",
        witness: "CommitAckLossReplayAbsent",
        rust_test: "lost_commit_ack_replays_the_same_decision",
        kill_condition: "retry advances authority twice or creates a second close operation",
    },
    CellExpectation {
        id: "source-crash-stale-binding",
        events: &[
            "PrepareIntent",
            "FreezeAdmission",
            "SourceCrash",
            "OldBindingReplyProbe",
        ],
        expected: "old binding publication rejects and the unknown decision remains frozen",
        witness: "SourceCrashStaleBindingAbsent",
        rust_test: "source_crash_rejects_old_binding_while_frozen",
        kill_condition: "old binding consumes or publishes a frozen completion",
    },
    CellExpectation {
        id: "duplicate-commit-close",
        events: &[
            "PrepareIntent",
            "FreezeAdmission",
            "AbortUncommitted",
            "CommitDecision",
            "Drain",
            "PublicationAck",
            "CommitClose",
            "CommitCloseReplay",
        ],
        expected: "the replay returns the identical closure receipt without republication",
        witness: "DuplicateCommitCloseAbsent",
        rust_test: "duplicate_commit_close_returns_the_same_closure",
        kill_condition: "replay publishes, terminalizes, or advances closure twice",
    },
    CellExpectation {
        id: "conflicting-abort-commit-decisions",
        events: &[
            "PrepareIntent",
            "FreezeAdmission",
            "AbortUncommitted",
            "CommitDecision",
            "AbortProbe",
        ],
        expected: "the later conflicting decision rejects without state mutation",
        witness: "ConflictingDecisionRejectedAbsent",
        rust_test: "conflicting_abort_after_commit_is_rejected_atomically",
        kill_condition: "both decisions become authoritative for one freeze generation",
    },
    CellExpectation {
        id: "postcommit-retained-blocks-activation",
        events: &[
            "FirstCommit",
            "PrepareIntent",
            "FreezeAdmission",
            "CommitDecision",
            "Retain",
            "ActivationProbe",
        ],
        expected: "ownership remains committed, closure is Retained, and activation is unauthorized",
        witness: "PostcommitRetainedRecoveryAbsent",
        rust_test: "postcommit_retained_effect_blocks_activation_without_rollback",
        kill_condition: "retained state rolls ownership back or authorizes destination activation",
    },
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultMatrix {
    schema: String,
    profile: String,
    expected_count: usize,
    fault_model: String,
    ownership_log: String,
    host_reboot_claimed: bool,
    malicious_rollback_claimed: bool,
    production_registry_modified: bool,
    required_invariants: Vec<String>,
    negative_mutations: Vec<String>,
    cell: Vec<FaultCell>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultCell {
    id: String,
    event_order: Vec<String>,
    expected: String,
    tla_witness: String,
    rust_test: String,
    kill_condition: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ConfigurationReceipt {
    config: String,
    status: String,
    generated: u64,
    distinct: u64,
    depth: u64,
    states_left_on_queue: u64,
    property_mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct WitnessReceipt {
    invariant: String,
    description: String,
    status: String,
}

#[derive(Serialize)]
struct FaultContractReceipt {
    matrix: &'static str,
    matrix_sha256: String,
    cells: usize,
    invariants: usize,
    negative_mutations: usize,
    fault_model: &'static str,
    ownership_log_tcb: &'static str,
}

#[derive(Serialize)]
struct FormalReceipt {
    specification: &'static str,
    declarative_tla: bool,
    complete_configurations: usize,
    configurations: Vec<ConfigurationReceipt>,
    reachability_witnesses: usize,
    witnesses: Vec<WitnessReceipt>,
    temporal_properties: usize,
}

#[derive(Serialize)]
struct RustOracleReceipt {
    independent_from_production_registry: bool,
    sequence_tests: usize,
    property_tests: usize,
    loom_tests: usize,
    total_tests: usize,
}

#[derive(Serialize)]
struct ProductionRegistryReceipt {
    registry_source: &'static str,
    substrate_source: &'static str,
    handoff_index_owned_by_registry: bool,
    admission_and_publication_share_registry_lock: bool,
    commit_close_reuses_revoke_lifecycle: bool,
    sequence_tests: usize,
    loom_tests: usize,
    total_tests: usize,
    local_fault_cells_mapped: usize,
    external_intent_only_cells: usize,
    real_ostd_execution_claimed: bool,
}

#[derive(Serialize)]
struct Boundaries {
    same_boot_only: bool,
    crash_stop_only: bool,
    ownership_log_non_equivocation_in_tcb: bool,
    host_reboot_claimed: bool,
    malicious_rollback_claimed: bool,
    cryptographic_freshness_claimed: bool,
    production_registry_modified: bool,
    production_registry_refinement_checked: bool,
    joint_visa_execution_claimed: bool,
    real_ostd_smp_claimed: bool,
    canonical_v0_1_catalog_modified: bool,
}

#[derive(Serialize)]
struct Logs {
    tla: &'static str,
    rust_oracle: &'static str,
    summary: &'static str,
}

#[derive(Serialize)]
struct Digests {
    tla_sha256: String,
    rust_oracle_sha256: String,
    summary_sha256: String,
}

#[derive(Serialize)]
struct Receipt {
    schema: &'static str,
    status: &'static str,
    prospective: bool,
    command: &'static str,
    revision: String,
    worktree_dirty: bool,
    source_fingerprint: String,
    source_files: Vec<String>,
    generated_unix_seconds: u64,
    fault_contract: FaultContractReceipt,
    formal: FormalReceipt,
    rust_oracle: RustOracleReceipt,
    production_registry: ProductionRegistryReceipt,
    boundaries: Boundaries,
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

pub(crate) fn run(root: &Path, release_specs: &[&str]) -> Result<()> {
    super::production_identity::validate_release_boundary(release_specs)?;
    if release_specs.contains(&SPEC) {
        return Err("HandoffAdmissionCser must remain outside the accepted v0.1.0 catalog".into());
    }
    let matrix = validate_fault_matrix(root)?;
    let output = root.join(OUTPUT_DIRECTORY);
    fs::create_dir_all(&output)?;
    let _lock = super::SpecRunLock::acquire(&output.join(".handoff-admission.lock"))?;
    clear_previous_outputs(root)?;

    let revision_before = git_text(root, &["rev-parse", "HEAD"])?;
    let source_before = fingerprint_paths(root, SOURCE_FILES)?;
    run_tla(root)?;
    let formal = validate_tla_log(&fs::read_to_string(root.join(TLA_LOG))?)?;
    run_rust_oracle(root)?;
    validate_rust_log(&fs::read_to_string(root.join(RUST_LOG))?)?;

    let revision_after = git_text(root, &["rev-parse", "HEAD"])?;
    let source_after = fingerprint_paths(root, SOURCE_FILES)?;
    if revision_before != revision_after || source_before != source_after {
        return Err(format!(
            "handoff-admission sources changed during verification: revision {revision_before}->{revision_after}, fingerprint {source_before}->{source_after}"
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

    let matrix_sha256 = sha256_file(&root.join(MATRIX_PATH))?;
    let receipt = Receipt {
        schema: SCHEMA,
        status: "passed",
        prospective: true,
        command: COMMAND,
        revision: revision_after,
        worktree_dirty,
        source_fingerprint: source_after,
        source_files: SOURCE_FILES.iter().map(|path| (*path).into()).collect(),
        generated_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        fault_contract: FaultContractReceipt {
            matrix: MATRIX_PATH,
            matrix_sha256,
            cells: matrix.cell.len(),
            invariants: matrix.required_invariants.len(),
            negative_mutations: matrix.negative_mutations.len(),
            fault_model: "same-boot-crash-stop-retry-reorder-lost-ack",
            ownership_log_tcb: "trusted-non-equivocating-no-rollback-tcb",
        },
        formal,
        rust_oracle: RustOracleReceipt {
            independent_from_production_registry: true,
            sequence_tests: SEQUENCE_TESTS.len(),
            property_tests: PROPERTY_TESTS.len(),
            loom_tests: LOOM_TESTS.len(),
            total_tests: SEQUENCE_TESTS.len() + PROPERTY_TESTS.len() + LOOM_TESTS.len(),
        },
        production_registry: ProductionRegistryReceipt {
            registry_source: PRODUCTION_REGISTRY,
            substrate_source: "crates/cser-transition-gates/src/handoff.rs",
            handoff_index_owned_by_registry: true,
            admission_and_publication_share_registry_lock: true,
            commit_close_reuses_revoke_lifecycle: true,
            sequence_tests: PRODUCTION_REGISTRY_TESTS.len(),
            loom_tests: SUBSTRATE_LOOM_TESTS.len(),
            total_tests: PRODUCTION_REGISTRY_TESTS.len() + SUBSTRATE_LOOM_TESTS.len(),
            local_fault_cells_mapped: 9,
            external_intent_only_cells: 1,
            real_ostd_execution_claimed: false,
        },
        boundaries: Boundaries {
            same_boot_only: true,
            crash_stop_only: true,
            ownership_log_non_equivocation_in_tcb: true,
            host_reboot_claimed: false,
            malicious_rollback_claimed: false,
            cryptographic_freshness_claimed: false,
            production_registry_modified: true,
            production_registry_refinement_checked: true,
            joint_visa_execution_claimed: false,
            real_ostd_smp_claimed: false,
            canonical_v0_1_catalog_modified: false,
        },
        logs: Logs {
            tla: TLA_LOG,
            rust_oracle: RUST_LOG,
            summary: SUMMARY_PATH,
        },
        digests: Digests {
            tla_sha256: sha256_file(&root.join(TLA_LOG))?,
            rust_oracle_sha256: sha256_file(&root.join(RUST_LOG))?,
            summary_sha256: sha256_file(&root.join(SUMMARY_PATH))?,
        },
    };
    let mut json = serde_json::to_vec_pretty(&receipt)?;
    json.push(b'\n');
    atomic_write(&root.join(RECEIPT_PATH), &json)?;

    println!(
        "HANDOFF ADMISSION RESEARCH PASS configurations={} witnesses={} rust_tests={} production_tests={} cells={} receipt={}",
        CONFIGURATIONS.len(),
        WITNESSES.len(),
        SEQUENCE_TESTS.len() + PROPERTY_TESTS.len() + LOOM_TESTS.len(),
        PRODUCTION_REGISTRY_TESTS.len() + SUBSTRATE_LOOM_TESTS.len(),
        CELLS.len(),
        RECEIPT_PATH
    );
    println!(
        "same_boot_only=true ownership_log_non_equivocation_in_tcb=true production_registry_modified=true production_registry_refinement_checked=true host_reboot_claimed=false malicious_rollback_claimed=false"
    );
    Ok(())
}

fn validate_fault_matrix(root: &Path) -> Result<FaultMatrix> {
    let path = root.join(MATRIX_PATH);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(
            format!("fault matrix must be a regular non-symlink file: {MATRIX_PATH}").into(),
        );
    }
    let matrix: FaultMatrix = toml::from_str(&fs::read_to_string(path)?)?;
    validate_fault_matrix_contract(&matrix)?;
    Ok(matrix)
}

fn validate_fault_matrix_contract(matrix: &FaultMatrix) -> Result<()> {
    if matrix.schema != "nexus.research.handoff-admission.fault-matrix.v1"
        || matrix.profile != "docs/rfcs/0002-handoff-admission-profile.md"
        || matrix.expected_count != CELLS.len()
        || matrix.fault_model != "same-boot-crash-stop-retry-reorder-lost-ack"
        || matrix.ownership_log != "trusted-non-equivocating-no-rollback-tcb"
        || matrix.host_reboot_claimed
        || matrix.malicious_rollback_claimed
        || matrix.production_registry_modified
    {
        return Err("handoff-admission fault matrix changed its first-round boundary".into());
    }
    if matrix.required_invariants != string_vec(REQUIRED_INVARIANTS)
        || matrix.negative_mutations != string_vec(NEGATIVE_MUTATIONS)
        || matrix.cell.len() != CELLS.len()
    {
        return Err("handoff-admission fault matrix population or order differs".into());
    }
    for (actual, expected) in matrix.cell.iter().zip(CELLS) {
        if actual.id != expected.id
            || actual.event_order != string_vec(expected.events)
            || actual.expected != expected.expected
            || actual.tla_witness != expected.witness
            || actual.rust_test != expected.rust_test
            || actual.kill_condition != expected.kill_condition
        {
            return Err(format!(
                "handoff-admission fault cell differs from the frozen contract: expected {}, got {}",
                expected.id, actual.id
            )
            .into());
        }
    }
    let matrix_witnesses: Vec<_> = matrix
        .cell
        .iter()
        .map(|cell| cell.tla_witness.as_str())
        .collect();
    let expected_witnesses: Vec<_> = WITNESSES.iter().map(|item| item.invariant).collect();
    let matrix_tests: Vec<_> = matrix
        .cell
        .iter()
        .map(|cell| cell.rust_test.as_str())
        .collect();
    if matrix_witnesses != expected_witnesses || matrix_tests != SEQUENCE_TESTS {
        return Err("fault matrix does not map one-to-one to witnesses and sequence tests".into());
    }
    Ok(())
}

fn run_tla(root: &Path) -> Result<()> {
    let jar = super::tla2tools_jar()?;
    let source_cser_dir = root.join("specs/cser");
    let workspace = super::IsolatedSpecWorkspace::create(&source_cser_dir)?;
    super::section("run prospective HandoffAdmissionCser first-round gate");
    let mut command = Command::new("sh");
    command
        .current_dir(workspace.cser_dir())
        .env("TLA2TOOLS_JAR", &jar)
        .env("TMPDIR", workspace.temp_dir())
        .arg(workspace.cser_dir().join("check.sh"))
        .arg(SPEC);
    super::run_bounded_logged_quiet(
        &mut command,
        &root.join(TLA_LOG),
        Duration::from_secs(300),
        16 * 1024 * 1024,
    )
}

fn run_rust_oracle(root: &Path) -> Result<()> {
    super::section("run independent handoff-admission safe-Rust oracle");
    let script = r#"
set -eu
echo '==> handoff-admission sequence oracle'
cargo test --locked -p cser-model --test handoff_admission_sequences
echo '==> handoff-admission property oracle'
cargo test --locked -p cser-model --test handoff_admission_properties
echo '==> handoff-admission Loom oracle'
cargo test --locked -p cser-model --test handoff_admission_loom
echo '==> handoff-admission substrate Loom refinement'
cargo test --locked -p cser-transition-gates --test handoff_loom
echo '==> handoff-admission production Registry refinement'
cargo test --locked -p cser-transition-gates --test production_handoff_registry
"#;
    let mut command = Command::new("sh");
    command.current_dir(root).arg("-c").arg(script);
    super::run_bounded_logged_quiet(
        &mut command,
        &root.join(RUST_LOG),
        Duration::from_secs(300),
        8 * 1024 * 1024,
    )
}

fn validate_tla_log(log: &str) -> Result<FormalReceipt> {
    let lines: Vec<_> = log.lines().collect();
    let mut expected_headings = vec![format!("==> {}", CONFIGURATIONS[0].heading)];
    expected_headings.extend(
        WITNESSES
            .iter()
            .map(|witness| format!("==> {SPEC} reachability: {}", witness.description)),
    );
    expected_headings.push(format!("==> {}", CONFIGURATIONS[1].heading));
    let actual_headings: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("==> HandoffAdmissionCser "))
        .map(|line| (*line).to_owned())
        .collect();
    if actual_headings != expected_headings {
        return Err(format!(
            "HandoffAdmissionCser section order differs: expected {expected_headings:?}, got {actual_headings:?}"
        )
        .into());
    }

    let completion_marker = "Model checking completed. No error has been found.";
    if lines
        .iter()
        .filter(|line| **line == completion_marker)
        .count()
        != CONFIGURATIONS.len()
    {
        return Err("HandoffAdmissionCser lacks two complete graph markers".into());
    }
    let coverage: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("COVERAGE_RESULT "))
        .map(|line| (*line).to_owned())
        .collect();
    let expected_coverage: Vec<_> = WITNESSES
        .iter()
        .map(|witness| format!("COVERAGE_RESULT PASS {}", witness.description))
        .collect();
    if coverage != expected_coverage {
        return Err("HandoffAdmissionCser witness population or order differs".into());
    }
    for witness in WITNESSES {
        let marker = format!("Invariant {} is violated", witness.invariant);
        if lines.iter().filter(|line| line.contains(&marker)).count() != 1 {
            return Err(format!("witness {} lacks one exact violation", witness.invariant).into());
        }
    }

    let starts: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            **line == format!("==> {}", CONFIGURATIONS[0].heading)
                || **line == format!("==> {}", CONFIGURATIONS[1].heading)
        })
        .map(|(index, _)| index)
        .collect();
    if starts.len() != CONFIGURATIONS.len() {
        return Err("HandoffAdmissionCser configuration sections are missing".into());
    }
    let first_end = lines
        .iter()
        .position(|line| line.starts_with("==> HandoffAdmissionCser reachability:"))
        .ok_or("HandoffAdmissionCser witness section is missing")?;
    let blocks = [&lines[starts[0]..first_end], &lines[starts[1]..]];
    let mut configurations = Vec::new();
    for (expected, block) in CONFIGURATIONS.iter().zip(blocks) {
        let stats = graph_stats(block)?;
        let required = GraphStats {
            generated: expected.generated,
            distinct: expected.distinct,
            left_on_queue: 0,
            depth: expected.depth,
        };
        if stats != required {
            return Err(format!(
                "{} graph population differs: expected {required:?}, got {stats:?}",
                expected.config
            )
            .into());
        }
        if let Some(branches) = expected.temporal_branches {
            let marker = format!(
                "Implied-temporal checking--satisfiability problem has {branches} branches."
            );
            if block.iter().filter(|line| **line == marker).count() != 1 {
                return Err(format!("{} lacks the exact temporal marker", expected.config).into());
            }
        }
        configurations.push(ConfigurationReceipt {
            config: expected.config.into(),
            status: "complete".into(),
            generated: expected.generated,
            distinct: expected.distinct,
            depth: expected.depth,
            states_left_on_queue: 0,
            property_mode: expected.property_mode.into(),
        });
    }

    Ok(FormalReceipt {
        specification: SPEC,
        declarative_tla: true,
        complete_configurations: CONFIGURATIONS.len(),
        configurations,
        reachability_witnesses: WITNESSES.len(),
        witnesses: WITNESSES
            .iter()
            .map(|witness| WitnessReceipt {
                invariant: witness.invariant.into(),
                description: witness.description.into(),
                status: "reachable".into(),
            })
            .collect(),
        temporal_properties: 2,
    })
}

fn graph_stats(block: &[&str]) -> Result<GraphStats> {
    let populations: Vec<_> = block
        .iter()
        .filter(|line| {
            line.as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_digit())
                && line.contains(" states generated, ")
                && line.contains(" states left on queue.")
        })
        .collect();
    let depths: Vec<_> = block
        .iter()
        .filter(|line| line.starts_with("The depth of the complete state graph search is "))
        .collect();
    if populations.len() != 1 || depths.len() != 1 {
        return Err("TLC configuration lacks one final population and depth".into());
    }
    let (generated, remainder) = populations[0]
        .split_once(" states generated, ")
        .ok_or("malformed generated states")?;
    let (distinct, remainder) = remainder
        .split_once(" distinct states found, ")
        .ok_or("malformed distinct states")?;
    let left = remainder
        .strip_suffix(" states left on queue.")
        .ok_or("malformed queued states")?;
    let depth = depths[0]
        .strip_prefix("The depth of the complete state graph search is ")
        .and_then(|value| value.strip_suffix('.'))
        .ok_or("malformed graph depth")?;
    Ok(GraphStats {
        generated: parse_u64(generated)?,
        distinct: parse_u64(distinct)?,
        left_on_queue: parse_u64(left)?,
        depth: parse_u64(depth)?,
    })
}

fn validate_rust_log(log: &str) -> Result<()> {
    let suites = [
        ("==> handoff-admission sequence oracle", SEQUENCE_TESTS),
        ("==> handoff-admission property oracle", PROPERTY_TESTS),
        ("==> handoff-admission Loom oracle", LOOM_TESTS),
        (
            "==> handoff-admission substrate Loom refinement",
            SUBSTRATE_LOOM_TESTS,
        ),
        (
            "==> handoff-admission production Registry refinement",
            PRODUCTION_REGISTRY_TESTS,
        ),
    ];
    let lines: Vec<_> = log.lines().collect();
    let headings: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("==> handoff-admission "))
        .map(|(index, line)| (index, *line))
        .collect();
    if headings.iter().map(|(_, line)| *line).collect::<Vec<_>>()
        != suites
            .iter()
            .map(|(heading, _)| *heading)
            .collect::<Vec<_>>()
    {
        return Err("handoff-admission Rust suite population or order differs".into());
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
            return Err(
                format!("Rust oracle suite lacks exact pass count: {}", tests.len()).into(),
            );
        }
    }
    Ok(())
}

fn summary_text(revision: &str, source_fingerprint: &str, worktree_dirty: bool) -> String {
    format!(
        "schema={SUMMARY_SCHEMA}\nstatus=passed\nprospective=true\ncommand={COMMAND}\nrevision={revision}\nworktree_dirty={worktree_dirty}\nsource_fingerprint={source_fingerprint}\nfault_cells={}\nrequired_invariants={}\nnegative_mutations={}\ncomplete_configurations={}\nreachability_witnesses={}\ntemporal_properties=2\nrust_sequence_tests={}\nrust_property_tests={}\nrust_loom_tests={}\nproduction_registry_sequence_tests={}\nproduction_registry_loom_tests={}\nsame_boot_only=true\nownership_log_non_equivocation_in_tcb=true\nproduction_registry_modified=true\nproduction_registry_refinement_checked=true\nhost_reboot_claimed=false\nmalicious_rollback_claimed=false\njoint_visa_execution_claimed=false\nreal_ostd_smp_claimed=false\ncanonical_v0_1_catalog_modified=false\nreceipt={RECEIPT_PATH}\n",
        CELLS.len(),
        REQUIRED_INVARIANTS.len(),
        NEGATIVE_MUTATIONS.len(),
        CONFIGURATIONS.len(),
        WITNESSES.len(),
        SEQUENCE_TESTS.len(),
        PROPERTY_TESTS.len(),
        LOOM_TESTS.len(),
        PRODUCTION_REGISTRY_TESTS.len(),
        SUBSTRATE_LOOM_TESTS.len(),
    )
}

fn clear_previous_outputs(root: &Path) -> Result<()> {
    for relative in [TLA_LOG, RUST_LOG, SUMMARY_PATH, RECEIPT_PATH] {
        match fs::remove_file(root.join(relative)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove stale {relative}: {error}").into()),
        }
    }
    Ok(())
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
            return Err(format!("source fingerprint path escapes repository: {relative}").into());
        }
        let absolute = root.join(path);
        let metadata = fs::symlink_metadata(&absolute)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!("source fingerprint input is not regular: {relative}").into());
        }
        let first = fs::read(&absolute)?;
        let second = fs::read(&absolute)?;
        if first != second {
            return Err(format!("source changed while fingerprinting: {relative}").into());
        }
        digest.update((relative.len() as u64).to_le_bytes());
        digest.update(relative.as_bytes());
        digest.update((first.len() as u64).to_le_bytes());
        digest.update(first);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git_bytes(root, args)?)?.trim().into())
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git").current_dir(root).args(args).output()?;
    if !output.status.success() {
        return Err(format!("git {} failed with {}", args.join(" "), output.status).into());
    }
    Ok(output.stdout)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("artifact path has no parent")?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("artifact path has no UTF-8 file name")?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    fs::write(&temporary, bytes)?;
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(temporary);
            Err(error.into())
        }
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

fn parse_u64(value: &str) -> Result<u64> {
    Ok(value.replace(',', "").parse()?)
}

fn string_vec(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
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

    #[test]
    fn checked_in_fault_matrix_matches_every_witness_and_sequence_test() {
        let matrix = validate_fault_matrix(&root()).expect("valid fault matrix");
        assert_eq!(matrix.cell.len(), 10);
        assert_eq!(matrix.required_invariants.len(), 10);
        assert_eq!(matrix.negative_mutations.len(), 11);
    }

    #[test]
    fn reordered_or_weakened_fault_matrix_rejects() {
        let mut matrix = validate_fault_matrix(&root()).expect("valid fault matrix");
        matrix.cell.swap(0, 1);
        assert!(validate_fault_matrix_contract(&matrix).is_err());

        let mut matrix = validate_fault_matrix(&root()).expect("valid fault matrix");
        matrix.host_reboot_claimed = true;
        assert!(validate_fault_matrix_contract(&matrix).is_err());
    }
}
