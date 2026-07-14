use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

const CONTRACT_PATH: &str = "evaluation/stage7b/contract.toml";
const RACE_MAP_PATH: &str = "evaluation/stage7b/cser-races.toml";
const REGISTRY_SOURCE_PATH: &str = "kernel/nexus-ostd/src/cser/effect_registry.rs";
const EVALUATOR_SOURCE_PATH: &str = "kernel/nexus-ostd/src/evaluation/stage7b.rs";
const ONESHOT_GATE_SOURCE_PATH: &str = "crates/cser-transition-gates/src/oneshot.rs";
const EFFECT_WAKER_SOURCE_PATH: &str = "kernel/nexus-ostd/src/cser/effect.rs";
const IO_GATE_SOURCE_PATH: &str = "crates/cser-transition-gates/src/io.rs";
const IO_PORTAL_SOURCE_PATH: &str = "crates/nexus-ostd-virtio/src/portal.rs";
const IO_ENTRY_SOURCE_PATH: &str = "experiments/ostd-virtio-cser-spike/src/lib.rs";

const RACE_IDS: &[&str] = &[
    "wait.wake-vs-timeout-single-winner",
    "wait.cancel-vs-wake-single-winner",
    "wait.stale-deadline-after-rearm",
    "pager.same-page-single-publication",
    "pager.handler-crash-before-resolution",
    "pager.old-binding-reply-after-rebind",
    "pager.adopt-vs-abort-single-winner",
    "continuation.resolve-vs-abort-one-shot",
    "scope.commit-vs-revoke-linearization",
    "scope.revoke-deferred-wait-timer",
    "budget.commit-vs-abort-conservation",
    "scheduler.fallback-before-rebind",
    "io.publish-vs-revoke-commit-gate",
    "io.timeout-vs-late-completion-tombstone",
];

const PRODUCTION_SOURCES: &[&str] = &[
    "crates/cser-transition-gates/src/oneshot.rs",
    "crates/cser-transition-gates/src/deadline.rs",
    "crates/cser-transition-gates/src/scheduler.rs",
    "crates/cser-transition-gates/src/pager.rs",
    "crates/cser-transition-gates/src/io.rs",
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
];

const HARNESSES: &[&str] = &[
    "crates/cser-transition-gates/tests/oneshot_loom.rs",
    "crates/cser-transition-gates/tests/deadline_loom.rs",
    "crates/cser-transition-gates/tests/scheduler_loom.rs",
    "crates/cser-transition-gates/tests/pager_loom.rs",
    "crates/cser-transition-gates/tests/io_loom.rs",
    "crates/cser-transition-gates/tests/registry_loom.rs",
];

const FAULT_FAMILIES: &[&str] = &["scheduler", "pager", "personality-readiness", "linux-io"];

const FAULT_CELL_IDS: &[&str] = &[
    "scheduler.lease-expiry-before-proposal",
    "scheduler.crash-after-proposal-before-pick",
    "scheduler.stale-proposal-before-rebind",
    "scheduler.stale-proposal-after-rebind",
    "scheduler.repeated-crash-fallback-progress",
    "pager.same-page-concurrent-fault",
    "pager.crash-before-prepare",
    "pager.crash-after-prepare-before-commit",
    "pager.crash-after-commit-before-resume",
    "pager.timeout-vs-late-reply",
    "personality-readiness.crash-before-backend-commit",
    "personality-readiness.crash-after-backend-commit",
    "personality-readiness.ready-vs-timeout",
    "personality-readiness.revoke-vs-ready",
    "personality-readiness.stale-deadline-after-rearm",
    "linux-io.revoke-before-device-publication",
    "linux-io.completion-vs-reset-ack",
    "linux-io.reset-timeout-retry",
    "linux-io.iotlb-timeout-late-ack",
    "linux-io.stale-duplicate-completion",
];

const SCALE_POINTS: &[(&str, u64, u64, u64)] = &[
    ("fixed-n.k0000", 1024, 0, 0),
    ("fixed-n.k0001", 1024, 1, 0),
    ("fixed-n.k0008", 1024, 8, 0),
    ("fixed-n.k0032", 1024, 32, 0),
    ("fixed-n.k0128", 1024, 128, 0),
    ("fixed-n.k0512", 1024, 512, 0),
    ("fixed-k.n0032", 32, 32, 0),
    ("fixed-k.n0128", 128, 32, 0),
    ("fixed-k.n0512", 512, 32, 0),
    ("fixed-k.n2048", 2048, 32, 0),
    ("fixed-k.n4096", 4096, 32, 0),
    ("history.h0000", 1024, 32, 0),
    ("history.h0064", 1024, 32, 64),
    ("history.h1024", 1024, 32, 1024),
];

const PERFORMANCE_CASES: &[(&str, &str, &str)] = &[
    ("begin.fixed-n.k0000", "begin", "fixed-n.k0000"),
    ("begin.fixed-n.k0001", "begin", "fixed-n.k0001"),
    ("begin.fixed-n.k0008", "begin", "fixed-n.k0008"),
    ("begin.fixed-n.k0032", "begin", "fixed-n.k0032"),
    ("begin.fixed-n.k0128", "begin", "fixed-n.k0128"),
    ("begin.fixed-n.k0512", "begin", "fixed-n.k0512"),
    ("complete.fixed-n.k0000", "complete", "fixed-n.k0000"),
    ("complete.fixed-n.k0001", "complete", "fixed-n.k0001"),
    ("complete.fixed-n.k0008", "complete", "fixed-n.k0008"),
    ("complete.fixed-n.k0032", "complete", "fixed-n.k0032"),
    ("complete.fixed-n.k0128", "complete", "fixed-n.k0128"),
    ("complete.fixed-n.k0512", "complete", "fixed-n.k0512"),
    ("closure.fixed-n.k0000", "closure", "fixed-n.k0000"),
    ("closure.fixed-n.k0001", "closure", "fixed-n.k0001"),
    ("closure.fixed-n.k0008", "closure", "fixed-n.k0008"),
    ("closure.fixed-n.k0032", "closure", "fixed-n.k0032"),
    ("closure.fixed-n.k0128", "closure", "fixed-n.k0128"),
    ("closure.fixed-n.k0512", "closure", "fixed-n.k0512"),
    ("closure.fixed-k.n0032", "closure", "fixed-k.n0032"),
    ("closure.fixed-k.n0128", "closure", "fixed-k.n0128"),
    ("closure.fixed-k.n0512", "closure", "fixed-k.n0512"),
    ("closure.fixed-k.n2048", "closure", "fixed-k.n2048"),
    ("closure.fixed-k.n4096", "closure", "fixed-k.n4096"),
    ("closure.history.h0000", "closure", "history.h0000"),
    ("closure.history.h0064", "closure", "history.h0064"),
    ("closure.history.h1024", "closure", "history.h1024"),
    ("projection.history.h0000", "projection", "history.h0000"),
    ("projection.history.h0064", "projection", "history.h0064"),
    ("projection.history.h1024", "projection", "history.h1024"),
];

const PRIOR_ART_IDS: &[&str] = &[
    "sel4.reply-capability-revoke",
    "cornucopia.async-authority",
    "portico-lingering-authority",
    "vino.extension-fallback",
    "curios.restartable-services",
    "shadow-drivers.device-recovery",
    "txos.os-transactions",
    "speculator.causal-dependencies",
    "rethink-the-sync.causal-dependencies",
    "chubby.fencing",
    "rifl.exactly-once-rpc",
    "atomic-rpc",
    "resource-containers",
    "fuchsia.rfc-0261",
    "linux.io-uring-cancel",
    "virtio-1.3-reset",
];

const CONCURRENCY_CLAIMS: &[&str] = &[
    "OSTD SpinLock verified",
    "SMP verified",
    "lock-free",
    "production liveness proved",
];

const CONCURRENCY_MUTATIONS: &[&str] = &[
    "drop-race",
    "duplicate-race",
    "unknown-race",
    "reorder-race",
    "model-only-source",
    "missing-production-source",
    "source-symlink",
    "missing-harness",
    "unknown-fault-cell",
    "drop-fault-mapping",
    "drop-assertion-marker",
    "duplicate-assertion-marker",
    "unknown-assertion-marker",
    "reorder-assertion-marker",
    "copyable-io-gate-instance",
    "forgeable-io-identity",
    "unbound-io-receipt-instance",
    "unbound-session-device-instance",
    "drop-pre-pci-session-negative-call",
    "move-session-negative-after-pci-discovery",
    "conditionally-skip-pre-pci-session-negative",
    "fabricate-pre-pci-session-marker",
    "drop-session-device-validity",
    "drop-session-bidirectional-negative",
    "move-session-receipt-before-assertions",
    "alias-copyable-session-receipt",
    "decouple-typed-terminal-registry-disposition",
    "decouple-oneshot-receipt-provenance",
    "reconstruct-identical-oneshot-instance",
    "alias-copyable-oneshot-gate",
];

const FAULT_RESULT_FIELDS: &[&str] = &[
    "id",
    "family",
    "injection_point",
    "expected_terminal",
    "observed_terminal",
    "terminalizations",
    "publications",
    "credits_before",
    "credits_after",
    "retained_before_quiescence",
    "final_quiescent",
    "status",
];

const FAULT_MUTATIONS: &[&str] = &[
    "drop-cell",
    "duplicate-cell",
    "unknown-cell",
    "reorder-cell",
    "wrong-family-cardinality",
    "duplicate-terminal-result",
    "mutated-rejected-operation",
    "early-retained-resource-release",
    "expected-copied-to-observed",
    "constant-final-quiescent",
    "population-as-credit",
    "constant-credit-self-report",
    "drop-composite-reserve",
    "drop-composite-commit",
    "drop-composite-terminal-release",
    "replace-composite-binding",
    "reintroduce-detached-credit-sidecar",
    "literal-scheduler-no-credit",
    "detach-io-registry-commit",
    "early-io-credit-release",
    "capacity-as-credit-self-report",
    "drop-scope-ledger-lineage",
    "fault-budget-helper-capacity-self-report",
    "hidden-fault-budget-registry-sidecar",
    "hidden-cloned-fault-budget-registry-sidecar",
    "drop-fault-budget-instance-validation",
    "unauthenticated-causal-commit-receipt",
];

const SCALE_METRICS: &[&str] = &[
    "target_count",
    "begin_target_record_visits",
    "next_calls",
    "head_selections",
    "terminalized",
    "completion_members_checked",
    "target_index_removals",
    "unrelated_effect_visits",
    "history_effect_visits",
    "final_target_state",
];

const SCALE_MUTATIONS: &[&str] = &[
    "drop-point",
    "duplicate-point",
    "unknown-point",
    "reorder-point",
    "parameter-drift",
    "nonzero-unrelated-visits",
    "nonzero-history-visits",
    "hardcoded-zero-work-counter",
    "untracked-begin-record-scan",
    "untracked-global-or-history-scan",
];

const PERFORMANCE_STATISTICS: &[&str] = &["min", "median", "p95", "max"];
const PERFORMANCE_EXCLUDES: &[&str] = &[
    "fixture-construction",
    "clone",
    "full-invariant-scan",
    "json",
    "serial-io",
];
const PERFORMANCE_MUTATIONS: &[&str] = &[
    "drop-case",
    "duplicate-case",
    "reorder-case",
    "unknown-scale-point",
    "operation-drift",
    "sample-count-drift",
    "statistic-recompute-mismatch",
    "fixture-inside-measurement",
];
const PERFORMANCE_OPERATION_DEFINITIONS: &[(&str, &str)] = &[
    ("begin", "measure RevokeBegin only"),
    (
        "complete",
        "pre-terminalize all k target effects, then measure RevokeComplete only",
    ),
    (
        "closure",
        "measure RevokeBegin plus every RevokeNext and terminalization plus RevokeComplete",
    ),
    (
        "projection",
        "measure scope_projection only over the configured retained history",
    ),
];

const PRIOR_ART_FIELDS: &[&str] = &[
    "id",
    "primary_source",
    "source_locator",
    "mechanism",
    "authority_scope",
    "async_effect_tracking",
    "commit_or_linearization_gate",
    "crash_or_rebind_fencing",
    "resource_accounting",
    "device_quiescence",
    "overlap_with_cser",
    "difference_from_fixed_cser_boundary",
    "claim_impact",
];
const PRIOR_ART_MUTATIONS: &[&str] = &[
    "drop-row",
    "duplicate-row",
    "unknown-row",
    "reorder-row",
    "secondary-only-source",
    "missing-claim-impact",
];

const ALLOWED_VERDICTS: &[&str] = &["support-bounded", "narrow", "reject"];
const SUPPORT_REQUIREMENTS: &[&str] = &[
    "race-coverage-14-of-14",
    "all-required-implementation-source-safety-gates-pass",
    "fault-matrix-20-of-20",
    "all-central-fault-safety-cells-pass",
    "scale-structure-14-of-14",
    "performance-protocol-29-of-29",
    "prior-art-16-of-16",
];
const NARROW_REQUIREMENTS: &[&str] = &[
    "failed-or-missing-boundaries-explicitly-excluded",
    "no-failed-central-safety-cell-described-as-supported",
];
const REJECT_CONDITIONS: &[&str] = &[
    "post-revoke-commit-exclusion-counterexample",
    "single-terminalization-counterexample",
    "budget-conservation-counterexample",
    "device-quiescence-counterexample",
];
const CONTRIBUTION_CLAIMS: &[&str] = &["novel", "first", "proved"];
const CONTRIBUTION_MUTATIONS: &[&str] = &[
    "unknown-verdict",
    "support-bounded-with-missing-required-gate",
    "support-bounded-with-failed-central-cell",
    "narrow-with-hidden-exclusion",
    "narrow-with-hidden-shared-fault-scope",
    "narrow-with-hidden-cross-object-atomicity",
    "forbidden-novelty-word",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    schema: String,
    stage: String,
    status: String,
    stop_after: String,
    final_research_narrative: bool,
    inputs: Inputs,
    concurrency: Concurrency,
    fault_matrix: FaultMatrix,
    scale: Scale,
    performance: Performance,
    prior_art: PriorArt,
    contribution: Contribution,
    acceptance: Acceptance,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    semantic_races: String,
    race_evidence_map: String,
    race_count: usize,
    fault_cell_count: usize,
    scale_point_count: usize,
    performance_case_count: usize,
    prior_art_row_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Concurrency {
    required_source_kind: String,
    synchronization_model: String,
    required_race_ids: Vec<String>,
    required_production_sources: Vec<String>,
    required_harnesses: Vec<String>,
    forbid_claims: Vec<String>,
    negative_mutations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultMatrix {
    families: Vec<String>,
    cells_per_family: usize,
    registry_backed_nonzero_credit_cells: usize,
    typed_no_credit_scheduler_witnesses: usize,
    registry_scope_model: String,
    shared_production_scope_claimed: bool,
    cross_object_crash_panic_atomicity_claimed: bool,
    required_cell_ids: Vec<String>,
    required_result_fields: Vec<String>,
    negative_mutations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scale {
    required_metrics: Vec<String>,
    negative_mutations: Vec<String>,
    point: Vec<ScalePoint>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScalePoint {
    id: String,
    n: u64,
    k: u64,
    history: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Performance {
    warmups: usize,
    samples: usize,
    empty_timer_samples: usize,
    statistics: Vec<String>,
    retain_raw_samples: bool,
    clock: String,
    environment: String,
    measurement_excludes: Vec<String>,
    negative_mutations: Vec<String>,
    operation_definitions: OperationDefinitions,
    case: Vec<PerformanceCase>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationDefinitions {
    begin: String,
    complete: String,
    closure: String,
    projection: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PerformanceCase {
    id: String,
    operation: String,
    scale_point: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PriorArt {
    source_policy: String,
    required_row_ids: Vec<String>,
    required_fields: Vec<String>,
    negative_mutations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contribution {
    allowed_verdicts: Vec<String>,
    support_bounded_requires: Vec<String>,
    narrow_requires: Vec<String>,
    reject_if: Vec<String>,
    forbid_claims: Vec<String>,
    negative_mutations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Acceptance {
    requires_clean_source: bool,
    requires_cold_verify: bool,
    requires_exact_pushed_sha_ci: bool,
    requires_quick_ci: bool,
    requires_full_ci: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RaceMap {
    schema: String,
    contract: String,
    semantic_catalog: String,
    expected_count: usize,
    race: Vec<RaceEvidence>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RaceEvidence {
    id: String,
    production_sources: Vec<String>,
    harness: String,
    harness_case: String,
    fault_cells: Vec<String>,
    positive_gate: String,
    negative_gates: Vec<String>,
    assertion_markers: Vec<String>,
}

#[derive(Clone, Copy)]
struct ExpectedRace {
    id: &'static str,
    sources: &'static [&'static str],
    harness: &'static str,
    harness_case: &'static str,
    fault_cells: &'static [&'static str],
    positive_gate: &'static str,
    negative_gates: &'static [&'static str],
    assertion_markers: &'static [&'static str],
}

const EXPECTED_RACES: &[ExpectedRace] = &[
    ExpectedRace {
        id: RACE_IDS[0],
        sources: &[
            PRODUCTION_SOURCES[0],
            PRODUCTION_SOURCES[1],
            PRODUCTION_SOURCES[5],
        ],
        harness: HARNESSES[0],
        harness_case: "wake_vs_timeout_single_winner",
        fault_cells: &[FAULT_CELL_IDS[12]],
        positive_gate: "one terminal winner, one publication acknowledgement, full credit return, and no live reverse-index membership",
        negative_gates: &[
            "double-terminal",
            "double-publication-ack",
            "terminal-effect-remains-live",
        ],
        assertion_markers: &[
            "oneshot-single-terminal",
            "oneshot-receipt-provenance",
            "deadline-single-consume",
            "registry-terminal-once",
            "typed-receipt-registry-disposition",
            "publication-ack-once",
            "credits-fully-returned",
            "reverse-indexes-empty",
            "scope-revoked",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[1],
        sources: &[
            PRODUCTION_SOURCES[0],
            PRODUCTION_SOURCES[1],
            PRODUCTION_SOURCES[5],
        ],
        harness: HARNESSES[0],
        harness_case: "cancel_vs_wake_single_winner",
        fault_cells: &[FAULT_CELL_IDS[13]],
        positive_gate: "cancel and wake have one applied terminal result and remove all live memberships",
        negative_gates: &["late-wake-mutates-cancelled-wait", "credit-returned-twice"],
        assertion_markers: &[
            "oneshot-single-terminal",
            "oneshot-receipt-provenance",
            "late-wake-rejected",
            "typed-receipt-registry-disposition",
            "publication-ack-once",
            "credits-fully-returned",
            "reverse-indexes-empty",
            "scope-revoked",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[2],
        sources: &[PRODUCTION_SOURCES[1]],
        harness: HARNESSES[1],
        harness_case: "stale_deadline_after_rearm",
        fault_cells: &[FAULT_CELL_IDS[14]],
        positive_gate: "the old deadline generation is rejected with the full projection unchanged and the new generation remains live",
        negative_gates: &[
            "old-deadline-terminalizes-new-wait",
            "rearm-inherits-terminal-state",
        ],
        assertion_markers: &[
            "old-token-rejected",
            "rejection-failure-atomic",
            "replacement-generation-advanced",
            "replacement-remains-live",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[3],
        sources: &[PRODUCTION_SOURCES[3], PRODUCTION_SOURCES[0]],
        harness: HARNESSES[3],
        harness_case: "same_page_single_publication",
        fault_cells: &[FAULT_CELL_IDS[5]],
        positive_gate: "one mapping publication resolves both one-shot continuations and releases the losing candidate exactly once",
        negative_gates: &[
            "double-mapping-publication",
            "resume-before-mapping-commit",
            "losing-frame-untracked",
        ],
        assertion_markers: &[
            "resume-before-commit-rejected",
            "publication-closure-once",
            "losing-candidate-released-once",
            "continuations-terminal-once",
            "duplicate-resume-rejected",
            "scope-revoked",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[4],
        sources: &[PRODUCTION_SOURCES[3], PRODUCTION_SOURCES[0]],
        harness: HARNESSES[3],
        harness_case: "handler_crash_before_resolution",
        fault_cells: &[FAULT_CELL_IDS[6], FAULT_CELL_IDS[7]],
        positive_gate: "crash fences the old binding and every registered continuation reaches adopt, resolve, or abort",
        negative_gates: &[
            "unindexed-suspension",
            "implicit-adoption",
            "old-binding-resume",
        ],
        assertion_markers: &[
            "crash-fences-old-binding",
            "committed-crash-kernel-terminal",
            "uncommitted-crash-aborts",
            "continuation-single-terminal",
            "no-implicit-adoption",
            "scope-revoked",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[5],
        sources: &[
            PRODUCTION_SOURCES[3],
            PRODUCTION_SOURCES[0],
            PRODUCTION_SOURCES[5],
        ],
        harness: HARNESSES[3],
        harness_case: "old_binding_reply_after_rebind",
        fault_cells: &[FAULT_CELL_IDS[8], FAULT_CELL_IDS[9]],
        positive_gate: "the old reply is rejected before page-table, continuation, or credit mutation",
        negative_gates: &[
            "old-reply-consumes-continuation",
            "old-reply-publishes-pte",
            "double-resume",
        ],
        assertion_markers: &[
            "mapping-committed-before-crash",
            "old-reply-failure-atomic",
            "old-reply-no-resume",
            "old-reply-credit-failure-atomic",
            "kernel-terminal-once",
            "scope-revoked",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[6],
        sources: &[PRODUCTION_SOURCES[3], PRODUCTION_SOURCES[0]],
        harness: HARNESSES[3],
        harness_case: "adopt_vs_abort_single_winner",
        fault_cells: &[FAULT_CELL_IDS[9]],
        positive_gate: "adoption or abort changes ownership or terminal state exactly once",
        negative_gates: &[
            "terminal-effect-adopted",
            "automatic-adoption",
            "credit-duplication",
        ],
        assertion_markers: &[
            "decision-single-winner",
            "adoption-explicit-only",
            "ownership-authority-consumed-once",
            "continuation-terminal-once",
            "late-action-failure-atomic",
            "scope-revoked",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[7],
        sources: &[PRODUCTION_SOURCES[0], PRODUCTION_SOURCES[5]],
        harness: HARNESSES[0],
        harness_case: "resolve_vs_abort_one_shot",
        fault_cells: &[FAULT_CELL_IDS[9]],
        positive_gate: "resolve and abort consume one terminal authority and one modeled publication acknowledgement at most once",
        negative_gates: &[
            "second-resume",
            "resolve-after-abort",
            "abort-after-resolve",
            "token-reuse",
        ],
        assertion_markers: &[
            "oneshot-single-terminal",
            "oneshot-receipt-provenance",
            "second-terminal-rejected",
            "token-reuse-rejected",
            "typed-receipt-registry-disposition",
            "publication-ack-once",
            "credits-fully-returned",
            "reverse-indexes-empty",
            "scope-revoked",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[8],
        sources: &[PRODUCTION_SOURCES[5]],
        harness: HARNESSES[5],
        harness_case: "commit_vs_revoke_linearization",
        fault_cells: &[FAULT_CELL_IDS[10], FAULT_CELL_IDS[11], FAULT_CELL_IDS[15]],
        positive_gate: "commit-first records drain work while revoke-first closes the old authority gate",
        negative_gates: &[
            "closed-epoch-commit",
            "committed-effect-reported-rolled-back",
        ],
        assertion_markers: &[
            "commit-revoke-single-order",
            "closed-epoch-commit-rejected",
            "committed-effect-drained",
            "uncommitted-effect-aborted",
            "reverse-index-empty",
            "scope-revoked",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[9],
        sources: &[
            PRODUCTION_SOURCES[1],
            PRODUCTION_SOURCES[0],
            PRODUCTION_SOURCES[5],
        ],
        harness: HARNESSES[5],
        harness_case: "revoke_deferred_wait_timer",
        fault_cells: &[FAULT_CELL_IDS[13], FAULT_CELL_IDS[14]],
        positive_gate: "revocation closes only the target cohort and late wait or timer activity cannot reopen it",
        negative_gates: &[
            "unrelated-effect-visit",
            "history-effect-visit",
            "late-notification",
            "revoked-scope-reopened",
        ],
        assertion_markers: &[
            "target-cohort-only",
            "oneshot-receipt-provenance",
            "typed-receipt-registry-disposition",
            "late-wake-failure-atomic",
            "late-timer-failure-atomic",
            "credits-fully-returned",
            "reverse-index-empty",
            "unrelated-history-unvisited",
            "scope-revoked",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[10],
        sources: &[PRODUCTION_SOURCES[5]],
        harness: HARNESSES[5],
        harness_case: "budget_commit_vs_abort_conservation",
        fault_cells: &[FAULT_CELL_IDS[10], FAULT_CELL_IDS[11]],
        positive_gate: "commit or abort selects one credit disposition and preserves free plus held plus committed capacity",
        negative_gates: &[
            "credit-copied",
            "completion-disposes-credit-twice",
            "abort-after-commit-returns-credit",
        ],
        assertion_markers: &[
            "single-credit-disposition",
            "free-held-committed-conserved",
            "credit-returned-once",
            "duplicate-completion-rejected",
            "abort-after-commit-not-reported",
            "scope-revoked",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[11],
        sources: &[PRODUCTION_SOURCES[2]],
        harness: HARNESSES[2],
        harness_case: "fallback_before_rebind",
        fault_cells: &[
            FAULT_CELL_IDS[0],
            FAULT_CELL_IDS[1],
            FAULT_CELL_IDS[2],
            FAULT_CELL_IDS[3],
            FAULT_CELL_IDS[4],
        ],
        positive_gate: "crash advances binding once, fallback picks before rebind, and pre-rebind or stale proposals are rejected",
        negative_gates: &[
            "rebind-advances-binding",
            "fallback-bypassed",
            "repeated-crash-advances-binding",
        ],
        assertion_markers: &[
            "crash-advances-binding-once",
            "repeated-crash-unchanged",
            "pending-proposal-cleared",
            "fallback-pick-before-rebind",
            "rebind-keeps-binding-epoch",
            "stale-proposals-failure-atomic",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[12],
        sources: &[PRODUCTION_SOURCES[4]],
        harness: HARNESSES[4],
        harness_case: "publish_vs_revoke_commit_gate",
        fault_cells: &[FAULT_CELL_IDS[15], FAULT_CELL_IDS[16]],
        positive_gate: "publication and revoke have one order, with uncommitted losers aborted and committed winners drained or reset",
        negative_gates: &[
            "committed-effect-reused-before-reset",
            "committed-request-reported-rolled-back",
        ],
        assertion_markers: &[
            "commit-revoke-single-order",
            "publication-closure-at-most-once",
            "uncommitted-loser-aborted",
            "committed-effect-retained-until-reset",
            "committed-result-not-rolled-back",
            "modeled-iotlb-owner-progress-complete",
            "pre-quiescence-reuse-rejected",
            "post-quiescence-new-binding",
            "final-quiescence-before-rebind",
        ],
    },
    ExpectedRace {
        id: RACE_IDS[13],
        sources: &[PRODUCTION_SOURCES[4]],
        harness: HARNESSES[4],
        harness_case: "timeout_vs_late_completion_tombstone",
        fault_cells: &[
            FAULT_CELL_IDS[16],
            FAULT_CELL_IDS[17],
            FAULT_CELL_IDS[18],
            FAULT_CELL_IDS[19],
        ],
        positive_gate: "timeout retains ownership until reset and IOTLB receipts allow exactly one retry completion",
        negative_gates: &[
            "owner-reused-before-quiescence",
            "second-user-result",
            "fabricated-iotlb-ack",
            "deadline-reported-revoked",
        ],
        assertion_markers: &[
            "reset-tombstone-preserves-identity",
            "completion-reset-single-terminal",
            "second-user-result-rejected",
            "modeled-iotlb-owner-tombstone-preserves-progress",
            "duplicate-owner-rejected",
            "fabricated-ack-failure-atomic",
            "duplicate-ack-failure-atomic",
            "pre-quiescence-reuse-rejected",
            "post-quiescence-new-binding",
            "retry-completes-exactly-once",
            "final-quiescence-before-rebind",
        ],
    },
];

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Summary {
    pub(crate) races: usize,
    pub(crate) fault_cells: usize,
    pub(crate) scale_points: usize,
    pub(crate) performance_cases: usize,
    pub(crate) prior_art_rows: usize,
}

pub(crate) fn validate(root: &Path) -> Result<Summary, String> {
    let contract_source = read(root, CONTRACT_PATH)?;
    let map_source = read(root, RACE_MAP_PATH)?;
    let contract: Contract = toml::from_str(&contract_source)
        .map_err(|error| format!("parse {CONTRACT_PATH}: {error}"))?;
    let map: RaceMap =
        toml::from_str(&map_source).map_err(|error| format!("parse {RACE_MAP_PATH}: {error}"))?;
    let semantic_ids = semantic_race_ids(root, &contract.inputs.semantic_races)?;

    validate_contract(&contract)?;
    validate_race_map(&map, &contract, &semantic_ids)?;
    validate_paths(root, &map)?;

    Ok(Summary {
        races: map.race.len(),
        fault_cells: contract.fault_matrix.required_cell_ids.len(),
        scale_points: contract.scale.point.len(),
        performance_cases: contract.performance.case.len(),
        prior_art_rows: contract.prior_art.required_row_ids.len(),
    })
}

fn validate_contract(contract: &Contract) -> Result<(), String> {
    expect_eq("schema", &contract.schema, "nexus.stage7b.contract.v1")?;
    expect_eq("stage", &contract.stage, "7b")?;
    expect_eq("status", &contract.status, "acceptance-contract")?;
    expect_eq("stop_after", &contract.stop_after, "contribution-decision")?;
    if contract.final_research_narrative {
        return Err("final_research_narrative must remain false in Stage 7B".into());
    }

    let inputs = &contract.inputs;
    expect_eq(
        "inputs.semantic_races",
        &inputs.semantic_races,
        "specs/oracles/cser-races.toml",
    )?;
    expect_eq(
        "inputs.race_evidence_map",
        &inputs.race_evidence_map,
        RACE_MAP_PATH,
    )?;
    expect_count("inputs.race_count", inputs.race_count, RACE_IDS.len())?;
    expect_count(
        "inputs.fault_cell_count",
        inputs.fault_cell_count,
        FAULT_CELL_IDS.len(),
    )?;
    expect_count(
        "inputs.scale_point_count",
        inputs.scale_point_count,
        SCALE_POINTS.len(),
    )?;
    expect_count(
        "inputs.performance_case_count",
        inputs.performance_case_count,
        PERFORMANCE_CASES.len(),
    )?;
    expect_count(
        "inputs.prior_art_row_count",
        inputs.prior_art_row_count,
        PRIOR_ART_IDS.len(),
    )?;

    let concurrency = &contract.concurrency;
    expect_eq(
        "concurrency.required_source_kind",
        &concurrency.required_source_kind,
        "production-transition-source",
    )?;
    expect_eq(
        "concurrency.synchronization_model",
        &concurrency.synchronization_model,
        "production transition source under a Loom-modeled outer mutex",
    )?;
    expect_strings(
        "concurrency.required_race_ids",
        &concurrency.required_race_ids,
        RACE_IDS,
    )?;
    expect_strings(
        "concurrency.required_production_sources",
        &concurrency.required_production_sources,
        PRODUCTION_SOURCES,
    )?;
    expect_strings(
        "concurrency.required_harnesses",
        &concurrency.required_harnesses,
        HARNESSES,
    )?;
    expect_strings(
        "concurrency.forbid_claims",
        &concurrency.forbid_claims,
        CONCURRENCY_CLAIMS,
    )?;
    expect_strings(
        "concurrency.negative_mutations",
        &concurrency.negative_mutations,
        CONCURRENCY_MUTATIONS,
    )?;

    let fault = &contract.fault_matrix;
    expect_strings("fault_matrix.families", &fault.families, FAULT_FAMILIES)?;
    expect_count("fault_matrix.cells_per_family", fault.cells_per_family, 5)?;
    expect_count(
        "fault_matrix.registry_backed_nonzero_credit_cells",
        fault.registry_backed_nonzero_credit_cells,
        15,
    )?;
    expect_count(
        "fault_matrix.typed_no_credit_scheduler_witnesses",
        fault.typed_no_credit_scheduler_witnesses,
        5,
    )?;
    expect_eq(
        "fault_matrix.registry_scope_model",
        &fault.registry_scope_model,
        "case-local",
    )?;
    if fault.shared_production_scope_claimed || fault.cross_object_crash_panic_atomicity_claimed {
        return Err(
            "fault matrix must not claim a shared production scope or cross-object crash/panic atomicity"
                .into(),
        );
    }
    expect_strings(
        "fault_matrix.required_cell_ids",
        &fault.required_cell_ids,
        FAULT_CELL_IDS,
    )?;
    expect_strings(
        "fault_matrix.required_result_fields",
        &fault.required_result_fields,
        FAULT_RESULT_FIELDS,
    )?;
    expect_strings(
        "fault_matrix.negative_mutations",
        &fault.negative_mutations,
        FAULT_MUTATIONS,
    )?;
    for (family_index, family) in FAULT_FAMILIES.iter().enumerate() {
        let start = family_index * fault.cells_per_family;
        let end = start + fault.cells_per_family;
        if fault.required_cell_ids[start..end]
            .iter()
            .any(|id| !id.starts_with(&format!("{family}.")))
        {
            return Err(format!(
                "fault_matrix family {family:?} does not own exactly its five ordered cells"
            ));
        }
    }

    expect_strings(
        "scale.required_metrics",
        &contract.scale.required_metrics,
        SCALE_METRICS,
    )?;
    expect_strings(
        "scale.negative_mutations",
        &contract.scale.negative_mutations,
        SCALE_MUTATIONS,
    )?;
    if contract.scale.point.len() != SCALE_POINTS.len() {
        return Err(format!(
            "scale.point count mismatch: expected {}, got {}",
            SCALE_POINTS.len(),
            contract.scale.point.len()
        ));
    }
    for (index, (actual, expected)) in contract.scale.point.iter().zip(SCALE_POINTS).enumerate() {
        let tuple = (actual.id.as_str(), actual.n, actual.k, actual.history);
        if tuple != *expected {
            return Err(format!(
                "scale.point[{index}] mismatch: expected {expected:?}, got {tuple:?}"
            ));
        }
        if actual.k > actual.n {
            return Err(format!("scale.point[{index}] has k greater than N"));
        }
    }

    let performance = &contract.performance;
    expect_count("performance.warmups", performance.warmups, 7)?;
    expect_count("performance.samples", performance.samples, 65)?;
    expect_count(
        "performance.empty_timer_samples",
        performance.empty_timer_samples,
        257,
    )?;
    expect_strings(
        "performance.statistics",
        &performance.statistics,
        PERFORMANCE_STATISTICS,
    )?;
    if !performance.retain_raw_samples {
        return Err("performance.retain_raw_samples must be true".into());
    }
    expect_eq(
        "performance.clock",
        &performance.clock,
        "guest-visible-tsc-lfence",
    )?;
    expect_eq(
        "performance.environment",
        &performance.environment,
        "single-vCPU single-thread TCG release-build hot-cache",
    )?;
    expect_strings(
        "performance.measurement_excludes",
        &performance.measurement_excludes,
        PERFORMANCE_EXCLUDES,
    )?;
    expect_strings(
        "performance.negative_mutations",
        &performance.negative_mutations,
        PERFORMANCE_MUTATIONS,
    )?;
    let operation_definitions = [
        ("begin", performance.operation_definitions.begin.as_str()),
        (
            "complete",
            performance.operation_definitions.complete.as_str(),
        ),
        (
            "closure",
            performance.operation_definitions.closure.as_str(),
        ),
        (
            "projection",
            performance.operation_definitions.projection.as_str(),
        ),
    ];
    if operation_definitions != PERFORMANCE_OPERATION_DEFINITIONS {
        return Err(format!(
            "performance.operation_definitions mismatch: expected {PERFORMANCE_OPERATION_DEFINITIONS:?}, got {operation_definitions:?}"
        ));
    }
    if performance.case.len() != PERFORMANCE_CASES.len() {
        return Err(format!(
            "performance.case count mismatch: expected {}, got {}",
            PERFORMANCE_CASES.len(),
            performance.case.len()
        ));
    }
    let scale_ids: BTreeSet<_> = contract
        .scale
        .point
        .iter()
        .map(|point| point.id.as_str())
        .collect();
    for (index, (actual, expected)) in performance.case.iter().zip(PERFORMANCE_CASES).enumerate() {
        let tuple = (
            actual.id.as_str(),
            actual.operation.as_str(),
            actual.scale_point.as_str(),
        );
        if tuple != *expected {
            return Err(format!(
                "performance.case[{index}] mismatch: expected {expected:?}, got {tuple:?}"
            ));
        }
        if !scale_ids.contains(actual.scale_point.as_str()) {
            return Err(format!(
                "performance.case[{index}] references unknown scale point {:?}",
                actual.scale_point
            ));
        }
    }

    let prior = &contract.prior_art;
    expect_eq(
        "prior_art.source_policy",
        &prior.source_policy,
        "primary-source-required",
    )?;
    expect_strings(
        "prior_art.required_row_ids",
        &prior.required_row_ids,
        PRIOR_ART_IDS,
    )?;
    expect_strings(
        "prior_art.required_fields",
        &prior.required_fields,
        PRIOR_ART_FIELDS,
    )?;
    expect_strings(
        "prior_art.negative_mutations",
        &prior.negative_mutations,
        PRIOR_ART_MUTATIONS,
    )?;

    let contribution = &contract.contribution;
    expect_strings(
        "contribution.allowed_verdicts",
        &contribution.allowed_verdicts,
        ALLOWED_VERDICTS,
    )?;
    expect_strings(
        "contribution.support_bounded_requires",
        &contribution.support_bounded_requires,
        SUPPORT_REQUIREMENTS,
    )?;
    expect_strings(
        "contribution.narrow_requires",
        &contribution.narrow_requires,
        NARROW_REQUIREMENTS,
    )?;
    expect_strings(
        "contribution.reject_if",
        &contribution.reject_if,
        REJECT_CONDITIONS,
    )?;
    expect_strings(
        "contribution.forbid_claims",
        &contribution.forbid_claims,
        CONTRIBUTION_CLAIMS,
    )?;
    expect_strings(
        "contribution.negative_mutations",
        &contribution.negative_mutations,
        CONTRIBUTION_MUTATIONS,
    )?;

    let acceptance = &contract.acceptance;
    if !acceptance.requires_clean_source
        || !acceptance.requires_cold_verify
        || !acceptance.requires_exact_pushed_sha_ci
        || !acceptance.requires_quick_ci
        || !acceptance.requires_full_ci
    {
        return Err("all Stage 7B acceptance authority flags must remain true".into());
    }
    Ok(())
}

fn validate_race_map(
    map: &RaceMap,
    contract: &Contract,
    semantic_ids: &[String],
) -> Result<(), String> {
    expect_eq(
        "race-map.schema",
        &map.schema,
        "nexus.stage7b.race-evidence-map.v1",
    )?;
    expect_eq("race-map.contract", &map.contract, CONTRACT_PATH)?;
    expect_eq(
        "race-map.semantic_catalog",
        &map.semantic_catalog,
        "specs/oracles/cser-races.toml",
    )?;
    expect_count(
        "race-map.expected_count",
        map.expected_count,
        RACE_IDS.len(),
    )?;
    expect_count("race-map.race", map.race.len(), RACE_IDS.len())?;

    let actual_ids: Vec<_> = map.race.iter().map(|race| race.id.clone()).collect();
    expect_strings("race-map.race ids", &actual_ids, RACE_IDS)?;
    expect_strings("semantic race ids", semantic_ids, RACE_IDS)?;
    expect_strings(
        "contract/map semantic race equality",
        &contract.concurrency.required_race_ids,
        &semantic_ids.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;

    let known_faults: BTreeSet<_> = contract
        .fault_matrix
        .required_cell_ids
        .iter()
        .map(String::as_str)
        .collect();
    let mut covered_faults = BTreeSet::new();
    let mut covered_sources = BTreeSet::new();
    let mut covered_harnesses = BTreeSet::new();
    let mut harness_cases = BTreeSet::new();

    for (index, (actual, expected)) in map.race.iter().zip(EXPECTED_RACES).enumerate() {
        expect_eq(&format!("race[{index}].id"), &actual.id, expected.id)?;
        expect_strings(
            &format!("race[{index}].production_sources"),
            &actual.production_sources,
            expected.sources,
        )?;
        expect_eq(
            &format!("race[{index}].harness"),
            &actual.harness,
            expected.harness,
        )?;
        expect_eq(
            &format!("race[{index}].harness_case"),
            &actual.harness_case,
            expected.harness_case,
        )?;
        expect_strings(
            &format!("race[{index}].fault_cells"),
            &actual.fault_cells,
            expected.fault_cells,
        )?;
        expect_eq(
            &format!("race[{index}].positive_gate"),
            &actual.positive_gate,
            expected.positive_gate,
        )?;
        expect_strings(
            &format!("race[{index}].negative_gates"),
            &actual.negative_gates,
            expected.negative_gates,
        )?;
        expect_strings(
            &format!("race[{index}].assertion_markers"),
            &actual.assertion_markers,
            expected.assertion_markers,
        )?;
        if !harness_cases.insert((actual.harness.as_str(), actual.harness_case.as_str())) {
            return Err(format!(
                "race[{index}] duplicates harness/case {:?}::{:?}",
                actual.harness, actual.harness_case
            ));
        }
        for source in &actual.production_sources {
            covered_sources.insert(source.as_str());
        }
        covered_harnesses.insert(actual.harness.as_str());
        for fault in &actual.fault_cells {
            if !known_faults.contains(fault.as_str()) {
                return Err(format!("race[{index}] maps unknown fault cell {fault:?}"));
            }
            covered_faults.insert(fault.as_str());
        }
    }

    expect_set(
        "race-map production source coverage",
        &covered_sources,
        PRODUCTION_SOURCES,
    )?;
    expect_set("race-map harness coverage", &covered_harnesses, HARNESSES)?;
    expect_set(
        "race-map fault-cell coverage",
        &covered_faults,
        FAULT_CELL_IDS,
    )?;
    Ok(())
}

fn validate_paths(root: &Path, map: &RaceMap) -> Result<(), String> {
    for relative in [CONTRACT_PATH, RACE_MAP_PATH, "evaluation/stage7b/README.md"] {
        validate_regular_repo_file(root, relative, "Stage 7B contract path")?;
    }
    let mut paths = BTreeSet::new();
    for race in &map.race {
        paths.extend(race.production_sources.iter().map(String::as_str));
        paths.insert(race.harness.as_str());
    }
    for relative in paths {
        let valid_prefix = relative.starts_with("crates/cser-transition-gates/src/")
            || relative.starts_with("crates/cser-transition-gates/tests/")
            || relative == "kernel/nexus-ostd/src/cser/effect_registry.rs";
        if !valid_prefix || !relative.ends_with(".rs") {
            return Err(format!(
                "Stage 7B source is outside the production/harness boundary: {relative}"
            ));
        }
        validate_regular_repo_file(root, relative, "Stage 7B production/harness path")?;
        if fs::metadata(root.join(relative))
            .map_err(|error| format!("read Stage 7B source metadata {relative}: {error}"))?
            .len()
            == 0
        {
            return Err(format!(
                "Stage 7B production/harness source is empty: {relative}"
            ));
        }
    }
    for (index, race) in map.race.iter().enumerate() {
        let harness = read(root, &race.harness)?;
        let stable = format!("fn {}(", race.harness_case);
        let prefixed = format!("fn loom_{}(", race.harness_case);
        let start = harness.find(&stable).or_else(|| harness.find(&prefixed));
        let Some(start) = start else {
            return Err(format!(
                "race[{index}] harness {:?} does not define stable case {:?} (with optional loom_ prefix)",
                race.harness, race.harness_case
            ));
        };
        for required_report_source in [
            "STAGE7B_CONCURRENCY case={case} status=PASS",
            "STAGE7B_CONCURRENCY_ASSERT case={case} assertion={assertion} status=PASS",
        ] {
            if harness.matches(required_report_source).count() != 1 {
                return Err(format!(
                    "race[{index}] harness {:?} lacks one exact runtime report format {required_report_source:?}",
                    race.harness
                ));
            }
        }
        let tail = &harness[start..];
        let end = tail.find("\n#[test]").unwrap_or(tail.len());
        let case_region = &tail[..end];
        let case_literal = format!("\"{}\"", race.harness_case);
        if case_region.matches(&case_literal).count() != 1 {
            return Err(format!(
                "race[{index}] case {:?} must report its exact case marker once",
                race.harness_case
            ));
        }
        for assertion in &race.assertion_markers {
            let literal = format!("\"{assertion}\"");
            if case_region.matches(&literal).count() != 1 {
                return Err(format!(
                    "race[{index}] case {:?} must report exact assertion marker {assertion:?} once",
                    race.harness_case
                ));
            }
        }
    }
    validate_scale_instrumentation_source(&read(root, REGISTRY_SOURCE_PATH)?)?;
    validate_performance_measurement_source(&read(root, EVALUATOR_SOURCE_PATH)?)?;
    validate_regular_repo_file(root, IO_GATE_SOURCE_PATH, "Stage 7B I/O gate source")?;
    validate_regular_repo_file(root, IO_PORTAL_SOURCE_PATH, "Stage 7B I/O adapter source")?;
    validate_regular_repo_file(root, IO_ENTRY_SOURCE_PATH, "Stage 7B I/O entrypoint source")?;
    validate_io_instance_source(
        &read(root, IO_GATE_SOURCE_PATH)?,
        &read(root, IO_PORTAL_SOURCE_PATH)?,
    )?;
    validate_io_entrypoint_source(&read(root, IO_ENTRY_SOURCE_PATH)?)?;
    validate_oneshot_provenance_source(
        &read(root, ONESHOT_GATE_SOURCE_PATH)?,
        &read(root, EFFECT_WAKER_SOURCE_PATH)?,
        &read(root, HARNESSES[0])?,
        &read(root, HARNESSES[5])?,
    )?;
    validate_terminal_registry_coupling_source(
        &read(root, HARNESSES[0])?,
        &read(root, HARNESSES[5])?,
    )?;
    Ok(())
}

fn validate_oneshot_provenance_source(
    gate: &str,
    effect: &str,
    oneshot: &str,
    registry: &str,
) -> Result<(), String> {
    for required in [
        "use core::sync::atomic::{AtomicU64, Ordering};",
        "static NEXT_GATE_NONCE: AtomicU64 = AtomicU64::new(1);",
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct OneShotToken {",
        "    gate_nonce: u64,\n    instance_id: u64,\n    id: u64,\n    generation: u64,",
        "#[derive(Debug, Eq, PartialEq)]\npub struct TerminalReceipt<T: Copy + Eq> {",
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct OneShotProjection<T: Copy + Eq> {",
        "#[derive(Debug, Eq, PartialEq)]\npub struct OneShotGate<T: Copy + Eq> {",
        "pub fn new(instance_id: u64, id: u64, generation: u64)",
        "if instance_id == 0 || id == 0 || generation == 0",
        "        let gate_nonce = next_gate_nonce()?;",
        "                gate_nonce,",
        "pub fn consume_terminal(&mut self, receipt: &TerminalReceipt<T>)",
        "        self.validate_token(receipt.token)?;",
        "        if self.terminal != Some(receipt.outcome) {",
        "        if self.receipt_consumed {",
        "        self.receipt_consumed = true;",
        "        if token.gate_nonce != self.token.gate_nonce || token.instance_id != self.token.instance_id",
        "            return Err(OneShotError::ForeignInstance);",
        "fn next_gate_nonce() -> Result<u64, OneShotError> {",
        ".fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {",
        "current.checked_add(1)",
        ".map_err(|_| OneShotError::InstanceNamespaceExhausted)",
        "let detached_receipt = detached.try_terminalize(detached.token(), 11_u8).unwrap();",
    ] {
        if !gate.contains(required) {
            return Err(format!(
                "OneShot provenance source lacks required fragment {required:?}"
            ));
        }
    }
    for forbidden in [
        "pub instance_id: u64",
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct TerminalReceipt",
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct OneShotGate",
    ] {
        if gate.contains(forbidden) {
            return Err(format!(
                "OneShot provenance source contains forbidden forge/copy fragment {forbidden:?}"
            ));
        }
    }
    let compact_gate: String = gate
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for required in
        ["assert_eq!(gate.consume_terminal(&detached_receipt),Err(OneShotError::ForeignInstance));"]
    {
        if !compact_gate.contains(required) {
            return Err(format!(
                "OneShot reconstructed-instance unit gate lacks required fragment {required:?}"
            ));
        }
    }
    let normalized_gate = compact_gate
        .replace("self::", "")
        .replace("crate::oneshot::", "")
        .replace("cser_transition_gates::oneshot::", "");
    for forbidden in [
        "CloneforTerminalReceipt",
        "CopyforTerminalReceipt",
        "CloneforOneShotGate",
        "CopyforOneShotGate",
    ] {
        if normalized_gate.contains(forbidden) {
            return Err(format!(
                "OneShot provenance source contains forbidden manual copy implementation {forbidden:?}"
            ));
        }
    }
    let implementation_headers: Vec<_> = gate
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("impl"))
        .collect();
    let expected_implementation_headers = [
        "impl OneShotToken {",
        "impl<T: Copy + Eq> TerminalReceipt<T> {",
        "impl<T: Copy + Eq> OneShotProjection<T> {",
        "impl<T: Copy + Eq> OneShotGate<T> {",
    ];
    if implementation_headers != expected_implementation_headers {
        return Err(format!(
            "OneShot implementation population drifted: expected {expected_implementation_headers:?}, got {implementation_headers:?}"
        ));
    }

    let token_impl = source_region(
        gate,
        "impl OneShotToken {",
        "\n}\n\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum OneShotError",
        "OneShotToken implementation",
    )?;
    let token_getters = [
        "pub const fn instance_id(self) -> u64 {",
        "pub const fn id(self) -> u64 {",
        "pub const fn generation(self) -> u64 {",
    ];
    let public_token_items: Vec<_> = token_impl
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub "))
        .collect();
    if public_token_items.len() != token_getters.len()
        || public_token_items
            .iter()
            .any(|line| !token_getters.contains(line))
    {
        return Err("OneShotToken must expose only its three read-only getters".into());
    }

    let receipt_impl = source_region(
        gate,
        "impl<T: Copy + Eq> TerminalReceipt<T> {",
        "\n}\n\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct OneShotProjection",
        "OneShot TerminalReceipt implementation",
    )?;
    let receipt_getters = [
        "pub const fn token(&self) -> OneShotToken {",
        "pub const fn outcome(&self) -> T {",
    ];
    let public_receipt_items: Vec<_> = receipt_impl
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub "))
        .collect();
    if public_receipt_items.len() != receipt_getters.len()
        || public_receipt_items
            .iter()
            .any(|line| !receipt_getters.contains(line))
    {
        return Err("OneShot TerminalReceipt must expose only read-only getters".into());
    }

    let expected_public_surface = [
        "pub struct OneShotToken {",
        "pub const fn instance_id(self) -> u64 {",
        "pub const fn id(self) -> u64 {",
        "pub const fn generation(self) -> u64 {",
        "pub enum OneShotError {",
        "pub struct TerminalReceipt<T: Copy + Eq> {",
        "pub const fn token(&self) -> OneShotToken {",
        "pub const fn outcome(&self) -> T {",
        "pub struct OneShotProjection<T: Copy + Eq> {",
        "pub const fn token(self) -> OneShotToken {",
        "pub const fn terminal(self) -> Option<T> {",
        "pub const fn receipt_consumed(self) -> bool {",
        "pub struct OneShotGate<T: Copy + Eq> {",
        "pub fn new(instance_id: u64, id: u64, generation: u64) -> Result<Self, OneShotError> {",
        "pub const fn token(&self) -> OneShotToken {",
        "pub const fn terminal(&self) -> Option<T> {",
        "pub const fn projection(&self) -> OneShotProjection<T> {",
        "pub fn try_terminalize(",
        "pub fn consume_terminal(&mut self, receipt: &TerminalReceipt<T>) -> Result<(), OneShotError> {",
    ];
    let public_surface: Vec<_> = gate
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub ") || line.starts_with("pub("))
        .collect();
    if public_surface != expected_public_surface {
        return Err(format!(
            "OneShot public surface drifted: expected {expected_public_surface:?}, got {public_surface:?}"
        ));
    }

    let effect: String = effect
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for required in [
        "OneShotGate::new(token.scope_id,token.effect_id,token.authority_epoch)",
        "gate.consume_terminal(&receipt)",
    ] {
        if effect.matches(required).count() != 1 {
            return Err(format!(
                "EffectWaker must bind and consume one OneShot receipt via {required:?}"
            ));
        }
    }

    let oneshot: String = oneshot
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for required in [
        "assert_same_counter_foreign_faults_failure_atomic();",
        "letmutreconstructed=OneShotGate::new(0x7101,0x71ff,1).unwrap();",
        "assert_eq!(first.consume_terminal(&reconstructed_receipt),Err(OneShotError::ForeignInstance));",
        "assert_eq!(reconstructed.consume_terminal(&first_receipt),Err(OneShotError::ForeignInstance));",
        "self.terminal.consume_terminal(&receipt).unwrap();",
        "Err(OneShotError::ForeignInstance)",
        "Err(OneShotError::ReceiptAlreadyConsumed)",
        "assert_eq!(first.projection(),before_first);",
        "assert_eq!(second.projection(),before_second);",
    ] {
        if !oneshot.contains(required) {
            return Err(format!(
                "OneShot Loom provenance gate lacks required fragment {required:?}"
            ));
        }
    }

    let registry: String = registry
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for required in [
        "assert_foreign_wait_receipts_failure_atomic();",
        "letmutreconstructed=OneShotGate::new(0x7b01,0x7bff,1).unwrap();",
        "assert_eq!(first.consume_terminal(&reconstructed_receipt),Err(OneShotError::ForeignInstance));",
        "assert_eq!(reconstructed.consume_terminal(&first_receipt),Err(OneShotError::ForeignInstance));",
        "self.terminal.consume_terminal(&receipt).unwrap();",
        "assert_eq!(self.projection(),*before);",
    ] {
        if !registry.contains(required) {
            return Err(format!(
                "deferred Registry OneShot provenance gate lacks required fragment {required:?}"
            ));
        }
    }
    Ok(())
}

fn validate_io_entrypoint_source(entry: &str) -> Result<(), String> {
    const NEGATIVE_CALL: &str = "let namespace_isolation = assert_session_namespace_isolation();";
    const NEGATIVE_MARKER: &str = "println!(\"{}\", namespace_isolation.into_marker());";
    const RAW_MARKER: &str = "IO Namespace foreign_bdf_rejected=true bidirectional=true portal_state_unchanged=true pre_pci_dma=true";
    const DISCOVERY_CALL: &str = "let mut root = discover_and_own_bars();";

    let kernel_start = entry
        .find("fn kernel_main() {")
        .ok_or_else(|| "Stage 7B I/O entrypoint lacks kernel_main".to_owned())?;
    let kernel = &entry[kernel_start..];
    let mut positions = Vec::new();
    for required in [NEGATIVE_CALL, NEGATIVE_MARKER, DISCOVERY_CALL] {
        if entry.matches(required).count() != 1 || kernel.matches(required).count() != 1 {
            return Err(format!(
                "Stage 7B I/O kernel entrypoint must contain one exact pre-PCI namespace step {required:?}"
            ));
        }
        positions.push(kernel.find(required).unwrap());
    }
    if !(positions[0] < positions[1] && positions[1] < positions[2]) {
        return Err(
            "Stage 7B I/O namespace negative must execute before its marker and PCI/DMA discovery"
                .into(),
        );
    }
    if entry.contains(RAW_MARKER) {
        return Err(
            "Stage 7B I/O entrypoint must publish the namespace marker only from its typed receipt"
                .into(),
        );
    }
    if entry.contains("if false {") {
        return Err("Stage 7B I/O entrypoint conditionally skipped a required negative".into());
    }
    Ok(())
}

fn validate_terminal_registry_coupling_source(oneshot: &str, registry: &str) -> Result<(), String> {
    let oneshot: String = oneshot
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for (required, count) in [
        (
            "fnterminalize_and_close(&mutself,winner:&OneShotTerminalReceipt<Outcome>)",
            1,
        ),
        ("letoutcome=winner.outcome();", 1),
        ("assert_eq!(receipt.token(),token);", 1),
        ("Self::Wake|Self::Resolve=>TerminalOutcome::Completed,", 1),
        (
            "Self::Timeout|Self::Cancel|Self::Abort=>TerminalOutcome::Aborted,",
            1,
        ),
        ("CommitMetadata::new(outcome.registry_result(),1)", 1),
        (
            "TerminalRequest::completed_by(outcome.registry_result(),commit.clone())",
            1,
        ),
        (
            "None=>TerminalRequest::aborted(outcome.registry_result()),",
            1,
        ),
        (
            "assert_eq!(terminal.receipt.outcome(),expected_terminal);",
            1,
        ),
        (
            "assert_eq!(terminal.receipt.result(),outcome.registry_result());",
            1,
        ),
        ("assert_eq!(ticket.outcome(),expected_terminal);", 1),
        ("assert_eq!(ticket.result(),outcome.registry_result());", 1),
        ("self.terminal.consume_terminal(&receipt).unwrap();", 1),
        ("self.continuation.terminalize_and_close(&receipt);", 1),
        (
            "assert_eq!(self.continuation.failure_atomic_projection(),before_continuation);",
            2,
        ),
        (
            "assert_eq!(gate.continuation.registry_terminal(),winner.registry_terminal());",
            1,
        ),
        (
            "assert_eq!(gate.continuation.registry_result(),winner.registry_result());",
            1,
        ),
    ] {
        if oneshot.matches(required).count() != count {
            return Err(format!(
                "one-shot/registry composite must contain {count} exact coupling fragment(s) {required:?}"
            ));
        }
    }

    let registry: String = registry
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for (required, count) in [
        (
            "fnclose_from_winner(&mutself,winner:&OneShotTerminalReceipt<WaitTerminal>)",
            1,
        ),
        ("assert_eq!(winner.token(),self.terminal.token());", 1),
        ("letoutcome=winner.outcome();", 1),
        ("Self::Wake=>TerminalOutcome::Completed,", 1),
        ("Self::Timeout|Self::Revoked=>TerminalOutcome::Aborted,", 1),
        ("self.fixture.commit_single_target(self.handle)", 1),
        ("self.fixture.finish_revoke(&selection).unwrap();", 1),
        ("self.close_from_winner(&receipt);", 3),
        ("assert_eq!(self.projection(),*before);", 3),
        ("assert_ne!(revoke_won,activity_won);", 1),
        ("terminal.registry_terminal()", 1),
    ] {
        if registry.matches(required).count() != count {
            return Err(format!(
                "deferred registry composite must contain {count} exact coupling fragment(s) {required:?}"
            ));
        }
    }
    Ok(())
}

fn validate_io_instance_source(gate: &str, portal: &str) -> Result<(), String> {
    let identity = source_region(
        gate,
        "pub struct IoIdentity {\n",
        "}\n\nimpl IoIdentity",
        "IoIdentity fields",
    )?;
    for field in [
        "    instance_id: u64,",
        "    request_id: u64,",
        "    authority_epoch: u64,",
        "    binding_epoch: u64,",
        "    device_generation: u64,",
    ] {
        if identity.matches(field).count() != 1 {
            return Err(format!(
                "IoIdentity must contain one exact private field {field:?}"
            ));
        }
    }
    if identity
        .lines()
        .skip(1)
        .any(|line| line.trim_start().starts_with("pub "))
    {
        return Err("IoIdentity fields must remain private and non-forgeable".into());
    }

    let identity_impl = source_region(
        gate,
        "impl IoIdentity {",
        "\n}\n\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum IoPhase",
        "IoIdentity implementation",
    )?;
    let identity_getters = [
        "pub const fn instance_id(self) -> u64 {",
        "pub const fn request_id(self) -> u64 {",
        "pub const fn authority_epoch(self) -> u64 {",
        "pub const fn binding_epoch(self) -> u64 {",
        "pub const fn device_generation(self) -> u64 {",
    ];
    for getter in identity_getters {
        if identity_impl.matches(getter).count() != 1 {
            return Err(format!(
                "IoIdentity must expose one exact read-only getter {getter:?}"
            ));
        }
    }
    let public_identity_items: Vec<_> = identity_impl
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub "))
        .collect();
    if public_identity_items.len() != identity_getters.len()
        || public_identity_items
            .iter()
            .any(|line| !identity_getters.contains(line))
    {
        return Err("IoIdentity must not expose a constructor or mutator".into());
    }

    let gate_declaration = "pub struct IoGate<const EFFECTS: usize> {";
    let gate_offset = gate
        .find(gate_declaration)
        .ok_or_else(|| "IoGate declaration is missing".to_string())?;
    let derive = gate[..gate_offset]
        .lines()
        .next_back()
        .ok_or_else(|| "IoGate derive boundary is missing".to_string())?;
    if derive != "#[derive(Debug, Eq, PartialEq)]" {
        return Err("IoGate must remain a unique non-Clone, non-Copy owner".into());
    }
    let compact_gate: String = gate
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact_gate.contains("CloneforIoGate") || compact_gate.contains("CopyforIoGate") {
        return Err("IoGate must not implement Clone or Copy manually".into());
    }
    for required in [
        "pub fn new(instance_id: u64) -> Result<Self, IoError>",
        "if EFFECTS == 0 || instance_id == 0",
        "pub fn state_projection(&self) -> IoStateProjection<EFFECTS>",
        "pub fn can_complete_device(&self, identity: IoIdentity) -> bool",
        "self.validate_device_completion(identity).is_ok()",
    ] {
        if gate.matches(required).count() != 1 {
            return Err(format!(
                "IoGate instance boundary lacks one exact source fragment {required:?}"
            ));
        }
    }
    for (label, start, end, check) in [
        (
            "IoGate::register",
            "    pub fn register(",
            "    pub fn accepts_service_action(",
            "binding.instance_id != self.instance_id",
        ),
        (
            "IoGate::validate_device_completion",
            "    fn validate_device_completion(",
            "    pub fn crash_service(",
            "identity.instance_id != self.instance_id",
        ),
        (
            "IoGate::begin_reset",
            "    pub fn begin_reset(",
            "    /// Closes a cohort without reset",
            "close.instance_id != self.instance_id",
        ),
        (
            "IoGate::mark_terminal_quiesced",
            "    pub fn mark_terminal_quiesced(",
            "    pub fn apply_reset(",
            "close.instance_id != self.instance_id",
        ),
        (
            "IoGate::apply_reset",
            "    pub fn apply_reset(",
            "    pub fn begin_iotlb<",
            "receipt.instance_id != self.instance_id",
        ),
        (
            "IoGate::begin_iotlb",
            "    pub fn begin_iotlb<",
            "    pub fn mark_quiesced(",
            "reset.instance_id != self.instance_id",
        ),
        (
            "IoGate::mark_quiesced",
            "    pub fn mark_quiesced(",
            "    pub fn rebind_after_quiescence(",
            "receipt.instance_id != self.instance_id",
        ),
        (
            "IoGate::validate_service",
            "    fn validate_service(",
            "    fn effect(",
            "identity.instance_id != self.instance_id",
        ),
    ] {
        let region = source_region(gate, start, end, label)?;
        if region.matches(check).count() != 1 {
            return Err(format!(
                "{label} must perform one exact instance check {check:?}"
            ));
        }
    }
    if gate.matches("instance_id: self.instance_id").count() != 17 {
        return Err(
            "IoGate projection, typed authorities, tombstones, outcomes, and receipts must preserve all 17 instance provenance writes"
                .into(),
        );
    }

    for required in [
        "fn portal_instance_id(device_function: DeviceFunction) -> u64 {",
        "device_function.valid(),",
        "\"invalid PCI device function namespace\"",
        "let instance_id = portal_instance_id(device_function);",
        "IoGate::new(instance_id)",
        "self.gate.can_complete_device(authority)",
        "(u64::from(device_function.bus) << 24)",
        "(u64::from(device_function.device) << 19)",
        "(u64::from(device_function.function) << 16)",
        "u64::from(QUEUE_INDEX)",
        "pub struct Portal {\n    device_function: DeviceFunction,",
        "struct SessionBinding {",
        "fn bind_session_authority(",
        "authority.instance_id() != self.gate.instance_id()",
        "portal_instance_id(self.device_function) != self.gate.instance_id()",
        "pub fn open_session(",
        "let binding = self.bind_session_authority(authority)?;",
        "Ok(Session::open_bound(root, binding))",
        "fn open_bound(root: &mut Root, binding: SessionBinding)",
        "pub fn assert_session_namespace_isolation()",
        "pub struct SessionNamespaceIsolationReceipt {",
        "pub const fn into_marker(self) -> &'static str {",
        "-> SessionNamespaceIsolationReceipt {",
        "    SessionNamespaceIsolationReceipt {\n        marker:",
        "marker: \"IO Namespace foreign_bdf_rejected=true bidirectional=true portal_state_unchanged=true pre_pci_dma=true\",",
        "left.bind_session_authority(right_authority)",
        "right.bind_session_authority(left_authority)",
    ] {
        if portal.matches(required).count() != 1 {
            return Err(format!(
                "Portal instance boundary lacks one exact source fragment {required:?}"
            ));
        }
    }
    for forbidden in [
        "let mut probe = self.gate",
        "self.gate.clone()",
        "pub fn open(",
        "Session::open(",
        "pub struct SessionNamespaceIsolationReceipt {\n    pub marker:",
        "#[derive(Clone, Copy)]\npub struct SessionNamespaceIsolationReceipt",
    ] {
        if portal.contains(forbidden) {
            return Err(format!(
                "Portal instance/session boundary contains forbidden source fragment {forbidden:?}"
            ));
        }
    }
    let compact_portal: String = portal
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if portal.matches("SessionNamespaceIsolationReceipt").count() != 4 {
        return Err(
            "Portal namespace-isolation receipt type/constructor population drifted".into(),
        );
    }
    if compact_portal.contains("CloneforSessionNamespaceIsolationReceipt")
        || compact_portal.contains("CopyforSessionNamespaceIsolationReceipt")
    {
        return Err("Portal namespace-isolation receipt must remain linear".into());
    }
    let namespace_negative = source_region(
        portal,
        "pub fn assert_session_namespace_isolation() -> SessionNamespaceIsolationReceipt {",
        "\nstruct RequestBuffers {",
        "Portal namespace-isolation negative",
    )?;
    let namespace_negative: String = namespace_negative
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let expected_namespace_negative = concat!(
        "pubfnassert_session_namespace_isolation()->SessionNamespaceIsolationReceipt{",
        "constLEFT_DEVICE:DeviceFunction=DeviceFunction{bus:0,device:5,function:0,};",
        "constRIGHT_DEVICE:DeviceFunction=DeviceFunction{bus:0,device:6,function:0,};",
        "assert!(LEFT_DEVICE.valid());assert!(RIGHT_DEVICE.valid());",
        "assert_ne!(LEFT_DEVICE,RIGHT_DEVICE);",
        "letmutleft=Portal::new(LEFT_DEVICE);letmutright=Portal::new(RIGHT_DEVICE);",
        "letleft_authority=left.register(left.binding_token().unwrap(),Operation::ReadSector0).unwrap();",
        "letright_authority=right.register(right.binding_token().unwrap(),Operation::ReadSector0).unwrap();",
        "assert_ne!(left_authority.instance_id(),right_authority.instance_id());",
        "letleft_before=left.state_projection();letright_before=right.state_projection();",
        "assert_eq!(left.bind_session_authority(right_authority).map(|_|()),Err(SessionOpenError::ForeignInstance));",
        "assert_eq!(left.state_projection(),left_before);assert_eq!(right.state_projection(),right_before);",
        "assert_eq!(right.bind_session_authority(left_authority).map(|_|()),Err(SessionOpenError::ForeignInstance));",
        "assert_eq!(left.state_projection(),left_before);assert_eq!(right.state_projection(),right_before);",
        "letown=left.bind_session_authority(left_authority).unwrap();",
        "assert_eq!(own.device_function,LEFT_DEVICE);assert_eq!(own.authority,left_authority);",
        "assert_eq!(left.state_projection(),left_before);assert_eq!(right.state_projection(),right_before);",
        "SessionNamespaceIsolationReceipt{marker:\"IONamespaceforeign_bdf_rejected=truebidirectional=trueportal_state_unchanged=truepre_pci_dma=true\",}",
        "}",
    );
    if namespace_negative != expected_namespace_negative {
        return Err(
            "Portal namespace-isolation negative must retain its exact validity, bidirectional foreign rejection, full-state, own-authority, and terminal receipt order"
                .into(),
        );
    }
    Ok(())
}

fn validate_scale_instrumentation_source(source: &str) -> Result<(), String> {
    let begin = source_region(
        source,
        "    pub(crate) fn revoke_begin(",
        "    pub(crate) fn revoke_targets(",
        "EffectRegistry::revoke_begin",
    )?;
    let next = source_region(
        source,
        "    pub(crate) fn revoke_next(",
        "    pub(crate) fn stage_revoke_terminal(",
        "EffectRegistry::revoke_next",
    )?;
    let terminal = source_region(
        source,
        "    pub(crate) fn stage_revoke_terminal(",
        "    pub(crate) fn revoke_complete(",
        "EffectRegistry::stage_revoke_terminal",
    )?;
    let complete = source_region(
        source,
        "    pub(crate) fn revoke_complete(",
        "    pub(crate) fn revoke_work_projection(",
        "EffectRegistry::revoke_complete",
    )?;
    let projection = source_region(
        source,
        "    pub(crate) fn revoke_work_projection(",
        "    pub(crate) fn scope_projection(",
        "EffectRegistry::revoke_work_projection",
    )?;
    let terminal_inner = source_region(
        source,
        "    fn stage_terminal_inner(",
        "    fn validate_revoke_selection(",
        "EffectRegistry::stage_terminal_inner",
    )?;
    let validate_selection = source_region(
        source,
        "    fn validate_revoke_selection(",
        "    fn insert_reverse_indexes(",
        "EffectRegistry::validate_revoke_selection",
    )?;
    let remove_indexes = source_region(
        source,
        "    fn remove_reverse_indexes(",
        "\n}\n\nfn validate_generation(",
        "EffectRegistry::remove_reverse_indexes",
    )?;
    let access = source_region(
        source,
        "fn instrument_revoke_record_access<'a>(",
        "fn remove_index_member<",
        "instrument_revoke_record_access",
    )?;

    // This is deliberately a lexical boundary over the measured revoke
    // functions and their known record-touching helpers. It pins direct record
    // access to one instrumented helper; it is not a general Rust call-graph
    // proof and must not be described as one.
    let compact_begin: String = begin
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact_begin.contains("self.effects")
        || compact_begin.contains("instrument_revoke_record_access")
    {
        return Err(
            "revoke_begin must move the closure index without visiting effect records".into(),
        );
    }
    for (label, body) in [
        ("revoke_begin", begin),
        ("revoke_next", next),
        ("stage_revoke_terminal", terminal),
        ("revoke_complete", complete),
        ("stage_terminal_inner", terminal_inner),
        ("validate_revoke_selection", validate_selection),
        ("remove_reverse_indexes", remove_indexes),
    ] {
        reject_effect_collection_scan(label, body)?;
    }
    for (label, body) in [("revoke_next", next), ("revoke_complete", complete)] {
        if body.matches("instrument_revoke_record_access(").count() != 1 {
            return Err(format!(
                "{label} must perform each effect-record read through the instrumented access boundary"
            ));
        }
        reject_direct_effect_record_access(label, body)?;
    }

    for required in [
        "cohort.contains(&effect)",
        "RevokeRecordAccess::Begin",
        "work.begin_target_record_visits",
        "record.phase.is_terminal()",
        "work.history_effect_visits",
        "work.unrelated_effect_visits",
        "effects.get(&effect)",
    ] {
        if !access.contains(required) {
            return Err(format!(
                "instrumented revoke access boundary lacks required source fragment {required:?}"
            ));
        }
    }
    reject_effect_collection_scan("instrument_revoke_record_access", access)?;
    let compact_access: String = access
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact_access.matches("effects.get(&effect)").count() != 1
        || compact_access.contains("effects.get_mut(")
        || compact_access.contains("effects.entry(")
        || compact_access.contains("effects[")
        || compact_access.contains("=effects;")
        || compact_access.contains("=effects,")
    {
        return Err(
            "instrumented revoke access helper must contain one unaliased immutable record lookup"
                .into(),
        );
    }

    for (field, expression) in [
        (
            "begin_target_record_visits",
            "begin_target_record_visits: revoke.work.begin_target_record_visits",
        ),
        (
            "unrelated_effect_visits",
            "unrelated_effect_visits: revoke.work.unrelated_effect_visits",
        ),
        (
            "history_effect_visits",
            "history_effect_visits: revoke.work.history_effect_visits",
        ),
    ] {
        if !projection.contains(expression) {
            return Err(format!(
                "revoke_work_projection must expose the actual {field} counter"
            ));
        }
        if projection.contains(&format!("{field}: 0")) {
            return Err(format!(
                "revoke_work_projection hard-codes the {field} work metric"
            ));
        }
    }
    Ok(())
}

fn reject_direct_effect_record_access(label: &str, source: &str) -> Result<(), String> {
    let compact: String = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for forbidden in [
        "self.effects.get(",
        "self.effects.get_mut(",
        "self.effects.entry(",
        "self.effects[",
        "effects.get(",
        "effects.get_mut(",
        "effects.entry(",
        "effects[",
    ] {
        if compact.contains(forbidden) {
            return Err(format!(
                "{label} bypasses the instrumented effect-record lookup with {forbidden:?}"
            ));
        }
    }
    Ok(())
}

fn reject_effect_collection_scan(label: &str, source: &str) -> Result<(), String> {
    let compact: String = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for forbidden in [
        "self.effects.iter(",
        "self.effects.values(",
        "self.effects.values_mut(",
        "self.effects.keys(",
        "self.effects.range(",
        "effects.iter(",
        "effects.values(",
        "effects.values_mut(",
        "effects.keys(",
        "effects.range(",
        "in&self.effects",
        "ineffects",
    ] {
        if compact.contains(forbidden) {
            return Err(format!(
                "{label} contains an uninstrumented global/history effect scan {forbidden:?}"
            ));
        }
    }
    Ok(())
}

fn validate_performance_measurement_source(source: &str) -> Result<(), String> {
    let performance = source_region(
        source,
        "fn run_performance()",
        "fn collect_samples(",
        "Stage 7B run_performance",
    )?;
    let expected = [
        "measure(|| black_box(()))",
        "measure(|| candidate.begin().unwrap())",
        "measure(|| candidate.complete().unwrap())",
        "measure(|| candidate.close_all().unwrap())",
        "measure(|| black_box(&fixture).target_projection().unwrap())",
    ];
    if performance.matches("measure(||").count() != expected.len() {
        return Err(format!(
            "run_performance must contain exactly {} pinned measured operations",
            expected.len()
        ));
    }
    for operation in expected {
        if performance.matches(operation).count() != 1 {
            return Err(format!(
                "run_performance lacks exact measured operation {operation:?}"
            ));
        }
    }
    for required_outside_operation in [
        "Stage7bActiveFixture::new(case.config)",
        "fixture.clone()",
        "baseline.clone()",
        "check_invariants()",
        "print_samples(",
    ] {
        if !performance.contains(required_outside_operation) {
            return Err(format!(
                "run_performance lacks required out-of-interval operation {required_outside_operation:?}"
            ));
        }
    }
    for measured in call_arguments(performance, "measure(")? {
        for excluded in [
            "Stage7bActiveFixture::new",
            ".clone()",
            "check_invariants",
            "print_samples",
            "println!",
            "write!",
            "String::",
            "sort_unstable",
        ] {
            if measured.contains(excluded) {
                return Err(format!(
                    "measured interval contains excluded fixture/clone/invariant/serial work {excluded:?}"
                ));
            }
        }
    }
    Ok(())
}

fn source_region<'a>(
    source: &'a str,
    start: &str,
    end: &str,
    label: &str,
) -> Result<&'a str, String> {
    let start_offset = source
        .find(start)
        .ok_or_else(|| format!("{label} start marker is missing"))?;
    let tail = &source[start_offset..];
    let end_offset = tail
        .find(end)
        .ok_or_else(|| format!("{label} end marker is missing"))?;
    Ok(&tail[..end_offset])
}

fn call_arguments<'a>(source: &'a str, call: &str) -> Result<Vec<&'a str>, String> {
    let mut arguments = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = source[cursor..].find(call) {
        let start = cursor + relative + call.len();
        let bytes = source.as_bytes();
        let mut depth = 1_usize;
        let mut offset = start;
        let mut quoted = false;
        let mut escaped = false;
        while offset < bytes.len() {
            let byte = bytes[offset];
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
            } else if byte == b'"' {
                quoted = true;
            } else if byte == b'(' {
                depth += 1;
            } else if byte == b')' {
                depth -= 1;
                if depth == 0 {
                    arguments.push(&source[start..offset]);
                    cursor = offset + 1;
                    break;
                }
            }
            offset += 1;
        }
        if depth != 0 {
            return Err(format!("unterminated {call:?} call in source validator"));
        }
    }
    Ok(arguments)
}

fn validate_regular_repo_file(root: &Path, relative: &str, label: &str) -> Result<(), String> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "{label} is not a normalized repository-relative path: {relative:?}"
        ));
    }
    let full = root.join(path);
    let metadata =
        fs::symlink_metadata(&full).map_err(|error| format!("{label} {relative}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} is not a regular non-symlink file: {relative}"
        ));
    }
    Ok(())
}

fn semantic_race_ids(root: &Path, relative: &str) -> Result<Vec<String>, String> {
    validate_regular_repo_file(root, relative, "semantic race catalog")?;
    let source = read(root, relative)?;
    let value: toml::Value = toml::from_str(&source)
        .map_err(|error| format!("parse semantic race catalog {relative}: {error}"))?;
    let table = value
        .as_table()
        .ok_or_else(|| format!("semantic race catalog {relative} root is not a table"))?;
    if table.get("catalog").and_then(toml::Value::as_str) != Some("nexus.cser.races")
        || table.get("normative").and_then(toml::Value::as_bool) != Some(false)
    {
        return Err(
            "semantic race catalog boundary is not nexus.cser.races normative=false".into(),
        );
    }
    let races = table
        .get("race")
        .and_then(toml::Value::as_array)
        .ok_or("semantic race catalog lacks race array")?;
    races
        .iter()
        .enumerate()
        .map(|(index, race)| {
            race.as_table()
                .and_then(|race| race.get("id"))
                .and_then(toml::Value::as_str)
                .map(String::from)
                .ok_or_else(|| format!("semantic race[{index}] lacks a string id"))
        })
        .collect()
}

fn read(root: &Path, relative: &str) -> Result<String, String> {
    fs::read_to_string(root.join(relative)).map_err(|error| format!("read {relative}: {error}"))
}

fn expect_eq(field: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual != expected {
        return Err(format!(
            "{field} mismatch: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn expect_count(field: &str, actual: usize, expected: usize) -> Result<(), String> {
    if actual != expected {
        return Err(format!(
            "{field} mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn expect_strings(field: &str, actual: &[String], expected: &[&str]) -> Result<(), String> {
    let actual: Vec<_> = actual.iter().map(String::as_str).collect();
    if actual != expected {
        return Err(format!(
            "{field} order/set mismatch: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn expect_set(field: &str, actual: &BTreeSet<&str>, expected: &[&str]) -> Result<(), String> {
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    if actual != &expected {
        return Err(format!(
            "{field} mismatch: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> Contract {
        toml::from_str(include_str!("../../../evaluation/stage7b/contract.toml"))
            .expect("checked-in Stage 7B contract parses")
    }

    fn race_map() -> RaceMap {
        toml::from_str(include_str!("../../../evaluation/stage7b/cser-races.toml"))
            .expect("checked-in Stage 7B race map parses")
    }

    fn semantic_ids() -> Vec<String> {
        RACE_IDS.iter().map(|id| String::from(*id)).collect()
    }

    #[test]
    fn checked_in_static_contract_and_map_are_exact() {
        let contract = contract();
        validate_contract(&contract).unwrap();
        validate_race_map(&race_map(), &contract, &semantic_ids()).unwrap();
    }

    #[test]
    fn deny_unknown_fields_applies_to_both_inputs() {
        let bad_contract = include_str!("../../../evaluation/stage7b/contract.toml").replacen(
            "stage = \"7b\"",
            "stage = \"7b\"\nsurprise = true",
            1,
        );
        assert!(toml::from_str::<Contract>(&bad_contract).is_err());

        let bad_map = include_str!("../../../evaluation/stage7b/cser-races.toml").replacen(
            "expected_count = 14",
            "expected_count = 14\nsurprise = true",
            1,
        );
        assert!(toml::from_str::<RaceMap>(&bad_map).is_err());
    }

    #[test]
    fn rejects_missing_duplicate_unknown_and_reordered_races() {
        let contract = contract();
        let mut missing = race_map();
        missing.race.pop();
        assert!(validate_race_map(&missing, &contract, &semantic_ids()).is_err());

        let mut duplicate = race_map();
        duplicate.race[1].id = duplicate.race[0].id.clone();
        assert!(validate_race_map(&duplicate, &contract, &semantic_ids()).is_err());

        let mut unknown = race_map();
        unknown.race[0].id = String::from("unknown.race");
        assert!(validate_race_map(&unknown, &contract, &semantic_ids()).is_err());

        let mut reordered = race_map();
        reordered.race.swap(0, 1);
        assert!(validate_race_map(&reordered, &contract, &semantic_ids()).is_err());
    }

    #[test]
    fn rejects_model_source_missing_source_and_wrong_harness_mapping() {
        let contract = contract();
        let mut model = race_map();
        model.race[0].production_sources[0] = String::from("crates/cser-model/src/model.rs");
        assert!(validate_race_map(&model, &contract, &semantic_ids()).is_err());

        let mut missing = race_map();
        missing.race[0].production_sources.pop();
        assert!(validate_race_map(&missing, &contract, &semantic_ids()).is_err());

        let mut harness = race_map();
        harness.race[0].harness = HARNESSES[1].into();
        assert!(validate_race_map(&harness, &contract, &semantic_ids()).is_err());
    }

    #[test]
    fn rejects_unknown_or_uncovered_fault_cells() {
        let contract = contract();
        let mut unknown = race_map();
        unknown.race[0].fault_cells[0] = String::from("unknown.cell");
        assert!(validate_race_map(&unknown, &contract, &semantic_ids()).is_err());

        let mut uncovered = race_map();
        uncovered.race[11].fault_cells.pop();
        assert!(validate_race_map(&uncovered, &contract, &semantic_ids()).is_err());
    }

    #[test]
    fn rejects_empty_or_duplicate_oracle_gates() {
        let contract = contract();
        let mut empty = race_map();
        empty.race[0].positive_gate.clear();
        assert!(validate_race_map(&empty, &contract, &semantic_ids()).is_err());

        let mut duplicate = race_map();
        let repeated = duplicate.race[0].negative_gates[0].clone();
        duplicate.race[0].negative_gates.push(repeated);
        assert!(validate_race_map(&duplicate, &contract, &semantic_ids()).is_err());
    }

    #[test]
    fn rejects_missing_extra_and_reordered_assertion_markers() {
        let contract = contract();
        let mut missing = race_map();
        missing.race[0].assertion_markers.pop();
        assert!(validate_race_map(&missing, &contract, &semantic_ids()).is_err());

        let mut extra = race_map();
        extra.race[0]
            .assertion_markers
            .push(String::from("unknown-assertion"));
        assert!(validate_race_map(&extra, &contract, &semantic_ids()).is_err());

        let mut duplicate = race_map();
        let repeated = duplicate.race[0].assertion_markers[0].clone();
        duplicate.race[0].assertion_markers.push(repeated);
        assert!(validate_race_map(&duplicate, &contract, &semantic_ids()).is_err());

        let mut reordered = race_map();
        reordered.race[0].assertion_markers.swap(0, 1);
        assert!(validate_race_map(&reordered, &contract, &semantic_ids()).is_err());
    }

    #[test]
    fn rejects_scale_performance_prior_art_and_decision_drift() {
        let mut scale = contract();
        scale.scale.point[0].k = 1;
        assert!(validate_contract(&scale).is_err());

        let mut performance = contract();
        performance.performance.case.swap(0, 1);
        assert!(validate_contract(&performance).is_err());

        let mut prior = contract();
        prior.prior_art.required_row_ids.swap(0, 1);
        assert!(validate_contract(&prior).is_err());

        let mut decision = contract();
        decision.contribution.support_bounded_requires.pop();
        assert!(validate_contract(&decision).is_err());
    }

    #[test]
    fn scale_source_gate_rejects_hardcoded_metrics_and_untracked_scans() {
        let source = include_str!("../../../kernel/nexus-ostd/src/cser/effect_registry.rs");
        validate_scale_instrumentation_source(source).unwrap();

        let hardcoded = source.replacen(
            "begin_target_record_visits: revoke.work.begin_target_record_visits",
            "begin_target_record_visits: 0",
            1,
        );
        assert!(validate_scale_instrumentation_source(&hardcoded).is_err());

        let begin = source.replacen(
            "    ) -> Result<RevokeSelection, RegistryError> {\n        let (closed_authority_epoch",
            "    ) -> Result<RevokeSelection, RegistryError> {\n        let _untracked = self.effects.values().count();\n        let (closed_authority_epoch",
            1,
        );
        assert_ne!(begin, source);
        assert!(validate_scale_instrumentation_source(&begin).is_err());

        let global = source.replacen(
            "    ) -> Result<Option<RevokeEffect>, RegistryError> {\n        self.validate_revoke_selection(selection)?;",
            "    ) -> Result<Option<RevokeEffect>, RegistryError> {\n        let _untracked = self.effects.values().count();\n        self.validate_revoke_selection(selection)?;",
            1,
        );
        assert_ne!(global, source);
        assert!(validate_scale_instrumentation_source(&global).is_err());

        let direct = source.replacen(
            "    ) -> Result<Option<RevokeEffect>, RegistryError> {\n        self.validate_revoke_selection(selection)?;",
            "    ) -> Result<Option<RevokeEffect>, RegistryError> {\n        let _untracked = self.effects.get(&EffectKey::new(1, 1));\n        self.validate_revoke_selection(selection)?;",
            1,
        );
        assert_ne!(direct, source);
        assert!(validate_scale_instrumentation_source(&direct).is_err());

        let aliased = source.replacen(
            "let record = effects.get(&effect).ok_or(RegistryError::UnknownEffect)?;",
            "let alias = effects; let record = alias.get(&effect).ok_or(RegistryError::UnknownEffect)?;",
            1,
        );
        assert_ne!(aliased, source);
        assert!(validate_scale_instrumentation_source(&aliased).is_err());

        let history_untracked = source.replacen("Some(&mut work.history_effect_visits)", "None", 1);
        assert_ne!(history_untracked, source);
        assert!(validate_scale_instrumentation_source(&history_untracked).is_err());
    }

    #[test]
    fn io_instance_source_gate_rejects_copyable_gate_and_forgeable_identity() {
        let gate = include_str!("../../../crates/cser-transition-gates/src/io.rs");
        let portal = include_str!("../../../crates/nexus-ostd-virtio/src/portal.rs");
        validate_io_instance_source(gate, portal).unwrap();

        let copyable = gate.replacen(
            "#[derive(Debug, Eq, PartialEq)]\npub struct IoGate<const EFFECTS: usize>",
            "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct IoGate<const EFFECTS: usize>",
            1,
        );
        assert_ne!(copyable, gate);
        assert!(validate_io_instance_source(&copyable, portal).is_err());

        for (private, public) in [
            (
                "pub struct IoIdentity {\n    instance_id: u64,",
                "pub struct IoIdentity {\n    pub instance_id: u64,",
            ),
            (
                "    instance_id: u64,\n    request_id: u64,\n    authority_epoch: u64,",
                "    instance_id: u64,\n    pub request_id: u64,\n    authority_epoch: u64,",
            ),
        ] {
            let forgeable = gate.replacen(private, public, 1);
            assert_ne!(forgeable, gate);
            assert!(validate_io_instance_source(&forgeable, portal).is_err());
        }

        let copied_probe = portal.replacen(
            "self.gate.can_complete_device(authority)",
            "{ let mut probe = self.gate; probe.complete_device(authority).is_ok() }",
            1,
        );
        assert_ne!(copied_probe, portal);
        assert!(validate_io_instance_source(gate, &copied_probe).is_err());

        let constant_namespace = portal.replacen("IoGate::new(instance_id)", "IoGate::new(1)", 1);
        assert_ne!(constant_namespace, portal);
        assert!(validate_io_instance_source(gate, &constant_namespace).is_err());

        let unbound_session = portal.replacen(
            "authority.instance_id() != self.gate.instance_id()",
            "self.gate.instance_id() == 0",
            1,
        );
        assert_ne!(unbound_session, portal);
        assert!(validate_io_instance_source(gate, &unbound_session).is_err());

        let raw_session_constructor = portal.replacen(
            "fn open_bound(root: &mut Root, binding: SessionBinding)",
            "pub fn open(root: &mut Root, binding: SessionBinding)",
            1,
        );
        assert_ne!(raw_session_constructor, portal);
        assert!(validate_io_instance_source(gate, &raw_session_constructor).is_err());

        let invalid_bdf_allowed = portal.replacen(
            "    assert!(\n        device_function.valid(),\n        \"invalid PCI device function namespace\"\n    );\n",
            "",
            1,
        );
        assert_ne!(invalid_bdf_allowed, portal);
        assert!(validate_io_instance_source(gate, &invalid_bdf_allowed).is_err());

        let missing_left_validity = portal.replacen("    assert!(LEFT_DEVICE.valid());\n", "", 1);
        assert_ne!(missing_left_validity, portal);
        assert!(validate_io_instance_source(gate, &missing_left_validity).is_err());

        let missing_direction = portal.replacen(
            "right.bind_session_authority(left_authority)",
            "right.bind_session_authority(right_authority)",
            1,
        );
        assert_ne!(missing_direction, portal);
        assert!(validate_io_instance_source(gate, &missing_direction).is_err());

        let early_receipt = portal
            .replacen(
                "    SessionNamespaceIsolationReceipt {\n        marker: \"IO Namespace foreign_bdf_rejected=true bidirectional=true portal_state_unchanged=true pre_pci_dma=true\",\n    }",
                "    receipt",
                1,
            )
            .replacen(
                "    let own = left.bind_session_authority(left_authority).unwrap();",
                "    let receipt = SessionNamespaceIsolationReceipt {\n        marker: \"IO Namespace foreign_bdf_rejected=true bidirectional=true portal_state_unchanged=true pre_pci_dma=true\",\n    };\n    let own = left.bind_session_authority(left_authority).unwrap();",
                1,
            );
        assert_ne!(early_receipt, portal);
        assert!(validate_io_instance_source(gate, &early_receipt).is_err());

        let aliased_receipt = format!(
            "{portal}\ntype NamespaceReceiptAlias = SessionNamespaceIsolationReceipt;\nimpl Clone for NamespaceReceiptAlias {{\n    fn clone(&self) -> Self {{ unreachable!() }}\n}}\n"
        );
        assert_ne!(aliased_receipt, portal);
        assert!(validate_io_instance_source(gate, &aliased_receipt).is_err());

        let unbound_receipt = gate.replacen(
            "            || close.instance_id != self.instance_id\n",
            "",
            1,
        );
        assert_ne!(unbound_receipt, gate);
        assert!(validate_io_instance_source(&unbound_receipt, portal).is_err());

        let dropped_provenance =
            gate.replacen("            instance_id: self.instance_id,\n", "", 1);
        assert_ne!(dropped_provenance, gate);
        assert!(validate_io_instance_source(&dropped_provenance, portal).is_err());
    }

    #[test]
    fn io_entrypoint_gate_rejects_marker_only_or_post_pci_namespace_negative() {
        let entry = include_str!("../../../experiments/ostd-virtio-cser-spike/src/lib.rs");
        validate_io_entrypoint_source(entry).unwrap();

        let negative_call = "    let namespace_isolation = assert_session_namespace_isolation();\n";
        let negative_marker = "    println!(\"{}\", namespace_isolation.into_marker());\n";
        let missing = entry.replacen(negative_call, "", 1);
        assert_ne!(missing, entry);
        assert!(validate_io_entrypoint_source(&missing).is_err());

        let discovery = "    let mut root = discover_and_own_bars();";
        let late = entry
            .replacen(negative_call, "", 1)
            .replacen(negative_marker, "", 1)
            .replacen(
                discovery,
                &format!("{discovery}\n{negative_call}{negative_marker}"),
                1,
            );
        assert_ne!(late, entry);
        assert!(validate_io_entrypoint_source(&late).is_err());

        let conditional = entry
            .replacen(
                negative_call,
                &format!("    if false {{\n{negative_call}"),
                1,
            )
            .replacen(negative_marker, &format!("{negative_marker}    }}\n"), 1);
        assert_ne!(conditional, entry);
        assert!(validate_io_entrypoint_source(&conditional).is_err());

        let fabricated = entry.replacen(
            negative_marker,
            "    println!(\"IO Namespace foreign_bdf_rejected=true bidirectional=true portal_state_unchanged=true pre_pci_dma=true\");\n",
            1,
        );
        assert_ne!(fabricated, entry);
        assert!(validate_io_entrypoint_source(&fabricated).is_err());
    }

    #[test]
    fn oneshot_source_gate_rejects_copy_forge_detach_and_replay_mutations() {
        let gate = include_str!("../../../crates/cser-transition-gates/src/oneshot.rs");
        let effect = include_str!("../../../kernel/nexus-ostd/src/cser/effect.rs");
        let oneshot = include_str!("../../../crates/cser-transition-gates/tests/oneshot_loom.rs");
        let registry = include_str!("../../../crates/cser-transition-gates/tests/registry_loom.rs");
        validate_oneshot_provenance_source(gate, effect, oneshot, registry).unwrap();

        for mutation in [
            gate.replacen(
                "#[derive(Debug, Eq, PartialEq)]\npub struct OneShotGate",
                "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct OneShotGate",
                1,
            ),
            gate.replacen(
                "#[derive(Debug, Eq, PartialEq)]\npub struct TerminalReceipt",
                "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct TerminalReceipt",
                1,
            ),
            gate.replacen("    instance_id: u64,", "    pub instance_id: u64,", 1),
            gate.replacen(
                "        if token.gate_nonce != self.token.gate_nonce || token.instance_id != self.token.instance_id\n        {",
                "        if false {",
                1,
            ),
            gate.replacen(
                "        let gate_nonce = next_gate_nonce()?;",
                "        let gate_nonce = instance_id;",
                1,
            ),
            gate.replacen("            current.checked_add(1)", "            Some(current)", 1),
            format!(
                "{gate}\nimpl<T: Copy + Eq> Clone for OneShotGate<T> {{\n    fn clone(&self) -> Self {{ unreachable!() }}\n}}\n"
            ),
            format!(
                "{gate}\nimpl<T: Copy + Eq> core::clone::Clone for self::OneShotGate<T> {{\n    fn clone(&self) -> Self {{ unreachable!() }}\n}}\n"
            ),
            format!(
                "{gate}\ntype GateAlias<T> = OneShotGate<T>;\nimpl<T: Copy + Eq> Clone for GateAlias<T> {{\n    fn clone(&self) -> Self {{ unreachable!() }}\n}}\n"
            ),
            gate.replacen(
                "impl OneShotToken {",
                "impl OneShotToken {\n    pub const fn from_raw(instance_id: u64, id: u64, generation: u64) -> Self {\n        Self { instance_id, id, generation }\n    }\n",
                1,
            ),
            gate.replacen(
                "impl<T: Copy + Eq> TerminalReceipt<T> {",
                "impl<T: Copy + Eq> TerminalReceipt<T> {\n    pub const fn from_raw(token: OneShotToken, outcome: T) -> Self {\n        Self { token, outcome }\n    }\n",
                1,
            ),
            format!(
                "{gate}\nimpl OneShotToken {{\n    pub const fn from_raw(instance_id: u64, id: u64, generation: u64) -> Self {{ Self {{ instance_id, id, generation }} }}\n}}\n"
            ),
            format!(
                "{gate}\nimpl<T: Copy + Eq> TerminalReceipt<T> {{\n    pub const fn from_raw(token: OneShotToken, outcome: T) -> Self {{ Self {{ token, outcome }} }}\n}}\n"
            ),
        ] {
            assert_ne!(mutation, gate);
            assert!(
                validate_oneshot_provenance_source(&mutation, effect, oneshot, registry).is_err()
            );
        }

        let constant_instance = effect.replacen(
            "OneShotGate::new(token.scope_id, token.effect_id, token.authority_epoch)",
            "OneShotGate::new(1, token.effect_id, token.authority_epoch)",
            1,
        );
        assert_ne!(constant_instance, effect);
        assert!(
            validate_oneshot_provenance_source(gate, &constant_instance, oneshot, registry)
                .is_err()
        );

        let dropped_consume = oneshot.replacen(
            "                self.terminal.consume_terminal(&receipt).unwrap();\n",
            "",
            1,
        );
        assert_ne!(dropped_consume, oneshot);
        assert!(
            validate_oneshot_provenance_source(gate, effect, &dropped_consume, registry).is_err()
        );

        let reconstructed_same_outcome = oneshot.replacen(
            "        first.consume_terminal(&reconstructed_receipt),\n        Err(OneShotError::ForeignInstance)",
            "        first.consume_terminal(&reconstructed_receipt),\n        Ok(())",
            1,
        );
        assert_ne!(reconstructed_same_outcome, oneshot);
        assert!(
            validate_oneshot_provenance_source(
                gate,
                effect,
                &reconstructed_same_outcome,
                registry,
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_registry_source_gate_rejects_decoupled_winner_and_loser_paths() {
        let oneshot = include_str!("../../../crates/cser-transition-gates/tests/oneshot_loom.rs");
        let registry = include_str!("../../../crates/cser-transition-gates/tests/registry_loom.rs");
        validate_terminal_registry_coupling_source(oneshot, registry).unwrap();

        let wrong_success = oneshot.replacen(
            "TerminalRequest::completed_by(outcome.registry_result(), commit.clone())",
            "TerminalRequest::aborted(outcome.registry_result())",
            1,
        );
        assert_ne!(wrong_success, oneshot);
        assert!(validate_terminal_registry_coupling_source(&wrong_success, registry).is_err());

        let missing_continuation_projection = oneshot.replacen(
            "                        self.continuation.failure_atomic_projection(),\n                        before_continuation",
            "                        before_continuation,\n                        before_continuation",
            1,
        );
        assert_ne!(missing_continuation_projection, oneshot);
        assert!(
            validate_terminal_registry_coupling_source(&missing_continuation_projection, registry,)
                .is_err()
        );

        let missing_winner_close = registry.replacen(
            "                    self.close_from_winner(&receipt);\n",
            "",
            1,
        );
        assert_ne!(missing_winner_close, registry);
        assert!(
            validate_terminal_registry_coupling_source(oneshot, &missing_winner_close).is_err()
        );

        let missing_loser_guard = registry.replacen(
            "                assert_eq!(self.projection(), *before);\n",
            "",
            1,
        );
        assert_ne!(missing_loser_guard, registry);
        assert!(validate_terminal_registry_coupling_source(oneshot, &missing_loser_guard).is_err());
    }

    #[test]
    fn performance_source_gate_keeps_excluded_work_outside_measurement() {
        let source = include_str!("../../../kernel/nexus-ostd/src/evaluation/stage7b.rs");
        validate_performance_measurement_source(source).unwrap();

        for excluded in [
            "Stage7bActiveFixture::new(case.config).unwrap()",
            "fixture.clone()",
            "fixture.check_invariants().unwrap()",
            "println!(\"serial\")",
        ] {
            let mutation = source.replacen(
                "measure(|| candidate.begin().unwrap())",
                &format!(
                    "measure(|| {{ let _excluded = {{ {excluded} }}; candidate.begin().unwrap() }})"
                ),
                1,
            );
            assert_ne!(mutation, source);
            assert!(validate_performance_measurement_source(&mutation).is_err());
        }
    }

    #[test]
    fn rejects_semantic_catalog_mismatch() {
        let contract = contract();
        let mut ids = semantic_ids();
        ids.swap(0, 1);
        assert!(validate_race_map(&race_map(), &contract, &ids).is_err());
    }

    #[test]
    fn rejects_non_normalized_missing_or_symlink_paths() {
        assert!(validate_regular_repo_file(Path::new("/tmp"), "../escape", "test").is_err());
        assert!(
            validate_regular_repo_file(Path::new("/tmp"), "definitely-missing", "test").is_err()
        );

        let root = std::env::temp_dir().join(format!("nexus-stage7b-path-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("source.rs"), "fn source() {}\n").unwrap();
        std::os::unix::fs::symlink("source.rs", root.join("link.rs")).unwrap();
        assert!(validate_regular_repo_file(&root, "link.rs", "test").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
