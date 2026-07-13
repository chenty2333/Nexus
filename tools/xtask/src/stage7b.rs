use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

const CONTRACT_PATH: &str = "evaluation/stage7b/contract.toml";
const RACE_MAP_PATH: &str = "evaluation/stage7b/cser-races.toml";

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
];

const SCALE_METRICS: &[&str] = &[
    "target_count",
    "begin_target_record_visits",
    "next_calls",
    "head_selections",
    "terminalized",
    "completion_members_checked",
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
    },
    ExpectedRace {
        id: RACE_IDS[1],
        sources: &[PRODUCTION_SOURCES[0], PRODUCTION_SOURCES[5]],
        harness: HARNESSES[0],
        harness_case: "cancel_vs_wake_single_winner",
        fault_cells: &[FAULT_CELL_IDS[13]],
        positive_gate: "cancel and wake have one applied terminal result and remove all live memberships",
        negative_gates: &["late-wake-mutates-cancelled-wait", "credit-returned-twice"],
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
    },
    ExpectedRace {
        id: RACE_IDS[5],
        sources: &[PRODUCTION_SOURCES[3]],
        harness: HARNESSES[3],
        harness_case: "old_binding_reply_after_rebind",
        fault_cells: &[FAULT_CELL_IDS[8], FAULT_CELL_IDS[9]],
        positive_gate: "the old reply is rejected before page-table, continuation, or credit mutation",
        negative_gates: &[
            "old-reply-consumes-continuation",
            "old-reply-publishes-pte",
            "double-resume",
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
    },
    ExpectedRace {
        id: RACE_IDS[7],
        sources: &[PRODUCTION_SOURCES[0], PRODUCTION_SOURCES[5]],
        harness: HARNESSES[0],
        harness_case: "resolve_vs_abort_one_shot",
        fault_cells: &[FAULT_CELL_IDS[9]],
        positive_gate: "resolve and abort consume one terminal authority and one waker at most once",
        negative_gates: &[
            "second-resume",
            "resolve-after-abort",
            "abort-after-resolve",
            "token-reuse",
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
    },
    ExpectedRace {
        id: RACE_IDS[12],
        sources: &[PRODUCTION_SOURCES[4]],
        harness: HARNESSES[4],
        harness_case: "publish_vs_revoke_commit_gate",
        fault_cells: &[FAULT_CELL_IDS[15], FAULT_CELL_IDS[16]],
        positive_gate: "publication and revoke have one order, with uncommitted losers aborted and committed winners drained or reset",
        negative_gates: &[
            "dma-owner-freed-on-software-cancel",
            "committed-request-reported-rolled-back",
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
        if !harness.lines().any(|line| {
            let line = line.trim_start();
            line.starts_with(&stable) || line.starts_with(&prefixed)
        }) {
            return Err(format!(
                "race[{index}] harness {:?} does not define stable case {:?} (with optional loom_ prefix)",
                race.harness, race.harness_case
            ));
        }
    }
    Ok(())
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
