use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const INPUT: &str = "kernel/nexus-ostd/artifacts/stage7b-evaluation.log";
const RUNTIME_METADATA: &str = "kernel/nexus-ostd/artifacts/stage7b-runtime-metadata.env";
const EVALUATOR_SOURCE: &str = "kernel/nexus-ostd/src/evaluation/stage7b.rs";
const FAULT_REGISTRY_SOURCE: &str = "kernel/nexus-ostd/src/cser/effect_registry.rs";
const OUTPUT_DIRECTORY: &str = "target/verification/stage7b";
const FAULT_OUTPUT: &str = "fault-matrix.jsonl";
const SCALE_OUTPUT: &str = "scale.jsonl";
const PERFORMANCE_OUTPUT: &str = "performance.json";
const ORACLE_OUTPUT: &str = "oracle.log";

const FAULT_FIELDS: &[&str] = &[
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

const SCALE_FIELDS: &[&str] = &[
    "point",
    "N",
    "k",
    "H",
    "target_count",
    "begin_target_record_visits",
    "next_calls",
    "head_selections",
    "terminalized",
    "completion_members_checked",
    "target_index_removals",
    "unrelated_effect_visits",
    "history_effect_visits",
    "pending_targets",
    "final_target_state",
    "status",
];

const META_FIELDS: &[&str] = &[
    "profile",
    "accel",
    "vcpus",
    "threads",
    "cache",
    "timer",
    "fence",
    "preemption",
    "local_irq",
    "warmups",
    "samples",
    "empty_samples",
    "adjusted",
    "raw_retained",
    "thresholds",
];

const EMPTY_FIELDS: &[&str] = &["samples", "min", "median", "p95", "max", "raw"];
const PERFORMANCE_FIELDS: &[&str] = &[
    "case", "op", "N", "k", "H", "samples", "min", "median", "p95", "max", "raw", "status",
];

#[derive(Clone, Copy)]
struct FaultSpec {
    id: &'static str,
    family: &'static str,
    injection: &'static str,
    terminal: &'static str,
    terminalizations: u64,
    publications: u64,
    credits: u64,
    retained: bool,
}

#[derive(Clone, Copy)]
struct OwnershipSpec {
    credits: u64,
    retained: bool,
}

const fn ownership(credits: u64, retained: bool) -> OwnershipSpec {
    OwnershipSpec { credits, retained }
}

const fn fault(
    id: &'static str,
    family: &'static str,
    injection: &'static str,
    terminal: &'static str,
    terminalizations: u64,
    publications: u64,
    ownership: OwnershipSpec,
) -> FaultSpec {
    FaultSpec {
        id,
        family,
        injection,
        terminal,
        terminalizations,
        publications,
        credits: ownership.credits,
        retained: ownership.retained,
    }
}

const FAULTS: &[FaultSpec] = &[
    fault(
        "scheduler.lease-expiry-before-proposal",
        "scheduler",
        "lease-expiry",
        "FallbackPick",
        1,
        1,
        ownership(0, false),
    ),
    fault(
        "scheduler.crash-after-proposal-before-pick",
        "scheduler",
        "after-proposal",
        "FallbackPick",
        1,
        1,
        ownership(0, false),
    ),
    fault(
        "scheduler.stale-proposal-before-rebind",
        "scheduler",
        "before-rebind",
        "FallbackPick",
        1,
        1,
        ownership(0, false),
    ),
    fault(
        "scheduler.stale-proposal-after-rebind",
        "scheduler",
        "after-rebind",
        "FallbackPick",
        1,
        1,
        ownership(0, false),
    ),
    fault(
        "scheduler.repeated-crash-fallback-progress",
        "scheduler",
        "repeated-crash",
        "FallbackPick",
        1,
        1,
        ownership(0, false),
    ),
    fault(
        "pager.same-page-concurrent-fault",
        "pager",
        "same-page-register",
        "Resolved",
        2,
        1,
        ownership(2, false),
    ),
    fault(
        "pager.crash-before-prepare",
        "pager",
        "before-prepare",
        "Aborted",
        1,
        0,
        ownership(1, false),
    ),
    fault(
        "pager.crash-after-prepare-before-commit",
        "pager",
        "after-prepare",
        "Aborted",
        1,
        0,
        ownership(1, false),
    ),
    fault(
        "pager.crash-after-commit-before-resume",
        "pager",
        "after-commit",
        "Resolved",
        1,
        1,
        ownership(1, false),
    ),
    fault(
        "pager.timeout-vs-late-reply",
        "pager",
        "timeout-before-late-reply",
        "Aborted",
        1,
        0,
        ownership(1, false),
    ),
    fault(
        "personality-readiness.crash-before-backend-commit",
        "personality-readiness",
        "before-backend-commit",
        "Aborted",
        1,
        0,
        ownership(1, false),
    ),
    fault(
        "personality-readiness.crash-after-backend-commit",
        "personality-readiness",
        "after-backend-commit",
        "Completed",
        1,
        1,
        ownership(1, false),
    ),
    fault(
        "personality-readiness.ready-vs-timeout",
        "personality-readiness",
        "ready-first",
        "Ready",
        1,
        1,
        ownership(1, false),
    ),
    fault(
        "personality-readiness.revoke-vs-ready",
        "personality-readiness",
        "revoke-first",
        "Aborted",
        1,
        0,
        ownership(1, false),
    ),
    fault(
        "personality-readiness.stale-deadline-after-rearm",
        "personality-readiness",
        "old-deadline-after-rearm",
        "TimedOut",
        1,
        0,
        ownership(1, false),
    ),
    fault(
        "linux-io.revoke-before-device-publication",
        "linux-io",
        "before-device-publication",
        "AbortedBeforeCommit",
        1,
        0,
        ownership(1, false),
    ),
    fault(
        "linux-io.completion-vs-reset-ack",
        "linux-io",
        "reset-ack-first",
        "IndeterminateAfterReset",
        1,
        1,
        ownership(1, true),
    ),
    fault(
        "linux-io.reset-timeout-retry",
        "linux-io",
        "reset-timeout-retry",
        "IndeterminateAfterReset",
        1,
        1,
        ownership(1, true),
    ),
    fault(
        "linux-io.iotlb-timeout-late-ack",
        "linux-io",
        "iotlb-timeout-late-ack",
        "Quiesced",
        1,
        1,
        ownership(1, true),
    ),
    fault(
        "linux-io.stale-duplicate-completion",
        "linux-io",
        "duplicate-completion",
        "Completed",
        1,
        1,
        ownership(1, false),
    ),
];

#[derive(Clone, Copy)]
struct ScaleSpec {
    id: &'static str,
    n: u64,
    k: u64,
    history: u64,
}

const SCALES: &[ScaleSpec] = &[
    scale("fixed-n.k0000", 1024, 0, 0),
    scale("fixed-n.k0001", 1024, 1, 0),
    scale("fixed-n.k0008", 1024, 8, 0),
    scale("fixed-n.k0032", 1024, 32, 0),
    scale("fixed-n.k0128", 1024, 128, 0),
    scale("fixed-n.k0512", 1024, 512, 0),
    scale("fixed-k.n0032", 32, 32, 0),
    scale("fixed-k.n0128", 128, 32, 0),
    scale("fixed-k.n0512", 512, 32, 0),
    scale("fixed-k.n2048", 2048, 32, 0),
    scale("fixed-k.n4096", 4096, 32, 0),
    scale("history.h0000", 1024, 32, 0),
    scale("history.h0064", 1024, 32, 64),
    scale("history.h1024", 1024, 32, 1024),
];

const fn scale(id: &'static str, n: u64, k: u64, history: u64) -> ScaleSpec {
    ScaleSpec { id, n, k, history }
}

#[derive(Clone, Copy)]
struct PerformanceSpec {
    id: &'static str,
    operation: &'static str,
    scale: ScaleSpec,
}

const PERFORMANCE: &[PerformanceSpec] = &[
    perf("begin.fixed-n.k0000", "begin", SCALES[0]),
    perf("begin.fixed-n.k0001", "begin", SCALES[1]),
    perf("begin.fixed-n.k0008", "begin", SCALES[2]),
    perf("begin.fixed-n.k0032", "begin", SCALES[3]),
    perf("begin.fixed-n.k0128", "begin", SCALES[4]),
    perf("begin.fixed-n.k0512", "begin", SCALES[5]),
    perf("complete.fixed-n.k0000", "complete", SCALES[0]),
    perf("complete.fixed-n.k0001", "complete", SCALES[1]),
    perf("complete.fixed-n.k0008", "complete", SCALES[2]),
    perf("complete.fixed-n.k0032", "complete", SCALES[3]),
    perf("complete.fixed-n.k0128", "complete", SCALES[4]),
    perf("complete.fixed-n.k0512", "complete", SCALES[5]),
    perf("closure.fixed-n.k0000", "closure", SCALES[0]),
    perf("closure.fixed-n.k0001", "closure", SCALES[1]),
    perf("closure.fixed-n.k0008", "closure", SCALES[2]),
    perf("closure.fixed-n.k0032", "closure", SCALES[3]),
    perf("closure.fixed-n.k0128", "closure", SCALES[4]),
    perf("closure.fixed-n.k0512", "closure", SCALES[5]),
    perf("closure.fixed-k.n0032", "closure", SCALES[6]),
    perf("closure.fixed-k.n0128", "closure", SCALES[7]),
    perf("closure.fixed-k.n0512", "closure", SCALES[8]),
    perf("closure.fixed-k.n2048", "closure", SCALES[9]),
    perf("closure.fixed-k.n4096", "closure", SCALES[10]),
    perf("closure.history.h0000", "closure", SCALES[11]),
    perf("closure.history.h0064", "closure", SCALES[12]),
    perf("closure.history.h1024", "closure", SCALES[13]),
    perf("projection.history.h0000", "projection", SCALES[11]),
    perf("projection.history.h0064", "projection", SCALES[12]),
    perf("projection.history.h1024", "projection", SCALES[13]),
];

const fn perf(id: &'static str, operation: &'static str, scale: ScaleSpec) -> PerformanceSpec {
    PerformanceSpec {
        id,
        operation,
        scale,
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Summary {
    pub(crate) fault_cells: usize,
    pub(crate) scale_points: usize,
    pub(crate) performance_cases: usize,
    pub(crate) runtime_metadata: bool,
}

#[derive(Serialize)]
struct FaultEvidence {
    id: String,
    family: String,
    injection_point: String,
    expected_terminal: String,
    observed_terminal: String,
    terminalizations: u64,
    publications: u64,
    credits_before: u64,
    credits_after: u64,
    retained_before_quiescence: bool,
    final_quiescent: bool,
    status: &'static str,
}

#[derive(Serialize)]
struct ScaleEvidence {
    id: String,
    n: u64,
    k: u64,
    history: u64,
    target_count: u64,
    begin_target_record_visits: u64,
    next_calls: u64,
    head_selections: u64,
    terminalized: u64,
    completion_members_checked: u64,
    target_index_removals: u64,
    unrelated_effect_visits: u64,
    history_effect_visits: u64,
    pending_targets: u64,
    final_target_state: String,
    status: &'static str,
}

#[derive(Serialize)]
struct PerformanceEvidence {
    schema: &'static str,
    status: &'static str,
    claim: &'static str,
    thresholds: Option<u64>,
    environment: PerformanceEnvironment,
    runtime_metadata: Option<RuntimeMetadata>,
    empty_timer: SampleSet,
    cases: Vec<PerformanceCase>,
}

#[derive(Serialize)]
struct PerformanceEnvironment {
    profile: String,
    accel: String,
    vcpus: u64,
    threads: u64,
    cache: String,
    timer: String,
    fence: String,
    preemption: String,
    local_irq: String,
    warmups: u64,
    samples: u64,
    empty_samples: u64,
    adjusted: bool,
    raw_retained: bool,
}

#[derive(Serialize)]
struct RuntimeMetadata {
    schema: String,
    accel: String,
    vcpus: u64,
    threads: u64,
    cpu_pin: u64,
    cpus_allowed_list: String,
}

#[derive(Serialize)]
struct SampleSet {
    samples: usize,
    min: u64,
    median: u64,
    p95: u64,
    max: u64,
    raw: Vec<u64>,
    status: &'static str,
}

#[derive(Serialize)]
struct PerformanceCase {
    id: String,
    operation: String,
    n: u64,
    k: u64,
    history: u64,
    samples: usize,
    min: u64,
    median: u64,
    p95: u64,
    max: u64,
    raw: Vec<u64>,
    status: &'static str,
}

struct ParsedEvidence {
    faults: Vec<FaultEvidence>,
    scales: Vec<ScaleEvidence>,
    performance: PerformanceEvidence,
}

pub(crate) fn run(root: &Path) -> Result<Summary, String> {
    let output = root.join(OUTPUT_DIRECTORY);
    fs::create_dir_all(&output).map_err(|error| format!("create {}: {error}", output.display()))?;
    clear_outputs(&output)?;
    validate_fault_sources(root)?;

    let log = read_regular(root, INPUT, false)?
        .ok_or_else(|| format!("required Stage 7B evaluation log is missing: {INPUT}"))?;
    let metadata_source = read_regular(root, RUNTIME_METADATA, true)?;
    let metadata = metadata_source
        .as_deref()
        .map(parse_runtime_metadata)
        .transpose()?;
    let parsed = parse_log(&log, metadata)?;

    let faults = json_lines(&parsed.faults)?;
    let scales = json_lines(&parsed.scales)?;
    let performance = pretty_json(&parsed.performance)?;
    let oracle = format!(
        "schema=nexus.stage7b.runtime-oracle.v1\nstatus=passed\nfault_source=typed-receipt-projection-checked\nfault_cells={}\nfault_registry_backed_nonzero_credit_cells=15\nfault_scheduler_typed_no_credit_witnesses=5\nfault_registry_scope=case-local\nfault_shared_production_scope_claimed=false\nfault_cross_object_crash_panic_atomicity_claimed=false\nscale_points={}\nperformance_cases={}\nruntime_metadata={}\nperformance_claim=Observed\nperformance_thresholds=none\n",
        parsed.faults.len(),
        parsed.scales.len(),
        parsed.performance.cases.len(),
        parsed.performance.runtime_metadata.is_some(),
    );

    atomic_write(&output, FAULT_OUTPUT, faults.as_bytes())?;
    atomic_write(&output, SCALE_OUTPUT, scales.as_bytes())?;
    atomic_write(&output, PERFORMANCE_OUTPUT, performance.as_bytes())?;
    atomic_write(&output, ORACLE_OUTPUT, oracle.as_bytes())?;

    Ok(Summary {
        fault_cells: parsed.faults.len(),
        scale_points: parsed.scales.len(),
        performance_cases: parsed.performance.cases.len(),
        runtime_metadata: parsed.performance.runtime_metadata.is_some(),
    })
}

fn validate_fault_sources(root: &Path) -> Result<(), String> {
    let source = read_regular(root, EVALUATOR_SOURCE, false)?.ok_or_else(|| {
        format!("required Stage 7B evaluator source is missing: {EVALUATOR_SOURCE}")
    })?;
    let registry = read_regular(root, FAULT_REGISTRY_SOURCE, false)?.ok_or_else(|| {
        format!("required Stage 7B fault Registry source is missing: {FAULT_REGISTRY_SOURCE}")
    })?;
    validate_fault_evaluator_source_text(&source)?;
    validate_fault_registry_source_text(&registry)
}

fn validate_fault_registry_source_text(source: &str) -> Result<(), String> {
    let registry_constructors = source.matches("EffectRegistry::new()").count();
    if registry_constructors != 9 {
        return Err(format!(
            "Stage 7B Registry source constructor population drifted; hidden sidecars are forbidden (expected 9, observed {registry_constructors})"
        ));
    }

    let atomic_start = source
        .find("fn stage7b_registry_refactor_self_test() {")
        .ok_or_else(|| "Stage 7B Registry lacks its implementation self-test".to_owned())?;
    let atomic_end = source[atomic_start..]
        .find("    let config = Stage7bFixtureConfig { n: 8, k: 3, h: 2 };")
        .map(|offset| atomic_start + offset)
        .ok_or_else(|| {
            "Stage 7B Registry lacks the end of its counter-overflow fixture".to_owned()
        })?;
    let atomic = &source[atomic_start..atomic_end];
    if atomic.matches("EffectRegistry::new()").count() != 1
        || atomic
            .matches("let mut atomic = EffectRegistry::new();")
            .count()
            != 1
        || atomic
            .matches("Err(RegistryError::CounterOverflow)")
            .count()
            != 4
        || atomic.matches("assert_eq!(atomic, before);").count() != 4
    {
        return Err(
            "Stage 7B Registry counter-overflow fixture must own exactly one implementation Registry and four failure-atomic rejection checks"
                .into(),
        );
    }

    let production_start = source
        .find("pub(crate) fn production_identity_registry_self_test() {")
        .ok_or_else(|| {
            "Stage 7B Registry lacks the production-identity implementation self-test".to_owned()
        })?;
    let production_end = source[production_start..]
        .find("pub(crate) fn bounded_registry_self_test() -> RegistrySelfTestReceipt {")
        .map(|offset| production_start + offset)
        .ok_or_else(|| {
            "Stage 7B Registry production-identity self-test boundary is unterminated".to_owned()
        })?;
    let production = &source[production_start..production_end];
    if production.matches("EffectRegistry::new()").count() != 1
        || production
            .matches("let mut registry = EffectRegistry::new();")
            .count()
            != 1
        || production.matches(".register_derived(").count() != 4
    {
        return Err(
            "production-identity implementation self-test must own exactly one Registry and the exact three-effect plus stale-parent registration population"
                .into(),
        );
    }
    for required in [
        "registry.add_domain(scope, config).unwrap();",
        ".crash_domain(scope, FILESYSTEM_DOMAIN, filesystem_v1)",
        ".rebind_domain(scope, FILESYSTEM_DOMAIN, filesystem_v2)",
        ".adopt_domain(scope, FILESYSTEM_DOMAIN, filesystem_v2, recovery.handle)",
        "let selection = registry.revoke_begin(scope).unwrap();",
        "let next = registry.revoke_next(&selection).unwrap().unwrap();",
        "assert!(registry.revoke_next(&selection).unwrap().is_none());",
    ] {
        if !production.contains(required) {
            return Err(format!(
                "production-identity implementation self-test lacks required transition: {required}"
            ));
        }
    }
    let bounded_self_test = &source[production_end..];
    if production.contains("Stage7bFaultCredit")
        || production.contains("Stage7bFaultBudget")
        || source
            .matches("production_identity_registry_self_test();")
            .count()
            != 1
        || bounded_self_test
            .matches("production_identity_registry_self_test();")
            .count()
            != 1
    {
        return Err(
            "production-identity Registry coverage must remain one implementation self-test call, not shared Stage 7B fault-matrix evidence"
                .into(),
        );
    }

    let helper_start = source
        .find("pub(crate) struct Stage7bFaultCredit {")
        .ok_or_else(|| "Stage 7B fault Registry lacks linear credit helper".to_owned())?;
    let helper_end = source
        .find("pub(crate) struct Stage7bNoCreditProjection {")
        .ok_or_else(|| "Stage 7B fault Registry lacks typed no-credit boundary".to_owned())?;
    if helper_end <= helper_start {
        return Err("Stage 7B fault Registry helper boundary is inverted".into());
    }
    let helper = &source[helper_start..helper_end];
    if helper.contains("Stage7bActiveFixture") || helper.contains("run_registry_") {
        return Err("Stage 7B fault Registry helper contains a detached fixture sidecar".into());
    }
    let registries = helper.matches("EffectRegistry::new()").count();
    if registries != 1 {
        return Err(format!(
            "Stage 7B fault Registry helper must own exactly one production Registry, observed {registries}"
        ));
    }
    let expected_budget = concat!(
        "#[derive(Debug, Eq, PartialEq)]\n",
        "pub(crate) struct Stage7bFaultBudget {\n",
        "    case: Stage7bFaultCase,\n",
        "    instance_id: u64,\n",
        "    registry: EffectRegistry,\n",
        "    scope: ScopeKey,\n",
        "    task: TaskKey,\n",
        "    credit: CreditClass,\n",
        "    bindings: BTreeSet<Stage7bFaultBinding>,\n",
        "    commit_operations: usize,\n",
        "    terminal_operations: usize,\n",
        "}\n",
    );
    let expected_state = concat!(
        "#[derive(Clone, Debug, Eq, PartialEq)]\n",
        "pub(crate) struct Stage7bFaultBudgetState {\n",
        "    case: Stage7bFaultCase,\n",
        "    instance_id: u64,\n",
        "    registry: EffectRegistry,\n",
        "    scope: ScopeKey,\n",
        "    task: TaskKey,\n",
        "    credit: CreditClass,\n",
        "    bindings: BTreeSet<Stage7bFaultBinding>,\n",
        "    commit_operations: usize,\n",
        "    terminal_operations: usize,\n",
        "}\n",
    );
    if helper
        .matches("pub(crate) struct Stage7bFaultBudget {")
        .count()
        != 1
        || !helper.contains(expected_budget)
        || helper
            .matches("pub(crate) struct Stage7bFaultBudgetState {")
            .count()
            != 1
        || !helper.contains(expected_state)
    {
        return Err(
            "Stage 7B fault budget and its failure-atomic snapshot must retain their exact complete field sets"
                .into(),
        );
    }
    if helper.matches("registry.clone()").count() != 1 {
        return Err(
            "Stage 7B fault budget permits exactly one Registry clone in its complete state snapshot"
                .into(),
        );
    }

    let observed_start = helper
        .find("pub(crate) fn observed_credit_units(")
        .ok_or_else(|| {
            "Stage 7B fault Registry lacks phase-derived credit observation".to_owned()
        })?;
    let observed_end = helper[observed_start..]
        .find("\n}\n\n#[derive(Debug, Eq, PartialEq)]")
        .map(|offset| observed_start + offset)
        .ok_or_else(|| {
            "Stage 7B fault Registry credit observation boundary is missing".to_owned()
        })?;
    let observed = &helper[observed_start..observed_end];
    let observed_compact: String = observed
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let expected_observed = concat!(
        "pub(crate)fnobserved_credit_units(&self)->Result<usize,RegistryError>{",
        "letcredits=self.registry.credits;",
        "letunits=matchself.registry.phase{",
        "ScopePhase::Active|ScopePhase::Closing=>credits.held.checked_add(credits.committed)",
        ".ok_or(RegistryError::CounterOverflow)?,",
        "ScopePhase::Revoked=>credits.free,",
        "};",
        "usize::try_from(units).map_err(|_|RegistryError::CounterOverflow)",
        "}",
    );
    if observed_compact != expected_observed {
        return Err(
            "Stage 7B fault Registry credit observation must remain the exact phase-derived held+committed/free projection"
                .into(),
        );
    }

    for required in [
        "instance_id: u64,\n    binding: Stage7bFaultBinding,",
        "pub(crate) instance_id: u64,",
        "instance_id: u64,\n    registry: EffectRegistry,",
        "pub(crate) fn new(case: Stage7bFaultCase, instance_id: u64)",
        "if capacity == 0 || instance_id == 0",
        "let scope = ScopeKey::new(instance_id, tag);",
        "usize::try_from(self.instance_id)",
        "instance_id: self.instance_id,",
        "credit.instance_id != self.instance_id",
        "pub(crate) struct Stage7bFaultBudgetState {",
        "registry: self.registry.clone(),",
        "ScopePhase::Active | ScopePhase::Closing => credits",
        ".held\n                .checked_add(credits.committed)",
        "ScopePhase::Revoked => credits.free,",
    ] {
        if !helper.contains(required) {
            return Err(format!(
                "Stage 7B fault Registry helper lacks instance/credit invariant {required:?}"
            ));
        }
    }

    for required in [
        "fn causal_commit_matches(",
        "causal.registry_instance_id != registry_instance_id",
        "causal.scope != target.scope",
        "causal.authority_epoch != target.authority_epoch",
        "source.identity.scope == target.scope",
        "source.identity.domain != target.domain",
        "causal.binding_epoch <= target.binding_epoch",
        "source.commit.as_ref() == Some(causal)",
        "completion has invalid causal commit",
        "pub(crate) fn stage7b_causal_commit_self_test()",
        "TerminalRequest::completed_by(2, source_commit.clone())",
        "assert_eq!(cross_scope, cross_scope_before);",
        "first_commit.registry_instance_id",
        "assert_eq!(first_commit.scope, second_commit.scope);",
        "assert_eq!(first, first_before);",
        "assert_eq!(second, second_before);",
    ] {
        if !source.contains(required) {
            return Err(format!(
                "Stage 7B Registry lacks causal receipt provenance gate {required:?}"
            ));
        }
    }
    if source.matches("!causal_commit_matches(").count() != 2 {
        return Err(
            "Stage 7B Registry must validate causal commits both at transition and invariant reconstruction"
                .into(),
        );
    }
    Ok(())
}

fn validate_fault_evaluator_source_text(source: &str) -> Result<(), String> {
    for forbidden in [
        "FaultCell::pass",
        "const fn pass(",
        "run_registry_budget",
        "run_registry_fault",
        "RegistryBudgetRun",
        "RegistryFaultRun",
        "final_quiescent=true",
        "observed_terminal: spec.expected_terminal",
        "observed_terminal: self.spec.expected_terminal",
        "final_quiescent: true",
        "credits: usize::from(self.pending.is_some())",
        "credits: usize::from(self.gate.pending.is_some())",
        "credits: self.waiter_count",
        "credits: self.gate.waiter_count",
        "credits: self.effect_count",
        "credits: self.gate.effect_count",
        "credits: usize::try_from(self.budget.registry.credits.capacity).unwrap(),",
        "credits: 0,",
        "credits: 1,",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "Stage 7B fault evaluator contains forbidden self-report pattern {forbidden:?}"
            ));
        }
    }

    let fault_start = source
        .find("fn run_fault_matrix()")
        .ok_or_else(|| "Stage 7B evaluator lacks fault-matrix entry point".to_owned())?;
    let fault_end = source
        .find("#[derive(Clone, Copy)]\nstruct ScalePoint")
        .ok_or_else(|| "Stage 7B evaluator lacks fault/scale boundary".to_owned())?;
    if fault_end <= fault_start {
        return Err("Stage 7B evaluator fault/scale source boundary is inverted".into());
    }
    let fault_source = &source[fault_start..fault_end];
    for detached in [
        "Stage7bActiveFixture::new",
        "Stage7bFixtureConfig",
        "EffectRegistry::new",
        "fn run_registry_",
    ] {
        if fault_source.contains(detached) {
            return Err(format!(
                "Stage 7B fault evaluator contains detached Registry sidecar {detached:?}"
            ));
        }
    }

    for required in [
        "fn from_projections<P: FaultProjection>(",
        "observed_terminal: observation.observed_terminal,",
        "final_quiescent: observation.final_quiescent,",
        ".checked_sub(observation.before.terminalizations)",
        ".checked_sub(observation.before.publications)",
        "retained_before_quiescence: retained.retained_for_retry(),",
        "final_quiescent: after.determinately_quiescent(),",
        "self.spec.expected_terminal.label(),\n            self.observed_terminal.label(),",
        "self.final_quiescent,",
        "FaultCell::checked(spec, observation).print();",
        "pick: FallbackPick,",
        "receipts: &[ContinuationReceipt],",
        "receipt: &OneShotTerminalReceipt<ReadinessOutcome>,",
        "receipt: ExpiryReceipt,",
        "budget: Stage7bNoCreditProjection,",
        "Stage7bNoCredit::new(case, scheduler_fault_binding(case, crash, 7, 1))",
        ".consume(scheduler_fault_binding(",
        "budget: Stage7bFaultBudgetProjection,",
        "let mut leader_credit = budget.reserve(leader_binding).unwrap();",
        "let mut follower_credit = budget.reserve(follower_binding).unwrap();",
        "budget.commit(&mut leader_credit, leader_binding, 0)?;",
        "budget.commit(&mut follower_credit, follower_binding, 0)",
        "terminalize_pager_credit(",
        "assert_eq!(pager_fault_binding(case, adopted), binding);",
        "terminalize_readiness_credit(",
        "token.instance_id(),",
        "OneShotGate::new(fault_budget_instance_id(case), 1, 1)",
        "gate.consume_terminal(&terminal).unwrap();",
        "readiness_deadline_binding(case, expiry.token()),",
        "struct IoFaultComposite {",
        ".commit_with(identity, || budget.commit(credit, binding, 0))",
        "assert_eq!(self.gate.projection().phase, IoPhase::Quiesced);",
        "retained.budget.registry.credits.committed",
        "budget: self.budget.finish().unwrap(),",
        "fault_budget_projection_is_quiescent(&self.budget)",
        "credits: self.budget.observed_credit_units().unwrap(),",
        "assert_ne!(before.instance_id, 0);",
        "assert_eq!(before.instance_id, retained.instance_id);",
        "assert_eq!(before.instance_id, after.instance_id);",
        "check_fault_budget_instance_isolation();",
        "Stage7bFaultBudget::new(case, 0)",
        "first.commit(&mut second_credit, binding, 0)",
        "second.commit(&mut first_credit, binding, 0)",
        "assert_ne!(first_before.instance_id, second_before.instance_id);",
        "assert_ne!(first_before.scope, second_before.scope);",
        "assert_eq!(first.state_snapshot(), first_state_before);",
        "assert_eq!(second.state_snapshot(), second_state_before);",
        "stage7b_causal_commit_self_test();",
        "assert_eq!(before.scope, retained.scope);",
        "assert_eq!(before.scope, after.scope);",
        "assert_eq!(before.registry.phase, ScopePhase::Active);",
        "assert_eq!(after.registry.phase, ScopePhase::Revoked);",
        "assert_eq!(after.registry.credits.free, after.registry.credits.capacity);",
        "assert_eq!(after.registry.credits.held, 0);",
        "assert_eq!(after.registry.credits.committed, 0);",
        "IoCommitReceipt,",
        "QuiescenceReceipt,",
        "self.gate.phase == IoPhase::Quiesced",
    ] {
        if !source.contains(required) {
            return Err(format!(
                "Stage 7B fault evaluator lacks required receipt/projection source gate {required:?}"
            ));
        }
    }

    for case in [
        "SchedulerLeaseExpiryBeforeProposal",
        "SchedulerCrashAfterProposalBeforePick",
        "SchedulerStaleProposalBeforeRebind",
        "SchedulerStaleProposalAfterRebind",
        "SchedulerRepeatedCrashFallbackProgress",
        "PagerSamePageConcurrentFault",
        "PagerCrashBeforePrepare",
        "PagerCrashAfterPrepareBeforeCommit",
        "PagerCrashAfterCommitBeforeResume",
        "PagerTimeoutVsLateReply",
        "ReadinessCrashBeforeBackendCommit",
        "ReadinessCrashAfterBackendCommit",
        "ReadinessReadyVsTimeout",
        "ReadinessRevokeVsReady",
        "ReadinessStaleDeadlineAfterRearm",
        "IoRevokeBeforeDevicePublication",
        "IoCompletionVsResetAck",
        "IoResetTimeoutRetry",
        "IoIotlbTimeoutLateAck",
        "IoStaleDuplicateCompletion",
    ] {
        let fragment = format!("Stage7bFaultCase::{case}");
        let expected = if case == "ReadinessCrashBeforeBackendCommit" {
            2
        } else {
            1
        };
        let observed = fault_source.matches(&fragment).count();
        if observed != expected {
            return Err(format!(
                "Stage 7B fault semantic case binding drift for {case}: expected {expected}, observed {observed}"
            ));
        }
    }

    for (fragment, expected, label) in [
        (
            "Stage7bFaultBudget::new(case,",
            12,
            "case-local and isolation composite budgets",
        ),
        ("budget.reserve(", 10, "paired credit reservations"),
        ("budget.commit(", 7, "paired credit commits"),
        ("budget.finish()", 9, "paired terminal releases"),
        (
            ".consume(scheduler_fault_binding(",
            5,
            "typed scheduler no-credit consumptions",
        ),
        (
            "terminalize_pager_credit(",
            6,
            "pager receipt/credit terminal pairings",
        ),
        (
            "terminalize_readiness_credit(",
            3,
            "readiness receipt/credit terminal pairings",
        ),
        (
            "gate.consume_terminal(&terminal)",
            2,
            "same-gate readiness receipt consumptions",
        ),
        (
            "OneShotGate::new(fault_budget_instance_id(case), 1, 1)",
            2,
            "caller-namespaced readiness gates",
        ),
        (
            "Stage7bFaultOperation::SchedulerFallbackPick",
            1,
            "scheduler operation binding",
        ),
        (
            "Stage7bFaultOperation::PagerContinuation",
            1,
            "pager operation binding",
        ),
        (
            "Stage7bFaultOperation::ReadinessCompletion",
            3,
            "readiness operation bindings",
        ),
        (
            "Stage7bFaultOperation::IoRequest",
            1,
            "I/O operation binding",
        ),
    ] {
        let observed = fault_source.matches(fragment).count();
        if observed != expected {
            return Err(format!(
                "Stage 7B fault source pairing drift for {label}: expected {expected}, observed {observed}"
            ));
        }
    }

    let spec_entries = source.matches("fault_spec(").count();
    if spec_entries != FAULTS.len() + 1 {
        return Err(format!(
            "Stage 7B fault evaluator spec population drift: expected {} entries plus constructor, observed {spec_entries}",
            FAULTS.len()
        ));
    }
    let composite_credit_sources = fault_source
        .matches("credits: self.budget.observed_credit_units().unwrap(),")
        .count();
    let no_credit_sources = fault_source
        .matches("credits: self.budget.case.credit_capacity(),")
        .count();
    if composite_credit_sources != 4 || no_credit_sources != 1 {
        return Err(format!(
            "Stage 7B fault credit source drift: expected four composite Registry projections and one typed no-credit projection, observed composite={composite_credit_sources} no_credit={no_credit_sources}"
        ));
    }
    if fault_source
        .matches("mark_terminal_quiesced(close)")
        .count()
        != 2
        || fault_source.matches("complete_iotlb(&mut io.gate").count() != 3
    {
        return Err(
            "Stage 7B I/O cells do not expose exactly two terminal-receipt and three reset/IOTLB quiescence paths"
                .into(),
        );
    }

    let io_finish_start = fault_source
        .find("fn finish_after_quiescence(&mut self) -> IoFaultProjection")
        .ok_or_else(|| "Stage 7B I/O composite lacks quiescence finalizer".to_owned())?;
    let io_finish_end = fault_source[io_finish_start..]
        .find("\n}\n\nfn complete_iotlb")
        .map(|offset| io_finish_start + offset)
        .ok_or_else(|| "Stage 7B I/O composite finalizer boundary is missing".to_owned())?;
    let io_finish = &fault_source[io_finish_start..io_finish_end];
    let quiescence = io_finish
        .find("IoPhase::Quiesced")
        .ok_or_else(|| "Stage 7B I/O credit release is not quiescence-gated".to_owned())?;
    let terminal = io_finish
        .find(".terminalize(")
        .ok_or_else(|| "Stage 7B I/O composite lacks paired terminalization".to_owned())?;
    let release = io_finish
        .find("self.budget.finish()")
        .ok_or_else(|| "Stage 7B I/O composite lacks paired credit release".to_owned())?;
    if !(quiescence < terminal && terminal < release) {
        return Err(
            "Stage 7B I/O Registry terminal/release must follow real gate quiescence".into(),
        );
    }
    Ok(())
}

fn parse_log(
    source: &str,
    runtime_metadata: Option<RuntimeMetadata>,
) -> Result<ParsedEvidence, String> {
    let mut faults = Vec::new();
    let mut scales = Vec::new();
    let mut meta = None;
    let mut empty = None;
    let mut cases = Vec::new();
    let mut fault_summary = 0;
    let mut scale_summary = 0;
    let mut performance_summary = 0;
    let mut evaluation_summary = 0;
    let mut phase = 0_u8;

    for raw_line in source.lines() {
        let line = raw_line.trim();
        let recognized_phase = if line.starts_with("STAGE7B_FAULT id=") {
            faults.push(parse_fault(line)?);
            Some(0)
        } else if line.starts_with("STAGE7B_FAULT_SUMMARY ") {
            parse_exact_summary(
                line,
                "STAGE7B_FAULT_SUMMARY",
                &[("cells", "20"), ("passed", "20"), ("status", "PASS")],
            )?;
            fault_summary += 1;
            Some(1)
        } else if line.starts_with("STAGE7B_SCALE point=") {
            scales.push(parse_scale(line)?);
            Some(2)
        } else if line.starts_with("STAGE7B_SCALE_SUMMARY ") {
            parse_exact_summary(
                line,
                "STAGE7B_SCALE_SUMMARY",
                &[("points", "14"), ("passed", "14"), ("status", "PASS")],
            )?;
            scale_summary += 1;
            Some(3)
        } else if line.starts_with("STAGE7B_TSC_META ") {
            if meta.is_some() {
                return Err("duplicate STAGE7B_TSC_META".into());
            }
            meta = Some(parse_meta(line)?);
            Some(4)
        } else if line.starts_with("STAGE7B_TSC_EMPTY ") {
            if empty.is_some() {
                return Err("duplicate STAGE7B_TSC_EMPTY".into());
            }
            empty = Some(parse_sample_line(
                fields(line, "STAGE7B_TSC_EMPTY", EMPTY_FIELDS)?,
                257,
                "empty timer",
            )?);
            Some(5)
        } else if line.starts_with("STAGE7B_TSC case=") {
            cases.push(parse_performance(line)?);
            Some(6)
        } else if line.starts_with("STAGE7B_TSC_SUMMARY ") {
            parse_exact_summary(
                line,
                "STAGE7B_TSC_SUMMARY",
                &[("cases", "29"), ("observed", "29"), ("status", "PASS")],
            )?;
            performance_summary += 1;
            Some(7)
        } else if line.starts_with("STAGE7B_EVALUATION ") {
            if line != "STAGE7B_EVALUATION PASS faults=20 scale_points=14 performance_cases=29" {
                return Err(format!("Stage 7B evaluation summary drift: {line}"));
            }
            evaluation_summary += 1;
            Some(8)
        } else if line.starts_with("STAGE7B_") {
            return Err(format!("unknown Stage 7B evaluation record: {line}"));
        } else {
            None
        };

        if let Some(record_phase) = recognized_phase {
            if record_phase < phase {
                return Err(format!("Stage 7B record reordered at: {line}"));
            }
            phase = record_phase;
        }
    }

    expect_count("fault cells", faults.len(), FAULTS.len())?;
    expect_count("fault summary", fault_summary, 1)?;
    expect_count("scale points", scales.len(), SCALES.len())?;
    expect_count("scale summary", scale_summary, 1)?;
    expect_count("performance cases", cases.len(), PERFORMANCE.len())?;
    expect_count("performance summary", performance_summary, 1)?;
    expect_count("evaluation summary", evaluation_summary, 1)?;
    let environment = meta.ok_or("missing STAGE7B_TSC_META")?;
    let empty_timer = empty.ok_or("missing STAGE7B_TSC_EMPTY")?;

    validate_order(
        "fault cell",
        faults.iter().map(|row| row.id.as_str()),
        FAULTS.iter().map(|row| row.id),
    )?;
    validate_order(
        "scale point",
        scales.iter().map(|row| row.id.as_str()),
        SCALES.iter().map(|row| row.id),
    )?;
    validate_order(
        "performance case",
        cases.iter().map(|row| row.id.as_str()),
        PERFORMANCE.iter().map(|row| row.id),
    )?;

    let mut families = BTreeMap::<&str, usize>::new();
    for row in &faults {
        *families.entry(row.family.as_str()).or_default() += 1;
    }
    for family in ["scheduler", "pager", "personality-readiness", "linux-io"] {
        if families.remove(family) != Some(5) {
            return Err(format!(
                "fault family {family:?} does not contain exactly five cells"
            ));
        }
    }
    if !families.is_empty() {
        return Err(format!("unknown fault families: {families:?}"));
    }

    Ok(ParsedEvidence {
        faults,
        scales,
        performance: PerformanceEvidence {
            schema: "nexus.stage7b.performance.v1",
            status: "Observed",
            claim: "single-vCPU single-thread TCG release hot-cache guest-visible TSC observations",
            thresholds: None,
            environment,
            runtime_metadata,
            empty_timer,
            cases,
        },
    })
}

fn parse_fault(line: &str) -> Result<FaultEvidence, String> {
    let values = fields(line, "STAGE7B_FAULT", FAULT_FIELDS)?;
    let index = FAULTS
        .iter()
        .position(|spec| spec.id == values[0])
        .ok_or_else(|| format!("unknown fault cell {:?}", values[0]))?;
    let spec = FAULTS[index];
    exact("fault family", values[1], spec.family)?;
    exact("fault injection point", values[2], spec.injection)?;
    exact("fault expected terminal", values[3], spec.terminal)?;
    exact("fault observed terminal", values[4], spec.terminal)?;
    let terminalizations = number("fault terminalizations", values[5])?;
    let publications = number("fault publications", values[6])?;
    let credits_before = number("fault credits_before", values[7])?;
    let credits_after = number("fault credits_after", values[8])?;
    let retained = boolean("fault retained_before_quiescence", values[9])?;
    let final_quiescent = boolean("fault final_quiescent", values[10])?;
    exact("fault status", values[11], "PASS")?;

    exact_number(
        "fault terminalizations",
        terminalizations,
        spec.terminalizations,
    )?;
    exact_number("fault publications", publications, spec.publications)?;
    exact_number("fault credits_before", credits_before, spec.credits)?;
    exact_number("fault credits_after", credits_after, spec.credits)?;
    if credits_before != credits_after {
        return Err(format!("fault {} does not conserve credits", spec.id));
    }
    if retained != spec.retained {
        return Err(format!(
            "fault {} retained-owner observation drift",
            spec.id
        ));
    }
    if !final_quiescent {
        return Err(format!(
            "fault {} released without final quiescence",
            spec.id
        ));
    }

    Ok(FaultEvidence {
        id: values[0].into(),
        family: values[1].into(),
        injection_point: values[2].into(),
        expected_terminal: values[3].into(),
        observed_terminal: values[4].into(),
        terminalizations,
        publications,
        credits_before,
        credits_after,
        retained_before_quiescence: retained,
        final_quiescent,
        status: "Checked",
    })
}

fn parse_scale(line: &str) -> Result<ScaleEvidence, String> {
    let values = fields(line, "STAGE7B_SCALE", SCALE_FIELDS)?;
    let spec = SCALES
        .iter()
        .find(|spec| spec.id == values[0])
        .copied()
        .ok_or_else(|| format!("unknown scale point {:?}", values[0]))?;
    let n = number("scale N", values[1])?;
    let k = number("scale k", values[2])?;
    let history = number("scale H", values[3])?;
    exact_number("scale N", n, spec.n)?;
    exact_number("scale k", k, spec.k)?;
    exact_number("scale H", history, spec.history)?;

    let target_count = number("scale target_count", values[4])?;
    let begin_visits = number("scale begin_target_record_visits", values[5])?;
    let next_calls = number("scale next_calls", values[6])?;
    let head_selections = number("scale head_selections", values[7])?;
    let terminalized = number("scale terminalized", values[8])?;
    let completion_checked = number("scale completion_members_checked", values[9])?;
    let index_removals = number("scale target_index_removals", values[10])?;
    let unrelated_visits = number("scale unrelated_effect_visits", values[11])?;
    let history_visits = number("scale history_effect_visits", values[12])?;
    let pending_targets = number("scale pending_targets", values[13])?;
    exact("scale final_target_state", values[14], "Revoked")?;
    exact("scale status", values[15], "PASS")?;

    for (label, observed, expected) in [
        ("target_count", target_count, k),
        ("begin_target_record_visits", begin_visits, 0),
        ("next_calls", next_calls, k + 1),
        ("head_selections", head_selections, k),
        ("terminalized", terminalized, k),
        ("completion_members_checked", completion_checked, k),
        ("target_index_removals", index_removals, k),
        ("unrelated_effect_visits", unrelated_visits, 0),
        ("history_effect_visits", history_visits, 0),
        ("pending_targets", pending_targets, 0),
    ] {
        exact_number(&format!("scale {label}"), observed, expected)?;
    }

    Ok(ScaleEvidence {
        id: values[0].into(),
        n,
        k,
        history,
        target_count,
        begin_target_record_visits: begin_visits,
        next_calls,
        head_selections,
        terminalized,
        completion_members_checked: completion_checked,
        target_index_removals: index_removals,
        unrelated_effect_visits: unrelated_visits,
        history_effect_visits: history_visits,
        pending_targets,
        final_target_state: values[14].into(),
        status: "Checked",
    })
}

fn parse_meta(line: &str) -> Result<PerformanceEnvironment, String> {
    let values = fields(line, "STAGE7B_TSC_META", META_FIELDS)?;
    for (label, observed, expected) in [
        ("profile", values[0], "release"),
        ("accel", values[1], "tcg"),
        ("vcpus", values[2], "1"),
        ("threads", values[3], "1"),
        ("cache", values[4], "hot"),
        ("timer", values[5], "guest_visible_tsc"),
        ("fence", values[6], "lfence"),
        ("preemption", values[7], "disabled"),
        ("local_irq", values[8], "disabled"),
        ("warmups", values[9], "7"),
        ("samples", values[10], "65"),
        ("empty_samples", values[11], "257"),
        ("adjusted", values[12], "false"),
        ("raw_retained", values[13], "true"),
        ("thresholds", values[14], "none"),
    ] {
        exact(&format!("performance metadata {label}"), observed, expected)?;
    }
    Ok(PerformanceEnvironment {
        profile: values[0].into(),
        accel: values[1].into(),
        vcpus: number("performance vcpus", values[2])?,
        threads: number("performance threads", values[3])?,
        cache: values[4].into(),
        timer: values[5].into(),
        fence: values[6].into(),
        preemption: values[7].into(),
        local_irq: values[8].into(),
        warmups: number("performance warmups", values[9])?,
        samples: number("performance samples", values[10])?,
        empty_samples: number("performance empty samples", values[11])?,
        adjusted: boolean("performance adjusted", values[12])?,
        raw_retained: boolean("performance raw_retained", values[13])?,
    })
}

fn parse_performance(line: &str) -> Result<PerformanceCase, String> {
    let values = fields(line, "STAGE7B_TSC", PERFORMANCE_FIELDS)?;
    let spec = PERFORMANCE
        .iter()
        .find(|spec| spec.id == values[0])
        .copied()
        .ok_or_else(|| format!("unknown performance case {:?}", values[0]))?;
    exact("performance operation", values[1], spec.operation)?;
    let n = number("performance N", values[2])?;
    let k = number("performance k", values[3])?;
    let history = number("performance H", values[4])?;
    exact_number("performance N", n, spec.scale.n)?;
    exact_number("performance k", k, spec.scale.k)?;
    exact_number("performance H", history, spec.scale.history)?;
    exact("performance status", values[11], "OBSERVED")?;
    let samples = parse_sample_line(
        vec![
            values[5], values[6], values[7], values[8], values[9], values[10],
        ],
        65,
        spec.id,
    )?;
    Ok(PerformanceCase {
        id: values[0].into(),
        operation: values[1].into(),
        n,
        k,
        history,
        samples: samples.samples,
        min: samples.min,
        median: samples.median,
        p95: samples.p95,
        max: samples.max,
        raw: samples.raw,
        status: "Observed",
    })
}

fn parse_sample_line(
    values: Vec<&str>,
    expected_count: usize,
    context: &str,
) -> Result<SampleSet, String> {
    let declared = usize::try_from(number(&format!("{context} sample count"), values[0])?)
        .map_err(|_| format!("{context} sample count exceeds usize"))?;
    if declared != expected_count {
        return Err(format!(
            "{context} sample count drift: expected {expected_count}, observed {declared}"
        ));
    }
    let raw = parse_raw(values[5], context)?;
    if raw.len() != expected_count {
        return Err(format!(
            "{context} raw sample count drift: expected {expected_count}, observed {}",
            raw.len()
        ));
    }
    let (min, median, p95, max) = statistics(&raw)?;
    for (label, declared, recomputed) in [
        ("min", number(&format!("{context} min"), values[1])?, min),
        (
            "median",
            number(&format!("{context} median"), values[2])?,
            median,
        ),
        ("p95", number(&format!("{context} p95"), values[3])?, p95),
        ("max", number(&format!("{context} max"), values[4])?, max),
    ] {
        if declared != recomputed {
            return Err(format!(
                "{context} {label} recomputation mismatch: declared {declared}, recomputed {recomputed}"
            ));
        }
    }
    Ok(SampleSet {
        samples: declared,
        min,
        median,
        p95,
        max,
        raw,
        status: "Observed",
    })
}

fn parse_runtime_metadata(source: &str) -> Result<RuntimeMetadata, String> {
    let mut values = Vec::new();
    for (line_number, raw) in source.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("runtime metadata line {} is not key=value", line_number + 1))?;
        if key.is_empty() || value.is_empty() || value.chars().any(char::is_whitespace) {
            return Err(format!("invalid runtime metadata line {}", line_number + 1));
        }
        values.push((key, value));
    }
    let expected = [
        "schema",
        "accel",
        "vcpus",
        "threads",
        "cpu_pin",
        "cpus_allowed_list",
    ];
    if values.len() != expected.len()
        || values
            .iter()
            .zip(expected)
            .any(|((observed, _), expected)| *observed != expected)
    {
        return Err(format!(
            "runtime metadata keys must be exactly ordered as {}",
            expected.join(",")
        ));
    }
    exact(
        "runtime metadata schema",
        values[0].1,
        "nexus.stage7b.runtime-metadata.v1",
    )?;
    exact("runtime metadata accel", values[1].1, "tcg")?;
    exact("runtime metadata vcpus", values[2].1, "1")?;
    exact("runtime metadata threads", values[3].1, "1")?;
    let cpu_pin = number("runtime metadata cpu_pin", values[4].1)?;
    if !cpu_list_contains(values[5].1, cpu_pin)? {
        return Err(format!(
            "runtime metadata cpu_pin {cpu_pin} is outside cpus_allowed_list {}",
            values[5].1
        ));
    }
    Ok(RuntimeMetadata {
        schema: values[0].1.into(),
        accel: values[1].1.into(),
        vcpus: number("runtime metadata vcpus", values[2].1)?,
        threads: number("runtime metadata threads", values[3].1)?,
        cpu_pin,
        cpus_allowed_list: values[5].1.into(),
    })
}

fn cpu_list_contains(list: &str, cpu: u64) -> Result<bool, String> {
    if list.is_empty() {
        return Err("runtime metadata cpus_allowed_list is empty".into());
    }
    let mut found = false;
    for item in list.split(',') {
        let (start, end) = if let Some((start, end)) = item.split_once('-') {
            (
                number("cpus_allowed_list range start", start)?,
                number("cpus_allowed_list range end", end)?,
            )
        } else {
            let value = number("cpus_allowed_list CPU", item)?;
            (value, value)
        };
        if start > end {
            return Err(format!("invalid descending CPU range {item:?}"));
        }
        found |= (start..=end).contains(&cpu);
    }
    Ok(found)
}

fn fields<'a>(line: &'a str, prefix: &str, expected: &[&str]) -> Result<Vec<&'a str>, String> {
    let body = line
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or_else(|| format!("record does not begin with {prefix:?}: {line}"))?;
    let mut values = Vec::new();
    let tokens: Vec<_> = body.split_whitespace().collect();
    if tokens.len() != expected.len() {
        return Err(format!(
            "{prefix} field count drift: expected {}, observed {}",
            expected.len(),
            tokens.len()
        ));
    }
    for (token, expected_key) in tokens.into_iter().zip(expected) {
        let (key, value) = token
            .split_once('=')
            .ok_or_else(|| format!("{prefix} field is not key=value: {token:?}"))?;
        if key != *expected_key || value.is_empty() || value.contains('=') {
            return Err(format!(
                "{prefix} expected field {expected_key:?}, observed {token:?}"
            ));
        }
        values.push(value);
    }
    Ok(values)
}

fn parse_exact_summary(line: &str, prefix: &str, expected: &[(&str, &str)]) -> Result<(), String> {
    let keys: Vec<_> = expected.iter().map(|(key, _)| *key).collect();
    let values = fields(line, prefix, &keys)?;
    for ((key, expected), observed) in expected.iter().zip(values) {
        exact(&format!("{prefix} {key}"), observed, expected)?;
    }
    Ok(())
}

fn parse_raw(source: &str, context: &str) -> Result<Vec<u64>, String> {
    if source.is_empty() {
        return Err(format!("{context} raw samples are empty"));
    }
    source
        .split(',')
        .map(|value| number(&format!("{context} raw sample"), value))
        .collect()
}

fn statistics(raw: &[u64]) -> Result<(u64, u64, u64, u64), String> {
    if raw.is_empty() {
        return Err("cannot compute statistics for an empty sample set".into());
    }
    let mut sorted = raw.to_vec();
    sorted.sort_unstable();
    let p95_index = (sorted.len() * 95).div_ceil(100) - 1;
    Ok((
        sorted[0],
        sorted[sorted.len() / 2],
        sorted[p95_index],
        *sorted.last().expect("non-empty sample set"),
    ))
}

fn read_regular(root: &Path, relative: &str, optional: bool) -> Result<Option<String>, String> {
    let path = root.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("inspect {relative}: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "Stage 7B input is not a regular non-symlink file: {relative}"
        ));
    }
    let source = fs::read_to_string(&path).map_err(|error| format!("read {relative}: {error}"))?;
    if source.is_empty() {
        return Err(format!("Stage 7B input is empty: {relative}"));
    }
    Ok(Some(source))
}

fn validate_order<'a>(
    kind: &str,
    observed: impl Iterator<Item = &'a str>,
    expected: impl Iterator<Item = &'a str>,
) -> Result<(), String> {
    for (index, (observed, expected)) in observed.zip(expected).enumerate() {
        if observed != expected {
            return Err(format!(
                "{kind} order mismatch at index {index}: expected {expected:?}, observed {observed:?}"
            ));
        }
    }
    Ok(())
}

fn number(context: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{context} is not an unsigned integer: {value:?}"))
}

fn boolean(context: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{context} is not true or false: {value:?}")),
    }
}

fn exact(context: &str, observed: &str, expected: &str) -> Result<(), String> {
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "{context} drift: expected {expected:?}, observed {observed:?}"
        ))
    }
}

fn exact_number(context: &str, observed: u64, expected: u64) -> Result<(), String> {
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "{context} drift: expected {expected}, observed {observed}"
        ))
    }
}

fn expect_count(context: &str, observed: usize, expected: usize) -> Result<(), String> {
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "{context} count drift: expected {expected}, observed {observed}"
        ))
    }
}

fn json_lines<T: Serialize>(rows: &[T]) -> Result<String, String> {
    let mut output = String::new();
    for row in rows {
        output.push_str(
            &serde_json::to_string(row).map_err(|error| format!("serialize JSONL: {error}"))?,
        );
        output.push('\n');
    }
    Ok(output)
}

fn pretty_json<T: Serialize>(value: &T) -> Result<String, String> {
    let mut output =
        serde_json::to_string_pretty(value).map_err(|error| format!("serialize JSON: {error}"))?;
    output.push('\n');
    Ok(output)
}

fn clear_outputs(directory: &Path) -> Result<(), String> {
    for name in [
        FAULT_OUTPUT,
        SCALE_OUTPUT,
        PERFORMANCE_OUTPUT,
        ORACLE_OUTPUT,
    ] {
        let path = directory.join(name);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove stale {}: {error}", path.display())),
        }
    }
    Ok(())
}

fn atomic_write(directory: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let output = directory.join(name);
    let temporary = directory.join(format!(".{name}.tmp"));
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("remove stale {}: {error}", temporary.display())),
    }
    fs::write(&temporary, bytes)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, &output)
        .map_err(|error| format!("publish {}: {error}", output.display()))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_line(prefix: &str, count: usize) -> String {
        let raw: Vec<u64> = (1..=count as u64).collect();
        let (min, median, p95, max) = statistics(&raw).unwrap();
        let encoded = raw.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        format!(
            "{prefix} samples={count} min={min} median={median} p95={p95} max={max} raw={encoded}"
        )
    }

    fn valid_log() -> String {
        let mut lines = Vec::new();
        for spec in FAULTS {
            lines.push(format!(
                "STAGE7B_FAULT id={} family={} injection_point={} expected_terminal={} observed_terminal={} terminalizations={} publications={} credits_before={} credits_after={} retained_before_quiescence={} final_quiescent=true status=PASS",
                spec.id,
                spec.family,
                spec.injection,
                spec.terminal,
                spec.terminal,
                spec.terminalizations,
                spec.publications,
                spec.credits,
                spec.credits,
                spec.retained,
            ));
        }
        lines.push("STAGE7B_FAULT_SUMMARY cells=20 passed=20 status=PASS".into());
        for spec in SCALES {
            lines.push(format!(
                "STAGE7B_SCALE point={} N={} k={} H={} target_count={} begin_target_record_visits=0 next_calls={} head_selections={} terminalized={} completion_members_checked={} target_index_removals={} unrelated_effect_visits=0 history_effect_visits=0 pending_targets=0 final_target_state=Revoked status=PASS",
                spec.id,
                spec.n,
                spec.k,
                spec.history,
                spec.k,
                spec.k + 1,
                spec.k,
                spec.k,
                spec.k,
                spec.k,
            ));
        }
        lines.push("STAGE7B_SCALE_SUMMARY points=14 passed=14 status=PASS".into());
        lines.push("STAGE7B_TSC_META profile=release accel=tcg vcpus=1 threads=1 cache=hot timer=guest_visible_tsc fence=lfence preemption=disabled local_irq=disabled warmups=7 samples=65 empty_samples=257 adjusted=false raw_retained=true thresholds=none".into());
        lines.push(sample_line("STAGE7B_TSC_EMPTY", 257));
        for spec in PERFORMANCE {
            lines.push(format!(
                "{} status=OBSERVED",
                sample_line(
                    &format!(
                        "STAGE7B_TSC case={} op={} N={} k={} H={}",
                        spec.id, spec.operation, spec.scale.n, spec.scale.k, spec.scale.history
                    ),
                    65,
                )
            ));
        }
        lines.push("STAGE7B_TSC_SUMMARY cases=29 observed=29 status=PASS".into());
        lines.push("STAGE7B_EVALUATION PASS faults=20 scale_points=14 performance_cases=29".into());
        lines.join("\n")
    }

    fn reject(rewrite: impl FnOnce(String) -> String) {
        let error = parse_log(&rewrite(valid_log()), None).err();
        assert!(error.is_some(), "mutated log unexpectedly passed");
    }

    fn checked_evaluator_source() -> String {
        include_str!("../../../kernel/nexus-ostd/src/evaluation/stage7b.rs").into()
    }

    fn checked_registry_source() -> String {
        include_str!("../../../kernel/nexus-ostd/src/cser/effect_registry.rs").into()
    }

    #[test]
    fn fault_source_gate_accepts_typed_receipt_projection_pipeline() {
        validate_fault_evaluator_source_text(&checked_evaluator_source()).unwrap();
        validate_fault_registry_source_text(&checked_registry_source()).unwrap();
    }

    #[test]
    fn fault_source_gate_rejects_expected_copy_and_constant_quiescence() {
        let source = checked_evaluator_source();
        for mutated in [
            source.replacen(
                "observed_terminal: observation.observed_terminal,",
                "observed_terminal: spec.expected_terminal,",
                1,
            ),
            source.replacen(
                "self.observed_terminal.label(),",
                "self.spec.expected_terminal.label(),",
                1,
            ),
            source.replacen(
                "final_quiescent: observation.final_quiescent,",
                "final_quiescent: true,",
                1,
            ),
            source.replacen("self.final_quiescent,", "true,", 1),
        ] {
            assert!(
                validate_fault_evaluator_source_text(&mutated).is_err(),
                "self-report source mutation unexpectedly passed"
            );
        }
    }

    #[test]
    fn fault_source_gate_rejects_missing_receipt_and_real_io_quiescence_paths() {
        let source = checked_evaluator_source();
        let missing_receipt = source.replacen("pick: FallbackPick,", "pick: FaultTerminal,", 1);
        assert!(validate_fault_evaluator_source_text(&missing_receipt).is_err());
        let missing_terminal_quiescence = source.replacen(
            "mark_terminal_quiesced(close)",
            "mark_terminal_quiesced_without_receipt(close)",
            1,
        );
        assert!(validate_fault_evaluator_source_text(&missing_terminal_quiescence).is_err());
        let missing_iotlb_quiescence =
            source.replacen("complete_iotlb(&mut io.gate", "skip_iotlb(&mut io.gate", 1);
        assert!(validate_fault_evaluator_source_text(&missing_iotlb_quiescence).is_err());
    }

    #[test]
    fn fault_source_gate_rejects_identity_or_population_credit_proxies() {
        let source = checked_evaluator_source();
        for proxy in [
            "usize::from(self.gate.pending.is_some())",
            "self.gate.waiter_count",
            "self.gate.effect_count",
            "usize::try_from(self.budget.registry.credits.capacity).unwrap()",
        ] {
            let mutated = source.replacen("self.budget.observed_credit_units().unwrap()", proxy, 1);
            assert!(
                validate_fault_evaluator_source_text(&mutated).is_err(),
                "credit proxy mutation unexpectedly passed: {proxy}"
            );
        }
        for literal in ["0", "1"] {
            let mutated =
                source.replacen("self.budget.observed_credit_units().unwrap()", literal, 1);
            assert!(
                validate_fault_evaluator_source_text(&mutated).is_err(),
                "constant credit mutation unexpectedly passed: {literal}"
            );
        }
    }

    #[test]
    fn fault_source_gate_rejects_unpaired_composite_credit_transitions() {
        let source = checked_evaluator_source();
        for (needle, replacement, label) in [
            (
                "budget.reserve(binding)",
                "sidecar.reserve(binding)",
                "reserve",
            ),
            (
                "budget.commit(&mut leader_credit, leader_binding, 0)?;",
                "sidecar.commit(&mut leader_credit, leader_binding, 0)?;",
                "commit",
            ),
            ("budget.finish()", "sidecar.finish()", "release"),
        ] {
            let mutated = source.replacen(needle, replacement, 1);
            assert_ne!(mutated, source, "missing mutation fixture for {label}");
            assert!(
                validate_fault_evaluator_source_text(&mutated).is_err(),
                "unpaired {label} mutation unexpectedly passed"
            );
        }
    }

    #[test]
    fn fault_source_gate_rejects_binding_sidecar_and_literal_no_credit_mutations() {
        let source = checked_evaluator_source();
        let wrong_binding = source.replacen(
            "Stage7bFaultOperation::PagerContinuation",
            "Stage7bFaultOperation::ReadinessCompletion",
            1,
        );
        assert!(validate_fault_evaluator_source_text(&wrong_binding).is_err());

        let detached = source.replacen(
            "Stage7bFaultBudget::new(case, fault_budget_instance_id(case)).unwrap();",
            "Stage7bActiveFixture::new(detached_config).unwrap();\n    let mut budget = Stage7bFaultBudget::new(case, fault_budget_instance_id(case)).unwrap();",
            1,
        );
        assert_ne!(detached, source);
        assert!(validate_fault_evaluator_source_text(&detached).is_err());

        let literal_scheduler = source.replacen(
            "credits: self.budget.case.credit_capacity(),",
            "credits: 0,",
            1,
        );
        assert_ne!(literal_scheduler, source);
        assert!(validate_fault_evaluator_source_text(&literal_scheduler).is_err());
    }

    #[test]
    fn fault_source_gate_rejects_capacity_self_report_and_dropped_scope_lineage() {
        let source = checked_evaluator_source();
        let capacity = source.replacen(
            "credits: self.budget.observed_credit_units().unwrap(),",
            "credits: usize::try_from(self.budget.registry.credits.capacity).unwrap(),",
            1,
        );
        assert_ne!(capacity, source);
        assert!(validate_fault_evaluator_source_text(&capacity).is_err());

        let dropped_scope = source.replacen(
            "assert_eq!(before.scope, retained.scope);",
            "assert_eq!(before.case, retained.case);",
            1,
        );
        assert_ne!(dropped_scope, source);
        assert!(validate_fault_evaluator_source_text(&dropped_scope).is_err());

        let dropped_final_balance = source.replacen(
            "assert_eq!(after.registry.credits.committed, 0);",
            "assert!(after.registry.credits.capacity > 0);",
            1,
        );
        assert_ne!(dropped_final_balance, source);
        assert!(validate_fault_evaluator_source_text(&dropped_final_balance).is_err());
    }

    #[test]
    fn fault_registry_gate_rejects_capacity_sidecar_instance_and_causal_mutations() {
        let source = checked_registry_source();
        let capacity = source.replacen(
            "ScopePhase::Revoked => credits.free,",
            "ScopePhase::Revoked => credits.capacity,",
            1,
        );
        assert_ne!(capacity, source);
        assert!(validate_fault_registry_source_text(&capacity).is_err());

        let sidecar = source.replacen(
            "registry.check_invariants()?;\n        Ok(Self {",
            "registry.check_invariants()?;\n        let _sidecar = EffectRegistry::new();\n        Ok(Self {",
            1,
        );
        assert_ne!(sidecar, source);
        assert!(validate_fault_registry_source_text(&sidecar).is_err());

        let external_sidecar = source.replacen(
            "pub(crate) struct Stage7bFaultCredit {",
            "fn hidden_fault_sidecar() -> EffectRegistry { EffectRegistry::new() }\n\npub(crate) struct Stage7bFaultCredit {",
            1,
        );
        assert_ne!(external_sidecar, source);
        assert!(validate_fault_registry_source_text(&external_sidecar).is_err());

        let cloned_sidecar = source
            .replacen(
                "    registry: EffectRegistry,\n    scope: ScopeKey,",
                "    registry: EffectRegistry,\n    sidecar: EffectRegistry,\n    scope: ScopeKey,",
                1,
            )
            .replacen(
                "            registry,\n            scope,",
                "            sidecar: registry.clone(),\n            registry,\n            scope,",
                1,
            );
        assert_ne!(cloned_sidecar, source);
        assert!(validate_fault_registry_source_text(&cloned_sidecar).is_err());

        let credit_sum = source.replacen(
            "ScopePhase::Revoked => credits.free,",
            "ScopePhase::Revoked => credits.free.checked_add(credits.held).and_then(|value| value.checked_add(credits.committed)).ok_or(RegistryError::CounterOverflow)?,",
            1,
        );
        assert_ne!(credit_sum, source);
        assert!(validate_fault_registry_source_text(&credit_sum).is_err());

        let missing_instance =
            source.replacen("|| credit.instance_id != self.instance_id", "|| false", 1);
        assert_ne!(missing_instance, source);
        assert!(validate_fault_registry_source_text(&missing_instance).is_err());

        let unauthenticated_causal = source.replacen(
            "source.commit.as_ref() == Some(causal)",
            "source.commit.is_some()",
            1,
        );
        assert_ne!(unauthenticated_causal, source);
        assert!(validate_fault_registry_source_text(&unauthenticated_causal).is_err());

        let foreign_registry_allowed = source.replacen(
            "causal.registry_instance_id != registry_instance_id",
            "registry_instance_id == 0",
            1,
        );
        assert_ne!(foreign_registry_allowed, source);
        assert!(validate_fault_registry_source_text(&foreign_registry_allowed).is_err());

        let cross_domain_unfenced = source.replacen(
            "&& (source.identity.domain != target.domain\n                || causal.binding_epoch <= target.binding_epoch)",
            "&& true",
            1,
        );
        assert_ne!(cross_domain_unfenced, source);
        assert!(validate_fault_registry_source_text(&cross_domain_unfenced).is_err());
    }

    #[test]
    fn fault_registry_gate_structurally_binds_the_two_new_self_test_registries() {
        let source = checked_registry_source();

        let moved_atomic = source
            .replacen(
                "let mut atomic = EffectRegistry::new();",
                "let mut atomic = EffectRegistry::default();",
                1,
            )
            .replacen(
                "pub(crate) struct Stage7bFaultCredit {",
                "fn hidden_atomic_sidecar() -> EffectRegistry { EffectRegistry::new() }\n\npub(crate) struct Stage7bFaultCredit {",
                1,
            );
        assert_eq!(
            moved_atomic.matches("EffectRegistry::new()").count(),
            source.matches("EffectRegistry::new()").count(),
            "mutation must preserve the global constructor count"
        );
        assert!(validate_fault_registry_source_text(&moved_atomic).is_err());

        let moved_production = source
            .replacen(
                "let unrelated_supervisor = TaskKey::new(0x2ff, 1);\n    let mut registry = EffectRegistry::new();",
                "let unrelated_supervisor = TaskKey::new(0x2ff, 1);\n    let mut registry = EffectRegistry::default();",
                1,
            )
            .replacen(
                "pub(crate) struct Stage7bFaultCredit {",
                "fn hidden_production_sidecar() -> EffectRegistry { EffectRegistry::new() }\n\npub(crate) struct Stage7bFaultCredit {",
                1,
            );
        assert_eq!(
            moved_production.matches("EffectRegistry::new()").count(),
            source.matches("EffectRegistry::new()").count(),
            "mutation must preserve the global constructor count"
        );
        assert!(validate_fault_registry_source_text(&moved_production).is_err());

        let detached = source.replacen(
            "production_identity_registry_self_test();",
            "/* detached production identity self-test */",
            1,
        );
        assert!(validate_fault_registry_source_text(&detached).is_err());

        let moved_to_fault_helper = source
            .replacen(
                "    production_identity_registry_self_test();\n",
                "",
                1,
            )
            .replacen(
                "pub(crate) struct Stage7bFaultCredit {",
                "fn mislabeled_fault_matrix_call() { production_identity_registry_self_test(); }\n\npub(crate) struct Stage7bFaultCredit {",
                1,
            );
        assert_eq!(
            moved_to_fault_helper
                .matches("production_identity_registry_self_test();")
                .count(),
            1,
            "mutation must preserve the implementation self-test call count"
        );
        assert!(validate_fault_registry_source_text(&moved_to_fault_helper).is_err());
    }

    #[test]
    fn fault_source_gate_requires_registry_commit_inside_io_commit_gate_and_late_release() {
        let source = checked_evaluator_source();
        let detached_commit = source.replacen(
            ".commit_with(identity, || budget.commit(credit, binding, 0))",
            ".commit_with(identity, || Ok::<_, ()>(()))",
            1,
        );
        assert_ne!(detached_commit, source);
        assert!(validate_fault_evaluator_source_text(&detached_commit).is_err());

        let early_release = source.replacen(
            "assert_eq!(self.gate.projection().phase, IoPhase::Quiesced);",
            "let _ = self.budget.finish();\n        assert_eq!(self.gate.projection().phase, IoPhase::Quiesced);",
            1,
        );
        assert_ne!(early_release, source);
        assert!(validate_fault_evaluator_source_text(&early_release).is_err());
    }

    #[test]
    fn accepts_exact_log_and_marks_only_performance_observed() {
        let parsed = parse_log(&valid_log().replace('\n', "\r\n"), None).unwrap();
        assert_eq!(parsed.faults.len(), 20);
        assert_eq!(parsed.scales.len(), 14);
        assert_eq!(parsed.performance.cases.len(), 29);
        assert_eq!(parsed.faults[0].status, "Checked");
        assert_eq!(parsed.performance.status, "Observed");
        assert!(parsed.performance.thresholds.is_none());
    }

    #[test]
    fn rejects_fault_missing_duplicate_unknown_and_reorder() {
        let first = valid_log().lines().next().unwrap().to_owned();
        reject(|log| log.replacen(&format!("{first}\n"), "", 1));
        reject(|log| log.replacen(&first, &format!("{first}\n{first}"), 1));
        reject(|log| log.replacen(FAULTS[0].id, "scheduler.unknown-cell", 1));
        reject(|log| {
            let a = log.lines().next().unwrap();
            let b = log.lines().nth(1).unwrap();
            log.replacen(&format!("{a}\n{b}"), &format!("{b}\n{a}"), 1)
        });
    }

    #[test]
    fn rejects_fault_family_terminal_publication_credit_and_quiescence_drift() {
        reject(|log| log.replacen("family=scheduler", "family=pager", 1));
        reject(|log| log.replacen("terminalizations=1", "terminalizations=2", 1));
        reject(|log| log.replacen("publications=1", "publications=2", 1));
        reject(|log| log.replacen("credits_after=0", "credits_after=1", 1));
        reject(|log| log.replacen("final_quiescent=true", "final_quiescent=false", 1));
    }

    #[test]
    fn rejects_scale_missing_duplicate_unknown_reorder_and_parameter_drift() {
        let first = valid_log()
            .lines()
            .find(|line| line.starts_with("STAGE7B_SCALE point="))
            .unwrap()
            .to_owned();
        reject(|log| log.replacen(&format!("{first}\n"), "", 1));
        reject(|log| log.replacen(&first, &format!("{first}\n{first}"), 1));
        reject(|log| log.replacen(SCALES[0].id, "fixed-n.unknown", 1));
        reject(|log| {
            let a = log
                .lines()
                .find(|line| line.starts_with("STAGE7B_SCALE point="))
                .unwrap();
            let b = log.lines().skip_while(|line| *line != a).nth(1).unwrap();
            log.replacen(&format!("{a}\n{b}"), &format!("{b}\n{a}"), 1)
        });
        reject(|log| log.replacen("N=1024 k=0 H=0", "N=1023 k=0 H=0", 1));
    }

    #[test]
    fn rejects_scale_work_and_final_state_drift() {
        reject(|log| log.replacen("next_calls=1", "next_calls=2", 1));
        reject(|log| log.replacen("unrelated_effect_visits=0", "unrelated_effect_visits=1", 1));
        reject(|log| log.replacen("history_effect_visits=0", "history_effect_visits=1", 1));
        reject(|log| log.replacen("final_target_state=Revoked", "final_target_state=Active", 1));
    }

    #[test]
    fn rejects_performance_meta_and_empty_timer_drift() {
        reject(|log| log.replacen("profile=release", "profile=debug", 1));
        reject(|log| log.replacen("accel=tcg", "accel=kvm", 1));
        reject(|log| log.replacen("empty_samples=257", "empty_samples=256", 1));
        reject(|log| {
            log.replacen(
                "STAGE7B_TSC_EMPTY samples=257",
                "STAGE7B_TSC_EMPTY samples=256",
                1,
            )
        });
        reject(|log| {
            log.replacen(
                "STAGE7B_TSC_EMPTY samples=257 min=1",
                "STAGE7B_TSC_EMPTY samples=257 min=2",
                1,
            )
        });
    }

    #[test]
    fn rejects_performance_case_missing_duplicate_unknown_and_reorder() {
        let rows: Vec<_> = valid_log()
            .lines()
            .filter(|line| line.starts_with("STAGE7B_TSC case="))
            .take(2)
            .map(str::to_owned)
            .collect();
        reject(|log| log.replacen(&format!("{}\n", rows[0]), "", 1));
        reject(|log| log.replacen(&rows[0], &format!("{}\n{}", rows[0], rows[0]), 1));
        reject(|log| log.replacen(PERFORMANCE[0].id, "begin.unknown", 1));
        reject(|log| {
            log.replacen(
                &format!("{}\n{}", rows[0], rows[1]),
                &format!("{}\n{}", rows[1], rows[0]),
                1,
            )
        });
    }

    #[test]
    fn rejects_performance_operation_sample_count_and_statistics_drift() {
        reject(|log| log.replacen("op=begin", "op=closure", 1));
        reject(|log| {
            let row = log
                .lines()
                .find(|line| line.starts_with("STAGE7B_TSC case="))
                .unwrap()
                .to_owned();
            let bad = row.replacen("samples=65", "samples=64", 1);
            log.replacen(&row, &bad, 1)
        });
        reject(|log| {
            let row = log
                .lines()
                .find(|line| line.starts_with("STAGE7B_TSC case="))
                .unwrap()
                .to_owned();
            let bad = row.replacen(" min=1 ", " min=2 ", 1);
            log.replacen(&row, &bad, 1)
        });
    }

    #[test]
    fn runtime_metadata_is_exact_and_cpu_pin_must_be_allowed() {
        let valid = "schema=nexus.stage7b.runtime-metadata.v1\naccel=tcg\nvcpus=1\nthreads=1\ncpu_pin=5\ncpus_allowed_list=0-3,5,8-9\n";
        let parsed = parse_runtime_metadata(valid).unwrap();
        assert_eq!(parsed.cpu_pin, 5);
        assert!(parse_runtime_metadata(&valid.replace("cpu_pin=5", "cpu_pin=7")).is_err());
        assert!(parse_runtime_metadata(&valid.replace("accel=tcg", "accel=kvm")).is_err());
        assert!(parse_runtime_metadata(&valid.replace("cpu_pin=5\n", "")).is_err());
    }

    #[test]
    fn run_publishes_stable_outputs_and_clears_them_on_invalid_input() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "nexus-stage7b-evidence-{}-{nonce}",
            std::process::id()
        ));
        let artifacts = root.join("kernel/nexus-ostd/artifacts");
        fs::create_dir_all(&artifacts).unwrap();
        let evaluator = root.join(EVALUATOR_SOURCE);
        fs::create_dir_all(evaluator.parent().unwrap()).unwrap();
        fs::write(&evaluator, checked_evaluator_source()).unwrap();
        let registry = root.join(FAULT_REGISTRY_SOURCE);
        fs::create_dir_all(registry.parent().unwrap()).unwrap();
        fs::write(&registry, checked_registry_source()).unwrap();
        fs::write(
            artifacts.join("stage7b-evaluation.log"),
            valid_log().replace('\n', "\r\n"),
        )
        .unwrap();
        fs::write(
            artifacts.join("stage7b-runtime-metadata.env"),
            "schema=nexus.stage7b.runtime-metadata.v1\naccel=tcg\nvcpus=1\nthreads=1\ncpu_pin=2\ncpus_allowed_list=0-3\n",
        )
        .unwrap();

        let summary = run(&root).unwrap();
        assert_eq!(
            summary,
            Summary {
                fault_cells: 20,
                scale_points: 14,
                performance_cases: 29,
                runtime_metadata: true,
            }
        );
        let output = root.join(OUTPUT_DIRECTORY);
        assert_eq!(
            fs::read_to_string(output.join(FAULT_OUTPUT))
                .unwrap()
                .lines()
                .count(),
            20
        );
        assert!(
            !fs::read(output.join(FAULT_OUTPUT))
                .unwrap()
                .contains(&b'\r')
        );
        assert_eq!(
            fs::read_to_string(output.join(SCALE_OUTPUT))
                .unwrap()
                .lines()
                .count(),
            14
        );
        let performance: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join(PERFORMANCE_OUTPUT)).unwrap()).unwrap();
        assert_eq!(performance["status"], "Observed");
        assert!(performance["thresholds"].is_null());
        assert_eq!(performance["cases"].as_array().unwrap().len(), 29);
        assert!(
            fs::read_to_string(output.join(ORACLE_OUTPUT))
                .unwrap()
                .contains("fault_registry_backed_nonzero_credit_cells=15")
        );

        fs::write(artifacts.join("stage7b-evaluation.log"), "invalid\n").unwrap();
        assert!(run(&root).is_err());
        for name in [
            FAULT_OUTPUT,
            SCALE_OUTPUT,
            PERFORMANCE_OUTPUT,
            ORACLE_OUTPUT,
        ] {
            assert!(!output.join(name).exists(), "stale output survived: {name}");
        }
        fs::remove_dir_all(root).unwrap();
    }
}
