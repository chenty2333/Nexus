use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

mod registry_source_set;
mod task_fault_source;

const INPUT: &str = "kernel/nexus-ostd/artifacts/stage7b-evaluation.log";
const RUNTIME_METADATA: &str = "kernel/nexus-ostd/artifacts/stage7b-runtime-metadata.env";
const EVALUATOR_SOURCE: &str = "kernel/nexus-ostd/src/evaluation/stage7b.rs";
const FAULT_REGISTRY_SOURCE: &str = registry_source_set::RegistryUnit::Authority.path();
const KERNEL_SOURCE_DIRECTORY: &str = "kernel/nexus-ostd/src";
const OUTPUT_DIRECTORY: &str = "target/verification/stage7b";
const FAULT_OUTPUT: &str = "fault-matrix.jsonl";
const EXPECTED_REGISTRY_CONSTRUCTORS: usize = 15;
const SCALE_OUTPUT: &str = "scale.jsonl";
const PERFORMANCE_OUTPUT: &str = "performance.json";
const ORACLE_OUTPUT: &str = "oracle.log";

// Production CSER sources deliberately resolve built-in derives and macros
// through exact local sysroot aliases. Keep Stage 7B's textual evidence gate
// just as strict by spelling those forms once and composing every checked
// declaration/call from them.
const CSER_CORE_DERIVE_DEBUG_EQ_PARTIAL_EQ: &str =
    "#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]";
const CSER_CORE_DERIVE_CLONE_COPY_DEBUG_EQ_PARTIAL_EQ: &str = concat!(
    "#[derive(\n",
    "    __cser_core::clone::Clone,\n",
    "    __cser_core::marker::Copy,\n",
    "    __cser_core::fmt::Debug,\n",
    "    __cser_core::cmp::Eq,\n",
    "    __cser_core::cmp::PartialEq,\n",
    ")]",
);
#[cfg(test)]
const CSER_CORE_DERIVE_CLONE_DEBUG_EQ_PARTIAL_EQ: &str = concat!(
    "#[derive(\n",
    "    __cser_core::clone::Clone,\n",
    "    __cser_core::fmt::Debug,\n",
    "    __cser_core::cmp::Eq,\n",
    "    __cser_core::cmp::PartialEq,\n",
    ")]",
);

macro_rules! cser_core_macro {
    ($name:literal, $tail:literal) => {
        concat!("__cser_core::", $name, "!", $tail)
    };
}

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
    let registry = registry_source_set::RegistrySourceSet::read_current(root)?;
    validate_fault_evaluator_source_text(&source)?;
    validate_fault_registry_source_set(&registry)?;
    validate_non_device_candidate_callers(root)
}

fn validate_non_device_candidate_callers(root: &Path) -> Result<(), String> {
    let source_root = root.join(KERNEL_SOURCE_DIRECTORY);
    let mut pending = vec![source_root.clone()];
    let mut observed = BTreeMap::<String, usize>::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| {
                format!(
                    "read directory entry under {}: {error}",
                    directory.display()
                )
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("inspect {}: {error}", path.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "kernel source caller audit rejects symlink: {}",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("rs")
            {
                continue;
            }
            let source = fs::read_to_string(&path)
                .map_err(|error| format!("read {}: {error}", path.display()))?;
            // Count the bare identifier rather than method-call syntax so
            // UFCS, comments between the name and parentheses, and multiline
            // calls cannot bypass the trusted-caller allowlist.
            let calls = source.matches("clone_non_device_candidate").count();
            if calls == 0 {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("kernel source escaped repository root: {}", path.display()))?
                .to_string_lossy()
                .into_owned();
            observed.insert(relative, calls);
        }
    }

    validate_non_device_candidate_caller_counts(&observed)
}

fn validate_non_device_candidate_caller_counts(
    observed: &BTreeMap<String, usize>,
) -> Result<(), String> {
    let expected = BTreeMap::from([
        (FAULT_REGISTRY_SOURCE.to_owned(), 4usize),
        (
            "kernel/nexus-ostd/src/cser/composition.rs".to_owned(),
            1usize,
        ),
        (
            "kernel/nexus-ostd/src/cser/linux_io_composition.rs".to_owned(),
            1usize,
        ),
    ]);
    if observed != &expected {
        return Err(format!(
            "non-device Registry candidate callers must remain the exact two legacy evaluators plus Registry self-tests; production callers are forbidden (expected {expected:?}, observed {observed:?})"
        ));
    }
    Ok(())
}

fn validate_fault_registry_source_set(
    sources: &registry_source_set::RegistrySourceSet,
) -> Result<(), String> {
    registry_source_set::validate_source_set(sources)?;

    let mut semantic_registry_constructors = 0usize;
    let mut textual_registry_constructors = 0usize;
    for (_, source) in sources.iter() {
        semantic_registry_constructors = semantic_registry_constructors
            .checked_add(task_fault_source::count_registry_constructors(source)?)
            .ok_or_else(|| "Stage 7B Registry constructor population overflowed".to_owned())?;
        textual_registry_constructors = textual_registry_constructors
            .checked_add(source.matches("EffectRegistry::new()").count())
            .ok_or_else(|| {
                "Stage 7B textual Registry constructor population overflowed".to_owned()
            })?;
    }
    if semantic_registry_constructors != EXPECTED_REGISTRY_CONSTRUCTORS
        || textual_registry_constructors != EXPECTED_REGISTRY_CONSTRUCTORS
    {
        return Err(format!(
            "Stage 7B Registry source-set constructor population drifted; hidden sidecars are forbidden (expected {EXPECTED_REGISTRY_CONSTRUCTORS}, observed semantic={semantic_registry_constructors} textual={textual_registry_constructors})"
        ));
    }

    let task_fault_source = sources.source(registry_source_set::TASK_FAULT_EVIDENCE_UNIT)?;
    task_fault_source::validate_task_fault_self_tests_source(task_fault_source)?;

    let authority = sources.source(registry_source_set::RegistryUnit::Authority)?;
    validate_fault_registry_authority_source_text(authority)
}

#[cfg(test)]
fn validate_fault_registry_source_text(source: &str) -> Result<(), String> {
    validate_fault_registry_source_set(&registry_source_set::RegistrySourceSet::from_authority(
        source,
    ))
}

fn validate_fault_registry_authority_source_text(source: &str) -> Result<(), String> {
    if source.contains("validate_device_replay_fence_candidate") {
        return Err(
            "production Registry must not retain the obsolete read-only replay-fence validator"
                .into(),
        );
    }
    let publication_start = source
        .find("fn publication_ack_and_revoke_complete_self_test() {")
        .ok_or_else(|| "Registry lacks combined publication/revoke self-test".to_owned())?;
    let publication_end = source[publication_start..]
        .find("#[cfg(test)]\nfn combined_scope_candidate_self_test() {")
        .map(|offset| publication_start + offset)
        .ok_or_else(|| {
            "combined publication/revoke self-test boundary is unterminated".to_owned()
        })?;
    let publication = &source[publication_start..publication_end];
    if publication.matches("EffectRegistry::new()").count() != 1
        || publication
            .matches("let mut registry = EffectRegistry::new();")
            .count()
            != 1
        || publication
            .matches("acknowledge_publication_and_revoke_complete_with_apply(")
            .count()
            != 4
        || publication
            .matches(cser_core_macro!(
                "assert_eq",
                "(two_pending_applies.get(), 0);"
            ))
            .count()
            != 1
        || publication
            .matches(cser_core_macro!("assert_eq", "(wrong_applies.get(), 0);"))
            .count()
            != 1
        || publication
            .matches(cser_core_macro!(
                "assert_eq",
                "(overflow_applies.get(), 0);"
            ))
            .count()
            != 1
        || publication
            .matches(cser_core_macro!(
                "assert_eq",
                "(successful_applies.get(), 1);"
            ))
            .count()
            != 1
    {
        return Err(
            "combined publication/revoke self-test must own one Registry and prove three prevalidation rejections plus one external apply"
                .into(),
        );
    }

    let combined_start = source
        .find("#[cfg(test)]\nfn combined_scope_candidate_self_test() {")
        .ok_or_else(|| "Registry lacks combined-scope candidate self-test".to_owned())?;
    let combined_end = source[combined_start..]
        .find("#[cfg(test)]\nfn task_owned_fault_outer_transaction_self_test() {")
        .map(|offset| combined_start + offset)
        .ok_or_else(|| "combined-scope candidate self-test boundary is unterminated".to_owned())?;
    let combined = &source[combined_start..combined_end];
    if combined.matches("EffectRegistry::new()").count() != 1
        || combined
            .matches("let mut registry = EffectRegistry::new();")
            .count()
            != 1
        || combined
            .matches("fn fixture() -> (EffectRegistry, EffectKey, EffectKey) {")
            .count()
            != 1
    {
        return Err(
            "combined-scope candidate self-test must own one fixture-local authoritative Registry"
                .into(),
        );
    }

    let retained_start = source
        .find("pub(crate) fn retained_semantic_test_fixture() -> RetainedSemanticTestFixture {")
        .ok_or_else(|| "Registry lacks retained-semantic fixture".to_owned())?;
    let retained = &source[retained_start..];
    if retained.matches("EffectRegistry::new()").count() != 1
        || retained
            .matches("ProductionDeviceBatchRaceFixture::from_empty_registry(EffectRegistry::new())")
            .count()
            != 1
        || retained
            .matches("let mut foreign_operation = exact_operation;")
            .count()
            != 1
        || retained
            .matches("Err(DeviceCloseError::Published { obligation, error })")
            .count()
            != 1
    {
        return Err(
            "retained-semantic fixture must own one Registry and derive exact/foreign identities from one authoritative published obligation"
                .into(),
        );
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
        || atomic
            .matches(cser_core_macro!("assert_eq", "(atomic, before);"))
            .count()
            != 4
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
        .find("fn production_device_batch_registry_self_test(")
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
        || production
            .matches("combined_scope_candidate_self_test();")
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
        cser_core_macro!(
            "assert",
            "(registry.revoke_next(&selection).unwrap().is_none());"
        ),
    ] {
        if !production.contains(required) {
            return Err(format!(
                "production-identity implementation self-test lacks required transition: {required}"
            ));
        }
    }
    let device_end = source[production_end..]
        .find("pub(crate) fn bounded_registry_self_test() -> RegistrySelfTestReceipt {")
        .map(|offset| production_end + offset)
        .ok_or_else(|| {
            "production device-batch Registry self-test boundary is unterminated".to_owned()
        })?;
    let device = &source[production_end..device_end];
    let population_end = device
        .find("let registered = [")
        .ok_or_else(|| "production device-batch population boundary is missing".to_owned())?;
    let population = &device[..population_end];
    if device.matches("EffectRegistry::new()").count() != 0
        || population.matches(".register_derived(").count() != 2
        || source.matches("clone_non_device_candidate").count() != 4
        || population.matches("clone_non_device_candidate").count() != 3
        || device.matches("clone_non_device_candidate").count() != 3
        || population.matches(".register_device_derived(").count() != 1
        || population
            .matches(".register_device_derived_cohort(")
            .count()
            != 4
        || device.matches("device_root_installed(").count() != 3
        || device.matches(".register_derived(").count() != 6
        || device.matches(".register_device_derived(").count() != 2
        || device.matches(".register_device_derived_cohort(").count() != 4
        || device.matches("commit_device_batch_with_publish(").count() != 8
        || device
            .matches("commit_or_recover_device_close_with_apply(")
            .count()
            != 9
        || device.matches("mint_device_close_operation(").count() != 4
        || device.matches("validate_device_batch_receipt(").count() != 8
        || device
            .matches("claim_device_replay_reset_and_revoke(")
            .count()
            != 0
        || device.matches("enroll_device_batch(").count() != 4
        || device.matches("freeze_pending_device_cancel(").count() != 2
        || device.matches(".cancel_only()").count() != 4
        || device
            .matches("close_pending_device_precommit_with_apply(")
            .count()
            != 2
        || device
            .matches("close_enrolled_device_precommit_with_apply(")
            .count()
            != 3
        || device
            .matches(cser_core_macro!("assert_eq", "(hardware_calls.get(), 0);"))
            .count()
            != 2
        || device.matches("begin_unpublished_device_cancel(").count() != 4
        || device.matches("retain_device_reset_timeout(").count() != 7
        || device.matches("retry_device_reset(").count() != 5
        || device.matches("retain_device_iotlb_timeout(").count() != 7
        || device.matches("retry_device_iotlb(").count() != 5
        || device
            .matches("acknowledge_device_iotlb_with_apply(")
            .count()
            != 9
    {
        return Err(
            "production device-batch self-test must reuse the production Registry and preserve its exact failure-atomic cohort, operation-id fresh/recovery, precommit, closure, timeout, retry, and receipt population"
                .into(),
        );
    }

    let operation_close_start = device
        .find("let close_operation = registry")
        .ok_or_else(|| {
            "production device-batch self-test lacks operation-id close coverage".to_owned()
        })?;
    let operation_close_end = device[operation_close_start..]
        .find("let legacy_operation = registry")
        .map(|offset| operation_close_start + offset)
        .ok_or_else(|| "operation-id close coverage boundary is unterminated".to_owned())?;
    let operation_close = &device[operation_close_start..operation_close_end];
    if operation_close
        .matches("commit_or_recover_device_close_with_apply(")
        .count()
        != 8
        || operation_close
            .matches("mint_device_close_operation(")
            .count()
            != 3
        || operation_close
            .matches("assert_fresh_close_overflow(&mut ")
            .count()
            != 5
        || operation_close
            .matches("DeviceCloseOutcome::Applied")
            .count()
            != 3
        || operation_close
            .matches("DeviceCloseOutcome::Recovered")
            .count()
            != 3
        || operation_close
            .matches("DeviceCloseError::Unpublished")
            .count()
            != 2
        || operation_close
            .matches("DeviceCloseError::Published")
            .count()
            != 3
    {
        return Err(
            "operation-id close self-test must preserve exact fresh, same-operation Closing/Revoked recovery, drift, corrupt-state, and overflow coverage"
                .into(),
        );
    }
    for required in [
        ".mint_device_close_operation(&enrollment, 0x51_0001)",
        "close_operation.registry_instance_id()",
        "close_operation.enrollment_sequence()",
        "close_operation.caller_nonce()",
        "registry.mint_device_close_operation(&enrollment, 0)",
        "let mut fresh_close = registry.clone();",
        "let fresh_close_revoke_sequence = fresh_close.next_revoke_sequence;",
        "let fresh_close_commit_sequence = fresh_close.next_commit_sequence;",
        "let fresh_close_batch_sequence = fresh_close.next_device_batch_sequence;",
        "DeviceCloseOutcome::Applied {",
        cser_core_macro!("assert_eq", "(fresh_close_publications.get(), 1);"),
        "fresh_close_before.authority_epoch + 1",
        "fresh_close_before.revision + 3",
        "fresh_close_revoke_sequence + 1",
        "fresh_close_commit_sequence + 6",
        "fresh_close_batch_sequence + 1",
        "&fresh_close_root.publication,",
        "DevicePublicationProvenance::Applied { operation, batch }",
        "if *operation == close_operation && batch == &fresh_close_receipt",
        "let mut rewritten_close = fresh_close.clone();",
        "rewritten_close.rewrite_registry_instance(rewritten_close_id);",
        "rewritten_close.check_invariants().unwrap();",
        "let before_closing_recovery = fresh_close.clone();",
        "DeviceCloseOutcome::Recovered { receipt, selection }",
        cser_core_macro!("assert_eq", "(closing_recovery_publications.get(), 0);"),
        cser_core_macro!("assert_eq", "(fresh_close, before_closing_recovery);"),
        "interrupted_close.revoke_begin(SCOPE)",
        "Err(RegistryError::DeviceClosurePending)",
        "forced_closing.begin_unpublished_device_cancel(&enrollment)",
        cser_core_macro!("assert_eq", "(forced_closing, forced_closing_before);"),
        "let assert_published_close_error =",
        "Err(DeviceCloseError::Published { obligation, .. })",
        "obligation.operation(), Some(close_operation)",
        "obligation.revoke(), Some(&fresh_close_selection)",
        "let mut wrong_operation_candidate = fresh_close.clone();",
        "let mut wrong_registry_candidate = fresh_close.clone();",
        "let mut wrong_enrollment_candidate = fresh_close.clone();",
        "let mut wrong_metadata_candidate = fresh_close.clone();",
        "let mut corrupt_operation_state = fresh_close.clone();",
        "root.batch_sequence = None;",
        "root.publication = DevicePublicationProvenance::Applied {",
        "Some(fresh_close_receipt.batch_sequence())",
        "let assert_fresh_close_overflow = |candidate: &mut EffectRegistry| {",
        "Err(DeviceCloseError::Unpublished(",
        cser_core_macro!("assert_eq", "(publish_calls.get(), 0);"),
        cser_core_macro!("assert_eq", "(*candidate, before);"),
        "close_revoke_overflow.next_revoke_sequence = u64::MAX;",
        "close_commit_overflow.next_commit_sequence = u64::MAX - 5;",
        "close_batch_overflow.next_device_batch_sequence = u64::MAX;",
        "let mut close_commit_revision_overflow = registry.clone();",
        ".revision = u64::MAX;",
        "let mut close_revoke_revision_overflow = registry.clone();",
        ".revision = u64::MAX - 1;",
        "let mut close_authority_overflow = registry.clone();",
        "overflow_enrollment.authority_epoch = u64::MAX;",
        "let mut revoked_recovery = fresh_close.clone();",
        ".revoke_complete(&fresh_close_selection)",
        "revoked_recovery.scope_projection(SCOPE).unwrap().phase,",
        "let before_revoked_recovery = revoked_recovery.clone();",
        cser_core_macro!("assert_eq", "(revoked_recovery_publications.get(), 0);"),
        cser_core_macro!("assert_eq", "(revoked_recovery, before_revoked_recovery);"),
    ] {
        if !operation_close.contains(required) {
            return Err(format!(
                "operation-id close self-test lacks required idempotency witness: {required}"
            ));
        }
    }
    for required in [
        "let device_cohort = || {",
        "negative.register_device_derived_cohort(entries)",
        cser_core_macro!("assert_eq", "(negative, before, \"{label}\");"),
        "\"middle credit\"",
        "\"middle resource\"",
        "\"middle ancestry\"",
        "\"middle device\"",
        "\"forward parent\"",
        "\"self parent\"",
        "\"invalid parent\"",
        "\"duplicate slot\"",
        "\"missing slot\"",
        "counter_failure.next_effect_id = u64::MAX - 1;",
        cser_core_macro!("assert_eq", "(counter_failure, counter_before);"),
        "disabled_cohort.register_device_derived_cohort(device_cohort())",
        cser_core_macro!("assert_eq", "(disabled_cohort, disabled_cohort_before);"),
        cser_core_macro!(
            "assert_eq",
            "(registry.device_root_installed(SCOPE), Ok(false));"
        ),
        "registry.device_root_installed(ScopeKey::new(0xdead, 1))",
        "let [block, dma_a, dma_b, dma_request] = registry",
        ".register_device_derived_cohort(device_cohort())",
        cser_core_macro!(
            "assert_eq",
            "(registry.device_root_installed(SCOPE), Ok(true));"
        ),
        cser_core_macro!(
            "assert_eq",
            "(dma.identity.parent(), Some(block.identity.effect()));"
        ),
        "let registered = [",
        cser_core_macro!("assert_eq", "(registry.effects_for_scope(SCOPE).len(), 6);"),
        cser_core_macro!("assert_eq", "(prepared.commits().len(), 6);"),
        cser_core_macro!("assert_eq", "(prepared.device_effects().len(), 4);"),
        "split.commit(PERSONALITY, syscall.handle, commits[0].1)",
        "Err(RegistryError::InvalidDeviceEnvelope)",
        "let assert_pending_precommit_error =",
        "candidate.close_pending_device_precommit_with_apply(SCOPE, |_| {",
        cser_core_macro!("assert_eq", "(compound_pending_hardware_calls.get(), 1);"),
        "compound_pending_before.revision + 3",
        "compound_pending_enrollment_sequence + 1",
        "let mut pending_retention_overflow = registry.clone();",
        "let mut pending_wrong_revoke_cohort = registry.clone();",
        "let cancel_enrollment = pending_cancel.freeze_pending_device_cancel(SCOPE).unwrap();",
        cser_core_macro!("assert", "(cancel_enrollment.cancel_only());"),
        "let registered_enrollment = registered_cancel",
        ".freeze_pending_device_cancel(SCOPE)",
        cser_core_macro!("assert", "(registered_enrollment.cancel_only());"),
        cser_core_macro!("assert_eq", "(registered_enrollment.effects().len(), 7);"),
        cser_core_macro!("assert_eq", "(registered_closed, 7);"),
        "let enrollment = registry",
        ".enroll_device_batch(authority, &handles, device)",
        "let assert_enrolled_precommit_error =",
        "candidate.close_enrolled_device_precommit_with_apply(presented, |_| {",
        cser_core_macro!("assert_eq", "(compound_enrolled_hardware_calls.get(), 1);"),
        "compound_enrolled_before.revision + 2",
        "let mut enrolled_retention_overflow = registry.clone();",
        "let mut enrolled_wrong_revoke_cohort = registry.clone();",
        "Err(RegistryError::DeviceClosurePending)",
        "retain_device_reset_timeout(&reset_ticket)",
        "DeviceClosureResult::IndeterminateAfterReset",
        "Err(RegistryError::StaleDeviceGeneration)",
        "retain_device_iotlb_timeout(&iotlb)",
        "stage_device_batch_terminal(",
        cser_core_macro!("assert_eq", "(closed.credits.retained, 0);"),
        "Err(RegistryError::StaleDeviceGeneration)",
        "Err(RegistryError::InvalidBatchReceipt)",
        "Err(RegistryError::CounterOverflow)",
        "DeviceBatchCommitOutcome::AlreadyCommitted",
        "let cancel_tombstone = revoke_first.retain_device_reset_timeout(&cancel).unwrap();",
        "let cancel_retry = revoke_first.retry_device_reset(&cancel_tombstone).unwrap();",
        "let final_reset_tombstone = final_reset_timeout",
        "retained unpublished credits lack uniform closing precommit abort",
        "let iotlb_tombstone = revoke_first.retain_device_iotlb_timeout(&iotlb).unwrap();",
        ".retry_device_iotlb(&reset, &iotlb_tombstone)",
        "let final_iotlb_tombstone = final_iotlb_timeout",
        "let legacy_operation = registry",
        ".mint_device_close_operation(&enrollment, 0x51_1001)",
        "let legacy_before = registry.clone();",
        "registry.commit_or_recover_device_close_with_apply(",
        "Err(DeviceCloseError::Published { obligation, error })",
        cser_core_macro!("assert_eq", "(obligation.operation(), None);"),
        cser_core_macro!("assert_eq", "(obligation.phase(), ScopePhase::Active);"),
        cser_core_macro!("assert_eq", "(obligation.revoke(), None);"),
        "legacy committed state was not an honest Published error",
        cser_core_macro!("assert_eq", "(legacy_publish_calls.get(), 0);"),
        cser_core_macro!("assert_eq", "(*registry, legacy_before);"),
        "wrong_completion_result.record_device_completion(&receipt, device, 512)",
        "Err(RegistryError::CommitConflict)",
        cser_core_macro!(
            "assert_eq",
            "(wrong_completion_result, wrong_completion_before);"
        ),
        cser_core_macro!(
            "assert_eq",
            "(completion.causal_root(), syscall.identity.effect());"
        ),
        "let selection = registry.revoke_begin(SCOPE).unwrap();",
        "registry.validate_device_batch_receipt(&receipt).unwrap();",
    ] {
        if !device.contains(required) {
            return Err(format!(
                "production device-batch Registry self-test lacks required transition: {required}"
            ));
        }
    }
    if source
        .matches("production_device_batch_registry_self_test(&mut registry);")
        .count()
        != 1
    {
        return Err(
            "production device-batch coverage must reuse exactly one workload-owned Registry"
                .into(),
        );
    }

    let bounded_self_test = &source[device_end..];
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
    let expected_budget = format!(
        "{CSER_CORE_DERIVE_DEBUG_EQ_PARTIAL_EQ}\n{}",
        concat!(
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
        ),
    );
    let expected_state = format!(
        "{CSER_CORE_DERIVE_DEBUG_EQ_PARTIAL_EQ}\n{}",
        concat!(
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
        ),
    );
    if helper
        .matches("pub(crate) struct Stage7bFaultBudget {")
        .count()
        != 1
        || !helper.contains(&expected_budget)
        || helper
            .matches("pub(crate) struct Stage7bFaultBudgetState {")
            .count()
            != 1
        || !helper.contains(&expected_state)
    {
        return Err(
            "Stage 7B fault budget and its failure-atomic snapshot must retain their exact complete field sets"
                .into(),
        );
    }
    let expected_state_clone = concat!(
        "impl Clone for Stage7bFaultBudgetState {\n",
        "    fn clone(&self) -> Self {\n",
        "        Self {\n",
        "            case: self.case,\n",
        "            instance_id: self.instance_id,\n",
        "            registry: self.registry.clone(),\n",
        "            scope: self.scope,\n",
        "            task: self.task,\n",
        "            credit: self.credit,\n",
        "            bindings: self.bindings.clone(),\n",
        "            commit_operations: self.commit_operations,\n",
        "            terminal_operations: self.terminal_operations,\n",
        "        }\n",
        "    }\n",
        "}\n",
    );
    if helper.matches("registry.clone()").count() != 2
        || helper
            .matches("impl Clone for Stage7bFaultBudgetState {")
            .count()
            != 1
        || !helper.contains(expected_state_clone)
    {
        return Err(
            "Stage 7B fault budget permits exactly one complete custom snapshot clone and one snapshot construction clone"
                .into(),
        );
    }

    let observed_start = helper
        .find("pub(crate) fn observed_credit_units(")
        .ok_or_else(|| {
            "Stage 7B fault Registry lacks phase-derived credit observation".to_owned()
        })?;
    let observed_end_marker = format!("\n}}\n\n{CSER_CORE_DERIVE_DEBUG_EQ_PARTIAL_EQ}");
    let observed_end = helper[observed_start..]
        .find(&observed_end_marker)
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
        ".and_then(|owned|owned.checked_add(credits.retained))",
        ".ok_or(RegistryError::CounterOverflow)?,",
        "ScopePhase::Revoked=>credits.free,",
        "};",
        "usize::try_from(units).map_err(|_|RegistryError::CounterOverflow)",
        "}",
    );
    if observed_compact != expected_observed {
        return Err(
            "Stage 7B fault Registry credit observation must remain the exact phase-derived held+committed+retained/free projection"
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
        ".and_then(|owned| owned.checked_add(credits.retained))",
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
        cser_core_macro!("assert_eq", "(cross_scope, cross_scope_before);"),
        "first_commit.registry_instance_id",
        cser_core_macro!("assert_eq", "(first_commit.scope, second_commit.scope);"),
        cser_core_macro!("assert_eq", "(first, first_before);"),
        cser_core_macro!("assert_eq", "(second, second_before);"),
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
    validate_production_device_batch_source_text(source)?;
    Ok(())
}

fn validate_production_device_batch_source_text(source: &str) -> Result<(), String> {
    let terminal_start = source
        .find("pub(crate) enum TerminalOutcome {")
        .ok_or_else(|| "production Registry lacks its terminal outcome type".to_owned())?;
    let terminal_end = source[terminal_start..]
        .find("pub(crate) enum EffectPhase {")
        .map(|offset| terminal_start + offset)
        .ok_or_else(|| "terminal outcome boundary is unterminated".to_owned())?;
    let terminal_outcome: String = source[terminal_start..terminal_end]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let compact_terminal_derive: String = CSER_CORE_DERIVE_CLONE_COPY_DEBUG_EQ_PARTIAL_EQ
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let expected_terminal_outcome = format!(
        "pub(crate)enumTerminalOutcome{{Completed,IndeterminateAfterReset,Aborted,}}{compact_terminal_derive}"
    );
    if terminal_outcome != expected_terminal_outcome {
        return Err(
            "TerminalOutcome must preserve exactly Completed, IndeterminateAfterReset, and Aborted"
                .into(),
        );
    }
    let compact_source: String = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact_source
        .matches(
            "pub(crate)constfnindeterminate_after_reset(result:i64)->Self{Self{outcome:TerminalOutcome::IndeterminateAfterReset,result,causal_commit:None,manifest_digest:None,}}",
        )
        .count()
        != 1
    {
        return Err(
            "TerminalRequest must expose exactly one real IndeterminateAfterReset constructor"
                .into(),
        );
    }

    let cohort_gate_start = source
        .find("pub(crate) fn register_device_derived_cohort(")
        .ok_or_else(|| "production Registry lacks failure-atomic device cohort gate".to_owned())?;
    let cohort_prepare_start = source[cohort_gate_start..]
        .find("    fn prepare_device_derived_cohort(")
        .map(|offset| cohort_gate_start + offset)
        .ok_or_else(|| "device cohort prepare boundary is unterminated".to_owned())?;
    let cohort_apply_start = source[cohort_prepare_start..]
        .find("    fn apply_device_derived_cohort(")
        .map(|offset| cohort_prepare_start + offset)
        .ok_or_else(|| "device cohort apply boundary is unterminated".to_owned())?;
    let cohort_end = source[cohort_apply_start..]
        .find("    pub(crate) fn descriptor(")
        .map(|offset| cohort_apply_start + offset)
        .ok_or_else(|| "device cohort apply boundary is unterminated".to_owned())?;
    let cohort_gate = &source[cohort_gate_start..cohort_prepare_start];
    let cohort_prepare = &source[cohort_prepare_start..cohort_apply_start];
    let cohort_apply = &source[cohort_apply_start..cohort_end];
    for required in [
        "self.require_unique_device_publication()?;",
        "let plan = self.prepare_device_derived_cohort(entries)?;",
        "Ok(self.apply_device_derived_cohort(plan))",
    ] {
        if !cohort_gate.contains(required) {
            return Err(format!(
                "device cohort gate lacks required prepare/apply step {required:?}"
            ));
        }
    }
    for required in [
        "let mut slots = [None, None, None, None];",
        "batch_index >= slots.len() || slots[batch_index].is_some()",
        "parent_index >= slots.len() || parent_index >= batch_index",
        "slots[batch_index] = Some(entry);",
        "DeviceCohortParent::Existing(parent) => parent,",
        "dma_a_entry.parent != DeviceCohortParent::BatchIndex(0)",
        "dma_b_entry.parent != DeviceCohortParent::BatchIndex(0)",
        "dma_request_entry.parent != DeviceCohortParent::BatchIndex(0)",
        "let mut candidate = self.clone();",
        "let block = candidate.register_device_derived(",
        "let block_effect = block.identity.effect();",
        "candidate.check_invariants()?;",
        "registered: [block, dma_a, dma_b, dma_request],",
    ] {
        if !cohort_prepare.contains(required) {
            return Err(format!(
                "device cohort prevalidation lacks required atomicity/ancestry step {required:?}"
            ));
        }
    }
    if cohort_prepare
        .matches("candidate.register_device_derived(")
        .count()
        != 4
        || cohort_prepare.contains("self.register_device_derived(")
    {
        return Err(
            "device cohort prevalidation must register exactly four entries only in its private candidate"
                .into(),
        );
    }
    let cohort_apply_compact: String = cohort_apply
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let expected_cohort_apply = concat!(
        "fnapply_device_derived_cohort(&mutself,plan:DeviceDerivedCohortPlan,)",
        "->[RegisteredEffect;4]{",
        "letDeviceDerivedCohortPlan{candidate,registered,}=plan;",
        "*self=candidate;",
        "registered",
        "}",
    );
    if cohort_apply_compact != expected_cohort_apply {
        return Err(
            "device cohort live apply must remain the canonical allocation-free, error-free candidate replacement"
                .into(),
        );
    }

    let registry_impl_start = source
        .find("impl EffectRegistry {")
        .ok_or_else(|| "production Registry lacks its inherent impl".to_owned())?;
    let registry_impl_end = source[registry_impl_start..]
        .find("\nfn validate_generation(")
        .map(|offset| registry_impl_start + offset)
        .ok_or_else(|| "production Registry inherent impl boundary is unterminated".to_owned())?;
    let registry_impl = &source[registry_impl_start..registry_impl_end];
    let candidate_clone_start = registry_impl
        .find("pub(super) fn clone_non_device_candidate(")
        .ok_or_else(|| "legacy candidate clone is not parent-module-only".to_owned())?;
    let candidate_clone_end = registry_impl[candidate_clone_start..]
        .find("    fn require_unique_device_publication(")
        .map(|offset| candidate_clone_start + offset)
        .ok_or_else(|| "legacy candidate clone boundary is unterminated".to_owned())?;
    let projection_clone_start = registry_impl
        .find("pub(crate) fn failure_atomic_projection(&self) -> String")
        .ok_or_else(|| "Registry lacks its diagnostic projection".to_owned())?;
    let projection_clone_end = registry_impl[projection_clone_start..]
        .find("    fn rewrite_registry_instance(")
        .map(|offset| projection_clone_start + offset)
        .ok_or_else(|| "Registry diagnostic projection boundary is unterminated".to_owned())?;
    let exact_registry_declaration =
        format!("{CSER_CORE_DERIVE_DEBUG_EQ_PARTIAL_EQ}\npub(crate) struct EffectRegistry {{");
    if source.matches(&exact_registry_declaration).count() != 1
        || registry_impl
            .matches("    fn clone(&self) -> Self {")
            .count()
            != 1
        || registry_impl.contains("pub(crate) fn clone(&self) -> Self")
        || registry_impl.contains("pub(super) fn clone(&self) -> Self")
        || source.contains("impl Clone for EffectRegistry")
        || registry_impl.contains("authority_copy")
        || registry_impl.matches("self.clone()").count() != 3
        || registry_impl[candidate_clone_start..candidate_clone_end]
            .matches("self.clone()")
            .count()
            != 1
        || registry_impl[projection_clone_start..projection_clone_end]
            .matches("self.clone()")
            .count()
            != 1
        || cohort_prepare.matches("self.clone()").count() != 1
    {
        return Err(
            "EffectRegistry inherent cloning must remain private and confined to the exact legacy candidate, diagnostic projection, and device-cohort preparation sites"
                .into(),
        );
    }

    let operation_start = source
        .find("pub(crate) struct DeviceCloseOperationId {")
        .ok_or_else(|| {
            "production Registry lacks opaque device-close operation identity".to_owned()
        })?;
    let operation_impl = source[operation_start..]
        .find("impl DeviceCloseOperationId {")
        .map(|offset| operation_start + offset)
        .ok_or_else(|| "device-close operation identity boundary is unterminated".to_owned())?;
    let operation_compact: String = source[operation_start..operation_impl]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let exact_operation_derive = format!("{CSER_CORE_DERIVE_CLONE_COPY_DEBUG_EQ_PARTIAL_EQ}\n");
    if operation_compact
        != concat!(
            "pub(crate)structDeviceCloseOperationId{",
            "registry_instance_id:u64,",
            "scope:ScopeKey,",
            "authority_epoch:u64,",
            "enrollment_sequence:u64,",
            "device:DeviceEnvelope,",
            "owner:TaskKey,",
            "caller_nonce:u64,",
            "}"
        )
        || !source[..operation_start].ends_with(&exact_operation_derive)
    {
        return Err(
            "DeviceCloseOperationId must remain opaque, Copy, and exactly bound to Registry/enrollment/root/caller coordinates"
                .into(),
        );
    }
    for required in [
        "pub(crate) const fn registry_instance_id(self) -> u64",
        "pub(crate) const fn scope(self) -> ScopeKey",
        "pub(crate) const fn enrollment_sequence(self) -> u64",
        "pub(crate) const fn caller_nonce(self) -> u64",
        "pub(crate) enum DeviceCloseOutcome<T> {",
        "Recovered {\n        receipt: DeviceBatchCommitReceipt,\n        selection: RevokeSelection,",
        "pub(crate) struct DevicePublishedObligation {",
        "batch_sequence: Option<u64>,",
        "operation: Option<DeviceCloseOperationId>,",
        "phase: ScopePhase,",
        "revoke: Option<RevokeSelection>,",
        "pub(crate) const fn batch_sequence(&self) -> Option<u64>",
        "pub(crate) const fn operation(&self) -> Option<DeviceCloseOperationId>",
        "pub(crate) const fn status(&self) -> DevicePublishedStatus",
        "pub(crate) const fn phase(&self) -> ScopePhase",
        "pub(crate) const fn revoke(&self) -> Option<&RevokeSelection>",
        "enum DevicePublicationProvenance {",
        "Publishing {\n        operation: DeviceCloseOperationId,\n        batch: DeviceBatchCommitReceipt,",
        "Applied {\n        operation: DeviceCloseOperationId,\n        batch: DeviceBatchCommitReceipt,",
        "publication: DevicePublicationProvenance,",
        "operation.rewrite_registry_instance(registry_instance_id);",
        "batch.rewrite_registry_instance(registry_instance_id);",
        "publishing device close provenance drift",
        "published root lacks applied publication provenance",
        "unpublished root retained applied publication provenance",
    ] {
        if !source.contains(required) {
            return Err(format!(
                "operation-id Registry state lacks required opaque/stored/invariant step {required:?}"
            ));
        }
    }

    let provenance_start = source
        .find("enum DevicePublicationProvenance {")
        .ok_or_else(|| "Registry lacks root-local publication provenance".to_owned())?;
    let provenance_end = source[provenance_start..]
        .find("impl DevicePublicationProvenance {")
        .map(|offset| provenance_start + offset)
        .ok_or_else(|| "publication provenance boundary is unterminated".to_owned())?;
    let provenance_compact: String = source[provenance_start..provenance_end]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if provenance_compact
        != concat!(
            "enumDevicePublicationProvenance{",
            "None,",
            "Legacy,",
            "Publishing{operation:DeviceCloseOperationId,batch:DeviceBatchCommitReceipt,},",
            "Applied{operation:DeviceCloseOperationId,batch:DeviceBatchCommitReceipt,},",
            "}"
        )
    {
        return Err(
            "device publication provenance must remain one exact None/Legacy/Publishing/Applied authority, with operation and batch inseparable"
                .into(),
        );
    }

    let close_error_start = source
        .find("pub(crate) enum DeviceCloseError {")
        .ok_or_else(|| "production Registry lacks honest device-close error type".to_owned())?;
    let close_error_end = source[close_error_start..]
        .find("/// Honest backend result retained through reset and IOTLB closure.")
        .map(|offset| close_error_start + offset)
        .ok_or_else(|| "device-close error boundary is unterminated".to_owned())?;
    let close_error_compact: String = source[close_error_start..close_error_end]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if close_error_compact
        != concat!(
            "pub(crate)enumDeviceCloseError{",
            "Unpublished(RegistryError),",
            "Published{obligation:DevicePublishedObligation,error:RegistryError,},",
            "}"
        )
    {
        return Err(
            "device-close errors must distinguish only unpublished state from published ownership obligation"
                .into(),
        );
    }

    let combined_start = source
        .find("pub(crate) fn acknowledge_publication_and_revoke_complete(")
        .ok_or_else(|| "Registry lacks combined publication/revoke transition".to_owned())?;
    let combined_apply_start = source[combined_start..]
        .find("pub(crate) fn acknowledge_publication_and_revoke_complete_with_apply<T>(")
        .map(|offset| combined_start + offset)
        .ok_or_else(|| {
            "combined publication/revoke transition lacks external apply gate".to_owned()
        })?;
    let combined_end = source[combined_apply_start..]
        .find("    fn prepare_publication_ack(")
        .map(|offset| combined_apply_start + offset)
        .ok_or_else(|| "combined publication/revoke apply boundary is unterminated".to_owned())?;
    let combined_wrapper = &source[combined_start..combined_apply_start];
    let combined_apply = &source[combined_apply_start..combined_end];
    if !combined_wrapper.contains(
        "self.acknowledge_publication_and_revoke_complete_with_apply(ticket, selection, || ())",
    ) {
        return Err(
            "plain combined publication/revoke transition must delegate to the prevalidated external-apply gate"
                .into(),
        );
    }
    let publication_prepare = combined_apply
        .find("let publication = self.prepare_publication_ack(ticket)?;")
        .ok_or_else(|| "combined transition skips publication prevalidation".to_owned())?;
    let revoke_prepare = combined_apply
        .find("let revoke = self.prepare_revoke_complete_apply(selection, Some(&publication))?;")
        .ok_or_else(|| "combined transition skips projected revoke prevalidation".to_owned())?;
    let external_apply = combined_apply
        .find("let applied = apply_publication();")
        .ok_or_else(|| "combined transition lacks its external publication point".to_owned())?;
    let publication_apply = combined_apply
        .find("self.apply_publication_ack(publication);")
        .ok_or_else(|| "combined transition lacks infallible publication apply".to_owned())?;
    let revoke_apply = combined_apply
        .find("self.apply_revoke_complete(revoke);")
        .ok_or_else(|| "combined transition lacks infallible revoke apply".to_owned())?;
    if !(publication_prepare < revoke_prepare
        && revoke_prepare < external_apply
        && external_apply < publication_apply
        && publication_apply < revoke_apply)
        || combined_apply.matches("apply_publication()").count() != 1
    {
        return Err(
            "combined publication/revoke must prevalidate both objects before one external publication and two infallible applies"
                .into(),
        );
    }

    let close_start = source
        .find("pub(crate) fn commit_or_recover_device_close_with_apply<T>(")
        .ok_or_else(|| "production Registry lacks operation-aware device close".to_owned())?;
    let close_prepare_start = source[close_start..]
        .find("    fn prepare_device_close(")
        .map(|offset| close_start + offset)
        .ok_or_else(|| "operation-aware device close lacks prepare phase".to_owned())?;
    let close_install_start = source[close_prepare_start..]
        .find("    fn install_device_close_publishing(")
        .map(|offset| close_prepare_start + offset)
        .ok_or_else(|| "operation-aware device close lacks Publishing install phase".to_owned())?;
    let close_apply_start = source[close_install_start..]
        .find("    fn apply_device_close(")
        .map(|offset| close_install_start + offset)
        .ok_or_else(|| "operation-aware device close lacks apply phase".to_owned())?;
    let close_recover_start = source[close_apply_start..]
        .find("    fn recover_device_close(")
        .map(|offset| close_apply_start + offset)
        .ok_or_else(|| "operation-aware device close lacks recovery phase".to_owned())?;
    let close_coordinates_start = source[close_recover_start..]
        .find("    fn validate_device_close_coordinates(")
        .map(|offset| close_recover_start + offset)
        .ok_or_else(|| "operation-aware device close lacks coordinate validation".to_owned())?;
    let obligation_attempt_start = source[close_coordinates_start..]
        .find("    fn device_published_obligation_for_attempt(")
        .map(|offset| close_coordinates_start + offset)
        .ok_or_else(|| "operation-aware device close lacks obligation routing".to_owned())?;
    let obligation_start = source[obligation_attempt_start..]
        .find("    fn device_published_obligation(")
        .map(|offset| obligation_attempt_start + offset)
        .ok_or_else(|| "operation-aware device close lacks root-local obligation".to_owned())?;
    let close_end = source[obligation_start..]
        .find("    fn device_revoke_selection(")
        .map(|offset| obligation_start + offset)
        .ok_or_else(|| "operation-aware device obligation boundary is unterminated".to_owned())?;
    let close_gate = &source[close_start..close_prepare_start];
    let close_prepare = &source[close_prepare_start..close_install_start];
    let close_install = &source[close_install_start..close_apply_start];
    let close_apply = &source[close_apply_start..close_recover_start];
    let close_recover = &source[close_recover_start..close_coordinates_start];
    let close_coordinates = &source[close_coordinates_start..obligation_attempt_start];
    let obligation = &source[obligation_start..close_end];

    for required in [
        "self.device_published_obligation_for_attempt(operation, enrollment)",
        "self.recover_device_close(operation, authority, enrollment, commits)",
        "Ok(DeviceCloseOutcome::Recovered { receipt, selection })",
        "Err(DeviceCloseError::Published { obligation, error })",
        ".prepare_device_close(operation, authority, enrollment, commits)",
        ".map_err(DeviceCloseError::Unpublished)?;",
        "let plan = self.install_device_close_publishing(prepared);",
        "let publication = publish(&plan.batch.receipt);",
        "let (receipt, selection) = self.apply_device_close(plan);",
        "Ok(DeviceCloseOutcome::Applied {",
    ] {
        if !close_gate.contains(required) {
            return Err(format!(
                "operation-aware device close lacks required classification/apply step {required:?}"
            ));
        }
    }
    let published_check = close_gate
        .find("self.device_published_obligation_for_attempt(operation, enrollment)")
        .unwrap();
    let recovery = close_gate
        .find("self.recover_device_close(operation, authority, enrollment, commits)")
        .unwrap();
    let prepare = close_gate
        .find(".prepare_device_close(operation, authority, enrollment, commits)")
        .unwrap();
    let install = close_gate
        .find("let plan = self.install_device_close_publishing(prepared);")
        .unwrap();
    let publish = close_gate
        .find("let publication = publish(&plan.batch.receipt);")
        .unwrap();
    let apply = close_gate
        .find("let (receipt, selection) = self.apply_device_close(plan);")
        .unwrap();
    if !(published_check < recovery
        && recovery < prepare
        && prepare < install
        && install < publish
        && publish < apply)
        || close_gate.matches("publish(").count() != 1
        || close_gate.contains("claim_device_replay_reset_and_revoke")
    {
        return Err(
            "operation-aware close must recover before fresh prepare, install Publishing before one fresh publish, and never synthesize a receipt-only reset claim"
                .into(),
        );
    }

    for required in [
        "self.validate_device_close_coordinates(operation, authority, enrollment)?;",
        "self.validate_kernel_root_authority(authority)?;",
        "PreparedDeviceBatch::Apply(plan) => plan,",
        "PreparedDeviceBatch::Replay(_) => return Err(RegistryError::InvalidState),",
        "let stored_batch = batch.receipt.clone();",
        "let publishing_revision = batch.next_scope_revision;",
        ".prepare_revoke_begin_after_publishing_and_batch(",
        "Ok(DeviceClosePreparePlan {",
        "publishing_revision,",
    ] {
        if !close_prepare.contains(required) {
            return Err(format!(
                "fresh operation-aware close lacks complete prepublication plan {required:?}"
            ));
        }
    }
    if close_prepare.contains("&mut self") || close_prepare.contains(".get_mut(") {
        return Err("fresh operation-aware close preparation must be read-only".into());
    }

    for required in [
        "let DeviceClosePreparePlan {",
        "root.publication = DevicePublicationProvenance::Publishing {",
        "scope.revision = publishing_revision;",
        "DeviceCloseApplyPlan {",
    ] {
        if !close_install.contains(required) {
            return Err(format!(
                "device close Publishing install lacks required durable step {required:?}"
            ));
        }
    }
    if close_install.contains('?')
        || close_install.contains("Vec::")
        || close_install.contains("BTreeMap")
        || close_install.contains(".clone(")
        || close_install.contains(".collect(")
        || close_install.contains("checked_add")
    {
        return Err(
            "Publishing provenance install must remain allocation-free and infallible before external publication"
                .into(),
        );
    }

    for required in [
        "let receipt = self.apply_device_batch(batch);",
        "let selection = self.apply_revoke_begin(revoke);",
        "__cser_core::mem::replace(&mut root.publication, DevicePublicationProvenance::None);",
        "DevicePublicationProvenance::Publishing {",
        "DevicePublicationProvenance::Applied {",
        "(receipt, selection)",
    ] {
        if !close_apply.contains(required) {
            return Err(format!(
                "operation-aware close apply lacks exact batch/revoke/provenance step {required:?}"
            ));
        }
    }
    let apply_batch = close_apply
        .find("let receipt = self.apply_device_batch(batch);")
        .unwrap();
    let apply_revoke = close_apply
        .find("let selection = self.apply_revoke_begin(revoke);")
        .unwrap();
    let take_publishing = close_apply
        .find(
            "__cser_core::mem::replace(&mut root.publication, DevicePublicationProvenance::None);",
        )
        .unwrap();
    let mark_applied = close_apply
        .find("DevicePublicationProvenance::Applied {")
        .unwrap();
    if !(apply_batch < apply_revoke
        && apply_revoke < take_publishing
        && take_publishing < mark_applied)
        || close_apply.contains('?')
        || close_apply.contains("Vec::")
        || close_apply.contains("BTreeMap")
        || close_apply.contains(".clone(")
        || close_apply.contains(".collect(")
        || close_apply.contains("checked_add")
    {
        return Err(
            "post-publication operation apply must remain allocation-free, infallible, and ordered batch-revoke-Publishing-to-Applied"
                .into(),
        );
    }

    for required in [
        "let (stored_operation, stored) = match &root.publication {",
        "DevicePublicationProvenance::Applied { operation, batch }",
        "if stored_operation != operation",
        "root.batch_sequence != Some(stored.batch_sequence)",
        "stored.commits.len() != enrollment.effects.len()",
        "commits.iter().zip(&stored.commits).enumerate()",
        "*handle != record.handle()",
        "metadata.result != authoritative.result",
        "record.commit.as_ref() != Some(authoritative)",
        "membership.sequence != stored.batch_sequence",
        cser_core_macro!(
            "matches",
            "(scope.phase, ScopePhase::Closing | ScopePhase::Revoked)"
        ),
        "Ok((stored.clone(), selection))",
    ] {
        if !close_recover.contains(required) {
            return Err(format!(
                "same-operation recovery lacks exact stored receipt/input validation {required:?}"
            ));
        }
    }
    for required in [
        "operation.registry_instance_id != self.instance_id",
        "operation.caller_nonce == 0",
        "operation.scope != enrollment.scope",
        "operation.enrollment_sequence != enrollment.enrollment_sequence",
        "authority.owner != operation.owner",
        "authority.authority_epoch != operation.authority_epoch",
        "self.validate_device_enrollment_receipt(enrollment)?;",
    ] {
        if !close_coordinates.contains(required) {
            return Err(format!(
                "device-close coordinate validation lacks exact authority/enrollment binding {required:?}"
            ));
        }
    }

    for required in [
        "root.batch_sequence.is_some()",
        "!root.publication.is_none()",
        "ticket.batch_sequence.is_some()",
        "if !has_published_or_closure_progress",
        "let batch_sequence = root",
        "root.publication.batch().map(|batch| batch.batch_sequence)",
        "operation: root.publication.operation(),",
        ".published_status()",
        ".unwrap_or(DevicePublishedStatus::CorruptPublished)",
        "phase: scope.phase,",
        "revoke: Self::device_revoke_selection(scope_key, scope),",
        "reset_ticket: root.reset_ticket,",
        "closure: root.closure,",
    ] {
        if !obligation.contains(required) {
            return Err(format!(
                "published obligation lacks allocation-free root-local progress {required:?}"
            ));
        }
    }
    if obligation.contains("reconstruct_device_batch_receipt")
        || obligation.contains(".clone(")
        || obligation.contains("Vec::")
        || obligation.contains("BTreeMap")
        || obligation.contains(".collect(")
    {
        return Err("published obligation must not allocate or scan global effect history".into());
    }
    if source.contains("pub(crate) fn claim_device_replay_reset_and_revoke(")
        || source
            .matches("    fn claim_device_replay_reset_and_revoke(")
            .count()
            != 1
    {
        return Err(
            "receipt-only replay reset claim must remain a single module-private legacy helper"
                .into(),
        );
    }

    let revoke_plan_start = source
        .find("struct RevokeBeginPlan {")
        .ok_or_else(|| "production Registry lacks RevokeBeginPlan".to_owned())?;
    let revoke_plan_end = source[revoke_plan_start..]
        .find("struct DeviceIotlbApplyPlan {")
        .map(|offset| revoke_plan_start + offset)
        .ok_or_else(|| "RevokeBeginPlan boundary is unterminated".to_owned())?;
    let revoke_plan_compact: String = source[revoke_plan_start..revoke_plan_end]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if revoke_plan_compact
        != concat!(
            "structRevokeBeginPlan{",
            "selection:RevokeSelection,",
            "next_revoke_sequence:u64,",
            "next_scope_revision:u64,",
            "}"
        )
    {
        return Err("RevokeBeginPlan must carry exactly selection and validated counters".into());
    }

    let revoke_gate_start = source
        .find("pub(crate) fn revoke_begin(")
        .ok_or_else(|| "production Registry lacks revoke_begin".to_owned())?;
    let revoke_prepare_start = source[revoke_gate_start..]
        .find("    fn prepare_revoke_begin(")
        .map(|offset| revoke_gate_start + offset)
        .ok_or_else(|| "revoke_begin lacks prepare helper".to_owned())?;
    let revoke_after_batch_start = source[revoke_prepare_start..]
        .find("    fn prepare_revoke_begin_after_device_batch(")
        .map(|offset| revoke_prepare_start + offset)
        .ok_or_else(|| "revoke prepare lacks post-batch helper".to_owned())?;
    let revoke_from_revision_start = source[revoke_after_batch_start..]
        .find("    fn prepare_revoke_begin_from_revision(")
        .map(|offset| revoke_after_batch_start + offset)
        .ok_or_else(|| "revoke prepare lacks revision helper".to_owned())?;
    let revoke_apply_start = source[revoke_from_revision_start..]
        .find("    fn apply_revoke_begin(")
        .map(|offset| revoke_from_revision_start + offset)
        .ok_or_else(|| "revoke_begin lacks apply helper".to_owned())?;
    let revoke_end = source[revoke_apply_start..]
        .find("    pub(crate) fn revoke_targets(")
        .map(|offset| revoke_apply_start + offset)
        .ok_or_else(|| "revoke apply boundary is unterminated".to_owned())?;
    let revoke_gate = &source[revoke_gate_start..revoke_prepare_start];
    let revoke_prepare = &source[revoke_prepare_start..revoke_after_batch_start];
    let revoke_after_batch = &source[revoke_after_batch_start..revoke_from_revision_start];
    let revoke_from_revision = &source[revoke_from_revision_start..revoke_apply_start];
    let revoke_apply = &source[revoke_apply_start..revoke_end];
    for required in [
        "let plan = self.prepare_revoke_begin(scope_key)?;",
        "Ok(self.apply_revoke_begin(plan))",
    ] {
        if !revoke_gate.contains(required) {
            return Err(format!(
                "revoke_begin gate lacks prepare/apply step {required:?}"
            ));
        }
    }
    if !revoke_prepare.contains(
        "fn prepare_revoke_begin(&self, scope_key: ScopeKey) -> Result<RevokeBeginPlan, RegistryError>",
    ) || revoke_prepare.contains("&mut self")
        || !revoke_prepare.contains("self.prepare_revoke_begin_from_revision(scope_key, revision)")
    {
        return Err("prepare_revoke_begin must remain read-only and delegate by revision".into());
    }
    for required in [
        "fn prepare_revoke_begin_after_device_batch(",
        "        &self,",
        "let expected_batch_revision = scope",
        ".revision\n            .checked_add(1)",
        "if batch_revision != expected_batch_revision",
        "self.prepare_revoke_begin_from_revision(scope_key, batch_revision)",
    ] {
        if !revoke_after_batch.contains(required) {
            return Err(format!(
                "post-batch revoke prepare lacks exact revision precheck {required:?}"
            ));
        }
    }
    if revoke_after_batch.contains("&mut self") {
        return Err("post-batch revoke preparation must take &self".into());
    }
    for required in [
        "fn prepare_revoke_begin_from_revision(",
        "        &self,",
        "if scope.phase != ScopePhase::Active",
        "if scope.revoke.is_some()",
        "scope.device_root.as_ref().is_some_and(|root| {",
        "DevicePublicationProvenance::Publishing { .. }",
        "return Err(RegistryError::DeviceClosurePending);",
        ".authority_epoch\n            .checked_add(1)",
        "let next_scope_revision = revision_before_revoke\n            .checked_add(1)",
        "let target_count = scope.closure_candidates.len();",
        "u64::try_from(target_count).map_err(|_| RegistryError::CounterOverflow)?;",
        "let sequence = self.next_revoke_sequence;",
        "let next_revoke_sequence = sequence\n            .checked_add(1)",
        "Ok(RevokeBeginPlan {",
    ] {
        if !revoke_from_revision.contains(required) {
            return Err(format!(
                "revision-based revoke prepare lacks failure-atomic precheck {required:?}"
            ));
        }
    }
    if revoke_from_revision.contains("&mut self")
        || revoke_from_revision.contains(".get_mut(")
        || revoke_from_revision.contains("self.next_revoke_sequence =")
    {
        return Err("revision-based revoke preparation must not mutate Registry state".into());
    }
    for required in [
        "self.next_revoke_sequence = next_revoke_sequence;",
        "let cohort = __cser_core::mem::take(&mut scope.closure_candidates);",
        "let retired_recovery = scope.recovery.take();",
        "scope.authority_epoch = selection.authority_epoch;",
        "scope.phase = ScopePhase::Closing;",
        "scope.revision = next_scope_revision;",
        "scope.revoke = Some(RevokeState {",
    ] {
        if !revoke_apply.contains(required) {
            return Err(format!(
                "revoke apply lacks exact prevalidated assignment {required:?}"
            ));
        }
    }
    if revoke_apply
        .matches("self.next_revoke_sequence = next_revoke_sequence;")
        .count()
        != 1
        || revoke_apply
            .matches("scope.revision = next_scope_revision;")
            .count()
            != 1
        || revoke_apply.contains('?')
        || revoke_apply.contains("checked_add")
        || revoke_apply.contains("saturating_add")
        || revoke_apply.contains("wrapping_add")
    {
        return Err(
            "revoke apply must use each prevalidated counter exactly once without recomputation"
                .into(),
        );
    }

    // Receipt-only replay/reset remains a private legacy primitive. The
    // operation-aware production gate above deliberately does not treat it
    // as caller authority or an automatic recovery path.

    let completion_helper_start = source
        .find("    fn device_batch_causal_root_commit<'a>(")
        .ok_or_else(|| "production Registry lacks causal-root completion binding".to_owned())?;
    let completion_start = source[completion_helper_start..]
        .find("pub(crate) fn record_device_completion(")
        .map(|offset| completion_helper_start + offset)
        .ok_or_else(|| "device completion boundary is missing".to_owned())?;
    let completion_end = source[completion_start..]
        .find("pub(crate) fn begin_device_reset(")
        .map(|offset| completion_start + offset)
        .ok_or_else(|| "device completion boundary is unterminated".to_owned())?;
    let completion_helper = &source[completion_helper_start..completion_start];
    let completion = &source[completion_start..completion_end];
    for required in [
        "for commit in &batch.commits",
        "if record.identity.parent.is_none() && causal_root.replace(commit).is_some()",
        "causal_root.ok_or(RegistryError::InvalidBatchReceipt)",
    ] {
        if !completion_helper.contains(required) {
            return Err(format!(
                "device completion causal-root helper lacks uniqueness step {required:?}"
            ));
        }
    }
    let receipt_validation = completion
        .find("self.validate_device_batch_receipt(batch)?;")
        .ok_or_else(|| "device completion skips authoritative batch validation".to_owned())?;
    let root_lookup = completion
        .find("let causal_root = self.device_batch_causal_root_commit(batch)?;")
        .ok_or_else(|| "device completion skips unique causal-root lookup".to_owned())?;
    let result_check = completion
        .find("if result != causal_root.result")
        .ok_or_else(|| "device completion accepts a leaf-selected result".to_owned())?;
    let root_state_lookup = completion
        .find("let root = self.scopes[&batch.scope]")
        .ok_or_else(|| "device completion lacks root state validation".to_owned())?;
    let result_guard_compact: String = completion[root_lookup..root_state_lookup]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let expected_result_guard = concat!(
        "letcausal_root=self.device_batch_causal_root_commit(batch)?;",
        "ifresult!=causal_root.result{",
        "returnErr(RegistryError::CommitConflict);",
        "}",
    );
    let sequence_apply = completion
        .find("self.next_device_closure_sequence = next_device_closure_sequence;")
        .ok_or_else(|| "device completion lacks sequence application".to_owned())?;
    let completion_binding_valid = receipt_validation < root_lookup
        && root_lookup < result_check
        && result_check < sequence_apply
        && result_guard_compact == expected_result_guard
        && completion.contains("return Err(RegistryError::CommitConflict);")
        && completion.contains("causal_root: causal_root.effect,")
        && completion.contains("causal_commit_sequence: causal_root.sequence,");
    if !completion_binding_valid {
        return Err(
            "device completion must bind the exact unique causal-root commit before any live mutation"
                .into(),
        );
    }

    let commit_start = source
        .find("pub(crate) fn commit_device_batch_with_publish<T>(")
        .ok_or_else(|| "production Registry lacks the root device publish gate".to_owned())?;
    let commit_end = source[commit_start..]
        .find("pub(crate) fn mint_device_close_operation(")
        .map(|offset| commit_start + offset)
        .ok_or_else(|| "production device publish-gate boundary is unterminated".to_owned())?;
    let commit = &source[commit_start..commit_end];
    let prepare = commit
        .find("self.prepare_device_batch(authority, enrollment, commits)?")
        .ok_or_else(|| "device publish gate skips complete prevalidation".to_owned())?;
    let publish = commit
        .find("let publication = publish(&plan.receipt);")
        .ok_or_else(|| "device publish gate lacks its unique hardware commit point".to_owned())?;
    let apply = commit
        .find("let receipt = self.apply_device_batch(plan);")
        .ok_or_else(|| "device publish gate lacks its infallible state application".to_owned())?;
    if !(prepare < publish && publish < apply)
        || commit.matches("publish(").count() != 1
        || commit.contains(
            "PreparedDeviceBatch::Replay(receipt) => {
                let publication = publish",
        )
    {
        return Err(
            "device batch must prevalidate before one publish and apply afterward; replay may not republish"
                .into(),
        );
    }

    let prepare_start = source
        .find("fn prepare_device_batch(")
        .ok_or_else(|| "production Registry lacks device-batch prevalidation".to_owned())?;
    let apply_start = source[prepare_start..]
        .find("fn apply_device_batch(")
        .map(|offset| prepare_start + offset)
        .ok_or_else(|| "production Registry lacks device-batch apply".to_owned())?;
    let prepare_source = &source[prepare_start..apply_start];
    for required in [
        "self.validate_kernel_root_authority(authority)?;",
        "root_state.enrollment.as_ref() != Some(enrollment)",
        "commits.iter().zip(&enrollment.effects)",
        "if live != &seen || root_count != 1 || device_effects.is_empty()",
        "let mut aggregate = BTreeMap::<CreditClass, u64>::new();",
        "let mut charges = Vec::with_capacity(aggregate.len());",
        ".validate_commit(&charges)?;",
        "let mut receipts = Vec::with_capacity(commits.len());",
        "PreparedDeviceBatch::Replay(receipt)",
        "PreparedDeviceBatch::Apply(DeviceBatchApplyPlan",
        "|| enrollment.cancel_only",
    ] {
        if !prepare_source.contains(required) {
            return Err(format!(
                "production device-batch prevalidation lacks required step {required:?}"
            ));
        }
    }

    let reconstruct_start = source[apply_start..]
        .find("fn reconstruct_device_batch_receipt(")
        .map(|offset| apply_start + offset)
        .ok_or_else(|| "production Registry lacks authoritative batch reconstruction".to_owned())?;
    let apply_source = &source[apply_start..reconstruct_start];
    if apply_source.contains('?')
        || apply_source.contains("Vec::")
        || apply_source.contains("BTreeMap")
        || apply_source.contains(".push(")
        || apply_source.contains(".insert(")
        || apply_source.contains(".collect(")
    {
        return Err(
            "post-publication device-batch apply must contain no fallible or allocating operation"
                .into(),
        );
    }
    for required in [
        ".commit_validated(&charges);",
        "self.next_commit_sequence = next_commit_sequence;",
        "self.next_device_batch_sequence = next_device_batch_sequence;",
        ".batch_sequence = Some(receipt.batch_sequence);",
        "record.phase = EffectPhase::Committed;",
        "record.credit_state = CreditState::Committed;",
        "record.device_batch = Some(DeviceBatchMembership {",
        "scope.revision = next_scope_revision;",
    ] {
        if !apply_source.contains(required) {
            return Err(format!(
                "infallible device-batch apply lacks required transition {required:?}"
            ));
        }
    }

    let reset_gate_start = source
        .find("pub(crate) fn acknowledge_device_reset_with_apply<T>(")
        .ok_or_else(|| "production Registry lacks coupled reset-generation apply".to_owned())?;
    let reset_gate_end = source[reset_gate_start..]
        .find("fn prepare_device_reset_apply(")
        .map(|offset| reset_gate_start + offset)
        .ok_or_else(|| "reset-generation gate boundary is unterminated".to_owned())?;
    let reset_gate = &source[reset_gate_start..reset_gate_end];
    let reset_prepare = reset_gate
        .find("let plan = self.prepare_device_reset_apply(ticket)?;")
        .ok_or_else(|| "reset-generation gate skips complete prevalidation".to_owned())?;
    let registry_apply = reset_gate
        .find("let receipt = self.apply_device_reset(plan);")
        .ok_or_else(|| "reset-generation gate lacks infallible Registry apply".to_owned())?;
    let external_apply = reset_gate
        .find("let publication = apply_generation(&receipt);")
        .ok_or_else(|| "reset-generation gate lacks its unique facade apply point".to_owned())?;
    if !(reset_prepare < registry_apply && registry_apply < external_apply)
        || reset_gate.matches("apply_generation(").count() != 1
    {
        return Err(
            "reset generation must prevalidate, install the Registry fence, then enter one facade apply"
                .into(),
        );
    }
    let reset_apply_start = source
        .find("fn apply_device_reset(")
        .ok_or_else(|| "production Registry lacks reset-generation apply".to_owned())?;
    let reset_apply_end = source[reset_apply_start..]
        .find("pub(crate) fn begin_device_iotlb(")
        .map(|offset| reset_apply_start + offset)
        .ok_or_else(|| "reset-generation apply boundary is unterminated".to_owned())?;
    let reset_apply = &source[reset_apply_start..reset_apply_end];
    if reset_apply.contains('?')
        || reset_apply.contains("Vec::")
        || reset_apply.contains("BTreeMap")
        || reset_apply.contains(".push(")
        || reset_apply.contains(".insert(")
        || reset_apply.contains(".collect(")
    {
        return Err(
            "post-facade reset-generation Registry apply must be allocation-free and error-free"
                .into(),
        );
    }
    for required in [
        "self.next_device_closure_sequence = next_device_closure_sequence;",
        "root.current_device = receipt.new_device;",
        "root.outcome = Some(receipt.outcome);",
        "root.reset_ticket = None;",
        "root.reset_receipt = Some(receipt);",
    ] {
        if !reset_apply.contains(required) {
            return Err(format!(
                "infallible reset-generation apply lacks transition {required:?}"
            ));
        }
    }

    let iotlb_gate_start = source
        .find("pub(crate) fn acknowledge_device_iotlb_with_apply<T>(")
        .ok_or_else(|| "production Registry lacks coupled IOTLB apply".to_owned())?;
    let iotlb_prepare_start = source[iotlb_gate_start..]
        .find("fn prepare_device_iotlb_apply(")
        .map(|offset| iotlb_gate_start + offset)
        .ok_or_else(|| "coupled IOTLB gate boundary is unterminated".to_owned())?;
    let iotlb_gate = &source[iotlb_gate_start..iotlb_prepare_start];
    let iotlb_prepare = iotlb_gate
        .find("let plan = self.prepare_device_iotlb_apply(ticket)?;")
        .ok_or_else(|| "IOTLB gate skips complete prevalidation".to_owned())?;
    let iotlb_registry_apply = iotlb_gate
        .find("let receipt = self.apply_device_iotlb(plan);")
        .ok_or_else(|| "IOTLB gate lacks its infallible Registry apply".to_owned())?;
    let quiescence_apply = iotlb_gate
        .find("let publication = apply_quiescence(&receipt);")
        .ok_or_else(|| "IOTLB gate lacks its unique facade quiescence apply".to_owned())?;
    if !(iotlb_prepare < iotlb_registry_apply && iotlb_registry_apply < quiescence_apply)
        || iotlb_gate.matches("apply_quiescence(").count() != 1
    {
        return Err(
            "IOTLB closure must prevalidate, install the Registry closure, then enter one facade quiescence apply"
                .into(),
        );
    }

    let iotlb_apply_start = source[iotlb_prepare_start..]
        .find("fn apply_device_iotlb(")
        .map(|offset| iotlb_prepare_start + offset)
        .ok_or_else(|| "production Registry lacks infallible IOTLB apply".to_owned())?;
    let iotlb_prepare_source = &source[iotlb_prepare_start..iotlb_apply_start];
    for required in [
        "self.validate_device_closure_context(",
        "root.iotlb_ticket.as_ref() != Some(ticket)",
        "let outcome = root.outcome.ok_or(RegistryError::InvalidState)?;",
        "let receipt = DeviceClosureReceipt {",
        "Ok(DeviceIotlbApplyPlan {",
    ] {
        if !iotlb_prepare_source.contains(required) {
            return Err(format!(
                "IOTLB prevalidation lacks required step {required:?}"
            ));
        }
    }
    let iotlb_apply_end = source[iotlb_apply_start..]
        .find("pub(crate) fn validate_device_closure_receipt(")
        .map(|offset| iotlb_apply_start + offset)
        .ok_or_else(|| "IOTLB Registry apply boundary is unterminated".to_owned())?;
    let iotlb_apply = &source[iotlb_apply_start..iotlb_apply_end];
    if iotlb_apply.contains('?')
        || iotlb_apply.contains("Result<")
        || iotlb_apply.contains("return Err")
        || iotlb_apply.contains("Vec::")
        || iotlb_apply.contains("BTreeMap")
        || iotlb_apply.contains(".push(")
        || iotlb_apply.contains(".insert(")
        || iotlb_apply.contains(".collect(")
    {
        return Err(
            "post-facade IOTLB Registry apply must be allocation-free and error-free".into(),
        );
    }
    for required in [
        "self.next_device_closure_sequence = next_device_closure_sequence;",
        "root.iotlb_ticket = None;",
        "root.closure = Some(receipt);",
        "scope.revision = next_scope_revision;",
    ] {
        if !iotlb_apply.contains(required) {
            return Err(format!(
                "infallible IOTLB Registry apply lacks transition {required:?}"
            ));
        }
    }

    let unpublished_cancel_start = source
        .find("pub(crate) fn begin_unpublished_device_cancel(")
        .ok_or_else(|| "production Registry lacks unpublished device cancellation".to_owned())?;
    let unpublished_cancel_end = source[unpublished_cancel_start..]
        .find("pub(crate) fn retain_device_reset_timeout(")
        .map(|offset| unpublished_cancel_start + offset)
        .ok_or_else(|| "unpublished device cancellation boundary is unterminated".to_owned())?;
    let unpublished_cancel = &source[unpublished_cancel_start..unpublished_cancel_end];
    if !unpublished_cancel.contains("|| !root.publication.is_none()") {
        return Err(
            "unpublished device cancellation must reject every existing publication provenance"
                .into(),
        );
    }

    let reset_timeout_start = source
        .find("pub(crate) fn retain_device_reset_timeout(")
        .ok_or_else(|| "production Registry lacks reset-timeout retention".to_owned())?;
    let reset_timeout_end = source[reset_timeout_start..]
        .find("pub(crate) fn retry_device_reset(")
        .map(|offset| reset_timeout_start + offset)
        .ok_or_else(|| "reset-timeout boundary is unterminated".to_owned())?;
    let reset_timeout = &source[reset_timeout_start..reset_timeout_end];
    let iotlb_timeout_start = source
        .find("pub(crate) fn retain_device_iotlb_timeout(")
        .ok_or_else(|| "production Registry lacks IOTLB-timeout retention".to_owned())?;
    let iotlb_timeout_end = source[iotlb_timeout_start..]
        .find("pub(crate) fn retry_device_iotlb(")
        .map(|offset| iotlb_timeout_start + offset)
        .ok_or_else(|| "IOTLB-timeout boundary is unterminated".to_owned())?;
    let iotlb_timeout = &source[iotlb_timeout_start..iotlb_timeout_end];
    for (label, timeout) in [("reset", reset_timeout), ("IOTLB", iotlb_timeout)] {
        if timeout.contains("root.outcome =")
            || !timeout
                .contains("self.apply_device_root_retention(&enrollment, retention.as_ref());")
        {
            return Err(format!(
                "{label} timeout must retain ownership without rewriting the workload outcome"
            ));
        }
    }
    let authority_guard = "self.require_unique_device_publication()?;";
    let mint_start = source
        .find("pub(crate) fn kernel_root_authority(")
        .ok_or_else(|| "production Registry lacks kernel root authority mint".to_owned())?;
    let mint_end = source[mint_start..]
        .find("pub(crate) fn register(")
        .map(|offset| mint_start + offset)
        .ok_or_else(|| "kernel root authority mint boundary is unterminated".to_owned())?;
    let close_mint_start = source
        .find("pub(crate) fn mint_device_close_operation(")
        .ok_or_else(|| "production Registry lacks device-close operation mint".to_owned())?;
    let close_mint_end = source[close_mint_start..]
        .find("pub(crate) fn commit_or_recover_device_close_with_apply<T>(")
        .map(|offset| close_mint_start + offset)
        .ok_or_else(|| "device-close operation mint boundary is unterminated".to_owned())?;
    let registration_start = source
        .find("pub(crate) fn register_device_derived(")
        .ok_or_else(|| "production Registry lacks device-derived registration".to_owned())?;
    let registration_end = source[registration_start..]
        .find("    fn register_in_domain(")
        .map(|offset| registration_start + offset)
        .ok_or_else(|| "device-derived registration boundary is unterminated".to_owned())?;
    let cohort_registration_start = source
        .find("pub(crate) fn register_device_derived_cohort(")
        .ok_or_else(|| "production Registry lacks device-derived cohort registration".to_owned())?;
    let cohort_registration_end = source[cohort_registration_start..]
        .find("    fn prepare_device_derived_cohort(")
        .map(|offset| cohort_registration_start + offset)
        .ok_or_else(|| "device-derived cohort registration boundary is unterminated".to_owned())?;
    let validation_start = source
        .find("    fn validate_kernel_root_authority(")
        .ok_or_else(|| "production Registry lacks kernel root authority validation".to_owned())?;
    let validation_end = source[validation_start..]
        .find("    fn validate_root_portal(")
        .map(|offset| validation_start + offset)
        .ok_or_else(|| "kernel root authority validation boundary is unterminated".to_owned())?;
    let unique_guard_start = source
        .find("    fn require_unique_device_publication(")
        .ok_or_else(|| "production Registry lacks the unique-publication guard".to_owned())?;
    let unique_guard_end = source[unique_guard_start..]
        .find("    /// Returns the complete registry debug projection")
        .map(|offset| unique_guard_start + offset)
        .ok_or_else(|| "unique-publication guard boundary is unterminated".to_owned())?;
    let guard_is_first_statement = |body: &str| {
        body.split_once('{')
            .is_some_and(|(_, body)| body.trim_start().starts_with(authority_guard))
    };
    let unique_guard_compact: String = source[unique_guard_start..unique_guard_end]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let expected_unique_guard = concat!(
        "fnrequire_unique_device_publication(&self)->Result<(),RegistryError>{",
        "ifself.device_publication_mode!=DevicePublicationMode::Unique{",
        "returnErr(RegistryError::InvalidDeviceEnvelope);",
        "}",
        "Ok(())",
        "}",
    );
    if source.matches(authority_guard).count() != 6
        || source[mint_start..mint_end]
            .matches(authority_guard)
            .count()
            != 1
        || !guard_is_first_statement(&source[mint_start..mint_end])
        || source[close_mint_start..close_mint_end]
            .matches(authority_guard)
            .count()
            != 1
        || !guard_is_first_statement(&source[close_mint_start..close_mint_end])
        || source[close_coordinates_start..obligation_attempt_start]
            .matches(authority_guard)
            .count()
            != 1
        || !guard_is_first_statement(&source[close_coordinates_start..obligation_attempt_start])
        || source[registration_start..registration_end]
            .matches(authority_guard)
            .count()
            != 1
        || !guard_is_first_statement(&source[registration_start..registration_end])
        || source[cohort_registration_start..cohort_registration_end]
            .matches(authority_guard)
            .count()
            != 1
        || !guard_is_first_statement(&source[cohort_registration_start..cohort_registration_end])
        || source[validation_start..validation_end]
            .matches(authority_guard)
            .count()
            != 1
        || !guard_is_first_statement(&source[validation_start..validation_end])
        || unique_guard_compact != expected_unique_guard
    {
        return Err(
            "device publication authority must guard exactly the root/close mints, single/cohort device-derived registrations, and root-validation functions"
                .into(),
        );
    }
    for required in [
        "enum DevicePublicationMode {",
        "DisabledNonDeviceCandidate",
        "device_publication_mode: DevicePublicationMode,",
        "pub(super) fn clone_non_device_candidate(&self) -> Result<Self, RegistryError>",
        "candidate.device_publication_mode = DevicePublicationMode::DisabledNonDeviceCandidate;",
        "fn require_unique_device_publication(&self) -> Result<(), RegistryError>",
        "pub(crate) enum DeviceCohortParent {",
        "Existing(EffectKey)",
        "BatchIndex(usize)",
        "pub(crate) struct DeviceDerivedCohortEntry {",
        "batch_index: usize,",
        "pub(crate) fn register_device_derived_cohort(",
        "fn prepare_device_derived_cohort(",
        "fn apply_device_derived_cohort(",
        "non-device candidate acquired device publication state",
        "let mut non_device_candidate = registry.clone_non_device_candidate().unwrap();",
        "non_device_candidate.kernel_root_authority(SCOPE, ROOT_OWNER)",
        "non_device_candidate.register_device_derived(DeviceDerivedRegisterRequest {",
        cser_core_macro!(
            "assert_eq",
            "(non_device_candidate, non_device_before_registration);"
        ),
        "registry.clone_non_device_candidate(),",
        "disabled_enrollment.device_publication_mode =",
        "DevicePublicationMode::DisabledNonDeviceCandidate;",
        "disabled_enrollment.enroll_device_batch(authority, &handles, device)",
        cser_core_macro!(
            "assert_eq",
            "(disabled_enrollment, disabled_enrollment_before);"
        ),
        "pub(crate) fn enroll_device_batch(",
        "if self.scopes[&record.identity.scope].device_root.is_some() {",
        "return Err(RegistryError::InvalidDeviceEnvelope);",
        "let mut ancestor = Some(parent);",
        "if record.commit.is_some() || record.phase.is_terminal()",
        "pub(crate) fn validate_device_batch_receipt(",
        "fn reconstruct_device_batch_receipt(",
        "pub(crate) fn record_device_completion(",
        "fn device_batch_causal_root_commit<'a>(",
        "if result != causal_root.result",
        "causal_root: causal_root.effect,",
        "causal_commit_sequence: causal_root.sequence,",
        "device completion causal root drift",
        "if presented_device != root.current_device",
        "pub(crate) fn begin_unpublished_device_cancel(",
        "|| !root.publication.is_none()",
        "root.outcome = Some(DeviceClosureResult::AbortedBeforeCommit);",
        "pub(crate) fn retain_device_reset_timeout(",
        "None if ticket.batch_sequence.is_some() => DeviceClosureResult::IndeterminateAfterReset,",
        "DeviceClosureResult::IndeterminateAfterReset",
        "self.apply_device_root_retention(&enrollment, retention.as_ref());",
        "pub(crate) fn retry_device_reset(",
        "pub(crate) fn acknowledge_device_reset_with_apply<T>(",
        "let receipt = self.apply_device_reset(plan);",
        "let publication = apply_generation(&receipt);",
        "root.current_device = receipt.new_device;",
        "pub(crate) fn retain_device_iotlb_timeout(",
        "pub(crate) fn retry_device_iotlb(",
        "pub(crate) fn acknowledge_device_iotlb_with_apply<T>(",
        "let receipt = self.apply_device_iotlb(plan);",
        "let publication = apply_quiescence(&receipt);",
        "pub(crate) fn validate_device_closure_receipt(",
        "pub(crate) fn stage_device_batch_terminal(",
        "authorized_device_enrollment != Some(enrollment.enrollment_sequence)",
        "return Err(RegistryError::DeviceClosurePending);",
        "CreditState::Retained => balance.retained",
        "retained published credits lack timeout tombstone",
        "TerminalOutcome::IndeterminateAfterReset",
        "DeviceClosureResult::AbortedBeforeCommit",
        "pub(crate) struct ProductionDeviceBatchRaceFixture",
    ] {
        if !source.contains(required) {
            return Err(format!(
                "production device-batch source lacks authority/replay/race invariant {required:?}"
            ));
        }
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

    fn checked_registry_source_set() -> registry_source_set::RegistrySourceSet {
        registry_source_set::RegistrySourceSet::from_authority(&checked_registry_source())
    }

    fn checked_non_device_candidate_callers() -> BTreeMap<String, usize> {
        BTreeMap::from([
            (FAULT_REGISTRY_SOURCE.to_owned(), 4usize),
            (
                "kernel/nexus-ostd/src/cser/composition.rs".to_owned(),
                1usize,
            ),
            (
                "kernel/nexus-ostd/src/cser/linux_io_composition.rs".to_owned(),
                1usize,
            ),
        ])
    }

    #[test]
    fn fault_source_gate_accepts_typed_receipt_projection_pipeline() {
        validate_fault_evaluator_source_text(&checked_evaluator_source()).unwrap();
        validate_fault_registry_source_set(&checked_registry_source_set()).unwrap();
        validate_non_device_candidate_caller_counts(&checked_non_device_candidate_callers())
            .unwrap();
    }

    #[test]
    fn registry_source_set_rejects_checked_item_moved_between_units() {
        let source = checked_registry_source();
        let moved = source.replacen(
            "pub(crate) struct Stage7bFaultBudget {",
            "pub(crate) struct Stage7bFaultBudgetMoved {",
            1,
        );
        assert_ne!(moved, source);
        let sources = registry_source_set::RegistrySourceSet::for_test([
            (registry_source_set::RegistryUnit::Authority, moved),
            (
                registry_source_set::RegistryUnit::Evidence,
                "pub(crate) struct Stage7bFaultBudget;".to_owned(),
            ),
        ])
        .unwrap();
        let error = registry_source_set::validate_source_set(&sources).unwrap_err();
        assert!(
            error.contains("checked-item ownership drifted")
                && error.contains("Stage7bFaultBudget"),
            "moved item failed through the wrong source-set gate: {error}"
        );
    }

    #[test]
    fn registry_source_set_rejects_checked_item_duplicate_between_units() {
        let sources = registry_source_set::RegistrySourceSet::for_test([
            (
                registry_source_set::RegistryUnit::Authority,
                checked_registry_source(),
            ),
            (
                registry_source_set::RegistryUnit::Evidence,
                "pub(crate) struct Stage7bFaultBudget;".to_owned(),
            ),
        ])
        .unwrap();
        let error = registry_source_set::validate_source_set(&sources).unwrap_err();
        assert!(
            error.contains("checked-item ownership drifted")
                && error.contains("Stage7bFaultBudget"),
            "duplicate item failed through the wrong source-set gate: {error}"
        );
    }

    #[test]
    fn registry_source_set_rejects_unbound_device_preparation_self_test() {
        let source = checked_registry_source();
        let mutated = source.replacen(
            "    device_preparation_outer_credit_self_test();",
            "    device_preparation_outer_credit_self_test_disabled();",
            1,
        );
        assert_ne!(mutated, source);
        let error = validate_fault_registry_source_text(&mutated).unwrap_err();
        assert!(
            error.contains("device-preparation credit self-test")
                && error.contains("must be called exactly once"),
            "unbound device-preparation self-test failed through the wrong gate: {error}"
        );
    }

    #[test]
    fn registry_source_set_rejects_duplicate_unit_coordinates() {
        let error = registry_source_set::RegistrySourceSet::for_test([
            (
                registry_source_set::RegistryUnit::Authority,
                checked_registry_source(),
            ),
            (
                registry_source_set::RegistryUnit::Authority,
                checked_registry_source(),
            ),
        ])
        .unwrap_err();
        assert!(error.contains("duplicates unit Authority"));
    }

    #[test]
    fn registry_source_set_rejects_unapproved_authority_wrapper() {
        let sources = registry_source_set::RegistrySourceSet::for_test([
            (
                registry_source_set::RegistryUnit::Authority,
                checked_registry_source(),
            ),
            (
                registry_source_set::RegistryUnit::Evidence,
                "struct HiddenRegistryWrapper { inner: EffectRegistry }".to_owned(),
            ),
        ])
        .unwrap();
        let error = registry_source_set::validate_source_set(&sources).unwrap_err();
        assert!(
            error.contains("unapproved authority wrapper/holder")
                && error.contains("HiddenRegistryWrapper.inner"),
            "wrapper failed through the wrong source-set gate: {error}"
        );
    }

    #[test]
    fn registry_source_set_rejects_second_registry_and_cross_unit_clone_impl() {
        let second = registry_source_set::RegistrySourceSet::for_test([
            (
                registry_source_set::RegistryUnit::Authority,
                checked_registry_source(),
            ),
            (
                registry_source_set::RegistryUnit::Core,
                "struct EffectRegistry;".to_owned(),
            ),
        ])
        .unwrap();
        let second_error = registry_source_set::validate_source_set(&second).unwrap_err();
        assert!(
            second_error.contains("checked-item ownership drifted")
                && second_error.contains("EffectRegistry"),
            "second Registry failed through the wrong source-set gate: {second_error}"
        );

        let clone_impl = registry_source_set::RegistrySourceSet::for_test([
            (
                registry_source_set::RegistryUnit::Authority,
                checked_registry_source(),
            ),
            (
                registry_source_set::RegistryUnit::Core,
                "impl Clone for EffectRegistry { fn clone(&self) -> Self { loop {} } }".to_owned(),
            ),
        ])
        .unwrap();
        let clone_error = registry_source_set::validate_source_set(&clone_impl).unwrap_err();
        assert!(
            clone_error.contains("must not implement Clone") && clone_error.contains("Core"),
            "cross-unit Clone impl failed through the wrong source-set gate: {clone_error}"
        );
    }

    #[test]
    fn registry_source_set_never_concatenates_unit_parse_boundaries() {
        let source = checked_registry_source();
        let needle = "pub(crate) struct EffectRegistry";
        let split = source.find(needle).unwrap() + "pub(crate) struct ".len();
        let authority = source[..split].to_owned();
        let evidence = source[split..].to_owned();
        assert_eq!(format!("{authority}{evidence}"), source);
        let sources = registry_source_set::RegistrySourceSet::for_test([
            (registry_source_set::RegistryUnit::Authority, authority),
            (registry_source_set::RegistryUnit::Evidence, evidence),
        ])
        .unwrap();
        let error = registry_source_set::validate_source_set(&sources).unwrap_err();
        assert!(
            error.contains("does not parse independently") && error.contains("Authority"),
            "split source failed through the wrong no-concatenation gate: {error}"
        );
    }

    #[test]
    fn registry_source_set_loader_rejects_unactivated_child_source() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "nexus-stage7b-registry-source-set-inactive-{}-{nonce}",
            std::process::id()
        ));
        let authority = root.join(FAULT_REGISTRY_SOURCE);
        fs::create_dir_all(authority.parent().unwrap()).unwrap();
        fs::write(&authority, checked_registry_source()).unwrap();
        let evidence = root.join(registry_source_set::RegistryUnit::Evidence.path());
        fs::create_dir_all(evidence.parent().unwrap()).unwrap();
        fs::write(&evidence, "struct HiddenEvidence;").unwrap();

        let error = registry_source_set::RegistrySourceSet::read_current(&root).unwrap_err();
        assert!(
            error.contains("inactive Stage 7B Registry unit") && error.contains("Evidence"),
            "inactive child failed through the wrong source-set gate: {error}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn registry_source_set_loader_rejects_symlinked_authority() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "nexus-stage7b-registry-source-set-symlink-{}-{nonce}",
            std::process::id()
        ));
        let target = root.join("registry-target.rs");
        fs::create_dir_all(&root).unwrap();
        fs::write(&target, checked_registry_source()).unwrap();
        let authority = root.join(FAULT_REGISTRY_SOURCE);
        fs::create_dir_all(authority.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &authority).unwrap();

        let error = registry_source_set::RegistrySourceSet::read_current(&root).unwrap_err();
        assert!(
            error.contains("not a regular non-symlink file")
                && error.contains(FAULT_REGISTRY_SOURCE),
            "symlink failed through the wrong source-set gate: {error}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn non_device_candidate_gate_rejects_production_and_unlisted_callers() {
        let mut production = checked_non_device_candidate_callers();
        production.insert(
            "kernel/nexus-ostd/src/personality/linux_fs.rs".to_owned(),
            1,
        );
        assert!(validate_non_device_candidate_caller_counts(&production).is_err());

        let mut third_legacy = checked_non_device_candidate_callers();
        third_legacy.insert(
            "kernel/nexus-ostd/src/cser/unlisted_evaluator.rs".to_owned(),
            1,
        );
        assert!(validate_non_device_candidate_caller_counts(&third_legacy).is_err());

        let mut missing_legacy = checked_non_device_candidate_callers();
        missing_legacy.remove("kernel/nexus-ostd/src/cser/composition.rs");
        assert!(validate_non_device_candidate_caller_counts(&missing_legacy).is_err());
    }

    #[test]
    fn non_device_candidate_caller_scan_rejects_ufcs_in_linux_fs() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "nexus-non-device-caller-scan-{}-{nonce}",
            std::process::id()
        ));
        for (relative, source) in [
            (
                FAULT_REGISTRY_SOURCE,
                "clone_non_device_candidate clone_non_device_candidate clone_non_device_candidate clone_non_device_candidate",
            ),
            (
                "kernel/nexus-ostd/src/cser/composition.rs",
                "clone_non_device_candidate",
            ),
            (
                "kernel/nexus-ostd/src/cser/linux_io_composition.rs",
                "clone_non_device_candidate",
            ),
        ] {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        validate_non_device_candidate_callers(&root).unwrap();

        let production = root.join("kernel/nexus-ostd/src/personality/linux_fs.rs");
        fs::create_dir_all(production.parent().unwrap()).unwrap();
        fs::write(
            &production,
            "let _ = EffectRegistry::clone_non_device_candidate(&registry);",
        )
        .unwrap();
        assert!(validate_non_device_candidate_callers(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn production_device_batch_gate_rejects_operation_publish_and_apply_mutations() {
        let source = checked_registry_source();

        let forgeable_operation = source.replacen(
            "    caller_nonce: u64,\n}",
            "    pub(crate) caller_nonce: u64,\n}",
            1,
        );
        assert_ne!(forgeable_operation, source);
        assert!(validate_fault_registry_source_text(&forgeable_operation).is_err());

        let copy_operation_declaration = format!(
            "{CSER_CORE_DERIVE_CLONE_COPY_DEBUG_EQ_PARTIAL_EQ}\npub(crate) struct DeviceCloseOperationId {{"
        );
        let noncopy_operation_declaration = format!(
            "{CSER_CORE_DERIVE_CLONE_DEBUG_EQ_PARTIAL_EQ}\npub(crate) struct DeviceCloseOperationId {{"
        );
        let noncopy_operation = source.replacen(
            &copy_operation_declaration,
            &noncopy_operation_declaration,
            1,
        );
        assert_ne!(noncopy_operation, source);
        assert!(validate_fault_registry_source_text(&noncopy_operation).is_err());

        let public_receipt_claim = source.replacen(
            "    fn claim_device_replay_reset_and_revoke(",
            "    pub(crate) fn claim_device_replay_reset_and_revoke(",
            1,
        );
        assert_ne!(public_receipt_claim, source);
        assert!(validate_fault_registry_source_text(&public_receipt_claim).is_err());

        let torn_publication_provenance = source.replacen(
            "enum DevicePublicationProvenance {\n    None,",
            "enum DevicePublicationProvenance {\n    OperationOnly(DeviceCloseOperationId),\n    None,",
            1,
        );
        assert_ne!(torn_publication_provenance, source);
        assert!(validate_fault_registry_source_text(&torn_publication_provenance).is_err());

        let recovery_republishes = source.replacen(
            "Ok((receipt, selection)) => {\n                    Ok(DeviceCloseOutcome::Recovered { receipt, selection })\n                }",
            "Ok((receipt, selection)) => {\n                    let _ = publish(&receipt);\n                    Ok(DeviceCloseOutcome::Recovered { receipt, selection })\n                }",
            1,
        );
        assert_ne!(recovery_republishes, source);
        assert!(validate_fault_registry_source_text(&recovery_republishes).is_err());

        let misclassified_unpublished = source.replacen(
            ".map_err(DeviceCloseError::Unpublished)?;",
            ".map_err(|error| DeviceCloseError::Published { obligation: unchecked_obligation(), error })?;",
            1,
        );
        assert_ne!(misclassified_unpublished, source);
        assert!(validate_fault_registry_source_text(&misclassified_unpublished).is_err());

        let premature_combined_apply = source.replacen(
            concat!(
                "let applied = apply_publication();\n",
                "        self.apply_publication_ack(publication);\n",
                "        self.apply_revoke_complete(revoke);",
            ),
            concat!(
                "self.apply_publication_ack(publication);\n",
                "        self.apply_revoke_complete(revoke);\n",
                "        let applied = apply_publication();",
            ),
            1,
        );
        assert_ne!(premature_combined_apply, source);
        assert!(validate_fault_registry_source_text(&premature_combined_apply).is_err());

        let reordered_operation_publish = source.replacen(
            "let publication = publish(&plan.batch.receipt);\n        let (receipt, selection) = self.apply_device_close(plan);",
            "let (receipt, selection) = self.apply_device_close(plan);\n        let publication = publish(&receipt);",
            1,
        );
        assert_ne!(reordered_operation_publish, source);
        assert!(validate_fault_registry_source_text(&reordered_operation_publish).is_err());

        let skipped_stored_preallocation = source.replacen(
            "let stored_batch = batch.receipt.clone();",
            "let stored_batch = reconstruct_after_publish(&batch.receipt);",
            1,
        );
        assert_ne!(skipped_stored_preallocation, source);
        assert!(validate_fault_registry_source_text(&skipped_stored_preallocation).is_err());

        let reordered_operation_apply = source.replacen(
            "let receipt = self.apply_device_batch(batch);\n        let selection = self.apply_revoke_begin(revoke);",
            "let selection = self.apply_revoke_begin(revoke);\n        let receipt = self.apply_device_batch(batch);",
            1,
        );
        assert_ne!(reordered_operation_apply, source);
        assert!(validate_fault_registry_source_text(&reordered_operation_apply).is_err());

        let scanning_obligation = source.replacen(
            "let scope = self.scopes.get(&scope_key)?;\n        let root = scope.device_root.as_ref()?;",
            "let _ = self.reconstruct_device_batch_receipt(scope_key, 1);\n        let scope = self.scopes.get(&scope_key)?;\n        let root = scope.device_root.as_ref()?;",
            1,
        );
        assert_ne!(scanning_obligation, source);
        assert!(validate_fault_registry_source_text(&scanning_obligation).is_err());

        let batch_only_obligation = source.replacen(
            "let has_published_or_closure_progress = root.batch_sequence.is_some()\n            || !root.publication.is_none()",
            "let has_published_or_closure_progress = root.batch_sequence.is_some()",
            1,
        );
        assert_ne!(batch_only_obligation, source);
        assert!(validate_fault_registry_source_text(&batch_only_obligation).is_err());

        let double_revoke_increment = source.replacen(
            "self.next_revoke_sequence = next_revoke_sequence;",
            "self.next_revoke_sequence = next_revoke_sequence.saturating_add(1);",
            1,
        );
        assert_ne!(double_revoke_increment, source);
        assert!(validate_fault_registry_source_text(&double_revoke_increment).is_err());

        let weakened_revoke_overflow = source.replacen(
            "close_revoke_overflow.next_revoke_sequence = u64::MAX;",
            "close_revoke_overflow.next_revoke_sequence = u64::MAX - 1;",
            1,
        );
        assert_ne!(weakened_revoke_overflow, source);
        assert!(validate_fault_registry_source_text(&weakened_revoke_overflow).is_err());

        let weakened_second_revision_overflow = source.replacen(
            "revision = u64::MAX - 1;\n    assert_fresh_close_overflow(&mut close_revoke_revision_overflow);",
            "revision = u64::MAX - 2;\n    assert_fresh_close_overflow(&mut close_revoke_revision_overflow);",
            1,
        );
        assert_ne!(weakened_second_revision_overflow, source);
        assert!(validate_fault_registry_source_text(&weakened_second_revision_overflow).is_err());

        let reordered = source.replacen(
            "let publication = publish(&plan.receipt);\n                let receipt = self.apply_device_batch(plan);",
            "let receipt = self.apply_device_batch(plan);\n                let publication = publish(&receipt);",
            1,
        );
        assert_ne!(reordered, source);
        assert!(validate_fault_registry_source_text(&reordered).is_err());

        let replay_publish = source.replacen(
            "PreparedDeviceBatch::Replay(receipt) => {\n                Ok(DeviceBatchCommitOutcome::AlreadyCommitted { receipt })",
            "PreparedDeviceBatch::Replay(receipt) => {\n                let _ = publish(&receipt);\n                Ok(DeviceBatchCommitOutcome::AlreadyCommitted { receipt })",
            1,
        );
        assert_ne!(replay_publish, source);
        assert!(validate_fault_registry_source_text(&replay_publish).is_err());

        let fallible_apply = source.replacen(
            ".commit_validated(&charges);",
            ".commit(&charges).unwrap();",
            1,
        );
        assert_ne!(fallible_apply, source);
        assert!(validate_fault_registry_source_text(&fallible_apply).is_err());

        let reordered_iotlb_apply = source.replacen(
            "let receipt = self.apply_device_iotlb(plan);\n        let publication = apply_quiescence(&receipt);",
            "let publication = apply_quiescence(&plan.receipt);\n        let receipt = self.apply_device_iotlb(plan);",
            1,
        );
        assert_ne!(reordered_iotlb_apply, source);
        assert!(validate_fault_registry_source_text(&reordered_iotlb_apply).is_err());

        let skipped_iotlb_prevalidation = source.replacen(
            "let plan = self.prepare_device_iotlb_apply(ticket)?;",
            "let plan = unchecked_device_iotlb_apply(ticket);",
            1,
        );
        assert_ne!(skipped_iotlb_prevalidation, source);
        assert!(validate_fault_registry_source_text(&skipped_iotlb_prevalidation).is_err());

        let skipped_quiescence_apply = source.replacen(
            "let publication = apply_quiescence(&receipt);",
            "let publication = ();",
            1,
        );
        assert_ne!(skipped_quiescence_apply, source);
        assert!(validate_fault_registry_source_text(&skipped_quiescence_apply).is_err());

        let fallible_iotlb_apply = source.replacen(
            "        root.iotlb_ticket = None;\n        root.closure = Some(receipt);",
            "        root.iotlb_ticket = fallible_iotlb_take()?;\n        root.closure = Some(receipt);",
            1,
        );
        assert_ne!(fallible_iotlb_apply, source);
        assert!(validate_fault_registry_source_text(&fallible_iotlb_apply).is_err());
    }

    #[test]
    fn production_device_closure_gate_rejects_enrollment_retention_and_generation_bypasses() {
        let source = checked_registry_source();

        let copyable_device_authority = source.replacen(
            "candidate.device_publication_mode = DevicePublicationMode::DisabledNonDeviceCandidate;",
            "candidate.device_publication_mode = DevicePublicationMode::Unique;",
            1,
        );
        assert_ne!(copyable_device_authority, source);
        assert!(validate_fault_registry_source_text(&copyable_device_authority).is_err());

        let missing_device_authority_guard = source.replacen(
            "self.require_unique_device_publication()?;",
            "let _ = self.device_publication_mode;",
            1,
        );
        assert_ne!(missing_device_authority_guard, source);
        assert!(validate_fault_registry_source_text(&missing_device_authority_guard).is_err());

        let registration_prefix = concat!(
            "pub(crate) fn register_device_derived(\n",
            "        &mut self,\n",
            "        request: DeviceDerivedRegisterRequest,\n",
            "    ) -> Result<RegisteredEffect, RegistryError> {\n",
            "        self.require_unique_device_publication()?;",
        );
        let mint_prefix = concat!(
            "pub(crate) fn kernel_root_authority(\n",
            "        &self,\n",
            "        scope_key: ScopeKey,\n",
            "        owner: TaskKey,\n",
            "    ) -> Result<KernelRootAuthority, RegistryError> {\n",
            "        self.require_unique_device_publication()?;",
        );
        let moved_device_authority_guard = source
            .replacen(
                registration_prefix,
                &registration_prefix.replace(
                    "self.require_unique_device_publication()?;",
                    "let _ = self.device_publication_mode;",
                ),
                1,
            )
            .replacen(
                mint_prefix,
                &mint_prefix.replace(
                    "self.require_unique_device_publication()?;",
                    concat!(
                        "self.require_unique_device_publication()?;\n",
                        "        self.require_unique_device_publication()?;",
                    ),
                ),
                1,
            );
        assert_ne!(moved_device_authority_guard, source);
        assert_eq!(
            moved_device_authority_guard
                .matches("self.require_unique_device_publication()?;")
                .count(),
            6
        );
        assert!(validate_fault_registry_source_text(&moved_device_authority_guard).is_err());

        let cohort_prefix = concat!(
            "pub(crate) fn register_device_derived_cohort(\n",
            "        &mut self,\n",
            "        entries: [DeviceDerivedCohortEntry; 4],\n",
            "    ) -> Result<[RegisteredEffect; 4], RegistryError> {\n",
            "        self.require_unique_device_publication()?;",
        );
        let missing_cohort_authority_guard = source.replacen(
            cohort_prefix,
            &cohort_prefix.replace(
                "self.require_unique_device_publication()?;",
                "let _ = self.device_publication_mode;",
            ),
            1,
        );
        assert_ne!(missing_cohort_authority_guard, source);
        assert!(validate_fault_registry_source_text(&missing_cohort_authority_guard).is_err());

        let public_inherent_registry_clone = source.replacen(
            "    fn clone(&self) -> Self {",
            "    pub(crate) fn clone(&self) -> Self {",
            1,
        );
        assert_ne!(public_inherent_registry_clone, source);
        assert!(validate_fault_registry_source_text(&public_inherent_registry_clone).is_err());

        let registry_declaration =
            format!("{CSER_CORE_DERIVE_DEBUG_EQ_PARTIAL_EQ}\npub(crate) struct EffectRegistry {{");
        let cloneable_registry_declaration = format!(
            "{CSER_CORE_DERIVE_CLONE_DEBUG_EQ_PARTIAL_EQ}\npub(crate) struct EffectRegistry {{"
        );
        let trait_cloneable_registry =
            source.replacen(&registry_declaration, &cloneable_registry_declaration, 1);
        assert_ne!(trait_cloneable_registry, source);
        assert!(validate_fault_registry_source_text(&trait_cloneable_registry).is_err());

        let public_legacy_candidate_clone = source.replacen(
            "pub(super) fn clone_non_device_candidate(&self) -> Result<Self, RegistryError>",
            "pub(crate) fn clone_non_device_candidate(&self) -> Result<Self, RegistryError>",
            1,
        );
        assert_ne!(public_legacy_candidate_clone, source);
        assert!(validate_fault_registry_source_text(&public_legacy_candidate_clone).is_err());

        let authority_copy_wrapper = source.replacen(
            "    /// Clones a legacy composition candidate without duplicating device",
            concat!(
                "    fn authority_copy(&self) -> Self {\n",
                "        self.clone()\n",
                "    }\n\n",
                "    /// Clones a legacy composition candidate without duplicating device",
            ),
            1,
        );
        assert_ne!(authority_copy_wrapper, source);
        assert!(validate_fault_registry_source_text(&authority_copy_wrapper).is_err());

        let extra_registry_clone = source.replacen(
            "let mut candidate = self.clone();\n        let block =",
            "let _extra = self.clone();\n        let mut candidate = self.clone();\n        let block =",
            1,
        );
        assert_ne!(extra_registry_clone, source);
        assert!(validate_fault_registry_source_text(&extra_registry_clone).is_err());

        let forward_parent_allowed = source.replacen(
            "parent_index >= slots.len() || parent_index >= batch_index",
            "parent_index >= slots.len()",
            1,
        );
        assert_ne!(forward_parent_allowed, source);
        assert!(validate_fault_registry_source_text(&forward_parent_allowed).is_err());

        let live_partial_registration = source.replacen(
            "let block = candidate.register_device_derived(",
            "let block = self.register_device_derived(",
            1,
        );
        assert_ne!(live_partial_registration, source);
        assert!(validate_fault_registry_source_text(&live_partial_registration).is_err());

        let unchecked_cohort_candidate =
            source.replacen("candidate.check_invariants()?;", "let _ = &candidate;", 1);
        assert_ne!(unchecked_cohort_candidate, source);
        assert!(validate_fault_registry_source_text(&unchecked_cohort_candidate).is_err());

        let allocating_cohort_apply = source.replacen(
            "*self = candidate;",
            "self.effects.insert(effect, record);\n        *self = candidate;",
            1,
        );
        assert_ne!(allocating_cohort_apply, source);
        assert!(validate_fault_registry_source_text(&allocating_cohort_apply).is_err());

        let post_swap_allocating_cohort_apply = source.replacen(
            "*self = candidate;\n        registered",
            "*self = candidate;\n        let _late = __cser_alloc::vec![registered.len()];\n        registered",
            1,
        );
        assert_ne!(post_swap_allocating_cohort_apply, source);
        assert!(validate_fault_registry_source_text(&post_swap_allocating_cohort_apply).is_err());

        let leaf_selected_completion_result =
            source.replacen("if result != causal_root.result", "if false", 1);
        assert_ne!(leaf_selected_completion_result, source);
        assert!(validate_fault_registry_source_text(&leaf_selected_completion_result).is_err());

        let disabled_completion_result_check = source.replacen(
            "if result != causal_root.result {",
            "if result != causal_root.result && false {",
            1,
        );
        assert_ne!(disabled_completion_result_check, source);
        assert!(validate_fault_registry_source_text(&disabled_completion_result_check).is_err());

        let unbound_completion_receipt = source.replacen(
            "causal_root: causal_root.effect,",
            "causal_root: batch.commits[1].effect,",
            1,
        );
        assert_ne!(unbound_completion_receipt, source);
        assert!(validate_fault_registry_source_text(&unbound_completion_receipt).is_err());

        let missing_candidate_invariant = source.replacen(
            "non-device candidate acquired device publication state",
            "candidate state accepted device publication",
            1,
        );
        assert_ne!(missing_candidate_invariant, source);
        assert!(validate_fault_registry_source_text(&missing_candidate_invariant).is_err());

        let ancestor_only = source.replacen(
            "if self.scopes[&record.identity.scope].device_root.is_some() {",
            "if record.identity.device.is_some() {",
            1,
        );
        assert_ne!(ancestor_only, source);
        assert!(validate_fault_registry_source_text(&ancestor_only).is_err());

        let late_attachment = source.replacen(
            "let mut ancestor = Some(parent);",
            "let mut ancestor = None;",
            1,
        );
        assert_ne!(late_attachment, source);
        assert!(validate_fault_registry_source_text(&late_attachment).is_err());

        let unenrolled_commit = source.replacen(
            "root_state.enrollment.as_ref() != Some(enrollment)",
            "false",
            1,
        );
        assert_ne!(unenrolled_commit, source);
        assert!(validate_fault_registry_source_text(&unenrolled_commit).is_err());

        let missing_emergency_freeze = source.replacen(
            "let cancel_enrollment = pending_cancel.freeze_pending_device_cancel(SCOPE).unwrap();",
            "let cancel_enrollment = enrollment.clone();",
            1,
        );
        assert_ne!(missing_emergency_freeze, source);
        assert!(validate_fault_registry_source_text(&missing_emergency_freeze).is_err());

        let missing_cancel_only_witness = source.replacen(
            cser_core_macro!("assert", "(cancel_enrollment.cancel_only());"),
            cser_core_macro!("assert_eq", "(cancel_enrollment.effects().len(), 6);"),
            1,
        );
        assert_ne!(missing_cancel_only_witness, source);
        assert!(validate_fault_registry_source_text(&missing_cancel_only_witness).is_err());

        let publishable_cancel_enrollment =
            source.replacen("|| enrollment.cancel_only", "|| false", 1);
        assert_ne!(publishable_cancel_enrollment, source);
        assert!(validate_fault_registry_source_text(&publishable_cancel_enrollment).is_err());

        let publishing_revoke_allowed = source.replacen(
            concat!(
                "if scope.device_root.as_ref().is_some_and(|root| {\n",
                "            __cser_core::matches!(\n",
                "                root.publication,\n",
                "                DevicePublicationProvenance::Publishing { .. }\n",
                "            )\n",
                "        }) {",
            ),
            "if false {",
            1,
        );
        assert_ne!(publishing_revoke_allowed, source);
        assert!(validate_fault_registry_source_text(&publishing_revoke_allowed).is_err());

        let publishing_cancel_allowed = source.replacen(
            concat!(
                "if self.scopes[&enrollment.scope].phase != ScopePhase::Closing\n",
                "            || root.batch_sequence.is_some()\n",
                "            || !root.publication.is_none()",
            ),
            concat!(
                "if self.scopes[&enrollment.scope].phase != ScopePhase::Closing\n",
                "            || root.batch_sequence.is_some()",
            ),
            1,
        );
        assert_ne!(publishing_cancel_allowed, source);
        assert!(validate_fault_registry_source_text(&publishing_cancel_allowed).is_err());

        let fake_indeterminate_terminal = source.replacen(
            "outcome: TerminalOutcome::IndeterminateAfterReset,\n            result,\n            causal_commit: None,",
            "outcome: TerminalOutcome::Completed,\n            result,\n            causal_commit: None,",
            1,
        );
        assert_ne!(fake_indeterminate_terminal, source);
        assert!(validate_fault_registry_source_text(&fake_indeterminate_terminal).is_err());

        let missing_indeterminate_digest = source.replacen(
            "outcome: TerminalOutcome::IndeterminateAfterReset,\n            result,\n            causal_commit: None,\n            manifest_digest: None,",
            "outcome: TerminalOutcome::IndeterminateAfterReset,\n            result,\n            causal_commit: None,",
            1,
        );
        assert_ne!(missing_indeterminate_digest, source);
        assert!(validate_fault_registry_source_text(&missing_indeterminate_digest).is_err());

        let forged_indeterminate_digest = source.replacen(
            "outcome: TerminalOutcome::IndeterminateAfterReset,\n            result,\n            causal_commit: None,\n            manifest_digest: None,",
            "outcome: TerminalOutcome::IndeterminateAfterReset,\n            result,\n            causal_commit: None,\n            manifest_digest: Some([0xa5; 32]),",
            1,
        );
        assert_ne!(forged_indeterminate_digest, source);
        assert!(validate_fault_registry_source_text(&forged_indeterminate_digest).is_err());

        let generic_terminal = source.replacen(
            "authorized_device_enrollment != Some(enrollment.enrollment_sequence)",
            "false",
            1,
        );
        assert_ne!(generic_terminal, source);
        assert!(validate_fault_registry_source_text(&generic_terminal).is_err());

        let released_timeout = source.replace(
            "self.apply_device_root_retention(&enrollment, retention.as_ref());",
            "let _ = retention.as_ref();",
        );
        assert_ne!(released_timeout, source);
        assert!(validate_fault_registry_source_text(&released_timeout).is_err());

        let false_timeout_result = source.replacen(
            "root.reset_tombstone = Some(tombstone);",
            "root.reset_tombstone = Some(tombstone);\n        root.outcome = Some(DeviceClosureResult::IndeterminateAfterReset);",
            1,
        );
        assert_ne!(false_timeout_result, source);
        assert!(validate_fault_registry_source_text(&false_timeout_result).is_err());

        let old_generation_allowed = source.replacen(
            "if presented_device != root.current_device {",
            "if false {",
            1,
        );
        assert_ne!(old_generation_allowed, source);
        assert!(validate_fault_registry_source_text(&old_generation_allowed).is_err());

        let split_generation_apply = source.replacen(
            "let receipt = self.apply_device_reset(plan);\n        let publication = apply_generation(&receipt);",
            "let publication = apply_generation(&plan.receipt);\n        let receipt = self.apply_device_reset(plan);",
            1,
        );
        assert_ne!(split_generation_apply, source);
        assert!(validate_fault_registry_source_text(&split_generation_apply).is_err());
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
    fn fault_registry_gate_structurally_binds_all_self_test_registries() {
        let source = checked_registry_source();

        let moved_combined = source
            .replacen(
                "fn fixture() -> (EffectRegistry, EffectKey, EffectKey) {\n        let mut registry = EffectRegistry::new();",
                "fn fixture() -> (EffectRegistry, EffectKey, EffectKey) {\n        let mut registry = EffectRegistry::default();",
                1,
            )
            .replacen(
                "pub(crate) struct Stage7bFaultCredit {",
                "fn hidden_combined_sidecar() -> EffectRegistry { EffectRegistry::new() }\n\npub(crate) struct Stage7bFaultCredit {",
                1,
            );
        assert_eq!(
            moved_combined.matches("EffectRegistry::new()").count(),
            source.matches("EffectRegistry::new()").count(),
            "mutation must preserve the global constructor count"
        );
        assert!(validate_fault_registry_source_text(&moved_combined).is_err());

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

        let moved_publication = source
            .replacen(
                "const CHILD_DOMAIN: DomainKey = DomainKey::new(1);\n\n    let mut registry = EffectRegistry::new();",
                "const CHILD_DOMAIN: DomainKey = DomainKey::new(1);\n\n    let mut registry = EffectRegistry::default();",
                1,
            )
            .replacen(
                "pub(crate) struct Stage7bFaultCredit {",
                "fn hidden_publication_sidecar() -> EffectRegistry { EffectRegistry::new() }\n\npub(crate) struct Stage7bFaultCredit {",
                1,
            );
        assert_eq!(
            moved_publication.matches("EffectRegistry::new()").count(),
            source.matches("EffectRegistry::new()").count(),
            "mutation must preserve the global constructor count"
        );
        assert!(validate_fault_registry_source_text(&moved_publication).is_err());

        let moved_retained = source
            .replacen(
                "ProductionDeviceBatchRaceFixture::from_empty_registry(EffectRegistry::new())",
                "ProductionDeviceBatchRaceFixture::from_empty_registry(EffectRegistry::default())",
                1,
            )
            .replacen(
                "pub(crate) struct Stage7bFaultCredit {",
                "fn hidden_retained_sidecar() -> EffectRegistry { EffectRegistry::new() }\n\npub(crate) struct Stage7bFaultCredit {",
                1,
            );
        assert_eq!(
            moved_retained.matches("EffectRegistry::new()").count(),
            source.matches("EffectRegistry::new()").count(),
            "mutation must preserve the global constructor count"
        );
        assert!(validate_fault_registry_source_text(&moved_retained).is_err());

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

        task_fault_source::exercise_negative_mutations(&source);
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
        for (relative, source) in [
            (
                "kernel/nexus-ostd/src/cser/composition.rs",
                include_str!("../../../kernel/nexus-ostd/src/cser/composition.rs"),
            ),
            (
                "kernel/nexus-ostd/src/cser/linux_io_composition.rs",
                include_str!("../../../kernel/nexus-ostd/src/cser/linux_io_composition.rs"),
            ),
        ] {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
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
