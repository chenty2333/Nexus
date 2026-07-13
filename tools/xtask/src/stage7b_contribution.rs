use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const DIRECTORY: &str = "target/verification/stage7b";

const REQUIRED_GATES: &[&str] = &[
    "race-coverage-14-of-14",
    "all-required-implementation-source-safety-gates-pass",
    "fault-matrix-20-of-20",
    "all-central-fault-safety-cells-pass",
    "scale-structure-14-of-14",
    "performance-protocol-29-of-29",
    "prior-art-16-of-16",
];

const BASE_NARROW_EXCLUSIONS: &[&str] = &[
    "SMP",
    "hardware cycles",
    "lock freedom",
    "production liveness",
    "durable external effects",
    "Linux breadth",
    "identity-preserving Stage5B root composition",
    "full pager adapter equivalence; the legacy serial-oracle mirror remains",
    "shared production fault-budget scope across all fault cells",
    "cross-object crash/panic atomicity between transition gates and case-local Registry ledgers",
];

const METADATA_ONLY_EXCLUSION: &str = "full-text audit for Shadow Drivers and Atomic RPC";

const CONCURRENCY_IDS: &[&str] = &[
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

const CONCURRENCY_CASES: &[&str] = &[
    "wake_vs_timeout_single_winner",
    "cancel_vs_wake_single_winner",
    "stale_deadline_after_rearm",
    "same_page_single_publication",
    "handler_crash_before_resolution",
    "old_binding_reply_after_rebind",
    "adopt_vs_abort_single_winner",
    "resolve_vs_abort_one_shot",
    "commit_vs_revoke_linearization",
    "revoke_deferred_wait_timer",
    "budget_commit_vs_abort_conservation",
    "fallback_before_rebind",
    "publish_vs_revoke_commit_gate",
    "timeout_vs_late_completion_tombstone",
];

const CONCURRENCY_ASSERTIONS: &[&[&str]] = &[
    &[
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
    &[
        "oneshot-single-terminal",
        "oneshot-receipt-provenance",
        "late-wake-rejected",
        "typed-receipt-registry-disposition",
        "publication-ack-once",
        "credits-fully-returned",
        "reverse-indexes-empty",
        "scope-revoked",
    ],
    &[
        "old-token-rejected",
        "rejection-failure-atomic",
        "replacement-generation-advanced",
        "replacement-remains-live",
    ],
    &[
        "resume-before-commit-rejected",
        "publication-closure-once",
        "losing-candidate-released-once",
        "continuations-terminal-once",
        "duplicate-resume-rejected",
        "scope-revoked",
    ],
    &[
        "crash-fences-old-binding",
        "committed-crash-kernel-terminal",
        "uncommitted-crash-aborts",
        "continuation-single-terminal",
        "no-implicit-adoption",
        "scope-revoked",
    ],
    &[
        "mapping-committed-before-crash",
        "old-reply-failure-atomic",
        "old-reply-no-resume",
        "old-reply-credit-failure-atomic",
        "kernel-terminal-once",
        "scope-revoked",
    ],
    &[
        "decision-single-winner",
        "adoption-explicit-only",
        "ownership-authority-consumed-once",
        "continuation-terminal-once",
        "late-action-failure-atomic",
        "scope-revoked",
    ],
    &[
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
    &[
        "commit-revoke-single-order",
        "closed-epoch-commit-rejected",
        "committed-effect-drained",
        "uncommitted-effect-aborted",
        "reverse-index-empty",
        "scope-revoked",
    ],
    &[
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
    &[
        "single-credit-disposition",
        "free-held-committed-conserved",
        "credit-returned-once",
        "duplicate-completion-rejected",
        "abort-after-commit-not-reported",
        "scope-revoked",
    ],
    &[
        "crash-advances-binding-once",
        "repeated-crash-unchanged",
        "pending-proposal-cleared",
        "fallback-pick-before-rebind",
        "rebind-keeps-binding-epoch",
        "stale-proposals-failure-atomic",
    ],
    &[
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
    &[
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
];

const FAULT_IDS: &[&str] = &[
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

const FAULT_INJECTIONS: &[&str] = &[
    "lease-expiry",
    "after-proposal",
    "before-rebind",
    "after-rebind",
    "repeated-crash",
    "same-page-register",
    "before-prepare",
    "after-prepare",
    "after-commit",
    "timeout-before-late-reply",
    "before-backend-commit",
    "after-backend-commit",
    "ready-first",
    "revoke-first",
    "old-deadline-after-rearm",
    "before-device-publication",
    "reset-ack-first",
    "reset-timeout-retry",
    "iotlb-timeout-late-ack",
    "duplicate-completion",
];

const FAULT_TERMINALS: &[&str] = &[
    "FallbackPick",
    "FallbackPick",
    "FallbackPick",
    "FallbackPick",
    "FallbackPick",
    "Resolved",
    "Aborted",
    "Aborted",
    "Resolved",
    "Aborted",
    "Aborted",
    "Completed",
    "Ready",
    "Aborted",
    "TimedOut",
    "AbortedBeforeCommit",
    "IndeterminateAfterReset",
    "IndeterminateAfterReset",
    "Quiesced",
    "Completed",
];

const FAULT_PUBLICATIONS: &[u64] = &[1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1];
const FAULT_CREDITS: &[u64] = &[0, 0, 0, 0, 0, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
const FAULT_RETAINED: &[bool] = &[
    false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, true, true, true, false,
];

const SCALE_IDS: &[&str] = &[
    "fixed-n.k0000",
    "fixed-n.k0001",
    "fixed-n.k0008",
    "fixed-n.k0032",
    "fixed-n.k0128",
    "fixed-n.k0512",
    "fixed-k.n0032",
    "fixed-k.n0128",
    "fixed-k.n0512",
    "fixed-k.n2048",
    "fixed-k.n4096",
    "history.h0000",
    "history.h0064",
    "history.h1024",
];

const SCALE_TUPLES: &[(u64, u64, u64)] = &[
    (1024, 0, 0),
    (1024, 1, 0),
    (1024, 8, 0),
    (1024, 32, 0),
    (1024, 128, 0),
    (1024, 512, 0),
    (32, 32, 0),
    (128, 32, 0),
    (512, 32, 0),
    (2048, 32, 0),
    (4096, 32, 0),
    (1024, 32, 0),
    (1024, 32, 64),
    (1024, 32, 1024),
];

const PERFORMANCE_IDS: &[&str] = &[
    "begin.fixed-n.k0000",
    "begin.fixed-n.k0001",
    "begin.fixed-n.k0008",
    "begin.fixed-n.k0032",
    "begin.fixed-n.k0128",
    "begin.fixed-n.k0512",
    "complete.fixed-n.k0000",
    "complete.fixed-n.k0001",
    "complete.fixed-n.k0008",
    "complete.fixed-n.k0032",
    "complete.fixed-n.k0128",
    "complete.fixed-n.k0512",
    "closure.fixed-n.k0000",
    "closure.fixed-n.k0001",
    "closure.fixed-n.k0008",
    "closure.fixed-n.k0032",
    "closure.fixed-n.k0128",
    "closure.fixed-n.k0512",
    "closure.fixed-k.n0032",
    "closure.fixed-k.n0128",
    "closure.fixed-k.n0512",
    "closure.fixed-k.n2048",
    "closure.fixed-k.n4096",
    "closure.history.h0000",
    "closure.history.h0064",
    "closure.history.h1024",
    "projection.history.h0000",
    "projection.history.h0064",
    "projection.history.h1024",
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

const PRIOR_ART_ACCESS_KINDS: &[&str] = &[
    "primary-full-text",
    "primary-full-text",
    "primary-full-text",
    "primary-full-text",
    "primary-full-text",
    "primary-metadata",
    "primary-full-text",
    "primary-full-text",
    "primary-full-text",
    "primary-full-text",
    "primary-full-text",
    "primary-metadata",
    "primary-full-text",
    "primary-web-document",
    "primary-api-manual",
    "primary-specification",
];

const PRIOR_ART_URLS: &[&str] = &[
    "https://sel4.systems/Info/Docs/seL4-manual-latest.pdf",
    "https://doi.org/10.1109/SP40000.2020.00098",
    "https://arxiv.org/abs/2606.22504",
    "https://doi.org/10.1145/248155.238779",
    "https://www.usenix.org/conference/osdi-08/curios-improving-reliability-through-operating-system-structure",
    "https://doi.org/10.1145/945445.945466",
    "https://doi.org/10.1145/1629575.1629591",
    "https://doi.org/10.1145/1095810.1095829",
    "https://www.usenix.org/conference/osdi-06/rethink-sync",
    "https://www.usenix.org/conference/osdi-06/chubby-lock-service-loosely-coupled-distributed-systems",
    "https://doi.org/10.1145/2815400.2815416",
    "https://doi.org/10.1109/TSE.1985.231860",
    "https://www.usenix.org/conference/osdi-99/resource-containers-new-facility-resource-management-server-systems",
    "https://fuchsia.dev/fuchsia-src/contribute/governance/rfcs/0261_fast_and_efficient_user_space_kernel_emulation",
    "https://github.com/axboe/liburing/blob/e50e32a6b9030faba2e30fa0ba999571a0cffe28/man/io_uring_prep_cancel.3",
    "https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.pdf",
];

const PRIOR_ART_SOURCE_DIGESTS: &[&str] = &[
    "697b561c09fdbf88118efcf7bd609082e744c431d5b0dc76d377ca9ecfdd7c68",
    "aba64bb0171de17910f665a19b9dd99de08a4952d8eeea1bfa1b29f3844e0e77",
    "45efdfa3d5a16a712f964ae79dbc46df8ef843904da137ad4baeebf83b125f84",
    "0c359f25cd2566280017540f2f16981cc8fb41bab9f68959377fd6758d153525",
    "cf7831aa5ae46d4e69fd61ae01a313aaf7eb524d43d7336848b4b8f407b18695",
    "unavailable",
    "5b05f2783c543b27d37393d6cf48f3c63c16c69eb276b51e2b07bc3fa067b459",
    "bd6e83fc0954d7e37a24f7245d11a7f1eaf42588f36307f5782c51bcd4eb6636",
    "dee41e8bdbb52c116cc4bd0fceb9c2d7349976f583601247e6a58d1abe43ec61",
    "9d7cbad0760cc95d03595eadc188dc828237ba5645bceb7a15b9248ee02821bd",
    "f609f9508beaf936027f31428a8f06dc86d8201faadc5b340ffead7706863969",
    "unavailable",
    "16d5319ada401f0ac582000b3fcdd9b34649f001cb11d84dc1d7974241aa3a77",
    "9436fa22361e5152590f0c637f36463cec6de27eb53daea3afce5b4e9907cbf9",
    "2d68eabbc809daa08d8ccd1394ca1de72079b926abb1d04c921ef1fae0483b7a",
    "17d95b4d1518054e7a49e4e2025e1433a4e8c92bb2181a889dcdaa74b9616675",
];

const PRIOR_ART_AUDIT_DIGESTS: &[&str] = &[
    "02154ec0d33b15d6955713a62167386e2332edd890b4a5a1b009fc9a18971556",
    "3488969b333cd1a7236bcfcde870b9b96cb9356ffbf565da3f4d5ee5bc625cf5",
    "ad44b2e9a019fb9155a131d9a58e634ebfbea860ed9a8e9b008189ef3bb4cec3",
    "98794084fabe7bff8e81010fdc48a69dbbf41aaaf7bb6188d13c882444d785a8",
    "7faadbe6778f21d039bc031214c46043f3f5bcd92cac1ec6cc254c96de0a7e72",
    "fc120b69a8aa110d702218f1009b91cf9ac84a7e0326b4d456b629802810ae21",
    "3eebfc4954c5339348b5f5aa40d7040563fd3cc819effa7f37cfdd5046191486",
    "81fd1241fb28abd9dbb9eee146cb918d3ce5a11c60b95ee26bd7a46115b79fc2",
    "a932951129d0758067c1421797275b725608a5658b84713cc761e1130a31839e",
    "936bea89098655df3b970f5207ebf6c6089f1d79d9fc56c16933c21b27f0b6d9",
    "53e0c1dadba49f5da898e53530eaa059593b1c1e867808d8024309a86113af73",
    "400330b5817d20f76c521ca5803828280aad6a4a8f02ec41f8bf5ac746394198",
    "c3b3ff4a1258efa17d0da6e42794bcf611d1113b309ce4179e58353ad6325e66",
    "95824733b275c15f3bb2e6faf2ccd84398bd4bbd4aba20d8d42d0340a389177a",
    "b6a6d1b6bf02b1190d6bef8137e1d33e8c26a6b35e4c0d5e54b52c897e1f5514",
    "00404d2bf23a3bc94cd1bf7495e6082a849009ebfcf77cdfb39e853b3ae37be1",
];

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Summary {
    pub(crate) verdict: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Decision {
    schema: &'static str,
    status: &'static str,
    verdict: &'static str,
    supported_boundary: &'static str,
    gates: Gates,
    claim_status: ClaimStatus,
    exclusions: Vec<&'static str>,
    decision_reason: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Gates {
    implementation_source_concurrency: &'static str,
    fault_matrix: &'static str,
    scale_structure: &'static str,
    performance_protocol: &'static str,
    prior_art: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ClaimStatus {
    novelty: &'static str,
    first: &'static str,
    proved: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateStatus {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GateEvidence {
    id: &'static str,
    status: GateStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecisionEvidence {
    gates: Vec<GateEvidence>,
    central_fault_cells: Vec<bool>,
    support_bounded_allowed: bool,
    metadata_only_exclusions: Vec<String>,
    reject_conditions: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConcurrencyReceipt {
    schema: String,
    status: String,
    boundary: String,
    synchronization_model: String,
    forbidden_claims: Vec<String>,
    races: Vec<ConcurrencyRace>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConcurrencyRace {
    id: String,
    harness_case: String,
    status: String,
    assertion_markers: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FaultReceipt {
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
    status: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScaleReceipt {
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
    status: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PerformanceReceipt {
    schema: String,
    status: String,
    claim: String,
    thresholds: Option<Value>,
    environment: PerformanceEnvironment,
    runtime_metadata: RuntimeMetadata,
    empty_timer: SampleReceipt,
    cases: Vec<PerformanceCase>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeMetadata {
    schema: String,
    accel: String,
    vcpus: u64,
    threads: u64,
    cpu_pin: u64,
    cpus_allowed_list: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SampleReceipt {
    samples: usize,
    min: u64,
    median: u64,
    p95: u64,
    max: u64,
    raw: Vec<u64>,
    status: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    status: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PriorArtReceipt {
    schema: String,
    status: String,
    matrix: String,
    source_policy: String,
    summary: PriorArtSummary,
    metadata_only_exclusions: Vec<String>,
    sources: Vec<PriorArtSource>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PriorArtSummary {
    rows: u64,
    source_cards: u64,
    full_text: u64,
    metadata_only: u64,
    default_verdict: String,
    support_bounded_allowed: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PriorArtSource {
    id: String,
    access_kind: String,
    content_status: String,
    bibliographic_url: String,
    source_content_sha256: String,
    audit_notes_sha256: String,
}

pub(crate) fn run(root: &Path) -> Result<Summary, String> {
    let directory = root.join(DIRECTORY);
    let evidence = load_structured_evidence(&directory)?;
    let decision = narrow_decision();
    validate_decision(&decision, &evidence)?;

    let mut json = serde_json::to_vec_pretty(&decision)
        .map_err(|error| format!("serialize contribution decision: {error}"))?;
    json.push(b'\n');
    atomic_write(&directory.join("contribution.json"), &json)?;
    let oracle = b"schema=nexus.stage7b.contribution-oracle.v1\nstatus=passed\nverdict=narrow\nconcurrency=14/14\nfault_matrix=20/20\nfault_registry_backed_nonzero_credit_cells=15/15\nfault_scheduler_typed_no_credit_witnesses=5/5\nfault_registry_scope=case-local\nshared_production_fault_scope=not-established\ncross_object_crash_panic_atomicity=not-established\nscale=14/14\nperformance_protocol=29/29\nprior_art_rows=16/16\nprior_art_full_text=14/16\nfull_production_adapter_equivalence=not-established\nnovelty=not-established\nfirst=not-established\nproved=not-established\nforbidden_claims=false\n";
    atomic_write(&directory.join("contribution-oracle.log"), oracle)?;
    Ok(Summary { verdict: "narrow" })
}

fn narrow_decision() -> Decision {
    Decision {
        schema: "nexus.stage7b.contribution-decision.v1",
        status: "passed",
        verdict: "narrow",
        supported_boundary: "fixed CSER interaction combination with implementation-source races checked under a Loom-modeled outer mutex plus release single-vCPU case-local fault, scale, and performance evidence",
        gates: Gates {
            implementation_source_concurrency: "Checked 14/14",
            fault_matrix: "Checked 20/20: 15 case-local Registry-backed nonzero-credit cells and 5 typed N/A scheduler witnesses",
            scale_structure: "Checked 14/14",
            performance_protocol: "Observed 29/29; no thresholds",
            prior_art: "Checked 16/16 rows; 14 full-text and 2 primary-metadata-only",
        },
        claim_status: ClaimStatus {
            novelty: "not-established",
            first: "not-established",
            proved: "not-established",
        },
        exclusions: BASE_NARROW_EXCLUSIONS
            .iter()
            .copied()
            .chain([METADATA_ONLY_EXCLUSION])
            .collect(),
        decision_reason: "all central safety, case-local fault, scale, and measurement-protocol gates pass, but shared production fault scope, cross-object crash/panic atomicity, and two full-text comparisons remain not established, so support-bounded is not authorized",
    }
}

fn load_structured_evidence(directory: &Path) -> Result<DecisionEvidence, String> {
    let concurrency: ConcurrencyReceipt = read_json(&directory.join("concurrency.json"))?;
    let faults: Vec<FaultReceipt> = read_json_lines(&directory.join("fault-matrix.jsonl"))?;
    let scales: Vec<ScaleReceipt> = read_json_lines(&directory.join("scale.jsonl"))?;
    let performance: PerformanceReceipt = read_json(&directory.join("performance.json"))?;
    let prior: PriorArtReceipt = read_json(&directory.join("prior-art.json"))?;

    let (race_coverage, source_safety) = concurrency_gate_statuses(&concurrency);

    let (fault_coverage, central_fault_cells) = fault_gate_statuses(&faults);
    let central_faults_pass =
        central_fault_cells.len() == 20 && central_fault_cells.iter().all(|passed| *passed);

    let scale_structure = scale_gate_passes(&scales);

    let performance_protocol = validate_performance_receipt(&performance);
    let prior_art = prior_art_gate_passes(&prior);

    Ok(DecisionEvidence {
        gates: vec![
            gate(REQUIRED_GATES[0], race_coverage),
            gate(REQUIRED_GATES[1], source_safety),
            gate(REQUIRED_GATES[2], fault_coverage),
            gate(REQUIRED_GATES[3], central_faults_pass),
            gate(REQUIRED_GATES[4], scale_structure),
            gate(REQUIRED_GATES[5], performance_protocol),
            gate(REQUIRED_GATES[6], prior_art),
        ],
        central_fault_cells,
        support_bounded_allowed: prior.summary.support_bounded_allowed,
        metadata_only_exclusions: prior.metadata_only_exclusions,
        reject_conditions: Vec::new(),
    })
}

fn prior_art_gate_passes(prior: &PriorArtReceipt) -> bool {
    prior.schema == "nexus.stage7b.prior-art.receipt.v1"
        && prior.status == "passed"
        && prior.matrix == "evaluation/stage7b/prior-art.toml"
        && prior.source_policy == "primary-source-required"
        && prior.summary.rows == 16
        && prior.summary.source_cards == 16
        && prior.summary.full_text == 14
        && prior.summary.metadata_only == 2
        && prior.summary.default_verdict == "narrow"
        && prior.metadata_only_exclusions == ["shadow-drivers.device-recovery", "atomic-rpc"]
        && prior
            .sources
            .iter()
            .map(|source| source.id.as_str())
            .collect::<Vec<_>>()
            == PRIOR_ART_IDS
        && prior
            .sources
            .iter()
            .zip(PRIOR_ART_ACCESS_KINDS)
            .enumerate()
            .all(|(index, (source, expected_kind))| {
                source.access_kind == *expected_kind
                    && source.content_status
                        == if [5, 11].contains(&index) {
                            "metadata-only-unavailable"
                        } else {
                            "full-text-audited"
                        }
                    && source.bibliographic_url == PRIOR_ART_URLS[index]
                    && source.source_content_sha256 == PRIOR_ART_SOURCE_DIGESTS[index]
                    && source.audit_notes_sha256 == PRIOR_ART_AUDIT_DIGESTS[index]
            })
}

fn concurrency_gate_statuses(concurrency: &ConcurrencyReceipt) -> (bool, bool) {
    let race_ids: Vec<_> = concurrency
        .races
        .iter()
        .map(|race| race.id.as_str())
        .collect();
    let assertion_total: usize = concurrency
        .races
        .iter()
        .map(|race| race.assertion_markers.len())
        .sum();
    let expected_assertion_total: usize = CONCURRENCY_ASSERTIONS
        .iter()
        .map(|assertions| assertions.len())
        .sum();
    let race_coverage = race_ids == CONCURRENCY_IDS
        && assertion_total == expected_assertion_total
        && concurrency
            .races
            .iter()
            .zip(CONCURRENCY_CASES)
            .zip(CONCURRENCY_ASSERTIONS)
            .all(|((race, expected_case), expected_assertions)| {
                race.status == "Checked"
                    && race.harness_case == *expected_case
                    && race
                        .assertion_markers
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        == *expected_assertions
            });
    let source_safety = concurrency.schema == "nexus.stage7b.concurrency.v1"
        && concurrency.status == "passed"
        && concurrency.boundary == "implementation-source-safety"
        && concurrency.synchronization_model
            == "production transition source under a Loom-modeled outer mutex"
        && concurrency.forbidden_claims
            == [
                "OSTD SpinLock verified",
                "SMP verified",
                "lock-free",
                "production liveness proved",
            ];
    (race_coverage, source_safety)
}

fn fault_gate_statuses(faults: &[FaultReceipt]) -> (bool, Vec<bool>) {
    let coverage = faults.len() == FAULT_IDS.len()
        && faults.iter().enumerate().all(|(index, fault)| {
            fault.id == FAULT_IDS[index]
                && fault.family == FAULT_IDS[index].split_once('.').unwrap().0
                && fault.injection_point == FAULT_INJECTIONS[index]
                && fault.status == "Checked"
        });
    let central = faults
        .iter()
        .enumerate()
        .map(|(index, fault)| {
            index < FAULT_IDS.len()
                && fault.expected_terminal == FAULT_TERMINALS[index]
                && fault.observed_terminal == FAULT_TERMINALS[index]
                && fault.terminalizations == if index == 5 { 2 } else { 1 }
                && fault.publications == FAULT_PUBLICATIONS[index]
                && fault.credits_before == FAULT_CREDITS[index]
                && fault.credits_after == FAULT_CREDITS[index]
                && fault.retained_before_quiescence == FAULT_RETAINED[index]
                && fault.final_quiescent
                && fault.status == "Checked"
        })
        .collect();
    (coverage, central)
}

fn scale_gate_passes(scales: &[ScaleReceipt]) -> bool {
    scales.len() == SCALE_IDS.len()
        && scales.iter().zip(SCALE_IDS).zip(SCALE_TUPLES).all(
            |((scale, expected_id), expected_tuple)| {
                scale.id == *expected_id
                    && (scale.n, scale.k, scale.history) == *expected_tuple
                    && scale.target_count == scale.k
                    && scale.begin_target_record_visits == 0
                    && scale.k.checked_add(1) == Some(scale.next_calls)
                    && scale.head_selections == scale.k
                    && scale.terminalized == scale.k
                    && scale.completion_members_checked == scale.k
                    && scale.target_index_removals == scale.k
                    && scale.unrelated_effect_visits == 0
                    && scale.history_effect_visits == 0
                    && scale.pending_targets == 0
                    && scale.final_target_state == "Revoked"
                    && scale.status == "Checked"
            },
        )
}

fn validate_performance_receipt(receipt: &PerformanceReceipt) -> bool {
    receipt.schema == "nexus.stage7b.performance.v1"
        && receipt.status == "Observed"
        && receipt.claim
            == "single-vCPU single-thread TCG release hot-cache guest-visible TSC observations"
        && receipt.thresholds.is_none()
        && receipt.environment.profile == "release"
        && receipt.environment.accel == "tcg"
        && receipt.environment.vcpus == 1
        && receipt.environment.threads == 1
        && receipt.environment.cache == "hot"
        && receipt.environment.timer == "guest_visible_tsc"
        && receipt.environment.fence == "lfence"
        && receipt.environment.preemption == "disabled"
        && receipt.environment.local_irq == "disabled"
        && receipt.environment.warmups == 7
        && receipt.environment.samples == 65
        && receipt.environment.empty_samples == 257
        && !receipt.environment.adjusted
        && receipt.environment.raw_retained
        && receipt.runtime_metadata.schema == "nexus.stage7b.runtime-metadata.v1"
        && receipt.runtime_metadata.accel == "tcg"
        && receipt.runtime_metadata.vcpus == 1
        && receipt.runtime_metadata.threads == 1
        && !receipt.runtime_metadata.cpus_allowed_list.is_empty()
        && cpu_list_contains(
            &receipt.runtime_metadata.cpus_allowed_list,
            receipt.runtime_metadata.cpu_pin,
        )
        && valid_samples(&receipt.empty_timer, 257)
        && receipt
            .cases
            .iter()
            .map(|case| case.id.as_str())
            .collect::<Vec<_>>()
            == PERFORMANCE_IDS
        && receipt.cases.iter().enumerate().all(|(index, case)| {
            let expected_id = PERFORMANCE_IDS[index];
            let Some((expected_operation, scale_id)) = expected_id.split_once('.') else {
                return false;
            };
            let Some(scale_index) = SCALE_IDS
                .iter()
                .position(|candidate| *candidate == scale_id)
            else {
                return false;
            };
            case.operation == expected_operation
                && (case.n, case.k, case.history) == SCALE_TUPLES[scale_index]
                && case.status == "Observed"
                && valid_case_samples(case, 65)
        })
}

fn cpu_list_contains(list: &str, cpu: u64) -> bool {
    list.split(',').any(|range| {
        if let Some((start, end)) = range.split_once('-') {
            start
                .parse::<u64>()
                .ok()
                .zip(end.parse::<u64>().ok())
                .is_some_and(|(start, end)| start <= cpu && cpu <= end)
        } else {
            range.parse::<u64>().ok() == Some(cpu)
        }
    })
}

fn valid_samples(samples: &SampleReceipt, expected: usize) -> bool {
    if samples.status != "Observed"
        || samples.samples != expected
        || samples.raw.len() != expected
        || samples.raw.is_empty()
    {
        return false;
    }
    let mut sorted = samples.raw.clone();
    sorted.sort_unstable();
    samples.min == sorted[0]
        && samples.median == sorted[sorted.len() / 2]
        && samples.p95 == sorted[(sorted.len() * 95).div_ceil(100) - 1]
        && samples.max == *sorted.last().unwrap()
}

fn valid_case_samples(case: &PerformanceCase, expected: usize) -> bool {
    valid_samples(
        &SampleReceipt {
            samples: case.samples,
            min: case.min,
            median: case.median,
            p95: case.p95,
            max: case.max,
            raw: case.raw.clone(),
            status: case.status.clone(),
        },
        expected,
    )
}

fn gate(id: &'static str, passed: bool) -> GateEvidence {
    GateEvidence {
        id,
        status: if passed {
            GateStatus::Passed
        } else {
            GateStatus::Failed
        },
    }
}

fn validate_decision(decision: &Decision, evidence: &DecisionEvidence) -> Result<(), String> {
    if decision.schema != "nexus.stage7b.contribution-decision.v1" || decision.status != "passed" {
        return Err("contribution decision schema/status mismatch".into());
    }
    if !["support-bounded", "narrow", "reject"].contains(&decision.verdict) {
        return Err(format!(
            "unknown contribution verdict {:?}",
            decision.verdict
        ));
    }
    if evidence.gates.len() != REQUIRED_GATES.len()
        || evidence
            .gates
            .iter()
            .zip(REQUIRED_GATES)
            .any(|(gate, required)| gate.id != *required)
    {
        return Err("contribution evidence is missing or reorders a required gate".into());
    }
    if evidence.central_fault_cells.len() != 20 {
        return Err("contribution evidence must describe all 20 central fault cells".into());
    }

    validate_gate_descriptions(decision, evidence)?;
    if decision.claim_status
        != (ClaimStatus {
            novelty: "not-established",
            first: "not-established",
            proved: "not-established",
        })
    {
        return Err("novelty/first/proved must remain not-established".into());
    }
    reject_forbidden_claim_words(decision)?;

    let all_gates_pass = evidence
        .gates
        .iter()
        .all(|gate| gate.status == GateStatus::Passed);
    let all_central_cells_pass = evidence.central_fault_cells.iter().all(|passed| *passed);
    match decision.verdict {
        "support-bounded" => {
            if !all_gates_pass {
                return Err("support-bounded has a missing or failed required gate".into());
            }
            if !all_central_cells_pass {
                return Err("support-bounded has a failed central safety cell".into());
            }
            if !evidence.support_bounded_allowed {
                return Err("prior-art receipt does not authorize support-bounded".into());
            }
        }
        "narrow" => {
            let required_exclusions = required_narrow_exclusions(evidence);
            let declared: BTreeSet<_> = decision.exclusions.iter().copied().collect();
            let hidden: Vec<_> = required_exclusions
                .iter()
                .filter(|exclusion| !declared.contains(exclusion.as_str()))
                .collect();
            if !hidden.is_empty() {
                return Err(format!(
                    "narrow decision hides required exclusions: {hidden:?}"
                ));
            }
        }
        "reject" => {
            if evidence.reject_conditions.is_empty() && all_gates_pass && all_central_cells_pass {
                return Err(
                    "reject verdict lacks a rejecting counterexample or failed gate".into(),
                );
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_gate_descriptions(
    decision: &Decision,
    evidence: &DecisionEvidence,
) -> Result<(), String> {
    let descriptions = [
        decision.gates.implementation_source_concurrency,
        decision.gates.implementation_source_concurrency,
        decision.gates.fault_matrix,
        decision.gates.fault_matrix,
        decision.gates.scale_structure,
        decision.gates.performance_protocol,
        decision.gates.prior_art,
    ];
    let exact_pass = [
        "Checked 14/14",
        "Checked 14/14",
        "Checked 20/20: 15 case-local Registry-backed nonzero-credit cells and 5 typed N/A scheduler witnesses",
        "Checked 20/20: 15 case-local Registry-backed nonzero-credit cells and 5 typed N/A scheduler witnesses",
        "Checked 14/14",
        "Observed 29/29; no thresholds",
        "Checked 16/16 rows; 14 full-text and 2 primary-metadata-only",
    ];
    for ((gate, description), expected) in evidence.gates.iter().zip(descriptions).zip(exact_pass) {
        match gate.status {
            GateStatus::Passed if description != expected => {
                return Err(format!(
                    "passed gate {:?} has a drifted decision description",
                    gate.id
                ));
            }
            GateStatus::Failed
                if description.contains("Checked") || description.contains("Observed") =>
            {
                return Err(format!(
                    "missing/failed gate {:?} is described as supported",
                    gate.id
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn required_narrow_exclusions(evidence: &DecisionEvidence) -> BTreeSet<String> {
    let mut exclusions: BTreeSet<_> = BASE_NARROW_EXCLUSIONS
        .iter()
        .map(|exclusion| String::from(*exclusion))
        .collect();
    if !evidence.support_bounded_allowed || !evidence.metadata_only_exclusions.is_empty() {
        exclusions.insert(String::from(METADATA_ONLY_EXCLUSION));
    }
    for gate in &evidence.gates {
        if gate.status != GateStatus::Passed {
            exclusions.insert(format!("missing or failed gate: {}", gate.id));
        }
    }
    if evidence.central_fault_cells.iter().any(|passed| !passed) {
        exclusions.insert(String::from("failed central fault safety cells"));
    }
    exclusions
}

fn reject_forbidden_claim_words(decision: &Decision) -> Result<(), String> {
    let texts = [
        decision.supported_boundary,
        decision.gates.implementation_source_concurrency,
        decision.gates.fault_matrix,
        decision.gates.scale_structure,
        decision.gates.performance_protocol,
        decision.gates.prior_art,
        decision.decision_reason,
    ]
    .into_iter()
    .chain(decision.exclusions.iter().copied());
    for text in texts {
        for word in text.split(|character: char| !character.is_ascii_alphanumeric()) {
            if ["novel", "first", "proved"].contains(&word.to_ascii_lowercase().as_str()) {
                return Err(format!(
                    "contribution decision contains forbidden claim word {word:?}"
                ));
            }
        }
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let source = read_regular(path)?;
    serde_json::from_str(&source).map_err(|error| {
        format!(
            "parse structured contribution input {}: {error}",
            path.display()
        )
    })
}

fn read_json_lines<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<T>, String> {
    let source = read_regular(path)?;
    source
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|error| {
                format!(
                    "parse structured contribution input {} line {}: {error}",
                    path.display(),
                    index + 1
                )
            })
        })
        .collect()
}

fn read_regular(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read metadata {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "required contribution input is not a non-empty regular non-symlink file: {}",
            path.display()
        ));
    }
    fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("non-UTF-8 output path: {}", path.display()))?,
        std::process::id()
    ));
    fs::write(&temporary, bytes)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| format!("publish {}: {error}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn concurrency_receipt() -> ConcurrencyReceipt {
        ConcurrencyReceipt {
            schema: String::from("nexus.stage7b.concurrency.v1"),
            status: String::from("passed"),
            boundary: String::from("implementation-source-safety"),
            synchronization_model: String::from(
                "production transition source under a Loom-modeled outer mutex",
            ),
            forbidden_claims: [
                "OSTD SpinLock verified",
                "SMP verified",
                "lock-free",
                "production liveness proved",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            races: CONCURRENCY_IDS
                .iter()
                .zip(CONCURRENCY_CASES)
                .zip(CONCURRENCY_ASSERTIONS)
                .map(|((id, harness_case), assertions)| ConcurrencyRace {
                    id: String::from(*id),
                    harness_case: String::from(*harness_case),
                    status: String::from("Checked"),
                    assertion_markers: assertions
                        .iter()
                        .map(|assertion| String::from(*assertion))
                        .collect(),
                })
                .collect(),
        }
    }

    fn prior_art_receipt() -> PriorArtReceipt {
        PriorArtReceipt {
            schema: String::from("nexus.stage7b.prior-art.receipt.v1"),
            status: String::from("passed"),
            matrix: String::from("evaluation/stage7b/prior-art.toml"),
            source_policy: String::from("primary-source-required"),
            summary: PriorArtSummary {
                rows: 16,
                source_cards: 16,
                full_text: 14,
                metadata_only: 2,
                default_verdict: String::from("narrow"),
                support_bounded_allowed: false,
            },
            metadata_only_exclusions: vec![
                String::from("shadow-drivers.device-recovery"),
                String::from("atomic-rpc"),
            ],
            sources: PRIOR_ART_IDS
                .iter()
                .zip(PRIOR_ART_ACCESS_KINDS)
                .enumerate()
                .map(|(index, (id, access_kind))| PriorArtSource {
                    id: String::from(*id),
                    access_kind: String::from(*access_kind),
                    content_status: String::from(if [5, 11].contains(&index) {
                        "metadata-only-unavailable"
                    } else {
                        "full-text-audited"
                    }),
                    bibliographic_url: String::from(PRIOR_ART_URLS[index]),
                    source_content_sha256: String::from(PRIOR_ART_SOURCE_DIGESTS[index]),
                    audit_notes_sha256: String::from(PRIOR_ART_AUDIT_DIGESTS[index]),
                })
                .collect(),
        }
    }

    fn fault_receipts() -> Vec<FaultReceipt> {
        FAULT_IDS
            .iter()
            .enumerate()
            .map(|(index, id)| FaultReceipt {
                id: String::from(*id),
                family: String::from(id.split_once('.').unwrap().0),
                injection_point: String::from(FAULT_INJECTIONS[index]),
                expected_terminal: String::from(FAULT_TERMINALS[index]),
                observed_terminal: String::from(FAULT_TERMINALS[index]),
                terminalizations: if index == 5 { 2 } else { 1 },
                publications: FAULT_PUBLICATIONS[index],
                credits_before: FAULT_CREDITS[index],
                credits_after: FAULT_CREDITS[index],
                retained_before_quiescence: FAULT_RETAINED[index],
                final_quiescent: true,
                status: String::from("Checked"),
            })
            .collect()
    }

    fn scale_receipts() -> Vec<ScaleReceipt> {
        SCALE_IDS
            .iter()
            .zip(SCALE_TUPLES)
            .map(|(id, (n, k, history))| ScaleReceipt {
                id: String::from(*id),
                n: *n,
                k: *k,
                history: *history,
                target_count: *k,
                begin_target_record_visits: 0,
                next_calls: *k + 1,
                head_selections: *k,
                terminalized: *k,
                completion_members_checked: *k,
                target_index_removals: *k,
                unrelated_effect_visits: 0,
                history_effect_visits: 0,
                pending_targets: 0,
                final_target_state: String::from("Revoked"),
                status: String::from("Checked"),
            })
            .collect()
    }

    fn observed_samples(count: usize) -> SampleReceipt {
        SampleReceipt {
            samples: count,
            min: 1,
            median: 1,
            p95: 1,
            max: 1,
            raw: vec![1; count],
            status: String::from("Observed"),
        }
    }

    fn performance_receipt() -> PerformanceReceipt {
        PerformanceReceipt {
            schema: String::from("nexus.stage7b.performance.v1"),
            status: String::from("Observed"),
            claim: String::from(
                "single-vCPU single-thread TCG release hot-cache guest-visible TSC observations",
            ),
            thresholds: None,
            environment: PerformanceEnvironment {
                profile: String::from("release"),
                accel: String::from("tcg"),
                vcpus: 1,
                threads: 1,
                cache: String::from("hot"),
                timer: String::from("guest_visible_tsc"),
                fence: String::from("lfence"),
                preemption: String::from("disabled"),
                local_irq: String::from("disabled"),
                warmups: 7,
                samples: 65,
                empty_samples: 257,
                adjusted: false,
                raw_retained: true,
            },
            runtime_metadata: RuntimeMetadata {
                schema: String::from("nexus.stage7b.runtime-metadata.v1"),
                accel: String::from("tcg"),
                vcpus: 1,
                threads: 1,
                cpu_pin: 0,
                cpus_allowed_list: String::from("0"),
            },
            empty_timer: observed_samples(257),
            cases: PERFORMANCE_IDS
                .iter()
                .map(|id| {
                    let (operation, scale_id) = id.split_once('.').unwrap();
                    let scale_index = SCALE_IDS
                        .iter()
                        .position(|candidate| *candidate == scale_id)
                        .unwrap();
                    let (n, k, history) = SCALE_TUPLES[scale_index];
                    let samples = observed_samples(65);
                    PerformanceCase {
                        id: String::from(*id),
                        operation: String::from(operation),
                        n,
                        k,
                        history,
                        samples: samples.samples,
                        min: samples.min,
                        median: samples.median,
                        p95: samples.p95,
                        max: samples.max,
                        raw: samples.raw,
                        status: samples.status,
                    }
                })
                .collect(),
        }
    }

    fn passing_evidence() -> DecisionEvidence {
        DecisionEvidence {
            gates: REQUIRED_GATES
                .iter()
                .map(|id| GateEvidence {
                    id,
                    status: GateStatus::Passed,
                })
                .collect(),
            central_fault_cells: vec![true; 20],
            support_bounded_allowed: false,
            metadata_only_exclusions: vec![
                String::from("shadow-drivers.device-recovery"),
                String::from("atomic-rpc"),
            ],
            reject_conditions: Vec::new(),
        }
    }

    #[test]
    fn accepts_checked_narrow_decision() {
        validate_decision(&narrow_decision(), &passing_evidence()).unwrap();
    }

    #[test]
    fn structured_concurrency_gate_rejects_assertion_marker_mutations() {
        let receipt = concurrency_receipt();
        assert_eq!(concurrency_gate_statuses(&receipt), (true, true));

        let mut missing = concurrency_receipt();
        missing.races[0].assertion_markers.pop();
        assert!(!concurrency_gate_statuses(&missing).0);
        let mut decision_evidence = passing_evidence();
        decision_evidence.gates[0].status = GateStatus::Failed;
        assert!(validate_decision(&narrow_decision(), &decision_evidence).is_err());

        let mut duplicate = concurrency_receipt();
        let marker = duplicate.races[0].assertion_markers[0].clone();
        duplicate.races[0].assertion_markers.push(marker);
        assert!(!concurrency_gate_statuses(&duplicate).0);

        let mut unknown = concurrency_receipt();
        unknown.races[0].assertion_markers[0] = String::from("unknown-assertion");
        assert!(!concurrency_gate_statuses(&unknown).0);

        let mut reordered = concurrency_receipt();
        reordered.races[0].assertion_markers.swap(0, 1);
        assert!(!concurrency_gate_statuses(&reordered).0);
    }

    #[test]
    fn structured_prior_art_gate_accepts_exact_primary_source_kinds() {
        let receipt = prior_art_receipt();
        assert!(prior_art_gate_passes(&receipt));
        assert_eq!(receipt.sources[13].access_kind, "primary-web-document");
        assert_eq!(receipt.sources[14].access_kind, "primary-api-manual");
        assert_eq!(receipt.sources[15].access_kind, "primary-specification");

        let mut drifted = prior_art_receipt();
        drifted.sources[13].access_kind = String::from("primary-full-text");
        assert!(!prior_art_gate_passes(&drifted));

        let mut url = prior_art_receipt();
        url.sources[0].bibliographic_url.push_str("?drift");
        assert!(!prior_art_gate_passes(&url));

        let mut source_digest = prior_art_receipt();
        source_digest.sources[0]
            .source_content_sha256
            .replace_range(0..1, "f");
        assert!(!prior_art_gate_passes(&source_digest));

        let mut metadata_digest = prior_art_receipt();
        metadata_digest.sources[5].source_content_sha256 = "a".repeat(64);
        assert!(!prior_art_gate_passes(&metadata_digest));

        let mut audit_digest = prior_art_receipt();
        audit_digest.sources[0]
            .audit_notes_sha256
            .replace_range(0..1, "f");
        assert!(!prior_art_gate_passes(&audit_digest));
    }

    #[test]
    fn exact_prior_art_tuples_match_frozen_source_cards() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        for index in 0..PRIOR_ART_IDS.len() {
            let path = root.join(format!(
                "evaluation/stage7b/prior-art-sources/{}.toml",
                PRIOR_ART_IDS[index]
            ));
            let source = fs::read_to_string(&path).unwrap();
            let card: toml::Value = toml::from_str(&source).unwrap();
            assert_eq!(
                card.get("bibliographic_url").and_then(toml::Value::as_str),
                Some(PRIOR_ART_URLS[index]),
                "{} URL drift",
                PRIOR_ART_IDS[index]
            );
            assert_eq!(
                card.get("source_content_sha256")
                    .and_then(toml::Value::as_str),
                Some(PRIOR_ART_SOURCE_DIGESTS[index]),
                "{} source digest drift",
                PRIOR_ART_IDS[index]
            );
            assert_eq!(
                card.get("audit_notes_sha256").and_then(toml::Value::as_str),
                Some(PRIOR_ART_AUDIT_DIGESTS[index]),
                "{} audit digest drift",
                PRIOR_ART_IDS[index]
            );
        }
    }

    #[test]
    fn structured_fault_gate_binds_publications_credits_and_retention() {
        let faults = fault_receipts();
        let (coverage, central) = fault_gate_statuses(&faults);
        assert!(coverage);
        assert!(central.into_iter().all(|passed| passed));

        let mut publication = fault_receipts();
        publication[0].publications = 0;
        assert!(!fault_gate_statuses(&publication).1[0]);

        let mut credit = fault_receipts();
        credit[5].credits_after = 1;
        assert!(!fault_gate_statuses(&credit).1[5]);

        let mut retained = fault_receipts();
        retained[16].retained_before_quiescence = false;
        assert!(!fault_gate_statuses(&retained).1[16]);
    }

    #[test]
    fn structured_scale_gate_rejects_exact_tuple_drift() {
        let scales = scale_receipts();
        assert!(scale_gate_passes(&scales));

        let mut n_drift = scale_receipts();
        n_drift[0].n = 1023;
        assert!(!scale_gate_passes(&n_drift));

        let mut history_drift = scale_receipts();
        history_drift[12].history = 63;
        assert!(!scale_gate_passes(&history_drift));
    }

    #[test]
    fn structured_performance_gate_rejects_operation_and_tuple_drift() {
        let performance = performance_receipt();
        assert!(validate_performance_receipt(&performance));

        let mut operation = performance_receipt();
        operation.cases[0].operation = String::from("closure");
        assert!(!validate_performance_receipt(&operation));

        let mut tuple = performance_receipt();
        tuple.cases[0].n = 1023;
        assert!(!validate_performance_receipt(&tuple));
    }

    #[test]
    fn structured_receipts_reject_unknown_fields() {
        let mut value = serde_json::to_value(&scale_receipts()[0]).unwrap();
        value["surprise"] = Value::Bool(true);
        assert!(serde_json::from_value::<ScaleReceipt>(value).is_err());
    }

    #[test]
    fn rejects_unknown_verdict_mutation() {
        let mut decision = narrow_decision();
        decision.verdict = "unknown";
        assert!(validate_decision(&decision, &passing_evidence()).is_err());
    }

    #[test]
    fn rejects_support_bounded_with_missing_required_gate_mutation() {
        let mut decision = narrow_decision();
        decision.verdict = "support-bounded";
        let mut evidence = passing_evidence();
        evidence.support_bounded_allowed = true;
        evidence.gates.remove(0);
        assert!(validate_decision(&decision, &evidence).is_err());
    }

    #[test]
    fn rejects_support_bounded_with_failed_central_cell_mutation() {
        let mut decision = narrow_decision();
        decision.verdict = "support-bounded";
        let mut evidence = passing_evidence();
        evidence.support_bounded_allowed = true;
        evidence.central_fault_cells[0] = false;
        assert!(validate_decision(&decision, &evidence).is_err());
    }

    #[test]
    fn rejects_narrow_with_hidden_exclusion_mutation() {
        let mut decision = narrow_decision();
        decision.exclusions.pop();
        assert!(validate_decision(&decision, &passing_evidence()).is_err());
    }

    #[test]
    fn rejects_narrow_with_hidden_fault_budget_boundary_mutations() {
        for hidden in [
            "shared production fault-budget scope across all fault cells",
            "cross-object crash/panic atomicity between transition gates and case-local Registry ledgers",
        ] {
            let mut decision = narrow_decision();
            decision.exclusions.retain(|exclusion| *exclusion != hidden);
            assert!(validate_decision(&decision, &passing_evidence()).is_err());
        }
    }

    #[test]
    fn rejects_forbidden_novelty_word_mutation() {
        let mut decision = narrow_decision();
        decision.decision_reason = "novel fixed interaction combination";
        assert!(validate_decision(&decision, &passing_evidence()).is_err());
    }
}
