use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

const OUTPUT_DIRECTORY: &str = "target/verification/stage7b";
const RAW_OUTPUT: &str = "concurrency.log";
const JSON_OUTPUT: &str = "concurrency.json";
const ORACLE_OUTPUT: &str = "concurrency-oracle.log";
const RACE_MAP_PATH: &str = "evaluation/stage7b/cser-races.toml";

#[derive(Clone, Copy)]
struct ExpectedCase {
    id: &'static str,
    harness_case: &'static str,
    assertion_markers: &'static [&'static str],
}

const CASES: &[ExpectedCase] = &[
    ExpectedCase {
        id: "wait.wake-vs-timeout-single-winner",
        harness_case: "wake_vs_timeout_single_winner",
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
    ExpectedCase {
        id: "wait.cancel-vs-wake-single-winner",
        harness_case: "cancel_vs_wake_single_winner",
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
    ExpectedCase {
        id: "wait.stale-deadline-after-rearm",
        harness_case: "stale_deadline_after_rearm",
        assertion_markers: &[
            "old-token-rejected",
            "rejection-failure-atomic",
            "replacement-generation-advanced",
            "replacement-remains-live",
        ],
    },
    ExpectedCase {
        id: "pager.same-page-single-publication",
        harness_case: "same_page_single_publication",
        assertion_markers: &[
            "resume-before-commit-rejected",
            "publication-closure-once",
            "losing-candidate-released-once",
            "continuations-terminal-once",
            "duplicate-resume-rejected",
            "scope-revoked",
        ],
    },
    ExpectedCase {
        id: "pager.handler-crash-before-resolution",
        harness_case: "handler_crash_before_resolution",
        assertion_markers: &[
            "crash-fences-old-binding",
            "committed-crash-kernel-terminal",
            "uncommitted-crash-aborts",
            "continuation-single-terminal",
            "no-implicit-adoption",
            "scope-revoked",
        ],
    },
    ExpectedCase {
        id: "pager.old-binding-reply-after-rebind",
        harness_case: "old_binding_reply_after_rebind",
        assertion_markers: &[
            "mapping-committed-before-crash",
            "old-reply-failure-atomic",
            "old-reply-no-resume",
            "old-reply-credit-failure-atomic",
            "kernel-terminal-once",
            "scope-revoked",
        ],
    },
    ExpectedCase {
        id: "pager.adopt-vs-abort-single-winner",
        harness_case: "adopt_vs_abort_single_winner",
        assertion_markers: &[
            "decision-single-winner",
            "adoption-explicit-only",
            "ownership-authority-consumed-once",
            "continuation-terminal-once",
            "late-action-failure-atomic",
            "scope-revoked",
        ],
    },
    ExpectedCase {
        id: "continuation.resolve-vs-abort-one-shot",
        harness_case: "resolve_vs_abort_one_shot",
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
    ExpectedCase {
        id: "scope.commit-vs-revoke-linearization",
        harness_case: "commit_vs_revoke_linearization",
        assertion_markers: &[
            "commit-revoke-single-order",
            "closed-epoch-commit-rejected",
            "committed-effect-drained",
            "uncommitted-effect-aborted",
            "reverse-index-empty",
            "scope-revoked",
        ],
    },
    ExpectedCase {
        id: "scope.revoke-deferred-wait-timer",
        harness_case: "revoke_deferred_wait_timer",
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
    ExpectedCase {
        id: "budget.commit-vs-abort-conservation",
        harness_case: "budget_commit_vs_abort_conservation",
        assertion_markers: &[
            "single-credit-disposition",
            "free-held-committed-conserved",
            "credit-returned-once",
            "duplicate-completion-rejected",
            "abort-after-commit-not-reported",
            "scope-revoked",
        ],
    },
    ExpectedCase {
        id: "scheduler.fallback-before-rebind",
        harness_case: "fallback_before_rebind",
        assertion_markers: &[
            "crash-advances-binding-once",
            "repeated-crash-unchanged",
            "pending-proposal-cleared",
            "fallback-pick-before-rebind",
            "rebind-keeps-binding-epoch",
            "stale-proposals-failure-atomic",
        ],
    },
    ExpectedCase {
        id: "io.publish-vs-revoke-commit-gate",
        harness_case: "publish_vs_revoke_commit_gate",
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
    ExpectedCase {
        id: "io.timeout-vs-late-completion-tombstone",
        harness_case: "timeout_vs_late_completion_tombstone",
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

#[derive(Clone, Debug, Deserialize)]
struct RaceMapLink {
    race: Vec<RaceMapCaseLink>,
}

#[derive(Clone, Debug, Deserialize)]
struct RaceMapCaseLink {
    id: String,
    harness_case: String,
    assertion_markers: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Summary {
    pub(crate) races: usize,
}

#[derive(Serialize)]
struct Receipt {
    schema: &'static str,
    status: &'static str,
    boundary: &'static str,
    synchronization_model: &'static str,
    forbidden_claims: [&'static str; 4],
    races: Vec<RaceReceipt>,
}

#[derive(Serialize)]
struct RaceReceipt {
    id: &'static str,
    harness_case: &'static str,
    status: &'static str,
    assertion_markers: Vec<&'static str>,
}

pub(crate) fn run(root: &Path) -> Result<Summary, String> {
    let race_map_source = fs::read_to_string(root.join(RACE_MAP_PATH))
        .map_err(|error| format!("read {RACE_MAP_PATH}: {error}"))?;
    let race_map: RaceMapLink = toml::from_str(&race_map_source)
        .map_err(|error| format!("parse {RACE_MAP_PATH} for runtime marker linkage: {error}"))?;
    validate_race_map_link(&race_map)?;

    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "cser-transition-gates",
            "--test",
            "oneshot_loom",
            "--test",
            "deadline_loom",
            "--test",
            "pager_loom",
            "--test",
            "registry_loom",
            "--test",
            "scheduler_loom",
            "--test",
            "io_loom",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("run implementation-source Loom harnesses: {error}"))?;

    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("Loom stdout is not UTF-8: {error}"))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|error| format!("Loom stderr is not UTF-8: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "implementation-source Loom harness failed with {}\n{stdout}\n{stderr}",
            output.status
        ));
    }
    parse_markers(&stdout)?;

    let directory = root.join(OUTPUT_DIRECTORY);
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create {}: {error}", directory.display()))?;
    let mut raw = stdout;
    if !raw.ends_with('\n') {
        raw.push('\n');
    }
    raw.push_str("--- cargo stderr ---\n");
    raw.push_str(&stderr);
    if !raw.ends_with('\n') {
        raw.push('\n');
    }
    atomic_write(&directory.join(RAW_OUTPUT), raw.as_bytes())?;

    let receipt = Receipt {
        schema: "nexus.stage7b.concurrency.v1",
        status: "passed",
        boundary: "implementation-source-safety",
        synchronization_model: "production transition source under a Loom-modeled outer mutex",
        forbidden_claims: [
            "OSTD SpinLock verified",
            "SMP verified",
            "lock-free",
            "production liveness proved",
        ],
        races: CASES
            .iter()
            .map(|case| RaceReceipt {
                id: case.id,
                harness_case: case.harness_case,
                status: "Checked",
                assertion_markers: case.assertion_markers.to_vec(),
            })
            .collect(),
    };
    let mut json = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| format!("serialize Stage 7B concurrency receipt: {error}"))?;
    json.push(b'\n');
    atomic_write(&directory.join(JSON_OUTPUT), &json)?;
    let assertion_count: usize = CASES.iter().map(|case| case.assertion_markers.len()).sum();
    let oracle = format!(
        "schema=nexus.stage7b.concurrency-oracle.v1\nstatus=passed\nraces={}\nassertion_markers={}\nsource_kind=production-transition-source\nsynchronization_model=production transition source under a Loom-modeled outer mutex\nforbidden_claims_enforced=true\n",
        CASES.len(),
        assertion_count
    );
    atomic_write(&directory.join(ORACLE_OUTPUT), oracle.as_bytes())?;
    Ok(Summary { races: CASES.len() })
}

fn validate_race_map_link(map: &RaceMapLink) -> Result<(), String> {
    if map.race.len() != CASES.len() {
        return Err(format!(
            "Stage 7B concurrency map/runtime case count mismatch: expected {}, got {}",
            CASES.len(),
            map.race.len()
        ));
    }
    for (index, (mapped, expected)) in map.race.iter().zip(CASES).enumerate() {
        if mapped.id != expected.id {
            return Err(format!(
                "Stage 7B concurrency map/runtime race[{index}] id mismatch: expected {:?}, got {:?}",
                expected.id, mapped.id
            ));
        }
        if mapped.harness_case != expected.harness_case {
            return Err(format!(
                "Stage 7B concurrency map/runtime race[{index}] harness case mismatch: expected {:?}, got {:?}",
                expected.harness_case, mapped.harness_case
            ));
        }
        let mapped_markers: Vec<_> = mapped
            .assertion_markers
            .iter()
            .map(String::as_str)
            .collect();
        if mapped_markers != expected.assertion_markers {
            return Err(format!(
                "Stage 7B concurrency map/runtime race[{index}] assertion markers mismatch: expected {:?}, got {:?}",
                expected.assertion_markers, mapped_markers
            ));
        }
    }
    Ok(())
}

fn parse_markers(stdout: &str) -> Result<(), String> {
    const CASE_PREFIX: &str = "STAGE7B_CONCURRENCY case=";
    const ASSERTION_PREFIX: &str = "STAGE7B_CONCURRENCY_ASSERT case=";
    const PASS_SUFFIX: &str = " status=PASS";

    let expected: BTreeMap<_, _> = CASES
        .iter()
        .map(|case| {
            (
                case.harness_case,
                case.assertion_markers
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect();
    let mut found_cases = BTreeSet::new();
    let mut found_assertions = BTreeMap::<&str, BTreeSet<&str>>::new();

    for line in stdout.lines().map(str::trim) {
        if let Some(marker) = line.find(ASSERTION_PREFIX).map(|offset| &line[offset..]) {
            let body = marker
                .strip_prefix(ASSERTION_PREFIX)
                .and_then(|line| line.strip_suffix(PASS_SUFFIX))
                .ok_or_else(|| {
                    format!("malformed Stage 7B concurrency assertion marker line {line:?}")
                })?;
            let (case, assertion) = body.split_once(" assertion=").ok_or_else(|| {
                format!("malformed Stage 7B concurrency assertion marker line {line:?}")
            })?;
            let expected_assertions = expected
                .get(case)
                .ok_or_else(|| format!("unknown Stage 7B concurrency assertion case {case:?}"))?;
            if !expected_assertions.contains(assertion) {
                return Err(format!(
                    "unknown Stage 7B concurrency assertion {case:?}::{assertion:?}"
                ));
            }
            if !found_assertions.entry(case).or_default().insert(assertion) {
                return Err(format!(
                    "duplicate Stage 7B concurrency assertion {case:?}::{assertion:?}"
                ));
            }
            continue;
        }

        let Some(marker) = line.find(CASE_PREFIX).map(|offset| &line[offset..]) else {
            continue;
        };
        let case = marker
            .strip_prefix(CASE_PREFIX)
            .and_then(|line| line.strip_suffix(PASS_SUFFIX))
            .ok_or_else(|| format!("malformed Stage 7B concurrency marker line {line:?}"))?;
        if !expected.contains_key(case) {
            return Err(format!("unknown Stage 7B concurrency case {case:?}"));
        }
        if !found_cases.insert(case) {
            return Err(format!("duplicate Stage 7B concurrency case {case:?}"));
        }
    }

    let expected_cases: BTreeSet<_> = expected.keys().copied().collect();
    if found_cases != expected_cases {
        let missing: Vec<_> = expected_cases.difference(&found_cases).copied().collect();
        return Err(format!("missing Stage 7B concurrency cases: {missing:?}"));
    }
    for (case, expected_assertions) in expected {
        let found = found_assertions.remove(case).unwrap_or_default();
        if found != expected_assertions {
            let missing: Vec<_> = expected_assertions.difference(&found).copied().collect();
            return Err(format!(
                "missing Stage 7B concurrency assertions for {case:?}: {missing:?}"
            ));
        }
    }
    if !found_assertions.is_empty() {
        return Err(format!(
            "unexpected Stage 7B concurrency assertion cases: {:?}",
            found_assertions.keys().collect::<Vec<_>>()
        ));
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output path has no parent: {}", path.display()))?;
    let file = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("output path has no UTF-8 file name: {}", path.display()))?;
    let temporary = parent.join(format!(".{file}.{}.tmp", std::process::id()));
    fs::write(&temporary, bytes)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| format!("publish {}: {error}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript() -> String {
        let mut transcript = String::new();
        for case in CASES {
            transcript.push_str(&format!(
                "STAGE7B_CONCURRENCY case={} status=PASS\n",
                case.harness_case
            ));
            for assertion in case.assertion_markers {
                transcript.push_str(&format!(
                    "STAGE7B_CONCURRENCY_ASSERT case={} assertion={assertion} status=PASS\n",
                    case.harness_case
                ));
            }
        }
        transcript
    }

    fn race_map_link() -> RaceMapLink {
        toml::from_str(include_str!("../../../evaluation/stage7b/cser-races.toml"))
            .expect("checked-in concurrency race map parses")
    }

    #[test]
    fn checked_in_map_matches_runtime_cases_and_assertions_exactly() {
        validate_race_map_link(&race_map_link()).unwrap();
    }

    #[test]
    fn rejects_map_runtime_id_case_and_assertion_drift() {
        let mut id = race_map_link();
        id.race[0].id = String::from("unknown.race");
        assert!(validate_race_map_link(&id).is_err());

        let mut case = race_map_link();
        case.race[0].harness_case = String::from("unknown_case");
        assert!(validate_race_map_link(&case).is_err());

        let mut missing = race_map_link();
        missing.race[0].assertion_markers.pop();
        assert!(validate_race_map_link(&missing).is_err());

        let mut duplicate = race_map_link();
        let repeated = duplicate.race[0].assertion_markers[0].clone();
        duplicate.race[0].assertion_markers.push(repeated);
        assert!(validate_race_map_link(&duplicate).is_err());

        let mut unknown = race_map_link();
        unknown.race[0].assertion_markers[0] = String::from("unknown-assertion");
        assert!(validate_race_map_link(&unknown).is_err());

        let mut reordered = race_map_link();
        reordered.race[0].assertion_markers.swap(0, 1);
        assert!(validate_race_map_link(&reordered).is_err());
    }

    #[test]
    fn accepts_exact_case_and_assertion_sets() {
        parse_markers(&transcript()).unwrap();
        parse_markers(&transcript().replace(
            "STAGE7B_CONCURRENCY case=",
            "test harness_name ... STAGE7B_CONCURRENCY case=",
        ))
        .unwrap();
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_cases() {
        let source = transcript();
        let first = format!(
            "STAGE7B_CONCURRENCY case={} status=PASS\n",
            CASES[0].harness_case
        );
        assert!(parse_markers(&source.replacen(&first, "", 1)).is_err());
        assert!(parse_markers(&(source.clone() + &first)).is_err());
        assert!(
            parse_markers(&(source + "STAGE7B_CONCURRENCY case=unknown_case status=PASS\n"))
                .is_err()
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_assertions() {
        let source = transcript();
        let first = format!(
            "STAGE7B_CONCURRENCY_ASSERT case={} assertion={} status=PASS\n",
            CASES[0].harness_case, CASES[0].assertion_markers[0]
        );
        assert!(parse_markers(&source.replacen(&first, "", 1)).is_err());
        assert!(parse_markers(&(source.clone() + &first)).is_err());
        assert!(
            parse_markers(&format!(
                "{source}STAGE7B_CONCURRENCY_ASSERT case={} assertion=unknown-assertion status=PASS\n",
                CASES[0].harness_case
            ))
            .is_err()
        );
        assert!(
            parse_markers(&format!(
                "{source}STAGE7B_CONCURRENCY_ASSERT case=unknown_case assertion={} status=PASS\n",
                CASES[0].assertion_markers[0]
            ))
            .is_err()
        );
    }
}
