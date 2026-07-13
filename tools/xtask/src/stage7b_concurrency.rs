use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

const OUTPUT_DIRECTORY: &str = "target/verification/stage7b";
const RAW_OUTPUT: &str = "concurrency.log";
const JSON_OUTPUT: &str = "concurrency.json";
const ORACLE_OUTPUT: &str = "concurrency-oracle.log";

const CASES: &[(&str, &str)] = &[
    (
        "wait.wake-vs-timeout-single-winner",
        "wake_vs_timeout_single_winner",
    ),
    (
        "wait.cancel-vs-wake-single-winner",
        "cancel_vs_wake_single_winner",
    ),
    (
        "wait.stale-deadline-after-rearm",
        "stale_deadline_after_rearm",
    ),
    (
        "pager.same-page-single-publication",
        "same_page_single_publication",
    ),
    (
        "pager.handler-crash-before-resolution",
        "handler_crash_before_resolution",
    ),
    (
        "pager.old-binding-reply-after-rebind",
        "old_binding_reply_after_rebind",
    ),
    (
        "pager.adopt-vs-abort-single-winner",
        "adopt_vs_abort_single_winner",
    ),
    (
        "continuation.resolve-vs-abort-one-shot",
        "resolve_vs_abort_one_shot",
    ),
    (
        "scope.commit-vs-revoke-linearization",
        "commit_vs_revoke_linearization",
    ),
    (
        "scope.revoke-deferred-wait-timer",
        "revoke_deferred_wait_timer",
    ),
    (
        "budget.commit-vs-abort-conservation",
        "budget_commit_vs_abort_conservation",
    ),
    ("scheduler.fallback-before-rebind", "fallback_before_rebind"),
    (
        "io.publish-vs-revoke-commit-gate",
        "publish_vs_revoke_commit_gate",
    ),
    (
        "io.timeout-vs-late-completion-tombstone",
        "timeout_vs_late_completion_tombstone",
    ),
];

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
}

pub(crate) fn run(root: &Path) -> Result<Summary, String> {
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
            .map(|(id, harness_case)| RaceReceipt {
                id,
                harness_case,
                status: "Checked",
            })
            .collect(),
    };
    let mut json = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| format!("serialize Stage 7B concurrency receipt: {error}"))?;
    json.push(b'\n');
    atomic_write(&directory.join(JSON_OUTPUT), &json)?;
    let oracle = b"schema=nexus.stage7b.concurrency-oracle.v1\nstatus=passed\nraces=14\nsource_kind=production-transition-source\nsynchronization_model=production transition source under a Loom-modeled outer mutex\nforbidden_claims_enforced=true\n";
    atomic_write(&directory.join(ORACLE_OUTPUT), oracle)?;
    Ok(Summary { races: CASES.len() })
}

fn parse_markers(stdout: &str) -> Result<(), String> {
    let prefix = "STAGE7B_CONCURRENCY case=";
    let suffix = " status=PASS";
    let mut found = BTreeSet::new();
    let expected: BTreeSet<_> = CASES.iter().map(|(_, case)| *case).collect();
    for line in stdout.lines().map(str::trim) {
        let Some(marker) = line.find(prefix).map(|offset| &line[offset..]) else {
            continue;
        };
        let Some(case) = marker
            .strip_prefix(prefix)
            .and_then(|line| line.strip_suffix(suffix))
        else {
            return Err(format!(
                "malformed Stage 7B concurrency marker line {line:?}"
            ));
        };
        if !expected.contains(case) {
            return Err(format!("unknown Stage 7B concurrency case {case:?}"));
        }
        if !found.insert(case) {
            return Err(format!("duplicate Stage 7B concurrency case {case:?}"));
        }
    }
    if found != expected {
        let missing: Vec<_> = expected.difference(&found).copied().collect();
        return Err(format!("missing Stage 7B concurrency cases: {missing:?}"));
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
        CASES
            .iter()
            .map(|(_, case)| format!("STAGE7B_CONCURRENCY case={case} status=PASS\n"))
            .collect()
    }

    #[test]
    fn accepts_exact_case_set() {
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
        let first = format!("STAGE7B_CONCURRENCY case={} status=PASS\n", CASES[0].1);
        assert!(parse_markers(&source.replacen(&first, "", 1)).is_err());
        assert!(parse_markers(&(source.clone() + &first)).is_err());
        assert!(
            parse_markers(&(source + "STAGE7B_CONCURRENCY case=unknown_case status=PASS\n"))
                .is_err()
        );
    }
}
