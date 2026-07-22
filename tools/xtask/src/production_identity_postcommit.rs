use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::Result;

const SCHEMA: &str = "nexus.research.production-identity-postcommit-crash.v1";
const COMMAND: &str = "./x research production-identity-postcommit-crash";
const OUTPUT_DIRECTORY: &str = "target/research/production-identity-postcommit-crash";
const RUST_LOG: &str = "target/research/production-identity-postcommit-crash/rust-oracle.log";
const SUMMARY_PATH: &str = "target/research/production-identity-postcommit-crash/summary.txt";
const RECEIPT_PATH: &str = "target/research/production-identity-postcommit-crash/receipt.json";

const PREDECESSOR_REVISION: &str = "8e5123c46569e8ebdaba9f4f56bea6584ab58586";
const PREDECESSOR_SOURCE_FINGERPRINT: &str =
    "b8f3fb55529e79c4f0aabe7443bdd94883f3b8fda1b9769ab47db4d2dc1a48fb";
const PREDECESSOR_DIRECTORY: &str =
    "evaluation/production-identity/phase1-8e5123c46569e8ebdaba9f4f56bea6584ab58586";
const PREDECESSOR_MANIFEST_SHA256: &str =
    "e5bcfaad402bd4ddb28e129a346649cd51d5ec7eb7b0e856afe5b6797e7c1e87";
const PREDECESSOR_RECEIPT_SHA256: &str =
    "641319c52589d8729684904190aa5a080afb585b5a3b16328988fa41b7352f84";

const PREDECESSOR_FILES: &[(&str, &str)] = &[
    (
        "pluscal.log",
        "7c6cab9c18d2e1d7ecc177d57a18b5bda9089914234161c0d86e75b5bc25fa9f",
    ),
    (
        "tlc.log",
        "f05b029a4e376d88ea63cadf8da9efeb309d9e85fd68d02ac063388cca4efe67",
    ),
    (
        "rust-oracle.log",
        "fdb7fa65f9a5ff062a8278fb3e54e8e94de5e372d62fa3df08516697e77c1a7c",
    ),
    (
        "summary.txt",
        "3c7c507e273f426c8bd92719ee79fa8dbe5344b21939c7b7787899dbfb54caf9",
    ),
    ("receipt.json", PREDECESSOR_RECEIPT_SHA256),
];

const SOURCE_FILES: &[&str] = &[
    "x",
    "Cargo.toml",
    "Cargo.lock",
    "crates/cser-model/Cargo.toml",
    "crates/cser-model/src/lib.rs",
    "crates/cser-model/src/production_identity_postcommit.rs",
    "crates/cser-model/tests/production_identity_postcommit_sequences.rs",
    "crates/cser-model/tests/production_identity_postcommit_properties.rs",
    "kernel/nexus-ostd/Cargo.toml",
    "kernel/nexus-ostd/Cargo.lock",
    "kernel/nexus-ostd/OSDK.toml",
    "kernel/nexus-ostd/x",
    "kernel/nexus-ostd/src/lib.rs",
    "kernel/nexus-ostd/src/cser/device_flight.rs",
    "kernel/nexus-ostd/src/cser/effect_registry.rs",
    "kernel/nexus-ostd/src/cser/effect_registry/runtime_causal.rs",
    "kernel/nexus-ostd/src/cser/effect_registry/runtime_service_task.rs",
    "kernel/nexus-ostd/src/cser/infrastructure/device_receipt_bridge.rs",
    "kernel/nexus-ostd/src/personality/linux_fs.rs",
    "kernel/nexus-ostd/src/personality/linux_fs_input.rs",
    "kernel/nexus-ostd/guest/linux-fsd-v2-postcommit.S",
    "kernel/nexus-ostd/guest/linux-fsd-v3.S",
    "kernel/nexus-ostd/scripts/build-guest.sh",
    "kernel/nexus-ostd/scripts/qemu-stream-capture.sh",
    "kernel/nexus-ostd/scripts/assert-runtime-fs-same-boot-postcommit-crash.sh",
    "kernel/nexus-ostd/scripts/assert-runtime-fs-same-boot-postcommit-crash.awk",
    "kernel/nexus-ostd/scripts/assert-runtime-fs-same-boot-postcommit-crash-source.sh",
    "tools/xtask/src/main.rs",
    "tools/xtask/src/workflow.rs",
    "tools/xtask/src/evidence.rs",
    "tools/xtask/src/evidence/bundle.rs",
    "tools/xtask/src/production_identity_postcommit.rs",
    "evaluation/production-identity/phase1-8e5123c46569e8ebdaba9f4f56bea6584ab58586/ARCHIVE.sha256",
    "evaluation/production-identity/phase1-8e5123c46569e8ebdaba9f4f56bea6584ab58586/receipt.json",
    "docs/rfcs/0001-production-identity.md",
    "docs/research/v0.2-preflight-decision.md",
    "README.md",
    "ARCHITECTURE.md",
    "ARTIFACT.md",
];

const SEQUENCE_TESTS: &[&str] = &[
    "compound_commit_precedes_backend_terminalization_and_keeps_root_active",
    "backend_terminalizes_once_and_enters_awaiting_publication_before_crash",
    "post_backend_crash_preserves_active_identity_and_fresh_v3_is_closure_only",
    "outer_ack_failure_keeps_closed_identity_and_exact_pending_retry",
    "successful_outer_ack_consumes_closed_identity_to_vacant_without_reterminalizing",
    "closure_trigger_and_attempt_substitution_are_failure_atomic",
];

const PROPERTY_TESTS: &[&str] = &[
    "arbitrary_outer_ack_failures_preserve_one_terminalization_and_exact_ticket",
    "post_backend_crash_preserves_active_causal_identity_and_registry_topology",
    "substituted_attempts_and_retries_are_failure_atomic",
];

const RUNTIME_ARTIFACTS: &[(&str, Option<&str>)] = &[
    (
        "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-postcommit-crash/serial.log",
        Some("LINUX_FS_POSTCOMMIT PASS"),
    ),
    (
        "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-postcommit-crash/qemu-debug.log",
        Some("vtd_inv_desc_iotlb_global"),
    ),
    (
        "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-postcommit-crash/task-entry-debugcon.log",
        None,
    ),
    (
        "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-postcommit-crash/task-entry-debugcon-oracle.log",
        Some("Linux futex entry debugcon assertions: PASS"),
    ),
    (
        "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-postcommit-crash/oracle.log",
        Some("runtime filesystem same-boot postcommit crash serial/debug assertions: PASS"),
    ),
];

#[derive(Serialize)]
struct PredecessorReceipt {
    revision: &'static str,
    directory: &'static str,
    manifest_sha256: &'static str,
    receipt_sha256: &'static str,
    source_fingerprint: &'static str,
    configurations: usize,
    witnesses: usize,
    rust_tests: usize,
}

#[derive(Clone, Serialize)]
struct ArtifactReceipt {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct RustOracleReceipt {
    independent_from_production_registry: bool,
    sequence_tests: usize,
    property_tests: usize,
    total_tests: usize,
    log: &'static str,
    log_sha256: String,
}

#[derive(Serialize)]
struct RuntimeReceipt {
    profile: &'static str,
    artifacts: Vec<ArtifactReceipt>,
    post_backend_pre_reply_same_boot_observed: bool,
    publication_pending_across_service_crash: bool,
    same_flight: bool,
    same_publication_obligation: bool,
    fresh_closure_trigger_observed: bool,
    registry_replacement_observed: bool,
    stale_service_authority_rejected_atomically: bool,
    fresh_trigger_rebind_adopt_observed: bool,
    causal_active_across_service_crash: bool,
    causal_close_before_outer_ack_apply: bool,
    causal_clear_after_outer_ack_success: bool,
    causal_closed_outer_ack_pending_runtime_observed: bool,
    causal_closed_outer_ack_pending_model_checked: bool,
    causal_service_task_facade_observed: bool,
    causal_fault_matrix_promotion: bool,
    post_commit_pre_backend_same_boot_observed: bool,
    logical_request_lost_ack_observed: bool,
    irq_observed: bool,
    smp_vcpus: u8,
}

#[derive(Serialize)]
struct Boundaries {
    bounded_one_vcpu: bool,
    polling: bool,
    intx_masked: bool,
    all_fault_paths_observed: bool,
    phase2_closed: bool,
    phase3_closed: bool,
    rfc0001_closed: bool,
    post_commit_pre_backend_model_checked: bool,
    production_adapter_equivalence_established: bool,
    rfc0003_guest_reply_cell_promoted: bool,
}

#[derive(Serialize)]
struct Receipt {
    schema: &'static str,
    status: &'static str,
    command: &'static str,
    revision: String,
    worktree_dirty: bool,
    source_fingerprint: String,
    source_files: Vec<String>,
    generated_unix_seconds: u64,
    predecessor: PredecessorReceipt,
    rust_oracle: RustOracleReceipt,
    runtime: RuntimeReceipt,
    boundaries: Boundaries,
    summary: &'static str,
    summary_sha256: String,
}

pub(crate) fn run(root: &Path) -> Result<()> {
    verify_predecessor(root)?;
    clear_previous_outputs(root)?;

    let revision_before = git_text(root, &["rev-parse", "HEAD"])?;
    let source_before = fingerprint_paths(root, SOURCE_FILES)?;
    run_rust_oracle(root)?;
    validate_rust_log(&fs::read_to_string(root.join(RUST_LOG))?)?;
    let runtime_artifacts = validate_runtime_artifacts(root)?;

    let revision_after = git_text(root, &["rev-parse", "HEAD"])?;
    let source_after = fingerprint_paths(root, SOURCE_FILES)?;
    if revision_before != revision_after || source_before != source_after {
        return Err(format!(
            "postcommit successor sources changed during verification: revision {revision_before}->{revision_after}, fingerprint {source_before}->{source_after}"
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
    let summary_sha256 = sha256(summary.as_bytes());
    let rust_log_sha256 = sha256_file(&root.join(RUST_LOG))?;

    let receipt = Receipt {
        schema: SCHEMA,
        status: "passed",
        command: COMMAND,
        revision: revision_after,
        worktree_dirty,
        source_fingerprint: source_after,
        source_files: SOURCE_FILES
            .iter()
            .map(|path| String::from(*path))
            .collect(),
        generated_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        predecessor: PredecessorReceipt {
            revision: PREDECESSOR_REVISION,
            directory: PREDECESSOR_DIRECTORY,
            manifest_sha256: PREDECESSOR_MANIFEST_SHA256,
            receipt_sha256: PREDECESSOR_RECEIPT_SHA256,
            source_fingerprint: PREDECESSOR_SOURCE_FINGERPRINT,
            configurations: 4,
            witnesses: 8,
            rust_tests: 11,
        },
        rust_oracle: RustOracleReceipt {
            independent_from_production_registry: true,
            sequence_tests: SEQUENCE_TESTS.len(),
            property_tests: PROPERTY_TESTS.len(),
            total_tests: SEQUENCE_TESTS.len() + PROPERTY_TESTS.len(),
            log: RUST_LOG,
            log_sha256: rust_log_sha256,
        },
        runtime: RuntimeReceipt {
            profile: "runtime-fs-same-boot-postcommit-crash",
            artifacts: runtime_artifacts,
            post_backend_pre_reply_same_boot_observed: true,
            publication_pending_across_service_crash: true,
            same_flight: true,
            same_publication_obligation: true,
            fresh_closure_trigger_observed: true,
            registry_replacement_observed: false,
            stale_service_authority_rejected_atomically: true,
            fresh_trigger_rebind_adopt_observed: false,
            causal_active_across_service_crash: true,
            causal_close_before_outer_ack_apply: true,
            causal_clear_after_outer_ack_success: true,
            causal_closed_outer_ack_pending_runtime_observed: false,
            causal_closed_outer_ack_pending_model_checked: true,
            causal_service_task_facade_observed: false,
            causal_fault_matrix_promotion: false,
            post_commit_pre_backend_same_boot_observed: false,
            logical_request_lost_ack_observed: false,
            irq_observed: false,
            smp_vcpus: 1,
        },
        boundaries: Boundaries {
            bounded_one_vcpu: true,
            polling: true,
            intx_masked: true,
            all_fault_paths_observed: false,
            phase2_closed: false,
            phase3_closed: false,
            rfc0001_closed: false,
            post_commit_pre_backend_model_checked: false,
            production_adapter_equivalence_established: false,
            rfc0003_guest_reply_cell_promoted: false,
        },
        summary: SUMMARY_PATH,
        summary_sha256,
    };
    let mut receipt_json = serde_json::to_vec_pretty(&receipt)?;
    receipt_json.push(b'\n');
    atomic_write(&root.join(RECEIPT_PATH), &receipt_json)?;
    validate_receipt_value(&serde_json::from_slice(&receipt_json)?)?;

    println!(
        "PRODUCTION IDENTITY POSTCOMMIT PASS predecessor={} rust_tests={} runtime_artifacts={} receipt={}",
        PREDECESSOR_REVISION,
        SEQUENCE_TESTS.len() + PROPERTY_TESTS.len(),
        RUNTIME_ARTIFACTS.len(),
        RECEIPT_PATH,
    );
    println!(
        "Bounded post-backend/pre-reply one-vCPU polling observation only; v3 is a closure trigger, not a Registry replacement. Lost-ACK runtime injection, causal-task facade wiring, causal fault-matrix promotion, IRQ, SMP, Phase 2/3, and RFC closure remain open."
    );
    Ok(())
}

fn verify_predecessor(root: &Path) -> Result<()> {
    let directory = root.join(PREDECESSOR_DIRECTORY);
    let manifest = directory.join("ARCHIVE.sha256");
    if sha256_file(&manifest)? != PREDECESSOR_MANIFEST_SHA256 {
        return Err("production-identity Phase 1 predecessor manifest digest drifted".into());
    }
    let expected_manifest = PREDECESSOR_FILES
        .iter()
        .map(|(file, digest)| format!("{digest}  {file}\n"))
        .collect::<String>();
    if fs::read_to_string(&manifest)? != expected_manifest {
        return Err("production-identity Phase 1 predecessor manifest population drifted".into());
    }
    for (file, expected) in PREDECESSOR_FILES {
        let path = directory.join(file);
        require_regular_file(&path, "Phase 1 predecessor")?;
        if sha256_file(&path)? != *expected {
            return Err(format!("production-identity Phase 1 predecessor drifted: {file}").into());
        }
    }

    let receipt: Value = serde_json::from_slice(&fs::read(directory.join("receipt.json"))?)?;
    let exact = [
        ("schema", "nexus.research.production-identity.v2"),
        ("status", "passed"),
        ("revision", PREDECESSOR_REVISION),
        ("source_fingerprint", PREDECESSOR_SOURCE_FINGERPRINT),
    ];
    for (field, expected) in exact {
        if receipt.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(format!("Phase 1 predecessor receipt changed {field}").into());
        }
    }
    if receipt.get("worktree_dirty").and_then(Value::as_bool) != Some(false)
        || receipt.get("prospective").and_then(Value::as_bool) != Some(true)
        || receipt.get("full_configurations").and_then(Value::as_u64) != Some(4)
        || receipt
            .get("reachability_witnesses")
            .and_then(Value::as_u64)
            != Some(8)
        || receipt
            .pointer("/rust_oracle/total_tests")
            .and_then(Value::as_u64)
            != Some(11)
        || receipt
            .get("real_ostd_smp_claimed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("Phase 1 predecessor receipt changed its bounded acceptance contract".into());
    }
    Ok(())
}

fn run_rust_oracle(root: &Path) -> Result<()> {
    super::section("run additive production-identity postcommit safe-Rust oracle");
    let script = r#"
set -eu
echo '==> production-identity postcommit sequence oracle'
cargo test --locked -p cser-model --test production_identity_postcommit_sequences
echo '==> production-identity postcommit property oracle'
cargo test --locked -p cser-model --test production_identity_postcommit_properties
"#;
    let mut command = Command::new("sh");
    command.current_dir(root).arg("-c").arg(script);
    super::run_bounded_logged_quiet(
        &mut command,
        &root.join(RUST_LOG),
        Duration::from_secs(300),
        2 * 1024 * 1024,
    )
}

fn validate_rust_log(log: &str) -> Result<()> {
    let suites = [
        (
            "==> production-identity postcommit sequence oracle",
            SEQUENCE_TESTS,
        ),
        (
            "==> production-identity postcommit property oracle",
            PROPERTY_TESTS,
        ),
    ];
    let headings: Vec<_> = log
        .lines()
        .filter(|line| line.starts_with("==> production-identity postcommit "))
        .collect();
    let expected_headings: Vec<_> = suites.iter().map(|(heading, _)| *heading).collect();
    if headings != expected_headings {
        return Err("postcommit Rust oracle suite population or order differs".into());
    }
    for (heading, tests) in suites {
        let start = log
            .find(heading)
            .ok_or("postcommit Rust suite heading missing")?;
        let end = log[start + heading.len()..]
            .find("==> production-identity postcommit ")
            .map_or(log.len(), |offset| start + heading.len() + offset);
        let section = &log[start..end];
        let marker = format!("test result: ok. {} passed; 0 failed;", tests.len());
        if !section.contains(&marker) {
            return Err(format!("postcommit Rust suite lacks exact pass count: {heading}").into());
        }
        for test in tests {
            if !section.contains(&format!("test {test} ... ok")) {
                return Err(format!("postcommit Rust suite lacks named test: {test}").into());
            }
        }
    }
    Ok(())
}

fn validate_runtime_artifacts(root: &Path) -> Result<Vec<ArtifactReceipt>> {
    RUNTIME_ARTIFACTS
        .iter()
        .map(|(relative, marker)| {
            let path = root.join(relative);
            require_regular_file(&path, "postcommit runtime artifact")?;
            let bytes = fs::read(&path)?;
            if bytes.is_empty() {
                return Err(format!("postcommit runtime artifact is empty: {relative}").into());
            }
            if let Some(marker) = marker {
                if !String::from_utf8_lossy(&bytes).contains(marker) {
                    return Err(format!(
                        "postcommit runtime artifact lacks {marker:?}: {relative}"
                    )
                    .into());
                }
            }
            Ok(ArtifactReceipt {
                path: String::from(*relative),
                bytes: u64::try_from(bytes.len())?,
                sha256: sha256(&bytes),
            })
        })
        .collect()
}

fn validate_receipt_value(receipt: &Value) -> Result<()> {
    if receipt.get("schema").and_then(Value::as_str) != Some(SCHEMA)
        || receipt.get("status").and_then(Value::as_str) != Some("passed")
        || receipt.get("command").and_then(Value::as_str) != Some(COMMAND)
        || receipt
            .pointer("/predecessor/receipt_sha256")
            .and_then(Value::as_str)
            != Some(PREDECESSOR_RECEIPT_SHA256)
        || receipt
            .pointer("/rust_oracle/total_tests")
            .and_then(Value::as_u64)
            != Some((SEQUENCE_TESTS.len() + PROPERTY_TESTS.len()) as u64)
        || receipt
            .pointer("/runtime/post_backend_pre_reply_same_boot_observed")
            .and_then(Value::as_bool)
            != Some(true)
        || receipt
            .pointer("/runtime/publication_pending_across_service_crash")
            .and_then(Value::as_bool)
            != Some(true)
        || receipt
            .pointer("/runtime/fresh_closure_trigger_observed")
            .and_then(Value::as_bool)
            != Some(true)
        || receipt
            .pointer("/runtime/registry_replacement_observed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .pointer("/runtime/causal_active_across_service_crash")
            .and_then(Value::as_bool)
            != Some(true)
        || receipt
            .pointer("/runtime/causal_close_before_outer_ack_apply")
            .and_then(Value::as_bool)
            != Some(true)
        || receipt
            .pointer("/runtime/causal_clear_after_outer_ack_success")
            .and_then(Value::as_bool)
            != Some(true)
        || receipt
            .pointer("/runtime/causal_closed_outer_ack_pending_runtime_observed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .pointer("/runtime/causal_closed_outer_ack_pending_model_checked")
            .and_then(Value::as_bool)
            != Some(true)
        || receipt
            .pointer("/runtime/causal_service_task_facade_observed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .pointer("/runtime/causal_fault_matrix_promotion")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .pointer("/runtime/logical_request_lost_ack_observed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .pointer("/runtime/post_commit_pre_backend_same_boot_observed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .pointer("/runtime/irq_observed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .pointer("/runtime/smp_vcpus")
            .and_then(Value::as_u64)
            != Some(1)
        || receipt
            .pointer("/boundaries/phase2_closed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .pointer("/boundaries/phase3_closed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .pointer("/boundaries/rfc0001_closed")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt
            .pointer("/boundaries/rfc0003_guest_reply_cell_promoted")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("postcommit successor receipt changed its bounded claim boundary".into());
    }
    Ok(())
}

fn summary_text(revision: &str, fingerprint: &str, worktree_dirty: bool) -> String {
    format!(
        "schema={SCHEMA}\nstatus=passed\ncommand={COMMAND}\nrevision={revision}\nworktree_dirty={worktree_dirty}\nsource_fingerprint={fingerprint}\npredecessor_revision={PREDECESSOR_REVISION}\npredecessor_receipt_sha256={PREDECESSOR_RECEIPT_SHA256}\nrust_sequence_tests={}\nrust_property_tests={}\nruntime_artifacts={}\npost_backend_pre_reply_same_boot_observed=true\npublication_pending_across_service_crash=true\nsame_flight=true\nsame_publication_obligation=true\nfresh_closure_trigger_observed=true\nregistry_replacement_observed=false\nfresh_trigger_rebind_adopt_observed=false\ncausal_active_across_service_crash=true\ncausal_close_before_outer_ack_apply=true\ncausal_clear_after_outer_ack_success=true\ncausal_closed_outer_ack_pending_runtime_observed=false\ncausal_closed_outer_ack_pending_model_checked=true\ncausal_service_task_facade_observed=false\ncausal_fault_matrix_promotion=false\npost_commit_pre_backend_same_boot_observed=false\nlogical_request_lost_ack_observed=false\nirq_observed=false\nsmp_vcpus=1\nphase2_closed=false\nphase3_closed=false\nrfc0001_closed=false\nrfc0003_guest_reply_cell_promoted=false\n",
        SEQUENCE_TESTS.len(),
        PROPERTY_TESTS.len(),
        RUNTIME_ARTIFACTS.len(),
    )
}

fn clear_previous_outputs(root: &Path) -> Result<()> {
    fs::create_dir_all(root.join(OUTPUT_DIRECTORY))?;
    for relative in [RUST_LOG, SUMMARY_PATH, RECEIPT_PATH] {
        match fs::remove_file(root.join(relative)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("remove stale postcommit artifact {relative}: {error}").into());
            }
        }
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular file: {}", path.display()).into());
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
        require_regular_file(&absolute, "source fingerprint input")?;
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

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256(&fs::read(path)?))
}

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git_bytes(root, args)?)?.trim().to_owned())
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

    #[test]
    fn checked_in_phase1_predecessor_is_exact() {
        verify_predecessor(&super::super::repo_root()).expect("exact Phase 1 predecessor");
    }

    #[test]
    fn bounded_receipt_rejects_claim_escalation() {
        let mut receipt = serde_json::json!({
            "schema": SCHEMA,
            "status": "passed",
            "command": COMMAND,
            "predecessor": { "receipt_sha256": PREDECESSOR_RECEIPT_SHA256 },
            "rust_oracle": { "total_tests": SEQUENCE_TESTS.len() + PROPERTY_TESTS.len() },
            "runtime": {
                "post_backend_pre_reply_same_boot_observed": true,
                "publication_pending_across_service_crash": true,
                "fresh_closure_trigger_observed": true,
                "registry_replacement_observed": false,
                "causal_active_across_service_crash": true,
                "causal_close_before_outer_ack_apply": true,
                "causal_clear_after_outer_ack_success": true,
                "causal_closed_outer_ack_pending_runtime_observed": false,
                "causal_closed_outer_ack_pending_model_checked": true,
                "causal_service_task_facade_observed": false,
                "causal_fault_matrix_promotion": false,
                "logical_request_lost_ack_observed": false,
                "post_commit_pre_backend_same_boot_observed": false,
                "irq_observed": false,
                "smp_vcpus": 1
            },
            "boundaries": {
                "phase2_closed": false,
                "phase3_closed": false,
                "rfc0001_closed": false,
                "rfc0003_guest_reply_cell_promoted": false
            }
        });
        validate_receipt_value(&receipt).expect("bounded receipt");
        for pointer in [
            "/runtime/post_backend_pre_reply_same_boot_observed",
            "/runtime/publication_pending_across_service_crash",
            "/runtime/fresh_closure_trigger_observed",
            "/runtime/causal_active_across_service_crash",
            "/runtime/causal_close_before_outer_ack_apply",
            "/runtime/causal_clear_after_outer_ack_success",
            "/runtime/causal_closed_outer_ack_pending_model_checked",
        ] {
            *receipt.pointer_mut(pointer).expect("observed field") = Value::Bool(false);
            assert!(
                validate_receipt_value(&receipt).is_err(),
                "accepted missing {pointer}"
            );
            *receipt.pointer_mut(pointer).expect("observed field") = Value::Bool(true);
        }
        for pointer in [
            "/runtime/logical_request_lost_ack_observed",
            "/runtime/registry_replacement_observed",
            "/runtime/causal_closed_outer_ack_pending_runtime_observed",
            "/runtime/causal_service_task_facade_observed",
            "/runtime/causal_fault_matrix_promotion",
            "/runtime/post_commit_pre_backend_same_boot_observed",
            "/runtime/irq_observed",
            "/boundaries/phase2_closed",
            "/boundaries/phase3_closed",
            "/boundaries/rfc0001_closed",
            "/boundaries/rfc0003_guest_reply_cell_promoted",
        ] {
            *receipt.pointer_mut(pointer).expect("claim field") = Value::Bool(true);
            assert!(
                validate_receipt_value(&receipt).is_err(),
                "accepted {pointer}"
            );
            *receipt.pointer_mut(pointer).expect("claim field") = Value::Bool(false);
        }
    }
}
