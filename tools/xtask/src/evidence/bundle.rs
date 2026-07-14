use super::{
    Artifact, Boundaries, COMPLETE_SCHEMA, COMPLETE_STAGES, COMPLETION_RECEIPT,
    FORMAL_VERIFIER_RECEIPT, FormalVerifierBinding, FormalVerifierReceipt, GateReceipt,
    MODEL_SPEC_RECEIPT, MODEL_SPEC_SCHEMA, OUTPUT as MANIFEST_PATH, SCHEMA, SENTINEL,
    SourceSnapshot, StartRecord, is_sha256, manifest_stages, model_spec_artifacts,
    read_regular_file_stable, required_artifacts, sha256, source_snapshot, toolchain_files,
    validate_formal_verifier_binding, validate_formal_verifier_receipt, validate_gate_receipt,
    validate_start_record, validate_toolchain_files,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub(super) const BUNDLE_DIRECTORY: &str = "target/verification/artifact-bundle";
const CHECKSUMS: &str = "SHA256SUMS";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishedManifest {
    schema: String,
    status: String,
    command: String,
    revision: String,
    source_sha256: String,
    worktree_dirty: bool,
    nexus_rebuild: Option<String>,
    rebuild_requested: bool,
    orchestration_token_sha256: String,
    run_nonce: String,
    completion_receipt_sha256: String,
    started_unix_nanos: u128,
    generated_unix_seconds: u64,
    formal_verifier: FormalVerifierBinding,
    boundaries: Value,
    specifications: Vec<String>,
    stages: Vec<PublishedStage>,
    artifacts: Vec<Artifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishedStage {
    id: String,
    evidence: Vec<String>,
}

struct ValidatedPayload {
    manifest: PublishedManifest,
    payload_digests: BTreeMap<String, String>,
}

pub(crate) fn write_bundle(root: &Path, specs: &[&str]) -> Result<PathBuf> {
    let validated = validate_payload(root, specs)?;
    let output = root.join(BUNDLE_DIRECTORY);
    let verification = output
        .parent()
        .ok_or("artifact bundle output has no parent")?;
    fs::create_dir_all(verification)?;

    let temporary = verification.join(format!(
        ".artifact-bundle.{}.tmp",
        validated.manifest.run_nonce
    ));
    remove_directory_if_present(&temporary, "stale temporary artifact bundle")?;
    fs::create_dir(&temporary)?;

    let result = (|| -> Result<()> {
        for relative in validated.payload_digests.keys() {
            let source = root.join(relative);
            let read = read_regular_file_stable(&source, "artifact bundle source")?;
            write_new_file(&temporary.join(relative), &read.bytes)?;
        }
        write_checksum_index(&temporary, &validated.payload_digests)?;
        verify_bundle_directory(&temporary, specs)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }

    remove_directory_if_present(&output, "previous artifact bundle")?;
    fs::rename(&temporary, &output)?;
    println!(
        "verification artifact bundle: PASS path={} payload_files={} artifacts={} schema={}",
        output.display(),
        validated.payload_digests.len(),
        validated.manifest.artifacts.len(),
        SCHEMA
    );
    Ok(output)
}

pub(crate) fn verify_bundle(root: &Path, bundle: &Path, specs: &[&str]) -> Result<()> {
    verify_bundle_directory(bundle, specs)?;
    let manifest_path = bundle.join(MANIFEST_PATH);
    let manifest: PublishedManifest = serde_json::from_slice(
        &read_regular_file_stable(&manifest_path, "artifact bundle manifest")?.bytes,
    )?;
    let current_source = source_snapshot(root)?;
    validate_checkout_binding(&manifest, &current_source)?;
    println!(
        "verification artifact bundle check: PASS path={} revision={} specifications={} stages={} artifacts={} dirty={} rebuild={}",
        bundle.display(),
        manifest.revision,
        manifest.specifications.len(),
        manifest.stages.len(),
        manifest.artifacts.len(),
        manifest.worktree_dirty,
        manifest.rebuild_requested
    );
    Ok(())
}

fn validate_checkout_binding(
    manifest: &PublishedManifest,
    current_source: &SourceSnapshot,
) -> Result<()> {
    if manifest.command != "./x verify" {
        return Err("release bundle must come from the canonical ./x verify invocation".into());
    }
    if !manifest.rebuild_requested || manifest.nexus_rebuild.as_deref() != Some("1") {
        return Err("release bundle must come from a cold NEXUS_REBUILD=1 verification".into());
    }
    if current_source.worktree_dirty {
        return Err("artifact bundle verification requires a clean checkout".into());
    }
    if manifest.worktree_dirty {
        return Err("artifact bundle manifest was not produced from a clean checkout".into());
    }
    if manifest.revision != current_source.revision
        || manifest.source_sha256 != current_source.source_sha256
    {
        return Err(format!(
            "artifact bundle does not bind the current checkout: revision {}->{}, fingerprint {}->{}",
            manifest.revision,
            current_source.revision,
            manifest.source_sha256,
            current_source.source_sha256
        )
        .into());
    }
    Ok(())
}

pub(super) fn clear_bundle(root: &Path) -> Result<()> {
    let output = root.join(BUNDLE_DIRECTORY);
    remove_directory_if_present(&output, "previous artifact bundle")?;
    let Some(parent) = output.parent() else {
        return Ok(());
    };
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".artifact-bundle.") && name.ends_with(".tmp") {
            remove_directory_if_present(&entry.path(), "temporary artifact bundle")?;
        }
    }
    Ok(())
}

fn verify_bundle_directory(bundle: &Path, specs: &[&str]) -> Result<()> {
    let metadata = fs::symlink_metadata(bundle)
        .map_err(|error| format!("artifact bundle {}: {error}", bundle.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "artifact bundle is not a real directory: {}",
            bundle.display()
        )
        .into());
    }

    let validated = validate_payload(bundle, specs)?;
    let checksum_path = bundle.join(CHECKSUMS);
    let checksum_file = read_regular_file_stable(&checksum_path, "artifact bundle checksum index")?;
    let recorded = parse_checksum_index(&checksum_file.bytes)?;
    if recorded != validated.payload_digests {
        return Err("artifact bundle SHA256SUMS does not match its exact payload".into());
    }

    let mut expected_files: BTreeSet<_> = validated.payload_digests.keys().cloned().collect();
    expected_files.insert(String::from(CHECKSUMS));
    let actual_files = collect_files(bundle)?;
    if actual_files != expected_files {
        let missing: Vec<_> = expected_files.difference(&actual_files).cloned().collect();
        let unexpected: Vec<_> = actual_files.difference(&expected_files).cloned().collect();
        return Err(format!(
            "artifact bundle file population differs: missing={missing:?} unexpected={unexpected:?}"
        )
        .into());
    }
    Ok(())
}

fn validate_payload(base: &Path, specs: &[&str]) -> Result<ValidatedPayload> {
    let manifest_file =
        read_regular_file_stable(&base.join(MANIFEST_PATH), "artifact bundle manifest")?;
    let manifest: PublishedManifest = serde_json::from_slice(&manifest_file.bytes)?;
    validate_manifest_population(&manifest, specs)?;

    let start_file = read_regular_file_stable(
        &base.join(SENTINEL),
        "artifact bundle verification start record",
    )?;
    let start: StartRecord = serde_json::from_slice(&start_file.bytes)?;
    let start_record_sha256 = sha256(&start_file.bytes);
    let source = SourceSnapshot {
        revision: manifest.revision.clone(),
        source_sha256: manifest.source_sha256.clone(),
        worktree_dirty: manifest.worktree_dirty,
    };
    validate_start_record(&start, &source, None)?;
    validate_manifest_start_binding(&manifest, &start)?;

    let verifier_file = read_regular_file_stable(
        &base.join(FORMAL_VERIFIER_RECEIPT),
        "artifact bundle formal verifier receipt",
    )?;
    let verifier: FormalVerifierReceipt = serde_json::from_slice(&verifier_file.bytes)?;
    validate_formal_verifier_receipt(&verifier, &start, &start_record_sha256)?;
    let verifier_sha256 = sha256(&verifier_file.bytes);
    if manifest.formal_verifier.toolchain != verifier.toolchain
        || manifest.formal_verifier.installed_path != verifier.installed_path
        || manifest.formal_verifier.runtime_receipt.path != FORMAL_VERIFIER_RECEIPT
        || manifest.formal_verifier.runtime_receipt.bytes
            != u64::try_from(verifier_file.bytes.len())?
        || manifest.formal_verifier.runtime_receipt.sha256 != verifier_sha256
    {
        return Err("artifact bundle formal verifier receipt does not match the manifest".into());
    }

    let model_file = read_regular_file_stable(
        &base.join(MODEL_SPEC_RECEIPT),
        "artifact bundle model/spec receipt",
    )?;
    let model: GateReceipt = serde_json::from_slice(&model_file.bytes)?;
    let by_path: BTreeMap<_, _> = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact.clone()))
        .collect();
    let model_artifacts: Vec<_> = model_spec_artifacts(specs)
        .iter()
        .map(|(path, _)| {
            by_path
                .get(path.as_str())
                .cloned()
                .ok_or_else(|| format!("manifest lacks model/spec artifact: {path}"))
        })
        .collect::<std::result::Result<_, _>>()?;
    validate_gate_receipt(
        &model,
        MODEL_SPEC_SCHEMA,
        &start,
        &["reference-model", "formal-specifications"],
        Some(&verifier_sha256),
        &model_artifacts,
    )?;
    let model_sha256 = sha256(&model_file.bytes);

    let completion_file = read_regular_file_stable(
        &base.join(COMPLETION_RECEIPT),
        "artifact bundle completion receipt",
    )?;
    let completion: GateReceipt = serde_json::from_slice(&completion_file.bytes)?;
    validate_gate_receipt(
        &completion,
        COMPLETE_SCHEMA,
        &start,
        &COMPLETE_STAGES,
        Some(&model_sha256),
        &manifest.artifacts,
    )?;
    if sha256(&completion_file.bytes) != manifest.completion_receipt_sha256 {
        return Err("artifact bundle completion receipt does not match the manifest".into());
    }

    let mut payload_digests = BTreeMap::new();
    insert_payload(
        &mut payload_digests,
        MANIFEST_PATH,
        sha256(&manifest_file.bytes),
    )?;
    insert_payload(&mut payload_digests, SENTINEL, sha256(&start_file.bytes))?;
    insert_payload(
        &mut payload_digests,
        FORMAL_VERIFIER_RECEIPT,
        verifier_sha256,
    )?;
    insert_payload(&mut payload_digests, MODEL_SPEC_RECEIPT, model_sha256)?;
    insert_payload(
        &mut payload_digests,
        COMPLETION_RECEIPT,
        manifest.completion_receipt_sha256.clone(),
    )?;

    validate_toolchain_files(base, &manifest.formal_verifier.toolchain)?;
    for file in toolchain_files(&manifest.formal_verifier.toolchain) {
        insert_payload(&mut payload_digests, &file.path, file.sha256.clone())?;
    }

    for artifact in &manifest.artifacts {
        validate_relative_path(&artifact.path)?;
        let read = read_regular_file_stable(
            &base.join(&artifact.path),
            "manifest-bound artifact bundle file",
        )?;
        if u64::try_from(read.bytes.len())? != artifact.bytes
            || sha256(&read.bytes) != artifact.sha256
        {
            return Err(format!(
                "artifact bundle bytes or SHA-256 disagree with manifest: {}",
                artifact.path
            )
            .into());
        }
        insert_payload(
            &mut payload_digests,
            &artifact.path,
            artifact.sha256.clone(),
        )?;
    }

    Ok(ValidatedPayload {
        manifest,
        payload_digests,
    })
}

fn validate_manifest_population(manifest: &PublishedManifest, specs: &[&str]) -> Result<()> {
    if manifest.schema != SCHEMA || manifest.status != "passed" {
        return Err(format!("artifact bundle manifest is not a passed {SCHEMA} record").into());
    }
    if !matches!(manifest.command.as_str(), "./x verify" | "./x test --full") {
        return Err(format!(
            "artifact bundle manifest has a non-full invocation: {:?}",
            manifest.command
        )
        .into());
    }
    if manifest.revision.is_empty()
        || !is_sha256(&manifest.source_sha256)
        || !is_sha256(&manifest.orchestration_token_sha256)
        || !is_sha256(&manifest.run_nonce)
        || !is_sha256(&manifest.completion_receipt_sha256)
        || manifest.started_unix_nanos == 0
        || manifest.generated_unix_seconds == 0
    {
        return Err("artifact bundle manifest has malformed bound fields".into());
    }
    if manifest.rebuild_requested != (manifest.nexus_rebuild.as_deref() == Some("1")) {
        return Err("artifact bundle manifest has inconsistent NEXUS_REBUILD fields".into());
    }
    validate_formal_verifier_binding(&manifest.formal_verifier)?;

    let expected_specs: Vec<_> = specs.iter().map(|spec| String::from(*spec)).collect();
    if manifest.specifications != expected_specs {
        return Err("artifact bundle specification population differs from the contract".into());
    }
    let expected_stages = manifest_stages(specs);
    if manifest.stages.len() != expected_stages.len()
        || manifest
            .stages
            .iter()
            .zip(&expected_stages)
            .any(|(actual, expected)| {
                actual.id != expected.id
                    || actual.evidence.as_slice() != expected.evidence.as_slice()
            })
    {
        return Err("artifact bundle stage population differs from the contract".into());
    }

    let expected_boundaries = serde_json::to_value(Boundaries::current())?;
    if manifest.boundaries != expected_boundaries {
        return Err("artifact bundle research boundaries differ from the contract".into());
    }

    let expected_paths: Vec<_> = required_artifacts(specs)
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    let actual_paths: Vec<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect();
    if actual_paths != expected_paths {
        return Err("artifact bundle artifact population differs from the contract".into());
    }
    for artifact in &manifest.artifacts {
        if artifact.bytes == 0 || !is_sha256(&artifact.sha256) {
            return Err(format!("manifest contains malformed artifact: {}", artifact.path).into());
        }
    }
    Ok(())
}

fn validate_manifest_start_binding(
    manifest: &PublishedManifest,
    start: &StartRecord,
) -> Result<()> {
    if manifest.revision != start.revision
        || manifest.source_sha256 != start.source_sha256
        || manifest.worktree_dirty != start.worktree_dirty
        || manifest.command != start.invocation
        || manifest.nexus_rebuild != start.nexus_rebuild
        || manifest.rebuild_requested != start.rebuild_requested
        || manifest.orchestration_token_sha256 != start.orchestration_token_sha256
        || manifest.run_nonce != start.nonce
        || manifest.started_unix_nanos != start.started_unix_nanos
    {
        return Err("artifact bundle manifest does not bind its start record".into());
    }
    Ok(())
}

fn insert_payload(
    payload: &mut BTreeMap<String, String>,
    relative: &str,
    digest: String,
) -> Result<()> {
    validate_relative_path(relative)?;
    if payload.insert(String::from(relative), digest).is_some() {
        return Err(
            format!("artifact bundle contains a duplicate payload path: {relative}").into(),
        );
    }
    Ok(())
}

fn validate_relative_path(relative: &str) -> Result<()> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("artifact bundle path is not clean and relative: {relative:?}").into());
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("artifact bundle file has no parent")?;
    fs::create_dir_all(parent)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_checksum_index(bundle: &Path, payload: &BTreeMap<String, String>) -> Result<()> {
    let mut output = String::new();
    for (relative, digest) in payload {
        output.push_str(digest);
        output.push_str("  ");
        output.push_str(relative);
        output.push('\n');
    }
    write_new_file(&bundle.join(CHECKSUMS), output.as_bytes())
}

fn parse_checksum_index(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes)?;
    if text.is_empty() || !text.ends_with('\n') || text.contains('\r') {
        return Err("artifact bundle SHA256SUMS is not canonical UTF-8 text".into());
    }
    let mut entries = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for line in text.lines() {
        let (digest, relative) = line
            .split_once("  ")
            .ok_or("artifact bundle SHA256SUMS line lacks two-space separator")?;
        if !is_sha256(digest) {
            return Err("artifact bundle SHA256SUMS contains a malformed digest".into());
        }
        validate_relative_path(relative)?;
        if previous.is_some_and(|value| value >= relative) {
            return Err("artifact bundle SHA256SUMS paths are not uniquely sorted".into());
        }
        previous = Some(relative);
        if entries
            .insert(String::from(relative), String::from(digest))
            .is_some()
        {
            return Err("artifact bundle SHA256SUMS contains a duplicate path".into());
        }
    }
    Ok(entries)
}

fn collect_files(root: &Path) -> Result<BTreeSet<String>> {
    let mut files = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries: Vec<_> = fs::read_dir(&directory)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(
                    format!("artifact bundle contains a symlink: {}", path.display()).into(),
                );
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let relative = path.strip_prefix(root)?;
                let relative = relative
                    .to_str()
                    .ok_or("artifact bundle contains a non-UTF-8 path")?;
                validate_relative_path(relative)?;
                files.insert(String::from(relative));
            } else {
                return Err(format!(
                    "artifact bundle contains a non-file entry: {}",
                    path.display()
                )
                .into());
            }
        }
    }
    Ok(files)
}

fn remove_directory_if_present(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path)?;
            Ok(())
        }
        Ok(_) => Err(format!("{label} is not a real directory: {}", path.display()).into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{
        FORMAL_VERIFIER_SCHEMA, GateReceipt, Manifest, Stage, TLA_TOOLCHAIN_INSTALLED_PATH,
        TLA_TOOLCHAIN_VERSION_LINE, VerificationEnvironment, expected_toolchain_receipt,
        formal_verifier_binding, gate_receipt, start_nonce, toolchain_files,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    const SPECS: [&str; 12] = [
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

    fn fixture() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nexus-artifact-bundle-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create bundle fixture");
        path
    }

    fn stage_population() -> Vec<Stage> {
        manifest_stages(&SPECS)
    }

    fn write_json(path: &Path, value: &impl serde::Serialize) {
        fs::create_dir_all(path.parent().expect("JSON parent")).expect("create JSON parent");
        fs::write(
            path,
            serde_json::to_vec_pretty(value).expect("serialize fixture"),
        )
        .expect("write fixture JSON");
    }

    fn write_source_fixture(root: &Path) {
        let toolchain = expected_toolchain_receipt();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for file in toolchain_files(&toolchain) {
            let destination = root.join(&file.path);
            fs::create_dir_all(destination.parent().expect("toolchain parent"))
                .expect("create toolchain parent");
            fs::copy(repository.join(&file.path), &destination)
                .expect("copy pinned toolchain fixture");
        }

        let mut artifacts = Vec::new();
        for (relative, _) in required_artifacts(&SPECS) {
            let bytes = format!("fixture artifact {relative}\n").into_bytes();
            let path = root.join(&relative);
            fs::create_dir_all(path.parent().expect("artifact parent"))
                .expect("create artifact parent");
            fs::write(&path, &bytes).expect("write artifact");
            artifacts.push(Artifact {
                path: relative,
                bytes: u64::try_from(bytes.len()).expect("artifact length"),
                sha256: sha256(&bytes),
            });
        }

        let source = SourceSnapshot {
            revision: String::from("0123456789abcdef0123456789abcdef01234567"),
            source_sha256: "a".repeat(64),
            worktree_dirty: false,
        };
        let environment = VerificationEnvironment {
            invocation: String::from("./x verify"),
            nexus_rebuild: Some(String::from("1")),
        };
        let started_unix_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("fixture clock")
            .as_nanos()
            - 1_000_000;
        let process_id = 17;
        let orchestration_token_sha256 = "b".repeat(64);
        let start = StartRecord {
            schema: String::from(super::super::START_SCHEMA),
            revision: source.revision.clone(),
            source_sha256: source.source_sha256.clone(),
            worktree_dirty: source.worktree_dirty,
            invocation: environment.invocation.clone(),
            nexus_rebuild: environment.nexus_rebuild.clone(),
            rebuild_requested: true,
            orchestration_token_sha256: orchestration_token_sha256.clone(),
            nonce: start_nonce(
                &source,
                &environment,
                &orchestration_token_sha256,
                process_id,
                started_unix_nanos,
            ),
            process_id,
            started_unix_nanos,
        };
        write_json(&root.join(SENTINEL), &start);

        let verifier = FormalVerifierReceipt {
            schema: String::from(FORMAL_VERIFIER_SCHEMA),
            start_record_sha256: sha256(&fs::read(root.join(SENTINEL)).expect("read start record")),
            revision: start.revision.clone(),
            source_sha256: start.source_sha256.clone(),
            worktree_dirty: start.worktree_dirty,
            invocation: start.invocation.clone(),
            nexus_rebuild: start.nexus_rebuild.clone(),
            rebuild_requested: start.rebuild_requested,
            orchestration_token_sha256: start.orchestration_token_sha256.clone(),
            run_nonce: start.nonce.clone(),
            completed_unix_nanos: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("fixture clock")
                .as_nanos(),
            installed_path: String::from(TLA_TOOLCHAIN_INSTALLED_PATH),
            installed_bytes: toolchain.jar.bytes,
            installed_sha256: toolchain.jar.sha256.clone(),
            reported_version: String::from(TLA_TOOLCHAIN_VERSION_LINE),
            toolchain: toolchain.clone(),
        };
        write_json(&root.join(FORMAL_VERIFIER_RECEIPT), &verifier);
        let verifier_bytes =
            fs::read(root.join(FORMAL_VERIFIER_RECEIPT)).expect("read verifier receipt");
        let verifier_file = read_regular_file_stable(
            &root.join(FORMAL_VERIFIER_RECEIPT),
            "fixture verifier receipt",
        )
        .expect("read stable verifier receipt");
        let formal_verifier =
            formal_verifier_binding(&verifier_file, &verifier).expect("formal verifier binding");

        let by_path: BTreeMap<_, _> = artifacts
            .iter()
            .map(|artifact| (artifact.path.clone(), artifact.clone()))
            .collect();
        let model_artifacts: Vec<_> = model_spec_artifacts(&SPECS)
            .into_iter()
            .map(|(path, _)| by_path.get(&path).expect("model artifact").clone())
            .collect();
        let model: GateReceipt = gate_receipt(
            MODEL_SPEC_SCHEMA,
            &start,
            ["reference-model", "formal-specifications"],
            Some(sha256(&verifier_bytes)),
            model_artifacts,
        )
        .expect("model receipt");
        write_json(&root.join(MODEL_SPEC_RECEIPT), &model);
        let model_bytes = fs::read(root.join(MODEL_SPEC_RECEIPT)).expect("read model receipt");

        let completion: GateReceipt = gate_receipt(
            COMPLETE_SCHEMA,
            &start,
            COMPLETE_STAGES,
            Some(sha256(&model_bytes)),
            artifacts.clone(),
        )
        .expect("completion receipt");
        write_json(&root.join(COMPLETION_RECEIPT), &completion);
        let completion_bytes =
            fs::read(root.join(COMPLETION_RECEIPT)).expect("read completion receipt");

        let manifest = Manifest {
            schema: SCHEMA,
            status: "passed",
            command: start.invocation.clone(),
            revision: start.revision.clone(),
            source_sha256: start.source_sha256.clone(),
            worktree_dirty: start.worktree_dirty,
            nexus_rebuild: start.nexus_rebuild.clone(),
            rebuild_requested: start.rebuild_requested,
            orchestration_token_sha256: start.orchestration_token_sha256.clone(),
            run_nonce: start.nonce.clone(),
            completion_receipt_sha256: sha256(&completion_bytes),
            started_unix_nanos: start.started_unix_nanos,
            generated_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("fixture clock")
                .as_secs(),
            formal_verifier,
            boundaries: Boundaries::current(),
            specifications: SPECS.iter().map(|spec| String::from(*spec)).collect(),
            stages: stage_population(),
            artifacts,
        };
        write_json(&root.join(MANIFEST_PATH), &manifest);
    }

    fn rewrite_checksum_index_from_payload(bundle: &Path) {
        let previous =
            parse_checksum_index(&fs::read(bundle.join(CHECKSUMS)).expect("read checksum index"))
                .expect("parse checksum index");
        let rewritten: BTreeMap<_, _> = previous
            .keys()
            .map(|relative| {
                let bytes = fs::read(bundle.join(relative)).expect("read bundle payload");
                (relative.clone(), sha256(&bytes))
            })
            .collect();
        fs::remove_file(bundle.join(CHECKSUMS)).expect("remove old checksums");
        write_checksum_index(bundle, &rewritten).expect("rewrite checksums");
    }

    fn reseal_after_formal_verifier_mutation(bundle: &Path) {
        let verifier_path = bundle.join(FORMAL_VERIFIER_RECEIPT);
        let verifier: Value =
            serde_json::from_slice(&fs::read(&verifier_path).expect("read verifier receipt"))
                .expect("parse verifier receipt");
        let verifier_bytes = fs::read(&verifier_path).expect("reread verifier receipt");
        let verifier_sha256 = sha256(&verifier_bytes);

        let model_path = bundle.join(MODEL_SPEC_RECEIPT);
        let mut model: Value =
            serde_json::from_slice(&fs::read(&model_path).expect("read model receipt"))
                .expect("parse model receipt");
        model["prerequisite_sha256"] = Value::String(verifier_sha256.clone());
        write_json(&model_path, &model);
        let model_sha256 = sha256(&fs::read(&model_path).expect("reread model receipt"));

        let completion_path = bundle.join(COMPLETION_RECEIPT);
        let mut completion: Value =
            serde_json::from_slice(&fs::read(&completion_path).expect("read completion receipt"))
                .expect("parse completion receipt");
        completion["prerequisite_sha256"] = Value::String(model_sha256);
        write_json(&completion_path, &completion);
        let completion_sha256 =
            sha256(&fs::read(&completion_path).expect("reread completion receipt"));

        let manifest_path = bundle.join(MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse manifest");
        manifest["formal_verifier"]["toolchain"] = verifier["toolchain"].clone();
        manifest["formal_verifier"]["runtime_receipt"]["bytes"] = Value::from(verifier_bytes.len());
        manifest["formal_verifier"]["runtime_receipt"]["sha256"] = Value::String(verifier_sha256);
        manifest["completion_receipt_sha256"] = Value::String(completion_sha256);
        write_json(&manifest_path, &manifest);
        rewrite_checksum_index_from_payload(bundle);
    }

    fn reseal_after_model_receipt_mutation(bundle: &Path) {
        let model_path = bundle.join(MODEL_SPEC_RECEIPT);
        let model_sha256 = sha256(&fs::read(&model_path).expect("read model receipt"));
        let completion_path = bundle.join(COMPLETION_RECEIPT);
        let mut completion: Value =
            serde_json::from_slice(&fs::read(&completion_path).expect("read completion receipt"))
                .expect("parse completion receipt");
        completion["prerequisite_sha256"] = Value::String(model_sha256);
        write_json(&completion_path, &completion);

        let manifest_path = bundle.join(MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse manifest");
        manifest["completion_receipt_sha256"] = Value::String(sha256(
            &fs::read(&completion_path).expect("reread completion receipt"),
        ));
        write_json(&manifest_path, &manifest);
        rewrite_checksum_index_from_payload(bundle);
    }

    #[test]
    fn complete_bundle_round_trips_and_has_an_exact_file_population() {
        let root = fixture();
        write_source_fixture(&root);
        let bundle = write_bundle(&root, &SPECS).expect("write complete bundle");
        let manifest: PublishedManifest = serde_json::from_slice(
            &fs::read(root.join(MANIFEST_PATH)).expect("read source manifest"),
        )
        .expect("parse source manifest");
        let checkout = SourceSnapshot {
            revision: manifest.revision.clone(),
            source_sha256: manifest.source_sha256.clone(),
            worktree_dirty: false,
        };
        validate_checkout_binding(&manifest, &checkout).expect("matching clean checkout");
        verify_bundle_directory(&bundle, &SPECS).expect("verify complete bundle internally");
        assert_eq!(manifest.specifications.len(), 12);
        assert_eq!(manifest.stages.len(), 17);
        assert_eq!(manifest.artifacts.len(), 52);
        assert_eq!(
            toolchain_files(&manifest.formal_verifier.toolchain).len(),
            4
        );

        let files = collect_files(&bundle).expect("collect bundle files");
        assert_eq!(files.len(), 62);
        let sums =
            parse_checksum_index(&fs::read(bundle.join(CHECKSUMS)).expect("read checksum index"))
                .expect("parse checksum index");
        assert_eq!(sums.len(), 61);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn bundle_rejects_artifact_mutation_even_with_a_rewritten_checksum_index() {
        let root = fixture();
        write_source_fixture(&root);
        let bundle = write_bundle(&root, &SPECS).expect("write complete bundle");
        let artifact = required_artifacts(&SPECS)[0].0.clone();
        fs::write(bundle.join(&artifact), "mutated\n").expect("mutate artifact");

        let mut sums =
            parse_checksum_index(&fs::read(bundle.join(CHECKSUMS)).expect("read checksum index"))
                .expect("parse checksum index");
        sums.insert(artifact, sha256(b"mutated\n"));
        fs::remove_file(bundle.join(CHECKSUMS)).expect("remove old checksums");
        write_checksum_index(&bundle, &sums).expect("rewrite checksums");

        let error = verify_bundle_directory(&bundle, &SPECS)
            .expect_err("manifest digest must reject mutation")
            .to_string();
        assert!(error.contains("disagree with manifest"));
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn bundle_rejects_every_toolchain_file_mutation_with_rewritten_checksums() {
        let expected = expected_toolchain_receipt();
        let paths: Vec<_> = toolchain_files(&expected)
            .into_iter()
            .map(|file| file.path.clone())
            .collect();

        for path in paths {
            let root = fixture();
            write_source_fixture(&root);
            let bundle = write_bundle(&root, &SPECS).expect("write complete bundle");
            fs::write(bundle.join(&path), b"mutated pinned toolchain\n")
                .expect("mutate toolchain file");
            rewrite_checksum_index_from_payload(&bundle);

            let error = verify_bundle_directory(&bundle, &SPECS)
                .expect_err("manifest toolchain receipt must reject payload mutation")
                .to_string();
            assert!(
                error.contains("pinned verification toolchain bytes"),
                "toolchain mutation for {path} returned an unexpected error: {error}"
            );
            fs::remove_dir_all(root).expect("remove fixture");
        }
    }

    #[test]
    fn bundle_rejects_resealed_static_descriptor_and_payload_substitutions() {
        let descriptor = expected_toolchain_receipt();
        for (field, path) in [
            ("jar", descriptor.jar.path),
            ("provenance", descriptor.provenance.path),
            ("license", descriptor.license.path),
            ("checksum_index", descriptor.checksum_index.path),
        ] {
            let root = fixture();
            write_source_fixture(&root);
            let bundle = write_bundle(&root, &SPECS).expect("write complete bundle");
            let substitute = format!("resealed substitute for {field}\n").into_bytes();
            fs::write(bundle.join(&path), &substitute).expect("mutate verifier payload");

            let verifier_path = bundle.join(FORMAL_VERIFIER_RECEIPT);
            let mut verifier: Value =
                serde_json::from_slice(&fs::read(&verifier_path).expect("read verifier receipt"))
                    .expect("parse verifier receipt");
            verifier["toolchain"][field]["bytes"] = Value::from(substitute.len());
            verifier["toolchain"][field]["sha256"] = Value::String(sha256(&substitute));
            if field == "jar" {
                verifier["installed_bytes"] = Value::from(substitute.len());
                verifier["installed_sha256"] = Value::String(sha256(&substitute));
            }
            write_json(&verifier_path, &verifier);
            reseal_after_formal_verifier_mutation(&bundle);

            let error = verify_bundle_directory(&bundle, &SPECS)
                .expect_err("canonical verifier contract must reject a resealed substitute")
                .to_string();
            assert!(
                error.contains("toolchain receipt differs from the pinned contract"),
                "resealed {field} substitute returned an unexpected error: {error}"
            );
            fs::remove_dir_all(root).expect("remove fixture");
        }
    }

    #[test]
    fn bundle_rejects_resealed_runtime_identity_mutations() {
        for field in [
            "installed_path",
            "installed_bytes",
            "installed_sha256",
            "reported_version",
            "start_record_sha256",
            "run_nonce",
        ] {
            let root = fixture();
            write_source_fixture(&root);
            let bundle = write_bundle(&root, &SPECS).expect("write complete bundle");
            let verifier_path = bundle.join(FORMAL_VERIFIER_RECEIPT);
            let mut verifier: Value =
                serde_json::from_slice(&fs::read(&verifier_path).expect("read verifier receipt"))
                    .expect("parse verifier receipt");
            verifier[field] = match field {
                "installed_bytes" => Value::from(1_u64),
                "installed_path" => Value::String(String::from("/tmp/substitute.jar")),
                "reported_version" => Value::String(String::from("TLC2 Version substitute")),
                _ => Value::String("0".repeat(64)),
            };
            write_json(&verifier_path, &verifier);
            reseal_after_formal_verifier_mutation(&bundle);

            let error = verify_bundle_directory(&bundle, &SPECS)
                .expect_err("runtime verifier identity mutation must be rejected after resealing")
                .to_string();
            assert!(
                error.contains("formal verifier receipt does not bind"),
                "resealed runtime field {field} returned an unexpected error: {error}"
            );
            fs::remove_dir_all(root).expect("remove fixture");
        }
    }

    #[test]
    fn bundle_rejects_a_resealed_missing_model_verifier_prerequisite() {
        let root = fixture();
        write_source_fixture(&root);
        let bundle = write_bundle(&root, &SPECS).expect("write complete bundle");
        let model_path = bundle.join(MODEL_SPEC_RECEIPT);
        let mut model: Value =
            serde_json::from_slice(&fs::read(&model_path).expect("read model receipt"))
                .expect("parse model receipt");
        model["prerequisite_sha256"] = Value::Null;
        write_json(&model_path, &model);
        reseal_after_model_receipt_mutation(&bundle);

        let error = verify_bundle_directory(&bundle, &SPECS)
            .expect_err("model receipt must retain the verifier prerequisite")
            .to_string();
        assert!(error.contains("prerequisite"));
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn bundle_rejects_same_boot_oracle_mutation_with_rewritten_checksums() {
        let root = fixture();
        write_source_fixture(&root);
        let bundle = write_bundle(&root, &SPECS).expect("write complete bundle");
        let artifact = "kernel/nexus-ostd/artifacts/runtime-fs-same-boot-precommit/oracle.log";
        assert!(
            required_artifacts(&SPECS)
                .iter()
                .any(|(path, _)| path == artifact)
        );
        fs::write(bundle.join(artifact), "mutated same-boot oracle\n")
            .expect("mutate same-boot oracle");
        rewrite_checksum_index_from_payload(&bundle);

        let error = verify_bundle_directory(&bundle, &SPECS)
            .expect_err("manifest digest must reject same-boot oracle mutation")
            .to_string();
        assert!(error.contains("disagree with manifest"));
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn bundle_rejects_a_resealed_but_broken_receipt_chain() {
        let root = fixture();
        write_source_fixture(&root);
        let bundle = write_bundle(&root, &SPECS).expect("write complete bundle");

        let completion_path = bundle.join(COMPLETION_RECEIPT);
        let mut completion: Value =
            serde_json::from_slice(&fs::read(&completion_path).expect("read completion receipt"))
                .expect("parse completion receipt");
        completion["prerequisite_sha256"] = Value::String("0".repeat(64));
        write_json(&completion_path, &completion);

        let manifest_path = bundle.join(MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse manifest");
        manifest["completion_receipt_sha256"] = Value::String(sha256(
            &fs::read(&completion_path).expect("read changed receipt"),
        ));
        write_json(&manifest_path, &manifest);
        rewrite_checksum_index_from_payload(&bundle);

        let error = verify_bundle_directory(&bundle, &SPECS)
            .expect_err("receipt prerequisite must reject mutation")
            .to_string();
        assert!(error.contains("prerequisite"));
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn bundle_rejects_research_boundary_drift_with_consistent_checksums() {
        let root = fixture();
        write_source_fixture(&root);
        let bundle = write_bundle(&root, &SPECS).expect("write complete bundle");

        let manifest_path = bundle.join(MANIFEST_PATH);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse manifest");
        manifest["boundaries"]["smp_checked"] = Value::Bool(true);
        write_json(&manifest_path, &manifest);
        rewrite_checksum_index_from_payload(&bundle);

        let error = verify_bundle_directory(&bundle, &SPECS)
            .expect_err("research boundary drift must be rejected")
            .to_string();
        assert!(error.contains("research boundaries"));
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn bundle_rejects_every_nonempty_stage_evidence_drift_with_consistent_checksums() {
        let root = fixture();
        write_source_fixture(&root);
        let bundle = write_bundle(&root, &SPECS).expect("write complete bundle");
        let manifest_path = bundle.join(MANIFEST_PATH);
        let original: Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse manifest");
        let stage_count = original["stages"]
            .as_array()
            .expect("manifest stage array")
            .len();

        for index in 0..stage_count {
            let mut manifest = original.clone();
            manifest["stages"][index]["evidence"] = Value::Array(vec![Value::String(format!(
                "target/verification/forged-stage-{index}.log"
            ))]);
            write_json(&manifest_path, &manifest);
            rewrite_checksum_index_from_payload(&bundle);

            let error = verify_bundle_directory(&bundle, &SPECS)
                .expect_err("canonical stage evidence must reject nonempty drift")
                .to_string();
            assert!(
                error.contains("stage population"),
                "stage {index} drift returned an unexpected error: {error}"
            );
        }

        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn public_bundle_binding_rejects_revision_source_and_dirty_drift() {
        let root = fixture();
        write_source_fixture(&root);
        let mut manifest: PublishedManifest = serde_json::from_slice(
            &fs::read(root.join(MANIFEST_PATH)).expect("read source manifest"),
        )
        .expect("parse source manifest");
        let matching = SourceSnapshot {
            revision: manifest.revision.clone(),
            source_sha256: manifest.source_sha256.clone(),
            worktree_dirty: false,
        };
        validate_checkout_binding(&manifest, &matching).expect("matching clean checkout");

        let mut changed_revision = matching.clone();
        changed_revision.revision.push('0');
        assert!(validate_checkout_binding(&manifest, &changed_revision).is_err());

        let mut changed_source = matching.clone();
        changed_source.source_sha256 = "f".repeat(64);
        assert!(validate_checkout_binding(&manifest, &changed_source).is_err());

        let mut dirty = matching;
        dirty.worktree_dirty = true;
        let error = validate_checkout_binding(&manifest, &dirty)
            .expect_err("dirty checkout must be rejected")
            .to_string();
        assert!(error.contains("clean checkout"));

        manifest.worktree_dirty = true;
        let error = validate_checkout_binding(
            &manifest,
            &SourceSnapshot {
                revision: manifest.revision.clone(),
                source_sha256: manifest.source_sha256.clone(),
                worktree_dirty: false,
            },
        )
        .expect_err("dirty manifest must be rejected")
        .to_string();
        assert!(error.contains("manifest was not produced from a clean checkout"));
        manifest.worktree_dirty = false;

        manifest.command = String::from("./x test --full");
        let error = validate_checkout_binding(
            &manifest,
            &SourceSnapshot {
                revision: manifest.revision.clone(),
                source_sha256: manifest.source_sha256.clone(),
                worktree_dirty: false,
            },
        )
        .expect_err("noncanonical full invocation must be rejected")
        .to_string();
        assert!(error.contains("canonical ./x verify"));

        manifest.command = String::from("./x verify");
        manifest.nexus_rebuild = None;
        manifest.rebuild_requested = false;
        let error = validate_checkout_binding(
            &manifest,
            &SourceSnapshot {
                revision: manifest.revision.clone(),
                source_sha256: manifest.source_sha256.clone(),
                worktree_dirty: false,
            },
        )
        .expect_err("noncold bundle must be rejected")
        .to_string();
        assert!(error.contains("NEXUS_REBUILD=1"));
        fs::remove_dir_all(root).expect("remove fixture");
    }
}
