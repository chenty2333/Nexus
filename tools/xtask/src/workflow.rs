use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const TLA2TOOLS_DIRECTORY: &str = "third_party/tlaplus/1.8.0-227f61b";
const TLA2TOOLS_JAR_NAME: &str = "tla2tools-227f61b.jar";
const TLA2TOOLS_SHA256: &str = "33de7da9ce1b7fffb9d1c184021178dbb051747be48504e65c584c423721a32e";
const TLA2TOOLS_BYTES: usize = 4_357_904;
const TLA2TOOLS_LICENSE_SHA256: &str =
    "3fa3a845ce5eb7b9b3508701dc1aa4d084b6b2c27cbae8cd44d277d10ee411bf";
const TLA2TOOLS_SHA256SUMS: &str =
    "33de7da9ce1b7fffb9d1c184021178dbb051747be48504e65c584c423721a32e  tla2tools-227f61b.jar\n";
const TLA2TOOLS_LICENSE_PATH: &str = "third_party/tlaplus/1.8.0-227f61b/LICENSE.upstream";
const TLA2TOOLS_LICENSE_PATHSPEC_EXCLUSION: &str =
    ":(exclude)third_party/tlaplus/1.8.0-227f61b/LICENSE.upstream";
const TLA2TOOLS_IMAGE_INPUTS: [&str; 4] = [
    "third_party/tlaplus/1.8.0-227f61b/tla2tools-227f61b.jar",
    "third_party/tlaplus/1.8.0-227f61b/SHA256SUMS",
    "third_party/tlaplus/1.8.0-227f61b/PROVENANCE.json",
    TLA2TOOLS_LICENSE_PATH,
];
const TLA2TOOLS_DOCKER_INSTALL: &str = r#"COPY --chmod=0444 third_party/tlaplus/1.8.0-227f61b/tla2tools-227f61b.jar \
    /opt/tla2tools/tla2tools.jar
COPY --chmod=0444 third_party/tlaplus/1.8.0-227f61b/SHA256SUMS \
    third_party/tlaplus/1.8.0-227f61b/PROVENANCE.json \
    third_party/tlaplus/1.8.0-227f61b/LICENSE.upstream \
    /opt/tla2tools/
RUN echo "${TLA2TOOLS_SHA256}  /opt/tla2tools/tla2tools.jar" | sha256sum -c - \
    && version_output=$(java -cp /opt/tla2tools/tla2tools.jar tlc2.TLC -version 2>&1 || true) \
    && version_line=$(printf '%s\n' "$version_output" | sed -n '/./{p;q;}') \
    && test "$version_line" = \
        "TLC2 Version ${TLA2TOOLS_TLC_VERSION} (rev: ${TLA2TOOLS_REVISION_SHORT})" \
    && chmod 0555 /opt/tla2tools"#;
const TLA2TOOLS_UPSTREAM_LICENSE: &str = r#"MIT License

Copyright (c) 199? HP Corporation
Copyright (c) 2003 Microsoft Corporation
Copyright (c) 2023 Linux Foundation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"#;

pub(crate) struct Summary {
    pub(crate) shell_sources: usize,
    pub(crate) pinned_actions: usize,
}

pub(crate) fn validate(root: &Path) -> Result<Summary> {
    let files = repository_files(root)?;
    let mut shell_sources = 0;
    for relative in files.iter().filter(|path| shell_source(path)) {
        validate_shell_declaration(root, relative)?;
        shell_sources += 1;
    }
    if shell_sources == 0 {
        return Err("no shell workflow sources were discovered".into());
    }

    let workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))?;
    validate_workflow_yaml(&workflow)?;
    validate_checkout_fetch_depth(&workflow)?;
    validate_release_metadata(root)?;
    for required in [
        "workflow_dispatch:",
        "concurrency:",
        "run: ./x verify",
        "NEXUS_REBUILD: \"1\"",
        "target/verification/artifact-bundle",
        "nexus-verification-bundle-${{ github.run_attempt }}",
        "include-hidden-files: true",
    ] {
        if !workflow.contains(required) {
            return Err(format!("CI workflow is missing Stage 7A contract: {required}").into());
        }
    }
    let pinned_actions = validate_pinned_actions(&workflow)?;

    let frontdoor = fs::read_to_string(root.join("x"))?;
    validate_full_verify_order(&frontdoor)?;
    validate_same_boot_acceptance_route(&frontdoor)?;
    validate_production_identity_route(&frontdoor)?;
    validate_image_identity_inputs(&frontdoor)?;

    let dockerfile = fs::read_to_string(root.join("Dockerfile"))?;
    for required in [
        "@sha256:",
        "TLA2TOOLS_SHA256",
        "GIT_PACKAGE_VERSION",
        "CARGO_NET_OFFLINE=true",
    ] {
        if !dockerfile.contains(required) {
            return Err(format!("root Dockerfile is missing pinned boundary: {required}").into());
        }
    }
    validate_vendored_tla2tools(root, &dockerfile)?;

    let readme = fs::read_to_string(root.join("README.md"))?;
    for command in [
        "doctor",
        "build",
        "test",
        "run",
        "verify",
        "verify-bundle",
        "clean",
    ] {
        if !readme.contains(&format!("./x {command}")) {
            return Err(format!("README lacks public command: ./x {command}").into());
        }
    }

    for (args, label) in [
        (
            &[
                "diff",
                "--check",
                "--",
                ".",
                TLA2TOOLS_LICENSE_PATHSPEC_EXCLUSION,
            ][..],
            "git diff --check rejected the working tree",
        ),
        (
            &[
                "diff",
                "--cached",
                "--check",
                "--",
                ".",
                TLA2TOOLS_LICENSE_PATHSPEC_EXCLUSION,
            ][..],
            "git diff --cached --check rejected the staged snapshot",
        ),
        (
            // Treat pure moves as renames so historical whitespace in an
            // unchanged file is not misclassified as newly added content.
            &[
                "diff-tree",
                "--check",
                "--no-commit-id",
                "--root",
                "-r",
                "-m",
                "-M",
                "HEAD",
                "--",
                ".",
                TLA2TOOLS_LICENSE_PATHSPEC_EXCLUSION,
            ][..],
            "git diff-tree --check rejected the checked-out revision",
        ),
    ] {
        let status = Command::new("git").current_dir(root).args(args).status()?;
        if !status.success() {
            return Err(label.into());
        }
    }

    Ok(Summary {
        shell_sources,
        pinned_actions,
    })
}

fn validate_full_verify_order(frontdoor: &str) -> Result<()> {
    let (_, tail) = frontdoor
        .split_once("verify_all() {")
        .ok_or("root workflow lacks verify_all")?;
    let (body, _) = tail
        .split_once("\n}")
        .ok_or("root verify_all body is not terminated")?;
    for required in [
        "local verify_token",
        "NEXUS_VERIFY_INVOCATION",
        "run_xtask begin",
        "run_xtask verify",
        "run_system",
        "run_same_boot_acceptance",
        "eval-stage7b",
        "run_xtask stage7b-evidence",
        "run_xtask complete",
        "run_xtask manifest",
        "run_xtask bundle",
    ] {
        if !body.contains(required) {
            return Err(format!("root verify_all lacks ordered stage: {required}").into());
        }
    }
    let mut remainder = body;
    for stage in [
        "run_xtask begin",
        "run_xtask verify",
        "run_system",
        "run_same_boot_acceptance",
        "eval-stage7b",
        "run_xtask stage7b-evidence",
        "run_xtask complete",
        "run_xtask manifest",
        "run_xtask bundle",
    ] {
        let (_, after) = remainder
            .split_once(stage)
            .ok_or_else(|| format!("root verify_all stage is missing or out of order: {stage}"))?;
        remainder = after;
    }
    if !frontdoor.contains("token_environment=(--env \"NEXUS_VERIFY_TOKEN=$verify_token\")") {
        return Err(
            "root workflow does not pass its orchestration token to evidence sealing".into(),
        );
    }
    if !frontdoor
        .contains("if [[ $command == begin || $command == complete || $command == manifest ]]")
    {
        return Err(
            "root workflow does not restrict token injection to begin/complete/manifest".into(),
        );
    }
    Ok(())
}

fn validate_same_boot_acceptance_route(frontdoor: &str) -> Result<()> {
    let (_, tail) = frontdoor
        .split_once("run_same_boot_acceptance() {")
        .ok_or("root workflow lacks run_same_boot_acceptance")?;
    let (body, _) = tail
        .split_once("\n}")
        .ok_or("root same-boot acceptance body is not terminated")?;
    let positive =
        "run_backend \"$kernel_backend\" test-same-boot \"Nexus same-boot production filesystem\"";
    let precommit = "run_backend \"$kernel_backend\" test-same-boot-precommit \"Nexus same-boot precommit revocation\"";
    let (_, after_positive) = body
        .split_once(positive)
        .ok_or("root same-boot acceptance lacks the positive production gate")?;
    if !after_positive.contains(precommit) {
        return Err("root same-boot acceptance lacks ordered precommit revocation gate".into());
    }
    if body.matches("run_backend ").count() != 2 {
        return Err("root same-boot acceptance has an unexpected backend population".into());
    }
    Ok(())
}

fn validate_production_identity_route(frontdoor: &str) -> Result<()> {
    for required in [
        "research production-identity",
        "doctor|build|test|run|fmt|check|quick|model|spec|system|research|verify|verify-bundle|clean",
        "research requires exactly one target: production-identity",
        "production-identity) run_xtask research production-identity",
        "unknown research target: $1",
    ] {
        if !frontdoor.contains(required) {
            return Err(format!(
                "root workflow lacks prospective production-identity route: {required}"
            )
            .into());
        }
    }
    Ok(())
}

fn validate_image_identity_inputs(frontdoor: &str) -> Result<()> {
    let (_, tail) = frontdoor
        .split_once("compute_image_identity() {")
        .ok_or("root workflow lacks compute_image_identity")?;
    let (body, _) = tail
        .split_once("\n}")
        .ok_or("root compute_image_identity body is not terminated")?;
    let (_, hash_tail) = body
        .split_once("image_key=$(sha256sum \\")
        .ok_or("root image identity lacks its sha256sum input pipeline")?;
    let (hash_inputs, _) = hash_tail
        .split_once("| cut -d ' ' -f1 | sha256sum | cut -c1-16)")
        .ok_or("root image identity lacks its canonical digest pipeline")?;

    let mut remainder = hash_inputs;
    for relative in TLA2TOOLS_IMAGE_INPUTS {
        let rendered = format!("\"$root/{relative}\"");
        if hash_inputs.matches(&rendered).count() != 1 {
            return Err(format!(
                "root image identity must hash vendored TLA+ input exactly once: {relative}"
            )
            .into());
        }
        let (_, after) = remainder.split_once(&rendered).ok_or_else(|| {
            format!("root image identity has out-of-order vendored TLA+ input: {relative}")
        })?;
        remainder = after;
    }
    Ok(())
}

fn validate_vendored_tla2tools(root: &Path, dockerfile: &str) -> Result<()> {
    validate_vendored_tla2tools_files(root)?;
    validate_tla2tools_docker_contract(dockerfile)
}

fn validate_vendored_tla2tools_files(root: &Path) -> Result<()> {
    let directory = root.join(TLA2TOOLS_DIRECTORY);
    let directory_metadata = fs::symlink_metadata(&directory).map_err(|error| {
        format!(
            "vendored TLA+ directory metadata failed for {}: {error}",
            directory.display()
        )
    })?;
    if !directory_metadata.file_type().is_dir() {
        return Err(format!(
            "vendored TLA+ path must be a real directory, not a symlink: {}",
            directory.display()
        )
        .into());
    }

    let mut population = fs::read_dir(&directory)?
        .map(|entry| {
            let entry = entry?;
            entry.file_name().into_string().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "vendored TLA+ directory contains a non-UTF-8 name",
                )
            })
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    population.sort();
    let expected_population = [
        "LICENSE.upstream",
        "PROVENANCE.json",
        "SHA256SUMS",
        TLA2TOOLS_JAR_NAME,
    ];
    if population != expected_population {
        return Err(
            format!("vendored TLA+ directory has unexpected population: {population:?}").into(),
        );
    }

    let jar_path = directory.join(TLA2TOOLS_JAR_NAME);
    let jar = read_regular_vendored_file(&jar_path, "TLA+ tools JAR")?;
    if jar.len() != TLA2TOOLS_BYTES {
        return Err(format!(
            "vendored TLA+ tools JAR has unexpected size: expected {TLA2TOOLS_BYTES}, got {}",
            jar.len()
        )
        .into());
    }
    let jar_sha256 = sha256(&jar);
    if jar_sha256 != TLA2TOOLS_SHA256 {
        return Err(format!(
            "vendored TLA+ tools JAR digest mismatch: expected {TLA2TOOLS_SHA256}, got {jar_sha256}"
        )
        .into());
    }

    let sums_path = directory.join("SHA256SUMS");
    let sums = read_regular_vendored_file(&sums_path, "vendored TLA+ SHA256SUMS")?;
    if sums != TLA2TOOLS_SHA256SUMS.as_bytes() {
        return Err("vendored TLA+ SHA256SUMS does not name the exact pinned JAR digest".into());
    }

    let provenance_path = directory.join("PROVENANCE.json");
    let provenance = read_regular_vendored_file(&provenance_path, "vendored TLA+ provenance")?;
    let parsed: serde_json::Value = serde_json::from_slice(&provenance)
        .map_err(|error| format!("vendored TLA+ provenance is not valid JSON: {error}"))?;
    if parsed != expected_tla2tools_provenance() {
        return Err("vendored TLA+ provenance fields do not match the audited artifact".into());
    }

    let license_path = directory.join("LICENSE.upstream");
    let license = read_regular_vendored_file(&license_path, "vendored TLA+ upstream license")?;
    let license_sha256 = sha256(&license);
    if license_sha256 != TLA2TOOLS_LICENSE_SHA256
        || license != TLA2TOOLS_UPSTREAM_LICENSE.as_bytes()
    {
        return Err(format!(
            "vendored TLA+ upstream license mismatch: expected {TLA2TOOLS_LICENSE_SHA256}, got {license_sha256}"
        )
        .into());
    }
    Ok(())
}

fn read_regular_vendored_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label} metadata failed for {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular non-symlink file: {}",
            path.display()
        )
        .into());
    }
    Ok(fs::read(path)?)
}

fn expected_tla2tools_provenance() -> serde_json::Value {
    serde_json::json!({
        "schema": "nexus.toolchain-provenance.v1",
        "name": "tla2tools-227f61b.jar",
        "jar_sha256": "33de7da9ce1b7fffb9d1c184021178dbb051747be48504e65c584c423721a32e",
        "jar_bytes": 4357904,
        "tlc_version": "2026.07.09.134028",
        "upstream_repository": "https://github.com/tlaplus/tlaplus",
        "upstream_source_revision": "227f61b983d0203a06db8184da45aed421e8f1b8",
        "upstream_source_revision_verification": "github-verified",
        "upstream_release_name": "v1.8.0",
        "upstream_release_prerelease_at_audit": true,
        "upstream_release_immutable_at_audit": false,
        "upstream_release_tag_revision_at_audit": "4ba7d8811289fb8e95dac4d5e554c05216ba3100",
        "upstream_asset_id": 471380474,
        "upstream_asset_created_at": "2026-07-09T13:46:11Z",
        "upstream_asset_uploader": "github-actions[bot]",
        "upstream_asset_status_at_audit": "deleted-and-replaced-by-upstream-workflow",
        "upstream_workflow_run": "https://github.com/tlaplus/tlaplus/actions/runs/29021387576",
        "build_jdk": "17.0.19+10 (Eclipse Adoptium)",
        "build_timestamp": "2026-07-09T13:40:28.65Z",
        "payload_without_manifest_canonical_sha256": "c21eb5e8de4f92341de33aa89c90e4c48fb15dd9c46b34665fa37786fede49c6",
        "recovered_from_local_oci_image": {
            "tag": "nexus/cser-dev:39ba912937340427",
            "manifest_digest": "sha256:7ef14abd728ad24afb20b9f1274fc60b14facff8d146e4a6e5fccea18ab2a09f"
        },
        "audited_at": "2026-07-14"
    })
}

fn validate_tla2tools_docker_contract(dockerfile: &str) -> Result<()> {
    if dockerfile
        .to_ascii_lowercase()
        .contains("tlaplus/tlaplus/releases")
    {
        return Err(
            "root Dockerfile must not fetch TLA+ tools from a mutable upstream release URL".into(),
        );
    }

    for (needle, label) in [
        (
            "ARG TLA2TOOLS_SHA256=33de7da9ce1b7fffb9d1c184021178dbb051747be48504e65c584c423721a32e",
            "TLA+ JAR digest argument",
        ),
        (
            "ARG TLA2TOOLS_TLC_VERSION=2026.07.09.134028",
            "TLC version argument",
        ),
        (
            "ARG TLA2TOOLS_REVISION_SHORT=227f61b",
            "TLC source revision argument",
        ),
        (
            "TLA2TOOLS_JAR=/opt/tla2tools/tla2tools.jar",
            "installed TLA+ JAR environment",
        ),
        (TLA2TOOLS_DOCKER_INSTALL, "vendored TLA+ install block"),
    ] {
        require_exactly_once(dockerfile, needle, label)?;
    }

    for (needle, expected) in [
        ("ARG TLA2TOOLS_", 3),
        ("third_party/tlaplus/1.8.0-227f61b/", 4),
        ("/opt/tla2tools", 6),
        ("TLA2TOOLS_SHA256", 2),
        ("TLA2TOOLS_TLC_VERSION", 2),
        ("TLA2TOOLS_REVISION_SHORT", 2),
    ] {
        let actual = dockerfile.matches(needle).count();
        if actual != expected {
            return Err(format!(
                "root Dockerfile has unexpected vendored TLA+ contract population for {needle}: expected {expected}, got {actual}"
            )
            .into());
        }
    }
    Ok(())
}

fn require_exactly_once(source: &str, needle: &str, label: &str) -> Result<()> {
    let count = source.matches(needle).count();
    if count != 1 {
        return Err(
            format!("root Dockerfile must contain exactly one {label}: found {count}").into(),
        );
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_workflow_yaml(workflow: &str) -> Result<()> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(workflow)
        .map_err(|error| format!("CI workflow is not valid YAML: {error}"))?;
    if !matches!(parsed, serde_yaml::Value::Mapping(_)) {
        return Err("CI workflow must be a top-level YAML mapping".into());
    }
    Ok(())
}

fn validate_release_metadata(root: &Path) -> Result<()> {
    let citation = fs::read_to_string(root.join("CITATION.cff"))?;
    validate_citation(&citation)?;
    let zenodo = fs::read_to_string(root.join(".zenodo.json"))?;
    validate_zenodo(&zenodo)
}

fn validate_citation(citation: &str) -> Result<()> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(citation)
        .map_err(|error| format!("CITATION.cff is not valid YAML: {error}"))?;
    for (field, expected) in [
        ("cff-version", "1.2.0"),
        ("title", "Nexus: Causally Scoped Effect Revocation"),
        ("type", "software"),
        ("version", "0.1.0"),
        ("date-released", "2026-07-14"),
        ("repository-code", "https://github.com/chenty2333/Nexus"),
        ("license", "Unlicense"),
    ] {
        if yaml_field(&parsed, field).and_then(serde_yaml::Value::as_str) != Some(expected) {
            return Err(format!("CITATION.cff has unexpected {field}").into());
        }
    }
    let authors = yaml_field(&parsed, "authors")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or("CITATION.cff authors must be a sequence")?;
    if authors.len() != 1 {
        return Err("CITATION.cff must name exactly one release author".into());
    }
    for (field, expected) in [
        ("family-names", "Chen"),
        ("given-names", "Tianyi"),
        ("affiliation", "Hangzhou Normal University"),
    ] {
        if yaml_field(&authors[0], field).and_then(serde_yaml::Value::as_str) != Some(expected) {
            return Err(format!("CITATION.cff author has unexpected {field}").into());
        }
    }
    Ok(())
}

fn validate_zenodo(zenodo: &str) -> Result<()> {
    let parsed: serde_json::Value = serde_json::from_str(zenodo)
        .map_err(|error| format!(".zenodo.json is not valid JSON: {error}"))?;
    for (field, expected) in [
        ("title", "Nexus: Causally Scoped Effect Revocation"),
        ("upload_type", "software"),
        ("access_right", "open"),
        ("license", "unlicense"),
        ("version", "0.1.0"),
    ] {
        if parsed.get(field).and_then(serde_json::Value::as_str) != Some(expected) {
            return Err(format!(".zenodo.json has unexpected {field}").into());
        }
    }
    let creators = parsed
        .get("creators")
        .and_then(serde_json::Value::as_array)
        .ok_or(".zenodo.json creators must be an array")?;
    if creators.len() != 1
        || creators[0].get("name").and_then(serde_json::Value::as_str) != Some("Chen, Tianyi")
        || creators[0]
            .get("affiliation")
            .and_then(serde_json::Value::as_str)
            != Some("Hangzhou Normal University")
    {
        return Err(".zenodo.json has an unexpected release creator".into());
    }
    Ok(())
}

fn validate_checkout_fetch_depth(workflow: &str) -> Result<usize> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(workflow)
        .map_err(|error| format!("CI workflow is not valid YAML: {error}"))?;
    let jobs = yaml_field(&parsed, "jobs")
        .and_then(serde_yaml::Value::as_mapping)
        .ok_or("CI workflow jobs must be a mapping")?;
    let mut checkouts = 0;
    for job in jobs.values() {
        let Some(steps) = yaml_field(job, "steps").and_then(serde_yaml::Value::as_sequence) else {
            continue;
        };
        for step in steps {
            let Some(uses) = yaml_field(step, "uses").and_then(serde_yaml::Value::as_str) else {
                continue;
            };
            if !uses.starts_with("actions/checkout@") {
                continue;
            }
            checkouts += 1;
            let depth = yaml_field(step, "with").and_then(|with| yaml_field(with, "fetch-depth"));
            let unshallow = match depth {
                Some(serde_yaml::Value::Number(number)) => number.as_u64() == Some(0),
                Some(serde_yaml::Value::String(value)) => value == "0",
                _ => false,
            };
            if !unshallow {
                return Err("every actions/checkout step must set fetch-depth: 0".into());
            }
        }
    }
    if checkouts == 0 {
        return Err("CI workflow has no actions/checkout step".into());
    }
    Ok(checkouts)
}

fn yaml_field<'a>(value: &'a serde_yaml::Value, field: &str) -> Option<&'a serde_yaml::Value> {
    value
        .as_mapping()?
        .get(serde_yaml::Value::String(String::from(field)))
}

fn validate_pinned_actions(workflow: &str) -> Result<usize> {
    let mut pinned_actions = 0;
    let mut has_checkout = false;
    let mut has_evidence_upload = false;

    for line in workflow.lines() {
        let entry = line.trim();
        let entry = entry.strip_prefix("- ").unwrap_or(entry).trim_start();
        let Some(uses) = entry.strip_prefix("uses:") else {
            continue;
        };
        let uses = uses
            .split_whitespace()
            .next()
            .ok_or("CI action uses entry is empty")?;
        let Some((action, revision)) = uses.rsplit_once('@') else {
            return Err(format!("CI action is not pinned: {uses}").into());
        };
        if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("CI action is not pinned to a 40-hex commit: {uses}").into());
        }

        has_checkout |= action == "actions/checkout";
        has_evidence_upload |= action == "actions/upload-artifact";
        pinned_actions += 1;
    }

    if !has_checkout {
        return Err("CI must pin an actions/checkout action".into());
    }
    if !has_evidence_upload {
        return Err("CI must pin an actions/upload-artifact evidence action".into());
    }

    Ok(pinned_actions)
}

fn repository_files(root: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .current_dir(root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!("git ls-files failed with {}", output.status).into());
    }
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| PathBuf::from(String::from_utf8_lossy(bytes).into_owned()))
        .filter(|path| root.join(path).is_file())
        .collect())
}

fn shell_source(path: &Path) -> bool {
    path == Path::new("x")
        || path.file_name().is_some_and(|name| name == "x")
        || path.extension().is_some_and(|extension| extension == "sh")
}

fn validate_shell_declaration(root: &Path, relative: &Path) -> Result<()> {
    let path = root.join(relative);
    let source = fs::read_to_string(&path)?;
    let shebang = source.lines().next().unwrap_or("");
    if !shebang.contains("bash") && !shebang.ends_with("/sh") && !shebang.contains("/sh ") {
        return Err(format!(
            "workflow shell source has no supported shebang: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    static FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);

    struct VendoredToolchainFixture {
        root: PathBuf,
    }

    impl VendoredToolchainFixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "nexus-vendored-tlaplus-{}-{}",
                std::process::id(),
                FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let source = repository_root().join(TLA2TOOLS_DIRECTORY);
            let destination = root.join(TLA2TOOLS_DIRECTORY);
            fs::create_dir_all(&destination).expect("create vendored-toolchain fixture");
            for name in [
                "LICENSE.upstream",
                "PROVENANCE.json",
                "SHA256SUMS",
                TLA2TOOLS_JAR_NAME,
            ] {
                fs::copy(source.join(name), destination.join(name))
                    .expect("copy vendored-toolchain fixture input");
            }
            Self { root }
        }

        fn directory(&self) -> PathBuf {
            self.root.join(TLA2TOOLS_DIRECTORY)
        }
    }

    impl Drop for VendoredToolchainFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn fixture_error(mutate: impl FnOnce(&Path)) -> String {
        let fixture = VendoredToolchainFixture::new();
        mutate(&fixture.directory());
        validate_vendored_tla2tools_files(&fixture.root)
            .expect_err("mutated vendored TLA+ toolchain must be rejected")
            .to_string()
    }

    fn valid_tla2tools_docker_contract() -> String {
        format!(
            "ARG TLA2TOOLS_SHA256={TLA2TOOLS_SHA256}\n\
             ARG TLA2TOOLS_TLC_VERSION=2026.07.09.134028\n\
             ARG TLA2TOOLS_REVISION_SHORT=227f61b\n\
             ENV TLA2TOOLS_JAR=/opt/tla2tools/tla2tools.jar\n\
             {TLA2TOOLS_DOCKER_INSTALL}\n"
        )
    }

    #[test]
    fn classifies_only_public_and_script_shell_sources() {
        assert!(shell_source(Path::new("x")));
        assert!(shell_source(Path::new("kernel/nexus-ostd/x")));
        assert!(shell_source(Path::new("scripts/check.sh")));
        assert!(!shell_source(Path::new("src/lib.rs")));
        assert!(!shell_source(Path::new("guest/probe.S")));
    }

    #[test]
    fn requires_all_vendored_tla2tools_inputs_in_the_image_identity() {
        let rendered = TLA2TOOLS_IMAGE_INPUTS
            .iter()
            .map(|relative| format!("    \"$root/{relative}\" \\\n"))
            .collect::<String>();
        let frontdoor = format!(
            "compute_image_identity() {{\n    image_key=$(sha256sum \\\n{rendered}    \"$root/Cargo.lock\" | cut -d ' ' -f1 | sha256sum | cut -c1-16)\n}}\n"
        );
        validate_image_identity_inputs(&frontdoor).expect("complete vendored image identity");

        for relative in TLA2TOOLS_IMAGE_INPUTS {
            let missing = frontdoor.replace(&format!("    \"$root/{relative}\" \\\n"), "");
            let error = validate_image_identity_inputs(&missing)
                .expect_err("missing vendored image input must be rejected")
                .to_string();
            assert!(error.contains(relative));
        }

        let reordered = frontdoor
            .replace(TLA2TOOLS_IMAGE_INPUTS[0], "FIRST")
            .replace(TLA2TOOLS_IMAGE_INPUTS[1], TLA2TOOLS_IMAGE_INPUTS[0])
            .replace("FIRST", TLA2TOOLS_IMAGE_INPUTS[1]);
        let error = validate_image_identity_inputs(&reordered)
            .expect_err("reordered vendored image inputs must be rejected")
            .to_string();
        assert!(error.contains("out-of-order"));
    }

    #[test]
    fn accepts_the_exact_vendored_tla2tools_files() {
        validate_vendored_tla2tools_files(&repository_root())
            .expect("repository vendored TLA+ toolchain must match its audit contract");
    }

    #[test]
    fn rejects_vendored_tla2tools_jar_size_digest_and_symlink_mutations() {
        let size_error = fixture_error(|directory| {
            OpenOptions::new()
                .write(true)
                .open(directory.join(TLA2TOOLS_JAR_NAME))
                .expect("open fixture JAR")
                .set_len((TLA2TOOLS_BYTES - 1) as u64)
                .expect("truncate fixture JAR");
        });
        assert!(size_error.contains("unexpected size"));

        let digest_error = fixture_error(|directory| {
            let mut jar = OpenOptions::new()
                .write(true)
                .open(directory.join(TLA2TOOLS_JAR_NAME))
                .expect("open fixture JAR");
            jar.seek(SeekFrom::Start(0)).expect("seek fixture JAR");
            jar.write_all(&[0]).expect("mutate fixture JAR");
        });
        assert!(digest_error.contains("digest mismatch"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let fixture = VendoredToolchainFixture::new();
            let jar = fixture.directory().join(TLA2TOOLS_JAR_NAME);
            let target = fixture.root.join("tla2tools-target.jar");
            fs::copy(&jar, &target).expect("copy fixture symlink target");
            fs::remove_file(&jar).expect("remove fixture JAR");
            symlink(&target, &jar).expect("symlink fixture JAR");
            let error = validate_vendored_tla2tools_files(&fixture.root)
                .expect_err("symlinked vendored JAR must be rejected")
                .to_string();
            assert!(error.contains("regular non-symlink"));
        }
    }

    #[test]
    fn rejects_vendored_tla2tools_metadata_mutations() {
        let sums_error = fixture_error(|directory| {
            fs::write(directory.join("SHA256SUMS"), b"0  wrong.jar\n")
                .expect("mutate fixture SHA256SUMS");
        });
        assert!(sums_error.contains("SHA256SUMS"));

        let provenance_error = fixture_error(|directory| {
            let mut provenance = expected_tla2tools_provenance();
            provenance["upstream_asset_id"] = serde_json::json!(0);
            fs::write(
                directory.join("PROVENANCE.json"),
                serde_json::to_vec_pretty(&provenance).expect("serialize fixture provenance"),
            )
            .expect("mutate fixture provenance");
        });
        assert!(provenance_error.contains("provenance fields"));

        let extra_field_error = fixture_error(|directory| {
            let mut provenance = expected_tla2tools_provenance();
            provenance["unreviewed"] = serde_json::json!(true);
            fs::write(
                directory.join("PROVENANCE.json"),
                serde_json::to_vec_pretty(&provenance).expect("serialize fixture provenance"),
            )
            .expect("extend fixture provenance");
        });
        assert!(extra_field_error.contains("provenance fields"));

        let license_error = fixture_error(|directory| {
            fs::write(
                directory.join("LICENSE.upstream"),
                format!("{TLA2TOOLS_UPSTREAM_LICENSE}mutation\n"),
            )
            .expect("mutate fixture license");
        });
        assert!(license_error.contains("license mismatch"));

        let population_error = fixture_error(|directory| {
            fs::write(directory.join("unreviewed.bin"), b"unexpected")
                .expect("extend fixture population");
        });
        assert!(population_error.contains("unexpected population"));
    }

    #[test]
    fn requires_the_exact_vendored_tla2tools_docker_contract() {
        let dockerfile = valid_tla2tools_docker_contract();
        validate_tla2tools_docker_contract(&dockerfile).expect("exact vendored Docker contract");

        let mutations = [
            dockerfile.replace(TLA2TOOLS_SHA256, &"0".repeat(64)),
            dockerfile.replace("2026.07.09.134028", "2026.07.14.071606"),
            dockerfile.replace(
                "ARG TLA2TOOLS_REVISION_SHORT=227f61b",
                "ARG TLA2TOOLS_REVISION_SHORT=deadbee",
            ),
            dockerfile.replace(TLA2TOOLS_JAR_NAME, "tla2tools.jar"),
            dockerfile.replace(
                "    third_party/tlaplus/1.8.0-227f61b/LICENSE.upstream \\\n",
                "",
            ),
            dockerfile.replace("sha256sum -c -", "sha256sum /dev/null"),
            dockerfile.replace("version_line=$(printf", "ignored_version=$(printf"),
            format!("{dockerfile}{TLA2TOOLS_DOCKER_INSTALL}\n"),
        ];
        for mutation in mutations {
            validate_tla2tools_docker_contract(&mutation)
                .expect_err("mutated vendored Docker contract must be rejected");
        }

        let mutable = format!(
            "{dockerfile}# https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar\n"
        );
        let error = validate_tla2tools_docker_contract(&mutable)
            .expect_err("mutable TLA+ release URL must be rejected")
            .to_string();
        assert!(error.contains("mutable upstream release URL"));
    }

    #[test]
    fn rejects_syntactically_invalid_workflow_yaml() {
        let error = validate_workflow_yaml("jobs:\n  invalid: [\n")
            .expect_err("invalid YAML must be rejected")
            .to_string();
        assert!(error.contains("not valid YAML"));
    }

    #[test]
    fn release_metadata_is_structured_and_frozen() {
        let citation = r#"
cff-version: 1.2.0
title: "Nexus: Causally Scoped Effect Revocation"
type: software
version: 0.1.0
date-released: 2026-07-14
repository-code: "https://github.com/chenty2333/Nexus"
license: Unlicense
authors:
  - family-names: Chen
    given-names: Tianyi
    affiliation: Hangzhou Normal University
"#;
        validate_citation(citation).expect("valid citation metadata");
        assert!(validate_citation(&citation.replace("0.1.0", "0.2.0")).is_err());

        let zenodo = r#"{
            "title": "Nexus: Causally Scoped Effect Revocation",
            "upload_type": "software",
            "access_right": "open",
            "license": "unlicense",
            "version": "0.1.0",
            "creators": [{
                "name": "Chen, Tianyi",
                "affiliation": "Hangzhou Normal University"
            }]
        }"#;
        validate_zenodo(zenodo).expect("valid Zenodo metadata");
        assert!(validate_zenodo(&zenodo.replace("unlicense", "mit")).is_err());
    }

    #[test]
    fn requires_every_checkout_to_fetch_its_parent_history() {
        let valid = format!(
            "jobs:\n  one:\n    steps:\n      - uses: actions/checkout@{SHA}\n        with:\n          fetch-depth: 0\n  two:\n    steps:\n      - uses: actions/checkout@{SHA}\n        with:\n          fetch-depth: '0'\n"
        );
        assert_eq!(validate_checkout_fetch_depth(&valid).unwrap(), 2);

        let shallow = format!(
            "jobs:\n  one:\n    steps:\n      - uses: actions/checkout@{SHA}\n        with:\n          fetch-depth: 1\n"
        );
        let error = validate_checkout_fetch_depth(&shallow)
            .expect_err("shallow checkout must be rejected")
            .to_string();
        assert!(error.contains("fetch-depth: 0"));
    }

    #[test]
    fn accepts_list_form_actions_pinned_to_full_commits() {
        let workflow = format!(
            "steps:\n  - uses: actions/checkout@{SHA}\n  - uses: actions/upload-artifact@{SHA}\n"
        );

        assert_eq!(validate_pinned_actions(&workflow).unwrap(), 2);
    }

    #[test]
    fn rejects_checkout_pinned_to_a_branch() {
        let workflow = format!(
            "steps:\n  - uses: actions/checkout@main\n  - uses: actions/upload-artifact@{SHA}\n"
        );

        let error = validate_pinned_actions(&workflow).unwrap_err().to_string();
        assert!(error.contains("not pinned to a 40-hex commit"));
    }

    #[test]
    fn requires_checkout_and_evidence_upload_actions_individually() {
        let workflow = format!("steps:\n  - uses: vendor/one@{SHA}\n  - uses: vendor/two@{SHA}\n");

        let error = validate_pinned_actions(&workflow).unwrap_err().to_string();
        assert!(error.contains("actions/checkout"));
    }

    #[test]
    fn requires_the_full_verify_receipt_order() {
        let prefix = r#"
	run_xtask() {
	    if [[ $command == begin || $command == complete || $command == manifest ]]; then
	    token_environment=(--env "NEXUS_VERIFY_TOKEN=$verify_token")
	    fi
	}
verify_all() {
    local verify_token
    export NEXUS_VERIFY_INVOCATION=./x-verify
"#;
        let suffix = "\n}\n";
        let ordered = format!(
            "{prefix}run_xtask begin\nrun_xtask verify\nrun_system\nrun_same_boot_acceptance\nrun_backend kernel eval-stage7b\nrun_xtask stage7b-evidence\nrun_xtask complete\nrun_xtask manifest\nrun_xtask bundle{suffix}"
        );
        validate_full_verify_order(&ordered).expect("ordered full verify");

        let spliced = format!(
            "{prefix}run_xtask begin\nrun_xtask verify\nrun_xtask complete\nrun_system\nrun_same_boot_acceptance\nrun_backend kernel eval-stage7b\nrun_xtask stage7b-evidence\nrun_xtask manifest\nrun_xtask bundle{suffix}"
        );
        let error = validate_full_verify_order(&spliced)
            .expect_err("completion before system must be rejected")
            .to_string();
        assert!(error.contains("missing or out of order"));

        let late_same_boot = format!(
            "{prefix}run_xtask begin\nrun_xtask verify\nrun_system\nrun_backend kernel eval-stage7b\nrun_xtask stage7b-evidence\nrun_xtask complete\nrun_same_boot_acceptance\nrun_xtask manifest\nrun_xtask bundle{suffix}"
        );
        let error = validate_full_verify_order(&late_same_boot)
            .expect_err("same-boot acceptance after completion must be rejected")
            .to_string();
        assert!(error.contains("missing or out of order"));
    }

    #[test]
    fn requires_the_same_boot_acceptance_route() {
        let positive = r#"run_backend "$kernel_backend" test-same-boot "Nexus same-boot production filesystem""#;
        let precommit = r#"run_backend "$kernel_backend" test-same-boot-precommit "Nexus same-boot precommit revocation""#;
        let route = format!("run_same_boot_acceptance() {{\n    {positive}\n    {precommit}\n}}\n");
        validate_same_boot_acceptance_route(&route).expect("complete same-boot route");

        for broken in [
            format!("run_same_boot_acceptance() {{\n    {precommit}\n}}\n"),
            format!("run_same_boot_acceptance() {{\n    {positive}\n}}\n"),
            format!("run_same_boot_acceptance() {{\n    {precommit}\n    {positive}\n}}\n"),
            route.replacen("$kernel_backend", "$virtio_backend", 1),
        ] {
            assert!(validate_same_boot_acceptance_route(&broken).is_err());
        }
    }

    #[test]
    fn requires_the_prospective_production_identity_route() {
        let route = r#"
research production-identity
doctor|build|test|run|fmt|check|quick|model|spec|system|research|verify|verify-bundle|clean
research requires exactly one target: production-identity
production-identity) run_xtask research production-identity
unknown research target: $1
"#;
        validate_production_identity_route(route).expect("complete research route");
        let missing_target = route.replace(
            "production-identity) run_xtask research production-identity",
            "production-identity) run_xtask spec",
        );
        assert!(validate_production_identity_route(&missing_target).is_err());
    }
}
