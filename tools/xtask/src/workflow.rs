use quote::ToTokens;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use syn::ext::IdentExt;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const TLA2TOOLS_DIRECTORY: &str = "third_party/tlaplus/1.8.0-227f61b";
const TLA2TOOLS_JAR_NAME: &str = "tla2tools-227f61b.jar";
const TLA2TOOLS_SHA256: &str = "33de7da9ce1b7fffb9d1c184021178dbb051747be48504e65c584c423721a32e";
const TLA2TOOLS_BYTES: usize = 4_357_904;
const TLA2TOOLS_LICENSE_SHA256: &str =
    "3fa3a845ce5eb7b9b3508701dc1aa4d084b6b2c27cbae8cd44d277d10ee411bf";
const TLA2TOOLS_SHA256SUMS: &str =
    "33de7da9ce1b7fffb9d1c184021178dbb051747be48504e65c584c423721a32e  tla2tools-227f61b.jar\n";
const ROOT_FRONTDOOR_SHA256: &str =
    "7854983fb24c464e3ef7b1d110bc3f742ebbbbac60ed95d621fd3f09e2fee439";
const TLA2TOOLS_LICENSE_PATHSPEC_EXCLUSION: &str =
    ":(exclude)third_party/tlaplus/1.8.0-227f61b/LICENSE.upstream";
const TRANSITION_GATE_MANIFEST: &str = "crates/cser-transition-gates/Cargo.toml";
const EFFECT_PEER_MANIFEST: &str = "crates/nexus-effect-peer/Cargo.toml";
const PORTAL_ABI_MANIFEST: &str = "crates/nexus-portal-abi/Cargo.toml";
const SUPERVISOR_MANIFEST: &str = "crates/nexus-supervisor/Cargo.toml";
const IMAGE_IDENTITY_INPUTS: [&str; 17] = [
    "Dockerfile",
    ".dockerignore",
    "third_party/tlaplus/1.8.0-227f61b/tla2tools-227f61b.jar",
    "third_party/tlaplus/1.8.0-227f61b/SHA256SUMS",
    "third_party/tlaplus/1.8.0-227f61b/PROVENANCE.json",
    "third_party/tlaplus/1.8.0-227f61b/LICENSE.upstream",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    "Cargo.toml",
    "Cargo.lock",
    "crates/cser-model/Cargo.toml",
    TRANSITION_GATE_MANIFEST,
    EFFECT_PEER_MANIFEST,
    PORTAL_ABI_MANIFEST,
    SUPERVISOR_MANIFEST,
    "tools/xtask/Cargo.toml",
    "tools/xtask/Cargo.lock",
];
const DEPENDENCY_CACHE_INPUTS: [(&str, &str); 10] = [
    ("Cargo.lock", "/tmp/nexus-locks/Cargo.lock"),
    (
        "tools/xtask/Cargo.lock",
        "/tmp/nexus-locks/xtask.Cargo.lock",
    ),
    ("Cargo.toml", "/tmp/nexus-inputs/root.Cargo.toml"),
    (
        "crates/cser-model/Cargo.toml",
        "/tmp/nexus-inputs/cser-model.Cargo.toml",
    ),
    (
        "crates/cser-transition-gates/Cargo.toml",
        "/tmp/nexus-inputs/cser-transition-gates.Cargo.toml",
    ),
    (
        "crates/nexus-effect-peer/Cargo.toml",
        "/tmp/nexus-inputs/nexus-effect-peer.Cargo.toml",
    ),
    (
        "crates/nexus-portal-abi/Cargo.toml",
        "/tmp/nexus-inputs/nexus-portal-abi.Cargo.toml",
    ),
    (
        "crates/nexus-supervisor/Cargo.toml",
        "/tmp/nexus-inputs/nexus-supervisor.Cargo.toml",
    ),
    (
        "tools/xtask/Cargo.toml",
        "/tmp/nexus-inputs/xtask.Cargo.toml",
    ),
    (".cargo/config.toml", "/tmp/nexus-inputs/cargo-config.toml"),
];
const PRODUCTION_REGISTRY_TEST: &str = "crates/cser-transition-gates/tests/production_registry.rs";
const CSER_PRODUCTION_SOURCE_MANIFEST: &str = "kernel/nexus-ostd/cser-production-sources.txt";
const CSER_SOURCE_ROOT: &str = "kernel/nexus-ostd/src/cser";
const OSTD_SUPERVISOR_RUNTIME_SOURCE: &str = "kernel/nexus-ostd/src/cser/supervisor_runtime.rs";
const CSER_PRODUCTION_ROOTS: [&str; 4] = [
    "device_flight.rs",
    "effect_registry.rs",
    "portal_v2.rs",
    "supervisor_runtime.rs",
];
const PINNED_DOCKER_SYNTAX: &str = "# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e";
const PORTAL_ABI_IMAGE_INPUTS: [&str; 15] = [
    "Cargo.toml",
    "src/capability.rs",
    "src/digest.rs",
    "src/dispatcher.rs",
    "src/error.rs",
    "src/handle.rs",
    "src/lib.rs",
    "src/lifecycle.rs",
    "src/message.rs",
    "src/request.rs",
    "src/response.rs",
    "src/response/error.rs",
    "src/response/lifecycle.rs",
    "src/response/negotiation.rs",
    "src/response/query.rs",
];
const VIRTIO_AUTHORITY_LOCK: &str = "kernel/nexus-ostd/osdk-runner-base/Cargo.lock";
const VIRTIO_PRODUCTION_LOCKS: [&str; 5] = [
    "crates/nexus-ostd-virtio/Cargo.lock",
    "kernel/nexus-ostd/Cargo.lock",
    VIRTIO_AUTHORITY_LOCK,
    "experiments/ostd-virtio-cser-spike/Cargo.lock",
    "experiments/ostd-virtio-cser-spike/osdk-runner-base/Cargo.lock",
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
    validate_root_frontdoor_snapshot(&frontdoor)?;
    validate_full_verify_order(&frontdoor)?;
    validate_linked_worktree_git_mount(&frontdoor)?;
    validate_same_boot_acceptance_route(&frontdoor)?;
    validate_production_identity_route(&frontdoor)?;
    validate_image_identity_inputs(&frontdoor)?;
    validate_clean_contract(&frontdoor)?;
    validate_cold_rebuild_contract(root, &frontdoor)?;
    validate_backend_source_binding(root)?;
    validate_transition_gate_route(root)?;
    validate_virtio_dependency_parity(root)?;

    let dockerfile = fs::read_to_string(root.join("Dockerfile"))?;
    validate_workspace_dependency_cache_inputs(&dockerfile)?;
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

fn validate_root_frontdoor_snapshot(frontdoor: &str) -> Result<()> {
    let observed = sha256(frontdoor.as_bytes());
    if observed != ROOT_FRONTDOOR_SHA256 {
        return Err(format!(
            "root workflow differs from its reviewed snapshot: expected {ROOT_FRONTDOOR_SHA256}, got {observed}"
        )
        .into());
    }
    Ok(())
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

fn validate_linked_worktree_git_mount(frontdoor: &str) -> Result<()> {
    let body = function_body(frontdoor, "run_xtask() {")?;
    for required in [
        "local -a git_mount=()",
        "if [[ -f \"$root/.git\" ]]",
        "git -C \"$root\" rev-parse --path-format=absolute --git-common-dir",
        "[[ ! -d $git_common_dir || $git_common_dir == *:* ]]",
        "--volume \"$git_common_dir:$git_common_dir:ro,z\"",
        "\"${git_mount[@]}\"",
    ] {
        if !body.contains(required) {
            return Err(format!(
                "root workflow does not preserve Git identity in linked worktrees: {required}"
            )
            .into());
        }
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
    let joined = frontdoor.replace("\\\n", "");
    if joined.matches("compute_image_identity").count() != 3 {
        return Err(
            "root workflow must contain one image-identity definition and two direct calls".into(),
        );
    }
    for declaration in ["build_image() {", "ensure_image() {"] {
        let caller = function_body(frontdoor, declaration)?;
        let direct_calls = continued_shell_lines(caller)?
            .iter()
            .filter(|line| line.as_str() == "compute_image_identity")
            .count();
        if direct_calls != 1 {
            return Err(format!(
                "root workflow {declaration} must contain exactly one direct image-identity call"
            )
            .into());
        }
    }
    let body = function_body(frontdoor, "compute_image_identity() {")?;
    let inputs = IMAGE_IDENTITY_INPUTS
        .iter()
        .map(|relative| format!("\"$root/{relative}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let pipeline =
        format!("image_key=$(sha256sum {inputs} | cut -d ' ' -f1 | sha256sum | cut -c1-16)");
    let expected = vec![
        "if [[ -n $image ]]; then".to_string(),
        "return".to_string(),
        "fi".to_string(),
        "local image_key".to_string(),
        pipeline,
        "image=\"nexus/cser-dev:$image_key\"".to_string(),
    ];
    let actual = continued_shell_lines(body)?;
    if actual != expected {
        return Err(format!(
            "root image identity function is not the exact reviewed command sequence: expected {expected:?}, found {actual:?}"
        )
        .into());
    }
    Ok(())
}

fn validate_workspace_dependency_cache_inputs(dockerfile: &str) -> Result<()> {
    let logical_lines = continued_shell_lines(dockerfile)?;
    for (relative, cached) in DEPENDENCY_CACHE_INPUTS {
        let copy = format!("COPY {relative} {cached}");
        if logical_lines.iter().filter(|line| **line == copy).count() != 1 {
            return Err(format!(
                "root Dockerfile must copy each dependency input exactly once: {relative}"
            )
            .into());
        }
    }

    let cache_run = logical_lines
        .iter()
        .filter(|line| {
            line.starts_with("RUN --mount=type=bind,source=.,target=/tmp/nexus-workspace,readonly ")
        })
        .collect::<Vec<_>>();
    if cache_run.len() != 1 {
        return Err("root Dockerfile must contain one canonical dependency-cache RUN".into());
    }
    let commands = cache_run[0]
        .split(" && ")
        .map(str::trim)
        .collect::<Vec<_>>();
    let mut expected_commands = Vec::new();
    for (index, (relative, cached)) in DEPENDENCY_CACHE_INPUTS.iter().enumerate() {
        let prefix = if index == 0 {
            "RUN --mount=type=bind,source=.,target=/tmp/nexus-workspace,readonly "
        } else {
            ""
        };
        expected_commands.push(format!(
            "{prefix}cmp {cached} /tmp/nexus-workspace/{relative}"
        ));
    }
    expected_commands.extend([
        "cargo fetch --locked --manifest-path /tmp/nexus-workspace/Cargo.toml".to_string(),
        "cargo fetch --locked --manifest-path /tmp/nexus-workspace/tools/xtask/Cargo.toml"
            .to_string(),
        "rm -rf /tmp/nexus-locks /tmp/nexus-inputs".to_string(),
        "chmod -R a+rwX /usr/local/cargo".to_string(),
    ]);
    if commands != expected_commands {
        return Err(format!(
            "root Dockerfile dependency-cache RUN is not the exact reviewed command sequence: expected {expected_commands:?}, found {commands:?}"
        )
        .into());
    }
    Ok(())
}

fn continued_shell_lines(source: &str) -> Result<Vec<String>> {
    let mut logical = Vec::new();
    let mut pending = String::new();
    for physical in source.lines() {
        let trimmed = physical.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            if pending.is_empty() {
                continue;
            }
            return Err("comment inside a continued shell command is forbidden".into());
        }
        let continued = trimmed.ends_with('\\');
        let fragment = if continued {
            trimmed[..trimmed.len() - 1].trim_end()
        } else {
            trimmed
        };
        if !pending.is_empty() && !fragment.is_empty() {
            pending.push(' ');
        }
        pending.push_str(fragment);
        if !continued {
            logical.push(pending.split_whitespace().collect::<Vec<_>>().join(" "));
            pending.clear();
        }
    }
    if !pending.is_empty() {
        logical.push(pending.split_whitespace().collect::<Vec<_>>().join(" "));
    }
    Ok(logical)
}

fn function_body<'a>(source: &'a str, declaration: &str) -> Result<&'a str> {
    let mut declaration_ends = Vec::new();
    let mut offset = 0_usize;
    for line in source.split_inclusive('\n') {
        if line.trim() == declaration {
            declaration_ends.push(offset + line.len());
        }
        offset += line.len();
    }
    if declaration_ends.len() != 1 {
        return Err(format!(
            "workflow must contain exactly one active function declaration: {declaration}"
        )
        .into());
    }
    let body_start = declaration_ends[0];
    let mut body_end = body_start;
    for line in source[body_start..].split_inclusive('\n') {
        if line.trim() == "}" {
            return Ok(&source[body_start..body_end]);
        }
        body_end += line.len();
    }
    Err(format!("workflow function is not terminated: {declaration}").into())
}

fn validate_clean_contract(frontdoor: &str) -> Result<()> {
    let cache = function_body(frontdoor, "clean_cache() {")?;
    for required in [
        "$root/target/cargo",
        "$root/target/docker",
        "$root/target/debug",
        "$root/tools/xtask/target",
        "$root/crates/nexus-ostd-virtio/target",
        "$root/kernel/nexus-ostd/target",
        "$root/kernel/nexus-ostd/userspace/personality/target",
        "$root/experiments/ostd-virtio-cser-spike/target",
        "$root/experiments/ostd-virtio-cser-spike/patch-work",
        "$root/specs/cser/states",
        "$root\"/kernel/nexus-ostd/guest/*.elf",
    ] {
        if !cache.contains(required) {
            return Err(format!("cache cleanup misses generated path: {required}").into());
        }
    }
    for preserved in [
        "\"$root/target/verification\"",
        "\"$root/target/release\"",
        "\"$root/target/release-audit\"",
        "\"$root/kernel/nexus-ostd/artifacts\"",
        "\"$root/experiments/ostd-virtio-cser-spike/artifacts\"",
    ] {
        if cache.contains(preserved) {
            return Err(format!("default cache cleanup would delete evidence: {preserved}").into());
        }
    }

    let evidence = function_body(frontdoor, "clean_evidence() {")?;
    for required in [
        "$root/target/scenario-artifacts",
        "$root/target/verification",
        "$root/target/research",
        "$root/kernel/nexus-ostd/artifacts",
        "$root/experiments/ostd-virtio-cser-spike/artifacts",
    ] {
        if !evidence.contains(required) {
            return Err(
                format!("explicit evidence cleanup misses generated path: {required}").into(),
            );
        }
    }
    for preserved in ["\"$root/target/release\"", "\"$root/target/release-audit\""] {
        if evidence.contains(preserved) {
            return Err(
                format!("evidence cleanup would delete release output: {preserved}").into(),
            );
        }
    }
    for required in [
        "mode=${1:-cache}",
        "cache) clean_cache",
        "--all)",
        "clean_evidence",
    ] {
        if !frontdoor.contains(required) {
            return Err(format!("root workflow lacks safe clean routing: {required}").into());
        }
    }
    Ok(())
}

fn validate_cold_rebuild_contract(root: &Path, frontdoor: &str) -> Result<()> {
    for (relative, source) in [
        ("x", frontdoor.to_owned()),
        (
            "kernel/nexus-ostd/x",
            fs::read_to_string(root.join("kernel/nexus-ostd/x"))?,
        ),
        (
            "experiments/ostd-virtio-cser-spike/x",
            fs::read_to_string(root.join("experiments/ostd-virtio-cser-spike/x"))?,
        ),
    ] {
        let build = function_body(&source, "build_image() {")?;
        for required in ["rebuild_args=(--no-cache)", "\"${rebuild_args[@]}\""] {
            if !build.contains(required) {
                return Err(format!(
                    "{relative} does not make NEXUS_REBUILD cache-cold: {required}"
                )
                .into());
            }
        }
        let container_prefix = if relative == "x" {
            "docker run --rm \\\n        --init"
        } else {
            "command \"$docker_bin\" run --rm \\\n        --init"
        };
        if !source.contains(container_prefix) {
            return Err(format!("{relative} does not run containers under Docker init").into());
        }
    }
    for required in [
        "prepare_cold_backend_images",
        "backend_rebuild=1",
        "backend_rebuild=0",
    ] {
        if !frontdoor.contains(required) {
            return Err(format!(
                "root cold workflow would rebuild backend images repeatedly: {required}"
            )
            .into());
        }
    }
    Ok(())
}

fn require_plain_regular_file_below(root: &Path, relative: &Path, label: &str) -> Result<()> {
    let canonical = canonical_relative_source_path(relative)?;
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect {label} root at {}: {error}", root.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
        return Err(format!(
            "{label} root must be a non-symlink directory: {}",
            root.display()
        )
        .into());
    }
    let components = Path::new(&canonical).components().collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(component) = component else {
            return Err(format!("{label} path became non-canonical: {canonical}").into());
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("cannot inspect {label} at {}: {error}", current.display()))?;
        let is_last = index + 1 == components.len();
        let valid_kind = if is_last {
            metadata.file_type().is_file()
        } else {
            metadata.file_type().is_dir()
        };
        if metadata.file_type().is_symlink() || !valid_kind {
            let expected = if is_last { "file" } else { "directory" };
            return Err(format!(
                "{label} path component must be a non-symlink {expected}: {}",
                current.display()
            )
            .into());
        }
    }
    Ok(())
}

fn canonical_relative_source_path(path: &Path) -> Result<String> {
    let raw = path.to_str().ok_or("CSER source path is not valid UTF-8")?;
    if raw.starts_with("./") || raw.contains("/./") {
        return Err(format!("CSER source path contains a current-directory alias: {raw}").into());
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(component) => {
                let component = component
                    .to_str()
                    .ok_or("CSER source path is not valid UTF-8")?;
                if component.is_empty() {
                    return Err("CSER source path contains an empty component".into());
                }
                components.push(component);
            }
            _ => {
                return Err(
                    format!("CSER source path is not canonical: {}", path.display()).into(),
                );
            }
        }
    }
    if components.is_empty() {
        return Err("CSER source path is empty".into());
    }
    let canonical = components.join("/");
    if raw != canonical {
        return Err(format!(
            "CSER source path is not byte-canonical: raw={raw:?} canonical={canonical:?}"
        )
        .into());
    }
    Ok(canonical)
}

fn external_module_relative_path(
    source_relative: &Path,
    module: &syn::ItemMod,
    cser_root: &Path,
) -> Result<PathBuf> {
    let path_attributes = module
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("path"))
        .collect::<Vec<_>>();
    if path_attributes.len() > 1 {
        return Err(format!(
            "external module {} has multiple path attributes",
            module.ident
        )
        .into());
    }
    let candidate = if let Some(path) = path_attributes.first() {
        let syn::Meta::NameValue(name_value) = &path.meta else {
            return Err(format!("module {} has a non-literal path attribute", module.ident).into());
        };
        let syn::Expr::Lit(expression) = &name_value.value else {
            return Err(format!("module {} path is not a string literal", module.ident).into());
        };
        let syn::Lit::Str(path) = &expression.lit else {
            return Err(format!("module {} path is not a string literal", module.ident).into());
        };
        source_relative
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(path.value())
    } else {
        let parent = source_relative.parent().unwrap_or_else(|| Path::new(""));
        let module_base =
            if source_relative.file_name().and_then(|name| name.to_str()) == Some("mod.rs") {
                parent.to_path_buf()
            } else {
                let stem = source_relative
                    .file_stem()
                    .ok_or("external module owner has no file stem")?;
                parent.join(stem)
            };
        let module_name = canonical_ident(&module.ident);
        let flat = module_base.join(format!("{module_name}.rs"));
        let nested = module_base.join(module_name).join("mod.rs");
        let flat_exists = cser_root.join(&flat).exists();
        let nested_exists = cser_root.join(&nested).exists();
        match (flat_exists, nested_exists) {
            (true, false) => flat,
            (false, true) => nested,
            (true, true) => {
                return Err(format!(
                    "external module {} has ambiguous flat and nested sources",
                    module.ident
                )
                .into());
            }
            (false, false) => {
                return Err(format!(
                    "external module {} has no source below {}",
                    module.ident,
                    module_base.display()
                )
                .into());
            }
        }
    };
    canonical_relative_source_path(&candidate)?;
    Ok(candidate)
}

fn validate_external_module_attributes(
    source_relative: &Path,
    module: &syn::ItemMod,
) -> Result<()> {
    let is_test_module = source_relative == Path::new("infrastructure/mod.rs")
        && canonical_ident(&module.ident) == "tests";
    if is_test_module {
        if module.attrs.len() != 1 || !module.attrs[0].path().is_ident("cfg") {
            return Err("infrastructure tests module must retain only exact #[cfg(test)]".into());
        }
        let syn::Meta::List(cfg) = &module.attrs[0].meta else {
            return Err("infrastructure tests module has malformed cfg".into());
        };
        if cfg.tokens.to_string() != "test" {
            return Err("infrastructure tests module must use exact #[cfg(test)]".into());
        }
    } else {
        for attribute in &module.attrs {
            if !attribute.path().is_ident("path") {
                return Err(format!(
                    "production external module {} has an unaudited attribute {}",
                    module.ident,
                    attribute
                        .path()
                        .segments
                        .last()
                        .map_or_else(|| "<empty>".to_owned(), |segment| segment.ident.to_string())
                )
                .into());
            }
        }
    }
    Ok(())
}

const CSER_FROZEN_TEST_MACRO_SOURCE: &str = "infrastructure/tests.rs";
// This is the SHA-256 of quote's normalized token stream for the complete
// evidence-test item. Unlike the invocation multiset below, it binds every
// invocation to its enclosing loops, branches, statement order, and function.
const CSER_FROZEN_TEST_FUNCTIONS: [(&str, &str); 1] = [(
    "service_lineage_commitment_schema_has_frozen_vectors_and_full_field_coverage",
    "ed95f99e17f884b6b47b1bd0a1acc8cc4681723d4baffb9e20df92d16bfb18a7",
)];
const CSER_FROZEN_TEST_MACROS: [(&str, &str, &[&str]); 4] = [
    (
        "assert_arm_plan_change",
        "4959d9dbf245fc82844e03fdefa640b496370eb523e915782b6807e818bda649",
        &[
            "3f440ef4a088f91b6de87db5324412e5b94073df5603a4d6c68b9ca31b71e24e",
            "596dee08fa52460dad17dbc37fb3078dcae936a81fabbc39e7f16282d03fe726",
            "9bf0da1b6bbf4c3e181fcf867698128c2fcb48abf2877e2b1ff8ccb01e91b1ca",
            "9d3d874fd8d6672c1e1bfbcb0f12b0e3c1b0e4b24472a687719c8af5f1b4c492",
        ],
    ),
    (
        "assert_arm_receipt_change",
        "6e6e413450d8081c04cb6c765324790d45fca6c854659b16e1c34277e52390e9",
        &["3f440ef4a088f91b6de87db5324412e5b94073df5603a4d6c68b9ca31b71e24e"],
    ),
    (
        "assert_enqueue_plan_change",
        "79c19ae03fa756fbcd24e997df71b221afd94079ab6e8144eaf5434e52b05173",
        &[
            "3f440ef4a088f91b6de87db5324412e5b94073df5603a4d6c68b9ca31b71e24e",
            "8d3f14cc12732bc75f6de7a2f68d2178692339a098a2813a1de2a72b518ad0d6",
            "93099e8e93fad73fcfde61e14bd9dc14607bda7c3feee32ce5ccca9917ed817c",
            "d3092d56d565d02d34f5f383d97a6d5ff68d2cd40393610f0aed8a67e4e6e4f3",
        ],
    ),
    (
        "assert_enqueue_receipt_change",
        "92a4ba8cb309c3de3f9ede77da959cbca264de38e3e9057859b1d92af3cfa8d5",
        &["3f440ef4a088f91b6de87db5324412e5b94073df5603a4d6c68b9ca31b71e24e"],
    ),
];

struct CserSourceMacroAudit<'a> {
    source_relative: &'a Path,
    rejected: Option<String>,
    local_definitions: BTreeMap<String, String>,
    local_invocations: BTreeMap<String, Vec<String>>,
    frozen_test_functions: BTreeMap<String, String>,
}

impl<'a> CserSourceMacroAudit<'a> {
    fn new(source_relative: &'a Path) -> Self {
        Self {
            source_relative,
            rejected: None,
            local_definitions: BTreeMap::new(),
            local_invocations: BTreeMap::new(),
            frozen_test_functions: BTreeMap::new(),
        }
    }

    fn reject(&mut self, reason: impl Into<String>) {
        if self.rejected.is_none() {
            self.rejected = Some(reason.into());
        }
    }

    fn record_frozen_local_invocation(&mut self, source_macro: &syn::Macro) {
        let Some(name) = source_macro_name(source_macro) else {
            self.reject("<absolute frozen local macro path>");
            return;
        };
        if self.source_relative != Path::new(CSER_FROZEN_TEST_MACRO_SOURCE) {
            self.reject(name);
            return;
        }
        if let Some(source_construct) =
            reject_source_construct_inside_macro(source_macro.tokens.clone())
        {
            self.reject(format!("{name} contains {source_construct}"));
            return;
        }
        if let Some(nested) = reject_unreviewed_nested_macro(source_macro.tokens.clone()) {
            self.reject(format!("{name} contains {nested}!"));
            return;
        }
        self.local_invocations
            .entry(name)
            .or_default()
            .push(sha256(source_macro.tokens.to_string().as_bytes()));
    }

    fn finish(mut self) -> Option<String> {
        if self.rejected.is_some() {
            return self.rejected;
        }
        if self.source_relative != Path::new(CSER_FROZEN_TEST_MACRO_SOURCE) {
            return None;
        }

        let expected_definitions = CSER_FROZEN_TEST_MACROS
            .iter()
            .map(|(name, definition, _)| ((*name).to_owned(), (*definition).to_owned()))
            .collect::<BTreeMap<_, _>>();
        let expected_invocations = CSER_FROZEN_TEST_MACROS
            .iter()
            .map(|(name, _, invocations)| {
                let mut invocations = invocations
                    .iter()
                    .map(|digest| (*digest).to_owned())
                    .collect::<Vec<_>>();
                invocations.sort();
                ((*name).to_owned(), invocations)
            })
            .collect::<BTreeMap<_, _>>();
        let expected_test_functions = CSER_FROZEN_TEST_FUNCTIONS
            .iter()
            .map(|(name, digest)| ((*name).to_owned(), (*digest).to_owned()))
            .collect::<BTreeMap<_, _>>();
        for invocations in self.local_invocations.values_mut() {
            invocations.sort();
        }

        if self.local_definitions != expected_definitions
            || self.local_invocations != expected_invocations
            || self.frozen_test_functions != expected_test_functions
        {
            return Some(format!(
                "frozen test-local macro fingerprint mismatch; definitions={:?}; invocations={:?}; test_functions={:?}",
                self.local_definitions, self.local_invocations, self.frozen_test_functions
            ));
        }
        None
    }
}

fn audited_cser_macro_path(name: &str) -> bool {
    matches!(
        name,
        "__cser_alloc::format"
            | "__cser_alloc::vec"
            | "__cser_core::assert"
            | "__cser_core::assert_eq"
            | "__cser_core::assert_ne"
            | "__cser_core::debug_assert"
            | "__cser_core::debug_assert_eq"
            | "__cser_core::debug_assert_ne"
            | "__cser_core::matches"
            | "__cser_core::panic"
            | "__cser_core::unreachable"
    )
}

fn macro_path_before_bang(tokens: &[proc_macro2::TokenTree], bang_index: usize) -> Option<String> {
    let proc_macro2::TokenTree::Ident(last) = tokens.get(bang_index.checked_sub(1)?)? else {
        return None;
    };
    let mut segments = vec![last.to_string()];
    let mut cursor = bang_index - 1;
    while cursor >= 3 {
        let (
            proc_macro2::TokenTree::Ident(previous),
            proc_macro2::TokenTree::Punct(first_colon),
            proc_macro2::TokenTree::Punct(second_colon),
        ) = (
            &tokens[cursor - 3],
            &tokens[cursor - 2],
            &tokens[cursor - 1],
        )
        else {
            break;
        };
        if first_colon.as_char() != ':' || second_colon.as_char() != ':' {
            break;
        }
        segments.push(previous.to_string());
        cursor -= 3;
    }
    segments.reverse();
    let name = segments.join("::");
    let absolute = cursor >= 2
        && matches!(
            (&tokens[cursor - 2], &tokens[cursor - 1]),
            (
                proc_macro2::TokenTree::Punct(first),
                proc_macro2::TokenTree::Punct(second)
            ) if first.as_char() == ':' && second.as_char() == ':'
        );
    Some(if absolute { format!("::{name}") } else { name })
}

fn reject_unreviewed_nested_macro(tokens: proc_macro2::TokenStream) -> Option<String> {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        if let proc_macro2::TokenTree::Group(group) = token
            && let Some(rejected) = reject_unreviewed_nested_macro(group.stream())
        {
            return Some(rejected);
        }
        let proc_macro2::TokenTree::Punct(punctuation) = token else {
            continue;
        };
        if punctuation.as_char() != '!'
            || !matches!(
                tokens.get(index + 1),
                Some(proc_macro2::TokenTree::Group(_))
            )
        {
            continue;
        }
        let Some(name) = macro_path_before_bang(&tokens, index) else {
            continue;
        };
        if !audited_cser_macro_path(&name) {
            return Some(name);
        }
    }
    None
}

fn reject_source_construct_inside_macro(tokens: proc_macro2::TokenStream) -> Option<&'static str> {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        if let proc_macro2::TokenTree::Group(group) = token
            && let Some(rejected) = reject_source_construct_inside_macro(group.stream())
        {
            return Some(rejected);
        }
        if let proc_macro2::TokenTree::Ident(ident) = token {
            match ident.to_string().as_str() {
                "mod" => return Some("module item inside opaque macro tokens"),
                "use" | "extern" | "macro" | "macro_rules" => {
                    return Some("binding item inside opaque macro tokens");
                }
                _ => {}
            }
        }
        if matches!(token, proc_macro2::TokenTree::Punct(punctuation) if punctuation.as_char() == '#')
        {
            let bracket_offset = if matches!(
                tokens.get(index + 1),
                Some(proc_macro2::TokenTree::Punct(punctuation))
                    if punctuation.as_char() == '!'
            ) {
                2
            } else {
                1
            };
            if matches!(
                tokens.get(index + bracket_offset),
                Some(proc_macro2::TokenTree::Group(group))
                    if group.delimiter() == proc_macro2::Delimiter::Bracket
            ) {
                return Some("attribute inside opaque macro tokens");
            }
        }
    }
    None
}

fn frozen_cser_test_macro(name: &str) -> bool {
    CSER_FROZEN_TEST_MACROS
        .iter()
        .any(|(frozen, _, _)| *frozen == name)
}

fn source_macro_name(source_macro: &syn::Macro) -> Option<String> {
    let name = source_macro
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.unraw().to_string())
        .collect::<Vec<_>>()
        .join("::");
    Some(if source_macro.path.leading_colon.is_some() {
        format!("::{name}")
    } else {
        name
    })
}

fn canonical_ident(ident: &syn::Ident) -> String {
    ident.unraw().to_string()
}

fn protected_cser_source_name(name: &str) -> bool {
    audited_cser_macro_path(name)
        || matches!(
            name,
            "alloc"
                | "core"
                | "__cser_alloc"
                | "__cser_core"
                | "assert"
                | "assert_eq"
                | "assert_ne"
                | "Clone"
                | "Copy"
                | "Debug"
                | "Default"
                | "debug_assert"
                | "debug_assert_eq"
                | "debug_assert_ne"
                | "Eq"
                | "Ord"
                | "PartialEq"
                | "PartialOrd"
                | "allow"
                | "cfg"
                | "derive"
                | "doc"
                | "format"
                | "matches"
                | "panic"
                | "path"
                | "test"
                | "unreachable"
                | "vec"
        )
        || frozen_cser_test_macro(name)
}

fn audit_cser_use_tree<'a>(tree: &'a syn::UseTree, root: Option<&'a syn::Ident>) -> Option<String> {
    match tree {
        syn::UseTree::Path(path) => audit_cser_use_tree(&path.tree, root.or(Some(&path.ident))),
        syn::UseTree::Name(name) => protected_cser_source_name(&canonical_ident(&name.ident))
            .then(|| format!("import shadows protected source name {}", name.ident)),
        syn::UseTree::Rename(rename) => {
            protected_cser_source_name(&canonical_ident(&rename.rename)).then(|| {
                format!(
                    "import renames {} to protected source name {}",
                    rename.ident, rename.rename
                )
            })
        }
        syn::UseTree::Glob(_) => Some(format!(
            "glob import from {} may hide macro provenance",
            root.map_or_else(|| "<root>".to_owned(), canonical_ident)
        )),
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .find_map(|tree| audit_cser_use_tree(tree, root)),
    }
}

fn exact_frozen_super_glob(item_use: &syn::ItemUse) -> bool {
    if item_use.leading_colon.is_some()
        || !item_use.attrs.is_empty()
        || !matches!(item_use.vis, syn::Visibility::Inherited)
    {
        return false;
    }
    matches!(
        &item_use.tree,
        syn::UseTree::Path(path)
            if canonical_ident(&path.ident) == "super"
                && matches!(path.tree.as_ref(), syn::UseTree::Glob(_))
    )
}

fn audit_cser_attribute(attribute: &syn::Attribute) -> Option<String> {
    use syn::parse::Parser;

    let name = if attribute.path().leading_colon.is_none() && attribute.path().segments.len() == 1 {
        canonical_ident(&attribute.path().segments[0].ident)
    } else {
        return Some("qualified or empty attribute path".to_owned());
    };
    match name.as_str() {
        "derive" => {
            let syn::Meta::List(list) = &attribute.meta else {
                return Some("derive attribute is not a list".to_owned());
            };
            let parser = syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated;
            let Ok(paths) = parser.parse2(list.tokens.clone()) else {
                return Some("derive attribute has malformed tokens".to_owned());
            };
            let mut seen = BTreeSet::new();
            for path in paths {
                let trait_path = path
                    .segments
                    .iter()
                    .map(|segment| canonical_ident(&segment.ident))
                    .collect::<Vec<_>>()
                    .join("::");
                let trait_name = match trait_path.as_str() {
                    "__cser_core::clone::Clone" => "Clone",
                    "__cser_core::marker::Copy" => "Copy",
                    "__cser_core::fmt::Debug" => "Debug",
                    "__cser_core::default::Default" => "Default",
                    "__cser_core::cmp::Eq" => "Eq",
                    "__cser_core::cmp::Ord" => "Ord",
                    "__cser_core::cmp::PartialEq" => "PartialEq",
                    "__cser_core::cmp::PartialOrd" => "PartialOrd",
                    _ => {
                        return Some(format!(
                            "derive attribute uses unaudited trait path {trait_path}"
                        ));
                    }
                };
                if path.leading_colon.is_some() {
                    return Some(format!(
                        "derive attribute uses an absolute path instead of the local sysroot alias: {trait_path}"
                    ));
                }
                if !seen.insert(trait_name) {
                    return Some(format!("derive attribute duplicates trait {trait_name}"));
                }
            }
            if seen.is_empty() {
                return Some("derive attribute is empty".to_owned());
            }
            None
        }
        "allow" => {
            let syn::Meta::List(list) = &attribute.meta else {
                return Some("allow attribute is not a list".to_owned());
            };
            matches!(
                list.tokens.to_string().as_str(),
                "dead_code"
                    | "clippy :: large_enum_variant"
                    | "clippy :: result_large_err"
                    | "clippy :: too_many_arguments"
            )
            .then_some(())
            .map_or_else(
                || Some(format!("allow attribute is unaudited: {}", list.tokens)),
                |_| None,
            )
        }
        "cfg" => {
            let syn::Meta::List(list) = &attribute.meta else {
                return Some("cfg attribute is not a list".to_owned());
            };
            (list.tokens.to_string() != "test")
                .then(|| format!("cfg attribute is not exact cfg(test): {}", list.tokens))
        }
        "inline" => {
            let syn::Meta::List(list) = &attribute.meta else {
                return Some("inline attribute must be exact inline(never)".to_owned());
            };
            (list.tokens.to_string() != "never").then(|| {
                format!(
                    "inline attribute is not exact inline(never): {}",
                    list.tokens
                )
            })
        }
        "test" => (!matches!(attribute.meta, syn::Meta::Path(_)))
            .then(|| "test attribute has arguments".to_owned()),
        "path" => {
            let syn::Meta::NameValue(name_value) = &attribute.meta else {
                return Some("path attribute is not a name-value string".to_owned());
            };
            let syn::Expr::Lit(expression) = &name_value.value else {
                return Some("path attribute is not a literal".to_owned());
            };
            let syn::Lit::Str(path) = &expression.lit else {
                return Some("path attribute is not a string".to_owned());
            };
            (!matches!(
                path.value().as_str(),
                "effect_registry/root_lanes.rs"
                    | "effect_registry/runtime_causal.rs"
                    | "effect_registry/runtime_service_task.rs"
                    | "effect_registry/runtime_task.rs"
                    | "infrastructure/mod.rs"
            ))
            .then(|| format!("path attribute targets unaudited source {}", path.value()))
        }
        "doc" => {
            let exact_literal = matches!(
                &attribute.meta,
                syn::Meta::NameValue(name_value)
                    if matches!(
                        &name_value.value,
                        syn::Expr::Lit(expression)
                            if matches!(expression.lit, syn::Lit::Str(_))
                    )
            );
            (!exact_literal).then(|| "doc attribute is not an inert string literal".to_owned())
        }
        _ => Some(format!("unaudited attribute {name}")),
    }
}

// A module-local `extern crate core/alloc as __cser_*` closes lexical owner
// shadowing, including inline-module consumers. It does not make rustc itself
// a root of trust: the pinned compiler/sysroot, Cargo manifests/configuration,
// build-std's actual --extern coordinates, and the absence of an injected
// compiler wrapper remain explicit build TCB inputs.
struct CserSourceProvenanceAudit<'a> {
    source_relative: &'a Path,
    frozen_super_globs: usize,
    local_sysroot_aliases: BTreeMap<Vec<String>, (usize, usize)>,
    inline_module_scopes: BTreeSet<Vec<String>>,
    module_path: Vec<String>,
    item_depth: usize,
    block_depth: usize,
    frozen_test_module: bool,
    rejected: Option<String>,
}

impl<'a> CserSourceProvenanceAudit<'a> {
    fn new(source_relative: &'a Path) -> Self {
        Self {
            source_relative,
            frozen_super_globs: 0,
            local_sysroot_aliases: BTreeMap::new(),
            inline_module_scopes: BTreeSet::new(),
            module_path: Vec::new(),
            item_depth: 0,
            block_depth: 0,
            frozen_test_module: false,
            rejected: None,
        }
    }

    fn finish(self) -> Option<String> {
        if self.rejected.is_some() {
            return self.rejected;
        }
        let mut expected_alias_scopes = self.inline_module_scopes;
        expected_alias_scopes.insert(Vec::new());
        let actual_alias_scopes = self
            .local_sysroot_aliases
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        if actual_alias_scopes != expected_alias_scopes {
            return Some(format!(
                "CSER source local sysroot alias scopes differ; expected={expected_alias_scopes:?}, actual={actual_alias_scopes:?}"
            ));
        }
        for scope in expected_alias_scopes {
            let aliases = self
                .local_sysroot_aliases
                .get(&scope)
                .copied()
                .unwrap_or_default();
            if aliases != (1, 1) {
                return Some(format!(
                    "CSER module {scope:?} must retain one exact local alloc/core alias; found={aliases:?}"
                ));
            }
        }
        let expected =
            usize::from(self.source_relative == Path::new("effect_registry/root_lanes.rs"));
        (self.frozen_super_globs != expected).then(|| {
            format!(
                "frozen super glob count differs: expected {expected}, found {}",
                self.frozen_super_globs
            )
        })
    }
}

impl<'ast> syn::visit::Visit<'ast> for CserSourceProvenanceAudit<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if self.rejected.is_some() {
            return;
        }
        self.item_depth += 1;
        syn::visit::visit_item(self, item);
        self.item_depth -= 1;
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        if self.rejected.is_some() {
            return;
        }
        self.block_depth += 1;
        syn::visit::visit_block(self, block);
        self.block_depth -= 1;
    }

    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if self.rejected.is_none() {
            self.rejected = audit_cser_attribute(attribute);
        }
    }

    fn visit_item_use(&mut self, item_use: &'ast syn::ItemUse) {
        if self.rejected.is_some() {
            return;
        }
        let frozen_super_glob = self.source_relative == Path::new("effect_registry/root_lanes.rs")
            && self.module_path == ["tests"]
            && self.item_depth == self.module_path.len() + 1
            && self.block_depth == 0
            && self.frozen_test_module
            && exact_frozen_super_glob(item_use);
        if frozen_super_glob {
            self.frozen_super_globs += 1;
            if self.frozen_super_globs != 1 {
                self.rejected = Some("frozen super glob import is duplicated".to_owned());
            }
        } else {
            self.rejected = audit_cser_use_tree(&item_use.tree, None);
        }
        if self.rejected.is_none() {
            syn::visit::visit_item_use(self, item_use);
        }
    }

    fn visit_item_mod(&mut self, item_mod: &'ast syn::ItemMod) {
        if self.rejected.is_some() {
            return;
        }
        if self.item_depth != self.module_path.len() + 1 || self.block_depth != 0 {
            self.rejected = Some(format!(
                "module {} is not a direct child of its CSER module scope",
                item_mod.ident
            ));
            return;
        }
        let module_name = canonical_ident(&item_mod.ident);
        if protected_cser_source_name(&module_name) {
            self.rejected = Some(format!(
                "module binds protected source name {}",
                item_mod.ident
            ));
            return;
        }
        let was_frozen_test_module = self.frozen_test_module;
        self.frozen_test_module = self.module_path.is_empty()
            && module_name == "tests"
            && item_mod.attrs.len() == 1
            && matches!(
                &item_mod.attrs[0].meta,
                syn::Meta::List(list)
                    if item_mod.attrs[0].path().is_ident("cfg")
                        && list.tokens.to_string() == "test"
            );
        self.module_path.push(module_name);
        if item_mod.content.is_some() {
            self.inline_module_scopes.insert(self.module_path.clone());
        }
        syn::visit::visit_item_mod(self, item_mod);
        self.module_path.pop();
        self.frozen_test_module = was_frozen_test_module;
    }

    fn visit_item_extern_crate(&mut self, extern_crate: &'ast syn::ItemExternCrate) {
        if self.rejected.is_some() {
            return;
        }
        let crate_name = canonical_ident(&extern_crate.ident);
        let rename = extern_crate
            .rename
            .as_ref()
            .map(|(_, rename)| canonical_ident(rename));
        let direct_module_child =
            self.item_depth == self.module_path.len() + 1 && self.block_depth == 0;
        let exact_private_alias = direct_module_child
            && extern_crate.attrs.is_empty()
            && matches!(extern_crate.vis, syn::Visibility::Inherited)
            && rename.as_deref().is_some_and(|rename| {
                (crate_name == "alloc" && rename == "__cser_alloc")
                    || (crate_name == "core" && rename == "__cser_core")
            });
        if !exact_private_alias {
            let binding = extern_crate
                .rename
                .as_ref()
                .map_or(&extern_crate.ident, |(_, rename)| rename);
            self.rejected = Some(format!(
                "extern crate {binding} is not an exact private module-root CSER sysroot alias"
            ));
            return;
        }
        let aliases = self
            .local_sysroot_aliases
            .entry(self.module_path.clone())
            .or_default();
        if crate_name == "alloc" {
            aliases.0 += 1;
            if aliases.0 != 1 {
                self.rejected = Some("duplicate __cser_alloc sysroot alias".to_owned());
            }
        } else {
            aliases.1 += 1;
            if aliases.1 != 1 {
                self.rejected = Some("duplicate __cser_core sysroot alias".to_owned());
            }
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for CserSourceMacroAudit<'_> {
    fn visit_item_fn(&mut self, item_fn: &'ast syn::ItemFn) {
        if self.rejected.is_some() {
            return;
        }
        let name = canonical_ident(&item_fn.sig.ident);
        if self.source_relative == Path::new(CSER_FROZEN_TEST_MACRO_SOURCE)
            && CSER_FROZEN_TEST_FUNCTIONS
                .iter()
                .any(|(frozen, _)| *frozen == name.as_str())
        {
            let mut normalized = proc_macro2::TokenStream::new();
            item_fn.to_tokens(&mut normalized);
            let digest = sha256(normalized.to_string().as_bytes());
            if self
                .frozen_test_functions
                .insert(name.clone(), digest)
                .is_some()
            {
                self.reject(format!("duplicate frozen test function {name}"));
                return;
            }
        }
        syn::visit::visit_item_fn(self, item_fn);
    }

    fn visit_item_macro(&mut self, item_macro: &'ast syn::ItemMacro) {
        if self.rejected.is_some() {
            return;
        }
        if source_macro_name(&item_macro.mac).as_deref() != Some("macro_rules") {
            syn::visit::visit_item_macro(self, item_macro);
            return;
        }

        if self.source_relative != Path::new(CSER_FROZEN_TEST_MACRO_SOURCE) {
            self.reject("macro_rules");
            return;
        }
        let Some(name) = item_macro.ident.as_ref().map(canonical_ident) else {
            self.reject("anonymous macro_rules");
            return;
        };
        if !frozen_cser_test_macro(&name) {
            self.reject(format!("macro_rules::{name}"));
            return;
        }
        if !item_macro.attrs.is_empty()
            || item_macro.semi_token.is_some()
            || !matches!(item_macro.mac.delimiter, syn::MacroDelimiter::Brace(_))
        {
            self.reject(format!(
                "macro_rules::{name} must retain its attribute-free braced item form"
            ));
            return;
        }
        if let Some(source_construct) =
            reject_source_construct_inside_macro(item_macro.mac.tokens.clone())
        {
            self.reject(format!("macro_rules::{name} contains {source_construct}"));
            return;
        }
        if let Some(nested) = reject_unreviewed_nested_macro(item_macro.mac.tokens.clone()) {
            self.reject(format!("macro_rules::{name} contains {nested}!"));
            return;
        }
        let digest = sha256(item_macro.mac.tokens.to_string().as_bytes());
        if self
            .local_definitions
            .insert(name.clone(), digest)
            .is_some()
        {
            self.reject(format!("duplicate macro_rules::{name}"));
        }
    }

    fn visit_stmt_macro(&mut self, statement_macro: &'ast syn::StmtMacro) {
        if self.rejected.is_some() {
            return;
        }
        let frozen_local = source_macro_name(&statement_macro.mac)
            .as_deref()
            .is_some_and(frozen_cser_test_macro);
        if !frozen_local {
            syn::visit::visit_stmt_macro(self, statement_macro);
            return;
        }
        if !statement_macro.attrs.is_empty()
            || statement_macro.semi_token.is_none()
            || !matches!(statement_macro.mac.delimiter, syn::MacroDelimiter::Paren(_))
        {
            self.reject(
                "frozen test-local invocation must retain its attribute-free parenthesized statement form",
            );
            return;
        }
        self.record_frozen_local_invocation(&statement_macro.mac);
    }

    fn visit_expr_macro(&mut self, expression_macro: &'ast syn::ExprMacro) {
        if source_macro_name(&expression_macro.mac)
            .as_deref()
            .is_some_and(frozen_cser_test_macro)
        {
            self.reject("frozen test-local macro used outside an audited statement");
            return;
        }
        syn::visit::visit_expr_macro(self, expression_macro);
    }

    fn visit_macro(&mut self, source_macro: &'ast syn::Macro) {
        if self.rejected.is_some() {
            return;
        }
        let name = source_macro_name(source_macro);
        let allowed = name.as_deref().is_some_and(audited_cser_macro_path);
        if name.as_deref().is_some_and(frozen_cser_test_macro) {
            self.reject("frozen test-local macro used outside an audited statement");
        } else if !allowed {
            self.reject(name.unwrap_or_else(|| "<absolute macro path>".to_owned()));
        }
        if self.rejected.is_none()
            && let Some(source_construct) =
                reject_source_construct_inside_macro(source_macro.tokens.clone())
        {
            self.reject(source_construct);
        }
        if self.rejected.is_none() {
            self.rejected = reject_unreviewed_nested_macro(source_macro.tokens.clone());
        }
        syn::visit::visit_macro(self, source_macro);
    }
}

#[derive(Default)]
struct NestedExternalModuleAudit {
    item_depth: usize,
    rejected: Option<String>,
}

impl<'ast> syn::visit::Visit<'ast> for NestedExternalModuleAudit {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if self.item_depth > 0
            && let syn::Item::Mod(module) = item
            && module.content.is_none()
            && self.rejected.is_none()
        {
            self.rejected = Some(module.ident.to_string());
        }
        self.item_depth += 1;
        syn::visit::visit_item(self, item);
        self.item_depth -= 1;
    }
}

fn reject_unbound_source_constructs(syntax: &syn::File, relative: &Path) -> Result<()> {
    use syn::visit::Visit;

    let mut provenance = CserSourceProvenanceAudit::new(relative);
    provenance.visit_file(syntax);
    if let Some(rejected) = provenance.finish() {
        return Err(format!(
            "CSER production source {} has unaudited macro or attribute provenance: {rejected}",
            relative.display()
        )
        .into());
    }
    let mut audit = CserSourceMacroAudit::new(relative);
    audit.visit_file(syntax);
    if let Some(rejected) = audit.finish() {
        return Err(format!(
            "CSER production source {} uses unaudited macro {rejected}!; include-style and dynamically generated source are forbidden",
            relative.display()
        )
        .into());
    }
    let mut nested_modules = NestedExternalModuleAudit::default();
    nested_modules.visit_file(syntax);
    if let Some(rejected) = nested_modules.rejected {
        return Err(format!(
            "CSER production source {} may not load external module {rejected} below file scope",
            relative.display()
        )
        .into());
    }
    Ok(())
}

fn collect_external_modules_from_items(
    cser_root: &Path,
    source_relative: &Path,
    items: &[syn::Item],
    inside_inline_module: bool,
    collected: &mut BTreeSet<String>,
) -> Result<()> {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if let Some((_, inline_items)) = &module.content {
            collect_external_modules_from_items(
                cser_root,
                source_relative,
                inline_items,
                true,
                collected,
            )?;
            continue;
        }
        if inside_inline_module {
            return Err(format!(
                "CSER production source {} may not load external module {} from an inline module",
                source_relative.display(),
                module.ident
            )
            .into());
        }
        validate_external_module_attributes(source_relative, module)?;
        let child = external_module_relative_path(source_relative, module, cser_root)?;
        collect_external_module_closure(cser_root, &child, collected)?;
    }
    Ok(())
}

fn collect_external_module_closure(
    cser_root: &Path,
    relative: &Path,
    collected: &mut BTreeSet<String>,
) -> Result<()> {
    let canonical = canonical_relative_source_path(relative)?;
    if !collected.insert(canonical) {
        return Ok(());
    }
    require_plain_regular_file_below(cser_root, relative, "CSER production source")?;
    let path = cser_root.join(relative);
    let source = fs::read_to_string(&path)?;
    let syntax = syn::parse_file(&source)
        .map_err(|error| format!("{} is not valid Rust source: {error}", path.display()))?;
    reject_unbound_source_constructs(&syntax, relative)?;
    collect_external_modules_from_items(cser_root, relative, &syntax.items, false, collected)
}

fn collect_rust_inventory(
    cser_root: &Path,
    directory: &Path,
    collected: &mut BTreeSet<String>,
) -> Result<()> {
    let absolute = cser_root.join(directory);
    let metadata = fs::symlink_metadata(&absolute)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(format!(
            "CSER infrastructure path must be a non-symlink directory: {}",
            absolute.display()
        )
        .into());
    }
    let mut entries = fs::read_dir(&absolute)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(format!(
                "CSER infrastructure inventory rejects symlink: {}",
                entry.path().display()
            )
            .into());
        }
        let relative = directory.join(entry.file_name());
        if file_type.is_dir() {
            collect_rust_inventory(cser_root, &relative, collected)?;
        } else if file_type.is_file()
            && entry.path().extension().and_then(|value| value.to_str()) == Some("rs")
        {
            collected.insert(canonical_relative_source_path(&relative)?);
        }
    }
    Ok(())
}

fn expected_cser_production_sources(root: &Path) -> Result<Vec<String>> {
    let cser_root = root.join(CSER_SOURCE_ROOT);
    let mut closure = BTreeSet::new();
    for root_source in CSER_PRODUCTION_ROOTS {
        collect_external_module_closure(&cser_root, Path::new(root_source), &mut closure)?;
    }
    let mut infrastructure_inventory = BTreeSet::new();
    collect_rust_inventory(
        &cser_root,
        Path::new("infrastructure"),
        &mut infrastructure_inventory,
    )?;
    let closure_infrastructure = closure
        .iter()
        .filter(|relative| relative.starts_with("infrastructure/"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if closure_infrastructure != infrastructure_inventory {
        return Err(format!(
            "CSER infrastructure module closure differs from its Rust inventory: closure={closure_infrastructure:?} inventory={infrastructure_inventory:?}"
        )
        .into());
    }
    Ok(closure.into_iter().collect())
}

fn validate_cser_production_manifest_text(
    source: &str,
    expected: &[String],
) -> Result<Vec<String>> {
    if !source.ends_with('\n') {
        return Err("CSER production source manifest must end with one newline".into());
    }
    let entries = source
        .lines()
        .map(|line| canonical_relative_source_path(Path::new(line)))
        .collect::<Result<Vec<_>>>()?;
    if entries.iter().any(|entry| !entry.ends_with(".rs")) {
        return Err("CSER production manifest may contain only Rust sources".into());
    }
    let unique = entries.iter().collect::<BTreeSet<_>>();
    if unique.len() != entries.len() {
        return Err("CSER production source manifest contains a duplicate".into());
    }
    let mut sorted = entries.clone();
    sorted.sort();
    if entries != sorted {
        return Err("CSER production source manifest is not strictly sorted".into());
    }
    if entries != expected {
        return Err(format!(
            "CSER production source manifest differs from module closure: manifest={entries:?} expected={expected:?}"
        )
        .into());
    }
    Ok(entries)
}

fn cser_production_source_files(root: &Path) -> Result<Vec<String>> {
    let manifest = root.join(CSER_PRODUCTION_SOURCE_MANIFEST);
    require_plain_regular_file_below(
        root,
        Path::new(CSER_PRODUCTION_SOURCE_MANIFEST),
        "CSER production source manifest",
    )?;
    let expected = expected_cser_production_sources(root)?;
    let entries =
        validate_cser_production_manifest_text(&fs::read_to_string(&manifest)?, &expected)?;
    for relative in &entries {
        let source_relative = Path::new(CSER_SOURCE_ROOT).join(relative);
        require_plain_regular_file_below(
            root,
            &source_relative,
            "manifest-bound CSER production source",
        )?;
    }
    Ok(entries)
}

fn require_source_order(label: &str, source: &str, fragments: &[&str]) -> Result<()> {
    let mut cursor = 0;
    for fragment in fragments {
        let Some(offset) = source[cursor..].find(fragment) else {
            return Err(format!("{label} is missing ordered source fragment: {fragment}").into());
        };
        cursor += offset + fragment.len();
    }
    Ok(())
}

fn source_function<'a>(source: &'a str, start: &str, next: &str) -> Result<&'a str> {
    let start = source
        .find(start)
        .ok_or_else(|| format!("supervisor runtime is missing function start: {start}"))?;
    let tail = &source[start..];
    let end = tail
        .find(next)
        .ok_or_else(|| format!("supervisor runtime is missing function boundary: {next}"))?;
    Ok(&tail[..end])
}

fn validate_ostd_supervisor_runtime_source(runtime: &str, kernel: &str) -> Result<()> {
    require_source_order(
        "supervisor activation completeness",
        source_function(
            runtime,
            "pub(crate) const fn is_complete",
            "/// Current exact",
        )?,
        &[
            "self.exact_task_exit_hook",
            "self.exact_task_reap_hook",
            "self.isolated_user_fault_boundary",
            "self.initial_active_task_binding",
            "self.nexus_owned_manager_worker",
            "self.worker_exact_reap_health",
            "self.generation_fenced_timer_ingress",
        ],
    )?;
    for capability in [
        "exact_task_exit_hook: true",
        "exact_task_reap_hook: true",
        "isolated_user_fault_boundary: true",
        "initial_active_task_binding: true",
        "nexus_owned_manager_worker: true",
        "worker_exact_reap_health: true",
        "generation_fenced_timer_ingress: true",
    ] {
        if !source_function(
            runtime,
            "pub(crate) const fn activation_report",
            "/// Opaque proof",
        )?
        .contains(capability)
        {
            return Err(format!(
                "supervisor activation report lost exact capability: {capability}"
            )
            .into());
        }
    }
    require_source_order(
        "supervisor permit gate",
        source_function(
            runtime,
            "fn permit_for_report",
            "/// Returns an activation permit",
        )?,
        &["if report.is_complete()", "OstdSupervisorActivationPermit"],
    )?;

    let enqueue = source_function(runtime, "    fn enqueue_signal_locked", "    fn emit_ready")?;
    if !enqueue.contains("self.events.disable_irq().lock()") {
        return Err("supervisor preallocated enqueue lost its events lock".into());
    }
    let emit = source_function(runtime, "    fn emit_ready", "    fn record_pending_exit")?;
    require_source_order(
        "supervisor event ingress lock order",
        emit,
        &[
            "self.replacement.disable_irq().lock()",
            "self.enqueue_signal_locked(",
        ],
    )?;
    let exact_reap = source_function(
        runtime,
        "    fn observe_exact_reap",
        "    fn mark_ready_accepted",
    )?;
    require_source_order(
        "supervisor exact-reap ingress lock order",
        exact_reap,
        &[
            "self.replacement.disable_irq().lock()",
            "self.enqueue_signal_locked(",
        ],
    )?;
    if exact_reap.matches("self.enqueue_signal_locked(").count() != 4 {
        return Err(
            "supervisor exact-reap ingress must retain four phase-scoped enqueue sites".into(),
        );
    }
    require_source_order(
        "supervisor exact-reap resource publication",
        exact_reap,
        &[
            "match slot.phase",
            "slot.phase = ReplacementSlotPhase::Reaped",
        ],
    )?;
    let wrapper_return =
        source_function(runtime, "    fn report_return", "/// Typed terminal result")?;
    if !wrapper_return.contains("record_pending_exit(")
        || wrapper_return.contains("enqueue_signal_locked")
        || wrapper_return.contains("OstdSupervisorEvent::Exit")
    {
        return Err(
            "service wrapper return must only retain an ExitReason until exact OSTD reap".into(),
        );
    }
    let user_fault_boundary = source_function(
        runtime,
        "    pub(crate) const fn from_user_mode_return",
        "/// Replacement program",
    )?;
    require_source_order(
        "isolated user-mode fault boundary",
        user_fault_boundary,
        &[
            "ReturnReason::UserException => Self::Fault",
            "ReturnReason::UserSyscall | ReturnReason::KernelEvent => Self::UnexpectedReturn",
        ],
    )?;
    if user_fault_boundary.contains("panic") || user_fault_boundary.contains("KernelFault") {
        return Err("user fault boundary may not claim or catch a kernel fault".into());
    }
    let flush = source_function(runtime, "    fn flush_oldest_retained", "    fn pop_event")?;
    require_source_order(
        "supervisor retained-event lock order",
        flush,
        &[
            "self.replacement.disable_irq().lock()",
            "self.events.disable_irq().lock()",
        ],
    )?;
    let pop = source_function(runtime, "    fn pop_event", "trait ExactTaskReapSink")?;
    require_source_order(
        "supervisor queue release before slot lock",
        pop,
        &[
            "let envelope = {",
            "self.events.disable_irq().lock()",
            "events.pop()?",
            "};",
            "self.replacement.disable_irq().lock()",
        ],
    )?;

    for (label, start, next) in [
        (
            "authority isolation slot-to-Registry lock order",
            "    fn isolate_authority",
            "    fn select_replacement",
        ),
        (
            "replacement selection slot-to-Registry lock order",
            "    fn select_replacement",
            "    fn construct_replacement",
        ),
        (
            "recovery abort slot-to-Registry lock order",
            "    fn abort_recovery_attempt",
            "    fn ready",
        ),
    ] {
        require_source_order(
            label,
            source_function(runtime, start, next)?,
            &["self.shared.replacement.disable_irq().lock()", ".registry"],
        )?;
    }

    require_source_order(
        "patched OSTD exact-reap binding",
        kernel,
        &[
            "supervisor_exit: Option<supervisor_runtime::OstdSupervisorTaskExitBinding>",
            "supervisor_worker_exit: Option<supervisor_runtime::OstdSupervisorWorkerExitBinding>",
            "fn new_supervised(",
            "fn new_supervisor_worker(",
            "inject_post_task_exit_handler(supervisor_runtime::observe_post_task_exit)",
        ],
    )?;
    let observer = source_function(
        runtime,
        "pub(crate) fn observe_post_task_exit",
        "/// Why a critical event",
    )?;
    require_source_order(
        "patched OSTD exact-reap observer",
        observer,
        &[
            "task.is_reaped()",
            "data.supervisor_exit",
            "binding.observe_exact_reap()",
            "data.supervisor_worker_exit",
            "binding.observe_exact_reap()",
        ],
    )?;

    let startup = source_function(
        runtime,
        "fn start_supervisor_runtime",
        "impl<const N: usize> OstdSupervisorRuntime<N>",
    )?;
    require_source_order(
        "initial-active and manager-worker install before publication",
        startup,
        &[
            "reserve_initial_active(selector)",
            "TaskData::new_supervised(",
            ".build()",
            "install_initial_active_task(",
            "install_runtime(runtime)",
            "TaskData::new_supervisor_worker(",
            ".build()",
            "install_initial_active_for_publication(selector)",
            "timer.install_on_current_cpu(config.timer_generation)",
            "worker.mark_published()",
            "shared.publish_initial_active(selector)",
            "worker_task.run()",
            "initial_task.run()",
        ],
    )?;
    if !startup.contains("authority: &OstdSupervisorActivationAuthority<N>")
        || !runtime.contains("authority: self,")
    {
        return Err("startup failure must return the exact linear activation authority".into());
    }
    let worker_run = source_function(
        runtime,
        "    fn run(&self)",
        "impl<const N: usize> ExactWorkerReapSink",
    )?;
    require_source_order(
        "worker takes runtime before bounded drive and restores it before return",
        worker_run,
        &[
            "self.runtime.disable_irq().lock().take()",
            "self.drive_until_stop(&mut runtime)",
            "self.install_runtime(runtime)",
            "self.mark_returned(terminal)",
        ],
    )?;
    require_source_order(
        "worker disables timer on every no-runtime terminal path",
        worker_run,
        &[
            "if !self.mark_running()",
            "self.finish_without_runtime(OstdSupervisorWorkerTerminal::LifecycleViolation)",
            "let Some(mut runtime) = self.runtime.disable_irq().lock().take() else",
            "self.finish_without_runtime(OstdSupervisorWorkerTerminal::MissingRuntime)",
            "self.drive_until_stop(&mut runtime)",
            "self.disable_timer_or_lifecycle(terminal)",
        ],
    )?;
    let worker_no_runtime_finish = source_function(
        runtime,
        "    fn finish_without_runtime",
        "    fn run(&self)",
    )?;
    require_source_order(
        "worker no-runtime terminal timer fence",
        worker_no_runtime_finish,
        &[
            "self.disable_timer_or_lifecycle(terminal)",
            "self.mark_returned",
        ],
    )?;
    if source_function(runtime, "    fn drive_until_stop", "    fn run(&self)")?
        .contains("self.runtime")
    {
        return Err("worker may not hold its runtime SpinLock across manager progress".into());
    }
    let timer = source_function(
        runtime,
        "    pub(crate) fn install_on_current_cpu",
        "    fn disable",
    )?;
    require_source_order(
        "generation-fenced weak timer ingress",
        timer,
        &[
            "generation == 0",
            "timer_generation",
            "Arc::downgrade(&self.shared)",
            "shared.timer_enabled.load(Ordering::Acquire)",
            "shared.timer_generation.load(Ordering::Acquire) == generation",
            "shared.tick_pending.store(true, Ordering::Release)",
        ],
    )?;
    Ok(())
}

fn parse_sha256_image_inputs(command: &str) -> Result<Vec<String>> {
    const PREFIX: &str = "image_key=$(sha256sum ";
    const SUFFIX: &str = " | cut -d ' ' -f1 | sha256sum | cut -c1-16)";
    let inputs = command
        .strip_prefix(PREFIX)
        .and_then(|command| command.strip_suffix(SUFFIX))
        .ok_or("image identity command has a non-canonical pipeline")?;
    let bytes = inputs.as_bytes();
    let mut offset = 0_usize;
    let mut parsed = Vec::new();
    while offset < bytes.len() {
        while bytes.get(offset) == Some(&b' ') {
            offset += 1;
        }
        if offset == bytes.len() {
            break;
        }
        if bytes.get(offset) != Some(&b'"') {
            return Err(format!(
                "image identity input is not one direct quoted path at byte {offset}"
            )
            .into());
        }
        offset += 1;
        let start = offset;
        while let Some(byte) = bytes.get(offset).copied() {
            if byte == b'"' {
                break;
            }
            if !(byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'$' | b'_' | b'/' | b'.' | b'-' | b'{' | b'}' | b'[' | b']' | b'@'
                ))
            {
                return Err(
                    format!("image identity path contains shell syntax at byte {offset}").into(),
                );
            }
            offset += 1;
        }
        if bytes.get(offset) != Some(&b'"') {
            return Err("unterminated image identity path".into());
        }
        let path = &inputs[start..offset];
        if !(path.starts_with("$root/")
            || path.starts_with("$repo_root/")
            || path == "$production_source_manifest"
            || path == "${cser_source_hash_inputs[@]}")
        {
            return Err(format!("image identity input has an unbound path root: {path}").into());
        }
        parsed.push(path.to_string());
        offset += 1;
        if offset < bytes.len() && bytes[offset] != b' ' {
            return Err(format!("image identity paths are not separated at byte {offset}").into());
        }
    }
    if parsed.is_empty() {
        return Err("image identity command has no inputs".into());
    }
    let unique = parsed.iter().collect::<BTreeSet<_>>();
    if unique.len() != parsed.len() {
        return Err("image identity command contains a duplicate input".into());
    }
    Ok(parsed)
}

fn validate_single_shell_command(command: &str) -> Result<()> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }
    let mut quote = Quote::None;
    let mut escaped = false;
    for byte in command.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match quote {
            Quote::Single => {
                if byte == b'\'' {
                    quote = Quote::None;
                }
            }
            Quote::Double => match byte {
                b'\\' => escaped = true,
                b'"' => quote = Quote::None,
                0x60 => return Err("shell command contains legacy substitution".into()),
                _ => {}
            },
            Quote::None => match byte {
                b'\\' => escaped = true,
                b'\'' => quote = Quote::Single,
                b'"' => quote = Quote::Double,
                b';' | b'|' | b'&' | b'#' | b'<' | b'>' | 0x60 => {
                    return Err("shell command contains an unreviewed control operator".into());
                }
                _ => {}
            },
        }
    }
    if escaped || quote != Quote::None {
        return Err("shell command has an unterminated quote or escape".into());
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum BackendValidationError {
    Semantic(String),
    RawAuthorityDrift {
        relative: String,
        expected: String,
        found: String,
    },
}

impl std::fmt::Display for BackendValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Semantic(reason) => write!(formatter, "semantic validation failed: {reason}"),
            Self::RawAuthorityDrift {
                relative,
                expected,
                found,
            } => write!(
                formatter,
                "{relative} raw authority source drifted: expected {expected}, found {found}"
            ),
        }
    }
}

impl Error for BackendValidationError {}

type BackendValidationResult<T> = std::result::Result<T, BackendValidationError>;

fn validate_backend_source_pair_semantics(
    relative: &str,
    source: &str,
    source_root: &str,
    files: &[String],
) -> Result<()> {
    if source.lines().next() != Some("#!/usr/bin/bash -p") {
        return Err(
            format!("{relative} must use the exact privileged absolute Bash interpreter").into(),
        );
    }
    let logical = continued_shell_lines(source)?;
    let active = logical.join("\n");
    let expected_manifest_assignment = match relative {
        "kernel/nexus-ostd/x" => {
            r#"production_source_manifest="$root/cser-production-sources.txt""#
        }
        "experiments/ostd-virtio-cser-spike/x" => {
            r#"production_source_manifest="$repo_root/kernel/nexus-ostd/cser-production-sources.txt""#
        }
        _ => return Err(format!("unknown production backend workflow: {relative}").into()),
    };
    // These digests freeze normalized logical command regions, not raw file
    // bytes: the binding digest covers the manifest assignment through both
    // readonly declarations, while the prelude digest proves that region runs
    // at top level. Update them only with the adversarial mutation matrix and a
    // real image build.
    let expected_binding_region_sha256 = match relative {
        "kernel/nexus-ostd/x" => "9c9e52ed7bb4be81a6bb98dde432749785a05931c948047438b5a7f253a8dc2f",
        "experiments/ostd-virtio-cser-spike/x" => {
            "1a80bca2d72fae2ce5081063d9d3d4270f51c8bbc17ba892facb1128ce08e8ee"
        }
        _ => return Err(format!("unknown production backend workflow: {relative}").into()),
    };
    let expected_prelude_sha256 = match relative {
        "kernel/nexus-ostd/x" => "d4df2814513b02f39046f899da30b40815502e705918ddd5a2d83c6b475b2c55",
        "experiments/ostd-virtio-cser-spike/x" => {
            "c287287fbe0148687c7fd2f3b2b8585b34bea8c94f49275dfa70d7a6321f252f"
        }
        _ => return Err(format!("unknown production backend workflow: {relative}").into()),
    };
    let binding_starts = logical
        .iter()
        .enumerate()
        .filter(|(_, line)| line.as_str() == expected_manifest_assignment)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let image_starts = logical
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("image_key=$(sha256sum "))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if binding_starts.len() != 1 || image_starts.len() != 1 || binding_starts[0] >= image_starts[0]
    {
        return Err(format!(
            "{relative} must have one ordered manifest-to-image source-binding region"
        )
        .into());
    }
    let prelude_sha256 = sha256(logical[..binding_starts[0]].join("\n").as_bytes());
    if prelude_sha256 != expected_prelude_sha256 {
        return Err(format!(
            "{relative} source-binding prelude drifted: expected {expected_prelude_sha256}, found {prelude_sha256}"
        )
        .into());
    }
    let binding_region = logical[binding_starts[0]..image_starts[0]].join("\n");
    let binding_region_sha256 = sha256(binding_region.as_bytes());
    if binding_region_sha256 != expected_binding_region_sha256 {
        return Err(format!(
            "{relative} source-binding command sequence drifted: expected {expected_binding_region_sha256}, found {binding_region_sha256}"
        )
        .into());
    }
    for required in [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "readonly PATH",
        "docker_bin=/usr/bin/docker",
        r#"if [[ ! -f $docker_bin || ! -x $docker_bin || -L $docker_bin ]] || [[ $(/usr/bin/realpath -e -- "$docker_bin") != "$docker_bin" ]]; then"#,
        "readonly docker_bin",
        r#"capture_helper="$root/scripts/qemu-stream-capture.sh""#,
        "capture_helper_sha256=b05544fb66e5d124fb141696accb1933742de561469f1c9e4a12eef3c6c5e7b7",
        r#"if [[ ! -f $capture_helper || -L $capture_helper ]] || [[ $(/usr/bin/realpath -e -- "$capture_helper") != "$capture_helper" ]]; then"#,
        r#"if [[ $(/usr/bin/sha256sum -- "$capture_helper" | /usr/bin/cut -d ' ' -f1) != "$capture_helper_sha256" ]]; then"#,
        "readonly capture_helper capture_helper_sha256",
        expected_manifest_assignment,
        r#"if [[ ! -f $production_source_manifest || -L $production_source_manifest ]] || [[ $(realpath -e -- "$production_source_manifest") != "$production_source_manifest" ]]; then"#,
        r#"mapfile -t cser_production_sources <"$production_source_manifest""#,
        r#"for relative in "${cser_production_sources[@]}"; do"#,
        r#"$relative == ./* || $relative == *"/./"*"#,
        &format!(r#"source_path="{source_root}/$relative""#),
        r#"target_path="/kernel/nexus-ostd/src/cser/$relative""#,
        r#"if [[ ! -f $source_path || -L $source_path ]] || [[ $(realpath -e -- "$source_path") != "$source_path" ]]; then"#,
        r#"cser_source_hash_inputs+=("$source_path")"#,
        r#"cser_source_mount_args+=(--mount "type=bind,source=$source_path,target=$target_path,readonly")"#,
        "readonly production_source_manifest",
        "readonly -a cser_production_sources cser_source_hash_inputs cser_source_mount_args",
    ] {
        if active.matches(required).count() != 1 {
            return Err(format!(
                "{relative} lacks one canonical manifest-driven source step: {required}"
            )
            .into());
        }
    }
    if active.matches("cser_production_sources").count() != 4
        || active.matches("cser_source_hash_inputs").count() != 4
        || active.matches("cser_source_mount_args").count() != 4
    {
        return Err(format!(
            "{relative} must derive hash and mount arrays only once from the canonical manifest"
        )
        .into());
    }
    let expected_helper_sources = if relative == "kernel/nexus-ostd/x" {
        4
    } else {
        1
    };
    if active.matches(r#"source "$capture_helper""#).count() != expected_helper_sources {
        return Err(format!(
            "{relative} must source only the raw-frozen QEMU capture helper at its exact reviewed sites"
        )
        .into());
    }
    let image_commands = logical
        .iter()
        .filter(|line| line.starts_with("image_key=$(sha256sum "))
        .collect::<Vec<_>>();
    if image_commands.len() != 1 {
        return Err(format!("{relative} must have one canonical image identity command").into());
    }
    let image_inputs = parse_sha256_image_inputs(image_commands[0])?;
    for expected in [
        "$production_source_manifest",
        "${cser_source_hash_inputs[@]}",
    ] {
        if image_inputs
            .iter()
            .filter(|input| input.as_str() == expected)
            .count()
            != 1
        {
            return Err(format!(
                "{relative} must hash the manifest and its derived exact source array"
            )
            .into());
        }
    }
    if image_inputs
        .iter()
        .any(|input| input.starts_with(&format!("{source_root}/")))
    {
        return Err(format!(
            "{relative} must not append hidden literal CSER inputs outside the manifest array"
        )
        .into());
    }
    let container = function_body(source, "container() {")?;
    let container_lines = continued_shell_lines(container)?;
    let docker_runs = container_lines
        .iter()
        .filter(|line| line.starts_with(r#"command "$docker_bin" run --rm "#))
        .collect::<Vec<_>>();
    if docker_runs.len() != 1 {
        return Err(format!("{relative} must have one canonical container command").into());
    }
    validate_single_shell_command(docker_runs[0])?;
    if docker_runs[0]
        .matches(r#""${cser_source_mount_args[@]}""#)
        .count()
        != 1
        || docker_runs[0].matches(r#""$image""#).count() != 1
        || docker_runs[0].contains("target=/kernel/nexus-ostd/src/cser/")
    {
        return Err(format!(
            "{relative} must mount only the exact manifest-derived CSER source array"
        )
        .into());
    }
    let mount_offset = docker_runs[0]
        .find(r#""${cser_source_mount_args[@]}""#)
        .expect("validated exact mount expansion");
    let image_offset = docker_runs[0]
        .find(r#""$image""#)
        .expect("validated exact image argument");
    if mount_offset >= image_offset || !docker_runs[0].ends_with(r#""$image" "$@""#) {
        return Err(format!(
            "{relative} must place the source mounts before the sole image and command tail"
        )
        .into());
    }
    for file in files {
        let source_path = format!("{source_root}/{file}");
        let target_path = format!("/kernel/nexus-ostd/src/cser/{file}");
        if active.contains(&source_path) || docker_runs[0].contains(&target_path) {
            return Err(format!(
                "{relative} duplicates manifest-owned source {file} outside the canonical loop"
            )
            .into());
        }
    }
    Ok(())
}

fn expected_backend_source_sha256(relative: &str) -> Result<&'static str> {
    match relative {
        "kernel/nexus-ostd/x" => {
            Ok("b2f3a6d65ef9996950ad59f21d387c24481e0f099f6cb62b9b4469c6c2ace0c4")
        }
        "experiments/ostd-virtio-cser-spike/x" => {
            Ok("e51d863a8134cfd8b25ff33438441c73a93f6548ea0202fad54a6c4270153ee9")
        }
        _ => Err(format!("unknown production backend workflow: {relative}").into()),
    }
}

fn validate_raw_backend_authority(
    relative: &str,
    source: &str,
    expected: &str,
) -> BackendValidationResult<()> {
    let found = sha256(source.as_bytes());
    if found != expected {
        return Err(BackendValidationError::RawAuthorityDrift {
            relative: relative.to_owned(),
            expected: expected.to_owned(),
            found,
        });
    }
    Ok(())
}

fn validate_backend_source_pair(
    relative: &str,
    source: &str,
    source_root: &str,
    files: &[String],
) -> BackendValidationResult<()> {
    validate_backend_source_pair_semantics(relative, source, source_root, files)
        .map_err(|error| BackendValidationError::Semantic(error.to_string()))?;
    let expected = expected_backend_source_sha256(relative)
        .map_err(|error| BackendValidationError::Semantic(error.to_string()))?;
    validate_raw_backend_authority(relative, source, expected)
}

fn validate_backend_docker_source_set_semantics(
    relative: &str,
    dockerfile: &str,
    files: &[String],
) -> Result<()> {
    // The fresh verifier stage prevents repository-controlled build steps from
    // replacing the candidate tree or its audit tools. The pinned frontend/base
    // image, BuildKit stage-snapshot and read-only-mount semantics, and the
    // host-context snapshot between this gate and BuildKit remain explicit TCB.
    if dockerfile.lines().next() != Some(PINNED_DOCKER_SYNTAX) {
        return Err(format!("{relative} must retain the exact pinned Docker syntax").into());
    }
    let directives = dockerfile
        .lines()
        .filter_map(|line| line.trim().strip_prefix('#').map(str::trim_start))
        .filter(|comment| {
            let lowercase = comment.to_ascii_lowercase();
            lowercase.starts_with("syntax=")
                || lowercase.starts_with("escape=")
                || lowercase.starts_with("check=")
        })
        .collect::<Vec<_>>();
    if directives != [PINNED_DOCKER_SYNTAX.trim_start_matches("# ")] {
        return Err(format!(
            "{relative} has an additional or mutated Docker parser directive: {directives:?}"
        )
        .into());
    }
    if dockerfile.contains("<<") {
        return Err(format!("{relative} may not use Docker or shell heredocs").into());
    }

    let copy_prefix = match relative {
        "kernel/nexus-ostd/Dockerfile" => "COPY ",
        "experiments/ostd-virtio-cser-spike/Dockerfile" => "COPY --from=nexus-root ",
        _ => return Err(format!("unknown production backend Dockerfile: {relative}").into()),
    };
    let expected_verifier_sha256 = match relative {
        "kernel/nexus-ostd/Dockerfile" => {
            "e34a04b60781fda89688343feae03b388da0888b53a3c1e925e9b8f324f62a5c"
        }
        "experiments/ostd-virtio-cser-spike/Dockerfile" => {
            "65d4f1517e342ca620afe57feace001cb5f12aff620522f501cfcb2cb4eab6cb"
        }
        _ => return Err(format!("unknown production backend Dockerfile: {relative}").into()),
    };
    let logical = continued_shell_lines(dockerfile)?;
    for (index, line) in logical.iter().enumerate() {
        let opcode = line
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| format!("{relative} has an empty Docker instruction"))?;
        if !opcode.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(
                format!("{relative} has a malformed Docker instruction opcode: {opcode}").into(),
            );
        }
        let uppercase = opcode.to_ascii_uppercase();
        if opcode != uppercase {
            return Err(format!(
                "{relative} Docker instruction must use canonical uppercase: {opcode}"
            )
            .into());
        }
        if matches!(uppercase.as_str(), "ADD" | "ONBUILD") {
            return Err(format!("{relative} may not use Docker {uppercase}").into());
        }
        if !matches!(
            uppercase.as_str(),
            "ARG" | "COPY" | "ENV" | "FROM" | "RUN" | "WORKDIR"
        ) {
            return Err(format!("{relative} uses unaudited Docker instruction {uppercase}").into());
        }
        if uppercase == "RUN"
            && (line.contains("/kernel/nexus-ostd/src/cser")
                || line.contains("/kernel/nexus-ostd/cser-production-sources.txt"))
            && index + 3 != logical.len()
        {
            return Err(format!(
                "{relative} may inspect the cold CSER tree only in the isolated verifier stage"
            )
            .into());
        }
    }
    if logical
        .iter()
        .filter(|line| line.starts_with("FROM "))
        .collect::<Vec<_>>()
        != [
            "FROM ${OSDK_IMAGE} AS build",
            "FROM ${OSDK_IMAGE} AS cser-verifier",
            "FROM build AS final",
        ]
    {
        return Err(format!(
            "{relative} must retain the exact build, fresh verifier, and marker-only final stages"
        )
        .into());
    }
    let tail = logical
        .get(logical.len().saturating_sub(4)..)
        .ok_or_else(|| format!("{relative} has no complete verifier/final stage tail"))?;
    let expected_verifier_from = "FROM ${OSDK_IMAGE} AS cser-verifier";
    let expected_final_from = "FROM build AS final";
    let expected_final_copy = "COPY --from=cser-verifier /verified /nexus-cser-verified";
    if tail[0] != expected_verifier_from
        || tail[2] != expected_final_from
        || tail[3] != expected_final_copy
    {
        return Err(format!(
            "{relative} must end with one fresh verifier RUN and the sole final proof-marker COPY"
        )
        .into());
    }
    let verifier = &tail[1];
    let expected_context_mount = match relative {
        "kernel/nexus-ostd/Dockerfile" => {
            "--mount=type=bind,source=kernel/nexus-ostd,target=/expected-kernel,readonly"
        }
        "experiments/ostd-virtio-cser-spike/Dockerfile" => {
            "--mount=type=bind,from=nexus-root,source=kernel/nexus-ostd,target=/expected-kernel,readonly"
        }
        _ => unreachable!("relative checked above"),
    };
    for required in [
        "RUN --network=none",
        "--mount=type=bind,from=build,source=/,target=/candidate-root,readonly",
        expected_context_mount,
        "test ! -e /candidate-root/nexus-cser-verified",
        "test ! -L /candidate-root/nexus-cser-verified",
        "/usr/bin/cmp /tmp/nexus-cser-expected /tmp/nexus-cser-candidate",
        "chmod 0444 /verified",
    ] {
        if verifier.matches(required).count() != 1 {
            return Err(format!(
                "{relative} isolated verifier lacks one canonical proof step: {required}"
            )
            .into());
        }
    }
    if verifier.matches("nexus.cser.image-source-proof.v1").count() != 2 {
        return Err(format!(
            "{relative} verifier must bind the proof schema into both aggregate input and marker"
        )
        .into());
    }
    if verifier.matches("test ! -L /verified").count() != 2 {
        return Err(format!(
            "{relative} verifier must reject a pre-existing and a substituted proof-marker symlink"
        )
        .into());
    }
    let verifier_sha256 = sha256(verifier.as_bytes());
    if verifier_sha256 != expected_verifier_sha256 {
        return Err(format!(
            "{relative} isolated verifier drifted: expected {expected_verifier_sha256}, found {verifier_sha256}"
        )
        .into());
    }

    let flat_sources = files
        .iter()
        .filter(|file| !file.contains('/'))
        .map(|file| format!("kernel/nexus-ostd/src/cser/{file}"))
        .collect::<Vec<_>>()
        .join(" ");
    let expected_flat = format!("{copy_prefix}{flat_sources} /kernel/nexus-ostd/src/cser/");
    let mut expected = vec![expected_flat];
    for file in files.iter().filter(|file| file.contains('/')) {
        expected.push(format!(
            "{copy_prefix}kernel/nexus-ostd/src/cser/{file} /kernel/nexus-ostd/src/cser/{file}"
        ));
    }
    expected.push(format!(
        "{copy_prefix}kernel/nexus-ostd/cser-production-sources.txt /kernel/nexus-ostd/cser-production-sources.txt"
    ));
    let actual = logical
        .iter()
        .filter(|line| {
            line.starts_with("COPY ")
                && (line.contains("kernel/nexus-ostd/src/cser")
                    || line.contains("/kernel/nexus-ostd/src/cser")
                    || line.contains("kernel/nexus-ostd/cser-production-sources.txt")
                    || line.contains("/kernel/nexus-ostd/cser-production-sources.txt"))
        })
        .cloned()
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(format!(
            "{relative} cold CSER COPY multiset differs from the canonical manifest: actual={actual:?} expected={expected:?}"
        )
        .into());
    }
    Ok(())
}

fn expected_backend_docker_sha256(relative: &str) -> Result<&'static str> {
    match relative {
        "kernel/nexus-ostd/Dockerfile" => {
            Ok("bc67ae442290e4aee975ad2e5ff4e40a5799ec9527f9cf29f36c5418939811a3")
        }
        "experiments/ostd-virtio-cser-spike/Dockerfile" => {
            Ok("c09f2565776d1695fbdae0a3f693e11978402d44c32436ff5e117af33bccc987")
        }
        _ => Err(format!("unknown production backend Dockerfile: {relative}").into()),
    }
}

fn validate_backend_docker_source_set(
    relative: &str,
    dockerfile: &str,
    files: &[String],
) -> BackendValidationResult<()> {
    validate_backend_docker_source_set_semantics(relative, dockerfile, files)
        .map_err(|error| BackendValidationError::Semantic(error.to_string()))?;
    let expected = expected_backend_docker_sha256(relative)
        .map_err(|error| BackendValidationError::Semantic(error.to_string()))?;
    validate_raw_backend_authority(relative, dockerfile, expected)
}

fn validate_portal_abi_image_binding(kernel: &str, kernel_dockerfile: &str) -> Result<()> {
    let logical = continued_shell_lines(kernel)?;
    let image_commands = logical
        .iter()
        .filter(|line| line.starts_with("image_key=$(sha256sum "))
        .collect::<Vec<_>>();
    if image_commands.len() != 1 {
        return Err("kernel/nexus-ostd/x must have one canonical image identity command".into());
    }
    let image_inputs = parse_sha256_image_inputs(image_commands[0])?;
    for relative in PORTAL_ABI_IMAGE_INPUTS {
        let input = format!("$repo_root/crates/nexus-portal-abi/{relative}");
        if image_inputs
            .iter()
            .filter(|candidate| candidate.as_str() == input)
            .count()
            != 1
        {
            return Err(format!(
                "kernel/nexus-ostd/x must hash portal ABI input exactly once: {relative}"
            )
            .into());
        }
    }
    let container = function_body(kernel, "container() {")?;
    let container_lines = continued_shell_lines(container)?;
    let docker_runs = container_lines
        .iter()
        .filter(|line| line.starts_with(r#"command "$docker_bin" run --rm "#))
        .collect::<Vec<_>>();
    let portal_mount = r#"-v "$repo_root/crates/nexus-portal-abi:/crates/nexus-portal-abi:ro,z""#;
    if docker_runs.len() != 1 {
        return Err("kernel/nexus-ostd/x must have one canonical container command".into());
    }
    validate_single_shell_command(docker_runs[0])?;
    if docker_runs[0].matches(portal_mount).count() != 1 {
        return Err("kernel/nexus-ostd/x must live-mount the portal ABI exactly once".into());
    }
    if continued_shell_lines(kernel_dockerfile)?
        .iter()
        .filter(|line| *line == "COPY crates/nexus-portal-abi /crates/nexus-portal-abi")
        .count()
        != 1
    {
        return Err("kernel Dockerfile must bake the portal ABI exactly once".into());
    }
    Ok(())
}

const QEMU_CAPTURE_HELPER_SHA256: &str =
    "b05544fb66e5d124fb141696accb1933742de561469f1c9e4a12eef3c6c5e7b7";
const QEMU_CAPTURE_HELPERS: [&str; 2] = [
    "kernel/nexus-ostd/scripts/qemu-stream-capture.sh",
    "experiments/ostd-virtio-cser-spike/scripts/qemu-stream-capture.sh",
];

fn validate_qemu_capture_helper_bytes(relative: &str, source: &[u8]) -> Result<()> {
    let found = sha256(source);
    if found != QEMU_CAPTURE_HELPER_SHA256 {
        return Err(format!(
            "{relative} raw helper source drifted: expected {QEMU_CAPTURE_HELPER_SHA256}, found {found}"
        )
        .into());
    }
    Ok(())
}

fn validate_qemu_capture_helpers(root: &Path) -> Result<()> {
    let mut canonical = None;
    for relative in QEMU_CAPTURE_HELPERS {
        require_plain_regular_file_below(
            root,
            Path::new(relative),
            "QEMU capture authority helper",
        )?;
        let source = fs::read(root.join(relative))?;
        validate_qemu_capture_helper_bytes(relative, &source)?;
        if let Some(expected) = &canonical {
            if expected != &source {
                return Err("QEMU capture authority helpers must remain byte-identical".into());
            }
        } else {
            canonical = Some(source);
        }
    }
    Ok(())
}

fn validate_backend_source_binding(root: &Path) -> Result<()> {
    validate_qemu_capture_helpers(root)?;
    let production_files = cser_production_source_files(root)?;
    validate_ostd_supervisor_runtime_source(
        &fs::read_to_string(root.join(OSTD_SUPERVISOR_RUNTIME_SOURCE))?,
        &fs::read_to_string(root.join("kernel/nexus-ostd/src/lib.rs"))?,
    )?;
    for (relative, source_root) in [
        ("kernel/nexus-ostd/x", "$root/src/cser"),
        (
            "experiments/ostd-virtio-cser-spike/x",
            "$repo_root/kernel/nexus-ostd/src/cser",
        ),
    ] {
        let source = fs::read_to_string(root.join(relative))?;
        validate_backend_source_pair(relative, &source, source_root, &production_files)?;
    }
    let substrate_binding = [
        "/usr/local/bin/assert-production-virtio-substrate",
        "/crates/nexus-ostd-virtio/src/production.rs",
        "/crates/nexus-ostd-virtio/src/lib.rs",
        "/crates/nexus-ostd-virtio/src/portal.rs",
        "/crates/nexus-ostd-virtio/src/pci.rs",
    ]
    .join(" \\\n        ");
    for relative in [
        "kernel/nexus-ostd/Dockerfile",
        "experiments/ostd-virtio-cser-spike/Dockerfile",
    ] {
        let dockerfile = fs::read_to_string(root.join(relative))?;
        validate_backend_docker_source_set(relative, &dockerfile, &production_files)?;
        for source in [
            "/crates/nexus-ostd-virtio/src/production.rs",
            "/crates/nexus-ostd-virtio/src/lib.rs",
            "/crates/nexus-ostd-virtio/src/portal.rs",
            "/crates/nexus-ostd-virtio/src/pci.rs",
        ] {
            if !dockerfile.contains(source) {
                return Err(
                    format!("{relative} does not prime production source: {source}").into(),
                );
            }
        }
        if !dockerfile.contains(&substrate_binding) {
            return Err(format!(
                "{relative} does not pass all four sources to the production substrate gate"
            )
            .into());
        }
    }
    let spike = fs::read_to_string(root.join("experiments/ostd-virtio-cser-spike/x"))?;
    for required in [
        "pci_source=/crates/nexus-ostd-virtio/src/pci.rs",
        "check_production_substrate() {",
        r#""$1" "$facade_lib" "$portal_source" "$pci_source""#,
    ] {
        if !spike.contains(required) {
            return Err(format!(
                "spike mutation gate lacks complete PCI source binding: {required}"
            )
            .into());
        }
    }
    if spike
        .matches("/repo/tools/virtio/assert-production-substrate.sh")
        .count()
        != 1
        || spike.matches("if check_production_substrate ").count() != 8
    {
        return Err(
            "spike production mutations must route exclusively through the four-source helper"
                .into(),
        );
    }
    let spike_assertion = fs::read_to_string(
        root.join("experiments/ostd-virtio-cser-spike/scripts/assert-patch.sh"),
    )?;
    let spike_assertion_binding = [
        r#""$facade_root/src/production.rs""#,
        r#""$facade_root/src/lib.rs""#,
        r#""$facade_root/src/portal.rs""#,
        r#""$facade_root/src/pci.rs""#,
    ]
    .join(" \\\n    ");
    if !spike_assertion.contains(&spike_assertion_binding) {
        return Err("spike positive substrate gate lacks explicit PCI source binding".into());
    }
    let kernel = fs::read_to_string(root.join("kernel/nexus-ostd/x"))?;
    let kernel_dockerfile = fs::read_to_string(root.join("kernel/nexus-ostd/Dockerfile"))?;
    validate_portal_abi_image_binding(&kernel, &kernel_dockerfile)
}

fn validate_transition_gate_route(root: &Path) -> Result<()> {
    let source = fs::read_to_string(root.join("tools/xtask/src/main.rs"))?;
    let host_build = cargo_route_invocation(
        &source,
        "fn build(root: &Path) -> Result<()> {",
        "build the root workspace for the host",
    )?;
    let expected_host_build = [
        "build",
        "--locked",
        "--workspace",
        "--all-targets",
        "--all-features",
    ];
    if host_build != expected_host_build {
        return Err(format!(
            "root workspace build route mismatch: expected {expected_host_build:?}, found {host_build:?}"
        )
        .into());
    }
    for (section, package, required) in [
        (
            "build cser-model for the bare-metal target without std",
            "cser-model",
            &[
                "--no-default-features",
                "--lib",
                "--target",
                "x86_64-unknown-none",
            ][..],
        ),
        (
            "build portal ABI v2 preview on the bare-metal target",
            "nexus-portal-abi",
            &["--lib", "--target", "x86_64-unknown-none"][..],
        ),
        (
            "build supervisor manager on the bare-metal target",
            "nexus-supervisor",
            &["--lib", "--target", "x86_64-unknown-none"][..],
        ),
    ] {
        validate_cargo_route_section(
            &source,
            "fn build(root: &Path) -> Result<()> {",
            section,
            "build",
            package,
            required,
        )?;
    }
    for (declaration, section, command, package) in [
        (
            "fn check(root: &Path) -> Result<()> {",
            "check production transition gates",
            "check",
            "cser-transition-gates",
        ),
        (
            "fn clippy(root: &Path) -> Result<()> {",
            "clippy production transition gates",
            "clippy",
            "cser-transition-gates",
        ),
        (
            "fn test(root: &Path) -> Result<()> {",
            "test production transition gates",
            "test",
            "cser-transition-gates",
        ),
        (
            "fn check(root: &Path) -> Result<()> {",
            "check production effect peer",
            "check",
            "nexus-effect-peer",
        ),
        (
            "fn clippy(root: &Path) -> Result<()> {",
            "clippy production effect peer",
            "clippy",
            "nexus-effect-peer",
        ),
        (
            "fn test(root: &Path) -> Result<()> {",
            "test production effect peer",
            "test",
            "nexus-effect-peer",
        ),
        (
            "fn check(root: &Path) -> Result<()> {",
            "check portal ABI v2 preview",
            "check",
            "nexus-portal-abi",
        ),
        (
            "fn clippy(root: &Path) -> Result<()> {",
            "clippy portal ABI v2 preview",
            "clippy",
            "nexus-portal-abi",
        ),
        (
            "fn test(root: &Path) -> Result<()> {",
            "test portal ABI v2 preview",
            "test",
            "nexus-portal-abi",
        ),
        (
            "fn check(root: &Path) -> Result<()> {",
            "check supervisor manager",
            "check",
            "nexus-supervisor",
        ),
        (
            "fn clippy(root: &Path) -> Result<()> {",
            "clippy supervisor manager",
            "clippy",
            "nexus-supervisor",
        ),
        (
            "fn test(root: &Path) -> Result<()> {",
            "test supervisor manager",
            "test",
            "nexus-supervisor",
        ),
    ] {
        let required: &[&str] = if command == "test" {
            &["--all-targets", "--no-fail-fast"]
        } else {
            &["--all-targets"]
        };
        validate_cargo_route_section(&source, declaration, section, command, package, required)?;
    }
    for (declaration, section, command, package) in [
        (
            "fn check(root: &Path) -> Result<()> {",
            "check portal ABI v2 preview on the bare-metal target",
            "check",
            "nexus-portal-abi",
        ),
        (
            "fn clippy(root: &Path) -> Result<()> {",
            "clippy portal ABI v2 preview on the bare-metal target",
            "clippy",
            "nexus-portal-abi",
        ),
        (
            "fn check(root: &Path) -> Result<()> {",
            "check supervisor manager on the bare-metal target",
            "check",
            "nexus-supervisor",
        ),
        (
            "fn clippy(root: &Path) -> Result<()> {",
            "clippy supervisor manager on the bare-metal target",
            "clippy",
            "nexus-supervisor",
        ),
    ] {
        validate_cargo_route_section(
            &source,
            declaration,
            section,
            command,
            package,
            &["--lib", "--target", "x86_64-unknown-none"],
        )?;
    }
    for (manifest, label) in [
        (EFFECT_PEER_MANIFEST, "production effect peer"),
        (PORTAL_ABI_MANIFEST, "portal ABI v2 preview"),
        (SUPERVISOR_MANIFEST, "supervisor manager"),
    ] {
        if !root.join(manifest).is_file() {
            return Err(format!("missing {label}: {manifest}").into());
        }
    }
    let production_registry = fs::read_to_string(root.join(PRODUCTION_REGISTRY_TEST))?;
    validate_production_registry_gate(&production_registry)?;
    Ok(())
}

fn validate_cargo_route_section(
    source: &str,
    declaration: &str,
    section: &str,
    command: &str,
    package: &str,
    required: &[&str],
) -> Result<()> {
    let invocation = cargo_route_invocation(source, declaration, section)?;
    let mut expected = vec![command, "--locked", "-p", package];
    expected.extend(required.iter().copied());
    if command == "clippy" {
        expected.extend(["--", "-D", "warnings"]);
    }
    if invocation != expected {
        return Err(format!(
            "{declaration} section {section} cargo arguments mismatch: expected {expected:?}, found {invocation:?}"
        )
        .into());
    }
    Ok(())
}

fn cargo_route_invocation(source: &str, declaration: &str, section: &str) -> Result<Vec<String>> {
    let body = function_body(source, declaration)?;
    let marker = format!("section(\"{section}\");");
    let (_, tail) = body
        .split_once(&marker)
        .ok_or_else(|| format!("{declaration} lacks workflow section: {section}"))?;
    let invocation = tail.trim_start();
    parse_direct_cargo_call(invocation).map_err(|error| {
        format!("{declaration} section {section} has invalid cargo route: {error}").into()
    })
}

struct CargoCallParser<'a> {
    source: &'a [u8],
    offset: usize,
}

impl<'a> CargoCallParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source: source.as_bytes(),
            offset: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        while self
            .source
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }

    fn expect_literal(&mut self, literal: &str) -> std::result::Result<(), String> {
        if self.source.get(self.offset..self.offset + literal.len()) == Some(literal.as_bytes()) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err(format!("expected {literal:?} at byte {}", self.offset))
        }
    }

    fn expect_byte(&mut self, expected: u8) -> std::result::Result<(), String> {
        if self.source.get(self.offset) == Some(&expected) {
            self.offset += 1;
            Ok(())
        } else {
            Err(format!(
                "expected {:?} at byte {}",
                char::from(expected),
                self.offset
            ))
        }
    }

    fn parse_string(&mut self) -> std::result::Result<String, String> {
        self.expect_byte(b'"')?;
        let start = self.offset;
        while let Some(byte) = self.source.get(self.offset).copied() {
            match byte {
                b'"' => {
                    let value = std::str::from_utf8(&self.source[start..self.offset])
                        .map_err(|_| "cargo argument is not UTF-8".to_string())?
                        .to_string();
                    self.offset += 1;
                    return Ok(value);
                }
                b'\\' | b'\n' | b'\r' => {
                    return Err(format!(
                        "cargo argument uses an unsupported escape or newline at byte {}",
                        self.offset
                    ));
                }
                _ => self.offset += 1,
            }
        }
        Err("cargo argument string is unterminated".into())
    }
}

fn parse_direct_cargo_call(source: &str) -> std::result::Result<Vec<String>, String> {
    let mut parser = CargoCallParser::new(source);
    parser.expect_literal("cargo")?;
    parser.skip_whitespace();
    parser.expect_byte(b'(')?;
    parser.skip_whitespace();
    parser.expect_literal("root")?;
    parser.skip_whitespace();
    parser.expect_byte(b',')?;
    parser.skip_whitespace();
    parser.expect_byte(b'[')?;

    let mut arguments = Vec::new();
    loop {
        parser.skip_whitespace();
        if parser.source.get(parser.offset) == Some(&b']') {
            parser.offset += 1;
            break;
        }
        arguments.push(parser.parse_string()?);
        parser.skip_whitespace();
        match parser.source.get(parser.offset) {
            Some(b',') => parser.offset += 1,
            Some(b']') => {}
            _ => {
                return Err(format!(
                    "expected a comma or array terminator at byte {}",
                    parser.offset
                ));
            }
        }
    }

    parser.skip_whitespace();
    parser.expect_byte(b',')?;
    parser.skip_whitespace();
    parser.expect_byte(b')')?;
    parser.expect_byte(b'?')?;
    parser.expect_byte(b';')?;
    Ok(arguments)
}

fn module_path(module: &syn::ItemMod) -> Result<String> {
    if module
        .attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
    {
        return Err(format!("module {} may not be conditionally compiled", module.ident).into());
    }
    let mut paths = module
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("path"));
    let path = paths
        .next()
        .ok_or_else(|| format!("module {} lacks an exact path attribute", module.ident))?;
    if paths.next().is_some() {
        return Err(format!("module {} has duplicate path attributes", module.ident).into());
    }
    let syn::Meta::NameValue(name_value) = &path.meta else {
        return Err(format!("module {} has a non-literal path attribute", module.ident).into());
    };
    let syn::Expr::Lit(expression) = &name_value.value else {
        return Err(format!("module {} has a computed path attribute", module.ident).into());
    };
    let syn::Lit::Str(path) = &expression.lit else {
        return Err(format!("module {} has a non-string path attribute", module.ident).into());
    };
    Ok(path.value())
}

fn direct_zero_argument_call(statement: &syn::Stmt) -> Option<String> {
    let syn::Stmt::Expr(syn::Expr::Call(call), Some(_semicolon)) = statement else {
        return None;
    };
    if !call.attrs.is_empty() || !call.args.is_empty() {
        return None;
    }
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return None;
    };
    if function.qself.is_some() || function.path.leading_colon.is_some() {
        return None;
    }
    let segments = function
        .path
        .segments
        .iter()
        .map(|segment| {
            if matches!(segment.arguments, syn::PathArguments::None) {
                Some(canonical_ident(&segment.ident))
            } else {
                None
            }
        })
        .collect::<Option<Vec<_>>>()?;
    Some(segments.join("::"))
}

fn validate_production_registry_gate(source: &str) -> Result<()> {
    let syntax = syn::parse_file(source)
        .map_err(|error| format!("{PRODUCTION_REGISTRY_TEST} is not valid Rust source: {error}"))?;
    let required_modules = [
        (
            "effect_registry",
            "../../../kernel/nexus-ostd/src/cser/effect_registry.rs",
        ),
        (
            "device_flight",
            "../../../kernel/nexus-ostd/src/cser/device_flight.rs",
        ),
        (
            "portal_v2",
            "../../../kernel/nexus-ostd/src/cser/portal_v2.rs",
        ),
    ];
    for (name, expected_path) in required_modules {
        let modules = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Mod(module) if module.ident == name => Some(module),
                _ => None,
            })
            .collect::<Vec<_>>();
        if modules.len() != 1
            || modules[0].content.is_some()
            || module_path(modules[0])? != expected_path
        {
            return Err(format!(
                "{PRODUCTION_REGISTRY_TEST} must bind module {name} exactly once to {expected_path}"
            )
            .into());
        }
    }

    let tests = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident
                    == "production_identity_chain_uses_one_registry_and_shared_ledger" =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if tests.len() != 1
        || !tests[0]
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("test"))
        || tests[0].attrs.iter().any(|attribute| {
            attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr")
        })
        || !tests[0].sig.inputs.is_empty()
        || !matches!(tests[0].sig.output, syn::ReturnType::Default)
    {
        return Err(format!(
            "{PRODUCTION_REGISTRY_TEST} must contain the exact zero-argument production test"
        )
        .into());
    }
    let calls = tests[0]
        .block
        .stmts
        .iter()
        .map(direct_zero_argument_call)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            format!(
                "{PRODUCTION_REGISTRY_TEST} production test may contain only direct propagated self-test calls"
            )
        })?;
    let expected = [
        "effect_registry::production_identity_registry_self_test",
        "device_flight::retained_semantic_self_test",
        "portal_v2::production_portal_v2_self_test",
    ];
    if calls != expected {
        return Err(format!(
            "{PRODUCTION_REGISTRY_TEST} production test call sequence mismatch: {calls:?}"
        )
        .into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectLockEdge {
    version: String,
    source: Option<String>,
}

fn facade_direct_edges(
    lock_source: &str,
    relative: &str,
) -> Result<BTreeMap<String, DirectLockEdge>> {
    let lock: toml::Value = toml::from_str(lock_source)?;
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("lockfile lacks package array: {relative}"))?;
    let facade = packages
        .iter()
        .find(|package| {
            package.get("name").and_then(toml::Value::as_str) == Some("nexus-ostd-virtio")
        })
        .ok_or_else(|| format!("lockfile lacks nexus-ostd-virtio: {relative}"))?;
    let facade_dependencies = facade
        .get("dependencies")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("facade package lacks dependencies: {relative}"))?;

    let mut edges = BTreeMap::new();
    for dependency in facade_dependencies {
        let descriptor = dependency
            .as_str()
            .ok_or_else(|| format!("facade dependency is not a string: {relative}"))?;
        let fields = descriptor.split_whitespace().collect::<Vec<_>>();
        if fields.is_empty() || fields.len() > 3 {
            return Err(format!("unsupported lock dependency descriptor: {descriptor}").into());
        }
        let name = fields[0];
        let requested_version = fields.get(1).copied();
        let requested_source = fields
            .get(2)
            .map(|source| source.trim_start_matches('(').trim_end_matches(')'));
        let candidates = packages
            .iter()
            .filter(|package| {
                package.get("name").and_then(toml::Value::as_str) == Some(name)
                    && requested_version.is_none_or(|version| {
                        package.get("version").and_then(toml::Value::as_str) == Some(version)
                    })
                    && requested_source.is_none_or(|source| {
                        package.get("source").and_then(toml::Value::as_str) == Some(source)
                    })
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Err(format!(
                "{relative} cannot resolve direct edge {descriptor} uniquely: candidates={}",
                candidates.len()
            )
            .into());
        }
        let package = candidates[0];
        let edge = DirectLockEdge {
            version: package
                .get("version")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("direct package lacks version: {relative}:{name}"))?
                .to_owned(),
            source: package
                .get("source")
                .and_then(toml::Value::as_str)
                .map(str::to_owned),
        };
        if edges.insert(name.to_owned(), edge).is_some() {
            return Err(format!("duplicate facade direct edge: {relative}:{name}").into());
        }
    }
    Ok(edges)
}

fn validate_virtio_dependency_sources(manifest_source: &str, locks: &[(&str, &str)]) -> Result<()> {
    let manifest: toml::Value = toml::from_str(manifest_source)?;
    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or("VirtIO manifest lacks dependencies")?;
    let authority_source = locks
        .iter()
        .find_map(|(relative, source)| (*relative == VIRTIO_AUTHORITY_LOCK).then_some(*source))
        .ok_or_else(|| format!("missing VirtIO authority lock: {VIRTIO_AUTHORITY_LOCK}"))?;
    let authority = facade_direct_edges(authority_source, VIRTIO_AUTHORITY_LOCK)?;
    let manifest_edges = dependencies.keys().cloned().collect::<BTreeSet<_>>();
    let authority_edges = authority.keys().cloned().collect::<BTreeSet<_>>();
    if manifest_edges != authority_edges {
        return Err(format!(
            "VirtIO manifest direct edges differ from production authority: manifest={manifest_edges:?} authority={authority_edges:?}"
        )
        .into());
    }

    for (name, dependency) in dependencies {
        let table = dependency
            .as_table()
            .ok_or_else(|| format!("VirtIO dependency is not structured: {name}"))?;
        let resolved = authority
            .get(name)
            .ok_or_else(|| format!("authority lacks manifest edge: {name}"))?;
        if let Some(requirement) = table.get("version").and_then(toml::Value::as_str) {
            let exact = format!("={}", resolved.version);
            if requirement != exact {
                return Err(format!(
                    "VirtIO production dependency must match the authority exactly: {name}={}",
                    resolved.version
                )
                .into());
            }
        } else if table.get("path").and_then(toml::Value::as_str).is_none() {
            return Err(format!(
                "VirtIO direct dependency must have an exact version or path: {name}"
            )
            .into());
        }
    }

    for (relative, lock_source) in locks {
        let edges = facade_direct_edges(lock_source, relative)?;
        if edges != authority {
            return Err(format!(
                "{relative} facade direct graph differs from {VIRTIO_AUTHORITY_LOCK}: actual={edges:?} authority={authority:?}"
            )
            .into());
        }
    }
    Ok(())
}

fn validate_virtio_dependency_parity(root: &Path) -> Result<()> {
    let manifest_source = fs::read_to_string(root.join("crates/nexus-ostd-virtio/Cargo.toml"))?;
    let lock_sources = VIRTIO_PRODUCTION_LOCKS
        .iter()
        .map(|relative| Ok((*relative, fs::read_to_string(root.join(relative))?)))
        .collect::<Result<Vec<_>>>()?;
    let locks = lock_sources
        .iter()
        .map(|(relative, source)| (*relative, source.as_str()))
        .collect::<Vec<_>>();
    validate_virtio_dependency_sources(&manifest_source, &locks)
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

    fn expect_backend_source_semantic_failure(
        relative: &str,
        source: &str,
        source_root: &str,
        files: &[String],
    ) {
        validate_backend_source_pair_semantics(relative, source, source_root, files)
            .expect_err("the semantic validator must reject the mutation directly");
        let failure = validate_backend_source_pair(relative, source, source_root, files)
            .expect_err("the classified validator must reject the mutation");
        assert!(
            matches!(failure, BackendValidationError::Semantic(_)),
            "semantic mutation was misclassified as {failure:?}"
        );
    }

    fn expect_backend_docker_semantic_failure(relative: &str, dockerfile: &str, files: &[String]) {
        validate_backend_docker_source_set_semantics(relative, dockerfile, files)
            .expect_err("the Docker semantic validator must reject the mutation directly");
        let failure = validate_backend_docker_source_set(relative, dockerfile, files)
            .expect_err("the classified Docker validator must reject the mutation");
        assert!(
            matches!(failure, BackendValidationError::Semantic(_)),
            "Docker semantic mutation was misclassified as {failure:?}"
        );
    }

    fn validate_virtio_fixture(manifest: &str, lock_sources: &[String]) -> Result<()> {
        let locks = VIRTIO_PRODUCTION_LOCKS
            .iter()
            .zip(lock_sources)
            .map(|(relative, source)| (*relative, source.as_str()))
            .collect::<Vec<_>>();
        validate_virtio_dependency_sources(manifest, &locks)
    }

    fn remove_facade_direct_edge(lock_source: &str, name: &str) -> String {
        let mut lock: toml::Value = toml::from_str(lock_source).expect("parse lock fixture");
        let packages = lock
            .get_mut("package")
            .and_then(toml::Value::as_array_mut)
            .expect("lock packages");
        let facade = packages
            .iter_mut()
            .find(|package| {
                package.get("name").and_then(toml::Value::as_str) == Some("nexus-ostd-virtio")
            })
            .expect("facade package");
        let dependencies = facade
            .get_mut("dependencies")
            .and_then(toml::Value::as_array_mut)
            .expect("facade dependencies");
        let before = dependencies.len();
        dependencies.retain(|dependency| {
            dependency
                .as_str()
                .and_then(|descriptor| descriptor.split_whitespace().next())
                != Some(name)
        });
        assert_eq!(dependencies.len() + 1, before, "remove direct edge {name}");
        toml::to_string(&lock).expect("serialize lock fixture")
    }

    fn drift_direct_edge(lock_source: &str, name: &str, edge: &DirectLockEdge) -> String {
        let mut lock: toml::Value = toml::from_str(lock_source).expect("parse lock fixture");
        let packages = lock
            .get_mut("package")
            .and_then(toml::Value::as_array_mut)
            .expect("lock packages");
        let mut changed = 0;
        for package in packages {
            let same_name = package.get("name").and_then(toml::Value::as_str) == Some(name);
            let same_version =
                package.get("version").and_then(toml::Value::as_str) == Some(edge.version.as_str());
            let same_source =
                package.get("source").and_then(toml::Value::as_str) == edge.source.as_deref();
            if same_name && same_version && same_source {
                *package.get_mut("version").expect("direct package version") =
                    toml::Value::String(format!("{}-drift", edge.version));
                changed += 1;
            }
        }
        assert_eq!(changed, 1, "drift direct edge {name}");
        toml::to_string(&lock).expect("serialize lock fixture")
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
    fn root_frontdoor_is_bound_to_the_reviewed_snapshot() {
        let root = repository_root();
        let frontdoor = fs::read_to_string(root.join("x")).expect("read root workflow");
        validate_root_frontdoor_snapshot(&frontdoor).expect("reviewed root workflow snapshot");

        for mutation in [
            "\nensure_image() { image=nexus/cser-dev:constant; }\n",
            "\nfunction ensure_image { image=nexus/cser-dev:constant; }\n",
            "\n: compute_image_identity\n",
        ] {
            validate_root_frontdoor_snapshot(&format!("{frontdoor}{mutation}"))
                .expect_err("any unreviewed root workflow mutation must fail");
        }
    }

    #[test]
    fn requires_the_exact_complete_image_identity_input_set() {
        let rendered = IMAGE_IDENTITY_INPUTS
            .iter()
            .map(|relative| format!("    \"$root/{relative}\" \\\n"))
            .collect::<String>();
        let frontdoor = format!(
            "compute_image_identity() {{\n    if [[ -n $image ]]; then\n        return\n    fi\n    local image_key\n    image_key=$(sha256sum \\\n{rendered}    | cut -d ' ' -f1 | sha256sum | cut -c1-16)\n    image=\"nexus/cser-dev:$image_key\"\n}}\ncompute_image_identity\ncompute_image_identity\n"
        );
        let frontdoor = frontdoor.replace(
            "\ncompute_image_identity\ncompute_image_identity\n",
            "\nbuild_image() {\n    compute_image_identity\n}\nensure_image() {\n    compute_image_identity\n}\n",
        );
        validate_image_identity_inputs(&frontdoor).expect("complete image identity");

        for relative in IMAGE_IDENTITY_INPUTS {
            let missing = frontdoor.replace(&format!("    \"$root/{relative}\" \\\n"), "");
            let error = validate_image_identity_inputs(&missing)
                .expect_err("missing image input must be rejected")
                .to_string();
            assert!(error.contains(relative));
        }
        let commented_input = frontdoor.replacen(
            &format!("    \"$root/{}\" \\\n", IMAGE_IDENTITY_INPUTS[0]),
            &format!("    # \"$root/{}\" \\\n", IMAGE_IDENTITY_INPUTS[0]),
            1,
        );
        validate_image_identity_inputs(&commented_input)
            .expect_err("an input inside a continued-command comment must be rejected");

        let commented_declaration = frontdoor.replacen("build_image() {", "# build_image() {", 1);
        validate_image_identity_inputs(&commented_declaration)
            .expect_err("a function declaration retained only in a comment must be rejected");

        let reordered = frontdoor
            .replace(IMAGE_IDENTITY_INPUTS[0], "FIRST")
            .replace(IMAGE_IDENTITY_INPUTS[1], IMAGE_IDENTITY_INPUTS[0])
            .replace("FIRST", IMAGE_IDENTITY_INPUTS[1]);
        let error = validate_image_identity_inputs(&reordered)
            .expect_err("reordered image inputs must be rejected")
            .to_string();
        assert!(error.contains("exact reviewed command"));

        let extra = frontdoor.replace("    | cut", "    \"$root/unreviewed-input\" \\\n    | cut");
        assert!(validate_image_identity_inputs(&extra).is_err());

        let substitution = frontdoor.replace(
            "    \"$root/Cargo.lock\" \\",
            "    $(printf '' \"$root/Cargo.lock\") \\",
        );
        validate_image_identity_inputs(&substitution)
            .expect_err("command substitution must not masquerade as an image input");

        let overridden = frontdoor.replace(
            "    image=\"nexus/cser-dev:$image_key\"",
            "    image_key=constant\n    image=\"nexus/cser-dev:$image_key\"",
        );
        validate_image_identity_inputs(&overridden)
            .expect_err("a later image-key assignment must not override the reviewed digest");

        for redefinition in [
            "\ncompute_image_identity() {\n    image=\"nexus/cser-dev:constant\"\n}\n",
            "\nfunction compute_image_identity {\n    image=\"nexus/cser-dev:constant\"\n}\n",
        ] {
            let redefined = format!("{frontdoor}{redefinition}");
            validate_image_identity_inputs(&redefined)
                .expect_err("a later Bash function definition must not replace the reviewed one");
        }

        for replacement in [
            ": compute_image_identity",
            "# compute_image_identity",
            "printf '%s' compute_image_identity",
        ] {
            let indirect = frontdoor.replacen(
                "    compute_image_identity",
                &format!("    {replacement}"),
                1,
            );
            validate_image_identity_inputs(&indirect)
                .expect_err("the image identity must be invoked as a direct shell command");
        }
    }

    #[test]
    fn cargo_routes_require_an_immediate_propagated_cargo_call() {
        let valid = r#"fn check(root: &Path) -> Result<()> {
    section("check fixture");
    cargo(
        root,
        ["check", "--locked", "-p", "fixture", "--all-targets"],
    )?;
}
"#;
        validate_cargo_route_section(
            valid,
            "fn check(root: &Path) -> Result<()> {",
            "check fixture",
            "check",
            "fixture",
            &["--all-targets"],
        )
        .expect("real propagated cargo route");

        let string_only = valid.replacen("cargo(", "let _ = (", 1);
        validate_cargo_route_section(
            &string_only,
            "fn check(root: &Path) -> Result<()> {",
            "check fixture",
            "check",
            "fixture",
            &["--all-targets"],
        )
        .expect_err("argument strings without a cargo call must fail");

        let discarded = valid.replacen(")?;", ");", 1);
        validate_cargo_route_section(
            &discarded,
            "fn check(root: &Path) -> Result<()> {",
            "check fixture",
            "check",
            "fixture",
            &["--all-targets"],
        )
        .expect_err("an unpropagated cargo result must fail");

        let computed_arguments = r#"fn check(root: &Path) -> Result<()> {
    section("check fixture");
    cargo(root, {
        let _ = ("check", "--locked", "-p", "fixture", "--all-targets");
        ["check", "--locked", "-p", "different"]
    })?;
}
"#;
        validate_cargo_route_section(
            computed_arguments,
            "fn check(root: &Path) -> Result<()> {",
            "check fixture",
            "check",
            "fixture",
            &["--all-targets"],
        )
        .expect_err("arguments hidden in an expression must fail");

        let fabricated_propagation = valid.replacen(
            ")?;",
            ").unwrap_or(());\n    let _ = \"fake )?; marker\";",
            1,
        );
        validate_cargo_route_section(
            &fabricated_propagation,
            "fn check(root: &Path) -> Result<()> {",
            "check fixture",
            "check",
            "fixture",
            &["--all-targets"],
        )
        .expect_err("a later text marker must not fake result propagation");
    }

    #[test]
    fn virtio_spike_portal_source_is_hash_mounted_and_explicitly_baked() {
        let root = repository_root();
        let relative = "experiments/ostd-virtio-cser-spike/x";
        let docker_relative = "experiments/ostd-virtio-cser-spike/Dockerfile";
        let spike = fs::read_to_string(root.join(relative)).expect("read spike workflow");
        let dockerfile =
            fs::read_to_string(root.join(docker_relative)).expect("read spike Dockerfile");
        let production_files =
            cser_production_source_files(&root).expect("canonical production source manifest");
        let source_root = "$repo_root/kernel/nexus-ostd/src/cser";
        validate_backend_source_pair(relative, &spike, source_root, &production_files)
            .expect("spike production source hash and live mounts");
        validate_backend_docker_source_set(docker_relative, &dockerfile, &production_files)
            .expect("spike explicit production source COPY");

        let missing_hash = spike.replacen(
            r#""${cser_source_hash_inputs[@]}""#,
            "\"removed-production-source-array\"",
            1,
        );
        assert_ne!(missing_hash, spike);
        validate_backend_source_pair(relative, &missing_hash, source_root, &production_files)
            .expect_err("the manifest-derived sources must affect spike image identity");

        let missing_mount = spike.replacen(
            r#""${cser_source_mount_args[@]}""#,
            "\"removed-production-source-mount-array\"",
            1,
        );
        assert_ne!(missing_mount, spike);
        validate_backend_source_pair(relative, &missing_mount, source_root, &production_files)
            .expect_err("the manifest-derived sources must be mounted into the spike");

        let flattened_loop = spike.replacen(
            r#"target_path="/kernel/nexus-ostd/src/cser/$relative""#,
            r#"target_path="/kernel/nexus-ostd/src/cser/${relative##*/}""#,
            1,
        );
        validate_backend_source_pair(relative, &flattened_loop, source_root, &production_files)
            .expect_err("the manifest loop may not flatten nested source targets");

        let appended_hidden = spike.replacen(
            "image_key=$(sha256sum \\",
            concat!(
                "cser_source_hash_inputs+=(\"$repo_root/kernel/nexus-ostd/src/cser/hidden.rs\")\n",
                "cser_source_mount_args+=(--mount ",
                "\"type=bind,source=$repo_root/kernel/nexus-ostd/src/cser/hidden.rs,",
                "target=/kernel/nexus-ostd/src/cser/hidden.rs,readonly\")\n",
                "image_key=$(sha256sum \\"
            ),
            1,
        );
        validate_backend_source_pair(relative, &appended_hidden, source_root, &production_files)
            .expect_err("post-loop hidden hash and mount array appends must be rejected");

        let missing_copy = dockerfile.replacen(
            concat!(
                "COPY --from=nexus-root ",
                "kernel/nexus-ostd/src/cser/infrastructure/deadline.rs \\\n",
                "    /kernel/nexus-ostd/src/cser/infrastructure/deadline.rs\n"
            ),
            "",
            1,
        );
        assert_ne!(missing_copy, dockerfile);
        validate_backend_docker_source_set(docker_relative, &missing_copy, &production_files)
            .expect_err(
                "every infrastructure source must be explicitly copied into the cold image",
            );
        let comment_only_copy = format!(
            "{missing_copy}\n# COPY --from=nexus-root kernel/nexus-ostd/src/cser/infrastructure/deadline.rs /kernel/nexus-ostd/src/cser/infrastructure/deadline.rs\n"
        );
        validate_backend_docker_source_set(docker_relative, &comment_only_copy, &production_files)
            .expect_err("a comment must not satisfy an infrastructure COPY");

        let flattened_nested_copy = dockerfile.replacen(
            "/kernel/nexus-ostd/src/cser/infrastructure/deadline.rs",
            "/kernel/nexus-ostd/src/cser/deadline.rs",
            1,
        );
        assert_ne!(flattened_nested_copy, dockerfile);
        validate_backend_docker_source_set(
            docker_relative,
            &flattened_nested_copy,
            &production_files,
        )
        .expect_err("nested infrastructure paths may not be flattened");

        let additive_directory_copy = dockerfile.replacen(
            "COPY --from=nexus-root kernel/nexus-ostd/cser-production-sources.txt \\",
            concat!(
                "COPY --from=nexus-root kernel/nexus-ostd/src/cser/ ",
                "/kernel/nexus-ostd/src/cser/\n",
                "COPY --from=nexus-root kernel/nexus-ostd/cser-production-sources.txt \\"
            ),
            1,
        );
        assert_ne!(additive_directory_copy, dockerfile);
        validate_backend_docker_source_set(
            docker_relative,
            &additive_directory_copy,
            &production_files,
        )
        .expect_err("an additive directory COPY must not hide cold-image sources");

        let additive_sidecar = dockerfile.replacen(
            "COPY --from=nexus-root kernel/nexus-ostd/cser-production-sources.txt \\",
            concat!(
                "COPY --from=nexus-root hidden.rs ",
                "/kernel/nexus-ostd/src/cser/infrastructure/hidden.rs\n",
                "COPY --from=nexus-root kernel/nexus-ostd/cser-production-sources.txt \\"
            ),
            1,
        );
        validate_backend_docker_source_set(docker_relative, &additive_sidecar, &production_files)
            .expect_err("an additive hidden sidecar COPY must be rejected");
    }

    #[test]
    fn backend_docker_cser_gate_rejects_instruction_and_final_image_bypasses() {
        let root = repository_root();
        let production_files =
            cser_production_source_files(&root).expect("canonical production source manifest");
        for relative in [
            "kernel/nexus-ostd/Dockerfile",
            "experiments/ostd-virtio-cser-spike/Dockerfile",
        ] {
            let dockerfile = fs::read_to_string(root.join(relative)).expect("read Dockerfile");
            validate_backend_docker_source_set(relative, &dockerfile, &production_files)
                .expect("exact isolated-verifier cold CSER image");
            let insertion = "# Audit the immutable build-stage snapshot";

            for (name, instruction) in [
                (
                    "lowercase copy",
                    "copy hidden.rs /kernel/nexus-ostd/src/cser/hidden.rs",
                ),
                (
                    "mixed-case copy",
                    "CoPy hidden.rs /kernel/nexus-ostd/src/cser/hidden.rs",
                ),
                (
                    "add instruction",
                    "ADD hidden.rs /kernel/nexus-ostd/src/cser/hidden.rs",
                ),
                (
                    "onbuild instruction",
                    "ONBUILD COPY hidden.rs /kernel/nexus-ostd/src/cser/hidden.rs",
                ),
                (
                    "wrong-stage copy",
                    "COPY --from=other-stage /hidden.rs /kernel/nexus-ostd/src/cser/hidden.rs",
                ),
                (
                    "pre-audit run overwrite",
                    "RUN cp /tmp/hidden.rs /kernel/nexus-ostd/src/cser/hidden.rs",
                ),
                (
                    "audit tool shadow",
                    "RUN ln -sf /bin/true /usr/local/bin/cmp",
                ),
                (
                    "reserved marker symlink",
                    "RUN ln -s /kernel/nexus-ostd/src/cser /nexus-cser-verified",
                ),
                ("audit path redirect", "ENV PATH=/tmp/attacker:/usr/bin"),
                ("second final stage", "FROM ${OSDK_IMAGE}"),
            ] {
                let mutation =
                    dockerfile.replacen(insertion, &format!("{instruction}\n{insertion}"), 1);
                assert_ne!(mutation, dockerfile, "{name} fixture must mutate");
                assert!(
                    validate_backend_docker_source_set(relative, &mutation, &production_files)
                        .is_err(),
                    "{name} unexpectedly passed for {relative}"
                );
            }

            let extra_directive = dockerfile.replacen(
                PINNED_DOCKER_SYNTAX,
                &format!("{PINNED_DOCKER_SYNTAX}\n# escape=`"),
                1,
            );
            assert_ne!(extra_directive, dockerfile);
            validate_backend_docker_source_set(relative, &extra_directive, &production_files)
                .expect_err("an additional parser directive may change Docker parsing");

            let heredoc = dockerfile.replacen(
                insertion,
                concat!(
                    "RUN <<EOF\n",
                    "COPY hidden.rs /kernel/nexus-ostd/src/cser/hidden.rs\n",
                    "EOF\n",
                    "# Audit the immutable build-stage snapshot"
                ),
                1,
            );
            assert_ne!(heredoc, dockerfile);
            validate_backend_docker_source_set(relative, &heredoc, &production_files)
                .expect_err("Docker and shell heredocs are outside the audited grammar");

            let weakened_audit = dockerfile.replacen(
                "/usr/bin/cmp /tmp/nexus-cser-expected /tmp/nexus-cser-candidate;",
                "test -f /tmp/nexus-cser-candidate;",
                1,
            );
            assert_ne!(weakened_audit, dockerfile);
            validate_backend_docker_source_set(relative, &weakened_audit, &production_files)
                .expect_err("the final exact inventory comparison may not be weakened");

            let writable_candidate = dockerfile.replacen(
                "target=/candidate-root,readonly",
                "target=/candidate-root",
                1,
            );
            assert_ne!(writable_candidate, dockerfile);
            validate_backend_docker_source_set(relative, &writable_candidate, &production_files)
                .expect_err("the verifier must inspect an immutable build-stage snapshot");

            let redirected_marker = dockerfile.replacen(
                "COPY --from=cser-verifier /verified /nexus-cser-verified",
                "COPY --from=cser-verifier /verified /kernel/nexus-ostd/src/cser/verified",
                1,
            );
            assert_ne!(redirected_marker, dockerfile);
            validate_backend_docker_source_set(relative, &redirected_marker, &production_files)
                .expect_err("the proof marker must remain at the reserved direct-root path");

            let post_audit_write = format!(
                "{dockerfile}\nRUN cp /tmp/hidden.rs /kernel/nexus-ostd/src/cser/hidden.rs\n"
            );
            validate_backend_docker_source_set(relative, &post_audit_write, &production_files)
                .expect_err("no filesystem instruction may follow the final source audit");
        }
    }

    #[test]
    fn backend_semantic_and_raw_authority_failures_are_independently_observable() {
        let root = repository_root();
        let production_files =
            cser_production_source_files(&root).expect("canonical production source manifest");
        for (relative, source_root) in [
            ("kernel/nexus-ostd/x", "$root/src/cser"),
            (
                "experiments/ostd-virtio-cser-spike/x",
                "$repo_root/kernel/nexus-ostd/src/cser",
            ),
        ] {
            let source = fs::read_to_string(root.join(relative)).expect("read backend workflow");
            validate_backend_source_pair_semantics(
                relative,
                &source,
                source_root,
                &production_files,
            )
            .expect("reviewed workflow passes semantic authority");

            let shebang = source.replacen("#!/usr/bin/bash -p", "#!/usr/bin/bash", 1);
            assert_ne!(shebang, source);
            expect_backend_source_semantic_failure(
                relative,
                &shebang,
                source_root,
                &production_files,
            );

            let helper = source.replacen(
                "capture_helper_sha256=b05544fb66e5d124fb141696accb1933742de561469f1c9e4a12eef3c6c5e7b7",
                "capture_helper_sha256=005544fb66e5d124fb141696accb1933742de561469f1c9e4a12eef3c6c5e7b7",
                1,
            );
            assert_ne!(helper, source);
            expect_backend_source_semantic_failure(
                relative,
                &helper,
                source_root,
                &production_files,
            );

            let mount = source.replacen(
                r#""${cser_source_mount_args[@]}""#,
                "\"removed-production-mount-array\"",
                1,
            );
            assert_ne!(mount, source);
            expect_backend_source_semantic_failure(
                relative,
                &mount,
                source_root,
                &production_files,
            );

            let raw_only = format!("{source}# raw-authority-only mutation\n");
            validate_backend_source_pair_semantics(
                relative,
                &raw_only,
                source_root,
                &production_files,
            )
            .expect("an inert trailing comment is outside normalized shell semantics");
            let failure =
                validate_backend_source_pair(relative, &raw_only, source_root, &production_files)
                    .expect_err("raw authority must still bind inert source bytes");
            assert!(matches!(
                failure,
                BackendValidationError::RawAuthorityDrift { .. }
            ));
        }

        for relative in [
            "kernel/nexus-ostd/Dockerfile",
            "experiments/ostd-virtio-cser-spike/Dockerfile",
        ] {
            let dockerfile = fs::read_to_string(root.join(relative)).expect("read Dockerfile");
            validate_backend_docker_source_set_semantics(relative, &dockerfile, &production_files)
                .expect("reviewed Dockerfile passes semantic authority");
            let insertion = "# Audit the immutable build-stage snapshot";

            let opcode = dockerfile.replacen(
                insertion,
                &format!("copy hidden.rs /tmp/hidden.rs\n{insertion}"),
                1,
            );
            assert_ne!(opcode, dockerfile);
            expect_backend_docker_semantic_failure(relative, &opcode, &production_files);

            let verifier = dockerfile.replacen(
                "/usr/bin/cmp /tmp/nexus-cser-expected /tmp/nexus-cser-candidate;",
                "test -f /tmp/nexus-cser-candidate;",
                1,
            );
            assert_ne!(verifier, dockerfile);
            expect_backend_docker_semantic_failure(relative, &verifier, &production_files);

            let marker = dockerfile.replacen(
                "COPY --from=cser-verifier /verified /nexus-cser-verified",
                "COPY --from=cser-verifier /verified /tmp/nexus-cser-verified",
                1,
            );
            assert_ne!(marker, dockerfile);
            expect_backend_docker_semantic_failure(relative, &marker, &production_files);

            let raw_only = format!("{dockerfile}# raw-authority-only mutation\n");
            validate_backend_docker_source_set_semantics(relative, &raw_only, &production_files)
                .expect("an inert trailing comment is outside normalized Docker semantics");
            let failure =
                validate_backend_docker_source_set(relative, &raw_only, &production_files)
                    .expect_err("raw authority must still bind inert Dockerfile bytes");
            assert!(matches!(
                failure,
                BackendValidationError::RawAuthorityDrift { .. }
            ));
        }
    }

    #[test]
    fn ostd_supervisor_source_gate_binds_capabilities_hooks_and_lock_order() {
        let root = repository_root();
        let runtime = fs::read_to_string(root.join(OSTD_SUPERVISOR_RUNTIME_SOURCE))
            .expect("read OSTD supervisor runtime");
        let kernel = fs::read_to_string(root.join("kernel/nexus-ostd/src/lib.rs"))
            .expect("read OSTD kernel root");
        validate_ostd_supervisor_runtime_source(&runtime, &kernel)
            .expect("canonical supervisor adapter source is bound");

        for capability in [
            "            && self.exact_task_exit_hook\n",
            "            && self.exact_task_reap_hook\n",
            "            && self.isolated_user_fault_boundary\n",
            "            && self.initial_active_task_binding\n",
            "            && self.nexus_owned_manager_worker\n",
            "            && self.worker_exact_reap_health\n",
            "            && self.generation_fenced_timer_ingress\n",
        ] {
            let mutation = runtime.replacen(capability, "", 1);
            assert_ne!(mutation, runtime, "capability mutation must apply");
            validate_ostd_supervisor_runtime_source(&mutation, &kernel)
                .expect_err("no mandatory capability may disappear from permit completeness");
        }

        let early_exit = runtime.replacen(
            "        match slot.phase {\n            ReplacementSlotPhase::Published => {",
            "        self.enqueue_signal_locked(&mut slot, observed_tick, OstdSupervisorEvent::Reaped { service, binding_epoch });\n        match slot.phase {\n            ReplacementSlotPhase::Published => {",
            1,
        );
        assert_ne!(early_exit, runtime, "exact-reap mutation must apply");
        validate_ostd_supervisor_runtime_source(&early_exit, &kernel)
            .expect_err("exact-reap ingress may not gain an early unscoped event");

        // The gate binds the audited slot-to-events edge before a runtime
        // oracle can exercise the race.
        let emit_ready =
            source_function(&runtime, "    fn emit_ready", "    fn record_pending_exit")
                .expect("extract ready ingress");
        let mutated_emit_ready = emit_ready.replacen(
            "        let mut slot = self.replacement.disable_irq().lock();\n",
            "        let mut slot = self.replacement.lock();\n",
            1,
        );
        let missing_slot_lock = runtime.replacen(emit_ready, &mutated_emit_ready, 1);
        assert_ne!(missing_slot_lock, runtime, "slot-lock mutation must apply");
        validate_ostd_supervisor_runtime_source(&missing_slot_lock, &kernel)
            .expect_err("event ingress must retain the IRQ-safe slot-first lock edge");

        let missing_hook = kernel.replacen(
            "    inject_post_task_exit_handler(supervisor_runtime::observe_post_task_exit);\n",
            "",
            1,
        );
        assert_ne!(missing_hook, kernel, "post-exit hook mutation must apply");
        validate_ostd_supervisor_runtime_source(&runtime, &missing_hook)
            .expect_err("kernel root must install the exact post-task-exit hook");

        let runtime_lock_across_drive = runtime.replacen(
            "                let result = runtime.drive_once();\n",
            "                let result = self.runtime.disable_irq().lock().as_mut().unwrap().drive_once();\n",
            1,
        );
        assert_ne!(runtime_lock_across_drive, runtime);
        validate_ostd_supervisor_runtime_source(&runtime_lock_across_drive, &kernel)
            .expect_err("manager progress may not run under the worker runtime lock");

        for no_timer_fence in [
            "            self.finish_without_runtime(OstdSupervisorWorkerTerminal::LifecycleViolation);\n",
            "            self.finish_without_runtime(OstdSupervisorWorkerTerminal::MissingRuntime);\n",
        ] {
            let mutation = runtime.replacen(no_timer_fence, "", 1);
            assert_ne!(mutation, runtime, "timer-fence mutation must apply");
            validate_ostd_supervisor_runtime_source(&mutation, &kernel)
                .expect_err("every no-runtime worker terminal must disable its timer generation");
        }

        let early_initial_publication = runtime.replacen(
            "    worker_task.run();\n    initial_task.run();\n",
            "    initial_task.run();\n    worker_task.run();\n",
            1,
        );
        assert_ne!(early_initial_publication, runtime);
        validate_ostd_supervisor_runtime_source(&early_initial_publication, &kernel)
            .expect_err("manager worker must be enqueued before initial-active publication");

        let strong_timer_owner = runtime.replacen(
            "        let shared = Arc::downgrade(&self.shared);\n",
            "        let shared = Arc::clone(&self.shared);\n",
            1,
        );
        assert_ne!(strong_timer_owner, runtime);
        validate_ostd_supervisor_runtime_source(&strong_timer_owner, &kernel)
            .expect_err("timer callback may not retain runtime authority forever");
    }

    #[test]
    fn cser_production_manifest_and_cold_copies_are_exact_closed_sets() {
        let root = repository_root();
        let expected =
            expected_cser_production_sources(&root).expect("discover production module closure");
        let manifest_path = root.join(CSER_PRODUCTION_SOURCE_MANIFEST);
        let manifest = fs::read_to_string(&manifest_path).expect("read production manifest");
        let files = validate_cser_production_manifest_text(&manifest, &expected)
            .expect("manifest equals production closure");
        assert_eq!(
            cser_production_source_files(&root).expect("validated source files"),
            expected
        );

        for file in &files {
            let missing = manifest.replacen(&format!("{file}\n"), "", 1);
            assert_ne!(missing, manifest, "manifest mutation must remove {file}");
            validate_cser_production_manifest_text(&missing, &expected)
                .expect_err("every missing manifest entry must be rejected");
        }

        let flattened = manifest.replacen("infrastructure/deadline.rs\n", "deadline.rs\n", 1);
        assert_ne!(flattened, manifest);
        validate_cser_production_manifest_text(&flattened, &expected)
            .expect_err("flattened manifest path must be rejected");

        let extra = manifest.replacen(
            "infrastructure/invariants.rs\n",
            "infrastructure/hidden.rs\ninfrastructure/invariants.rs\n",
            1,
        );
        assert_ne!(extra, manifest);
        validate_cser_production_manifest_text(&extra, &expected)
            .expect_err("extra hidden manifest source must be rejected");

        let duplicate = manifest.replacen(
            "infrastructure/invariants.rs\n",
            "infrastructure/invariants.rs\ninfrastructure/invariants.rs\n",
            1,
        );
        assert_ne!(duplicate, manifest);
        validate_cser_production_manifest_text(&duplicate, &expected)
            .expect_err("duplicate manifest source must be rejected");

        for invalid in [
            format!("# retained marker\n{manifest}"),
            format!("../hidden.rs\n{manifest}"),
            format!("./effect_registry.rs\n{manifest}"),
            manifest.replacen(
                "infrastructure/deadline.rs\n",
                "infrastructure/./deadline.rs\n",
                1,
            ),
            manifest.replacen(
                "infrastructure/deadline.rs\n",
                "infrastructure//deadline.rs\n",
                1,
            ),
        ] {
            validate_cser_production_manifest_text(&invalid, &expected)
                .expect_err("comments, traversal, and current-directory aliases must be rejected");
        }

        let mut hidden_inventory = expected.clone();
        hidden_inventory.push("infrastructure/hidden.rs".to_owned());
        hidden_inventory.sort();
        validate_cser_production_manifest_text(&manifest, &hidden_inventory)
            .expect_err("an orphan hidden infrastructure source must fail closure");

        let hidden_module: syn::ItemMod =
            syn::parse_str("#[cfg(any())] mod hidden;").expect("parse hidden module");
        validate_external_module_attributes(Path::new("infrastructure/mod.rs"), &hidden_module)
            .expect_err("a cfg-hidden production module must be rejected");
        let tests_module: syn::ItemMod =
            syn::parse_str("#[cfg(test)] mod tests;").expect("parse tests module");
        validate_external_module_attributes(Path::new("infrastructure/mod.rs"), &tests_module)
            .expect("the exact test-only infrastructure module remains in closure");
        let cfg_attr_module: syn::ItemMod = syn::parse_str(
            "#[path = \"child.rs\"]\n#[cfg_attr(any(), path = \"hidden.rs\")]\nmod child;",
        )
        .expect("parse cfg_attr path module");
        validate_external_module_attributes(Path::new("effect_registry.rs"), &cfg_attr_module)
            .expect_err("cfg_attr may not redirect an external production module");

        for docker_relative in [
            "kernel/nexus-ostd/Dockerfile",
            "experiments/ostd-virtio-cser-spike/Dockerfile",
        ] {
            let dockerfile =
                fs::read_to_string(root.join(docker_relative)).expect("read backend Dockerfile");
            validate_backend_docker_source_set(docker_relative, &dockerfile, &files)
                .expect("complete cold CSER source set");
            for file in &files {
                let source_path = format!("kernel/nexus-ostd/src/cser/{file}");
                let missing =
                    dockerfile.replacen(&source_path, "removed-cser-production-source", 1);
                assert_ne!(
                    missing, dockerfile,
                    "Docker mutation must remove source {file}"
                );
                validate_backend_docker_source_set(docker_relative, &missing, &files)
                    .expect_err("every missing Docker source entry must be rejected");
            }
            let missing_manifest = dockerfile.replacen(
                "kernel/nexus-ostd/cser-production-sources.txt",
                "removed-cser-production-source-manifest",
                1,
            );
            assert_ne!(missing_manifest, dockerfile);
            validate_backend_docker_source_set(docker_relative, &missing_manifest, &files)
                .expect_err("cold image must retain the canonical source manifest");
        }
    }

    #[test]
    fn cser_source_closure_rejects_unbound_macro_and_inline_module_sources() {
        let temporary = std::env::temp_dir().join(format!(
            "nexus-cser-source-closure-mutations-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temporary);
        fs::create_dir_all(&temporary).expect("create temporary CSER source root");
        let root = temporary.as_path();
        let source_path = root.join("effect_registry.rs");

        let safe = concat!(
            "extern crate alloc as __cser_alloc;\n",
            "extern crate core as __cser_core;\n",
            "pub fn safe(value: bool) {\n",
            "    __cser_core::assert!(__cser_core::matches!(value, true | false));\n",
            "    __cser_core::assert!(!value || 1 != 2);\n",
            "}\n",
        );
        fs::write(&source_path, safe).expect("write safe source fixture");
        let mut safe_closure = BTreeSet::new();
        collect_external_module_closure(root, Path::new("effect_registry.rs"), &mut safe_closure)
            .expect("audited non-source macros remain permitted");
        let safe_inline = format!(
            "{safe}\nmod child {{\n    extern crate alloc as __cser_alloc;\n    extern crate core as __cser_core;\n    #[derive(__cser_core::marker::Copy, __cser_core::clone::Clone)]\n    struct Local;\n}}\n"
        );
        fs::write(&source_path, &safe_inline).expect("write safe inline-module fixture");
        let mut safe_inline_closure = BTreeSet::new();
        collect_external_module_closure(
            root,
            Path::new("effect_registry.rs"),
            &mut safe_inline_closure,
        )
        .expect("each inline module retains its own exact sysroot aliases");
        let exact_inline_never =
            format!("{safe}\n#[inline(never)]\npub fn retained_frame() {{}}\n");
        fs::write(&source_path, &exact_inline_never).expect("write exact inline(never) fixture");
        let mut exact_inline_never_closure = BTreeSet::new();
        collect_external_module_closure(
            root,
            Path::new("effect_registry.rs"),
            &mut exact_inline_never_closure,
        )
        .expect("only exact inline(never) remains an audited stack-safety attribute");
        let safe_without_aliases = safe
            .replacen("extern crate alloc as __cser_alloc;\n", "", 1)
            .replacen("extern crate core as __cser_core;\n", "", 1);

        for (name, mutation) in [
            (
                "inline module missing local sysroot aliases",
                format!("{safe}\nmod child {{ pub fn local() {{}} }}\n"),
            ),
            (
                "crate-self core alias",
                format!("{safe}\nextern crate self as core;\n"),
            ),
            (
                "block-local aliases cannot satisfy module-root provenance",
                format!(
                    "{safe_without_aliases}\npub fn local_aliases() {{\n    extern crate alloc as __cser_alloc;\n    extern crate core as __cser_core;\n}}\n"
                ),
            ),
            (
                "raw UseTree Name spelling shadows protected macro",
                format!("{safe}\nuse core::r#assert;\n"),
            ),
            (
                "raw UseTree Rename spelling shadows protected macro",
                format!("{safe}\nuse core::include as r#assert;\n"),
            ),
            (
                "raw inline module spelling binds protected sysroot alias",
                format!(
                    "{safe}\nmod r#__cser_core {{\n    extern crate alloc as __cser_alloc;\n    extern crate core as __cser_core;\n}}\n"
                ),
            ),
            (
                "unqualified derive macro",
                format!("{safe}\n#[derive(Clone)]\nstruct Hidden;\n"),
            ),
            (
                "bare inline attribute",
                format!("{safe}\n#[inline]\npub fn hidden() {{}}\n"),
            ),
            (
                "inline always attribute",
                format!("{safe}\n#[inline(always)]\npub fn hidden() {{}}\n"),
            ),
            (
                "unknown inline argument",
                format!("{safe}\n#[inline(sometimes)]\npub fn hidden() {{}}\n"),
            ),
            (
                "inline name-value attribute",
                format!("{safe}\n#[inline = \"never\"]\npub fn hidden() {{}}\n"),
            ),
            (
                "inline external module",
                format!("{safe}\nmod outer {{ mod hidden; }}\n"),
            ),
            (
                "block-local external module",
                format!("{safe}\npub fn hidden() {{ #[path = \"hidden.rs\"] mod hidden; }}\n"),
            ),
            (
                "include item",
                format!("{safe}\ninclude!(\"hidden.rs\");\n"),
            ),
            (
                "nested include expression",
                format!(
                    "{safe}\npub fn hidden() -> bool {{ __cser_core::assert!(include!(\"hidden.rs\")); true }}\n"
                ),
            ),
            (
                "include string expression",
                format!("{safe}\nconst HIDDEN: &str = include_str!(\"hidden.txt\");\n"),
            ),
            (
                "include bytes expression",
                format!("{safe}\nconst HIDDEN: &[u8] = include_bytes!(\"hidden.bin\");\n"),
            ),
            (
                "dynamic item macro",
                format!("{safe}\nmake_hidden_source!();\n"),
            ),
            (
                "nested dynamic macro",
                format!(
                    "{safe}\npub fn hidden() -> bool {{ __cser_core::assert!(make_hidden_source!()); true }}\n"
                ),
            ),
            (
                "external module hidden in allowed macro tokens",
                format!(
                    "{safe}\npub fn hidden() {{ __cser_core::assert!({{ #[path = \"hidden.rs\"] mod hidden; true }}); }}\n"
                ),
            ),
            (
                "attribute hidden in allowed macro tokens",
                format!(
                    "{safe}\npub fn hidden() {{ __cser_core::assert!({{ #[allow(unused)] let hidden = true; hidden }}); }}\n"
                ),
            ),
            (
                "inner attribute hidden in allowed macro tokens",
                format!(
                    "{safe}\npub fn hidden() {{ __cser_core::assert!({{ #![loader(\"hidden.rs\")] true }}); }}\n"
                ),
            ),
            (
                "macro alias binding hidden in allowed macro tokens",
                format!(
                    "{safe}\npub fn hidden() {{ __cser_core::assert!({{ use core::include as assert_eq; assert_eq!(\"hidden.rs\"); true }}); }}\n"
                ),
            ),
            (
                "allowed macro name imported as include alias",
                format!(
                    "{safe}\nuse core::include as assert;\npub fn hidden() {{ assert!(\"hidden.rs\"); }}\n"
                ),
            ),
            (
                "audited alloc macro path shadowed by local module",
                format!(
                    "{safe}\nmod __cser_alloc {{ pub use core::assert as vec; }}\npub fn hidden() {{ __cser_alloc::vec!(true); }}\n"
                ),
            ),
            (
                "unqualified builtin macro",
                format!("{safe}\npub fn hidden() {{ assert!(true); }}\n"),
            ),
            (
                "unqualified alloc macro",
                format!("{safe}\npub fn hidden() {{ alloc::vec!(true); }}\n"),
            ),
            (
                "audited alloc macro terminal name imported from another macro",
                format!(
                    "{safe}\nmod helper {{ pub use core::assert as format; }}\nuse helper::format;\n"
                ),
            ),
            (
                "external glob may import protected macro names",
                format!("{safe}\nuse core::*;\n"),
            ),
            (
                "unfrozen local glob may import protected macro names",
                format!("{safe}\nuse super::*;\n"),
            ),
            (
                "unknown source-loading attribute",
                format!("{safe}\n#[loader(\"hidden.rs\")]\npub fn hidden() {{}}\n"),
            ),
            (
                "macro-use extern crate",
                format!("{safe}\n#[macro_use]\nextern crate alloc;\n"),
            ),
            (
                "cfg_attr path redirect",
                format!(
                    "{safe}\n#[path = \"child.rs\"]\n#[cfg_attr(any(), path = \"hidden.rs\")]\nmod child;\n"
                ),
            ),
        ] {
            fs::write(&source_path, mutation)
                .unwrap_or_else(|error| panic!("write {name} mutation: {error}"));
            let mut closure = BTreeSet::new();
            let result = collect_external_module_closure(
                root,
                Path::new("effect_registry.rs"),
                &mut closure,
            );
            assert!(result.is_err(), "{name} mutation unexpectedly passed");
        }

        fs::remove_dir_all(&temporary).expect("remove temporary CSER source root");
    }

    #[test]
    fn cser_test_local_macros_are_exact_frozen_and_file_scoped() {
        let root = repository_root();
        let source = fs::read_to_string(
            root.join(CSER_SOURCE_ROOT)
                .join(CSER_FROZEN_TEST_MACRO_SOURCE),
        )
        .expect("read frozen test-local macro source");
        let exact = syn::parse_file(&source).expect("parse frozen test-local macro source");
        reject_unbound_source_constructs(&exact, Path::new(CSER_FROZEN_TEST_MACRO_SOURCE))
            .expect("the exact frozen definitions and invocation arguments remain audited");
        reject_unbound_source_constructs(&exact, Path::new("effect_registry.rs"))
            .expect_err("the same local macro definitions may not move to another source");

        let renamed = source.replacen(
            "macro_rules! assert_enqueue_plan_change",
            "macro_rules! assert_enqueue_plan_change_renamed",
            1,
        );
        assert_ne!(renamed, source);
        let renamed = syn::parse_file(&renamed).expect("parse renamed macro mutation");
        reject_unbound_source_constructs(&renamed, Path::new(CSER_FROZEN_TEST_MACRO_SOURCE))
            .expect_err("renaming a frozen macro must fail closed");

        let attributed_definition = source.replacen(
            "    macro_rules! assert_enqueue_plan_change",
            "    #[cfg(test)]\n    macro_rules! assert_enqueue_plan_change",
            1,
        );
        assert_ne!(attributed_definition, source);
        let attributed_definition =
            syn::parse_file(&attributed_definition).expect("parse attributed macro definition");
        reject_unbound_source_constructs(
            &attributed_definition,
            Path::new(CSER_FROZEN_TEST_MACRO_SOURCE),
        )
        .expect_err("a frozen definition may not gain configuration attributes");

        let mutated_body = source.replacen(
            concat!(
                "macro_rules! assert_enqueue_plan_change {\n",
                "        ($change:expr) => {{\n",
                "            let mut changed_plan = enqueue_plan;"
            ),
            concat!(
                "macro_rules! assert_enqueue_plan_change {\n",
                "        ($change:expr) => {{\n",
                "            mod hidden;\n",
                "            let mut changed_plan = enqueue_plan;"
            ),
            1,
        );
        assert_ne!(mutated_body, source);
        let mutated_body =
            syn::parse_file(&mutated_body).expect("parse macro-body source mutation");
        reject_unbound_source_constructs(&mutated_body, Path::new(CSER_FROZEN_TEST_MACRO_SOURCE))
            .expect_err("a frozen macro body may not generate a hidden external module");

        let unknown_invocation = format!("{source}\nunknown_local_source!();\n");
        let unknown_invocation =
            syn::parse_file(&unknown_invocation).expect("parse unknown local invocation");
        reject_unbound_source_constructs(
            &unknown_invocation,
            Path::new(CSER_FROZEN_TEST_MACRO_SOURCE),
        )
        .expect_err("an unknown local macro invocation must fail closed");

        let removed_invocation =
            source.replacen("        assert_enqueue_plan_change!(mutate);\n", "", 1);
        assert_ne!(removed_invocation, source);
        let removed_invocation =
            syn::parse_file(&removed_invocation).expect("parse removed invocation mutation");
        reject_unbound_source_constructs(
            &removed_invocation,
            Path::new(CSER_FROZEN_TEST_MACRO_SOURCE),
        )
        .expect_err("the exact invocation multiset must remain frozen");

        for (name, replacement) in [
            (
                "disabled branch",
                concat!(
                    "        if false {\n",
                    "            assert_enqueue_plan_change!(mutate);\n",
                    "        }\n"
                ),
            ),
            (
                "zero-trip loop",
                concat!(
                    "        for _ in 0..0 {\n",
                    "            assert_enqueue_plan_change!(mutate);\n",
                    "        }\n"
                ),
            ),
            (
                "relocated nested block",
                concat!(
                    "        {\n",
                    "            assert_enqueue_plan_change!(mutate);\n",
                    "        }\n"
                ),
            ),
        ] {
            let mutation = source.replacen(
                "        assert_enqueue_plan_change!(mutate);\n",
                replacement,
                1,
            );
            assert_ne!(mutation, source, "{name} fixture must mutate");
            let mutation = syn::parse_file(&mutation)
                .unwrap_or_else(|error| panic!("parse {name} control-flow mutation: {error}"));
            reject_unbound_source_constructs(&mutation, Path::new(CSER_FROZEN_TEST_MACRO_SOURCE))
                .expect_err("the normalized evidence-test AST must bind invocation control flow");
        }

        let attributed_invocation = source.replacen(
            "        assert_enqueue_plan_change!(mutate);\n",
            "        #[cfg(test)]\n        assert_enqueue_plan_change!(mutate);\n",
            1,
        );
        assert_ne!(attributed_invocation, source);
        let attributed_invocation =
            syn::parse_file(&attributed_invocation).expect("parse attributed macro invocation");
        reject_unbound_source_constructs(
            &attributed_invocation,
            Path::new(CSER_FROZEN_TEST_MACRO_SOURCE),
        )
        .expect_err("a frozen invocation may not gain configuration attributes");

        let changed_delimiter = source.replacen(
            "        assert_enqueue_plan_change!(mutate);\n",
            "        assert_enqueue_plan_change! { mutate }\n",
            1,
        );
        assert_ne!(changed_delimiter, source);
        let changed_delimiter =
            syn::parse_file(&changed_delimiter).expect("parse changed invocation delimiter");
        reject_unbound_source_constructs(
            &changed_delimiter,
            Path::new(CSER_FROZEN_TEST_MACRO_SOURCE),
        )
        .expect_err("a frozen invocation may not change delimiter or statement form");

        let opaque_source_in_argument = source.replacen(
            "        assert_enqueue_plan_change!(mutate);\n",
            concat!(
                "        assert_enqueue_plan_change!({\n",
                "            #[path = \"hidden.rs\"]\n",
                "            mod hidden;\n",
                "            mutate\n",
                "        });\n"
            ),
            1,
        );
        assert_ne!(opaque_source_in_argument, source);
        let opaque_source_in_argument = syn::parse_file(&opaque_source_in_argument)
            .expect("parse opaque macro-argument source mutation");
        reject_unbound_source_constructs(
            &opaque_source_in_argument,
            Path::new(CSER_FROZEN_TEST_MACRO_SOURCE),
        )
        .expect_err("macro arguments may not hide an external source module");
    }

    #[test]
    fn cser_root_lane_super_glob_is_single_file_frozen() {
        let root = repository_root();
        let relative = Path::new("effect_registry/root_lanes.rs");
        let source = fs::read_to_string(root.join(CSER_SOURCE_ROOT).join(relative))
            .expect("read root lanes");
        let exact = syn::parse_file(&source).expect("parse root lanes");
        reject_unbound_source_constructs(&exact, relative)
            .expect("the one audited test-local super glob remains exact");

        let removed = source.replacen("    use super::*;\n", "", 1);
        assert_ne!(removed, source);
        let removed = syn::parse_file(&removed).expect("parse removed super glob mutation");
        reject_unbound_source_constructs(&removed, relative).expect_err(
            "the frozen root-lane super glob may not disappear or move by substitution",
        );

        let duplicated = source.replacen(
            "    use super::*;\n",
            "    use super::*;\n    use super::*;\n",
            1,
        );
        assert_ne!(duplicated, source);
        let duplicated =
            syn::parse_file(&duplicated).expect("parse duplicated super glob mutation");
        reject_unbound_source_constructs(&duplicated, relative)
            .expect_err("the frozen root-lane super glob may not be duplicated");

        for (name, replacement) in [
            ("nested super path", "    use super::hidden::*;\n"),
            ("grouped super path", "    use super::{hidden::*};\n"),
            ("public super glob", "    pub use super::*;\n"),
        ] {
            let mutated = source.replacen("    use super::*;\n", replacement, 1);
            assert_ne!(mutated, source, "{name} fixture must mutate");
            let mutated = syn::parse_file(&mutated).expect("parse super glob shape mutation");
            reject_unbound_source_constructs(&mutated, relative)
                .expect_err("only the exact unqualified private super glob may be frozen");
        }

        let ungated = source.replacen("#[cfg(test)]\nmod tests {", "mod tests {", 1);
        assert_ne!(ungated, source);
        let ungated = syn::parse_file(&ungated).expect("parse ungated tests module mutation");
        reject_unbound_source_constructs(&ungated, relative)
            .expect_err("the frozen super glob must stay in the top-level cfg(test) module");

        let moved = source.replacen(
            "#[cfg(test)]\nmod tests {",
            "use super::*;\n\n#[cfg(test)]\nmod tests {",
            1,
        );
        assert_ne!(moved, source);
        let moved = syn::parse_file(&moved).expect("parse moved super glob mutation");
        reject_unbound_source_constructs(&moved, relative)
            .expect_err("a super glob outside the frozen tests module must fail closed");

        let block_local = source.replacen(
            "    use super::*;\n",
            "    fn hidden_import() { use super::*; }\n",
            1,
        );
        assert_ne!(block_local, source);
        let block_local =
            syn::parse_file(&block_local).expect("parse block-local super glob mutation");
        reject_unbound_source_constructs(&block_local, relative)
            .expect_err("the frozen super glob must remain a direct module child");
    }

    #[cfg(unix)]
    #[test]
    fn cser_source_binding_rejects_symlink_sources() {
        use std::os::unix::fs::symlink;

        let temporary =
            std::env::temp_dir().join(format!("nexus-cser-source-binding-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temporary);
        fs::create_dir_all(&temporary).expect("create temporary source directory");
        let source = temporary.join("source.rs");
        let alias = temporary.join("alias.rs");
        fs::write(&source, "pub fn source() {}\n").expect("write temporary source");
        symlink(&source, &alias).expect("create source symlink");
        require_plain_regular_file_below(&temporary, Path::new("source.rs"), "test source")
            .expect("plain source accepted");
        require_plain_regular_file_below(&temporary, Path::new("alias.rs"), "test source")
            .expect_err("source symlink must be rejected");

        let source_root = temporary.join("source-root");
        let target_directory = source_root.join("target");
        let alias_directory = source_root.join("alias");
        fs::create_dir_all(&target_directory).expect("create source target directory");
        fs::write(target_directory.join("child.rs"), "pub fn child() {}\n")
            .expect("write source below target directory");
        symlink(&target_directory, &alias_directory).expect("create source directory symlink");
        require_plain_regular_file_below(&source_root, Path::new("alias/child.rs"), "test source")
            .expect_err("a symlinked source path component must be rejected");

        let trusted_repository = temporary.join("trusted-repository");
        let real_kernel = temporary.join("real-kernel");
        let real_cser = real_kernel.join("nexus-ostd/src/cser");
        fs::create_dir_all(&trusted_repository).expect("create trusted repository root");
        fs::create_dir_all(&real_cser).expect("create real CSER source ancestry");
        fs::write(real_cser.join("source.rs"), "pub fn source() {}\n")
            .expect("write source below real kernel ancestry");
        symlink(&real_kernel, trusted_repository.join("kernel"))
            .expect("create repository kernel ancestor symlink");
        require_plain_regular_file_below(
            &trusted_repository,
            Path::new("kernel/nexus-ostd/src/cser/source.rs"),
            "manifest-bound source",
        )
        .expect_err("a symlink before the CSER root must be rejected from the trusted repo root");
        fs::remove_dir_all(&temporary).expect("remove temporary source directory");
    }

    #[test]
    fn qemu_capture_authority_helper_is_raw_frozen_and_shared() {
        let root = repository_root();
        validate_qemu_capture_helpers(&root).expect("exact shared QEMU capture helper");
        let kernel =
            fs::read(root.join(QEMU_CAPTURE_HELPERS[0])).expect("read kernel QEMU capture helper");
        let spike =
            fs::read(root.join(QEMU_CAPTURE_HELPERS[1])).expect("read spike QEMU capture helper");
        assert_eq!(kernel, spike);
        let mut mutation = kernel;
        mutation.extend_from_slice(b"\nfunction /usr/bin/docker { return 0; }\n");
        validate_qemu_capture_helper_bytes(QEMU_CAPTURE_HELPERS[0], &mutation)
            .expect_err("a helper-side slash-named Docker function must fail raw provenance");
    }

    #[test]
    fn production_build_surfaces_keep_cache_evidence_and_source_identity_separate() {
        let root = repository_root();
        let frontdoor = fs::read_to_string(root.join("x")).expect("read root workflow");
        let dockerfile = fs::read_to_string(root.join("Dockerfile")).expect("read Dockerfile");
        validate_workspace_dependency_cache_inputs(&dockerfile)
            .expect("complete workspace dependency cache inputs");
        for (relative, cached) in DEPENDENCY_CACHE_INPUTS {
            let copy = format!("COPY {relative} {cached}");
            let missing = dockerfile.replacen(&copy, "COPY removed-input /tmp/removed", 1);
            let error = validate_workspace_dependency_cache_inputs(&missing)
                .expect_err("every dependency cache input must be required")
                .to_string();
            assert!(error.contains(relative));
        }
        let (first_relative, first_cached) = DEPENDENCY_CACHE_INPUTS[0];
        let first_mounted = format!("/tmp/nexus-workspace/{first_relative}");
        let first_compare = format!("cmp {first_cached} {first_mounted}");
        let wrong_pair = dockerfile.replacen(
            &first_compare,
            &format!("cmp {first_cached} /tmp/nexus-workspace/Cargo.toml"),
            1,
        );
        validate_workspace_dependency_cache_inputs(&wrong_pair)
            .expect_err("a comparison with the wrong mounted operand must fail");

        let substituted = dockerfile.replacen(
            &first_compare,
            &format!("cmp {first_cached} $(printf '%s' {first_mounted})"),
            1,
        );
        validate_workspace_dependency_cache_inputs(&substituted)
            .expect_err("a command-substituted operand must fail");

        let ignored = dockerfile.replacen(&first_compare, &format!("{first_compare} || true"), 1);
        validate_workspace_dependency_cache_inputs(&ignored)
            .expect_err("an ignored comparison failure must fail");

        let tail_recovery = dockerfile.replacen(
            "chmod -R a+rwX /usr/local/cargo",
            "chmod -R a+rwX /usr/local/cargo || true",
            1,
        );
        validate_workspace_dependency_cache_inputs(&tail_recovery)
            .expect_err("a tail recovery must not swallow any earlier comparison failure");

        validate_clean_contract(&frontdoor).expect("safe cache cleanup contract");
        validate_cold_rebuild_contract(&root, &frontdoor).expect("cache-cold rebuild contract");
        validate_backend_source_binding(&root).expect("production source binding");
        validate_transition_gate_route(&root).expect("transition-gate CI route");

        let kernel_source =
            fs::read_to_string(root.join("kernel/nexus-ostd/x")).expect("read kernel workflow");
        let kernel_dockerfile = fs::read_to_string(root.join("kernel/nexus-ostd/Dockerfile"))
            .expect("read kernel Dockerfile");
        validate_portal_abi_image_binding(&kernel_source, &kernel_dockerfile)
            .expect("portal ABI image binding");
        let early_exit_identity = kernel_source.replacen(
            "    \"$root/Dockerfile\" \\\n",
            "    \"$root/Dockerfile\" \\\n    ; exit 0; \\\n",
            1,
        );
        validate_portal_abi_image_binding(&early_exit_identity, &kernel_dockerfile)
            .expect_err("an early exit may not hide unhashed identity inputs");
        let commented_container = kernel_source.replacen("container() {", "# container() {", 1);
        validate_portal_abi_image_binding(&commented_container, &kernel_dockerfile)
            .expect_err("a container declaration retained only in a comment must be rejected");
        for relative in PORTAL_ABI_IMAGE_INPUTS {
            let input = format!("$repo_root/crates/nexus-portal-abi/{relative}");
            let missing = kernel_source.replacen(&input, "removed-portal-abi-input", 1);
            validate_portal_abi_image_binding(&missing, &kernel_dockerfile)
                .expect_err("every portal ABI source must affect the kernel image identity");
            let commented = format!("{missing}\n# retained marker only: {input}\n");
            validate_portal_abi_image_binding(&commented, &kernel_dockerfile)
                .expect_err("a portal ABI input retained only in a comment must be rejected");
            let in_command_comment = missing.replacen(
                "image_key=$(sha256sum \\\n",
                &format!("image_key=$(sha256sum \\\n    # \"{input}\" \\\n"),
                1,
            );
            validate_portal_abi_image_binding(&in_command_comment, &kernel_dockerfile)
                .expect_err("a portal ABI input in a continued-command comment must be rejected");
        }
        let missing_portal_mount = kernel_source.replacen(
            r#"-v "$repo_root/crates/nexus-portal-abi:/crates/nexus-portal-abi:ro,z""#,
            "removed-portal-abi-mount",
            1,
        );
        validate_portal_abi_image_binding(&missing_portal_mount, &kernel_dockerfile)
            .expect_err("the live kernel build must mount the portal ABI source");
        let early_exit_container = kernel_source.replacen(
            "        -v \"$repo_root/crates/nexus-portal-abi:/crates/nexus-portal-abi:ro,z\" \\\n",
            "        ; exit 0; \\\n        -v \"$repo_root/crates/nexus-portal-abi:/crates/nexus-portal-abi:ro,z\" \\\n",
            1,
        );
        validate_portal_abi_image_binding(&early_exit_container, &kernel_dockerfile)
            .expect_err("an early exit may not bypass the live portal ABI mount");
        let commented_portal_mount = format!(
            "{missing_portal_mount}\n# retained marker only: -v \"$repo_root/crates/nexus-portal-abi:/crates/nexus-portal-abi:ro,z\"\n"
        );
        validate_portal_abi_image_binding(&commented_portal_mount, &kernel_dockerfile)
            .expect_err("a portal ABI mount retained only in a comment must be rejected");
        let missing_portal_copy = kernel_dockerfile.replacen(
            "COPY crates/nexus-portal-abi /crates/nexus-portal-abi",
            "COPY removed-portal-abi /crates/nexus-portal-abi",
            1,
        );
        validate_portal_abi_image_binding(&kernel_source, &missing_portal_copy)
            .expect_err("the cold kernel image must bake the portal ABI source");
        let commented_portal_copy = format!(
            "{missing_portal_copy}\n# COPY crates/nexus-portal-abi /crates/nexus-portal-abi\n"
        );
        validate_portal_abi_image_binding(&kernel_source, &commented_portal_copy)
            .expect_err("a portal ABI COPY retained only in a comment must be rejected");

        let unsafe_default = frontdoor.replace("mode=${1:-cache}", "mode=${1:---all}");
        validate_clean_contract(&unsafe_default)
            .expect_err("evidence-deleting default clean must be rejected");

        let production_files =
            cser_production_source_files(&root).expect("canonical production source manifest");
        for (relative, source_root) in [
            ("kernel/nexus-ostd/x", "$root/src/cser"),
            (
                "experiments/ostd-virtio-cser-spike/x",
                "$repo_root/kernel/nexus-ostd/src/cser",
            ),
        ] {
            let source = fs::read_to_string(root.join(relative)).expect("read backend workflow");
            validate_backend_source_pair(relative, &source, source_root, &production_files)
                .expect("manifest-driven source binding");

            let unprivileged_interpreter =
                source.replacen("#!/usr/bin/bash -p", "#!/usr/bin/bash", 1);
            assert_ne!(unprivileged_interpreter, source);
            validate_backend_source_pair(
                relative,
                &unprivileged_interpreter,
                source_root,
                &production_files,
            )
            .expect_err("the backend shell must ignore exported functions and startup hooks");

            let path_resolved_interpreter =
                source.replacen("#!/usr/bin/bash", "#!/usr/bin/env bash", 1);
            assert_ne!(path_resolved_interpreter, source);
            validate_backend_source_pair(
                relative,
                &path_resolved_interpreter,
                source_root,
                &production_files,
            )
            .expect_err("the production backend interpreter may not be PATH-resolved");

            let manifest_symlink_bypass =
                source.replacen(" || -L $production_source_manifest", "", 1);
            assert_ne!(manifest_symlink_bypass, source);
            validate_backend_source_pair(
                relative,
                &manifest_symlink_bypass,
                source_root,
                &production_files,
            )
            .expect_err("direct backend execution must reject a symlinked source manifest");

            let source_symlink_bypass = source.replacen(" || -L $source_path", "", 1);
            assert_ne!(source_symlink_bypass, source);
            validate_backend_source_pair(
                relative,
                &source_symlink_bypass,
                source_root,
                &production_files,
            )
            .expect_err("direct backend execution must reject symlinked manifest sources");

            let manifest_ancestor_symlink_bypass = source.replacen(
                r#" || [[ $(realpath -e -- "$production_source_manifest") != "$production_source_manifest" ]]"#,
                "",
                1,
            );
            assert_ne!(manifest_ancestor_symlink_bypass, source);
            validate_backend_source_pair(
                relative,
                &manifest_ancestor_symlink_bypass,
                source_root,
                &production_files,
            )
            .expect_err("direct backend execution must reject symlinked manifest ancestors");

            let source_ancestor_symlink_bypass = source.replacen(
                r#" || [[ $(realpath -e -- "$source_path") != "$source_path" ]]"#,
                "",
                1,
            );
            assert_ne!(source_ancestor_symlink_bypass, source);
            validate_backend_source_pair(
                relative,
                &source_ancestor_symlink_bypass,
                source_root,
                &production_files,
            )
            .expect_err("direct backend execution must reject symlinked source ancestors");

            let current_directory_alias_bypass =
                source.replacen(r#" || $relative == ./* || $relative == *"/./"*"#, "", 1);
            assert_ne!(current_directory_alias_bypass, source);
            validate_backend_source_pair(
                relative,
                &current_directory_alias_bypass,
                source_root,
                &production_files,
            )
            .expect_err("direct backend execution must reject current-directory path aliases");

            let missing_hash = source.replacen(
                r#""${cser_source_hash_inputs[@]}""#,
                "\"removed-production-hash-array\"",
                1,
            );
            assert_ne!(missing_hash, source);
            validate_backend_source_pair(relative, &missing_hash, source_root, &production_files)
                .expect_err("missing manifest-derived source hash array must be rejected");

            let missing_mount = source.replacen(
                r#""${cser_source_mount_args[@]}""#,
                "\"removed-production-mount-array\"",
                1,
            );
            assert_ne!(missing_mount, source);
            validate_backend_source_pair(relative, &missing_mount, source_root, &production_files)
                .expect_err("missing manifest-derived source mount array must be rejected");

            let flattened = source.replacen(
                r#"target_path="/kernel/nexus-ostd/src/cser/$relative""#,
                r#"target_path="/kernel/nexus-ostd/src/cser/${relative##*/}""#,
                1,
            );
            assert_ne!(flattened, source);
            validate_backend_source_pair(relative, &flattened, source_root, &production_files)
                .expect_err("flattened manifest-derived target must be rejected");

            let selective_loop = source.replacen(
                r#"for relative in "${cser_production_sources[@]}"; do"#,
                concat!(
                    "for relative in \"${cser_production_sources[@]}\"; do\n",
                    "    [[ $relative == device_flight.rs ]] || continue"
                ),
                1,
            );
            assert_ne!(selective_loop, source);
            validate_backend_source_pair(relative, &selective_loop, source_root, &production_files)
                .expect_err("a condition may not narrow the manifest-driven hash and mount loop");

            let reassigned_manifest = source.replacen(
                r#"mapfile -t cser_production_sources <"$production_source_manifest""#,
                concat!(
                    "mapfile -t cser_production_sources <\"$production_source_manifest\"\n",
                    "cser_production_sources=(device_flight.rs)"
                ),
                1,
            );
            assert_ne!(reassigned_manifest, source);
            validate_backend_source_pair(
                relative,
                &reassigned_manifest,
                source_root,
                &production_files,
            )
            .expect_err("the canonical manifest array may not be reassigned before hashing");

            let missing_readonly = source.replacen(
                "readonly -a cser_production_sources cser_source_hash_inputs cser_source_mount_args\n",
                "",
                1,
            );
            assert_ne!(missing_readonly, source);
            validate_backend_source_pair(
                relative,
                &missing_readonly,
                source_root,
                &production_files,
            )
            .expect_err("manifest and derived source arrays must become immutable");

            let inactive_binding = source
                .replacen(
                    "production_source_manifest=",
                    "if false; then\nproduction_source_manifest=",
                    1,
                )
                .replacen("image_key=", "fi\nimage_key=", 1);
            assert_ne!(inactive_binding, source);
            validate_backend_source_pair(
                relative,
                &inactive_binding,
                source_root,
                &production_files,
            )
            .expect_err("the exact source-binding block must execute at top level");

            let mount_after_image = source
                .replacen("        \"${cser_source_mount_args[@]}\" \\\n", "", 1)
                .replacen(
                    "        \"$image\" \\\n",
                    concat!(
                        "        \"$image\" \\\n",
                        "        \"${cser_source_mount_args[@]}\" \\\n"
                    ),
                    1,
                );
            assert_ne!(mount_after_image, source);
            validate_backend_source_pair(
                relative,
                &mount_after_image,
                source_root,
                &production_files,
            )
            .expect_err("source mounts after the image are container command arguments");

            for (name, insertion) in [
                (
                    "late Docker function shadow",
                    "docker() { return 0; }\nrunner_base=",
                ),
                (
                    "late command function shadow",
                    "command() { return 0; }\nrunner_base=",
                ),
                (
                    "late slash-named Docker function shadow",
                    "function /usr/bin/docker { return 0; }\nrunner_base=",
                ),
                (
                    "late PATH shadow",
                    "PATH=/tmp/nexus-attacker:$PATH\nrunner_base=",
                ),
            ] {
                let mutation = source.replacen("runner_base=", insertion, 1);
                assert_ne!(mutation, source, "{name} fixture must mutate");
                validate_backend_source_pair(relative, &mutation, source_root, &production_files)
                    .expect_err("late command provenance changes must be script-vector bound");
            }

            let mutable_docker_path = source.replacen("readonly docker_bin\n", "", 1);
            assert_ne!(mutable_docker_path, source);
            validate_backend_source_pair(
                relative,
                &mutable_docker_path,
                source_root,
                &production_files,
            )
            .expect_err("the absolute Docker command path must be immutable");

            let mutable_path = source.replacen("readonly PATH\n", "", 1);
            assert_ne!(mutable_path, source);
            validate_backend_source_pair(relative, &mutable_path, source_root, &production_files)
                .expect_err("the host command search path must be immutable");

            let unbound_helper =
                source.replacen(r#"source "$capture_helper""#, "source /tmp/attacker", 1);
            assert_ne!(unbound_helper, source);
            validate_backend_source_pair(relative, &unbound_helper, source_root, &production_files)
                .expect_err("the backend may source only the raw-frozen helper");

            let bare_docker =
                source.replacen(r#"command "$docker_bin" run --rm"#, "docker run --rm", 1);
            assert_ne!(bare_docker, source);
            validate_backend_source_pair(relative, &bare_docker, source_root, &production_files)
                .expect_err("container execution may not use a PATH-resolved Docker command");
        }

        let production_registry =
            fs::read_to_string(root.join(PRODUCTION_REGISTRY_TEST)).expect("read registry gate");
        let disabled_test = production_registry.replacen(
            "#[test]\nfn production_identity_chain_uses_one_registry_and_shared_ledger()",
            "#[test]\n#[cfg(any())]\nfn production_identity_chain_uses_one_registry_and_shared_ledger()",
            1,
        );
        validate_production_registry_gate(&disabled_test)
            .expect_err("a conditionally compiled-out production test must be rejected");
        let conditional_module = production_registry.replacen(
            "#[path = \"../../../kernel/nexus-ostd/src/cser/effect_registry.rs\"]",
            "#[cfg(any())]\n#[path = \"../../../kernel/nexus-ostd/src/cser/effect_registry.rs\"]",
            1,
        );
        validate_production_registry_gate(&conditional_module)
            .expect_err("a conditionally compiled-out production module must be rejected");
        for required_call in [
            "effect_registry::production_identity_registry_self_test();",
            "device_flight::retained_semantic_self_test();",
            "portal_v2::production_portal_v2_self_test();",
        ] {
            let missing = production_registry.replace(required_call, "removed_self_test();");
            validate_production_registry_gate(&missing)
                .expect_err("missing production self-test call must be rejected");

            let comment_only =
                production_registry.replacen(required_call, &format!("// {required_call}"), 1);
            validate_production_registry_gate(&comment_only)
                .expect_err("a self-test name retained only in a comment must be rejected");

            let string_only = production_registry.replacen(
                required_call,
                &format!("let _ = {required_call:?};"),
                1,
            );
            validate_production_registry_gate(&string_only)
                .expect_err("a self-test name retained only in a string must be rejected");

            let disabled_call = production_registry.replacen(
                required_call,
                &format!("#[cfg(any())]\n    {required_call}"),
                1,
            );
            validate_production_registry_gate(&disabled_call)
                .expect_err("a conditionally compiled-out self-test call must be rejected");
        }
    }

    #[test]
    fn production_virtio_dependency_graph_is_exact_across_workspaces() {
        let root = repository_root();
        let manifest = fs::read_to_string(root.join("crates/nexus-ostd-virtio/Cargo.toml"))
            .expect("read facade manifest");
        let lock_sources = VIRTIO_PRODUCTION_LOCKS
            .iter()
            .map(|relative| fs::read_to_string(root.join(relative)).expect("read lock fixture"))
            .collect::<Vec<_>>();
        validate_virtio_fixture(&manifest, &lock_sources)
            .expect("production VirtIO dependency parity");

        let authority_index = VIRTIO_PRODUCTION_LOCKS
            .iter()
            .position(|relative| *relative == VIRTIO_AUTHORITY_LOCK)
            .expect("authority lock index");
        let authority = facade_direct_edges(&lock_sources[authority_index], VIRTIO_AUTHORITY_LOCK)
            .expect("authority direct graph");
        for consumer in 0..lock_sources.len() {
            for (name, edge) in &authority {
                let mut missing = lock_sources.clone();
                missing[consumer] = remove_facade_direct_edge(&missing[consumer], name);
                validate_virtio_fixture(&manifest, &missing)
                    .expect_err("missing facade direct edge must be rejected");

                let mut drifted = lock_sources.clone();
                drifted[consumer] = drift_direct_edge(&drifted[consumer], name, edge);
                validate_virtio_fixture(&manifest, &drifted)
                    .expect_err("drifted facade direct edge must be rejected");
            }
        }
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
    fn requires_a_read_only_linked_worktree_git_mount() {
        let route = r#"
run_xtask() {
    local -a git_mount=()
    if [[ -f "$root/.git" ]]; then
        if ! git_common_dir=$(git -C "$root" rev-parse --path-format=absolute --git-common-dir) ||
            [[ ! -d $git_common_dir || $git_common_dir == *:* ]]; then
            exit 1
        fi
        git_mount=(
            --volume "$git_common_dir:$git_common_dir:ro,z"
        )
    fi
    "${git_mount[@]}"
}
"#;
        validate_linked_worktree_git_mount(route).expect("complete linked-worktree mount");

        for broken in [
            route.replace(":ro,z", ":z"),
            route.replace(":ro,z", ":ro"),
            route.replace("\"${git_mount[@]}\"", ""),
            route.replace("--path-format=absolute --git-common-dir", "--git-dir"),
            route.replace("if [[ -f \"$root/.git\" ]]", "if [[ -d \"$root/.git\" ]]"),
        ] {
            assert!(validate_linked_worktree_git_mount(&broken).is_err());
        }
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
