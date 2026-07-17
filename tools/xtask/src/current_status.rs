use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

const LEDGER_PATH: &str = "status/current-capabilities.toml";
const WIRE_FREEZE_PATH: &str = "status/effect-peer-native-v1.json";
const LEDGER_SCHEMA: &str = "nexus.current-capability-ledger.v1";
const WIRE_FREEZE_SCHEMA: &str = "nexus.effect-peer.wire-freeze.v1";
const WIRE_CONTRACT_ID: &str = "nexus-effect-peer-native-v1";
const NEXUS_REPOSITORY: &str = "https://github.com/chenty2333/Nexus";
const VISA_REPOSITORY: &str = "https://github.com/chenty2333/vISA";
const REQUEST_SCHEMA: &str = "nexus.effect-peer.request.v1";
const RESPONSE_SCHEMA: &str = "nexus.effect-peer.response.v1";
const RECEIPT_SCHEMA: &str = "nexus.effect-peer.native-receipt.v1";
const AUTHENTICATION_BOUNDARY: &str = "sha256-integrity-only-not-authenticity";
const OPERATIONS: [&str; 14] = [
    "initialize",
    "register",
    "prepare",
    "commit",
    "complete",
    "acknowledge-publication",
    "crash-service",
    "rebind-service",
    "freeze",
    "abort-uncommitted",
    "thaw",
    "close-step",
    "query",
    "shutdown",
];
const RECEIPT_KINDS: [&str; 14] = [
    "initialized",
    "effect-registered",
    "effect-prepared",
    "effect-committed",
    "effect-completed",
    "publication-acknowledged",
    "service-crashed",
    "service-rebound",
    "admission-frozen",
    "uncommitted-aborted",
    "admission-thawed",
    "closure-progress",
    "handoff-query",
    "shutdown",
];

pub(crate) struct Summary {
    pub(crate) checkpoints: usize,
    pub(crate) local: usize,
    pub(crate) external: usize,
    pub(crate) frozen_wire_contracts: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: String,
    ledger_revision: u32,
    as_of: String,
    classification: String,
    canonical_release: String,
    canonical_release_evidence_unchanged: bool,
    checkpoint_count: usize,
    wire_contracts: Vec<String>,
    policy: LedgerPolicy,
    checkpoint: Vec<Checkpoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerPolicy {
    local_checkpoint: String,
    external_checkpoint: String,
    frozen_release: String,
    supersession: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    kind: String,
    id: String,
    status: String,
    repository: String,
    revision: String,
    recorded_on: String,
    evidence_level: String,
    wire_contract: String,
    ci_url: String,
    commands: Option<Vec<String>>,
    capabilities: Vec<String>,
    boundaries: Vec<String>,
    sources: Vec<String>,
    pins_local_checkpoint: Option<String>,
    pins_local_revision: Option<String>,
    claim_id: Option<String>,
    qualification_lock_schema: Option<String>,
    qualification_lock_sha256: Option<String>,
    artifact_name: Option<String>,
    artifact_digest: Option<String>,
    artifact_expires_at: Option<String>,
    archive_status: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFreeze {
    schema: String,
    contract_id: String,
    status: String,
    protocol_major: u32,
    transport: String,
    canonical_encoding: String,
    request_schema: String,
    response_schema: String,
    receipt_schema: String,
    authentication_boundary: String,
    canonical_snapshot_sha256: String,
    operations: Vec<String>,
    receipt_kinds: Vec<String>,
    change_policy: WireChangePolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireChangePolicy {
    additive_v1_changes_allowed: bool,
    compatible_bugfixes: String,
    new_capabilities: String,
    extension_requirement: String,
}

pub(crate) fn validate(root: &Path) -> Result<Summary, String> {
    let wire = read_wire_freeze(root)?;
    validate_wire_freeze(&wire)?;
    let ledger = read_ledger(root)?;
    validate_ledger(root, &ledger, &wire)
}

fn read_ledger(root: &Path) -> Result<Ledger, String> {
    let path = root.join(LEDGER_PATH);
    let source =
        fs::read_to_string(&path).map_err(|error| format!("read {LEDGER_PATH}: {error}"))?;
    toml::from_str(&source).map_err(|error| format!("parse {LEDGER_PATH}: {error}"))
}

fn read_wire_freeze(root: &Path) -> Result<WireFreeze, String> {
    let path = root.join(WIRE_FREEZE_PATH);
    let source =
        fs::read_to_string(&path).map_err(|error| format!("read {WIRE_FREEZE_PATH}: {error}"))?;
    serde_json::from_str(&source).map_err(|error| format!("parse {WIRE_FREEZE_PATH}: {error}"))
}

fn validate_wire_freeze(wire: &WireFreeze) -> Result<(), String> {
    require_eq("wire.schema", &wire.schema, WIRE_FREEZE_SCHEMA)?;
    require_eq("wire.contract_id", &wire.contract_id, WIRE_CONTRACT_ID)?;
    require_eq("wire.status", &wire.status, "frozen")?;
    if wire.protocol_major != 1 {
        return Err("wire.protocol_major must remain 1".into());
    }
    require_eq("wire.transport", &wire.transport, "bounded-json-lines-lf")?;
    require_eq(
        "wire.canonical_encoding",
        &wire.canonical_encoding,
        "serde-struct-field-order-compact-json",
    )?;
    require_eq("wire.request_schema", &wire.request_schema, REQUEST_SCHEMA)?;
    require_eq(
        "wire.response_schema",
        &wire.response_schema,
        RESPONSE_SCHEMA,
    )?;
    require_eq("wire.receipt_schema", &wire.receipt_schema, RECEIPT_SCHEMA)?;
    require_eq(
        "wire.authentication_boundary",
        &wire.authentication_boundary,
        AUTHENTICATION_BOUNDARY,
    )?;
    require_sha256(
        "wire.canonical_snapshot_sha256",
        &wire.canonical_snapshot_sha256,
    )?;
    require_exact_list("wire.operations", &wire.operations, &OPERATIONS)?;
    require_exact_list("wire.receipt_kinds", &wire.receipt_kinds, &RECEIPT_KINDS)?;
    if wire.change_policy.additive_v1_changes_allowed {
        return Err("native wire v1 must reject additive capability changes".into());
    }
    require_eq(
        "wire.change_policy.compatible_bugfixes",
        &wire.change_policy.compatible_bugfixes,
        "preserve-all-frozen-v1-serde-shapes-and-semantics",
    )?;
    require_eq(
        "wire.change_policy.new_capabilities",
        &wire.change_policy.new_capabilities,
        "new-major-version-or-explicit-versioned-extension",
    )?;
    require_eq(
        "wire.change_policy.extension_requirement",
        &wire.change_policy.extension_requirement,
        "distinct-schema-identifiers-and-independent-freeze-contract",
    )
}

fn validate_ledger(root: &Path, ledger: &Ledger, wire: &WireFreeze) -> Result<Summary, String> {
    require_eq("ledger.schema", &ledger.schema, LEDGER_SCHEMA)?;
    if ledger.ledger_revision != 1 {
        return Err("ledger.ledger_revision must be 1".into());
    }
    require_date("ledger.as_of", &ledger.as_of)?;
    require_eq(
        "ledger.classification",
        &ledger.classification,
        "current-checkpoints-not-release-evidence",
    )?;
    require_eq(
        "ledger.canonical_release",
        &ledger.canonical_release,
        "v0.1.0",
    )?;
    if !ledger.canonical_release_evidence_unchanged {
        return Err("current ledger must not rewrite frozen v0.1.0 evidence".into());
    }
    if ledger.checkpoint_count != ledger.checkpoint.len() {
        return Err("ledger.checkpoint_count does not match checkpoint entries".into());
    }
    if ledger.wire_contracts != [wire.contract_id.clone()] {
        return Err(
            "ledger wire contract inventory differs from the frozen native-v1 contract".into(),
        );
    }
    for (field, actual, expected) in [
        (
            "policy.local_checkpoint",
            &ledger.policy.local_checkpoint,
            "exact-revision-bounded-observation",
        ),
        (
            "policy.external_checkpoint",
            &ledger.policy.external_checkpoint,
            "separately-owned-evidence-never-upgrades-nexus-local-claims",
        ),
        (
            "policy.frozen_release",
            &ledger.policy.frozen_release,
            "never-rewrite-or-relabel-v0.1.0-evidence",
        ),
        (
            "policy.supersession",
            &ledger.policy.supersession,
            "replace-current-entry-with-explicit-exact-revision",
        ),
    ] {
        require_eq(field, actual, expected)?;
    }

    let mut ids = BTreeSet::new();
    let mut local = Vec::new();
    let mut external = Vec::new();
    for checkpoint in &ledger.checkpoint {
        if !ids.insert(checkpoint.id.as_str()) {
            return Err(format!("duplicate checkpoint id: {}", checkpoint.id));
        }
        require_id("checkpoint.id", &checkpoint.id)?;
        require_sha("checkpoint.revision", &checkpoint.revision)?;
        require_date("checkpoint.recorded_on", &checkpoint.recorded_on)?;
        require_nonempty("checkpoint.evidence_level", &checkpoint.evidence_level)?;
        require_eq(
            "checkpoint.wire_contract",
            &checkpoint.wire_contract,
            WIRE_CONTRACT_ID,
        )?;
        require_nonempty_list("checkpoint.capabilities", &checkpoint.capabilities)?;
        require_nonempty_list("checkpoint.boundaries", &checkpoint.boundaries)?;
        require_nonempty_list("checkpoint.sources", &checkpoint.sources)?;
        match checkpoint.kind.as_str() {
            "local" => local.push(checkpoint),
            "external" => external.push(checkpoint),
            other => return Err(format!("unsupported checkpoint kind: {other}")),
        }
    }
    if local.len() != 1 || external.len() != 1 {
        return Err(
            "current ledger must contain exactly one local and one external checkpoint".into(),
        );
    }

    let local = local[0];
    require_eq("local.status", &local.status, "current-local-baseline")?;
    require_eq("local.repository", &local.repository, NEXUS_REPOSITORY)?;
    require_actions_url("local.ci_url", &local.ci_url, NEXUS_REPOSITORY)?;
    let commands = local
        .commands
        .as_ref()
        .ok_or("local checkpoint must list verification commands")?;
    require_nonempty_list("local.commands", commands)?;
    require_absent_external_fields(local)?;
    require_git_ancestor(root, &local.revision)?;
    for source in &local.sources {
        require_revision_path(root, &local.revision, source)?;
    }

    let external = external[0];
    require_eq(
        "external.status",
        &external.status,
        "exact-sha-ci-checked-not-canonical-or-archived",
    )?;
    require_eq("external.repository", &external.repository, VISA_REPOSITORY)?;
    require_actions_url("external.ci_url", &external.ci_url, VISA_REPOSITORY)?;
    if external.commands.is_some() {
        return Err("external checkpoint commands are owned by the external repository".into());
    }
    require_eq(
        "external.pins_local_checkpoint",
        required(&external.pins_local_checkpoint, "pins_local_checkpoint")?,
        &local.id,
    )?;
    require_eq(
        "external.pins_local_revision",
        required(&external.pins_local_revision, "pins_local_revision")?,
        &local.revision,
    )?;
    require_nonempty(
        "external.claim_id",
        required(&external.claim_id, "claim_id")?,
    )?;
    require_eq(
        "external.qualification_lock_schema",
        required(
            &external.qualification_lock_schema,
            "qualification_lock_schema",
        )?,
        "visa.nexus-handoff-qualification-lock.v2",
    )?;
    require_sha256(
        "external.qualification_lock_sha256",
        required(
            &external.qualification_lock_sha256,
            "qualification_lock_sha256",
        )?,
    )?;
    require_eq(
        "external.artifact_name",
        required(&external.artifact_name, "artifact_name")?,
        "nexus-visa-same-boot-qualification-evidence",
    )?;
    require_artifact_digest(
        "external.artifact_digest",
        required(&external.artifact_digest, "artifact_digest")?,
    )?;
    require_utc_timestamp(
        "external.artifact_expires_at",
        required(&external.artifact_expires_at, "artifact_expires_at")?,
    )?;
    require_eq(
        "external.archive_status",
        required(&external.archive_status, "archive_status")?,
        "ephemeral-actions-artifact-not-long-term-checkpoint",
    )?;
    for source in &external.sources {
        require_external_source("external.sources", source, &external.revision)?;
    }

    Ok(Summary {
        checkpoints: ledger.checkpoint.len(),
        local: 1,
        external: 1,
        frozen_wire_contracts: ledger.wire_contracts.len(),
    })
}

fn require_absent_external_fields(checkpoint: &Checkpoint) -> Result<(), String> {
    if checkpoint.pins_local_checkpoint.is_some()
        || checkpoint.pins_local_revision.is_some()
        || checkpoint.claim_id.is_some()
        || checkpoint.qualification_lock_schema.is_some()
        || checkpoint.qualification_lock_sha256.is_some()
        || checkpoint.artifact_name.is_some()
        || checkpoint.artifact_digest.is_some()
        || checkpoint.artifact_expires_at.is_some()
        || checkpoint.archive_status.is_some()
    {
        return Err("local checkpoint contains external-only fields".into());
    }
    Ok(())
}

fn required<'a>(value: &'a Option<String>, field: &str) -> Result<&'a String, String> {
    value
        .as_ref()
        .ok_or_else(|| format!("external checkpoint omits {field}"))
}

fn require_git_ancestor(root: &Path, revision: &str) -> Result<(), String> {
    let status = Command::new("git")
        .current_dir(root)
        .args(["merge-base", "--is-ancestor", revision, "HEAD"])
        .status()
        .map_err(|error| format!("run git merge-base: {error}"))?;
    if !status.success() {
        return Err(format!(
            "local checkpoint revision {revision} is not an ancestor of HEAD"
        ));
    }
    Ok(())
}

fn require_revision_path(root: &Path, revision: &str, path: &str) -> Result<(), String> {
    if path.starts_with('/') || path.contains("..") {
        return Err(format!(
            "local checkpoint source is not repository-relative: {path}"
        ));
    }
    let object = format!("{revision}:{path}");
    let status = Command::new("git")
        .current_dir(root)
        .args(["cat-file", "-e", &object])
        .status()
        .map_err(|error| format!("run git cat-file for {path}: {error}"))?;
    if !status.success() {
        return Err(format!("checkpoint source is absent at {revision}: {path}"));
    }
    Ok(())
}

fn require_exact_list(field: &str, actual: &[String], expected: &[&str]) -> Result<(), String> {
    if actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
    {
        Ok(())
    } else {
        Err(format!(
            "{field} differs from the frozen native-v1 inventory"
        ))
    }
}

fn require_nonempty_list(field: &str, values: &[String]) -> Result<(), String> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("{field} must contain nonempty strings"));
    }
    let unique: BTreeSet<_> = values.iter().collect();
    if unique.len() != values.len() {
        return Err(format!("{field} contains duplicates"));
    }
    Ok(())
}

fn require_eq(field: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} must be {expected:?}, got {actual:?}"))
    }
}

fn require_nonempty(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_id(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!("{field} is not a lowercase stable identifier"));
    }
    Ok(())
}

fn require_sha(field: &str, value: &str) -> Result<(), String> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{field} must be an exact lowercase Git SHA"));
    }
    Ok(())
}

fn require_sha256(field: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{field} must be a lowercase SHA-256"));
    }
    Ok(())
}

fn require_date(field: &str, value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return Err(format!("{field} must use YYYY-MM-DD"));
    }
    Ok(())
}

fn require_actions_url(field: &str, value: &str, repository: &str) -> Result<(), String> {
    let prefix = format!("{repository}/actions/runs/");
    let run = value
        .strip_prefix(&prefix)
        .ok_or_else(|| format!("{field} must use the canonical Actions URL prefix {prefix}"))?;
    if run.is_empty() || !run.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{field} must end in one numeric Actions run ID"));
    }
    Ok(())
}

fn require_external_source(field: &str, value: &str, revision: &str) -> Result<(), String> {
    let prefix = format!("{VISA_REPOSITORY}/blob/{revision}/");
    let path = value
        .strip_prefix(&prefix)
        .ok_or_else(|| format!("{field} must bind the canonical vISA blob prefix {prefix}"))?;
    if path.is_empty()
        || path.chars().any(char::is_whitespace)
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(format!("{field} contains an invalid repository path"));
    }
    Ok(())
}

fn require_artifact_digest(field: &str, value: &str) -> Result<(), String> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("{field} must use the sha256:<hex> form"))?;
    require_sha256(field, digest)
}

fn require_utc_timestamp(field: &str, value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return Err(format!("{field} must use YYYY-MM-DDTHH:MM:SSZ"));
    }

    let number = |start, end| {
        value[start..end]
            .parse::<u32>()
            .expect("digits checked above")
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let hour = number(11, 13);
    let minute = number(14, 16);
    let second = number(17, 19);
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return Err(format!("{field} is not a valid UTC timestamp"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_urls_are_bound_to_the_expected_repository_and_numeric_run() {
        assert!(
            require_actions_url(
                "ci",
                "https://github.com/chenty2333/Nexus/actions/runs/29536334333",
                NEXUS_REPOSITORY,
            )
            .is_ok()
        );
        assert!(
            require_actions_url(
                "ci",
                "https://example.invalid/actions/runs/29536334333",
                NEXUS_REPOSITORY,
            )
            .is_err()
        );
        assert!(
            require_actions_url(
                "ci",
                "https://github.com/chenty2333/Nexus/actions/runs/1/attempts/2",
                NEXUS_REPOSITORY,
            )
            .is_err()
        );
    }

    #[test]
    fn external_sources_are_exact_revision_v_isa_blob_urls() {
        let revision = "4314a181ded0862d7b1c7054f57f1bafd0595f07";
        assert!(
            require_external_source(
                "source",
                &format!("{VISA_REPOSITORY}/blob/{revision}/scripts/check.sh"),
                revision,
            )
            .is_ok()
        );
        assert!(
            require_external_source(
                "source",
                &format!("https://example.invalid/{revision}/scripts/check.sh"),
                revision,
            )
            .is_err()
        );
        assert!(
            require_external_source(
                "source",
                &format!("{VISA_REPOSITORY}/blob/{revision}/../other"),
                revision,
            )
            .is_err()
        );
    }

    #[test]
    fn external_artifact_identity_uses_typed_digest_and_valid_utc_expiry() {
        assert!(require_artifact_digest("digest", &format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(require_artifact_digest("digest", &"a".repeat(64)).is_err());
        assert!(require_utc_timestamp("expiry", "2026-07-31T06:11:52Z").is_ok());
        assert!(require_utc_timestamp("expiry", "2026-02-30T06:11:52Z").is_err());
        assert!(require_utc_timestamp("expiry", "2026-07-31T06:11:52+00:00").is_err());
    }
}
