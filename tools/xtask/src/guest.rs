use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceCatalog {
    schema_version: u32,
    catalog: String,
    source_snapshot: String,
    legacy_root: String,
    copy_root: String,
    hash_algorithm: String,
    copy_policy: String,
    source: Vec<Source>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    id: String,
    path: String,
    legacy_path: String,
    sha256: String,
    language: String,
    build_profile: String,
    role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityCatalog {
    schema_version: u32,
    catalog: String,
    normative: bool,
    target_stage: String,
    description: String,
    policy: CompatibilityPolicy,
    tier_policy: TierPolicy,
    workload: Vec<Workload>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TierPolicy {
    core: String,
    stretch: String,
    archive_input: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityPolicy {
    identity: String,
    implementation: String,
    uapi: String,
    success: String,
    legacy_provenance: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Workload {
    id: String,
    status: String,
    tier: String,
    class: String,
    source_ids: Vec<String>,
    legacy_scenarios: Vec<String>,
    #[serde(default)]
    external_assets: Vec<String>,
    required_behaviors: Vec<String>,
    success_markers: Vec<String>,
    #[serde(default)]
    cser_effects: Vec<String>,
    #[serde(default)]
    injection_profile: Vec<String>,
    #[serde(default)]
    expected_properties: Vec<String>,
    #[serde(default)]
    adaptation_required: Vec<String>,
    notes: Option<String>,
}

pub(crate) struct Summary {
    pub(crate) sources: usize,
    pub(crate) workloads: usize,
}

pub(crate) fn validate(root: &Path) -> Result<Summary, String> {
    let base = root.join("tests/guest/linux");
    let source_catalog: SourceCatalog = read_toml(&base.join("SOURCES.toml"))?;
    let source_ids = validate_sources(root, &base, &source_catalog)?;
    let compatibility: CompatibilityCatalog = read_toml(&base.join("COMPATIBILITY.toml"))?;
    validate_compatibility(&base, &compatibility, &source_ids)?;
    Ok(Summary {
        sources: source_ids.len(),
        workloads: compatibility.workload.len(),
    })
}

fn read_toml<T>(path: &Path) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let source =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    toml::from_str(&source).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn validate_sources(
    root: &Path,
    base: &Path,
    catalog: &SourceCatalog,
) -> Result<BTreeSet<String>, String> {
    require(
        catalog.schema_version == 1,
        "SOURCES.toml schema_version must be 1",
    )?;
    require(
        catalog.catalog == "nexus.linux-guest.sources",
        "unexpected SOURCES.toml catalog",
    )?;
    require(
        catalog.legacy_root == "user",
        "SOURCES.toml legacy_root must be user",
    )?;
    require(
        catalog.copy_root == "tests/guest/linux/sources",
        "unexpected SOURCES.toml copy_root",
    )?;
    require(
        catalog.hash_algorithm == "sha256",
        "SOURCES.toml hash_algorithm must be sha256",
    )?;
    require(
        catalog.copy_policy == "exact-source-copy",
        "SOURCES.toml copy_policy must be exact-source-copy",
    )?;
    require_hex(&catalog.source_snapshot, 40, "source_snapshot")?;
    require(
        !catalog.source.is_empty(),
        "SOURCES.toml source array must not be empty",
    )?;

    let allowed_languages = ["assembly", "c"];
    let allowed_profiles = [
        "static-raw",
        "dynamic-exec-raw",
        "shared-interpreter-raw",
        "dynamic-pie-raw",
        "glibc-pie",
    ];
    let mut ids = BTreeSet::new();
    let mut paths = BTreeMap::new();
    for source in &catalog.source {
        validate_id(&source.id, "source")?;
        require(
            ids.insert(source.id.clone()),
            &format!("duplicate source id {:?}", source.id),
        )?;
        require_safe_relative(&source.path, "source.path")?;
        require(
            source.path.starts_with("sources/"),
            &format!("source {} path must begin with sources/", source.id),
        )?;
        require_safe_relative(&source.legacy_path, "source.legacy_path")?;
        require(
            source.legacy_path.starts_with("user/linux-"),
            &format!(
                "source {} legacy_path must begin with user/linux-",
                source.id
            ),
        )?;
        require_hex(&source.sha256, 64, &format!("source {} sha256", source.id))?;
        require(
            allowed_languages.contains(&source.language.as_str()),
            &format!(
                "source {} has unsupported language {:?}",
                source.id, source.language
            ),
        )?;
        require(
            allowed_profiles.contains(&source.build_profile.as_str()),
            &format!(
                "source {} has unsupported build_profile {:?}",
                source.id, source.build_profile
            ),
        )?;
        require(
            !source.role.trim().is_empty(),
            &format!("source {} role is empty", source.id),
        )?;

        let copied = base.join(&source.path);
        let copied_type = fs::symlink_metadata(&copied)
            .map_err(|error| format!("inspect {}: {error}", copied.display()))?
            .file_type();
        require(
            copied_type.is_file() && !copied_type.is_symlink(),
            &format!("copied source must be a regular file: {}", copied.display()),
        )?;
        let digest = digest_file(&copied)?;
        require(
            digest == source.sha256,
            &format!(
                "source {} digest mismatch for {}: expected {}, got {}",
                source.id,
                copied.display(),
                source.sha256,
                digest
            ),
        )?;
        require(
            paths
                .insert(source.path.clone(), source.id.clone())
                .is_none(),
            &format!("duplicate copied source path {:?}", source.path),
        )?;

        // Provenance paths intentionally become optional after the legacy tree
        // is deleted. While they still exist, demand byte-for-byte identity so
        // cleanup cannot silently preserve a stale copy.
        let legacy = root.join(&source.legacy_path);
        if legacy.exists() {
            let legacy_type = fs::symlink_metadata(&legacy)
                .map_err(|error| format!("inspect {}: {error}", legacy.display()))?
                .file_type();
            require(
                legacy_type.is_file() && !legacy_type.is_symlink(),
                &format!(
                    "legacy provenance must be a regular file: {}",
                    legacy.display()
                ),
            )?;
            let legacy_digest = digest_file(&legacy)?;
            require(
                legacy_digest == source.sha256,
                &format!(
                    "legacy provenance mismatch for {}: expected {}, got {}",
                    legacy.display(),
                    source.sha256,
                    legacy_digest
                ),
            )?;
        }
    }

    let copied_root = root.join(&catalog.copy_root);
    let actual = source_files(&copied_root, base)?;
    let declared: BTreeSet<_> = paths.keys().cloned().collect();
    require(
        actual == declared,
        &format!(
            "SOURCES.toml file closure mismatch; undeclared={:?}, missing={:?}",
            actual.difference(&declared).collect::<Vec<_>>(),
            declared.difference(&actual).collect::<Vec<_>>()
        ),
    )?;
    Ok(ids)
}

fn validate_compatibility(
    base: &Path,
    catalog: &CompatibilityCatalog,
    source_ids: &BTreeSet<String>,
) -> Result<(), String> {
    require(
        catalog.schema_version == 1,
        "COMPATIBILITY.toml schema_version must be 1",
    )?;
    require(
        catalog.catalog == "nexus.linux-guest.compatibility",
        "unexpected COMPATIBILITY.toml catalog",
    )?;
    require(
        !catalog.normative,
        "COMPATIBILITY.toml must remain non-normative",
    )?;
    require(
        catalog.target_stage == "linux-personality-pressure-test",
        "unexpected compatibility target_stage",
    )?;
    require(
        !catalog.description.trim().is_empty(),
        "compatibility description is empty",
    )?;
    for (name, value) in [
        ("identity", &catalog.policy.identity),
        ("implementation", &catalog.policy.implementation),
        ("uapi", &catalog.policy.uapi),
        ("success", &catalog.policy.success),
        ("legacy_provenance", &catalog.policy.legacy_provenance),
    ] {
        require(
            !value.trim().is_empty(),
            &format!("compatibility policy {name} is empty"),
        )?;
    }
    for (name, value) in [
        ("core", &catalog.tier_policy.core),
        ("stretch", &catalog.tier_policy.stretch),
        ("archive_input", &catalog.tier_policy.archive_input),
    ] {
        require(
            !value.trim().is_empty(),
            &format!("compatibility tier_policy {name} is empty"),
        )?;
    }
    require(
        !catalog.workload.is_empty(),
        "COMPATIBILITY.toml workload array is empty",
    )?;

    let allowed_status = [
        "retained",
        "retained-superseded",
        "external-artifact-intent",
    ];
    let allowed_tiers = ["core", "stretch", "archive-input"];
    let known_properties = [
        "PostRevokeCommitExclusion",
        "QuiescentClosure",
        "SingleTerminalization",
        "CrashRebindFencing",
        "FallbackProgress",
        "BudgetConservation",
        "WorkProportionality",
    ];
    let mut workload_ids = BTreeSet::new();
    let mut referenced = BTreeSet::new();
    let mut core_profiles = 0;
    for workload in &catalog.workload {
        validate_id(&workload.id, "workload")?;
        require(
            workload_ids.insert(workload.id.clone()),
            &format!("duplicate workload id {:?}", workload.id),
        )?;
        require(
            allowed_status.contains(&workload.status.as_str()),
            &format!(
                "workload {} has unknown status {:?}",
                workload.id, workload.status
            ),
        )?;
        require(
            allowed_tiers.contains(&workload.tier.as_str()),
            &format!(
                "workload {} has unknown tier {:?}",
                workload.id, workload.tier
            ),
        )?;
        require(
            !workload.class.trim().is_empty(),
            &format!("workload {} class is empty", workload.id),
        )?;
        require(
            !workload.required_behaviors.is_empty()
                && workload
                    .required_behaviors
                    .iter()
                    .all(|value| !value.trim().is_empty()),
            &format!(
                "workload {} requires nonempty required_behaviors",
                workload.id
            ),
        )?;
        require(
            workload
                .success_markers
                .iter()
                .all(|value| !value.is_empty()),
            &format!("workload {} contains an empty success marker", workload.id),
        )?;
        require(
            workload
                .adaptation_required
                .iter()
                .all(|value| !value.trim().is_empty()),
            &format!(
                "workload {} contains an empty adaptation requirement",
                workload.id
            ),
        )?;

        if workload.tier == "core" {
            core_profiles += 1;
            for (field, values) in [
                ("cser_effects", &workload.cser_effects),
                ("injection_profile", &workload.injection_profile),
                ("expected_properties", &workload.expected_properties),
            ] {
                require(
                    !values.is_empty() && values.iter().all(|value| !value.trim().is_empty()),
                    &format!("core workload {} needs nonempty {field}", workload.id),
                )?;
            }
            let mut properties = BTreeSet::new();
            for property in &workload.expected_properties {
                require(
                    known_properties.contains(&property.as_str()),
                    &format!(
                        "core workload {} names unknown CSER property {:?}",
                        workload.id, property
                    ),
                )?;
                require(
                    properties.insert(property),
                    &format!(
                        "core workload {} repeats CSER property {:?}",
                        workload.id, property
                    ),
                )?;
            }
        } else {
            require(
                workload.cser_effects.is_empty()
                    && workload.injection_profile.is_empty()
                    && workload.expected_properties.is_empty(),
                &format!(
                    "non-core workload {} must not silently define a default CSER gate",
                    workload.id
                ),
            )?;
        }
        require(
            workload
                .legacy_scenarios
                .iter()
                .all(|value| safe_legacy_reference(value)),
            &format!(
                "workload {} contains an unsafe legacy scenario path",
                workload.id
            ),
        )?;
        require(
            workload
                .external_assets
                .iter()
                .all(|value| !value.trim().is_empty()),
            &format!("workload {} contains an empty external asset", workload.id),
        )?;
        if workload.source_ids.is_empty() {
            require(
                workload.status == "external-artifact-intent",
                &format!(
                    "workload {} has no source_ids but is not external intent",
                    workload.id
                ),
            )?;
            require(
                !workload.external_assets.is_empty(),
                &format!(
                    "external workload {} must declare external_assets",
                    workload.id
                ),
            )?;
        }
        for id in &workload.source_ids {
            require(
                source_ids.contains(id),
                &format!(
                    "workload {} refers to unknown source id {id:?}",
                    workload.id
                ),
            )?;
            require(
                referenced.insert(id.clone())
                    || workload
                        .source_ids
                        .iter()
                        .filter(|value| *value == id)
                        .count()
                        == 1,
                &format!("workload {} repeats source id {id:?}", workload.id),
            )?;
        }
        if let Some(notes) = &workload.notes {
            require(
                !notes.trim().is_empty(),
                &format!("workload {} notes are empty", workload.id),
            )?;
        }
    }
    require(
        &referenced == source_ids,
        &format!(
            "COMPATIBILITY.toml does not cover every source id; missing={:?}",
            source_ids.difference(&referenced).collect::<Vec<_>>()
        ),
    )?;
    require(
        core_profiles > 0 && core_profiles <= 8 && core_profiles < catalog.workload.len(),
        "compatibility catalog core tier must be nonempty and bounded to at most eight workloads",
    )?;
    require(
        base.join("README.md").is_file(),
        "retained Linux guest README.md is missing",
    )?;
    Ok(())
}

fn digest_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn source_files(directory: &Path, base: &Path) -> Result<BTreeSet<String>, String> {
    let mut files = BTreeSet::new();
    collect_files(directory, base, &mut files)?;
    Ok(files)
}

fn collect_files(
    directory: &Path,
    base: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("read source directory {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("read source directory entry: {error}"))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|error| format!("inspect {}: {error}", path.display()))?;
        if kind.is_symlink() {
            return Err(format!(
                "symlinks are forbidden in retained sources: {}",
                path.display()
            ));
        }
        if kind.is_dir() {
            collect_files(&path, base, files)?;
        } else if kind.is_file() {
            let relative = path
                .strip_prefix(base)
                .map_err(|error| format!("relativize {}: {error}", path.display()))?;
            files.insert(relative.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

fn require_safe_relative(value: &str, field: &str) -> Result<(), String> {
    let path = Path::new(value);
    require(
        !value.is_empty() && !path.is_absolute(),
        &format!("{field} must be relative"),
    )?;
    require(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        &format!("{field} contains an unsafe path component: {value:?}"),
    )
}

fn safe_legacy_reference(value: &str) -> bool {
    !value.is_empty()
        && value.starts_with("specs/conformance/scenarios/")
        && require_safe_relative(value, "legacy scenario").is_ok()
}

fn validate_id(id: &str, kind: &str) -> Result<(), String> {
    require(
        !id.is_empty()
            && !id.starts_with('.')
            && id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            }),
        &format!("invalid {kind} id {id:?}"),
    )
}

fn require_hex(value: &str, length: usize, field: &str) -> Result<(), String> {
    require(
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        &format!("{field} must be {length} lowercase hexadecimal characters"),
    )
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_components() {
        assert!(require_safe_relative("sources/../secret", "path").is_err());
        assert!(require_safe_relative("sources/good/file.S", "path").is_ok());
    }

    #[test]
    fn validates_hex_shape() {
        assert!(require_hex(&"a".repeat(64), 64, "digest").is_ok());
        assert!(require_hex(&"A".repeat(64), 64, "digest").is_err());
    }
}
