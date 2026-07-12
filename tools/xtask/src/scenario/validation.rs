use super::schema::{FAILURE_METADATA, MAX_OUTPUT_BYTES, MIN_OUTPUT_BYTES, Scenario, ScenarioFile};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub(super) fn load_all(root: &Path) -> Result<Vec<Scenario>, String> {
    let directory = root.join("tests/scenarios");
    let mut paths = toml_files(&directory)?;
    if paths.is_empty() {
        return Err(format!(
            "no runner scenarios found in {}",
            directory.display()
        ));
    }
    paths.sort();

    let mut all = Vec::new();
    let mut ids = BTreeSet::new();
    for path in paths {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        let file: ScenarioFile = toml::from_str(&source)
            .map_err(|error| format!("parse {}: {error}", path.display()))?;
        if file.schema_version != 1 {
            return Err(format!(
                "{}: schema_version must be 1, got {}",
                path.display(),
                file.schema_version
            ));
        }
        if file.scenario.is_empty() {
            return Err(format!(
                "{}: scenario array must not be empty",
                path.display()
            ));
        }
        for scenario in file.scenario {
            validate_scenario(&path, &scenario)?;
            if !ids.insert(scenario.id.clone()) {
                return Err(format!(
                    "{}: duplicate scenario id {:?}",
                    path.display(),
                    scenario.id
                ));
            }
            all.push(scenario);
        }
    }
    Ok(all)
}

fn toml_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    let read_dir = fs::read_dir(directory)
        .map_err(|error| format!("read scenario directory {}: {error}", directory.display()))?;
    for entry in read_dir {
        let entry = entry.map_err(|error| format!("read scenario directory entry: {error}"))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("toml") {
            paths.push(path);
        }
    }
    Ok(paths)
}

pub(super) fn validate_scenario(path: &Path, scenario: &Scenario) -> Result<(), String> {
    validate_id(path, &scenario.id)?;
    if scenario.command.is_empty() || scenario.command[0].trim().is_empty() {
        return Err(format!(
            "{}: {}: command must not be empty",
            path.display(),
            scenario.id
        ));
    }
    if scenario.timeout_ms == 0 || scenario.timeout_ms > 600_000 {
        return Err(format!(
            "{}: {}: timeout_ms must be in 1..=600000",
            path.display(),
            scenario.id
        ));
    }
    if !(MIN_OUTPUT_BYTES..=MAX_OUTPUT_BYTES).contains(&scenario.max_output_bytes) {
        return Err(format!(
            "{}: {}: max_output_bytes must be in {}..={}",
            path.display(),
            scenario.id,
            MIN_OUTPUT_BYTES,
            MAX_OUTPUT_BYTES
        ));
    }
    for (kind, values) in [
        ("expect", &scenario.serial.expect),
        ("ordered", &scenario.serial.ordered),
        ("forbid", &scenario.serial.forbid),
    ] {
        if values.iter().any(|value| value.is_empty()) {
            return Err(format!(
                "{}: {}: serial.{kind} entries must not be empty",
                path.display(),
                scenario.id
            ));
        }
    }

    let mut numeric_keys = BTreeSet::new();
    for numeric in &scenario.numeric {
        if numeric.key.is_empty() || !numeric_keys.insert(numeric.key.clone()) {
            return Err(format!(
                "{}: {}: numeric keys must be nonempty and unique",
                path.display(),
                scenario.id
            ));
        }
        if numeric.exact.is_some() && (numeric.min.is_some() || numeric.max.is_some()) {
            return Err(format!(
                "{}: {}: numeric {} cannot combine exact with min/max",
                path.display(),
                scenario.id,
                numeric.key
            ));
        }
        if numeric.exact.is_none() && numeric.min.is_none() && numeric.max.is_none() {
            return Err(format!(
                "{}: {}: numeric {} needs exact, min, or max",
                path.display(),
                scenario.id,
                numeric.key
            ));
        }
        if let (Some(min), Some(max)) = (numeric.min, numeric.max)
            && min > max
        {
            return Err(format!(
                "{}: {}: numeric {} has min greater than max",
                path.display(),
                scenario.id,
                numeric.key
            ));
        }
    }

    let serial_path = Path::new(&scenario.artifacts.serial);
    if scenario.artifacts.serial.is_empty()
        || serial_path.components().count() != 1
        || !matches!(serial_path.components().next(), Some(Component::Normal(_)))
        || scenario.artifacts.serial == FAILURE_METADATA
    {
        return Err(format!(
            "{}: {}: artifacts.serial must be one relative filename other than {FAILURE_METADATA}",
            path.display(),
            scenario.id
        ));
    }
    Ok(())
}

fn validate_id(path: &Path, id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.starts_with('.')
        || !id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(format!(
            "{}: invalid scenario id {id:?}; use lowercase ASCII, digits, '.', '_' or '-'",
            path.display()
        ));
    }
    Ok(())
}
