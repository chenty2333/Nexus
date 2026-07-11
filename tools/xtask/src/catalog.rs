use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use toml::Value;
use toml::map::Map;

pub(crate) fn validate_all(root: &Path) -> Result<usize, String> {
    let directory = root.join("specs/oracles");
    let paths = toml_files(&directory)?;
    if paths.is_empty() {
        return Err(format!(
            "no oracle catalogs found in {}",
            directory.display()
        ));
    }

    let mut ids = BTreeSet::new();
    let mut entries = 0;
    for path in paths {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        let value: Value = toml::from_str(&source)
            .map_err(|error| format!("parse {}: {error}", path.display()))?;
        entries += validate_catalog(&path, &value, &mut ids)?;
    }
    Ok(entries)
}

fn toml_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    let read_dir = fs::read_dir(directory)
        .map_err(|error| format!("read oracle directory {}: {error}", directory.display()))?;
    for entry in read_dir {
        let entry = entry.map_err(|error| format!("read oracle directory entry: {error}"))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("toml") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn validate_catalog(
    path: &Path,
    value: &Value,
    global_ids: &mut BTreeSet<String>,
) -> Result<usize, String> {
    let table = value
        .as_table()
        .ok_or_else(|| field_error(path, "root", "must be a table"))?;
    require_exact_integer(path, table, "schema_version", 1)?;
    require_string(path, table, "description")?;
    require_bool(path, table, "normative")?;
    validate_interpretation(path, table)?;

    let catalog = require_string(path, table, "catalog")?;
    let (entry_key, entry_fields, required_arrays): (&str, &[&str], &[&str]) =
        match catalog.as_str() {
            "nexus.cser.races" => (
                "race",
                &[
                    "id",
                    "title",
                    "phases",
                    "origin",
                    "source_refs",
                    "setup",
                    "schedule",
                    "require",
                    "forbid",
                ],
                &[
                    "phases",
                    "source_refs",
                    "setup",
                    "schedule",
                    "require",
                    "forbid",
                ],
            ),
            "nexus.legacy.slices" => (
                "slice",
                &[
                    "id",
                    "title",
                    "future_phase",
                    "origin_paths",
                    "legacy_scope",
                    "actions",
                    "retained_observations",
                    "discarded_assumptions",
                    "future_gate",
                ],
                &[
                    "origin_paths",
                    "actions",
                    "retained_observations",
                    "discarded_assumptions",
                ],
            ),
            other => {
                return Err(field_error(
                    path,
                    "catalog",
                    &format!("unsupported catalog {other:?}"),
                ));
            }
        };

    ensure_keys(
        path,
        table,
        &[
            "schema_version",
            "catalog",
            "normative",
            "description",
            "interpretation",
            entry_key,
        ],
        "root",
    )?;

    let values = table
        .get(entry_key)
        .and_then(Value::as_array)
        .ok_or_else(|| field_error(path, entry_key, "must be an array of tables"))?;
    if values.is_empty() {
        return Err(field_error(path, entry_key, "must not be empty"));
    }

    for (index, value) in values.iter().enumerate() {
        let location = format!("{entry_key}[{index}]");
        let entry = value
            .as_table()
            .ok_or_else(|| field_error(path, &location, "must be a table"))?;
        ensure_keys(path, entry, entry_fields, &location)?;

        let id = require_entry_string(path, entry, &location, "id")?;
        validate_id(path, &location, &id)?;
        if !global_ids.insert(id.clone()) {
            return Err(field_error(
                path,
                &format!("{location}.id"),
                &format!("duplicate oracle id {id:?}"),
            ));
        }

        for field in entry_fields {
            if *field == "id" || required_arrays.contains(field) {
                continue;
            }
            require_entry_string(path, entry, &location, field)?;
        }
        for field in required_arrays {
            require_entry_string_array(path, entry, &location, field)?;
        }
    }
    Ok(values.len())
}

fn validate_interpretation(path: &Path, table: &Map<String, Value>) -> Result<(), String> {
    let interpretation = table
        .get("interpretation")
        .and_then(Value::as_table)
        .ok_or_else(|| field_error(path, "interpretation", "must be a table"))?;
    if interpretation.is_empty() {
        return Err(field_error(path, "interpretation", "must not be empty"));
    }
    for (key, value) in interpretation {
        let text = value.as_str().ok_or_else(|| {
            field_error(path, &format!("interpretation.{key}"), "must be a string")
        })?;
        if text.trim().is_empty() {
            return Err(field_error(
                path,
                &format!("interpretation.{key}"),
                "must not be empty",
            ));
        }
    }
    Ok(())
}

fn ensure_keys(
    path: &Path,
    table: &Map<String, Value>,
    allowed: &[&str],
    location: &str,
) -> Result<(), String> {
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(field_error(
                path,
                &format!("{location}.{key}"),
                "unknown field",
            ));
        }
    }
    for key in allowed {
        if !table.contains_key(*key) {
            return Err(field_error(
                path,
                &format!("{location}.{key}"),
                "missing field",
            ));
        }
    }
    Ok(())
}

fn require_exact_integer(
    path: &Path,
    table: &Map<String, Value>,
    key: &str,
    expected: i64,
) -> Result<(), String> {
    let actual = table
        .get(key)
        .and_then(Value::as_integer)
        .ok_or_else(|| field_error(path, key, "must be an integer"))?;
    if actual != expected {
        return Err(field_error(
            path,
            key,
            &format!("must be {expected}, got {actual}"),
        ));
    }
    Ok(())
}

fn require_bool(path: &Path, table: &Map<String, Value>, key: &str) -> Result<bool, String> {
    table
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| field_error(path, key, "must be a boolean"))
}

fn require_string(path: &Path, table: &Map<String, Value>, key: &str) -> Result<String, String> {
    let value = table
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| field_error(path, key, "must be a string"))?;
    if value.trim().is_empty() {
        return Err(field_error(path, key, "must not be empty"));
    }
    Ok(value.to_owned())
}

fn require_entry_string(
    path: &Path,
    table: &Map<String, Value>,
    location: &str,
    key: &str,
) -> Result<String, String> {
    let field = format!("{location}.{key}");
    let value = table
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| field_error(path, &field, "must be a string"))?;
    if value.trim().is_empty() {
        return Err(field_error(path, &field, "must not be empty"));
    }
    Ok(value.to_owned())
}

fn require_entry_string_array(
    path: &Path,
    table: &Map<String, Value>,
    location: &str,
    key: &str,
) -> Result<(), String> {
    let field = format!("{location}.{key}");
    let values = table
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| field_error(path, &field, "must be an array of strings"))?;
    if values.is_empty() {
        return Err(field_error(path, &field, "must not be empty"));
    }
    for (index, value) in values.iter().enumerate() {
        let text = value
            .as_str()
            .ok_or_else(|| field_error(path, &format!("{field}[{index}]"), "must be a string"))?;
        if text.trim().is_empty() {
            return Err(field_error(
                path,
                &format!("{field}[{index}]"),
                "must not be empty",
            ));
        }
    }
    Ok(())
}

fn validate_id(path: &Path, location: &str, id: &str) -> Result<(), String> {
    if id.starts_with('.')
        || !id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(field_error(
            path,
            &format!("{location}.id"),
            "must contain only lowercase ASCII letters, digits, '.', '_' or '-' and not start with '.'",
        ));
    }
    Ok(())
}

fn field_error(path: &Path, field: &str, message: &str) -> String {
    format!("{}: {field}: {message}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_unknown_catalog_field() {
        let value: Value = toml::from_str(
            r#"
schema_version = 1
catalog = "nexus.cser.races"
normative = false
description = "test"
surprise = true
[interpretation]
purpose = "test"
[[race]]
id = "race.test"
title = "test"
phases = ["pager"]
origin = "test"
source_refs = ["source"]
setup = ["setup"]
schedule = ["schedule"]
require = ["require"]
forbid = ["forbid"]
"#,
        )
        .expect("valid TOML");
        let error = validate_catalog(Path::new("test.toml"), &value, &mut BTreeSet::new())
            .expect_err("unknown field must fail");
        assert!(error.contains("surprise"));
    }
}
