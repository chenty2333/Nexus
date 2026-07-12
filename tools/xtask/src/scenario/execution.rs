use super::capture::{Captured, FailureKind, ScenarioFailure, execute};
use super::schema::{FAILURE_METADATA, Retain, Scenario};
use serde::Serialize;
use std::fs;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::ExitStatus;

#[derive(Serialize)]
struct FailureMetadata<'a> {
    schema_version: u32,
    scenario_id: &'a str,
    kind: &'a str,
    message: &'a str,
    timed_out: bool,
    output_overflow: bool,
    max_output_bytes: u64,
    captured_output_bytes: usize,
    observed_output_bytes: u64,
    exit_code: Option<i32>,
    signal: Option<i32>,
}
pub(super) fn run_one(
    root: &Path,
    artifact_root: &Path,
    scenario: &Scenario,
) -> Result<(), String> {
    let captured = execute(root, scenario)?;
    let failure = match captured.failure.clone() {
        Some(failure) => Some(failure),
        None => evaluate(scenario, &captured)
            .err()
            .map(|message| ScenarioFailure::new(FailureKind::Evaluate, message)),
    };
    retain_artifact(artifact_root, scenario, &captured, failure.as_ref())?;
    match failure {
        Some(failure) => Err(failure.message),
        None => Ok(()),
    }
}

pub(super) fn evaluate(scenario: &Scenario, captured: &Captured) -> Result<(), String> {
    if captured.timed_out {
        return Err(format!(
            "scenario {} exceeded {} ms",
            scenario.id, scenario.timeout_ms
        ));
    }
    if captured.output_overflow {
        return Err(format!(
            "scenario {} exceeded max_output_bytes={}",
            scenario.id, scenario.max_output_bytes
        ));
    }
    let exit_code = captured.status.as_ref().and_then(ExitStatus::code);
    if exit_code != Some(scenario.expected_exit) {
        return Err(format!(
            "scenario {} exited {:?}; expected {}",
            scenario.id, exit_code, scenario.expected_exit
        ));
    }

    for expected in &scenario.serial.expect {
        if !captured.serial.contains(expected) {
            return Err(format!(
                "scenario {} missing expected text {expected:?}",
                scenario.id
            ));
        }
    }

    let mut remainder = captured.serial.as_str();
    for expected in &scenario.serial.ordered {
        let offset = remainder.find(expected).ok_or_else(|| {
            format!(
                "scenario {} missing ordered text {expected:?} after the previous match",
                scenario.id
            )
        })?;
        remainder = &remainder[offset + expected.len()..];
    }

    for forbidden in &scenario.serial.forbid {
        if captured.serial.contains(forbidden) {
            return Err(format!(
                "scenario {} contains forbidden text {forbidden:?}",
                scenario.id
            ));
        }
    }

    for oracle in &scenario.numeric {
        let values = numeric_values(&captured.serial, &oracle.key);
        if values.is_empty() {
            return Err(format!(
                "scenario {} has no numeric value for {:?}",
                scenario.id, oracle.key
            ));
        }
        for value in values {
            if let Some(exact) = oracle.exact
                && value != exact
            {
                return Err(format!(
                    "scenario {}: {}={} does not equal {}",
                    scenario.id, oracle.key, value, exact
                ));
            }
            if let Some(min) = oracle.min
                && value < min
            {
                return Err(format!(
                    "scenario {}: {}={} is below {}",
                    scenario.id, oracle.key, value, min
                ));
            }
            if let Some(max) = oracle.max
                && value > max
            {
                return Err(format!(
                    "scenario {}: {}={} exceeds {}",
                    scenario.id, oracle.key, value, max
                ));
            }
        }
    }
    Ok(())
}

fn numeric_values(text: &str, key: &str) -> Vec<i64> {
    let mut values = Vec::new();
    for (offset, _) in text.match_indices(key) {
        let before = text[..offset].chars().next_back();
        if before.is_some_and(|value| value.is_ascii_alphanumeric() || value == '_') {
            continue;
        }
        let after_key = &text[offset + key.len()..];
        let Some(rest) = after_key
            .strip_prefix('=')
            .or_else(|| after_key.strip_prefix(':'))
        else {
            continue;
        };
        let rest = rest.trim_start();
        let length = rest
            .char_indices()
            .take_while(|(index, value)| value.is_ascii_digit() || (*index == 0 && *value == '-'))
            .map(|(index, value)| index + value.len_utf8())
            .last()
            .unwrap_or(0);
        if length == 0 {
            continue;
        }
        if let Ok(value) = rest[..length].parse() {
            values.push(value);
        }
    }
    values
}

fn retain_artifact(
    artifact_root: &Path,
    scenario: &Scenario,
    captured: &Captured,
    failure: Option<&ScenarioFailure>,
) -> Result<(), String> {
    let directory = artifact_root.join(&scenario.id);
    let retain = scenario.artifacts.retain == Retain::Always
        || (scenario.artifacts.retain == Retain::OnFailure && failure.is_some());
    if !retain {
        if directory.exists() {
            fs::remove_dir_all(&directory)
                .map_err(|error| format!("remove {}: {error}", directory.display()))?;
        }
        return Ok(());
    }
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create {}: {error}", directory.display()))?;
    let path = directory.join(&scenario.artifacts.serial);
    fs::write(&path, &captured.serial)
        .map_err(|error| format!("write {}: {error}", path.display()))?;

    let metadata_path = directory.join(FAILURE_METADATA);
    if let Some(failure) = failure {
        let metadata = FailureMetadata {
            schema_version: 1,
            scenario_id: &scenario.id,
            kind: failure.kind.as_str(),
            message: &failure.message,
            timed_out: captured.timed_out,
            output_overflow: captured.output_overflow,
            max_output_bytes: scenario.max_output_bytes,
            captured_output_bytes: captured.serial.len(),
            observed_output_bytes: captured.observed_output_bytes,
            exit_code: captured.status.as_ref().and_then(ExitStatus::code),
            signal: captured.status.as_ref().and_then(|status| status.signal()),
        };
        let source = toml::to_string_pretty(&metadata)
            .map_err(|error| format!("encode {}: {error}", metadata_path.display()))?;
        fs::write(&metadata_path, source)
            .map_err(|error| format!("write {}: {error}", metadata_path.display()))?;
        eprintln!("retained scenario artifact: {}", metadata_path.display());
    } else if metadata_path.exists() {
        fs::remove_file(&metadata_path)
            .map_err(|error| format!("remove {}: {error}", metadata_path.display()))?;
    }
    eprintln!("retained scenario artifact: {}", path.display());
    Ok(())
}
