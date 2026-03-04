use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::contracts::{build_coverage_report, load_contract_catalog};
use crate::elf::inspect_elf;
use crate::gc::prune_runs;
use crate::model::{load_profile, load_scenarios};
use crate::report::{CaseReport, CaseStatus, Manifest, RunSummary};
use crate::selection::select_scenarios;
use crate::test_id::new_test_id;

/// Conformance execution configuration.
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub profile: Option<String>,
    pub scenario_filters: Vec<String>,
    pub tag_filters: Vec<String>,
    pub keep_runs: usize,
    pub verbose: bool,
    pub out_dir: PathBuf,
    pub scenarios_dir: PathBuf,
    pub profiles_dir: PathBuf,
    pub contracts_file: PathBuf,
    pub workspace_root: PathBuf,
    pub jobs: usize,
    pub retries: u32,
}

impl RunConfig {
    /// Build default paths from workspace layout.
    pub fn with_workspace_defaults() -> Self {
        let workspace_root = workspace_root_from_manifest_dir();
        let specs_root = workspace_root.join("specs").join("conformance");
        Self {
            profile: Some("pr".to_string()),
            scenario_filters: Vec::new(),
            tag_filters: Vec::new(),
            keep_runs: 100,
            verbose: false,
            out_dir: workspace_root.join("target").join("axle-conformance"),
            scenarios_dir: specs_root.join("scenarios"),
            profiles_dir: specs_root.join("profiles"),
            contracts_file: specs_root.join("contracts.toml"),
            workspace_root,
            jobs: 1,
            retries: 0,
        }
    }
}

/// Run selected conformance scenarios and write structured reports.
pub fn run_conformance(config: &RunConfig) -> Result<RunSummary> {
    fs::create_dir_all(&config.out_dir)
        .with_context(|| format!("create output dir {}", config.out_dir.display()))?;

    let scenarios = load_scenarios(&config.scenarios_dir)?;
    let contracts_catalog = load_contract_catalog(&config.contracts_file)?;
    let coverage = build_coverage_report(&contracts_catalog, &scenarios);
    if !coverage.unknown_contract_refs.is_empty() {
        let (scenario_id, contract_id) = &coverage.unknown_contract_refs[0];
        bail!(
            "unknown contract reference: scenario='{}' contract='{}'",
            scenario_id,
            contract_id
        );
    }
    let profile_spec = if let Some(profile_name) = &config.profile {
        Some(load_profile(&config.profiles_dir, profile_name)?)
    } else {
        None
    };

    let selected = select_scenarios(
        &scenarios,
        profile_spec.as_ref(),
        &config.scenario_filters,
        &config.tag_filters,
    )?;

    if selected.is_empty() {
        bail!("selection produced zero scenarios");
    }

    let keep_before_create = config.keep_runs.saturating_sub(1);
    let _ = prune_runs(&config.out_dir, keep_before_create)?;

    let test_id = new_test_id();
    let run_dir = config.out_dir.join(&test_id);
    let cases_dir = run_dir.join("cases");
    fs::create_dir_all(&cases_dir)
        .with_context(|| format!("create cases dir {}", cases_dir.display()))?;

    println!(
        "axle-conformance test-id={} profile={} total={}",
        test_id,
        config.profile.as_deref().unwrap_or("none"),
        selected.len()
    );

    let manifest = Manifest {
        test_id: test_id.clone(),
        profile: config.profile.clone(),
        selected_scenarios: selected.iter().map(|s| s.id.clone()).collect(),
        scenario_filters: config.scenario_filters.clone(),
        tag_filters: config.tag_filters.clone(),
        started_unix_ms: now_unix_ms(),
    };

    write_json(&run_dir.join("manifest.json"), &manifest)?;

    let run_start = Instant::now();
    let mut planned = Vec::with_capacity(selected.len());
    for scenario in &selected {
        let case_dir_name = sanitize_case_dir_name(&scenario.id);
        let case_dir = cases_dir.join(&case_dir_name);
        fs::create_dir_all(&case_dir)
            .with_context(|| format!("create case dir {}", case_dir.display()))?;
        write_json(&case_dir.join("scenario.json"), scenario)?;
        fs::write(
            case_dir.join("command.txt"),
            render_command(&scenario.command),
        )
        .with_context(|| format!("write command file for scenario '{}'", scenario.id))?;
        planned.push((scenario.clone(), case_dir));
    }

    let mut case_reports = execute_cases(
        &planned,
        &config.workspace_root,
        config.jobs,
        config.retries,
    )?;
    case_reports.sort_by(|a, b| a.scenario_id.cmp(&b.scenario_id));

    for report in &case_reports {
        if config.verbose || report.status == CaseStatus::Fail {
            if report.status == CaseStatus::Fail {
                let reason = report
                    .reason
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                println!("[FAIL] {} reason={}", report.scenario_id, reason);
            } else if config.verbose {
                let suffix = if report.attempts > 1 {
                    format!(" attempts={}", report.attempts)
                } else {
                    String::new()
                };
                println!(
                    "[PASS] {} {}ms{}",
                    report.scenario_id, report.duration_ms, suffix
                );
            }
        }
    }

    let duration_ms = run_start.elapsed().as_millis();
    let pass = case_reports
        .iter()
        .filter(|r| r.status == CaseStatus::Pass)
        .count();
    let fail = case_reports.len().saturating_sub(pass);
    let flaky_pass = case_reports
        .iter()
        .filter(|r| r.status == CaseStatus::Pass && r.attempts > 1)
        .count();

    let summary = RunSummary {
        test_id: test_id.clone(),
        total: case_reports.len(),
        pass,
        fail,
        flaky_pass,
        duration_ms,
        report_path: run_dir.join("summary.json").display().to_string(),
        cases: case_reports,
    };

    write_json(&run_dir.join("summary.json"), &summary)?;

    println!(
        "summary: pass={} fail={} flaky_pass={} duration={}ms report={}",
        summary.pass, summary.fail, summary.flaky_pass, summary.duration_ms, summary.report_path
    );

    Ok(summary)
}

fn execute_cases(
    planned: &[(crate::model::ScenarioSpec, PathBuf)],
    workspace_root: &Path,
    jobs: usize,
    retries: u32,
) -> Result<Vec<CaseReport>> {
    if planned.is_empty() {
        return Ok(Vec::new());
    }

    let jobs = jobs.max(1).min(planned.len());
    if jobs == 1 {
        let mut out = Vec::with_capacity(planned.len());
        for (scenario, case_dir) in planned {
            let report = run_case_with_retries(scenario, case_dir, workspace_root, retries)?;
            write_json(&case_dir.join("result.json"), &report)?;
            out.push(report);
        }
        return Ok(out);
    }

    let tasks: Vec<_> = planned
        .iter()
        .enumerate()
        .map(|(idx, (scenario, case_dir))| (idx, scenario.clone(), case_dir.clone()))
        .collect();
    let task_rx = Arc::new(Mutex::new(tasks.into_iter()));
    let (result_tx, result_rx) = mpsc::channel();
    let workspace_root = Arc::new(workspace_root.to_path_buf());

    let mut workers = Vec::with_capacity(jobs);
    for _ in 0..jobs {
        let task_rx = Arc::clone(&task_rx);
        let result_tx = result_tx.clone();
        let workspace_root = Arc::clone(&workspace_root);

        workers.push(thread::spawn(move || {
            loop {
                let next = {
                    let mut guard = task_rx.lock().expect("task mutex poisoned");
                    guard.next()
                };
                let Some((idx, scenario, case_dir)) = next else {
                    break;
                };

                let result = run_case_with_retries(&scenario, &case_dir, &workspace_root, retries);
                let _ = result_tx.send((idx, case_dir, result));
            }
        }));
    }
    drop(result_tx);

    let mut ordered: Vec<Option<CaseReport>> = vec![None; planned.len()];
    for _ in 0..planned.len() {
        let (idx, case_dir, result) = result_rx
            .recv()
            .context("receive case result from worker thread")?;
        let report = result?;
        write_json(&case_dir.join("result.json"), &report)?;
        ordered[idx] = Some(report);
    }

    for worker in workers {
        let _ = worker.join();
    }

    let mut out = Vec::with_capacity(planned.len());
    for entry in ordered {
        match entry {
            Some(report) => out.push(report),
            None => bail!("missing case report from worker"),
        }
    }
    Ok(out)
}

fn run_case_with_retries(
    scenario: &crate::model::ScenarioSpec,
    case_dir: &Path,
    workspace_root: &Path,
    retries: u32,
) -> Result<CaseReport> {
    let max_attempts = retries.saturating_add(1);
    let mut last = None;

    for attempt in 1..=max_attempts {
        let attempt_dir = if max_attempts > 1 {
            case_dir.join(format!("attempt-{attempt}"))
        } else {
            case_dir.to_path_buf()
        };
        fs::create_dir_all(&attempt_dir)
            .with_context(|| format!("create attempt dir {}", attempt_dir.display()))?;

        let mut report = run_case(scenario, &attempt_dir, workspace_root)?;
        report.attempts = attempt;
        last = Some(report.clone());

        if report.status == CaseStatus::Pass {
            return Ok(report);
        }
    }

    last.context("missing report after retries")
}

fn run_case(
    scenario: &crate::model::ScenarioSpec,
    case_dir: &Path,
    workspace_root: &Path,
) -> Result<CaseReport> {
    let stdout_path = case_dir.join("stdout.log");
    let stderr_path = case_dir.join("stderr.log");

    let stdout_file = File::create(&stdout_path)
        .with_context(|| format!("create stdout log {}", stdout_path.display()))?;
    let stderr_file = File::create(&stderr_path)
        .with_context(|| format!("create stderr log {}", stderr_path.display()))?;

    let mut command = Command::new(&scenario.command[0]);
    command
        .args(&scenario.command[1..])
        .current_dir(workspace_root)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    let start = Instant::now();

    let mut child = command
        .spawn()
        .with_context(|| format!("spawn scenario '{}'", scenario.id))?;

    let timeout = Duration::from_millis(scenario.timeout_ms);
    let mut exit_code = None;
    let mut timed_out = false;

    loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("wait scenario '{}'", scenario.id))?
        {
            exit_code = status.code();
            break;
        }

        if start.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            let _ = child.wait();
            break;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    let stdout_text = fs::read_to_string(&stdout_path).unwrap_or_default();
    let stderr_text = fs::read_to_string(&stderr_path).unwrap_or_default();
    let combined = format!("{stdout_text}\n{stderr_text}");

    let missing_expect: Vec<String> = scenario
        .expect
        .iter()
        .filter(|needle| !combined.contains(needle.as_str()))
        .cloned()
        .collect();

    let matched_forbid: Vec<String> = scenario
        .forbid
        .iter()
        .filter(|needle| combined.contains(needle.as_str()))
        .cloned()
        .collect();
    let parsed_metrics = parse_kv_metrics(&combined);
    let assertion_mismatches = evaluate_assertions(scenario, &parsed_metrics);

    let mut reason = None;

    if timed_out {
        reason = Some("timeout".to_string());
    } else if exit_code.unwrap_or(1) != 0 {
        reason = Some(format!("non_zero_exit({})", exit_code.unwrap_or(-1)));
    } else if !missing_expect.is_empty() {
        reason = Some(format!("missing_expect({})", missing_expect.join(",")));
    } else if !matched_forbid.is_empty() {
        reason = Some(format!("matched_forbid({})", matched_forbid.join(",")));
    } else if !assertion_mismatches.is_empty() {
        reason = Some(format!(
            "assertion_mismatch({})",
            assertion_mismatches.join(";")
        ));
    }

    let mut elf_check = None;
    if let Some(elf_spec) = &scenario.elf_check {
        let elf_path = workspace_root.join(&elf_spec.path);
        match inspect_elf(&elf_path) {
            Ok(report) => {
                if reason.is_none()
                    && elf_spec.require_xen_pvh_note
                    && report.xen_pvh_entry.is_none()
                {
                    reason = Some("missing_xen_pvh_note".to_string());
                }
                elf_check = Some(report);
            }
            Err(err) => {
                if reason.is_none() {
                    reason = Some(format!("elf_check_error({err})"));
                }
            }
        }
    }

    let status = if reason.is_some() {
        CaseStatus::Fail
    } else {
        CaseStatus::Pass
    };

    Ok(CaseReport {
        scenario_id: scenario.id.clone(),
        status,
        attempts: 1,
        duration_ms: start.elapsed().as_millis(),
        exit_code,
        timed_out,
        reason,
        missing_expect,
        matched_forbid,
        parsed_metrics,
        assertion_mismatches,
        elf_check,
        case_dir: case_dir.display().to_string(),
    })
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let raw = serde_json::to_vec_pretty(value).context("serialize json")?;
    fs::write(path, raw).with_context(|| format!("write {}", path.display()))
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn sanitize_case_dir_name(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn render_command(command: &[String]) -> String {
    let mut out = String::new();
    for (idx, part) in command.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        if part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | ':'))
        {
            out.push_str(part);
        } else {
            out.push('"');
            for c in part.chars() {
                if c == '"' || c == '\\' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
        }
    }
    out
}

fn parse_kv_metrics(text: &str) -> BTreeMap<String, i64> {
    let mut out = BTreeMap::new();
    for token in text
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | '(' | ')' | '[' | ']'))
        .filter(|s| !s.is_empty())
    {
        let Some((k, v)) = token.split_once('=') else {
            continue;
        };
        if k.is_empty() || v.is_empty() {
            continue;
        }
        if let Some(parsed) = parse_i64(v) {
            out.insert(k.to_string(), parsed);
        }
    }
    out
}

fn parse_i64(raw: &str) -> Option<i64> {
    if let Some(rest) = raw.strip_prefix("-0x") {
        let n = i64::from_str_radix(rest, 16).ok()?;
        return Some(-n);
    }
    if let Some(rest) = raw.strip_prefix("0x") {
        return i64::from_str_radix(rest, 16).ok();
    }
    raw.parse::<i64>().ok()
}

fn evaluate_assertions(
    scenario: &crate::model::ScenarioSpec,
    parsed_metrics: &BTreeMap<String, i64>,
) -> Vec<String> {
    let Some(assertions) = &scenario.assertions else {
        return Vec::new();
    };

    let mut mismatches = Vec::new();
    check_assertion_group(
        "status_code",
        &assertions.status_code,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group(
        "error_code",
        &assertions.error_code,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group(
        "signal_mask",
        &assertions.signal_mask,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group(
        "packet_fields",
        &assertions.packet_fields,
        parsed_metrics,
        &mut mismatches,
    );

    mismatches
}

fn check_assertion_group(
    group: &str,
    expected: &BTreeMap<String, i64>,
    parsed_metrics: &BTreeMap<String, i64>,
    mismatches: &mut Vec<String>,
) {
    for (k, expected_v) in expected {
        match parsed_metrics.get(k) {
            Some(actual_v) if actual_v == expected_v => {}
            Some(actual_v) => mismatches.push(format!(
                "{}.{} expected={} actual={}",
                group, k, expected_v, actual_v
            )),
            None => mismatches.push(format!("{}.{} missing", group, k)),
        }
    }
}

fn workspace_root_from_manifest_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root ancestor")
        .to_path_buf()
}

/// Run exactly one scenario from a previous run snapshot.
pub fn replay_from_snapshot(
    config: &RunConfig,
    run_id: &str,
    scenario_id: &str,
) -> Result<RunSummary> {
    let scenario_path = config
        .out_dir
        .join(run_id)
        .join("cases")
        .join(sanitize_case_dir_name(scenario_id))
        .join("scenario.json");

    let raw = fs::read_to_string(&scenario_path)
        .with_context(|| format!("read snapshot scenario {}", scenario_path.display()))?;
    let scenario: crate::model::ScenarioSpec =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", scenario_path.display()))?;
    scenario.validate()?;

    let replay_id = new_test_id();
    let run_dir = config.out_dir.join(&replay_id);
    let cases_dir = run_dir.join("cases");
    fs::create_dir_all(&cases_dir)
        .with_context(|| format!("create replay case dir {}", cases_dir.display()))?;

    println!(
        "axle-conformance test-id={} replay-from={} scenario={}",
        replay_id, run_id, scenario_id
    );

    let case_dir = cases_dir.join(sanitize_case_dir_name(&scenario.id));
    fs::create_dir_all(&case_dir)
        .with_context(|| format!("create replay scenario dir {}", case_dir.display()))?;
    write_json(&case_dir.join("scenario.json"), &scenario)?;
    fs::write(
        case_dir.join("command.txt"),
        render_command(&scenario.command),
    )
    .with_context(|| format!("write replay command for scenario '{}'", scenario.id))?;

    let started_unix_ms = now_unix_ms();
    let report =
        run_case_with_retries(&scenario, &case_dir, &config.workspace_root, config.retries)?;
    write_json(&case_dir.join("result.json"), &report)?;

    if report.status == CaseStatus::Fail {
        let reason = report
            .reason
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        println!("[FAIL] {} reason={}", report.scenario_id, reason);
    } else if config.verbose {
        println!("[PASS] {} {}ms", report.scenario_id, report.duration_ms);
    }

    let pass = usize::from(report.status == CaseStatus::Pass);
    let fail = usize::from(report.status == CaseStatus::Fail);

    let summary = RunSummary {
        test_id: replay_id,
        total: 1,
        pass,
        fail,
        flaky_pass: usize::from(report.status == CaseStatus::Pass && report.attempts > 1),
        duration_ms: report.duration_ms,
        report_path: run_dir.join("summary.json").display().to_string(),
        cases: vec![report],
    };

    let manifest = Manifest {
        test_id: summary.test_id.clone(),
        profile: None,
        selected_scenarios: vec![scenario.id],
        scenario_filters: vec![scenario_id.to_string()],
        tag_filters: vec![],
        started_unix_ms,
    };

    write_json(&run_dir.join("manifest.json"), &manifest)?;
    write_json(&run_dir.join("summary.json"), &summary)?;

    println!(
        "summary: pass={} fail={} flaky_pass={} duration={}ms report={}",
        summary.pass, summary.fail, summary.flaky_pass, summary.duration_ms, summary.report_path
    );

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kv_metrics_handles_decimal_and_hex() {
        let m = parse_kv_metrics("a=1 b=-2 c=0x10 d=-0x20 x=nope");
        assert_eq!(m.get("a"), Some(&1));
        assert_eq!(m.get("b"), Some(&-2));
        assert_eq!(m.get("c"), Some(&16));
        assert_eq!(m.get("d"), Some(&-32));
        assert!(!m.contains_key("x"));
    }

    #[test]
    fn evaluate_assertions_reports_missing_and_mismatch() {
        let scenario = crate::model::ScenarioSpec {
            id: "s".into(),
            description: String::new(),
            tags: vec![],
            timeout_ms: 100,
            command: vec!["true".into()],
            expect: vec![],
            forbid: vec![],
            contracts: vec![],
            assertions: Some(crate::model::AssertionsSpec {
                status_code: BTreeMap::from([("ok".to_string(), 0), ("missing".to_string(), 1)]),
                error_code: BTreeMap::new(),
                signal_mask: BTreeMap::new(),
                packet_fields: BTreeMap::new(),
            }),
            elf_check: None,
        };

        let parsed = BTreeMap::from([("ok".to_string(), 5)]);
        let mismatches = evaluate_assertions(&scenario, &parsed);
        assert!(mismatches.iter().any(|m| m.contains("status_code.ok")));
        assert!(
            mismatches
                .iter()
                .any(|m| m.contains("status_code.missing missing"))
        );
    }
}
