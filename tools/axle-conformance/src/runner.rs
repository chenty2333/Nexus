use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::contracts::{build_coverage_report, load_contract_catalog};
use crate::elf::inspect_elf;
use crate::gc::prune_runs;
use crate::model::{ScenarioSpec, load_scenarios};
use crate::report::{CaseReport, CaseStatus, GroupReport, Manifest, RunSummary};
use crate::selection::select_scenarios;
use crate::test_id::new_test_id;

/// Conformance execution configuration.
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub scenario_filters: Vec<String>,
    pub tag_filters: Vec<String>,
    pub keep_runs: usize,
    pub verbose: bool,
    pub out_dir: PathBuf,
    pub scenarios_dir: PathBuf,
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
            scenario_filters: Vec::new(),
            tag_filters: Vec::new(),
            keep_runs: 100,
            verbose: false,
            out_dir: workspace_root.join("target").join("axle-conformance"),
            scenarios_dir: specs_root.join("scenarios"),
            contracts_file: specs_root.join("contracts.toml"),
            workspace_root,
            jobs: 1,
            retries: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct PlannedCase {
    index: usize,
    scenario: ScenarioSpec,
    case_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct CommandGroupPlan {
    group_id: String,
    command: Vec<String>,
    timeout_ms: u64,
    members: Vec<PlannedCase>,
    group_dir: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
struct CommandGroupSpec {
    group_id: String,
    command: Vec<String>,
    scenario_ids: Vec<String>,
    timeout_ms: u64,
}

#[derive(Debug)]
struct CommandRunResult {
    duration_ms: u128,
    exit_code: Option<i32>,
    timed_out: bool,
    combined: String,
    parsed_metrics: BTreeMap<String, i64>,
}

#[derive(Debug)]
struct GroupExecutionOutput {
    group_report: GroupReport,
    case_reports: Vec<(usize, PathBuf, CaseReport)>,
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
    let selected = select_scenarios(&scenarios, &config.scenario_filters, &config.tag_filters)?;

    if selected.is_empty() {
        bail!("selection produced zero scenarios");
    }

    let keep_before_create = config.keep_runs.saturating_sub(1);
    let _ = prune_runs(&config.out_dir, keep_before_create)?;

    let test_id = new_test_id();
    let run_dir = config.out_dir.join(&test_id);
    let cases_dir = run_dir.join("cases");
    let groups_dir = run_dir.join("groups");
    fs::create_dir_all(&cases_dir)
        .with_context(|| format!("create cases dir {}", cases_dir.display()))?;
    fs::create_dir_all(&groups_dir)
        .with_context(|| format!("create groups dir {}", groups_dir.display()))?;

    let planned_cases = prepare_planned_cases(&selected, &cases_dir)?;
    let planned_groups = build_command_groups(&planned_cases, &groups_dir)?;

    println!(
        "axle-conformance test-id={} total={} groups={}",
        test_id,
        selected.len(),
        planned_groups.len()
    );

    let manifest = Manifest {
        test_id: test_id.clone(),
        selected_scenarios: selected.iter().map(|s| s.id.clone()).collect(),
        scenario_filters: config.scenario_filters.clone(),
        tag_filters: config.tag_filters.clone(),
        started_unix_ms: now_unix_ms(),
    };

    write_json(&run_dir.join("manifest.json"), &manifest)?;

    let run_start = Instant::now();
    let (case_reports, group_reports) = execute_groups(
        &planned_groups,
        planned_cases.len(),
        &config.workspace_root,
        config.jobs,
        config.retries,
    )?;

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
        groups: group_reports,
        cases: case_reports,
    };

    write_json(&run_dir.join("summary.json"), &summary)?;

    println!(
        "summary: pass={} fail={} flaky_pass={} duration={}ms report={}",
        summary.pass, summary.fail, summary.flaky_pass, summary.duration_ms, summary.report_path
    );

    Ok(summary)
}

fn prepare_planned_cases(selected: &[ScenarioSpec], cases_dir: &Path) -> Result<Vec<PlannedCase>> {
    let mut planned = Vec::with_capacity(selected.len());
    for (index, scenario) in selected.iter().cloned().enumerate() {
        let case_dir_name = sanitize_case_dir_name(&scenario.id);
        let case_dir = cases_dir.join(&case_dir_name);
        fs::create_dir_all(&case_dir)
            .with_context(|| format!("create case dir {}", case_dir.display()))?;
        write_json(&case_dir.join("scenario.json"), &scenario)?;
        fs::write(
            case_dir.join("command.txt"),
            render_command(&scenario.command),
        )
        .with_context(|| format!("write command file for scenario '{}'", scenario.id))?;
        planned.push(PlannedCase {
            index,
            scenario,
            case_dir,
        });
    }
    Ok(planned)
}

fn build_command_groups(
    planned_cases: &[PlannedCase],
    groups_dir: &Path,
) -> Result<Vec<CommandGroupPlan>> {
    let mut grouped: BTreeMap<Vec<String>, Vec<PlannedCase>> = BTreeMap::new();
    for planned_case in planned_cases.iter().cloned() {
        grouped
            .entry(planned_case.scenario.command.clone())
            .or_default()
            .push(planned_case);
    }

    let mut plans = Vec::with_capacity(grouped.len());
    for (group_index, (command, members)) in grouped.into_iter().enumerate() {
        let group_id = format!(
            "group-{group_index:03}-{:016x}",
            command_fingerprint(&command)
        );
        let group_dir = groups_dir.join(&group_id);
        fs::create_dir_all(&group_dir)
            .with_context(|| format!("create group dir {}", group_dir.display()))?;

        let timeout_ms = members
            .iter()
            .map(|member| member.scenario.timeout_ms)
            .max()
            .unwrap_or(1);
        let spec = CommandGroupSpec {
            group_id: group_id.clone(),
            command: command.clone(),
            scenario_ids: members
                .iter()
                .map(|member| member.scenario.id.clone())
                .collect(),
            timeout_ms,
        };
        write_json(&group_dir.join("group.json"), &spec)?;
        fs::write(group_dir.join("command.txt"), render_command(&command))
            .with_context(|| format!("write command file for group '{}'", group_id))?;

        plans.push(CommandGroupPlan {
            group_id,
            command,
            timeout_ms,
            members,
            group_dir,
        });
    }

    Ok(plans)
}

fn execute_groups(
    planned_groups: &[CommandGroupPlan],
    total_cases: usize,
    workspace_root: &Path,
    jobs: usize,
    retries: u32,
) -> Result<(Vec<CaseReport>, Vec<GroupReport>)> {
    if planned_groups.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let jobs = jobs.max(1).min(planned_groups.len());
    let mut ordered = Vec::with_capacity(planned_groups.len());

    if jobs == 1 {
        for planned_group in planned_groups {
            ordered.push(run_group_with_retries(
                planned_group,
                workspace_root,
                retries,
            )?);
        }
    } else {
        let tasks: Vec<_> = planned_groups
            .iter()
            .enumerate()
            .map(|(idx, planned_group)| (idx, planned_group.clone()))
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
                    let Some((idx, planned_group)) = next else {
                        break;
                    };

                    let result = run_group_with_retries(&planned_group, &workspace_root, retries);
                    let _ = result_tx.send((idx, result));
                }
            }));
        }
        drop(result_tx);

        let mut gathered: Vec<Option<GroupExecutionOutput>> =
            (0..planned_groups.len()).map(|_| None).collect();
        for _ in 0..planned_groups.len() {
            let (idx, result) = result_rx
                .recv()
                .context("receive group result from worker thread")?;
            gathered[idx] = Some(result?);
        }

        for worker in workers {
            let _ = worker.join();
        }

        for entry in gathered {
            match entry {
                Some(output) => ordered.push(output),
                None => bail!("missing group report from worker"),
            }
        }
    }

    let mut case_reports: Vec<Option<CaseReport>> = (0..total_cases).map(|_| None).collect();
    let mut group_reports = Vec::with_capacity(ordered.len());
    for output in ordered {
        persist_group_execution(&output)?;
        group_reports.push(output.group_report.clone());
        for (case_index, _, report) in output.case_reports {
            case_reports[case_index] = Some(report);
        }
    }

    let mut ordered_cases = Vec::with_capacity(total_cases);
    for entry in case_reports {
        match entry {
            Some(report) => ordered_cases.push(report),
            None => bail!("missing case report from grouped execution"),
        }
    }

    Ok((ordered_cases, group_reports))
}

fn persist_group_execution(output: &GroupExecutionOutput) -> Result<()> {
    let group_dir = PathBuf::from(&output.group_report.group_dir);
    write_json(&group_dir.join("result.json"), &output.group_report)?;
    for (_, case_dir, report) in &output.case_reports {
        write_json(&case_dir.join("result.json"), report)?;
    }
    Ok(())
}

fn run_group_with_retries(
    planned_group: &CommandGroupPlan,
    workspace_root: &Path,
    retries: u32,
) -> Result<GroupExecutionOutput> {
    let max_attempts = retries.saturating_add(1);
    let mut selected_reports: Vec<Option<CaseReport>> =
        (0..planned_group.members.len()).map(|_| None).collect();
    let mut attempts_executed = 0;
    let mut total_duration_ms = 0;
    let mut last_attempt_duration_ms = 0;
    let mut last_exit_code = None;
    let mut last_timed_out = false;

    for attempt in 1..=max_attempts {
        let attempt_dir = if max_attempts > 1 {
            planned_group.group_dir.join(format!("attempt-{attempt}"))
        } else {
            planned_group.group_dir.clone()
        };
        fs::create_dir_all(&attempt_dir)
            .with_context(|| format!("create attempt dir {}", attempt_dir.display()))?;

        let run = run_group_command(
            &planned_group.command,
            workspace_root,
            planned_group.timeout_ms,
            &attempt_dir,
            &planned_group.group_id,
        )?;

        attempts_executed = attempt;
        total_duration_ms += run.duration_ms;
        last_attempt_duration_ms = run.duration_ms;
        last_exit_code = run.exit_code;
        last_timed_out = run.timed_out;

        for (member_index, member) in planned_group.members.iter().enumerate() {
            let report =
                evaluate_scenario_attempt(member, planned_group, &run, workspace_root, attempt);
            match selected_reports[member_index].as_ref() {
                Some(existing) if existing.status == CaseStatus::Pass => {}
                _ => selected_reports[member_index] = Some(report),
            }
        }

        if selected_reports.iter().all(|report| {
            report
                .as_ref()
                .is_some_and(|report| report.status == CaseStatus::Pass)
        }) {
            break;
        }
    }

    let status = if selected_reports.iter().all(|report| {
        report
            .as_ref()
            .is_some_and(|report| report.status == CaseStatus::Pass)
    }) {
        CaseStatus::Pass
    } else {
        CaseStatus::Fail
    };

    let scenario_ids = planned_group
        .members
        .iter()
        .map(|member| member.scenario.id.clone())
        .collect();
    let group_report = GroupReport {
        group_id: planned_group.group_id.clone(),
        status,
        attempts: attempts_executed,
        duration_ms: total_duration_ms,
        last_attempt_duration_ms,
        exit_code: last_exit_code,
        timed_out: last_timed_out,
        command: planned_group.command.clone(),
        scenario_ids,
        group_dir: planned_group.group_dir.display().to_string(),
    };

    let mut case_reports = Vec::with_capacity(planned_group.members.len());
    for (member_index, member) in planned_group.members.iter().enumerate() {
        let report = selected_reports[member_index].take().with_context(|| {
            format!("missing case report for scenario '{}'", member.scenario.id)
        })?;
        case_reports.push((member.index, member.case_dir.clone(), report));
    }

    Ok(GroupExecutionOutput {
        group_report,
        case_reports,
    })
}

fn run_group_command(
    command: &[String],
    workspace_root: &Path,
    timeout_ms: u64,
    output_dir: &Path,
    group_id: &str,
) -> Result<CommandRunResult> {
    let stdout_path = output_dir.join("stdout.log");
    let stderr_path = output_dir.join("stderr.log");

    let stdout_file = File::create(&stdout_path)
        .with_context(|| format!("create stdout log {}", stdout_path.display()))?;
    let stderr_file = File::create(&stderr_path)
        .with_context(|| format!("create stderr log {}", stderr_path.display()))?;

    let mut process = Command::new(&command[0]);
    process
        .args(&command[1..])
        .current_dir(workspace_root)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    let start = Instant::now();

    let mut child = process
        .spawn()
        .with_context(|| format!("spawn command group '{}'", group_id))?;

    let timeout = Duration::from_millis(timeout_ms);
    let mut exit_code = None;
    let mut timed_out = false;

    loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("wait command group '{}'", group_id))?
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

        thread::sleep(Duration::from_millis(10));
    }

    let stdout_text = fs::read_to_string(&stdout_path).unwrap_or_default();
    let stderr_text = fs::read_to_string(&stderr_path).unwrap_or_default();
    let combined = format!("{stdout_text}\n{stderr_text}");
    let parsed_metrics = parse_kv_metrics(&combined);

    Ok(CommandRunResult {
        duration_ms: start.elapsed().as_millis(),
        exit_code,
        timed_out,
        combined,
        parsed_metrics,
    })
}

fn evaluate_scenario_attempt(
    planned_case: &PlannedCase,
    planned_group: &CommandGroupPlan,
    run: &CommandRunResult,
    workspace_root: &Path,
    attempt: u32,
) -> CaseReport {
    let scenario = &planned_case.scenario;
    let scenario_timed_out = run.timed_out || run.duration_ms > u128::from(scenario.timeout_ms);

    let missing_expect: Vec<String> = scenario
        .expect
        .iter()
        .filter(|needle| !run.combined.contains(needle.as_str()))
        .cloned()
        .collect();
    let matched_forbid: Vec<String> = scenario
        .forbid
        .iter()
        .filter(|needle| run.combined.contains(needle.as_str()))
        .cloned()
        .collect();
    let assertion_mismatches = evaluate_assertions(scenario, &run.parsed_metrics);

    let mut reason = None;
    if scenario_timed_out {
        reason = Some("timeout".to_string());
    } else if run.exit_code.unwrap_or(1) != 0 {
        reason = Some(format!("non_zero_exit({})", run.exit_code.unwrap_or(-1)));
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

    CaseReport {
        scenario_id: scenario.id.clone(),
        group_id: planned_group.group_id.clone(),
        status,
        attempts: attempt,
        duration_ms: run.duration_ms,
        exit_code: run.exit_code,
        timed_out: scenario_timed_out,
        reason,
        missing_expect,
        matched_forbid,
        parsed_metrics: run.parsed_metrics.clone(),
        assertion_mismatches,
        elf_check,
        group_dir: planned_group.group_dir.display().to_string(),
        case_dir: planned_case.case_dir.display().to_string(),
    }
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

fn command_fingerprint(command: &[String]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    command.hash(&mut hasher);
    hasher.finish()
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
    scenario: &ScenarioSpec,
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
    check_assertion_group_min(
        "status_code_min",
        &assertions.status_code_min,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group_max(
        "status_code_max",
        &assertions.status_code_max,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group(
        "error_code",
        &assertions.error_code,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group_min(
        "error_code_min",
        &assertions.error_code_min,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group_max(
        "error_code_max",
        &assertions.error_code_max,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group(
        "signal_mask",
        &assertions.signal_mask,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group_min(
        "signal_mask_min",
        &assertions.signal_mask_min,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group_max(
        "signal_mask_max",
        &assertions.signal_mask_max,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group(
        "packet_fields",
        &assertions.packet_fields,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group_min(
        "packet_fields_min",
        &assertions.packet_fields_min,
        parsed_metrics,
        &mut mismatches,
    );
    check_assertion_group_max(
        "packet_fields_max",
        &assertions.packet_fields_max,
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

fn check_assertion_group_min(
    group: &str,
    expected: &BTreeMap<String, i64>,
    parsed_metrics: &BTreeMap<String, i64>,
    mismatches: &mut Vec<String>,
) {
    for (k, expected_v) in expected {
        match parsed_metrics.get(k) {
            Some(actual_v) if actual_v >= expected_v => {}
            Some(actual_v) => mismatches.push(format!(
                "{}.{} expected>={} actual={}",
                group, k, expected_v, actual_v
            )),
            None => mismatches.push(format!("{}.{} missing", group, k)),
        }
    }
}

fn check_assertion_group_max(
    group: &str,
    expected: &BTreeMap<String, i64>,
    parsed_metrics: &BTreeMap<String, i64>,
    mismatches: &mut Vec<String>,
) {
    for (k, expected_v) in expected {
        match parsed_metrics.get(k) {
            Some(actual_v) if actual_v <= expected_v => {}
            Some(actual_v) => mismatches.push(format!(
                "{}.{} expected<={} actual={}",
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
    let scenario: ScenarioSpec =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", scenario_path.display()))?;
    scenario.validate()?;

    let replay_id = new_test_id();
    let run_dir = config.out_dir.join(&replay_id);
    let cases_dir = run_dir.join("cases");
    let groups_dir = run_dir.join("groups");
    fs::create_dir_all(&cases_dir)
        .with_context(|| format!("create replay cases dir {}", cases_dir.display()))?;
    fs::create_dir_all(&groups_dir)
        .with_context(|| format!("create replay groups dir {}", groups_dir.display()))?;

    println!(
        "axle-conformance test-id={} replay-from={} scenario={}",
        replay_id, run_id, scenario_id
    );

    let selected = vec![scenario];
    let planned_cases = prepare_planned_cases(&selected, &cases_dir)?;
    let planned_groups = build_command_groups(&planned_cases, &groups_dir)?;

    let started_unix_ms = now_unix_ms();
    let run_start = Instant::now();
    let (case_reports, group_reports) = execute_groups(
        &planned_groups,
        planned_cases.len(),
        &config.workspace_root,
        1,
        config.retries,
    )?;

    for report in &case_reports {
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

    let pass = case_reports
        .iter()
        .filter(|report| report.status == CaseStatus::Pass)
        .count();
    let fail = case_reports.len().saturating_sub(pass);
    let flaky_pass = case_reports
        .iter()
        .filter(|report| report.status == CaseStatus::Pass && report.attempts > 1)
        .count();

    let summary = RunSummary {
        test_id: replay_id.clone(),
        total: case_reports.len(),
        pass,
        fail,
        flaky_pass,
        duration_ms: run_start.elapsed().as_millis(),
        report_path: run_dir.join("summary.json").display().to_string(),
        groups: group_reports,
        cases: case_reports,
    };

    let manifest = Manifest {
        test_id: replay_id,
        selected_scenarios: selected
            .iter()
            .map(|scenario| scenario.id.clone())
            .collect(),
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
    fn command_groups_collapse_identical_commands() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cases_dir = tmp.path().join("cases");
        let groups_dir = tmp.path().join("groups");
        fs::create_dir_all(&cases_dir).expect("mkdir cases");
        fs::create_dir_all(&groups_dir).expect("mkdir groups");

        let selected = vec![
            ScenarioSpec {
                id: "sample.one".into(),
                description: String::new(),
                tags: vec![],
                timeout_ms: 100,
                command: vec!["true".into()],
                expect: vec![],
                forbid: vec![],
                contracts: vec![],
                assertions: None,
                elf_check: None,
            },
            ScenarioSpec {
                id: "sample.two".into(),
                description: String::new(),
                tags: vec![],
                timeout_ms: 100,
                command: vec!["true".into()],
                expect: vec![],
                forbid: vec![],
                contracts: vec![],
                assertions: None,
                elf_check: None,
            },
        ];

        let planned_cases = prepare_planned_cases(&selected, &cases_dir).expect("planned cases");
        let groups = build_command_groups(&planned_cases, &groups_dir).expect("group plans");

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].members.len(), 2);
    }

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
        let scenario = ScenarioSpec {
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
                ..crate::model::AssertionsSpec::default()
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

    #[test]
    fn evaluate_assertions_reports_min_and_max_mismatches() {
        let scenario = ScenarioSpec {
            id: "s".into(),
            description: String::new(),
            tags: vec![],
            timeout_ms: 100,
            command: vec!["true".into()],
            expect: vec![],
            forbid: vec![],
            contracts: vec![],
            assertions: Some(crate::model::AssertionsSpec {
                packet_fields_min: BTreeMap::from([("cycles".to_string(), 10)]),
                packet_fields_max: BTreeMap::from([("latency".to_string(), 20)]),
                ..crate::model::AssertionsSpec::default()
            }),
            elf_check: None,
        };

        let parsed = BTreeMap::from([("cycles".to_string(), 9), ("latency".to_string(), 21)]);
        let mismatches = evaluate_assertions(&scenario, &parsed);
        assert!(
            mismatches
                .iter()
                .any(|m| m.contains("packet_fields_min.cycles expected>=10 actual=9"))
        );
        assert!(
            mismatches
                .iter()
                .any(|m| m.contains("packet_fields_max.latency expected<=20 actual=21"))
        );
    }

    #[test]
    fn evaluate_assertions_accepts_min_and_max_bounds() {
        let scenario = ScenarioSpec {
            id: "s".into(),
            description: String::new(),
            tags: vec![],
            timeout_ms: 100,
            command: vec!["true".into()],
            expect: vec![],
            forbid: vec![],
            contracts: vec![],
            assertions: Some(crate::model::AssertionsSpec {
                packet_fields_min: BTreeMap::from([("cycles".to_string(), 10)]),
                packet_fields_max: BTreeMap::from([("cycles".to_string(), 20)]),
                ..crate::model::AssertionsSpec::default()
            }),
            elf_check: None,
        };

        let parsed = BTreeMap::from([("cycles".to_string(), 15)]);
        let mismatches = evaluate_assertions(&scenario, &parsed);
        assert!(mismatches.is_empty());
    }
}
