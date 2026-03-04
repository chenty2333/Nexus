use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

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
    pub workspace_root: PathBuf,
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
            workspace_root,
        }
    }
}

/// Run selected conformance scenarios and write structured reports.
pub fn run_conformance(config: &RunConfig) -> Result<RunSummary> {
    fs::create_dir_all(&config.out_dir)
        .with_context(|| format!("create output dir {}", config.out_dir.display()))?;

    let scenarios = load_scenarios(&config.scenarios_dir)?;
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
    let mut case_reports = Vec::with_capacity(selected.len());

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

        let report = run_case(scenario, &case_dir, &config.workspace_root)?;

        if config.verbose || report.status == CaseStatus::Fail {
            if report.status == CaseStatus::Fail {
                let reason = report
                    .reason
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                println!("[FAIL] {} reason={}", report.scenario_id, reason);
            } else if config.verbose {
                println!("[PASS] {} {}ms", report.scenario_id, report.duration_ms);
            }
        }

        write_json(&case_dir.join("result.json"), &report)?;
        case_reports.push(report);
    }

    let duration_ms = run_start.elapsed().as_millis();
    let pass = case_reports
        .iter()
        .filter(|r| r.status == CaseStatus::Pass)
        .count();
    let fail = case_reports.len().saturating_sub(pass);

    let summary = RunSummary {
        test_id: test_id.clone(),
        total: case_reports.len(),
        pass,
        fail,
        duration_ms,
        report_path: run_dir.join("summary.json").display().to_string(),
        cases: case_reports,
    };

    write_json(&run_dir.join("summary.json"), &summary)?;

    println!(
        "summary: pass={} fail={} duration={}ms report={}",
        summary.pass, summary.fail, summary.duration_ms, summary.report_path
    );

    Ok(summary)
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

    let mut reason = None;

    if timed_out {
        reason = Some("timeout".to_string());
    } else if exit_code.unwrap_or(1) != 0 {
        reason = Some(format!("non_zero_exit({})", exit_code.unwrap_or(-1)));
    } else if !missing_expect.is_empty() {
        reason = Some(format!("missing_expect({})", missing_expect.join(",")));
    } else if !matched_forbid.is_empty() {
        reason = Some(format!("matched_forbid({})", matched_forbid.join(",")));
    }

    let status = if reason.is_some() {
        CaseStatus::Fail
    } else {
        CaseStatus::Pass
    };

    Ok(CaseReport {
        scenario_id: scenario.id.clone(),
        status,
        duration_ms: start.elapsed().as_millis(),
        exit_code,
        timed_out,
        reason,
        missing_expect,
        matched_forbid,
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
    let report = run_case(&scenario, &case_dir, &config.workspace_root)?;
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
        "summary: pass={} fail={} duration={}ms report={}",
        summary.pass, summary.fail, summary.duration_ms, summary.report_path
    );

    Ok(summary)
}
