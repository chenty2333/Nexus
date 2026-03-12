#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nexus_fs_model::{
    ReplayCase, ReplayResult, Scenario, built_in_scenarios, explore_scenario, inject_faults,
    replay_case, scenario_by_name,
};

#[derive(Debug, Parser)]
#[command(name = "datafs-check")]
#[command(about = "Reference-model explorer and crash checker for DataFS-prep")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// List the built-in DataFS-prep scenarios.
    List,
    /// Explore one scenario and report invariant failures across injected faults.
    Explore {
        /// Built-in scenario name.
        #[arg(long)]
        scenario: String,
        /// Optional JSON report output path.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Expand one scenario into fault-injected replay cases.
    Inject {
        /// Built-in scenario name.
        #[arg(long)]
        scenario: String,
        /// JSON output path for replay cases.
        #[arg(long)]
        out: PathBuf,
    },
    /// Replay one saved case or array of saved cases.
    Replay {
        /// Input JSON file containing one replay case or an array of them.
        #[arg(long)]
        input: PathBuf,
        /// Optional case index when the input contains an array.
        #[arg(long)]
        index: Option<usize>,
        /// Optional JSON report output path.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("datafs-check: {err:?}");
        std::process::exit(2);
    }
}

fn real_main() -> Result<()> {
    match Cli::parse().command {
        Commands::List => list_scenarios(),
        Commands::Explore { scenario, out } => explore(&scenario, out),
        Commands::Inject { scenario, out } => inject(&scenario, &out),
        Commands::Replay { input, index, out } => replay(&input, index, out.as_deref()),
    }
}

fn list_scenarios() -> Result<()> {
    for scenario in built_in_scenarios() {
        println!("{}", scenario.name);
    }
    Ok(())
}

fn explore(name: &str, out: Option<PathBuf>) -> Result<()> {
    let scenario = load_scenario(name)?;
    let report = explore_scenario(&scenario).with_context(|| format!("explore scenario {name}"))?;
    println!(
        "scenario={} cases={} clean={} failing={}",
        report.scenario,
        report.cases_checked,
        report.clean_cases,
        report.failing_cases.len()
    );
    for failure in &report.failing_cases {
        print_replay_summary(failure);
    }
    write_json_if_requested(out.as_deref(), &report)
}

fn inject(name: &str, out: &Path) -> Result<()> {
    let scenario = load_scenario(name)?;
    let cases = inject_faults(&scenario).with_context(|| format!("inject scenario {name}"))?;
    write_json(out, &cases)?;
    println!(
        "scenario={} replay_cases={} out={}",
        scenario.name,
        cases.len(),
        out.display()
    );
    Ok(())
}

fn replay(input: &Path, index: Option<usize>, out: Option<&Path>) -> Result<()> {
    let bytes = fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let cases = parse_cases(&bytes).with_context(|| format!("parse {}", input.display()))?;
    let results = match index {
        Some(index) => vec![replay_selected_case(&cases, index)?],
        None => cases.iter().map(replay_case).collect(),
    };
    for result in &results {
        print_replay_summary(result);
    }
    match out {
        Some(path) => write_json(path, &results),
        None => {
            println!("{}", serde_json::to_string_pretty(&results)?);
            Ok(())
        }
    }
}

fn replay_selected_case(cases: &[ReplayCase], index: usize) -> Result<ReplayResult> {
    let Some(case) = cases.get(index) else {
        bail!("case index {} out of range (len={})", index, cases.len());
    };
    Ok(replay_case(case))
}

fn parse_cases(bytes: &[u8]) -> Result<Vec<ReplayCase>> {
    if let Ok(case) = serde_json::from_slice::<ReplayCase>(bytes) {
        return Ok(vec![case]);
    }
    Ok(serde_json::from_slice::<Vec<ReplayCase>>(bytes)?)
}

fn load_scenario(name: &str) -> Result<Scenario> {
    scenario_by_name(name)
        .with_context(|| format!("unknown scenario {name}; try `datafs-check list`"))
}

fn print_replay_summary(result: &ReplayResult) {
    println!(
        "fault={:?} journal_violations={} state_violations={} stopped_at_seq={:?}",
        result.fault,
        result.journal_violations.len(),
        result.state_violations.len(),
        result.stopped_at_seq
    );
}

fn write_json_if_requested<T>(out: Option<&Path>, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    match out {
        Some(path) => write_json(path, value),
        None => {
            println!("{}", serde_json::to_string_pretty(value)?);
            Ok(())
        }
    }
}

fn write_json<T>(path: &Path, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
