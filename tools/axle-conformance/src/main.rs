#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use axle_conformance::gc::prune_runs;
use axle_conformance::model::{load_profile, load_scenarios};
use axle_conformance::runner::{RunConfig, replay_from_snapshot, run_conformance};
use axle_conformance::selection::select_scenarios;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "axle-conformance")]
#[command(about = "Axle kernel conformance runner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run conformance scenarios.
    Run {
        /// Profile name from specs/conformance/profiles/<name>.toml.
        #[arg(long)]
        profile: Option<String>,
        /// Run only these scenario ids.
        #[arg(long = "scenario")]
        scenario_filters: Vec<String>,
        /// Require these tags (AND semantics).
        #[arg(long = "tag")]
        tag_filters: Vec<String>,
        /// Number of historical runs to retain.
        #[arg(long, default_value_t = 100)]
        keep_runs: usize,
        /// Print PASS lines in addition to FAIL lines.
        #[arg(long)]
        verbose: bool,
    },
    /// List scenarios after applying filters.
    List {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long = "tag")]
        tag_filters: Vec<String>,
    },
    /// Replay a single case from a previous run snapshot.
    Replay {
        #[arg(long)]
        run_id: String,
        #[arg(long = "scenario")]
        scenario_id: String,
        #[arg(long)]
        verbose: bool,
    },
    /// Garbage collect old run directories.
    Gc {
        #[arg(long, default_value_t = 100)]
        keep_runs: usize,
    },
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("axle-conformance: {err:?}");
        std::process::exit(2);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            profile,
            scenario_filters,
            tag_filters,
            keep_runs,
            verbose,
        } => {
            let mut config = RunConfig::with_workspace_defaults();
            config.profile = profile.or(config.profile);
            config.scenario_filters = scenario_filters;
            config.tag_filters = tag_filters;
            config.keep_runs = keep_runs;
            config.verbose = verbose;

            let summary = run_conformance(&config)?;
            if summary.fail > 0 {
                std::process::exit(1);
            }
            Ok(())
        }
        Commands::List {
            profile,
            tag_filters,
        } => {
            let base = RunConfig::with_workspace_defaults();
            let scenarios = load_scenarios(&base.scenarios_dir)?;
            let profile_spec = if let Some(p) = profile.or(base.profile) {
                Some(load_profile(&base.profiles_dir, &p)?)
            } else {
                None
            };
            let selected = select_scenarios(&scenarios, profile_spec.as_ref(), &[], &tag_filters)?;

            for scenario in &selected {
                println!("{}\t{}", scenario.id, scenario.tags.join(","));
            }
            println!("total={}", selected.len());
            Ok(())
        }
        Commands::Replay {
            run_id,
            scenario_id,
            verbose,
        } => {
            let mut config = RunConfig::with_workspace_defaults();
            config.profile = None;
            config.verbose = verbose;

            let summary = replay_from_snapshot(&config, &run_id, &scenario_id)
                .with_context(|| format!("replay run_id={} scenario={}", run_id, scenario_id))?;

            if summary.fail > 0 {
                std::process::exit(1);
            }
            Ok(())
        }
        Commands::Gc { keep_runs } => {
            let base = RunConfig::with_workspace_defaults();
            let removed = prune_runs(&base.out_dir, keep_runs)?;
            println!(
                "gc: removed={} keep_runs={} dir={}",
                removed.len(),
                keep_runs,
                base.out_dir.display()
            );
            Ok(())
        }
    }
}
