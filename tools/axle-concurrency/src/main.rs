#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use axle_concurrency::corpus::Corpus;
use axle_concurrency::model::run_seed;
use axle_concurrency::qemu::replay_seed_via_qemu;
use axle_concurrency::seed::ConcurrentSeed;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "axle-concurrency")]
#[command(about = "Axle concurrent seed replay and smoke runner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run a small host-side guided smoke search and retain interesting seeds.
    Smoke {
        /// Number of mutated seeds to execute after the built-in corpus.
        #[arg(long, default_value_t = 64)]
        iterations: usize,
        /// Step budget for each replay.
        #[arg(long, default_value_t = 32)]
        max_steps: u16,
        /// Output directory for retained seeds.
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Replay one saved seed.
    Replay {
        /// Path to one saved JSON seed.
        #[arg(long)]
        seed: PathBuf,
    },
    /// Replay one retained seed by selecting and executing the closest QEMU scenario bundle.
    QemuReplay {
        /// Path to one saved JSON seed.
        #[arg(long)]
        seed: PathBuf,
        /// Print PASS lines from the underlying conformance runner.
        #[arg(long)]
        verbose: bool,
        /// Retry failed scenarios up to this count.
        #[arg(long, default_value_t = 0)]
        retries: u32,
        /// Number of historical runs to retain.
        #[arg(long, default_value_t = 100)]
        keep_runs: usize,
    },
    /// Triage a saved host corpus by replaying each retained seed through QEMU scenario bundles.
    QemuTriage {
        /// Directory containing retained seed JSON files.
        #[arg(long)]
        corpus_dir: Option<PathBuf>,
        /// Limit the number of seeds replayed.
        #[arg(long)]
        limit: Option<usize>,
        /// Print PASS lines from the underlying conformance runner.
        #[arg(long)]
        verbose: bool,
        /// Retry failed scenarios up to this count.
        #[arg(long, default_value_t = 0)]
        retries: u32,
        /// Number of historical runs to retain.
        #[arg(long, default_value_t = 100)]
        keep_runs: usize,
    },
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("axle-concurrency: {err:?}");
        std::process::exit(2);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Smoke {
            iterations,
            max_steps,
            out_dir,
        } => smoke(iterations, max_steps, out_dir),
        Commands::Replay { seed } => replay(seed),
        Commands::QemuReplay {
            seed,
            verbose,
            retries,
            keep_runs,
        } => qemu_replay(seed, verbose, retries, keep_runs),
        Commands::QemuTriage {
            corpus_dir,
            limit,
            verbose,
            retries,
            keep_runs,
        } => qemu_triage(corpus_dir, limit, verbose, retries, keep_runs),
    }
}

fn smoke(iterations: usize, max_steps: u16, out_dir: Option<PathBuf>) -> Result<()> {
    let out_dir = out_dir.unwrap_or_else(default_host_corpus_dir);
    let mut corpus = Corpus::new();
    let mut retained = 0usize;
    let base = ConcurrentSeed::base_corpus(max_steps);

    for seed in &base {
        let observation = run_seed(seed);
        if corpus
            .consider(&out_dir, seed.clone(), observation)
            .context("retain base seed")?
        {
            retained += 1;
        }
    }

    for round in 0..iterations {
        let parent = if corpus.retained().is_empty() {
            &base[round % base.len()]
        } else {
            &corpus.retained()[round % corpus.retained().len()].seed
        };
        let child = parent.mutated(0x5eed_0000_u64.wrapping_add(round as u64));
        let observation = run_seed(&child);
        if corpus
            .consider(&out_dir, child, observation)
            .with_context(|| format!("retain mutated seed round={round}"))?
        {
            retained += 1;
        }
    }

    println!(
        "concurrency-smoke: retained={} total_saved={} dir={}",
        retained,
        corpus.retained().len(),
        out_dir.display()
    );
    for seed in corpus.retained().iter().take(8) {
        println!(
            "seed={} failure={:?} edges={} states={} path={}",
            seed.id,
            seed.observation.failure_kind,
            seed.observation.edge_hits.len(),
            seed.observation.state_signatures.len(),
            seed.path.display()
        );
    }
    Ok(())
}

fn replay(seed_path: PathBuf) -> Result<()> {
    let bytes = fs::read(&seed_path).with_context(|| format!("read {}", seed_path.display()))?;
    let seed: ConcurrentSeed =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", seed_path.display()))?;
    let observation = run_seed(&seed);
    println!(
        "replay: system={:?} edges={} states={} failure={:?}",
        seed.system,
        observation.edge_hits.len(),
        observation.state_signatures.len(),
        observation.failure_kind
    );
    for event in &observation.events {
        println!("event: {event}");
    }
    Ok(())
}

fn qemu_replay(seed_path: PathBuf, verbose: bool, retries: u32, keep_runs: usize) -> Result<()> {
    let report = replay_seed_via_qemu(&seed_path, verbose, retries, keep_runs)?;
    println!(
        "qemu-replay: seed={} scenarios={} pass={} fail={} report={}",
        report.seed_path.display(),
        report.scenarios.join(","),
        report.summary.pass,
        report.summary.fail,
        report.summary.report_path
    );
    Ok(())
}

fn qemu_triage(
    corpus_dir: Option<PathBuf>,
    limit: Option<usize>,
    verbose: bool,
    retries: u32,
    keep_runs: usize,
) -> Result<()> {
    let corpus_dir = corpus_dir.unwrap_or_else(default_host_corpus_dir);
    let mut seeds = fs::read_dir(&corpus_dir)
        .with_context(|| format!("read_dir {}", corpus_dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<_>>();
    seeds.sort();
    if let Some(limit) = limit {
        seeds.truncate(limit);
    }
    if seeds.is_empty() {
        anyhow::bail!("no retained seeds found under {}", corpus_dir.display());
    }

    let triage_root = workspace_root()
        .join("target")
        .join("axle-concurrency")
        .join("qemu-triage");
    fs::create_dir_all(&triage_root)
        .with_context(|| format!("create {}", triage_root.display()))?;

    let mut pass = 0usize;
    let mut fail = 0usize;
    for seed_path in seeds {
        let report = replay_seed_via_qemu(&seed_path, verbose, retries, keep_runs)?;
        let file_name = seed_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("seed.json");
        let report_path = triage_root.join(format!("{file_name}.qemu.json"));
        fs::write(&report_path, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("write {}", report_path.display()))?;
        if report.summary.fail == 0 {
            pass += 1;
        } else {
            fail += 1;
        }
        println!(
            "triage: seed={} scenarios={} pass={} fail={} saved={}",
            report.seed_path.display(),
            report.scenarios.join(","),
            report.summary.pass,
            report.summary.fail,
            report_path.display()
        );
    }

    println!("qemu-triage: pass={} fail={}", pass, fail);
    Ok(())
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.join("../..");
    workspace_root.canonicalize().unwrap_or(workspace_root)
}

fn default_host_corpus_dir() -> PathBuf {
    workspace_root()
        .join("target")
        .join("axle-concurrency")
        .join("host-corpus")
}
