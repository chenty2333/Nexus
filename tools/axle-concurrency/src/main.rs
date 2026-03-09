#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use axle_concurrency::corpus::Corpus;
use axle_concurrency::model::run_seed;
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
    }
}

fn smoke(iterations: usize, max_steps: u16, out_dir: Option<PathBuf>) -> Result<()> {
    let out_dir =
        out_dir.unwrap_or_else(|| PathBuf::from("/home/dia/Nexus/out/concurrency/host-corpus"));
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
