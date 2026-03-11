use std::{fs, path::PathBuf};

use anyhow::Context;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(about = "Compile a minimal Nexus component manifest into binary IR")]
struct Args {
    /// Input TOML manifest path.
    input: PathBuf,
    /// Output binary manifest path.
    #[arg(short, long)]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let source = fs::read_to_string(&args.input)
        .with_context(|| format!("read manifest {}", args.input.display()))?;
    let blob = nexus_manifestc::compile_manifest(&source)?;
    fs::write(&args.output, blob)
        .with_context(|| format!("write manifest {}", args.output.display()))?;
    Ok(())
}
