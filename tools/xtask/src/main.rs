mod system;

use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const BARE_METAL_TARGET: &str = "x86_64-unknown-none";
fn main() {
    if let Err(error) = real_main() {
        eprintln!("nexus: {error}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let root = repo_root();
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    let option = args.next();
    if args.next().is_some() {
        return Err(usage().into());
    }

    match command.as_str() {
        "check" if option.is_none() => check(&root),
        "test" if option.is_none() => test(&root),
        "kernel" if option.is_none() => kernel(&root),
        "system" if option.is_none() => system(&root),
        "clean" => clean(&root, option.as_deref()),
        _ => Err(usage().into()),
    }
}

fn usage() -> String {
    "usage: cargo nexus <check|test|kernel|system|clean>".into()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask lives at tools/xtask")
        .to_path_buf()
}

fn check(root: &Path) -> Result<()> {
    section("check workspace formatting");
    cargo(root, &["fmt", "--all", "--", "--check"])?;
    section("clippy portable workspace");
    cargo(
        root,
        &[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    section("check portable workspace");
    cargo(
        root,
        &[
            "check",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
        ],
    )?;
    section("check portable core without std");
    cargo(
        root,
        &[
            "check",
            "--locked",
            "-p",
            "cser-core",
            "--no-default-features",
            "--lib",
            "--target",
            BARE_METAL_TARGET,
        ],
    )?;
    section("check independent model without std");
    cargo(
        root,
        &[
            "check",
            "--locked",
            "-p",
            "cser-model",
            "--no-default-features",
            "--lib",
            "--target",
            BARE_METAL_TARGET,
        ],
    )?;
    section("check Nexus OSTD kernel closure");
    system::check(root)
}

fn test(root: &Path) -> Result<()> {
    section("test endpoint and provider host reference");
    run(
        root,
        "python3",
        &[
            "-m",
            "unittest",
            "discover",
            "-s",
            "kernel/nexus-ostd/tools/cser-experiment/tests",
            "-v",
        ],
    )?;
    section("test portable core");
    cargo(
        root,
        &[
            "test",
            "--locked",
            "-p",
            "cser-core",
            "--all-targets",
            "--all-features",
            "--no-fail-fast",
        ],
    )?;
    section("test independent model");
    cargo(
        root,
        &[
            "test",
            "--locked",
            "-p",
            "cser-model",
            "--all-targets",
            "--all-features",
            "--no-fail-fast",
        ],
    )?;
    section("test Nexus system false-PASS checkers");
    cargo(root, &["test", "--locked", "-p", "nexus-xtask"])
}

fn kernel(root: &Path) -> Result<()> {
    system::build(root)
}

fn system(root: &Path) -> Result<()> {
    system::run(root)
}

fn clean(root: &Path, option: Option<&str>) -> Result<()> {
    if option.is_some() {
        return Err("usage: cargo nexus clean".into());
    }
    let _lock = system::lock(root)?;
    section("clean portable workspace");
    cargo(root, &["clean"])?;
    system::clean(root)
}

fn cargo(root: &Path, args: &[&str]) -> Result<()> {
    run(root, "cargo", args)
}

fn run(root: &Path, program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .current_dir(root)
        .args(args)
        .status()?;
    if !status.success() {
        return Err(format!("{program} {} failed with {status}", args.join(" ")).into());
    }
    Ok(())
}

fn section(title: &str) {
    println!("\n==> {title}");
}
