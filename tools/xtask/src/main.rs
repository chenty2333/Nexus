use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const REQUIRED_PATHS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "docs/rfcs/0006-cser-core-semantic-rebaseline.md",
    "crates/cser-core/Cargo.toml",
    "crates/cser-model/Cargo.toml",
    "crates/cser-trace-conformance/Cargo.toml",
    "crates/nexus-effect-peer-wire/Cargo.toml",
    "kernel/nexus-ostd/Cargo.toml",
    "kernel/nexus-ostd/cser-production-sources.txt",
    "kernel/nexus-ostd/scripts/assert-cser-core-production-cutover.sh",
    "kernel/nexus-ostd/src/cser/core_production_registry.rs",
    "kernel/nexus-ostd/src/cser/core_persistent_runtime.rs",
    "x",
];

fn main() {
    if let Err(error) = real_main() {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let root = repo_root();
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| String::from("help"));
    if let Some(extra) = args.next() {
        return Err(format!("unexpected argument: {extra}").into());
    }

    match command.as_str() {
        "build" => build(&root),
        "doctor" => doctor(&root),
        "fmt" => fmt(&root),
        "check" => check(&root),
        "clippy" => clippy(&root),
        "test" => test(&root),
        "quick" | "model" | "verify" => verify(&root),
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        _ => Err(format!("unknown command: {command}").into()),
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask lives at tools/xtask")
        .to_path_buf()
}

fn print_usage() {
    eprintln!("usage: cargo run --manifest-path tools/xtask/Cargo.toml -- <command>");
    eprintln!("commands: doctor build fmt check clippy test quick model verify");
}

fn doctor(root: &Path) -> Result<()> {
    section("validate CSER core rebaseline layout");
    for relative in REQUIRED_PATHS {
        let path = root.join(relative);
        if !path.is_file() {
            return Err(format!("required rebaseline path is missing: {}", path.display()).into());
        }
    }
    run(root, "rustc", &["--version"])?;
    run(root, "cargo", &["--version"])?;
    run(root, "git", &["--version"])?;
    assert_cutover(root)?;
    println!(
        "CSER CORE DOCTOR PASS paths={} production_registry=single persistent_runner=four-boot",
        REQUIRED_PATHS.len()
    );
    Ok(())
}

fn build(root: &Path) -> Result<()> {
    section("build the rebaselined host workspace");
    cargo(
        root,
        &[
            "build",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
        ],
    )?;
    section("build portable core for bare metal without std");
    cargo(
        root,
        &[
            "build",
            "--locked",
            "-p",
            "cser-core",
            "--no-default-features",
            "--lib",
            "--target",
            "x86_64-unknown-none",
        ],
    )?;
    section("build independent oracle for bare metal without std");
    cargo(
        root,
        &[
            "build",
            "--locked",
            "-p",
            "cser-model",
            "--no-default-features",
            "--lib",
            "--target",
            "x86_64-unknown-none",
        ],
    )
}

fn fmt(root: &Path) -> Result<()> {
    section("format production workspaces");
    cargo(root, &["fmt", "--all"])?;
    cargo(root, &["fmt", "--manifest-path", "tools/xtask/Cargo.toml"])
}

fn fmt_check(root: &Path) -> Result<()> {
    section("check Rust formatting");
    cargo(root, &["fmt", "--all", "--", "--check"])?;
    cargo(
        root,
        &[
            "fmt",
            "--manifest-path",
            "tools/xtask/Cargo.toml",
            "--",
            "--check",
        ],
    )
}

fn check(root: &Path) -> Result<()> {
    section("assert the atomic production cutover graph");
    assert_cutover(root)?;
    cargo_package(root, "check", "cser-core", true)?;
    section("check portable core for bare metal without std");
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
            "x86_64-unknown-none",
        ],
    )?;
    cargo_package(root, "check", "cser-model", true)?;
    cargo_package(root, "check", "cser-trace-conformance", false)?;
    cargo_package(root, "check", "nexus-effect-peer-wire", false)?;
    section("check the production workflow runner");
    cargo(
        root,
        &[
            "check",
            "--locked",
            "--manifest-path",
            "tools/xtask/Cargo.toml",
            "--all-targets",
        ],
    )
}

fn clippy(root: &Path) -> Result<()> {
    clippy_package(root, "cser-core", true)?;
    clippy_package(root, "cser-model", true)?;
    clippy_package(root, "cser-trace-conformance", false)?;
    clippy_package(root, "nexus-effect-peer-wire", false)?;
    section("clippy the production workflow runner");
    cargo(
        root,
        &[
            "clippy",
            "--locked",
            "--manifest-path",
            "tools/xtask/Cargo.toml",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )
}

fn test(root: &Path) -> Result<()> {
    test_package(root, "cser-core", true)?;
    test_package(root, "cser-model", true)?;
    test_package(root, "cser-trace-conformance", false)?;
    test_package(root, "nexus-effect-peer-wire", false)?;
    section("test the production workflow runner");
    cargo(
        root,
        &[
            "test",
            "--locked",
            "--manifest-path",
            "tools/xtask/Cargo.toml",
        ],
    )
}

fn verify(root: &Path) -> Result<()> {
    fmt_check(root)?;
    check(root)?;
    clippy(root)?;
    test(root)?;
    println!(
        "CSER CORE VERIFY PASS portable_core=true independent_oracle=true loom=true journal_recovery=true frozen_wire=archive-only"
    );
    Ok(())
}

fn cargo_package(root: &Path, verb: &str, package: &str, all_features: bool) -> Result<()> {
    section(&format!("{verb} {package}"));
    let mut args = vec![verb, "--locked", "-p", package, "--all-targets"];
    if all_features {
        args.push("--all-features");
    }
    cargo(root, &args)
}

fn clippy_package(root: &Path, package: &str, all_features: bool) -> Result<()> {
    section(&format!("clippy {package}"));
    let mut args = vec!["clippy", "--locked", "-p", package, "--all-targets"];
    if all_features {
        args.push("--all-features");
    }
    args.extend(["--", "-D", "warnings"]);
    cargo(root, &args)
}

fn test_package(root: &Path, package: &str, all_features: bool) -> Result<()> {
    section(&format!("test {package}"));
    let mut args = vec!["test", "--locked", "-p", package, "--all-targets"];
    if all_features {
        args.push("--all-features");
    }
    args.push("--no-fail-fast");
    cargo(root, &args)
}

fn assert_cutover(root: &Path) -> Result<()> {
    let script = root.join("kernel/nexus-ostd/scripts/assert-cser-core-production-cutover.sh");
    let script = script
        .to_str()
        .ok_or("production cutover script path is not UTF-8")?;
    let root_text = root.to_str().ok_or("repository root path is not UTF-8")?;
    run(root, script, &[root_text])
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
