mod system;

use std::env;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const BARE_METAL_TARGET: &str = "x86_64-unknown-none";
const PUBLIC_RECEIPT: &str = "combined-receipt.txt";
const PUBLIC_CHECKSUM: &str = "combined-receipt.sha256";

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
        "seal" if option.is_none() => seal(&root),
        "clean" => clean(&root, option.as_deref()),
        _ => Err(usage().into()),
    }
}

fn usage() -> String {
    "usage: cargo nexus <check|test|kernel|system|seal|clean>".into()
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
    system::run(root).map(|_| ())
}

fn seal(root: &Path) -> Result<()> {
    require_clean_source(root)?;
    let _lock = system::lock(root)?;
    let public = prepare_public_incomplete(root)?;
    let (snapshot, revision) = archive_snapshot(root)?;
    let result = match system::seal_from(&snapshot, root, &revision) {
        Ok(_) => {
            move_raw_artifacts(&snapshot, root)?;
            publish_receipt(root, &public)
        }
        Err(error) => {
            let staged = snapshot.join("kernel/nexus-ostd/artifacts/cser-production");
            if staged.is_dir()
                && let Err(move_error) = move_raw_artifacts(&snapshot, root)
            {
                return Err(format!(
                    "{error}; incomplete raw evidence remains at {} because it could not be moved: {move_error}",
                    snapshot.display()
                )
                .into());
            }
            Err(error)
        }
    };
    let _ = fs::remove_dir_all(&snapshot);
    result
}

fn clean(root: &Path, option: Option<&str>) -> Result<()> {
    if !matches!(option, None | Some("--raw")) {
        return Err("usage: cargo nexus clean [--raw]".into());
    }
    let _lock = system::lock(root)?;
    section("clean portable workspace");
    cargo(root, &["clean"])?;
    system::clean(root, option == Some("--raw"))
}

fn prepare_public_incomplete(root: &Path) -> Result<PathBuf> {
    let public = root.join("target/nexus/public");
    if public.exists() {
        fs::remove_dir_all(&public)?;
    }
    fs::create_dir_all(&public)?;
    atomic_write(&public.join("INCOMPLETE"), b"INCOMPLETE\n")?;
    Ok(public)
}

fn archive_snapshot(root: &Path) -> Result<(PathBuf, String)> {
    let resolved = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "--verify", "HEAD^{commit}"])
        .output()?;
    if !resolved.status.success() {
        return Err(format!("git rev-parse HEAD failed with {}", resolved.status).into());
    }
    let revision = String::from_utf8(resolved.stdout)?.trim().to_owned();
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("git resolved a malformed seal revision".into());
    }
    let snapshot = root.join(format!("target/nexus/seal-{}", std::process::id()));
    if snapshot.exists() {
        return Err(format!("seal snapshot already exists: {}", snapshot.display()).into());
    }
    fs::create_dir_all(&snapshot)?;
    let result: Result<()> = (|| {
        let archive = Command::new("git")
            .current_dir(root)
            .args(["archive", "--format=tar", &revision])
            .output()?;
        if !archive.status.success() {
            return Err(format!("git archive {revision} failed with {}", archive.status).into());
        }
        let mut extract = Command::new("tar")
            .current_dir(root)
            .args(["-xf", "-", "-C"])
            .arg(&snapshot)
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        extract
            .stdin
            .as_mut()
            .ok_or("tar archive input is unavailable")?
            .write_all(&archive.stdout)?;
        if !extract.wait()?.success() {
            return Err("git archive extraction failed".into());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&snapshot);
    }
    result?;
    Ok((snapshot, revision))
}

fn move_raw_artifacts(snapshot: &Path, root: &Path) -> Result<()> {
    let staged = snapshot.join("kernel/nexus-ostd/artifacts/cser-production");
    let raw = root.join("kernel/nexus-ostd/artifacts/cser-production");
    if !staged.is_dir() {
        return Err(format!(
            "sealed raw artifact directory is missing: {}",
            staged.display()
        )
        .into());
    }
    if let Some(parent) = raw.parent() {
        fs::create_dir_all(parent)?;
    }
    if raw.exists() {
        fs::remove_dir_all(&raw)?;
    }
    fs::rename(staged, raw)?;
    Ok(())
}

fn publish_receipt(root: &Path, public: &Path) -> Result<()> {
    let raw = root.join("kernel/nexus-ostd/artifacts/cser-production");
    let receipt = fs::read(raw.join("combined-receipt.txt"))?;
    let checksum = fs::read(raw.join("combined-receipt.sha256"))?;
    ensure_public_incomplete(public)?;
    atomic_write(&public.join(PUBLIC_RECEIPT), &receipt)?;
    atomic_write(&public.join(PUBLIC_CHECKSUM), &checksum)?;
    let mut names = fs::read_dir(public)?
        .map(|entry| entry.map(|value| value.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    let expected = ["INCOMPLETE", PUBLIC_CHECKSUM, PUBLIC_RECEIPT].map(std::ffi::OsString::from);
    if names != expected {
        return Err("public receipt staging contains an unexpected file".into());
    }
    let verified = Command::new("sha256sum")
        .current_dir(public)
        .args(["-c", PUBLIC_CHECKSUM])
        .stdout(std::process::Stdio::null())
        .status()?;
    if !verified.success() {
        return Err("public receipt checksum verification failed".into());
    }
    fs::remove_file(public.join("INCOMPLETE"))?;
    fs::File::open(public)?.sync_all()?;
    println!("NEXUS SEAL PASS public_receipt={}", public.display());
    Ok(())
}

fn ensure_public_incomplete(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let name = entry?.file_name();
        if name != "INCOMPLETE" {
            return Err(format!(
                "public receipt directory is not incomplete: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn require_clean_source(root: &Path) -> Result<()> {
    let status = Command::new("git")
        .current_dir(root)
        .args([
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            ".",
            ":(exclude)target/**",
            ":(exclude)kernel/nexus-ostd/target/**",
            ":(exclude)kernel/nexus-ostd/artifacts/**",
        ])
        .output()?;
    if !status.status.success() {
        return Err(format!("git status failed with {}", status.status).into());
    }
    if !status.stdout.is_empty() {
        return Err("production receipt seal rejected: source tree is dirty".into());
    }
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("receipt path has no parent")?;
    let name = path.file_name().ok_or("receipt path has no file name")?;
    let temporary = parent.join(format!(
        ".{}-{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result: Result<()> = (|| {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
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
