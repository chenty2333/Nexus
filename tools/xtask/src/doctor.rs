use std::error::Error;
use std::path::Path;
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const REQUIRED_PATHS: &[&str] = &[
    "Cargo.toml",
    "Dockerfile",
    "x",
    ".github/workflows/ci.yml",
    "crates/cser-model/Cargo.toml",
    "crates/cser-transition-gates/tests/production_registry.rs",
    "crates/nexus-effect-peer/Cargo.toml",
    "crates/nexus-portal-abi/Cargo.toml",
    "crates/nexus-supervisor/Cargo.toml",
    "crates/nexus-ostd-virtio/Cargo.toml",
    "kernel/nexus-ostd/Cargo.toml",
    "experiments/ostd-virtio-cser-spike/Cargo.toml",
    "patches/ostd-0.18.0-cser.patch",
    "patches/virtio-drivers-0.13.0-cser.patch",
    "patches/virtio-drivers-0.13.0-LICENSE-MIT",
    "patches/cser-cargo-config.toml",
    "tools/ostd/assert-cser-patch.sh",
    "tools/virtio/assert-cser-patch.sh",
    "tools/virtio/assert-production-substrate.sh",
    "tools/workflow/system-composition.sh",
    "tools/workflow/runtime-fs-composition.sh",
    "tools/workflow/linux-io-composition.sh",
    "specs/oracles/cser-races.toml",
    "evaluation/stage7b/contract.toml",
    "evaluation/stage7b/cser-races.toml",
    "evaluation/stage7b/prior-art.toml",
    "evaluation/stage7b/README.md",
    "evaluation/production-identity/causal-coverage.toml",
    "tools/xtask/src/stage7b.rs",
    "tools/xtask/src/stage7b_concurrency.rs",
    "tools/xtask/src/stage7b_contribution.rs",
    "tools/xtask/src/stage7b_evidence.rs",
    "tools/xtask/src/stage7b_prior_art.rs",
    "kernel/nexus-ostd/src/evaluation/stage7b.rs",
    "experiments/ostd-virtio-cser-spike/scripts/check-io-gate.sh",
    "specs/cser/RuntimeNetCserSafetyMC.cfg",
    "specs/cser/RuntimeNetCserMC.cfg",
    "specs/cser/RUNTIME_NET.md",
    "specs/cser/LinuxIoCompositionCserSafetyMC.cfg",
    "specs/cser/LinuxIoCompositionCserMC.cfg",
    "specs/cser/LinuxIoCompositionCserFallbackMC.cfg",
    "specs/cser/LINUX_IO_COMPOSITION.md",
    "tests/guest/linux/SOURCES.toml",
];

pub(crate) fn run(root: &Path, specs: &[&str]) -> Result<()> {
    for relative in REQUIRED_PATHS {
        let path = root.join(relative);
        if !path.is_file() {
            return Err(format!("required acceptance path is missing: {}", path.display()).into());
        }
    }
    for spec in specs {
        let path = root.join("specs/cser").join(format!("{spec}.tla"));
        if !path.is_file() {
            return Err(
                format!("required TLA+ specification is missing: {}", path.display()).into(),
            );
        }
    }

    let rustc = version("rustc", &["--version"])?;
    let cargo = version("cargo", &["--version"])?;
    let git = version("git", &["--version"])?;
    let java = version("java", &["-version"])?;
    let jar = crate::evidence::pinned_tla2tools_jar(root)?;

    println!(
        "DOCTOR PASS layout=stage7a+linux-io-composition+stage7b specs={} rustc={:?} cargo={:?} git={:?} java={:?} tla2tools={}",
        specs.len(),
        first_line(&rustc),
        first_line(&cargo),
        first_line(&git),
        first_line(&java),
        jar.display()
    );
    Ok(())
}

fn version(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(format!("{program} version probe failed with {}", output.status).into());
    }
    let mut text = String::from_utf8(output.stdout)?;
    text.push_str(&String::from_utf8(output.stderr)?);
    Ok(text)
}

fn first_line(value: &str) -> &str {
    value.lines().next().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_line_is_stable_for_empty_and_multiline_versions() {
        assert_eq!(first_line(""), "");
        assert_eq!(first_line("one\ntwo\n"), "one");
    }
}
