use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub(crate) struct Summary {
    pub(crate) shell_sources: usize,
    pub(crate) pinned_actions: usize,
}

pub(crate) fn validate(root: &Path) -> Result<Summary> {
    let files = repository_files(root)?;
    let mut shell_sources = 0;
    for relative in files.iter().filter(|path| shell_source(path)) {
        validate_shell_declaration(root, relative)?;
        shell_sources += 1;
    }
    if shell_sources == 0 {
        return Err("no shell workflow sources were discovered".into());
    }

    let workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))?;
    validate_workflow_yaml(&workflow)?;
    validate_checkout_fetch_depth(&workflow)?;
    for required in [
        "workflow_dispatch:",
        "concurrency:",
        "run: ./x verify",
        "target/verification/manifest.json",
        "target/verification/.stage7a-verify-start.json",
        "target/verification/.stage7a-verify-complete.json",
        "target/verification/stage7b",
        "include-hidden-files: true",
    ] {
        if !workflow.contains(required) {
            return Err(format!("CI workflow is missing Stage 7A contract: {required}").into());
        }
    }
    let pinned_actions = validate_pinned_actions(&workflow)?;

    let frontdoor = fs::read_to_string(root.join("x"))?;
    validate_full_verify_order(&frontdoor)?;

    let dockerfile = fs::read_to_string(root.join("Dockerfile"))?;
    for required in [
        "@sha256:",
        "TLA2TOOLS_SHA256",
        "GIT_PACKAGE_VERSION",
        "CARGO_NET_OFFLINE=true",
    ] {
        if !dockerfile.contains(required) {
            return Err(format!("root Dockerfile is missing pinned boundary: {required}").into());
        }
    }

    let readme = fs::read_to_string(root.join("README.md"))?;
    for command in ["doctor", "build", "test", "run", "verify", "clean"] {
        if !readme.contains(&format!("./x {command}")) {
            return Err(format!("README lacks public command: ./x {command}").into());
        }
    }

    for (args, label) in [
        (
            &["diff", "--check"][..],
            "git diff --check rejected the working tree",
        ),
        (
            &["diff", "--cached", "--check"][..],
            "git diff --cached --check rejected the staged snapshot",
        ),
        (
            // Treat pure moves as renames so historical whitespace in an
            // unchanged file is not misclassified as newly added content.
            &[
                "diff-tree",
                "--check",
                "--no-commit-id",
                "--root",
                "-r",
                "-m",
                "-M",
                "HEAD",
            ][..],
            "git diff-tree --check rejected the checked-out revision",
        ),
    ] {
        let status = Command::new("git").current_dir(root).args(args).status()?;
        if !status.success() {
            return Err(label.into());
        }
    }

    Ok(Summary {
        shell_sources,
        pinned_actions,
    })
}

fn validate_full_verify_order(frontdoor: &str) -> Result<()> {
    let (_, tail) = frontdoor
        .split_once("verify_all() {")
        .ok_or("root workflow lacks verify_all")?;
    let (body, _) = tail
        .split_once("\n}")
        .ok_or("root verify_all body is not terminated")?;
    for required in [
        "local verify_token",
        "NEXUS_VERIFY_INVOCATION",
        "run_xtask begin",
        "run_xtask verify",
        "run_system",
        "eval-stage7b",
        "run_xtask stage7b-evidence",
        "run_xtask complete",
        "run_xtask manifest",
    ] {
        if !body.contains(required) {
            return Err(format!("root verify_all lacks ordered stage: {required}").into());
        }
    }
    let mut remainder = body;
    for stage in [
        "run_xtask begin",
        "run_xtask verify",
        "run_system",
        "eval-stage7b",
        "run_xtask stage7b-evidence",
        "run_xtask complete",
        "run_xtask manifest",
    ] {
        let (_, after) = remainder
            .split_once(stage)
            .ok_or_else(|| format!("root verify_all stage is missing or out of order: {stage}"))?;
        remainder = after;
    }
    if !frontdoor.contains("token_environment=(--env \"NEXUS_VERIFY_TOKEN=$verify_token\")") {
        return Err(
            "root workflow does not pass its orchestration token to evidence sealing".into(),
        );
    }
    if !frontdoor
        .contains("if [[ $command == begin || $command == complete || $command == manifest ]]")
    {
        return Err(
            "root workflow does not restrict token injection to begin/complete/manifest".into(),
        );
    }
    Ok(())
}

fn validate_workflow_yaml(workflow: &str) -> Result<()> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(workflow)
        .map_err(|error| format!("CI workflow is not valid YAML: {error}"))?;
    if !matches!(parsed, serde_yaml::Value::Mapping(_)) {
        return Err("CI workflow must be a top-level YAML mapping".into());
    }
    Ok(())
}

fn validate_checkout_fetch_depth(workflow: &str) -> Result<usize> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(workflow)
        .map_err(|error| format!("CI workflow is not valid YAML: {error}"))?;
    let jobs = yaml_field(&parsed, "jobs")
        .and_then(serde_yaml::Value::as_mapping)
        .ok_or("CI workflow jobs must be a mapping")?;
    let mut checkouts = 0;
    for job in jobs.values() {
        let Some(steps) = yaml_field(job, "steps").and_then(serde_yaml::Value::as_sequence) else {
            continue;
        };
        for step in steps {
            let Some(uses) = yaml_field(step, "uses").and_then(serde_yaml::Value::as_str) else {
                continue;
            };
            if !uses.starts_with("actions/checkout@") {
                continue;
            }
            checkouts += 1;
            let depth = yaml_field(step, "with").and_then(|with| yaml_field(with, "fetch-depth"));
            let unshallow = match depth {
                Some(serde_yaml::Value::Number(number)) => number.as_u64() == Some(0),
                Some(serde_yaml::Value::String(value)) => value == "0",
                _ => false,
            };
            if !unshallow {
                return Err("every actions/checkout step must set fetch-depth: 0".into());
            }
        }
    }
    if checkouts == 0 {
        return Err("CI workflow has no actions/checkout step".into());
    }
    Ok(checkouts)
}

fn yaml_field<'a>(value: &'a serde_yaml::Value, field: &str) -> Option<&'a serde_yaml::Value> {
    value
        .as_mapping()?
        .get(serde_yaml::Value::String(String::from(field)))
}

fn validate_pinned_actions(workflow: &str) -> Result<usize> {
    let mut pinned_actions = 0;
    let mut has_checkout = false;
    let mut has_evidence_upload = false;

    for line in workflow.lines() {
        let entry = line.trim();
        let entry = entry.strip_prefix("- ").unwrap_or(entry).trim_start();
        let Some(uses) = entry.strip_prefix("uses:") else {
            continue;
        };
        let uses = uses
            .split_whitespace()
            .next()
            .ok_or("CI action uses entry is empty")?;
        let Some((action, revision)) = uses.rsplit_once('@') else {
            return Err(format!("CI action is not pinned: {uses}").into());
        };
        if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("CI action is not pinned to a 40-hex commit: {uses}").into());
        }

        has_checkout |= action == "actions/checkout";
        has_evidence_upload |= action == "actions/upload-artifact";
        pinned_actions += 1;
    }

    if !has_checkout {
        return Err("CI must pin an actions/checkout action".into());
    }
    if !has_evidence_upload {
        return Err("CI must pin an actions/upload-artifact evidence action".into());
    }

    Ok(pinned_actions)
}

fn repository_files(root: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .current_dir(root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!("git ls-files failed with {}", output.status).into());
    }
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| PathBuf::from(String::from_utf8_lossy(bytes).into_owned()))
        .filter(|path| root.join(path).is_file())
        .collect())
}

fn shell_source(path: &Path) -> bool {
    path == Path::new("x")
        || path.file_name().is_some_and(|name| name == "x")
        || path.extension().is_some_and(|extension| extension == "sh")
}

fn validate_shell_declaration(root: &Path, relative: &Path) -> Result<()> {
    let path = root.join(relative);
    let source = fs::read_to_string(&path)?;
    let shebang = source.lines().next().unwrap_or("");
    if !shebang.contains("bash") && !shebang.ends_with("/sh") && !shebang.contains("/sh ") {
        return Err(format!(
            "workflow shell source has no supported shebang: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn classifies_only_public_and_script_shell_sources() {
        assert!(shell_source(Path::new("x")));
        assert!(shell_source(Path::new("kernel/nexus-ostd/x")));
        assert!(shell_source(Path::new("scripts/check.sh")));
        assert!(!shell_source(Path::new("src/lib.rs")));
        assert!(!shell_source(Path::new("guest/probe.S")));
    }

    #[test]
    fn rejects_syntactically_invalid_workflow_yaml() {
        let error = validate_workflow_yaml("jobs:\n  invalid: [\n")
            .expect_err("invalid YAML must be rejected")
            .to_string();
        assert!(error.contains("not valid YAML"));
    }

    #[test]
    fn requires_every_checkout_to_fetch_its_parent_history() {
        let valid = format!(
            "jobs:\n  one:\n    steps:\n      - uses: actions/checkout@{SHA}\n        with:\n          fetch-depth: 0\n  two:\n    steps:\n      - uses: actions/checkout@{SHA}\n        with:\n          fetch-depth: '0'\n"
        );
        assert_eq!(validate_checkout_fetch_depth(&valid).unwrap(), 2);

        let shallow = format!(
            "jobs:\n  one:\n    steps:\n      - uses: actions/checkout@{SHA}\n        with:\n          fetch-depth: 1\n"
        );
        let error = validate_checkout_fetch_depth(&shallow)
            .expect_err("shallow checkout must be rejected")
            .to_string();
        assert!(error.contains("fetch-depth: 0"));
    }

    #[test]
    fn accepts_list_form_actions_pinned_to_full_commits() {
        let workflow = format!(
            "steps:\n  - uses: actions/checkout@{SHA}\n  - uses: actions/upload-artifact@{SHA}\n"
        );

        assert_eq!(validate_pinned_actions(&workflow).unwrap(), 2);
    }

    #[test]
    fn rejects_checkout_pinned_to_a_branch() {
        let workflow = format!(
            "steps:\n  - uses: actions/checkout@main\n  - uses: actions/upload-artifact@{SHA}\n"
        );

        let error = validate_pinned_actions(&workflow).unwrap_err().to_string();
        assert!(error.contains("not pinned to a 40-hex commit"));
    }

    #[test]
    fn requires_checkout_and_evidence_upload_actions_individually() {
        let workflow = format!("steps:\n  - uses: vendor/one@{SHA}\n  - uses: vendor/two@{SHA}\n");

        let error = validate_pinned_actions(&workflow).unwrap_err().to_string();
        assert!(error.contains("actions/checkout"));
    }

    #[test]
    fn requires_the_full_verify_receipt_order() {
        let prefix = r#"
	run_xtask() {
	    if [[ $command == begin || $command == complete || $command == manifest ]]; then
	    token_environment=(--env "NEXUS_VERIFY_TOKEN=$verify_token")
	    fi
	}
verify_all() {
    local verify_token
    export NEXUS_VERIFY_INVOCATION=./x-verify
"#;
        let suffix = "\n}\n";
        let ordered = format!(
            "{prefix}run_xtask begin\nrun_xtask verify\nrun_system\nrun_backend kernel eval-stage7b\nrun_xtask stage7b-evidence\nrun_xtask complete\nrun_xtask manifest{suffix}"
        );
        validate_full_verify_order(&ordered).expect("ordered full verify");

        let spliced = format!(
            "{prefix}run_xtask begin\nrun_xtask verify\nrun_xtask complete\nrun_system\nrun_backend kernel eval-stage7b\nrun_xtask stage7b-evidence\nrun_xtask manifest{suffix}"
        );
        let error = validate_full_verify_order(&spliced)
            .expect_err("completion before system must be rejected")
            .to_string();
        assert!(error.contains("missing or out of order"));
    }
}
