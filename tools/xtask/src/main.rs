use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

mod catalog;
mod current_status;
mod doctor;
mod evidence;
mod guest;
mod handoff_admission;
mod production_identity;
mod scenario;
mod stage7b;
mod stage7b_concurrency;
mod stage7b_contribution;
mod stage7b_evidence;
mod stage7b_prior_art;
mod workflow;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const TRACE_ACTIONS: [&str; 9] = [
    "CreateScope",
    "Register",
    "Prepare",
    "Crash",
    "FallbackPick",
    "Rebind",
    "Adopt",
    "Commit",
    "Complete",
];

const TLA_SPECS: [&str; 12] = [
    "Cser",
    "PagerCser",
    "IoCser",
    "PersonalityCser",
    "PersonalityFutexCser",
    "PersonalityFutexRequeueCser",
    "PersonalityReadinessCser",
    "PersonalityExecCser",
    "RuntimeFsCser",
    "RuntimeNetCser",
    "CompositionCser",
    "LinuxIoCompositionCser",
];

static NEXT_SPEC_WORKSPACE: AtomicU64 = AtomicU64::new(0);

fn main() {
    if let Err(error) = real_main() {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    }
}

#[derive(Debug, Eq, PartialEq)]
enum XtaskInvocation {
    Command(String),
    VerifyBundle(Option<PathBuf>),
    HandoffAdmissionResearch,
    ProductionIdentityResearch,
}

fn real_main() -> Result<()> {
    let root = repo_root();
    match parse_invocation(env::args().skip(1))? {
        XtaskInvocation::HandoffAdmissionResearch => handoff_admission::run(&root, &TLA_SPECS),
        XtaskInvocation::ProductionIdentityResearch => production_identity::run(&root, &TLA_SPECS),
        XtaskInvocation::VerifyBundle(argument) => {
            let path =
                argument.unwrap_or_else(|| PathBuf::from("target/verification/artifact-bundle"));
            let path = if path.is_absolute() {
                path
            } else {
                root.join(path)
            };
            evidence::verify_bundle(&root, &path, &TLA_SPECS)
        }
        XtaskInvocation::Command(command) => match command.as_str() {
            "build" => build(&root),
            "doctor" => doctor(&root),
            "begin" => evidence::begin(&root, &TLA_SPECS).map(|_| ()),
            "fmt" => fmt(&root),
            "check" => check(&root),
            "test" => test(&root),
            "quick" => model(&root),
            "model" => model(&root),
            "spec" => spec(&root),
            "verify" => {
                model(&root)?;
                spec(&root)?;
                evidence::mark_model_spec_complete(&root, &TLA_SPECS).map(|_| ())
            }
            "complete" => evidence::complete(&root, &TLA_SPECS).map(|_| ()),
            "manifest" => evidence::write(&root, &TLA_SPECS).map(|_| ()),
            "bundle" => evidence::write_bundle(&root, &TLA_SPECS).map(|_| ()),
            "stage7b-evidence" => stage7b_evidence_all(&root),
            "help" | "-h" | "--help" => {
                print_usage();
                Ok(())
            }
            _ => Err(format!("unknown command: {command}").into()),
        },
    }
}

fn parse_invocation(mut args: impl Iterator<Item = String>) -> Result<XtaskInvocation> {
    let command = args.next().unwrap_or_else(|| String::from("help"));
    let arguments: Vec<_> = args.collect();
    match (command.as_str(), arguments.as_slice()) {
        ("verify-bundle", []) => Ok(XtaskInvocation::VerifyBundle(None)),
        ("verify-bundle", [path]) => Ok(XtaskInvocation::VerifyBundle(Some(PathBuf::from(path)))),
        ("verify-bundle", [_, extra, ..]) => Err(format!("unexpected argument: {extra}").into()),
        ("research", [target]) if target == "production-identity" => {
            Ok(XtaskInvocation::ProductionIdentityResearch)
        }
        ("research", [target]) if target == "handoff-admission" => {
            Ok(XtaskInvocation::HandoffAdmissionResearch)
        }
        ("research", []) => {
            Err("research requires target production-identity or handoff-admission".into())
        }
        ("research", [target]) => Err(format!("unknown research target: {target}").into()),
        ("research", [_, extra, ..]) => Err(format!("unexpected argument: {extra}").into()),
        (_, []) => Ok(XtaskInvocation::Command(command)),
        (_, [argument, ..]) => Err(format!("unexpected argument: {argument}").into()),
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
    eprintln!("commands: doctor build fmt check test quick model spec verify verify-bundle");
    eprintln!("prospective research: research production-identity|handoff-admission");
    eprintln!("internal evidence commands: begin stage7b-evidence complete manifest bundle");
}

fn stage7b_evidence_all(root: &Path) -> Result<()> {
    let concurrency = stage7b_concurrency::run(root)
        .map_err(|error| format!("Stage 7B concurrency evidence: {error}"))?;
    let runtime = stage7b_evidence::run(root)
        .map_err(|error| format!("Stage 7B runtime evidence: {error}"))?;
    let prior = stage7b_prior_art::run(root)
        .map_err(|error| format!("Stage 7B prior-art evidence: {error}"))?;
    let contribution = stage7b_contribution::run(root)
        .map_err(|error| format!("Stage 7B contribution decision: {error}"))?;
    println!(
        "STAGE7B EVIDENCE PASS races={} fault_cells={} scale_points={} performance_cases={} prior_art_rows={} verdict={}",
        concurrency.races,
        runtime.fault_cells,
        runtime.scale_points,
        runtime.performance_cases,
        prior.rows,
        contribution.verdict,
    );
    Ok(())
}

fn doctor(root: &Path) -> Result<()> {
    section("validate Stage 7A repository, Stage 7B static contract, and pinned toolchain");
    doctor::run(root, &TLA_SPECS)?;
    let oracle_count =
        catalog::validate_all(root).map_err(|error| format!("oracle schema: {error}"))?;
    let scenario_count =
        scenario::validate_all(root).map_err(|error| format!("runner schema: {error}"))?;
    let guest = guest::validate(root).map_err(|error| format!("Linux guest catalog: {error}"))?;
    let stage7b =
        stage7b::validate(root).map_err(|error| format!("Stage 7B static contract: {error}"))?;
    let prior_art = stage7b_prior_art::check(root)
        .map_err(|error| format!("Stage 7B prior-art truth source: {error}"))?;
    println!(
        "DOCTOR CATALOGS PASS oracles={oracle_count} scenarios={scenario_count} guest_sources={} guest_workloads={}",
        guest.sources, guest.workloads
    );
    println!(
        "DOCTOR STAGE7B STATIC PASS races={} fault_cells={} scale_points={} performance_cases={} prior_art_rows={}",
        stage7b.races,
        stage7b.fault_cells,
        stage7b.scale_points,
        stage7b.performance_cases,
        stage7b.prior_art_rows,
    );
    println!(
        "DOCTOR STAGE7B PRIOR ART PASS rows={} full_text={} metadata_only={} verdict={}",
        prior_art.rows, prior_art.full_text, prior_art.metadata_only, prior_art.default_verdict,
    );
    Ok(())
}

fn build(root: &Path) -> Result<()> {
    section("build cser-model for the host");
    cargo(
        root,
        ["build", "--locked", "-p", "cser-model", "--all-features"],
    )?;
    section("build cser-model for the bare-metal target without std");
    cargo(
        root,
        [
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
    section("format Rust workspaces");
    cargo(root, ["fmt", "--all"])?;
    cargo(root, ["fmt", "--manifest-path", "tools/xtask/Cargo.toml"])
}

fn fmt_check(root: &Path) -> Result<()> {
    section("check Rust formatting");
    cargo(root, ["fmt", "--all", "--", "--check"])?;
    cargo(
        root,
        [
            "fmt",
            "--manifest-path",
            "tools/xtask/Cargo.toml",
            "--",
            "--check",
        ],
    )
}

fn check(root: &Path) -> Result<()> {
    section("validate current capability and native-wire status");
    let current = current_status::validate(root)
        .map_err(|error| format!("current capability status: {error}"))?;
    println!(
        "current capability status: PASS ({} checkpoints: {} local, {} external; {} frozen wire contract)",
        current.checkpoints, current.local, current.external, current.frozen_wire_contracts,
    );

    section("validate repository workflow surfaces");
    let workflow = workflow::validate(root)?;
    println!(
        "workflow surfaces: PASS ({} shell sources, {} pinned CI actions)",
        workflow.shell_sources, workflow.pinned_actions
    );
    let prior_art = stage7b_prior_art::check(root)
        .map_err(|error| format!("Stage 7B prior-art truth source: {error}"))?;
    println!(
        "Stage 7B prior-art truth source: PASS ({} rows, {} full-text, {} metadata-only, verdict={})",
        prior_art.rows, prior_art.full_text, prior_art.metadata_only, prior_art.default_verdict,
    );

    section("validate implementation-neutral oracle catalogs");
    let oracle_count =
        catalog::validate_all(root).map_err(|error| format!("oracle schema: {error}"))?;
    println!("oracle catalogs: PASS ({oracle_count} entries)");

    section("validate Stage 7B static acceptance contract");
    let stage7b =
        stage7b::validate(root).map_err(|error| format!("Stage 7B static contract: {error}"))?;
    println!(
        "Stage 7B static contract: PASS ({} races, {} fault cells, {} scale points, {} performance cases, {} prior-art rows)",
        stage7b.races,
        stage7b.fault_cells,
        stage7b.scale_points,
        stage7b.performance_cases,
        stage7b.prior_art_rows,
    );

    section("validate neutral runner scenarios");
    let scenario_count =
        scenario::validate_all(root).map_err(|error| format!("runner schema: {error}"))?;
    println!("runner scenarios: PASS ({scenario_count} scenarios)");

    section("validate retained Linux guest inputs");
    let guest = guest::validate(root).map_err(|error| format!("Linux guest catalog: {error}"))?;
    println!(
        "Linux guest catalogs: PASS ({} sources, {} workloads)",
        guest.sources, guest.workloads
    );

    section("check workflow runner");
    cargo(
        root,
        [
            "check",
            "--locked",
            "--manifest-path",
            "tools/xtask/Cargo.toml",
            "--all-targets",
        ],
    )?;

    section("check production transition gates");
    cargo(
        root,
        [
            "check",
            "--locked",
            "-p",
            "cser-transition-gates",
            "--all-targets",
        ],
    )?;

    section("check production effect peer");
    cargo(
        root,
        [
            "check",
            "--locked",
            "-p",
            "nexus-effect-peer",
            "--all-targets",
        ],
    )?;

    section("check cser-model on the bare-metal target without std");
    cargo(
        root,
        [
            "check",
            "--locked",
            "-p",
            "cser-model",
            "--no-default-features",
            "--lib",
            "--target",
            "x86_64-unknown-none",
        ],
    )?;

    section("check all cser-model targets");
    cargo(
        root,
        [
            "check",
            "--locked",
            "-p",
            "cser-model",
            "--all-targets",
            "--all-features",
        ],
    )
}

fn clippy(root: &Path) -> Result<()> {
    section("clippy neutral workflow runner");
    cargo(
        root,
        [
            "clippy",
            "--locked",
            "--manifest-path",
            "tools/xtask/Cargo.toml",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;

    section("clippy production transition gates");
    cargo(
        root,
        [
            "clippy",
            "--locked",
            "-p",
            "cser-transition-gates",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;

    section("clippy production effect peer");
    cargo(
        root,
        [
            "clippy",
            "--locked",
            "-p",
            "nexus-effect-peer",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;

    section("clippy cser-model on the bare-metal target without std");
    cargo(
        root,
        [
            "clippy",
            "--locked",
            "-p",
            "cser-model",
            "--no-default-features",
            "--lib",
            "--target",
            "x86_64-unknown-none",
            "--",
            "-D",
            "warnings",
        ],
    )?;

    section("clippy all cser-model targets");
    cargo(
        root,
        [
            "clippy",
            "--locked",
            "-p",
            "cser-model",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )
}

fn test(root: &Path) -> Result<()> {
    section("test cser-model");
    cargo(
        root,
        ["test", "--locked", "-p", "cser-model", "--all-features"],
    )?;

    section("test production transition gates");
    cargo(
        root,
        [
            "test",
            "--locked",
            "-p",
            "cser-transition-gates",
            "--all-targets",
            "--no-fail-fast",
        ],
    )?;

    section("test production effect peer");
    cargo(
        root,
        [
            "test",
            "--locked",
            "-p",
            "nexus-effect-peer",
            "--all-targets",
            "--no-fail-fast",
        ],
    )?;

    section("test neutral workflow runner");
    cargo(
        root,
        [
            "test",
            "--locked",
            "--manifest-path",
            "tools/xtask/Cargo.toml",
        ],
    )?;

    section("execute checked-in neutral runner scenarios");
    let count = scenario::run_all(root).map_err(|error| format!("runner scenario: {error}"))?;
    println!("runner execution: PASS ({count} scenarios)");
    Ok(())
}

fn model(root: &Path) -> Result<()> {
    fmt_check(root)?;
    check(root)?;
    clippy(root)?;
    test(root)?;
    canonical_trace(root)
}

fn canonical_trace(root: &Path) -> Result<()> {
    section("check canonical cser-model trace");
    let output = cargo_output(
        root,
        [
            "run",
            "--quiet",
            "--locked",
            "-p",
            "cser-model",
            "--all-features",
            "--bin",
            "cser-model",
        ],
    )?;
    replay_output(&output)?;

    let stdout = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = stdout.lines().filter(|line| !line.is_empty()).collect();
    if lines.len() != TRACE_ACTIONS.len() {
        return Err(format!(
            "canonical trace has {} events; expected {}",
            lines.len(),
            TRACE_ACTIONS.len()
        )
        .into());
    }

    for (seq, (line, action)) in lines.iter().zip(TRACE_ACTIONS).enumerate() {
        let expected = format!("seq: {seq}, action: {action},");
        if !line.contains(&expected) {
            return Err(format!(
                "canonical trace event {seq} does not contain {expected:?}: {line}"
            )
            .into());
        }
    }

    println!("canonical trace: PASS ({} ordered events)", lines.len());
    Ok(())
}

fn spec(root: &Path) -> Result<()> {
    let jar = tla2tools_jar()?;
    let artifact_dir = root.join("target/verification");
    fs::create_dir_all(&artifact_dir)?;
    let _lock = SpecRunLock::acquire(&artifact_dir.join(".spec.lock"))?;
    let source_cser_dir = root.join("specs/cser");
    let workspace = IsolatedSpecWorkspace::create(&source_cser_dir)?;

    for spec in TLA_SPECS {
        pluscal_translation_is_current(
            &source_cser_dir,
            workspace.cser_dir(),
            &jar,
            spec,
            &artifact_dir.join(format!("{spec}-pluscal.log")),
        )?;
    }

    for spec in TLA_SPECS {
        section(&format!("run TLC for {spec}"));
        let mut command = Command::new("sh");
        command
            .current_dir(workspace.cser_dir())
            .env("TLA2TOOLS_JAR", &jar)
            .env("TMPDIR", workspace.temp_dir())
            .arg(workspace.cser_dir().join("check.sh"))
            .arg(spec);
        run_bounded_logged(
            &mut command,
            &artifact_dir.join(format!("{spec}-tlc.log")),
            spec_timeout(spec),
            8 * 1024 * 1024,
        )?;
    }
    Ok(())
}

fn spec_timeout(spec: &str) -> Duration {
    Duration::from_secs(match spec {
        // The three-ID I/O safety quotient explores about 22 million states
        // before the two witness gates and action graph. Keep a cold/shared-
        // host run from being mislabeled as a failure.
        "IoCser" => 1_800,
        "RuntimeFsCser" => 900,
        "RuntimeNetCser" => 900,
        "CompositionCser" => 600,
        // This family deliberately performs a full reject-enabled safety and
        // action traversal, ten distinct witnesses across six reachability
        // traversals, and two non-vacuous liveness quotients. Four-core CI is
        // substantially slower than the pinned 16-core development host.
        "LinuxIoCompositionCser" => 2_700,
        _ => 300,
    })
}

struct SpecRunLock {
    file: File,
}

impl SpecRunLock {
    fn acquire(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        loop {
            // SAFETY: flock only observes the live file descriptor owned by
            // `file`; no pointers or borrowed memory cross the FFI boundary.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(Self { file });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(format!(
                    "lock specification artifacts at {}: {error}",
                    path.display()
                )
                .into());
            }
        }
    }
}

impl Drop for SpecRunLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains valid for the duration of this call
        // and belongs to this guard. The kernel also releases it on process
        // exit, including abrupt termination.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

struct IsolatedSpecWorkspace {
    root: PathBuf,
    cser_dir: PathBuf,
    temp_dir: PathBuf,
}

impl IsolatedSpecWorkspace {
    fn create(source_cser_dir: &Path) -> Result<Self> {
        let root = create_unique_spec_workspace()?;
        let cser_dir = root.join("specs/cser");
        let temp_dir = root.join("tmp");
        let result = (|| -> Result<()> {
            fs::create_dir_all(&cser_dir)?;
            fs::create_dir(&temp_dir)?;
            copy_spec_inputs(source_cser_dir, &cser_dir)?;
            Ok(())
        })();
        if let Err(error) = result {
            let cleanup = fs::remove_dir_all(&root);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!(
                    "{error}; remove incomplete isolated specification workspace {}: {cleanup_error}",
                    root.display()
                )
                .into()),
            };
        }
        Ok(Self {
            root,
            cser_dir,
            temp_dir,
        })
    }

    fn cser_dir(&self) -> &Path {
        &self.cser_dir
    }

    fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }
}

impl Drop for IsolatedSpecWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn create_unique_spec_workspace() -> Result<PathBuf> {
    for _ in 0..100 {
        let sequence = NEXT_SPEC_WORKSPACE.fetch_add(1, Ordering::Relaxed);
        let path =
            env::temp_dir().join(format!("nexus-cser-spec-{}-{sequence}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "create isolated specification workspace {}: {error}",
                    path.display()
                )
                .into());
            }
        }
    }
    Err("could not allocate a unique isolated specification workspace".into())
}

fn copy_spec_inputs(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if generated_spec_entry(&name) {
            continue;
        }
        let source_path = entry.path();
        let destination_path = destination.join(&name);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            fs::create_dir(&destination_path)?;
            copy_spec_inputs(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)?;
        } else {
            return Err(format!(
                "unsupported specification input type: {}",
                source_path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn generated_spec_entry(name: &OsStr) -> bool {
    name == "states"
        || name
            .to_str()
            .is_some_and(|name| name.contains("_TTrace_") || name.ends_with(".old"))
}

fn tla2tools_jar() -> Result<PathBuf> {
    evidence::pinned_tla2tools_jar(&repo_root())
}

fn pluscal_translation_is_current(
    source_cser_dir: &Path,
    isolated_cser_dir: &Path,
    jar: &Path,
    spec: &str,
    log: &Path,
) -> Result<()> {
    section(&format!("check PlusCal translation drift for {spec}"));
    let file_name = format!("{spec}.tla");
    let line_width = pluscal_line_width(spec);
    let original_path = source_cser_dir.join(&file_name);
    let generated_path = isolated_cser_dir.join(&file_name);
    let mut command = Command::new("java");
    command
        .current_dir(isolated_cser_dir)
        .arg("-cp")
        .arg(jar)
        .args(["pcal.trans", "-nocfg", "-lineWidth", line_width, &file_name]);
    run_bounded_logged(&mut command, log, Duration::from_secs(30), 1024 * 1024)?;

    let original = fs::read_to_string(&original_path)?;
    let generated = fs::read_to_string(&generated_path)?;
    if original != generated {
        let detail = first_difference(&original, &generated);
        return Err(format!(
            "PlusCal translation drifted for {spec} ({detail}); regenerate {} with TLA+ tools",
            original_path.display()
        )
        .into());
    }
    println!("PlusCal translation: PASS ({spec})");
    Ok(())
}

fn pluscal_line_width(spec: &str) -> &'static str {
    if matches!(
        spec,
        "IoCser"
            | "PersonalityFutexCser"
            | "PersonalityFutexRequeueCser"
            | "PersonalityReadinessCser"
            | "PersonalityExecCser"
            | "RuntimeFsCser"
            | "RuntimeNetCser"
            | "CompositionCser"
            | "LinuxIoCompositionCser"
            | "ProductionIdentityCser"
    ) {
        "10000"
    } else {
        "1000"
    }
}

fn first_difference(expected: &str, actual: &str) -> String {
    let expected_lines: Vec<_> = expected.lines().collect();
    let actual_lines: Vec<_> = actual.lines().collect();
    let common = expected_lines.len().min(actual_lines.len());
    for index in 0..common {
        if expected_lines[index] != actual_lines[index] {
            let mut detail = String::new();
            let _ = write!(
                detail,
                "line {}: committed {:?}, generated {:?}",
                index + 1,
                expected_lines[index],
                actual_lines[index]
            );
            return detail;
        }
    }
    format!(
        "line count differs: committed {}, generated {}",
        expected_lines.len(),
        actual_lines.len()
    )
}

struct LoggedChild {
    child: Option<Child>,
    leader: u32,
}

impl LoggedChild {
    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("logged child is present")
    }

    fn cleanup(&mut self) -> io::Result<std::process::ExitStatus> {
        let group_result = kill_process_group(self.leader);
        let child_result = match self.child_mut().try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => self.child_mut().kill().or_else(ignore_already_exited),
            Err(error) => {
                let kill_result = self.child_mut().kill().or_else(ignore_already_exited);
                kill_result.and(Err(error))
            }
        };
        let wait_result = self.child_mut().wait();
        if wait_result.is_ok() {
            self.child = None;
        }
        group_result?;
        child_result?;
        wait_result
    }
}

impl Drop for LoggedChild {
    fn drop(&mut self) {
        let _ = kill_process_group(self.leader);
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn ignore_already_exited(error: io::Error) -> io::Result<()> {
    if error.kind() == io::ErrorKind::InvalidInput {
        Ok(())
    } else {
        Err(error)
    }
}

fn kill_process_group(leader: u32) -> io::Result<()> {
    let process_group = -(leader as libc::pid_t);
    // SAFETY: the negative value names the process group created with
    // process_group(0); no pointers or borrowed memory cross the FFI.
    let result = unsafe { libc::kill(process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

struct StreamCapture {
    bytes: Vec<u8>,
    observed_bytes: u64,
    overflow: bool,
    error: Option<String>,
}

fn capture_pipe() -> io::Result<(File, File)> {
    let mut descriptors = [0; 2];
    // SAFETY: pipe2 initializes both descriptors on success. Each descriptor
    // is transferred exactly once into a File immediately below.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful pipe2 call returned two newly owned descriptors.
    let reader = unsafe { File::from_raw_fd(descriptors[0]) };
    let writer = unsafe { File::from_raw_fd(descriptors[1]) };
    Ok((reader, writer))
}

fn capture_stream(
    mut reader: File,
    max_output_bytes: u64,
    process_group: u32,
    overflow: Arc<AtomicBool>,
) -> StreamCapture {
    let capacity = usize::try_from(max_output_bytes).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity.min(64 * 1024));
    let mut observed_bytes = 0_u64;
    let mut buffer = [0_u8; 8192];
    let mut error = None;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                observed_bytes = observed_bytes.saturating_add(count as u64);
                let remaining = capacity.saturating_sub(bytes.len());
                bytes.extend_from_slice(&buffer[..count.min(remaining)]);
                if observed_bytes > max_output_bytes {
                    overflow.store(true, Ordering::Release);
                    if let Err(kill_error) = kill_process_group(process_group) {
                        error = Some(format!("terminate overflowing command: {kill_error}"));
                    }
                    break;
                }
            }
            Err(read_error) if read_error.kind() == io::ErrorKind::Interrupted => {}
            Err(read_error) => {
                error = Some(format!("capture command output: {read_error}"));
                let _ = kill_process_group(process_group);
                break;
            }
        }
    }
    StreamCapture {
        bytes,
        observed_bytes,
        overflow: overflow.load(Ordering::Acquire),
        error,
    }
}

fn run_bounded_logged(
    command: &mut Command,
    artifact: &Path,
    timeout: Duration,
    max_output_bytes: u64,
) -> Result<()> {
    run_bounded_logged_with_replay(command, artifact, timeout, max_output_bytes, true)
}

fn run_bounded_logged_quiet(
    command: &mut Command,
    artifact: &Path,
    timeout: Duration,
    max_output_bytes: u64,
) -> Result<()> {
    run_bounded_logged_with_replay(command, artifact, timeout, max_output_bytes, false)
}

fn run_bounded_logged_with_replay(
    command: &mut Command,
    artifact: &Path,
    timeout: Duration,
    max_output_bytes: u64,
    replay: bool,
) -> Result<()> {
    let parent = artifact
        .parent()
        .ok_or_else(|| format!("log path has no parent: {}", artifact.display()))?;
    fs::create_dir_all(parent)?;
    let (reader, writer) = capture_pipe()?;
    let stderr = writer.try_clone()?;
    command
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(stderr))
        .process_group(0);
    println!("+ {command:?}");

    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let message = format!("spawn failed: {error}\n");
            // Command keeps its configured Stdio objects. Replace them before
            // dropping the read side so no parent-owned pipe handle lingers.
            command.stdout(Stdio::null()).stderr(Stdio::null());
            drop(reader);
            fs::write(artifact, &message)?;
            return Err(message.into());
        }
    };
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let leader = child.id();
    let mut guard = LoggedChild {
        child: Some(child),
        leader,
    };
    let overflow = Arc::new(AtomicBool::new(false));
    let capture_overflow = Arc::clone(&overflow);
    let capture_thread = match thread::Builder::new()
        .name(String::from("nexus-verification-capture"))
        .spawn(move || capture_stream(reader, max_output_bytes, leader, capture_overflow))
    {
        Ok(thread) => thread,
        Err(error) => {
            let cleanup = guard.cleanup().err();
            let reason = cleanup
                .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                .unwrap_or_default();
            let message = format!("start output capture thread: {error}{reason}\n");
            fs::write(artifact, &message)?;
            return Err(message.into());
        }
    };
    let started = Instant::now();
    let mut failure = None;
    loop {
        if overflow.load(Ordering::Acquire) {
            failure = Some(format!("output exceeded {max_output_bytes} bytes"));
            break;
        }
        match guard.child_mut().try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => {
                failure = Some(format!("poll command: {error}"));
                break;
            }
        }
        if started.elapsed() >= timeout {
            failure = Some(format!("timeout after {} ms", timeout.as_millis()));
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    match guard.cleanup() {
        Ok(status) if !status.success() && failure.is_none() => {
            failure = Some(format!("command failed with {status}"));
        }
        Ok(_) => {}
        Err(error) => {
            failure = Some(match failure {
                Some(reason) => format!("{reason}; cleanup process group: {error}"),
                None => format!("cleanup process group: {error}"),
            });
        }
    }

    let capture = match capture_thread.join() {
        Ok(capture) => capture,
        Err(_) => StreamCapture {
            bytes: Vec::new(),
            observed_bytes: 0,
            overflow: false,
            error: Some(String::from("command-output capture thread panicked")),
        },
    };
    if capture.overflow && failure.is_none() {
        failure = Some(format!("output exceeded {max_output_bytes} bytes"));
    }
    if let Some(error) = capture.error {
        failure = Some(match failure {
            Some(reason) => format!("{reason}; {error}"),
            None => error,
        });
    }
    let mut transcript = String::from_utf8_lossy(&capture.bytes).into_owned();
    let mut suffix = String::new();
    if capture.overflow {
        suffix.push_str(&format!(
            "\n[output truncated: observed at least {} bytes, retained {max_output_bytes}]\n",
            capture.observed_bytes
        ));
    }
    if let Some(reason) = &failure {
        suffix.push_str(&format!("\n[verification failure: {reason}]\n"));
    }
    let output_limit = usize::try_from(max_output_bytes).unwrap_or(usize::MAX);
    truncate_utf8(&mut suffix, output_limit);
    truncate_utf8(&mut transcript, output_limit.saturating_sub(suffix.len()));
    transcript.push_str(&suffix);
    fs::write(artifact, transcript.as_bytes())?;
    if replay || failure.is_some() {
        print!("{transcript}");
    }

    if let Some(reason) = failure {
        return Err(reason.into());
    }
    Ok(())
}

fn truncate_utf8(value: &mut String, mut limit: usize) {
    if value.len() <= limit {
        return;
    }
    while !value.is_char_boundary(limit) {
        limit -= 1;
    }
    value.truncate(limit);
}

fn cargo<I, S>(root: &Path, args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new("cargo");
    command.current_dir(root).args(args);
    run(&mut command)
}

fn cargo_output<I, S>(root: &Path, args: I) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new("cargo");
    command.current_dir(root).args(args);
    println!("+ {command:?}");
    let output = command.output()?;
    if !output.status.success() {
        replay_output(&output)?;
        return Err(format!("command failed with {}: {command:?}", output.status).into());
    }
    Ok(output)
}

fn run(command: &mut Command) -> Result<()> {
    println!("+ {command:?}");
    let status = command.status()?;
    if !status.success() {
        return Err(format!("command failed with {status}: {command:?}").into());
    }
    Ok(())
}

fn replay_output(output: &Output) -> Result<()> {
    io::stdout().write_all(&output.stdout)?;
    io::stderr().write_all(&output.stderr)?;
    Ok(())
}

fn section(title: &str) {
    println!("\n==> {title}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Barrier, mpsc};

    static NEXT_CAPTURE: AtomicUsize = AtomicUsize::new(0);

    fn artifact(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "nexus-xtask-{name}-{}-{}.log",
            std::process::id(),
            NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn fixture_dir(name: &str) -> PathBuf {
        let path = artifact(name);
        fs::create_dir(&path).expect("create fixture directory");
        path
    }

    #[test]
    fn parses_the_independent_production_identity_research_route() {
        assert_eq!(
            parse_invocation(
                [
                    String::from("research"),
                    String::from("production-identity")
                ]
                .into_iter()
            )
            .expect("prospective research route"),
            XtaskInvocation::ProductionIdentityResearch
        );
        assert!(parse_invocation([String::from("research")].into_iter()).is_err());
        assert!(
            parse_invocation([String::from("research"), String::from("unknown")].into_iter())
                .is_err()
        );
        assert!(
            parse_invocation(
                [
                    String::from("research"),
                    String::from("production-identity"),
                    String::from("extra"),
                ]
                .into_iter()
            )
            .is_err()
        );
    }

    #[test]
    fn parses_the_independent_handoff_admission_research_route() {
        assert_eq!(
            parse_invocation(
                [String::from("research"), String::from("handoff-admission")].into_iter()
            )
            .expect("prospective handoff research route"),
            XtaskInvocation::HandoffAdmissionResearch
        );
    }

    #[test]
    fn production_identity_translation_uses_the_checked_in_wide_form() {
        assert_eq!(pluscal_line_width("ProductionIdentityCser"), "10000");
        assert_eq!(pluscal_line_width("Cser"), "1000");
        assert!(first_difference("same\ncommitted\n", "same\ndrifted\n").contains("line 2"));
    }

    #[test]
    fn accepted_v0_1_specification_population_remains_frozen_at_twelve() {
        assert_eq!(TLA_SPECS.len(), 12);
        assert!(!TLA_SPECS.contains(&"ProductionIdentityCser"));
        production_identity::validate_release_boundary(&TLA_SPECS)
            .expect("the root manifest and bundle still receive the frozen catalog");
    }

    #[test]
    fn isolated_spec_workspace_copies_only_source_inputs() {
        let fixture = fixture_dir("spec-inputs");
        let source = fixture.join("cser");
        fs::create_dir(&source).expect("create source directory");
        fs::write(source.join("IoCser.tla"), "---- MODULE IoCser ----\n")
            .expect("write source specification");
        fs::write(source.join("IoCser.old"), "generated backup").expect("write generated backup");
        fs::write(source.join("IoCser_TTrace_1.tla"), "generated trace")
            .expect("write generated trace");
        fs::create_dir(source.join("states")).expect("create generated state directory");
        fs::write(source.join("states/checkpoint"), "generated state")
            .expect("write generated state");
        fs::create_dir(source.join("nested")).expect("create nested input directory");
        fs::write(source.join("nested/model.cfg"), "SPECIFICATION Spec\n")
            .expect("write nested input");

        let workspace = IsolatedSpecWorkspace::create(&source).expect("create isolated workspace");
        assert_eq!(
            fs::read_to_string(workspace.cser_dir().join("IoCser.tla"))
                .expect("read copied specification"),
            "---- MODULE IoCser ----\n"
        );
        assert!(workspace.cser_dir().join("nested/model.cfg").is_file());
        assert!(!workspace.cser_dir().join("IoCser.old").exists());
        assert!(!workspace.cser_dir().join("IoCser_TTrace_1.tla").exists());
        assert!(!workspace.cser_dir().join("states").exists());

        drop(workspace);
        fs::remove_dir_all(fixture).expect("remove fixture directory");
    }

    #[test]
    fn isolated_spec_workspace_drop_removes_generated_state() {
        let fixture = fixture_dir("spec-cleanup");
        let source = fixture.join("cser");
        fs::create_dir(&source).expect("create source directory");
        fs::write(source.join("IoCser.tla"), "---- MODULE IoCser ----\n")
            .expect("write source specification");

        let workspace = IsolatedSpecWorkspace::create(&source).expect("create isolated workspace");
        let workspace_root = workspace.root.clone();
        fs::create_dir(workspace.cser_dir().join("states"))
            .expect("create generated state directory");
        fs::write(
            workspace.cser_dir().join("IoCser_TTrace_timeout.tla"),
            "generated trace",
        )
        .expect("write generated trace");
        fs::write(
            workspace.temp_dir().join("coverage.log"),
            "temporary evidence",
        )
        .expect("write temporary evidence");

        drop(workspace);
        assert!(!workspace_root.exists());
        fs::remove_dir_all(fixture).expect("remove fixture directory");
    }

    #[test]
    fn linux_io_composition_timeout_covers_the_complete_formal_family() {
        assert_eq!(
            spec_timeout("LinuxIoCompositionCser"),
            Duration::from_secs(2_700)
        );
        assert_eq!(spec_timeout("Cser"), Duration::from_secs(300));
    }

    #[test]
    fn timed_out_spec_process_leaves_no_workspace_artifacts() {
        let fixture = fixture_dir("spec-timeout-cleanup");
        let source = fixture.join("cser");
        fs::create_dir(&source).expect("create source directory");
        fs::write(source.join("IoCser.tla"), "---- MODULE IoCser ----\n")
            .expect("write source specification");

        let workspace = IsolatedSpecWorkspace::create(&source).expect("create isolated workspace");
        let workspace_root = workspace.root.clone();
        let mut command = Command::new("sh");
        command.current_dir(workspace.cser_dir()).args([
            "-c",
            "mkdir states; touch IoCser_TTrace_timeout.tla; sleep 10",
        ]);
        let error = run_bounded_logged(
            &mut command,
            &fixture.join("timeout.log"),
            Duration::from_millis(100),
            1024,
        )
        .expect_err("fixture must time out");
        assert!(error.to_string().contains("timeout"));
        assert!(workspace.cser_dir().join("states").is_dir());
        assert!(
            workspace
                .cser_dir()
                .join("IoCser_TTrace_timeout.tla")
                .is_file()
        );

        drop(workspace);
        assert!(!workspace_root.exists());
        assert!(!source.join("states").exists());
        assert!(!source.join("IoCser_TTrace_timeout.tla").exists());
        fs::remove_dir_all(fixture).expect("remove fixture directory");
    }

    #[test]
    fn spec_run_lock_serializes_independent_acquisitions() {
        let fixture = fixture_dir("spec-lock");
        let lock_path = fixture.join(".spec.lock");
        let first = SpecRunLock::acquire(&lock_path).expect("acquire first lock");
        let barrier = Arc::new(Barrier::new(2));
        let second_barrier = Arc::clone(&barrier);
        let (sender, receiver) = mpsc::channel();
        let second = thread::spawn(move || {
            second_barrier.wait();
            sender.send("attempting").expect("announce lock attempt");
            let guard = SpecRunLock::acquire(&lock_path).expect("acquire second lock");
            sender.send("acquired").expect("announce lock acquisition");
            guard
        });

        barrier.wait();
        assert_eq!(receiver.recv().expect("receive lock attempt"), "attempting");
        assert!(
            matches!(
                receiver.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "the second lock acquisition must block while the first is held"
        );
        drop(first);
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("second lock must eventually acquire"),
            "acquired"
        );
        drop(second.join().expect("join second lock thread"));
        fs::remove_dir_all(fixture).expect("remove fixture directory");
    }

    #[test]
    fn bounded_log_retains_timeout_evidence() {
        let artifact = artifact("timeout");
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10"]);
        let error = run_bounded_logged(&mut command, &artifact, Duration::from_millis(20), 1024)
            .expect_err("fixture must time out");
        assert!(error.to_string().contains("timeout"));
        let log = fs::read_to_string(&artifact).expect("read timeout artifact");
        assert!(log.contains("verification failure: timeout"));
        fs::remove_file(artifact).expect("remove timeout artifact");
    }

    #[test]
    fn bounded_log_terminates_and_truncates_output() {
        let artifact = artifact("overflow");
        let mut command = Command::new("sh");
        command.args(["-c", "head -c 65536 /dev/zero"]);
        let error = run_bounded_logged(&mut command, &artifact, Duration::from_secs(2), 1024)
            .expect_err("fixture must exceed the output limit");
        assert!(error.to_string().contains("output exceeded"));
        let log = fs::read(&artifact).expect("read overflow artifact");
        assert!(log.len() < 2048, "retained log must remain bounded");
        assert!(String::from_utf8_lossy(&log).contains("output truncated"));
        fs::remove_file(artifact).expect("remove overflow artifact");
    }

    #[test]
    fn failed_command_cannot_leave_a_background_writer() {
        let artifact = artifact("background");
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30 & printf 'ORPHAN_PID=%s\\n' \"$!\"; exit 7"]);
        let error = run_bounded_logged(&mut command, &artifact, Duration::from_secs(2), 4096)
            .expect_err("fixture must report the nonzero status");
        assert!(error.to_string().contains("command failed"));
        let log = fs::read_to_string(&artifact).expect("read background artifact");
        let pid: libc::pid_t = log
            .lines()
            .find_map(|line| line.strip_prefix("ORPHAN_PID="))
            .expect("background PID marker")
            .parse()
            .expect("numeric background PID");
        let deadline = Instant::now() + Duration::from_millis(500);
        while process_is_live(pid) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !process_is_live(pid),
            "background child {pid} remained live"
        );
        fs::remove_file(artifact).expect("remove background artifact");
    }

    fn process_is_live(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only checks whether the process still exists.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
        }
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        stat.split_once(") ")
            .and_then(|(_, fields)| fields.chars().next())
            .is_none_or(|state| state != 'Z')
    }
}
