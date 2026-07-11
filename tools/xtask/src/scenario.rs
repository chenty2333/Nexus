use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd as _;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MIN_OUTPUT_BYTES: u64 = 1_024;
const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const FAILURE_METADATA: &str = "failure.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioFile {
    schema_version: u32,
    scenario: Vec<Scenario>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    id: String,
    command: Vec<String>,
    timeout_ms: u64,
    max_output_bytes: u64,
    #[serde(default = "successful_exit")]
    expected_exit: i32,
    serial: SerialOracle,
    #[serde(default)]
    numeric: Vec<NumericOracle>,
    artifacts: ArtifactPolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SerialOracle {
    #[serde(default)]
    expect: Vec<String>,
    #[serde(default)]
    ordered: Vec<String>,
    #[serde(default)]
    forbid: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NumericOracle {
    key: String,
    exact: Option<i64>,
    min: Option<i64>,
    max: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Retain {
    Always,
    OnFailure,
    Never,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPolicy {
    retain: Retain,
    serial: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureKind {
    Capture,
    Spawn,
    Wait,
    Timeout,
    OutputOverflow,
    Evaluate,
}

impl FailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Spawn => "spawn",
            Self::Wait => "wait",
            Self::Timeout => "timeout",
            Self::OutputOverflow => "output-overflow",
            Self::Evaluate => "evaluate",
        }
    }
}

#[derive(Clone, Debug)]
struct ScenarioFailure {
    kind: FailureKind,
    message: String,
}

impl ScenarioFailure {
    fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
struct Captured {
    status: Option<ExitStatus>,
    timed_out: bool,
    output_overflow: bool,
    observed_output_bytes: u64,
    serial: String,
    failure: Option<ScenarioFailure>,
}

impl Captured {
    fn failed(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            status: None,
            timed_out: false,
            output_overflow: false,
            observed_output_bytes: 0,
            serial: String::new(),
            failure: Some(ScenarioFailure::new(kind, message)),
        }
    }
}

/// A uniquely named capture file that is removed on every return path,
/// including unwinding inside the capture thread.
struct TempCapture {
    path: PathBuf,
    file: File,
}

impl TempCapture {
    fn create(scenario_id: &str) -> io::Result<Self> {
        let path = env::temp_dir().join(format!(
            "nexus-scenario-{}-{}-{}.log",
            std::process::id(),
            scenario_id,
            NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self { path, file })
    }

    fn read(&self) -> io::Result<Vec<u8>> {
        fs::read(&self.path)
    }
}

impl Drop for TempCapture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Owns both the direct child and its process-group identity. Dropping it is a
/// last-resort cleanup barrier: the group is killed and the direct child is
/// reaped even when polling, capture, or artifact handling returns early.
struct ChildProcessGroup {
    leader: u32,
    child: Option<Child>,
    cleaned: bool,
}

impl ChildProcessGroup {
    fn new(child: Child) -> Self {
        Self {
            leader: child.id(),
            child: Some(child),
            cleaned: false,
        }
    }

    fn leader(&self) -> u32 {
        self.leader
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child
            .as_mut()
            .expect("process group must own its child until cleanup")
            .try_wait()
    }

    fn cleanup(&mut self) -> Result<ExitStatus, String> {
        let group_result = kill_process_group(self.leader);
        let child = self
            .child
            .as_mut()
            .expect("process group must own its child until cleanup");

        // Also signal the direct child. A command can move itself out of the
        // process group with setsid/setpgid; group cleanup must not then block
        // indefinitely while waiting for that escaped leader.
        let child_result = match child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => child.kill().or_else(ignore_already_exited),
            Err(error) => Err(error),
        };
        let wait_result = child.wait();
        self.child = None;
        self.cleaned = true;

        group_result?;
        if let Err(error) = child_result {
            return Err(format!("kill scenario child {}: {error}", self.leader));
        }
        wait_result.map_err(|error| format!("collect scenario status: {error}"))
    }
}

impl Drop for ChildProcessGroup {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        let _ = kill_process_group(self.leader);
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct StreamCapture {
    capture: TempCapture,
    overflow: bool,
    observed_bytes: u64,
    error: Option<String>,
}

#[derive(Serialize)]
struct FailureMetadata<'a> {
    schema_version: u32,
    scenario_id: &'a str,
    kind: &'a str,
    message: &'a str,
    timed_out: bool,
    output_overflow: bool,
    max_output_bytes: u64,
    captured_output_bytes: usize,
    observed_output_bytes: u64,
    exit_code: Option<i32>,
    signal: Option<i32>,
}

static NEXT_CAPTURE: AtomicUsize = AtomicUsize::new(0);

fn successful_exit() -> i32 {
    0
}

pub(crate) fn validate_all(root: &Path) -> Result<usize, String> {
    let scenarios = load_all(root)?;
    Ok(scenarios.len())
}

pub(crate) fn run_all(root: &Path) -> Result<usize, String> {
    let scenarios = load_all(root)?;
    let artifact_root = root.join("target/scenario-artifacts");
    for scenario in &scenarios {
        println!("\n==> scenario {}", scenario.id);
        run_one(root, &artifact_root, scenario)?;
        println!("scenario {}: PASS", scenario.id);
    }
    Ok(scenarios.len())
}

fn load_all(root: &Path) -> Result<Vec<Scenario>, String> {
    let directory = root.join("tests/scenarios");
    let mut paths = toml_files(&directory)?;
    if paths.is_empty() {
        return Err(format!(
            "no runner scenarios found in {}",
            directory.display()
        ));
    }
    paths.sort();

    let mut all = Vec::new();
    let mut ids = BTreeSet::new();
    for path in paths {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        let file: ScenarioFile = toml::from_str(&source)
            .map_err(|error| format!("parse {}: {error}", path.display()))?;
        if file.schema_version != 1 {
            return Err(format!(
                "{}: schema_version must be 1, got {}",
                path.display(),
                file.schema_version
            ));
        }
        if file.scenario.is_empty() {
            return Err(format!(
                "{}: scenario array must not be empty",
                path.display()
            ));
        }
        for scenario in file.scenario {
            validate_scenario(&path, &scenario)?;
            if !ids.insert(scenario.id.clone()) {
                return Err(format!(
                    "{}: duplicate scenario id {:?}",
                    path.display(),
                    scenario.id
                ));
            }
            all.push(scenario);
        }
    }
    Ok(all)
}

fn toml_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    let read_dir = fs::read_dir(directory)
        .map_err(|error| format!("read scenario directory {}: {error}", directory.display()))?;
    for entry in read_dir {
        let entry = entry.map_err(|error| format!("read scenario directory entry: {error}"))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("toml") {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn validate_scenario(path: &Path, scenario: &Scenario) -> Result<(), String> {
    validate_id(path, &scenario.id)?;
    if scenario.command.is_empty() || scenario.command[0].trim().is_empty() {
        return Err(format!(
            "{}: {}: command must not be empty",
            path.display(),
            scenario.id
        ));
    }
    if scenario.timeout_ms == 0 || scenario.timeout_ms > 600_000 {
        return Err(format!(
            "{}: {}: timeout_ms must be in 1..=600000",
            path.display(),
            scenario.id
        ));
    }
    if !(MIN_OUTPUT_BYTES..=MAX_OUTPUT_BYTES).contains(&scenario.max_output_bytes) {
        return Err(format!(
            "{}: {}: max_output_bytes must be in {}..={}",
            path.display(),
            scenario.id,
            MIN_OUTPUT_BYTES,
            MAX_OUTPUT_BYTES
        ));
    }
    for (kind, values) in [
        ("expect", &scenario.serial.expect),
        ("ordered", &scenario.serial.ordered),
        ("forbid", &scenario.serial.forbid),
    ] {
        if values.iter().any(|value| value.is_empty()) {
            return Err(format!(
                "{}: {}: serial.{kind} entries must not be empty",
                path.display(),
                scenario.id
            ));
        }
    }

    let mut numeric_keys = BTreeSet::new();
    for numeric in &scenario.numeric {
        if numeric.key.is_empty() || !numeric_keys.insert(numeric.key.clone()) {
            return Err(format!(
                "{}: {}: numeric keys must be nonempty and unique",
                path.display(),
                scenario.id
            ));
        }
        if numeric.exact.is_some() && (numeric.min.is_some() || numeric.max.is_some()) {
            return Err(format!(
                "{}: {}: numeric {} cannot combine exact with min/max",
                path.display(),
                scenario.id,
                numeric.key
            ));
        }
        if numeric.exact.is_none() && numeric.min.is_none() && numeric.max.is_none() {
            return Err(format!(
                "{}: {}: numeric {} needs exact, min, or max",
                path.display(),
                scenario.id,
                numeric.key
            ));
        }
        if let (Some(min), Some(max)) = (numeric.min, numeric.max)
            && min > max
        {
            return Err(format!(
                "{}: {}: numeric {} has min greater than max",
                path.display(),
                scenario.id,
                numeric.key
            ));
        }
    }

    let serial_path = Path::new(&scenario.artifacts.serial);
    if scenario.artifacts.serial.is_empty()
        || serial_path.components().count() != 1
        || !matches!(serial_path.components().next(), Some(Component::Normal(_)))
        || scenario.artifacts.serial == FAILURE_METADATA
    {
        return Err(format!(
            "{}: {}: artifacts.serial must be one relative filename other than {FAILURE_METADATA}",
            path.display(),
            scenario.id
        ));
    }
    Ok(())
}

fn validate_id(path: &Path, id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.starts_with('.')
        || !id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(format!(
            "{}: invalid scenario id {id:?}; use lowercase ASCII, digits, '.', '_' or '-'",
            path.display()
        ));
    }
    Ok(())
}

fn run_one(root: &Path, artifact_root: &Path, scenario: &Scenario) -> Result<(), String> {
    let captured = execute(root, scenario)?;
    let failure = match captured.failure.clone() {
        Some(failure) => Some(failure),
        None => evaluate(scenario, &captured)
            .err()
            .map(|message| ScenarioFailure::new(FailureKind::Evaluate, message)),
    };
    retain_artifact(artifact_root, scenario, &captured, failure.as_ref())?;
    match failure {
        Some(failure) => Err(failure.message),
        None => Ok(()),
    }
}

fn execute(root: &Path, scenario: &Scenario) -> Result<Captured, String> {
    let capture = match TempCapture::create(&scenario.id) {
        Ok(capture) => capture,
        Err(error) => {
            return Ok(Captured::failed(
                FailureKind::Capture,
                format!("create scenario {} capture: {error}", scenario.id),
            ));
        }
    };
    let (reader, writer) = match capture_pipe() {
        Ok(pipe) => pipe,
        Err(error) => {
            return Ok(Captured::failed(
                FailureKind::Capture,
                format!("create scenario {} output pipe: {error}", scenario.id),
            ));
        }
    };
    let stderr = match writer.try_clone() {
        Ok(stderr) => stderr,
        Err(error) => {
            return Ok(Captured::failed(
                FailureKind::Capture,
                format!("clone scenario {} output pipe: {error}", scenario.id),
            ));
        }
    };

    let mut command = Command::new(&scenario.command[0]);
    command
        .args(&scenario.command[1..])
        .current_dir(root)
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(stderr))
        // A timeout must terminate a shell and every QEMU/helper process it
        // launched, not merely the immediate child.
        .process_group(0);
    println!("+ {command:?}");
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            drop(command);
            drop(reader);
            drop(capture);
            return Ok(Captured::failed(
                FailureKind::Spawn,
                format!("spawn scenario {}: {error}", scenario.id),
            ));
        }
    };
    // Command retains its configured stdio for possible subsequent spawns.
    // Drop it now so only the child group owns pipe writers.
    drop(command);
    let mut group = ChildProcessGroup::new(child);
    let process_group = group.leader();
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stream_stop = Arc::clone(&stop_requested);
    let max_output_bytes = scenario.max_output_bytes;
    let capture_thread = match thread::Builder::new()
        .name(format!("scenario-capture-{}", scenario.id))
        .spawn(move || {
            stream_output(
                reader,
                capture,
                max_output_bytes,
                process_group,
                &stream_stop,
            )
        }) {
        Ok(handle) => handle,
        Err(error) => {
            let cleanup = group.cleanup().err();
            let suffix = cleanup
                .map(|message| format!("; cleanup also failed: {message}"))
                .unwrap_or_default();
            return Ok(Captured::failed(
                FailureKind::Capture,
                format!(
                    "start scenario {} capture thread: {error}{suffix}",
                    scenario.id
                ),
            ));
        }
    };

    let deadline = Instant::now() + Duration::from_millis(scenario.timeout_ms);
    let mut timed_out = false;
    let mut wait_error = None;
    loop {
        match group.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => {
                wait_error = Some(format!("wait for scenario {}: {error}", scenario.id));
                break;
            }
        }
        if stop_requested.load(Ordering::Acquire) {
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    // Clean the whole group even if the direct child exited successfully: a
    // checked-in scenario may not leave background QEMU/helper processes.
    let cleanup = group.cleanup();
    let stream = match capture_thread.join() {
        Ok(stream) => stream,
        Err(_) => {
            return Ok(Captured::failed(
                FailureKind::Capture,
                format!("scenario {} capture thread panicked", scenario.id),
            ));
        }
    };
    let captured_bytes = match stream.capture.read() {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(Captured::failed(
                FailureKind::Capture,
                format!("read capture {}: {error}", stream.capture.path.display()),
            ));
        }
    };
    let serial = decode_serial(captured_bytes, scenario.max_output_bytes, stream.overflow);
    print!("{serial}");

    let status = cleanup.as_ref().ok().copied();
    let failure = if stream.overflow {
        Some(ScenarioFailure::new(
            FailureKind::OutputOverflow,
            format!(
                "scenario {} exceeded max_output_bytes={}",
                scenario.id, scenario.max_output_bytes
            ),
        ))
    } else if timed_out {
        Some(ScenarioFailure::new(
            FailureKind::Timeout,
            format!(
                "scenario {} exceeded {} ms",
                scenario.id, scenario.timeout_ms
            ),
        ))
    } else if let Some(error) = stream.error.or(wait_error) {
        Some(ScenarioFailure::new(FailureKind::Capture, error))
    } else if let Err(error) = cleanup {
        Some(ScenarioFailure::new(FailureKind::Wait, error))
    } else {
        None
    };

    Ok(Captured {
        status,
        timed_out,
        output_overflow: stream.overflow,
        observed_output_bytes: stream.observed_bytes,
        serial,
        failure,
    })
}

fn capture_pipe() -> io::Result<(File, File)> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors points to writable storage for exactly two file
    // descriptors. On success ownership is transferred once into File; on
    // failure pipe2 creates no descriptors that need closing.
    let result = unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 initialized both descriptors and ownership has not been
    // transferred elsewhere.
    let reader = unsafe { File::from_raw_fd(descriptors[0]) };
    // SAFETY: as above, for the distinct write descriptor.
    let writer = unsafe { File::from_raw_fd(descriptors[1]) };
    Ok((reader, writer))
}

fn stream_output(
    mut reader: File,
    mut capture: TempCapture,
    max_output_bytes: u64,
    process_group: u32,
    stop_requested: &AtomicBool,
) -> StreamCapture {
    let mut buffer = [0_u8; 8 * 1024];
    let mut written = 0_u64;
    let mut observed = 0_u64;
    let mut overflow = false;
    let mut error = None;

    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(read_error) if read_error.kind() == io::ErrorKind::Interrupted => continue,
            Err(read_error) => {
                error = Some(format!("read scenario output: {read_error}"));
                stop_requested.store(true, Ordering::Release);
                let _ = kill_process_group(process_group);
                break;
            }
        };
        observed = observed.saturating_add(count as u64);
        let remaining = max_output_bytes.saturating_sub(written) as usize;
        let retained = count.min(remaining);
        if retained != 0
            && let Err(write_error) = capture.file.write_all(&buffer[..retained])
        {
            error = Some(format!("write bounded scenario capture: {write_error}"));
            stop_requested.store(true, Ordering::Release);
            let _ = kill_process_group(process_group);
            break;
        }
        written = written.saturating_add(retained as u64);
        if retained < count {
            overflow = true;
            stop_requested.store(true, Ordering::Release);
            if let Err(kill_error) = kill_process_group(process_group) {
                error = Some(kill_error);
            }
            break;
        }
    }
    if let Err(flush_error) = capture.file.flush()
        && error.is_none()
    {
        error = Some(format!("flush bounded scenario capture: {flush_error}"));
    }
    StreamCapture {
        capture,
        overflow,
        observed_bytes: observed,
        error,
    }
}

fn decode_serial(bytes: Vec<u8>, max_output_bytes: u64, overflow: bool) -> String {
    let mut serial = String::from_utf8_lossy(&bytes).into_owned();
    let limit = usize::try_from(max_output_bytes).expect("validated output limit fits usize");
    let marker =
        format!("\n[scenario output truncated: exceeded max_output_bytes={max_output_bytes}]\n");
    let content_limit = if overflow {
        limit.saturating_sub(marker.len())
    } else {
        limit
    };
    truncate_utf8(&mut serial, content_limit);
    if overflow {
        serial.push_str(&marker);
    }
    serial
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

fn ignore_already_exited(error: io::Error) -> io::Result<()> {
    if error.kind() == io::ErrorKind::InvalidInput {
        Ok(())
    } else {
        Err(error)
    }
}

fn kill_process_group(leader: u32) -> Result<(), String> {
    let process_group = -(leader as libc::pid_t);
    // SAFETY: process_group is the negative PID returned by Child::id for a
    // child created with process_group(0). No pointer or borrowed memory is
    // involved. ESRCH is benign because the child may have exited between the
    // last try_wait and this timeout edge.
    let result = unsafe { libc::kill(process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(format!("kill process group {}: {error}", leader))
    }
}

fn evaluate(scenario: &Scenario, captured: &Captured) -> Result<(), String> {
    if captured.timed_out {
        return Err(format!(
            "scenario {} exceeded {} ms",
            scenario.id, scenario.timeout_ms
        ));
    }
    if captured.output_overflow {
        return Err(format!(
            "scenario {} exceeded max_output_bytes={}",
            scenario.id, scenario.max_output_bytes
        ));
    }
    let exit_code = captured.status.as_ref().and_then(ExitStatus::code);
    if exit_code != Some(scenario.expected_exit) {
        return Err(format!(
            "scenario {} exited {:?}; expected {}",
            scenario.id, exit_code, scenario.expected_exit
        ));
    }

    for expected in &scenario.serial.expect {
        if !captured.serial.contains(expected) {
            return Err(format!(
                "scenario {} missing expected text {expected:?}",
                scenario.id
            ));
        }
    }

    let mut remainder = captured.serial.as_str();
    for expected in &scenario.serial.ordered {
        let offset = remainder.find(expected).ok_or_else(|| {
            format!(
                "scenario {} missing ordered text {expected:?} after the previous match",
                scenario.id
            )
        })?;
        remainder = &remainder[offset + expected.len()..];
    }

    for forbidden in &scenario.serial.forbid {
        if captured.serial.contains(forbidden) {
            return Err(format!(
                "scenario {} contains forbidden text {forbidden:?}",
                scenario.id
            ));
        }
    }

    for oracle in &scenario.numeric {
        let values = numeric_values(&captured.serial, &oracle.key);
        if values.is_empty() {
            return Err(format!(
                "scenario {} has no numeric value for {:?}",
                scenario.id, oracle.key
            ));
        }
        for value in values {
            if let Some(exact) = oracle.exact
                && value != exact
            {
                return Err(format!(
                    "scenario {}: {}={} does not equal {}",
                    scenario.id, oracle.key, value, exact
                ));
            }
            if let Some(min) = oracle.min
                && value < min
            {
                return Err(format!(
                    "scenario {}: {}={} is below {}",
                    scenario.id, oracle.key, value, min
                ));
            }
            if let Some(max) = oracle.max
                && value > max
            {
                return Err(format!(
                    "scenario {}: {}={} exceeds {}",
                    scenario.id, oracle.key, value, max
                ));
            }
        }
    }
    Ok(())
}

fn numeric_values(text: &str, key: &str) -> Vec<i64> {
    let mut values = Vec::new();
    for (offset, _) in text.match_indices(key) {
        let before = text[..offset].chars().next_back();
        if before.is_some_and(|value| value.is_ascii_alphanumeric() || value == '_') {
            continue;
        }
        let after_key = &text[offset + key.len()..];
        let Some(rest) = after_key
            .strip_prefix('=')
            .or_else(|| after_key.strip_prefix(':'))
        else {
            continue;
        };
        let rest = rest.trim_start();
        let length = rest
            .char_indices()
            .take_while(|(index, value)| value.is_ascii_digit() || (*index == 0 && *value == '-'))
            .map(|(index, value)| index + value.len_utf8())
            .last()
            .unwrap_or(0);
        if length == 0 {
            continue;
        }
        if let Ok(value) = rest[..length].parse() {
            values.push(value);
        }
    }
    values
}

fn retain_artifact(
    artifact_root: &Path,
    scenario: &Scenario,
    captured: &Captured,
    failure: Option<&ScenarioFailure>,
) -> Result<(), String> {
    let directory = artifact_root.join(&scenario.id);
    let retain = scenario.artifacts.retain == Retain::Always
        || (scenario.artifacts.retain == Retain::OnFailure && failure.is_some());
    if !retain {
        if directory.exists() {
            fs::remove_dir_all(&directory)
                .map_err(|error| format!("remove {}: {error}", directory.display()))?;
        }
        return Ok(());
    }
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create {}: {error}", directory.display()))?;
    let path = directory.join(&scenario.artifacts.serial);
    fs::write(&path, &captured.serial)
        .map_err(|error| format!("write {}: {error}", path.display()))?;

    let metadata_path = directory.join(FAILURE_METADATA);
    if let Some(failure) = failure {
        let metadata = FailureMetadata {
            schema_version: 1,
            scenario_id: &scenario.id,
            kind: failure.kind.as_str(),
            message: &failure.message,
            timed_out: captured.timed_out,
            output_overflow: captured.output_overflow,
            max_output_bytes: scenario.max_output_bytes,
            captured_output_bytes: captured.serial.len(),
            observed_output_bytes: captured.observed_output_bytes,
            exit_code: captured.status.as_ref().and_then(ExitStatus::code),
            signal: captured.status.as_ref().and_then(|status| status.signal()),
        };
        let source = toml::to_string_pretty(&metadata)
            .map_err(|error| format!("encode {}: {error}", metadata_path.display()))?;
        fs::write(&metadata_path, source)
            .map_err(|error| format!("write {}: {error}", metadata_path.display()))?;
        eprintln!("retained scenario artifact: {}", metadata_path.display());
    } else if metadata_path.exists() {
        fs::remove_file(&metadata_path)
            .map_err(|error| format!("remove {}: {error}", metadata_path.display()))?;
    }
    eprintln!("retained scenario artifact: {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    fn scenario() -> Scenario {
        Scenario {
            id: String::from("runner.unit"),
            command: vec![String::from("sh"), String::from("-c"), String::from("true")],
            timeout_ms: 1_000,
            max_output_bytes: 32 * 1024,
            expected_exit: 0,
            serial: SerialOracle {
                expect: vec![String::from("READY")],
                ordered: vec![
                    String::from("BOOT"),
                    String::from("READY"),
                    String::from("DONE"),
                ],
                forbid: vec![String::from("PANIC")],
            },
            numeric: vec![
                NumericOracle {
                    key: String::from("exact"),
                    exact: Some(7),
                    min: None,
                    max: None,
                },
                NumericOracle {
                    key: String::from("bounded"),
                    exact: None,
                    min: Some(2),
                    max: Some(4),
                },
            ],
            artifacts: ArtifactPolicy {
                retain: Retain::Never,
                serial: String::from("serial.log"),
            },
        }
    }

    fn captured(serial: &str) -> Captured {
        Captured {
            status: Some(
                Command::new("sh")
                    .args(["-c", "exit 0"])
                    .status()
                    .expect("obtain success status"),
            ),
            timed_out: false,
            output_overflow: false,
            observed_output_bytes: serial.len() as u64,
            serial: serial.to_owned(),
            failure: None,
        }
    }

    fn clear_oracles(value: &mut Scenario) {
        value.serial = SerialOracle {
            expect: Vec::new(),
            ordered: Vec::new(),
            forbid: Vec::new(),
        };
        value.numeric.clear();
    }

    fn temp_dir() -> PathBuf {
        env::temp_dir().join(format!(
            "nexus-runner-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn evaluates_text_order_and_numeric_bounds() {
        evaluate(
            &scenario(),
            &captured("BOOT\nREADY exact=7 bounded: 3\nDONE\n"),
        )
        .expect("oracle should pass");
    }

    #[test]
    fn rejects_forbidden_text() {
        let error = evaluate(
            &scenario(),
            &captured("BOOT\nREADY exact=7 bounded=3\nPANIC\nDONE\n"),
        )
        .expect_err("forbidden marker must fail");
        assert!(error.contains("forbidden"));
    }

    #[test]
    fn enforces_timeout() {
        let mut value = scenario();
        value.command = vec![
            String::from("sh"),
            String::from("-c"),
            String::from("sleep 1"),
        ];
        value.timeout_ms = 20;
        clear_oracles(&mut value);
        let output = execute(Path::new("."), &value).expect("run timeout fixture");
        assert!(output.timed_out);
        assert_eq!(
            output.failure.as_ref().map(|failure| failure.kind),
            Some(FailureKind::Timeout)
        );
    }

    #[test]
    fn output_overflow_is_bounded_and_terminates_the_group() {
        let mut value = scenario();
        value.command = vec![
            String::from("sh"),
            String::from("-c"),
            String::from("head -c 262144 /dev/zero | tr '\\0' x; sleep 30"),
        ];
        value.timeout_ms = 2_000;
        value.max_output_bytes = MIN_OUTPUT_BYTES;
        clear_oracles(&mut value);
        let output = execute(Path::new("."), &value).expect("run overflow fixture");
        assert!(!output.timed_out);
        assert!(output.output_overflow);
        assert!(output.serial.len() <= value.max_output_bytes as usize);
        assert!(output.serial.contains("[scenario output truncated:"));
        assert_eq!(
            output.failure.as_ref().map(|failure| failure.kind),
            Some(FailureKind::OutputOverflow)
        );
    }

    #[test]
    fn non_utf8_output_is_retained_lossily() {
        let mut value = scenario();
        value.command = vec![
            String::from("sh"),
            String::from("-c"),
            String::from("printf '\\377OK\\n'"),
        ];
        clear_oracles(&mut value);
        let output = execute(Path::new("."), &value).expect("run non-UTF-8 fixture");
        assert!(output.failure.is_none());
        assert!(output.serial.contains('\u{fffd}'));
        assert!(output.serial.contains("OK"));
    }

    #[test]
    fn failures_retain_serial_and_structured_metadata() {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("create fixture root");
        let artifact_root = root.join("artifacts");
        let cases = [
            (
                "artifact.spawn",
                vec![String::from("nexus-runner-command-that-does-not-exist")],
                1_000,
                32 * 1024,
                "spawn",
            ),
            (
                "artifact.timeout",
                vec![
                    String::from("sh"),
                    String::from("-c"),
                    String::from("printf before-timeout; sleep 30"),
                ],
                20,
                32 * 1024,
                "timeout",
            ),
            (
                "artifact.overflow",
                vec![
                    String::from("sh"),
                    String::from("-c"),
                    String::from("head -c 262144 /dev/zero | tr '\\0' x"),
                ],
                2_000,
                MIN_OUTPUT_BYTES,
                "output-overflow",
            ),
            (
                "artifact.evaluate",
                vec![
                    String::from("sh"),
                    String::from("-c"),
                    String::from("printf not-ready"),
                ],
                1_000,
                32 * 1024,
                "evaluate",
            ),
        ];

        for (id, command, timeout_ms, max_output_bytes, expected_kind) in cases {
            let mut value = scenario();
            value.id = id.to_owned();
            value.command = command;
            value.timeout_ms = timeout_ms;
            value.max_output_bytes = max_output_bytes;
            value.artifacts.retain = Retain::OnFailure;
            let error =
                run_one(&root, &artifact_root, &value).expect_err("failure fixture must not pass");
            assert!(!error.is_empty());

            let directory = artifact_root.join(id);
            assert!(directory.join("serial.log").is_file());
            let metadata = fs::read_to_string(directory.join(FAILURE_METADATA))
                .expect("read failure metadata");
            let metadata: toml::Value = toml::from_str(&metadata).expect("parse failure metadata");
            assert_eq!(metadata["scenario_id"].as_str(), Some(id));
            assert_eq!(metadata["kind"].as_str(), Some(expected_kind));
            assert_eq!(
                metadata["max_output_bytes"].as_integer(),
                Some(max_output_bytes as i64)
            );
        }
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn successful_parent_cannot_leave_a_live_background_child() {
        let mut value = scenario();
        value.command = vec![
            String::from("sh"),
            String::from("-c"),
            String::from("sleep 30 & printf 'ORPHAN_PID=%s\\n' \"$!\""),
        ];
        clear_oracles(&mut value);
        let output = execute(Path::new("."), &value).expect("run background-child fixture");
        assert!(output.failure.is_none());
        let pid: libc::pid_t = output
            .serial
            .trim()
            .strip_prefix("ORPHAN_PID=")
            .expect("background PID marker")
            .parse()
            .expect("numeric background PID");

        let deadline = Instant::now() + Duration::from_millis(500);
        let stopped = loop {
            if !process_is_live(pid) {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(stopped, "background child {pid} remained live");
    }

    fn process_is_live(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 performs existence/permission checking only.
        let result = unsafe { libc::kill(pid, 0) };
        if result != 0 {
            return io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
        }
        // A killed grandchild may briefly remain as an init-owned zombie. It
        // is no longer executing and therefore is not a live orphan.
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        stat.split_once(") ")
            .and_then(|(_, fields)| fields.chars().next())
            .is_none_or(|state| state != 'Z')
    }

    #[test]
    fn temp_capture_removes_its_file_on_drop() {
        let capture = TempCapture::create("runner.raii").expect("create temp capture");
        let path = capture.path.clone();
        assert!(path.is_file());
        drop(capture);
        assert!(!path.exists());
    }

    #[test]
    fn parses_checked_in_runner_schema() {
        let source = include_str!("../../../tests/scenarios/runner-selftest.toml");
        let file: ScenarioFile = toml::from_str(source).expect("parse runner fixture");
        assert_eq!(file.schema_version, 1);
        assert_eq!(file.scenario.len(), 1);
        validate_scenario(Path::new("runner-selftest.toml"), &file.scenario[0])
            .expect("validate runner fixture");

        let missing_limit = source.replace("max_output_bytes = 65536\n", "");
        assert!(toml::from_str::<ScenarioFile>(&missing_limit).is_err());
    }
}
