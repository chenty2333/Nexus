use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::os::fd::FromRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

mod catalog;
mod guest;
mod scenario;

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
        "fmt" => fmt(&root),
        "check" => check(&root),
        "test" => test(&root),
        "model" => model(&root),
        "spec" => spec(&root),
        "verify" => {
            model(&root)?;
            spec(&root)
        }
        "clean" => clean(&root),
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
    eprintln!("commands: fmt check test model spec verify clean");
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
    section("validate implementation-neutral oracle catalogs");
    let oracle_count =
        catalog::validate_all(root).map_err(|error| format!("oracle schema: {error}"))?;
    println!("oracle catalogs: PASS ({oracle_count} entries)");

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
    pluscal_translation_is_current(root, &jar, &artifact_dir.join("pluscal.log"))?;

    section("run TLC");
    let mut command = Command::new("sh");
    command
        .current_dir(root)
        .env("TLA2TOOLS_JAR", &jar)
        .arg("specs/cser/check.sh");
    run_bounded_logged(
        &mut command,
        &artifact_dir.join("tlc.log"),
        Duration::from_secs(300),
        8 * 1024 * 1024,
    )
}

fn tla2tools_jar() -> Result<PathBuf> {
    let value = env::var_os("TLA2TOOLS_JAR")
        .ok_or("TLA2TOOLS_JAR must point to the pinned tla2tools.jar")?;
    let path = PathBuf::from(value);
    if !path.is_file() {
        return Err(format!("TLA2TOOLS_JAR is not a file: {}", path.display()).into());
    }
    Ok(path)
}

fn pluscal_translation_is_current(root: &Path, jar: &Path, log: &Path) -> Result<()> {
    section("check PlusCal translation drift");
    let original_path = root.join("specs/cser/Cser.tla");
    let temp = env::temp_dir().join(format!("nexus-cser-pcal-{}", std::process::id()));
    if temp.exists() {
        fs::remove_dir_all(&temp)?;
    }
    fs::create_dir(&temp)?;
    let generated_path = temp.join("Cser.tla");
    fs::copy(&original_path, &generated_path)?;

    let translation = (|| -> Result<()> {
        let mut command = Command::new("java");
        command.current_dir(&temp).arg("-cp").arg(jar).args([
            "pcal.trans",
            "-nocfg",
            "-lineWidth",
            "1000",
            "Cser.tla",
        ]);
        run_bounded_logged(&mut command, log, Duration::from_secs(30), 1024 * 1024)?;

        let original = fs::read_to_string(&original_path)?;
        let generated = fs::read_to_string(&generated_path)?;
        if original != generated {
            let detail = first_difference(&original, &generated);
            return Err(format!(
                "PlusCal translation drifted ({detail}); regenerate specs/cser/Cser.tla with TLA+ tools"
            )
            .into());
        }
        println!("PlusCal translation: PASS");
        Ok(())
    })();

    let cleanup = fs::remove_dir_all(&temp);
    translation?;
    cleanup?;
    Ok(())
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

fn clean(root: &Path) -> Result<()> {
    section("clean root Docker artifacts");
    let docker_target = root.join("target/docker");
    if docker_target.exists() {
        fs::remove_dir_all(&docker_target)?;
    }
    let states = root.join("specs/cser/states");
    if states.exists() {
        fs::remove_dir_all(states)?;
    }
    for path in [
        root.join("target/scenario-artifacts"),
        root.join("target/verification"),
    ] {
        if path.exists() {
            fs::remove_dir_all(path)?;
        }
    }
    Ok(())
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
    print!("{transcript}");

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

    static NEXT_CAPTURE: AtomicUsize = AtomicUsize::new(0);

    fn artifact(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "nexus-xtask-{name}-{}-{}.log",
            std::process::id(),
            NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed)
        ))
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
