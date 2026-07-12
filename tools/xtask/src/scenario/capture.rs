use super::schema::Scenario;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailureKind {
    Capture,
    Spawn,
    Wait,
    Timeout,
    OutputOverflow,
    Evaluate,
}

impl FailureKind {
    pub(super) fn as_str(self) -> &'static str {
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
pub(super) struct ScenarioFailure {
    pub(super) kind: FailureKind,
    pub(super) message: String,
}

impl ScenarioFailure {
    pub(super) fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
pub(super) struct Captured {
    pub(super) status: Option<ExitStatus>,
    pub(super) timed_out: bool,
    pub(super) output_overflow: bool,
    pub(super) observed_output_bytes: u64,
    pub(super) serial: String,
    pub(super) failure: Option<ScenarioFailure>,
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
pub(super) struct TempCapture {
    pub(super) path: PathBuf,
    file: File,
}

impl TempCapture {
    pub(super) fn create(scenario_id: &str) -> io::Result<Self> {
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

static NEXT_CAPTURE: AtomicUsize = AtomicUsize::new(0);

pub(super) fn execute(root: &Path, scenario: &Scenario) -> Result<Captured, String> {
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
