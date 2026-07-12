use super::capture::{Captured, FailureKind, TempCapture, execute};
use super::execution::{evaluate, run_one};
use super::schema::{
    ArtifactPolicy, FAILURE_METADATA, MIN_OUTPUT_BYTES, NumericOracle, Retain, Scenario,
    ScenarioFile, SerialOracle,
};
use super::validation::validate_scenario;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

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
        let metadata =
            fs::read_to_string(directory.join(FAILURE_METADATA)).expect("read failure metadata");
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
    let source = include_str!("../../../../tests/scenarios/runner-selftest.toml");
    let file: ScenarioFile = toml::from_str(source).expect("parse runner fixture");
    assert_eq!(file.schema_version, 1);
    assert_eq!(file.scenario.len(), 1);
    validate_scenario(Path::new("runner-selftest.toml"), &file.scenario[0])
        .expect("validate runner fixture");

    let missing_limit = source.replace("max_output_bytes = 65536\n", "");
    assert!(toml::from_str::<ScenarioFile>(&missing_limit).is_err());
}
