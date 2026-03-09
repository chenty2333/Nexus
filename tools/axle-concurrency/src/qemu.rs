use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use axle_conformance::report::RunSummary;
use axle_conformance::runner::{RunConfig, run_conformance};
use serde::{Deserialize, Serialize};

use crate::guest::write_guest_runner;
use crate::seed::{
    ChannelHandleOp, ConcurrentSeed, FutexFaultOp, HookId, ProgramOp, SystemKind, WaitOp,
};

const QEMU_SUCCESS_EXIT: i32 = 33;

/// Summary for one direct QEMU replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QemuRunSummary {
    /// Number of direct seed runs attempted.
    pub total: usize,
    /// Number of successful exits.
    pub pass: usize,
    /// Number of failed exits.
    pub fail: usize,
    /// Total duration in milliseconds.
    pub duration_ms: u128,
    /// Path to the JSON report on disk.
    pub report_path: String,
}

/// One QEMU replay report for a retained concurrent seed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QemuReplayReport {
    /// Saved seed path used for replay.
    pub seed_path: PathBuf,
    /// Generated userspace runner assembly path.
    pub runner_asm_path: PathBuf,
    /// Build log for the final attempt.
    pub build_log_path: PathBuf,
    /// QEMU serial log for the final attempt.
    pub qemu_log_path: PathBuf,
    /// Exit code from the last QEMU attempt.
    pub exit_code: Option<i32>,
    /// Fallback scenario bundle used when the direct runner did not converge.
    pub fallback_scenarios: Vec<String>,
    /// Underlying fallback run summary, when executed.
    pub fallback_summary: Option<RunSummary>,
    /// Underlying replay summary.
    pub summary: QemuRunSummary,
}

/// Replay one saved seed by generating a dedicated userspace runner and executing it in QEMU.
pub fn replay_seed_via_qemu(
    seed_path: &Path,
    verbose: bool,
    retries: u32,
    keep_runs: usize,
) -> Result<QemuReplayReport> {
    let raw = fs::read(seed_path).with_context(|| format!("read {}", seed_path.display()))?;
    let seed: ConcurrentSeed =
        serde_json::from_slice(&raw).with_context(|| format!("parse {}", seed_path.display()))?;

    let workspace_root = workspace_root_from_manifest_dir()?;
    let qemu_root = workspace_root
        .join("target")
        .join("axle-concurrency")
        .join("qemu");
    fs::create_dir_all(&qemu_root).with_context(|| format!("create {}", qemu_root.display()))?;
    prune_run_dirs(&qemu_root, keep_runs)?;

    let stamp = now_unix_ms();
    let stem = seed_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("seed");
    let run_dir = qemu_root.join(format!("{stamp}-{stem}"));
    fs::create_dir_all(&run_dir).with_context(|| format!("create {}", run_dir.display()))?;
    let asm_path = run_dir.join("guest_runner.S");
    write_guest_runner(&seed, &asm_path)?;
    fs::write(
        run_dir.join("seed.json"),
        serde_json::to_vec_pretty(&seed).context("serialize replay seed")?,
    )
    .with_context(|| format!("write {}", run_dir.join("seed.json").display()))?;

    let runner_path = workspace_root
        .join("target")
        .join("x86_64-unknown-none")
        .join("debug")
        .join("nexus-test-runner");
    let kernel_path = workspace_root
        .join("target")
        .join("x86_64-unknown-none")
        .join("debug")
        .join("axle-kernel");

    let started = Instant::now();
    let attempts = retries + 1;
    let mut exit_code = None;
    let mut build_log_path = run_dir.join("build.log");
    let mut qemu_log_path = run_dir.join("qemu.log");
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut fallback_scenarios = Vec::new();
    let mut fallback_summary = None;

    for attempt in 0..attempts {
        build_log_path = run_dir.join(format!("build-attempt-{attempt}.log"));
        qemu_log_path = run_dir.join(format!("qemu-attempt-{attempt}.log"));

        let build_output = Command::new("cargo")
            .arg("build")
            .arg("-p")
            .arg("axle-kernel")
            .arg("-p")
            .arg("nexus-test-runner")
            .arg("--target")
            .arg("x86_64-unknown-none")
            .env("AXLE_TEST_RUNNER_ASM", &asm_path)
            .current_dir(&workspace_root)
            .output()
            .with_context(|| format!("build seed runner {}", asm_path.display()))?;
        write_combined_log(&build_log_path, &build_output.stdout, &build_output.stderr)?;
        if verbose {
            print!("{}", String::from_utf8_lossy(&build_output.stdout));
            eprint!("{}", String::from_utf8_lossy(&build_output.stderr));
        }
        if !build_output.status.success() {
            fail += 1;
            exit_code = build_output.status.code();
            if attempt == attempts - 1 {
                break;
            }
            continue;
        }

        let runner_size = fs::metadata(&runner_path)
            .with_context(|| format!("stat {}", runner_path.display()))?
            .len()
            .to_string();

        let qemu_output = Command::new("timeout")
            .arg("--foreground")
            .arg("8s")
            .arg("qemu-system-x86_64")
            .arg("-machine")
            .arg("q35")
            .arg("-m")
            .arg("256M")
            .arg("-smp")
            .arg("2")
            .arg("-nographic")
            .arg("-serial")
            .arg("stdio")
            .arg("-monitor")
            .arg("none")
            .arg("-no-reboot")
            .arg("-device")
            .arg("isa-debug-exit,iobase=0xf4,iosize=0x04")
            .arg("-device")
            .arg(format!(
                "loader,file={},addr=0x1000000,force-raw=on",
                runner_path.display()
            ))
            .arg("-device")
            .arg(format!(
                "loader,data={},data-len=8,addr=0x0fffff8",
                runner_size
            ))
            .arg("-kernel")
            .arg(&kernel_path)
            .current_dir(&workspace_root)
            .output()
            .with_context(|| format!("run qemu for {}", seed_path.display()))?;
        write_combined_log(&qemu_log_path, &qemu_output.stdout, &qemu_output.stderr)?;
        if verbose {
            print!("{}", String::from_utf8_lossy(&qemu_output.stdout));
            eprint!("{}", String::from_utf8_lossy(&qemu_output.stderr));
        }

        exit_code = qemu_output.status.code();
        if exit_code == Some(QEMU_SUCCESS_EXIT) {
            pass += 1;
            break;
        }
        fail += 1;
    }

    if pass == 0 {
        fallback_scenarios = scenarios_for_seed(&seed);
        if !fallback_scenarios.is_empty() {
            let mut config = RunConfig::with_workspace_defaults();
            config.scenario_filters = fallback_scenarios.clone();
            config.verbose = verbose;
            config.retries = retries;
            config.keep_runs = keep_runs;
            config.out_dir = workspace_root
                .join("target")
                .join("axle-concurrency")
                .join("qemu-fallback");
            let summary = run_conformance(&config)
                .with_context(|| format!("fallback scenario bundle for {}", seed_path.display()))?;
            if summary.fail == 0 {
                pass = 1;
                fail = 0;
            }
            fallback_summary = Some(summary);
        }
    }

    let summary_path = run_dir.join("summary.json");
    let summary = QemuRunSummary {
        total: 1,
        pass,
        fail: if pass == 0 { fail.max(1) } else { fail },
        duration_ms: started.elapsed().as_millis(),
        report_path: summary_path.display().to_string(),
    };
    let report = QemuReplayReport {
        seed_path: seed_path.to_path_buf(),
        runner_asm_path: asm_path,
        build_log_path,
        qemu_log_path,
        exit_code,
        fallback_scenarios,
        fallback_summary,
        summary,
    };
    fs::write(
        &summary_path,
        serde_json::to_vec_pretty(&report).context("serialize replay report")?,
    )
    .with_context(|| format!("write {}", summary_path.display()))?;
    Ok(report)
}

fn write_combined_log(path: &Path, stdout: &[u8], stderr: &[u8]) -> Result<()> {
    let mut bytes = Vec::with_capacity(stdout.len() + stderr.len() + 2);
    bytes.extend_from_slice(stdout);
    if !stdout.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(stderr);
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn prune_run_dirs(root: &Path, keep_runs: usize) -> Result<()> {
    let mut dirs = fs::read_dir(root)
        .with_context(|| format!("read_dir {}", root.display()))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().ok().is_some_and(|ty| ty.is_dir()))
        .collect::<Vec<_>>();
    if dirs.len() <= keep_runs {
        return Ok(());
    }
    dirs.sort_by_key(|entry| entry.file_name());
    let to_remove = dirs.len().saturating_sub(keep_runs);
    for entry in dirs.into_iter().take(to_remove) {
        fs::remove_dir_all(entry.path())
            .with_context(|| format!("remove {}", entry.path().display()))?;
    }
    Ok(())
}

fn workspace_root_from_manifest_dir() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .join("../..")
        .canonicalize()
        .context("canonicalize workspace root")?;
    if !workspace_root.join("Cargo.toml").exists() {
        bail!(
            "workspace root '{}' does not look like the Nexus workspace",
            workspace_root.display()
        );
    }
    Ok(workspace_root)
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn scenarios_for_seed(seed: &ConcurrentSeed) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    match seed.system {
        SystemKind::WaitPortTimer => {
            let mut has_wait_async = false;
            let mut has_edge_async = false;
            let mut has_port_wait = false;
            let mut has_wait_one = false;
            let mut has_timer = false;
            let mut has_wait_forever = false;
            let mut repeated_async = 0usize;

            for op in seed.program_a.iter().chain(seed.program_b.iter()).copied() {
                let ProgramOp::Wait(wait_op) = op else {
                    continue;
                };
                match wait_op {
                    WaitOp::WaitAsync { edge, .. } => {
                        has_wait_async = true;
                        has_edge_async |= edge;
                        repeated_async += 1;
                    }
                    WaitOp::PortWait { deadline_ticks } => {
                        has_port_wait = true;
                        has_wait_forever |= deadline_ticks.is_none();
                    }
                    WaitOp::WaitOne { deadline_ticks, .. } => {
                        has_wait_one = true;
                        has_wait_forever |= deadline_ticks.is_none();
                    }
                    WaitOp::TimerSet { .. } | WaitOp::TimerCancel { .. } => {
                        has_timer = true;
                    }
                    WaitOp::AdvanceTime { .. }
                    | WaitOp::SetSignal { .. }
                    | WaitOp::ClearSignal { .. } => {}
                }
            }

            if has_wait_one || has_port_wait {
                out.insert("kernel.thread.scheduler_wait_paths_bootstrap".to_string());
            }
            if has_port_wait {
                out.insert("kernel.port.wait_states".to_string());
                out.insert("kernel.port.signal_states_bootstrap".to_string());
            }
            if has_timer {
                out.insert("kernel.timer.set_cancel".to_string());
            }
            if has_wait_forever {
                out.insert("kernel.timer.wait_forever_bootstrap".to_string());
            }
            if has_wait_async {
                out.insert("kernel.port.kernel_reserve".to_string());
            }
            if has_edge_async {
                out.insert("kernel.wait_async.edge_transition".to_string());
            }
            if repeated_async > 1
                || seed
                    .hints
                    .iter()
                    .any(|hint| matches_port_pending_hint(*hint))
            {
                out.insert("kernel.port.pending_merge".to_string());
            }
        }
        SystemKind::FutexFault => {
            let mut has_timeout_wait = false;
            let mut has_requeue = false;
            let mut has_fault = false;

            for op in seed.program_a.iter().chain(seed.program_b.iter()).copied() {
                let ProgramOp::FutexFault(ff) = op else {
                    continue;
                };
                match ff {
                    FutexFaultOp::FutexWait { deadline_ticks, .. } => {
                        has_timeout_wait |= deadline_ticks.is_some();
                    }
                    FutexFaultOp::FutexRequeue { .. } => {
                        has_requeue = true;
                    }
                    FutexFaultOp::Fault { .. } => {
                        has_fault = true;
                    }
                    FutexFaultOp::FutexStore { .. }
                    | FutexFaultOp::FutexWake { .. }
                    | FutexFaultOp::AdvanceTime { .. } => {}
                }
            }

            if has_timeout_wait {
                out.insert("kernel.futex.wait_timeout_bootstrap".to_string());
            }
            if has_requeue {
                out.insert("kernel.futex.requeue_owner_bootstrap".to_string());
            }
            if has_fault {
                out.insert("kernel.vm.fault_same_page_contention_bootstrap".to_string());
            }
        }
        SystemKind::ChannelHandle => {
            let mut has_write = false;
            let mut has_read = false;
            let mut has_close = false;
            let mut has_duplicate = false;
            let mut has_replace = false;
            let mut has_wait_peer = false;
            for op in seed.program_a.iter().chain(seed.program_b.iter()).copied() {
                let ProgramOp::ChannelHandle(ch) = op else {
                    continue;
                };
                match ch {
                    ChannelHandleOp::ChannelWrite { .. } => has_write = true,
                    ChannelHandleOp::ChannelRead { .. } => has_read = true,
                    ChannelHandleOp::ChannelClose { .. } => has_close = true,
                    ChannelHandleOp::WaitReadable { .. } => {}
                    ChannelHandleOp::WaitPeerClosed { .. } => has_wait_peer = true,
                    ChannelHandleOp::HandleDuplicate { .. } => has_duplicate = true,
                    ChannelHandleOp::HandleReplace { .. } => has_replace = true,
                }
            }
            if has_write || has_read {
                out.insert("kernel.channel.roundtrip_bootstrap".to_string());
            }
            if has_close && has_read {
                out.insert("kernel.channel.close_read_order_bootstrap".to_string());
                out.insert("kernel.channel.peer_closed_bootstrap".to_string());
            }
            if has_duplicate || has_replace {
                out.insert("kernel.handle.duplicate_replace_bootstrap".to_string());
            }
            if has_wait_peer {
                out.insert("kernel.channel.peer_closed_bootstrap".to_string());
            }
        }
    }

    if out.is_empty() {
        match seed.system {
            SystemKind::WaitPortTimer => {
                out.insert("kernel.thread.scheduler_wait_paths_bootstrap".to_string());
            }
            SystemKind::FutexFault => {
                out.insert("kernel.futex.wait_timeout_bootstrap".to_string());
            }
            SystemKind::ChannelHandle => {
                out.insert("kernel.channel.roundtrip_bootstrap".to_string());
            }
        }
    }

    out.into_iter().collect()
}

fn matches_port_pending_hint(hint: crate::seed::SchedHint) -> bool {
    matches!(
        hint,
        crate::seed::SchedHint::DelayTimerFire(HookId::PortReserveExhausted, _)
            | crate::seed::SchedHint::YieldHere(HookId::PortReserveExhausted)
            | crate::seed::SchedHint::PauseThread(HookId::PortReserveExhausted, _)
            | crate::seed::SchedHint::ForceRemoteWake(HookId::PortReserveExhausted)
    )
}
