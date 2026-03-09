use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use axle_conformance::report::RunSummary;
use axle_conformance::runner::{RunConfig, run_conformance};
use serde::{Deserialize, Serialize};

use crate::seed::{ConcurrentSeed, FutexFaultOp, HookId, ProgramOp, SystemKind, WaitOp};

/// One QEMU replay report for a retained concurrent seed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QemuReplayReport {
    /// Saved seed path used for replay.
    pub seed_path: PathBuf,
    /// Selected QEMU scenario ids.
    pub scenarios: Vec<String>,
    /// Underlying axle-conformance run summary.
    pub summary: RunSummary,
}

/// Select the current best-effort QEMU scenario bundle for a retained seed.
pub fn scenarios_for_seed(seed: &ConcurrentSeed) -> Vec<String> {
    let mut out = BTreeSet::new();
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
    }

    if out.is_empty() {
        match seed.system {
            SystemKind::WaitPortTimer => {
                out.insert("kernel.thread.scheduler_wait_paths_bootstrap".to_string());
            }
            SystemKind::FutexFault => {
                out.insert("kernel.futex.wait_timeout_bootstrap".to_string());
            }
        }
    }

    out.into_iter().collect()
}

/// Replay one saved seed through the current QEMU scenario bundle.
pub fn replay_seed_via_qemu(
    seed_path: &Path,
    verbose: bool,
    retries: u32,
    keep_runs: usize,
) -> Result<QemuReplayReport> {
    let raw = fs::read(seed_path).with_context(|| format!("read {}", seed_path.display()))?;
    let seed: ConcurrentSeed =
        serde_json::from_slice(&raw).with_context(|| format!("parse {}", seed_path.display()))?;
    let scenarios = scenarios_for_seed(&seed);
    if scenarios.is_empty() {
        bail!(
            "seed '{}' did not map to any QEMU scenarios",
            seed_path.display()
        );
    }

    let mut config = RunConfig::with_workspace_defaults();
    config.scenario_filters = scenarios.clone();
    config.verbose = verbose;
    config.retries = retries;
    config.keep_runs = keep_runs;
    config.out_dir = config
        .workspace_root
        .join("target")
        .join("axle-concurrency")
        .join("qemu");

    let summary = run_conformance(&config)?;
    Ok(QemuReplayReport {
        seed_path: seed_path.to_path_buf(),
        scenarios,
        summary,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::ConcurrentSeed;

    #[test]
    fn wait_seed_maps_to_wait_qemu_bundle() {
        let seed = ConcurrentSeed::base_corpus(32).remove(0);
        let scenarios = scenarios_for_seed(&seed);
        assert!(
            scenarios
                .iter()
                .any(|scenario| scenario == "kernel.port.kernel_reserve")
        );
        assert!(
            scenarios
                .iter()
                .any(|scenario| scenario == "kernel.thread.scheduler_wait_paths_bootstrap")
        );
    }

    #[test]
    fn futex_fault_seed_maps_to_fault_qemu_bundle() {
        let seed = ConcurrentSeed::base_corpus(32).remove(3);
        let scenarios = scenarios_for_seed(&seed);
        assert!(
            scenarios
                .iter()
                .any(|scenario| scenario == "kernel.vm.fault_same_page_contention_bootstrap")
        );
    }
}
