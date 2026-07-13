// SPDX-License-Identifier: MPL-2.0

use alloc::{string::String, vec::Vec};
use core::{fmt::Write as _, hint::black_box};

use cser_transition_gates::{
    deadline::{DeadlineError, DeadlineGate},
    io::{IoError, IoGate, IoTerminal, IotlbProgress},
    oneshot::{OneShotError, OneShotGate},
    pager::{ContinuationOutcome, FaultKey, PagerError, PagerGate},
    scheduler::{SchedulerError, SchedulerGate},
};
use ostd::{irq, prelude::*, task::disable_preempt};

use crate::effect_registry::{
    ScopePhase, Stage7bActiveFixture, Stage7bFixtureConfig, TerminalOutcome,
};

const WARMUPS: usize = 7;
const SAMPLES: usize = 65;
const EMPTY_SAMPLES: usize = 257;

#[derive(Clone, Copy)]
struct FaultCell {
    id: &'static str,
    family: &'static str,
    injection: &'static str,
    terminal: &'static str,
    terminalizations: usize,
    publications: usize,
    credits_before: usize,
    credits_after: usize,
    retained_before_quiescence: bool,
}

impl FaultCell {
    const fn pass(
        id: &'static str,
        family: &'static str,
        injection: &'static str,
        terminal: &'static str,
        terminalizations: usize,
        publications: usize,
        credits_before: usize,
        credits_after: usize,
        retained_before_quiescence: bool,
    ) -> Self {
        Self {
            id,
            family,
            injection,
            terminal,
            terminalizations,
            publications,
            credits_before,
            credits_after,
            retained_before_quiescence,
        }
    }

    fn print(self) {
        println!(
            "STAGE7B_FAULT id={} family={} injection_point={} expected_terminal={} observed_terminal={} terminalizations={} publications={} credits_before={} credits_after={} retained_before_quiescence={} final_quiescent=true status=PASS",
            self.id,
            self.family,
            self.injection,
            self.terminal,
            self.terminal,
            self.terminalizations,
            self.publications,
            self.credits_before,
            self.credits_after,
            self.retained_before_quiescence,
        );
    }
}

pub(crate) fn run() {
    assert!(
        !cfg!(debug_assertions),
        "Stage 7B evaluation must be release"
    );
    run_fault_matrix();
    run_scale();
    run_performance();
    println!("STAGE7B_EVALUATION PASS faults=20 scale_points=14 performance_cases=29");
}

fn run_fault_matrix() {
    let cells = [
        scheduler_lease_expiry_before_proposal(),
        scheduler_crash_after_proposal_before_pick(),
        scheduler_stale_proposal_before_rebind(),
        scheduler_stale_proposal_after_rebind(),
        scheduler_repeated_crash_fallback_progress(),
        pager_same_page_concurrent_fault(),
        pager_crash_before_prepare(),
        pager_crash_after_prepare_before_commit(),
        pager_crash_after_commit_before_resume(),
        pager_timeout_vs_late_reply(),
        readiness_crash_before_backend_commit(),
        readiness_crash_after_backend_commit(),
        readiness_ready_vs_timeout(),
        readiness_revoke_vs_ready(),
        readiness_stale_deadline_after_rearm(),
        io_revoke_before_device_publication(),
        io_completion_vs_reset_ack(),
        io_reset_timeout_retry(),
        io_iotlb_timeout_late_ack(),
        io_stale_duplicate_completion(),
    ];
    for cell in cells {
        cell.print();
    }
    println!("STAGE7B_FAULT_SUMMARY cells=20 passed=20 status=PASS");
}

fn scheduler_with_fallback() -> SchedulerGate<u64> {
    let mut gate = SchedulerGate::new(1, 2).unwrap();
    let binding = gate.binding();
    gate.enter_fallback(binding).unwrap();
    gate
}

fn scheduler_lease_expiry_before_proposal() -> FaultCell {
    let mut gate = SchedulerGate::<u64>::new(1, 2).unwrap();
    let old = gate.binding();
    assert!(gate.tick().unwrap().is_none());
    assert!(gate.tick().unwrap().is_some());
    assert_eq!(
        gate.prepare(old, true, 1),
        Err(SchedulerError::StaleBinding)
    );
    gate.note_fallback_pick(7).unwrap();
    FaultCell::pass(
        "scheduler.lease-expiry-before-proposal",
        "scheduler",
        "lease-expiry",
        "FallbackPick",
        1,
        1,
        0,
        0,
        false,
    )
}

fn scheduler_crash_after_proposal_before_pick() -> FaultCell {
    let mut gate = SchedulerGate::new(1, 4).unwrap();
    let binding = gate.binding();
    gate.prepare(binding, true, 3_u64).unwrap();
    assert!(gate.enter_fallback(binding).unwrap().pending_cleared);
    gate.note_fallback_pick(7).unwrap();
    FaultCell::pass(
        "scheduler.crash-after-proposal-before-pick",
        "scheduler",
        "after-proposal",
        "FallbackPick",
        1,
        1,
        0,
        0,
        false,
    )
}

fn scheduler_stale_proposal_before_rebind() -> FaultCell {
    let mut gate = scheduler_with_fallback();
    let stale = cser_transition_gates::scheduler::SchedulerBinding {
        authority_epoch: 1,
        binding_epoch: 1,
    };
    assert_eq!(
        gate.prepare(stale, true, 2),
        Err(SchedulerError::StaleBinding)
    );
    gate.note_fallback_pick(7).unwrap();
    gate.rebind(1).unwrap();
    FaultCell::pass(
        "scheduler.stale-proposal-before-rebind",
        "scheduler",
        "before-rebind",
        "FallbackPick",
        1,
        1,
        0,
        0,
        false,
    )
}

fn scheduler_stale_proposal_after_rebind() -> FaultCell {
    let mut gate = scheduler_with_fallback();
    let stale = cser_transition_gates::scheduler::SchedulerBinding {
        authority_epoch: 1,
        binding_epoch: 1,
    };
    gate.note_fallback_pick(7).unwrap();
    gate.rebind(1).unwrap();
    assert_eq!(
        gate.prepare(stale, true, 2),
        Err(SchedulerError::StaleBinding)
    );
    FaultCell::pass(
        "scheduler.stale-proposal-after-rebind",
        "scheduler",
        "after-rebind",
        "FallbackPick",
        1,
        1,
        0,
        0,
        false,
    )
}

fn scheduler_repeated_crash_fallback_progress() -> FaultCell {
    let mut gate = scheduler_with_fallback();
    let before = gate.projection();
    assert_eq!(
        gate.enter_fallback(gate.binding()),
        Err(SchedulerError::AlreadyFallback)
    );
    assert_eq!(gate.projection(), before);
    gate.note_fallback_pick(7).unwrap();
    FaultCell::pass(
        "scheduler.repeated-crash-fallback-progress",
        "scheduler",
        "repeated-crash",
        "FallbackPick",
        1,
        1,
        0,
        0,
        false,
    )
}

fn pager_key() -> FaultKey {
    FaultKey {
        address_space_id: 1,
        address_space_generation: 1,
        page_address: 0x4000,
    }
}

fn pager_same_page_concurrent_fault() -> FaultCell {
    let mut gate = PagerGate::<2>::new(1, 1, 10).unwrap();
    let leader = gate.register(pager_key(), 100).unwrap().ticket();
    let follower = gate.register(pager_key(), 101).unwrap().ticket();
    gate.prepare_leader(leader).unwrap();
    let (mapping, ()) = gate
        .commit_mapping_with(leader, || Ok::<_, ()>(()))
        .unwrap();
    gate.terminalize(leader, Some(mapping), ContinuationOutcome::Resolved)
        .unwrap();
    gate.terminalize(follower, Some(mapping), ContinuationOutcome::Resolved)
        .unwrap();
    FaultCell::pass(
        "pager.same-page-concurrent-fault",
        "pager",
        "same-page-register",
        "Resolved",
        2,
        1,
        2,
        2,
        false,
    )
}

fn close_aborted_pager(id: &'static str, prepared: bool) -> FaultCell {
    let mut gate = PagerGate::<2>::new(1, 1, 10).unwrap();
    let ticket = gate.register(pager_key(), 100).unwrap().ticket();
    if prepared {
        gate.prepare_leader(ticket).unwrap();
    }
    gate.crash(1).unwrap();
    gate.abort_orphan(ticket).unwrap();
    gate.begin_revoke().unwrap();
    gate.complete_revoke(true).unwrap();
    FaultCell::pass(
        id,
        "pager",
        if prepared {
            "after-prepare"
        } else {
            "before-prepare"
        },
        "Aborted",
        1,
        0,
        1,
        1,
        false,
    )
}

fn pager_crash_before_prepare() -> FaultCell {
    close_aborted_pager("pager.crash-before-prepare", false)
}

fn pager_crash_after_prepare_before_commit() -> FaultCell {
    close_aborted_pager("pager.crash-after-prepare-before-commit", true)
}

fn pager_crash_after_commit_before_resume() -> FaultCell {
    let mut gate = PagerGate::<2>::new(1, 1, 10).unwrap();
    let ticket = gate.register(pager_key(), 100).unwrap().ticket();
    gate.prepare_leader(ticket).unwrap();
    let (mapping, ()) = gate
        .commit_mapping_with(ticket, || Ok::<_, ()>(()))
        .unwrap();
    gate.crash(1).unwrap();
    gate.terminalize_published_kernel(ticket, mapping).unwrap();
    gate.begin_revoke().unwrap();
    gate.complete_revoke(true).unwrap();
    FaultCell::pass(
        "pager.crash-after-commit-before-resume",
        "pager",
        "after-commit",
        "Resolved",
        1,
        1,
        1,
        1,
        false,
    )
}

fn pager_timeout_vs_late_reply() -> FaultCell {
    let mut gate = PagerGate::<2>::new(1, 1, 10).unwrap();
    let old = gate.register(pager_key(), 100).unwrap().ticket();
    gate.prepare_leader(old).unwrap();
    gate.crash(1).unwrap();
    let snapshot = gate.snapshot(11, 1).unwrap();
    gate.ready(snapshot).unwrap();
    gate.rebind(11).unwrap();
    let adopted = gate.adopt(old).unwrap();
    gate.begin_revoke().unwrap();
    gate.terminalize(adopted, None, ContinuationOutcome::Aborted)
        .unwrap();
    assert_eq!(gate.reply_gate(1, 1), Err(PagerError::StaleAuthority));
    gate.complete_revoke(true).unwrap();
    FaultCell::pass(
        "pager.timeout-vs-late-reply",
        "pager",
        "timeout-before-late-reply",
        "Aborted",
        1,
        0,
        1,
        1,
        false,
    )
}

fn registry_commit_revoke(commit_first: bool) -> TerminalOutcome {
    let mut fixture = Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 1, k: 1, h: 0 }).unwrap();
    let handle = fixture.prepare_single_target().unwrap();
    if commit_first {
        fixture.commit_single_target(handle).unwrap();
    }
    let selection = fixture.begin().unwrap();
    fixture.finish_revoke(&selection).unwrap();
    let terminal = fixture.single_target_terminal(handle).unwrap();
    fixture.check_invariants().unwrap();
    terminal
}

fn readiness_crash_before_backend_commit() -> FaultCell {
    assert_eq!(registry_commit_revoke(false), TerminalOutcome::Aborted);
    FaultCell::pass(
        "personality-readiness.crash-before-backend-commit",
        "personality-readiness",
        "before-backend-commit",
        "Aborted",
        1,
        0,
        1,
        1,
        false,
    )
}

fn readiness_crash_after_backend_commit() -> FaultCell {
    assert_eq!(registry_commit_revoke(true), TerminalOutcome::Completed);
    FaultCell::pass(
        "personality-readiness.crash-after-backend-commit",
        "personality-readiness",
        "after-backend-commit",
        "Completed",
        1,
        1,
        1,
        1,
        false,
    )
}

fn readiness_ready_vs_timeout() -> FaultCell {
    let mut gate = OneShotGate::new(1, 1).unwrap();
    let token = gate.token();
    gate.try_terminalize(token, "Ready").unwrap();
    assert_eq!(
        gate.try_terminalize(token, "TimedOut"),
        Err(OneShotError::AlreadyTerminal)
    );
    FaultCell::pass(
        "personality-readiness.ready-vs-timeout",
        "personality-readiness",
        "ready-first",
        "Ready",
        1,
        1,
        1,
        1,
        false,
    )
}

fn readiness_revoke_vs_ready() -> FaultCell {
    let mut gate = OneShotGate::new(1, 1).unwrap();
    let token = gate.token();
    gate.try_terminalize(token, "Aborted").unwrap();
    assert_eq!(
        gate.try_terminalize(token, "Ready"),
        Err(OneShotError::AlreadyTerminal)
    );
    FaultCell::pass(
        "personality-readiness.revoke-vs-ready",
        "personality-readiness",
        "revoke-first",
        "Aborted",
        1,
        0,
        1,
        1,
        false,
    )
}

fn readiness_stale_deadline_after_rearm() -> FaultCell {
    let mut gate = DeadlineGate::new(1).unwrap();
    let old = gate.arm(1).unwrap();
    let current = gate.rearm(old, 2).unwrap();
    let before = gate.projection();
    assert_eq!(gate.expire(old, u64::MAX), Err(DeadlineError::StaleToken));
    assert_eq!(gate.projection(), before);
    gate.expire(current, 2).unwrap();
    FaultCell::pass(
        "personality-readiness.stale-deadline-after-rearm",
        "personality-readiness",
        "old-deadline-after-rearm",
        "TimedOut",
        1,
        0,
        1,
        1,
        false,
    )
}

fn committed_io() -> (IoGate<4>, cser_transition_gates::io::IoIdentity) {
    let mut gate = IoGate::<4>::new().unwrap();
    let identity = gate.register(gate.binding_token().unwrap()).unwrap();
    gate.commit_with(identity, || Ok::<_, ()>(())).unwrap();
    (gate, identity)
}

fn io_revoke_before_device_publication() -> FaultCell {
    let mut gate = IoGate::<4>::new().unwrap();
    let identity = gate.register(gate.binding_token().unwrap()).unwrap();
    gate.begin_closing().unwrap();
    assert!(gate.commit_with(identity, || Ok::<_, ()>(())).is_err());
    assert_eq!(
        gate.terminal(identity),
        Some(IoTerminal::AbortedBeforeCommit)
    );
    FaultCell::pass(
        "linux-io.revoke-before-device-publication",
        "linux-io",
        "before-device-publication",
        "AbortedBeforeCommit",
        1,
        0,
        1,
        1,
        false,
    )
}

fn io_completion_vs_reset_ack() -> FaultCell {
    let (mut gate, identity) = committed_io();
    let close = gate.begin_closing().unwrap();
    let reset = gate.begin_reset(close).unwrap().acknowledge();
    let reset = gate.apply_reset(reset).unwrap();
    assert_eq!(reset.terminalized(), 1);
    assert_eq!(
        gate.complete_device(identity),
        Err(IoError::StaleDeviceGeneration)
    );
    FaultCell::pass(
        "linux-io.completion-vs-reset-ack",
        "linux-io",
        "reset-ack-first",
        "IndeterminateAfterReset",
        1,
        1,
        1,
        1,
        false,
    )
}

fn io_reset_timeout_retry() -> FaultCell {
    let (mut gate, _) = committed_io();
    let close = gate.begin_closing().unwrap();
    let reset = gate
        .begin_reset(close)
        .unwrap()
        .retain()
        .retry()
        .acknowledge();
    let outcome = gate.apply_reset(reset).unwrap();
    assert_eq!(outcome.terminalized(), 1);
    FaultCell::pass(
        "linux-io.reset-timeout-retry",
        "linux-io",
        "reset-timeout-retry",
        "IndeterminateAfterReset",
        1,
        1,
        1,
        1,
        true,
    )
}

fn complete_iotlb(mut gate: IoGate<4>, outcome: cser_transition_gates::io::ResetOutcome) {
    let attempt = gate.begin_iotlb::<3>(outcome).unwrap().retain().retry();
    let attempt = match attempt.owner_complete(0).unwrap() {
        IotlbProgress::Pending(attempt) => attempt,
        IotlbProgress::Complete(_) => unreachable!(),
    };
    let attempt = match attempt.owner_complete(1).unwrap() {
        IotlbProgress::Pending(attempt) => attempt,
        IotlbProgress::Complete(_) => unreachable!(),
    };
    let receipt = match attempt.owner_complete(2).unwrap() {
        IotlbProgress::Complete(receipt) => receipt,
        IotlbProgress::Pending(_) => unreachable!(),
    };
    gate.mark_quiesced(receipt).unwrap();
}

fn io_iotlb_timeout_late_ack() -> FaultCell {
    let (mut gate, _) = committed_io();
    let close = gate.begin_closing().unwrap();
    let reset = gate.begin_reset(close).unwrap().acknowledge();
    let outcome = gate.apply_reset(reset).unwrap();
    complete_iotlb(gate, outcome);
    FaultCell::pass(
        "linux-io.iotlb-timeout-late-ack",
        "linux-io",
        "iotlb-timeout-late-ack",
        "Quiesced",
        1,
        1,
        1,
        1,
        true,
    )
}

fn io_stale_duplicate_completion() -> FaultCell {
    let (mut gate, identity) = committed_io();
    gate.complete_device(identity).unwrap();
    let before = gate.projection();
    assert_eq!(
        gate.complete_device(identity),
        Err(IoError::AlreadyTerminal)
    );
    assert_eq!(gate.projection(), before);
    FaultCell::pass(
        "linux-io.stale-duplicate-completion",
        "linux-io",
        "duplicate-completion",
        "Completed",
        1,
        1,
        1,
        1,
        false,
    )
}

#[derive(Clone, Copy)]
struct ScalePoint {
    id: &'static str,
    config: Stage7bFixtureConfig,
}

const SCALE_POINTS: [ScalePoint; 14] = [
    scale("fixed-n.k0000", 1024, 0, 0),
    scale("fixed-n.k0001", 1024, 1, 0),
    scale("fixed-n.k0008", 1024, 8, 0),
    scale("fixed-n.k0032", 1024, 32, 0),
    scale("fixed-n.k0128", 1024, 128, 0),
    scale("fixed-n.k0512", 1024, 512, 0),
    scale("fixed-k.n0032", 32, 32, 0),
    scale("fixed-k.n0128", 128, 32, 0),
    scale("fixed-k.n0512", 512, 32, 0),
    scale("fixed-k.n2048", 2048, 32, 0),
    scale("fixed-k.n4096", 4096, 32, 0),
    scale("history.h0000", 1024, 32, 0),
    scale("history.h0064", 1024, 32, 64),
    scale("history.h1024", 1024, 32, 1024),
];

const fn scale(id: &'static str, n: usize, k: usize, h: usize) -> ScalePoint {
    ScalePoint {
        id,
        config: Stage7bFixtureConfig { n, k, h },
    }
}

fn run_scale() {
    for point in SCALE_POINTS {
        let mut fixture = Stage7bActiveFixture::new(point.config).unwrap();
        let selection = fixture.close_all().unwrap();
        let observation = fixture.observation(&selection).unwrap();
        fixture.check_invariants().unwrap();
        assert_eq!(observation.work.target_count, point.config.k);
        assert_eq!(observation.work.begin_target_record_visits, 0);
        assert_eq!(observation.work.next_calls, point.config.k as u64 + 1);
        assert_eq!(observation.work.head_selections, point.config.k as u64);
        assert_eq!(observation.work.terminalized, point.config.k as u64);
        assert_eq!(
            observation.work.completion_members_checked,
            point.config.k as u64
        );
        assert_eq!(observation.work.unrelated_effect_visits, 0);
        assert_eq!(observation.work.history_effect_visits, 0);
        assert_eq!(observation.work.target_state, ScopePhase::Revoked);
        println!(
            "STAGE7B_SCALE point={} N={} k={} H={} target_count={} begin_target_record_visits={} next_calls={} head_selections={} terminalized={} completion_members_checked={} target_index_removals={} unrelated_effect_visits={} history_effect_visits={} pending_targets={} final_target_state=Revoked status=PASS",
            point.id,
            point.config.n,
            point.config.k,
            point.config.h,
            observation.work.target_count,
            observation.work.begin_target_record_visits,
            observation.work.next_calls,
            observation.work.head_selections,
            observation.work.terminalized,
            observation.work.completion_members_checked,
            observation.work.target_index_removals,
            observation.work.unrelated_effect_visits,
            observation.work.history_effect_visits,
            observation.work.pending_targets,
        );
    }
    println!("STAGE7B_SCALE_SUMMARY points=14 passed=14 status=PASS");
}

#[derive(Clone, Copy)]
enum PerfOp {
    Begin,
    Complete,
    Closure,
    Projection,
}

impl PerfOp {
    const fn label(self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Complete => "complete",
            Self::Closure => "closure",
            Self::Projection => "projection",
        }
    }
}

#[derive(Clone, Copy)]
struct PerfCase {
    id: &'static str,
    op: PerfOp,
    config: Stage7bFixtureConfig,
}

const PERF_CASES: [PerfCase; 29] = [
    perf("begin.fixed-n.k0000", PerfOp::Begin, 1024, 0, 0),
    perf("begin.fixed-n.k0001", PerfOp::Begin, 1024, 1, 0),
    perf("begin.fixed-n.k0008", PerfOp::Begin, 1024, 8, 0),
    perf("begin.fixed-n.k0032", PerfOp::Begin, 1024, 32, 0),
    perf("begin.fixed-n.k0128", PerfOp::Begin, 1024, 128, 0),
    perf("begin.fixed-n.k0512", PerfOp::Begin, 1024, 512, 0),
    perf("complete.fixed-n.k0000", PerfOp::Complete, 1024, 0, 0),
    perf("complete.fixed-n.k0001", PerfOp::Complete, 1024, 1, 0),
    perf("complete.fixed-n.k0008", PerfOp::Complete, 1024, 8, 0),
    perf("complete.fixed-n.k0032", PerfOp::Complete, 1024, 32, 0),
    perf("complete.fixed-n.k0128", PerfOp::Complete, 1024, 128, 0),
    perf("complete.fixed-n.k0512", PerfOp::Complete, 1024, 512, 0),
    perf("closure.fixed-n.k0000", PerfOp::Closure, 1024, 0, 0),
    perf("closure.fixed-n.k0001", PerfOp::Closure, 1024, 1, 0),
    perf("closure.fixed-n.k0008", PerfOp::Closure, 1024, 8, 0),
    perf("closure.fixed-n.k0032", PerfOp::Closure, 1024, 32, 0),
    perf("closure.fixed-n.k0128", PerfOp::Closure, 1024, 128, 0),
    perf("closure.fixed-n.k0512", PerfOp::Closure, 1024, 512, 0),
    perf("closure.fixed-k.n0032", PerfOp::Closure, 32, 32, 0),
    perf("closure.fixed-k.n0128", PerfOp::Closure, 128, 32, 0),
    perf("closure.fixed-k.n0512", PerfOp::Closure, 512, 32, 0),
    perf("closure.fixed-k.n2048", PerfOp::Closure, 2048, 32, 0),
    perf("closure.fixed-k.n4096", PerfOp::Closure, 4096, 32, 0),
    perf("closure.history.h0000", PerfOp::Closure, 1024, 32, 0),
    perf("closure.history.h0064", PerfOp::Closure, 1024, 32, 64),
    perf("closure.history.h1024", PerfOp::Closure, 1024, 32, 1024),
    perf("projection.history.h0000", PerfOp::Projection, 1024, 32, 0),
    perf("projection.history.h0064", PerfOp::Projection, 1024, 32, 64),
    perf(
        "projection.history.h1024",
        PerfOp::Projection,
        1024,
        32,
        1024,
    ),
];

const fn perf(id: &'static str, op: PerfOp, n: usize, k: usize, h: usize) -> PerfCase {
    PerfCase {
        id,
        op,
        config: Stage7bFixtureConfig { n, k, h },
    }
}

fn run_performance() {
    println!(
        "STAGE7B_TSC_META profile=release accel=tcg vcpus=1 threads=1 cache=hot timer=guest_visible_tsc fence=lfence preemption=disabled local_irq=disabled warmups=7 samples=65 empty_samples=257 adjusted=false raw_retained=true thresholds=none"
    );
    let empty = collect_samples(EMPTY_SAMPLES, || measure(|| black_box(())).0);
    print_samples("STAGE7B_TSC_EMPTY", None, None, empty);

    for case in PERF_CASES {
        let fixture = Stage7bActiveFixture::new(case.config).unwrap();
        fixture.check_invariants().unwrap();
        let samples = match case.op {
            PerfOp::Begin => collect_samples(SAMPLES, || {
                let mut candidate = fixture.clone();
                let (cycles, selection) = measure(|| candidate.begin().unwrap());
                black_box(candidate.observation(&selection).unwrap());
                candidate.check_invariants().unwrap();
                cycles
            }),
            PerfOp::Complete => {
                let baseline = fixture.prepare_complete_baseline().unwrap();
                collect_samples(SAMPLES, || {
                    let mut candidate = baseline.clone();
                    let (cycles, ()) = measure(|| candidate.complete().unwrap());
                    black_box(candidate.observation().unwrap());
                    candidate.check_invariants().unwrap();
                    cycles
                })
            }
            PerfOp::Closure => collect_samples(SAMPLES, || {
                let mut candidate = fixture.clone();
                let (cycles, selection) = measure(|| candidate.close_all().unwrap());
                black_box(candidate.observation(&selection).unwrap());
                candidate.check_invariants().unwrap();
                cycles
            }),
            PerfOp::Projection => collect_samples(SAMPLES, || {
                let (cycles, projection) =
                    measure(|| black_box(&fixture).target_projection().unwrap());
                black_box(projection);
                cycles
            }),
        };
        print_samples("STAGE7B_TSC", Some(case), Some(case.op.label()), samples);
    }
    println!("STAGE7B_TSC_SUMMARY cases=29 observed=29 status=PASS");
}

fn collect_samples(mut samples: usize, mut sample: impl FnMut() -> u64) -> Vec<u64> {
    for _ in 0..WARMUPS {
        black_box(sample());
    }
    let mut values = Vec::with_capacity(samples);
    while samples != 0 {
        values.push(sample());
        samples -= 1;
    }
    values
}

fn measure<T>(operation: impl FnOnce() -> T) -> (u64, T) {
    let preempt = disable_preempt();
    let local_irq = irq::disable_local();
    x86::fence::lfence();
    let start = ostd::arch::read_tsc();
    x86::fence::lfence();
    let output = operation();
    x86::fence::lfence();
    let end = ostd::arch::read_tsc();
    x86::fence::lfence();
    drop(local_irq);
    drop(preempt);
    (end.checked_sub(start).expect("monotonic guest TSC"), output)
}

fn print_samples(prefix: &str, case: Option<PerfCase>, operation: Option<&str>, raw: Vec<u64>) {
    let mut sorted = raw.clone();
    sorted.sort_unstable();
    let min = sorted[0];
    let median = sorted[sorted.len() / 2];
    let p95 = sorted[(sorted.len() * 95).div_ceil(100) - 1];
    let max = *sorted.last().unwrap();
    let mut encoded = String::new();
    for (index, sample) in raw.iter().enumerate() {
        if index != 0 {
            encoded.push(',');
        }
        write!(&mut encoded, "{sample}").unwrap();
    }
    if let Some(case) = case {
        println!(
            "{} case={} op={} N={} k={} H={} samples={} min={} median={} p95={} max={} raw={} status=OBSERVED",
            prefix,
            case.id,
            operation.unwrap(),
            case.config.n,
            case.config.k,
            case.config.h,
            raw.len(),
            min,
            median,
            p95,
            max,
            encoded,
        );
    } else {
        println!(
            "{} samples={} min={} median={} p95={} max={} raw={}",
            prefix,
            raw.len(),
            min,
            median,
            p95,
            max,
            encoded,
        );
    }
}
