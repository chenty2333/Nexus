// SPDX-License-Identifier: MPL-2.0

use alloc::{string::String, vec::Vec};
use core::{fmt::Write as _, hint::black_box};

use cser_transition_gates::{
    deadline::{DeadlineError, DeadlineGate, DeadlineProjection, DeadlineToken, ExpiryReceipt},
    io::{
        IoCommitReceipt, IoError, IoGate, IoIdentity, IoPhase, IoProjection, IoTerminal,
        IotlbProgress, QuiescenceReceipt, ResetOutcome,
    },
    oneshot::{
        OneShotError, OneShotGate, OneShotProjection, OneShotToken,
        TerminalReceipt as OneShotTerminalReceipt,
    },
    pager::{
        ContinuationOutcome, ContinuationReceipt, FaultKey, FaultTicket, PagerError, PagerGate,
        PagerLifecycle, PagerProjection, PagerRevokeReceipt,
    },
    scheduler::{
        FallbackPick, SchedulerCrashReceipt, SchedulerError, SchedulerGate, SchedulerProjection,
    },
};
use ostd::{irq, prelude::*, task::disable_preempt};

use crate::effect_registry::{
    RegistryError, RegistryProjection, ScopePhase, Stage7bActiveFixture, Stage7bFaultBinding,
    Stage7bFaultBudget, Stage7bFaultBudgetProjection, Stage7bFaultCase, Stage7bFaultCredit,
    Stage7bFaultOperation, Stage7bFaultTerminal, Stage7bFixtureConfig, Stage7bNoCredit,
    Stage7bNoCreditProjection, TerminalOutcome, stage7b_causal_commit_self_test,
};

const WARMUPS: usize = 7;
const SAMPLES: usize = 65;
const EMPTY_SAMPLES: usize = 257;
const FAULT_BUDGET_INSTANCE_PREFIX: u64 = 0x5354_3742_4642_0000;
const FOREIGN_BUDGET_INSTANCE_A: u64 = 0x5354_3742_4642_ff01;
const FOREIGN_BUDGET_INSTANCE_B: u64 = 0x5354_3742_4642_ff02;

fn fault_budget_instance_id(case: Stage7bFaultCase) -> u64 {
    FAULT_BUDGET_INSTANCE_PREFIX
        .checked_add(u64::from(case.tag()))
        .unwrap()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultTerminal {
    FallbackPick,
    Resolved,
    Aborted,
    Completed,
    Ready,
    TimedOut,
    AbortedBeforeCommit,
    IndeterminateAfterReset,
    Quiesced,
}

impl FaultTerminal {
    const fn label(self) -> &'static str {
        match self {
            Self::FallbackPick => "FallbackPick",
            Self::Resolved => "Resolved",
            Self::Aborted => "Aborted",
            Self::Completed => "Completed",
            Self::Ready => "Ready",
            Self::TimedOut => "TimedOut",
            Self::AbortedBeforeCommit => "AbortedBeforeCommit",
            Self::IndeterminateAfterReset => "IndeterminateAfterReset",
            Self::Quiesced => "Quiesced",
        }
    }
}

#[derive(Clone, Copy)]
struct FaultSpec {
    id: &'static str,
    family: &'static str,
    injection: &'static str,
    expected_terminal: FaultTerminal,
    expected_terminalizations: usize,
    expected_publications: usize,
    expected_credits: usize,
    expected_retained: bool,
}

const fn fault_spec(
    id: &'static str,
    family: &'static str,
    injection: &'static str,
    expected_terminal: FaultTerminal,
    expected_terminalizations: usize,
    expected_publications: usize,
    expected_credits: usize,
    expected_retained: bool,
) -> FaultSpec {
    FaultSpec {
        id,
        family,
        injection,
        expected_terminal,
        expected_terminalizations,
        expected_publications,
        expected_credits,
        expected_retained,
    }
}

const FAULT_SPECS: [FaultSpec; 20] = [
    fault_spec(
        "scheduler.lease-expiry-before-proposal",
        "scheduler",
        "lease-expiry",
        FaultTerminal::FallbackPick,
        1,
        1,
        0,
        false,
    ),
    fault_spec(
        "scheduler.crash-after-proposal-before-pick",
        "scheduler",
        "after-proposal",
        FaultTerminal::FallbackPick,
        1,
        1,
        0,
        false,
    ),
    fault_spec(
        "scheduler.stale-proposal-before-rebind",
        "scheduler",
        "before-rebind",
        FaultTerminal::FallbackPick,
        1,
        1,
        0,
        false,
    ),
    fault_spec(
        "scheduler.stale-proposal-after-rebind",
        "scheduler",
        "after-rebind",
        FaultTerminal::FallbackPick,
        1,
        1,
        0,
        false,
    ),
    fault_spec(
        "scheduler.repeated-crash-fallback-progress",
        "scheduler",
        "repeated-crash",
        FaultTerminal::FallbackPick,
        1,
        1,
        0,
        false,
    ),
    fault_spec(
        "pager.same-page-concurrent-fault",
        "pager",
        "same-page-register",
        FaultTerminal::Resolved,
        2,
        1,
        2,
        false,
    ),
    fault_spec(
        "pager.crash-before-prepare",
        "pager",
        "before-prepare",
        FaultTerminal::Aborted,
        1,
        0,
        1,
        false,
    ),
    fault_spec(
        "pager.crash-after-prepare-before-commit",
        "pager",
        "after-prepare",
        FaultTerminal::Aborted,
        1,
        0,
        1,
        false,
    ),
    fault_spec(
        "pager.crash-after-commit-before-resume",
        "pager",
        "after-commit",
        FaultTerminal::Resolved,
        1,
        1,
        1,
        false,
    ),
    fault_spec(
        "pager.timeout-vs-late-reply",
        "pager",
        "timeout-before-late-reply",
        FaultTerminal::Aborted,
        1,
        0,
        1,
        false,
    ),
    fault_spec(
        "personality-readiness.crash-before-backend-commit",
        "personality-readiness",
        "before-backend-commit",
        FaultTerminal::Aborted,
        1,
        0,
        1,
        false,
    ),
    fault_spec(
        "personality-readiness.crash-after-backend-commit",
        "personality-readiness",
        "after-backend-commit",
        FaultTerminal::Completed,
        1,
        1,
        1,
        false,
    ),
    fault_spec(
        "personality-readiness.ready-vs-timeout",
        "personality-readiness",
        "ready-first",
        FaultTerminal::Ready,
        1,
        1,
        1,
        false,
    ),
    fault_spec(
        "personality-readiness.revoke-vs-ready",
        "personality-readiness",
        "revoke-first",
        FaultTerminal::Aborted,
        1,
        0,
        1,
        false,
    ),
    fault_spec(
        "personality-readiness.stale-deadline-after-rearm",
        "personality-readiness",
        "old-deadline-after-rearm",
        FaultTerminal::TimedOut,
        1,
        0,
        1,
        false,
    ),
    fault_spec(
        "linux-io.revoke-before-device-publication",
        "linux-io",
        "before-device-publication",
        FaultTerminal::AbortedBeforeCommit,
        1,
        0,
        1,
        false,
    ),
    fault_spec(
        "linux-io.completion-vs-reset-ack",
        "linux-io",
        "reset-ack-first",
        FaultTerminal::IndeterminateAfterReset,
        1,
        1,
        1,
        true,
    ),
    fault_spec(
        "linux-io.reset-timeout-retry",
        "linux-io",
        "reset-timeout-retry",
        FaultTerminal::IndeterminateAfterReset,
        1,
        1,
        1,
        true,
    ),
    fault_spec(
        "linux-io.iotlb-timeout-late-ack",
        "linux-io",
        "iotlb-timeout-late-ack",
        FaultTerminal::Quiesced,
        1,
        1,
        1,
        true,
    ),
    fault_spec(
        "linux-io.stale-duplicate-completion",
        "linux-io",
        "duplicate-completion",
        FaultTerminal::Completed,
        1,
        1,
        1,
        false,
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultCounters {
    terminalizations: usize,
    publications: usize,
    credits: usize,
}

trait FaultProjection {
    fn fault_counters(&self) -> FaultCounters;
    fn retained_for_retry(&self) -> bool;
    fn determinately_quiescent(&self) -> bool;
}

#[derive(Clone, Copy)]
struct FaultObservation {
    observed_terminal: FaultTerminal,
    before: FaultCounters,
    after: FaultCounters,
    retained_before_quiescence: bool,
    final_quiescent: bool,
}

impl FaultObservation {
    fn from_projections<P: FaultProjection>(
        observed_terminal: FaultTerminal,
        before: &P,
        retained: &P,
        after: &P,
    ) -> Self {
        Self {
            observed_terminal,
            before: before.fault_counters(),
            after: after.fault_counters(),
            retained_before_quiescence: retained.retained_for_retry(),
            final_quiescent: after.determinately_quiescent(),
        }
    }
}

#[derive(Clone, Copy)]
struct FaultCell {
    spec: FaultSpec,
    observed_terminal: FaultTerminal,
    terminalizations: usize,
    publications: usize,
    credits_before: usize,
    credits_after: usize,
    retained_before_quiescence: bool,
    final_quiescent: bool,
}

impl FaultCell {
    fn checked(spec: FaultSpec, observation: FaultObservation) -> Self {
        let terminalizations = observation
            .after
            .terminalizations
            .checked_sub(observation.before.terminalizations)
            .expect("fault terminalization counter regressed");
        let publications = observation
            .after
            .publications
            .checked_sub(observation.before.publications)
            .expect("fault publication counter regressed");
        let cell = Self {
            spec,
            observed_terminal: observation.observed_terminal,
            terminalizations,
            publications,
            credits_before: observation.before.credits,
            credits_after: observation.after.credits,
            retained_before_quiescence: observation.retained_before_quiescence,
            final_quiescent: observation.final_quiescent,
        };
        assert_eq!(cell.observed_terminal, cell.spec.expected_terminal);
        assert_eq!(cell.terminalizations, cell.spec.expected_terminalizations);
        assert_eq!(cell.publications, cell.spec.expected_publications);
        assert_eq!(cell.credits_before, cell.spec.expected_credits);
        assert_eq!(cell.credits_after, cell.spec.expected_credits);
        assert_eq!(cell.retained_before_quiescence, cell.spec.expected_retained);
        assert!(cell.final_quiescent);
        cell
    }

    fn print(self) {
        println!(
            "STAGE7B_FAULT id={} family={} injection_point={} expected_terminal={} observed_terminal={} terminalizations={} publications={} credits_before={} credits_after={} retained_before_quiescence={} final_quiescent={} status=PASS",
            self.spec.id,
            self.spec.family,
            self.spec.injection,
            self.spec.expected_terminal.label(),
            self.observed_terminal.label(),
            self.terminalizations,
            self.publications,
            self.credits_before,
            self.credits_after,
            self.retained_before_quiescence,
            self.final_quiescent,
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
    stage7b_causal_commit_self_test();
    check_fault_budget_instance_isolation();
    let observations = [
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
    let mut passed = 0;
    for (spec, observation) in FAULT_SPECS.into_iter().zip(observations) {
        FaultCell::checked(spec, observation).print();
        passed += 1;
    }
    println!(
        "STAGE7B_FAULT_SUMMARY cells={} passed={} status=PASS",
        FAULT_SPECS.len(),
        passed
    );
}

#[derive(Clone, Copy)]
struct SchedulerFaultProjection<P: Copy + Eq> {
    gate: SchedulerProjection<P>,
    budget: Stage7bNoCreditProjection,
}

impl<P: Copy + Eq> FaultProjection for SchedulerFaultProjection<P> {
    fn fault_counters(&self) -> FaultCounters {
        let selections = usize::try_from(self.gate.fallback_selection_attempts).unwrap();
        FaultCounters {
            terminalizations: selections,
            publications: selections,
            credits: self.budget.case.credit_capacity(),
        }
    }

    fn retained_for_retry(&self) -> bool {
        self.gate.pending.is_some()
    }

    fn determinately_quiescent(&self) -> bool {
        self.gate.pending.is_none()
            && self.gate.first_fallback_pick.is_some()
            && self.budget.binding.case() == self.budget.case
            && self.budget.consumed
    }
}

fn scheduler_fault_binding(
    case: Stage7bFaultCase,
    crash: SchedulerCrashReceipt,
    task_id: u64,
    selection_attempt: u64,
) -> Stage7bFaultBinding {
    Stage7bFaultBinding::new(
        case,
        Stage7bFaultOperation::SchedulerFallbackPick,
        [
            task_id,
            selection_attempt,
            crash.previous_binding_epoch,
            crash.binding_epoch,
            crash.crash_tick,
        ],
    )
}

fn scheduler_no_credit(case: Stage7bFaultCase, crash: SchedulerCrashReceipt) -> Stage7bNoCredit {
    Stage7bNoCredit::new(case, scheduler_fault_binding(case, crash, 7, 1)).unwrap()
}

fn scheduler_with_fallback() -> (SchedulerGate<u64>, SchedulerCrashReceipt) {
    let mut gate = SchedulerGate::new(1, 2).unwrap();
    let binding = gate.binding();
    let crash = gate.enter_fallback(binding).unwrap();
    (gate, crash)
}

fn observe_scheduler(
    crash: SchedulerCrashReceipt,
    pick: FallbackPick,
    before: SchedulerProjection<u64>,
    after: SchedulerProjection<u64>,
    budget_before: Stage7bNoCreditProjection,
    budget_after: Stage7bNoCreditProjection,
) -> FaultObservation {
    assert_eq!(crash.binding_epoch, crash.previous_binding_epoch + 1);
    assert_eq!(pick.selection_attempt, 1);
    assert_ne!(pick.task_id, 0);
    assert_eq!(after.first_fallback_pick, Some(pick));
    assert_eq!(budget_before.case, budget_after.case);
    assert_eq!(budget_before.binding, budget_after.binding);
    assert!(!budget_before.consumed);
    assert!(budget_after.consumed);
    let before = SchedulerFaultProjection {
        gate: before,
        budget: budget_before,
    };
    let after = SchedulerFaultProjection {
        gate: after,
        budget: budget_after,
    };
    FaultObservation::from_projections(FaultTerminal::FallbackPick, &before, &before, &after)
}

fn scheduler_lease_expiry_before_proposal() -> FaultObservation {
    let case = Stage7bFaultCase::SchedulerLeaseExpiryBeforeProposal;
    let mut gate = SchedulerGate::<u64>::new(1, 2).unwrap();
    let old = gate.binding();
    assert!(gate.tick().unwrap().is_none());
    let crash = gate.tick().unwrap().unwrap();
    assert_eq!(
        gate.prepare(old, true, 1),
        Err(SchedulerError::StaleBinding)
    );
    let mut budget = scheduler_no_credit(case, crash);
    let budget_before = budget.projection();
    let before = gate.projection();
    let pick = gate.note_fallback_pick(7).unwrap();
    budget
        .consume(scheduler_fault_binding(
            case,
            crash,
            pick.task_id,
            pick.selection_attempt,
        ))
        .unwrap();
    observe_scheduler(
        crash,
        pick,
        before,
        gate.projection(),
        budget_before,
        budget.projection(),
    )
}

fn scheduler_crash_after_proposal_before_pick() -> FaultObservation {
    let case = Stage7bFaultCase::SchedulerCrashAfterProposalBeforePick;
    let mut gate = SchedulerGate::new(1, 4).unwrap();
    let binding = gate.binding();
    gate.prepare(binding, true, 3_u64).unwrap();
    let crash = gate.enter_fallback(binding).unwrap();
    assert!(crash.pending_cleared);
    let mut budget = scheduler_no_credit(case, crash);
    let budget_before = budget.projection();
    let before = gate.projection();
    let pick = gate.note_fallback_pick(7).unwrap();
    budget
        .consume(scheduler_fault_binding(
            case,
            crash,
            pick.task_id,
            pick.selection_attempt,
        ))
        .unwrap();
    observe_scheduler(
        crash,
        pick,
        before,
        gate.projection(),
        budget_before,
        budget.projection(),
    )
}

fn scheduler_stale_proposal_before_rebind() -> FaultObservation {
    let case = Stage7bFaultCase::SchedulerStaleProposalBeforeRebind;
    let (mut gate, crash) = scheduler_with_fallback();
    let stale = cser_transition_gates::scheduler::SchedulerBinding {
        authority_epoch: 1,
        binding_epoch: 1,
    };
    assert_eq!(
        gate.prepare(stale, true, 2),
        Err(SchedulerError::StaleBinding)
    );
    let mut budget = scheduler_no_credit(case, crash);
    let budget_before = budget.projection();
    let before = gate.projection();
    let pick = gate.note_fallback_pick(7).unwrap();
    budget
        .consume(scheduler_fault_binding(
            case,
            crash,
            pick.task_id,
            pick.selection_attempt,
        ))
        .unwrap();
    gate.rebind(1).unwrap();
    observe_scheduler(
        crash,
        pick,
        before,
        gate.projection(),
        budget_before,
        budget.projection(),
    )
}

fn scheduler_stale_proposal_after_rebind() -> FaultObservation {
    let case = Stage7bFaultCase::SchedulerStaleProposalAfterRebind;
    let (mut gate, crash) = scheduler_with_fallback();
    let stale = cser_transition_gates::scheduler::SchedulerBinding {
        authority_epoch: 1,
        binding_epoch: 1,
    };
    let mut budget = scheduler_no_credit(case, crash);
    let budget_before = budget.projection();
    let before = gate.projection();
    let pick = gate.note_fallback_pick(7).unwrap();
    budget
        .consume(scheduler_fault_binding(
            case,
            crash,
            pick.task_id,
            pick.selection_attempt,
        ))
        .unwrap();
    gate.rebind(1).unwrap();
    assert_eq!(
        gate.prepare(stale, true, 2),
        Err(SchedulerError::StaleBinding)
    );
    observe_scheduler(
        crash,
        pick,
        before,
        gate.projection(),
        budget_before,
        budget.projection(),
    )
}

fn scheduler_repeated_crash_fallback_progress() -> FaultObservation {
    let case = Stage7bFaultCase::SchedulerRepeatedCrashFallbackProgress;
    let (mut gate, crash) = scheduler_with_fallback();
    let mut budget = scheduler_no_credit(case, crash);
    let budget_before = budget.projection();
    let before = gate.projection();
    assert_eq!(
        gate.enter_fallback(gate.binding()),
        Err(SchedulerError::AlreadyFallback)
    );
    assert_eq!(gate.projection(), before);
    let pick = gate.note_fallback_pick(7).unwrap();
    budget
        .consume(scheduler_fault_binding(
            case,
            crash,
            pick.task_id,
            pick.selection_attempt,
        ))
        .unwrap();
    observe_scheduler(
        crash,
        pick,
        before,
        gate.projection(),
        budget_before,
        budget.projection(),
    )
}

fn pager_key() -> FaultKey {
    FaultKey {
        address_space_id: 1,
        address_space_generation: 1,
        page_address: 0x4000,
    }
}

#[derive(Clone, Copy)]
struct PagerFaultProjection {
    gate: PagerProjection,
    budget: Stage7bFaultBudgetProjection,
}

impl FaultProjection for PagerFaultProjection {
    fn fault_counters(&self) -> FaultCounters {
        FaultCounters {
            terminalizations: self.gate.terminalizations,
            publications: usize::try_from(self.gate.mapping_publications).unwrap(),
            credits: self.budget.observed_credit_units().unwrap(),
        }
    }

    fn retained_for_retry(&self) -> bool {
        self.gate.lifecycle == PagerLifecycle::Closing
            && self.gate.terminalizations < self.gate.waiter_count
    }

    fn determinately_quiescent(&self) -> bool {
        self.gate.lifecycle == PagerLifecycle::Revoked
            && self.gate.terminalizations == self.gate.waiter_count
            && self.gate.waiter_count != 0
            && fault_budget_projection_is_quiescent(&self.budget)
    }
}

fn pager_fault_binding(case: Stage7bFaultCase, ticket: FaultTicket) -> Stage7bFaultBinding {
    Stage7bFaultBinding::new(
        case,
        Stage7bFaultOperation::PagerContinuation,
        [
            ticket.slot_generation(),
            ticket.continuation_id(),
            ticket.authority_epoch(),
            0,
            0,
        ],
    )
}

fn terminalize_pager_credit(
    budget: &mut Stage7bFaultBudget,
    credit: &mut Stage7bFaultCredit,
    binding: Stage7bFaultBinding,
    receipt: ContinuationReceipt,
) {
    let terminal = match receipt.outcome {
        ContinuationOutcome::Resolved => Stage7bFaultTerminal::Completed(0),
        ContinuationOutcome::Aborted => Stage7bFaultTerminal::Aborted(0),
    };
    let registry_terminal = budget.terminalize(credit, binding, terminal).unwrap();
    assert_eq!(
        registry_terminal,
        match receipt.outcome {
            ContinuationOutcome::Resolved => TerminalOutcome::Completed,
            ContinuationOutcome::Aborted => TerminalOutcome::Aborted,
        }
    );
}

fn observed_pager_terminal(receipts: &[ContinuationReceipt]) -> FaultTerminal {
    let first = receipts
        .first()
        .expect("pager fault lacks terminal receipt");
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.outcome == first.outcome)
    );
    match first.outcome {
        ContinuationOutcome::Resolved => FaultTerminal::Resolved,
        ContinuationOutcome::Aborted => FaultTerminal::Aborted,
    }
}

fn observe_pager(
    receipts: &[ContinuationReceipt],
    revoke: PagerRevokeReceipt,
    before: PagerProjection,
    retained: PagerProjection,
    after: PagerProjection,
    budget_before: Stage7bFaultBudgetProjection,
    budget_retained: Stage7bFaultBudgetProjection,
    budget_after: Stage7bFaultBudgetProjection,
) -> FaultObservation {
    assert_eq!(revoke.authority_epoch, revoke.closed_authority_epoch + 1);
    assert_eq!(after.authority_epoch, revoke.authority_epoch);
    assert_eq!(before.waiter_count, after.waiter_count);
    assert_eq!(budget_before.case, budget_retained.case);
    assert_eq!(budget_before.case, budget_after.case);
    assert_fault_budget_lineage(&budget_before, &budget_retained, &budget_after);
    assert_eq!(budget_before.reservations, receipts.len());
    assert_eq!(budget_after.terminal_operations, receipts.len());
    let before = PagerFaultProjection {
        gate: before,
        budget: budget_before,
    };
    let retained = PagerFaultProjection {
        gate: retained,
        budget: budget_retained,
    };
    let after = PagerFaultProjection {
        gate: after,
        budget: budget_after,
    };
    FaultObservation::from_projections(
        observed_pager_terminal(receipts),
        &before,
        &retained,
        &after,
    )
}

fn pager_same_page_concurrent_fault() -> FaultObservation {
    let case = Stage7bFaultCase::PagerSamePageConcurrentFault;
    let mut gate = PagerGate::<2>::new(1, 1, 10).unwrap();
    let leader = gate.register(pager_key(), 100).unwrap().ticket();
    let follower = gate.register(pager_key(), 101).unwrap().ticket();
    let leader_binding = pager_fault_binding(case, leader);
    let follower_binding = pager_fault_binding(case, follower);
    let mut budget = Stage7bFaultBudget::new(case, fault_budget_instance_id(case)).unwrap();
    let mut leader_credit = budget.reserve(leader_binding).unwrap();
    let mut follower_credit = budget.reserve(follower_binding).unwrap();
    let before = gate.projection();
    let budget_before = budget.projection().unwrap();
    gate.prepare_leader(leader).unwrap();
    let (mapping, ()) = gate
        .commit_mapping_with(leader, || {
            budget.commit(&mut leader_credit, leader_binding, 0)?;
            budget.commit(&mut follower_credit, follower_binding, 0)
        })
        .unwrap();
    let leader_receipt = gate
        .terminalize(leader, Some(mapping), ContinuationOutcome::Resolved)
        .unwrap();
    terminalize_pager_credit(
        &mut budget,
        &mut leader_credit,
        leader_binding,
        leader_receipt,
    );
    let follower_receipt = gate
        .terminalize(follower, Some(mapping), ContinuationOutcome::Resolved)
        .unwrap();
    terminalize_pager_credit(
        &mut budget,
        &mut follower_credit,
        follower_binding,
        follower_receipt,
    );
    let retained = gate.projection();
    let budget_retained = budget.projection().unwrap();
    let revoke = gate.begin_revoke().unwrap();
    gate.complete_revoke(true).unwrap();
    let budget_after = budget.finish().unwrap();
    observe_pager(
        &[leader_receipt, follower_receipt],
        revoke,
        before,
        retained,
        gate.projection(),
        budget_before,
        budget_retained,
        budget_after,
    )
}

fn close_aborted_pager(case: Stage7bFaultCase, prepared: bool) -> FaultObservation {
    let mut gate = PagerGate::<2>::new(1, 1, 10).unwrap();
    let ticket = gate.register(pager_key(), 100).unwrap().ticket();
    let binding = pager_fault_binding(case, ticket);
    let mut budget = Stage7bFaultBudget::new(case, fault_budget_instance_id(case)).unwrap();
    let mut credit = budget.reserve(binding).unwrap();
    let before = gate.projection();
    let budget_before = budget.projection().unwrap();
    if prepared {
        gate.prepare_leader(ticket).unwrap();
    }
    gate.crash(1).unwrap();
    let terminal = gate.abort_orphan(ticket).unwrap();
    terminalize_pager_credit(&mut budget, &mut credit, binding, terminal);
    let retained = gate.projection();
    let budget_retained = budget.projection().unwrap();
    let revoke = gate.begin_revoke().unwrap();
    gate.complete_revoke(true).unwrap();
    let budget_after = budget.finish().unwrap();
    observe_pager(
        &[terminal],
        revoke,
        before,
        retained,
        gate.projection(),
        budget_before,
        budget_retained,
        budget_after,
    )
}

fn pager_crash_before_prepare() -> FaultObservation {
    close_aborted_pager(Stage7bFaultCase::PagerCrashBeforePrepare, false)
}

fn pager_crash_after_prepare_before_commit() -> FaultObservation {
    close_aborted_pager(Stage7bFaultCase::PagerCrashAfterPrepareBeforeCommit, true)
}

fn pager_crash_after_commit_before_resume() -> FaultObservation {
    let case = Stage7bFaultCase::PagerCrashAfterCommitBeforeResume;
    let mut gate = PagerGate::<2>::new(1, 1, 10).unwrap();
    let ticket = gate.register(pager_key(), 100).unwrap().ticket();
    let binding = pager_fault_binding(case, ticket);
    let mut budget = Stage7bFaultBudget::new(case, fault_budget_instance_id(case)).unwrap();
    let mut credit = budget.reserve(binding).unwrap();
    let before = gate.projection();
    let budget_before = budget.projection().unwrap();
    gate.prepare_leader(ticket).unwrap();
    let (mapping, ()) = gate
        .commit_mapping_with(ticket, || budget.commit(&mut credit, binding, 0))
        .unwrap();
    gate.crash(1).unwrap();
    let terminal = gate.terminalize_published_kernel(ticket, mapping).unwrap();
    terminalize_pager_credit(&mut budget, &mut credit, binding, terminal);
    let retained = gate.projection();
    let budget_retained = budget.projection().unwrap();
    let revoke = gate.begin_revoke().unwrap();
    gate.complete_revoke(true).unwrap();
    let budget_after = budget.finish().unwrap();
    observe_pager(
        &[terminal],
        revoke,
        before,
        retained,
        gate.projection(),
        budget_before,
        budget_retained,
        budget_after,
    )
}

fn pager_timeout_vs_late_reply() -> FaultObservation {
    let case = Stage7bFaultCase::PagerTimeoutVsLateReply;
    let mut gate = PagerGate::<2>::new(1, 1, 10).unwrap();
    let old = gate.register(pager_key(), 100).unwrap().ticket();
    let binding = pager_fault_binding(case, old);
    let mut budget = Stage7bFaultBudget::new(case, fault_budget_instance_id(case)).unwrap();
    let mut credit = budget.reserve(binding).unwrap();
    let before = gate.projection();
    let budget_before = budget.projection().unwrap();
    gate.prepare_leader(old).unwrap();
    gate.crash(1).unwrap();
    let snapshot = gate.snapshot(11, 1).unwrap();
    gate.ready(snapshot).unwrap();
    gate.rebind(11).unwrap();
    let adopted = gate.adopt(old).unwrap();
    assert_eq!(pager_fault_binding(case, adopted), binding);
    let revoke = gate.begin_revoke().unwrap();
    let terminal = gate
        .terminalize(adopted, None, ContinuationOutcome::Aborted)
        .unwrap();
    terminalize_pager_credit(&mut budget, &mut credit, binding, terminal);
    assert_eq!(gate.reply_gate(1, 1), Err(PagerError::StaleAuthority));
    let retained = gate.projection();
    let budget_retained = budget.projection().unwrap();
    gate.complete_revoke(true).unwrap();
    let budget_after = budget.finish().unwrap();
    observe_pager(
        &[terminal],
        revoke,
        before,
        retained,
        gate.projection(),
        budget_before,
        budget_retained,
        budget_after,
    )
}

#[derive(Clone, Copy)]
struct RegistryFaultProjection {
    budget: Stage7bFaultBudgetProjection,
}

fn registry_projection_is_quiescent(projection: &RegistryProjection) -> bool {
    projection.phase == ScopePhase::Revoked
        && projection.live_effects == 0
        && projection.pending_publications == 0
        && projection.credits.free == projection.credits.capacity
        && projection.credits.held == 0
        && projection.credits.committed == 0
}

fn assert_fault_budget_lineage(
    before: &Stage7bFaultBudgetProjection,
    retained: &Stage7bFaultBudgetProjection,
    after: &Stage7bFaultBudgetProjection,
) {
    assert_eq!(before.case, retained.case);
    assert_eq!(before.case, after.case);
    assert_ne!(before.instance_id, 0);
    assert_eq!(before.instance_id, retained.instance_id);
    assert_eq!(before.instance_id, after.instance_id);
    assert_eq!(before.scope, retained.scope);
    assert_eq!(before.scope, after.scope);
    assert_eq!(
        before.registry.credits.capacity,
        retained.registry.credits.capacity
    );
    assert_eq!(
        before.registry.credits.capacity,
        after.registry.credits.capacity
    );
    assert_eq!(before.registry.phase, ScopePhase::Active);
    assert_eq!(before.registry.credits.free, 0);
    assert_eq!(
        before
            .registry
            .credits
            .held
            .checked_add(before.registry.credits.committed)
            .unwrap(),
        before.registry.credits.capacity
    );
    assert_eq!(after.registry.phase, ScopePhase::Revoked);
    assert_eq!(after.registry.credits.free, after.registry.credits.capacity);
    assert_eq!(after.registry.credits.held, 0);
    assert_eq!(after.registry.credits.committed, 0);
}

fn fault_budget_projection_is_quiescent(projection: &Stage7bFaultBudgetProjection) -> bool {
    projection.reservations == projection.case.credit_capacity()
        && projection.terminal_operations == projection.reservations
        && registry_projection_is_quiescent(&projection.registry)
}

impl FaultProjection for RegistryFaultProjection {
    fn fault_counters(&self) -> FaultCounters {
        FaultCounters {
            terminalizations: self.budget.terminal_operations,
            publications: self.budget.commit_operations,
            credits: self.budget.observed_credit_units().unwrap(),
        }
    }

    fn retained_for_retry(&self) -> bool {
        self.budget.registry.pending_publications != 0
    }

    fn determinately_quiescent(&self) -> bool {
        fault_budget_projection_is_quiescent(&self.budget)
    }
}

fn readiness_backend_binding(case: Stage7bFaultCase) -> Stage7bFaultBinding {
    Stage7bFaultBinding::new(
        case,
        Stage7bFaultOperation::ReadinessCompletion,
        [u64::from(case.tag()), 1, 1, 0, 0],
    )
}

fn check_fault_budget_instance_isolation() {
    let case = Stage7bFaultCase::ReadinessCrashBeforeBackendCommit;
    let binding = readiness_backend_binding(case);
    assert_eq!(
        Stage7bFaultBudget::new(case, 0),
        Err(RegistryError::InvalidCreditConfiguration)
    );
    let mut first = Stage7bFaultBudget::new(case, FOREIGN_BUDGET_INSTANCE_A).unwrap();
    let mut second = Stage7bFaultBudget::new(case, FOREIGN_BUDGET_INSTANCE_B).unwrap();
    let mut first_credit = first.reserve(binding).unwrap();
    let mut second_credit = second.reserve(binding).unwrap();
    let first_before = first.projection().unwrap();
    let second_before = second.projection().unwrap();
    let first_state_before = first.state_snapshot();
    let second_state_before = second.state_snapshot();
    assert_ne!(first_before.instance_id, second_before.instance_id);
    assert_ne!(first_before.scope, second_before.scope);

    assert_eq!(
        first.commit(&mut second_credit, binding, 0),
        Err(RegistryError::InvalidHandle)
    );
    assert_eq!(first.state_snapshot(), first_state_before);
    assert_eq!(second.state_snapshot(), second_state_before);
    assert_eq!(
        second.commit(&mut first_credit, binding, 0),
        Err(RegistryError::InvalidHandle)
    );
    assert_eq!(first.state_snapshot(), first_state_before);
    assert_eq!(second.state_snapshot(), second_state_before);

    assert_eq!(
        first
            .terminalize(&mut first_credit, binding, Stage7bFaultTerminal::Aborted(0),)
            .unwrap(),
        TerminalOutcome::Aborted
    );
    assert_eq!(
        second
            .terminalize(
                &mut second_credit,
                binding,
                Stage7bFaultTerminal::Aborted(0),
            )
            .unwrap(),
        TerminalOutcome::Aborted
    );
    let first_after = first.finish().unwrap();
    let second_after = second.finish().unwrap();
    assert_fault_budget_lineage(&first_before, &first_before, &first_after);
    assert_fault_budget_lineage(&second_before, &second_before, &second_after);
}

fn readiness_backend_operation(case: Stage7bFaultCase, commit_first: bool) -> FaultObservation {
    let binding = readiness_backend_binding(case);
    let mut budget = Stage7bFaultBudget::new(case, fault_budget_instance_id(case)).unwrap();
    let mut credit = budget.reserve(binding).unwrap();
    let before = RegistryFaultProjection {
        budget: budget.projection().unwrap(),
    };
    if commit_first {
        budget.commit(&mut credit, binding, 0).unwrap();
    }
    let terminal = budget
        .terminalize(
            &mut credit,
            binding,
            if commit_first {
                Stage7bFaultTerminal::Completed(0)
            } else {
                Stage7bFaultTerminal::Aborted(0)
            },
        )
        .unwrap();
    let after = RegistryFaultProjection {
        budget: budget.finish().unwrap(),
    };
    assert_fault_budget_lineage(&before.budget, &after.budget, &after.budget);
    let observed_terminal = match terminal {
        TerminalOutcome::Completed => FaultTerminal::Completed,
        TerminalOutcome::Aborted => FaultTerminal::Aborted,
    };
    FaultObservation::from_projections(observed_terminal, &before, &after, &after)
}

fn readiness_crash_before_backend_commit() -> FaultObservation {
    readiness_backend_operation(Stage7bFaultCase::ReadinessCrashBeforeBackendCommit, false)
}

fn readiness_crash_after_backend_commit() -> FaultObservation {
    readiness_backend_operation(Stage7bFaultCase::ReadinessCrashAfterBackendCommit, true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadinessOutcome {
    Ready,
    Aborted,
}

#[derive(Clone, Copy)]
struct ReadinessFaultProjection {
    terminalizations: usize,
    publications: usize,
    budget: Stage7bFaultBudgetProjection,
    local_quiescent: bool,
}

impl FaultProjection for ReadinessFaultProjection {
    fn fault_counters(&self) -> FaultCounters {
        FaultCounters {
            terminalizations: self.terminalizations,
            publications: self.publications,
            credits: self.budget.observed_credit_units().unwrap(),
        }
    }

    fn retained_for_retry(&self) -> bool {
        self.budget.registry.pending_publications != 0
    }

    fn determinately_quiescent(&self) -> bool {
        self.local_quiescent
            && self.terminalizations == self.budget.terminal_operations
            && fault_budget_projection_is_quiescent(&self.budget)
    }
}

fn readiness_oneshot_binding(case: Stage7bFaultCase, token: OneShotToken) -> Stage7bFaultBinding {
    Stage7bFaultBinding::new(
        case,
        Stage7bFaultOperation::ReadinessCompletion,
        [token.instance_id(), token.id(), token.generation(), 0, 0],
    )
}

fn readiness_deadline_binding(case: Stage7bFaultCase, token: DeadlineToken) -> Stage7bFaultBinding {
    Stage7bFaultBinding::new(
        case,
        Stage7bFaultOperation::ReadinessCompletion,
        [token.owner(), token.generation(), token.deadline(), 0, 0],
    )
}

fn terminalize_readiness_credit(
    budget: &mut Stage7bFaultBudget,
    credit: &mut Stage7bFaultCredit,
    binding: Stage7bFaultBinding,
    outcome: ReadinessOutcome,
) {
    if outcome == ReadinessOutcome::Ready {
        budget.commit(credit, binding, 0).unwrap();
    }
    let terminal = budget
        .terminalize(
            credit,
            binding,
            match outcome {
                ReadinessOutcome::Ready => Stage7bFaultTerminal::Completed(0),
                ReadinessOutcome::Aborted => Stage7bFaultTerminal::Aborted(0),
            },
        )
        .unwrap();
    assert_eq!(
        terminal,
        match outcome {
            ReadinessOutcome::Ready => TerminalOutcome::Completed,
            ReadinessOutcome::Aborted => TerminalOutcome::Aborted,
        }
    );
}

fn observe_oneshot(
    receipt: &OneShotTerminalReceipt<ReadinessOutcome>,
    before: OneShotProjection<ReadinessOutcome>,
    after: OneShotProjection<ReadinessOutcome>,
    budget_before: Stage7bFaultBudgetProjection,
    budget_after: Stage7bFaultBudgetProjection,
) -> FaultObservation {
    assert_eq!(receipt.token(), before.token());
    let observed_terminal = match receipt.outcome() {
        ReadinessOutcome::Ready => FaultTerminal::Ready,
        ReadinessOutcome::Aborted => FaultTerminal::Aborted,
    };
    assert_fault_budget_lineage(&budget_before, &budget_after, &budget_after);
    let before = ReadinessFaultProjection {
        terminalizations: usize::from(before.terminal().is_some()),
        publications: budget_before.commit_operations,
        budget: budget_before,
        local_quiescent: before.terminal().is_some() && before.receipt_consumed(),
    };
    let after = ReadinessFaultProjection {
        terminalizations: usize::from(after.terminal().is_some()),
        publications: budget_after.commit_operations,
        budget: budget_after,
        local_quiescent: after.terminal().is_some() && after.receipt_consumed(),
    };
    FaultObservation::from_projections(observed_terminal, &before, &after, &after)
}

fn readiness_ready_vs_timeout() -> FaultObservation {
    let case = Stage7bFaultCase::ReadinessReadyVsTimeout;
    let mut gate = OneShotGate::new(fault_budget_instance_id(case), 1, 1).unwrap();
    let token = gate.token();
    let binding = readiness_oneshot_binding(case, token);
    let mut budget = Stage7bFaultBudget::new(case, fault_budget_instance_id(case)).unwrap();
    let mut credit = budget.reserve(binding).unwrap();
    let before = gate.projection();
    let budget_before = budget.projection().unwrap();
    let terminal = gate
        .try_terminalize(token, ReadinessOutcome::Ready)
        .unwrap();
    let winner = gate.projection();
    let budget_before_loser = budget.projection().unwrap();
    assert_eq!(
        gate.try_terminalize(token, ReadinessOutcome::Aborted),
        Err(OneShotError::AlreadyTerminal)
    );
    assert_eq!(gate.projection(), winner);
    assert_eq!(budget.projection().unwrap(), budget_before_loser);
    gate.consume_terminal(&terminal).unwrap();
    assert!(gate.projection().receipt_consumed());
    terminalize_readiness_credit(&mut budget, &mut credit, binding, terminal.outcome());
    let budget_after = budget.finish().unwrap();
    observe_oneshot(
        &terminal,
        before,
        gate.projection(),
        budget_before,
        budget_after,
    )
}

fn readiness_revoke_vs_ready() -> FaultObservation {
    let case = Stage7bFaultCase::ReadinessRevokeVsReady;
    let mut gate = OneShotGate::new(fault_budget_instance_id(case), 1, 1).unwrap();
    let token = gate.token();
    let binding = readiness_oneshot_binding(case, token);
    let mut budget = Stage7bFaultBudget::new(case, fault_budget_instance_id(case)).unwrap();
    let mut credit = budget.reserve(binding).unwrap();
    let before = gate.projection();
    let budget_before = budget.projection().unwrap();
    let terminal = gate
        .try_terminalize(token, ReadinessOutcome::Aborted)
        .unwrap();
    let winner = gate.projection();
    let budget_before_loser = budget.projection().unwrap();
    assert_eq!(
        gate.try_terminalize(token, ReadinessOutcome::Ready),
        Err(OneShotError::AlreadyTerminal)
    );
    assert_eq!(gate.projection(), winner);
    assert_eq!(budget.projection().unwrap(), budget_before_loser);
    gate.consume_terminal(&terminal).unwrap();
    assert!(gate.projection().receipt_consumed());
    terminalize_readiness_credit(&mut budget, &mut credit, binding, terminal.outcome());
    let budget_after = budget.finish().unwrap();
    observe_oneshot(
        &terminal,
        before,
        gate.projection(),
        budget_before,
        budget_after,
    )
}

fn observe_expiry(
    receipt: ExpiryReceipt,
    before: DeadlineProjection,
    after: DeadlineProjection,
    budget_before: Stage7bFaultBudgetProjection,
    budget_after: Stage7bFaultBudgetProjection,
) -> FaultObservation {
    assert!(receipt.observed_now() >= receipt.token().deadline());
    assert_fault_budget_lineage(&budget_before, &budget_after, &budget_after);
    let before = ReadinessFaultProjection {
        terminalizations: usize::from(before.current.is_none()),
        publications: budget_before.commit_operations,
        budget: budget_before,
        local_quiescent: before.current.is_none(),
    };
    let after = ReadinessFaultProjection {
        terminalizations: usize::from(after.current.is_none()),
        publications: budget_after.commit_operations,
        budget: budget_after,
        local_quiescent: after.current.is_none(),
    };
    FaultObservation::from_projections(FaultTerminal::TimedOut, &before, &after, &after)
}

fn readiness_stale_deadline_after_rearm() -> FaultObservation {
    let case = Stage7bFaultCase::ReadinessStaleDeadlineAfterRearm;
    let mut gate = DeadlineGate::new(1).unwrap();
    let old = gate.arm(1).unwrap();
    let current = gate.rearm(old, 2).unwrap();
    let binding = readiness_deadline_binding(case, current);
    let mut budget = Stage7bFaultBudget::new(case, fault_budget_instance_id(case)).unwrap();
    let mut credit = budget.reserve(binding).unwrap();
    let before = gate.projection();
    let budget_before = budget.projection().unwrap();
    assert_eq!(gate.expire(old, u64::MAX), Err(DeadlineError::StaleToken));
    assert_eq!(gate.projection(), before);
    assert_eq!(budget.projection().unwrap(), budget_before);
    let expiry = gate.expire(current, 2).unwrap();
    let terminal = budget
        .terminalize(
            &mut credit,
            readiness_deadline_binding(case, expiry.token()),
            Stage7bFaultTerminal::Aborted(0),
        )
        .unwrap();
    assert_eq!(terminal, TerminalOutcome::Aborted);
    let budget_after = budget.finish().unwrap();
    observe_expiry(
        expiry,
        before,
        gate.projection(),
        budget_before,
        budget_after,
    )
}

#[derive(Clone, Copy)]
struct IoFaultProjection {
    gate: IoProjection,
    budget: Stage7bFaultBudgetProjection,
}

// Stable, caller-unique namespaces for the five independent Stage 7B I/O
// fixtures. The prefix is "ST7BIO"; the low word identifies the fault cell.
const IO_REVOKE_INSTANCE_ID: u64 = 0x5354_3742_494f_0001;
const IO_COMPLETION_RESET_INSTANCE_ID: u64 = 0x5354_3742_494f_0002;
const IO_RESET_TIMEOUT_INSTANCE_ID: u64 = 0x5354_3742_494f_0003;
const IO_IOTLB_TIMEOUT_INSTANCE_ID: u64 = 0x5354_3742_494f_0004;
const IO_DUPLICATE_COMPLETION_INSTANCE_ID: u64 = 0x5354_3742_494f_0005;

impl FaultProjection for IoFaultProjection {
    fn fault_counters(&self) -> FaultCounters {
        FaultCounters {
            terminalizations: self.gate.terminalized,
            publications: self.gate.committed,
            credits: self.budget.observed_credit_units().unwrap(),
        }
    }

    fn retained_for_retry(&self) -> bool {
        self.gate.reset_pending || self.gate.iotlb_pending
    }

    fn determinately_quiescent(&self) -> bool {
        self.gate.phase == IoPhase::Quiesced
            && self.gate.terminalized == self.gate.effect_count
            && !self.gate.reset_pending
            && !self.gate.iotlb_pending
            && fault_budget_projection_is_quiescent(&self.budget)
    }
}

fn io_fault_binding(case: Stage7bFaultCase, identity: IoIdentity) -> Stage7bFaultBinding {
    Stage7bFaultBinding::new(
        case,
        Stage7bFaultOperation::IoRequest,
        [
            identity.instance_id(),
            identity.request_id(),
            identity.authority_epoch(),
            identity.binding_epoch(),
            identity.device_generation(),
        ],
    )
}

struct IoFaultComposite {
    gate: IoGate<4>,
    budget: Stage7bFaultBudget,
    identity: IoIdentity,
    binding: Stage7bFaultBinding,
    credit: Stage7bFaultCredit,
}

impl IoFaultComposite {
    fn new(case: Stage7bFaultCase, instance_id: u64) -> Self {
        let mut gate = IoGate::<4>::new(instance_id).unwrap();
        let identity = gate.register(gate.binding_token().unwrap()).unwrap();
        let binding = io_fault_binding(case, identity);
        let mut budget = Stage7bFaultBudget::new(case, instance_id).unwrap();
        let credit = budget.reserve(binding).unwrap();
        Self {
            gate,
            budget,
            identity,
            binding,
            credit,
        }
    }

    fn projection(&self) -> IoFaultProjection {
        self.projection_with_gate(self.gate.projection())
    }

    fn projection_with_gate(&self, gate: IoProjection) -> IoFaultProjection {
        IoFaultProjection {
            gate,
            budget: self.budget.projection().unwrap(),
        }
    }

    fn commit(&mut self) -> IoCommitReceipt {
        let identity = self.identity;
        let binding = self.binding;
        let (gate, budget, credit) = (&mut self.gate, &mut self.budget, &mut self.credit);
        let (commit, ()) = gate
            .commit_with(identity, || budget.commit(credit, binding, 0))
            .unwrap();
        assert_eq!(commit.identity(), identity);
        commit
    }

    fn terminal(&self) -> IoTerminal {
        self.gate
            .terminal(self.identity)
            .expect("I/O fault request lacks a production terminal")
    }

    fn finish_after_quiescence(&mut self) -> IoFaultProjection {
        assert_eq!(self.gate.projection().phase, IoPhase::Quiesced);
        let terminal = self.terminal();
        let registry_terminal = self
            .budget
            .terminalize(
                &mut self.credit,
                self.binding,
                match terminal {
                    IoTerminal::AbortedBeforeCommit => Stage7bFaultTerminal::Aborted(0),
                    IoTerminal::Completed | IoTerminal::IndeterminateAfterReset => {
                        Stage7bFaultTerminal::Completed(0)
                    }
                },
            )
            .unwrap();
        assert_eq!(
            registry_terminal,
            match terminal {
                IoTerminal::AbortedBeforeCommit => TerminalOutcome::Aborted,
                IoTerminal::Completed | IoTerminal::IndeterminateAfterReset => {
                    TerminalOutcome::Completed
                }
            }
        );
        IoFaultProjection {
            gate: self.gate.projection(),
            budget: self.budget.finish().unwrap(),
        }
    }
}

fn complete_iotlb(
    gate: &mut IoGate<4>,
    outcome: ResetOutcome,
    retain_once: bool,
) -> (IoProjection, QuiescenceReceipt) {
    let attempt = gate.begin_iotlb::<3>(outcome).unwrap();
    let retained = gate.projection();
    assert!(retained.iotlb_pending);
    let (retained, attempt) = if retain_once {
        let tombstone = attempt.retain();
        assert_eq!(tombstone.generation(), outcome.closed_generation());
        (retained, tombstone.retry())
    } else {
        (retained, attempt)
    };
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
    assert_eq!(receipt.completed(), 3);
    gate.mark_quiesced(receipt).unwrap();
    (retained, receipt)
}

fn observed_io_terminal(terminal: IoTerminal) -> FaultTerminal {
    match terminal {
        IoTerminal::Completed => FaultTerminal::Completed,
        IoTerminal::IndeterminateAfterReset => FaultTerminal::IndeterminateAfterReset,
        IoTerminal::AbortedBeforeCommit => FaultTerminal::AbortedBeforeCommit,
    }
}

fn observe_io(
    terminal: FaultTerminal,
    before: IoFaultProjection,
    retained: IoFaultProjection,
    after: IoFaultProjection,
) -> FaultObservation {
    assert_eq!(before.gate.effect_count, after.gate.effect_count);
    assert_eq!(before.budget.case, retained.budget.case);
    assert_eq!(before.budget.case, after.budget.case);
    assert_fault_budget_lineage(&before.budget, &retained.budget, &after.budget);
    assert_eq!(before.budget.reservations, 1);
    assert_eq!(after.budget.terminal_operations, 1);
    if retained.retained_for_retry() {
        assert_eq!(retained.budget.registry.credits.committed, 1);
        assert_eq!(retained.budget.terminal_operations, 0);
    }
    FaultObservation::from_projections(terminal, &before, &retained, &after)
}

fn io_revoke_before_device_publication() -> FaultObservation {
    let mut io = IoFaultComposite::new(
        Stage7bFaultCase::IoRevokeBeforeDevicePublication,
        IO_REVOKE_INSTANCE_ID,
    );
    let before = io.projection();
    let close = io.gate.begin_closing().unwrap();
    assert_eq!(close.aborted(), 1);
    let (gate, budget, credit) = (&mut io.gate, &mut io.budget, &mut io.credit);
    assert!(
        gate.commit_with(io.identity, || budget.commit(credit, io.binding, 0))
            .is_err()
    );
    assert_eq!(io.budget.projection().unwrap(), before.budget);
    let retained = io.projection();
    let quiescence = io.gate.mark_terminal_quiesced(close).unwrap();
    assert_eq!(quiescence.terminalized(), 1);
    let terminal = io.terminal();
    let after = io.finish_after_quiescence();
    observe_io(observed_io_terminal(terminal), before, retained, after)
}

fn io_completion_vs_reset_ack() -> FaultObservation {
    let mut io = IoFaultComposite::new(
        Stage7bFaultCase::IoCompletionVsResetAck,
        IO_COMPLETION_RESET_INSTANCE_ID,
    );
    let before = io.projection();
    let commit = io.commit();
    assert_ne!(commit.sequence(), 0);
    let close = io.gate.begin_closing().unwrap();
    let reset = io.gate.begin_reset(close).unwrap().acknowledge();
    let reset = io.gate.apply_reset(reset).unwrap();
    assert_eq!(reset.terminalized(), 1);
    assert_eq!(
        io.gate.complete_device(io.identity),
        Err(IoError::StaleDeviceGeneration)
    );
    let (retained_gate, _) = complete_iotlb(&mut io.gate, reset, false);
    let retained = io.projection_with_gate(retained_gate);
    let terminal = io.terminal();
    let after = io.finish_after_quiescence();
    observe_io(observed_io_terminal(terminal), before, retained, after)
}

fn io_reset_timeout_retry() -> FaultObservation {
    let mut io = IoFaultComposite::new(
        Stage7bFaultCase::IoResetTimeoutRetry,
        IO_RESET_TIMEOUT_INSTANCE_ID,
    );
    let before = io.projection();
    let commit = io.commit();
    assert_ne!(commit.sequence(), 0);
    let close = io.gate.begin_closing().unwrap();
    let tombstone = io.gate.begin_reset(close).unwrap().retain();
    let retained = io.projection();
    assert!(retained.gate.reset_pending);
    let reset = tombstone.retry().acknowledge();
    let outcome = io.gate.apply_reset(reset).unwrap();
    assert_eq!(outcome.terminalized(), 1);
    complete_iotlb(&mut io.gate, outcome, false);
    let terminal = io.terminal();
    let after = io.finish_after_quiescence();
    observe_io(observed_io_terminal(terminal), before, retained, after)
}

fn io_iotlb_timeout_late_ack() -> FaultObservation {
    let mut io = IoFaultComposite::new(
        Stage7bFaultCase::IoIotlbTimeoutLateAck,
        IO_IOTLB_TIMEOUT_INSTANCE_ID,
    );
    let before = io.projection();
    let commit = io.commit();
    assert_ne!(commit.sequence(), 0);
    let close = io.gate.begin_closing().unwrap();
    let reset = io.gate.begin_reset(close).unwrap().acknowledge();
    let outcome = io.gate.apply_reset(reset).unwrap();
    let (retained_gate, quiescence) = complete_iotlb(&mut io.gate, outcome, true);
    assert_eq!(quiescence.generation(), outcome.closed_generation());
    let retained = io.projection_with_gate(retained_gate);
    let after = io.finish_after_quiescence();
    observe_io(FaultTerminal::Quiesced, before, retained, after)
}

fn io_stale_duplicate_completion() -> FaultObservation {
    let mut io = IoFaultComposite::new(
        Stage7bFaultCase::IoStaleDuplicateCompletion,
        IO_DUPLICATE_COMPLETION_INSTANCE_ID,
    );
    let before = io.projection();
    let commit = io.commit();
    assert_ne!(commit.sequence(), 0);
    let terminal = io.gate.complete_device(io.identity).unwrap();
    let before_duplicate = io.gate.projection();
    let budget_before_duplicate = io.budget.projection().unwrap();
    assert_eq!(
        io.gate.complete_device(io.identity),
        Err(IoError::AlreadyTerminal)
    );
    assert_eq!(io.gate.projection(), before_duplicate);
    assert_eq!(io.budget.projection().unwrap(), budget_before_duplicate);
    let close = io.gate.begin_closing().unwrap();
    let retained = io.projection();
    let quiescence = io.gate.mark_terminal_quiesced(close).unwrap();
    assert_eq!(quiescence.terminalized(), 1);
    let after = io.finish_after_quiescence();
    observe_io(
        observed_io_terminal(terminal.terminal),
        before,
        retained,
        after,
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
