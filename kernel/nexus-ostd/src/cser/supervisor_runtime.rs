// SPDX-License-Identifier: MPL-2.0

//! Nexus-owned OSTD adapter for the bounded supervisor state machine.
//!
//! This module is compiled into the kernel, but cannot be activated on the
//! pinned OSTD 0.18 substrate. OSTD provides a real monotonic `Jiffies` clock,
//! unpublished `TaskOptions::build`, scheduler publication by `Task::run`, and
//! an exact once-only post-exit observation after terminal CPU switch-out. It
//! still does not provide the isolated task-fault boundary required by
//! `nexus-supervisor`, and this tranche does not yet bind the initial active
//! task or start a Nexus-owned manager worker. [`activation_report`] keeps
//! those gaps machine-readable and [`request_activation`] therefore fails
//! closed.
//!
//! The code below is still the production-shaped adapter, not a second manager:
//! one worker would own [`SupervisorManager`], untrusted child events carry only
//! manager-selected identity and binding coordinates, the Registry backend is
//! private to that manager, and every replacement task/attempt stays in a
//! fixed-size Nexus-owned slot until exact cleanup.

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use __cser_alloc::sync::{Arc, Weak};
use __cser_core::sync::atomic::{AtomicBool, Ordering};

use nexus_supervisor::{
    CohortIdentity, CrashObservation, ExitReason, PollProgress, RebindObservation,
    RecoveryCompletion, RecoverySnapshot, ReplacementLaunch, ServiceIdentity, StopCompletion,
    StopReason, SupervisorBackend, SupervisorError, SupervisorHealth, SupervisorManager,
    SupervisorPhase, SupervisorPolicy,
};
use ostd::{
    sync::SpinLock,
    task::{Task, TaskOptions},
    timer::Jiffies,
};
use sha2::{Digest, Sha256};

use crate::{
    TaskData,
    effect_registry::{
        DomainIsolationOutcome, DomainKey, DomainRecoveryAbortReason, DomainRecoverySnapshot,
        EffectKey, EffectRegistry, PortalHandle, RecoveryItem, RegistryError, ScopeKey, TaskKey,
    },
};

const MIN_EVENT_CAPACITY: usize = 4;

/// Exact capabilities supplied by this adapter and the pinned OSTD substrate.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct OstdSupervisorActivationReport {
    pub(crate) registry_backend: bool,
    pub(crate) bounded_event_queue: bool,
    pub(crate) monotonic_jiffies: bool,
    pub(crate) construct_unpublished: bool,
    pub(crate) scheduler_publication: bool,
    pub(crate) cooperative_stop_flag: bool,
    pub(crate) task_return_boundary: bool,
    pub(crate) exact_task_exit_hook: bool,
    pub(crate) exact_task_reap_hook: bool,
    pub(crate) isolated_task_fault_hook: bool,
    pub(crate) initial_active_task_binding: bool,
    pub(crate) nexus_owned_manager_worker: bool,
}

impl OstdSupervisorActivationReport {
    /// Returns true only when the adapter may drive a production manager.
    pub(crate) const fn is_complete(self) -> bool {
        self.registry_backend
            && self.bounded_event_queue
            && self.monotonic_jiffies
            && self.construct_unpublished
            && self.scheduler_publication
            && self.cooperative_stop_flag
            && self.task_return_boundary
            && self.exact_task_exit_hook
            && self.exact_task_reap_hook
            && self.isolated_task_fault_hook
            && self.initial_active_task_binding
            && self.nexus_owned_manager_worker
    }
}

/// Current exact substrate report.
pub(crate) const fn activation_report() -> OstdSupervisorActivationReport {
    OstdSupervisorActivationReport {
        registry_backend: true,
        bounded_event_queue: true,
        monotonic_jiffies: true,
        construct_unpublished: true,
        scheduler_publication: true,
        cooperative_stop_flag: true,
        task_return_boundary: true,
        exact_task_exit_hook: true,
        exact_task_reap_hook: true,
        isolated_task_fault_hook: false,
        initial_active_task_binding: false,
        nexus_owned_manager_worker: false,
    }
}

/// Opaque proof that every mandatory lifecycle capability is present.
pub(crate) struct OstdSupervisorActivationPermit {
    _private: (),
}

fn permit_for_report(
    report: OstdSupervisorActivationReport,
) -> Result<OstdSupervisorActivationPermit, OstdSupervisorActivationReport> {
    if report.is_complete() {
        Ok(OstdSupervisorActivationPermit { _private: () })
    } else {
        Err(report)
    }
}

/// Returns an activation permit only for a complete substrate.
pub(crate) fn request_activation()
-> Result<OstdSupervisorActivationPermit, OstdSupervisorActivationReport> {
    permit_for_report(activation_report())
}

/// Event kind accepted by the single manager-owning worker.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum OstdSupervisorEvent {
    Ready {
        service: ServiceIdentity,
        binding_epoch: u64,
    },
    Exit {
        service: ServiceIdentity,
        binding_epoch: u64,
        reason: ExitReason,
    },
    Reaped {
        service: ServiceIdentity,
        binding_epoch: u64,
    },
}

impl OstdSupervisorEvent {
    const fn service(self) -> ServiceIdentity {
        match self {
            Self::Ready { service, .. }
            | Self::Exit { service, .. }
            | Self::Reaped { service, .. } => service,
        }
    }

    const fn binding_epoch(self) -> u64 {
        match self {
            Self::Ready { binding_epoch, .. }
            | Self::Exit { binding_epoch, .. }
            | Self::Reaped { binding_epoch, .. } => binding_epoch,
        }
    }

    const fn signal_kind(self) -> SignalKind {
        match self {
            Self::Ready { .. } => SignalKind::Ready,
            Self::Exit { .. } => SignalKind::Exit,
            Self::Reaped { .. } => SignalKind::Reaped,
        }
    }
}

/// One FIFO event with its manager time and non-repeating queue sequence.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct OstdSupervisorEventEnvelope {
    pub(crate) sequence: u64,
    pub(crate) observed_tick: u64,
    pub(crate) event: OstdSupervisorEvent,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum EventQueuePushError {
    Full,
    SequenceExhausted,
}

struct BoundedEventQueue<const N: usize> {
    entries: [Option<OstdSupervisorEventEnvelope>; N],
    head: usize,
    len: usize,
    next_sequence: Option<u64>,
}

impl<const N: usize> BoundedEventQueue<N> {
    const fn new() -> Self {
        Self {
            entries: [None; N],
            head: 0,
            len: 0,
            next_sequence: Some(1),
        }
    }

    const fn advance(index: usize) -> usize {
        if index + 1 == N { 0 } else { index + 1 }
    }

    fn push(
        &mut self,
        observed_tick: u64,
        event: OstdSupervisorEvent,
    ) -> Result<u64, EventQueuePushError> {
        if N == 0 || self.len == N {
            return Err(EventQueuePushError::Full);
        }
        let sequence = self
            .next_sequence
            .ok_or(EventQueuePushError::SequenceExhausted)?;
        let tail = if self.len == 0 {
            self.head
        } else {
            let mut tail = self.head;
            let mut remaining = self.len;
            while remaining != 0 {
                tail = Self::advance(tail);
                remaining -= 1;
            }
            tail
        };
        self.entries[tail] = Some(OstdSupervisorEventEnvelope {
            sequence,
            observed_tick,
            event,
        });
        self.len += 1;
        self.next_sequence = sequence.checked_add(1);
        Ok(sequence)
    }

    fn pop(&mut self) -> Option<OstdSupervisorEventEnvelope> {
        if self.len == 0 {
            return None;
        }
        let event = self.entries[self.head].take();
        self.head = Self::advance(self.head);
        self.len -= 1;
        event
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
enum SignalKind {
    Ready,
    Exit,
    Reaped,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum SignalState {
    Empty,
    Retained {
        observed_tick: u64,
        event: OstdSupervisorEvent,
        reason: OstdSupervisorRetentionReason,
    },
    Queued {
        sequence: u64,
    },
    Consumed,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum ReplacementSlotPhase {
    Vacant,
    Selected,
    Constructing,
    Constructed,
    Published,
    Active,
    StopRequested,
    Reaped,
    DiscardedUnpublished,
}

struct ReplacementSlot {
    phase: ReplacementSlotPhase,
    failed: Option<ServiceIdentity>,
    launch: Option<ReplacementLaunch>,
    attempt: Option<u32>,
    task: Option<Arc<Task>>,
    pending_exit_reason: Option<ExitReason>,
    ready: SignalState,
    exit: SignalState,
    reaped: SignalState,
}

impl ReplacementSlot {
    const fn new() -> Self {
        Self {
            phase: ReplacementSlotPhase::Vacant,
            failed: None,
            launch: None,
            attempt: None,
            task: None,
            pending_exit_reason: None,
            ready: SignalState::Empty,
            exit: SignalState::Empty,
            reaped: SignalState::Empty,
        }
    }

    fn clear(&mut self) {
        self.phase = ReplacementSlotPhase::Vacant;
        self.failed = None;
        self.launch = None;
        self.attempt = None;
        self.task = None;
        self.pending_exit_reason = None;
        self.ready = SignalState::Empty;
        self.exit = SignalState::Empty;
        self.reaped = SignalState::Empty;
    }

    fn signal(&self, kind: SignalKind) -> SignalState {
        match kind {
            SignalKind::Ready => self.ready,
            SignalKind::Exit => self.exit,
            SignalKind::Reaped => self.reaped,
        }
    }

    fn signal_mut(&mut self, kind: SignalKind) -> &mut SignalState {
        match kind {
            SignalKind::Ready => &mut self.ready,
            SignalKind::Exit => &mut self.exit,
            SignalKind::Reaped => &mut self.reaped,
        }
    }

    fn matches(&self, service: ServiceIdentity, binding_epoch: u64) -> bool {
        self.launch.is_some_and(|launch| {
            launch.replacement() == service && launch.binding_epoch() == binding_epoch
        })
    }
}

fn oldest_retained(slot: &ReplacementSlot) -> Option<(u64, SignalKind, OstdSupervisorEvent)> {
    let mut retained = None;
    for kind in [SignalKind::Ready, SignalKind::Exit, SignalKind::Reaped] {
        if let SignalState::Retained {
            observed_tick,
            event,
            ..
        } = slot.signal(kind)
        {
            let ordering_key = (observed_tick, kind);
            if retained.is_none_or(|(current_tick, current_kind, _)| {
                ordering_key < (current_tick, current_kind)
            }) {
                retained = Some((observed_tick, kind, event));
            }
        }
    }
    retained
}

struct OstdSupervisorShared<const N: usize> {
    events: SpinLock<BoundedEventQueue<N>>,
    replacement: SpinLock<ReplacementSlot>,
    stop_requested: AtomicBool,
    tick_pending: AtomicBool,
    timer_installed: AtomicBool,
    lifecycle_ingress_rejected: AtomicBool,
}

impl<const N: usize> OstdSupervisorShared<N> {
    const fn new() -> Self {
        Self {
            events: SpinLock::new(BoundedEventQueue::new()),
            replacement: SpinLock::new(ReplacementSlot::new()),
            stop_requested: AtomicBool::new(false),
            tick_pending: AtomicBool::new(false),
            timer_installed: AtomicBool::new(false),
            lifecycle_ingress_rejected: AtomicBool::new(false),
        }
    }

    fn latch_lifecycle_ingress_rejection(&self) {
        self.lifecycle_ingress_rejected
            .store(true, Ordering::Release);
    }

    fn enqueue_signal_locked(
        &self,
        slot: &mut ReplacementSlot,
        observed_tick: u64,
        event: OstdSupervisorEvent,
    ) -> OstdSupervisorSignalDisposition {
        let kind = event.signal_kind();
        if slot.signal(kind) != SignalState::Empty {
            return OstdSupervisorSignalDisposition::AlreadyObserved;
        }
        match self.events.disable_irq().lock().push(observed_tick, event) {
            Ok(sequence) => {
                *slot.signal_mut(kind) = SignalState::Queued { sequence };
                OstdSupervisorSignalDisposition::Queued { sequence }
            }
            Err(reason) => {
                let reason = match reason {
                    EventQueuePushError::Full => OstdSupervisorRetentionReason::QueueFull,
                    EventQueuePushError::SequenceExhausted => {
                        OstdSupervisorRetentionReason::SequenceExhausted
                    }
                };
                *slot.signal_mut(kind) = SignalState::Retained {
                    observed_tick,
                    event,
                    reason,
                };
                OstdSupervisorSignalDisposition::Retained { reason }
            }
        }
    }

    fn emit_ready(
        &self,
        service: ServiceIdentity,
        binding_epoch: u64,
    ) -> Result<OstdSupervisorSignalDisposition, OstdSupervisorSignalError> {
        let mut slot = self.replacement.disable_irq().lock();
        if !slot.matches(service, binding_epoch) {
            return Err(OstdSupervisorSignalError::StaleTaskContext);
        }
        if slot.phase != ReplacementSlotPhase::Published {
            return Err(OstdSupervisorSignalError::InvalidTaskPhase);
        }

        let observed_tick = Jiffies::elapsed().as_u64();
        Ok(self.enqueue_signal_locked(
            &mut slot,
            observed_tick,
            OstdSupervisorEvent::Ready {
                service,
                binding_epoch,
            },
        ))
    }

    fn record_pending_exit(
        &self,
        service: ServiceIdentity,
        binding_epoch: u64,
        reason: ExitReason,
    ) -> Result<(), OstdSupervisorSignalError> {
        let mut slot = self.replacement.disable_irq().lock();
        if !slot.matches(service, binding_epoch) {
            return Err(OstdSupervisorSignalError::StaleTaskContext);
        }
        if !__cser_core::matches!(
            slot.phase,
            ReplacementSlotPhase::Published
                | ReplacementSlotPhase::Active
                | ReplacementSlotPhase::StopRequested
        ) {
            return Err(OstdSupervisorSignalError::InvalidTaskPhase);
        }
        match slot.pending_exit_reason {
            None => slot.pending_exit_reason = Some(reason),
            Some(previous) if previous == reason => {}
            Some(_) => return Err(OstdSupervisorSignalError::ConflictingExitReason),
        }
        Ok(())
    }

    fn observe_exact_reap(
        &self,
        service: ServiceIdentity,
        binding_epoch: u64,
    ) -> Result<(), OstdSupervisorSignalError> {
        let mut slot = self.replacement.disable_irq().lock();
        if !slot.matches(service, binding_epoch) {
            return Err(OstdSupervisorSignalError::StaleTaskContext);
        }
        let observed_tick = Jiffies::elapsed().as_u64();
        match slot.phase {
            ReplacementSlotPhase::Published => {
                let reason = slot
                    .pending_exit_reason
                    .ok_or(OstdSupervisorSignalError::MissingExitReason)?;
                self.enqueue_signal_locked(
                    &mut slot,
                    observed_tick,
                    OstdSupervisorEvent::Exit {
                        service,
                        binding_epoch,
                        reason,
                    },
                );
                self.enqueue_signal_locked(
                    &mut slot,
                    observed_tick,
                    OstdSupervisorEvent::Reaped {
                        service,
                        binding_epoch,
                    },
                );
            }
            ReplacementSlotPhase::Active => {
                let reason = slot
                    .pending_exit_reason
                    .ok_or(OstdSupervisorSignalError::MissingExitReason)?;
                self.enqueue_signal_locked(
                    &mut slot,
                    observed_tick,
                    OstdSupervisorEvent::Exit {
                        service,
                        binding_epoch,
                        reason,
                    },
                );
                // Running services need no manager stop completion. Their
                // exact reap releases this slot before Exit can start Backoff.
                slot.reaped = SignalState::Consumed;
            }
            ReplacementSlotPhase::StopRequested => {
                self.enqueue_signal_locked(
                    &mut slot,
                    observed_tick,
                    OstdSupervisorEvent::Reaped {
                        service,
                        binding_epoch,
                    },
                );
            }
            _ => return Err(OstdSupervisorSignalError::InvalidTaskPhase),
        }
        slot.phase = ReplacementSlotPhase::Reaped;
        Ok(())
    }

    fn mark_ready_accepted(&self, service: ServiceIdentity, binding_epoch: u64) {
        let mut slot = self.replacement.disable_irq().lock();
        if !slot.matches(service, binding_epoch) {
            self.latch_lifecycle_ingress_rejection();
            return;
        }
        match slot.phase {
            ReplacementSlotPhase::Published => slot.phase = ReplacementSlotPhase::Active,
            // Exact reaping can race with manager consumption of an earlier
            // Ready event. Never overwrite the stronger substrate fact.
            ReplacementSlotPhase::Reaped => {}
            _ => self.latch_lifecycle_ingress_rejection(),
        }
    }

    fn flush_oldest_retained(&self) -> Result<bool, OstdSupervisorRuntimeLocalError> {
        let mut slot = self.replacement.disable_irq().lock();
        let Some((observed_tick, kind, event)) = oldest_retained(&slot) else {
            return Ok(false);
        };
        match self.events.disable_irq().lock().push(observed_tick, event) {
            Ok(sequence) => {
                *slot.signal_mut(kind) = SignalState::Queued { sequence };
                Ok(true)
            }
            Err(EventQueuePushError::Full) => Ok(false),
            Err(EventQueuePushError::SequenceExhausted) => {
                *slot.signal_mut(kind) = SignalState::Retained {
                    observed_tick,
                    event,
                    reason: OstdSupervisorRetentionReason::SequenceExhausted,
                };
                Err(OstdSupervisorRuntimeLocalError::EventSequenceExhausted)
            }
        }
    }

    fn pop_event(&self) -> Option<OstdSupervisorEventEnvelope> {
        // Never acquire the slot while the queue is locked. Event ingress and
        // retained flushing use slot -> events, so this explicit scope is the
        // reverse-edge exclusion that keeps the global order acyclic.
        let envelope = {
            let mut events = self.events.disable_irq().lock();
            events.pop()?
        };
        let mut slot = self.replacement.disable_irq().lock();
        let signal = slot.signal_mut(envelope.event.signal_kind());
        if *signal
            == (SignalState::Queued {
                sequence: envelope.sequence,
            })
        {
            *signal = SignalState::Consumed;
        }
        Some(envelope)
    }
}

trait ExactTaskReapSink: Send + Sync {
    fn observe_exact_reap(&self, service: ServiceIdentity, binding_epoch: u64);
}

impl<const N: usize> ExactTaskReapSink for OstdSupervisorShared<N> {
    fn observe_exact_reap(&self, service: ServiceIdentity, binding_epoch: u64) {
        if self.observe_exact_reap(service, binding_epoch).is_err() {
            self.latch_lifecycle_ingress_rejection();
        }
    }
}

/// Non-owning exact lifecycle binding embedded in one OSTD task.
///
/// The weak sink avoids a `shared -> task -> binding -> shared` ownership
/// cycle. The manager runtime is the strong owner; if it has already gone away,
/// the task no longer has lifecycle authority to notify.
pub(crate) struct OstdSupervisorTaskExitBinding {
    service: ServiceIdentity,
    binding_epoch: u64,
    sink: Weak<dyn ExactTaskReapSink>,
}

impl OstdSupervisorTaskExitBinding {
    fn new<const N: usize>(
        shared: &Arc<OstdSupervisorShared<N>>,
        launch: ReplacementLaunch,
    ) -> Self {
        let erased: Arc<dyn ExactTaskReapSink> = Arc::clone(shared) as Arc<dyn ExactTaskReapSink>;
        let sink = Arc::downgrade(&erased);
        Self {
            service: launch.replacement(),
            binding_epoch: launch.binding_epoch(),
            sink,
        }
    }

    fn observe_exact_reap(&self) {
        if let Some(sink) = self.sink.upgrade() {
            sink.observe_exact_reap(self.service, self.binding_epoch);
        }
    }
}

/// OSTD's patched switch tail calls this exactly once after terminal task
/// switch-out and before releasing its final temporary task reference.
pub(crate) fn observe_post_task_exit(task: &Task) {
    if !task.is_reaped() {
        return;
    }
    let Some(data) = task.data().downcast_ref::<TaskData>() else {
        return;
    };
    if let Some(binding) = data.supervisor_exit.as_ref() {
        binding.observe_exact_reap();
    }
}

/// Why a critical event remains in its preallocated task slot.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum OstdSupervisorRetentionReason {
    QueueFull,
    SequenceExhausted,
}

/// Result of reporting one exact child event.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum OstdSupervisorSignalDisposition {
    Queued {
        sequence: u64,
    },
    Retained {
        reason: OstdSupervisorRetentionReason,
    },
    AlreadyObserved,
}

/// Child-context failure. It never grants manager or Registry authority.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum OstdSupervisorSignalError {
    StaleTaskContext,
    InvalidTaskPhase,
    MissingExitReason,
    ConflictingExitReason,
}

/// Context passed to one manager-selected replacement entry.
pub(crate) struct OstdSupervisorServiceContext<const N: usize> {
    shared: Arc<OstdSupervisorShared<N>>,
    launch: ReplacementLaunch,
}

impl<const N: usize> OstdSupervisorServiceContext<N> {
    fn new(shared: Arc<OstdSupervisorShared<N>>, launch: ReplacementLaunch) -> Self {
        Self { shared, launch }
    }

    pub(crate) const fn service(&self) -> ServiceIdentity {
        self.launch.replacement()
    }

    pub(crate) const fn binding_epoch(&self) -> u64 {
        self.launch.binding_epoch()
    }

    pub(crate) const fn ready_deadline_tick(&self) -> u64 {
        self.launch.ready_deadline_tick()
    }

    /// Reports Ready without exposing rebind or adoption authority.
    pub(crate) fn report_ready(
        &self,
    ) -> Result<OstdSupervisorSignalDisposition, OstdSupervisorSignalError> {
        self.shared.emit_ready(self.service(), self.binding_epoch())
    }

    /// Returns the manager-owned cooperative stop flag.
    pub(crate) fn stop_requested(&self) -> bool {
        self.shared.stop_requested.load(Ordering::Acquire)
    }

    fn report_return(&self) {
        // Do not deliver Exit until OSTD's post-task-exit hook proves terminal
        // switch-out. Otherwise Backoff could select the next generation while
        // this task still occupies the exact slot. The task wrapper owns only
        // this pending reason; the later hook owns event publication.
        if self
            .shared
            .record_pending_exit(
                self.service(),
                self.binding_epoch(),
                ExitReason::UnexpectedReturn,
            )
            .is_err()
        {
            self.shared.latch_lifecycle_ingress_rejection();
        }
    }
}

/// Replacement program selected by the Nexus-owned backend.
pub(crate) trait OstdSupervisorServiceProgram<const N: usize>: Send + Sync {
    fn run(&self, context: &OstdSupervisorServiceContext<N>);
}

/// Timer-side handle. The IRQ callback only coalesces a wake request; it never
/// enters the manager or Registry.
pub(crate) struct OstdSupervisorTimerIngress<const N: usize> {
    shared: Arc<OstdSupervisorShared<N>>,
}

impl<const N: usize> OstdSupervisorTimerIngress<N> {
    /// Installs one callback on the current CPU.
    pub(crate) fn install_on_current_cpu(&self) -> Result<(), OstdSupervisorTimerError> {
        if self
            .shared
            .timer_installed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(OstdSupervisorTimerError::AlreadyInstalled);
        }
        let shared = Arc::clone(&self.shared);
        ostd::timer::register_callback_on_cpu(move || {
            shared.tick_pending.store(true, Ordering::Release);
        });
        Ok(())
    }
}

/// Timer installation failure.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum OstdSupervisorTimerError {
    AlreadyInstalled,
}

/// Stable task-slot mismatch reported by the backend.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum OstdSupervisorSlotError {
    Busy,
    WrongIdentity,
    WrongPhase,
    RecoveryCleanupPending,
}

/// Typed OSTD/Registry backend failure.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum OstdSupervisorBackendError {
    Registry(RegistryError),
    Slot(OstdSupervisorSlotError),
    InvalidIdentity,
    CohortTooLarge,
    GenerationExhausted,
    TaskBuild,
}

impl From<RegistryError> for OstdSupervisorBackendError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

/// Linear recovery item returned only by the private Registry backend.
pub(crate) struct OstdSupervisorRecoveryItem {
    item: RecoveryItem,
}

struct OstdRegistrySupervisorBackend<const N: usize> {
    registry: Arc<SpinLock<EffectRegistry>>,
    scope: ScopeKey,
    domain: DomainKey,
    shared: Arc<OstdSupervisorShared<N>>,
    program: Arc<dyn OstdSupervisorServiceProgram<N>>,
}

impl<const N: usize> OstdRegistrySupervisorBackend<N> {
    fn new(
        registry: Arc<SpinLock<EffectRegistry>>,
        scope: ScopeKey,
        domain: DomainKey,
        active: ServiceIdentity,
        binding_epoch: u64,
        shared: Arc<OstdSupervisorShared<N>>,
        program: Arc<dyn OstdSupervisorServiceProgram<N>>,
    ) -> Result<Self, OstdSupervisorBackendError> {
        let projection = registry.lock().domain_projection(scope, domain)?;
        if projection.binding_epoch != binding_epoch
            || projection.supervisor != Some(service_task(active))
            || projection.fallback_running
            || projection.quarantine.is_some()
        {
            return Err(OstdSupervisorBackendError::InvalidIdentity);
        }
        Ok(Self {
            registry,
            scope,
            domain,
            shared,
            program,
        })
    }

    fn slot_attempt(
        &self,
        replacement: ServiceIdentity,
        phase: ReplacementSlotPhase,
    ) -> Result<u32, OstdSupervisorBackendError> {
        let slot = self.shared.replacement.lock();
        if slot.phase != phase {
            return Err(OstdSupervisorBackendError::Slot(
                OstdSupervisorSlotError::WrongPhase,
            ));
        }
        let launch = slot.launch.ok_or(OstdSupervisorBackendError::Slot(
            OstdSupervisorSlotError::WrongPhase,
        ))?;
        if launch.replacement() != replacement {
            return Err(OstdSupervisorBackendError::Slot(
                OstdSupervisorSlotError::WrongIdentity,
            ));
        }
        slot.attempt.ok_or(OstdSupervisorBackendError::Slot(
            OstdSupervisorSlotError::WrongPhase,
        ))
    }
}

fn service_task(service: ServiceIdentity) -> TaskKey {
    TaskKey::new(service.id(), service.generation())
}

fn task_service(task: TaskKey) -> Result<ServiceIdentity, OstdSupervisorBackendError> {
    ServiceIdentity::new(task.id(), task.generation())
        .ok_or(OstdSupervisorBackendError::InvalidIdentity)
}

fn replacement_identity(
    failed: ServiceIdentity,
    attempt: u32,
) -> Result<ServiceIdentity, OstdSupervisorBackendError> {
    if attempt == 0 {
        return Err(OstdSupervisorBackendError::InvalidIdentity);
    }
    // The manager's attempt is lifetime-monotonic. Incorporating it prevents
    // construction/publication failures from reusing an unpublished service
    // incarnation when the manager retries from the same failed identity.
    let generation = failed
        .generation()
        .checked_add(u64::from(attempt))
        .ok_or(OstdSupervisorBackendError::GenerationExhausted)?;
    ServiceIdentity::new(failed.id(), generation).ok_or(OstdSupervisorBackendError::InvalidIdentity)
}

fn cohort_identity_from_effects<'a>(
    effects: impl IntoIterator<Item = &'a EffectKey>,
) -> Result<CohortIdentity, OstdSupervisorBackendError> {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.supervisor-cohort.v1\0");
    let mut len = 0_u32;
    for effect in effects {
        len = len
            .checked_add(1)
            .ok_or(OstdSupervisorBackendError::CohortTooLarge)?;
        hasher.update(effect.id().to_le_bytes());
        hasher.update(effect.generation().to_le_bytes());
    }
    Ok(CohortIdentity::new(len, hasher.finalize().into()))
}

fn abort_reason(reason: StopReason) -> DomainRecoveryAbortReason {
    match reason {
        StopReason::ExitedBeforeReady => DomainRecoveryAbortReason::ExitedBeforeReady,
        StopReason::ReadyTimeout => DomainRecoveryAbortReason::ReadyTimeout,
        StopReason::RecoveryRejected => DomainRecoveryAbortReason::RecoveryRejected,
        StopReason::PartialRecoveryFailed => DomainRecoveryAbortReason::PartialRecoveryFailed,
    }
}

impl<const N: usize> SupervisorBackend for OstdRegistrySupervisorBackend<N> {
    type Snapshot = DomainRecoverySnapshot;
    type RecoveryItem = OstdSupervisorRecoveryItem;
    type Error = OstdSupervisorBackendError;

    fn crash_active(&mut self, service: ServiceIdentity) -> Result<CrashObservation, Self::Error> {
        let receipt =
            self.registry
                .lock()
                .crash_domain(self.scope, self.domain, service_task(service))?;
        let cohort = cohort_identity_from_effects(receipt.cohort.iter())?;
        Ok(CrashObservation {
            previous_binding_epoch: receipt.previous_binding_epoch,
            crashed_binding_epoch: receipt.binding_epoch,
            cohort,
        })
    }

    fn isolate_authority(
        &mut self,
        service: ServiceIdentity,
        last_known_binding_epoch: Option<u64>,
    ) {
        // Slot first is the adapter-wide order. The fixed Registry isolation
        // write cannot allocate or fail; every non-success outcome below means
        // the exact domain no longer contains authority addressable by these
        // configured coordinates.
        let _slot = self.shared.replacement.disable_irq().lock();
        self.shared.stop_requested.store(true, Ordering::Release);
        match self.registry.disable_irq().lock().isolate_domain_authority(
            self.scope,
            self.domain,
            service_task(service),
            last_known_binding_epoch,
        ) {
            DomainIsolationOutcome::Isolated(_)
            | DomainIsolationOutcome::AlreadyIsolated(_)
            | DomainIsolationOutcome::UnknownScope
            | DomainIsolationOutcome::UnknownDomain
            | DomainIsolationOutcome::InvalidTarget => {}
        }
    }

    fn select_replacement(
        &mut self,
        failed: ServiceIdentity,
        attempt: u32,
    ) -> Result<ServiceIdentity, Self::Error> {
        let replacement = replacement_identity(failed, attempt)?;

        let mut slot = self.shared.replacement.disable_irq().lock();
        if slot.phase == ReplacementSlotPhase::DiscardedUnpublished {
            let projection = self
                .registry
                .disable_irq()
                .lock()
                .domain_projection(self.scope, self.domain)?;
            if projection.recovery_attempt.is_some() {
                return Err(OstdSupervisorBackendError::Slot(
                    OstdSupervisorSlotError::RecoveryCleanupPending,
                ));
            }
            slot.clear();
        }
        if slot.phase == ReplacementSlotPhase::Reaped {
            slot.clear();
        }
        if slot.phase != ReplacementSlotPhase::Vacant {
            return Err(OstdSupervisorBackendError::Slot(
                OstdSupervisorSlotError::Busy,
            ));
        }
        slot.phase = ReplacementSlotPhase::Selected;
        slot.failed = Some(failed);
        slot.launch = None;
        slot.attempt = Some(attempt);
        self.shared.stop_requested.store(false, Ordering::Release);
        Ok(replacement)
    }

    fn construct_replacement(&mut self, launch: ReplacementLaunch) -> Result<(), Self::Error> {
        {
            let mut slot = self.shared.replacement.disable_irq().lock();
            if slot.phase != ReplacementSlotPhase::Selected {
                return Err(OstdSupervisorBackendError::Slot(
                    OstdSupervisorSlotError::WrongPhase,
                ));
            }
            let failed = slot.failed.ok_or(OstdSupervisorBackendError::Slot(
                OstdSupervisorSlotError::WrongPhase,
            ))?;
            if launch.replacement().id() != failed.id()
                || launch.replacement().generation() <= failed.generation()
            {
                return Err(OstdSupervisorBackendError::Slot(
                    OstdSupervisorSlotError::WrongIdentity,
                ));
            }
            slot.phase = ReplacementSlotPhase::Constructing;
            slot.launch = Some(launch);
        }

        let shared = Arc::clone(&self.shared);
        let program = Arc::clone(&self.program);
        let context = OstdSupervisorServiceContext::new(Arc::clone(&shared), launch);
        let replacement = service_task(launch.replacement());
        // Install the manager-selected identity before scheduler publication.
        // The patched OSTD switch tail can therefore report exact reaping
        // without reconstructing either identity coordinate.
        let exit_binding = OstdSupervisorTaskExitBinding::new(&shared, launch);
        let task_data = TaskData::new_supervised(replacement, exit_binding, None);
        let built = TaskOptions::new(move || {
            program.run(&context);
            context.report_return();
        })
        .data(task_data)
        .build();
        let task = match built {
            Ok(task) => Arc::new(task),
            Err(_) => {
                let mut slot = shared.replacement.disable_irq().lock();
                if slot.phase == ReplacementSlotPhase::Constructing && slot.launch == Some(launch) {
                    slot.clear();
                }
                return Err(OstdSupervisorBackendError::TaskBuild);
            }
        };

        let mut slot = self.shared.replacement.disable_irq().lock();
        if slot.phase != ReplacementSlotPhase::Constructing || slot.launch != Some(launch) {
            return Err(OstdSupervisorBackendError::Slot(
                OstdSupervisorSlotError::WrongPhase,
            ));
        }
        slot.task = Some(task);
        slot.phase = ReplacementSlotPhase::Constructed;
        Ok(())
    }

    fn discard_unpublished_replacement(&mut self, replacement: ServiceIdentity) {
        let mut slot = self.shared.replacement.disable_irq().lock();
        if slot.phase == ReplacementSlotPhase::DiscardedUnpublished
            && slot
                .launch
                .is_some_and(|launch| launch.replacement() == replacement)
        {
            return;
        }
        if slot.phase == ReplacementSlotPhase::Constructed
            && slot
                .launch
                .is_some_and(|launch| launch.replacement() == replacement)
        {
            slot.task = None;
            slot.phase = ReplacementSlotPhase::DiscardedUnpublished;
        }
    }

    fn recovery_snapshot(
        &mut self,
        replacement: ServiceIdentity,
    ) -> Result<RecoverySnapshot<Self::Snapshot>, Self::Error> {
        let attempt = self.slot_attempt(replacement, ReplacementSlotPhase::Constructed)?;
        let snapshot = self.registry.lock().domain_recovery_snapshot(
            self.scope,
            self.domain,
            service_task(replacement),
            attempt,
        )?;
        let cohort =
            cohort_identity_from_effects(snapshot.effects.iter().map(|item| &item.effect))?;
        Ok(RecoverySnapshot::new(snapshot, cohort))
    }

    fn publish_replacement(&mut self, replacement: ServiceIdentity) -> Result<(), Self::Error> {
        let task = {
            let mut slot = self.shared.replacement.disable_irq().lock();
            if slot.phase != ReplacementSlotPhase::Constructed
                || slot
                    .launch
                    .is_none_or(|launch| launch.replacement() != replacement)
            {
                return Err(OstdSupervisorBackendError::Slot(
                    OstdSupervisorSlotError::WrongPhase,
                ));
            }
            let task = slot
                .task
                .as_ref()
                .cloned()
                .ok_or(OstdSupervisorBackendError::Slot(
                    OstdSupervisorSlotError::WrongPhase,
                ))?;
            // Publish state precedes Task::run. An immediately scheduled Ready
            // or return event therefore sees the complete selector slot.
            slot.phase = ReplacementSlotPhase::Published;
            task
        };
        task.run();
        Ok(())
    }

    fn request_stop_replacement(
        &mut self,
        replacement: ServiceIdentity,
        _reason: StopReason,
    ) -> Result<(), Self::Error> {
        let mut slot = self.shared.replacement.disable_irq().lock();
        if slot
            .launch
            .is_none_or(|launch| launch.replacement() != replacement)
        {
            return Err(OstdSupervisorBackendError::Slot(
                OstdSupervisorSlotError::WrongIdentity,
            ));
        }
        match slot.phase {
            ReplacementSlotPhase::Published
            | ReplacementSlotPhase::StopRequested
            | ReplacementSlotPhase::Active => {
                self.shared.stop_requested.store(true, Ordering::Release);
                if __cser_core::matches!(
                    slot.phase,
                    ReplacementSlotPhase::Published | ReplacementSlotPhase::Active
                ) {
                    slot.phase = ReplacementSlotPhase::StopRequested;
                }
                Ok(())
            }
            // The exact post-exit hook may win before the manager consumes the
            // queued pre-Ready Exit. Cancellation is then already complete;
            // the following queued Reaped event still drives manager cleanup.
            ReplacementSlotPhase::Reaped => Ok(()),
            _ => Err(OstdSupervisorBackendError::Slot(
                OstdSupervisorSlotError::WrongPhase,
            )),
        }
    }

    fn abort_recovery_attempt(
        &mut self,
        replacement: ServiceIdentity,
        snapshot: &RecoverySnapshot<Self::Snapshot>,
        reason: StopReason,
    ) -> Result<(), Self::Error> {
        let mut slot = self.shared.replacement.disable_irq().lock();
        if !__cser_core::matches!(
            slot.phase,
            ReplacementSlotPhase::DiscardedUnpublished | ReplacementSlotPhase::Reaped
        ) || slot
            .launch
            .is_none_or(|launch| launch.replacement() != replacement)
        {
            return Err(OstdSupervisorBackendError::Slot(
                OstdSupervisorSlotError::WrongPhase,
            ));
        }
        self.registry
            .disable_irq()
            .lock()
            .abort_domain_recovery_attempt(
                self.scope,
                self.domain,
                service_task(replacement),
                snapshot.value().attempt(),
                snapshot.value(),
                abort_reason(reason),
            )?;
        slot.clear();
        self.shared.stop_requested.store(false, Ordering::Release);
        Ok(())
    }

    fn ready(
        &mut self,
        replacement: ServiceIdentity,
        snapshot: &Self::Snapshot,
    ) -> Result<(), Self::Error> {
        self.registry.lock().domain_ready(
            self.scope,
            self.domain,
            service_task(replacement),
            snapshot,
        )?;
        Ok(())
    }

    fn rebind(&mut self, replacement: ServiceIdentity) -> Result<RebindObservation, Self::Error> {
        let receipt = self.registry.lock().rebind_domain(
            self.scope,
            self.domain,
            service_task(replacement),
        )?;
        Ok(RebindObservation {
            binding_epoch: receipt.binding_epoch,
            supervisor: task_service(receipt.supervisor)?,
        })
    }

    fn peek_recovery_item(
        &mut self,
        replacement: ServiceIdentity,
    ) -> Result<Option<Self::RecoveryItem>, Self::Error> {
        Ok(self
            .registry
            .lock()
            .recover_next_domain(self.scope, self.domain, service_task(replacement))?
            .map(|item| OstdSupervisorRecoveryItem { item }))
    }

    fn adopt(
        &mut self,
        replacement: ServiceIdentity,
        item: Self::RecoveryItem,
    ) -> Result<(), Self::Error> {
        let OstdSupervisorRecoveryItem { item } = item;
        let _: PortalHandle = self.registry.lock().adopt_domain(
            self.scope,
            self.domain,
            service_task(replacement),
            item.handle,
        )?;
        Ok(())
    }
}

/// One bounded unit of manager-worker progress.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum OstdSupervisorDriveProgress {
    Idle,
    Event {
        envelope: OstdSupervisorEventEnvelope,
        recovery: Option<RecoveryCompletion>,
        stop: Option<StopCompletion>,
    },
    Timer(PollProgress),
}

/// Adapter-local failure which carries no backend payload.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum OstdSupervisorRuntimeLocalError {
    EventSequenceExhausted,
    ExactLifecycleIngressRejected,
}

/// One consumed event or timer failure. Events are removed after exactly one
/// manager call; the manager's own bounded replay and terminal state determine
/// the resulting lifecycle disposition.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum OstdSupervisorRuntimeError {
    Local(OstdSupervisorRuntimeLocalError),
    Manager {
        event: Option<OstdSupervisorEventEnvelope>,
        source: SupervisorError<OstdSupervisorBackendError>,
    },
}

/// Single-owner OSTD manager driver.
pub(crate) struct OstdSupervisorRuntime<const N: usize> {
    manager: SupervisorManager<OstdRegistrySupervisorBackend<N>>,
    shared: Arc<OstdSupervisorShared<N>>,
}

/// Runtime construction failure.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum OstdSupervisorRuntimeBuildError {
    EventCapacityTooSmall,
    Backend(OstdSupervisorBackendError),
    Manager(SupervisorError<OstdSupervisorBackendError>),
}

/// Fixed coordinates and policy for one manager-owned service domain.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct OstdSupervisorRuntimeConfig {
    pub(crate) scope: ScopeKey,
    pub(crate) domain: DomainKey,
    pub(crate) active: ServiceIdentity,
    pub(crate) binding_epoch: u64,
    pub(crate) policy: SupervisorPolicy,
}

impl<const N: usize> OstdSupervisorRuntime<N> {
    pub(crate) fn new(
        _permit: OstdSupervisorActivationPermit,
        registry: Arc<SpinLock<EffectRegistry>>,
        config: OstdSupervisorRuntimeConfig,
        program: Arc<dyn OstdSupervisorServiceProgram<N>>,
    ) -> Result<Self, OstdSupervisorRuntimeBuildError> {
        if N < MIN_EVENT_CAPACITY {
            return Err(OstdSupervisorRuntimeBuildError::EventCapacityTooSmall);
        }
        let shared = Arc::new(OstdSupervisorShared::new());
        let backend = OstdRegistrySupervisorBackend::new(
            registry,
            config.scope,
            config.domain,
            config.active,
            config.binding_epoch,
            Arc::clone(&shared),
            program,
        )
        .map_err(OstdSupervisorRuntimeBuildError::Backend)?;
        let manager = SupervisorManager::new(
            backend,
            config.policy,
            config.active,
            config.binding_epoch,
            Jiffies::elapsed().as_u64(),
        )
        .map_err(OstdSupervisorRuntimeBuildError::Manager)?;
        Ok(Self { manager, shared })
    }

    pub(crate) fn timer_ingress(&self) -> OstdSupervisorTimerIngress<N> {
        OstdSupervisorTimerIngress {
            shared: Arc::clone(&self.shared),
        }
    }

    pub(crate) fn health(&self) -> SupervisorHealth {
        self.manager.health()
    }

    /// Processes at most one event or one coalesced timer observation.
    pub(crate) fn drive_once(
        &mut self,
    ) -> Result<OstdSupervisorDriveProgress, OstdSupervisorRuntimeError> {
        if self
            .shared
            .lifecycle_ingress_rejected
            .load(Ordering::Acquire)
        {
            return Err(OstdSupervisorRuntimeError::Local(
                OstdSupervisorRuntimeLocalError::ExactLifecycleIngressRejected,
            ));
        }
        self.shared
            .flush_oldest_retained()
            .map_err(OstdSupervisorRuntimeError::Local)?;
        if let Some(envelope) = self.shared.pop_event() {
            let result = match envelope.event {
                OstdSupervisorEvent::Ready {
                    service,
                    binding_epoch,
                } => self
                    .manager
                    .replacement_ready_at_epoch(envelope.observed_tick, service, binding_epoch)
                    .map(|recovery| {
                        self.shared.mark_ready_accepted(service, binding_epoch);
                        OstdSupervisorDriveProgress::Event {
                            envelope,
                            recovery: Some(recovery),
                            stop: None,
                        }
                    }),
                OstdSupervisorEvent::Exit {
                    service,
                    binding_epoch,
                    reason,
                } => self
                    .manager
                    .observe_exit_at_epoch(envelope.observed_tick, service, binding_epoch, reason)
                    .map(|()| OstdSupervisorDriveProgress::Event {
                        envelope,
                        recovery: None,
                        stop: None,
                    }),
                OstdSupervisorEvent::Reaped {
                    service,
                    binding_epoch,
                } if self.manager.health().phase == SupervisorPhase::Stopping => self
                    .manager
                    .replacement_reaped_at_epoch(envelope.observed_tick, service, binding_epoch)
                    .map(|stop| OstdSupervisorDriveProgress::Event {
                        envelope,
                        recovery: None,
                        stop: Some(stop),
                    }),
                OstdSupervisorEvent::Reaped { .. } => {
                    // Reaping an active service follows its already-accepted
                    // Exit event. The manager is then in Backoff and does not
                    // own stop cleanup for that task; this event releases the
                    // adapter slot only. A replacement stopped before Ready is
                    // instead handled by the Stopping arm above.
                    Ok(OstdSupervisorDriveProgress::Event {
                        envelope,
                        recovery: None,
                        stop: None,
                    })
                }
            };
            return result.map_err(|source| OstdSupervisorRuntimeError::Manager {
                event: Some(envelope),
                source,
            });
        }
        if !self.shared.tick_pending.swap(false, Ordering::AcqRel) {
            return Ok(OstdSupervisorDriveProgress::Idle);
        }
        self.manager
            .poll(Jiffies::elapsed().as_u64())
            .map(OstdSupervisorDriveProgress::Timer)
            .map_err(|source| OstdSupervisorRuntimeError::Manager {
                event: None,
                source,
            })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc as __cser_alloc;
    extern crate core as __cser_core;

    use nexus_supervisor::{ExitReason, ServiceIdentity};

    use super::{
        BoundedEventQueue, EventQueuePushError, OstdSupervisorActivationReport,
        OstdSupervisorBackendError, OstdSupervisorEvent, OstdSupervisorEventEnvelope,
        OstdSupervisorRetentionReason, ReplacementSlot, ReplacementSlotPhase, SignalKind,
        SignalState, activation_report, cohort_identity_from_effects, oldest_retained,
        permit_for_report, replacement_identity, request_activation,
    };
    use crate::effect_registry::EffectKey;

    fn service(generation: u64) -> ServiceIdentity {
        ServiceIdentity::new(7, generation).unwrap()
    }

    #[test]
    fn activation_stays_closed_over_missing_isolated_fault_hook() {
        let report = activation_report();
        __cser_core::assert!(report.registry_backend);
        __cser_core::assert!(report.construct_unpublished);
        __cser_core::assert!(report.task_return_boundary);
        __cser_core::assert!(report.exact_task_exit_hook);
        __cser_core::assert!(report.exact_task_reap_hook);
        __cser_core::assert!(!report.isolated_task_fault_hook);
        __cser_core::assert!(!report.initial_active_task_binding);
        __cser_core::assert!(!report.nexus_owned_manager_worker);
        __cser_core::assert!(!report.is_complete());
        __cser_core::assert!(request_activation().is_err());
    }

    #[test]
    fn every_exact_lifecycle_capability_is_mandatory_for_a_permit() {
        let complete = OstdSupervisorActivationReport {
            registry_backend: true,
            bounded_event_queue: true,
            monotonic_jiffies: true,
            construct_unpublished: true,
            scheduler_publication: true,
            cooperative_stop_flag: true,
            task_return_boundary: true,
            exact_task_exit_hook: true,
            exact_task_reap_hook: true,
            isolated_task_fault_hook: true,
            initial_active_task_binding: true,
            nexus_owned_manager_worker: true,
        };
        __cser_core::assert!(permit_for_report(complete).is_ok());

        let mut missing_exit = complete;
        missing_exit.exact_task_exit_hook = false;
        __cser_core::assert!(permit_for_report(missing_exit).is_err());

        let mut missing_reap = complete;
        missing_reap.exact_task_reap_hook = false;
        __cser_core::assert!(permit_for_report(missing_reap).is_err());

        let mut missing_fault = complete;
        missing_fault.isolated_task_fault_hook = false;
        __cser_core::assert!(permit_for_report(missing_fault).is_err());

        let mut missing_initial_binding = complete;
        missing_initial_binding.initial_active_task_binding = false;
        __cser_core::assert!(permit_for_report(missing_initial_binding).is_err());

        let mut missing_worker = complete;
        missing_worker.nexus_owned_manager_worker = false;
        __cser_core::assert!(permit_for_report(missing_worker).is_err());
    }

    #[test]
    fn retained_exit_precedes_reap_even_after_slot_reaches_reaped_phase() {
        let exit = OstdSupervisorEvent::Exit {
            service: service(2),
            binding_epoch: 9,
            reason: ExitReason::UnexpectedReturn,
        };
        let reaped = OstdSupervisorEvent::Reaped {
            service: service(2),
            binding_epoch: 9,
        };
        let mut slot = ReplacementSlot::new();
        // Exact substrate facts advance the resource phase immediately. Their
        // manager delivery order remains independently retained by tick/kind.
        slot.phase = ReplacementSlotPhase::Reaped;
        slot.exit = SignalState::Retained {
            observed_tick: 17,
            event: exit,
            reason: OstdSupervisorRetentionReason::QueueFull,
        };
        slot.reaped = SignalState::Retained {
            observed_tick: 17,
            event: reaped,
            reason: OstdSupervisorRetentionReason::QueueFull,
        };

        __cser_core::assert_eq!(oldest_retained(&slot), Some((17, SignalKind::Exit, exit)));
        slot.exit = SignalState::Consumed;
        __cser_core::assert_eq!(
            oldest_retained(&slot),
            Some((17, SignalKind::Reaped, reaped))
        );
    }

    #[test]
    fn every_retry_gets_a_fresh_service_incarnation() {
        __cser_core::assert_eq!(replacement_identity(service(1), 1).unwrap(), service(2));
        __cser_core::assert_eq!(replacement_identity(service(1), 2).unwrap(), service(3));
        __cser_core::assert_eq!(
            replacement_identity(service(1), 0),
            Err(OstdSupervisorBackendError::InvalidIdentity)
        );
        __cser_core::assert_eq!(
            replacement_identity(ServiceIdentity::new(7, u64::MAX).unwrap(), 1),
            Err(OstdSupervisorBackendError::GenerationExhausted)
        );
    }

    #[test]
    fn bounded_queue_preserves_exact_fifo_identity_and_sequence() {
        let mut queue = BoundedEventQueue::<4>::new();
        let ready = OstdSupervisorEvent::Ready {
            service: service(2),
            binding_epoch: 9,
        };
        let exit = OstdSupervisorEvent::Exit {
            service: service(2),
            binding_epoch: 9,
            reason: ExitReason::Fault,
        };
        __cser_core::assert_eq!(queue.push(11, ready), Ok(1));
        __cser_core::assert_eq!(queue.push(12, exit), Ok(2));
        __cser_core::assert_eq!(
            queue.pop(),
            Some(OstdSupervisorEventEnvelope {
                sequence: 1,
                observed_tick: 11,
                event: ready,
            })
        );
        __cser_core::assert_eq!(
            queue.pop(),
            Some(OstdSupervisorEventEnvelope {
                sequence: 2,
                observed_tick: 12,
                event: exit,
            })
        );
        __cser_core::assert_eq!(queue.pop(), None);
    }

    #[test]
    fn full_queue_returns_failure_without_losing_presented_event() {
        let mut queue = BoundedEventQueue::<1>::new();
        let ready = OstdSupervisorEvent::Ready {
            service: service(2),
            binding_epoch: 9,
        };
        let exit = OstdSupervisorEvent::Exit {
            service: service(2),
            binding_epoch: 9,
            reason: ExitReason::UnexpectedReturn,
        };
        __cser_core::assert_eq!(queue.push(1, ready), Ok(1));
        __cser_core::assert_eq!(queue.push(2, exit), Err(EventQueuePushError::Full));
        __cser_core::assert_eq!(queue.pop().unwrap().event, ready);
        __cser_core::assert_eq!(queue.push(2, exit), Ok(2));
        __cser_core::assert_eq!(queue.pop().unwrap().event, exit);
    }

    #[test]
    fn cohort_digest_is_order_and_generation_bound() {
        let a = [EffectKey::new(1, 1), EffectKey::new(2, 1)];
        let b = [EffectKey::new(2, 1), EffectKey::new(1, 1)];
        let c = [EffectKey::new(1, 1), EffectKey::new(2, 2)];
        let first = cohort_identity_from_effects(a.iter()).unwrap();
        __cser_core::assert_eq!(first.len(), 2);
        __cser_core::assert_ne!(first, cohort_identity_from_effects(b.iter()).unwrap());
        __cser_core::assert_ne!(first, cohort_identity_from_effects(c.iter()).unwrap());
    }
}
