use std::collections::{BTreeMap, BTreeSet, VecDeque, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};

use axle_conformance::contracts::{ConcurrencyHookClass, ConcurrencyStateProjection};
use axle_core::{
    FakeClock, ObjectKey, ObserverRegistry, PacketKind, Port, PortError, Signals, Time, TimerId,
    TimerService, WaitAsyncOptions, WaitAsyncRegistration, WaitAsyncTimestamp, WaitOne, wait_one,
};
use axle_mm::{FutexKey, GlobalVmoId};
use axle_types::koid::ZX_KOID_INVALID;

use crate::seed::{
    ChannelHandleOp, ConcurrentSeed, FutexFaultOp, HookId, ProgramOp, SchedHint, SystemKind, WaitOp,
};

const TIMER_WAITABLE_BASE: u64 = 0x10;
const PORT_OBSERVER_ID: u64 = 1;

fn observer_port_key() -> ObjectKey {
    PORT_OBSERVER_ID.into()
}

fn waitable_key(id: u64) -> ObjectKey {
    id.into()
}

/// Observation summary for one concurrent seed replay.
#[derive(Clone, Debug, Default)]
pub struct RunObservation {
    /// Semantic edge/block coverage hits.
    pub edge_hits: BTreeSet<String>,
    /// Stable semantic hook classes reached during replay.
    pub hook_classes: BTreeSet<ConcurrencyHookClass>,
    /// Abstract state signatures reached during replay.
    pub state_signatures: BTreeSet<u64>,
    /// Stable abstract state projections reached during replay.
    pub state_projections: BTreeSet<ConcurrencyStateProjection>,
    /// Failure kind for invariant failure or hang.
    pub failure_kind: Option<String>,
    /// Human-readable event log for replay/debugging.
    pub events: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ActorId {
    A,
    B,
}

impl ActorId {
    fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockedWait {
    Signal {
        waitable: u64,
        watched: Signals,
        deadline: Option<Time>,
    },
    Port {
        deadline: Option<Time>,
    },
    Futex {
        key: FutexKey,
        deadline: Option<Time>,
    },
    Fault {
        key: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActorResult {
    Ok,
    TimedOut,
    ShouldWait,
    Woken,
    FaultResolved,
}

#[derive(Clone, Debug)]
enum Continuation {
    PublishSignals {
        waitable: u64,
    },
    FireTimers {
        waitables: Vec<u64>,
    },
    FutexRequeue {
        source: FutexKey,
        target: FutexKey,
        wake_count: usize,
        requeue_count: usize,
    },
    FaultLeader {
        key: u64,
        phase: FaultPhase,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultPhase {
    Prepare,
    Commit,
}

#[derive(Clone, Debug)]
struct ActorState {
    pc: usize,
    blocked: Option<BlockedWait>,
    continuation: Option<Continuation>,
    pause_turns: u8,
    last_result: ActorResult,
}

impl Default for ActorState {
    fn default() -> Self {
        Self {
            pc: 0,
            blocked: None,
            continuation: None,
            pause_turns: 0,
            last_result: ActorResult::Ok,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct HookDirective {
    switch_to_other: bool,
    pause_turns: u8,
    delay_timer_ticks: u8,
    prefer_other_once: bool,
}

#[derive(Clone, Debug)]
struct HintState {
    hint: SchedHint,
    used: bool,
}

#[derive(Clone, Debug)]
struct HookRuntime {
    hints: Vec<HintState>,
    prefer_other_once: bool,
}

impl HookRuntime {
    fn new(hints: &[SchedHint]) -> Self {
        Self {
            hints: hints
                .iter()
                .copied()
                .map(|hint| HintState { hint, used: false })
                .collect(),
            prefer_other_once: false,
        }
    }

    fn hit(
        &mut self,
        actor: ActorId,
        hook: HookId,
        observation: &mut RunObservation,
    ) -> HookDirective {
        observation
            .edge_hits
            .insert(format!("hook:{hook:?}:actor:{actor:?}"));
        observation.hook_classes.insert(map_hook_class(hook));
        observation
            .events
            .push(format!("actor={actor:?} hook={hook:?}"));
        let mut directive = HookDirective::default();
        for entry in &mut self.hints {
            if entry.used {
                continue;
            }
            match entry.hint {
                SchedHint::YieldHere(h) if h == hook => {
                    directive.switch_to_other = true;
                    entry.used = true;
                }
                SchedHint::PauseThread(h, turns) if h == hook => {
                    directive.switch_to_other = true;
                    directive.pause_turns = turns;
                    entry.used = true;
                }
                SchedHint::DelayTimerFire(h, ticks) if h == hook => {
                    directive.switch_to_other = true;
                    directive.delay_timer_ticks = ticks;
                    entry.used = true;
                }
                SchedHint::ForceRemoteWake(h) if h == hook => {
                    directive.switch_to_other = true;
                    directive.prefer_other_once = true;
                    entry.used = true;
                }
                _ => {}
            }
        }
        if directive.switch_to_other || directive.prefer_other_once {
            self.prefer_other_once = true;
        }
        directive
    }

    fn should_prefer_other(&mut self) -> bool {
        let prefer = self.prefer_other_once;
        self.prefer_other_once = false;
        prefer
    }
}

const fn map_hook_class(hook: HookId) -> ConcurrencyHookClass {
    match hook {
        HookId::WaiterLinked => ConcurrencyHookClass::WaiterLinked,
        HookId::SignalUpdatedBeforeWake => ConcurrencyHookClass::SignalUpdatedBeforeWake,
        HookId::PortReserveExhausted => ConcurrencyHookClass::PortReserveExhausted,
        HookId::TimerBeforeFire => ConcurrencyHookClass::TimerBeforeFire,
        HookId::FutexRequeueBeforeMove => ConcurrencyHookClass::FutexRequeueBeforeMove,
        HookId::FutexRequeueAfterMove => ConcurrencyHookClass::FutexRequeueAfterMove,
        HookId::FaultLeaderClaimed => ConcurrencyHookClass::FaultLeaderClaimed,
        HookId::FaultHeavyPrepareBeforeCommit => {
            ConcurrencyHookClass::FaultHeavyPrepareBeforeCommit
        }
        HookId::FaultTxBeforeCommit => ConcurrencyHookClass::FaultTxBeforeCommit,
        HookId::ChannelCloseBeforeReadDrain => ConcurrencyHookClass::ChannelCloseBeforeReadDrain,
        HookId::HandleReplaceBeforePublish => ConcurrencyHookClass::HandleReplaceBeforePublish,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StepDisposition {
    Progress,
    NoProgress,
}

/// Replay one concurrent seed and return semantic coverage, state signatures, and failure kind.
pub fn run_seed(seed: &ConcurrentSeed) -> RunObservation {
    match seed.system {
        SystemKind::WaitPortTimer => WaitPortTimerRunner::new(seed).run(),
        SystemKind::FutexFault => FutexFaultRunner::new(seed).run(),
        SystemKind::ChannelHandle => ChannelHandleRunner::new(seed).run(),
    }
}

struct WaitPortTimerRunner<'a> {
    seed: &'a ConcurrentSeed,
    actors: [ActorState; 2],
    current_actor: ActorId,
    hooks: HookRuntime,
    observation: RunObservation,
    port: Port,
    observers: ObserverRegistry,
    clock: FakeClock,
    timers: TimerService,
    timer_slots: [TimerId; 2],
    signals: BTreeMap<u64, Signals>,
    async_registrations: usize,
    delayed_timer_waitables: VecDeque<(u8, Vec<u64>)>,
}

impl<'a> WaitPortTimerRunner<'a> {
    fn new(seed: &'a ConcurrentSeed) -> Self {
        let mut timers = TimerService::new();
        let timer_slots = [timers.create_timer(), timers.create_timer()];
        Self {
            seed,
            actors: [ActorState::default(), ActorState::default()],
            current_actor: ActorId::A,
            hooks: HookRuntime::new(&seed.hints),
            observation: RunObservation::default(),
            port: Port::new(4, 1),
            observers: ObserverRegistry::new(),
            clock: FakeClock::new(),
            timers,
            timer_slots,
            signals: BTreeMap::new(),
            async_registrations: 0,
            delayed_timer_waitables: VecDeque::new(),
        }
    }

    fn run(mut self) -> RunObservation {
        self.snapshot_state();
        let budget = usize::from(self.seed.replay.max_steps.max(1));
        for _ in 0..budget {
            if self.is_done() {
                return self.finish();
            }
            self.service_delayed_timers();
            self.service_deadlines();
            let mut disposition = self.step_actor(self.current_actor);
            if matches!(disposition, StepDisposition::NoProgress) {
                disposition = self.step_actor(self.current_actor.other());
                if matches!(disposition, StepDisposition::NoProgress) {
                    if self.is_done() {
                        return self.finish();
                    }
                    self.observation.failure_kind = Some("hang.wait_port_timer".into());
                    self.observation
                        .events
                        .push("runner=wait_port_timer hang".into());
                    return self.finish();
                }
                self.current_actor = self.current_actor.other();
            } else if self.hooks.should_prefer_other() {
                self.current_actor = self.current_actor.other();
            }
            self.snapshot_state();
        }
        self.observation.failure_kind = Some("hang.step_budget".into());
        self.observation
            .events
            .push("runner=wait_port_timer step_budget".into());
        self.finish()
    }

    fn finish(mut self) -> RunObservation {
        if self.port.len() > self.port.capacity() {
            self.observation.failure_kind = Some("invariant.port_overflow".into());
        }
        self.observation
    }

    fn is_done(&self) -> bool {
        self.actors.iter().enumerate().all(|(idx, actor)| {
            let program = if idx == 0 {
                &self.seed.program_a
            } else {
                &self.seed.program_b
            };
            actor.pc >= program.len() && actor.blocked.is_none() && actor.continuation.is_none()
        })
    }

    fn step_actor(&mut self, actor_id: ActorId) -> StepDisposition {
        let actor = &mut self.actors[actor_id.index()];
        if actor.pause_turns > 0 {
            actor.pause_turns -= 1;
            self.observation.events.push(format!(
                "actor={actor_id:?} pause_turns={}",
                actor.pause_turns
            ));
            return StepDisposition::Progress;
        }
        if actor.blocked.is_some() {
            return StepDisposition::NoProgress;
        }
        if let Some(cont) = actor.continuation.take() {
            return self.run_wait_continuation(actor_id, cont);
        }
        let program = if actor_id == ActorId::A {
            &self.seed.program_a
        } else {
            &self.seed.program_b
        };
        let Some(op) = program.get(actor.pc).copied() else {
            return StepDisposition::NoProgress;
        };
        actor.pc += 1;
        match op {
            ProgramOp::Wait(op) => self.run_wait_op(actor_id, op),
            ProgramOp::FutexFault(_) => {
                self.observation.failure_kind = Some("invalid.seed.system_mismatch".into());
                StepDisposition::Progress
            }
            ProgramOp::ChannelHandle(_) => {
                self.observation.failure_kind = Some("invalid.seed.system_mismatch".into());
                StepDisposition::Progress
            }
        }
    }

    fn run_wait_op(&mut self, actor_id: ActorId, op: WaitOp) -> StepDisposition {
        self.observation
            .edge_hits
            .insert(format!("wait_op:{op:?}:actor:{actor_id:?}"));
        match op {
            WaitOp::SetSignal { waitable, bits } => {
                let waitable = u64::from(waitable);
                let next = self.signal_bits(bits);
                let current = self
                    .signals
                    .get(&waitable)
                    .copied()
                    .unwrap_or(Signals::NONE);
                self.signals.insert(waitable, current | next);
                let directive = self.hooks.hit(
                    actor_id,
                    HookId::SignalUpdatedBeforeWake,
                    &mut self.observation,
                );
                self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                self.actors[actor_id.index()].continuation =
                    Some(Continuation::PublishSignals { waitable });
                if directive.switch_to_other {
                    self.current_actor = actor_id.other();
                }
                StepDisposition::Progress
            }
            WaitOp::ClearSignal { waitable, bits } => {
                let waitable = u64::from(waitable);
                let clear = self.signal_bits(bits);
                let current = self
                    .signals
                    .get(&waitable)
                    .copied()
                    .unwrap_or(Signals::NONE);
                self.signals.insert(waitable, current.without(clear));
                let directive = self.hooks.hit(
                    actor_id,
                    HookId::SignalUpdatedBeforeWake,
                    &mut self.observation,
                );
                self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                self.actors[actor_id.index()].continuation =
                    Some(Continuation::PublishSignals { waitable });
                if directive.switch_to_other {
                    self.current_actor = actor_id.other();
                }
                StepDisposition::Progress
            }
            WaitOp::WaitOne {
                waitable,
                bits,
                deadline_ticks,
            } => {
                let waitable = u64::from(waitable);
                let watched = self.signal_bits(bits);
                let observed = self
                    .signals
                    .get(&waitable)
                    .copied()
                    .unwrap_or(Signals::NONE);
                match wait_one(observed, watched) {
                    WaitOne::Ready(_) => {
                        self.actors[actor_id.index()].last_result = ActorResult::Ok;
                    }
                    WaitOne::ShouldWait => {
                        let deadline =
                            deadline_ticks.map(|ticks| self.clock.now() + i64::from(ticks));
                        self.actors[actor_id.index()].blocked = Some(BlockedWait::Signal {
                            waitable,
                            watched,
                            deadline,
                        });
                        let directive =
                            self.hooks
                                .hit(actor_id, HookId::WaiterLinked, &mut self.observation);
                        self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                    }
                }
                StepDisposition::Progress
            }
            WaitOp::WaitAsync {
                waitable,
                key,
                bits,
                edge,
            } => {
                let waitable_id = u64::from(waitable);
                let current = self
                    .signals
                    .get(&waitable_id)
                    .copied()
                    .unwrap_or(Signals::NONE);
                let watched = self.signal_bits(bits);
                let before_len = self.port.len();
                let observers = &mut self.observers;
                let port = &mut self.port;
                match observers.wait_async(
                    WaitAsyncRegistration {
                        port: observer_port_key(),
                        waitable: waitable_key(waitable_id),
                        key: u64::from(key),
                        watched,
                        options: WaitAsyncOptions {
                            edge_triggered: edge,
                            timestamp: WaitAsyncTimestamp::Monotonic,
                        },
                    },
                    current,
                    self.clock.now(),
                    |port_id, packet| {
                        debug_assert_eq!(port_id, observer_port_key());
                        port.queue_kernel(packet).is_ok()
                    },
                ) {
                    Ok(()) => {
                        self.async_registrations = self.async_registrations.saturating_add(1);
                        if before_len == self.port.len() && !current.intersects(watched) {
                            let directive = self.hooks.hit(
                                actor_id,
                                HookId::WaiterLinked,
                                &mut self.observation,
                            );
                            self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                        }
                    }
                    Err(PortError::AlreadyExists)
                    | Err(PortError::ShouldWait)
                    | Err(PortError::NotFound) => {
                        self.actors[actor_id.index()].last_result = ActorResult::ShouldWait;
                    }
                }
                StepDisposition::Progress
            }
            WaitOp::PortWait { deadline_ticks } => {
                match self.port.pop() {
                    Ok(packet) => {
                        self.actors[actor_id.index()].last_result = match packet.kind {
                            PacketKind::Signal | PacketKind::User => ActorResult::Ok,
                        };
                        self.flush_pending_port_packets();
                    }
                    Err(PortError::ShouldWait) => {
                        let deadline =
                            deadline_ticks.map(|ticks| self.clock.now() + i64::from(ticks));
                        self.actors[actor_id.index()].blocked =
                            Some(BlockedWait::Port { deadline });
                        let directive =
                            self.hooks
                                .hit(actor_id, HookId::WaiterLinked, &mut self.observation);
                        self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                    }
                    Err(PortError::AlreadyExists) | Err(PortError::NotFound) => {
                        self.actors[actor_id.index()].last_result = ActorResult::ShouldWait;
                    }
                }
                StepDisposition::Progress
            }
            WaitOp::TimerSet {
                slot,
                deadline_ticks,
            } => {
                let slot = usize::from(slot % 2);
                let timer = self.timer_slots[slot];
                let _ = self
                    .timers
                    .set(timer, self.clock.now() + i64::from(deadline_ticks));
                self.signals.insert(
                    TIMER_WAITABLE_BASE + u64::try_from(slot).unwrap(),
                    Signals::NONE,
                );
                StepDisposition::Progress
            }
            WaitOp::TimerCancel { slot } => {
                let slot = usize::from(slot % 2);
                let timer = self.timer_slots[slot];
                let _ = self.timers.cancel(timer);
                self.signals.insert(
                    TIMER_WAITABLE_BASE + u64::try_from(slot).unwrap(),
                    Signals::NONE,
                );
                StepDisposition::Progress
            }
            WaitOp::AdvanceTime { ticks } => {
                self.clock.advance_by(i64::from(ticks.max(1)));
                let fired = self.timers.poll(self.clock.now());
                if fired.is_empty() {
                    return StepDisposition::Progress;
                }
                let waitables = fired
                    .into_iter()
                    .filter_map(|timer_id| self.timer_waitable(timer_id))
                    .collect::<Vec<_>>();
                let directive =
                    self.hooks
                        .hit(actor_id, HookId::TimerBeforeFire, &mut self.observation);
                self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                if directive.delay_timer_ticks != 0 {
                    self.delayed_timer_waitables
                        .push_back((directive.delay_timer_ticks, waitables));
                } else {
                    self.actors[actor_id.index()].continuation =
                        Some(Continuation::FireTimers { waitables });
                }
                StepDisposition::Progress
            }
        }
    }

    fn run_wait_continuation(
        &mut self,
        actor_id: ActorId,
        continuation: Continuation,
    ) -> StepDisposition {
        match continuation {
            Continuation::PublishSignals { waitable } => {
                self.notify_signal_change(waitable);
                StepDisposition::Progress
            }
            Continuation::FireTimers { waitables } => {
                for waitable in waitables {
                    self.signals.insert(waitable, Signals::TIMER_SIGNALED);
                    self.notify_signal_change(waitable);
                }
                StepDisposition::Progress
            }
            Continuation::FutexRequeue { .. } | Continuation::FaultLeader { .. } => {
                self.observation.failure_kind = Some("invalid.runner.continuation".into());
                self.observation
                    .events
                    .push(format!("actor={actor_id:?} invalid wait continuation"));
                StepDisposition::Progress
            }
        }
    }

    fn notify_signal_change(&mut self, waitable: u64) {
        let current = self
            .signals
            .get(&waitable)
            .copied()
            .unwrap_or(Signals::NONE);
        for actor_id in [ActorId::A, ActorId::B] {
            let blocked = self.actors[actor_id.index()].blocked;
            let Some(BlockedWait::Signal {
                waitable: blocked_waitable,
                watched,
                ..
            }) = blocked
            else {
                continue;
            };
            if blocked_waitable == waitable && current.intersects(watched) {
                self.actors[actor_id.index()].blocked = None;
                self.actors[actor_id.index()].last_result = ActorResult::Woken;
                self.observation
                    .edge_hits
                    .insert(format!("wake:signal:actor:{actor_id:?}"));
            }
        }

        let before_len = self.port.len();
        let observers = &mut self.observers;
        let port = &mut self.port;
        let changed_ports = observers.on_signals_changed(
            waitable_key(waitable),
            current,
            self.clock.now(),
            |port_id, packet| {
                debug_assert_eq!(port_id, observer_port_key());
                port.queue_kernel(packet).is_ok()
            },
        );
        if before_len == self.port.capacity() && self.port.len() == before_len {
            let _ = self.hooks.hit(
                ActorId::A,
                HookId::PortReserveExhausted,
                &mut self.observation,
            );
        }
        if before_len == 0 && changed_ports.contains(&observer_port_key()) {
            self.observation
                .edge_hits
                .insert("port:empty_to_nonempty".into());
        }
        self.wake_port_waiter();
    }

    fn wake_port_waiter(&mut self) {
        if self.port.is_empty() {
            return;
        }
        let waiter = [ActorId::A, ActorId::B].into_iter().find(|actor_id| {
            matches!(
                self.actors[actor_id.index()].blocked,
                Some(BlockedWait::Port { .. })
            )
        });
        let Some(actor_id) = waiter else {
            return;
        };
        let _ = self.port.pop();
        self.flush_pending_port_packets();
        self.actors[actor_id.index()].blocked = None;
        self.actors[actor_id.index()].last_result = ActorResult::Woken;
        self.observation
            .edge_hits
            .insert(format!("wake:port:actor:{actor_id:?}"));
    }

    fn service_deadlines(&mut self) {
        for actor_id in [ActorId::A, ActorId::B] {
            let blocked = self.actors[actor_id.index()].blocked;
            match blocked {
                Some(BlockedWait::Signal { deadline, .. })
                | Some(BlockedWait::Port { deadline })
                    if deadline.is_some_and(|deadline| self.clock.now() >= deadline) =>
                {
                    self.actors[actor_id.index()].blocked = None;
                    self.actors[actor_id.index()].last_result = ActorResult::TimedOut;
                    self.observation
                        .edge_hits
                        .insert(format!("timeout:actor:{actor_id:?}"));
                }
                _ => {}
            }
        }
    }

    fn flush_pending_port_packets(&mut self) {
        let observers = &mut self.observers;
        let port = &mut self.port;
        observers.flush_port(observer_port_key(), |port_id, packet| {
            debug_assert_eq!(port_id, observer_port_key());
            port.queue_kernel(packet).is_ok()
        });
    }

    fn service_delayed_timers(&mut self) {
        let mut remaining = VecDeque::new();
        while let Some((delay, waitables)) = self.delayed_timer_waitables.pop_front() {
            if delay <= 1 {
                for waitable in waitables {
                    self.signals.insert(waitable, Signals::TIMER_SIGNALED);
                    self.notify_signal_change(waitable);
                }
            } else {
                remaining.push_back((delay - 1, waitables));
            }
        }
        self.delayed_timer_waitables = remaining;
    }

    fn timer_waitable(&self, timer_id: TimerId) -> Option<u64> {
        self.timer_slots
            .iter()
            .position(|candidate| *candidate == timer_id)
            .map(|slot| TIMER_WAITABLE_BASE + u64::try_from(slot).unwrap())
    }

    fn signal_bits(&self, bits: u8) -> Signals {
        let mut out = Signals::NONE;
        if bits & 0b0001 != 0 {
            out = out | Signals::USER_SIGNAL_0;
        }
        if bits & 0b0010 != 0 {
            out = out | Signals::USER_SIGNAL_1;
        }
        if bits & 0b0100 != 0 {
            out = out | Signals::USER_SIGNAL_2;
        }
        if bits & 0b1000 != 0 {
            out = out | Signals::TIMER_SIGNALED;
        }
        out
    }

    fn snapshot_state(&mut self) {
        let blocked_count = self
            .actors
            .iter()
            .filter(|actor| actor.blocked.is_some())
            .count();
        let blocked_signal = self
            .actors
            .iter()
            .filter(|actor| matches!(actor.blocked, Some(BlockedWait::Signal { .. })))
            .count();
        let blocked_port = self
            .actors
            .iter()
            .filter(|actor| matches!(actor.blocked, Some(BlockedWait::Port { .. })))
            .count();
        let signal_summary = self
            .signals
            .values()
            .fold(Signals::NONE, |acc, signals| acc | *signals)
            .bits();
        let timer_signaled = self
            .timer_slots
            .iter()
            .filter_map(|timer| self.timers.is_signaled(*timer).ok())
            .filter(|signaled| *signaled)
            .count();
        if blocked_count != 0 {
            self.observation
                .state_projections
                .insert(ConcurrencyStateProjection::WaitPortTimerBlockedWaiters);
        }
        if !self.port.is_empty() || !self.port.signals().is_empty() || self.async_registrations != 0
        {
            self.observation
                .state_projections
                .insert(ConcurrencyStateProjection::WaitPortTimerPortQueue);
        }
        if timer_signaled != 0 {
            self.observation
                .state_projections
                .insert(ConcurrencyStateProjection::WaitPortTimerTimerSignals);
        }
        if signal_summary != 0 {
            self.observation
                .state_projections
                .insert(ConcurrencyStateProjection::WaitPortTimerObjectSignals);
        }
        let state = (
            blocked_count,
            blocked_signal,
            blocked_port,
            self.port.len(),
            self.port.signals().bits(),
            self.async_registrations,
            timer_signaled,
            signal_summary,
            self.clock.now(),
        );
        self.observation.state_signatures.insert(hash_value(&state));
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultEntry {
    in_flight: bool,
    blocked_waiters: BTreeSet<ActorId>,
    leader: Option<ActorId>,
}

#[derive(Clone, Debug, Default)]
struct FutexQueue {
    waiters: VecDeque<ActorId>,
    owner_koid: u64,
}

#[derive(Clone, Debug, Default)]
struct FutexTableModel {
    queues: BTreeMap<FutexKey, FutexQueue>,
}

impl FutexTableModel {
    fn owner(&self, key: FutexKey) -> u64 {
        self.queues
            .get(&key)
            .map(|queue| queue.owner_koid)
            .unwrap_or(ZX_KOID_INVALID)
    }

    fn enqueue_waiter(&mut self, key: FutexKey, actor: ActorId) {
        self.queues.entry(key).or_default().waiters.push_back(actor);
    }

    fn cancel_waiter(&mut self, key: FutexKey, actor: ActorId) -> bool {
        let Some(queue) = self.queues.get_mut(&key) else {
            return false;
        };
        let before = queue.waiters.len();
        queue.waiters.retain(|candidate| *candidate != actor);
        let removed = before != queue.waiters.len();
        self.gc_key(key);
        removed
    }

    fn wake(&mut self, key: FutexKey, count: usize) -> Vec<ActorId> {
        let Some(queue) = self.queues.get_mut(&key) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for _ in 0..count {
            let Some(actor) = queue.waiters.pop_front() else {
                break;
            };
            out.push(actor);
        }
        queue.owner_koid = ZX_KOID_INVALID;
        self.gc_key(key);
        out
    }

    fn requeue(
        &mut self,
        source: FutexKey,
        target: FutexKey,
        wake_count: usize,
        requeue_count: usize,
    ) -> (Vec<ActorId>, Vec<ActorId>) {
        if source == target {
            let woken = self.wake(source, wake_count);
            return (woken, Vec::new());
        }
        let mut woken = Vec::new();
        let mut requeued = Vec::new();
        let mut moved = VecDeque::new();
        if let Some(queue) = self.queues.get_mut(&source) {
            for _ in 0..wake_count {
                let Some(actor) = queue.waiters.pop_front() else {
                    break;
                };
                woken.push(actor);
            }
            for _ in 0..requeue_count {
                let Some(actor) = queue.waiters.pop_front() else {
                    break;
                };
                moved.push_back(actor);
                requeued.push(actor);
            }
            queue.owner_koid = ZX_KOID_INVALID;
        }
        let target_queue = self.queues.entry(target).or_default();
        target_queue.owner_koid = 1;
        target_queue.waiters.extend(moved);
        self.gc_key(source);
        self.gc_key(target);
        (woken, requeued)
    }

    fn occupancy(&self) -> Vec<usize> {
        self.queues
            .values()
            .map(|queue| queue.waiters.len())
            .collect()
    }

    fn gc_key(&mut self, key: FutexKey) {
        let should_remove = self
            .queues
            .get(&key)
            .map(|queue| queue.waiters.is_empty() && queue.owner_koid == ZX_KOID_INVALID)
            .unwrap_or(false);
        if should_remove {
            let _ = self.queues.remove(&key);
        }
    }
}

struct FutexFaultRunner<'a> {
    seed: &'a ConcurrentSeed,
    actors: [ActorState; 2],
    current_actor: ActorId,
    hooks: HookRuntime,
    observation: RunObservation,
    now: i64,
    futex_words: BTreeMap<FutexKey, u32>,
    futex: FutexTableModel,
    faults: BTreeMap<u64, FaultEntry>,
}

impl<'a> FutexFaultRunner<'a> {
    fn new(seed: &'a ConcurrentSeed) -> Self {
        Self {
            seed,
            actors: [ActorState::default(), ActorState::default()],
            current_actor: ActorId::A,
            hooks: HookRuntime::new(&seed.hints),
            observation: RunObservation::default(),
            now: 0,
            futex_words: BTreeMap::new(),
            futex: FutexTableModel::default(),
            faults: BTreeMap::new(),
        }
    }

    fn run(mut self) -> RunObservation {
        self.snapshot_state();
        let budget = usize::from(self.seed.replay.max_steps.max(1));
        for _ in 0..budget {
            if self.is_done() {
                return self.finish();
            }
            self.service_deadlines();
            let mut disposition = self.step_actor(self.current_actor);
            if matches!(disposition, StepDisposition::NoProgress) {
                disposition = self.step_actor(self.current_actor.other());
                if matches!(disposition, StepDisposition::NoProgress) {
                    if self.is_done() {
                        return self.finish();
                    }
                    self.observation.failure_kind = Some("hang.futex_fault".into());
                    self.observation
                        .events
                        .push("runner=futex_fault hang".into());
                    return self.finish();
                }
                self.current_actor = self.current_actor.other();
            } else if self.hooks.should_prefer_other() {
                self.current_actor = self.current_actor.other();
            }
            self.snapshot_state();
        }
        self.observation.failure_kind = Some("hang.step_budget".into());
        self.finish()
    }

    fn finish(mut self) -> RunObservation {
        for actor_id in [ActorId::A, ActorId::B] {
            if let Some(BlockedWait::Futex { key, .. }) = self.actors[actor_id.index()].blocked
                && !self
                    .futex
                    .queues
                    .get(&key)
                    .map(|queue| queue.waiters.contains(&actor_id))
                    .unwrap_or(false)
            {
                self.observation.failure_kind = Some("invariant.futex_waiter_lost".into());
            }
        }
        self.observation
    }

    fn is_done(&self) -> bool {
        self.actors.iter().enumerate().all(|(idx, actor)| {
            let program = if idx == 0 {
                &self.seed.program_a
            } else {
                &self.seed.program_b
            };
            actor.pc >= program.len() && actor.blocked.is_none() && actor.continuation.is_none()
        })
    }

    fn step_actor(&mut self, actor_id: ActorId) -> StepDisposition {
        let actor = &mut self.actors[actor_id.index()];
        if actor.pause_turns > 0 {
            actor.pause_turns -= 1;
            return StepDisposition::Progress;
        }
        if actor.blocked.is_some() {
            return StepDisposition::NoProgress;
        }
        if let Some(continuation) = actor.continuation.take() {
            return self.run_continuation(actor_id, continuation);
        }
        let program = if actor_id == ActorId::A {
            &self.seed.program_a
        } else {
            &self.seed.program_b
        };
        let Some(op) = program.get(actor.pc).copied() else {
            return StepDisposition::NoProgress;
        };
        actor.pc += 1;
        match op {
            ProgramOp::FutexFault(op) => self.run_op(actor_id, op),
            ProgramOp::Wait(_) => {
                self.observation.failure_kind = Some("invalid.seed.system_mismatch".into());
                StepDisposition::Progress
            }
            ProgramOp::ChannelHandle(_) => {
                self.observation.failure_kind = Some("invalid.seed.system_mismatch".into());
                StepDisposition::Progress
            }
        }
    }

    fn run_op(&mut self, actor_id: ActorId, op: FutexFaultOp) -> StepDisposition {
        self.observation
            .edge_hits
            .insert(format!("futex_fault_op:{op:?}:actor:{actor_id:?}"));
        match op {
            FutexFaultOp::FutexStore { key, value } => {
                self.futex_words.insert(shared_key(key), value);
                StepDisposition::Progress
            }
            FutexFaultOp::FutexWait {
                key,
                expected,
                deadline_ticks,
            } => {
                let key = shared_key(key);
                let observed = self.futex_words.get(&key).copied().unwrap_or(0);
                if observed != expected {
                    self.actors[actor_id.index()].last_result = ActorResult::ShouldWait;
                    return StepDisposition::Progress;
                }
                self.futex.enqueue_waiter(key, actor_id);
                self.actors[actor_id.index()].blocked = Some(BlockedWait::Futex {
                    key,
                    deadline: deadline_ticks.map(|ticks| self.now + i64::from(ticks)),
                });
                let directive =
                    self.hooks
                        .hit(actor_id, HookId::WaiterLinked, &mut self.observation);
                self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                StepDisposition::Progress
            }
            FutexFaultOp::FutexWake { key, count } => {
                let key = shared_key(key);
                for actor in self.futex.wake(key, usize::from(count.max(1))) {
                    self.actors[actor.index()].blocked = None;
                    self.actors[actor.index()].last_result = ActorResult::Woken;
                    self.observation
                        .edge_hits
                        .insert(format!("wake:futex:actor:{actor:?}"));
                }
                StepDisposition::Progress
            }
            FutexFaultOp::FutexRequeue {
                source,
                target,
                wake_count,
                requeue_count,
            } => {
                let source = shared_key(source);
                let target = shared_key(target);
                let before = self.hooks.hit(
                    actor_id,
                    HookId::FutexRequeueBeforeMove,
                    &mut self.observation,
                );
                self.actors[actor_id.index()].pause_turns = before.pause_turns;
                self.actors[actor_id.index()].continuation = Some(Continuation::FutexRequeue {
                    source,
                    target,
                    wake_count: usize::from(wake_count),
                    requeue_count: usize::from(requeue_count.max(1)),
                });
                StepDisposition::Progress
            }
            FutexFaultOp::Fault { key } => {
                let key = u64::from(key);
                match self.faults.get(&key).cloned() {
                    Some(entry) if entry.in_flight => {
                        let mut updated = entry;
                        updated.blocked_waiters.insert(actor_id);
                        self.faults.insert(key, updated);
                        self.actors[actor_id.index()].blocked = Some(BlockedWait::Fault { key });
                        StepDisposition::Progress
                    }
                    _ => {
                        self.faults.insert(
                            key,
                            FaultEntry {
                                in_flight: true,
                                blocked_waiters: BTreeSet::new(),
                                leader: Some(actor_id),
                            },
                        );
                        let directive = self.hooks.hit(
                            actor_id,
                            HookId::FaultLeaderClaimed,
                            &mut self.observation,
                        );
                        self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                        self.actors[actor_id.index()].continuation =
                            Some(Continuation::FaultLeader {
                                key,
                                phase: FaultPhase::Prepare,
                            });
                        StepDisposition::Progress
                    }
                }
            }
            FutexFaultOp::AdvanceTime { ticks } => {
                self.now += i64::from(ticks.max(1));
                StepDisposition::Progress
            }
        }
    }

    fn run_continuation(
        &mut self,
        actor_id: ActorId,
        continuation: Continuation,
    ) -> StepDisposition {
        match continuation {
            Continuation::FutexRequeue {
                source,
                target,
                wake_count,
                requeue_count,
            } => {
                let (woken, requeued) =
                    self.futex
                        .requeue(source, target, wake_count, requeue_count);
                for actor in woken {
                    self.actors[actor.index()].blocked = None;
                    self.actors[actor.index()].last_result = ActorResult::Woken;
                }
                for actor in requeued {
                    if matches!(
                        self.actors[actor.index()].blocked,
                        Some(BlockedWait::Futex { .. })
                    ) {
                        self.actors[actor.index()].blocked = Some(BlockedWait::Futex {
                            key: target,
                            deadline: match self.actors[actor.index()].blocked {
                                Some(BlockedWait::Futex { deadline, .. }) => deadline,
                                _ => None,
                            },
                        });
                    }
                }
                let after = self.hooks.hit(
                    actor_id,
                    HookId::FutexRequeueAfterMove,
                    &mut self.observation,
                );
                self.actors[actor_id.index()].pause_turns = after.pause_turns;
                StepDisposition::Progress
            }
            Continuation::FaultLeader { key, phase } => match phase {
                FaultPhase::Prepare => {
                    let directive = self.hooks.hit(
                        actor_id,
                        HookId::FaultHeavyPrepareBeforeCommit,
                        &mut self.observation,
                    );
                    self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                    self.actors[actor_id.index()].continuation = Some(Continuation::FaultLeader {
                        key,
                        phase: FaultPhase::Commit,
                    });
                    StepDisposition::Progress
                }
                FaultPhase::Commit => {
                    let directive = self.hooks.hit(
                        actor_id,
                        HookId::FaultTxBeforeCommit,
                        &mut self.observation,
                    );
                    self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                    if let Some(entry) = self.faults.remove(&key) {
                        for waiter in entry.blocked_waiters {
                            self.actors[waiter.index()].blocked = None;
                            self.actors[waiter.index()].last_result = ActorResult::FaultResolved;
                        }
                    }
                    self.actors[actor_id.index()].last_result = ActorResult::FaultResolved;
                    StepDisposition::Progress
                }
            },
            Continuation::PublishSignals { .. } | Continuation::FireTimers { .. } => {
                self.observation.failure_kind = Some("invalid.runner.continuation".into());
                StepDisposition::Progress
            }
        }
    }

    fn service_deadlines(&mut self) {
        for actor_id in [ActorId::A, ActorId::B] {
            let blocked = self.actors[actor_id.index()].blocked;
            if let Some(BlockedWait::Futex { key, deadline }) = blocked
                && deadline.is_some_and(|deadline| self.now >= deadline)
            {
                let _ = self.futex.cancel_waiter(key, actor_id);
                self.actors[actor_id.index()].blocked = None;
                self.actors[actor_id.index()].last_result = ActorResult::TimedOut;
                self.observation
                    .edge_hits
                    .insert(format!("timeout:futex:actor:{actor_id:?}"));
            }
        }
    }

    fn snapshot_state(&mut self) {
        let blocked_futex = self
            .actors
            .iter()
            .filter(|actor| matches!(actor.blocked, Some(BlockedWait::Futex { .. })))
            .count();
        let blocked_fault = self
            .actors
            .iter()
            .filter(|actor| matches!(actor.blocked, Some(BlockedWait::Fault { .. })))
            .count();
        let fault_waiters = self
            .faults
            .values()
            .map(|entry| entry.blocked_waiters.len())
            .sum::<usize>();
        let fault_leaders = self
            .faults
            .values()
            .filter(|entry| entry.leader.is_some())
            .count();
        let futex_hist = self.futex.occupancy();
        let owners = self
            .futex
            .queues
            .keys()
            .filter(|key| self.futex.owner(**key) != ZX_KOID_INVALID)
            .count();
        if blocked_futex != 0 || futex_hist.iter().any(|count| *count != 0) {
            self.observation
                .state_projections
                .insert(ConcurrencyStateProjection::FutexFaultWaitQueues);
        }
        if blocked_fault != 0 || fault_waiters != 0 || fault_leaders != 0 || !self.faults.is_empty()
        {
            self.observation
                .state_projections
                .insert(ConcurrencyStateProjection::FutexFaultInflightShape);
        }
        if owners != 0 {
            self.observation
                .state_projections
                .insert(ConcurrencyStateProjection::FutexFaultOwnership);
        }
        let state = (
            blocked_futex,
            blocked_fault,
            fault_waiters,
            fault_leaders,
            owners,
            futex_hist,
            self.faults.len(),
            self.now,
        );
        self.observation.state_signatures.insert(hash_value(&state));
    }
}

fn shared_key(id: u8) -> FutexKey {
    FutexKey::Shared {
        global_vmo_id: GlobalVmoId::new(u64::from(id) + 1),
        offset: 0,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChannelBlockedWait {
    Readable { slot: u8, deadline: Option<u64> },
    PeerClosed { slot: u8, deadline: Option<u64> },
}

#[derive(Clone, Debug, Default)]
struct ChannelActorState {
    pc: usize,
    blocked: Option<ChannelBlockedWait>,
    pause_turns: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChannelHandleState {
    endpoint: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct EndpointState {
    incoming_messages: usize,
    peer_closed: bool,
    live_handles: usize,
}

struct ChannelHandleRunner<'a> {
    seed: &'a ConcurrentSeed,
    actors: [ChannelActorState; 2],
    current_actor: ActorId,
    hooks: HookRuntime,
    observation: RunObservation,
    now: u64,
    handles: [Option<ChannelHandleState>; 4],
    endpoints: [EndpointState; 2],
}

impl<'a> ChannelHandleRunner<'a> {
    fn new(seed: &'a ConcurrentSeed) -> Self {
        let mut endpoints = [EndpointState::default(), EndpointState::default()];
        endpoints[0].live_handles = 1;
        endpoints[1].live_handles = 1;
        Self {
            seed,
            actors: [ChannelActorState::default(), ChannelActorState::default()],
            current_actor: ActorId::A,
            hooks: HookRuntime::new(&seed.hints),
            observation: RunObservation::default(),
            now: 0,
            handles: [
                Some(ChannelHandleState { endpoint: 0 }),
                Some(ChannelHandleState { endpoint: 1 }),
                None,
                None,
            ],
            endpoints,
        }
    }

    fn run(mut self) -> RunObservation {
        self.snapshot_state();
        let budget = usize::from(self.seed.replay.max_steps.max(1));
        for _ in 0..budget {
            if self.is_done() {
                return self.finish();
            }
            self.service_deadlines();
            let actor = self.current_actor;
            let progress = self.step_actor(actor);
            if progress == StepDisposition::NoProgress {
                let other = actor.other();
                if self.step_actor(other) == StepDisposition::NoProgress {
                    self.service_deadlines();
                    if self.actors.iter().all(|state| state.blocked.is_some()) {
                        self.observation.failure_kind = Some("hang.channel_handle".into());
                        self.observation.events.push("hang:channel_handle".into());
                        return self.finish();
                    }
                } else {
                    self.current_actor = other;
                }
            }
            if self.hooks.should_prefer_other() {
                self.current_actor = self.current_actor.other();
            }
            self.now = self.now.saturating_add(1);
            self.snapshot_state();
        }
        self.observation.failure_kind = Some("budget_exhausted.channel_handle".into());
        self.finish()
    }

    fn is_done(&self) -> bool {
        let a_done =
            self.actors[0].pc >= self.seed.program_a.len() && self.actors[0].blocked.is_none();
        let b_done =
            self.actors[1].pc >= self.seed.program_b.len() && self.actors[1].blocked.is_none();
        a_done && b_done
    }

    fn finish(mut self) -> RunObservation {
        if self.observation.failure_kind.is_none() {
            self.observation.events.push(format!(
                "done:channel_handle now={} live={} queues={}/{}",
                self.now,
                self.handles.iter().flatten().count(),
                self.endpoints[0].incoming_messages,
                self.endpoints[1].incoming_messages
            ));
        }
        self.observation
    }

    fn program_for(&self, actor: ActorId) -> &[ProgramOp] {
        match actor {
            ActorId::A => &self.seed.program_a,
            ActorId::B => &self.seed.program_b,
        }
    }

    fn step_actor(&mut self, actor_id: ActorId) -> StepDisposition {
        let actor_index = actor_id.index();
        if self.actors[actor_index].pause_turns > 0 {
            self.actors[actor_index].pause_turns -= 1;
            return StepDisposition::Progress;
        }
        if self.actors[actor_index].blocked.is_some() {
            return StepDisposition::NoProgress;
        }
        let pc = self.actors[actor_index].pc;
        let Some(op) = self.program_for(actor_id).get(pc).copied() else {
            return StepDisposition::NoProgress;
        };
        self.actors[actor_index].pc += 1;
        let ProgramOp::ChannelHandle(op) = op else {
            self.observation.failure_kind = Some("invalid.seed.channel_handle".into());
            return StepDisposition::Progress;
        };
        self.execute_channel_op(actor_id, op)
    }

    fn execute_channel_op(&mut self, actor_id: ActorId, op: ChannelHandleOp) -> StepDisposition {
        match op {
            ChannelHandleOp::ChannelWrite { handle, bytes } => {
                let Some(state) = self.handle_state(handle) else {
                    self.observation
                        .edge_hits
                        .insert(format!("channel.invalid_write:slot:{handle}"));
                    return StepDisposition::Progress;
                };
                let peer = state.endpoint ^ 1;
                if self.endpoints[peer].live_handles == 0 {
                    self.observation
                        .edge_hits
                        .insert(format!("channel.write_peer_closed:slot:{handle}"));
                    return StepDisposition::Progress;
                }
                let was_empty = self.endpoints[peer].incoming_messages == 0;
                self.endpoints[peer].incoming_messages += 1;
                self.observation
                    .edge_hits
                    .insert(format!("channel.write:actor:{actor_id:?}:bytes:{bytes}"));
                if was_empty {
                    self.observation
                        .edge_hits
                        .insert(format!("channel.empty_to_nonempty:endpoint:{peer}"));
                }
                self.wake_channel_waiters(peer);
                StepDisposition::Progress
            }
            ChannelHandleOp::ChannelRead { handle } => {
                let Some(state) = self.handle_state(handle) else {
                    self.observation
                        .edge_hits
                        .insert(format!("channel.invalid_read:slot:{handle}"));
                    return StepDisposition::Progress;
                };
                let endpoint = state.endpoint;
                if self.endpoints[endpoint].incoming_messages == 0 {
                    self.observation
                        .edge_hits
                        .insert(format!("channel.read_empty:slot:{handle}"));
                } else {
                    self.endpoints[endpoint].incoming_messages -= 1;
                    self.observation
                        .edge_hits
                        .insert(format!("channel.read:actor:{actor_id:?}:slot:{handle}"));
                }
                StepDisposition::Progress
            }
            ChannelHandleOp::ChannelClose { handle } => {
                if let Some(state) = self.handle_state(handle) {
                    let peer = state.endpoint ^ 1;
                    if self.endpoints[peer].incoming_messages != 0 {
                        let directive = self.hooks.hit(
                            actor_id,
                            HookId::ChannelCloseBeforeReadDrain,
                            &mut self.observation,
                        );
                        self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                    }
                }
                self.close_handle_slot(handle);
                StepDisposition::Progress
            }
            ChannelHandleOp::WaitReadable {
                handle,
                deadline_ticks,
            } => {
                let Some(state) = self.handle_state(handle) else {
                    self.observation
                        .edge_hits
                        .insert(format!("wait.readable.invalid:slot:{handle}"));
                    return StepDisposition::Progress;
                };
                let endpoint = state.endpoint;
                if self.endpoints[endpoint].incoming_messages != 0 {
                    self.observation
                        .edge_hits
                        .insert(format!("wait.readable.hit:slot:{handle}"));
                    return StepDisposition::Progress;
                }
                self.actors[actor_id.index()].blocked = Some(ChannelBlockedWait::Readable {
                    slot: handle,
                    deadline: deadline_ticks.map(|ticks| self.now + u64::from(ticks)),
                });
                let directive =
                    self.hooks
                        .hit(actor_id, HookId::WaiterLinked, &mut self.observation);
                self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                StepDisposition::Progress
            }
            ChannelHandleOp::WaitPeerClosed {
                handle,
                deadline_ticks,
            } => {
                let Some(state) = self.handle_state(handle) else {
                    self.observation
                        .edge_hits
                        .insert(format!("wait.peer_closed.invalid:slot:{handle}"));
                    return StepDisposition::Progress;
                };
                let endpoint = state.endpoint;
                if self.endpoints[endpoint].peer_closed {
                    self.observation
                        .edge_hits
                        .insert(format!("wait.peer_closed.hit:slot:{handle}"));
                    return StepDisposition::Progress;
                }
                self.actors[actor_id.index()].blocked = Some(ChannelBlockedWait::PeerClosed {
                    slot: handle,
                    deadline: deadline_ticks.map(|ticks| self.now + u64::from(ticks)),
                });
                let directive =
                    self.hooks
                        .hit(actor_id, HookId::WaiterLinked, &mut self.observation);
                self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                StepDisposition::Progress
            }
            ChannelHandleOp::HandleDuplicate { handle, dst } => {
                let Some(state) = self.handle_state(handle) else {
                    self.observation
                        .edge_hits
                        .insert(format!("handle.duplicate.invalid:src:{handle}"));
                    return StepDisposition::Progress;
                };
                self.close_handle_slot(dst);
                self.endpoints[state.endpoint].live_handles += 1;
                self.handles[usize::from(dst)] = Some(state);
                self.observation
                    .edge_hits
                    .insert(format!("handle.duplicate:{handle}->{dst}"));
                StepDisposition::Progress
            }
            ChannelHandleOp::HandleReplace { handle, dst } => {
                let Some(state) = self.handle_state(handle) else {
                    self.observation
                        .edge_hits
                        .insert(format!("handle.replace.invalid:src:{handle}"));
                    return StepDisposition::Progress;
                };
                let directive = self.hooks.hit(
                    actor_id,
                    HookId::HandleReplaceBeforePublish,
                    &mut self.observation,
                );
                self.actors[actor_id.index()].pause_turns = directive.pause_turns;
                if handle != dst {
                    self.close_handle_slot(dst);
                }
                self.handles[usize::from(handle)] = None;
                self.handles[usize::from(dst)] = Some(state);
                self.observation
                    .edge_hits
                    .insert(format!("handle.replace:{handle}->{dst}"));
                if handle == dst {
                    self.observation
                        .edge_hits
                        .insert("handle.replace.same_slot".into());
                }
                StepDisposition::Progress
            }
        }
    }

    fn service_deadlines(&mut self) {
        for actor_id in [ActorId::A, ActorId::B] {
            let blocked = self.actors[actor_id.index()].blocked;
            match blocked {
                Some(ChannelBlockedWait::Readable { deadline, .. })
                | Some(ChannelBlockedWait::PeerClosed { deadline, .. })
                    if deadline.is_some_and(|deadline| self.now >= deadline) =>
                {
                    self.actors[actor_id.index()].blocked = None;
                    self.observation
                        .edge_hits
                        .insert(format!("timeout:channel:actor:{actor_id:?}"));
                }
                _ => {}
            }
        }
    }

    fn wake_channel_waiters(&mut self, endpoint: usize) {
        for actor_id in [ActorId::A, ActorId::B] {
            let blocked = self.actors[actor_id.index()].blocked;
            match blocked {
                Some(ChannelBlockedWait::Readable { slot, .. })
                    if self.handle_state(slot).is_some_and(|state| {
                        state.endpoint == endpoint
                            && self.endpoints[endpoint].incoming_messages != 0
                    }) =>
                {
                    self.actors[actor_id.index()].blocked = None;
                    self.observation
                        .edge_hits
                        .insert(format!("wake.channel.readable:actor:{actor_id:?}"));
                }
                Some(ChannelBlockedWait::PeerClosed { slot, .. })
                    if self.handle_state(slot).is_some_and(|state| {
                        state.endpoint == endpoint && self.endpoints[endpoint].peer_closed
                    }) =>
                {
                    self.actors[actor_id.index()].blocked = None;
                    self.observation
                        .edge_hits
                        .insert(format!("wake.channel.peer_closed:actor:{actor_id:?}"));
                }
                _ => {}
            }
        }
    }

    fn close_handle_slot(&mut self, handle: u8) {
        let Some(state) = self.handles[usize::from(handle)].take() else {
            return;
        };
        let endpoint = state.endpoint;
        if self.endpoints[endpoint].live_handles != 0 {
            self.endpoints[endpoint].live_handles -= 1;
        }
        if self.endpoints[endpoint].live_handles == 0 {
            let peer = endpoint ^ 1;
            self.endpoints[peer].peer_closed = true;
            self.wake_channel_waiters(peer);
        }
        self.observation
            .edge_hits
            .insert(format!("handle.close:slot:{handle}:endpoint:{endpoint}"));
    }

    fn handle_state(&self, handle: u8) -> Option<ChannelHandleState> {
        self.handles.get(usize::from(handle)).copied().flatten()
    }

    fn snapshot_state(&mut self) {
        let blocked_readable = self
            .actors
            .iter()
            .filter(|actor| matches!(actor.blocked, Some(ChannelBlockedWait::Readable { .. })))
            .count();
        let blocked_peer_closed = self
            .actors
            .iter()
            .filter(|actor| matches!(actor.blocked, Some(ChannelBlockedWait::PeerClosed { .. })))
            .count();
        let live_slots = self.handles.iter().flatten().count();
        let endpoint_summary = (
            self.endpoints[0].incoming_messages,
            self.endpoints[0].peer_closed,
            self.endpoints[0].live_handles,
            self.endpoints[1].incoming_messages,
            self.endpoints[1].peer_closed,
            self.endpoints[1].live_handles,
        );
        let handle_summary = self
            .handles
            .iter()
            .map(|slot| slot.map(|state| state.endpoint).unwrap_or(usize::MAX))
            .collect::<Vec<_>>();
        if blocked_readable != 0 || blocked_peer_closed != 0 {
            self.observation
                .state_projections
                .insert(ConcurrencyStateProjection::ChannelHandleWaiters);
        }
        if self
            .endpoints
            .iter()
            .any(|endpoint| endpoint.incoming_messages != 0 || endpoint.peer_closed)
        {
            self.observation
                .state_projections
                .insert(ConcurrencyStateProjection::ChannelHandleEndpoints);
        }
        if live_slots != 2
            || self
                .handles
                .iter()
                .enumerate()
                .any(|(idx, slot)| !matches!(slot, Some(state) if state.endpoint == idx))
        {
            self.observation
                .state_projections
                .insert(ConcurrencyStateProjection::ChannelHandleHandleTable);
        }
        let state = (
            blocked_readable,
            blocked_peer_closed,
            live_slots,
            endpoint_summary,
            handle_summary,
            self.now,
        );
        self.observation.state_signatures.insert(hash_value(&state));
    }
}

fn hash_value(value: &impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::ConcurrentSeed;

    #[test]
    fn wait_port_timer_seed_produces_edges_and_states() {
        let seed = ConcurrentSeed::base_corpus(32).remove(0);
        let observation = run_seed(&seed);
        assert!(!observation.edge_hits.is_empty());
        assert!(!observation.hook_classes.is_empty());
        assert!(!observation.state_signatures.is_empty());
        assert!(!observation.state_projections.is_empty());
    }

    #[test]
    fn futex_fault_seed_produces_edges_and_states() {
        let seed = ConcurrentSeed::base_corpus(32).remove(3);
        let observation = run_seed(&seed);
        assert!(!observation.edge_hits.is_empty());
        assert!(!observation.hook_classes.is_empty());
        assert!(!observation.state_signatures.is_empty());
        assert!(!observation.state_projections.is_empty());
    }

    #[test]
    fn channel_handle_seed_produces_edges_and_states() {
        let seed = ConcurrentSeed::base_corpus(32).remove(4);
        let observation = run_seed(&seed);
        assert!(!observation.edge_hits.is_empty());
        assert!(!observation.hook_classes.is_empty());
        assert!(!observation.state_signatures.is_empty());
        assert!(!observation.state_projections.is_empty());
    }

    #[test]
    fn wait_port_timer_reserve_seed_hits_port_reserve_hook() {
        let seed = ConcurrentSeed::base_corpus(32).remove(6);
        let observation = run_seed(&seed);
        assert!(
            observation
                .hook_classes
                .contains(&ConcurrencyHookClass::PortReserveExhausted),
            "{observation:#?}"
        );
    }
}
