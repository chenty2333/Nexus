use std::collections::{BTreeMap, BTreeSet, VecDeque, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};

use axle_core::{
    FakeClock, PacketKind, Port, PortError, Signals, Time, TimerId, TimerService, WaitAsyncOptions,
    WaitAsyncTimestamp, WaitOne, wait_one,
};
use axle_mm::{FutexKey, GlobalVmoId};
use axle_types::koid::ZX_KOID_INVALID;

use crate::seed::{ConcurrentSeed, FutexFaultOp, HookId, ProgramOp, SchedHint, SystemKind, WaitOp};

const TIMER_WAITABLE_BASE: u64 = 0x10;

/// Observation summary for one concurrent seed replay.
#[derive(Clone, Debug, Default)]
pub struct RunObservation {
    /// Semantic edge/block coverage hits.
    pub edge_hits: BTreeSet<String>,
    /// Abstract state signatures reached during replay.
    pub state_signatures: BTreeSet<u64>,
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
    }
}

struct WaitPortTimerRunner<'a> {
    seed: &'a ConcurrentSeed,
    actors: [ActorState; 2],
    current_actor: ActorId,
    hooks: HookRuntime,
    observation: RunObservation,
    port: Port,
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
                match self.port.wait_async(
                    waitable_id,
                    u64::from(key),
                    watched,
                    WaitAsyncOptions {
                        edge_triggered: edge,
                        timestamp: WaitAsyncTimestamp::Monotonic,
                    },
                    current,
                    self.clock.now(),
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
        self.port
            .on_signals_changed(waitable, current, self.clock.now());
        if before_len == self.port.capacity() && self.port.len() == before_len {
            let _ = self.hooks.hit(
                ActorId::A,
                HookId::PortReserveExhausted,
                &mut self.observation,
            );
        }
        if before_len == 0 && !self.port.is_empty() {
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
        assert!(!observation.state_signatures.is_empty());
    }

    #[test]
    fn futex_fault_seed_produces_edges_and_states() {
        let seed = ConcurrentSeed::base_corpus(32).remove(3);
        let observation = run_seed(&seed);
        assert!(!observation.edge_hits.is_empty());
        assert!(!observation.state_signatures.is_empty());
    }
}
