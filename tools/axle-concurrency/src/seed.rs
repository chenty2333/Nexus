use serde::{Deserialize, Serialize};

/// Which subsystem family a seed targets.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SystemKind {
    /// Wait/port/timer interactions.
    WaitPortTimer,
    /// Futex/fault contention interactions.
    FutexFault,
    /// Channel/handle lifecycle and signal interactions.
    ChannelHandle,
}

/// Stable semantic hook ids used by schedule hints and replay.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HookId {
    /// A blocking waiter was linked into a wait list.
    WaiterLinked,
    /// Signals changed after publication but before wake fanout.
    SignalUpdatedBeforeWake,
    /// Port kernel reserve was exhausted.
    PortReserveExhausted,
    /// Timer fire is about to publish signals/wakes.
    TimerBeforeFire,
    /// Futex requeue has validated and is about to move waiters.
    FutexRequeueBeforeMove,
    /// Futex requeue moved waiters and is about to finish.
    FutexRequeueAfterMove,
    /// Fault leader claimed an in-flight slot.
    FaultLeaderClaimed,
    /// Fault leader finished heavy prepare and is about to commit.
    FaultHeavyPrepareBeforeCommit,
    /// Fault leader is about to publish commit and wake waiters.
    FaultTxBeforeCommit,
    /// Channel close won the race before the peer drained readable data.
    ChannelCloseBeforeReadDrain,
    /// Handle replacement is about to publish the new handle slot.
    HandleReplaceBeforePublish,
}

/// Logical schedule hint attached to a semantic hook.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SchedHint {
    /// Switch away from the current actor once when the hook fires.
    YieldHere(HookId),
    /// Pause the current actor for `turns` scheduler turns when the hook fires.
    PauseThread(HookId, u8),
    /// Delay timer publication for `ticks` scheduler turns when the hook fires.
    DelayTimerFire(HookId, u8),
    /// Prefer the opposite actor immediately after this hook.
    ForceRemoteWake(HookId),
}

/// Replay metadata that must be saved with every seed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayMeta {
    /// Seed schema version.
    pub version: u32,
    /// Logical CPU count used by the runner.
    pub cpu_count: u8,
    /// Test flags for future extension.
    pub flags: u32,
    /// PRNG seed used for mutation/replay.
    pub rng_seed: u64,
    /// Step budget before declaring a hang.
    pub max_steps: u16,
}

impl ReplayMeta {
    /// Default replay metadata for the current host runner.
    pub fn new(rng_seed: u64, max_steps: u16) -> Self {
        Self {
            version: 1,
            cpu_count: 2,
            flags: 0,
            rng_seed,
            max_steps,
        }
    }
}

/// One wait/port/timer operation in a concurrent seed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WaitOp {
    /// Set one signal bit on a waitable.
    SetSignal { waitable: u8, bits: u8 },
    /// Clear one signal bit on a waitable.
    ClearSignal { waitable: u8, bits: u8 },
    /// Block on signals until satisfied or deadline ticks elapse.
    WaitOne {
        waitable: u8,
        bits: u8,
        deadline_ticks: Option<u8>,
    },
    /// Register a one-shot async wait into the shared port.
    WaitAsync {
        waitable: u8,
        key: u16,
        bits: u8,
        edge: bool,
    },
    /// Block on one port packet.
    PortWait { deadline_ticks: Option<u8> },
    /// Arm one timer slot at `deadline_ticks` in the future.
    TimerSet { slot: u8, deadline_ticks: u8 },
    /// Cancel one timer slot.
    TimerCancel { slot: u8 },
    /// Advance logical time.
    AdvanceTime { ticks: u8 },
}

/// One futex/fault operation in a concurrent seed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FutexFaultOp {
    /// Store a futex word before waiting.
    FutexStore { key: u8, value: u32 },
    /// Wait on one futex key.
    FutexWait {
        key: u8,
        expected: u32,
        deadline_ticks: Option<u8>,
    },
    /// Wake some futex waiters.
    FutexWake { key: u8, count: u8 },
    /// Requeue futex waiters.
    FutexRequeue {
        source: u8,
        target: u8,
        wake_count: u8,
        requeue_count: u8,
    },
    /// Trigger one same-page fault.
    Fault { key: u8 },
    /// Advance logical time for deadlines.
    AdvanceTime { ticks: u8 },
}

/// One channel/handle operation in a concurrent seed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChannelHandleOp {
    /// Write a tiny payload through one channel handle slot.
    ChannelWrite { handle: u8, bytes: u8 },
    /// Read one message from one channel handle slot.
    ChannelRead { handle: u8 },
    /// Close one handle slot.
    ChannelClose { handle: u8 },
    /// Wait until one handle slot becomes readable.
    WaitReadable {
        handle: u8,
        deadline_ticks: Option<u8>,
    },
    /// Wait until one handle slot observes peer closed.
    WaitPeerClosed {
        handle: u8,
        deadline_ticks: Option<u8>,
    },
    /// Duplicate one handle slot into another slot.
    HandleDuplicate { handle: u8, dst: u8 },
    /// Replace one handle slot into another slot.
    HandleReplace { handle: u8, dst: u8 },
}

/// One actor operation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProgramOp {
    /// Wait/port/timer operation.
    Wait(WaitOp),
    /// Futex/fault operation.
    FutexFault(FutexFaultOp),
    /// Channel/handle operation.
    ChannelHandle(ChannelHandleOp),
}

/// Concurrent two-actor seed with schedule hints and replay metadata.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConcurrentSeed {
    /// Replay metadata.
    pub replay: ReplayMeta,
    /// Target subsystem family.
    pub system: SystemKind,
    /// Actor A program.
    pub program_a: Vec<ProgramOp>,
    /// Actor B program.
    pub program_b: Vec<ProgramOp>,
    /// Schedule hints used during replay.
    pub hints: Vec<SchedHint>,
}

impl ConcurrentSeed {
    /// Built-in corpus used by the smoke runner.
    pub fn base_corpus(max_steps: u16) -> Vec<Self> {
        vec![
            Self {
                replay: ReplayMeta::new(0x1001, max_steps),
                system: SystemKind::WaitPortTimer,
                program_a: vec![
                    ProgramOp::Wait(WaitOp::WaitAsync {
                        waitable: 1,
                        key: 0x10,
                        bits: 1,
                        edge: false,
                    }),
                    ProgramOp::Wait(WaitOp::PortWait {
                        deadline_ticks: Some(5),
                    }),
                ],
                program_b: vec![
                    ProgramOp::Wait(WaitOp::SetSignal {
                        waitable: 1,
                        bits: 1,
                    }),
                    ProgramOp::Wait(WaitOp::AdvanceTime { ticks: 1 }),
                ],
                hints: vec![SchedHint::YieldHere(HookId::SignalUpdatedBeforeWake)],
            },
            Self {
                replay: ReplayMeta::new(0x1002, max_steps),
                system: SystemKind::WaitPortTimer,
                program_a: vec![
                    ProgramOp::Wait(WaitOp::TimerSet {
                        slot: 0,
                        deadline_ticks: 2,
                    }),
                    ProgramOp::Wait(WaitOp::WaitOne {
                        waitable: 16,
                        bits: 8,
                        deadline_ticks: Some(5),
                    }),
                ],
                program_b: vec![
                    ProgramOp::Wait(WaitOp::AdvanceTime { ticks: 1 }),
                    ProgramOp::Wait(WaitOp::AdvanceTime { ticks: 1 }),
                ],
                hints: vec![SchedHint::DelayTimerFire(HookId::TimerBeforeFire, 1)],
            },
            Self {
                replay: ReplayMeta::new(0x2001, max_steps),
                system: SystemKind::FutexFault,
                program_a: vec![
                    ProgramOp::FutexFault(FutexFaultOp::FutexStore { key: 0, value: 7 }),
                    ProgramOp::FutexFault(FutexFaultOp::FutexWait {
                        key: 0,
                        expected: 7,
                        deadline_ticks: Some(4),
                    }),
                ],
                program_b: vec![
                    ProgramOp::FutexFault(FutexFaultOp::AdvanceTime { ticks: 1 }),
                    ProgramOp::FutexFault(FutexFaultOp::FutexWake { key: 0, count: 1 }),
                ],
                hints: vec![SchedHint::PauseThread(HookId::WaiterLinked, 1)],
            },
            Self {
                replay: ReplayMeta::new(0x2002, max_steps),
                system: SystemKind::FutexFault,
                program_a: vec![ProgramOp::FutexFault(FutexFaultOp::Fault { key: 1 })],
                program_b: vec![ProgramOp::FutexFault(FutexFaultOp::Fault { key: 1 })],
                hints: vec![
                    SchedHint::PauseThread(HookId::FaultLeaderClaimed, 1),
                    SchedHint::YieldHere(HookId::FaultHeavyPrepareBeforeCommit),
                ],
            },
            Self {
                replay: ReplayMeta::new(0x3001, max_steps),
                system: SystemKind::ChannelHandle,
                program_a: vec![
                    ProgramOp::ChannelHandle(ChannelHandleOp::ChannelWrite {
                        handle: 0,
                        bytes: 8,
                    }),
                    ProgramOp::ChannelHandle(ChannelHandleOp::ChannelClose { handle: 0 }),
                ],
                program_b: vec![
                    ProgramOp::ChannelHandle(ChannelHandleOp::WaitReadable {
                        handle: 1,
                        deadline_ticks: Some(4),
                    }),
                    ProgramOp::ChannelHandle(ChannelHandleOp::ChannelRead { handle: 1 }),
                    ProgramOp::ChannelHandle(ChannelHandleOp::WaitPeerClosed {
                        handle: 1,
                        deadline_ticks: Some(4),
                    }),
                ],
                hints: vec![SchedHint::YieldHere(HookId::ChannelCloseBeforeReadDrain)],
            },
            Self {
                replay: ReplayMeta::new(0x3002, max_steps),
                system: SystemKind::ChannelHandle,
                program_a: vec![
                    ProgramOp::ChannelHandle(ChannelHandleOp::HandleDuplicate {
                        handle: 0,
                        dst: 2,
                    }),
                    ProgramOp::ChannelHandle(ChannelHandleOp::HandleReplace { handle: 2, dst: 3 }),
                ],
                program_b: vec![
                    ProgramOp::ChannelHandle(ChannelHandleOp::WaitPeerClosed {
                        handle: 1,
                        deadline_ticks: Some(2),
                    }),
                    ProgramOp::ChannelHandle(ChannelHandleOp::ChannelClose { handle: 0 }),
                ],
                hints: vec![SchedHint::PauseThread(
                    HookId::HandleReplaceBeforePublish,
                    1,
                )],
            },
        ]
    }

    /// Return a mutated variant of this seed.
    pub fn mutated(&self, rng_seed: u64) -> Self {
        let mut out = self.clone();
        let mut rng = SeedRng::new(rng_seed);
        out.replay.rng_seed = rng_seed;
        if rng.next_bool() && !out.hints.is_empty() {
            let idx = rng.index(out.hints.len());
            out.hints[idx] = random_hint(&mut rng);
        } else if rng.next_bool() || out.hints.is_empty() {
            out.hints.push(random_hint(&mut rng));
        }

        mutate_program(&mut out.program_a, out.system, &mut rng);
        mutate_program(&mut out.program_b, out.system, &mut rng);
        out
    }
}

fn mutate_program(program: &mut Vec<ProgramOp>, system: SystemKind, rng: &mut SeedRng) {
    if program.is_empty() || rng.next_bool() {
        let idx = rng.insert_index(program.len());
        program.insert(idx, random_op(system, rng));
        return;
    }

    match rng.next_u8() % 3 {
        0 => {
            let idx = rng.index(program.len());
            program[idx] = random_op(system, rng);
        }
        1 if program.len() < 8 => {
            let idx = rng.insert_index(program.len());
            program.insert(idx, random_op(system, rng));
        }
        _ if program.len() > 1 => {
            let idx = rng.index(program.len());
            let _ = program.remove(idx);
        }
        _ => {
            let idx = rng.index(program.len());
            program[idx] = random_op(system, rng);
        }
    }
}

fn random_op(system: SystemKind, rng: &mut SeedRng) -> ProgramOp {
    match system {
        SystemKind::WaitPortTimer => ProgramOp::Wait(match rng.next_u8() % 8 {
            0 => WaitOp::SetSignal {
                waitable: rng.next_u8() % 4,
                bits: 1 << (rng.next_u8() % 4),
            },
            1 => WaitOp::ClearSignal {
                waitable: rng.next_u8() % 4,
                bits: 1 << (rng.next_u8() % 4),
            },
            2 => WaitOp::WaitOne {
                waitable: rng.next_u8() % 4,
                bits: 1 << (rng.next_u8() % 4),
                deadline_ticks: maybe_deadline(rng),
            },
            3 => WaitOp::WaitAsync {
                waitable: rng.next_u8() % 4,
                key: u16::from(rng.next_u8()) | (u16::from(rng.next_u8()) << 8),
                bits: 1 << (rng.next_u8() % 4),
                edge: rng.next_bool(),
            },
            4 => WaitOp::PortWait {
                deadline_ticks: maybe_deadline(rng),
            },
            5 => WaitOp::TimerSet {
                slot: rng.next_u8() % 2,
                deadline_ticks: 1 + (rng.next_u8() % 4),
            },
            6 => WaitOp::TimerCancel {
                slot: rng.next_u8() % 2,
            },
            _ => WaitOp::AdvanceTime {
                ticks: 1 + (rng.next_u8() % 3),
            },
        }),
        SystemKind::FutexFault => ProgramOp::FutexFault(match rng.next_u8() % 6 {
            0 => FutexFaultOp::FutexStore {
                key: rng.next_u8() % 3,
                value: u32::from(rng.next_u8() % 4),
            },
            1 => FutexFaultOp::FutexWait {
                key: rng.next_u8() % 3,
                expected: u32::from(rng.next_u8() % 4),
                deadline_ticks: maybe_deadline(rng),
            },
            2 => FutexFaultOp::FutexWake {
                key: rng.next_u8() % 3,
                count: 1 + (rng.next_u8() % 2),
            },
            3 => FutexFaultOp::FutexRequeue {
                source: rng.next_u8() % 3,
                target: rng.next_u8() % 3,
                wake_count: rng.next_u8() % 2,
                requeue_count: 1 + (rng.next_u8() % 2),
            },
            4 => FutexFaultOp::Fault {
                key: rng.next_u8() % 3,
            },
            _ => FutexFaultOp::AdvanceTime {
                ticks: 1 + (rng.next_u8() % 3),
            },
        }),
        SystemKind::ChannelHandle => ProgramOp::ChannelHandle(match rng.next_u8() % 7 {
            0 => ChannelHandleOp::ChannelWrite {
                handle: rng.next_u8() % 4,
                bytes: 1 + (rng.next_u8() % 16),
            },
            1 => ChannelHandleOp::ChannelRead {
                handle: rng.next_u8() % 4,
            },
            2 => ChannelHandleOp::ChannelClose {
                handle: rng.next_u8() % 4,
            },
            3 => ChannelHandleOp::WaitReadable {
                handle: rng.next_u8() % 4,
                deadline_ticks: maybe_deadline(rng),
            },
            4 => ChannelHandleOp::WaitPeerClosed {
                handle: rng.next_u8() % 4,
                deadline_ticks: maybe_deadline(rng),
            },
            5 => ChannelHandleOp::HandleDuplicate {
                handle: rng.next_u8() % 4,
                dst: rng.next_u8() % 4,
            },
            _ => ChannelHandleOp::HandleReplace {
                handle: rng.next_u8() % 4,
                dst: rng.next_u8() % 4,
            },
        }),
    }
}

fn random_hint(rng: &mut SeedRng) -> SchedHint {
    let hook = match rng.next_u8() % 11 {
        0 => HookId::WaiterLinked,
        1 => HookId::SignalUpdatedBeforeWake,
        2 => HookId::PortReserveExhausted,
        3 => HookId::TimerBeforeFire,
        4 => HookId::FutexRequeueBeforeMove,
        5 => HookId::FutexRequeueAfterMove,
        6 => HookId::FaultLeaderClaimed,
        7 => HookId::FaultHeavyPrepareBeforeCommit,
        8 => HookId::FaultTxBeforeCommit,
        9 => HookId::ChannelCloseBeforeReadDrain,
        _ => HookId::HandleReplaceBeforePublish,
    };
    match rng.next_u8() % 4 {
        0 => SchedHint::YieldHere(hook),
        1 => SchedHint::PauseThread(hook, 1 + (rng.next_u8() % 2)),
        2 => SchedHint::DelayTimerFire(hook, 1 + (rng.next_u8() % 2)),
        _ => SchedHint::ForceRemoteWake(hook),
    }
}

fn maybe_deadline(rng: &mut SeedRng) -> Option<u8> {
    rng.next_bool().then_some(1 + (rng.next_u8() % 4))
}

#[derive(Clone, Copy, Debug)]
struct SeedRng {
    state: u64,
}

impl SeedRng {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 7;
        x ^= x >> 9;
        x ^= x << 8;
        self.state = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) != 0
    }

    fn index(&mut self, len: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(len).unwrap()).unwrap()
    }

    fn insert_index(&mut self, len: usize) -> usize {
        usize::try_from(self.next_u64() % (u64::try_from(len).unwrap() + 1)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_preserves_seed_shape() {
        let seed = ConcurrentSeed::base_corpus(32).remove(0);
        let mutated = seed.mutated(0xdead_beef);
        assert_eq!(mutated.system, seed.system);
        assert!(!mutated.program_a.is_empty());
        assert!(!mutated.program_b.is_empty());
        assert_eq!(mutated.replay.max_steps, seed.replay.max_steps);
    }
}
