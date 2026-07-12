//! Bounded concurrency refinements of runtime-filesystem linearization gates.
//!
//! These deliberately small `loom::sync` surrogates do not execute
//! `RuntimeFsModel` and do not model a filesystem, VirtIO queue, IOMMU, or
//! concrete OSTD lock implementation. They check only the ordering and
//! ownership relationships named by each test under Loom's bounded schedules.

use loom::{
    model,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    thread,
};

const PWRITE_WORD: u32 = 0x0000_7879;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopePhase {
    Active,
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PwritePhase {
    Prepared,
    Committed,
    Completed,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyscallPhase {
    Prepared,
    Aborted,
}

#[derive(Debug)]
struct PwriteState {
    scope: ScopePhase,
    filesystem: PwritePhase,
    syscall: SyscallPhase,
    inode_generation: u64,
    inode_version: u64,
    pwrite_publications: usize,
    reply_publications: usize,
    filesystem_terminalizations: usize,
    syscall_terminalizations: usize,
}

#[derive(Debug)]
struct PwriteGate {
    state: Mutex<PwriteState>,
    inode_word: AtomicU32,
}

impl PwriteGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(PwriteState {
                scope: ScopePhase::Active,
                filesystem: PwritePhase::Prepared,
                syscall: SyscallPhase::Prepared,
                inode_generation: 1,
                inode_version: 0,
                pwrite_publications: 0,
                reply_publications: 0,
                filesystem_terminalizations: 0,
                syscall_terminalizations: 0,
            }),
            inode_word: AtomicU32::new(0),
        }
    }

    fn commit_pwrite(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.scope != ScopePhase::Active || state.filesystem != PwritePhase::Prepared {
            return false;
        }

        // This critical section refines RuntimeFsModel's failure-atomic inode
        // word, version, generation, publication count, and effect commit.
        self.inode_word.store(PWRITE_WORD, Ordering::Release);
        state.inode_generation += 1;
        state.inode_version += 1;
        state.pwrite_publications += 1;
        state.filesystem = PwritePhase::Committed;
        true
    }

    fn revoke_begin(&self) {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.scope, ScopePhase::Active);
        state.scope = ScopePhase::Closing;
    }

    fn close_frozen_effects(&self) {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.scope, ScopePhase::Closing);
        state.filesystem = match state.filesystem {
            PwritePhase::Prepared => PwritePhase::Aborted,
            PwritePhase::Committed => PwritePhase::Completed,
            PwritePhase::Completed | PwritePhase::Aborted => {
                panic!("the bounded schedule terminalizes each effect once")
            }
        };
        state.filesystem_terminalizations += 1;
        assert_eq!(state.syscall, SyscallPhase::Prepared);
        state.syscall = SyscallPhase::Aborted;
        state.syscall_terminalizations += 1;
    }
}

#[test]
fn loom_pwrite_commit_and_revoke_share_one_scope_gate() {
    model(|| {
        let gate = Arc::new(PwriteGate::new());
        let commit_gate = gate.clone();
        let revoke_gate = gate.clone();
        let commit = thread::spawn(move || commit_gate.commit_pwrite());
        let revoke = thread::spawn(move || revoke_gate.revoke_begin());

        let committed = commit.join().unwrap();
        revoke.join().unwrap();
        gate.close_frozen_effects();

        assert!(!gate.commit_pwrite(), "a closed root fences late commit");
        let visible_word = gate.inode_word.load(Ordering::Acquire);
        let state = gate.state.lock().unwrap();
        assert_eq!(state.scope, ScopePhase::Closing);
        assert_eq!(state.syscall, SyscallPhase::Aborted);
        assert_eq!(state.reply_publications, 0);
        assert_eq!(state.filesystem_terminalizations, 1);
        assert_eq!(state.syscall_terminalizations, 1);
        if committed {
            assert_eq!(state.filesystem, PwritePhase::Completed);
            assert_eq!(visible_word, PWRITE_WORD);
            assert_eq!(state.inode_generation, 2);
            assert_eq!(state.inode_version, 1);
            assert_eq!(state.pwrite_publications, 1);
        } else {
            assert_eq!(state.filesystem, PwritePhase::Aborted);
            assert_eq!(visible_word, 0);
            assert_eq!(state.inode_generation, 1);
            assert_eq!(state.inode_version, 0);
            assert_eq!(state.pwrite_publications, 0);
        }
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeviceOutcome {
    Awaiting,
    CompletionAccepted,
    ResetIndeterminate,
}

#[derive(Debug)]
struct DeviceState {
    outcome: DeviceOutcome,
    device_generation: u64,
    outcome_publications: usize,
    iotlb_pending: bool,
    dma_credit_owned: bool,
}

#[derive(Debug)]
struct DeviceGate {
    state: Mutex<DeviceState>,
}

impl DeviceGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(DeviceState {
                outcome: DeviceOutcome::Awaiting,
                device_generation: 1,
                outcome_publications: 0,
                iotlb_pending: false,
                dma_credit_owned: true,
            }),
        }
    }

    fn observe_completion(&self, receipt_generation: u64) -> bool {
        let mut state = self.state.lock().unwrap();
        if receipt_generation != state.device_generation || state.outcome != DeviceOutcome::Awaiting
        {
            return false;
        }
        state.outcome = DeviceOutcome::CompletionAccepted;
        state.outcome_publications += 1;
        state.iotlb_pending = true;
        true
    }

    fn acknowledge_reset(&self, recovery_generation: u64) -> bool {
        let mut state = self.state.lock().unwrap();
        if recovery_generation != state.device_generation {
            return false;
        }
        if state.outcome == DeviceOutcome::Awaiting {
            state.outcome = DeviceOutcome::ResetIndeterminate;
            state.outcome_publications += 1;
        }
        state.device_generation += 1;
        state.iotlb_pending = true;
        true
    }
}

#[test]
fn loom_completion_and_reset_ack_choose_one_device_outcome_and_fence_generation() {
    model(|| {
        let gate = Arc::new(DeviceGate::new());
        let completion_gate = gate.clone();
        let reset_gate = gate.clone();
        let completion = thread::spawn(move || completion_gate.observe_completion(1));
        let reset = thread::spawn(move || reset_gate.acknowledge_reset(1));

        let completion_won = completion.join().unwrap();
        assert!(reset.join().unwrap());
        assert!(
            !gate.observe_completion(1),
            "the pre-reset block receipt must be stale"
        );
        assert!(
            !gate.acknowledge_reset(1),
            "the pre-reset recovery token must be stale"
        );

        let state = gate.state.lock().unwrap();
        assert_eq!(state.device_generation, 2);
        assert_eq!(state.outcome_publications, 1);
        assert!(state.iotlb_pending);
        assert!(
            state.dma_credit_owned,
            "reset acknowledgement alone cannot return DMA credit"
        );
        assert_eq!(
            state.outcome,
            if completion_won {
                DeviceOutcome::CompletionAccepted
            } else {
                DeviceOutcome::ResetIndeterminate
            }
        );
    });
}

const EFFECT_IDENTITY: u64 = 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IotlbReceipt {
    effect: u64,
    attempt: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TimeoutTombstone {
    effect: u64,
    attempt: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DmaPhase {
    IotlbInFlight,
    Tombstoned,
    Released,
}

#[derive(Debug)]
struct DmaState {
    effect: u64,
    attempt: u64,
    phase: DmaPhase,
    tombstone_attempt: Option<u64>,
    dma_credit_owned: bool,
}

#[derive(Debug)]
struct DmaGate {
    state: Mutex<DmaState>,
    credit_returns: AtomicUsize,
}

impl DmaGate {
    fn new() -> (Self, IotlbReceipt) {
        (
            Self {
                state: Mutex::new(DmaState {
                    effect: EFFECT_IDENTITY,
                    attempt: 1,
                    phase: DmaPhase::IotlbInFlight,
                    tombstone_attempt: None,
                    dma_credit_owned: true,
                }),
                credit_returns: AtomicUsize::new(0),
            },
            IotlbReceipt {
                effect: EFFECT_IDENTITY,
                attempt: 1,
            },
        )
    }

    fn timeout(&self, receipt: IotlbReceipt) -> Option<TimeoutTombstone> {
        let mut state = self.state.lock().unwrap();
        if receipt.effect != state.effect
            || receipt.attempt != state.attempt
            || state.phase != DmaPhase::IotlbInFlight
        {
            return None;
        }
        state.phase = DmaPhase::Tombstoned;
        state.tombstone_attempt = Some(receipt.attempt);
        assert!(state.dma_credit_owned);
        assert_eq!(self.credit_returns.load(Ordering::Relaxed), 0);
        Some(TimeoutTombstone {
            effect: receipt.effect,
            attempt: receipt.attempt,
        })
    }

    fn retry(&self, tombstone: TimeoutTombstone) -> Option<IotlbReceipt> {
        let mut state = self.state.lock().unwrap();
        if tombstone.effect != state.effect
            || state.phase != DmaPhase::Tombstoned
            || state.tombstone_attempt != Some(tombstone.attempt)
            || state.attempt != tombstone.attempt
        {
            return None;
        }
        state.attempt += 1;
        state.phase = DmaPhase::IotlbInFlight;
        state.tombstone_attempt = None;
        Some(IotlbReceipt {
            effect: state.effect,
            attempt: state.attempt,
        })
    }

    fn acknowledge_iotlb(&self, receipt: IotlbReceipt) -> bool {
        let mut state = self.state.lock().unwrap();
        if receipt.effect != state.effect
            || receipt.attempt != state.attempt
            || state.phase != DmaPhase::IotlbInFlight
        {
            return false;
        }
        state.phase = DmaPhase::Released;
        state.dma_credit_owned = false;
        self.credit_returns.fetch_add(1, Ordering::Release);
        true
    }
}

#[test]
fn loom_timeout_retry_fences_receipts_and_iotlb_ack_returns_one_dma_credit() {
    model(|| {
        let (gate, first_receipt) = DmaGate::new();
        let gate = Arc::new(gate);
        let first_tombstone = gate
            .timeout(first_receipt)
            .expect("the first timeout creates a retained tombstone");
        assert_eq!(gate.credit_returns.load(Ordering::Acquire), 0);

        let retry_gate = gate.clone();
        let stale_ack_gate = gate.clone();
        let retry = thread::spawn(move || retry_gate.retry(first_tombstone));
        let stale_ack = thread::spawn(move || stale_ack_gate.acknowledge_iotlb(first_receipt));
        let second_receipt = retry
            .join()
            .unwrap()
            .expect("the exact tombstone remains retryable");
        assert!(!stale_ack.join().unwrap());
        assert_eq!(second_receipt.effect, first_receipt.effect);
        assert_eq!(second_receipt.attempt, first_receipt.attempt + 1);
        assert!(gate.retry(first_tombstone).is_none(), "retry is one-shot");

        let timeout_gate = gate.clone();
        let ack_gate = gate.clone();
        let timeout = thread::spawn(move || timeout_gate.timeout(second_receipt));
        let ack = thread::spawn(move || ack_gate.acknowledge_iotlb(second_receipt));
        let second_tombstone = timeout.join().unwrap();
        let acknowledged = ack.join().unwrap();
        assert_ne!(second_tombstone.is_some(), acknowledged);

        if let Some(tombstone) = second_tombstone {
            assert_eq!(gate.credit_returns.load(Ordering::Acquire), 0);
            let third_receipt = gate
                .retry(tombstone)
                .expect("a timed-out current attempt remains retryable");
            assert!(
                !gate.acknowledge_iotlb(second_receipt),
                "retry must fence the prior IOTLB receipt"
            );
            assert!(gate.acknowledge_iotlb(third_receipt));
        }

        assert!(
            !gate.acknowledge_iotlb(second_receipt),
            "a consumed IOTLB receipt cannot return credit twice"
        );
        let state = gate.state.lock().unwrap();
        assert_eq!(state.effect, EFFECT_IDENTITY);
        assert_eq!(state.phase, DmaPhase::Released);
        assert_eq!(state.tombstone_attempt, None);
        assert!(!state.dma_credit_owned);
        assert_eq!(gate.credit_returns.load(Ordering::Acquire), 1);
    });
}
