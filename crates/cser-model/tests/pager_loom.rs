use loom::{
    model,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    thread,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopePhase {
    Active,
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateFault {
    Pending,
    Committed,
    Completed,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimeoutDecision {
    RevokedUncommitted,
    CompletionOnly,
}

#[derive(Debug)]
struct PublicationState {
    scope: ScopePhase,
    fault: GateFault,
}

#[derive(Debug)]
struct PublicationGate {
    state: Mutex<PublicationState>,
    pte_published: AtomicBool,
}

impl PublicationGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(PublicationState {
                scope: ScopePhase::Active,
                fault: GateFault::Pending,
            }),
            pte_published: AtomicBool::new(false),
        }
    }

    fn commit(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.scope != ScopePhase::Active || state.fault != GateFault::Pending {
            return false;
        }

        // This critical section refines the real scope gate: validation,
        // publication, and continuation consumption have one order relative to
        // TimeoutRevoke.
        self.pte_published.store(true, Ordering::Release);
        state.fault = GateFault::Committed;
        true
    }

    fn timeout_revoke(&self) -> TimeoutDecision {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.scope, ScopePhase::Active);
        match state.fault {
            GateFault::Pending => {
                state.scope = ScopePhase::Closing;
                state.fault = GateFault::Aborted;
                TimeoutDecision::RevokedUncommitted
            }
            GateFault::Committed => TimeoutDecision::CompletionOnly,
            GateFault::Completed | GateFault::Aborted => {
                panic!("the bounded schedule has no prior terminal actor")
            }
        }
    }

    fn complete(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.fault != GateFault::Committed {
            return false;
        }
        state.fault = GateFault::Completed;
        true
    }

    fn snapshot(&self) -> (ScopePhase, GateFault) {
        let state = self.state.lock().unwrap();
        (state.scope, state.fault)
    }
}

#[test]
fn loom_commit_publication_and_timeout_share_one_scope_gate() {
    model(|| {
        let gate = Arc::new(PublicationGate::new());
        let commit_gate = gate.clone();
        let timeout_gate = gate.clone();

        let commit = thread::spawn(move || commit_gate.commit());
        let timeout = thread::spawn(move || timeout_gate.timeout_revoke());

        let commit_won = commit.join().unwrap();
        let timeout_decision = timeout.join().unwrap();
        let published = gate.pte_published.load(Ordering::Acquire);

        if commit_won {
            assert_eq!(timeout_decision, TimeoutDecision::CompletionOnly);
            assert!(published);
            assert_eq!(gate.snapshot(), (ScopePhase::Active, GateFault::Committed));
            assert!(gate.complete());
            assert_eq!(gate.snapshot(), (ScopePhase::Active, GateFault::Completed));
        } else {
            assert_eq!(timeout_decision, TimeoutDecision::RevokedUncommitted);
            assert!(!published, "timeout-first must close publication");
            assert_eq!(gate.snapshot(), (ScopePhase::Closing, GateFault::Aborted));
            assert!(!gate.complete());
        }
    });
}

const OLD_BINDING: u64 = 1;
const NEW_BINDING: u64 = 2;

#[derive(Debug)]
struct AdoptionState {
    scope: ScopePhase,
    fault: GateFault,
    current_binding: u64,
    owner_binding: u64,
    adoptions: usize,
    terminalizations: usize,
    credit_returns: usize,
    prepared_frame_retained: bool,
}

#[derive(Debug)]
struct AdoptionGate {
    state: Mutex<AdoptionState>,
}

impl AdoptionGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(AdoptionState {
                scope: ScopePhase::Active,
                fault: GateFault::Pending,
                current_binding: NEW_BINDING,
                owner_binding: OLD_BINDING,
                adoptions: 0,
                terminalizations: 0,
                credit_returns: 0,
                prepared_frame_retained: true,
            }),
        }
    }

    fn adopt(&self, old_token_binding: u64, new_binding: u64) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.scope != ScopePhase::Active
            || state.fault != GateFault::Pending
            || state.owner_binding != old_token_binding
            || state.current_binding != new_binding
        {
            return false;
        }
        state.owner_binding = new_binding;
        state.adoptions += 1;
        true
    }

    fn timeout(&self) -> TimeoutDecision {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.scope, ScopePhase::Active);
        match state.fault {
            GateFault::Pending => {
                state.scope = ScopePhase::Closing;
                state.fault = GateFault::Aborted;
                state.prepared_frame_retained = false;
                state.credit_returns += 1;
                state.terminalizations += 1;
                TimeoutDecision::RevokedUncommitted
            }
            GateFault::Completed => TimeoutDecision::CompletionOnly,
            GateFault::Committed | GateFault::Aborted => {
                panic!("the bounded adoption schedule cannot reach this state")
            }
        }
    }

    fn reply(&self, token_binding: u64) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.scope != ScopePhase::Active
            || state.fault != GateFault::Pending
            || state.current_binding != token_binding
            || state.owner_binding != token_binding
        {
            return false;
        }
        state.fault = GateFault::Completed;
        state.terminalizations += 1;
        true
    }
}

#[test]
fn loom_adopt_timeout_and_old_reply_cannot_double_terminalize() {
    model(|| {
        let gate = Arc::new(AdoptionGate::new());
        let adopt_gate = gate.clone();
        let timeout_gate = gate.clone();
        let reply_gate = gate.clone();

        let adopt = thread::spawn(move || adopt_gate.adopt(OLD_BINDING, NEW_BINDING));
        let timeout = thread::spawn(move || timeout_gate.timeout());
        let replies = thread::spawn(move || {
            let stale = reply_gate.reply(OLD_BINDING);
            let rebound = reply_gate.reply(NEW_BINDING);
            (stale, rebound)
        });

        let adopted = adopt.join().unwrap();
        let timeout_decision = timeout.join().unwrap();
        let (stale_reply, rebound_reply) = replies.join().unwrap();
        assert!(!stale_reply);
        assert!(!gate.reply(OLD_BINDING));
        assert!(!gate.reply(NEW_BINDING));

        let state = gate.state.lock().unwrap();
        assert_eq!(state.adoptions, usize::from(adopted));
        assert!(matches!(state.owner_binding, OLD_BINDING | NEW_BINDING));
        assert_eq!(state.terminalizations, 1);
        match timeout_decision {
            TimeoutDecision::RevokedUncommitted => {
                assert!(!rebound_reply);
                assert_eq!(state.scope, ScopePhase::Closing);
                assert_eq!(state.fault, GateFault::Aborted);
                assert_eq!(state.credit_returns, 1);
                assert!(!state.prepared_frame_retained);
            }
            TimeoutDecision::CompletionOnly => {
                assert!(adopted);
                assert!(rebound_reply);
                assert_eq!(state.scope, ScopePhase::Active);
                assert_eq!(state.fault, GateFault::Completed);
                assert_eq!(state.owner_binding, NEW_BINDING);
                assert_eq!(state.credit_returns, 0);
                assert!(state.prepared_frame_retained);
            }
        }
    });
}

const SLOT_PENDING: u8 = 0;
const SLOT_COMPLETED: u8 = 1;
const SLOT_ABORTED: u8 = 2;
const OUTCOME_NONE: u8 = 0;
const OUTCOME_SUCCESS: u8 = 1;
const OUTCOME_FAILURE: u8 = 2;

#[derive(Debug)]
struct WakeAuthority;

#[derive(Debug)]
struct OneShotSlot {
    state: AtomicU8,
    outcome: AtomicU8,
    waker: Mutex<Option<WakeAuthority>>,
    waker_takes: AtomicUsize,
    wakes: AtomicUsize,
}

impl OneShotSlot {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(SLOT_PENDING),
            outcome: AtomicU8::new(OUTCOME_NONE),
            waker: Mutex::new(Some(WakeAuthority)),
            waker_takes: AtomicUsize::new(0),
            wakes: AtomicUsize::new(0),
        }
    }

    fn finish(&self, terminal_state: u8, outcome: u8) -> bool {
        if self
            .state
            .compare_exchange(
                SLOT_PENDING,
                terminal_state,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }

        // The winner publishes the outcome before the release operation that
        // represents wake delivery. An observer that acquires `wakes` must see
        // the matching outcome.
        self.outcome.store(outcome, Ordering::Relaxed);
        let _authority = self
            .waker
            .lock()
            .unwrap()
            .take()
            .expect("the unique winner owns the wake authority");
        self.waker_takes.fetch_add(1, Ordering::Relaxed);
        self.wakes.fetch_add(1, Ordering::Release);
        true
    }
}

#[test]
fn loom_complete_abort_and_duplicate_reply_take_one_waker() {
    model(|| {
        let slot = Arc::new(OneShotSlot::new());
        let complete_slot = slot.clone();
        let abort_slot = slot.clone();
        let duplicate_slot = slot.clone();

        let complete = thread::spawn(move || complete_slot.finish(SLOT_COMPLETED, OUTCOME_SUCCESS));
        let abort = thread::spawn(move || abort_slot.finish(SLOT_ABORTED, OUTCOME_FAILURE));
        let duplicate =
            thread::spawn(move || duplicate_slot.finish(SLOT_COMPLETED, OUTCOME_SUCCESS));

        let winners = usize::from(complete.join().unwrap())
            + usize::from(abort.join().unwrap())
            + usize::from(duplicate.join().unwrap());
        assert_eq!(winners, 1);
        assert_eq!(slot.waker_takes.load(Ordering::Relaxed), 1);
        assert_eq!(slot.wakes.load(Ordering::Acquire), 1);
        assert!(slot.waker.lock().unwrap().is_none());

        let state = slot.state.load(Ordering::Acquire);
        let outcome = slot.outcome.load(Ordering::Relaxed);
        assert!(matches!(
            (state, outcome),
            (SLOT_COMPLETED, OUTCOME_SUCCESS) | (SLOT_ABORTED, OUTCOME_FAILURE)
        ));
    });

    // Keep the publication-order refinement separate from the three-writer
    // contention model. Combining the observer with all three writers adds
    // equivalent scheduler permutations without strengthening this ordering
    // assertion.
    model(|| {
        let slot = Arc::new(OneShotSlot::new());
        let producer_slot = slot.clone();
        let producer = thread::spawn(move || {
            assert!(producer_slot.finish(SLOT_COMPLETED, OUTCOME_SUCCESS));
        });

        // This observation occurs before the join. Some schedules see no wake
        // yet; every schedule that acquires the Release publication must also
        // observe the matching Relaxed outcome.
        if slot.wakes.load(Ordering::Acquire) == 1 {
            assert_eq!(slot.outcome.load(Ordering::Relaxed), OUTCOME_SUCCESS);
        }

        producer.join().unwrap();
        assert_eq!(slot.wakes.load(Ordering::Acquire), 1);
        assert_eq!(slot.outcome.load(Ordering::Relaxed), OUTCOME_SUCCESS);
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClosurePhase {
    Active,
    Closing,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreditState {
    Retained,
    Returned,
}

#[derive(Debug)]
struct RetainedResource {
    dropped: Arc<AtomicBool>,
}

impl Drop for RetainedResource {
    fn drop(&mut self) {
        assert!(!self.dropped.swap(true, Ordering::Release));
    }
}

#[derive(Debug)]
struct ClosureWakeAuthority {
    wake_done: Arc<AtomicBool>,
    destroyed: Arc<AtomicBool>,
}

impl ClosureWakeAuthority {
    fn wake(&self) {
        assert!(!self.wake_done.swap(true, Ordering::Release));
    }
}

impl Drop for ClosureWakeAuthority {
    fn drop(&mut self) {
        assert!(self.wake_done.load(Ordering::Acquire));
        assert!(!self.destroyed.swap(true, Ordering::Release));
    }
}

#[derive(Debug)]
struct ClosureState {
    phase: ClosurePhase,
    fault_aborted: bool,
    credit: CreditState,
    cleanup_obligation: bool,
    wake_obligation: bool,
    authority_obligation: bool,
    resource: Option<RetainedResource>,
    waker: Option<ClosureWakeAuthority>,
}

#[derive(Debug)]
struct ThreeStageClosure {
    state: Mutex<ClosureState>,
    resource_dropped: Arc<AtomicBool>,
    wake_done: Arc<AtomicBool>,
    authority_destroyed: Arc<AtomicBool>,
}

impl ThreeStageClosure {
    fn new() -> Self {
        let resource_dropped = Arc::new(AtomicBool::new(false));
        let wake_done = Arc::new(AtomicBool::new(false));
        let authority_destroyed = Arc::new(AtomicBool::new(false));
        Self {
            state: Mutex::new(ClosureState {
                phase: ClosurePhase::Active,
                fault_aborted: false,
                credit: CreditState::Retained,
                cleanup_obligation: false,
                wake_obligation: false,
                authority_obligation: false,
                resource: Some(RetainedResource {
                    dropped: resource_dropped.clone(),
                }),
                waker: Some(ClosureWakeAuthority {
                    wake_done: wake_done.clone(),
                    destroyed: authority_destroyed.clone(),
                }),
            }),
            resource_dropped,
            wake_done,
            authority_destroyed,
        }
    }

    fn close(&self) {
        // Stage 1: atomically close reply authority and detach cleanup objects,
        // but retain credit and explicit obligations in shared state.
        let (resource, waker) = {
            let mut state = self.state.lock().unwrap();
            assert_eq!(state.phase, ClosurePhase::Active);
            state.phase = ClosurePhase::Closing;
            state.fault_aborted = true;
            state.cleanup_obligation = true;
            state.wake_obligation = true;
            state.authority_obligation = true;
            (state.resource.take().unwrap(), state.waker.take().unwrap())
        };

        // Stage 2: perform fallible/externally visible cleanup outside the state
        // lock. Credit remains retained and the scope remains Closing.
        drop(resource);
        waker.wake();
        drop(waker);

        // Stage 3: only proven cleanup may publish Returned/Revoked.
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.phase, ClosurePhase::Closing);
        assert_eq!(state.credit, CreditState::Retained);
        assert!(self.resource_dropped.load(Ordering::Acquire));
        assert!(self.wake_done.load(Ordering::Acquire));
        assert!(self.authority_destroyed.load(Ordering::Acquire));
        state.cleanup_obligation = false;
        state.wake_obligation = false;
        state.authority_obligation = false;
        state.credit = CreditState::Returned;
        state.phase = ClosurePhase::Revoked;
    }

    fn observe(&self) {
        let state = self.state.lock().unwrap();
        match state.phase {
            ClosurePhase::Active => {
                assert!(!state.fault_aborted);
                assert_eq!(state.credit, CreditState::Retained);
                assert!(state.resource.is_some());
                assert!(state.waker.is_some());
            }
            ClosurePhase::Closing => {
                assert!(state.fault_aborted);
                assert_eq!(state.credit, CreditState::Retained);
                assert!(state.cleanup_obligation);
                assert!(state.wake_obligation);
                assert!(state.authority_obligation);
                assert!(state.resource.is_none());
                assert!(state.waker.is_none());
            }
            ClosurePhase::Revoked => {
                assert!(state.fault_aborted);
                assert_eq!(state.credit, CreditState::Returned);
                assert!(!state.cleanup_obligation);
                assert!(!state.wake_obligation);
                assert!(!state.authority_obligation);
                assert!(self.resource_dropped.load(Ordering::Acquire));
                assert!(self.wake_done.load(Ordering::Acquire));
                assert!(self.authority_destroyed.load(Ordering::Acquire));
            }
        }
    }
}

#[test]
fn loom_three_stage_closure_never_publishes_revoked_early() {
    model(|| {
        let closure = Arc::new(ThreeStageClosure::new());
        let close_actor = closure.clone();
        let observer = closure.clone();

        let close = thread::spawn(move || close_actor.close());
        let observe = thread::spawn(move || observer.observe());

        close.join().unwrap();
        observe.join().unwrap();
        closure.observe();
        let final_state = closure.state.lock().unwrap();
        assert_eq!(final_state.phase, ClosurePhase::Revoked);
        assert_eq!(final_state.credit, CreditState::Returned);
    });
}
