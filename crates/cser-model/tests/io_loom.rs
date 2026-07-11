//! Bounded concurrency refinements of three Stage 5 linearization gates.
//!
//! These deliberately small `loom::sync` surrogates do not execute `IoModel`
//! and do not model a real VirtIO ring, interrupt path, IOMMU, cache, PCI
//! reset, or OSTD lock implementation. They check only the gate relationships
//! named by each test under Loom's bounded schedules.

use loom::{
    model,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopePhase {
    Active,
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishRequest {
    Prepared,
    Cancelling,
    Committed,
}

#[derive(Debug)]
struct PublishState {
    scope: ScopePhase,
    request: PublishRequest,
}

#[derive(Debug)]
struct PublishGate {
    state: Mutex<PublishState>,
    avail_idx_published: AtomicBool,
}

impl PublishGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(PublishState {
                scope: ScopePhase::Active,
                request: PublishRequest::Prepared,
            }),
            avail_idx_published: AtomicBool::new(false),
        }
    }

    fn publish_avail(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.scope != ScopePhase::Active || state.request != PublishRequest::Prepared {
            return false;
        }
        // This Release store is the surrogate for split-ring avail.idx, not
        // for the later notification hint.
        self.avail_idx_published.store(true, Ordering::Release);
        state.request = PublishRequest::Committed;
        true
    }

    fn revoke_begin(&self) {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.scope, ScopePhase::Active);
        state.scope = ScopePhase::Closing;
        if state.request == PublishRequest::Prepared {
            state.request = PublishRequest::Cancelling;
        }
    }
}

#[test]
fn loom_avail_publication_and_revoke_share_one_publish_gate() {
    model(|| {
        let gate = Arc::new(PublishGate::new());
        let publisher = gate.clone();
        let revoker = gate.clone();
        let publish = thread::spawn(move || publisher.publish_avail());
        let revoke = thread::spawn(move || revoker.revoke_begin());

        let published = publish.join().unwrap();
        revoke.join().unwrap();
        let release_visible = gate.avail_idx_published.load(Ordering::Acquire);
        let state = gate.state.lock().unwrap();
        assert_eq!(state.scope, ScopePhase::Closing);
        if published {
            assert!(release_visible);
            assert_eq!(state.request, PublishRequest::Committed);
        } else {
            assert!(!release_visible);
            assert_eq!(state.request, PublishRequest::Cancelling);
        }
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeviceRequest {
    Committed,
    Completed,
    IndeterminateAfterReset,
}

#[derive(Debug)]
struct DeviceState {
    request: DeviceRequest,
    generation: u64,
    terminalizations: usize,
    quiesced: bool,
}

#[derive(Debug)]
struct DeviceGate {
    state: Mutex<DeviceState>,
}

impl DeviceGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(DeviceState {
                request: DeviceRequest::Committed,
                generation: 1,
                terminalizations: 0,
                quiesced: false,
            }),
        }
    }

    fn completion(&self, generation: u64) -> bool {
        let mut state = self.state.lock().unwrap();
        if generation != state.generation || state.request != DeviceRequest::Committed {
            return false;
        }
        state.request = DeviceRequest::Completed;
        state.terminalizations += 1;
        true
    }

    fn reset_ack(&self) {
        let mut state = self.state.lock().unwrap();
        if state.request == DeviceRequest::Committed {
            state.request = DeviceRequest::IndeterminateAfterReset;
            state.terminalizations += 1;
        }
        state.generation += 1;
        state.quiesced = true;
    }
}

#[test]
fn loom_completion_and_reset_ack_publish_one_terminal_outcome() {
    model(|| {
        let gate = Arc::new(DeviceGate::new());
        let completion_gate = gate.clone();
        let reset_gate = gate.clone();
        let completion = thread::spawn(move || completion_gate.completion(1));
        let reset = thread::spawn(move || reset_gate.reset_ack());

        let completion_won = completion.join().unwrap();
        reset.join().unwrap();
        assert!(
            !gate.completion(1),
            "old generation completion must be fenced"
        );
        let state = gate.state.lock().unwrap();
        assert_eq!(state.generation, 2);
        assert!(state.quiesced);
        assert_eq!(state.terminalizations, 1);
        assert_eq!(
            state.request,
            if completion_won {
                DeviceRequest::Completed
            } else {
                DeviceRequest::IndeterminateAfterReset
            }
        );
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptPhase {
    InFlight,
    TimedOut,
    Acknowledged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeasePhase {
    Mapped,
    Invalidating,
    TimedOut,
    Released,
}

#[derive(Debug)]
struct TombstoneState {
    reset: AttemptPhase,
    queue: LeasePhase,
    credit_returned: bool,
}

#[derive(Debug)]
struct TombstoneGate {
    state: Mutex<TombstoneState>,
    releases: AtomicUsize,
}

impl TombstoneGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(TombstoneState {
                reset: AttemptPhase::InFlight,
                queue: LeasePhase::Mapped,
                credit_returned: false,
            }),
            releases: AtomicUsize::new(0),
        }
    }

    fn reset_timeout(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.reset != AttemptPhase::InFlight {
            return false;
        }
        state.reset = AttemptPhase::TimedOut;
        assert_eq!(state.queue, LeasePhase::Mapped);
        assert!(!state.credit_returned);
        true
    }

    fn reset_ack(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.reset != AttemptPhase::InFlight {
            return false;
        }
        state.reset = AttemptPhase::Acknowledged;
        true
    }

    fn retry_reset(&self) {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.reset, AttemptPhase::TimedOut);
        state.reset = AttemptPhase::InFlight;
    }

    fn begin_invalidate(&self) {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.reset, AttemptPhase::Acknowledged);
        assert_eq!(state.queue, LeasePhase::Mapped);
        state.queue = LeasePhase::Invalidating;
    }

    fn invalidate_timeout(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.queue != LeasePhase::Invalidating {
            return false;
        }
        state.queue = LeasePhase::TimedOut;
        assert!(!state.credit_returned);
        assert_eq!(self.releases.load(Ordering::Relaxed), 0);
        true
    }

    fn invalidate_ack(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.queue != LeasePhase::Invalidating {
            return false;
        }
        state.queue = LeasePhase::Released;
        state.credit_returned = true;
        self.releases.fetch_add(1, Ordering::Release);
        true
    }

    fn retry_invalidate(&self) {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.queue, LeasePhase::TimedOut);
        state.queue = LeasePhase::Invalidating;
    }
}

#[test]
fn loom_timeouts_retain_queue_until_reset_and_invalidation_ack() {
    model(|| {
        let gate = Arc::new(TombstoneGate::new());
        let timeout_gate = gate.clone();
        let ack_gate = gate.clone();
        let timeout = thread::spawn(move || timeout_gate.reset_timeout());
        let ack = thread::spawn(move || ack_gate.reset_ack());
        let timed_out = timeout.join().unwrap();
        let acknowledged = ack.join().unwrap();
        assert_ne!(timed_out, acknowledged);
        if timed_out {
            gate.retry_reset();
            assert!(gate.reset_ack());
        }
        gate.begin_invalidate();

        let timeout_gate = gate.clone();
        let ack_gate = gate.clone();
        let timeout = thread::spawn(move || timeout_gate.invalidate_timeout());
        let ack = thread::spawn(move || ack_gate.invalidate_ack());
        let timed_out = timeout.join().unwrap();
        let acknowledged = ack.join().unwrap();
        assert_ne!(timed_out, acknowledged);
        if timed_out {
            assert_eq!(gate.releases.load(Ordering::Acquire), 0);
            gate.retry_invalidate();
            assert!(gate.invalidate_ack());
        }

        let state = gate.state.lock().unwrap();
        assert_eq!(state.reset, AttemptPhase::Acknowledged);
        assert_eq!(state.queue, LeasePhase::Released);
        assert!(state.credit_returned);
        assert_eq!(gate.releases.load(Ordering::Acquire), 1);
    });
}
