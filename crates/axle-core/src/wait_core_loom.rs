use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitSource {
    Signal(u64),
    Futex(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Completion {
    Pending,
    Wake,
    Timeout,
    Cancel,
}

impl Completion {
    const fn as_usize(self) -> usize {
        match self {
            Self::Pending => 0,
            Self::Wake => 1,
            Self::Timeout => 2,
            Self::Cancel => 3,
        }
    }
}

struct WaitModel {
    current_seq: AtomicUsize,
    completion: AtomicUsize,
    deadline_armed: AtomicBool,
    source: Mutex<Option<WaitSource>>,
}

impl WaitModel {
    fn new() -> Self {
        Self {
            current_seq: AtomicUsize::new(0),
            completion: AtomicUsize::new(Completion::Pending.as_usize()),
            deadline_armed: AtomicBool::new(false),
            source: Mutex::new(None),
        }
    }

    fn arm(&self, source: WaitSource, deadline_armed: bool) -> usize {
        let seq = self
            .current_seq
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        self.completion
            .store(Completion::Pending.as_usize(), Ordering::Release);
        self.deadline_armed.store(deadline_armed, Ordering::Release);
        *self.source.lock().unwrap() = Some(source);
        seq
    }

    fn complete(&self, seq: usize, winner: Completion) -> bool {
        if self.current_seq.load(Ordering::Acquire) != seq {
            return false;
        }
        if self
            .completion
            .compare_exchange(
                Completion::Pending.as_usize(),
                winner.as_usize(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        *self.source.lock().unwrap() = None;
        self.deadline_armed.store(false, Ordering::Release);
        true
    }

    fn wake(&self, seq: usize) -> bool {
        self.complete(seq, Completion::Wake)
    }

    fn timeout(&self, seq: usize) -> bool {
        if !self.deadline_armed.load(Ordering::Acquire) {
            return false;
        }
        self.complete(seq, Completion::Timeout)
    }

    fn cancel(&self, seq: usize) -> bool {
        self.complete(seq, Completion::Cancel)
    }

    fn requeue(&self, seq: usize, source: WaitSource) -> bool {
        let mut current_source = self.source.lock().unwrap();
        if self.current_seq.load(Ordering::Acquire) != seq
            || self.completion.load(Ordering::Acquire) != Completion::Pending.as_usize()
        {
            return false;
        }
        *current_source = Some(source);
        true
    }

    fn source(&self) -> Option<WaitSource> {
        *self.source.lock().unwrap()
    }

    fn completion(&self) -> Completion {
        match self.completion.load(Ordering::Acquire) {
            0 => Completion::Pending,
            1 => Completion::Wake,
            2 => Completion::Timeout,
            3 => Completion::Cancel,
            _ => unreachable!(),
        }
    }
}

#[test]
fn loom_wait_wake_and_timeout_have_single_winner() {
    loom::model(|| {
        let model = Arc::new(WaitModel::new());
        let seq = model.arm(WaitSource::Signal(7), true);

        let wake_model = Arc::clone(&model);
        let wake = thread::spawn(move || {
            thread::yield_now();
            wake_model.wake(seq)
        });

        let timeout_model = Arc::clone(&model);
        let timeout = thread::spawn(move || timeout_model.timeout(seq));

        let wake_won = wake.join().unwrap();
        let timeout_won = timeout.join().unwrap();

        assert_ne!(wake_won, timeout_won);
        assert!(matches!(
            model.completion(),
            Completion::Wake | Completion::Timeout
        ));
        assert!(model.source().is_none());
    });
}

#[test]
fn loom_wait_cancel_and_wake_have_single_winner() {
    loom::model(|| {
        let model = Arc::new(WaitModel::new());
        let seq = model.arm(WaitSource::Signal(11), true);

        let cancel_model = Arc::clone(&model);
        let cancel = thread::spawn(move || {
            thread::yield_now();
            cancel_model.cancel(seq)
        });

        let wake_model = Arc::clone(&model);
        let wake = thread::spawn(move || wake_model.wake(seq));

        let cancel_won = cancel.join().unwrap();
        let wake_won = wake.join().unwrap();

        assert_ne!(cancel_won, wake_won);
        assert!(matches!(
            model.completion(),
            Completion::Wake | Completion::Cancel
        ));
        assert!(model.source().is_none());
    });
}

#[test]
fn loom_wait_requeue_preserves_deadline_until_timeout_wins() {
    loom::model(|| {
        let model = Arc::new(WaitModel::new());
        let seq = model.arm(WaitSource::Futex(1), true);

        let requeue_model = Arc::clone(&model);
        let requeue = thread::spawn(move || {
            thread::yield_now();
            requeue_model.requeue(seq, WaitSource::Futex(2))
        });

        let timeout_model = Arc::clone(&model);
        let timeout = thread::spawn(move || timeout_model.timeout(seq));

        let requeue_won = requeue.join().unwrap();
        let timeout_won = timeout.join().unwrap();

        if timeout_won {
            assert_eq!(model.completion(), Completion::Timeout);
            assert!(model.source().is_none());
            assert!(!model.deadline_armed.load(Ordering::Acquire));
        } else {
            assert!(requeue_won);
            assert_eq!(model.completion(), Completion::Pending);
            assert_eq!(model.source(), Some(WaitSource::Futex(2)));
            assert!(model.deadline_armed.load(Ordering::Acquire));
        }
    });
}

#[test]
fn loom_stale_timeout_cannot_complete_rearmed_wait() {
    loom::model(|| {
        let model = Arc::new(WaitModel::new());
        let stale_seq = model.arm(WaitSource::Signal(3), true);
        assert!(model.cancel(stale_seq));
        let current_seq = model.arm(WaitSource::Signal(3), true);

        let timeout_model = Arc::clone(&model);
        let timeout = thread::spawn(move || timeout_model.timeout(stale_seq));

        let wake_model = Arc::clone(&model);
        let wake = thread::spawn(move || {
            thread::yield_now();
            wake_model.wake(current_seq)
        });

        assert!(!timeout.join().unwrap());
        assert!(wake.join().unwrap());
        assert_eq!(model.completion(), Completion::Wake);
        assert!(model.source().is_none());
    });
}
