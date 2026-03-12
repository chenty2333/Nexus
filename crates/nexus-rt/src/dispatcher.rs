use alloc::boxed::Box;
use alloc::collections::{BinaryHeap, VecDeque};
use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::cmp::Ordering;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use core::task::{Context, Poll, Waker};

use libax::compat::handle::ZX_HANDLE_INVALID;
use libax::compat::packet::ZX_PKT_TYPE_USER;
use libax::compat::signals::{
    ZX_CHANNEL_PEER_CLOSED, ZX_CHANNEL_READABLE, ZX_CHANNEL_WRITABLE, ZX_SOCKET_PEER_CLOSED,
};
use libax::compat::status::{ZX_ERR_CANCELED, ZX_ERR_NOT_FOUND, ZX_ERR_SHOULD_WAIT, ZX_OK};
use libax::compat::{
    ZX_TIME_INFINITE, zx_channel_read, zx_channel_write, zx_handle_close, zx_handle_t,
    zx_packet_user_t, zx_port_packet_t, zx_port_queue, zx_signals_t, zx_status_t, zx_time_t,
    zx_timer_cancel, zx_timer_create_monotonic, zx_timer_set,
};

use crate::{Event, Reactor};

const READY_BUDGET: usize = 64;
const FUTURE_POLL_BUDGET: usize = 16;
const TIMER_PACKET_KEY: u64 = u64::MAX;
const USER_WAKE_KIND_TASK: u64 = 1;

/// Stable task identifier with ABA protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TaskId {
    slot: u32,
    generation: u32,
}

impl TaskId {
    /// Return the task slot index.
    pub const fn slot(self) -> u32 {
        self.slot
    }

    /// Return the task generation.
    pub const fn generation(self) -> u32 {
        self.generation
    }

    fn new(slot: usize, generation: u32) -> Self {
        Self {
            slot: slot as u32,
            generation,
        }
    }

    fn raw_key(self) -> u64 {
        ((self.slot as u64) << 32) | self.generation as u64
    }

    fn from_raw(raw: u64) -> Self {
        Self {
            slot: (raw >> 32) as u32,
            generation: raw as u32,
        }
    }
}

/// Stable signal-registration identifier with ABA protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RegistrationId {
    slot: u32,
    generation: u32,
}

impl RegistrationId {
    /// Return the registration slot index.
    pub const fn slot(self) -> u32 {
        self.slot
    }

    /// Return the registration generation.
    pub const fn generation(self) -> u32 {
        self.generation
    }

    fn new(slot: usize, generation: u32) -> Self {
        Self {
            slot: slot as u32,
            generation,
        }
    }

    fn raw_key(self) -> u64 {
        ((self.slot as u64) << 32) | self.generation as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SleepId {
    slot: u32,
    generation: u32,
}

impl SleepId {
    fn new(slot: usize, generation: u32) -> Self {
        Self {
            slot: slot as u32,
            generation,
        }
    }
}

type LocalFuture = Pin<Box<dyn Future<Output = ()> + 'static>>;

struct TaskSlot {
    generation: u32,
    future: Option<LocalFuture>,
    waker: Arc<TaskWaker>,
    queued: bool,
}

struct SignalSlot {
    generation: u32,
    active: bool,
    handle: zx_handle_t,
    mask: zx_signals_t,
    armed: bool,
    observed: Option<zx_signals_t>,
    task: Option<TaskId>,
    waker: Option<Waker>,
}

struct SleepSlot {
    generation: u32,
    active: bool,
    deadline: zx_time_t,
    fired: bool,
    task: Option<TaskId>,
    waker: Option<Waker>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeapEntry {
    deadline: zx_time_t,
    id: SleepId,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.id.slot.cmp(&self.id.slot))
            .then_with(|| other.id.generation.cmp(&self.id.generation))
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct DispatcherState {
    reactor: Reactor,
    timer: zx_handle_t,
    timer_wait_armed: bool,
    timer_deadline: Option<zx_time_t>,
    tasks: Vec<TaskSlot>,
    task_free: Vec<usize>,
    ready: VecDeque<TaskId>,
    registrations: Vec<SignalSlot>,
    registration_free: Vec<usize>,
    sleeps: Vec<SleepSlot>,
    sleep_free: Vec<usize>,
    sleep_heap: BinaryHeap<HeapEntry>,
}

struct DispatcherCore {
    current_task: Cell<Option<TaskId>>,
    state: RefCell<DispatcherState>,
}

impl Drop for DispatcherCore {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        if state.timer != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(state.timer);
            state.timer = ZX_HANDLE_INVALID;
        }
        let port = state.reactor.port_handle();
        if port != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(port);
        }
    }
}

/// Single-thread dispatcher plus executor.
pub struct Dispatcher {
    handle: DispatcherHandle,
}

/// Cloneable handle used by tasks and awaitables.
#[derive(Clone)]
pub struct DispatcherHandle {
    core: Rc<DispatcherCore>,
}

/// Owned signal-interest registration.
///
/// Dropping the registration logically cancels it and frees the slot for reuse
/// under a bumped generation.
pub struct SignalRegistration {
    dispatcher: DispatcherHandle,
    id: Cell<Option<RegistrationId>>,
}

/// Future returned by [`SignalRegistration::wait`].
pub struct OnSignals<'a> {
    registration: &'a SignalRegistration,
}

/// Future returned by [`DispatcherHandle::sleep_until`].
pub struct Sleep {
    dispatcher: DispatcherHandle,
    id: Cell<Option<SleepId>>,
}

/// Result metadata for an async channel receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelReadResult {
    /// Number of bytes written into the caller-provided buffer.
    pub actual_bytes: u32,
    /// Number of transferred handles written into the caller-provided buffer.
    pub actual_handles: u32,
}

/// Future that waits until a channel read succeeds or returns a terminal error.
pub struct AsyncChannelRecv<'a> {
    dispatcher: DispatcherHandle,
    handle: zx_handle_t,
    bytes: &'a mut [u8],
    handles: &'a mut [zx_handle_t],
    registration: Option<SignalRegistration>,
}

/// Future that writes a request into a channel and then waits for the reply.
///
/// This helper is intentionally minimal: it models a single in-flight request
/// on one handle, which is enough for bootstrap RPC/server-controller bring-up.
pub struct AsyncChannelCall<'a> {
    dispatcher: DispatcherHandle,
    handle: zx_handle_t,
    request_bytes: &'a [u8],
    reply_bytes: &'a mut [u8],
    reply_handles: &'a mut [zx_handle_t],
    write_status: Option<zx_status_t>,
    wrote_request: bool,
    write_registration: Option<SignalRegistration>,
    read_registration: Option<SignalRegistration>,
}

/// Future that waits for socket readiness signals.
pub struct AsyncSocketReadiness {
    dispatcher: DispatcherHandle,
    handle: zx_handle_t,
    mask: zx_signals_t,
    registration: Option<SignalRegistration>,
}

struct TaskWaker {
    port: zx_handle_t,
    task: TaskId,
    queued: AtomicBool,
}

impl TaskWaker {
    fn clear_queued(&self) {
        self.queued.store(false, AtomicOrdering::Release);
    }
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.queued.swap(true, AtomicOrdering::AcqRel) {
            return;
        }

        let packet = zx_port_packet_t {
            key: self.task.raw_key(),
            type_: ZX_PKT_TYPE_USER,
            status: 0,
            user: zx_packet_user_t {
                u64: [USER_WAKE_KIND_TASK, 0, 0, 0],
            },
        };
        let _ = zx_port_queue(self.port, &packet);
    }
}

impl Dispatcher {
    /// Create a dispatcher with one port, one dispatcher timer, and empty
    /// task/registration state.
    pub fn create() -> Result<Self, zx_status_t> {
        let reactor = Reactor::create()?;
        let mut timer = ZX_HANDLE_INVALID;
        let status = zx_timer_create_monotonic(0, &mut timer);
        if status != ZX_OK {
            let _ = zx_handle_close(reactor.port_handle());
            return Err(status);
        }

        Ok(Self {
            handle: DispatcherHandle {
                core: Rc::new(DispatcherCore {
                    current_task: Cell::new(None),
                    state: RefCell::new(DispatcherState {
                        reactor,
                        timer,
                        timer_wait_armed: false,
                        timer_deadline: None,
                        tasks: Vec::new(),
                        task_free: Vec::new(),
                        ready: VecDeque::new(),
                        registrations: Vec::new(),
                        registration_free: Vec::new(),
                        sleeps: Vec::new(),
                        sleep_free: Vec::new(),
                        sleep_heap: BinaryHeap::new(),
                    }),
                }),
            },
        })
    }

    /// Return a cloneable dispatcher handle.
    pub fn handle(&self) -> DispatcherHandle {
        self.handle.clone()
    }

    /// Spawn a future onto this dispatcher.
    pub fn spawn<F>(&self, future: F) -> Result<TaskId, zx_status_t>
    where
        F: Future<Output = ()> + 'static,
    {
        self.handle.spawn(future)
    }

    /// Run tasks until no live task remains.
    pub fn run(&self) -> Result<(), zx_status_t> {
        while self.handle.has_live_tasks() {
            self.run_ready_tasks()?;
            if !self.handle.has_live_tasks() {
                break;
            }
            self.handle.refresh_dispatcher_timer()?;
            self.block_once()?;
        }
        Ok(())
    }

    /// Spawn one future and drive the dispatcher until it completes.
    pub fn block_on<F>(&self, future: F) -> Result<F::Output, zx_status_t>
    where
        F: Future,
    {
        let port = self.handle.core.state.borrow().reactor.port_handle();
        let waker = Arc::new(TaskWaker {
            port,
            task: TaskId {
                slot: u32::MAX,
                generation: 1,
            },
            queued: AtomicBool::new(false),
        });
        let task_waker = Waker::from(Arc::clone(&waker));
        let mut future = core::pin::pin!(future);

        loop {
            self.run_ready_tasks()?;
            waker.clear_queued();
            let mut cx = Context::from_waker(&task_waker);
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return Ok(output);
            }
            self.handle.refresh_dispatcher_timer()?;
            self.block_once()?;
        }
    }

    fn run_ready_tasks(&self) -> Result<(), zx_status_t> {
        for _ in 0..READY_BUDGET {
            let Some(task_id) = self.handle.pop_ready_task() else {
                return Ok(());
            };
            self.poll_task(task_id)?;
        }
        Ok(())
    }

    fn poll_task(&self, task_id: TaskId) -> Result<(), zx_status_t> {
        let (mut future, waker) = {
            let mut state = self.handle.core.state.borrow_mut();
            let Some(slot) = state.task_slot_mut(task_id) else {
                return Ok(());
            };
            slot.queued = false;
            slot.waker.clear_queued();
            let Some(future) = slot.future.take() else {
                return Ok(());
            };
            (future, Arc::clone(&slot.waker))
        };

        let waker = Waker::from(waker);
        let mut cx = Context::from_waker(&waker);
        self.handle.core.current_task.set(Some(task_id));
        let poll_result = future.as_mut().poll(&mut cx);
        self.handle.core.current_task.set(None);
        match poll_result {
            Poll::Ready(()) => {
                self.handle.finish_task(task_id);
            }
            Poll::Pending => {
                let mut state = self.handle.core.state.borrow_mut();
                if let Some(slot) = state.task_slot_mut(task_id) {
                    slot.future = Some(future);
                }
            }
        }
        Ok(())
    }

    fn block_once(&self) -> Result<(), zx_status_t> {
        let event = {
            let state = self.handle.core.state.borrow();
            state.reactor.wait_until(ZX_TIME_INFINITE)
        }?;
        self.handle_event(event)?;

        loop {
            let event = {
                let state = self.handle.core.state.borrow();
                state.reactor.wait_until(0)
            };
            match event {
                Ok(event) => self.handle_event(event)?,
                Err(ZX_ERR_SHOULD_WAIT) => return Ok(()),
                Err(status) => return Err(status),
            }
        }
    }

    fn handle_event(&self, event: Event) -> Result<(), zx_status_t> {
        match event {
            Event::Signal(signal) if signal.key == TIMER_PACKET_KEY => {
                self.handle.on_dispatcher_timer_fired()
            }
            Event::Signal(signal) => self.handle.on_signal_packet(signal.key, signal.observed),
            Event::User(packet) => {
                self.handle.on_user_packet(packet);
                Ok(())
            }
            Event::Unknown(_) => Ok(()),
        }
    }
}

impl DispatcherHandle {
    /// Spawn a future onto this dispatcher.
    pub fn spawn<F>(&self, future: F) -> Result<TaskId, zx_status_t>
    where
        F: Future<Output = ()> + 'static,
    {
        let mut state = self.core.state.borrow_mut();
        let index = state.task_free.pop().unwrap_or_else(|| {
            let port = state.reactor.port_handle();
            let slot_index = state.tasks.len();
            state.tasks.push(TaskSlot {
                generation: 1,
                future: None,
                waker: Arc::new(TaskWaker {
                    port,
                    task: TaskId::new(slot_index, 1),
                    queued: AtomicBool::new(false),
                }),
                queued: false,
            });
            slot_index
        });

        let generation = state.tasks[index].generation;
        let task_id = TaskId::new(index, generation);
        state.tasks[index] = TaskSlot {
            generation,
            future: Some(Box::pin(future)),
            waker: Arc::new(TaskWaker {
                port: state.reactor.port_handle(),
                task: task_id,
                queued: AtomicBool::new(false),
            }),
            queued: true,
        };
        state.ready.push_back(task_id);
        Ok(task_id)
    }

    /// Register long-lived signal interest on one handle.
    pub fn register_signals(
        &self,
        handle: zx_handle_t,
        mask: zx_signals_t,
    ) -> Result<SignalRegistration, zx_status_t> {
        let id = {
            let mut state = self.core.state.borrow_mut();
            let index = state.registration_free.pop().unwrap_or_else(|| {
                state.registrations.push(SignalSlot {
                    generation: 1,
                    active: false,
                    handle: ZX_HANDLE_INVALID,
                    mask: 0,
                    armed: false,
                    observed: None,
                    task: None,
                    waker: None,
                });
                state.registrations.len() - 1
            });
            let generation = state.registrations[index].generation;
            state.registrations[index] = SignalSlot {
                generation,
                active: true,
                handle,
                mask,
                armed: false,
                observed: None,
                task: None,
                waker: None,
            };
            RegistrationId::new(index, generation)
        };
        self.arm_registration(id)?;
        Ok(SignalRegistration {
            dispatcher: self.clone(),
            id: Cell::new(Some(id)),
        })
    }

    /// Create one future that resolves when `deadline` is reached.
    pub fn sleep_until(&self, deadline: zx_time_t) -> Result<Sleep, zx_status_t> {
        let id = {
            let mut state = self.core.state.borrow_mut();
            let index = state.sleep_free.pop().unwrap_or_else(|| {
                state.sleeps.push(SleepSlot {
                    generation: 1,
                    active: false,
                    deadline: 0,
                    fired: false,
                    task: None,
                    waker: None,
                });
                state.sleeps.len() - 1
            });
            let generation = state.sleeps[index].generation;
            let id = SleepId::new(index, generation);
            state.sleeps[index] = SleepSlot {
                generation,
                active: true,
                deadline,
                fired: false,
                task: None,
                waker: None,
            };
            state.sleep_heap.push(HeapEntry { deadline, id });
            id
        };
        self.refresh_dispatcher_timer()?;
        Ok(Sleep {
            dispatcher: self.clone(),
            id: Cell::new(Some(id)),
        })
    }

    /// Wait for the next readable channel message.
    pub fn channel_recv<'a>(
        &self,
        handle: zx_handle_t,
        bytes: &'a mut [u8],
        handles: &'a mut [zx_handle_t],
    ) -> AsyncChannelRecv<'a> {
        AsyncChannelRecv {
            dispatcher: self.clone(),
            handle,
            bytes,
            handles,
            registration: None,
        }
    }

    /// Write one request into a channel and then wait for the reply.
    ///
    /// This helper opportunistically issues the request write before the
    /// returned future is first polled. That lets a peer task already queued on
    /// the same dispatcher observe the request on its first poll instead of
    /// waiting for a second wake cycle.
    pub fn channel_call<'a>(
        &self,
        handle: zx_handle_t,
        request_bytes: &'a [u8],
        reply_bytes: &'a mut [u8],
        reply_handles: &'a mut [zx_handle_t],
    ) -> AsyncChannelCall<'a> {
        let write_status = zx_channel_write(
            handle,
            0,
            request_bytes.as_ptr(),
            request_bytes.len() as u32,
            core::ptr::null(),
            0,
        );
        AsyncChannelCall {
            dispatcher: self.clone(),
            handle,
            request_bytes,
            reply_bytes,
            reply_handles,
            write_status: Some(write_status),
            wrote_request: write_status == ZX_OK,
            write_registration: None,
            read_registration: None,
        }
    }

    /// Wait for socket readiness signals.
    pub fn socket_readiness(
        &self,
        handle: zx_handle_t,
        mask: zx_signals_t,
    ) -> AsyncSocketReadiness {
        AsyncSocketReadiness {
            dispatcher: self.clone(),
            handle,
            mask,
            registration: None,
        }
    }

    fn has_live_tasks(&self) -> bool {
        self.core
            .state
            .borrow()
            .tasks
            .iter()
            .any(|slot| slot.future.is_some())
    }

    fn pop_ready_task(&self) -> Option<TaskId> {
        self.core.state.borrow_mut().ready.pop_front()
    }

    fn finish_task(&self, task_id: TaskId) {
        let mut state = self.core.state.borrow_mut();
        let Some(slot) = state.task_slot_mut(task_id) else {
            return;
        };
        slot.future = None;
        slot.queued = false;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        state.task_free.push(task_id.slot as usize);
    }

    fn cancel_registration(&self, id: RegistrationId) -> Result<(), zx_status_t> {
        let mut state = self.core.state.borrow_mut();
        let Some(slot) = state.registration_slot_mut(id) else {
            return Err(ZX_ERR_NOT_FOUND);
        };
        slot.active = false;
        slot.armed = false;
        slot.observed = None;
        slot.task = None;
        slot.waker = None;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        state.registration_free.push(id.slot as usize);
        Ok(())
    }

    fn cancel_sleep(&self, id: SleepId) {
        {
            let mut state = self.core.state.borrow_mut();
            let Some(slot) = state.sleep_slot_mut(id) else {
                return;
            };
            slot.active = false;
            slot.fired = false;
            slot.task = None;
            slot.waker = None;
            slot.generation = slot.generation.wrapping_add(1).max(1);
            state.sleep_free.push(id.slot as usize);
        }
        let _ = self.refresh_dispatcher_timer();
    }

    fn poll_registration(
        &self,
        id: RegistrationId,
        waker: &Waker,
        rearm_after_delivery: bool,
    ) -> Poll<Result<zx_signals_t, zx_status_t>> {
        let (result, maybe_rearm) = {
            let mut state = self.core.state.borrow_mut();
            let Some(slot) = state.registration_slot_mut(id) else {
                return Poll::Ready(Err(ZX_ERR_CANCELED));
            };
            if !slot.active {
                return Poll::Ready(Err(ZX_ERR_CANCELED));
            }
            if let Some(observed) = slot.observed.take() {
                slot.task = None;
                slot.waker = None;
                (
                    Poll::Ready(Ok(observed)),
                    rearm_after_delivery && !slot.armed,
                )
            } else {
                slot.task = self.core.current_task.get();
                slot.waker = Some(waker.clone());
                if !slot.armed {
                    (
                        Poll::Pending,
                        true, // arm after dropping the borrow
                    )
                } else {
                    (Poll::Pending, false)
                }
            }
        };

        if maybe_rearm {
            match self.arm_registration(id) {
                Ok(()) => result,
                Err(status) => Poll::Ready(Err(status)),
            }
        } else {
            result
        }
    }

    fn poll_sleep(&self, id: SleepId, waker: &Waker) -> Poll<Result<(), zx_status_t>> {
        {
            let mut state = self.core.state.borrow_mut();
            let Some(slot) = state.sleep_slot_mut(id) else {
                return Poll::Ready(Err(ZX_ERR_CANCELED));
            };
            if !slot.active {
                return Poll::Ready(Err(ZX_ERR_CANCELED));
            }
            if slot.fired {
                slot.active = false;
                slot.fired = false;
                slot.task = None;
                slot.waker = None;
                slot.generation = slot.generation.wrapping_add(1).max(1);
                state.sleep_free.push(id.slot as usize);
                return Poll::Ready(Ok(()));
            }
            slot.task = self.core.current_task.get();
            slot.waker = Some(waker.clone());
        }

        if let Err(status) = self.refresh_dispatcher_timer() {
            return Poll::Ready(Err(status));
        }
        Poll::Pending
    }

    fn arm_registration(&self, id: RegistrationId) -> Result<(), zx_status_t> {
        let (reactor, handle, mask) = {
            let state = self.core.state.borrow();
            let Some(slot) = state.registration_slot(id) else {
                return Err(ZX_ERR_NOT_FOUND);
            };
            if !slot.active {
                return Err(ZX_ERR_CANCELED);
            }
            (state.reactor, slot.handle, slot.mask)
        };
        reactor.wait_async(handle, id.raw_key(), mask, 0)?;
        let mut state = self.core.state.borrow_mut();
        if let Some(slot) = state.registration_slot_mut(id) {
            slot.armed = true;
        }
        Ok(())
    }

    fn refresh_dispatcher_timer(&self) -> Result<(), zx_status_t> {
        let (timer, reactor, timer_wait_armed, next_deadline, previous_deadline) = {
            let mut state = self.core.state.borrow_mut();
            state.discard_stale_sleep_entries();
            (
                state.timer,
                state.reactor,
                state.timer_wait_armed,
                state.sleep_heap.peek().copied().map(|entry| entry.deadline),
                state.timer_deadline,
            )
        };

        match next_deadline {
            Some(deadline) => {
                if !timer_wait_armed {
                    reactor.wait_async(
                        timer,
                        TIMER_PACKET_KEY,
                        libax::compat::signals::ZX_TIMER_SIGNALED,
                        0,
                    )?;
                    let mut state = self.core.state.borrow_mut();
                    state.timer_wait_armed = true;
                }
                if previous_deadline != Some(deadline) {
                    let status = zx_timer_set(timer, deadline, 0);
                    if status != ZX_OK {
                        return Err(status);
                    }
                    let mut state = self.core.state.borrow_mut();
                    state.timer_deadline = Some(deadline);
                }
            }
            None => {
                if previous_deadline.is_some() {
                    let status = zx_timer_cancel(timer);
                    if status != ZX_OK {
                        return Err(status);
                    }
                    let mut state = self.core.state.borrow_mut();
                    state.timer_deadline = None;
                }
            }
        }
        Ok(())
    }

    fn on_dispatcher_timer_fired(&self) -> Result<(), zx_status_t> {
        let (due, should_cancel) = {
            let mut state = self.core.state.borrow_mut();
            let Some(deadline) = state.timer_deadline.take() else {
                state.timer_wait_armed = false;
                return Ok(());
            };
            state.timer_wait_armed = false;
            let due = state.take_due_sleeps(deadline);
            let should_cancel = state.sleep_heap.is_empty();
            (due, should_cancel)
        };

        for id in due {
            let (task, waker) = {
                let mut state = self.core.state.borrow_mut();
                let Some(slot) = state.sleep_slot_mut(id) else {
                    continue;
                };
                if !slot.active {
                    (None, None)
                } else {
                    slot.fired = true;
                    (slot.task.take(), slot.waker.take())
                }
            };
            if let Some(task_id) = task {
                self.enqueue_task_ready(task_id);
            } else if let Some(waker) = waker {
                waker.wake();
            }
        }

        if should_cancel {
            let timer = self.core.state.borrow().timer;
            let _ = zx_timer_cancel(timer);
        }
        self.refresh_dispatcher_timer()
    }

    fn on_signal_packet(&self, key: u64, observed: zx_signals_t) -> Result<(), zx_status_t> {
        let id = RegistrationId::new((key >> 32) as usize, key as u32);
        let (task, waker) = {
            let mut state = self.core.state.borrow_mut();
            let Some(slot) = state.registration_slot_mut(id) else {
                return Ok(());
            };
            if !slot.active {
                return Ok(());
            }
            slot.armed = false;
            slot.observed = Some(slot.observed.unwrap_or(0) | observed);
            (slot.task.take(), slot.waker.take())
        };
        if let Some(task_id) = task {
            self.enqueue_task_ready(task_id);
        } else if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }

    fn on_user_packet(&self, packet: zx_port_packet_t) {
        if packet.user.u64[0] != USER_WAKE_KIND_TASK {
            return;
        }
        let task_id = TaskId::from_raw(packet.key);
        let mut state = self.core.state.borrow_mut();
        let Some(slot) = state.task_slot_mut(task_id) else {
            return;
        };
        if slot.queued {
            return;
        }
        slot.queued = true;
        state.ready.push_back(task_id);
    }

    fn enqueue_task_ready(&self, task_id: TaskId) {
        let mut state = self.core.state.borrow_mut();
        let Some(slot) = state.task_slot_mut(task_id) else {
            return;
        };
        if slot.queued {
            return;
        }
        slot.queued = true;
        state.ready.push_back(task_id);
    }
}

impl SignalRegistration {
    /// Return the stable slot/generation id for this registration.
    pub fn id(&self) -> Option<RegistrationId> {
        self.id.get()
    }

    /// Cancel this registration.
    pub fn cancel(&self) -> Result<(), zx_status_t> {
        let Some(id) = self.id.take() else {
            return Ok(());
        };
        self.dispatcher.cancel_registration(id)
    }

    /// Wait for the next delivery on this registration without freeing the
    /// underlying slot.
    pub fn wait(&self) -> OnSignals<'_> {
        OnSignals { registration: self }
    }
}

impl Drop for SignalRegistration {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let _ = self.dispatcher.cancel_registration(id);
        }
    }
}

impl Future for OnSignals<'_> {
    type Output = Result<zx_signals_t, zx_status_t>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(id) = self.registration.id.get() else {
            return Poll::Ready(Err(ZX_ERR_CANCELED));
        };
        self.registration
            .dispatcher
            .poll_registration(id, cx.waker(), true)
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.dispatcher.cancel_sleep(id);
        }
    }
}

impl Future for Sleep {
    type Output = Result<(), zx_status_t>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(id) = self.id.get() else {
            return Poll::Ready(Err(ZX_ERR_CANCELED));
        };
        match self.dispatcher.poll_sleep(id, cx.waker()) {
            Poll::Ready(Ok(())) => {
                let _ = self.id.take();
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl Future for AsyncChannelRecv<'_> {
    type Output = Result<ChannelReadResult, zx_status_t>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        for _ in 0..FUTURE_POLL_BUDGET {
            let mut actual_bytes = 0u32;
            let mut actual_handles = 0u32;
            let status = zx_channel_read(
                self.handle,
                0,
                self.bytes.as_mut_ptr(),
                self.handles.as_mut_ptr(),
                self.bytes.len() as u32,
                self.handles.len() as u32,
                &mut actual_bytes,
                &mut actual_handles,
            );
            if status == ZX_OK {
                return Poll::Ready(Ok(ChannelReadResult {
                    actual_bytes,
                    actual_handles,
                }));
            }
            if status != ZX_ERR_SHOULD_WAIT {
                return Poll::Ready(Err(status));
            }

            if self.registration.is_none() {
                let registration = match self
                    .dispatcher
                    .register_signals(self.handle, ZX_CHANNEL_READABLE | ZX_CHANNEL_PEER_CLOSED)
                {
                    Ok(registration) => registration,
                    Err(status) => return Poll::Ready(Err(status)),
                };
                self.registration = Some(registration);
            }

            let Some(id) = self.registration.as_ref().and_then(SignalRegistration::id) else {
                return Poll::Ready(Err(ZX_ERR_CANCELED));
            };
            match self.dispatcher.poll_registration(id, cx.waker(), false) {
                Poll::Ready(Ok(_)) => continue,
                Poll::Ready(Err(status)) => return Poll::Ready(Err(status)),
                Poll::Pending => return Poll::Pending,
            }
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl Future for AsyncChannelCall<'_> {
    type Output = Result<ChannelReadResult, zx_status_t>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        for _ in 0..FUTURE_POLL_BUDGET {
            if !self.wrote_request {
                let status = self.write_status.take().unwrap_or_else(|| {
                    zx_channel_write(
                        self.handle,
                        0,
                        self.request_bytes.as_ptr(),
                        self.request_bytes.len() as u32,
                        core::ptr::null(),
                        0,
                    )
                });
                if status == ZX_OK {
                    self.wrote_request = true;
                    self.write_registration = None;
                    continue;
                }
                if status != ZX_ERR_SHOULD_WAIT {
                    return Poll::Ready(Err(status));
                }
                if self.write_registration.is_none() {
                    let registration = match self
                        .dispatcher
                        .register_signals(self.handle, ZX_CHANNEL_WRITABLE | ZX_CHANNEL_PEER_CLOSED)
                    {
                        Ok(registration) => registration,
                        Err(status) => return Poll::Ready(Err(status)),
                    };
                    self.write_registration = Some(registration);
                }
                let Some(id) = self
                    .write_registration
                    .as_ref()
                    .and_then(SignalRegistration::id)
                else {
                    return Poll::Ready(Err(ZX_ERR_CANCELED));
                };
                match self.dispatcher.poll_registration(id, cx.waker(), false) {
                    Poll::Ready(Ok(_)) => continue,
                    Poll::Ready(Err(status)) => return Poll::Ready(Err(status)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let mut actual_bytes = 0u32;
            let mut actual_handles = 0u32;
            let status = zx_channel_read(
                self.handle,
                0,
                self.reply_bytes.as_mut_ptr(),
                self.reply_handles.as_mut_ptr(),
                self.reply_bytes.len() as u32,
                self.reply_handles.len() as u32,
                &mut actual_bytes,
                &mut actual_handles,
            );
            if status == ZX_OK {
                return Poll::Ready(Ok(ChannelReadResult {
                    actual_bytes,
                    actual_handles,
                }));
            }
            if status != ZX_ERR_SHOULD_WAIT {
                return Poll::Ready(Err(status));
            }
            if self.read_registration.is_none() {
                let registration = match self
                    .dispatcher
                    .register_signals(self.handle, ZX_CHANNEL_READABLE | ZX_CHANNEL_PEER_CLOSED)
                {
                    Ok(registration) => registration,
                    Err(status) => return Poll::Ready(Err(status)),
                };
                self.read_registration = Some(registration);
            }
            let Some(id) = self
                .read_registration
                .as_ref()
                .and_then(SignalRegistration::id)
            else {
                return Poll::Ready(Err(ZX_ERR_CANCELED));
            };
            match self.dispatcher.poll_registration(id, cx.waker(), false) {
                Poll::Ready(Ok(_)) => continue,
                Poll::Ready(Err(status)) => return Poll::Ready(Err(status)),
                Poll::Pending => return Poll::Pending,
            }
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl Future for AsyncSocketReadiness {
    type Output = Result<zx_signals_t, zx_status_t>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.registration.is_none() {
            let registration = match self
                .dispatcher
                .register_signals(self.handle, self.mask | ZX_SOCKET_PEER_CLOSED)
            {
                Ok(registration) => registration,
                Err(status) => return Poll::Ready(Err(status)),
            };
            self.registration = Some(registration);
        }
        let Some(id) = self.registration.as_ref().and_then(SignalRegistration::id) else {
            return Poll::Ready(Err(ZX_ERR_CANCELED));
        };
        self.dispatcher.poll_registration(id, cx.waker(), false)
    }
}

impl DispatcherState {
    fn task_slot_mut(&mut self, id: TaskId) -> Option<&mut TaskSlot> {
        let slot = self.tasks.get_mut(id.slot as usize)?;
        (slot.generation == id.generation && slot.future.is_some()).then_some(slot)
    }

    fn registration_slot(&self, id: RegistrationId) -> Option<&SignalSlot> {
        let slot = self.registrations.get(id.slot as usize)?;
        (slot.generation == id.generation).then_some(slot)
    }

    fn registration_slot_mut(&mut self, id: RegistrationId) -> Option<&mut SignalSlot> {
        let slot = self.registrations.get_mut(id.slot as usize)?;
        (slot.generation == id.generation).then_some(slot)
    }

    fn sleep_slot_mut(&mut self, id: SleepId) -> Option<&mut SleepSlot> {
        let slot = self.sleeps.get_mut(id.slot as usize)?;
        (slot.generation == id.generation).then_some(slot)
    }

    fn discard_stale_sleep_entries(&mut self) {
        while let Some(top) = self.sleep_heap.peek().copied() {
            let Some(slot) = self.sleeps.get(top.id.slot as usize) else {
                let _ = self.sleep_heap.pop();
                continue;
            };
            if !slot.active || slot.generation != top.id.generation || slot.deadline != top.deadline
            {
                let _ = self.sleep_heap.pop();
                continue;
            }
            break;
        }
    }

    fn take_due_sleeps(&mut self, deadline: zx_time_t) -> Vec<SleepId> {
        let mut out = Vec::new();
        loop {
            self.discard_stale_sleep_entries();
            let Some(top) = self.sleep_heap.peek().copied() else {
                break;
            };
            if top.deadline > deadline {
                break;
            }
            let _ = self.sleep_heap.pop();
            let Some(slot) = self.sleeps.get(top.id.slot as usize) else {
                continue;
            };
            if !slot.active || slot.generation != top.id.generation {
                continue;
            }
            out.push(top.id);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{DispatcherState, HeapEntry, RegistrationId, SignalSlot, SleepId, SleepSlot};
    use crate::Reactor;
    use alloc::collections::{BinaryHeap, VecDeque};
    use alloc::vec;
    use alloc::vec::Vec;
    use libax::compat::handle::ZX_HANDLE_INVALID;

    #[test]
    fn timer_heap_discards_stale_entries() {
        let mut state = DispatcherState {
            reactor: Reactor::create()
                .err()
                .map_or(Reactor { port: 0 }, |_| Reactor { port: 0 }),
            timer: ZX_HANDLE_INVALID,
            timer_wait_armed: false,
            timer_deadline: None,
            tasks: Vec::new(),
            task_free: Vec::new(),
            ready: VecDeque::new(),
            registrations: Vec::new(),
            registration_free: Vec::new(),
            sleeps: vec![SleepSlot {
                generation: 2,
                active: true,
                deadline: 20,
                fired: false,
                task: None,
                waker: None,
            }],
            sleep_free: Vec::new(),
            sleep_heap: BinaryHeap::from([
                HeapEntry {
                    deadline: 10,
                    id: SleepId {
                        slot: 0,
                        generation: 1,
                    },
                },
                HeapEntry {
                    deadline: 20,
                    id: SleepId {
                        slot: 0,
                        generation: 2,
                    },
                },
            ]),
        };

        state.discard_stale_sleep_entries();
        assert_eq!(state.sleep_heap.peek().unwrap().deadline, 20);
    }

    #[test]
    fn registration_lookup_rejects_stale_generation() {
        let state = DispatcherState {
            reactor: Reactor { port: 0 },
            timer: ZX_HANDLE_INVALID,
            timer_wait_armed: false,
            timer_deadline: None,
            tasks: Vec::new(),
            task_free: Vec::new(),
            ready: VecDeque::new(),
            registrations: vec![SignalSlot {
                generation: 2,
                active: true,
                handle: 5,
                mask: 7,
                armed: false,
                observed: None,
                task: None,
                waker: None,
            }],
            registration_free: Vec::new(),
            sleeps: Vec::new(),
            sleep_free: Vec::new(),
            sleep_heap: BinaryHeap::new(),
        };

        assert!(
            state
                .registration_slot(RegistrationId {
                    slot: 0,
                    generation: 1
                })
                .is_none()
        );
        assert!(
            state
                .registration_slot(RegistrationId {
                    slot: 0,
                    generation: 2
                })
                .is_some()
        );
    }
}
