//! Observer registry for `wait_async` / reactor semantics.
//!
//! This layer owns:
//! - async wait registration uniqueness
//! - reverse indexing by waitable id
//! - one-shot delivery
//! - edge-triggered transitions
//! - pending overflow merge state
//!
//! Ports remain pure packet queues; the registry decides which port should
//! receive which signal packet and when.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::port::{Packet, PortError, PortKey, WaitAsyncOptions, WaitAsyncTimestamp, WaitableId};
use crate::signals::Signals;
use crate::timer::Time;

/// Identifier of one observing port.
pub type ObserverPortId = u64;

/// One async wait registration request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitAsyncRegistration {
    /// Destination port that will receive the packet.
    pub port: ObserverPortId,
    /// Waitable object being observed.
    pub waitable: WaitableId,
    /// User packet key.
    pub key: PortKey,
    /// Signal mask watched by this observer.
    pub watched: Signals,
    /// Delivery options.
    pub options: WaitAsyncOptions,
}

#[derive(Clone, Copy, Debug)]
struct PendingState {
    count: u32,
    trigger: Signals,
    observed: Signals,
    timestamp: Time,
}

#[derive(Clone, Copy, Debug)]
struct Observer {
    watched: Signals,
    options: WaitAsyncOptions,
    last_satisfied: bool,
    pending: Option<PendingState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ObserverRegistration {
    waitable: WaitableId,
    port: ObserverPortId,
    key: PortKey,
}

impl ObserverRegistration {
    const fn new(waitable: WaitableId, port: ObserverPortId, key: PortKey) -> Self {
        Self {
            waitable,
            port,
            key,
        }
    }

    const fn min_for_waitable(waitable: WaitableId) -> Self {
        Self::new(waitable, 0, 0)
    }

    const fn max_for_waitable(waitable: WaitableId) -> Self {
        Self::new(waitable, u64::MAX, u64::MAX)
    }

    const fn min_for_port_pair(waitable: WaitableId, port: ObserverPortId) -> Self {
        Self::new(waitable, port, 0)
    }

    const fn max_for_port_pair(waitable: WaitableId, port: ObserverPortId) -> Self {
        Self::new(waitable, port, u64::MAX)
    }
}

/// Host-testable async wait registry.
#[derive(Debug, Default)]
pub struct ObserverRegistry {
    observers: BTreeMap<ObserverRegistration, Observer>,
    waitables_by_port: BTreeMap<ObserverPortId, BTreeSet<WaitableId>>,
    pending_order_by_port: BTreeMap<ObserverPortId, VecDeque<ObserverRegistration>>,
}

impl ObserverRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an async wait on `waitable` targeting `port`.
    ///
    /// The `try_queue` callback should enqueue one kernel-generated signal packet
    /// into the destination port and return whether it was accepted.
    pub fn wait_async<F>(
        &mut self,
        registration: WaitAsyncRegistration,
        current_signals: Signals,
        current_time: Time,
        mut try_queue: F,
    ) -> Result<(), PortError>
    where
        F: FnMut(ObserverPortId, Packet) -> bool,
    {
        let reg =
            ObserverRegistration::new(registration.waitable, registration.port, registration.key);
        if self.observers.contains_key(&reg) {
            return Err(PortError::AlreadyExists);
        }

        let satisfied = current_signals.intersects(registration.watched);
        self.observers.insert(
            reg,
            Observer {
                watched: registration.watched,
                options: registration.options,
                last_satisfied: satisfied,
                pending: None,
            },
        );
        self.note_port_waitable(registration.port, registration.waitable);

        if satisfied && !registration.options.edge_triggered {
            self.enqueue_or_pending(
                reg,
                registration.watched,
                current_signals,
                current_time,
                &mut try_queue,
            );
        }

        Ok(())
    }

    /// Cancel one async wait.
    pub fn cancel(
        &mut self,
        port: ObserverPortId,
        waitable: WaitableId,
        key: PortKey,
    ) -> Result<(), PortError> {
        let reg = ObserverRegistration::new(waitable, port, key);
        if self.remove_observer(reg).is_none() {
            return Err(PortError::NotFound);
        }
        Ok(())
    }

    /// Deliver one signal transition to the observers of `waitable`.
    pub fn on_signals_changed<F>(
        &mut self,
        waitable: WaitableId,
        current: Signals,
        now: Time,
        mut try_queue: F,
    ) -> Vec<ObserverPortId>
    where
        F: FnMut(ObserverPortId, Packet) -> bool,
    {
        let mut changed_ports = BTreeSet::new();
        let keys: Vec<ObserverRegistration> = self
            .observers
            .range(
                ObserverRegistration::min_for_waitable(waitable)
                    ..=ObserverRegistration::max_for_waitable(waitable),
            )
            .map(|(k, _)| *k)
            .collect();

        for key in keys {
            let fire = {
                let Some(observer) = self.observers.get_mut(&key) else {
                    continue;
                };

                let satisfied = current.intersects(observer.watched);
                let fire = if observer.options.edge_triggered {
                    !observer.last_satisfied && satisfied
                } else {
                    satisfied
                };
                observer.last_satisfied = satisfied;
                fire
            };

            if fire {
                let trigger = self
                    .observers
                    .get(&key)
                    .map(|observer| observer.watched)
                    .unwrap_or(Signals::NONE);
                if self.enqueue_or_pending(key, trigger, current, now, &mut try_queue) {
                    changed_ports.insert(key.port);
                }
            }
        }
        changed_ports.into_iter().collect()
    }

    /// Attempt to flush pending packets for `port` after queue space becomes available.
    pub fn flush_port<F>(&mut self, port: ObserverPortId, mut try_queue: F)
    where
        F: FnMut(ObserverPortId, Packet) -> bool,
    {
        while let Some(reg) = self
            .pending_order_by_port
            .get_mut(&port)
            .and_then(VecDeque::pop_front)
        {
            let Some(observer) = self.observers.get(&reg).copied() else {
                continue;
            };
            let Some(pending) = observer.pending else {
                continue;
            };

            let pkt = Packet::signal(
                reg.key,
                reg.waitable,
                pending.trigger,
                pending.observed,
                pending.count,
                pending.timestamp,
            );
            if !try_queue(port, pkt) {
                if let Some(queue) = self.pending_order_by_port.get_mut(&port) {
                    queue.push_front(reg);
                }
                break;
            }

            let _ = self.remove_observer(reg);
        }

        if self
            .pending_order_by_port
            .get(&port)
            .is_some_and(VecDeque::is_empty)
        {
            let _ = self.pending_order_by_port.remove(&port);
        }
    }

    /// Remove every observer attached to one port.
    pub fn remove_port(&mut self, port: ObserverPortId) {
        let Some(waitables) = self.waitables_by_port.remove(&port) else {
            let _ = self.pending_order_by_port.remove(&port);
            return;
        };

        for waitable in waitables {
            let regs: Vec<ObserverRegistration> = self
                .observers
                .range(
                    ObserverRegistration::min_for_port_pair(waitable, port)
                        ..=ObserverRegistration::max_for_port_pair(waitable, port),
                )
                .map(|(reg, _)| *reg)
                .collect();
            for reg in regs {
                let _ = self.observers.remove(&reg);
            }
        }

        let _ = self.pending_order_by_port.remove(&port);
    }

    /// Remove every observer attached to one waitable object.
    pub fn remove_waitable(&mut self, waitable: WaitableId) {
        let regs: Vec<ObserverRegistration> = self
            .observers
            .range(
                ObserverRegistration::min_for_waitable(waitable)
                    ..=ObserverRegistration::max_for_waitable(waitable),
            )
            .map(|(reg, _)| *reg)
            .collect();
        for reg in regs {
            let _ = self.remove_observer(reg);
        }
    }

    fn note_port_waitable(&mut self, port: ObserverPortId, waitable: WaitableId) {
        self.waitables_by_port
            .entry(port)
            .or_default()
            .insert(waitable);
    }

    fn maybe_forget_port_waitable(&mut self, port: ObserverPortId, waitable: WaitableId) {
        let still_observing = self
            .observers
            .range(
                ObserverRegistration::min_for_port_pair(waitable, port)
                    ..=ObserverRegistration::max_for_port_pair(waitable, port),
            )
            .next()
            .is_some();
        if still_observing {
            return;
        }

        if let Some(waitables) = self.waitables_by_port.get_mut(&port) {
            let _ = waitables.remove(&waitable);
            if waitables.is_empty() {
                let _ = self.waitables_by_port.remove(&port);
            }
        }
    }

    fn remove_observer(&mut self, reg: ObserverRegistration) -> Option<Observer> {
        let removed = self.observers.remove(&reg)?;
        self.maybe_forget_port_waitable(reg.port, reg.waitable);
        Some(removed)
    }

    fn enqueue_or_pending<F>(
        &mut self,
        reg: ObserverRegistration,
        trigger: Signals,
        current: Signals,
        now: Time,
        try_queue: &mut F,
    ) -> bool
    where
        F: FnMut(ObserverPortId, Packet) -> bool,
    {
        let timestamp = self
            .observers
            .get(&reg)
            .map(|observer| match observer.options.timestamp {
                WaitAsyncTimestamp::None => 0,
                WaitAsyncTimestamp::Monotonic | WaitAsyncTimestamp::Boot => now,
            })
            .unwrap_or(0);

        let pkt = Packet::signal(reg.key, reg.waitable, trigger, current, 1, timestamp);
        if try_queue(reg.port, pkt) {
            let _ = self.remove_observer(reg);
            return true;
        }

        let Some(observer) = self.observers.get_mut(&reg) else {
            return false;
        };

        match &mut observer.pending {
            None => {
                observer.pending = Some(PendingState {
                    count: 1,
                    trigger,
                    observed: current,
                    timestamp,
                });
                self.pending_order_by_port
                    .entry(reg.port)
                    .or_default()
                    .push_back(reg);
            }
            Some(pending) => {
                pending.count = pending.count.saturating_add(1);
                pending.observed = pending.observed | current;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::{PacketKind, Port};

    fn queue(port: &mut Port, packet: Packet) -> bool {
        port.queue_kernel(packet).is_ok()
    }

    #[test]
    fn immediate_level_registration_queues_once() {
        let mut registry = ObserverRegistry::new();
        let mut port = Port::new(4, 2);

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: 10,
                    waitable: 42,
                    key: 7,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::CHANNEL_READABLE,
                12,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();

        let pkt = port.pop().unwrap();
        assert_eq!(pkt.kind, PacketKind::Signal);
        assert_eq!(pkt.waitable, 42);
        assert_eq!(pkt.key, 7);
        assert_eq!(port.pop(), Err(PortError::ShouldWait));
    }

    #[test]
    fn pending_merge_and_flush_are_per_port() {
        let mut registry = ObserverRegistry::new();
        let mut port = Port::new(1, 1);

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: 10,
                    waitable: 1,
                    key: 10,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                100,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();
        registry.on_signals_changed(1, Signals::CHANNEL_READABLE, 101, |_, packet| {
            queue(&mut port, packet)
        });
        assert_eq!(port.len(), 1);

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: 10,
                    waitable: 1,
                    key: 11,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions {
                        edge_triggered: false,
                        timestamp: WaitAsyncTimestamp::Monotonic,
                    },
                },
                Signals::NONE,
                200,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();
        registry.on_signals_changed(1, Signals::CHANNEL_READABLE, 201, |_, packet| {
            queue(&mut port, packet)
        });
        registry.on_signals_changed(1, Signals::CHANNEL_READABLE, 202, |_, packet| {
            queue(&mut port, packet)
        });

        let first = port.pop().unwrap();
        assert_eq!(first.key, 10);
        registry.flush_port(10, |_, packet| queue(&mut port, packet));
        let merged = port.pop().unwrap();
        assert_eq!(merged.kind, PacketKind::Signal);
        assert_eq!(merged.key, 11);
        assert_eq!(merged.count, 2);
        assert_eq!(merged.timestamp, 201);
        assert!(merged.observed.intersects(Signals::CHANNEL_READABLE));
    }

    #[test]
    fn edge_triggered_wait_requires_false_to_true_transition() {
        let mut registry = ObserverRegistry::new();
        let mut port = Port::new(4, 1);

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: 10,
                    waitable: 1,
                    key: 33,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions {
                        edge_triggered: true,
                        timestamp: WaitAsyncTimestamp::None,
                    },
                },
                Signals::CHANNEL_READABLE,
                300,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();
        assert_eq!(port.pop(), Err(PortError::ShouldWait));

        registry.on_signals_changed(1, Signals::NONE, 301, |_, packet| queue(&mut port, packet));
        registry.on_signals_changed(1, Signals::CHANNEL_READABLE, 302, |_, packet| {
            queue(&mut port, packet)
        });

        let pkt = port.pop().unwrap();
        assert_eq!(pkt.key, 33);
        assert_eq!(pkt.timestamp, 0);
        assert_eq!(port.pop(), Err(PortError::ShouldWait));
    }

    #[test]
    fn duplicate_registration_is_rejected_per_port_waitable_key() {
        let mut registry = ObserverRegistry::new();
        let mut port = Port::new(4, 1);

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: 10,
                    waitable: 5,
                    key: 9,
                    watched: Signals::TIMER_SIGNALED,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                0,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();
        assert_eq!(
            registry.wait_async(
                WaitAsyncRegistration {
                    port: 10,
                    waitable: 5,
                    key: 9,
                    watched: Signals::TIMER_SIGNALED,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                0,
                |_, packet| queue(&mut port, packet),
            ),
            Err(PortError::AlreadyExists)
        );
    }

    #[test]
    fn remove_port_drops_all_registrations() {
        let mut registry = ObserverRegistry::new();
        let mut port = Port::new(4, 1);

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: 10,
                    waitable: 7,
                    key: 1,
                    watched: Signals::TIMER_SIGNALED,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                0,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();
        registry.remove_port(10);
        registry.on_signals_changed(7, Signals::TIMER_SIGNALED, 1, |_, packet| {
            queue(&mut port, packet)
        });
        assert_eq!(port.pop(), Err(PortError::ShouldWait));
    }
}
