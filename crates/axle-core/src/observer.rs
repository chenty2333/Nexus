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

use crate::capability::ObjectKey;
use crate::port::{Packet, PortError, PortKey, WaitAsyncOptions, WaitAsyncTimestamp, WaitableId};
use crate::revocation::{DeferredRevocationIndex, RevocationGroupId, RevocationSet};
use crate::signals::Signals;
use crate::timer::Time;

/// Identifier of one observing port.
pub type ObserverPortId = ObjectKey;

/// One async wait registration request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitAsyncRegistration {
    /// Destination port that will receive the packet.
    pub port: ObserverPortId,
    /// Waitable object being observed.
    pub waitable: WaitableId,
    /// Revocation provenance carried by the handles that created this deferred observer.
    pub revocation: RevocationSet,
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
    revocation: RevocationSet,
    last_satisfied: bool,
    pending: Option<PendingState>,
}

/// Per-port async-wait overflow/flush telemetry snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObserverPortTelemetrySnapshot {
    /// Registrations currently pending on this port because queue delivery overflowed.
    pub pending_current: u32,
    /// Peak number of simultaneously pending registrations on this port.
    pub pending_peak: u32,
    /// Number of first-time pending registrations on this port.
    pub pending_new_count: u64,
    /// Number of merges into an already pending registration on this port.
    pub pending_merge_count: u64,
    /// Number of pending registrations later delivered by `flush_port`.
    pub flush_delivered_count: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct ObserverPortTelemetry {
    pending_current: u32,
    pending_peak: u32,
    pending_new_count: u64,
    pending_merge_count: u64,
    flush_delivered_count: u64,
}

impl ObserverPortTelemetry {
    fn snapshot(self) -> ObserverPortTelemetrySnapshot {
        ObserverPortTelemetrySnapshot {
            pending_current: self.pending_current,
            pending_peak: self.pending_peak,
            pending_new_count: self.pending_new_count,
            pending_merge_count: self.pending_merge_count,
            flush_delivered_count: self.flush_delivered_count,
        }
    }
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
        Self::new(waitable, ObjectKey::INVALID, 0)
    }

    const fn max_for_waitable(waitable: WaitableId) -> Self {
        Self::new(waitable, ObjectKey::new(u64::MAX, u32::MAX), u64::MAX)
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
    telemetry_by_port: BTreeMap<ObserverPortId, ObserverPortTelemetry>,
    revocation_index: DeferredRevocationIndex<ObserverRegistration>,
}

impl ObserverRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Telemetry snapshot for one observing port.
    pub fn port_telemetry_snapshot(&self, port: ObserverPortId) -> ObserverPortTelemetrySnapshot {
        self.telemetry_by_port
            .get(&port)
            .copied()
            .unwrap_or_default()
            .snapshot()
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
                revocation: registration.revocation,
                last_satisfied: satisfied,
                pending: None,
            },
        );
        self.revocation_index.insert(reg, registration.revocation);
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

            let pkt = Packet::signal_with_revocation(
                reg.key,
                reg.waitable,
                pending.trigger,
                pending.observed,
                pending.count,
                pending.timestamp,
                observer.revocation,
            );
            if !try_queue(port, pkt) {
                if let Some(queue) = self.pending_order_by_port.get_mut(&port) {
                    queue.push_front(reg);
                }
                break;
            }

            if let Some(telemetry) = self.telemetry_by_port.get_mut(&port) {
                telemetry.flush_delivered_count = telemetry.flush_delivered_count.saturating_add(1);
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
            let _ = self.telemetry_by_port.remove(&port);
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
                let _ = self.remove_observer(reg);
            }
        }

        let _ = self.pending_order_by_port.remove(&port);
        let _ = self.telemetry_by_port.remove(&port);
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

    /// Remove every observer that was created through one revoked group epoch.
    pub fn remove_revoked_group(
        &mut self,
        group: RevocationGroupId,
        generation: u64,
        current_epoch: u64,
    ) {
        let regs = self.revocation_index.candidates(group, generation);
        for reg in regs {
            let revoked = self.observers.get(&reg).is_some_and(|observer| {
                observer
                    .revocation
                    .contains_revoked(group, generation, current_epoch)
            });
            if revoked {
                let _ = self.remove_observer(reg);
            }
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

    fn remove_pending_registration(&mut self, reg: ObserverRegistration) {
        let should_remove_port = if let Some(queue) = self.pending_order_by_port.get_mut(&reg.port)
        {
            queue.retain(|queued| *queued != reg);
            queue.is_empty()
        } else {
            false
        };

        if should_remove_port {
            let _ = self.pending_order_by_port.remove(&reg.port);
        }
    }

    fn remove_observer(&mut self, reg: ObserverRegistration) -> Option<Observer> {
        let removed = self.observers.remove(&reg)?;
        self.revocation_index.remove(reg, removed.revocation);
        if removed.pending.is_some() {
            if let Some(telemetry) = self.telemetry_by_port.get_mut(&reg.port) {
                telemetry.pending_current = telemetry.pending_current.saturating_sub(1);
            }
            self.remove_pending_registration(reg);
        }
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
        let (timestamp, revocation) = self
            .observers
            .get(&reg)
            .map(|observer| {
                let timestamp = match observer.options.timestamp {
                    WaitAsyncTimestamp::None => 0,
                    WaitAsyncTimestamp::Monotonic | WaitAsyncTimestamp::Boot => now,
                };
                (timestamp, observer.revocation)
            })
            .unwrap_or((0, RevocationSet::none()));

        let pkt = Packet::signal_with_revocation(
            reg.key,
            reg.waitable,
            trigger,
            current,
            1,
            timestamp,
            revocation,
        );
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
                let telemetry = self.telemetry_by_port.entry(reg.port).or_default();
                telemetry.pending_new_count = telemetry.pending_new_count.saturating_add(1);
                telemetry.pending_current = telemetry.pending_current.saturating_add(1);
                telemetry.pending_peak = telemetry.pending_peak.max(telemetry.pending_current);
                self.pending_order_by_port
                    .entry(reg.port)
                    .or_default()
                    .push_back(reg);
            }
            Some(pending) => {
                // Merge into an existing pending entry: bump the count and
                // OR-merge the observed signals.  The `timestamp` field
                // intentionally retains the value captured when the entry was
                // first created (i.e. the time of the first trigger that could
                // not be delivered).  This matches the contract that the
                // delivered timestamp reflects the *earliest* firing event,
                // allowing the consumer to reconstruct a lower-bound latency.
                let telemetry = self.telemetry_by_port.entry(reg.port).or_default();
                telemetry.pending_merge_count = telemetry.pending_merge_count.saturating_add(1);
                pending.count = pending.count.saturating_add(1);
                pending.observed = pending.observed | current;
            }
        }
        false
    }

    #[cfg(test)]
    fn pending_count_for_port(&self, port: ObserverPortId) -> usize {
        self.pending_order_by_port
            .get(&port)
            .map_or(0, VecDeque::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::{PacketKind, Port};
    use crate::revocation::RevocationManager;

    fn key(id: u64) -> ObjectKey {
        id.into()
    }

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
                    port: key(10),
                    waitable: key(42),
                    revocation: RevocationSet::none(),
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
        assert_eq!(pkt.waitable, key(42));
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
                    port: key(10),
                    waitable: key(1),
                    revocation: RevocationSet::none(),
                    key: 10,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                100,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();
        registry.on_signals_changed(key(1), Signals::CHANNEL_READABLE, 101, |_, packet| {
            queue(&mut port, packet)
        });
        assert_eq!(port.len(), 1);

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: key(10),
                    waitable: key(1),
                    revocation: RevocationSet::none(),
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
        registry.on_signals_changed(key(1), Signals::CHANNEL_READABLE, 201, |_, packet| {
            queue(&mut port, packet)
        });
        registry.on_signals_changed(key(1), Signals::CHANNEL_READABLE, 202, |_, packet| {
            queue(&mut port, packet)
        });

        let first = port.pop().unwrap();
        assert_eq!(first.key, 10);
        registry.flush_port(key(10), |_, packet| queue(&mut port, packet));
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
                    port: key(10),
                    waitable: key(1),
                    revocation: RevocationSet::none(),
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

        registry.on_signals_changed(key(1), Signals::NONE, 301, |_, packet| {
            queue(&mut port, packet)
        });
        registry.on_signals_changed(key(1), Signals::CHANNEL_READABLE, 302, |_, packet| {
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
                    port: key(10),
                    waitable: key(5),
                    revocation: RevocationSet::none(),
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
                    port: key(10),
                    waitable: key(5),
                    revocation: RevocationSet::none(),
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
                    port: key(10),
                    waitable: key(7),
                    revocation: RevocationSet::none(),
                    key: 1,
                    watched: Signals::TIMER_SIGNALED,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                0,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();
        registry.remove_port(key(10));
        registry.on_signals_changed(key(7), Signals::TIMER_SIGNALED, 1, |_, packet| {
            queue(&mut port, packet)
        });
        assert_eq!(port.pop(), Err(PortError::ShouldWait));
    }

    #[test]
    fn cancel_pending_registration_cleans_pending_queue() {
        let mut registry = ObserverRegistry::new();
        let mut port = Port::new(1, 1);

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: key(10),
                    waitable: key(1),
                    revocation: RevocationSet::none(),
                    key: 10,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                10,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();
        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: key(10),
                    waitable: key(2),
                    revocation: RevocationSet::none(),
                    key: 11,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                11,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();

        registry.on_signals_changed(key(1), Signals::CHANNEL_READABLE, 12, |_, packet| {
            queue(&mut port, packet)
        });
        registry.on_signals_changed(key(2), Signals::CHANNEL_READABLE, 13, |_, packet| {
            queue(&mut port, packet)
        });
        assert_eq!(registry.pending_count_for_port(key(10)), 1);

        registry.cancel(key(10), key(2), 11).unwrap();
        assert_eq!(registry.pending_count_for_port(key(10)), 0);
    }

    #[test]
    fn remove_waitable_cleans_pending_queue() {
        let mut registry = ObserverRegistry::new();
        let mut port = Port::new(1, 1);

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: key(10),
                    waitable: key(1),
                    revocation: RevocationSet::none(),
                    key: 10,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                10,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();
        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: key(10),
                    waitable: key(2),
                    revocation: RevocationSet::none(),
                    key: 11,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                11,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();

        registry.on_signals_changed(key(1), Signals::CHANNEL_READABLE, 12, |_, packet| {
            queue(&mut port, packet)
        });
        registry.on_signals_changed(key(2), Signals::CHANNEL_READABLE, 13, |_, packet| {
            queue(&mut port, packet)
        });
        assert_eq!(registry.pending_count_for_port(key(10)), 1);

        registry.remove_waitable(key(2));
        assert_eq!(registry.pending_count_for_port(key(10)), 0);
    }

    #[test]
    fn remove_port_cleans_pending_queue() {
        let mut registry = ObserverRegistry::new();
        let mut port = Port::new(1, 1);

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: key(10),
                    waitable: key(1),
                    revocation: RevocationSet::none(),
                    key: 10,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                10,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();
        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: key(10),
                    waitable: key(2),
                    revocation: RevocationSet::none(),
                    key: 11,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                11,
                |_, packet| queue(&mut port, packet),
            )
            .unwrap();

        registry.on_signals_changed(key(1), Signals::CHANNEL_READABLE, 12, |_, packet| {
            queue(&mut port, packet)
        });
        registry.on_signals_changed(key(2), Signals::CHANNEL_READABLE, 13, |_, packet| {
            queue(&mut port, packet)
        });
        assert_eq!(registry.pending_count_for_port(key(10)), 1);

        registry.remove_port(key(10));
        assert_eq!(registry.pending_count_for_port(key(10)), 0);
    }

    #[test]
    fn remove_revoked_group_drops_only_matching_observers() {
        let mut registry = ObserverRegistry::new();
        let mut mgr = RevocationManager::new();
        let waitable_group = mgr.create_group();
        let port_group = mgr.create_group();
        let live_waitable = mgr.snapshot(waitable_group).unwrap();
        let live_port = mgr.snapshot(port_group).unwrap();

        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: key(10),
                    waitable: key(1),
                    revocation: RevocationSet::one(Some(live_waitable)),
                    key: 1,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                0,
                |_, _| true,
            )
            .unwrap();
        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: key(10),
                    waitable: key(2),
                    revocation: RevocationSet::one(Some(live_port)),
                    key: 2,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                0,
                |_, _| true,
            )
            .unwrap();
        registry
            .wait_async(
                WaitAsyncRegistration {
                    port: key(10),
                    waitable: key(3),
                    revocation: RevocationSet::none(),
                    key: 3,
                    watched: Signals::CHANNEL_READABLE,
                    options: WaitAsyncOptions::default(),
                },
                Signals::NONE,
                0,
                |_, _| true,
            )
            .unwrap();

        mgr.revoke(waitable_group).unwrap();
        registry.remove_revoked_group(
            waitable_group.id(),
            waitable_group.generation(),
            mgr.epoch_of(waitable_group.id()).unwrap(),
        );
        assert_eq!(
            registry.cancel(key(10), key(1), 1),
            Err(PortError::NotFound)
        );
        assert_eq!(registry.cancel(key(10), key(2), 2), Ok(()));
        assert_eq!(registry.cancel(key(10), key(3), 3), Ok(()));
    }
}
