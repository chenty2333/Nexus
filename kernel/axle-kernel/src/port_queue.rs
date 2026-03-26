extern crate alloc;

use axle_core::{
    Packet, PacketKind, PacketQueue, PacketQueueError, PortError, PortState, PortTelemetrySnapshot,
    RevocationSet, Signals,
};
use axle_types::packet::{ZX_PKT_TYPE_SIGNAL_ONE, ZX_PKT_TYPE_USER};
use axle_types::status::ZX_OK;
use axle_types::{zx_packet_signal_t, zx_port_packet_t, zx_status_t};
use core::mem::size_of;

#[derive(Debug)]
pub(crate) struct KernelPortQueue {
    backing: crate::task::KernelVmoBacking,
    revocations: alloc::vec::Vec<RevocationSet>,
    head: usize,
    len: usize,
    capacity: usize,
}

impl KernelPortQueue {
    pub(crate) fn new(
        kernel: &mut crate::task::Kernel,
        capacity: usize,
    ) -> Result<Self, zx_status_t> {
        assert!(capacity > 0, "port_queue: capacity must be > 0");
        let bytes = capacity
            .checked_mul(size_of::<zx_port_packet_t>())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(axle_types::status::ZX_ERR_OUT_OF_RANGE)?;
        let backing = kernel.create_kernel_vmo_backing(bytes)?;
        Ok(Self {
            backing,
            revocations: alloc::vec![RevocationSet::none(); capacity],
            head: 0,
            len: 0,
            capacity,
        })
    }

    pub(crate) fn destroy(self, kernel: &mut crate::task::Kernel) -> Result<(), zx_status_t> {
        kernel.destroy_kernel_vmo_backing(self.backing)
    }

    fn slot_offset(&self, slot: usize) -> Option<usize> {
        slot.checked_mul(size_of::<zx_port_packet_t>())
    }

    fn tail_index(&self) -> usize {
        (self.head + self.len) % self.capacity
    }

    fn write_slot(&mut self, slot: usize, pkt: Packet) -> Result<(), PacketQueueError> {
        let Some(offset) = self.slot_offset(slot) else {
            return Err(PacketQueueError::Backend);
        };
        self.revocations[slot] = pkt.revocation;
        let raw = port_packet_from_core(pkt);
        crate::userspace::write_bootstrap_value(self.backing.base_paddr(), offset, &raw)
            .ok_or(PacketQueueError::Backend)
    }

    fn read_slot(&self, slot: usize) -> Option<Packet> {
        let offset = self.slot_offset(slot)?;
        let raw: zx_port_packet_t =
            crate::userspace::read_bootstrap_value(self.backing.base_paddr(), offset)?;
        packet_from_port_packet(raw, self.revocations.get(slot).copied().unwrap_or_default())
    }
}

impl PacketQueue for KernelPortQueue {
    fn len(&self) -> usize {
        self.len
    }

    fn push_back(&mut self, pkt: Packet) -> Result<(), PacketQueueError> {
        if self.len >= self.capacity {
            return Err(PacketQueueError::Full);
        }
        let tail = self.tail_index();
        self.write_slot(tail, pkt)?;
        self.len += 1;
        Ok(())
    }

    fn pop_front(&mut self) -> Option<Packet> {
        if self.len == 0 {
            return None;
        }
        let slot = self.head;
        let pkt = self.read_slot(slot)?;
        if let Some(revocation) = self.revocations.get_mut(slot) {
            *revocation = RevocationSet::none();
        }
        self.head = (self.head + 1) % self.capacity;
        self.len -= 1;
        Some(pkt)
    }

    fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&Packet) -> bool,
    {
        if self.len == 0 {
            return;
        }
        let mut retained = alloc::vec::Vec::with_capacity(self.len);
        for offset in 0..self.len {
            let slot = (self.head + offset) % self.capacity;
            if let Some(packet) = self.read_slot(slot)
                && keep(&packet)
            {
                retained.push(packet);
            }
            if let Some(revocation) = self.revocations.get_mut(slot) {
                *revocation = RevocationSet::none();
            }
        }
        self.head = 0;
        self.len = 0;
        for packet in retained {
            let _ = self.push_back(packet);
        }
    }
}

#[derive(Debug)]
pub(crate) struct KernelPort {
    state: PortState<KernelPortQueue>,
}

impl KernelPort {
    pub(crate) fn new(
        kernel: &mut crate::task::Kernel,
        capacity: usize,
        kernel_reserve: usize,
    ) -> Result<Self, zx_status_t> {
        let queue = KernelPortQueue::new(kernel, capacity)?;
        Ok(Self {
            state: PortState::with_queue(capacity, kernel_reserve, queue),
        })
    }

    pub(crate) fn destroy(self, kernel: &mut crate::task::Kernel) -> Result<(), zx_status_t> {
        self.state.into_queue().destroy(kernel)
    }

    pub(crate) fn signals(&self) -> Signals {
        self.state.signals()
    }

    pub(crate) fn queue_user(&mut self, pkt: Packet) -> Result<(), PortError> {
        self.state.queue_user(pkt)
    }

    pub(crate) fn pop(&mut self) -> Result<Packet, PortError> {
        self.state.pop()
    }

    pub(crate) fn queue_kernel(&mut self, pkt: Packet) -> Result<(), PortError> {
        self.state.queue_kernel(pkt)
    }

    pub(crate) fn drain_kernel_packets_where<F>(&mut self, keep: F) -> alloc::vec::Vec<Packet>
    where
        F: FnMut(&Packet) -> bool,
    {
        self.state.drain_kernel_packets_where(keep)
    }

    pub(crate) fn telemetry_snapshot(&self) -> PortTelemetrySnapshot {
        self.state.telemetry_snapshot()
    }
}

pub(crate) fn port_packet_from_core(pkt: Packet) -> zx_port_packet_t {
    match pkt.kind {
        PacketKind::User => zx_port_packet_t {
            key: pkt.key,
            type_: ZX_PKT_TYPE_USER,
            status: pkt.status,
            user: axle_types::zx_packet_user_t { u64: pkt.user },
        },
        PacketKind::Signal => {
            let sig = zx_packet_signal_t {
                trigger: pkt.trigger.bits(),
                observed: pkt.observed.bits(),
                count: pkt.count as u64,
                timestamp: pkt.timestamp,
                reserved1: 0,
            };
            zx_port_packet_t {
                key: pkt.key,
                type_: ZX_PKT_TYPE_SIGNAL_ONE,
                status: ZX_OK,
                user: sig.to_user(),
            }
        }
    }
}

fn packet_from_port_packet(raw: zx_port_packet_t, revocation: RevocationSet) -> Option<Packet> {
    match raw.type_ {
        ZX_PKT_TYPE_USER => Some(Packet::user_with_data(raw.key, raw.status, raw.user.u64)),
        ZX_PKT_TYPE_SIGNAL_ONE => {
            let sig = zx_packet_signal_t::from_user(raw.user);
            Some(Packet::signal_with_revocation(
                raw.key,
                0.into(),
                Signals::from_bits(sig.trigger),
                Signals::from_bits(sig.observed),
                u32::try_from(sig.count).ok()?,
                sig.timestamp,
                revocation,
            ))
        }
        _ => None,
    }
}
