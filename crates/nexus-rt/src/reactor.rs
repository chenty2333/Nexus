use libax::compat::packet::{ZX_PKT_TYPE_SIGNAL_ONE, ZX_PKT_TYPE_USER};
use libax::compat::status::ZX_OK;
use libax::compat::{
    zx_handle_t, zx_object_wait_async, zx_packet_signal_t, zx_port_create, zx_port_packet_t,
    zx_port_wait, zx_signals_t, zx_status_t, zx_time_t,
};

/// A decoded signal packet delivered through a reactor port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalEvent {
    /// Port packet key selected when the async wait was armed.
    pub key: u64,
    /// Packet status field.
    pub status: zx_status_t,
    /// Trigger mask recorded by the kernel.
    pub trigger: zx_signals_t,
    /// Observed signal mask at delivery time.
    pub observed: zx_signals_t,
    /// Merge count for the observer.
    pub count: u64,
    /// Optional timestamp payload.
    pub timestamp: zx_time_t,
}

/// One event drained from the reactor port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// User-queued packet.
    User(zx_port_packet_t),
    /// Signal packet emitted by `zx_object_wait_async`.
    Signal(SignalEvent),
    /// Any packet type the current runtime does not decode yet.
    Unknown(zx_port_packet_t),
}

impl Event {
    /// Decode a raw port packet into the runtime event shape.
    pub fn from_port_packet(packet: zx_port_packet_t) -> Self {
        match packet.type_ {
            ZX_PKT_TYPE_USER => Self::User(packet),
            ZX_PKT_TYPE_SIGNAL_ONE => {
                let signal = zx_packet_signal_t::from_user(packet.user);
                Self::Signal(SignalEvent {
                    key: packet.key,
                    status: packet.status,
                    trigger: signal.trigger,
                    observed: signal.observed,
                    count: signal.count,
                    timestamp: signal.timestamp,
                })
            }
            _ => Self::Unknown(packet),
        }
    }

    /// Return the packet key associated with this event.
    pub const fn key(&self) -> u64 {
        match self {
            Self::User(packet) | Self::Unknown(packet) => packet.key,
            Self::Signal(signal) => signal.key,
        }
    }

    /// Return the raw packet type value.
    pub const fn packet_type(&self) -> u32 {
        match self {
            Self::User(packet) | Self::Unknown(packet) => packet.type_,
            Self::Signal(_) => ZX_PKT_TYPE_SIGNAL_ONE,
        }
    }

    /// Return observed signals when this is a signal event.
    pub const fn observed_signals(&self) -> Option<zx_signals_t> {
        match self {
            Self::Signal(signal) => Some(signal.observed),
            Self::User(_) | Self::Unknown(_) => None,
        }
    }
}

/// Minimal single-thread reactor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reactor {
    pub(crate) port: zx_handle_t,
}

impl Reactor {
    /// Create a reactor with one owned port.
    pub fn create() -> Result<Self, zx_status_t> {
        let mut port = 0;
        let status = zx_port_create(0, &mut port);
        if status == ZX_OK {
            Ok(Self { port })
        } else {
            Err(status)
        }
    }

    /// Return the backing port handle.
    pub const fn port_handle(&self) -> zx_handle_t {
        self.port
    }

    /// Register a one-shot async wait routed to this reactor's port.
    pub fn wait_async(
        &self,
        handle: zx_handle_t,
        key: u64,
        signals: zx_signals_t,
        options: u32,
    ) -> Result<(), zx_status_t> {
        let status = zx_object_wait_async(handle, self.port, key, signals, options);
        if status == ZX_OK { Ok(()) } else { Err(status) }
    }

    /// Wait for the next event until `deadline`.
    pub fn wait_until(&self, deadline: zx_time_t) -> Result<Event, zx_status_t> {
        let mut packet = zx_port_packet_t::default();
        let status = zx_port_wait(self.port, deadline, &mut packet);
        if status == ZX_OK {
            Ok(Event::from_port_packet(packet))
        } else {
            Err(status)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, SignalEvent};
    use libax::compat::packet::{ZX_PKT_TYPE_SIGNAL_ONE, ZX_PKT_TYPE_USER};
    use libax::compat::{zx_packet_signal_t, zx_packet_user_t, zx_port_packet_t};

    #[test]
    fn decodes_signal_packets() {
        let packet = zx_port_packet_t {
            key: 0x55,
            type_: ZX_PKT_TYPE_SIGNAL_ONE,
            status: -9,
            user: zx_packet_signal_t {
                trigger: 0x1,
                observed: 0x5,
                count: 3,
                timestamp: 99,
                reserved1: 0,
            }
            .to_user(),
        };

        assert_eq!(
            Event::from_port_packet(packet),
            Event::Signal(SignalEvent {
                key: 0x55,
                status: -9,
                trigger: 0x1,
                observed: 0x5,
                count: 3,
                timestamp: 99,
            })
        );
    }

    #[test]
    fn leaves_user_packets_unchanged() {
        let packet = zx_port_packet_t {
            key: 7,
            type_: ZX_PKT_TYPE_USER,
            status: 0,
            user: zx_packet_user_t { u64: [1, 2, 3, 4] },
        };

        assert_eq!(Event::from_port_packet(packet), Event::User(packet));
    }
}
