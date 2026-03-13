use libax::packet::{AX_PKT_TYPE_SIGNAL_ONE, AX_PKT_TYPE_USER};
use libax::status::AX_OK;
use libax::{
    ax_handle_t, ax_object_wait_async, ax_packet_signal_t, ax_port_create, ax_port_packet_t,
    ax_port_wait, ax_signals_t, ax_status_t, ax_time_t,
};

/// A decoded signal packet delivered through a reactor port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalEvent {
    /// Port packet key selected when the async wait was armed.
    pub key: u64,
    /// Packet status field.
    pub status: ax_status_t,
    /// Trigger mask recorded by the kernel.
    pub trigger: ax_signals_t,
    /// Observed signal mask at delivery time.
    pub observed: ax_signals_t,
    /// Merge count for the observer.
    pub count: u64,
    /// Optional timestamp payload.
    pub timestamp: ax_time_t,
}

/// One event drained from the reactor port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// User-queued packet.
    User(ax_port_packet_t),
    /// Signal packet emitted by `ax_object_wait_async`.
    Signal(SignalEvent),
    /// Any packet type the current runtime does not decode yet.
    Unknown(ax_port_packet_t),
}

impl Event {
    /// Decode a raw port packet into the runtime event shape.
    pub fn from_port_packet(packet: ax_port_packet_t) -> Self {
        match packet.type_ {
            AX_PKT_TYPE_USER => Self::User(packet),
            AX_PKT_TYPE_SIGNAL_ONE => {
                let signal = ax_packet_signal_t::from_user(packet.user);
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
            Self::Signal(_) => AX_PKT_TYPE_SIGNAL_ONE,
        }
    }

    /// Return observed signals when this is a signal event.
    pub const fn observed_signals(&self) -> Option<ax_signals_t> {
        match self {
            Self::Signal(signal) => Some(signal.observed),
            Self::User(_) | Self::Unknown(_) => None,
        }
    }
}

/// Minimal single-thread reactor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reactor {
    pub(crate) port: ax_handle_t,
}

impl Reactor {
    /// Create a reactor with one owned port.
    pub fn create() -> Result<Self, ax_status_t> {
        let mut port = 0;
        let status = ax_port_create(0, &mut port);
        if status == AX_OK {
            Ok(Self { port })
        } else {
            Err(status)
        }
    }

    /// Return the backing port handle.
    pub const fn port_handle(&self) -> ax_handle_t {
        self.port
    }

    /// Register a one-shot async wait routed to this reactor's port.
    pub fn wait_async(
        &self,
        handle: ax_handle_t,
        key: u64,
        signals: ax_signals_t,
        options: u32,
    ) -> Result<(), ax_status_t> {
        let status = ax_object_wait_async(handle, self.port, key, signals, options);
        if status == AX_OK { Ok(()) } else { Err(status) }
    }

    /// Wait for the next event until `deadline`.
    pub fn wait_until(&self, deadline: ax_time_t) -> Result<Event, ax_status_t> {
        let mut packet = ax_port_packet_t::default();
        let status = ax_port_wait(self.port, deadline, &mut packet);
        if status == AX_OK {
            Ok(Event::from_port_packet(packet))
        } else {
            Err(status)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, SignalEvent};
    use libax::packet::{AX_PKT_TYPE_SIGNAL_ONE, AX_PKT_TYPE_USER};
    use libax::{ax_packet_signal_t, ax_packet_user_t, ax_port_packet_t};

    #[test]
    fn decodes_signal_packets() {
        let packet = ax_port_packet_t {
            key: 0x55,
            type_: AX_PKT_TYPE_SIGNAL_ONE,
            status: -9,
            user: ax_packet_signal_t {
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
        let packet = ax_port_packet_t {
            key: 7,
            type_: AX_PKT_TYPE_USER,
            status: 0,
            user: ax_packet_user_t { u64: [1, 2, 3, 4] },
        };

        assert_eq!(Event::from_port_packet(packet), Event::User(packet));
    }
}
