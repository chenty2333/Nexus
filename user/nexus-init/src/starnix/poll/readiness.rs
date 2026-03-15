use super::super::*;

pub(in crate::starnix) fn filter_wait_interest(interest: WaitSpec, op: FdWaitOp) -> WaitSpec {
    let peer_closed = ZX_CHANNEL_PEER_CLOSED | ZX_SOCKET_PEER_CLOSED;
    let signals = match op {
        FdWaitOp::Read => {
            interest.signals()
                & (ZX_CHANNEL_READABLE
                    | ZX_SOCKET_READABLE
                    | EVENTFD_READABLE_SIGNAL
                    | SIGNALFD_READABLE_SIGNAL
                    | ZX_TIMER_SIGNALED
                    | peer_closed)
        }
        FdWaitOp::Write => {
            interest.signals()
                & (ZX_CHANNEL_WRITABLE | ZX_SOCKET_WRITABLE | EVENTFD_WRITABLE_SIGNAL | peer_closed)
        }
    };
    WaitSpec::new(interest.handle(), signals)
}
