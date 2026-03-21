use super::super::*;

pub(in crate::starnix) fn map_wait_signals_to_epoll(signals: u32) -> u32 {
    let mut events = 0u32;
    if (signals
        & (ZX_CHANNEL_READABLE
            | ZX_SOCKET_READABLE
            | EVENTFD_READABLE_SIGNAL
            | INET_READABLE_SIGNAL
            | SIGNALFD_READABLE_SIGNAL
            | PIDFD_READABLE_SIGNAL
            | ZX_TIMER_SIGNALED))
        != 0
    {
        events |= LINUX_EPOLLIN;
    }
    if (signals
        & (ZX_CHANNEL_WRITABLE
            | ZX_SOCKET_WRITABLE
            | EVENTFD_WRITABLE_SIGNAL
            | INET_WRITABLE_SIGNAL))
        != 0
    {
        events |= LINUX_EPOLLOUT;
    }
    if (signals & (ZX_CHANNEL_PEER_CLOSED | ZX_SOCKET_PEER_CLOSED | INET_PEER_CLOSED_SIGNAL)) != 0 {
        events |= LINUX_EPOLLHUP;
    }
    events
}

pub(in crate::starnix) fn filter_epoll_ready_events(interest: u32, ready: u32) -> u32 {
    let requested = interest & (LINUX_EPOLLIN | LINUX_EPOLLOUT);
    (ready & requested) | (ready & (LINUX_EPOLLERR | LINUX_EPOLLHUP))
}

pub(in crate::starnix) fn filter_epoll_wait_interest(
    interest: WaitSpec,
    epoll_interest: u32,
) -> WaitSpec {
    let peer_closed = ZX_CHANNEL_PEER_CLOSED | ZX_SOCKET_PEER_CLOSED | INET_PEER_CLOSED_SIGNAL;
    let mut signals = 0;
    if (epoll_interest & LINUX_EPOLLIN) != 0 {
        signals |= interest.signals()
            & (ZX_CHANNEL_READABLE
                | ZX_SOCKET_READABLE
                | EVENTFD_READABLE_SIGNAL
                | INET_READABLE_SIGNAL
                | SIGNALFD_READABLE_SIGNAL
                | ZX_TIMER_SIGNALED);
    }
    if (epoll_interest & LINUX_EPOLLOUT) != 0 {
        signals |= interest.signals()
            & (ZX_CHANNEL_WRITABLE
                | ZX_SOCKET_WRITABLE
                | EVENTFD_WRITABLE_SIGNAL
                | INET_WRITABLE_SIGNAL);
    }
    if signals != 0 || (epoll_interest & LINUX_EPOLLHUP) != 0 {
        signals |= interest.signals() & peer_closed;
    }
    WaitSpec::new(interest.handle(), signals)
}

pub(in crate::starnix) fn filter_wait_interest(interest: WaitSpec, op: FdWaitOp) -> WaitSpec {
    let peer_closed = ZX_CHANNEL_PEER_CLOSED | ZX_SOCKET_PEER_CLOSED | INET_PEER_CLOSED_SIGNAL;
    let signals = match op {
        FdWaitOp::Read => {
            interest.signals()
                & (ZX_CHANNEL_READABLE
                    | ZX_SOCKET_READABLE
                    | EVENTFD_READABLE_SIGNAL
                    | INET_READABLE_SIGNAL
                    | SIGNALFD_READABLE_SIGNAL
                    | ZX_TIMER_SIGNALED
                    | peer_closed)
        }
        FdWaitOp::Write => {
            interest.signals()
                & (ZX_CHANNEL_WRITABLE
                    | ZX_SOCKET_WRITABLE
                    | EVENTFD_WRITABLE_SIGNAL
                    | INET_WRITABLE_SIGNAL
                    | peer_closed)
        }
    };
    WaitSpec::new(interest.handle(), signals)
}
