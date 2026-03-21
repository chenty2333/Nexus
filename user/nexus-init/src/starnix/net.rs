use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::starnix) struct LoopbackSocketAddr {
    pub(in crate::starnix) ip: u32,
    pub(in crate::starnix) port: u16,
}

impl LoopbackSocketAddr {
    pub(in crate::starnix) const fn any(port: u16) -> Self {
        Self {
            ip: LINUX_INADDR_ANY,
            port,
        }
    }

    pub(in crate::starnix) const fn loopback(port: u16) -> Self {
        Self {
            ip: LINUX_INADDR_LOOPBACK,
            port,
        }
    }

    pub(in crate::starnix) const fn canonicalize(self) -> Option<Self> {
        match self.ip {
            LINUX_INADDR_ANY | LINUX_INADDR_LOOPBACK => Some(Self::loopback(self.port)),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::starnix) struct InetSocketOptions {
    pub(in crate::starnix) reuseaddr: bool,
    pub(in crate::starnix) keepalive: bool,
    pub(in crate::starnix) nodelay: bool,
}

#[derive(Clone)]
pub(in crate::starnix) struct InetSocketFd {
    state: Arc<Mutex<InetSocketState>>,
}

pub(in crate::starnix) struct LoopbackNetStack {
    next_ephemeral_port: u16,
    bound: BTreeMap<LoopbackSocketAddr, Weak<Mutex<InetSocketState>>>,
    listeners: BTreeMap<LoopbackSocketAddr, Weak<Mutex<TcpListenerState>>>,
}

struct TcpListenerState {
    wait_handle: zx_handle_t,
    peer_handle: zx_handle_t,
    local_addr: LoopbackSocketAddr,
    backlog: usize,
    pending: VecDeque<Arc<Mutex<TcpStreamEndpointState>>>,
    closed: bool,
}

struct TcpStreamEndpointState {
    wait_handle: zx_handle_t,
    peer_handle: zx_handle_t,
    local_addr: LoopbackSocketAddr,
    peer_addr: LoopbackSocketAddr,
    rx: VecDeque<u8>,
    peer: Weak<Mutex<TcpStreamEndpointState>>,
    write_shutdown: bool,
    read_shutdown: bool,
    peer_write_closed: bool,
    peer_gone: bool,
    closed: bool,
}

enum InetSocketState {
    Init {
        local_addr: Option<LoopbackSocketAddr>,
        options: InetSocketOptions,
    },
    Listener {
        listener: Arc<Mutex<TcpListenerState>>,
        options: InetSocketOptions,
    },
    Stream {
        stream: Arc<Mutex<TcpStreamEndpointState>>,
        options: InetSocketOptions,
    },
    Closed,
}

type TcpStreamEndpoint = Arc<Mutex<TcpStreamEndpointState>>;

fn create_inet_wait_pair() -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    let mut wait_handle = ZX_HANDLE_INVALID;
    let mut peer_handle = ZX_HANDLE_INVALID;
    let status = ax_eventpair_create(0, &mut wait_handle, &mut peer_handle);
    if status == ZX_OK {
        return Ok((wait_handle, peer_handle));
    }
    #[cfg(test)]
    {
        Ok((ZX_HANDLE_INVALID, ZX_HANDLE_INVALID))
    }
    #[cfg(not(test))]
    {
        Err(status)
    }
}

fn signal_inet_wait_handle(
    handle: zx_handle_t,
    clear_mask: u32,
    set_mask: u32,
) -> Result<(), zx_status_t> {
    if handle == ZX_HANDLE_INVALID {
        return Ok(());
    }
    zx_status_result(ax_object_signal(handle, clear_mask, set_mask))
}

impl Default for LoopbackNetStack {
    fn default() -> Self {
        Self {
            next_ephemeral_port: LINUX_EPHEMERAL_PORT_START,
            bound: BTreeMap::new(),
            listeners: BTreeMap::new(),
        }
    }
}

impl LoopbackNetStack {
    fn alloc_ephemeral_addr(
        &mut self,
        socket: &Arc<Mutex<InetSocketState>>,
    ) -> Result<LoopbackSocketAddr, zx_status_t> {
        for _ in 0..u16::MAX {
            let port = self.next_ephemeral_port;
            self.next_ephemeral_port = if self.next_ephemeral_port == u16::MAX {
                LINUX_EPHEMERAL_PORT_START
            } else {
                self.next_ephemeral_port.saturating_add(1)
            };
            let candidate = LoopbackSocketAddr::loopback(port);
            if self.bound_addr_in_use(candidate) {
                continue;
            }
            self.bound.insert(candidate, Arc::downgrade(socket));
            return Ok(candidate);
        }
        Err(ZX_ERR_NO_MEMORY)
    }

    fn bound_addr_in_use(&mut self, addr: LoopbackSocketAddr) -> bool {
        let Some(entry) = self.bound.get(&addr).cloned() else {
            return false;
        };
        let Some(state) = entry.upgrade() else {
            let _ = self.bound.remove(&addr);
            return false;
        };
        let in_use = !matches!(*state.lock(), InetSocketState::Closed);
        if !in_use {
            let _ = self.bound.remove(&addr);
        }
        in_use
    }

    fn listener_for(
        &mut self,
        addr: LoopbackSocketAddr,
    ) -> Result<Arc<Mutex<TcpListenerState>>, zx_status_t> {
        let Some(entry) = self.listeners.get(&addr).cloned() else {
            return Err(ZX_ERR_CONNECTION_REFUSED);
        };
        let Some(listener) = entry.upgrade() else {
            let _ = self.listeners.remove(&addr);
            return Err(ZX_ERR_CONNECTION_REFUSED);
        };
        if listener.lock().closed {
            let _ = self.listeners.remove(&addr);
            return Err(ZX_ERR_CONNECTION_REFUSED);
        }
        Ok(listener)
    }

    fn reserve_bound_addr(
        &mut self,
        socket: &Arc<Mutex<InetSocketState>>,
        requested: LoopbackSocketAddr,
    ) -> Result<LoopbackSocketAddr, zx_status_t> {
        let requested = requested.canonicalize().ok_or(ZX_ERR_ADDRESS_UNREACHABLE)?;
        if requested.port == 0 {
            return self.alloc_ephemeral_addr(socket);
        }
        if self.bound_addr_in_use(requested) {
            return Err(ZX_ERR_ADDRESS_IN_USE);
        }
        self.bound.insert(requested, Arc::downgrade(socket));
        Ok(requested)
    }

    fn register_listener(
        &mut self,
        addr: LoopbackSocketAddr,
        listener: &Arc<Mutex<TcpListenerState>>,
    ) -> Result<(), zx_status_t> {
        if self
            .listeners
            .get(&addr)
            .and_then(Weak::upgrade)
            .is_some_and(|live| !live.lock().closed)
        {
            return Err(ZX_ERR_ADDRESS_IN_USE);
        }
        self.listeners.insert(addr, Arc::downgrade(listener));
        Ok(())
    }
}

impl TcpListenerState {
    fn new(
        local_addr: LoopbackSocketAddr,
        backlog: usize,
    ) -> Result<Arc<Mutex<Self>>, zx_status_t> {
        let (wait_handle, peer_handle) = create_inet_wait_pair()?;
        let listener = Arc::new(Mutex::new(Self {
            wait_handle,
            peer_handle,
            local_addr,
            backlog: backlog.max(1),
            pending: VecDeque::new(),
            closed: false,
        }));
        Self::refresh_signals(&listener)?;
        Ok(listener)
    }

    fn refresh_signals(listener: &Arc<Mutex<Self>>) -> Result<(), zx_status_t> {
        let guard = listener.lock();
        if guard.closed {
            return Ok(());
        }
        let mut set_mask = 0u32;
        if !guard.pending.is_empty() {
            set_mask |= INET_READABLE_SIGNAL;
        }
        signal_inet_wait_handle(guard.wait_handle, INET_SIGNAL_MASK, set_mask)
    }
}

impl TcpStreamEndpointState {
    fn new_pair(
        client_addr: LoopbackSocketAddr,
        server_addr: LoopbackSocketAddr,
    ) -> Result<(TcpStreamEndpoint, TcpStreamEndpoint), zx_status_t> {
        let client = Arc::new(Mutex::new(Self::new(client_addr, server_addr)?));
        let server = Arc::new(Mutex::new(Self::new(server_addr, client_addr)?));
        client.lock().peer = Arc::downgrade(&server);
        server.lock().peer = Arc::downgrade(&client);
        Self::refresh_signals(&client)?;
        Self::refresh_signals(&server)?;
        Ok((client, server))
    }

    fn new(
        local_addr: LoopbackSocketAddr,
        peer_addr: LoopbackSocketAddr,
    ) -> Result<Self, zx_status_t> {
        let (wait_handle, peer_handle) = create_inet_wait_pair()?;
        Ok(Self {
            wait_handle,
            peer_handle,
            local_addr,
            peer_addr,
            rx: VecDeque::new(),
            peer: Weak::new(),
            write_shutdown: false,
            read_shutdown: false,
            peer_write_closed: false,
            peer_gone: false,
            closed: false,
        })
    }

    fn refresh_signals(stream: &Arc<Mutex<Self>>) -> Result<(), zx_status_t> {
        let guard = stream.lock();
        if guard.closed {
            return Ok(());
        }
        let mut set_mask = 0u32;
        if !guard.read_shutdown && !guard.rx.is_empty() {
            set_mask |= INET_READABLE_SIGNAL;
        }
        if !guard.write_shutdown && !guard.peer_gone {
            set_mask |= INET_WRITABLE_SIGNAL;
        }
        if guard.peer_write_closed || guard.peer_gone {
            set_mask |= INET_PEER_CLOSED_SIGNAL;
        }
        signal_inet_wait_handle(guard.wait_handle, INET_SIGNAL_MASK, set_mask)
    }

    fn notify_peer_write_closed(
        stream: &Arc<Mutex<Self>>,
        peer_gone: bool,
    ) -> Result<(), zx_status_t> {
        let peer = stream.lock().peer.clone();
        if let Some(peer) = peer.upgrade() {
            {
                let mut guard = peer.lock();
                guard.peer_write_closed = true;
                if peer_gone {
                    guard.peer_gone = true;
                }
            }
            Self::refresh_signals(&peer)?;
        }
        Ok(())
    }
}

impl InetSocketFd {
    pub(in crate::starnix) fn new_stream() -> Self {
        Self {
            state: Arc::new(Mutex::new(InetSocketState::Init {
                local_addr: None,
                options: InetSocketOptions::default(),
            })),
        }
    }
    pub(in crate::starnix) fn bind(
        &self,
        net: &mut LoopbackNetStack,
        requested: LoopbackSocketAddr,
    ) -> Result<LoopbackSocketAddr, zx_status_t> {
        let reserved = net.reserve_bound_addr(&self.state, requested)?;
        let mut guard = self.state.lock();
        match &mut *guard {
            InetSocketState::Init { local_addr, .. } => {
                if local_addr.is_some() {
                    return Err(ZX_ERR_ALREADY_BOUND);
                }
                *local_addr = Some(reserved);
                Ok(reserved)
            }
            _ => Err(ZX_ERR_BAD_STATE),
        }
    }

    pub(in crate::starnix) fn connect(
        &self,
        net: &mut LoopbackNetStack,
        remote: LoopbackSocketAddr,
    ) -> Result<(), zx_status_t> {
        let remote = remote.canonicalize().ok_or(ZX_ERR_ADDRESS_UNREACHABLE)?;
        if remote.port == 0 {
            return Err(ZX_ERR_CONNECTION_REFUSED);
        }
        let listener = net.listener_for(remote)?;
        let local_addr = {
            let guard = self.state.lock();
            match &*guard {
                InetSocketState::Init { local_addr, .. } => *local_addr,
                _ => return Err(ZX_ERR_BAD_STATE),
            }
        };
        let local_addr = if let Some(local_addr) = local_addr {
            local_addr
                .canonicalize()
                .ok_or(ZX_ERR_ADDRESS_UNREACHABLE)?
        } else {
            net.alloc_ephemeral_addr(&self.state)?
        };
        let (client_stream, server_stream) = TcpStreamEndpointState::new_pair(local_addr, remote)?;
        {
            let mut listener_guard = listener.lock();
            if listener_guard.closed {
                return Err(ZX_ERR_CONNECTION_REFUSED);
            }
            if listener_guard.pending.len() >= listener_guard.backlog {
                return Err(ZX_ERR_SHOULD_WAIT);
            }
            listener_guard.pending.push_back(server_stream);
        }
        TcpListenerState::refresh_signals(&listener)?;
        let options = match &*self.state.lock() {
            InetSocketState::Init { options, .. } => *options,
            _ => return Err(ZX_ERR_BAD_STATE),
        };
        *self.state.lock() = InetSocketState::Stream {
            stream: client_stream.clone(),
            options,
        };
        TcpStreamEndpointState::refresh_signals(&client_stream)
    }

    pub(in crate::starnix) fn listen(
        &self,
        net: &mut LoopbackNetStack,
        backlog: usize,
    ) -> Result<(), zx_status_t> {
        let (local_addr, options) = {
            let mut guard = self.state.lock();
            match &mut *guard {
                InetSocketState::Init {
                    local_addr,
                    options,
                } => {
                    let addr = if let Some(addr) = *local_addr {
                        addr
                    } else {
                        let allocated = net.alloc_ephemeral_addr(&self.state)?;
                        *local_addr = Some(allocated);
                        allocated
                    };
                    (addr, *options)
                }
                _ => return Err(ZX_ERR_BAD_STATE),
            }
        };
        let listener = TcpListenerState::new(local_addr, backlog)?;
        net.register_listener(local_addr, &listener)?;
        *self.state.lock() = InetSocketState::Listener { listener, options };
        Ok(())
    }

    pub(in crate::starnix) fn accept(&self) -> Result<InetSocketFd, zx_status_t> {
        let (accepted, options) = {
            let guard = self.state.lock();
            let InetSocketState::Listener { listener, options } = &*guard else {
                return Err(ZX_ERR_BAD_STATE);
            };
            let mut listener_guard = listener.lock();
            let Some(stream) = listener_guard.pending.pop_front() else {
                return Err(ZX_ERR_SHOULD_WAIT);
            };
            (stream, *options)
        };
        if let InetSocketState::Listener { listener, .. } = &*self.state.lock() {
            TcpListenerState::refresh_signals(listener)?;
        }
        Ok(InetSocketFd {
            state: Arc::new(Mutex::new(InetSocketState::Stream {
                stream: accepted,
                options,
            })),
        })
    }

    pub(in crate::starnix) fn shutdown(&self, how: i32) -> Result<(), zx_status_t> {
        let stream = {
            let guard = self.state.lock();
            let InetSocketState::Stream { stream, .. } = &*guard else {
                return Err(ZX_ERR_NOT_CONNECTED);
            };
            stream.clone()
        };
        {
            let mut guard = stream.lock();
            match how {
                LINUX_SHUT_RD => {
                    guard.read_shutdown = true;
                    guard.rx.clear();
                }
                LINUX_SHUT_WR => {
                    guard.write_shutdown = true;
                }
                LINUX_SHUT_RDWR => {
                    guard.read_shutdown = true;
                    guard.rx.clear();
                    guard.write_shutdown = true;
                }
                _ => return Err(ZX_ERR_INVALID_ARGS),
            }
        }
        if how == LINUX_SHUT_WR || how == LINUX_SHUT_RDWR {
            TcpStreamEndpointState::notify_peer_write_closed(&stream, false)?;
        }
        TcpStreamEndpointState::refresh_signals(&stream)
    }

    pub(in crate::starnix) fn getsockname(&self) -> Result<LoopbackSocketAddr, zx_status_t> {
        let guard = self.state.lock();
        match &*guard {
            InetSocketState::Init {
                local_addr: Some(local_addr),
                ..
            } => Ok(*local_addr),
            InetSocketState::Init { .. } => Ok(LoopbackSocketAddr::any(0)),
            InetSocketState::Listener { listener, .. } => Ok(listener.lock().local_addr),
            InetSocketState::Stream { stream, .. } => Ok(stream.lock().local_addr),
            InetSocketState::Closed => Err(ZX_ERR_BAD_STATE),
        }
    }

    pub(in crate::starnix) fn getpeername(&self) -> Result<LoopbackSocketAddr, zx_status_t> {
        let guard = self.state.lock();
        match &*guard {
            InetSocketState::Stream { stream, .. } => Ok(stream.lock().peer_addr),
            _ => Err(ZX_ERR_NOT_CONNECTED),
        }
    }

    pub(in crate::starnix) fn setsockopt(
        &self,
        level: i32,
        optname: i32,
        value: &[u8],
    ) -> Result<(), zx_status_t> {
        let enabled = read_bool_sockopt(value)?;
        let mut guard = self.state.lock();
        let options = match &mut *guard {
            InetSocketState::Init { options, .. }
            | InetSocketState::Listener { options, .. }
            | InetSocketState::Stream { options, .. } => options,
            InetSocketState::Closed => return Err(ZX_ERR_BAD_STATE),
        };
        match (level, optname) {
            (LINUX_SOL_SOCKET, LINUX_SO_REUSEADDR) => options.reuseaddr = enabled,
            (LINUX_SOL_SOCKET, LINUX_SO_KEEPALIVE) => options.keepalive = enabled,
            (LINUX_IPPROTO_TCP, LINUX_TCP_NODELAY) => options.nodelay = enabled,
            _ => return Err(ZX_ERR_NOT_SUPPORTED),
        }
        Ok(())
    }

    pub(in crate::starnix) fn getsockopt(
        &self,
        level: i32,
        optname: i32,
    ) -> Result<i32, zx_status_t> {
        let guard = self.state.lock();
        let options = match &*guard {
            InetSocketState::Init { options, .. }
            | InetSocketState::Listener { options, .. }
            | InetSocketState::Stream { options, .. } => *options,
            InetSocketState::Closed => return Err(ZX_ERR_BAD_STATE),
        };
        match (level, optname) {
            (LINUX_SOL_SOCKET, LINUX_SO_REUSEADDR) => Ok(i32::from(options.reuseaddr)),
            (LINUX_SOL_SOCKET, LINUX_SO_KEEPALIVE) => Ok(i32::from(options.keepalive)),
            (LINUX_SOL_SOCKET, LINUX_SO_TYPE) => Ok(LINUX_SOCK_STREAM as i32),
            (LINUX_SOL_SOCKET, LINUX_SO_ERROR) => Ok(0),
            (LINUX_IPPROTO_TCP, LINUX_TCP_NODELAY) => Ok(i32::from(options.nodelay)),
            _ => Err(ZX_ERR_NOT_SUPPORTED),
        }
    }
}

impl FdOps for InetSocketFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        let stream = {
            let guard = self.state.lock();
            let InetSocketState::Stream { stream, .. } = &*guard else {
                return Err(ZX_ERR_NOT_CONNECTED);
            };
            stream.clone()
        };
        let mut guard = stream.lock();
        if guard.read_shutdown {
            return Ok(0);
        }
        if guard.rx.is_empty() {
            if guard.peer_write_closed || guard.peer_gone {
                return Ok(0);
            }
            return Err(ZX_ERR_SHOULD_WAIT);
        }
        let actual = buffer.len().min(guard.rx.len());
        for slot in buffer.iter_mut().take(actual) {
            *slot = guard.rx.pop_front().ok_or(ZX_ERR_BAD_STATE)?;
        }
        drop(guard);
        TcpStreamEndpointState::refresh_signals(&stream)?;
        Ok(actual)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        let stream = {
            let guard = self.state.lock();
            let InetSocketState::Stream { stream, .. } = &*guard else {
                return Err(ZX_ERR_NOT_CONNECTED);
            };
            stream.clone()
        };
        {
            let guard = stream.lock();
            if guard.write_shutdown || guard.peer_gone {
                return Err(ZX_ERR_PEER_CLOSED);
            }
            let Some(peer) = guard.peer.upgrade() else {
                return Err(ZX_ERR_PEER_CLOSED);
            };
            drop(guard);
            {
                let mut peer_guard = peer.lock();
                if peer_guard.closed || peer_guard.read_shutdown {
                    peer_guard.peer_gone = true;
                    drop(peer_guard);
                    TcpStreamEndpointState::refresh_signals(&peer)?;
                    return Err(ZX_ERR_PEER_CLOSED);
                }
                peer_guard
                    .rx
                    .try_reserve(buffer.len())
                    .map_err(|_| ZX_ERR_NO_MEMORY)?;
                peer_guard.rx.extend(buffer.iter().copied());
            }
            TcpStreamEndpointState::refresh_signals(&peer)?;
        }
        TcpStreamEndpointState::refresh_signals(&stream)?;
        Ok(buffer.len())
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        if Arc::strong_count(&self.state) != 1 {
            return Ok(());
        }
        let previous = {
            let mut guard = self.state.lock();
            core::mem::replace(&mut *guard, InetSocketState::Closed)
        };
        match previous {
            InetSocketState::Init { .. } => Ok(()),
            InetSocketState::Listener { listener, .. } => {
                let (wait_handle, peer_handle) = {
                    let mut guard = listener.lock();
                    if guard.closed {
                        return Ok(());
                    }
                    guard.closed = true;
                    (guard.wait_handle, guard.peer_handle)
                };
                let _ = zx_handle_close(peer_handle);
                let _ = zx_handle_close(wait_handle);
                Ok(())
            }
            InetSocketState::Stream { stream, .. } => {
                {
                    let mut guard = stream.lock();
                    if guard.closed {
                        return Ok(());
                    }
                    guard.closed = true;
                    guard.write_shutdown = true;
                    guard.read_shutdown = true;
                    guard.rx.clear();
                }
                TcpStreamEndpointState::notify_peer_write_closed(&stream, true)?;
                let (wait_handle, peer_handle) = {
                    let guard = stream.lock();
                    (guard.wait_handle, guard.peer_handle)
                };
                let _ = zx_handle_close(peer_handle);
                let _ = zx_handle_close(wait_handle);
                Ok(())
            }
            InetSocketState::Closed => Ok(()),
        }
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        let guard = self.state.lock();
        match &*guard {
            InetSocketState::Init { .. } => None,
            InetSocketState::Listener { listener, .. } => {
                let listener_guard = listener.lock();
                (!listener_guard.closed)
                    .then_some(WaitSpec::new(listener_guard.wait_handle, INET_SIGNAL_MASK))
            }
            InetSocketState::Stream { stream, .. } => {
                let stream_guard = stream.lock();
                (!stream_guard.closed)
                    .then_some(WaitSpec::new(stream_guard.wait_handle, INET_SIGNAL_MASK))
            }
            InetSocketState::Closed => None,
        }
    }
}

fn read_bool_sockopt(value: &[u8]) -> Result<bool, zx_status_t> {
    if value.len() < 4 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let parsed = i32::from_ne_bytes(
        value[..4]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    Ok(parsed != 0)
}
