use super::*;

impl KernelState {
    pub(super) fn alloc_socket_core_id(&mut self) -> u64 {
        let id = self.next_socket_core_id;
        self.next_socket_core_id = self.next_socket_core_id.wrapping_add(1);
        id
    }

    pub(super) fn note_socket_write(
        &mut self,
        requested: usize,
        written: usize,
        buffered_after: usize,
    ) {
        if written == 0 && requested != 0 {
            self.socket_telemetry.write_should_wait_count = self
                .socket_telemetry
                .write_should_wait_count
                .wrapping_add(1);
            return;
        }
        if written < requested {
            self.socket_telemetry.short_write_count =
                self.socket_telemetry.short_write_count.wrapping_add(1);
        }
        self.socket_telemetry.current_buffered_bytes = self
            .socket_telemetry
            .current_buffered_bytes
            .saturating_add(written as u64);
        self.socket_telemetry.peak_buffered_bytes = self
            .socket_telemetry
            .peak_buffered_bytes
            .max(buffered_after as u64);
    }

    pub(super) fn note_socket_read(&mut self, consumed: usize) {
        self.socket_telemetry.current_buffered_bytes = self
            .socket_telemetry
            .current_buffered_bytes
            .saturating_sub(consumed as u64);
    }

    pub(super) fn note_socket_core_drop(&mut self, core: &SocketCore) {
        self.socket_telemetry.current_buffered_bytes = self
            .socket_telemetry
            .current_buffered_bytes
            .saturating_sub(core.buffered_bytes() as u64);
    }
}

pub(crate) fn socket_telemetry_snapshot() -> SocketTelemetrySnapshot {
    let mut guard = STATE.lock();
    let Some(state) = guard.as_mut() else {
        return SocketTelemetrySnapshot::default();
    };
    state.socket_telemetry
}

/// Create a socket endpoint pair and return both handles.
pub fn create_socket(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    match options {
        ZX_SOCKET_STREAM => {}
        ZX_SOCKET_DATAGRAM => return Err(ZX_ERR_NOT_SUPPORTED),
        _ => return Err(ZX_ERR_INVALID_ARGS),
    }

    with_state_mut(|state| {
        let core_id = state.alloc_socket_core_id();
        let core = SocketCore::new_stream(SOCKET_STREAM_CAPACITY)?;
        state.socket_cores.insert(core_id, core);

        let left_object_id = state.alloc_object_id();
        let right_object_id = state.alloc_object_id();
        state.objects.insert(
            left_object_id,
            KernelObject::Socket(SocketEndpoint {
                core_id,
                peer_object_id: right_object_id,
                side: SocketSide::A,
            }),
        );
        state.objects.insert(
            right_object_id,
            KernelObject::Socket(SocketEndpoint {
                core_id,
                peer_object_id: left_object_id,
                side: SocketSide::B,
            }),
        );

        let left_handle =
            match state.alloc_handle_for_object(left_object_id, handle::socket_default_rights()) {
                Ok(handle) => handle,
                Err(err) => {
                    let _ = state.objects.remove(&left_object_id);
                    let _ = state.objects.remove(&right_object_id);
                    let _ = state.socket_cores.remove(&core_id);
                    return Err(err);
                }
            };
        let right_handle =
            match state.alloc_handle_for_object(right_object_id, handle::socket_default_rights()) {
                Ok(handle) => handle,
                Err(err) => {
                    let _ = state.close_handle(left_handle);
                    let _ = state.objects.remove(&left_object_id);
                    let _ = state.objects.remove(&right_object_id);
                    let _ = state.socket_cores.remove(&core_id);
                    return Err(err);
                }
            };

        Ok((left_handle, right_handle))
    })
}

/// Create a channel endpoint pair and return both handles.
pub fn create_channel(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let owner_process_id = state
            .with_kernel(|kernel| kernel.current_process_info())?
            .process_id();
        let left_object_id = state.alloc_object_id();
        let right_object_id = state.alloc_object_id();
        state.objects.insert(
            left_object_id,
            KernelObject::Channel(ChannelEndpoint::new(right_object_id, owner_process_id)),
        );
        state.objects.insert(
            right_object_id,
            KernelObject::Channel(ChannelEndpoint::new(left_object_id, owner_process_id)),
        );

        let left_handle =
            match state.alloc_handle_for_object(left_object_id, handle::channel_default_rights()) {
                Ok(handle) => handle,
                Err(e) => {
                    let _ = state.objects.remove(&left_object_id);
                    let _ = state.objects.remove(&right_object_id);
                    return Err(e);
                }
            };
        let right_handle = match state
            .alloc_handle_for_object(right_object_id, handle::channel_default_rights())
        {
            Ok(handle) => handle,
            Err(e) => {
                let _ = state.close_handle(left_handle);
                let _ = state.objects.remove(&left_object_id);
                let _ = state.objects.remove(&right_object_id);
                return Err(e);
            }
        };

        Ok((left_handle, right_handle))
    })
}

pub(super) fn release_channel_payload(state: &mut KernelState, payload: ChannelPayload) {
    if let Some(loaned) = payload.loaned_body() {
        let _ = state.with_vm_mut(|vm| {
            vm.release_loaned_user_pages(loaned);
            Ok(())
        });
    }
}

fn retain_transferred_handles(state: &mut KernelState, handles: &[TransferredCap]) {
    for transferred in handles {
        state
            .object_handle_refs
            .entry(transferred.capability().object_id())
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }
}

fn release_transferred_handles(state: &mut KernelState, handles: &[TransferredCap]) {
    for transferred in handles {
        state.decrement_object_handle_ref(transferred.capability().object_id());
    }
}

fn release_channel_message(state: &mut KernelState, message: ChannelMessage) {
    release_transferred_handles(state, &message.handles);
    release_channel_payload(state, message.payload);
}

pub(super) fn drain_channel_messages(
    state: &mut KernelState,
    messages: impl IntoIterator<Item = ChannelMessage>,
) {
    for message in messages {
        release_channel_message(state, message);
    }
}

fn channel_endpoint_address_space_id(
    state: &KernelState,
    endpoint: &ChannelEndpoint,
) -> Result<u64, zx_status_t> {
    state.with_core(|kernel| kernel.process_address_space_id(endpoint.owner_process_id))
}

pub(super) fn transport_signals(
    state: &KernelState,
    object: &KernelObject,
) -> Option<Result<Signals, zx_status_t>> {
    match object {
        KernelObject::Socket(endpoint) => {
            let core = state
                .socket_cores
                .get(&endpoint.core_id)
                .ok_or(ZX_ERR_BAD_STATE);
            Some(core.map(|core| core.signals_for(endpoint.side)))
        }
        KernelObject::Channel(endpoint) => {
            let mut signals = Signals::NONE;
            if endpoint.is_readable() {
                signals = signals | Signals::CHANNEL_READABLE;
            }
            if endpoint.peer_closed {
                signals = signals | Signals::CHANNEL_PEER_CLOSED;
            } else {
                let peer = match state.objects.get(&endpoint.peer_object_id) {
                    Some(KernelObject::Channel(peer)) => peer,
                    Some(_) | None => return Some(Err(ZX_ERR_BAD_STATE)),
                };
                if endpoint.writable_via_peer(peer) {
                    signals = signals | Signals::CHANNEL_WRITABLE;
                }
            }
            Some(Ok(signals))
        }
        _ => None,
    }
}

pub(crate) fn try_loan_current_user_pages(
    ptr: u64,
    len: usize,
) -> Result<Option<crate::task::LoanedUserPages>, zx_status_t> {
    let address_space_id = with_core(|kernel| {
        let process = kernel.current_process_info()?;
        kernel.process_address_space_id(process.process_id())
    })?;
    with_vm_mut(|vm| vm.try_loan_user_pages(address_space_id, ptr, len))
}

pub(crate) fn try_remap_loaned_channel_read(
    dst_base: u64,
    loaned: &crate::task::LoanedUserPages,
) -> Result<bool, zx_status_t> {
    with_state_mut(|state| {
        let address_space_id = state.with_core(|kernel| {
            let process = kernel.current_process_info()?;
            kernel.process_address_space_id(process.process_id())
        })?;
        let (remapped, tlb_commit) = state.with_vm_mut(|vm| {
            vm.try_remap_loaned_channel_read(address_space_id, dst_base, loaned)
        })?;
        state.apply_tlb_commit_reqs(&[tlb_commit])?;
        Ok(remapped)
    })
}

/// Write bytes into one stream socket.
pub fn socket_write(handle: zx_handle_t, options: u32, bytes: &[u8]) -> Result<usize, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let endpoint = match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Socket(endpoint)) => *endpoint,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        require_handle_rights(resolved, crate::task::HandleRights::WRITE)?;

        let write_result = {
            let core = state
                .socket_cores
                .get_mut(&endpoint.core_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            match core.write(endpoint.side, bytes) {
                Ok(written) => Ok((written, core.buffered_bytes())),
                Err(ZX_ERR_SHOULD_WAIT) => Err((ZX_ERR_SHOULD_WAIT, core.buffered_bytes())),
                Err(e) => Err((e, core.buffered_bytes())),
            }
        };
        let (written, buffered_after) = match write_result {
            Ok(result) => result,
            Err((ZX_ERR_SHOULD_WAIT, buffered_after)) => {
                state.note_socket_write(bytes.len(), 0, buffered_after);
                return Err(ZX_ERR_SHOULD_WAIT);
            }
            Err((e, _)) => return Err(e),
        };
        state.note_socket_write(bytes.len(), written, buffered_after);

        let _ = crate::wait::notify_waitable_signals_changed(state, resolved.object_id());
        let _ = crate::wait::notify_waitable_signals_changed(state, endpoint.peer_object_id);
        Ok(written)
    })
}

/// Read bytes from one stream socket.
pub fn socket_read(handle: zx_handle_t, options: u32, len: usize) -> Result<Vec<u8>, zx_status_t> {
    let peek = match options {
        0 => false,
        ZX_SOCKET_PEEK => true,
        _ => return Err(ZX_ERR_INVALID_ARGS),
    };

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let endpoint = match state.objects.get(&resolved.object_id()) {
            Some(KernelObject::Socket(endpoint)) => *endpoint,
            Some(_) => return Err(ZX_ERR_WRONG_TYPE),
            None => return Err(ZX_ERR_BAD_HANDLE),
        };
        require_handle_rights(resolved, crate::task::HandleRights::READ)?;

        let bytes = {
            let core = state
                .socket_cores
                .get_mut(&endpoint.core_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            core.read(endpoint.side, len, !peek)?
        };

        if !peek {
            state.note_socket_read(bytes.len());
            let _ = crate::wait::notify_waitable_signals_changed(state, resolved.object_id());
            let _ = crate::wait::notify_waitable_signals_changed(state, endpoint.peer_object_id);
        }
        Ok(bytes)
    })
}

/// Write one copied message into the peer side of a channel.
pub fn channel_write(
    handle: zx_handle_t,
    options: u32,
    payload: ChannelPayload,
    handles: Vec<zx_handle_t>,
) -> Result<(), zx_status_t> {
    if options != 0 {
        let _ = with_state_mut(|state| {
            release_channel_payload(state, payload);
            Ok(())
        });
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let mut payload = Some(payload);
        let mut transferred = Vec::new();
        let resolved = match state.lookup_handle(handle, crate::task::HandleRights::empty()) {
            Ok(resolved) => resolved,
            Err(status) => {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(status);
            }
        };
        let object_id = resolved.object_id();
        let peer_object_id = {
            let endpoint = match state.objects.get(&object_id) {
                Some(KernelObject::Channel(endpoint)) => endpoint,
                Some(_) => {
                    if let Some(payload) = payload.take() {
                        release_channel_payload(state, payload);
                    }
                    return Err(ZX_ERR_WRONG_TYPE);
                }
                None => {
                    if let Some(payload) = payload.take() {
                        release_channel_payload(state, payload);
                    }
                    return Err(ZX_ERR_BAD_HANDLE);
                }
            };
            if let Err(status) = require_handle_rights(resolved, crate::task::HandleRights::WRITE) {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(status);
            }
            endpoint.peer_object_id
        };

        let receiver_address_space_id = {
            let peer = match state.objects.get(&peer_object_id) {
                Some(KernelObject::Channel(peer)) => peer,
                Some(_) => {
                    if let Some(payload) = payload.take() {
                        release_channel_payload(state, payload);
                    }
                    return Err(ZX_ERR_BAD_STATE);
                }
                None => {
                    if let Some(payload) = payload.take() {
                        release_channel_payload(state, payload);
                    }
                    return Err(ZX_ERR_PEER_CLOSED);
                }
            };
            if peer.closed {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(ZX_ERR_PEER_CLOSED);
            }
            if peer.messages.len() >= CHANNEL_CAPACITY {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(ZX_ERR_SHOULD_WAIT);
            }
            channel_endpoint_address_space_id(state, peer)?
        };

        if let Some(loaned) = payload.as_mut().and_then(ChannelPayload::loaned_body_mut) {
            match state.with_vm_mut(|vm| {
                vm.prepare_loaned_channel_write(loaned, receiver_address_space_id)
            }) {
                Ok(tlb_commit) => {
                    if let Err(status) = state.apply_tlb_commit_reqs(&[tlb_commit]) {
                        if let Some(released) = payload.take() {
                            release_channel_payload(state, released);
                        }
                        return Err(status);
                    }
                }
                Err(status) => {
                    if let Some(released) = payload.take() {
                        release_channel_payload(state, released);
                    }
                    return Err(status);
                }
            }
        }

        let mut seen_handles = BTreeSet::new();
        for raw in &handles {
            if !seen_handles.insert(*raw) {
                if let Some(released) = payload.take() {
                    release_channel_payload(state, released);
                }
                return Err(ZX_ERR_INVALID_ARGS);
            }
            match state.snapshot_handle_for_transfer(*raw, crate::task::HandleRights::TRANSFER) {
                Ok(entry) => transferred.push(entry),
                Err(status) => {
                    if let Some(released) = payload.take() {
                        release_channel_payload(state, released);
                    }
                    return Err(status);
                }
            }
        }

        let peer_status = match state.objects.get(&peer_object_id) {
            Some(KernelObject::Channel(peer)) if peer.closed => Some(ZX_ERR_PEER_CLOSED),
            Some(KernelObject::Channel(peer)) if peer.messages.len() >= CHANNEL_CAPACITY => {
                Some(ZX_ERR_SHOULD_WAIT)
            }
            Some(KernelObject::Channel(_)) => None,
            Some(_) => Some(ZX_ERR_BAD_STATE),
            None => Some(ZX_ERR_PEER_CLOSED),
        };
        if let Some(status) = peer_status {
            if let Some(payload) = payload.take() {
                release_channel_payload(state, payload);
            }
            return Err(status);
        }

        retain_transferred_handles(state, &transferred);
        let message = ChannelMessage {
            payload: payload.take().ok_or(ZX_ERR_BAD_STATE)?,
            handles: transferred,
        };
        match state.objects.get_mut(&peer_object_id) {
            Some(KernelObject::Channel(peer)) => peer.messages.push_back(message),
            Some(_) => return Err(ZX_ERR_BAD_STATE),
            None => return Err(ZX_ERR_PEER_CLOSED),
        }

        for raw in handles {
            state.close_handle(raw)?;
        }

        let _ = crate::wait::notify_waitable_signals_changed(state, object_id);
        let _ = crate::wait::notify_waitable_signals_changed(state, peer_object_id);
        Ok(())
    })
}

/// Read one copied message from a channel endpoint.
pub fn channel_read(
    handle: zx_handle_t,
    options: u32,
    num_bytes: u32,
    num_handles: u32,
) -> Result<ChannelReadResult, (zx_status_t, u32, u32)> {
    if options != 0 {
        return Err((ZX_ERR_INVALID_ARGS, 0, 0));
    }

    let mut guard = STATE.lock();
    let state = guard.as_mut().ok_or((ZX_ERR_BAD_STATE, 0, 0))?;
    let resolved = state
        .lookup_handle(handle, crate::task::HandleRights::empty())
        .map_err(|e| (e, 0, 0))?;
    let object_id = resolved.object_id();
    let (peer_object_id, transferred_handles) = {
        let endpoint = match state.objects.get(&object_id) {
            Some(KernelObject::Channel(endpoint)) => endpoint,
            Some(_) => return Err((ZX_ERR_WRONG_TYPE, 0, 0)),
            None => return Err((ZX_ERR_BAD_HANDLE, 0, 0)),
        };
        require_handle_rights(resolved, crate::task::HandleRights::READ).map_err(|e| (e, 0, 0))?;
        if let Some(message) = endpoint.messages.front() {
            let actual_bytes = message.actual_bytes().map_err(|e| (e, 0, 0))?;
            let actual_handles = message.actual_handles().map_err(|e| (e, 0, 0))?;
            if num_bytes < actual_bytes {
                return Err((ZX_ERR_BUFFER_TOO_SMALL, actual_bytes, actual_handles));
            }
            if num_handles < actual_handles {
                return Err((ZX_ERR_BUFFER_TOO_SMALL, actual_bytes, actual_handles));
            }
            (endpoint.peer_object_id, message.handles.clone())
        } else if endpoint.peer_closed {
            return Err((ZX_ERR_PEER_CLOSED, 0, 0));
        } else {
            return Err((ZX_ERR_SHOULD_WAIT, 0, 0));
        }
    };

    let mut installed_handles = Vec::new();
    for transferred in transferred_handles {
        match state.install_transferred_handle(transferred) {
            Ok(raw) => installed_handles.push(raw),
            Err(status) => {
                for raw in installed_handles {
                    let _ = state.close_handle(raw);
                }
                return Err((status, 0, 0));
            }
        }
    }

    let message = {
        let endpoint = match state.objects.get_mut(&object_id) {
            Some(KernelObject::Channel(endpoint)) => endpoint,
            Some(_) => return Err((ZX_ERR_WRONG_TYPE, 0, 0)),
            None => return Err((ZX_ERR_BAD_HANDLE, 0, 0)),
        };
        endpoint
            .messages
            .pop_front()
            .ok_or((ZX_ERR_BAD_STATE, 0, 0))?
    };
    let actual_bytes = message.actual_bytes().map_err(|e| (e, 0, 0))?;
    let actual_handles = message.actual_handles().map_err(|e| (e, 0, 0))?;
    release_transferred_handles(state, &message.handles);

    let _ = crate::wait::notify_waitable_signals_changed(state, object_id);
    let _ = crate::wait::notify_waitable_signals_changed(state, peer_object_id);

    Ok(ChannelReadResult {
        payload: message.payload,
        handles: installed_handles,
        actual_bytes,
        actual_handles,
    })
}

pub(crate) fn release_channel_read_result(result: ChannelReadResult) {
    let _ = with_state_mut(|state| {
        release_channel_payload(state, result.payload);
        Ok(())
    });
}
