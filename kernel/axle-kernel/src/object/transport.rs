use super::*;
const CHANNEL_FRAGMENT_PAGE_BYTES: usize = crate::userspace::USER_PAGE_BYTES as usize;
const CHANNEL_FRAGMENT_POOL_CACHE_LIMIT_PER_CPU: usize = 8;

fn current_transport_cpu_id() -> usize {
    crate::arch::apic::this_apic_id() as usize
}

impl TransportCore {
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

    pub(super) fn note_socket_datagram_write(
        &mut self,
        requested: usize,
        buffered_after: usize,
        messages_after: usize,
    ) {
        if requested == 0 {
            return;
        }
        self.socket_telemetry.datagram_write_count =
            self.socket_telemetry.datagram_write_count.wrapping_add(1);
        self.socket_telemetry.datagram_current_buffered_bytes = buffered_after as u64;
        self.socket_telemetry.datagram_peak_buffered_bytes = self
            .socket_telemetry
            .datagram_peak_buffered_bytes
            .max(buffered_after as u64);
        self.socket_telemetry.datagram_current_buffered_messages = messages_after as u64;
        self.socket_telemetry.datagram_peak_buffered_messages = self
            .socket_telemetry
            .datagram_peak_buffered_messages
            .max(messages_after as u64);
    }

    pub(super) fn note_socket_datagram_write_should_wait(&mut self) {
        self.socket_telemetry.datagram_write_should_wait_count = self
            .socket_telemetry
            .datagram_write_should_wait_count
            .wrapping_add(1);
    }

    pub(super) fn note_socket_read(&mut self, consumed: usize) {
        self.socket_telemetry.current_buffered_bytes = self
            .socket_telemetry
            .current_buffered_bytes
            .saturating_sub(consumed as u64);
    }

    pub(super) fn note_socket_datagram_read(
        &mut self,
        buffered_after: usize,
        messages_after: usize,
        truncated: bool,
    ) {
        self.socket_telemetry.datagram_read_count =
            self.socket_telemetry.datagram_read_count.wrapping_add(1);
        if truncated {
            self.socket_telemetry.datagram_truncated_read_count = self
                .socket_telemetry
                .datagram_truncated_read_count
                .wrapping_add(1);
        }
        self.socket_telemetry.datagram_current_buffered_bytes = buffered_after as u64;
        self.socket_telemetry.datagram_current_buffered_messages = messages_after as u64;
    }

    pub(super) fn note_socket_core_drop(&mut self, core: &SocketCore) {
        match core.mode() {
            SocketMode::Stream => {
                self.socket_telemetry.current_buffered_bytes = self
                    .socket_telemetry
                    .current_buffered_bytes
                    .saturating_sub(core.buffered_bytes() as u64);
            }
            SocketMode::Datagram => {
                self.socket_telemetry.datagram_current_buffered_bytes = self
                    .socket_telemetry
                    .datagram_current_buffered_bytes
                    .saturating_sub(core.buffered_bytes() as u64);
                self.socket_telemetry.datagram_current_buffered_messages = self
                    .socket_telemetry
                    .datagram_current_buffered_messages
                    .saturating_sub(core.buffered_messages() as u64);
            }
        }
    }

    fn drain_remote_fragment_returns(&mut self, cpu_id: usize) {
        let Some(mut returned) = self.channel_fragment_pool.remote_returns.remove(&cpu_id) else {
            return;
        };
        self.channel_fragment_pool
            .local_cache
            .entry(cpu_id)
            .or_default()
            .append(&mut returned);
    }

    fn alloc_channel_fragment(&mut self, len: usize) -> Result<ChannelFragment, zx_status_t> {
        if len == 0 || len > CHANNEL_FRAGMENT_PAGE_BYTES {
            return Err(ZX_ERR_INVALID_ARGS);
        }

        let cpu_id = current_transport_cpu_id();
        self.drain_remote_fragment_returns(cpu_id);
        let page = if let Some(page) = self
            .channel_fragment_pool
            .local_cache
            .entry(cpu_id)
            .or_default()
            .pop()
        {
            self.channel_telemetry.fragment_pool_reuse_count = self
                .channel_telemetry
                .fragment_pool_reuse_count
                .wrapping_add(1);
            self.channel_telemetry.fragment_pool_cached_current = self
                .channel_telemetry
                .fragment_pool_cached_current
                .saturating_sub(1);
            page
        } else {
            let mut page_bytes = Vec::new();
            page_bytes
                .try_reserve_exact(CHANNEL_FRAGMENT_PAGE_BYTES)
                .map_err(|_| axle_types::status::ZX_ERR_NO_MEMORY)?;
            page_bytes.resize(CHANNEL_FRAGMENT_PAGE_BYTES, 0);
            self.channel_telemetry.fragment_pool_new_count = self
                .channel_telemetry
                .fragment_pool_new_count
                .wrapping_add(1);
            ChannelFragmentPage {
                owner_cpu: cpu_id,
                bytes: page_bytes,
            }
        };

        let mut page = page;
        page.owner_cpu = cpu_id;
        Ok(ChannelFragment {
            page,
            len: u16::try_from(len).map_err(|_| axle_types::status::ZX_ERR_OUT_OF_RANGE)?,
        })
    }

    fn recycle_channel_fragment(&mut self, fragment: ChannelFragment) {
        let cpu_id = current_transport_cpu_id();
        let page = fragment.into_page();
        let owner_cpu = page.owner_cpu;
        let cache = if owner_cpu == cpu_id {
            self.channel_telemetry.fragment_pool_local_free_count = self
                .channel_telemetry
                .fragment_pool_local_free_count
                .wrapping_add(1);
            self.channel_fragment_pool
                .local_cache
                .entry(owner_cpu)
                .or_default()
        } else {
            self.channel_telemetry.fragment_pool_remote_free_count = self
                .channel_telemetry
                .fragment_pool_remote_free_count
                .wrapping_add(1);
            self.channel_fragment_pool
                .remote_returns
                .entry(owner_cpu)
                .or_default()
        };
        if cache.len() < CHANNEL_FRAGMENT_POOL_CACHE_LIMIT_PER_CPU {
            cache.push(page);
            self.channel_telemetry.fragment_pool_cached_current = self
                .channel_telemetry
                .fragment_pool_cached_current
                .wrapping_add(1);
            self.channel_telemetry.fragment_pool_cached_peak = self
                .channel_telemetry
                .fragment_pool_cached_peak
                .max(self.channel_telemetry.fragment_pool_cached_current);
        }
    }

    fn note_channel_desc_enqueued(
        &mut self,
        fragmented: bool,
        actual_bytes: u32,
        actual_handles: u32,
    ) {
        self.channel_telemetry.desc_enqueued_count =
            self.channel_telemetry.desc_enqueued_count.wrapping_add(1);
        if fragmented {
            self.channel_telemetry.fragmented_desc_count =
                self.channel_telemetry.fragmented_desc_count.wrapping_add(1);
            self.channel_telemetry.fragmented_bytes_total = self
                .channel_telemetry
                .fragmented_bytes_total
                .wrapping_add(u64::from(actual_bytes));
        }
        crate::trace::record_channel_enqueue(actual_bytes, actual_handles, fragmented);
    }

    fn note_channel_desc_dequeued(&mut self) {
        self.channel_telemetry.desc_dequeued_count =
            self.channel_telemetry.desc_dequeued_count.wrapping_add(1);
    }

    fn note_channel_desc_reclaimed(&mut self, drained: bool) {
        self.channel_telemetry.desc_reclaimed_count =
            self.channel_telemetry.desc_reclaimed_count.wrapping_add(1);
        if drained {
            self.channel_telemetry.desc_drained_count =
                self.channel_telemetry.desc_drained_count.wrapping_add(1);
        }
    }
}

pub(crate) fn socket_telemetry_snapshot() -> SocketTelemetrySnapshot {
    with_state_mut(|state| state.with_transport(|transport| Ok(transport.socket_telemetry)))
        .unwrap_or_default()
}

pub(crate) fn channel_telemetry_snapshot() -> ChannelTelemetrySnapshot {
    with_state_mut(|state| state.with_transport(|transport| Ok(transport.channel_telemetry)))
        .unwrap_or_default()
}

pub(crate) fn allocate_channel_fragment(len: usize) -> Result<ChannelFragment, zx_status_t> {
    with_state_mut(|state| {
        state.with_transport_mut(|transport| transport.alloc_channel_fragment(len))
    })
}

/// Create a socket endpoint pair and return both handles.
pub fn create_socket(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    let core = match options {
        ZX_SOCKET_STREAM => SocketCore::new_stream(SOCKET_STREAM_CAPACITY)?,
        ZX_SOCKET_DATAGRAM => SocketCore::new_datagram(
            SOCKET_DATAGRAM_CAPACITY_BYTES,
            SOCKET_DATAGRAM_CAPACITY_MESSAGES,
        ),
        _ => return Err(ZX_ERR_INVALID_ARGS),
    };

    with_state_mut(|state| {
        let job_id = state.current_job_id()?;
        state.quota_check_and_increment(job_id, ObjectKindTag::Socket)?;

        let result = (|| {
            let core_id =
                state.with_transport_mut(|transport| Ok(transport.alloc_socket_core_id()))?;
            state.with_transport_mut(|transport| {
                transport.socket_cores.insert(core_id, core);
                Ok(())
            })?;

            let left_object_id = state.alloc_object_id();
            let right_object_id = state.alloc_object_id();
            state.with_registry_mut(|registry| {
                registry.insert(
                    left_object_id,
                    KernelObject::Socket(SocketEndpoint {
                        core_id,
                        peer_object: right_object_id,
                        side: SocketSide::A,
                    }),
                )?;
                registry.insert(
                    right_object_id,
                    KernelObject::Socket(SocketEndpoint {
                        core_id,
                        peer_object: left_object_id,
                        side: SocketSide::B,
                    }),
                )?;
                Ok(())
            })?;

            let left_handle = match state
                .alloc_handle_for_object(left_object_id, handle::socket_default_rights())
            {
                Ok(handle) => handle,
                Err(err) => {
                    let _ = state.with_registry_mut(|registry| {
                        let _ = registry.remove(left_object_id);
                        let _ = registry.remove(right_object_id);
                        Ok(())
                    });
                    let _ = state.with_transport_mut(|transport| {
                        let _ = transport.socket_cores.remove(&core_id);
                        Ok(())
                    });
                    return Err(err);
                }
            };
            let right_handle = match state
                .alloc_handle_for_object(right_object_id, handle::socket_default_rights())
            {
                Ok(handle) => handle,
                Err(err) => {
                    let _ = state.close_handle(left_handle);
                    let _ = state.with_registry_mut(|registry| {
                        let _ = registry.remove(left_object_id);
                        let _ = registry.remove(right_object_id);
                        Ok(())
                    });
                    let _ = state.with_transport_mut(|transport| {
                        let _ = transport.socket_cores.remove(&core_id);
                        Ok(())
                    });
                    return Err(err);
                }
            };

            Ok((left_handle, right_handle))
        })();

        if result.is_err() {
            state.quota_decrement(job_id, ObjectKindTag::Socket);
        }
        result
    })
}

/// Create a channel endpoint pair and return both handles.
pub fn create_channel(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let job_id = state.current_job_id()?;
        state.quota_check_and_increment(job_id, ObjectKindTag::Channel)?;

        let result = (|| {
            let owner_process_id = state
                .with_kernel(|kernel| kernel.current_process_info())?
                .process_id();
            let left_object_id = state.alloc_object_id();
            let right_object_id = state.alloc_object_id();
            state.with_registry_mut(|registry| {
                registry.insert(
                    left_object_id,
                    KernelObject::Channel(ChannelEndpoint::new(
                        right_object_id,
                        owner_process_id,
                    )),
                )?;
                registry.insert(
                    right_object_id,
                    KernelObject::Channel(ChannelEndpoint::new(
                        left_object_id,
                        owner_process_id,
                    )),
                )?;
                Ok(())
            })?;

            let left_handle = match state
                .alloc_handle_for_object(left_object_id, handle::channel_default_rights())
            {
                Ok(handle) => handle,
                Err(e) => {
                    let _ = state.with_registry_mut(|registry| {
                        let _ = registry.remove(left_object_id);
                        let _ = registry.remove(right_object_id);
                        Ok(())
                    });
                    return Err(e);
                }
            };
            let right_handle = match state
                .alloc_handle_for_object(right_object_id, handle::channel_default_rights())
            {
                Ok(handle) => handle,
                Err(e) => {
                    let _ = state.close_handle(left_handle);
                    let _ = state.with_registry_mut(|registry| {
                        let _ = registry.remove(left_object_id);
                        let _ = registry.remove(right_object_id);
                        Ok(())
                    });
                    return Err(e);
                }
            };

            Ok((left_handle, right_handle))
        })();

        if result.is_err() {
            state.quota_decrement(job_id, ObjectKindTag::Channel);
        }
        result
    })
}

pub(super) fn release_data_payload(state: &KernelState, payload: DataPayload) {
    match payload {
        ChannelPayload::Copied(_) => {}
        ChannelPayload::Loaned(loaned) => {
            let _ = state.with_vm_mut(|vm| {
                vm.release_loaned_user_pages(loaned);
                Ok(())
            });
        }
        ChannelPayload::Fragmented(payload) => {
            if let Some(loaned) = payload.body {
                let _ = state.with_vm_mut(|vm| {
                    vm.release_loaned_user_pages(loaned);
                    Ok(())
                });
            }
            if let Some(head) = payload.head {
                let _ = state.with_transport_mut(|transport| {
                    transport.recycle_channel_fragment(head);
                    Ok(())
                });
            }
            if let Some(tail) = payload.tail {
                let _ = state.with_transport_mut(|transport| {
                    transport.recycle_channel_fragment(tail);
                    Ok(())
                });
            }
        }
    }
}

pub(super) fn release_channel_payload(state: &KernelState, payload: ChannelPayload) {
    release_data_payload(state, payload);
}

fn reclaim_data_payload(state: &KernelState, payload: DataPayload, drained: bool) {
    let actual_bytes = payload.actual_bytes().unwrap_or(0);
    let fragmented = matches!(&payload, ChannelPayload::Fragmented(_));
    let _ = state.with_transport_mut(|transport| {
        transport.note_channel_desc_reclaimed(drained);
        Ok(())
    });
    crate::trace::record_channel_reclaim(actual_bytes, fragmented, drained);
    release_data_payload(state, payload);
}

fn reclaim_channel_payload(state: &KernelState, payload: ChannelPayload, drained: bool) {
    reclaim_data_payload(state, payload, drained);
}

fn release_channel_message(state: &KernelState, message: ChannelMsgDesc) {
    let (payload, handles) = message.into_parts();
    release_transferred_handles(state, &handles);
    reclaim_data_payload(state, payload, true);
}

fn retain_transferred_handles(state: &KernelState, handles: &[TransferredCap]) {
    for transferred in handles {
        let _ = state.with_registry_mut(|registry| {
            registry.increment_handle_ref(transferred.capability().object_key())
        });
    }
}

fn release_transferred_handles(state: &KernelState, handles: &[TransferredCap]) {
    for transferred in handles {
        state.decrement_object_handle_ref(transferred.capability().object_key());
    }
}

struct HandleInstallBatch<'a> {
    state: &'a KernelState,
    installed: Vec<zx_handle_t>,
}

impl<'a> HandleInstallBatch<'a> {
    fn new(state: &'a KernelState) -> Self {
        Self {
            state,
            installed: Vec::new(),
        }
    }

    fn install(&mut self, transferred: TransferredCap) -> Result<(), zx_status_t> {
        let raw = self.state.install_transferred_handle(transferred)?;
        self.installed.push(raw);
        Ok(())
    }

    fn commit(mut self) -> Vec<zx_handle_t> {
        core::mem::take(&mut self.installed)
    }
}

impl Drop for HandleInstallBatch<'_> {
    fn drop(&mut self) {
        for raw in self.installed.drain(..) {
            let _ = self.state.close_handle(raw);
        }
    }
}

pub(super) fn drain_channel_messages(
    state: &KernelState,
    messages: impl IntoIterator<Item = ChannelMsgDesc>,
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
        KernelObject::Socket(endpoint) => Some(state.with_transport(|transport| {
            let core = transport
                .socket_cores
                .get(&endpoint.core_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            Ok(core.signals_for(endpoint.side))
        })),
        KernelObject::Channel(endpoint) => Some(state.with_registry(|registry| {
            let mut signals = Signals::NONE;
            if endpoint.is_readable() {
                signals = signals | Signals::CHANNEL_READABLE;
            }
            if endpoint.peer_closed {
                signals = signals | Signals::CHANNEL_PEER_CLOSED;
            } else {
                let peer = match registry.get(endpoint.peer_object) {
                    Some(KernelObject::Channel(peer)) => peer,
                    _ => return Err(ZX_ERR_BAD_STATE),
                };
                if endpoint.writable_via_peer(peer) {
                    signals = signals | Signals::CHANNEL_WRITABLE;
                }
            }
            Ok(signals)
        })),
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
    with_state_mut(|state| {
        state.with_vm_mut(|vm| vm.try_loan_user_pages(address_space_id, ptr, len))
    })
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
        let remap = state.with_vm_mut(|vm| {
            vm.try_remap_loaned_channel_read(address_space_id, dst_base, loaned)
        })?;
        state.apply_tlb_commit_reqs(&[remap.tlb_commit()])?;
        if !remap.retire_plan().is_empty() {
            state.retire_bootstrap_frames_after_quiescence(
                remap.retire_plan().barrier_address_spaces(),
                remap.retire_plan().retired_frames(),
            )?;
        }
        Ok(remap.did_remap())
    })
}

pub(crate) fn socket_is_datagram(handle: zx_handle_t) -> Result<bool, zx_status_t> {
    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::empty())?;
        let endpoint =
            state.with_registry(|registry| match registry.get(resolved.object_key()) {
                Some(KernelObject::Socket(endpoint)) => Ok(*endpoint),
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            })?;
        state.with_transport(|transport| {
            let core = transport
                .socket_cores
                .get(&endpoint.core_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            Ok(core.mode() == SocketMode::Datagram)
        })
    })
}

/// Write bytes into one socket endpoint.
pub fn socket_write(handle: zx_handle_t, options: u32, bytes: &[u8]) -> Result<usize, zx_status_t> {
    if options != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::WRITE)?;
        let endpoint =
            state.with_registry(|registry| match registry.get(resolved.object_key()) {
                Some(KernelObject::Socket(endpoint)) => Ok(*endpoint),
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            })?;

        let write_result = state.with_transport_mut(|transport| {
            let core = transport
                .socket_cores
                .get_mut(&endpoint.core_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            Ok(match core.write(endpoint.side, bytes) {
                Ok(written) => Ok((
                    written,
                    core.mode(),
                    core.buffered_bytes(),
                    core.buffered_messages(),
                )),
                Err(ZX_ERR_SHOULD_WAIT) => Err((
                    ZX_ERR_SHOULD_WAIT,
                    core.mode(),
                    core.buffered_bytes(),
                    core.buffered_messages(),
                )),
                Err(e) => Err((
                    e,
                    core.mode(),
                    core.buffered_bytes(),
                    core.buffered_messages(),
                )),
            })
        })?;
        let (written, mode, buffered_after, messages_after) = match write_result {
            Ok(result) => result,
            Err((ZX_ERR_SHOULD_WAIT, mode, buffered_after, _messages_after)) => {
                let _ = state.with_transport_mut(|transport| {
                    match mode {
                        SocketMode::Stream => {
                            transport.note_socket_write(bytes.len(), 0, buffered_after);
                        }
                        SocketMode::Datagram => transport.note_socket_datagram_write_should_wait(),
                    }
                    Ok(())
                });
                return Err(ZX_ERR_SHOULD_WAIT);
            }
            Err((e, _, _, _)) => return Err(e),
        };
        state.with_transport_mut(|transport| {
            match mode {
                SocketMode::Stream => {
                    transport.note_socket_write(bytes.len(), written, buffered_after)
                }
                SocketMode::Datagram => {
                    transport.note_socket_datagram_write(written, buffered_after, messages_after);
                    crate::trace::record_socket_datagram_enqueue(
                        written as u32,
                        messages_after as u32,
                        buffered_after as u32,
                    );
                }
            }
            Ok(())
        })?;
        let _ = publish_object_signals(state, resolved.object_key());
        let _ = publish_object_signals(state, endpoint.peer_object);
        Ok(written)
    })
}

/// Write one message-atomic payload into one DATAGRAM socket endpoint.
pub fn socket_write_payload(
    handle: zx_handle_t,
    options: u32,
    payload: DataPayload,
) -> Result<usize, zx_status_t> {
    if options != 0 {
        let _ = with_state_mut(|state| {
            release_data_payload(state, payload);
            Ok(())
        });
        return Err(ZX_ERR_INVALID_ARGS);
    }

    with_state_mut(|state| {
        let mut payload = Some(payload);
        let resolved = match state.lookup_handle(handle, crate::task::HandleRights::WRITE) {
            Ok(resolved) => resolved,
            Err(status) => {
                if let Some(payload) = payload.take() {
                    release_data_payload(state, payload);
                }
                return Err(status);
            }
        };
        let endpoint =
            match state.with_registry(|registry| match registry.get(resolved.object_key()) {
                Some(KernelObject::Socket(endpoint)) => Ok(*endpoint),
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            }) {
                Ok(endpoint) => endpoint,
                Err(status) => {
                    if let Some(payload) = payload.take() {
                        release_data_payload(state, payload);
                    }
                    return Err(status);
                }
            };

        let Some(write_payload) = payload.take() else {
            return Err(ZX_ERR_BAD_STATE);
        };
        let payload_len =
            usize::try_from(write_payload.actual_bytes()?).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let preflight = state.with_transport(|transport| {
            let Some(core) = transport.socket_cores.get(&endpoint.core_id) else {
                return Err(ZX_ERR_BAD_STATE);
            };
            if core.mode() != SocketMode::Datagram {
                return Err(ZX_ERR_WRONG_TYPE);
            }
            let (queue, peer_open) = match endpoint.side {
                SocketSide::A => (&core.dir_ab, core.open_b),
                SocketSide::B => (&core.dir_ba, core.open_a),
            };
            if !peer_open {
                return Err(ZX_ERR_PEER_CLOSED);
            }
            match queue {
                SocketQueue::Stream(_) => Err(ZX_ERR_WRONG_TYPE),
                SocketQueue::Datagram(queue) => {
                    let Some(next_bytes) = queue.buffered_bytes().checked_add(payload_len) else {
                        return Err(ZX_ERR_OUT_OF_RANGE);
                    };
                    if queue.queued_messages() >= queue.capacity_messages
                        || next_bytes > queue.capacity_bytes
                    {
                        return Err(ZX_ERR_SHOULD_WAIT);
                    }
                    Ok(())
                }
            }
        });

        if let Err(status) = preflight {
            release_data_payload(state, write_payload);
            if status == ZX_ERR_SHOULD_WAIT {
                let _ = state.with_transport_mut(|transport| {
                    transport.note_socket_datagram_write_should_wait();
                    Ok(())
                });
            }
            return Err(status);
        }

        let (written, buffered_after, messages_after) = state.with_transport_mut(|transport| {
            let core = transport
                .socket_cores
                .get_mut(&endpoint.core_id)
                .ok_or(ZX_ERR_BAD_STATE)?;
            let written = core.write_payload(endpoint.side, write_payload)?;
            Ok((written, core.buffered_bytes(), core.buffered_messages()))
        })?;

        state.with_transport_mut(|transport| {
            transport.note_socket_datagram_write(written, buffered_after, messages_after);
            crate::trace::record_socket_datagram_enqueue(
                written as u32,
                messages_after as u32,
                buffered_after as u32,
            );
            Ok(())
        })?;
        let _ = publish_object_signals(state, resolved.object_key());
        let _ = publish_object_signals(state, endpoint.peer_object);
        Ok(payload_len)
    })
}

/// Read bytes from one socket endpoint.
pub fn socket_read(
    handle: zx_handle_t,
    options: u32,
    len: usize,
) -> Result<SocketReadResult, zx_status_t> {
    let peek = match options {
        0 => false,
        ZX_SOCKET_PEEK => true,
        _ => return Err(ZX_ERR_INVALID_ARGS),
    };

    with_state_mut(|state| {
        let resolved = state.lookup_handle(handle, crate::task::HandleRights::READ)?;
        let endpoint =
            state.with_registry(|registry| match registry.get(resolved.object_key()) {
                Some(KernelObject::Socket(endpoint)) => Ok(*endpoint),
                Some(_) => Err(ZX_ERR_WRONG_TYPE),
                None => Err(ZX_ERR_BAD_HANDLE),
            })?;

        let (result, mode, buffered_after, messages_after) =
            state.with_transport_mut(|transport| {
                let core = transport
                    .socket_cores
                    .get_mut(&endpoint.core_id)
                    .ok_or(ZX_ERR_BAD_STATE)?;
                let result = core.read(endpoint.side, len, !peek)?;
                Ok((
                    result,
                    core.mode(),
                    core.buffered_bytes(),
                    core.buffered_messages(),
                ))
            })?;

        if !peek {
            let copied_bytes = match &result.payload {
                SocketReadPayload::Copied(bytes) => bytes.len(),
                SocketReadPayload::Payload(_) => len.min(result.actual_bytes),
            };
            let truncated = result.actual_bytes > copied_bytes;
            state.with_transport_mut(|transport| {
                match mode {
                    SocketMode::Stream => transport.note_socket_read(copied_bytes),
                    SocketMode::Datagram => transport.note_socket_datagram_read(
                        buffered_after,
                        messages_after,
                        truncated,
                    ),
                }
                if mode == SocketMode::Datagram {
                    crate::trace::record_socket_datagram_dequeue(
                        copied_bytes as u32,
                        truncated,
                        messages_after as u32,
                    );
                }
                Ok(())
            })?;
            let _ = publish_object_signals(state, resolved.object_key());
            let _ = publish_object_signals(state, endpoint.peer_object);
        }
        Ok(result)
    })
}

pub(super) fn release_socket_core(state: &KernelState, core: SocketCore) {
    let _ = state.with_transport_mut(|transport| {
        transport.note_socket_core_drop(&core);
        Ok(())
    });
    for payload in core.into_queued_payloads() {
        release_data_payload(state, payload);
    }
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
        let resolved = match state.lookup_handle(handle, crate::task::HandleRights::WRITE) {
            Ok(resolved) => resolved,
            Err(status) => {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(status);
            }
        };
        let object_id = resolved.object_key();
        let peer_object_id = {
            let peer_object_id =
                match state.with_registry(|registry| match registry.get(object_id) {
                    Some(KernelObject::Channel(endpoint)) => Ok(endpoint.peer_object),
                    Some(_) => Err(ZX_ERR_WRONG_TYPE),
                    None => Err(ZX_ERR_BAD_HANDLE),
                }) {
                    Ok(peer_object_id) => peer_object_id,
                    Err(status) => {
                        if let Some(payload) = payload.take() {
                            release_channel_payload(state, payload);
                        }
                        return Err(status);
                    }
                };
            peer_object_id
        };

        let receiver_address_space_id = {
            let (peer_closed, peer_len, owner_process_id) =
                match state.with_registry(|registry| match registry.get(peer_object_id) {
                    Some(KernelObject::Channel(peer)) => {
                        Ok((peer.closed, peer.messages.len(), peer.owner_process_id))
                    }
                    Some(_) => Err(ZX_ERR_BAD_STATE),
                    None => Err(ZX_ERR_PEER_CLOSED),
                }) {
                    Ok(peer_state) => peer_state,
                    Err(status) => {
                        if let Some(payload) = payload.take() {
                            release_channel_payload(state, payload);
                        }
                        return Err(status);
                    }
                };
            if peer_closed {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(ZX_ERR_PEER_CLOSED);
            }
            if peer_len >= CHANNEL_CAPACITY {
                if let Some(payload) = payload.take() {
                    release_channel_payload(state, payload);
                }
                return Err(ZX_ERR_SHOULD_WAIT);
            }
            let peer = ChannelEndpoint::new(peer_object_id, owner_process_id);
            match channel_endpoint_address_space_id(state, &peer) {
                Ok(address_space_id) => address_space_id,
                Err(status) => {
                    if let Some(payload) = payload.take() {
                        release_channel_payload(state, payload);
                    }
                    return Err(status);
                }
            }
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

        let peer_status = state.with_registry(|registry| {
            Ok(match registry.get(peer_object_id) {
                Some(KernelObject::Channel(peer)) if peer.closed => Some(ZX_ERR_PEER_CLOSED),
                Some(KernelObject::Channel(peer)) if peer.messages.len() >= CHANNEL_CAPACITY => {
                    Some(ZX_ERR_SHOULD_WAIT)
                }
                Some(KernelObject::Channel(_)) => None,
                Some(_) => Some(ZX_ERR_BAD_STATE),
                None => Some(ZX_ERR_PEER_CLOSED),
            })
        })?;
        if let Some(status) = peer_status {
            if let Some(payload) = payload.take() {
                release_channel_payload(state, payload);
            }
            return Err(status);
        }

        let message = ChannelMsgDesc::new(payload.take().ok_or(ZX_ERR_BAD_STATE)?, transferred)?;
        let actual_bytes = message.actual_bytes();
        let actual_handles = message.actual_handles();
        let fragmented = message.is_fragmented();
        retain_transferred_handles(state, message.handles());
        state.with_registry_mut(|registry| {
            match registry.get_mut(peer_object_id) {
                Some(KernelObject::Channel(peer)) => peer.messages.push_back(message),
                Some(_) => return Err(ZX_ERR_BAD_STATE),
                None => return Err(ZX_ERR_PEER_CLOSED),
            }
            Ok(())
        })?;
        state.with_transport_mut(|transport| {
            transport.note_channel_desc_enqueued(fragmented, actual_bytes, actual_handles);
            Ok(())
        })?;

        for raw in handles {
            // Ignore close errors: handles were already validated during the
            // snapshot-for-transfer step above.  Propagating a mid-loop error
            // here would leave some source handles unclosed while the message
            // has already been enqueued with retained object references,
            // causing a handle leak.
            let _ = state.close_handle(raw);
        }

        let _ = publish_object_signals(state, object_id);
        let _ = publish_object_signals(state, peer_object_id);
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

    let state = state().map_err(|e| (e, 0, 0))?;
    let resolved = state
        .lookup_handle(handle, crate::task::HandleRights::READ)
        .map_err(|e| (e, 0, 0))?;
    let object_id = resolved.object_key();
    let (peer_object_id, transferred_handles, actual_bytes, actual_handles) = state
        .with_registry(|registry| {
            let endpoint = match registry.get(object_id) {
                Some(KernelObject::Channel(endpoint)) => endpoint,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            let Some(message) = endpoint.messages.front() else {
                return Err(if endpoint.peer_closed {
                    ZX_ERR_PEER_CLOSED
                } else {
                    ZX_ERR_SHOULD_WAIT
                });
            };
            let actual_bytes = message.actual_bytes();
            let actual_handles = message.actual_handles();
            Ok((
                endpoint.peer_object,
                message.handles().to_vec(),
                actual_bytes,
                actual_handles,
            ))
        })
        .map_err(|status| (status, 0, 0))?;
    if num_bytes < actual_bytes || num_handles < actual_handles {
        return Err((ZX_ERR_BUFFER_TOO_SMALL, actual_bytes, actual_handles));
    }

    let installed_handles = {
        let mut installs = HandleInstallBatch::new(state);
        for transferred in transferred_handles {
            installs
                .install(transferred)
                .map_err(|status| (status, 0, 0))?;
        }
        installs.commit()
    };

    let message = state
        .with_registry_mut(|registry| {
            let endpoint = match registry.get_mut(object_id) {
                Some(KernelObject::Channel(endpoint)) => endpoint,
                Some(_) => return Err(ZX_ERR_WRONG_TYPE),
                None => return Err(ZX_ERR_BAD_HANDLE),
            };
            endpoint.messages.pop_front().ok_or(ZX_ERR_BAD_STATE)
        })
        .map_err(|status| (status, 0, 0))?;
    state
        .with_transport_mut(|transport| {
            transport.note_channel_desc_dequeued();
            Ok(())
        })
        .map_err(|status| (status, 0, 0))?;
    let fragmented = message.is_fragmented();
    let (payload, retained_handles) = message.into_parts();
    crate::trace::record_channel_dequeue(actual_bytes, actual_handles, fragmented);
    release_transferred_handles(state, &retained_handles);

    let _ = publish_object_signals(state, object_id);
    let _ = publish_object_signals(state, peer_object_id);

    Ok(ChannelReadResult {
        payload,
        handles: installed_handles,
        actual_bytes,
        actual_handles,
    })
}

pub(crate) fn release_channel_read_result(result: ChannelReadResult) {
    let _ = with_state_mut(|state| {
        reclaim_channel_payload(state, result.payload, false);
        Ok(())
    });
}

pub(crate) fn release_socket_read_result(result: SocketReadResult) {
    if let SocketReadPayload::Payload(payload) = result.payload {
        let _ = with_state_mut(|state| {
            reclaim_data_payload(state, payload, false);
            Ok(())
        });
    }
}
