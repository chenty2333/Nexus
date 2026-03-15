use super::super::*;

pub(in crate::starnix) fn prepare_process_carrier(
    parent_process: zx_handle_t,
    port: zx_handle_t,
    packet_key: u64,
    image_vmo: zx_handle_t,
    exec_blob: &[u8],
) -> Result<PreparedProcessCarrier, zx_status_t> {
    let mut process = ZX_HANDLE_INVALID;
    let mut root_vmar = ZX_HANDLE_INVALID;
    zx_status_result(zx_process_create(
        parent_process,
        0,
        &mut process,
        &mut root_vmar,
    ))?;
    let mut thread = ZX_HANDLE_INVALID;
    if let Err(status) = zx_status_result(zx_thread_create(process, 0, &mut thread)) {
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        return Err(status);
    }
    let mut sidecar = ZX_HANDLE_INVALID;
    if let Err(status) = zx_status_result(zx_vmo_create(
        ax_guest_stop_state_t::BYTE_LEN as u64,
        0,
        &mut sidecar,
    )) {
        let _ = zx_handle_close(thread);
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        return Err(status);
    }
    let mut session = ZX_HANDLE_INVALID;
    if let Err(status) = zx_status_result(ax_guest_session_create(
        thread,
        sidecar,
        port,
        packet_key,
        0,
        &mut session,
    )) {
        let _ = zx_handle_close(sidecar);
        let _ = zx_handle_close(thread);
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        return Err(status);
    }
    let mut prepared_entry = 0u64;
    let mut prepared_stack = 0u64;
    let prepare_status = ax_process_prepare_linux_exec(
        process,
        image_vmo,
        0,
        exec_blob,
        &mut prepared_entry,
        &mut prepared_stack,
    );
    if prepare_status != ZX_OK {
        let carrier = TaskCarrier {
            thread_handle: thread,
            session_handle: session,
            sidecar_vmo: sidecar,
            packet_key,
        };
        carrier.close();
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        return Err(prepare_status);
    }
    Ok(PreparedProcessCarrier {
        process_handle: process,
        root_vmar,
        carrier: TaskCarrier {
            thread_handle: thread,
            session_handle: session,
            sidecar_vmo: sidecar,
            packet_key,
        },
        prepared_entry,
        prepared_stack,
    })
}

pub(in crate::starnix) fn linux_guest_initial_regs(entry: u64, stack: u64) -> ax_guest_x64_regs_t {
    ax_guest_x64_regs_t {
        rax: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        r10: 0,
        r8: 0,
        r9: 0,
        rcx: 0,
        r11: 0,
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rip: entry,
        rsp: stack,
        rflags: 0x202,
    }
}

pub(in crate::starnix) fn start_prepared_carrier_guest(
    prepared: PreparedProcessCarrier,
    regs: &ax_guest_x64_regs_t,
    resources: ExecutiveState,
) -> Result<(ExecutiveState, TaskCarrier), zx_status_t> {
    let start_status = ax_process_start_guest(
        prepared.process_handle,
        prepared.carrier.thread_handle,
        regs,
        0,
    );
    if let Err(status) = zx_status_result(start_status) {
        prepared.close();
        return Err(status);
    }
    Ok((resources, prepared.carrier))
}

pub(in crate::starnix) fn create_thread_carrier(
    process_handle: zx_handle_t,
    port: zx_handle_t,
    packet_key: u64,
) -> Result<TaskCarrier, zx_status_t> {
    let mut thread = ZX_HANDLE_INVALID;
    zx_status_result(zx_thread_create(process_handle, 0, &mut thread))?;

    let mut sidecar = ZX_HANDLE_INVALID;
    if let Err(status) = zx_status_result(zx_vmo_create(
        ax_guest_stop_state_t::BYTE_LEN as u64,
        0,
        &mut sidecar,
    )) {
        let _ = zx_handle_close(thread);
        return Err(status);
    }

    let mut session = ZX_HANDLE_INVALID;
    if let Err(status) = zx_status_result(ax_guest_session_create(
        thread,
        sidecar,
        port,
        packet_key,
        0,
        &mut session,
    )) {
        let _ = zx_handle_close(sidecar);
        let _ = zx_handle_close(thread);
        return Err(status);
    }

    Ok(TaskCarrier {
        thread_handle: thread,
        session_handle: session,
        sidecar_vmo: sidecar,
        packet_key,
    })
}

pub(in crate::starnix) fn read_guest_bytes(
    session: zx_handle_t,
    addr: u64,
    len: usize,
) -> Result<Vec<u8>, zx_status_t> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_INTERNAL)?;
    bytes.resize(len, 0);
    let status = ax_guest_session_read_memory(session, addr, &mut bytes);
    if status != ZX_OK {
        return Err(status);
    }
    Ok(bytes)
}

pub(in crate::starnix) fn read_guest_u32(
    session: zx_handle_t,
    addr: u64,
) -> Result<u32, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, 4)?;
    let raw = bytes.get(..4).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(u32::from_ne_bytes(
        raw.try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    ))
}

pub(in crate::starnix) fn write_guest_u32(
    session: zx_handle_t,
    addr: u64,
    value: u32,
) -> Result<(), zx_status_t> {
    write_guest_bytes(session, addr, &value.to_ne_bytes())
}

pub(in crate::starnix) fn write_guest_bytes(
    session: zx_handle_t,
    addr: u64,
    bytes: &[u8],
) -> Result<(), zx_status_t> {
    let status = ax_guest_session_write_memory(session, addr, bytes);
    if status == ZX_OK { Ok(()) } else { Err(status) }
}

pub(in crate::starnix) fn copy_guest_region(
    src_session: zx_handle_t,
    dst_session: zx_handle_t,
    base: u64,
    len: u64,
) -> Result<(), zx_status_t> {
    let mut offset = 0u64;
    let chunk = [0u8; 4096];
    while offset < len {
        let remaining = len - offset;
        let chunk_len = remaining.min(chunk.len() as u64) as usize;
        let bytes = read_guest_bytes(src_session, base + offset, chunk_len)?;
        write_guest_bytes(dst_session, base + offset, &bytes)?;
        offset = offset
            .checked_add(chunk_len as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    }
    Ok(())
}

pub(in crate::starnix) fn read_guest_c_string(
    session: zx_handle_t,
    addr: u64,
    limit: usize,
) -> Result<String, zx_status_t> {
    let mut out = Vec::new();
    out.try_reserve_exact(limit.min(256))
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for index in 0..limit {
        let mut byte = [0u8; 1];
        let status = ax_guest_session_read_memory(session, addr + index as u64, &mut byte);
        if status != ZX_OK {
            return Err(status);
        }
        if byte[0] == 0 {
            return String::from_utf8(out).map_err(|_| ZX_ERR_BAD_PATH);
        }
        out.push(byte[0]);
    }
    Err(ZX_ERR_OUT_OF_RANGE)
}

pub(in crate::starnix) fn read_guest_u64(
    session: zx_handle_t,
    addr: u64,
) -> Result<u64, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, 8)?;
    Ok(u64::from_ne_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub(in crate::starnix) fn write_guest_u64(
    session: zx_handle_t,
    addr: u64,
    value: u64,
) -> Result<(), zx_status_t> {
    write_guest_bytes(session, addr, &value.to_ne_bytes())
}

pub(in crate::starnix) fn read_guest_i64(
    session: zx_handle_t,
    addr: u64,
) -> Result<i64, zx_status_t> {
    let value = read_guest_u64(session, addr)?;
    Ok(i64::from_ne_bytes(value.to_ne_bytes()))
}
