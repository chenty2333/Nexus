use super::super::*;

pub(in crate::starnix) fn read_guest_msghdr(
    session: zx_handle_t,
    addr: u64,
) -> Result<LinuxMsgHdr, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, LINUX_MSGHDR_BYTES)?;
    let name_addr = u64::from_ne_bytes(
        bytes[0..8]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    let name_len = u32::from_ne_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    let iov_addr = u64::from_ne_bytes(
        bytes[16..24]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    let iov_len = usize::try_from(u64::from_ne_bytes(
        bytes[24..32]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    ))
    .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let control_addr = u64::from_ne_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    let control_len = usize::try_from(u64::from_ne_bytes(
        bytes[40..48]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    ))
    .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let _flags = u32::from_ne_bytes(
        bytes[48..52]
            .try_into()
            .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    Ok(LinuxMsgHdr {
        name_addr,
        name_len,
        iov_addr,
        iov_len,
        control_addr,
        control_len,
    })
}

pub(in crate::starnix) fn read_guest_iovecs(
    session: zx_handle_t,
    addr: u64,
    count: usize,
) -> Result<Vec<LinuxIovec>, zx_status_t> {
    if count > LINUX_IOV_MAX {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    let mut iovecs = Vec::new();
    iovecs
        .try_reserve_exact(count)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for index in 0..count {
        let base = addr
            .checked_add(
                u64::try_from(
                    index
                        .checked_mul(LINUX_IOVEC_BYTES)
                        .ok_or(ZX_ERR_OUT_OF_RANGE)?,
                )
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
            )
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let bytes = read_guest_bytes(session, base, LINUX_IOVEC_BYTES)?;
        iovecs.push(LinuxIovec {
            base: u64::from_ne_bytes(
                bytes[0..8]
                    .try_into()
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
            ),
            len: usize::try_from(u64::from_ne_bytes(
                bytes[8..16]
                    .try_into()
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
            ))
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
        });
    }
    Ok(iovecs)
}

pub(in crate::starnix) fn total_iovec_len(iovecs: &[LinuxIovec]) -> Option<usize> {
    iovecs
        .iter()
        .try_fold(0usize, |total, iovec| total.checked_add(iovec.len))
}

pub(in crate::starnix) fn read_guest_iovec_payload(
    session: zx_handle_t,
    iovecs: &[LinuxIovec],
) -> Result<Vec<u8>, zx_status_t> {
    let total_len = total_iovec_len(iovecs).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(total_len)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for iovec in iovecs {
        if iovec.len == 0 {
            continue;
        }
        let bytes = read_guest_bytes(session, iovec.base, iovec.len)?;
        payload.extend_from_slice(&bytes);
    }
    Ok(payload)
}

pub(in crate::starnix) fn write_guest_iovec_payload(
    session: zx_handle_t,
    iovecs: &[LinuxIovec],
    payload: &[u8],
) -> Result<usize, zx_status_t> {
    let mut written = 0usize;
    for iovec in iovecs {
        if written >= payload.len() {
            break;
        }
        let chunk_len = (payload.len() - written).min(iovec.len);
        if chunk_len == 0 {
            continue;
        }
        write_guest_bytes(session, iovec.base, &payload[written..written + chunk_len])?;
        written = written.checked_add(chunk_len).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    }
    Ok(written)
}

pub(in crate::starnix) fn parse_scm_rights(
    session: zx_handle_t,
    fd_table: &FdTable,
    msg: &LinuxMsgHdr,
) -> Result<Option<PendingScmRights>, zx_status_t> {
    if msg.control_addr == 0 || msg.control_len == 0 {
        return Ok(None);
    }
    let control = read_guest_bytes(session, msg.control_addr, msg.control_len)?;
    let mut offset = 0usize;
    let mut descriptions = Vec::new();
    while offset
        .checked_add(LINUX_CMSGHDR_BYTES)
        .is_some_and(|end| end <= control.len())
    {
        let len = usize::try_from(u64::from_ne_bytes(
            control[offset..offset + 8]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ))
        .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let level = i32::from_ne_bytes(
            control[offset + 8..offset + 12]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        );
        let kind = i32::from_ne_bytes(
            control[offset + 12..offset + 16]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        );
        if len < LINUX_CMSGHDR_BYTES {
            return Err(ZX_ERR_IO_DATA_INTEGRITY);
        }
        let end = offset.checked_add(len).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if end > control.len() {
            return Err(ZX_ERR_IO_DATA_INTEGRITY);
        }
        if level == LINUX_SOL_SOCKET && kind == LINUX_SCM_RIGHTS {
            let data = &control[offset + LINUX_CMSGHDR_BYTES..end];
            if !data.len().is_multiple_of(4) {
                return Err(ZX_ERR_IO_DATA_INTEGRITY);
            }
            descriptions
                .try_reserve_exact(data.len() / 4)
                .map_err(|_| ZX_ERR_NO_MEMORY)?;
            for raw_fd in data.chunks_exact(4) {
                let fd =
                    i32::from_ne_bytes(raw_fd.try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?);
                let entry = fd_table.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
                descriptions.push(Arc::clone(entry.description()));
            }
        }
        let step = align_up(len, 8)?;
        offset = offset.checked_add(step).ok_or(ZX_ERR_OUT_OF_RANGE)?;
    }
    if descriptions.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PendingScmRights { descriptions }))
    }
}

pub(in crate::starnix) fn write_guest_recv_msghdr(
    session: zx_handle_t,
    msg_addr: u64,
    control_len: usize,
    flags: u32,
) -> Result<(), zx_status_t> {
    write_guest_u32(session, msg_addr + 8, 0)?;
    write_guest_u64(
        session,
        msg_addr + 40,
        u64::try_from(control_len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
    )?;
    write_guest_u32(session, msg_addr + 48, flags)?;
    Ok(())
}

pub(in crate::starnix) fn scm_rights_control_bytes(fd_count: usize) -> Result<usize, zx_status_t> {
    let raw_len = LINUX_CMSGHDR_BYTES
        .checked_add(fd_count.checked_mul(4).ok_or(ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    align_up(raw_len, 8)
}

pub(in crate::starnix) fn encode_scm_rights_control(fds: &[i32]) -> Result<Vec<u8>, zx_status_t> {
    let raw_len = LINUX_CMSGHDR_BYTES
        .checked_add(fds.len().checked_mul(4).ok_or(ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let total_len = scm_rights_control_bytes(fds.len())?;
    let mut control = Vec::new();
    control
        .try_reserve_exact(total_len)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    control.resize(total_len, 0);
    control[0..8].copy_from_slice(
        &u64::try_from(raw_len)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?
            .to_ne_bytes(),
    );
    control[8..12].copy_from_slice(&LINUX_SOL_SOCKET.to_ne_bytes());
    control[12..16].copy_from_slice(&LINUX_SCM_RIGHTS.to_ne_bytes());
    let mut cursor = LINUX_CMSGHDR_BYTES;
    for fd in fds {
        control[cursor..cursor + 4].copy_from_slice(&fd.to_ne_bytes());
        cursor += 4;
    }
    Ok(control)
}
