use super::super::*;

pub(in crate::starnix) fn read_guest_epoll_event(
    session: zx_handle_t,
    addr: u64,
) -> Result<LinuxEpollEvent, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, LINUX_EPOLL_EVENT_BYTES)?;
    let raw = bytes
        .get(..LINUX_EPOLL_EVENT_BYTES)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(LinuxEpollEvent {
        events: u32::from_ne_bytes(raw[0..4].try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?),
        data: u64::from_ne_bytes(
            raw[4..12]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ),
    })
}

pub(in crate::starnix) fn encode_epoll_events(
    events: &[LinuxEpollEvent],
) -> Result<Vec<u8>, zx_status_t> {
    let total = events
        .len()
        .checked_mul(LINUX_EPOLL_EVENT_BYTES)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    bytes.resize(total, 0);
    for (index, event) in events.iter().enumerate() {
        let start = index
            .checked_mul(LINUX_EPOLL_EVENT_BYTES)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        bytes[start..start + 4].copy_from_slice(&event.events.to_ne_bytes());
        bytes[start + 4..start + 12].copy_from_slice(&event.data.to_ne_bytes());
    }
    Ok(bytes)
}
