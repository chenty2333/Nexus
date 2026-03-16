use super::super::*;

#[derive(Clone, Copy, Default)]
pub(in crate::starnix) struct LinuxSigAction {
    pub(in crate::starnix) handler: u64,
    pub(in crate::starnix) flags: u64,
    pub(in crate::starnix) restorer: u64,
    pub(in crate::starnix) mask: u64,
}

pub(in crate::starnix) fn read_guest_signal_mask(
    session: zx_handle_t,
    addr: u64,
) -> Result<u64, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, LINUX_SIGNAL_SET_BYTES)?;
    let raw = bytes
        .get(..LINUX_SIGNAL_SET_BYTES)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(u64::from_ne_bytes(
        raw.try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
    ))
}

pub(in crate::starnix) fn write_guest_signal_mask(
    session: zx_handle_t,
    addr: u64,
    mask: u64,
) -> Result<(), zx_status_t> {
    write_guest_bytes(session, addr, &mask.to_ne_bytes())
}

pub(in crate::starnix) fn read_guest_sigaction(
    session: zx_handle_t,
    addr: u64,
) -> Result<LinuxSigAction, zx_status_t> {
    let bytes = read_guest_bytes(session, addr, LINUX_SIGACTION_BYTES)?;
    let raw = bytes
        .get(..LINUX_SIGACTION_BYTES)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(LinuxSigAction {
        handler: u64::from_ne_bytes(raw[0..8].try_into().map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?),
        flags: u64::from_ne_bytes(
            raw[8..16]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ),
        restorer: u64::from_ne_bytes(
            raw[16..24]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ),
        mask: u64::from_ne_bytes(
            raw[24..32]
                .try_into()
                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
        ),
    })
}

pub(in crate::starnix) fn write_guest_sigaction(
    session: zx_handle_t,
    addr: u64,
    action: LinuxSigAction,
) -> Result<(), zx_status_t> {
    let mut bytes = [0u8; LINUX_SIGACTION_BYTES];
    bytes[0..8].copy_from_slice(&action.handler.to_ne_bytes());
    bytes[8..16].copy_from_slice(&action.flags.to_ne_bytes());
    bytes[16..24].copy_from_slice(&action.restorer.to_ne_bytes());
    bytes[24..32].copy_from_slice(&action.mask.to_ne_bytes());
    write_guest_bytes(session, addr, &bytes)
}
