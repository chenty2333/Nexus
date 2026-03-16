use super::super::*;

fn read_all_fd_bytes(ops: &dyn FdOps) -> Result<Vec<u8>, zx_status_t> {
    let metadata = local_fd_metadata(ops).ok_or(ZX_ERR_NOT_SUPPORTED)?;
    let len = usize::try_from(metadata.size_bytes).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
    bytes.resize(len, 0);
    let actual = ops.read(&mut bytes)?;
    bytes.truncate(actual);
    Ok(bytes)
}

pub(in crate::starnix) fn open_exec_image_from_namespace(
    namespace: &nexus_io::ProcessNamespace,
    path: &str,
) -> Result<(String, Vec<u8>, zx_handle_t), zx_status_t> {
    let resolved = namespace.resolve_path(path)?;
    let ops = namespace.open(resolved.as_str(), OpenFlags::READABLE)?;
    let bytes = read_all_fd_bytes(ops.as_ref())?;
    let vmo = ops.as_vmo(nexus_io::VmoFlags::READ | nexus_io::VmoFlags::EXECUTE)?;
    Ok((resolved, bytes, vmo))
}

pub(in crate::starnix) fn read_exec_image_bytes_from_namespace(
    namespace: &nexus_io::ProcessNamespace,
    path: &str,
) -> Result<(String, Vec<u8>), zx_status_t> {
    let resolved = namespace.resolve_path(path)?;
    let ops = namespace.open(resolved.as_str(), OpenFlags::READABLE)?;
    let bytes = read_all_fd_bytes(ops.as_ref())?;
    Ok((resolved, bytes))
}

pub(in crate::starnix) fn read_guest_string_array(
    session: zx_handle_t,
    addr: u64,
    max_entries: usize,
) -> Result<Vec<String>, zx_status_t> {
    if addr == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    out.try_reserve(max_entries.min(8))
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for index in 0..max_entries {
        let entry_addr = addr
            .checked_add((index * 8) as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let value = read_guest_u64(session, entry_addr)?;
        if value == 0 {
            return Ok(out);
        }
        out.push(read_guest_c_string(session, value, LINUX_PATH_MAX)?);
    }
    Err(ZX_ERR_OUT_OF_RANGE)
}
