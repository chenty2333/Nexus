use alloc::vec;
use alloc::vec::Vec;

use axle_types::status::{
    ZX_ERR_BAD_STATE, ZX_ERR_IO_DATA_INTEGRITY, ZX_ERR_NOT_SUPPORTED, ZX_ERR_OUT_OF_RANGE,
    ZX_ERR_PEER_CLOSED, ZX_ERR_SHOULD_WAIT, ZX_OK,
};
use axle_types::{zx_handle_t, zx_status_t};
use libax::compat::{
    ZX_TIME_INFINITE, zx_channel_read_alloc, zx_channel_write, zx_handle_close, zx_vmo_create,
    zx_vmo_read, zx_vmo_write,
};
use nexus_fs_proto::{
    CloneRequest, CloseRequest, DescribeResponse, DirEntryRecord, FsMessageKind, GetVmoRequest,
    GetVmoResponse, NodeDescriptor, NodeKind, ObjectIdentity, OpenRequest, ReadDirRequest,
    ReadDirResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse, decode_message_kind,
};
use nexus_io::OpenFlags;

use crate::ECHO_PROTOCOL_NAME;
use crate::lifecycle::wait_for_channel_readable;

type ChannelMessage = (Vec<u8>, Vec<zx_handle_t>);

const FS_SESSION_ID: u64 = 1;
const ROOT_NODE_ID: u64 = 1;
const ROOT_OPEN_FILE_ID: u64 = 1;
const ROOT_CLONE_OPEN_FILE_ID: u64 = 3;
const ECHO_NODE_ID: u64 = 2;
const ECHO_FILE_OPEN_FILE_ID: u64 = 2;
const ECHO_FILE_FROM_CLONED_DIR_OPEN_FILE_ID: u64 = 4;
const ECHO_FILE_CLONE_OPEN_FILE_ID: u64 = 5;
const BULK_DATA_THRESHOLD: usize = 1024;
const BULK_VMO_PAGE_BYTES: u64 = 4096;

pub(crate) fn root_directory_descriptor() -> NodeDescriptor {
    NodeDescriptor::new(
        ObjectIdentity::new(FS_SESSION_ID, ROOT_OPEN_FILE_ID, ROOT_NODE_ID),
        (OpenFlags::READABLE | OpenFlags::DIRECTORY).bits(),
        NodeKind::Directory,
    )
}

pub(crate) fn run_echo_fs_provider(outgoing: zx_handle_t, echo_bytes: &[u8]) -> i32 {
    match serve_directory(outgoing, root_directory_descriptor(), echo_bytes) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

pub(crate) fn proxy_directory_requests_until_peer_closed(
    client_directory: zx_handle_t,
    provider_directory: zx_handle_t,
    first_message: Option<ChannelMessage>,
) -> Result<(), zx_status_t> {
    if let Some((bytes, handles)) = first_message {
        forward_raw_message(provider_directory, &bytes, &handles)?;
    }
    loop {
        let Some((bytes, handles)) = read_message_waiting(client_directory)? else {
            return Ok(());
        };
        forward_raw_message(provider_directory, &bytes, &handles)?;
    }
}

pub(crate) fn read_directory_request_for_launch(
    handle: zx_handle_t,
) -> Result<Option<ChannelMessage>, zx_status_t> {
    read_message_waiting(handle)
}

fn serve_directory(
    handle: zx_handle_t,
    descriptor: NodeDescriptor,
    echo_bytes: &[u8],
) -> Result<(), zx_status_t> {
    loop {
        let Some((bytes, handles)) = read_message_polling(handle)? else {
            return Ok(());
        };
        match decode_message_kind(&bytes).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)? {
            FsMessageKind::OpenRequest => {
                let request = OpenRequest::decode_channel_message(&bytes, &handles)
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
                ensure_identity(request.object, descriptor.identity)?;
                if !echo_service_path_matches(request.path.as_str()) {
                    return Err(ZX_ERR_BAD_STATE);
                }
                let file_descriptor =
                    file_descriptor_for_directory(descriptor.identity.open_file_id, request.flags)?;
                send_describe(request.opened_object, file_descriptor)?;
                serve_file(request.opened_object, file_descriptor, echo_bytes)?;
            }
            FsMessageKind::ReadDirRequest => {
                let request = ReadDirRequest::decode_channel_message(&bytes, &handles)
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
                ensure_identity(request.object, descriptor.identity)?;
                send_readdir_response(
                    handle,
                    ZX_OK,
                    &[DirEntryRecord::new(ECHO_PROTOCOL_NAME, NodeKind::Service)],
                )?;
            }
            FsMessageKind::CloneRequest => {
                let request = CloneRequest::decode_channel_message(&bytes, &handles)
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
                ensure_identity(request.object, descriptor.identity)?;
                let cloned_descriptor = clone_directory_descriptor(descriptor, request.flags)?;
                send_describe(request.cloned_object, cloned_descriptor)?;
                serve_directory(request.cloned_object, cloned_descriptor, echo_bytes)?;
            }
            FsMessageKind::CloseRequest => {
                let request = CloseRequest::decode_channel_message(&bytes, &handles)
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
                ensure_identity(request.object, descriptor.identity)?;
                return Ok(());
            }
            FsMessageKind::GetVmoRequest => {
                let request = GetVmoRequest::decode_channel_message(&bytes, &handles)
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
                ensure_identity(request.object, descriptor.identity)?;
                send_get_vmo_response(handle, ZX_ERR_NOT_SUPPORTED, None)?;
            }
            _ => return Err(ZX_ERR_IO_DATA_INTEGRITY),
        }
    }
}

fn serve_file(
    handle: zx_handle_t,
    descriptor: NodeDescriptor,
    echo_bytes: &[u8],
) -> Result<(), zx_status_t> {
    let mut pending = echo_bytes.to_vec();
    loop {
        let Some((bytes, handles)) = read_message_polling(handle)? else {
            return Ok(());
        };
        match decode_message_kind(&bytes).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)? {
            FsMessageKind::WriteRequest => {
                let request = WriteRequest::decode_channel_message(&bytes, &handles)
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
                ensure_identity(request.object, descriptor.identity)?;
                pending = if let Some(vmo) = request.vmo {
                    read_bulk_vmo_bytes(vmo, request.bulk_len as usize)?
                } else {
                    request.bytes.clone()
                };
                send_write_response(
                    handle,
                    ZX_OK,
                    u32::try_from(pending.len()).map_err(|_| ZX_ERR_BAD_STATE)?,
                )?;
            }
            FsMessageKind::ReadRequest => {
                let request = ReadRequest::decode_channel_message(&bytes, &handles)
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
                ensure_identity(request.object, descriptor.identity)?;
                let max_bytes = usize::try_from(request.max_bytes).map_err(|_| ZX_ERR_BAD_STATE)?;
                let actual = pending.iter().copied().take(max_bytes).collect::<Vec<u8>>();
                send_read_response(handle, ZX_OK, &actual)?;
            }
            FsMessageKind::CloneRequest => {
                let request = CloneRequest::decode_channel_message(&bytes, &handles)
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
                ensure_identity(request.object, descriptor.identity)?;
                let cloned_descriptor = clone_file_descriptor(descriptor, request.flags)?;
                send_describe(request.cloned_object, cloned_descriptor)?;
                serve_file(request.cloned_object, cloned_descriptor, &pending)?;
            }
            FsMessageKind::CloseRequest => {
                let request = CloseRequest::decode_channel_message(&bytes, &handles)
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
                ensure_identity(request.object, descriptor.identity)?;
                return Ok(());
            }
            FsMessageKind::GetVmoRequest => {
                let request = GetVmoRequest::decode_channel_message(&bytes, &handles)
                    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
                ensure_identity(request.object, descriptor.identity)?;
                send_get_vmo_response(handle, ZX_ERR_NOT_SUPPORTED, None)?;
            }
            _ => return Err(ZX_ERR_IO_DATA_INTEGRITY),
        }
    }
}

fn file_descriptor_for_directory(
    directory_open_file_id: u64,
    flags: u32,
) -> Result<NodeDescriptor, zx_status_t> {
    let open_file_id = match directory_open_file_id {
        ROOT_OPEN_FILE_ID => ECHO_FILE_OPEN_FILE_ID,
        ROOT_CLONE_OPEN_FILE_ID => ECHO_FILE_FROM_CLONED_DIR_OPEN_FILE_ID,
        _ => return Err(ZX_ERR_BAD_STATE),
    };
    Ok(NodeDescriptor::new(
        ObjectIdentity::new(FS_SESSION_ID, open_file_id, ECHO_NODE_ID),
        flags,
        NodeKind::Service,
    ))
}

fn clone_directory_descriptor(
    descriptor: NodeDescriptor,
    flags: u32,
) -> Result<NodeDescriptor, zx_status_t> {
    if descriptor.identity.open_file_id != ROOT_OPEN_FILE_ID {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    Ok(NodeDescriptor::new(
        ObjectIdentity::new(FS_SESSION_ID, ROOT_CLONE_OPEN_FILE_ID, ROOT_NODE_ID),
        if flags == 0 { descriptor.flags } else { flags },
        NodeKind::Directory,
    ))
}

fn clone_file_descriptor(
    descriptor: NodeDescriptor,
    flags: u32,
) -> Result<NodeDescriptor, zx_status_t> {
    match descriptor.identity.open_file_id {
        ECHO_FILE_OPEN_FILE_ID | ECHO_FILE_FROM_CLONED_DIR_OPEN_FILE_ID => {}
        _ => return Err(ZX_ERR_NOT_SUPPORTED),
    }
    Ok(NodeDescriptor::new(
        ObjectIdentity::new(FS_SESSION_ID, ECHO_FILE_CLONE_OPEN_FILE_ID, ECHO_NODE_ID),
        if flags == 0 { descriptor.flags } else { flags },
        descriptor.kind,
    ))
}

fn ensure_identity(actual: ObjectIdentity, expected: ObjectIdentity) -> Result<(), zx_status_t> {
    if actual == expected {
        Ok(())
    } else {
        Err(ZX_ERR_BAD_STATE)
    }
}

fn send_describe(handle: zx_handle_t, descriptor: NodeDescriptor) -> Result<(), zx_status_t> {
    write_message(
        handle,
        DescribeResponse {
            status: ZX_OK,
            descriptor,
        }
        .encode_channel_message(),
    )
}

fn send_read_response(
    handle: zx_handle_t,
    status: zx_status_t,
    bytes: &[u8],
) -> Result<(), zx_status_t> {
    let message = if status == ZX_OK && bytes.len() >= BULK_DATA_THRESHOLD {
        ReadResponse::bulk(
            status,
            u32::try_from(bytes.len()).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
            create_bulk_vmo_from_bytes(bytes)?,
        )
        .encode_channel_message()
    } else {
        ReadResponse::inline(status, bytes.to_vec()).encode_channel_message()
    };
    write_message(handle, message)
}

fn send_write_response(
    handle: zx_handle_t,
    status: zx_status_t,
    actual: u32,
) -> Result<(), zx_status_t> {
    write_message(
        handle,
        WriteResponse { status, actual }.encode_channel_message(),
    )
}

fn send_get_vmo_response(
    handle: zx_handle_t,
    status: zx_status_t,
    vmo: Option<zx_handle_t>,
) -> Result<(), zx_status_t> {
    write_message(
        handle,
        GetVmoResponse { status, vmo }.encode_channel_message(),
    )
}

fn send_readdir_response(
    handle: zx_handle_t,
    status: zx_status_t,
    entries: &[DirEntryRecord],
) -> Result<(), zx_status_t> {
    write_message(
        handle,
        ReadDirResponse {
            status,
            entries: entries.to_vec(),
        }
        .encode_channel_message(),
    )
}

fn write_message(
    handle: zx_handle_t,
    message: nexus_fs_proto::EncodedMessage,
) -> Result<(), zx_status_t> {
    let status = zx_channel_write(
        handle,
        0,
        message.bytes.as_ptr(),
        message.bytes.len() as u32,
        if message.handles.is_empty() {
            core::ptr::null()
        } else {
            message.handles.as_ptr()
        },
        message.handles.len() as u32,
    );
    if status == ZX_OK {
        Ok(())
    } else {
        for transferred in message.handles {
            let _ = zx_handle_close(transferred);
        }
        Err(status)
    }
}

fn forward_raw_message(
    handle: zx_handle_t,
    bytes: &[u8],
    handles: &[zx_handle_t],
) -> Result<(), zx_status_t> {
    let status = zx_channel_write(
        handle,
        0,
        bytes.as_ptr(),
        bytes.len() as u32,
        if handles.is_empty() {
            core::ptr::null()
        } else {
            handles.as_ptr()
        },
        handles.len() as u32,
    );
    if status == ZX_OK {
        Ok(())
    } else {
        for &transferred in handles {
            let _ = zx_handle_close(transferred);
        }
        Err(status)
    }
}

fn round_bulk_vmo_size(len: usize) -> Result<u64, zx_status_t> {
    if len == 0 {
        return Ok(BULK_VMO_PAGE_BYTES);
    }
    let raw = u64::try_from(len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let mask = BULK_VMO_PAGE_BYTES - 1;
    raw.checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or(ZX_ERR_OUT_OF_RANGE)
}

fn create_bulk_vmo_from_bytes(bytes: &[u8]) -> Result<zx_handle_t, zx_status_t> {
    let mut handle = 0;
    let status = zx_vmo_create(round_bulk_vmo_size(bytes.len())?, 0, &mut handle);
    if status != ZX_OK {
        return Err(status);
    }
    if !bytes.is_empty() {
        let status = zx_vmo_write(handle, bytes, 0);
        if status != ZX_OK {
            let _ = zx_handle_close(handle);
            return Err(status);
        }
    }
    Ok(handle)
}

fn read_bulk_vmo_bytes(vmo: zx_handle_t, len: usize) -> Result<Vec<u8>, zx_status_t> {
    let mut bytes = vec![0u8; len];
    let status = zx_vmo_read(vmo, &mut bytes, 0);
    let _ = zx_handle_close(vmo);
    if status != ZX_OK {
        return Err(status);
    }
    Ok(bytes)
}

fn read_message_waiting(handle: zx_handle_t) -> Result<Option<ChannelMessage>, zx_status_t> {
    match wait_for_channel_readable(handle, ZX_TIME_INFINITE) {
        Ok(()) => {}
        Err(ZX_ERR_PEER_CLOSED) => return Ok(None),
        Err(status) => return Err(status),
    }
    match zx_channel_read_alloc(handle, 0) {
        Ok(message) => Ok(Some(message)),
        Err(ZX_ERR_PEER_CLOSED) => Ok(None),
        Err(status) => Err(status),
    }
}

fn read_message_polling(handle: zx_handle_t) -> Result<Option<ChannelMessage>, zx_status_t> {
    loop {
        match zx_channel_read_alloc(handle, 0) {
            Ok(message) => return Ok(Some(message)),
            Err(ZX_ERR_SHOULD_WAIT) => core::hint::spin_loop(),
            Err(ZX_ERR_PEER_CLOSED) => return Ok(None),
            Err(status) => return Err(status),
        }
    }
}

fn echo_service_path_matches(path: &str) -> bool {
    let mut depth = 0usize;
    for component in path.split('/').filter(|component| !component.is_empty()) {
        match component {
            "." => {}
            ".." => {
                depth = depth.saturating_sub(1);
            }
            component if component == ECHO_PROTOCOL_NAME => {
                depth = depth.saturating_add(1);
            }
            _ => return false,
        }
    }
    depth == 1
}
