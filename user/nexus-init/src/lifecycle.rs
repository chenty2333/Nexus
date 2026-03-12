use alloc::string::String;

use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::signals::{ZX_CHANNEL_PEER_CLOSED, ZX_CHANNEL_READABLE};
use axle_types::status::{ZX_ERR_IO_DATA_INTEGRITY, ZX_ERR_SHOULD_WAIT, ZX_OK};
use axle_types::{zx_handle_t, zx_status_t, zx_time_t};
use libax::compat::{
    ZX_TIME_INFINITE, zx_channel_read, zx_channel_read_alloc, zx_channel_write, zx_object_wait_one,
};
use nexus_component::{ComponentStartInfo, ControllerEvent, ControllerRequest};

use crate::runner::RunningComponent;
use crate::{
    CHILD_ROLE_CLIENT, CHILD_ROLE_CONTROLLER_WORKER, CHILD_ROLE_PROVIDER,
    MAX_SMALL_CHANNEL_HANDLES, STARTUP_HANDLE_COMPONENT_STATUS, SVC_NAMESPACE_PATH,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MinimalRole {
    Provider,
    Client,
    ControllerWorker,
    Unknown,
}

pub(crate) struct MinimalStartInfo {
    pub(crate) role: MinimalRole,
    pub(crate) svc: Option<zx_handle_t>,
    pub(crate) status: Option<zx_handle_t>,
    pub(crate) outgoing: Option<zx_handle_t>,
    pub(crate) controller: Option<zx_handle_t>,
}

pub(crate) fn read_component_start_info_minimal(
    bootstrap_channel: zx_handle_t,
) -> Result<MinimalStartInfo, zx_status_t> {
    let (bytes, handles) = read_channel_alloc_blocking(bootstrap_channel)?;
    let start_info = ComponentStartInfo::decode_channel_message(&bytes, &handles)
        .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    minimal_start_info_from_component(start_info)
}

pub(crate) fn send_status_event(handle: zx_handle_t, return_code: i32) -> zx_status_t {
    let bytes = i64::from(return_code).to_le_bytes();
    zx_channel_write(
        handle,
        0,
        bytes.as_ptr(),
        bytes.len() as u32,
        core::ptr::null(),
        0,
    )
}

pub(crate) fn send_controller_event(handle: zx_handle_t, return_code: i32) -> zx_status_t {
    let encoded = ControllerEvent::OnTerminated {
        return_code: i64::from(return_code),
    }
    .encode_channel_message();
    zx_channel_write(
        handle,
        0,
        encoded.bytes.as_ptr(),
        encoded.bytes.len() as u32,
        core::ptr::null(),
        0,
    )
}

pub(crate) fn run_controller_lifecycle_step(
    component: &mut RunningComponent,
    request: ControllerRequest,
) -> Result<i64, zx_status_t> {
    let status = send_controller_request(component.controller, request);
    if status != ZX_OK {
        return Err(status);
    }
    read_controller_event_blocking(component.controller, ZX_TIME_INFINITE)
}

pub(crate) fn read_controller_request_blocking(
    handle: zx_handle_t,
    deadline: zx_time_t,
) -> Result<ControllerRequest, zx_status_t> {
    wait_for_channel_readable(handle, deadline)?;
    let mut bytes = [0u8; 32];
    let mut handles = [ZX_HANDLE_INVALID; MAX_SMALL_CHANNEL_HANDLES];
    let (actual_bytes, actual_handles) = read_channel_fixed(handle, &mut bytes, &mut handles)?;
    ControllerRequest::decode_channel_message(&bytes[..actual_bytes], &handles[..actual_handles])
        .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)
}

pub(crate) fn read_controller_event_blocking(
    handle: zx_handle_t,
    deadline: zx_time_t,
) -> Result<i64, zx_status_t> {
    wait_for_channel_readable(handle, deadline)?;
    try_read_controller_event(handle)?.ok_or(ZX_ERR_SHOULD_WAIT)
}

pub(crate) fn read_channel_fixed(
    handle: zx_handle_t,
    bytes: &mut [u8],
    handles: &mut [zx_handle_t],
) -> Result<(usize, usize), zx_status_t> {
    let mut actual_bytes = 0u32;
    let mut actual_handles = 0u32;
    let status = zx_channel_read(
        handle,
        0,
        bytes.as_mut_ptr(),
        handles.as_mut_ptr(),
        bytes.len() as u32,
        handles.len() as u32,
        &mut actual_bytes,
        &mut actual_handles,
    );
    if status != ZX_OK {
        return Err(status);
    }
    Ok((actual_bytes as usize, actual_handles as usize))
}

pub(crate) fn read_channel_blocking(
    handle: zx_handle_t,
    bytes: &mut [u8],
    handles: &mut [zx_handle_t],
) -> Result<(usize, usize), zx_status_t> {
    loop {
        match read_channel_fixed(handle, bytes, handles) {
            Ok(message) => return Ok(message),
            Err(ZX_ERR_SHOULD_WAIT) => wait_for_channel_readable(handle, ZX_TIME_INFINITE)?,
            Err(status) => return Err(status),
        }
    }
}

pub(crate) fn read_channel_alloc_blocking(
    handle: zx_handle_t,
) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<zx_handle_t>), zx_status_t> {
    loop {
        match zx_channel_read_alloc(handle, 0) {
            Ok(message) => return Ok(message),
            Err(ZX_ERR_SHOULD_WAIT) => wait_for_channel_readable(handle, ZX_TIME_INFINITE)?,
            Err(status) => return Err(status),
        }
    }
}

pub(crate) fn wait_for_channel_readable(
    handle: zx_handle_t,
    deadline: zx_time_t,
) -> Result<(), zx_status_t> {
    let mut observed = 0;
    let status = zx_object_wait_one(
        handle,
        ZX_CHANNEL_READABLE | ZX_CHANNEL_PEER_CLOSED,
        deadline,
        &mut observed,
    );
    if status != ZX_OK {
        return Err(status);
    }
    if (observed & ZX_CHANNEL_READABLE) != 0 {
        return Ok(());
    }
    if (observed & ZX_CHANNEL_PEER_CLOSED) != 0 {
        return Err(axle_types::status::ZX_ERR_PEER_CLOSED);
    }
    Err(ZX_ERR_SHOULD_WAIT)
}

fn minimal_start_info_from_component(
    start_info: ComponentStartInfo,
) -> Result<MinimalStartInfo, zx_status_t> {
    let role = match start_info.args.first().map(String::as_str) {
        Some(CHILD_ROLE_PROVIDER) => MinimalRole::Provider,
        Some(CHILD_ROLE_CLIENT) => MinimalRole::Client,
        Some(CHILD_ROLE_CONTROLLER_WORKER) => MinimalRole::ControllerWorker,
        _ => MinimalRole::Unknown,
    };
    let mut svc = None;
    for entry in start_info.namespace_entries {
        let handle = entry.handle;
        let path = entry.path;
        if path == SVC_NAMESPACE_PATH {
            svc = Some(handle);
        }
    }
    let mut status = None;
    for entry in start_info.numbered_handles {
        if entry.id == STARTUP_HANDLE_COMPONENT_STATUS {
            status = Some(entry.handle);
        }
    }
    Ok(MinimalStartInfo {
        role,
        svc,
        status,
        outgoing: start_info.outgoing_dir_server_end,
        controller: start_info.controller_channel,
    })
}

fn try_read_controller_event(handle: zx_handle_t) -> Result<Option<i64>, zx_status_t> {
    let mut bytes = [0u8; 32];
    let mut handles = [ZX_HANDLE_INVALID; MAX_SMALL_CHANNEL_HANDLES];
    let (actual_bytes, actual_handles) = match read_channel_fixed(handle, &mut bytes, &mut handles)
    {
        Ok(message) => message,
        Err(ZX_ERR_SHOULD_WAIT) => return Ok(None),
        Err(status) => return Err(status),
    };
    if actual_handles != 0 {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    let event = ControllerEvent::decode_channel_message(&bytes[..actual_bytes], &[])
        .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    match event {
        ControllerEvent::OnTerminated { return_code } => Ok(Some(return_code)),
    }
}

fn send_controller_request(handle: zx_handle_t, request: ControllerRequest) -> zx_status_t {
    let encoded = request.encode_channel_message();
    zx_channel_write(
        handle,
        0,
        encoded.bytes.as_ptr(),
        encoded.bytes.len() as u32,
        core::ptr::null(),
        0,
    )
}
