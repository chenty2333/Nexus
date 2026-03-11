use alloc::string::String;
use alloc::vec::Vec;

use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::status::{ZX_ERR_INVALID_ARGS, ZX_ERR_IO_DATA_INTEGRITY, ZX_ERR_NOT_FOUND};
use axle_types::{zx_handle_t, zx_status_t, zx_time_t};
use libzircon::zx_channel_write;
use nexus_component::{CapabilityKind, ComponentDecl, DirectoryOpenRequest, NamespaceEntry};

use crate::lifecycle::{read_channel_blocking, read_channel_fixed, wait_for_channel_readable};
use crate::{ECHO_PROTOCOL_NAME, MAX_SMALL_CHANNEL_BYTES, MAX_SMALL_CHANNEL_HANDLES};

pub(crate) struct CapabilityRegistry {
    protocols: Vec<(String, zx_handle_t)>,
}

impl CapabilityRegistry {
    pub(crate) fn new() -> Self {
        Self {
            protocols: Vec::new(),
        }
    }

    pub(crate) fn publish_protocol(&mut self, name: &str, handle: zx_handle_t) {
        self.protocols.push((String::from(name), handle));
    }

    pub(crate) fn take_protocol(&mut self, name: &str) -> Result<zx_handle_t, zx_status_t> {
        let index = self
            .protocols
            .iter()
            .position(|(protocol, _)| protocol == name)
            .ok_or(ZX_ERR_NOT_FOUND)?;
        Ok(self.protocols.remove(index).1)
    }
}

pub(crate) fn build_namespace_entries(
    decl: &ComponentDecl,
    registry: &mut CapabilityRegistry,
) -> Result<Vec<NamespaceEntry>, zx_status_t> {
    let mut entries = Vec::new();
    for use_decl in &decl.uses {
        match use_decl.kind {
            CapabilityKind::Protocol | CapabilityKind::Directory => {
                let Some(path) = &use_decl.target_path else {
                    return Err(ZX_ERR_INVALID_ARGS);
                };
                let handle = registry.take_protocol(&use_decl.source_name)?;
                entries.push(NamespaceEntry {
                    path: path.clone(),
                    handle,
                });
            }
            CapabilityKind::Runner | CapabilityKind::Resolver => {}
        }
    }
    Ok(entries)
}

pub(crate) fn publish_protocols(
    decl: &ComponentDecl,
    registry: &mut CapabilityRegistry,
    outgoing: zx_handle_t,
) {
    for expose in &decl.exposes {
        if expose.target_name == ECHO_PROTOCOL_NAME {
            registry.publish_protocol(&expose.target_name, outgoing);
            return;
        }
    }
}

pub(crate) fn read_directory_open_request_minimal(
    handle: zx_handle_t,
) -> Result<(bool, zx_handle_t), zx_status_t> {
    let mut bytes = [0u8; MAX_SMALL_CHANNEL_BYTES];
    let mut handles = [ZX_HANDLE_INVALID; MAX_SMALL_CHANNEL_HANDLES];
    let (actual_bytes, actual_handles) = read_channel_blocking(handle, &mut bytes, &mut handles)?;
    let request = DirectoryOpenRequest::decode_channel_message(
        &bytes[..actual_bytes],
        &handles[..actual_handles],
    )
    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok((request.path == ECHO_PROTOCOL_NAME, request.object))
}

pub(crate) fn read_directory_open_request_blocking(
    handle: zx_handle_t,
    deadline: zx_time_t,
) -> Result<DirectoryOpenRequest, zx_status_t> {
    wait_for_channel_readable(handle, deadline)?;
    let mut bytes = [0u8; MAX_SMALL_CHANNEL_BYTES];
    let mut handles = [ZX_HANDLE_INVALID; MAX_SMALL_CHANNEL_HANDLES];
    let (actual_bytes, actual_handles) = read_channel_fixed(handle, &mut bytes, &mut handles)?;
    DirectoryOpenRequest::decode_channel_message(&bytes[..actual_bytes], &handles[..actual_handles])
        .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)
}

pub(crate) fn forward_directory_open_request(
    handle: zx_handle_t,
    request: DirectoryOpenRequest,
) -> zx_status_t {
    let encoded = request.encode_channel_message();
    zx_channel_write(
        handle,
        0,
        encoded.bytes.as_ptr(),
        encoded.bytes.len() as u32,
        encoded.handles.as_ptr(),
        encoded.handles.len() as u32,
    )
}

pub(crate) fn encode_directory_open_request_minimal(
    out: &mut [u8],
    path: &str,
    flags: u32,
) -> Result<usize, zx_status_t> {
    let mut writer = WireWriter::new(out);
    writer.write_message(2)?;
    writer.write_str(path)?;
    writer.write_u32(flags)?;
    Ok(writer.len())
}

struct WireWriter<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl<'a> WireWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write_message(&mut self, kind: u8) -> Result<(), zx_status_t> {
        self.write_bytes(b"NXCM")?;
        self.write_u16(1)?;
        self.write_u8(kind)
    }

    fn write_u8(&mut self, value: u8) -> Result<(), zx_status_t> {
        self.write_bytes(&[value])
    }

    fn write_u16(&mut self, value: u16) -> Result<(), zx_status_t> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_u32(&mut self, value: u32) -> Result<(), zx_status_t> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_str(&mut self, value: &str) -> Result<(), zx_status_t> {
        self.write_u32(value.len() as u32)?;
        self.write_bytes(value.as_bytes())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), zx_status_t> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
        let dst = self
            .bytes
            .get_mut(self.len..end)
            .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
        dst.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}
