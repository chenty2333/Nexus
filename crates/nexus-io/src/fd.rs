use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::signals::{
    ZX_CHANNEL_PEER_CLOSED, ZX_CHANNEL_READABLE, ZX_CHANNEL_WRITABLE, ZX_SOCKET_PEER_CLOSED,
    ZX_SOCKET_READABLE, ZX_SOCKET_WRITABLE,
};
use axle_types::status::{
    ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_PATH, ZX_ERR_IO_DATA_INTEGRITY, ZX_ERR_NOT_DIR,
    ZX_ERR_NOT_SUPPORTED, ZX_ERR_OUT_OF_RANGE, ZX_ERR_SHOULD_WAIT, ZX_OK,
};
use axle_types::{zx_handle_t, zx_signals_t, zx_status_t};
use bitflags::bitflags;
use core::any::Any;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use libax::compat::{
    zx_channel_create, zx_channel_read_alloc, zx_channel_write, zx_handle_close, zx_socket_read,
    zx_socket_write,
};
use nexus_fs_proto::{
    CloneRequest, CloseRequest, CodecError, DescribeResponse, DirEntryRecord, GetVmoRequest,
    GetVmoResponse, NodeDescriptor, NodeKind, ObjectIdentity, OpenRequest, ReadDirRequest,
    ReadDirResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse,
};

/// POSIX-shaped file descriptor number.
pub type RawFd = i32;

/// One reactor registration request derived from one fd-like object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitSpec {
    handle: zx_handle_t,
    signals: zx_signals_t,
}

impl WaitSpec {
    /// Build one wait request against `handle`.
    pub const fn new(handle: zx_handle_t, signals: zx_signals_t) -> Self {
        Self { handle, signals }
    }

    /// Backing handle to register with the reactor.
    pub const fn handle(self) -> zx_handle_t {
        self.handle
    }

    /// Signal mask that should wake the reactor registration.
    pub const fn signals(self) -> zx_signals_t {
        self.signals
    }
}

/// Seek anchor used by `FdOps::seek`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekOrigin {
    /// Seek relative to the start of the object.
    Start,
    /// Seek relative to the current position.
    Current,
    /// Seek relative to the end of the object.
    End,
}

bitflags! {
    /// Open-file-description flags shared by duplicated fd table entries.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenFlags: u32 {
        /// Allow reads.
        const READABLE = 1 << 0;
        /// Allow writes.
        const WRITABLE = 1 << 1;
        /// Force writes to append to the end of the file.
        const APPEND = 1 << 2;
        /// Directory-only open.
        const DIRECTORY = 1 << 3;
        /// Create the node when it does not exist.
        const CREATE = 1 << 4;
        /// Truncate the opened object to zero length.
        const TRUNCATE = 1 << 5;
        /// Non-blocking behavior for operations that support it.
        const NONBLOCK = 1 << 6;
        /// Path-only open without data access.
        const PATH = 1 << 7;
    }
}

bitflags! {
    /// Per-fd flags that do not belong to the shared open file description.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FdFlags: u32 {
        /// Close this fd during `exec`-style replacement.
        const CLOEXEC = 1 << 0;
    }
}

bitflags! {
    /// Flags accepted by `FdOps::as_vmo`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VmoFlags: u32 {
        /// Request a read-only backing VMO.
        const READ = 1 << 0;
        /// Request execute rights on the returned VMO when supported.
        const EXECUTE = 1 << 1;
    }
}

/// One directory entry returned by a future `readdir` surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Entry name relative to the opened directory.
    pub name: String,
    /// High-level entry type, when known.
    pub kind: DirectoryEntryKind,
}

/// Coarse node type for one directory entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symlink.
    Symlink,
    /// Socket-like endpoint.
    Socket,
    /// Pseudo node exposed by one service.
    Service,
    /// Unknown or protocol-defined node kind.
    Unknown,
}

/// fd-shaped operations for one open file description.
pub trait FdOps: Any + Send + Sync {
    /// Type-erased view used for same-filesystem coordination operations.
    fn as_any(&self) -> &dyn Any;

    /// Read bytes into `buffer`, returning the number of bytes read.
    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t>;

    /// Write bytes from `buffer`, returning the number of bytes written.
    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t>;

    /// Reposition the current stream/file offset.
    fn seek(&self, origin: SeekOrigin, offset: i64) -> Result<u64, zx_status_t>;

    /// Explicitly close the underlying description.
    ///
    /// Implementations should be idempotent because the last-fd close path and
    /// best-effort `Drop` cleanup may both attempt to close.
    fn close(&self) -> Result<(), zx_status_t>;

    /// Clone the underlying description into a new independently owned object.
    fn clone_fd(&self, flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t>;

    /// Reactor registration interest for readiness-style waiting.
    fn wait_interest(&self) -> Option<WaitSpec>;

    /// Return a read-only backing VMO when supported.
    fn as_vmo(&self, flags: VmoFlags) -> Result<zx_handle_t, zx_status_t> {
        let _ = flags;
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    /// Enumerate child entries when this object behaves like a directory.
    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        Err(ZX_ERR_NOT_DIR)
    }

    /// Open one relative path beneath this object when it behaves like a directory.
    fn openat(&self, path: &str, flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let _ = (path, flags);
        Err(ZX_ERR_NOT_DIR)
    }

    /// Remove one relative path beneath this directory.
    fn unlinkat(&self, path: &str) -> Result<(), zx_status_t> {
        let _ = path;
        Err(ZX_ERR_NOT_DIR)
    }

    /// Create one additional hard link beneath `target_dir`.
    fn linkat(
        &self,
        src_path: &str,
        target_dir: &dyn FdOps,
        target_path: &str,
    ) -> Result<(), zx_status_t> {
        let _ = (src_path, target_dir, target_path);
        Err(ZX_ERR_NOT_DIR)
    }

    /// Rename one relative path beneath this directory into `target_dir`.
    fn renameat(
        &self,
        src_path: &str,
        target_dir: &dyn FdOps,
        target_path: &str,
    ) -> Result<(), zx_status_t> {
        let _ = (src_path, target_dir, target_path);
        Err(ZX_ERR_NOT_DIR)
    }
}

/// Stable identifier for one open file description.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenFileDescriptionId(u64);

impl OpenFileDescriptionId {
    /// Raw numeric id.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Shared open-file-description state referenced by one or more fd entries.
#[derive(Clone)]
pub struct OpenFileDescription {
    id: OpenFileDescriptionId,
    flags: OpenFlags,
    ops: Arc<dyn FdOps>,
}

impl OpenFileDescription {
    /// Build one open file description around one `FdOps` implementation.
    pub fn new(id: OpenFileDescriptionId, flags: OpenFlags, ops: Arc<dyn FdOps>) -> Self {
        Self { id, flags, ops }
    }

    /// Stable open-file-description id.
    pub const fn id(&self) -> OpenFileDescriptionId {
        self.id
    }

    /// Shared open flags for this description.
    pub const fn flags(&self) -> OpenFlags {
        self.flags
    }

    /// Borrow the object operations.
    pub fn ops(&self) -> &Arc<dyn FdOps> {
        &self.ops
    }
}

impl fmt::Debug for OpenFileDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenFileDescription")
            .field("id", &self.id)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

/// One installed fd entry.
#[derive(Clone)]
pub struct FdEntry {
    description: Arc<OpenFileDescription>,
    flags: FdFlags,
}

impl FdEntry {
    /// Shared open file description referenced by this fd.
    pub fn description(&self) -> &Arc<OpenFileDescription> {
        &self.description
    }

    /// Per-fd flags.
    pub const fn flags(&self) -> FdFlags {
        self.flags
    }
}

impl fmt::Debug for FdEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FdEntry")
            .field("description_id", &self.description.id())
            .field("flags", &self.flags)
            .finish()
    }
}

/// Userspace-owned fd table.
#[derive(Clone, Debug, Default)]
pub struct FdTable {
    entries: Vec<Option<FdEntry>>,
    next_description_id: u64,
}

impl FdTable {
    /// Build an empty table.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_description_id: 1,
        }
    }

    /// Return the number of live fd entries.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }

    /// Return `true` when no fd is installed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Install one fresh open file description and return its fd number.
    pub fn open(
        &mut self,
        ops: Arc<dyn FdOps>,
        open_flags: OpenFlags,
        fd_flags: FdFlags,
    ) -> Result<RawFd, zx_status_t> {
        let description_id = self.allocate_description_id()?;
        let description = Arc::new(OpenFileDescription::new(description_id, open_flags, ops));
        Ok(self.install_entry(FdEntry {
            description,
            flags: fd_flags,
        }))
    }

    /// Install one already-created description and return its fd number.
    pub fn install(&mut self, description: Arc<OpenFileDescription>, fd_flags: FdFlags) -> RawFd {
        self.install_entry(FdEntry {
            description,
            flags: fd_flags,
        })
    }

    /// Return one entry by fd number.
    pub fn get(&self, fd: RawFd) -> Option<&FdEntry> {
        self.entries.get(fd_index(fd)?).and_then(Option::as_ref)
    }

    /// Read from one fd.
    pub fn read(&self, fd: RawFd, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        self.get(fd)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .description()
            .ops()
            .read(buffer)
    }

    /// Write to one fd.
    pub fn write(&self, fd: RawFd, buffer: &[u8]) -> Result<usize, zx_status_t> {
        self.get(fd)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .description()
            .ops()
            .write(buffer)
    }

    /// Seek one fd.
    pub fn seek(&self, fd: RawFd, origin: SeekOrigin, offset: i64) -> Result<u64, zx_status_t> {
        self.get(fd)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .description()
            .ops()
            .seek(origin, offset)
    }

    /// Open one relative path beneath an fd that behaves like a directory.
    pub fn openat(
        &mut self,
        fd: RawFd,
        path: &str,
        open_flags: OpenFlags,
        fd_flags: FdFlags,
    ) -> Result<RawFd, zx_status_t> {
        let opened = self
            .get(fd)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .description()
            .ops()
            .openat(path, open_flags)?;
        self.open(opened, open_flags, fd_flags)
    }

    /// Return readiness interest for one fd when supported.
    pub fn wait_interest(&self, fd: RawFd) -> Result<Option<WaitSpec>, zx_status_t> {
        Ok(self
            .get(fd)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .description()
            .ops()
            .wait_interest())
    }

    /// Request a read-only VMO from one fd when supported.
    pub fn as_vmo(&self, fd: RawFd, flags: VmoFlags) -> Result<zx_handle_t, zx_status_t> {
        self.get(fd)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .description()
            .ops()
            .as_vmo(flags)
    }

    /// Read one full directory listing from `fd`.
    pub fn readdir(&self, fd: RawFd) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        self.get(fd)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .description()
            .ops()
            .readdir()
    }

    /// Remove one relative path beneath directory `fd`.
    pub fn unlinkat(&self, fd: RawFd, path: &str) -> Result<(), zx_status_t> {
        self.get(fd)
            .ok_or(ZX_ERR_BAD_HANDLE)?
            .description()
            .ops()
            .unlinkat(path)
    }

    /// Rename one relative path from `src_fd` into `dst_fd`.
    pub fn renameat(
        &self,
        src_fd: RawFd,
        src_path: &str,
        dst_fd: RawFd,
        dst_path: &str,
    ) -> Result<(), zx_status_t> {
        let src = Arc::clone(
            self.get(src_fd)
                .ok_or(ZX_ERR_BAD_HANDLE)?
                .description()
                .ops(),
        );
        let dst = Arc::clone(
            self.get(dst_fd)
                .ok_or(ZX_ERR_BAD_HANDLE)?
                .description()
                .ops(),
        );
        src.renameat(src_path, dst.as_ref(), dst_path)
    }

    /// Create one additional hard link from `src_fd/src_path` into `dst_fd/dst_path`.
    pub fn linkat(
        &self,
        src_fd: RawFd,
        src_path: &str,
        dst_fd: RawFd,
        dst_path: &str,
    ) -> Result<(), zx_status_t> {
        let src = Arc::clone(
            self.get(src_fd)
                .ok_or(ZX_ERR_BAD_HANDLE)?
                .description()
                .ops(),
        );
        let dst = Arc::clone(
            self.get(dst_fd)
                .ok_or(ZX_ERR_BAD_HANDLE)?
                .description()
                .ops(),
        );
        src.linkat(src_path, dst.as_ref(), dst_path)
    }

    /// Duplicate one fd so both entries reference the same open description.
    pub fn duplicate(&mut self, fd: RawFd, new_flags: FdFlags) -> Result<RawFd, zx_status_t> {
        let entry = self.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?.clone();
        Ok(self.install_entry(FdEntry {
            description: entry.description,
            flags: new_flags,
        }))
    }

    /// Clone one fd into a new open file description through `FdOps::clone_fd`.
    pub fn clone_fd(&mut self, fd: RawFd, new_flags: FdFlags) -> Result<RawFd, zx_status_t> {
        let entry = self.get(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        let cloned = entry.description.ops().clone_fd(new_flags)?;
        self.open(cloned, entry.description.flags(), new_flags)
    }

    /// Remove one fd entry from the table.
    pub fn close(&mut self, fd: RawFd) -> Result<(), zx_status_t> {
        let fd_index = fd_index(fd).ok_or(ZX_ERR_BAD_HANDLE)?;
        let slot = self.entries.get_mut(fd_index).ok_or(ZX_ERR_BAD_HANDLE)?;
        let Some(entry) = slot.take() else {
            return Err(ZX_ERR_BAD_HANDLE);
        };
        // Open-file-description identity can be shared across duplicated entries
        // and across fork-cloned fd tables, so the close decision must follow the
        // shared `Arc<OpenFileDescription>` lifetime rather than only this table.
        let last_fd_for_description = Arc::strong_count(entry.description()) == 1;
        if last_fd_for_description {
            entry.description.ops().close()?;
        }
        Ok(())
    }

    fn allocate_description_id(&mut self) -> Result<OpenFileDescriptionId, zx_status_t> {
        let id = self.next_description_id;
        self.next_description_id = self
            .next_description_id
            .checked_add(1)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok(OpenFileDescriptionId(id))
    }

    fn install_entry(&mut self, entry: FdEntry) -> RawFd {
        if let Some((index, slot)) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(entry);
            index as RawFd
        } else {
            self.entries.push(Some(entry));
            (self.entries.len() - 1) as RawFd
        }
    }
}

#[derive(Debug)]
struct RemoteNode {
    handle: OwnedHandle,
    descriptor: NodeDescriptor,
    wait_interest: WaitSpec,
}

impl RemoteNode {
    fn new(handle: zx_handle_t, descriptor: NodeDescriptor) -> Self {
        Self {
            handle: OwnedHandle::new(handle),
            descriptor,
            wait_interest: WaitSpec::new(
                handle,
                ZX_CHANNEL_READABLE | ZX_CHANNEL_WRITABLE | ZX_CHANNEL_PEER_CLOSED,
            ),
        }
    }

    fn handle(&self) -> zx_handle_t {
        self.handle.get()
    }

    fn descriptor(&self) -> NodeDescriptor {
        self.descriptor
    }
}

/// Channel-backed remote file or service endpoint.
#[derive(Debug)]
pub struct RemoteFile {
    node: RemoteNode,
}

impl RemoteFile {
    /// Wrap one remote file channel using the default bootstrap descriptor.
    pub fn new(handle: zx_handle_t) -> Self {
        Self::from_descriptor(handle, default_remote_file_descriptor())
    }

    /// Wrap one remote file channel with an explicit descriptor.
    pub fn from_descriptor(handle: zx_handle_t, descriptor: NodeDescriptor) -> Self {
        Self {
            node: RemoteNode::new(handle, descriptor),
        }
    }

    /// Borrow the underlying channel handle.
    pub fn handle(&self) -> zx_handle_t {
        self.node.handle()
    }

    /// Borrow the remote descriptor carried by this handle.
    pub fn descriptor(&self) -> NodeDescriptor {
        self.node.descriptor()
    }
}

impl FdOps for RemoteFile {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        let handle = checked_channel_handle(self.node.handle())?;
        let request = ReadRequest {
            object: self.node.descriptor.identity,
            flags: 0,
            max_bytes: u32::try_from(buffer.len()).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
        };
        write_encoded_message(handle, request.encode_channel_message())?;
        let (bytes, handles) = read_channel_message(handle)?;
        let response =
            ReadResponse::decode_channel_message(&bytes, &handles).map_err(map_codec_error)?;
        if response.status != ZX_OK {
            return Err(response.status);
        }
        let actual = response.bytes.len().min(buffer.len());
        buffer[..actual].copy_from_slice(&response.bytes[..actual]);
        Ok(actual)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        let handle = checked_channel_handle(self.node.handle())?;
        let request = WriteRequest {
            object: self.node.descriptor.identity,
            flags: 0,
            bytes: buffer.to_vec(),
        };
        write_encoded_message(handle, request.encode_channel_message())?;
        let (bytes, handles) = read_channel_message(handle)?;
        let response =
            WriteResponse::decode_channel_message(&bytes, &handles).map_err(map_codec_error)?;
        if response.status != ZX_OK {
            return Err(response.status);
        }
        Ok(response.actual as usize)
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        close_remote_channel(
            self.node.handle(),
            self.node.descriptor.identity,
            &self.node.handle,
        )
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        clone_remote_object(self.node.handle(), self.node.descriptor)
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        Some(self.node.wait_interest)
    }

    fn as_vmo(&self, flags: VmoFlags) -> Result<zx_handle_t, zx_status_t> {
        let handle = checked_channel_handle(self.node.handle())?;
        let request = GetVmoRequest {
            object: self.node.descriptor.identity,
            flags: flags.bits(),
        };
        write_encoded_message(handle, request.encode_channel_message())?;
        let (bytes, handles) = read_channel_message(handle)?;
        let response =
            GetVmoResponse::decode_channel_message(&bytes, &handles).map_err(map_codec_error)?;
        if response.status != ZX_OK {
            return Err(response.status);
        }
        response.vmo.ok_or(ZX_ERR_IO_DATA_INTEGRITY)
    }
}

/// Channel-backed remote directory protocol.
#[derive(Debug)]
pub struct RemoteDir {
    node: RemoteNode,
}

impl RemoteDir {
    /// Wrap one remote directory channel using the default bootstrap root descriptor.
    pub fn new(handle: zx_handle_t) -> Self {
        Self::from_descriptor(handle, default_remote_dir_descriptor())
    }

    /// Wrap one remote directory channel with an explicit descriptor.
    pub fn from_descriptor(handle: zx_handle_t, descriptor: NodeDescriptor) -> Self {
        Self {
            node: RemoteNode::new(handle, descriptor),
        }
    }

    /// Borrow the underlying channel handle.
    pub fn handle(&self) -> zx_handle_t {
        self.node.handle()
    }

    /// Borrow the remote descriptor carried by this handle.
    pub fn descriptor(&self) -> NodeDescriptor {
        self.node.descriptor()
    }
}

impl FdOps for RemoteDir {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        close_remote_channel(
            self.node.handle(),
            self.node.descriptor.identity,
            &self.node.handle,
        )
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        clone_remote_object(self.node.handle(), self.node.descriptor)
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        Some(self.node.wait_interest)
    }

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        let handle = checked_channel_handle(self.node.handle())?;
        let request = ReadDirRequest {
            object: self.node.descriptor.identity,
            flags: 0,
        };
        write_encoded_message(handle, request.encode_channel_message())?;
        let (bytes, handles) = read_channel_message(handle)?;
        let response =
            ReadDirResponse::decode_channel_message(&bytes, &handles).map_err(map_codec_error)?;
        if response.status != ZX_OK {
            return Err(response.status);
        }
        Ok(response
            .entries
            .into_iter()
            .map(map_dir_entry_record)
            .collect())
    }

    fn openat(&self, path: &str, flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let normalized = normalize_remote_path(path)?;
        let handle = checked_channel_handle(self.node.handle())?;

        let mut opened_client = ZX_HANDLE_INVALID;
        let mut opened_server = ZX_HANDLE_INVALID;
        let status = zx_channel_create(0, &mut opened_client, &mut opened_server);
        if status != ZX_OK {
            return Err(status);
        }

        let request = OpenRequest {
            object: self.node.descriptor.identity,
            flags: flags.bits(),
            path: normalized,
            opened_object: opened_server,
        };
        if let Err(status) = write_encoded_message(handle, request.encode_channel_message()) {
            let _ = zx_handle_close(opened_client);
            return Err(status);
        }

        match receive_described_remote_object(opened_client) {
            Ok(opened) => Ok(opened),
            Err(status) => {
                let _ = zx_handle_close(opened_client);
                Err(status)
            }
        }
    }
}

/// Socket-backed fd implementation.
#[derive(Debug)]
pub struct SocketFd {
    handle: OwnedHandle,
    wait_interest: WaitSpec,
}

impl SocketFd {
    /// Wrap one socket handle.
    pub fn new(handle: zx_handle_t) -> Self {
        Self {
            handle: OwnedHandle::new(handle),
            wait_interest: WaitSpec::new(
                handle,
                ZX_SOCKET_READABLE | ZX_SOCKET_WRITABLE | ZX_SOCKET_PEER_CLOSED,
            ),
        }
    }

    /// Borrow the underlying socket handle.
    pub fn handle(&self) -> zx_handle_t {
        self.handle.get()
    }
}

impl FdOps for SocketFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        let handle = self.handle.get();
        if handle == ZX_HANDLE_INVALID {
            return Err(ZX_ERR_BAD_HANDLE);
        }
        let mut actual = 0usize;
        let status = zx_socket_read(handle, 0, buffer.as_mut_ptr(), buffer.len(), &mut actual);
        if status == ZX_OK {
            Ok(actual)
        } else {
            Err(status)
        }
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        let handle = self.handle.get();
        if handle == ZX_HANDLE_INVALID {
            return Err(ZX_ERR_BAD_HANDLE);
        }
        let mut actual = 0usize;
        let status = zx_socket_write(handle, 0, buffer.as_ptr(), buffer.len(), &mut actual);
        if status == ZX_OK {
            Ok(actual)
        } else {
            Err(status)
        }
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        self.handle.close_once()
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        Some(self.wait_interest)
    }
}

/// Pipe wrapper built on top of the current stream-socket semantics.
#[derive(Debug)]
pub struct PipeFd {
    inner: SocketFd,
}

impl PipeFd {
    /// Wrap one pipe endpoint backed by a kernel stream socket.
    pub fn new(handle: zx_handle_t) -> Self {
        Self {
            inner: SocketFd::new(handle),
        }
    }

    /// Borrow the underlying socket handle.
    pub fn handle(&self) -> zx_handle_t {
        self.inner.handle()
    }
}

impl FdOps for PipeFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        self.inner.read(buffer)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        self.inner.write(buffer)
    }

    fn seek(&self, origin: SeekOrigin, offset: i64) -> Result<u64, zx_status_t> {
        self.inner.seek(origin, offset)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        self.inner.close()
    }

    fn clone_fd(&self, flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        self.inner.clone_fd(flags)
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        self.inner.wait_interest()
    }
}

/// Wrapper for inherited or bootstrap stdio handles.
#[derive(Debug)]
pub struct StdioFd {
    handle: OwnedHandle,
    wait_interest: Option<WaitSpec>,
}

impl StdioFd {
    /// Wrap one stdio-like handle with optional readiness interest.
    pub fn new(handle: zx_handle_t, wait_interest: Option<WaitSpec>) -> Self {
        Self {
            handle: OwnedHandle::new(handle),
            wait_interest,
        }
    }

    /// Borrow the underlying handle.
    pub fn handle(&self) -> zx_handle_t {
        self.handle.get()
    }
}

impl FdOps for StdioFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        self.handle.close_once()
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        self.wait_interest
    }
}

/// Pure userspace pseudo node without one kernel backing handle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PseudoNodeFd {
    wait_interest: Option<WaitSpec>,
}

impl PseudoNodeFd {
    /// Build one pseudo node with optional readiness interest.
    pub const fn new(wait_interest: Option<WaitSpec>) -> Self {
        Self { wait_interest }
    }
}

impl FdOps for PseudoNodeFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(*self))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        self.wait_interest
    }
}

#[derive(Debug)]
struct OwnedHandle {
    handle: AtomicU64,
}

impl OwnedHandle {
    fn new(handle: zx_handle_t) -> Self {
        Self {
            handle: AtomicU64::new(handle),
        }
    }

    fn get(&self) -> zx_handle_t {
        self.handle.load(Ordering::Acquire)
    }

    fn close_once(&self) -> Result<(), zx_status_t> {
        let handle = self.handle.swap(ZX_HANDLE_INVALID, Ordering::AcqRel);
        if handle == ZX_HANDLE_INVALID {
            return Ok(());
        }
        let status = zx_handle_close(handle);
        if status == ZX_OK { Ok(()) } else { Err(status) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let handle = self.handle.swap(ZX_HANDLE_INVALID, Ordering::AcqRel);
        if handle != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(handle);
        }
    }
}

fn default_remote_dir_descriptor() -> NodeDescriptor {
    NodeDescriptor::new(
        ObjectIdentity::new(1, 1, 1),
        (OpenFlags::READABLE | OpenFlags::DIRECTORY).bits(),
        NodeKind::Directory,
    )
}

fn default_remote_file_descriptor() -> NodeDescriptor {
    NodeDescriptor::new(
        ObjectIdentity::new(1, 2, 2),
        (OpenFlags::READABLE | OpenFlags::WRITABLE).bits(),
        NodeKind::File,
    )
}

fn fd_index(fd: RawFd) -> Option<usize> {
    usize::try_from(fd).ok()
}

fn checked_channel_handle(handle: zx_handle_t) -> Result<zx_handle_t, zx_status_t> {
    if handle == ZX_HANDLE_INVALID {
        Err(ZX_ERR_BAD_HANDLE)
    } else {
        Ok(handle)
    }
}

fn normalize_remote_path(path: &str) -> Result<String, zx_status_t> {
    if path.is_empty() || path.starts_with('/') {
        return Err(ZX_ERR_BAD_PATH);
    }
    let mut normalized = String::new();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(component);
    }
    if normalized.is_empty() {
        return Err(ZX_ERR_BAD_PATH);
    }
    Ok(normalized)
}

fn map_dir_entry_record(entry: DirEntryRecord) -> DirectoryEntry {
    DirectoryEntry {
        name: entry.name,
        kind: match entry.kind {
            NodeKind::File => DirectoryEntryKind::File,
            NodeKind::Directory => DirectoryEntryKind::Directory,
            NodeKind::Service => DirectoryEntryKind::Service,
            NodeKind::Socket => DirectoryEntryKind::Socket,
            NodeKind::Pseudo => DirectoryEntryKind::Unknown,
        },
    }
}

fn write_encoded_message(
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
    if status == ZX_OK { Ok(()) } else { Err(status) }
}

fn read_channel_message(handle: zx_handle_t) -> Result<(Vec<u8>, Vec<zx_handle_t>), zx_status_t> {
    loop {
        match zx_channel_read_alloc(handle, 0) {
            Ok(message) => return Ok(message),
            Err(ZX_ERR_SHOULD_WAIT) => core::hint::spin_loop(),
            Err(status) => return Err(status),
        }
    }
}

fn map_codec_error(_error: CodecError) -> zx_status_t {
    ZX_ERR_IO_DATA_INTEGRITY
}

fn receive_described_remote_object(
    opened_client: zx_handle_t,
) -> Result<Arc<dyn FdOps>, zx_status_t> {
    let (bytes, handles) = read_channel_message(opened_client)?;
    let describe =
        DescribeResponse::decode_channel_message(&bytes, &handles).map_err(map_codec_error)?;
    if describe.status != ZX_OK {
        return Err(describe.status);
    }
    wrap_remote_object(opened_client, describe.descriptor)
}

fn wrap_remote_object(
    handle: zx_handle_t,
    descriptor: NodeDescriptor,
) -> Result<Arc<dyn FdOps>, zx_status_t> {
    let wrapped: Arc<dyn FdOps> = match descriptor.kind {
        NodeKind::Directory => Arc::new(RemoteDir::from_descriptor(handle, descriptor)),
        NodeKind::File | NodeKind::Service | NodeKind::Socket | NodeKind::Pseudo => {
            Arc::new(RemoteFile::from_descriptor(handle, descriptor))
        }
    };
    Ok(wrapped)
}

fn clone_remote_object(
    handle: zx_handle_t,
    descriptor: NodeDescriptor,
) -> Result<Arc<dyn FdOps>, zx_status_t> {
    let handle = checked_channel_handle(handle)?;
    let mut cloned_client = ZX_HANDLE_INVALID;
    let mut cloned_server = ZX_HANDLE_INVALID;
    let status = zx_channel_create(0, &mut cloned_client, &mut cloned_server);
    if status != ZX_OK {
        return Err(status);
    }

    let request = CloneRequest {
        object: descriptor.identity,
        flags: descriptor.flags,
        cloned_object: cloned_server,
    };
    if let Err(status) = write_encoded_message(handle, request.encode_channel_message()) {
        let _ = zx_handle_close(cloned_client);
        return Err(status);
    }

    match receive_described_remote_object(cloned_client) {
        Ok(cloned) => Ok(cloned),
        Err(status) => {
            let _ = zx_handle_close(cloned_client);
            Err(status)
        }
    }
}

fn close_remote_channel(
    handle: zx_handle_t,
    identity: ObjectIdentity,
    owned: &OwnedHandle,
) -> Result<(), zx_status_t> {
    if handle != ZX_HANDLE_INVALID {
        let _ = write_encoded_message(
            handle,
            CloseRequest {
                object: identity,
                flags: 0,
            }
            .encode_channel_message(),
        );
    }
    owned.close_once()
}

#[cfg(test)]
mod tests {
    use super::{
        FdFlags, FdOps, FdTable, OpenFlags, PseudoNodeFd, RawFd, RemoteDir, SeekOrigin, WaitSpec,
    };
    use alloc::string::String;
    use alloc::sync::Arc;
    use axle_types::status::{ZX_ERR_BAD_PATH, ZX_ERR_NOT_SUPPORTED};
    use axle_types::zx_status_t;
    use core::any::Any;
    use std::sync::{Mutex, MutexGuard};

    #[derive(Default)]
    struct MockState {
        closes: usize,
        clones: usize,
    }

    struct MockFd {
        name: &'static str,
        state: Arc<Mutex<MockState>>,
    }

    impl MockFd {
        fn new(name: &'static str, state: Arc<Mutex<MockState>>) -> Self {
            Self { name, state }
        }

        fn state(&self) -> MutexGuard<'_, MockState> {
            self.state.lock().expect("mock state poisoned")
        }
    }

    impl FdOps for MockFd {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
            Err(ZX_ERR_NOT_SUPPORTED)
        }

        fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
            Err(ZX_ERR_NOT_SUPPORTED)
        }

        fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
            Err(ZX_ERR_NOT_SUPPORTED)
        }

        fn close(&self) -> Result<(), zx_status_t> {
            self.state().closes += 1;
            Ok(())
        }

        fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
            self.state().clones += 1;
            Ok(Arc::new(Self::new(self.name, self.state.clone())))
        }

        fn wait_interest(&self) -> Option<WaitSpec> {
            None
        }

        fn openat(&self, path: &str, _flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
            Ok(Arc::new(Self::new(
                if path == "child" { "child" } else { self.name },
                self.state.clone(),
            )))
        }
    }

    #[test]
    fn duplicate_shares_open_file_description_until_last_close() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut table = FdTable::new();
        let fd0 = table
            .open(
                Arc::new(MockFd::new("primary", state.clone())),
                OpenFlags::READABLE,
                FdFlags::empty(),
            )
            .expect("open should succeed");
        let fd1 = table
            .duplicate(fd0, FdFlags::CLOEXEC)
            .expect("duplicate should succeed");

        let description0 = table.get(fd0).expect("fd0 installed").description().id();
        let description1 = table.get(fd1).expect("fd1 installed").description().id();
        assert_eq!(description0, description1);

        table.close(fd0).expect("first close should succeed");
        assert_eq!(state.lock().expect("state poisoned").closes, 0);

        table.close(fd1).expect("last close should succeed");
        assert_eq!(state.lock().expect("state poisoned").closes, 1);
    }

    #[test]
    fn fork_cloned_tables_keep_shared_descriptions_alive_until_last_close() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut parent = FdTable::new();
        let fd = parent
            .open(
                Arc::new(MockFd::new("shared", state.clone())),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            )
            .expect("open should succeed");
        let mut child = parent.clone();

        parent.close(fd).expect("parent close should succeed");
        assert_eq!(state.lock().expect("state poisoned").closes, 0);

        child.close(fd).expect("child close should succeed");
        assert_eq!(state.lock().expect("state poisoned").closes, 1);
    }

    #[test]
    fn clone_fd_creates_new_open_file_description() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut table = FdTable::new();
        let fd0 = table
            .open(
                Arc::new(MockFd::new("primary", state.clone())),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            )
            .expect("open should succeed");
        let fd1 = table
            .clone_fd(fd0, FdFlags::CLOEXEC)
            .expect("clone should succeed");

        let description0 = table.get(fd0).expect("fd0 installed").description().id();
        let description1 = table.get(fd1).expect("fd1 installed").description().id();
        assert_ne!(description0, description1);
        assert_eq!(state.lock().expect("state poisoned").clones, 1);
    }

    #[test]
    fn table_openat_uses_directory_operations() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mut table = FdTable::new();
        let dir_fd = table
            .open(
                Arc::new(MockFd::new("dir", state)),
                OpenFlags::DIRECTORY | OpenFlags::READABLE,
                FdFlags::empty(),
            )
            .expect("dir open");
        let child_fd = table
            .openat(dir_fd, "child", OpenFlags::READABLE, FdFlags::empty())
            .expect("openat should succeed");
        assert!(table.get(child_fd).is_some());
    }

    #[test]
    fn close_rejects_unknown_fd() {
        let mut table = FdTable::new();
        assert!(table.close(99).is_err());
    }

    #[test]
    fn pseudo_nodes_can_be_cloned_without_kernel_handles() {
        let node = PseudoNodeFd::new(None);
        let clone = node
            .clone_fd(FdFlags::empty())
            .expect("pseudo node clone should succeed");
        assert!(clone.wait_interest().is_none());
    }

    #[test]
    fn remote_dirs_reject_absolute_paths_before_touching_kernel() {
        let dir = RemoteDir::new(axle_types::handle::ZX_HANDLE_INVALID);
        let result = dir.openat("/child", OpenFlags::READABLE);
        assert_eq!(result.err(), Some(ZX_ERR_BAD_PATH));
    }

    #[test]
    fn remote_dirs_preserve_dot_segments_for_server_side_path_walk() {
        let dir = RemoteDir::new(axle_types::handle::ZX_HANDLE_INVALID);
        let result = dir.openat("svc/../echo", OpenFlags::READABLE);
        assert_eq!(result.err(), Some(axle_types::status::ZX_ERR_BAD_HANDLE));
    }

    #[allow(dead_code)]
    fn _keep_string(_value: String, _fd: RawFd) {}
}
