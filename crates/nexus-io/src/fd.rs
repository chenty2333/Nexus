use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::signals::{
    ZX_CHANNEL_PEER_CLOSED, ZX_CHANNEL_READABLE, ZX_CHANNEL_WRITABLE, ZX_SOCKET_PEER_CLOSED,
    ZX_SOCKET_READABLE, ZX_SOCKET_WRITABLE,
};
use axle_types::status::{
    ZX_ERR_BAD_HANDLE, ZX_ERR_NOT_DIR, ZX_ERR_NOT_SUPPORTED, ZX_ERR_OUT_OF_RANGE, ZX_OK,
};
use axle_types::{zx_handle_t, zx_signals_t, zx_status_t};
use bitflags::bitflags;
use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};
use libzircon::{zx_handle_close, zx_socket_read, zx_socket_write};

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
pub trait FdOps: Send + Sync {
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

    /// Open one relative path beneath this object when it behaves like a directory.
    fn openat(&self, path: &str, flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let _ = (path, flags);
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
#[derive(Debug, Default)]
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
        let last_fd_for_description = self.entries.iter().all(|existing| {
            existing
                .as_ref()
                .map(|candidate| !Arc::ptr_eq(candidate.description(), entry.description()))
                .unwrap_or(true)
        });
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

/// Channel-backed placeholder for a remote file protocol.
#[derive(Debug)]
pub struct RemoteFile {
    handle: OwnedHandle,
    wait_interest: WaitSpec,
}

impl RemoteFile {
    /// Wrap one remote file channel.
    pub fn new(handle: zx_handle_t) -> Self {
        Self {
            handle: OwnedHandle::new(handle),
            wait_interest: WaitSpec::new(
                handle,
                ZX_CHANNEL_READABLE | ZX_CHANNEL_WRITABLE | ZX_CHANNEL_PEER_CLOSED,
            ),
        }
    }

    /// Borrow the underlying channel handle.
    pub fn handle(&self) -> zx_handle_t {
        self.handle.get()
    }
}

impl FdOps for RemoteFile {
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
        Some(self.wait_interest)
    }
}

/// Channel-backed placeholder for a remote directory protocol.
#[derive(Debug)]
pub struct RemoteDir {
    handle: OwnedHandle,
    wait_interest: WaitSpec,
}

impl RemoteDir {
    /// Wrap one remote directory channel.
    pub fn new(handle: zx_handle_t) -> Self {
        Self {
            handle: OwnedHandle::new(handle),
            wait_interest: WaitSpec::new(
                handle,
                ZX_CHANNEL_READABLE | ZX_CHANNEL_WRITABLE | ZX_CHANNEL_PEER_CLOSED,
            ),
        }
    }

    /// Borrow the underlying channel handle.
    pub fn handle(&self) -> zx_handle_t {
        self.handle.get()
    }
}

impl FdOps for RemoteDir {
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
        Some(self.wait_interest)
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
    handle: AtomicU32,
}

impl OwnedHandle {
    fn new(handle: zx_handle_t) -> Self {
        Self {
            handle: AtomicU32::new(handle),
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

fn fd_index(fd: RawFd) -> Option<usize> {
    usize::try_from(fd).ok()
}

#[cfg(test)]
mod tests {
    use super::{
        FdFlags, FdOps, FdTable, OpenFlags, PseudoNodeFd, RawFd, RemoteDir, SeekOrigin, WaitSpec,
    };
    use alloc::string::String;
    use alloc::sync::Arc;
    use axle_types::status::ZX_ERR_NOT_SUPPORTED;
    use axle_types::zx_status_t;
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
    fn remote_dirs_default_to_not_dir_open_until_rpc_glue_lands() {
        let dir = RemoteDir::new(axle_types::handle::ZX_HANDLE_INVALID);
        let result = dir.openat("child", OpenFlags::READABLE);
        assert_eq!(result.err(), Some(axle_types::status::ZX_ERR_NOT_DIR));
    }

    #[allow(dead_code)]
    fn _keep_string(_value: String, _fd: RawFd) {}
}
