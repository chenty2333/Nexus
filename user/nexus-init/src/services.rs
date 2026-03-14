use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;

use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::rights::ZX_RIGHT_SAME_RIGHTS;
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_PATH,
    ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_INVALID_ARGS, ZX_ERR_IO_DATA_INTEGRITY,
    ZX_ERR_NOT_DIR, ZX_ERR_NOT_EMPTY, ZX_ERR_NOT_FILE, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED,
    ZX_ERR_OUT_OF_RANGE, ZX_OK,
};
use axle_types::syscall_numbers::{
    AXLE_SYS_HANDLE_DUPLICATE, AXLE_SYS_VMO_CREATE, AXLE_SYS_VMO_WRITE,
};
use axle_types::{zx_handle_t, zx_rights_t, zx_status_t};
use libax::compat::{zx_handle_close, zx_socket_create};
use nexus_io::{
    DirectoryEntry, DirectoryEntryKind, FdFlags, FdOps, FdTable, OpenFlags, PipeFd,
    ProcessNamespace, SeekOrigin, SocketFd, VmoFlags,
};
use spin::Mutex;

pub(crate) struct BootAssetEntry {
    path: &'static str,
    bytes: Option<&'static [u8]>,
    vmo: Option<zx_handle_t>,
}

impl BootAssetEntry {
    pub(crate) const fn bytes(path: &'static str, bytes: &'static [u8]) -> Self {
        Self {
            path,
            bytes: Some(bytes),
            vmo: None,
        }
    }

    pub(crate) const fn vmo(path: &'static str, vmo: zx_handle_t) -> Self {
        Self {
            path,
            bytes: None,
            vmo: Some(vmo),
        }
    }
}

pub(crate) struct BootstrapNamespace {
    boot_root: Arc<dyn FdOps>,
    namespace: ProcessNamespace,
}

impl BootstrapNamespace {
    pub(crate) fn build(boot_assets: &[BootAssetEntry]) -> Result<Self, zx_status_t> {
        let boot_root = build_boot_root(boot_assets)?;
        let tmp_root = new_tmp_root();
        let mut namespace = nexus_io::NamespaceTrie::<Arc<dyn FdOps>>::new();
        namespace.insert("/boot", Arc::clone(&boot_root))?;
        namespace.insert("/pkg", Arc::clone(&boot_root))?;
        namespace.insert("/tmp", tmp_root)?;
        Ok(Self {
            boot_root,
            namespace: ProcessNamespace::new(namespace),
        })
    }

    pub(crate) fn boot_root(&self) -> Arc<dyn FdOps> {
        Arc::clone(&self.boot_root)
    }

    pub(crate) fn namespace(&self) -> &ProcessNamespace {
        &self.namespace
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalFdMetadataKind {
    Directory,
    RegularFile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalFdMetadata {
    pub(crate) kind: LocalFdMetadataKind,
    pub(crate) size_bytes: u64,
}

pub(crate) fn local_fd_metadata(fd: &dyn FdOps) -> Option<LocalFdMetadata> {
    if fd.as_any().downcast_ref::<LocalDirFd>().is_some() {
        return Some(LocalFdMetadata {
            kind: LocalFdMetadataKind::Directory,
            size_bytes: 4096,
        });
    }
    fd.as_any()
        .downcast_ref::<LocalFileFd>()
        .map(LocalFileFd::metadata)
}

pub(crate) fn local_fd_pread(
    fd: &dyn FdOps,
    offset: u64,
    buffer: &mut [u8],
) -> Option<Result<usize, zx_status_t>> {
    fd.as_any()
        .downcast_ref::<LocalFileFd>()
        .map(|file| file.pread_at(offset, buffer))
}

pub(crate) fn local_fd_pwrite(
    fd: &dyn FdOps,
    offset: u64,
    buffer: &[u8],
) -> Option<Result<usize, zx_status_t>> {
    fd.as_any()
        .downcast_ref::<LocalFileFd>()
        .map(|file| file.pwrite_at(offset, buffer))
}

pub(crate) fn run_tmpfs_smoke(namespace: &ProcessNamespace) -> Result<(), zx_status_t> {
    let tmp = namespace.open(
        "/tmp/bootstrap-note",
        OpenFlags::READABLE | OpenFlags::WRITABLE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
    )?;
    let mut table = FdTable::new();
    let fd = table.open(
        tmp,
        OpenFlags::READABLE | OpenFlags::WRITABLE,
        FdFlags::empty(),
    )?;
    let clone_fd = table.clone_fd(fd, FdFlags::empty())?;
    let payload = b"bootstrap tmpfs";
    let written = table.write(clone_fd, payload)?;
    if written != payload.len() {
        return Err(ZX_ERR_BAD_STATE);
    }
    let mut actual = [0u8; 64];
    let read = table.read(fd, &mut actual)?;
    if &actual[..read] != payload {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    table.close(clone_fd)?;
    table.close(fd)?;
    Ok(())
}

pub(crate) fn run_socket_fd_smoke() -> Result<(), zx_status_t> {
    let mut socket_a = ZX_HANDLE_INVALID;
    let mut socket_b = ZX_HANDLE_INVALID;
    let status = zx_socket_create(0, &mut socket_a, &mut socket_b);
    if status != ZX_OK {
        return Err(status);
    }

    let mut table = FdTable::new();
    let socket_fd = table.open(
        Arc::new(SocketFd::new(socket_a)),
        OpenFlags::READABLE | OpenFlags::WRITABLE,
        FdFlags::empty(),
    )?;
    let pipe_fd = table.open(
        Arc::new(PipeFd::new(socket_b)),
        OpenFlags::READABLE | OpenFlags::WRITABLE,
        FdFlags::empty(),
    )?;

    let payload = b"socket glue";
    let written = table.write(socket_fd, payload)?;
    if written != payload.len() {
        return Err(ZX_ERR_BAD_STATE);
    }
    let mut actual = [0u8; 64];
    let read = table.read(pipe_fd, &mut actual)?;
    if &actual[..read] != payload {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    table.close(pipe_fd)?;
    table.close(socket_fd)?;
    Ok(())
}

fn build_boot_root(entries: &[BootAssetEntry]) -> Result<Arc<dyn FdOps>, zx_status_t> {
    let root = Arc::new(LocalDirectoryNode::new(true));
    for entry in entries {
        insert_boot_asset(&root, entry)?;
    }
    Ok(Arc::new(LocalDirFd::new(root)))
}

fn new_tmp_root() -> Arc<dyn FdOps> {
    Arc::new(LocalDirFd::new(Arc::new(LocalDirectoryNode::new(false))))
}

fn insert_boot_asset(
    root: &Arc<LocalDirectoryNode>,
    entry: &BootAssetEntry,
) -> Result<(), zx_status_t> {
    let components = split_boot_asset_path(entry.path)?;
    let (leaf_name, parents) = components.split_last().ok_or(ZX_ERR_BAD_PATH)?;
    let mut directory = Arc::clone(root);
    for component in parents {
        directory = directory.ensure_directory(component)?;
    }
    let node = Arc::new(LocalNode::ReadOnlyFile(Arc::new(
        LocalReadOnlyFileNode::new(entry.bytes, entry.vmo),
    )));
    directory.insert_child(leaf_name, node)
}

#[derive(Debug)]
struct LocalDirFd {
    node: Arc<LocalDirectoryNode>,
}

impl LocalDirFd {
    fn new(node: Arc<LocalDirectoryNode>) -> Self {
        Self { node }
    }
}

impl FdOps for LocalDirFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(Self::new(Arc::clone(&self.node))))
    }

    fn wait_interest(&self) -> Option<nexus_io::WaitSpec> {
        None
    }

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        Ok(self.node.list_entries())
    }

    fn openat(&self, path: &str, flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let components = split_local_walk_path(path, true)?;
        if components.is_empty() {
            return self.clone_fd(FdFlags::empty());
        }

        let mut directory = Arc::clone(&self.node);
        for (index, component) in components.iter().enumerate() {
            let last = index + 1 == components.len();
            match component {
                LocalWalkComponent::Current => {
                    if last {
                        return Ok(Arc::new(Self::new(directory)));
                    }
                }
                LocalWalkComponent::Parent => {
                    directory = directory.parent_or_self();
                    if last {
                        return Ok(Arc::new(Self::new(directory)));
                    }
                }
                LocalWalkComponent::Name(component) if last => {
                    if let Some(existing) = directory.child(component) {
                        if flags.contains(OpenFlags::DIRECTORY)
                            && !matches!(existing.as_ref(), LocalNode::Directory(_))
                        {
                            return Err(ZX_ERR_NOT_DIR);
                        }
                        if flags.contains(OpenFlags::TRUNCATE) {
                            truncate_local_node(&existing)?;
                        }
                        return wrap_local_node(existing);
                    }
                    if directory.read_only || !flags.contains(OpenFlags::CREATE) {
                        return Err(ZX_ERR_NOT_FOUND);
                    }
                    if flags.contains(OpenFlags::DIRECTORY) {
                        return Err(ZX_ERR_NOT_SUPPORTED);
                    }
                    let created = Arc::new(LocalNode::MutableFile(Arc::new(
                        LocalMutableFileNode::default(),
                    )));
                    directory.insert_child(component, Arc::clone(&created))?;
                    return wrap_local_node(created);
                }
                LocalWalkComponent::Name(component) => {
                    let Some(child) = directory.child(component) else {
                        return Err(ZX_ERR_NOT_FOUND);
                    };
                    directory = child.directory_node()?;
                }
            }
        }

        Err(ZX_ERR_INTERNAL)
    }

    fn unlinkat(&self, path: &str) -> Result<(), zx_status_t> {
        let (parent, leaf) = resolve_local_parent_and_leaf(&self.node, path)?;
        if parent.read_only {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        let removed = parent.remove_child(leaf)?;
        if let LocalNode::Directory(directory) = removed.as_ref()
            && !directory.is_empty()
        {
            parent.insert_existing_child(leaf, removed)?;
            return Err(ZX_ERR_NOT_EMPTY);
        }
        Ok(())
    }

    fn linkat(
        &self,
        src_path: &str,
        target_dir: &dyn FdOps,
        target_path: &str,
    ) -> Result<(), zx_status_t> {
        let Some(target_dir) = target_dir.as_any().downcast_ref::<LocalDirFd>() else {
            return Err(ZX_ERR_NOT_SUPPORTED);
        };
        let source = resolve_local_existing_node(&self.node, src_path)?;
        if matches!(source.as_ref(), LocalNode::Directory(_)) {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let (target_parent, target_leaf) =
            resolve_local_parent_and_leaf(&target_dir.node, target_path)?;
        if target_parent.read_only {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        target_parent.insert_existing_child(target_leaf, source)
    }

    fn renameat(
        &self,
        src_path: &str,
        target_dir: &dyn FdOps,
        target_path: &str,
    ) -> Result<(), zx_status_t> {
        let Some(target_dir) = target_dir.as_any().downcast_ref::<LocalDirFd>() else {
            return Err(ZX_ERR_NOT_SUPPORTED);
        };
        let (source_parent, source_leaf) = resolve_local_parent_and_leaf(&self.node, src_path)?;
        let (target_parent, target_leaf) =
            resolve_local_parent_and_leaf(&target_dir.node, target_path)?;
        if source_parent.read_only || target_parent.read_only {
            return Err(ZX_ERR_ACCESS_DENIED);
        }
        let node = source_parent.remove_child(source_leaf)?;
        if let Err(status) = target_parent.insert_existing_child(target_leaf, Arc::clone(&node)) {
            source_parent.insert_existing_child(source_leaf, node)?;
            return Err(status);
        }
        if let LocalNode::Directory(directory) = node.as_ref() {
            directory.set_parent(Some(Arc::downgrade(&target_parent)));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum LocalFileBacking {
    ReadOnly(Arc<LocalReadOnlyFileNode>),
    Mutable(Arc<LocalMutableFileNode>),
}

#[derive(Debug)]
struct LocalFileFd {
    backing: LocalFileBacking,
    cursor: Mutex<u64>,
}

impl LocalFileFd {
    fn new(backing: LocalFileBacking) -> Self {
        Self {
            backing,
            cursor: Mutex::new(0),
        }
    }

    fn read_all(&self) -> Vec<u8> {
        match &self.backing {
            LocalFileBacking::ReadOnly(file) => file.bytes.unwrap_or(&[]).to_vec(),
            LocalFileBacking::Mutable(file) => file.bytes.lock().clone(),
        }
    }

    fn len(&self) -> usize {
        match &self.backing {
            LocalFileBacking::ReadOnly(file) => file.bytes.unwrap_or(&[]).len(),
            LocalFileBacking::Mutable(file) => file.bytes.lock().len(),
        }
    }

    fn seek_cursor(&self, origin: SeekOrigin, offset: i64) -> Result<u64, zx_status_t> {
        let base = match origin {
            SeekOrigin::Start => 0i128,
            SeekOrigin::Current => i128::from(*self.cursor.lock()),
            SeekOrigin::End => i128::try_from(self.len()).map_err(|_| ZX_ERR_INVALID_ARGS)?,
        };
        let next = base
            .checked_add(i128::from(offset))
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let next = u64::try_from(next).map_err(|_| ZX_ERR_INVALID_ARGS)?;
        *self.cursor.lock() = next;
        Ok(next)
    }

    fn metadata(&self) -> LocalFdMetadata {
        let size_bytes = match &self.backing {
            LocalFileBacking::ReadOnly(file) => file.bytes.unwrap_or(&[]).len() as u64,
            LocalFileBacking::Mutable(file) => file.bytes.lock().len() as u64,
        };
        LocalFdMetadata {
            kind: LocalFdMetadataKind::RegularFile,
            size_bytes,
        }
    }

    fn pread_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        let bytes = self.read_all();
        let start = usize::try_from(offset).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        if start >= bytes.len() {
            return Ok(0);
        }
        let actual = (bytes.len() - start).min(buffer.len());
        buffer[..actual].copy_from_slice(&bytes[start..start + actual]);
        Ok(actual)
    }

    fn pwrite_at(&self, offset: u64, buffer: &[u8]) -> Result<usize, zx_status_t> {
        match &self.backing {
            LocalFileBacking::ReadOnly(_) => Err(ZX_ERR_ACCESS_DENIED),
            LocalFileBacking::Mutable(file) => {
                let start = usize::try_from(offset).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
                let mut bytes = file.bytes.lock();
                let end = start.checked_add(buffer.len()).ok_or(ZX_ERR_OUT_OF_RANGE)?;
                if bytes.len() < end {
                    bytes.resize(end, 0);
                }
                bytes[start..end].copy_from_slice(buffer);
                Ok(buffer.len())
            }
        }
    }
}

impl FdOps for LocalFileFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        let bytes = self.read_all();
        let mut cursor = self.cursor.lock();
        let start = usize::try_from(*cursor).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        if start >= bytes.len() {
            return Ok(0);
        }
        let actual = (bytes.len() - start).min(buffer.len());
        buffer[..actual].copy_from_slice(&bytes[start..start + actual]);
        *cursor = cursor
            .checked_add(u64::try_from(actual).map_err(|_| ZX_ERR_OUT_OF_RANGE)?)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        Ok(actual)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        match &self.backing {
            LocalFileBacking::ReadOnly(_) => Err(ZX_ERR_ACCESS_DENIED),
            LocalFileBacking::Mutable(file) => {
                let mut cursor = self.cursor.lock();
                let start = usize::try_from(*cursor).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
                let mut bytes = file.bytes.lock();
                let end = start.checked_add(buffer.len()).ok_or(ZX_ERR_OUT_OF_RANGE)?;
                if bytes.len() < end {
                    bytes.resize(end, 0);
                }
                bytes[start..end].copy_from_slice(buffer);
                *cursor = u64::try_from(end).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
                Ok(buffer.len())
            }
        }
    }

    fn seek(&self, origin: SeekOrigin, offset: i64) -> Result<u64, zx_status_t> {
        self.seek_cursor(origin, offset)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let cloned = Self::new(self.backing.clone());
        *cloned.cursor.lock() = *self.cursor.lock();
        Ok(Arc::new(cloned))
    }

    fn wait_interest(&self) -> Option<nexus_io::WaitSpec> {
        None
    }

    fn as_vmo(&self, flags: VmoFlags) -> Result<zx_handle_t, zx_status_t> {
        if !flags.contains(VmoFlags::READ) {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        match &self.backing {
            LocalFileBacking::ReadOnly(file) => file
                .get_or_create_vmo()
                .and_then(|handle| duplicate_handle(handle, ZX_RIGHT_SAME_RIGHTS)),
            LocalFileBacking::Mutable(_) => Err(ZX_ERR_NOT_SUPPORTED),
        }
    }
}

#[derive(Debug)]
enum LocalNode {
    Directory(Arc<LocalDirectoryNode>),
    ReadOnlyFile(Arc<LocalReadOnlyFileNode>),
    MutableFile(Arc<LocalMutableFileNode>),
}

impl LocalNode {
    fn directory_node(&self) -> Result<Arc<LocalDirectoryNode>, zx_status_t> {
        match self {
            Self::Directory(directory) => Ok(Arc::clone(directory)),
            _ => Err(ZX_ERR_NOT_DIR),
        }
    }
}

#[derive(Debug)]
struct LocalDirectoryNode {
    read_only: bool,
    parent: Mutex<Option<Weak<LocalDirectoryNode>>>,
    children: Mutex<BTreeMap<String, Arc<LocalNode>>>,
}

impl LocalDirectoryNode {
    fn new(read_only: bool) -> Self {
        Self {
            read_only,
            parent: Mutex::new(None),
            children: Mutex::new(BTreeMap::new()),
        }
    }

    fn set_parent(&self, parent: Option<Weak<LocalDirectoryNode>>) {
        *self.parent.lock() = parent;
    }

    fn parent_or_self(self: &Arc<Self>) -> Arc<Self> {
        self.parent
            .lock()
            .as_ref()
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| Arc::clone(self))
    }

    fn is_empty(&self) -> bool {
        self.children.lock().is_empty()
    }

    fn list_entries(&self) -> Vec<DirectoryEntry> {
        self.children
            .lock()
            .iter()
            .map(|(name, node)| DirectoryEntry {
                name: name.clone(),
                kind: match node.as_ref() {
                    LocalNode::Directory(_) => DirectoryEntryKind::Directory,
                    LocalNode::ReadOnlyFile(_) | LocalNode::MutableFile(_) => {
                        DirectoryEntryKind::File
                    }
                },
            })
            .collect()
    }

    fn child(&self, name: &str) -> Option<Arc<LocalNode>> {
        self.children.lock().get(name).cloned()
    }

    fn insert_child(self: &Arc<Self>, name: &str, node: Arc<LocalNode>) -> Result<(), zx_status_t> {
        let mut children = self.children.lock();
        if children.contains_key(name) {
            return Err(ZX_ERR_ALREADY_EXISTS);
        }
        if let LocalNode::Directory(directory) = node.as_ref() {
            directory.set_parent(Some(Arc::downgrade(self)));
        }
        children.insert(name.to_string(), node);
        Ok(())
    }

    fn insert_existing_child(
        self: &Arc<Self>,
        name: &str,
        node: Arc<LocalNode>,
    ) -> Result<(), zx_status_t> {
        self.insert_child(name, node)
    }

    fn remove_child(&self, name: &str) -> Result<Arc<LocalNode>, zx_status_t> {
        self.children.lock().remove(name).ok_or(ZX_ERR_NOT_FOUND)
    }

    fn ensure_directory(
        self: &Arc<Self>,
        name: &str,
    ) -> Result<Arc<LocalDirectoryNode>, zx_status_t> {
        if let Some(existing) = self.child(name) {
            return existing.directory_node();
        }
        let directory = Arc::new(LocalDirectoryNode::new(self.read_only));
        directory.set_parent(Some(Arc::downgrade(self)));
        self.insert_child(name, Arc::new(LocalNode::Directory(Arc::clone(&directory))))?;
        Ok(directory)
    }
}

#[derive(Debug)]
struct LocalReadOnlyFileNode {
    bytes: Option<&'static [u8]>,
    cached_vmo: Mutex<Option<zx_handle_t>>,
}

impl LocalReadOnlyFileNode {
    fn new(bytes: Option<&'static [u8]>, vmo: Option<zx_handle_t>) -> Self {
        Self {
            bytes,
            cached_vmo: Mutex::new(vmo),
        }
    }

    fn get_or_create_vmo(&self) -> Result<zx_handle_t, zx_status_t> {
        if let Some(handle) = *self.cached_vmo.lock() {
            return Ok(handle);
        }
        let bytes = self.bytes.unwrap_or(&[]);
        let handle = create_vmo_with_bytes(bytes)?;
        *self.cached_vmo.lock() = Some(handle);
        Ok(handle)
    }
}

#[derive(Debug, Default)]
struct LocalMutableFileNode {
    bytes: Mutex<Vec<u8>>,
}

fn truncate_local_node(node: &Arc<LocalNode>) -> Result<(), zx_status_t> {
    match node.as_ref() {
        LocalNode::ReadOnlyFile(_) => Err(ZX_ERR_ACCESS_DENIED),
        LocalNode::MutableFile(file) => {
            file.bytes.lock().clear();
            Ok(())
        }
        LocalNode::Directory(_) => Err(ZX_ERR_NOT_FILE),
    }
}

fn wrap_local_node(node: Arc<LocalNode>) -> Result<Arc<dyn FdOps>, zx_status_t> {
    match node.as_ref() {
        LocalNode::Directory(directory) => Ok(Arc::new(LocalDirFd::new(Arc::clone(directory)))),
        LocalNode::ReadOnlyFile(file) => Ok(Arc::new(LocalFileFd::new(
            LocalFileBacking::ReadOnly(Arc::clone(file)),
        ))),
        LocalNode::MutableFile(file) => Ok(Arc::new(LocalFileFd::new(LocalFileBacking::Mutable(
            Arc::clone(file),
        )))),
    }
}

#[derive(Clone, Copy)]
enum LocalWalkComponent<'a> {
    Current,
    Parent,
    Name(&'a str),
}

fn split_boot_asset_path(path: &str) -> Result<Vec<&str>, zx_status_t> {
    if path.is_empty() || path.starts_with('/') {
        return Err(ZX_ERR_BAD_PATH);
    }
    let mut components = Vec::new();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        if matches!(component, "." | "..") {
            return Err(ZX_ERR_BAD_PATH);
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err(ZX_ERR_BAD_PATH);
    }
    Ok(components)
}

fn split_local_walk_path(
    path: &str,
    allow_empty: bool,
) -> Result<Vec<LocalWalkComponent<'_>>, zx_status_t> {
    if path.starts_with('/') {
        return Err(ZX_ERR_BAD_PATH);
    }
    if path.is_empty() {
        return if allow_empty {
            Ok(Vec::new())
        } else {
            Err(ZX_ERR_BAD_PATH)
        };
    }
    let mut components = Vec::new();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        components.push(match component {
            "." => LocalWalkComponent::Current,
            ".." => LocalWalkComponent::Parent,
            _ => LocalWalkComponent::Name(component),
        });
    }
    if components.is_empty() && !allow_empty {
        return Err(ZX_ERR_BAD_PATH);
    }
    Ok(components)
}

fn resolve_local_existing_node(
    start: &Arc<LocalDirectoryNode>,
    path: &str,
) -> Result<Arc<LocalNode>, zx_status_t> {
    let components = split_local_walk_path(path, false)?;
    let mut directory = Arc::clone(start);
    for (index, component) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        match component {
            LocalWalkComponent::Current => {
                if last {
                    return Ok(Arc::new(LocalNode::Directory(directory)));
                }
            }
            LocalWalkComponent::Parent => {
                directory = directory.parent_or_self();
                if last {
                    return Ok(Arc::new(LocalNode::Directory(directory)));
                }
            }
            LocalWalkComponent::Name(name) if last => {
                return directory.child(name).ok_or(ZX_ERR_NOT_FOUND);
            }
            LocalWalkComponent::Name(name) => {
                let child = directory.child(name).ok_or(ZX_ERR_NOT_FOUND)?;
                directory = child.directory_node()?;
            }
        }
    }
    Err(ZX_ERR_BAD_PATH)
}

fn resolve_local_parent_and_leaf<'a>(
    start: &Arc<LocalDirectoryNode>,
    path: &'a str,
) -> Result<(Arc<LocalDirectoryNode>, &'a str), zx_status_t> {
    let components = split_local_walk_path(path, false)?;
    let mut directory = Arc::clone(start);
    let mut leaf = None;
    for (index, component) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        match component {
            LocalWalkComponent::Current if last => return Err(ZX_ERR_BAD_PATH),
            LocalWalkComponent::Current => {}
            LocalWalkComponent::Parent if last => return Err(ZX_ERR_BAD_PATH),
            LocalWalkComponent::Parent => directory = directory.parent_or_self(),
            LocalWalkComponent::Name(name) if last => leaf = Some(*name),
            LocalWalkComponent::Name(name) => {
                let child = directory.child(name).ok_or(ZX_ERR_NOT_FOUND)?;
                directory = child.directory_node()?;
            }
        }
    }
    Ok((directory, leaf.ok_or(ZX_ERR_BAD_PATH)?))
}

fn duplicate_handle(handle: zx_handle_t, rights: zx_rights_t) -> Result<zx_handle_t, zx_status_t> {
    if handle == ZX_HANDLE_INVALID {
        return Err(ZX_ERR_BAD_HANDLE);
    }
    let mut duplicate = ZX_HANDLE_INVALID;
    let status = axle_arch_x86_64::int80_syscall(
        AXLE_SYS_HANDLE_DUPLICATE as u64,
        [
            handle,
            rights as u64,
            &mut duplicate as *mut zx_handle_t as u64,
            0,
            0,
            0,
        ],
    );
    if status == ZX_OK {
        Ok(duplicate)
    } else {
        Err(status)
    }
}

fn create_vmo_with_bytes(bytes: &[u8]) -> Result<zx_handle_t, zx_status_t> {
    let mut handle = ZX_HANDLE_INVALID;
    let size = bytes.len().max(1) as u64;
    let status = axle_arch_x86_64::int80_syscall(
        AXLE_SYS_VMO_CREATE as u64,
        [size, 0, &mut handle as *mut zx_handle_t as u64, 0, 0, 0],
    );
    if status != ZX_OK {
        return Err(status);
    }
    if !bytes.is_empty() {
        let status = axle_arch_x86_64::int80_syscall(
            AXLE_SYS_VMO_WRITE as u64,
            [handle, bytes.as_ptr() as u64, 0, bytes.len() as u64, 0, 0],
        );
        if status != ZX_OK {
            let _ = zx_handle_close(handle);
            return Err(status);
        }
    }
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::{BootAssetEntry, BootstrapNamespace, local_fd_pread, local_fd_pwrite};
    use alloc::vec;
    use nexus_io::{FdTable, OpenFlags, SeekOrigin};

    #[test]
    fn boot_namespace_reads_manifest_assets() {
        let namespace = BootstrapNamespace::build(&[
            BootAssetEntry::bytes("manifests/root.nxcd", b"root"),
            BootAssetEntry::bytes("manifests/echo-client.nxcd", b"client"),
        ])
        .expect("build boot namespace");

        let root = namespace
            .namespace()
            .open("/boot/manifests/root.nxcd", OpenFlags::READABLE)
            .expect("open root manifest");
        let mut bytes = [0u8; 16];
        let actual = root.read(&mut bytes).expect("read manifest");
        assert_eq!(&bytes[..actual], b"root");

        let pkg = namespace
            .namespace()
            .open("/pkg/manifests/echo-client.nxcd", OpenFlags::READABLE)
            .expect("open /pkg alias");
        let actual = pkg.read(&mut bytes).expect("read manifest alias");
        assert_eq!(&bytes[..actual], b"client");
    }

    #[test]
    fn tmpfs_create_clone_and_read_roundtrips() {
        let namespace =
            BootstrapNamespace::build(&[BootAssetEntry::bytes("manifests/root.nxcd", b"root")])
                .expect("build namespace");

        let mut table = FdTable::new();
        let file = namespace
            .namespace()
            .open(
                "/tmp/state.bin",
                OpenFlags::READABLE | OpenFlags::WRITABLE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            )
            .expect("open tmp file");
        let fd = table
            .open(
                file,
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                nexus_io::FdFlags::empty(),
            )
            .expect("install tmp file");
        let clone = table
            .clone_fd(fd, nexus_io::FdFlags::empty())
            .expect("clone tmp file");
        let payload = vec![1u8, 2, 3, 4];
        let actual = table.write(clone, &payload).expect("write tmp file");
        assert_eq!(actual, payload.len());
        let mut read_back = [0u8; 8];
        let actual = table.read(fd, &mut read_back).expect("read tmp file");
        assert_eq!(&read_back[..actual], payload.as_slice());
    }

    #[test]
    fn tmpfs_supports_readdir_link_rename_and_unlink() {
        let namespace =
            BootstrapNamespace::build(&[BootAssetEntry::bytes("manifests/root.nxcd", b"root")])
                .expect("build namespace");

        let source = namespace
            .namespace()
            .open(
                "/tmp/original.txt",
                OpenFlags::READABLE | OpenFlags::WRITABLE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            )
            .expect("create source");
        source.write(b"hello").expect("write source");

        namespace
            .namespace()
            .link("/tmp/original.txt", "/tmp/linked.txt")
            .expect("link file");
        namespace
            .namespace()
            .rename("/tmp/linked.txt", "/tmp/renamed.txt")
            .expect("rename file");

        let entries = namespace
            .namespace()
            .readdir("/tmp")
            .expect("readdir tmpfs");
        assert!(entries.iter().any(|entry| entry.name == "original.txt"));
        assert!(entries.iter().any(|entry| entry.name == "renamed.txt"));

        namespace
            .namespace()
            .unlink("/tmp/original.txt")
            .expect("unlink original");
        namespace
            .namespace()
            .unlink("/tmp/renamed.txt")
            .expect("unlink renamed");

        let entries = namespace
            .namespace()
            .readdir("/tmp")
            .expect("readdir tmpfs after cleanup");
        assert!(entries.is_empty());
    }

    #[test]
    fn boot_assets_support_seek_and_offset_reads() {
        let namespace = BootstrapNamespace::build(&[BootAssetEntry::bytes("bin/app", b"abcdef")])
            .expect("build namespace");

        let mut table = FdTable::new();
        let file = namespace
            .namespace()
            .open("/boot/bin/app", OpenFlags::READABLE)
            .expect("open boot asset");
        let fd = table
            .open(file, OpenFlags::READABLE, nexus_io::FdFlags::empty())
            .expect("install file");

        let end = table.seek(fd, SeekOrigin::End, 0).expect("seek end");
        assert_eq!(end, 6);

        let start = table.seek(fd, SeekOrigin::Start, 2).expect("seek start");
        assert_eq!(start, 2);

        let mut bytes = [0u8; 8];
        let actual = table.read(fd, &mut bytes).expect("read from offset");
        assert_eq!(actual, 4);
        assert_eq!(&bytes[..actual], b"cdef");
    }

    #[test]
    fn local_file_pread_and_pwrite_preserve_cursor() {
        let namespace =
            BootstrapNamespace::build(&[BootAssetEntry::bytes("manifests/root.nxcd", b"root")])
                .expect("build namespace");

        let file = namespace
            .namespace()
            .open(
                "/tmp/state.bin",
                OpenFlags::READABLE | OpenFlags::WRITABLE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            )
            .expect("open tmp file");
        file.write(b"abcdef").expect("seed bytes");

        let mut read_back = [0u8; 4];
        let actual = local_fd_pread(file.as_ref(), 2, &mut read_back)
            .expect("local file helper")
            .expect("pread");
        assert_eq!(actual, 4);
        assert_eq!(&read_back[..actual], b"cdef");

        local_fd_pwrite(file.as_ref(), 1, b"XY")
            .expect("local file helper")
            .expect("pwrite");

        let end = file
            .seek(SeekOrigin::Current, 0)
            .expect("cursor preserved at end");
        assert_eq!(end, 6);

        let mut sequential = [0u8; 6];
        let actual = file
            .read(&mut sequential)
            .expect("read after pwrite at end");
        assert_eq!(actual, 0);

        file.seek(SeekOrigin::Start, 0)
            .expect("seek back to start for content check");
        let actual = file.read(&mut sequential).expect("read after pread/pwrite");
        assert_eq!(actual, 6);
        assert_eq!(&sequential[..actual], b"aXYdef");
    }
}
