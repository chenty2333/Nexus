use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::rights::ZX_RIGHT_SAME_RIGHTS;
use axle_types::status::{
    ZX_ERR_ACCESS_DENIED, ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_PATH,
    ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_INVALID_ARGS, ZX_ERR_IO_DATA_INTEGRITY,
    ZX_ERR_NOT_DIR, ZX_ERR_NOT_FILE, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED, ZX_OK,
};
use axle_types::syscall_numbers::AXLE_SYS_HANDLE_DUPLICATE;
use axle_types::{zx_handle_t, zx_rights_t, zx_status_t};
use libzircon::zx_socket_create;
use nexus_io::{
    FdFlags, FdOps, FdTable, NamespaceTrie, OpenFlags, PipeFd, SeekOrigin, SocketFd, VmoFlags,
    open_namespace_path,
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
    namespace: NamespaceTrie<Arc<dyn FdOps>>,
}

impl BootstrapNamespace {
    pub(crate) fn build(boot_assets: &[BootAssetEntry]) -> Result<Self, zx_status_t> {
        let boot_root = build_boot_root(boot_assets)?;
        let tmp_root = new_tmp_root();
        let mut namespace = NamespaceTrie::<Arc<dyn FdOps>>::new();
        namespace.insert("/boot", Arc::clone(&boot_root))?;
        namespace.insert("/pkg", Arc::clone(&boot_root))?;
        namespace.insert("/tmp", tmp_root)?;
        Ok(Self {
            boot_root,
            namespace,
        })
    }

    pub(crate) fn boot_root(&self) -> Arc<dyn FdOps> {
        Arc::clone(&self.boot_root)
    }

    pub(crate) fn namespace(&self) -> &NamespaceTrie<Arc<dyn FdOps>> {
        &self.namespace
    }
}

pub(crate) fn run_tmpfs_smoke(
    namespace: &NamespaceTrie<Arc<dyn FdOps>>,
) -> Result<(), zx_status_t> {
    let tmp = open_namespace_path(
        namespace,
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
    let components = split_local_path(entry.path)?;
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

    fn openat(&self, path: &str, flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let components = split_local_path(path)?;
        if components.is_empty() {
            return self.clone_fd(FdFlags::empty());
        }

        let mut directory = Arc::clone(&self.node);
        for (index, component) in components.iter().enumerate() {
            let last = index + 1 == components.len();
            if last {
                if let Some(existing) = directory.child(component) {
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

            let Some(child) = directory.child(component) else {
                return Err(ZX_ERR_NOT_FOUND);
            };
            directory = child.directory_node()?;
        }

        Err(ZX_ERR_INTERNAL)
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
}

impl LocalFileFd {
    fn new(backing: LocalFileBacking) -> Self {
        Self { backing }
    }

    fn read_all(&self) -> Vec<u8> {
        match &self.backing {
            LocalFileBacking::ReadOnly(file) => file.bytes.unwrap_or(&[]).to_vec(),
            LocalFileBacking::Mutable(file) => file.bytes.lock().clone(),
        }
    }
}

impl FdOps for LocalFileFd {
    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        let bytes = self.read_all();
        let actual = bytes.len().min(buffer.len());
        buffer[..actual].copy_from_slice(&bytes[..actual]);
        Ok(actual)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        match &self.backing {
            LocalFileBacking::ReadOnly(_) => Err(ZX_ERR_ACCESS_DENIED),
            LocalFileBacking::Mutable(file) => {
                let mut bytes = file.bytes.lock();
                bytes.clear();
                bytes.extend_from_slice(buffer);
                Ok(buffer.len())
            }
        }
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(Self::new(self.backing.clone())))
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
                .vmo
                .ok_or(ZX_ERR_NOT_SUPPORTED)
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
    children: Mutex<BTreeMap<String, Arc<LocalNode>>>,
}

impl LocalDirectoryNode {
    fn new(read_only: bool) -> Self {
        Self {
            read_only,
            children: Mutex::new(BTreeMap::new()),
        }
    }

    fn child(&self, name: &str) -> Option<Arc<LocalNode>> {
        self.children.lock().get(name).cloned()
    }

    fn insert_child(&self, name: &str, node: Arc<LocalNode>) -> Result<(), zx_status_t> {
        let mut children = self.children.lock();
        if children.contains_key(name) {
            return Err(ZX_ERR_ALREADY_EXISTS);
        }
        children.insert(name.to_string(), node);
        Ok(())
    }

    fn ensure_directory(&self, name: &str) -> Result<Arc<LocalDirectoryNode>, zx_status_t> {
        if let Some(existing) = self.child(name) {
            return existing.directory_node();
        }
        let directory = Arc::new(LocalDirectoryNode::new(self.read_only));
        self.insert_child(name, Arc::new(LocalNode::Directory(Arc::clone(&directory))))?;
        Ok(directory)
    }
}

#[derive(Debug)]
struct LocalReadOnlyFileNode {
    bytes: Option<&'static [u8]>,
    vmo: Option<zx_handle_t>,
}

impl LocalReadOnlyFileNode {
    fn new(bytes: Option<&'static [u8]>, vmo: Option<zx_handle_t>) -> Self {
        Self { bytes, vmo }
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

fn split_local_path(path: &str) -> Result<Vec<&str>, zx_status_t> {
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

fn duplicate_handle(handle: zx_handle_t, rights: zx_rights_t) -> Result<zx_handle_t, zx_status_t> {
    if handle == ZX_HANDLE_INVALID {
        return Err(ZX_ERR_BAD_HANDLE);
    }
    let mut duplicate = ZX_HANDLE_INVALID;
    let status = axle_arch_x86_64::int80_syscall(
        AXLE_SYS_HANDLE_DUPLICATE as u64,
        [
            handle as u64,
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

#[cfg(test)]
mod tests {
    use super::{BootAssetEntry, BootstrapNamespace};
    use alloc::vec;
    use nexus_io::{FdTable, OpenFlags, open_namespace_path};

    #[test]
    fn boot_namespace_reads_manifest_assets() {
        let namespace = BootstrapNamespace::build(&[
            BootAssetEntry::bytes("manifests/root.nxcd", b"root"),
            BootAssetEntry::bytes("manifests/echo-client.nxcd", b"client"),
        ])
        .expect("build boot namespace");

        let root = open_namespace_path(
            namespace.namespace(),
            "/boot/manifests/root.nxcd",
            OpenFlags::READABLE,
        )
        .expect("open root manifest");
        let mut bytes = [0u8; 16];
        let actual = root.read(&mut bytes).expect("read manifest");
        assert_eq!(&bytes[..actual], b"root");

        let pkg = open_namespace_path(
            namespace.namespace(),
            "/pkg/manifests/echo-client.nxcd",
            OpenFlags::READABLE,
        )
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
        let file = open_namespace_path(
            namespace.namespace(),
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
}
