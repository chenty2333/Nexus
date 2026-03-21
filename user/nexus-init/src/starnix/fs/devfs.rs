use super::super::*;
use alloc::vec;

#[derive(Clone)]
pub(in crate::starnix) struct NullFd;

impl FdOps for NullFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Ok(0)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        Ok(buffer.len())
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }
}

#[derive(Clone)]
pub(in crate::starnix) struct ZeroFd;

impl FdOps for ZeroFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        buffer.fill(0);
        Ok(buffer.len())
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        Ok(buffer.len())
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }
}

#[derive(Clone)]
pub(in crate::starnix) struct DevDirFd {
    tty: Arc<dyn FdOps>,
    null: Arc<dyn FdOps>,
    zero: Arc<dyn FdOps>,
}

impl DevDirFd {
    pub(in crate::starnix) fn new(
        tty: Arc<dyn FdOps>,
        null: Arc<dyn FdOps>,
        zero: Arc<dyn FdOps>,
    ) -> Self {
        Self { tty, null, zero }
    }

    fn entry(&self, path: &str) -> Result<Arc<dyn FdOps>, zx_status_t> {
        match path {
            "" | "." => Ok(Arc::new(self.clone())),
            "tty" => Ok(Arc::clone(&self.tty)),
            "null" => Ok(Arc::clone(&self.null)),
            "zero" => Ok(Arc::clone(&self.zero)),
            _ => Err(ZX_ERR_NOT_FOUND),
        }
    }
}

impl FdOps for DevDirFd {
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
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        Ok(vec![
            DirectoryEntry {
                name: String::from("tty"),
                kind: DirectoryEntryKind::Unknown,
            },
            DirectoryEntry {
                name: String::from("null"),
                kind: DirectoryEntryKind::Unknown,
            },
            DirectoryEntry {
                name: String::from("zero"),
                kind: DirectoryEntryKind::Unknown,
            },
        ])
    }

    fn openat(&self, path: &str, _flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let normalized = path.trim_matches('/');
        if normalized.contains('/') {
            return Err(ZX_ERR_NOT_FOUND);
        }
        self.entry(normalized)
    }
}
