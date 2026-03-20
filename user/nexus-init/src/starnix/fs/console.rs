use super::super::*;

#[derive(Clone, Default)]
pub(in crate::starnix) struct ConsoleFd;

impl ConsoleFd {
    pub(in crate::starnix) const fn new() -> Self {
        Self
    }
}

impl FdOps for ConsoleFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        let mut actual = 0usize;
        zx_status_result(ax_console_read(buffer, &mut actual))?;
        Ok(actual)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        let mut actual = 0usize;
        zx_status_result(ax_console_write(buffer, &mut actual))?;
        Ok(actual)
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(Self::new()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }
}
