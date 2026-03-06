use axle_page_table::{PageMapping, PageRange, PageTable, PageTableError, PageTableLock};

/// Bootstrap backend over the fixed userspace `USER_PT` bridge.
#[derive(Debug, Default)]
pub(crate) struct BootstrapUserPageTable;

#[derive(Debug)]
pub(crate) struct LockedBootstrapUserPageTable {
    range: PageRange,
}

impl PageTable for BootstrapUserPageTable {
    type Lock<'a>
        = LockedBootstrapUserPageTable
    where
        Self: 'a;

    fn lock(&mut self, range: PageRange) -> Result<Self::Lock<'_>, PageTableError> {
        Ok(LockedBootstrapUserPageTable { range })
    }
}

impl PageTableLock for LockedBootstrapUserPageTable {
    fn range(&self) -> PageRange {
        self.range
    }

    fn query_page(&mut self, va: u64) -> Result<Option<PageMapping>, PageTableError> {
        match crate::userspace::query_user_page_frame(va) {
            Ok(Some(frame)) => PageMapping::new(frame.paddr(), frame.writable()).map(Some),
            Ok(None) => Ok(None),
            Err(()) => Err(PageTableError::Backend),
        }
    }

    fn map_page(&mut self, va: u64, mapping: PageMapping) -> Result<(), PageTableError> {
        crate::userspace::install_user_page_frame(va, mapping.paddr(), mapping.writable())
            .map_err(|_| PageTableError::Backend)
    }

    fn unmap_page(&mut self, va: u64) -> Result<(), PageTableError> {
        crate::userspace::clear_user_page_frame(va).map_err(|_| PageTableError::Backend)
    }

    fn protect_page(&mut self, va: u64, writable: bool) -> Result<(), PageTableError> {
        crate::userspace::set_user_page_writable(va, writable).map_err(|_| PageTableError::Backend)
    }

    fn flush_page(&mut self, va: u64) -> Result<(), PageTableError> {
        crate::arch::tlb::flush_page_global(va);
        Ok(())
    }

    fn commit(self) -> Result<(), PageTableError> {
        Ok(())
    }
}
