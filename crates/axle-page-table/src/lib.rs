//! Minimal page-table transaction core.
//!
//! This crate provides a tiny, `no_std` transaction cursor that can drive
//! bootstrap page-table backends while keeping page-table mutation behind one
//! narrow interface.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

/// Canonical base page size used by the bootstrap page-table layer.
pub const PAGE_SIZE: u64 = 0x1000;

/// One mapped leaf-page entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageMapping {
    paddr: u64,
    writable: bool,
}

impl PageMapping {
    /// Build one page mapping from a page-aligned physical address.
    pub fn new(paddr: u64, writable: bool) -> Result<Self, PageTableError> {
        if !is_page_aligned(paddr) {
            return Err(PageTableError::InvalidArgs);
        }
        Ok(Self { paddr, writable })
    }

    /// Backing physical address.
    pub const fn paddr(self) -> u64 {
        self.paddr
    }

    /// Whether the mapping should be writable.
    pub const fn writable(self) -> bool {
        self.writable
    }
}

/// Errors returned by the page-table transaction layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageTableError {
    /// Invalid alignment, zero length, or overflowed arithmetic.
    InvalidArgs,
    /// The requested page is not currently mapped.
    NotMapped,
    /// The concrete backend rejected the operation.
    Backend,
}

/// Backend used by the transaction cursor.
pub trait PageTableBackend {
    /// Query one page-aligned virtual address.
    fn query_page(&mut self, va: u64) -> Result<Option<PageMapping>, PageTableError>;

    /// Install or replace one page mapping.
    fn map_page(&mut self, va: u64, mapping: PageMapping) -> Result<(), PageTableError>;

    /// Remove one mapped page.
    fn unmap_page(&mut self, va: u64) -> Result<(), PageTableError>;

    /// Update writability on one mapped page.
    fn protect_page(&mut self, va: u64, writable: bool) -> Result<(), PageTableError>;

    /// Flush one page from the active TLB view.
    fn flush_page(&mut self, va: u64) -> Result<(), PageTableError>;
}

/// Transaction cursor over one page-table backend.
#[derive(Debug)]
pub struct TxCursor<'a, B: PageTableBackend> {
    backend: &'a mut B,
}

impl<'a, B: PageTableBackend> TxCursor<'a, B> {
    /// Create a new cursor over one concrete page-table backend.
    pub fn new(backend: &'a mut B) -> Self {
        Self { backend }
    }

    /// Query one page-aligned virtual address.
    pub fn query(&mut self, va: u64) -> Result<Option<PageMapping>, PageTableError> {
        validate_page(va)?;
        self.backend.query_page(va)
    }

    /// Install or replace every page in one aligned range.
    pub fn map<F>(&mut self, base: u64, len: u64, mut mapping_at: F) -> Result<(), PageTableError>
    where
        F: FnMut(u64) -> Result<PageMapping, PageTableError>,
    {
        let page_count = validate_range(base, len)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * PAGE_SIZE;
            let mapping = mapping_at(va)?;
            self.backend.map_page(va, mapping)?;
            self.backend.flush_page(va)?;
        }
        Ok(())
    }

    /// Remove every page in one aligned range.
    pub fn unmap(&mut self, base: u64, len: u64) -> Result<(), PageTableError> {
        let page_count = validate_range(base, len)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * PAGE_SIZE;
            self.backend.unmap_page(va)?;
            self.backend.flush_page(va)?;
        }
        Ok(())
    }

    /// Update writability for every page in one aligned range.
    pub fn protect<F>(
        &mut self,
        base: u64,
        len: u64,
        mut writable_at: F,
    ) -> Result<(), PageTableError>
    where
        F: FnMut(u64) -> Result<bool, PageTableError>,
    {
        let page_count = validate_range(base, len)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * PAGE_SIZE;
            let writable = writable_at(va)?;
            self.backend.protect_page(va, writable)?;
            self.backend.flush_page(va)?;
        }
        Ok(())
    }
}

fn validate_page(va: u64) -> Result<(), PageTableError> {
    if !is_page_aligned(va) {
        return Err(PageTableError::InvalidArgs);
    }
    Ok(())
}

fn validate_range(base: u64, len: u64) -> Result<usize, PageTableError> {
    if len == 0 || !is_page_aligned(base) || !is_page_aligned(len) {
        return Err(PageTableError::InvalidArgs);
    }
    let Some(_end) = base.checked_add(len) else {
        return Err(PageTableError::InvalidArgs);
    };
    usize::try_from(len / PAGE_SIZE).map_err(|_| PageTableError::InvalidArgs)
}

const fn is_page_aligned(value: u64) -> bool {
    value & (PAGE_SIZE - 1) == 0
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::vec;
    use std::vec::Vec;

    #[derive(Default)]
    struct MockBackend {
        pages: BTreeMap<u64, PageMapping>,
        flushes: Vec<u64>,
    }

    impl PageTableBackend for MockBackend {
        fn query_page(&mut self, va: u64) -> Result<Option<PageMapping>, PageTableError> {
            Ok(self.pages.get(&va).copied())
        }

        fn map_page(&mut self, va: u64, mapping: PageMapping) -> Result<(), PageTableError> {
            self.pages.insert(va, mapping);
            Ok(())
        }

        fn unmap_page(&mut self, va: u64) -> Result<(), PageTableError> {
            self.pages.remove(&va).ok_or(PageTableError::NotMapped)?;
            Ok(())
        }

        fn protect_page(&mut self, va: u64, writable: bool) -> Result<(), PageTableError> {
            let Some(mapping) = self.pages.get_mut(&va) else {
                return Err(PageTableError::NotMapped);
            };
            *mapping = PageMapping::new(mapping.paddr(), writable)?;
            Ok(())
        }

        fn flush_page(&mut self, va: u64) -> Result<(), PageTableError> {
            self.flushes.push(va);
            Ok(())
        }
    }

    #[test]
    fn query_reports_existing_mapping() {
        let mut backend = MockBackend::default();
        backend
            .pages
            .insert(PAGE_SIZE, PageMapping::new(0x20_000, true).unwrap());
        let mut tx = TxCursor::new(&mut backend);

        assert_eq!(
            tx.query(PAGE_SIZE).unwrap(),
            Some(PageMapping::new(0x20_000, true).unwrap())
        );
        assert_eq!(tx.query(PAGE_SIZE * 2).unwrap(), None);
    }

    #[test]
    fn map_populates_each_page_and_flushes() {
        let mut backend = MockBackend::default();
        let mut tx = TxCursor::new(&mut backend);

        tx.map(PAGE_SIZE, PAGE_SIZE * 2, |va| {
            let page_index = (va / PAGE_SIZE) - 1;
            PageMapping::new(0x40_000 + (page_index * PAGE_SIZE), page_index == 0)
        })
        .unwrap();

        assert_eq!(backend.pages.len(), 2);
        assert_eq!(backend.flushes, vec![PAGE_SIZE, PAGE_SIZE * 2]);
        assert_eq!(
            backend.pages.get(&PAGE_SIZE).copied().unwrap(),
            PageMapping::new(0x40_000, true).unwrap()
        );
        assert_eq!(
            backend.pages.get(&(PAGE_SIZE * 2)).copied().unwrap(),
            PageMapping::new(0x41_000, false).unwrap()
        );
    }

    #[test]
    fn unmap_removes_each_page_and_flushes() {
        let mut backend = MockBackend::default();
        backend
            .pages
            .insert(PAGE_SIZE, PageMapping::new(0x20_000, true).unwrap());
        backend
            .pages
            .insert(PAGE_SIZE * 2, PageMapping::new(0x30_000, false).unwrap());
        let mut tx = TxCursor::new(&mut backend);

        tx.unmap(PAGE_SIZE, PAGE_SIZE * 2).unwrap();

        assert!(backend.pages.is_empty());
        assert_eq!(backend.flushes, vec![PAGE_SIZE, PAGE_SIZE * 2]);
    }

    #[test]
    fn protect_updates_permissions_and_flushes() {
        let mut backend = MockBackend::default();
        backend
            .pages
            .insert(PAGE_SIZE, PageMapping::new(0x20_000, false).unwrap());
        backend
            .pages
            .insert(PAGE_SIZE * 2, PageMapping::new(0x30_000, false).unwrap());
        let mut tx = TxCursor::new(&mut backend);

        tx.protect(PAGE_SIZE, PAGE_SIZE * 2, |va| Ok(va == PAGE_SIZE * 2))
            .unwrap();

        assert_eq!(
            backend.pages.get(&PAGE_SIZE).copied().unwrap(),
            PageMapping::new(0x20_000, false).unwrap()
        );
        assert_eq!(
            backend.pages.get(&(PAGE_SIZE * 2)).copied().unwrap(),
            PageMapping::new(0x30_000, true).unwrap()
        );
        assert_eq!(backend.flushes, vec![PAGE_SIZE, PAGE_SIZE * 2]);
    }

    #[test]
    fn range_ops_reject_unaligned_ranges() {
        let mut backend = MockBackend::default();
        let mut tx = TxCursor::new(&mut backend);

        assert_eq!(
            tx.map(PAGE_SIZE + 1, PAGE_SIZE, |_| PageMapping::new(
                0x20_000, true
            )),
            Err(PageTableError::InvalidArgs)
        );
        assert_eq!(
            tx.unmap(PAGE_SIZE, PAGE_SIZE - 1),
            Err(PageTableError::InvalidArgs)
        );
        assert_eq!(
            tx.protect(PAGE_SIZE, 0, |_| Ok(false)),
            Err(PageTableError::InvalidArgs)
        );
    }
}
