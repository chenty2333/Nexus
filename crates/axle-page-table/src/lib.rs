//! Minimal page-table transaction core.
//!
//! This crate provides a tiny, `no_std` transaction cursor that can drive
//! bootstrap page-table backends while already exposing a future-shaped
//! `lock(range) -> query/map/unmap/protect/commit` interface.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

/// Canonical base page size used by the bootstrap page-table layer.
pub const PAGE_SIZE: u64 = 0x1000;

/// One page-aligned virtual-address range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageRange {
    base: u64,
    len: u64,
}

impl PageRange {
    /// Build one aligned page range.
    pub fn new(base: u64, len: u64) -> Result<Self, PageTableError> {
        validate_range(base, len)?;
        Ok(Self { base, len })
    }

    /// Base virtual address.
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Range length in bytes.
    pub const fn len(self) -> u64 {
        self.len
    }

    /// Whether the range is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Exclusive end virtual address.
    pub const fn end(self) -> u64 {
        self.base + self.len
    }

    /// Whether the range contains the given page-aligned address.
    pub fn contains_page(self, va: u64) -> bool {
        is_page_aligned(va) && va >= self.base && va < self.end()
    }

    /// Whether the range fully contains another aligned range.
    pub fn contains_range(self, base: u64, len: u64) -> bool {
        let Ok(subrange) = Self::new(base, len) else {
            return false;
        };
        subrange.base >= self.base && subrange.end() <= self.end()
    }
}

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

/// One locked page-table window.
pub trait PageTableLock {
    /// Locked virtual-address window.
    fn range(&self) -> PageRange;

    /// Query one page-aligned virtual address.
    fn query_page(&mut self, va: u64) -> Result<Option<PageMapping>, PageTableError>;

    /// Install or replace one page mapping.
    fn map_page(&mut self, va: u64, mapping: PageMapping) -> Result<(), PageTableError>;

    /// Remove one mapped page.
    fn unmap_page(&mut self, va: u64) -> Result<(), PageTableError>;

    /// Update writability on one mapped page.
    fn protect_page(&mut self, va: u64, writable: bool) -> Result<(), PageTableError>;

    /// Flush one page from whatever TLB view this session manages.
    fn flush_page(&mut self, va: u64) -> Result<(), PageTableError>;

    /// Finish the session and publish any deferred synchronization work.
    fn commit(self) -> Result<(), PageTableError>;
}

/// Page-table object that can vend locked mutation sessions.
pub trait PageTable {
    /// Concrete lock/session type for this page table.
    type Lock<'a>: PageTableLock + 'a
    where
        Self: 'a;

    /// Lock one aligned window and return a mutation session for it.
    fn lock(&mut self, range: PageRange) -> Result<Self::Lock<'_>, PageTableError>;
}

/// Transaction cursor over one locked page-table session.
#[derive(Debug)]
pub struct TxCursor<L: PageTableLock> {
    lock: L,
}

impl<L: PageTableLock> TxCursor<L> {
    /// Create a new cursor over one locked page-table session.
    pub fn new(lock: L) -> Self {
        Self { lock }
    }

    /// Locked virtual-address window.
    pub fn range(&self) -> PageRange {
        self.lock.range()
    }

    /// Query one page-aligned virtual address.
    pub fn query(&mut self, va: u64) -> Result<Option<PageMapping>, PageTableError> {
        validate_page_in_range(self.range(), va)?;
        self.lock.query_page(va)
    }

    /// Install or replace every page in one aligned range.
    pub fn map<F>(&mut self, base: u64, len: u64, mut mapping_at: F) -> Result<(), PageTableError>
    where
        F: FnMut(u64) -> Result<PageMapping, PageTableError>,
    {
        let page_count = validate_subrange(self.range(), base, len)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * PAGE_SIZE;
            let mapping = mapping_at(va)?;
            self.lock.map_page(va, mapping)?;
            self.lock.flush_page(va)?;
        }
        Ok(())
    }

    /// Remove every page in one aligned range.
    pub fn unmap(&mut self, base: u64, len: u64) -> Result<(), PageTableError> {
        let page_count = validate_subrange(self.range(), base, len)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * PAGE_SIZE;
            self.lock.unmap_page(va)?;
            self.lock.flush_page(va)?;
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
        let page_count = validate_subrange(self.range(), base, len)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * PAGE_SIZE;
            let writable = writable_at(va)?;
            self.lock.protect_page(va, writable)?;
            self.lock.flush_page(va)?;
        }
        Ok(())
    }

    /// Commit the current session.
    pub fn commit(self) -> Result<(), PageTableError> {
        self.lock.commit()
    }
}

fn validate_page_in_range(range: PageRange, va: u64) -> Result<(), PageTableError> {
    if !range.contains_page(va) {
        return Err(PageTableError::InvalidArgs);
    }
    Ok(())
}

fn validate_subrange(range: PageRange, base: u64, len: u64) -> Result<usize, PageTableError> {
    let page_count = validate_range(base, len)?;
    if !range.contains_range(base, len) {
        return Err(PageTableError::InvalidArgs);
    }
    Ok(page_count)
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
        commits: usize,
    }

    struct MockLock<'a> {
        backend: &'a mut MockBackend,
        range: PageRange,
    }

    impl PageTable for MockBackend {
        type Lock<'a>
            = MockLock<'a>
        where
            Self: 'a;

        fn lock(&mut self, range: PageRange) -> Result<Self::Lock<'_>, PageTableError> {
            Ok(MockLock {
                backend: self,
                range,
            })
        }
    }

    impl PageTableLock for MockLock<'_> {
        fn range(&self) -> PageRange {
            self.range
        }

        fn query_page(&mut self, va: u64) -> Result<Option<PageMapping>, PageTableError> {
            Ok(self.backend.pages.get(&va).copied())
        }

        fn map_page(&mut self, va: u64, mapping: PageMapping) -> Result<(), PageTableError> {
            self.backend.pages.insert(va, mapping);
            Ok(())
        }

        fn unmap_page(&mut self, va: u64) -> Result<(), PageTableError> {
            self.backend
                .pages
                .remove(&va)
                .ok_or(PageTableError::NotMapped)?;
            Ok(())
        }

        fn protect_page(&mut self, va: u64, writable: bool) -> Result<(), PageTableError> {
            let Some(mapping) = self.backend.pages.get_mut(&va) else {
                return Err(PageTableError::NotMapped);
            };
            *mapping = PageMapping::new(mapping.paddr(), writable)?;
            Ok(())
        }

        fn flush_page(&mut self, va: u64) -> Result<(), PageTableError> {
            self.backend.flushes.push(va);
            Ok(())
        }

        fn commit(self) -> Result<(), PageTableError> {
            self.backend.commits += 1;
            Ok(())
        }
    }

    #[test]
    fn query_reports_existing_mapping() {
        let mut backend = MockBackend::default();
        backend
            .pages
            .insert(PAGE_SIZE, PageMapping::new(0x20_000, true).unwrap());
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        let mut tx = TxCursor::new(backend.lock(range).unwrap());

        assert_eq!(
            tx.query(PAGE_SIZE).unwrap(),
            Some(PageMapping::new(0x20_000, true).unwrap())
        );
        assert_eq!(tx.query(PAGE_SIZE * 2).unwrap(), None);
        tx.commit().unwrap();
        assert_eq!(backend.commits, 1);
    }

    #[test]
    fn map_populates_each_page_and_flushes() {
        let mut backend = MockBackend::default();
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        let mut tx = TxCursor::new(backend.lock(range).unwrap());

        tx.map(PAGE_SIZE, PAGE_SIZE * 2, |va| {
            let page_index = (va / PAGE_SIZE) - 1;
            PageMapping::new(0x40_000 + (page_index * PAGE_SIZE), page_index == 0)
        })
        .unwrap();
        tx.commit().unwrap();

        assert_eq!(backend.pages.len(), 2);
        assert_eq!(backend.flushes, vec![PAGE_SIZE, PAGE_SIZE * 2]);
        assert_eq!(backend.commits, 1);
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
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        let mut tx = TxCursor::new(backend.lock(range).unwrap());

        tx.unmap(PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        tx.commit().unwrap();

        assert!(backend.pages.is_empty());
        assert_eq!(backend.flushes, vec![PAGE_SIZE, PAGE_SIZE * 2]);
        assert_eq!(backend.commits, 1);
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
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        let mut tx = TxCursor::new(backend.lock(range).unwrap());

        tx.protect(PAGE_SIZE, PAGE_SIZE * 2, |va| Ok(va == PAGE_SIZE * 2))
            .unwrap();
        tx.commit().unwrap();

        assert_eq!(
            backend.pages.get(&PAGE_SIZE).copied().unwrap(),
            PageMapping::new(0x20_000, false).unwrap()
        );
        assert_eq!(
            backend.pages.get(&(PAGE_SIZE * 2)).copied().unwrap(),
            PageMapping::new(0x30_000, true).unwrap()
        );
        assert_eq!(backend.flushes, vec![PAGE_SIZE, PAGE_SIZE * 2]);
        assert_eq!(backend.commits, 1);
    }

    #[test]
    fn range_ops_reject_unaligned_or_unlocked_ranges() {
        let mut backend = MockBackend::default();
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE).unwrap();
        let mut tx = TxCursor::new(backend.lock(range).unwrap());

        assert_eq!(
            tx.map(PAGE_SIZE + 1, PAGE_SIZE, |_| PageMapping::new(
                0x20_000, true
            ),),
            Err(PageTableError::InvalidArgs)
        );
        assert_eq!(
            tx.unmap(PAGE_SIZE, PAGE_SIZE * 2),
            Err(PageTableError::InvalidArgs)
        );
        assert_eq!(
            tx.protect(PAGE_SIZE, 0, |_| Ok(false)),
            Err(PageTableError::InvalidArgs)
        );
        assert_eq!(tx.query(PAGE_SIZE * 2), Err(PageTableError::InvalidArgs));
    }
}
