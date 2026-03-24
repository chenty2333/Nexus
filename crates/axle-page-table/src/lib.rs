//! Minimal page-table transaction core.
//!
//! This crate provides a tiny, `no_std` transaction cursor that can drive
//! bootstrap page-table backends while already exposing a future-shaped
//! `lock(range) -> query/map/unmap/protect/commit` interface.
//!
//! Mutations record invalidation work into one `ShootdownBatch` and only publish
//! it at `commit`, so callers already program against batched synchronization
//! rather than per-page immediate flushes.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

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
pub enum MappingCachePolicy {
    /// Normal cacheable memory.
    Cached,
    /// Device/MMIO-style uncached mapping.
    DeviceMmio,
}

/// One mapped leaf-page entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageMapping {
    paddr: u64,
    writable: bool,
    executable: bool,
    cache_policy: MappingCachePolicy,
}

impl PageMapping {
    /// Build one page mapping from a page-aligned physical address.
    pub fn new(paddr: u64, writable: bool, executable: bool) -> Result<Self, PageTableError> {
        Self::with_perms(paddr, writable, executable)
    }

    /// Build one page mapping from a page-aligned physical address with explicit permissions.
    pub fn with_perms(
        paddr: u64,
        writable: bool,
        executable: bool,
    ) -> Result<Self, PageTableError> {
        Self::with_cache_policy(paddr, writable, executable, MappingCachePolicy::Cached)
    }

    /// Build one page mapping from a page-aligned physical address with explicit cache policy.
    pub fn with_cache_policy(
        paddr: u64,
        writable: bool,
        executable: bool,
        cache_policy: MappingCachePolicy,
    ) -> Result<Self, PageTableError> {
        if !is_page_aligned(paddr) {
            return Err(PageTableError::InvalidArgs);
        }
        Ok(Self {
            paddr,
            writable,
            executable,
            cache_policy,
        })
    }

    /// Backing physical address.
    pub const fn paddr(self) -> u64 {
        self.paddr
    }

    /// Whether the mapping should be writable.
    pub const fn writable(self) -> bool {
        self.writable
    }

    /// Whether the mapping should be executable.
    pub const fn executable(self) -> bool {
        self.executable
    }

    /// Leaf-page cache policy.
    pub const fn cache_policy(self) -> MappingCachePolicy {
        self.cache_policy
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

/// One deferred invalidation operation to publish at transaction commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushOp {
    /// Invalidate one page-aligned virtual page.
    Page(u64),
    /// Invalidate the entire address space (replaces individual page entries
    /// when the per-page list exceeds a compaction threshold).
    All,
}

/// Threshold at which individual page invalidations are promoted to a
/// full address-space flush.
const SHOOTDOWN_PROMOTION_THRESHOLD: usize = 16;

/// Batched invalidation work collected during one transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShootdownBatch {
    ops: Vec<FlushOp>,
}

impl ShootdownBatch {
    /// Build one empty invalidation batch.
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Return the collected invalidation operations in insertion order.
    pub fn ops(&self) -> &[FlushOp] {
        &self.ops
    }

    /// Whether the batch contains no invalidation work.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Number of deferred invalidation operations in the batch.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Record one page invalidation, deduplicating repeated entries.
    ///
    /// When the number of individual page invalidation entries exceeds
    /// [`SHOOTDOWN_PROMOTION_THRESHOLD`], the entire batch is replaced
    /// with a single [`FlushOp::All`] to avoid O(n) deduplication costs
    /// on large batches.
    pub fn invalidate_page(&mut self, va: u64) {
        // Already promoted -- nothing to do.
        if self.ops.first() == Some(&FlushOp::All) {
            return;
        }

        let op = FlushOp::Page(va);
        if !self.ops.contains(&op) {
            self.ops.push(op);
        }

        if self.ops.len() > SHOOTDOWN_PROMOTION_THRESHOLD {
            self.ops.clear();
            self.ops.push(FlushOp::All);
        }
    }
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

    /// Update write and execute permissions on one mapped page.
    fn protect_page(
        &mut self,
        va: u64,
        writable: bool,
        executable: bool,
    ) -> Result<(), PageTableError>;

    /// Finish the session and publish any deferred synchronization work.
    fn commit(self, shootdown: ShootdownBatch) -> Result<(), PageTableError>;
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
    shootdown: ShootdownBatch,
}

impl<L: PageTableLock> TxCursor<L> {
    /// Create a new cursor over one locked page-table session.
    pub fn new(lock: L) -> Self {
        Self {
            lock,
            shootdown: ShootdownBatch::new(),
        }
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
            self.shootdown.invalidate_page(va);
        }
        Ok(())
    }

    /// Remove every page in one aligned range.
    pub fn unmap(&mut self, base: u64, len: u64) -> Result<(), PageTableError> {
        let page_count = validate_subrange(self.range(), base, len)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * PAGE_SIZE;
            self.lock.unmap_page(va)?;
            self.shootdown.invalidate_page(va);
        }
        Ok(())
    }

    /// Update write and execute permissions for every page in one aligned range.
    pub fn protect<F>(&mut self, base: u64, len: u64, mut perms_at: F) -> Result<(), PageTableError>
    where
        F: FnMut(u64) -> Result<(bool, bool), PageTableError>,
    {
        let page_count = validate_subrange(self.range(), base, len)?;
        for page_index in 0..page_count {
            let va = base + (page_index as u64) * PAGE_SIZE;
            let (writable, executable) = perms_at(va)?;
            self.lock.protect_page(va, writable, executable)?;
            self.shootdown.invalidate_page(va);
        }
        Ok(())
    }

    /// Commit the current session.
    pub fn commit(self) -> Result<(), PageTableError> {
        self.lock.commit(self.shootdown)
    }
}

#[derive(Debug)]
struct TxSetEntry<K, L: PageTableLock> {
    key: K,
    cursor: TxCursor<L>,
}

/// Ordered set of page-table transaction cursors.
///
/// `TxSet` models the future "lock many address spaces/ranges in a global
/// order" shape needed by cross-address-space VM operations such as page-loan.
/// Callers must insert sessions in strictly increasing key order so lock
/// acquisition order remains explicit and reviewable.
#[derive(Debug)]
pub struct TxSet<K, L: PageTableLock> {
    entries: Vec<TxSetEntry<K, L>>,
}

impl<K: Ord, L: PageTableLock> TxSet<K, L> {
    /// Build one empty ordered transaction set.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Whether the set contains no locked sessions.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of locked sessions in the set.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Insert one locked session in strictly increasing key order.
    pub fn push(&mut self, key: K, cursor: TxCursor<L>) -> Result<(), PageTableError> {
        if self.entries.last().is_some_and(|last| last.key >= key) {
            return Err(PageTableError::InvalidArgs);
        }
        self.entries.push(TxSetEntry { key, cursor });
        Ok(())
    }

    /// Return the cursor for one previously inserted key.
    pub fn cursor_mut(&mut self, key: &K) -> Option<&mut TxCursor<L>> {
        self.entries
            .iter_mut()
            .find(|entry| &entry.key == key)
            .map(|entry| &mut entry.cursor)
    }

    /// Commit every locked session in reverse acquisition order.
    pub fn commit(mut self) -> Result<(), PageTableError> {
        while let Some(entry) = self.entries.pop() {
            entry.cursor.commit()?;
        }
        Ok(())
    }
}

impl<K: Ord, L: PageTableLock> Default for TxSet<K, L> {
    fn default() -> Self {
        Self::new()
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
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;
    use std::vec;
    use std::vec::Vec;

    struct MockBackend {
        id: u64,
        pages: BTreeMap<u64, PageMapping>,
        flushes: Vec<u64>,
        commits: usize,
        commit_log: Rc<RefCell<Vec<u64>>>,
    }

    impl Default for MockBackend {
        fn default() -> Self {
            Self::new(0, Rc::new(RefCell::new(Vec::new())))
        }
    }

    impl MockBackend {
        fn new(id: u64, commit_log: Rc<RefCell<Vec<u64>>>) -> Self {
            Self {
                id,
                pages: BTreeMap::new(),
                flushes: Vec::new(),
                commits: 0,
                commit_log,
            }
        }
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

        fn protect_page(
            &mut self,
            va: u64,
            writable: bool,
            executable: bool,
        ) -> Result<(), PageTableError> {
            let Some(mapping) = self.backend.pages.get_mut(&va) else {
                return Err(PageTableError::NotMapped);
            };
            *mapping = PageMapping::new(mapping.paddr(), writable, executable)?;
            Ok(())
        }

        fn commit(self, shootdown: ShootdownBatch) -> Result<(), PageTableError> {
            self.backend.commits += 1;
            self.backend
                .flushes
                .extend(shootdown.ops().iter().filter_map(|op| match *op {
                    FlushOp::Page(va) => Some(va),
                    FlushOp::All => None,
                }));
            self.backend.commit_log.borrow_mut().push(self.backend.id);
            Ok(())
        }
    }

    #[test]
    fn query_reports_existing_mapping() {
        let mut backend = MockBackend::default();
        backend
            .pages
            .insert(PAGE_SIZE, PageMapping::new(0x20_000, true, false).unwrap());
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        let mut tx = TxCursor::new(backend.lock(range).unwrap());

        assert_eq!(
            tx.query(PAGE_SIZE).unwrap(),
            Some(PageMapping::new(0x20_000, true, false).unwrap())
        );
        assert_eq!(tx.query(PAGE_SIZE * 2).unwrap(), None);
        tx.commit().unwrap();
        assert_eq!(backend.commits, 1);
    }

    #[test]
    fn map_populates_each_page_and_batches_flushes() {
        let mut backend = MockBackend::default();
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        let mut tx = TxCursor::new(backend.lock(range).unwrap());

        tx.map(PAGE_SIZE, PAGE_SIZE * 2, |va| {
            let page_index = (va / PAGE_SIZE) - 1;
            PageMapping::new(
                0x40_000 + (page_index * PAGE_SIZE),
                page_index == 0,
                page_index != 0,
            )
        })
        .unwrap();
        tx.commit().unwrap();

        assert_eq!(backend.pages.len(), 2);
        assert_eq!(backend.flushes, vec![PAGE_SIZE, PAGE_SIZE * 2]);
        assert_eq!(backend.commits, 1);
        assert_eq!(
            backend.pages.get(&PAGE_SIZE).copied().unwrap(),
            PageMapping::new(0x40_000, true, false).unwrap()
        );
        assert_eq!(
            backend.pages.get(&(PAGE_SIZE * 2)).copied().unwrap(),
            PageMapping::new(0x41_000, false, true).unwrap()
        );
    }

    #[test]
    fn unmap_removes_each_page_and_batches_flushes() {
        let mut backend = MockBackend::default();
        backend
            .pages
            .insert(PAGE_SIZE, PageMapping::new(0x20_000, true, true).unwrap());
        backend.pages.insert(
            PAGE_SIZE * 2,
            PageMapping::new(0x30_000, false, false).unwrap(),
        );
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        let mut tx = TxCursor::new(backend.lock(range).unwrap());

        tx.unmap(PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        tx.commit().unwrap();

        assert!(backend.pages.is_empty());
        assert_eq!(backend.flushes, vec![PAGE_SIZE, PAGE_SIZE * 2]);
        assert_eq!(backend.commits, 1);
    }

    #[test]
    fn protect_updates_permissions_and_batches_flushes() {
        let mut backend = MockBackend::default();
        backend
            .pages
            .insert(PAGE_SIZE, PageMapping::new(0x20_000, false, false).unwrap());
        backend.pages.insert(
            PAGE_SIZE * 2,
            PageMapping::new(0x30_000, false, true).unwrap(),
        );
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        let mut tx = TxCursor::new(backend.lock(range).unwrap());

        tx.protect(PAGE_SIZE, PAGE_SIZE * 2, |va| {
            Ok((va == PAGE_SIZE * 2, va == PAGE_SIZE))
        })
        .unwrap();
        tx.commit().unwrap();

        assert_eq!(
            backend.pages.get(&PAGE_SIZE).copied().unwrap(),
            PageMapping::new(0x20_000, false, true).unwrap()
        );
        assert_eq!(
            backend.pages.get(&(PAGE_SIZE * 2)).copied().unwrap(),
            PageMapping::new(0x30_000, true, false).unwrap()
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
                0x20_000, true, false
            ),),
            Err(PageTableError::InvalidArgs)
        );
        assert_eq!(
            tx.unmap(PAGE_SIZE, PAGE_SIZE * 2),
            Err(PageTableError::InvalidArgs)
        );
        assert_eq!(
            tx.protect(PAGE_SIZE, 0, |_| Ok((false, false))),
            Err(PageTableError::InvalidArgs)
        );
        assert_eq!(tx.query(PAGE_SIZE * 2), Err(PageTableError::InvalidArgs));
    }

    #[test]
    fn tx_set_requires_strictly_increasing_keys() {
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE).unwrap();
        let commit_log = Rc::new(RefCell::new(Vec::new()));
        let mut left = MockBackend::new(1, commit_log.clone());
        let mut right = MockBackend::new(2, commit_log);
        let mut tx_set = TxSet::new();

        tx_set
            .push(1_u64, TxCursor::new(left.lock(range).unwrap()))
            .unwrap();
        assert_eq!(
            tx_set.push(1_u64, TxCursor::new(right.lock(range).unwrap())),
            Err(PageTableError::InvalidArgs)
        );
    }

    #[test]
    fn tx_set_commits_locked_sessions_in_reverse_order() {
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE).unwrap();
        let commit_log = Rc::new(RefCell::new(Vec::new()));
        let mut left = MockBackend::new(1, commit_log.clone());
        let mut right = MockBackend::new(2, commit_log.clone());
        let mut tx_set = TxSet::new();

        tx_set
            .push(1_u64, TxCursor::new(left.lock(range).unwrap()))
            .unwrap();
        tx_set
            .push(2_u64, TxCursor::new(right.lock(range).unwrap()))
            .unwrap();

        assert_eq!(tx_set.len(), 2);
        assert!(tx_set.cursor_mut(&1).is_some());

        tx_set.commit().unwrap();

        assert_eq!(*commit_log.borrow(), vec![2, 1]);
        assert_eq!(left.commits, 1);
        assert_eq!(right.commits, 1);
    }

    #[test]
    fn repeated_page_updates_deduplicate_shootdown_entries() {
        let mut backend = MockBackend::default();
        backend
            .pages
            .insert(PAGE_SIZE, PageMapping::new(0x20_000, false, false).unwrap());
        let range = PageRange::new(PAGE_SIZE, PAGE_SIZE).unwrap();
        let mut tx = TxCursor::new(backend.lock(range).unwrap());

        tx.protect(PAGE_SIZE, PAGE_SIZE, |_| Ok((true, true)))
            .unwrap();
        tx.protect(PAGE_SIZE, PAGE_SIZE, |_| Ok((false, false)))
            .unwrap();
        tx.commit().unwrap();

        assert_eq!(backend.flushes, vec![PAGE_SIZE]);
        assert_eq!(backend.commits, 1);
    }
}
