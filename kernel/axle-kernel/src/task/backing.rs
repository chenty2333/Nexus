use super::*;

#[derive(Clone, Debug)]
pub(super) struct GlobalVmo {
    size_bytes: u64,
    source: VmoBackingSource,
}

impl GlobalVmo {
    pub(super) fn kind(&self) -> VmoKind {
        self.source.kind()
    }

    pub(super) fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub(super) fn frames(&self) -> &[Option<FrameId>] {
        self.source.frames()
    }

    pub(super) fn read_bytes_into(&self, offset: u64, dst: &mut [u8]) -> Result<bool, zx_status_t> {
        self.source.read_bytes_into(offset, dst)
    }
}

pub(super) type PagerReadAtFn = fn(offset: u64, dst: &mut [u8]) -> Result<(), zx_status_t>;

pub(super) trait PagerReadOnlySource: Send + Sync {
    fn size_bytes(&self) -> u64;

    fn read_bytes(&self, offset: u64, dst: &mut [u8]) -> Result<(), zx_status_t>;

    fn materialize_page(&self, page_offset: u64, dst_paddr: u64) -> Result<(), zx_status_t> {
        let mut scratch = alloc::vec![0; crate::userspace::USER_PAGE_BYTES as usize];
        self.read_bytes(page_offset, &mut scratch)?;
        crate::copy::write_bootstrap_frame_bytes(dst_paddr, 0, &scratch)
    }
}

#[derive(Clone)]
pub(super) struct PagerSourceHandle(Arc<dyn PagerReadOnlySource>);

impl core::fmt::Debug for PagerSourceHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PagerSourceHandle(..)")
    }
}

impl PagerSourceHandle {
    pub(super) fn new(source: impl PagerReadOnlySource + 'static) -> Self {
        Self(Arc::new(source))
    }

    pub(super) fn size_bytes(&self) -> u64 {
        self.0.size_bytes()
    }

    pub(super) fn read_bytes(&self, offset: u64, dst: &mut [u8]) -> Result<(), zx_status_t> {
        self.0.read_bytes(offset, dst)
    }

    fn materialize_page(&self, page_offset: u64, dst_paddr: u64) -> Result<(), zx_status_t> {
        self.0.materialize_page(page_offset, dst_paddr)
    }
}

#[derive(Clone, Debug)]
struct StaticPagerSource {
    bytes: &'static [u8],
}

impl PagerReadOnlySource for StaticPagerSource {
    fn size_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_bytes(&self, offset: u64, dst: &mut [u8]) -> Result<(), zx_status_t> {
        let end = offset
            .checked_add(dst.len() as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let start = usize::try_from(offset).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let end = usize::try_from(end).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let src = self.bytes.get(start..end).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        crate::copy::copy_kernel_bytes(dst, src)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct FilePagerSource {
    pub(super) size_bytes: u64,
    pub(super) read_at: PagerReadAtFn,
}

impl PagerReadOnlySource for FilePagerSource {
    fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    fn read_bytes(&self, offset: u64, dst: &mut [u8]) -> Result<(), zx_status_t> {
        let end = offset
            .checked_add(dst.len() as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if end > self.size_bytes {
            return Err(ZX_ERR_OUT_OF_RANGE);
        }
        (self.read_at)(offset, dst)
    }
}

#[derive(Clone, Debug)]
enum VmoBackingSource {
    Anonymous {
        frames: Vec<Option<FrameId>>,
    },
    Physical {
        frames: Vec<Option<FrameId>>,
    },
    Contiguous {
        frames: Vec<Option<FrameId>>,
    },
    PagerReadOnly {
        frames: Vec<Option<FrameId>>,
        source: PagerSourceHandle,
    },
}

impl VmoBackingSource {
    fn kind(&self) -> VmoKind {
        match self {
            Self::Anonymous { .. } => VmoKind::Anonymous,
            Self::Physical { .. } => VmoKind::Physical,
            Self::Contiguous { .. } => VmoKind::Contiguous,
            Self::PagerReadOnly { .. } => VmoKind::PagerBacked,
        }
    }

    fn from_kind(kind: VmoKind, page_count: usize) -> Result<Self, zx_status_t> {
        Ok(match kind {
            VmoKind::Anonymous => Self::Anonymous {
                frames: alloc::vec![None; page_count],
            },
            VmoKind::Physical => Self::Physical {
                frames: alloc::vec![None; page_count],
            },
            VmoKind::Contiguous => Self::Contiguous {
                frames: alloc::vec![None; page_count],
            },
            VmoKind::PagerBacked => return Err(ZX_ERR_INVALID_ARGS),
        })
    }

    fn frames(&self) -> &[Option<FrameId>] {
        match self {
            Self::Anonymous { frames }
            | Self::Physical { frames }
            | Self::Contiguous { frames }
            | Self::PagerReadOnly { frames, .. } => frames,
        }
    }

    fn read_bytes_into(&self, offset: u64, dst: &mut [u8]) -> Result<bool, zx_status_t> {
        match self {
            Self::PagerReadOnly { source, .. } => {
                source.read_bytes(offset, dst)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn frames_mut(&mut self) -> Option<&mut Vec<Option<FrameId>>> {
        match self {
            Self::Anonymous { frames }
            | Self::Physical { frames }
            | Self::Contiguous { frames }
            | Self::PagerReadOnly { frames, .. } => Some(frames),
        }
    }

    fn materialize_page_into(&self, page_offset: u64, dst_paddr: u64) -> Result<bool, zx_status_t> {
        match self {
            Self::PagerReadOnly { source, .. } => {
                source.materialize_page(page_offset, dst_paddr)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct GlobalVmoStore {
    entries: BTreeMap<KernelVmoId, GlobalVmo>,
}

impl GlobalVmoStore {
    fn page_count_for_size(size_bytes: u64) -> Result<usize, zx_status_t> {
        if size_bytes == 0 || (size_bytes & (crate::userspace::USER_PAGE_BYTES - 1)) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        usize::try_from(size_bytes / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)
    }

    pub(super) fn register_snapshot(
        &mut self,
        global_vmo_id: KernelVmoId,
        snapshot: &Vmo,
    ) -> Result<(), zx_status_t> {
        let mut source = VmoBackingSource::from_kind(snapshot.kind(), snapshot.frames().len())?;
        if let Some(frames) = source.frames_mut() {
            *frames = snapshot.frames().to_vec();
        }
        self.entries.insert(
            global_vmo_id,
            GlobalVmo {
                size_bytes: snapshot.size_bytes(),
                source,
            },
        );
        Ok(())
    }

    pub(super) fn register_empty(
        &mut self,
        global_vmo_id: KernelVmoId,
        kind: VmoKind,
        size_bytes: u64,
    ) -> Result<(), zx_status_t> {
        if self.entries.contains_key(&global_vmo_id) {
            return Err(ZX_ERR_ALREADY_EXISTS);
        }
        let page_count = Self::page_count_for_size(size_bytes)?;
        self.entries.insert(
            global_vmo_id,
            GlobalVmo {
                size_bytes,
                source: VmoBackingSource::from_kind(kind, page_count)?,
            },
        );
        Ok(())
    }

    pub(super) fn register_pager_source(
        &mut self,
        global_vmo_id: KernelVmoId,
        source: PagerSourceHandle,
    ) -> Result<(), zx_status_t> {
        if self.entries.contains_key(&global_vmo_id) {
            return Err(ZX_ERR_ALREADY_EXISTS);
        }
        let size_bytes = source.size_bytes();
        let page_count = Self::page_count_for_size(size_bytes)?;
        self.entries.insert(
            global_vmo_id,
            GlobalVmo {
                size_bytes,
                source: VmoBackingSource::PagerReadOnly {
                    frames: alloc::vec![None; page_count],
                    source,
                },
            },
        );
        Ok(())
    }

    pub(super) fn register_pager_read_only(
        &mut self,
        global_vmo_id: KernelVmoId,
        bytes: &'static [u8],
    ) -> Result<(), zx_status_t> {
        self.register_pager_source(
            global_vmo_id,
            PagerSourceHandle::new(StaticPagerSource { bytes }),
        )
    }

    pub(super) fn register_pager_file_source(
        &mut self,
        global_vmo_id: KernelVmoId,
        size_bytes: u64,
        read_at: PagerReadAtFn,
    ) -> Result<(), zx_status_t> {
        self.register_pager_source(
            global_vmo_id,
            PagerSourceHandle::new(FilePagerSource {
                size_bytes,
                read_at,
            }),
        )
    }

    pub(super) fn remove(&mut self, global_vmo_id: KernelVmoId) -> Option<GlobalVmo> {
        self.entries.remove(&global_vmo_id)
    }

    pub(super) fn snapshot(&self, global_vmo_id: KernelVmoId) -> Result<GlobalVmo, zx_status_t> {
        self.entries
            .get(&global_vmo_id)
            .cloned()
            .ok_or(ZX_ERR_BAD_HANDLE)
    }

    pub(super) fn resize(
        &mut self,
        global_vmo_id: KernelVmoId,
        new_size_bytes: u64,
    ) -> Result<Vec<FrameId>, zx_status_t> {
        let new_page_count = Self::page_count_for_size(new_size_bytes)?;
        let global_vmo = self
            .entries
            .get_mut(&global_vmo_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        let mut dropped = Vec::new();
        let frames = global_vmo.source.frames_mut().ok_or(ZX_ERR_NOT_SUPPORTED)?;
        if new_page_count < frames.len() {
            dropped.extend(frames[new_page_count..].iter().flatten().copied());
        }
        global_vmo.size_bytes = new_size_bytes;
        frames.truncate(new_page_count);
        if new_page_count > frames.len() {
            frames.resize(new_page_count, None);
        }
        Ok(dropped)
    }

    pub(super) fn frame(
        &self,
        global_vmo_id: KernelVmoId,
        offset: u64,
    ) -> Result<Option<FrameId>, zx_status_t> {
        let global_vmo = self.entries.get(&global_vmo_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        if offset & (crate::userspace::USER_PAGE_BYTES - 1) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let page_index = usize::try_from(offset / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        Ok(global_vmo
            .source
            .frames()
            .get(page_index)
            .copied()
            .flatten())
    }

    pub(super) fn update_frame(
        &mut self,
        global_vmo_id: KernelVmoId,
        offset: u64,
        frame_id: FrameId,
    ) -> Result<(), zx_status_t> {
        let global_vmo = self
            .entries
            .get_mut(&global_vmo_id)
            .ok_or(ZX_ERR_BAD_HANDLE)?;
        if offset & (crate::userspace::USER_PAGE_BYTES - 1) != 0 {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let page_index = usize::try_from(offset / crate::userspace::USER_PAGE_BYTES)
            .map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
        let frames = global_vmo.source.frames_mut().ok_or(ZX_ERR_NOT_SUPPORTED)?;
        let slot = frames.get_mut(page_index).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        *slot = Some(frame_id);
        Ok(())
    }

    pub(super) fn materialize_page_into(
        &self,
        global_vmo_id: KernelVmoId,
        page_offset: u64,
        dst_paddr: u64,
    ) -> Result<bool, zx_status_t> {
        let global_vmo = self.entries.get(&global_vmo_id).ok_or(ZX_ERR_BAD_HANDLE)?;
        global_vmo
            .source
            .materialize_page_into(page_offset, dst_paddr)
    }
}
