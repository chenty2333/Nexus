use super::*;

/// Kernel-visible description of one current-process VMO.
#[derive(Clone, Debug)]
pub(crate) struct CreatedVmo {
    pub(super) process_id: ProcessId,
    pub(super) address_space_id: AddressSpaceId,
    pub(super) vmo: Vmo,
}

impl CreatedVmo {
    pub(crate) fn process_id(&self) -> ProcessId {
        self.process_id
    }

    pub(crate) fn address_space_id(&self) -> AddressSpaceId {
        self.address_space_id
    }

    pub(crate) fn vmo_id(&self) -> VmoId {
        self.vmo.id()
    }

    pub(crate) fn global_vmo_id(&self) -> KernelVmoId {
        self.vmo.global_id()
    }

    pub(crate) fn size_bytes(&self) -> u64 {
        self.vmo.size_bytes()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProcessImageSegment {
    vaddr: u64,
    vmo_offset: u64,
    file_size_bytes: u64,
    mem_size_bytes: u64,
    perms: MappingPerms,
}

impl ProcessImageSegment {
    pub(crate) const fn new(
        vaddr: u64,
        vmo_offset: u64,
        file_size_bytes: u64,
        mem_size_bytes: u64,
        perms: MappingPerms,
    ) -> Self {
        Self {
            vaddr,
            vmo_offset,
            file_size_bytes,
            mem_size_bytes,
            perms,
        }
    }

    pub(crate) const fn vaddr(self) -> u64 {
        self.vaddr
    }

    pub(crate) const fn vmo_offset(self) -> u64 {
        self.vmo_offset
    }

    pub(crate) const fn file_size_bytes(self) -> u64 {
        self.file_size_bytes
    }

    pub(crate) const fn mem_size_bytes(self) -> u64 {
        self.mem_size_bytes
    }

    pub(crate) const fn perms(self) -> MappingPerms {
        self.perms
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProcessImageElfInfo {
    phdr_vaddr: u64,
    phent: u16,
    phnum: u16,
}

impl ProcessImageElfInfo {
    pub(crate) const fn new(phdr_vaddr: u64, phent: u16, phnum: u16) -> Self {
        Self {
            phdr_vaddr,
            phent,
            phnum,
        }
    }

    pub(crate) const fn phdr_vaddr(self) -> u64 {
        self.phdr_vaddr
    }

    pub(crate) const fn phent(self) -> u16 {
        self.phent
    }

    pub(crate) const fn phnum(self) -> u16 {
        self.phnum
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessImageLayout {
    code_base: u64,
    code_size_bytes: u64,
    entry: u64,
    elf: Option<ProcessImageElfInfo>,
    segments: heapless::Vec<ProcessImageSegment, 16>,
}

impl ProcessImageLayout {
    pub(crate) fn bootstrap_conformance() -> Self {
        Self {
            code_base: crate::userspace::USER_CODE_VA,
            code_size_bytes: crate::userspace::USER_CODE_BYTES,
            entry: crate::userspace::USER_CODE_VA,
            elf: None,
            segments: heapless::Vec::new(),
        }
    }

    pub(crate) fn with_segments(
        code_base: u64,
        code_size_bytes: u64,
        entry: u64,
        segments: &[ProcessImageSegment],
    ) -> Result<Self, zx_status_t> {
        Self::with_segments_and_elf(code_base, code_size_bytes, entry, segments, None)
    }

    pub(crate) fn with_segments_and_elf(
        code_base: u64,
        code_size_bytes: u64,
        entry: u64,
        segments: &[ProcessImageSegment],
        elf: Option<ProcessImageElfInfo>,
    ) -> Result<Self, zx_status_t> {
        let mut stored = heapless::Vec::new();
        for segment in segments {
            stored.push(*segment).map_err(|_| ZX_ERR_NO_RESOURCES)?;
        }
        Ok(Self {
            code_base,
            code_size_bytes,
            entry,
            elf,
            segments: stored,
        })
    }

    pub(crate) fn code_base(&self) -> u64 {
        self.code_base
    }

    pub(crate) fn code_size_bytes(&self) -> u64 {
        self.code_size_bytes
    }

    pub(crate) fn entry(&self) -> u64 {
        self.entry
    }

    pub(crate) fn segments(&self) -> &[ProcessImageSegment] {
        self.segments.as_slice()
    }

    pub(crate) const fn elf(&self) -> Option<ProcessImageElfInfo> {
        self.elf
    }

    pub(crate) fn rebased_for_loaded_image(&self) -> Result<Self, zx_status_t> {
        let mut stored = heapless::Vec::new();
        for segment in &self.segments {
            let rebased_offset = segment
                .vaddr()
                .checked_sub(self.code_base)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            stored
                .push(ProcessImageSegment::new(
                    segment.vaddr(),
                    rebased_offset,
                    segment.file_size_bytes(),
                    segment.mem_size_bytes(),
                    segment.perms(),
                ))
                .map_err(|_| ZX_ERR_NO_RESOURCES)?;
        }
        Ok(Self {
            code_base: self.code_base,
            code_size_bytes: self.code_size_bytes,
            entry: self.entry,
            elf: self.elf,
            segments: stored,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LinuxExecExtraImage<'a> {
    layout: ProcessImageLayout,
    image_bytes: &'a [u8],
}

impl<'a> LinuxExecExtraImage<'a> {
    pub(crate) fn new(layout: ProcessImageLayout, image_bytes: &'a [u8]) -> Self {
        Self {
            layout,
            image_bytes,
        }
    }

    pub(crate) const fn layout(&self) -> &ProcessImageLayout {
        &self.layout
    }

    pub(crate) const fn image_bytes(&self) -> &'a [u8] {
        self.image_bytes
    }
}

pub(crate) const fn process_image_default_code_perms() -> MappingPerms {
    MappingPerms::READ.union(MappingPerms::EXECUTE)
}

const STACK_ARGV0: &[u8] = b"axle-child\0";
pub(super) const PROCESS_START_STACK_BYTES: u64 = crate::userspace::USER_PAGE_BYTES * 16;
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;

pub(super) fn align_up_user_page(value: u64) -> Result<u64, zx_status_t> {
    let align = crate::userspace::USER_PAGE_BYTES;
    value
        .checked_add(align - 1)
        .map(|rounded| rounded & !(align - 1))
        .ok_or(ZX_ERR_OUT_OF_RANGE)
}

pub(super) fn exec_image_backing_size(
    layout: &ProcessImageLayout,
    image_size: u64,
) -> Result<u64, zx_status_t> {
    let mut required = image_size;
    for segment in layout.segments() {
        let map_base = segment.vaddr() & !(crate::userspace::USER_PAGE_BYTES - 1);
        let map_offset = segment.vmo_offset() & !(crate::userspace::USER_PAGE_BYTES - 1);
        let page_delta = segment
            .vaddr()
            .checked_sub(map_base)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let len = align_up_user_page(
            page_delta
                .checked_add(segment.mem_size_bytes())
                .ok_or(ZX_ERR_OUT_OF_RANGE)?,
        )?;
        required = required.max(map_offset.checked_add(len).ok_or(ZX_ERR_OUT_OF_RANGE)?);
    }
    align_up_user_page(required)
}

pub(super) fn build_process_start_stack_image(
    stack_base: u64,
    stack_len: u64,
    layout: &ProcessImageLayout,
) -> Result<PreparedStackImage, zx_status_t> {
    let stack_len_usize = usize::try_from(stack_len).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let mut auxv = Vec::new();
    auxv.try_reserve_exact(6).map_err(|_| ZX_ERR_NO_MEMORY)?;
    auxv.push((AT_PAGESZ, crate::userspace::USER_PAGE_BYTES));
    auxv.push((AT_ENTRY, layout.entry()));
    if let Some(elf) = layout.elf() {
        auxv.push((AT_PHDR, elf.phdr_vaddr()));
        auxv.push((AT_PHENT, u64::from(elf.phent())));
        auxv.push((AT_PHNUM, u64::from(elf.phnum())));
    }
    auxv.push((AT_NULL, 0));

    let mut words = Vec::new();
    let word_count = 4usize
        .checked_add(auxv.len().checked_mul(2).ok_or(ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    words
        .try_reserve_exact(word_count)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;

    let mut cursor = stack_len_usize;
    cursor = cursor
        .checked_sub(STACK_ARGV0.len())
        .ok_or(ZX_ERR_NO_MEMORY)?;
    let argv0_offset = cursor;
    let argv0_ptr = stack_base
        .checked_add(u64::try_from(argv0_offset).map_err(|_| ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;

    words.push(1);
    words.push(argv0_ptr);
    words.push(0);
    words.push(0);
    for (key, value) in auxv {
        words.push(key);
        words.push(value);
    }

    let words_bytes = words
        .len()
        .checked_mul(size_of::<u64>())
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    cursor = cursor.checked_sub(words_bytes).ok_or(ZX_ERR_NO_MEMORY)?;
    cursor &= !0xFusize;

    let total_bytes = stack_len_usize
        .checked_sub(cursor)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let mut image = Vec::new();
    image
        .try_reserve_exact(total_bytes)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    image.resize(total_bytes, 0);

    for (index, word) in words.iter().enumerate() {
        let start = index * size_of::<u64>();
        image[start..start + size_of::<u64>()].copy_from_slice(&word.to_ne_bytes());
    }
    let string_offset = argv0_offset
        .checked_sub(cursor)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    image[string_offset..string_offset + STACK_ARGV0.len()].copy_from_slice(STACK_ARGV0);

    let stack_pointer = stack_base
        .checked_add(u64::try_from(cursor).map_err(|_| ZX_ERR_OUT_OF_RANGE)?)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let stack_vmo_offset = u64::try_from(cursor).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    Ok(PreparedStackImage {
        stack_pointer,
        stack_vmo_offset,
        image,
    })
}

#[derive(Clone, Debug)]
pub(super) struct PreparedStackImage {
    pub(super) stack_pointer: u64,
    pub(super) stack_vmo_offset: u64,
    pub(super) image: Vec<u8>,
}

pub(super) fn validate_linux_exec_stack_spec(
    header: ax_linux_exec_spec_header_t,
    stack_image: &[u8],
) -> Result<(), zx_status_t> {
    if header.stack_bytes_len != stack_image.len() as u64 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if header.stack_pointer == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let stack_end = header
        .stack_vmo_offset
        .checked_add(header.stack_bytes_len)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if stack_end > PROCESS_START_STACK_BYTES {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }
    let stack_base = crate::userspace::USER_STACK_VA;
    let stack_limit = stack_base
        .checked_add(PROCESS_START_STACK_BYTES)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if header.stack_pointer < stack_base || header.stack_pointer > stack_limit {
        return Err(ZX_ERR_OUT_OF_RANGE);
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct ImportedProcessImage {
    pub(super) code_vmo: CreatedVmo,
    pub(super) layout: ProcessImageLayout,
}

impl ImportedProcessImage {
    pub(crate) fn layout(&self) -> ProcessImageLayout {
        self.layout.clone()
    }

    pub(crate) const fn code_vmo(&self) -> &CreatedVmo {
        &self.code_vmo
    }
}

#[derive(Clone, Debug)]
pub(crate) struct KernelVmoBacking {
    pub(super) global_vmo_id: KernelVmoId,
    pub(super) base_paddr: u64,
    pub(super) page_count: usize,
    pub(super) frame_ids: Vec<FrameId>,
    pub(super) size_bytes: u64,
}

impl KernelVmoBacking {
    pub(crate) fn global_vmo_id(&self) -> KernelVmoId {
        self.global_vmo_id
    }

    pub(crate) fn frame_ids(&self) -> &[FrameId] {
        &self.frame_ids
    }

    pub(crate) fn base_paddr(&self) -> u64 {
        self.base_paddr
    }

    pub(crate) fn page_count(&self) -> usize {
        self.page_count
    }

    pub(crate) fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}
