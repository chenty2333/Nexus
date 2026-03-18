use core::mem::size_of;

pub(crate) const PAGE_SIZE: u64 = 4096;
pub(crate) const QUEUE_VMO_BYTES: u64 = 4 * PAGE_SIZE;
pub(crate) const QUEUE_SIZE: usize = 1;
pub(crate) const QUEUE_DESC_OFFSET: u64 = 0;
pub(crate) const QUEUE_AVAIL_OFFSET: u64 = 64;
pub(crate) const QUEUE_USED_OFFSET: u64 = 128;
pub(crate) const TX_QUEUE_OFFSET: u64 = 0;
pub(crate) const TX_BUFFER_OFFSET: u64 = PAGE_SIZE;
pub(crate) const RX_QUEUE_OFFSET: u64 = 2 * PAGE_SIZE;
pub(crate) const RX_BUFFER_OFFSET: u64 = 3 * PAGE_SIZE;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VirtqDesc {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) flags: u16,
    pub(crate) next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VirtqAvail {
    pub(crate) flags: u16,
    pub(crate) idx: u16,
    pub(crate) ring: [u16; QUEUE_SIZE],
    pub(crate) used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VirtqUsedElem {
    pub(crate) id: u32,
    pub(crate) len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VirtqUsed {
    pub(crate) flags: u16,
    pub(crate) idx: u16,
    pub(crate) ring: [VirtqUsedElem; QUEUE_SIZE],
    pub(crate) avail_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VirtioNetHdr {
    pub(crate) flags: u8,
    pub(crate) gso_type: u8,
    pub(crate) hdr_len: u16,
    pub(crate) gso_size: u16,
    pub(crate) csum_start: u16,
    pub(crate) csum_offset: u16,
}

pub(crate) const fn frame_len(payload_len: usize) -> usize {
    size_of::<VirtioNetHdr>() + payload_len
}

pub(crate) const fn empty_avail() -> VirtqAvail {
    VirtqAvail {
        flags: 0,
        idx: 0,
        ring: [0],
        used_event: 0,
    }
}

pub(crate) const fn empty_used() -> VirtqUsed {
    VirtqUsed {
        flags: 0,
        idx: 0,
        ring: [VirtqUsedElem { id: 0, len: 0 }],
        avail_event: 0,
    }
}
