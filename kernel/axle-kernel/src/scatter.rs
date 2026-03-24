//! Unified scatter/gather descriptor for kernel data movement.
//!
//! `ScatterList` provides a common representation for payloads that may
//! combine inline-copied bytes, loaned user pages, and channel fragment
//! pages.  Channel and socket paths can convert their legacy payload
//! types into this shared shape.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

/// One contiguous segment within a scatter list.
#[derive(Clone, Debug)]
pub(crate) enum ScatterSegment {
    /// Inline byte buffer (small messages, already copied into kernel memory).
    Inline(Vec<u8>),
    /// Loaned full user pages (zero-copy for page-aligned bodies).
    LoanedPages {
        /// Physical addresses of the loaned pages.
        paddrs: Vec<u64>,
        /// Total byte length covered by the loaned pages.
        len: usize,
    },
    /// Sub-page fragment (head or tail around a loaned body).
    Fragment {
        /// Physical address of the fragment page.
        paddr: u64,
        /// Byte offset within the page where valid data starts.
        offset: usize,
        /// Number of valid bytes.
        len: usize,
    },
}

/// A scatter/gather list of data segments representing one logical payload.
#[derive(Clone, Debug)]
pub(crate) struct ScatterList {
    segments: Vec<ScatterSegment>,
    total_bytes: usize,
}

impl ScatterList {
    /// Create an empty scatter list.
    pub(crate) fn empty() -> Self {
        Self {
            segments: Vec::new(),
            total_bytes: 0,
        }
    }

    /// Create a scatter list from a single inline buffer.
    pub(crate) fn from_inline(data: Vec<u8>) -> Self {
        let len = data.len();
        Self {
            segments: vec![ScatterSegment::Inline(data)],
            total_bytes: len,
        }
    }

    /// Total payload bytes across all segments.
    pub(crate) fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Number of segments.
    pub(crate) fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Iterate over segments.
    pub(crate) fn segments(&self) -> &[ScatterSegment] {
        &self.segments
    }

    /// Append one segment.
    pub(crate) fn push(&mut self, segment: ScatterSegment) {
        match &segment {
            ScatterSegment::Inline(data) => self.total_bytes += data.len(),
            ScatterSegment::LoanedPages { len, .. } => self.total_bytes += len,
            ScatterSegment::Fragment { len, .. } => self.total_bytes += len,
        }
        self.segments.push(segment);
    }

    /// Flatten all segments into a single contiguous byte vector.
    /// This copies loaned/fragment data and is intended for compatibility
    /// or small-message paths where zero-copy is not beneficial.
    pub(crate) fn flatten(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.total_bytes);
        for segment in &self.segments {
            match segment {
                ScatterSegment::Inline(data) => out.extend_from_slice(data),
                ScatterSegment::LoanedPages { paddrs, len } => {
                    // Read from identity-mapped physical addresses.
                    let mut remaining = *len;
                    for &paddr in paddrs {
                        let chunk = remaining.min(4096);
                        let src = paddr as *const u8;
                        // SAFETY: loaned pages are identity-mapped and pinned.
                        let bytes = unsafe { core::slice::from_raw_parts(src, chunk) };
                        out.extend_from_slice(bytes);
                        remaining -= chunk;
                    }
                }
                ScatterSegment::Fragment { paddr, offset, len } => {
                    let src = (*paddr as usize + *offset) as *const u8;
                    // SAFETY: fragment pages are identity-mapped and owned.
                    let bytes = unsafe { core::slice::from_raw_parts(src, *len) };
                    out.extend_from_slice(bytes);
                }
            }
        }
        out
    }
}
