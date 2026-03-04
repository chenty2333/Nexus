use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use bytemuck::{Pod, Zeroable, pod_read_unaligned};
use goblin::elf::Elf;
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};

const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct ElfNoteHeader {
    namesz: u32,
    descsz: u32,
    n_type: u32,
}

/// ELF inspection output written into case reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfCheckReport {
    pub path: String,
    pub object_arch: String,
    pub object_entry: u64,
    pub goblin_entry: u64,
    pub xen_pvh_entry: Option<u32>,
}

pub fn inspect_elf(path: &Path) -> Result<ElfCheckReport> {
    let bytes = fs::read(path).with_context(|| format!("read elf {}", path.display()))?;

    let obj = object::File::parse(&*bytes)
        .with_context(|| format!("object::File parse {}", path.display()))?;
    let goblin = Elf::parse(&bytes).with_context(|| format!("goblin parse {}", path.display()))?;

    let mut xen_pvh_entry = None;
    for section in obj.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        if name != ".note.Xen" {
            continue;
        }
        let data = section
            .data()
            .with_context(|| format!("read .note.Xen data {}", path.display()))?;
        xen_pvh_entry = parse_xen_entry_note(data);
        break;
    }

    Ok(ElfCheckReport {
        path: path.display().to_string(),
        object_arch: format!("{:?}", obj.architecture()),
        object_entry: obj.entry(),
        goblin_entry: goblin.entry,
        xen_pvh_entry,
    })
}

fn parse_xen_entry_note(section_data: &[u8]) -> Option<u32> {
    let mut off = 0usize;

    while off + core::mem::size_of::<ElfNoteHeader>() <= section_data.len() {
        let hdr_size = core::mem::size_of::<ElfNoteHeader>();
        let header_bytes = &section_data[off..off + hdr_size];
        let header: ElfNoteHeader = pod_read_unaligned(header_bytes);
        off += hdr_size;

        let namesz = usize::try_from(header.namesz).ok()?;
        let descsz = usize::try_from(header.descsz).ok()?;

        if off + namesz > section_data.len() {
            return None;
        }
        let name = &section_data[off..off + namesz];
        off += align4(namesz);

        if off + descsz > section_data.len() {
            return None;
        }
        let desc = &section_data[off..off + descsz];
        off += align4(descsz);

        let is_xen = name.starts_with(b"Xen\0") || name == b"Xen";
        if is_xen && header.n_type == XEN_ELFNOTE_PHYS32_ENTRY && desc.len() >= 4 {
            let entry = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]);
            return Some(entry);
        }
    }

    None
}

#[inline]
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_xen_note() {
        let mut data = Vec::new();
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&XEN_ELFNOTE_PHYS32_ENTRY.to_le_bytes());
        data.extend_from_slice(b"Xen\0");
        data.extend_from_slice(&0x1234_5678u32.to_le_bytes());

        let entry = parse_xen_entry_note(&data);
        assert_eq!(entry, Some(0x1234_5678));
    }
}
