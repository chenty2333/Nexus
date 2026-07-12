// SPDX-License-Identifier: MPL-2.0

//! Shared bounded ELF/stack/TLS loader for the successor Linux personality.
//!
//! The Stage 6A and 6B.1 receipts remain frozen in their original modules.
//! New retained-workload slices use this loader so static Round 4/Round 5 and
//! dynamic PIE share one W^X, overlap, auxv, and address-bias boundary.  A
//! dynamic image is built in a fresh staging `VmSpace`; making that space the
//! process image is a separate registry-protected `ExecCommit` operation.

use alloc::{string::String, sync::Arc, vec, vec::Vec};
use core::str;

use linux_raw_sys::auxvec::{
    AT_BASE, AT_ENTRY, AT_EXECFN, AT_HWCAP, AT_HWCAP2, AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT,
    AT_PHNUM, AT_PLATFORM, AT_RANDOM,
};
use object::{Architecture, BinaryFormat, Endianness, Object};
use object::{
    elf,
    read::elf::{ElfFile64, FileHeader, ProgramHeader},
};
use ostd::{
    mm::{
        CachePolicy, FrameAllocOptions, MAX_USERSPACE_VADDR, PAGE_SIZE, PageFlags, PageProperty,
        Vaddr, VmIo, VmSpace,
    },
    task::disable_preempt,
};

pub(crate) const LINUX_STACK_TOP: Vaddr = 0x0000_7fff_ffff_f000;
pub(crate) const DYNAMIC_MAIN_BIAS: Vaddr = 0x0000_0001_0000_0000;
pub(crate) const DYNAMIC_INTERP_BIAS: Vaddr = 0x0000_0002_0000_0000;
const INITIAL_TLS_BASE: Vaddr = 0x0000_7000_0000_0000;
const PLATFORM: &[u8] = b"x86_64\0";
const RANDOM: [u8; 16] = *b"NexusExecCser01!";

/// One mapped PT_LOAD receipt in a staging or current image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LoadSegmentReceipt {
    pub(crate) image: ImageRole,
    pub(crate) ordinal: usize,
    pub(crate) start: Vaddr,
    pub(crate) end: Vaddr,
    pub(crate) flags: PageFlags,
}

/// Identity of the ELF that owns one staged segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImageRole {
    Static,
    Main,
    Interpreter,
}

/// Loaded static image used by the full futex and readiness workloads.
pub(crate) struct LoadedStaticImage {
    pub(crate) vm_space: Arc<VmSpace>,
    pub(crate) entry: Vaddr,
    pub(crate) stack_pointer: Vaddr,
    pub(crate) phdr: Vaddr,
    pub(crate) phent: usize,
    pub(crate) phnum: usize,
    pub(crate) segments: Vec<LoadSegmentReceipt>,
}

/// Initial-TLS receipt for the bounded dynamic PIE image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InitialTlsReceipt {
    pub(crate) map_start: Vaddr,
    pub(crate) map_end: Vaddr,
    pub(crate) fs_base: Vaddr,
    pub(crate) module_offsets: Vec<usize>,
}

/// Fully prepared but not yet process-visible dynamic image.
pub(crate) struct StagedDynamicImage {
    pub(crate) vm_space: Arc<VmSpace>,
    pub(crate) main_entry: Vaddr,
    pub(crate) interpreter_entry: Vaddr,
    pub(crate) stack_pointer: Vaddr,
    pub(crate) fs_base: Vaddr,
    pub(crate) main_phdr: Vaddr,
    pub(crate) main_phent: usize,
    pub(crate) main_phnum: usize,
    pub(crate) interpreter_path: String,
    pub(crate) segments: Vec<LoadSegmentReceipt>,
    pub(crate) tls: InitialTlsReceipt,
}

#[derive(Clone)]
struct TlsTemplate {
    init: Vec<u8>,
    mem_size: usize,
    align: usize,
}

struct SegmentPlan {
    start: Vaddr,
    end: Vaddr,
    contents: Vec<u8>,
    flags: PageFlags,
}

struct ParsedElf {
    entry: Vaddr,
    phdr: Vaddr,
    phent: usize,
    phnum: usize,
    interpreter: Option<String>,
    tls: Option<TlsTemplate>,
    segments: Vec<SegmentPlan>,
}

/// Loads one static x86-64 ET_EXEC into a fresh address space.
pub(crate) fn load_static_image(image: &[u8], executable_name: &[u8]) -> LoadedStaticImage {
    load_static_image_with_stack_pages(image, executable_name, 1)
}

/// Loads one static image with an explicitly bounded initial stack mapping.
///
/// Existing retained slices use the one-page wrapper above. The unchanged
/// runtime-filesystem input reserves 4096 bytes below its entry stack pointer,
/// so that successor requests exactly two pages rather than changing the guest.
pub(crate) fn load_static_image_with_stack_pages(
    image: &[u8],
    executable_name: &[u8],
    stack_pages: usize,
) -> LoadedStaticImage {
    assert_eq!(executable_name.last(), Some(&0));
    assert!((1..=2).contains(&stack_pages));
    let parsed = parse_elf(image, elf::ET_EXEC, 0);
    assert!(
        parsed.interpreter.is_none(),
        "static slice rejects PT_INTERP"
    );
    assert!(parsed.tls.is_none(), "static slice does not install PT_TLS");

    let vm_space = VmSpace::new();
    let segments = map_segments(&vm_space, ImageRole::Static, &parsed.segments);
    let stack_pointer = map_initial_stack(
        &vm_space,
        StackMetadata {
            executable_name,
            entry: parsed.entry,
            phdr: parsed.phdr,
            phent: parsed.phent,
            phnum: parsed.phnum,
            at_base: None,
        },
        stack_pages,
    );
    LoadedStaticImage {
        vm_space: Arc::new(vm_space),
        entry: parsed.entry,
        stack_pointer,
        phdr: parsed.phdr,
        phent: parsed.phent,
        phnum: parsed.phnum,
        segments,
    }
}

/// Prepares a fixed-bias ET_DYN main plus ET_DYN interpreter in a fresh
/// staging address space. The caller must perform the separate atomic image
/// install before any user task may execute `interpreter_entry`.
pub(crate) fn stage_dynamic_pie(
    main_image: &[u8],
    interpreter_image: &[u8],
    executable_name: &[u8],
    expected_interpreter: &str,
) -> StagedDynamicImage {
    assert_eq!(executable_name.last(), Some(&0));
    let main = parse_elf(main_image, elf::ET_DYN, DYNAMIC_MAIN_BIAS);
    let interpreter = parse_elf(interpreter_image, elf::ET_DYN, DYNAMIC_INTERP_BIAS);
    assert_eq!(main.interpreter.as_deref(), Some(expected_interpreter));
    assert!(interpreter.interpreter.is_none());

    let mut all_ranges = Vec::new();
    for segment in main.segments.iter().chain(&interpreter.segments) {
        assert!(
            all_ranges
                .iter()
                .all(|(start, end)| segment.end <= *start || segment.start >= *end),
            "main and interpreter PT_LOAD ranges must not overlap"
        );
        all_ranges.push((segment.start, segment.end));
    }
    assert!(
        all_ranges
            .iter()
            .all(|(start, end)| LINUX_STACK_TOP <= *start || LINUX_STACK_TOP - PAGE_SIZE >= *end),
        "ELF PT_LOAD overlaps initial stack"
    );
    assert!(
        all_ranges.iter().all(|(start, end)| {
            INITIAL_TLS_BASE + PAGE_SIZE <= *start || INITIAL_TLS_BASE >= *end
        }),
        "ELF PT_LOAD overlaps initial TLS"
    );

    let vm_space = VmSpace::new();
    let mut segments = map_segments(&vm_space, ImageRole::Main, &main.segments);
    segments.extend(map_segments(
        &vm_space,
        ImageRole::Interpreter,
        &interpreter.segments,
    ));

    // x86-64 static initial TLS uses variant II: interpreter first, main
    // second, followed immediately by the thread pointer/TCB. This ordering is
    // part of the retained workload contract (the interpreter checks -20/-12).
    let tls_templates = [
        interpreter
            .tls
            .clone()
            .expect("retained interpreter must contain PT_TLS"),
        main.tls
            .clone()
            .expect("retained PIE main must contain PT_TLS"),
    ];
    let tls = install_initial_tls(&vm_space, &tls_templates);
    let stack_pointer = map_initial_stack(
        &vm_space,
        StackMetadata {
            executable_name,
            entry: main.entry,
            phdr: main.phdr,
            phent: main.phent,
            phnum: main.phnum,
            at_base: Some(DYNAMIC_INTERP_BIAS),
        },
        1,
    );

    StagedDynamicImage {
        vm_space: Arc::new(vm_space),
        main_entry: main.entry,
        interpreter_entry: interpreter.entry,
        stack_pointer,
        fs_base: tls.fs_base,
        main_phdr: main.phdr,
        main_phent: main.phent,
        main_phnum: main.phnum,
        interpreter_path: main.interpreter.expect("checked PT_INTERP"),
        segments,
        tls,
    }
}

fn parse_elf(image: &[u8], expected_type: u16, bias: Vaddr) -> ParsedElf {
    let raw = ElfFile64::<Endianness>::parse(image).expect("parse ELF64 headers");
    let endian = raw.endian();
    let header = raw.elf_header();
    assert_eq!(header.e_type(endian), expected_type);
    assert_eq!(header.e_machine(endian), elf::EM_X86_64);
    assert_eq!(bias % PAGE_SIZE, 0);

    let file = object::File::parse(image).expect("parse ELF object");
    assert_eq!(file.format(), BinaryFormat::Elf);
    assert_eq!(file.architecture(), Architecture::X86_64);
    assert_eq!(file.endianness(), Endianness::Little);
    assert!(file.is_64());

    let raw_entry =
        usize::try_from(Into::<u64>::into(header.e_entry(endian))).expect("ELF entry fits Vaddr");
    let entry = bias.checked_add(raw_entry).expect("biased entry overflow");
    let phoff = usize::try_from(Into::<u64>::into(header.e_phoff(endian)))
        .expect("program-header offset fits usize");
    let phent = usize::from(header.e_phentsize(endian));
    let phnum = raw.elf_program_headers().len();
    assert_eq!(
        phent,
        core::mem::size_of::<elf::ProgramHeader64<Endianness>>()
    );
    let phdr_file_end = phoff
        .checked_add(phent.checked_mul(phnum).expect("PHDR length overflow"))
        .expect("PHDR file end overflow");
    assert!(phdr_file_end <= image.len());

    let mut interpreter = None;
    let mut tls = None;
    let mut segments = Vec::new();
    let mut phdr = None;
    let mut entry_executable = false;
    let mut ranges = Vec::new();

    for program in raw.elf_program_headers() {
        let program_type = program.p_type(endian);
        let file_offset = usize::try_from(Into::<u64>::into(program.p_offset(endian)))
            .expect("program file offset fits usize");
        let file_size = usize::try_from(Into::<u64>::into(program.p_filesz(endian)))
            .expect("program file size fits usize");
        let memory_size = usize::try_from(Into::<u64>::into(program.p_memsz(endian)))
            .expect("program memory size fits usize");
        let raw_address = usize::try_from(Into::<u64>::into(program.p_vaddr(endian)))
            .expect("program virtual address fits Vaddr");
        let address = bias
            .checked_add(raw_address)
            .expect("program biased address overflow");
        let alignment = usize::try_from(Into::<u64>::into(program.p_align(endian)))
            .expect("program alignment fits usize");

        if program_type == elf::PT_INTERP {
            assert!(interpreter.is_none(), "multiple PT_INTERP headers");
            let end = file_offset
                .checked_add(file_size)
                .expect("PT_INTERP range overflow");
            let raw_path = image
                .get(file_offset..end)
                .expect("PT_INTERP lies within ELF");
            let terminator = raw_path
                .iter()
                .position(|byte| *byte == 0)
                .expect("PT_INTERP must be NUL terminated");
            let path = str::from_utf8(&raw_path[..terminator]).expect("PT_INTERP is UTF-8");
            assert!(!path.is_empty());
            interpreter = Some(String::from(path));
            continue;
        }

        if program_type == elf::PT_TLS {
            assert!(tls.is_none(), "multiple PT_TLS headers");
            assert!(file_size <= memory_size);
            let end = file_offset
                .checked_add(file_size)
                .expect("PT_TLS file range overflow");
            let init = image
                .get(file_offset..end)
                .expect("PT_TLS lies within ELF")
                .to_vec();
            let align = alignment.max(1);
            assert!(align.is_power_of_two());
            tls = Some(TlsTemplate {
                init,
                mem_size: memory_size,
                align,
            });
            continue;
        }

        if program_type == elf::PT_PHDR {
            phdr = Some(address);
            continue;
        }

        if program_type != elf::PT_LOAD || memory_size == 0 {
            continue;
        }
        assert!(file_size <= memory_size);
        assert!(alignment == 0 || alignment.is_power_of_two());
        assert_eq!(raw_address % PAGE_SIZE, file_offset % PAGE_SIZE);
        let file_end = file_offset
            .checked_add(file_size)
            .expect("PT_LOAD file range overflow");
        let data = image
            .get(file_offset..file_end)
            .expect("PT_LOAD lies within ELF");
        let segment_end = address
            .checked_add(memory_size)
            .expect("PT_LOAD memory range overflow");
        let map_start = align_down(address);
        let map_end = align_up(segment_end);
        assert!(map_end <= MAX_USERSPACE_VADDR);
        assert!(
            ranges
                .iter()
                .all(|(start, end)| map_end <= *start || map_start >= *end),
            "PT_LOAD mappings must not overlap"
        );
        ranges.push((map_start, map_end));

        let raw_flags = program.p_flags(endian);
        let readable = raw_flags & elf::PF_R != 0;
        let writable = raw_flags & elf::PF_W != 0;
        let executable = raw_flags & elf::PF_X != 0;
        assert!(readable, "Nexus requires readable PT_LOAD mappings");
        assert!(!(writable && executable), "Nexus enforces W^X");
        let mut flags = PageFlags::R;
        if writable {
            flags |= PageFlags::W;
        }
        if executable {
            flags |= PageFlags::X;
        }

        let mut contents = vec![0; map_end - map_start];
        let data_offset = address - map_start;
        contents[data_offset..data_offset + data.len()].copy_from_slice(data);
        if (address..segment_end).contains(&entry) && executable {
            entry_executable = true;
        }
        if phdr.is_none() && file_offset <= phoff && phdr_file_end <= file_end {
            phdr = Some(
                address
                    .checked_add(phoff - file_offset)
                    .expect("AT_PHDR overflow"),
            );
        }
        segments.push(SegmentPlan {
            start: map_start,
            end: map_end,
            contents,
            flags,
        });
    }

    assert!(!segments.is_empty());
    assert!(entry_executable, "ELF entry must lie in executable PT_LOAD");
    ParsedElf {
        entry,
        phdr: phdr.expect("program headers must be mapped"),
        phent,
        phnum,
        interpreter,
        tls,
        segments,
    }
}

fn map_segments(
    vm_space: &VmSpace,
    image: ImageRole,
    plans: &[SegmentPlan],
) -> Vec<LoadSegmentReceipt> {
    let mut receipts = Vec::with_capacity(plans.len());
    for (ordinal, segment) in plans.iter().enumerate() {
        map_bytes(vm_space, segment.start, &segment.contents, segment.flags);
        receipts.push(LoadSegmentReceipt {
            image,
            ordinal,
            start: segment.start,
            end: segment.end,
            flags: segment.flags,
        });
    }
    receipts
}

struct StackMetadata<'a> {
    executable_name: &'a [u8],
    entry: Vaddr,
    phdr: Vaddr,
    phent: usize,
    phnum: usize,
    at_base: Option<Vaddr>,
}

fn map_initial_stack(vm_space: &VmSpace, metadata: StackMetadata<'_>, stack_pages: usize) -> Vaddr {
    assert!(stack_pages > 0);
    let stack_bytes = stack_pages
        .checked_mul(PAGE_SIZE)
        .expect("initial stack size overflow");
    let stack_base = LINUX_STACK_TOP - stack_bytes;
    let stack_pointer = LINUX_STACK_TOP - 512;
    let execfn_address = LINUX_STACK_TOP - 64;
    let platform_address = LINUX_STACK_TOP - 96;
    let random_address = LINUX_STACK_TOP - 128;
    assert_eq!(stack_pointer % 16, 0);

    let mut contents = vec![0; stack_bytes];
    write_at(
        &mut contents,
        execfn_address - stack_base,
        metadata.executable_name,
    );
    write_at(&mut contents, platform_address - stack_base, PLATFORM);
    write_at(&mut contents, random_address - stack_base, &RANDOM);

    let mut words = vec![1, execfn_address, 0, 0];
    words.extend_from_slice(&[
        AT_PHDR as usize,
        metadata.phdr,
        AT_PHENT as usize,
        metadata.phent,
        AT_PHNUM as usize,
        metadata.phnum,
        AT_PAGESZ as usize,
        PAGE_SIZE,
        AT_ENTRY as usize,
        metadata.entry,
    ]);
    if let Some(at_base) = metadata.at_base {
        words.extend_from_slice(&[AT_BASE as usize, at_base]);
    }
    words.extend_from_slice(&[
        AT_PLATFORM as usize,
        platform_address,
        AT_HWCAP as usize,
        0,
        AT_HWCAP2 as usize,
        0,
        AT_RANDOM as usize,
        random_address,
        AT_EXECFN as usize,
        execfn_address,
        AT_NULL as usize,
        0,
    ]);
    for (index, word) in words.into_iter().enumerate() {
        write_at(
            &mut contents,
            stack_pointer - stack_base + index * core::mem::size_of::<usize>(),
            &word.to_le_bytes(),
        );
    }
    map_bytes(vm_space, stack_base, &contents, PageFlags::RW);
    stack_pointer
}

fn install_initial_tls(vm_space: &VmSpace, templates: &[TlsTemplate]) -> InitialTlsReceipt {
    assert!(!templates.is_empty());
    let mut module_offsets = Vec::with_capacity(templates.len());
    let mut tls_span = 0usize;
    for template in templates {
        tls_span = align_up_to(tls_span, template.align);
        module_offsets.push(tls_span);
        tls_span = tls_span
            .checked_add(align_up_to(template.mem_size, template.align))
            .expect("initial TLS span overflow");
    }

    let tcb_offset = tls_span;
    let dtv_storage_offset = align_up_to(tcb_offset.checked_add(64).expect("TCB overflow"), 16);
    let dtv_words = 4usize
        .checked_add(templates.len().checked_mul(2).expect("DTV slots overflow"))
        .expect("DTV words overflow");
    let used = dtv_storage_offset
        .checked_add(dtv_words.checked_mul(8).expect("DTV bytes overflow"))
        .expect("initial TLS allocation overflow");
    let map_len = align_up(used);
    assert!(
        map_len <= PAGE_SIZE,
        "bounded initial TLS must fit one page"
    );
    let mut contents = vec![0; map_len];
    for (template, offset) in templates.iter().zip(&module_offsets) {
        write_at(&mut contents, *offset, &template.init);
    }

    let fs_base = INITIAL_TLS_BASE
        .checked_add(tcb_offset)
        .expect("FS base overflow");
    let dtv_storage_base = INITIAL_TLS_BASE + dtv_storage_offset;
    let dtv_pointer = dtv_storage_base + 16;
    write_word(&mut contents, dtv_storage_offset, templates.len().max(1));
    write_word(&mut contents, dtv_storage_offset + 8, 0);
    write_word(&mut contents, dtv_storage_offset + 16, 1);
    write_word(&mut contents, dtv_storage_offset + 24, 0);
    for (index, offset) in module_offsets.iter().enumerate() {
        write_word(
            &mut contents,
            dtv_storage_offset + 32 + index * 16,
            INITIAL_TLS_BASE + *offset,
        );
        write_word(&mut contents, dtv_storage_offset + 40 + index * 16, 0);
    }
    write_word(&mut contents, tcb_offset, fs_base);
    write_word(&mut contents, tcb_offset + 8, dtv_pointer);
    write_word(&mut contents, tcb_offset + 16, fs_base);
    map_bytes(vm_space, INITIAL_TLS_BASE, &contents, PageFlags::RW);

    InitialTlsReceipt {
        map_start: INITIAL_TLS_BASE,
        map_end: INITIAL_TLS_BASE + map_len,
        fs_base,
        module_offsets,
    }
}

fn map_bytes(vm_space: &VmSpace, start: Vaddr, contents: &[u8], flags: PageFlags) {
    assert_eq!(start % PAGE_SIZE, 0);
    assert!(!contents.is_empty());
    assert_eq!(contents.len() % PAGE_SIZE, 0);
    let frames = FrameAllocOptions::new()
        .alloc_segment(contents.len() / PAGE_SIZE)
        .expect("allocate user mapping frames");
    frames
        .write_bytes(0, contents)
        .expect("populate user mapping frames");
    let guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&guard, &(start..start + contents.len()))
        .expect("create user mapping cursor");
    for frame in frames {
        cursor.map(
            frame.into(),
            PageProperty::new_user(flags, CachePolicy::Writeback),
        );
    }
}

fn write_word(contents: &mut [u8], offset: usize, word: usize) {
    write_at(contents, offset, &word.to_le_bytes());
}

fn write_at(contents: &mut [u8], offset: usize, bytes: &[u8]) {
    let end = offset
        .checked_add(bytes.len())
        .expect("write range overflow");
    contents
        .get_mut(offset..end)
        .expect("write range lies within mapping")
        .copy_from_slice(bytes);
}

const fn align_down(value: usize) -> usize {
    value & !(PAGE_SIZE - 1)
}

fn align_up(value: usize) -> usize {
    value
        .checked_add(PAGE_SIZE - 1)
        .expect("page alignment overflow")
        & !(PAGE_SIZE - 1)
}

fn align_up_to(value: usize, alignment: usize) -> usize {
    assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .expect("alignment overflow")
        & !(alignment - 1)
}
