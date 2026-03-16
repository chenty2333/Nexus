use super::super::*;

fn read_all_fd_bytes(ops: &dyn FdOps) -> Result<Vec<u8>, zx_status_t> {
    let metadata = local_fd_metadata(ops).ok_or(ZX_ERR_NOT_SUPPORTED)?;
    let len = usize::try_from(metadata.size_bytes).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
    bytes.resize(len, 0);
    let actual = ops.read(&mut bytes)?;
    bytes.truncate(actual);
    Ok(bytes)
}

pub(in crate::starnix) fn open_exec_image_from_namespace(
    namespace: &nexus_io::ProcessNamespace,
    path: &str,
) -> Result<(String, Vec<u8>, zx_handle_t), zx_status_t> {
    let resolved = namespace.resolve_path(path)?;
    let ops = namespace.open(resolved.as_str(), OpenFlags::READABLE)?;
    let bytes = read_all_fd_bytes(ops.as_ref())?;
    let vmo = ops.as_vmo(nexus_io::VmoFlags::READ | nexus_io::VmoFlags::EXECUTE)?;
    Ok((resolved, bytes, vmo))
}

pub(in crate::starnix) fn read_exec_image_bytes_from_namespace(
    namespace: &nexus_io::ProcessNamespace,
    path: &str,
) -> Result<(String, Vec<u8>), zx_status_t> {
    let resolved = namespace.resolve_path(path)?;
    let ops = namespace.open(resolved.as_str(), OpenFlags::READABLE)?;
    let bytes = read_all_fd_bytes(ops.as_ref())?;
    Ok((resolved, bytes))
}

pub(in crate::starnix) fn read_guest_string_array(
    session: zx_handle_t,
    addr: u64,
    max_entries: usize,
) -> Result<Vec<String>, zx_status_t> {
    if addr == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    out.try_reserve(max_entries.min(8))
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    for index in 0..max_entries {
        let entry_addr = addr
            .checked_add((index * 8) as u64)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let value = read_guest_u64(session, entry_addr)?;
        if value == 0 {
            return Ok(out);
        }
        out.push(read_guest_c_string(session, value, LINUX_PATH_MAX)?);
    }
    Err(ZX_ERR_OUT_OF_RANGE)
}

pub(in crate::starnix) fn build_task_image(
    path: &str,
    args: &[String],
    env: &[String],
    bytes: &[u8],
    stack_random: [u8; 16],
    mut resolve_interp_image: impl FnMut(&str) -> Result<Vec<u8>, zx_status_t>,
) -> Result<TaskImage, zx_status_t> {
    let elf = parse_elf(bytes, None)?;
    let mut cmdline = Vec::new();
    for arg in args {
        cmdline
            .try_reserve_exact(arg.len().checked_add(1).ok_or(ZX_ERR_OUT_OF_RANGE)?)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        cmdline.extend_from_slice(arg.as_bytes());
        cmdline.push(0);
    }
    let mut writable_ranges = Vec::new();
    collect_writable_ranges(&mut writable_ranges, &elf)?;
    let mut initial_tls_modules = Vec::new();

    let exec_blob = if let Some(interp_path) = elf.interp_path.as_deref() {
        let interp_load_bias =
            align_up_u64(elf.image_end, USER_PAGE_BYTES).ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let interp_bytes = resolve_interp_image(interp_path)?;
        let interp_elf = parse_elf(&interp_bytes, Some(interp_load_bias))?;
        collect_initial_tls_template(&mut initial_tls_modules, &interp_bytes, &interp_elf)?;
        collect_initial_tls_template(&mut initial_tls_modules, bytes, &elf)?;
        collect_writable_ranges(&mut writable_ranges, &interp_elf)?;
        let stack =
            build_initial_stack(path, args, env, &elf, Some(interp_load_bias), stack_random)?;
        ax_linux_exec_spec_blob_with_interp(
            ax_linux_exec_spec_header_t {
                version: AX_LINUX_EXEC_SPEC_V2,
                flags: AX_LINUX_EXEC_SPEC_F_INTERP,
                entry: interp_elf.entry,
                stack_pointer: stack.stack_pointer,
                stack_vmo_offset: stack.stack_vmo_offset,
                stack_bytes_len: stack.image.len() as u64,
            },
            &stack.image,
            ax_linux_exec_interp_header_t {
                load_bias: interp_load_bias,
                image_bytes_len: interp_bytes.len() as u64,
            },
            &interp_bytes,
        )?
    } else {
        collect_initial_tls_template(&mut initial_tls_modules, bytes, &elf)?;
        let stack = build_initial_stack(path, args, env, &elf, None, stack_random)?;
        ax_linux_exec_spec_blob(
            ax_linux_exec_spec_header_t {
                version: AX_LINUX_EXEC_SPEC_V1,
                flags: 0,
                entry: elf.entry,
                stack_pointer: stack.stack_pointer,
                stack_vmo_offset: stack.stack_vmo_offset,
                stack_bytes_len: stack.image.len() as u64,
            },
            &stack.image,
        )?
    };

    Ok(TaskImage {
        path: String::from(path),
        cmdline,
        exec_blob,
        initial_tls_modules,
        runtime_random: stack_random,
        writable_ranges,
    })
}

fn collect_initial_tls_template(
    templates: &mut Vec<LinuxInitialTls>,
    bytes: &[u8],
    elf: &LinuxElf<'_>,
) -> Result<(), zx_status_t> {
    let Some(tls) = elf.tls else {
        return Ok(());
    };
    let mut init_image = Vec::new();
    init_image
        .try_reserve_exact(tls.file_size)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    init_image.extend_from_slice(
        bytes
            .get(tls.file_offset..tls.file_offset + tls.file_size)
            .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?,
    );
    templates.try_reserve(1).map_err(|_| ZX_ERR_NO_MEMORY)?;
    templates.push(LinuxInitialTls {
        init_image,
        mem_size: tls.mem_size,
        align: tls.align,
    });
    Ok(())
}

fn collect_writable_ranges(
    writable_ranges: &mut Vec<LinuxWritableRange>,
    elf: &LinuxElf<'_>,
) -> Result<(), zx_status_t> {
    for segment in &elf.segments {
        if (segment.flags & 0x2) == 0 {
            continue;
        }
        let map_base = segment.vaddr & !(USER_PAGE_BYTES - 1);
        let page_delta = segment
            .vaddr
            .checked_sub(map_base)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let len = align_up_u64(
            page_delta
                .checked_add(segment.mem_size as u64)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?,
            USER_PAGE_BYTES,
        )
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        if len == 0 {
            continue;
        }
        writable_ranges
            .try_reserve(1)
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        writable_ranges.push(LinuxWritableRange {
            base: map_base,
            len,
        });
    }
    Ok(())
}

fn parse_elf(bytes: &[u8], load_bias: Option<u64>) -> Result<LinuxElf<'_>, zx_status_t> {
    if bytes.len() < ELF64_EHDR_SIZE || &bytes[..4] != b"\x7fELF" {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    if bytes[4] != ELF_CLASS_64 || bytes[5] != ELF_DATA_LE {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let elf_type = read_u16(bytes, 16)?;
    if read_u16(bytes, 18)? != EM_X86_64 {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let image_bias = match (elf_type, load_bias) {
        (ET_EXEC, None) => 0,
        (ET_DYN, None) => USER_MAIN_ET_DYN_LOAD_BIAS,
        (ET_DYN, Some(load_bias)) if (load_bias & (USER_PAGE_BYTES - 1)) == 0 => load_bias,
        _ => return Err(ZX_ERR_NOT_SUPPORTED),
    };
    let entry = read_u64(bytes, 24)?
        .checked_add(image_bias)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    let image_limit = USER_CODE_VA
        .checked_add(USER_CODE_BYTES)
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
    if entry < USER_CODE_VA || entry >= image_limit {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let phoff = usize::try_from(read_u64(bytes, 32)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    let phentsize = read_u16(bytes, 54)?;
    let phnum = read_u16(bytes, 56)?;
    if phentsize as usize != ELF64_PHDR_SIZE {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let phdr_table_bytes = usize::from(phnum)
        .checked_mul(ELF64_PHDR_SIZE)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    let phdr_end = phoff
        .checked_add(phdr_table_bytes)
        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    if phdr_end > bytes.len() {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }

    let mut phdr_vaddr = None;
    let mut interp_path = None;
    let mut image_end = 0u64;
    let mut tls = None;
    let mut segments = Vec::new();
    for index in 0..usize::from(phnum) {
        let base = phoff + index * ELF64_PHDR_SIZE;
        let p_type = read_u32(bytes, base)?;
        let p_offset =
            usize::try_from(read_u64(bytes, base + 8)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
        let p_vaddr = read_u64(bytes, base + 16)?
            .checked_add(image_bias)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let p_align = read_u64(bytes, base + 48)?;
        let p_filesz =
            usize::try_from(read_u64(bytes, base + 32)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
        let p_memsz =
            usize::try_from(read_u64(bytes, base + 40)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
        if p_type == PT_PHDR {
            phdr_vaddr = Some(p_vaddr);
        }
        if p_type == PT_INTERP {
            let file_end = p_offset
                .checked_add(p_filesz)
                .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
            let raw = bytes
                .get(p_offset..file_end)
                .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
            let trimmed = raw.split(|byte| *byte == 0).next().unwrap_or(raw);
            let path = core::str::from_utf8(trimmed).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
            interp_path = Some(String::from(path));
        }
        if p_type == PT_TLS {
            if tls.is_some() {
                return Err(ZX_ERR_NOT_SUPPORTED);
            }
            if p_filesz > p_memsz {
                return Err(ZX_ERR_IO_DATA_INTEGRITY);
            }
            let file_end = p_offset
                .checked_add(p_filesz)
                .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
            if file_end > bytes.len() {
                return Err(ZX_ERR_IO_DATA_INTEGRITY);
            }
            let align = if p_align == 0 { 1 } else { p_align };
            if !align.is_power_of_two() {
                return Err(ZX_ERR_NOT_SUPPORTED);
            }
            tls = Some(LinuxTlsSegment {
                file_offset: p_offset,
                file_size: p_filesz,
                mem_size: u64::try_from(p_memsz).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
                align,
            });
        }
        if p_type == PT_LOAD {
            let file_end = p_offset
                .checked_add(p_filesz)
                .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
            if file_end > bytes.len() {
                return Err(ZX_ERR_IO_DATA_INTEGRITY);
            }
            let vend = p_vaddr
                .checked_add(u64::try_from(p_memsz).map_err(|_| ZX_ERR_OUT_OF_RANGE)?)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if p_vaddr < USER_CODE_VA || vend > image_limit {
                return Err(ZX_ERR_NOT_SUPPORTED);
            }
            if phdr_vaddr.is_none() && p_offset <= phoff && phdr_end <= file_end {
                phdr_vaddr = Some(
                    p_vaddr
                        .checked_add(
                            u64::try_from(phoff - p_offset)
                                .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?,
                        )
                        .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?,
                );
            }
            segments.try_reserve(1).map_err(|_| ZX_ERR_INTERNAL)?;
            segments.push(LinuxLoadSegment {
                vaddr: p_vaddr,
                mem_size: p_memsz,
                flags: read_u32(bytes, base + 4)?,
            });
            image_end = image_end.max(vend);
        }
    }
    if segments.is_empty() {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    Ok(LinuxElf {
        entry,
        phdr_vaddr,
        phent: phentsize,
        phnum,
        image_end,
        interp_path,
        tls,
        segments,
        _bytes: bytes,
    })
}

fn build_initial_stack(
    path: &str,
    args: &[String],
    env: &[String],
    elf: &LinuxElf<'_>,
    at_base: Option<u64>,
    stack_random: [u8; 16],
) -> Result<PreparedLinuxStack, zx_status_t> {
    let argv = if args.is_empty() {
        let mut argv = Vec::new();
        argv.try_reserve_exact(1).map_err(|_| ZX_ERR_INTERNAL)?;
        argv.push(String::from(path));
        argv
    } else {
        args.to_vec()
    };
    let envv = env.to_vec();
    let execfn = path.as_bytes();
    let platform = LINUX_AUX_PLATFORM;
    let random_bytes = stack_random;
    let mut blobs = Vec::new();
    blobs
        .try_reserve_exact(
            argv.len()
                .checked_add(envv.len())
                .and_then(|count| count.checked_add(3))
                .ok_or(ZX_ERR_INTERNAL)?,
        )
        .map_err(|_| ZX_ERR_INTERNAL)?;
    let mut auxv = Vec::new();
    auxv.try_reserve_exact(17).map_err(|_| ZX_ERR_INTERNAL)?;
    auxv.push((AT_PAGESZ, USER_PAGE_BYTES));
    auxv.push((AT_ENTRY, elf.entry));
    if let Some(at_base) = at_base {
        auxv.push((AT_BASE, at_base));
    }
    if let Some(phdr_vaddr) = elf.phdr_vaddr {
        auxv.push((AT_PHDR, phdr_vaddr));
        auxv.push((AT_PHENT, u64::from(elf.phent)));
        auxv.push((AT_PHNUM, u64::from(elf.phnum)));
    }
    let stack_len = usize::try_from(USER_STACK_BYTES).map_err(|_| ZX_ERR_INTERNAL)?;
    let mut cursor = stack_len;
    let random_ptr =
        reserve_stack_blob(&mut cursor, USER_STACK_VA, &random_bytes, false, &mut blobs)?;
    let execfn_ptr = reserve_stack_blob(&mut cursor, USER_STACK_VA, execfn, true, &mut blobs)?;
    let platform_ptr = reserve_stack_blob(&mut cursor, USER_STACK_VA, platform, true, &mut blobs)?;
    let mut argv_ptrs = Vec::new();
    argv_ptrs
        .try_reserve_exact(argv.len())
        .map_err(|_| ZX_ERR_INTERNAL)?;
    for value in argv.iter().rev() {
        argv_ptrs.push(reserve_stack_blob(
            &mut cursor,
            USER_STACK_VA,
            value.as_bytes(),
            true,
            &mut blobs,
        )?);
    }
    argv_ptrs.reverse();
    let mut env_ptrs = Vec::new();
    env_ptrs
        .try_reserve_exact(envv.len())
        .map_err(|_| ZX_ERR_INTERNAL)?;
    for value in envv.iter().rev() {
        env_ptrs.push(reserve_stack_blob(
            &mut cursor,
            USER_STACK_VA,
            value.as_bytes(),
            true,
            &mut blobs,
        )?);
    }
    env_ptrs.reverse();

    auxv.push((AT_UID, 0));
    auxv.push((AT_EUID, 0));
    auxv.push((AT_GID, 0));
    auxv.push((AT_EGID, 0));
    auxv.push((AT_PLATFORM, platform_ptr));
    auxv.push((AT_HWCAP, LINUX_AUX_HWCAP));
    auxv.push((AT_CLKTCK, LINUX_AUX_CLKTCK));
    auxv.push((AT_SECURE, 0));
    auxv.push((AT_RANDOM, random_ptr));
    auxv.push((AT_HWCAP2, LINUX_AUX_HWCAP2));
    auxv.push((AT_EXECFN, execfn_ptr));
    auxv.push((AT_NULL, 0));

    let mut words = Vec::new();
    let word_count = 1usize
        .checked_add(argv_ptrs.len())
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_add(env_ptrs.len()))
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_add(auxv.len().checked_mul(2)?))
        .ok_or(ZX_ERR_INTERNAL)?;
    words
        .try_reserve_exact(word_count)
        .map_err(|_| ZX_ERR_INTERNAL)?;
    words.push(argv.len() as u64);
    for ptr in &argv_ptrs {
        words.push(*ptr);
    }
    words.push(0);
    for ptr in &env_ptrs {
        words.push(*ptr);
    }
    words.push(0);
    for (key, value) in auxv {
        words.push(key);
        words.push(value);
    }

    let words_bytes = words.len().checked_mul(8).ok_or(ZX_ERR_INTERNAL)?;
    cursor = cursor.checked_sub(words_bytes).ok_or(ZX_ERR_INTERNAL)?;
    cursor &= !0xFusize;
    let total_bytes = stack_len.checked_sub(cursor).ok_or(ZX_ERR_INTERNAL)?;
    let mut image = Vec::new();
    image
        .try_reserve_exact(total_bytes)
        .map_err(|_| ZX_ERR_INTERNAL)?;
    image.resize(total_bytes, 0);

    let words_offset = 0usize;
    for (index, word) in words.iter().enumerate() {
        let start = words_offset + index * 8;
        image[start..start + 8].copy_from_slice(&word.to_ne_bytes());
    }
    for blob in &blobs {
        let guest_offset =
            usize::try_from(blob.ptr.checked_sub(USER_STACK_VA).ok_or(ZX_ERR_INTERNAL)?)
                .map_err(|_| ZX_ERR_INTERNAL)?;
        let local_offset = guest_offset.checked_sub(cursor).ok_or(ZX_ERR_INTERNAL)?;
        let end = local_offset
            .checked_add(blob.bytes.len())
            .ok_or(ZX_ERR_INTERNAL)?;
        image[local_offset..end].copy_from_slice(blob.bytes);
        if blob.nul_terminated {
            image[end] = 0;
        }
    }

    Ok(PreparedLinuxStack {
        stack_pointer: USER_STACK_VA
            .checked_add(u64::try_from(cursor).map_err(|_| ZX_ERR_INTERNAL)?)
            .ok_or(ZX_ERR_INTERNAL)?,
        stack_vmo_offset: u64::try_from(cursor).map_err(|_| ZX_ERR_INTERNAL)?,
        image,
    })
}

struct StackBlob<'a> {
    ptr: u64,
    bytes: &'a [u8],
    nul_terminated: bool,
}

fn reserve_stack_blob<'a>(
    cursor: &mut usize,
    guest_base: u64,
    bytes: &'a [u8],
    nul_terminated: bool,
    blobs: &mut Vec<StackBlob<'a>>,
) -> Result<u64, zx_status_t> {
    let reserve = bytes
        .len()
        .checked_add(usize::from(nul_terminated))
        .ok_or(ZX_ERR_INTERNAL)?;
    *cursor = cursor.checked_sub(reserve).ok_or(ZX_ERR_INTERNAL)?;
    let ptr = guest_base
        .checked_add(u64::try_from(*cursor).map_err(|_| ZX_ERR_INTERNAL)?)
        .ok_or(ZX_ERR_INTERNAL)?;
    blobs.try_reserve_exact(1).map_err(|_| ZX_ERR_INTERNAL)?;
    blobs.push(StackBlob {
        ptr,
        bytes,
        nul_terminated,
    });
    Ok(ptr)
}

impl ExecutiveState {
    pub(in crate::starnix) fn install_initial_tls(
        &mut self,
        session: zx_handle_t,
        task_image: &TaskImage,
    ) -> Result<Option<u64>, zx_status_t> {
        let mut tls_span = 0u64;
        let mut tls_module_offsets = Vec::new();
        tls_module_offsets
            .try_reserve_exact(task_image.initial_tls_modules.len())
            .map_err(|_| ZX_ERR_NO_MEMORY)?;
        for initial_tls in &task_image.initial_tls_modules {
            let offset = tls_span;
            tls_module_offsets.push(offset);
            if initial_tls.mem_size == 0 {
                continue;
            }
            let module_align = initial_tls.align.max(1);
            tls_span = align_up_u64(tls_span, module_align).ok_or(ZX_ERR_OUT_OF_RANGE)?;
            *tls_module_offsets.last_mut().ok_or(ZX_ERR_BAD_STATE)? = tls_span;
            let module_span =
                align_up_u64(initial_tls.mem_size, module_align).ok_or(ZX_ERR_OUT_OF_RANGE)?;
            tls_span = tls_span
                .checked_add(module_span)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        }
        let dtv_module_slots = task_image
            .initial_tls_modules
            .len()
            .max(X64_TLS_DTV_MIN_MODULE_SLOTS as usize);
        let dtv_storage_words = X64_TLS_DTV_PREFIX_WORDS
            .checked_add(X64_TLS_DTV_HEADER_WORDS)
            .and_then(|words| {
                words.checked_add(
                    u64::try_from(dtv_module_slots)
                        .ok()?
                        .checked_mul(X64_TLS_DTV_WORDS_PER_MODULE)?,
                )
            })
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let dtv_storage_bytes = dtv_storage_words
            .checked_mul(8)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let tcb_offset = tls_span;
        let dtv_storage_offset = align_up_u64(
            tcb_offset
                .checked_add(X64_TLS_TCB_BYTES)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?,
            16,
        )
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let map_len = align_up_u64(
            dtv_storage_offset
                .checked_add(dtv_storage_bytes)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?,
            USER_PAGE_BYTES,
        )
        .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let map_base = self.map_private_anon(map_len, LINUX_PROT_READ | LINUX_PROT_WRITE)?;
        for (index, initial_tls) in task_image.initial_tls_modules.iter().enumerate() {
            if initial_tls.mem_size == 0 {
                continue;
            }
            let module_addr = map_base
                .checked_add(*tls_module_offsets.get(index).ok_or(ZX_ERR_BAD_STATE)?)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            if !initial_tls.init_image.is_empty() {
                write_guest_bytes(session, module_addr, &initial_tls.init_image)?;
            }
        }
        let dtv_storage_base = map_base
            .checked_add(dtv_storage_offset)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let dtv_ptr = dtv_storage_base
            .checked_add(
                X64_TLS_DTV_PREFIX_WORDS
                    .checked_mul(8)
                    .ok_or(ZX_ERR_OUT_OF_RANGE)?,
            )
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        write_guest_u64(
            session,
            dtv_storage_base,
            u64::try_from(dtv_module_slots).map_err(|_| ZX_ERR_OUT_OF_RANGE)?,
        )?;
        write_guest_u64(
            session,
            dtv_storage_base.checked_add(8).ok_or(ZX_ERR_OUT_OF_RANGE)?,
            0,
        )?;
        write_guest_u64(session, dtv_ptr, 1)?;
        write_guest_u64(
            session,
            dtv_ptr.checked_add(8).ok_or(ZX_ERR_OUT_OF_RANGE)?,
            0,
        )?;
        for (index, _) in task_image.initial_tls_modules.iter().enumerate() {
            let slot_offset = u64::try_from(index)
                .map_err(|_| ZX_ERR_OUT_OF_RANGE)?
                .checked_mul(X64_TLS_DTV_WORDS_PER_MODULE)
                .and_then(|words| words.checked_mul(8))
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let slot_addr = dtv_ptr
                .checked_add(
                    X64_TLS_DTV_HEADER_WORDS
                        .checked_mul(8)
                        .and_then(|header| header.checked_add(slot_offset))
                        .ok_or(ZX_ERR_OUT_OF_RANGE)?,
                )
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            let module_addr = map_base
                .checked_add(*tls_module_offsets.get(index).ok_or(ZX_ERR_BAD_STATE)?)
                .ok_or(ZX_ERR_OUT_OF_RANGE)?;
            write_guest_u64(session, slot_addr, module_addr)?;
            write_guest_u64(
                session,
                slot_addr.checked_add(8).ok_or(ZX_ERR_OUT_OF_RANGE)?,
                0,
            )?;
        }
        let fs_base = map_base
            .checked_add(tcb_offset)
            .ok_or(ZX_ERR_OUT_OF_RANGE)?;
        let stack_guard = u64::from_ne_bytes(task_image.runtime_random[..8].try_into().unwrap());
        let pointer_guard = u64::from_ne_bytes(task_image.runtime_random[8..].try_into().unwrap());
        write_guest_u64(session, fs_base, fs_base)?;
        write_guest_u64(
            session,
            fs_base.checked_add(8).ok_or(ZX_ERR_OUT_OF_RANGE)?,
            dtv_ptr,
        )?;
        write_guest_u64(
            session,
            fs_base.checked_add(16).ok_or(ZX_ERR_OUT_OF_RANGE)?,
            fs_base,
        )?;
        write_guest_u64(
            session,
            fs_base.checked_add(0x28).ok_or(ZX_ERR_OUT_OF_RANGE)?,
            stack_guard,
        )?;
        write_guest_u64(
            session,
            fs_base.checked_add(0x30).ok_or(ZX_ERR_OUT_OF_RANGE)?,
            pointer_guard,
        )?;
        Ok(Some(fs_base))
    }
}
