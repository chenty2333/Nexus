use alloc::string::String;
use alloc::vec::Vec;

use axle_types::guest::{
    AX_GUEST_STOP_REASON_X64_SYSCALL, AX_GUEST_X64_SYSCALL_INSN_LEN, AX_LINUX_EXEC_SPEC_V1,
};
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::packet::ZX_PKT_TYPE_USER;
use axle_types::signals::{ZX_SOCKET_PEER_CLOSED, ZX_SOCKET_WRITABLE};
use axle_types::status::{
    ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_INVALID_ARGS, ZX_ERR_IO_DATA_INTEGRITY,
    ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED, ZX_OK,
};
use axle_types::{ax_guest_stop_state_t, ax_linux_exec_spec_header_t, zx_handle_t, zx_status_t};
use libzircon::{
    ZX_TIME_INFINITE, ax_guest_session_create, ax_guest_session_read_memory,
    ax_guest_session_resume, ax_guest_stop_state_read, ax_guest_stop_state_write,
    ax_linux_exec_spec_blob, ax_process_prepare_linux_exec, zx_handle_close, zx_object_wait_one,
    zx_port_create, zx_port_packet_t, zx_port_wait, zx_process_create, zx_process_start,
    zx_socket_write, zx_task_kill, zx_thread_create, zx_vmo_create,
};
use nexus_component::{ComponentStartInfo, NumberedHandle};

use crate::lifecycle::{read_channel_blocking, send_controller_event, send_status_event};
use crate::{
    LINUX_HELLO_BYTES, MAX_BOOTSTRAP_MESSAGE_BYTES, MAX_BOOTSTRAP_MESSAGE_HANDLES,
    STARTUP_HANDLE_COMPONENT_STATUS, STARTUP_HANDLE_STARNIX_IMAGE_VMO,
    STARTUP_HANDLE_STARNIX_PARENT_PROCESS, STARTUP_HANDLE_STARNIX_STDOUT,
};

const USER_PAGE_BYTES: u64 = 0x1000;
const USER_CODE_BYTES: u64 = USER_PAGE_BYTES * 256;
const USER_SHARED_BYTES: u64 = USER_PAGE_BYTES * 2;
const USER_STACK_BYTES: u64 = USER_PAGE_BYTES * 16;
const USER_CODE_VA: u64 = 0x0000_0001_0000_0000;
const USER_STACK_VA: u64 = USER_CODE_VA + USER_CODE_BYTES + USER_SHARED_BYTES;
const STARNIX_GUEST_PACKET_KEY: u64 = 0x5354_4e58_0000_0001;
const LINUX_SYSCALL_WRITE: u64 = 1;
const LINUX_SYSCALL_EXIT: u64 = 60;
const LINUX_SYSCALL_EXIT_GROUP: u64 = 231;
const LINUX_EBADF: i32 = 9;
const LINUX_ENOSYS: i32 = 38;
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LE: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const LINUX_HELLO_EXPECTED_STDOUT: &[u8] = b"hello from linux-hello\n";

pub(crate) fn starnix_kernel_program_start(bootstrap_channel: zx_handle_t) -> ! {
    let mut status_handle = None;
    let mut controller_handle = None;
    let return_code = match read_start_info(bootstrap_channel) {
        Ok(start_info) => {
            status_handle = start_info.status_handle;
            controller_handle = start_info.controller_handle;
            run_executive(start_info)
        }
        Err(status) => map_status_to_return_code(status),
    };

    if let Some(handle) = status_handle {
        let _ = send_status_event(handle, return_code);
        let _ = zx_handle_close(handle);
    }
    if let Some(handle) = controller_handle {
        let _ = send_controller_event(handle, return_code);
        let _ = zx_handle_close(handle);
    }
    loop {
        core::hint::spin_loop();
    }
}

struct StarnixStartInfo {
    args: Vec<String>,
    env: Vec<String>,
    parent_process: zx_handle_t,
    linux_image_vmo: zx_handle_t,
    stdout_handle: Option<zx_handle_t>,
    status_handle: Option<zx_handle_t>,
    controller_handle: Option<zx_handle_t>,
}

struct PreparedLinuxStack {
    stack_pointer: u64,
    stack_vmo_offset: u64,
    image: Vec<u8>,
}

#[derive(Clone, Copy)]
struct LinuxLoadSegment {
    vaddr: u64,
    file_offset: usize,
    file_size: usize,
}

struct LinuxElf<'a> {
    entry: u64,
    phdr_vaddr: Option<u64>,
    phent: u16,
    phnum: u16,
    segments: Vec<LinuxLoadSegment>,
    bytes: &'a [u8],
}

enum SyscallAction {
    Resume,
    Exit(i32),
}

fn read_start_info(bootstrap_channel: zx_handle_t) -> Result<StarnixStartInfo, zx_status_t> {
    let mut bytes = [0u8; MAX_BOOTSTRAP_MESSAGE_BYTES];
    let mut handles = [ZX_HANDLE_INVALID; MAX_BOOTSTRAP_MESSAGE_HANDLES];
    let (actual_bytes, actual_handles) =
        read_channel_blocking(bootstrap_channel, &mut bytes, &mut handles)?;
    let start_info = ComponentStartInfo::decode_channel_message(
        &bytes[..actual_bytes],
        &handles[..actual_handles],
    )
    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    let mut linux_image_vmo = ZX_HANDLE_INVALID;
    let mut parent_process = ZX_HANDLE_INVALID;
    let mut stdout_handle = None;
    let mut status_handle = None;
    for NumberedHandle { id, handle } in start_info.numbered_handles {
        if id == STARTUP_HANDLE_COMPONENT_STATUS {
            status_handle = Some(handle);
        } else if id == STARTUP_HANDLE_STARNIX_IMAGE_VMO {
            linux_image_vmo = handle;
        } else if id == STARTUP_HANDLE_STARNIX_PARENT_PROCESS {
            parent_process = handle;
        } else if id == STARTUP_HANDLE_STARNIX_STDOUT {
            stdout_handle = Some(handle);
        }
    }
    if linux_image_vmo == ZX_HANDLE_INVALID || parent_process == ZX_HANDLE_INVALID {
        return Err(ZX_ERR_NOT_FOUND);
    }
    Ok(StarnixStartInfo {
        args: start_info.args,
        env: start_info.env,
        parent_process,
        linux_image_vmo,
        stdout_handle,
        status_handle,
        controller_handle: start_info.controller_channel,
    })
}

fn run_executive(start_info: StarnixStartInfo) -> i32 {
    let StarnixStartInfo {
        args,
        env,
        parent_process,
        linux_image_vmo,
        stdout_handle,
        status_handle: _,
        controller_handle: _,
    } = start_info;
    let Some(payload_bytes) = payload_bytes_for(&args) else {
        return map_status_to_return_code(ZX_ERR_NOT_SUPPORTED);
    };
    let elf = match parse_elf(payload_bytes) {
        Ok(elf) => elf,
        Err(status) => return map_status_to_return_code(status),
    };
    let stack = match build_initial_stack(&args, &env, &elf) {
        Ok(stack) => stack,
        Err(status) => return map_status_to_return_code(status),
    };
    let exec_blob = match ax_linux_exec_spec_blob(
        ax_linux_exec_spec_header_t {
            version: AX_LINUX_EXEC_SPEC_V1,
            flags: 0,
            entry: elf.entry,
            stack_pointer: stack.stack_pointer,
            stack_vmo_offset: stack.stack_vmo_offset,
            stack_bytes_len: stack.image.len() as u64,
        },
        &stack.image,
    ) {
        Ok(blob) => blob,
        Err(status) => return map_status_to_return_code(status),
    };

    let mut process = ZX_HANDLE_INVALID;
    let mut root_vmar = ZX_HANDLE_INVALID;
    if zx_process_create(parent_process, 0, &mut process, &mut root_vmar) != ZX_OK {
        if parent_process != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(parent_process);
        }
        if linux_image_vmo != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(linux_image_vmo);
        }
        if let Some(stdout) = stdout_handle {
            let _ = zx_handle_close(stdout);
        }
        return 1;
    }
    let _ = zx_handle_close(parent_process);
    let mut thread = ZX_HANDLE_INVALID;
    if zx_thread_create(process, 0, &mut thread) != ZX_OK {
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        let _ = zx_handle_close(linux_image_vmo);
        if let Some(stdout) = stdout_handle {
            let _ = zx_handle_close(stdout);
        }
        return 1;
    }
    let mut port = ZX_HANDLE_INVALID;
    if zx_port_create(0, &mut port) != ZX_OK {
        let _ = zx_handle_close(thread);
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        let _ = zx_handle_close(linux_image_vmo);
        if let Some(stdout) = stdout_handle {
            let _ = zx_handle_close(stdout);
        }
        return 1;
    }
    let mut sidecar = ZX_HANDLE_INVALID;
    if zx_vmo_create(ax_guest_stop_state_t::BYTE_LEN as u64, 0, &mut sidecar) != ZX_OK {
        let _ = zx_handle_close(port);
        let _ = zx_handle_close(thread);
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        let _ = zx_handle_close(linux_image_vmo);
        if let Some(stdout) = stdout_handle {
            let _ = zx_handle_close(stdout);
        }
        return 1;
    }
    let mut prepared_entry = 0u64;
    let mut prepared_stack = 0u64;
    let prepare_status = ax_process_prepare_linux_exec(
        process,
        linux_image_vmo,
        0,
        &exec_blob,
        &mut prepared_entry,
        &mut prepared_stack,
    );
    let _ = zx_handle_close(linux_image_vmo);
    if prepare_status != ZX_OK {
        let _ = zx_handle_close(sidecar);
        let _ = zx_handle_close(port);
        let _ = zx_handle_close(thread);
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        if let Some(stdout) = stdout_handle {
            let _ = zx_handle_close(stdout);
        }
        return map_status_to_return_code(prepare_status);
    }
    let mut session = ZX_HANDLE_INVALID;
    let session_status = ax_guest_session_create(
        thread,
        sidecar,
        port,
        STARNIX_GUEST_PACKET_KEY,
        0,
        &mut session,
    );
    if session_status != ZX_OK {
        let _ = zx_handle_close(sidecar);
        let _ = zx_handle_close(port);
        let _ = zx_handle_close(thread);
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        if let Some(stdout) = stdout_handle {
            let _ = zx_handle_close(stdout);
        }
        return map_status_to_return_code(session_status);
    }
    let start_status = zx_process_start(
        process,
        thread,
        prepared_entry,
        prepared_stack,
        ZX_HANDLE_INVALID,
        0,
    );
    let _ = zx_handle_close(thread);
    let _ = zx_handle_close(root_vmar);
    if start_status != ZX_OK {
        let _ = zx_handle_close(session);
        let _ = zx_handle_close(sidecar);
        let _ = zx_handle_close(port);
        let _ = zx_handle_close(process);
        if let Some(stdout) = stdout_handle {
            let _ = zx_handle_close(stdout);
        }
        return map_status_to_return_code(start_status);
    }

    let result = supervise_guest(process, session, port, sidecar, stdout_handle);
    let _ = zx_task_kill(process);
    let _ = zx_handle_close(session);
    let _ = zx_handle_close(sidecar);
    let _ = zx_handle_close(port);
    let _ = zx_handle_close(process);
    if let Some(stdout) = stdout_handle {
        let _ = zx_handle_close(stdout);
    }
    result
}

fn supervise_guest(
    process: zx_handle_t,
    session: zx_handle_t,
    port: zx_handle_t,
    sidecar: zx_handle_t,
    stdout_handle: Option<zx_handle_t>,
) -> i32 {
    let mut stdout = Vec::new();
    loop {
        let mut packet = zx_port_packet_t::default();
        let wait_status = zx_port_wait(port, ZX_TIME_INFINITE, &mut packet);
        if wait_status != ZX_OK {
            return map_status_to_return_code(wait_status);
        }
        if packet.type_ != ZX_PKT_TYPE_USER || packet.key != STARNIX_GUEST_PACKET_KEY {
            return map_status_to_return_code(ZX_ERR_BAD_STATE);
        }
        let stop_seq = packet.user.u64[0];
        let reason = packet.user.u64[1] as u16;
        if reason != AX_GUEST_STOP_REASON_X64_SYSCALL {
            return map_status_to_return_code(ZX_ERR_NOT_SUPPORTED);
        }
        let mut stop_state = match ax_guest_stop_state_read(sidecar) {
            Ok(stop_state) => stop_state,
            Err(status) => return map_status_to_return_code(status),
        };
        match emulate_syscall(session, &mut stop_state, stdout_handle, &mut stdout) {
            Ok(SyscallAction::Resume) => {
                let write_status = ax_guest_stop_state_write(sidecar, &stop_state);
                if write_status != ZX_OK {
                    return map_status_to_return_code(write_status);
                }
                let resume_status = ax_guest_session_resume(session, stop_seq, 0);
                if resume_status != ZX_OK {
                    return map_status_to_return_code(resume_status);
                }
            }
            Ok(SyscallAction::Exit(code)) => {
                let _ = zx_task_kill(process);
                if code == 0 && stdout == LINUX_HELLO_EXPECTED_STDOUT {
                    return 0;
                }
                return if code == 0 {
                    stdout_mismatch_return_code(&stdout)
                } else {
                    code
                };
            }
            Err(status) => {
                let _ = zx_task_kill(process);
                return map_status_to_return_code(status);
            }
        }
    }
}

fn emulate_syscall(
    session: zx_handle_t,
    stop_state: &mut ax_guest_stop_state_t,
    stdout_handle: Option<zx_handle_t>,
    stdout: &mut Vec<u8>,
) -> Result<SyscallAction, zx_status_t> {
    match stop_state.regs.rax {
        LINUX_SYSCALL_WRITE => {
            let fd = stop_state.regs.rdi;
            let buf = stop_state.regs.rsi;
            let len = usize::try_from(stop_state.regs.rdx).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            let result = if fd == 1 || fd == 2 {
                let bytes = read_guest_bytes(session, buf, len)?;
                if let Some(handle) = stdout_handle {
                    write_socket_all(handle, &bytes)?;
                }
                stdout.extend_from_slice(&bytes);
                len as u64
            } else {
                linux_errno(LINUX_EBADF)
            };
            stop_state.regs.rax = result;
            stop_state.regs.rip = stop_state
                .regs
                .rip
                .checked_add(AX_GUEST_X64_SYSCALL_INSN_LEN)
                .ok_or(ZX_ERR_INVALID_ARGS)?;
            Ok(SyscallAction::Resume)
        }
        LINUX_SYSCALL_EXIT | LINUX_SYSCALL_EXIT_GROUP => {
            let code =
                i32::try_from(stop_state.regs.rdi & 0xff).map_err(|_| ZX_ERR_INVALID_ARGS)?;
            Ok(SyscallAction::Exit(code))
        }
        _ => {
            stop_state.regs.rax = linux_errno(LINUX_ENOSYS);
            stop_state.regs.rip = stop_state
                .regs
                .rip
                .checked_add(AX_GUEST_X64_SYSCALL_INSN_LEN)
                .ok_or(ZX_ERR_INVALID_ARGS)?;
            Ok(SyscallAction::Resume)
        }
    }
}

fn payload_bytes_for(args: &[String]) -> Option<&'static [u8]> {
    match args.first().map(String::as_str) {
        Some("linux-hello") | None => Some(LINUX_HELLO_BYTES),
        Some(_) => None,
    }
}

fn parse_elf(bytes: &[u8]) -> Result<LinuxElf<'_>, zx_status_t> {
    if bytes.len() < ELF64_EHDR_SIZE || &bytes[..4] != b"\x7fELF" {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    if bytes[4] != ELF_CLASS_64 || bytes[5] != ELF_DATA_LE {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    if read_u16(bytes, 16)? != ET_EXEC || read_u16(bytes, 18)? != EM_X86_64 {
        return Err(ZX_ERR_NOT_SUPPORTED);
    }
    let entry = read_u64(bytes, 24)?;
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
    let mut segments = Vec::new();
    for index in 0..usize::from(phnum) {
        let base = phoff + index * ELF64_PHDR_SIZE;
        let p_type = read_u32(bytes, base)?;
        let p_offset =
            usize::try_from(read_u64(bytes, base + 8)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
        let p_vaddr = read_u64(bytes, base + 16)?;
        let p_filesz =
            usize::try_from(read_u64(bytes, base + 32)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
        let p_memsz =
            usize::try_from(read_u64(bytes, base + 40)?).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
        if p_type == PT_PHDR {
            phdr_vaddr = Some(p_vaddr);
        }
        if p_type == PT_LOAD {
            let file_end = p_offset
                .checked_add(p_filesz)
                .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
            if file_end > bytes.len() {
                return Err(ZX_ERR_IO_DATA_INTEGRITY);
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
                file_offset: p_offset,
                file_size: p_filesz,
            });
            let _ = p_memsz;
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
        segments,
        bytes,
    })
}

fn build_initial_stack(
    args: &[String],
    env: &[String],
    elf: &LinuxElf<'_>,
) -> Result<PreparedLinuxStack, zx_status_t> {
    let argv = if args.is_empty() {
        let mut argv = Vec::new();
        argv.try_reserve_exact(1).map_err(|_| ZX_ERR_INTERNAL)?;
        argv.push(String::from("linux-hello"));
        argv
    } else {
        args.to_vec()
    };
    let envv = env.to_vec();
    let mut auxv = Vec::new();
    auxv.try_reserve_exact(6).map_err(|_| ZX_ERR_INTERNAL)?;
    auxv.push((AT_PAGESZ, USER_PAGE_BYTES));
    auxv.push((AT_ENTRY, elf.entry));
    if let Some(phdr_vaddr) = elf.phdr_vaddr {
        auxv.push((AT_PHDR, phdr_vaddr));
        auxv.push((AT_PHENT, u64::from(elf.phent)));
        auxv.push((AT_PHNUM, u64::from(elf.phnum)));
    }
    auxv.push((AT_NULL, 0));

    let stack_len = usize::try_from(USER_STACK_BYTES).map_err(|_| ZX_ERR_INTERNAL)?;
    let mut cursor = stack_len;
    let mut string_ptrs = Vec::new();
    let total_strings = argv.len().checked_add(envv.len()).ok_or(ZX_ERR_INTERNAL)?;
    string_ptrs
        .try_reserve_exact(total_strings)
        .map_err(|_| ZX_ERR_INTERNAL)?;

    for value in envv.iter().rev().chain(argv.iter().rev()) {
        let bytes = value.as_bytes();
        cursor = cursor
            .checked_sub(bytes.len().checked_add(1).ok_or(ZX_ERR_INTERNAL)?)
            .ok_or(ZX_ERR_INTERNAL)?;
        string_ptrs.push((
            USER_STACK_VA
                .checked_add(u64::try_from(cursor).map_err(|_| ZX_ERR_INTERNAL)?)
                .ok_or(ZX_ERR_INTERNAL)?,
            bytes,
        ));
    }
    string_ptrs.reverse();

    let argv_ptrs = &string_ptrs[..argv.len()];
    let env_ptrs = &string_ptrs[argv.len()..];
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
    for (ptr, _) in argv_ptrs {
        words.push(*ptr);
    }
    words.push(0);
    for (ptr, _) in env_ptrs {
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
    for (ptr, bytes) in &string_ptrs {
        let guest_offset = usize::try_from(ptr.checked_sub(USER_STACK_VA).ok_or(ZX_ERR_INTERNAL)?)
            .map_err(|_| ZX_ERR_INTERNAL)?;
        let local_offset = guest_offset.checked_sub(cursor).ok_or(ZX_ERR_INTERNAL)?;
        let end = local_offset
            .checked_add(bytes.len())
            .ok_or(ZX_ERR_INTERNAL)?;
        image[local_offset..end].copy_from_slice(bytes);
        image[end] = 0;
    }

    Ok(PreparedLinuxStack {
        stack_pointer: USER_STACK_VA
            .checked_add(u64::try_from(cursor).map_err(|_| ZX_ERR_INTERNAL)?)
            .ok_or(ZX_ERR_INTERNAL)?,
        stack_vmo_offset: u64::try_from(cursor).map_err(|_| ZX_ERR_INTERNAL)?,
        image,
    })
}

fn read_guest_bytes(session: zx_handle_t, addr: u64, len: usize) -> Result<Vec<u8>, zx_status_t> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| ZX_ERR_INTERNAL)?;
    bytes.resize(len, 0);
    let status = ax_guest_session_read_memory(session, addr, &mut bytes);
    if status != ZX_OK {
        return Err(status);
    }
    Ok(bytes)
}

fn write_socket_all(handle: zx_handle_t, bytes: &[u8]) -> Result<(), zx_status_t> {
    let mut written = 0usize;
    while written < bytes.len() {
        let mut actual = 0usize;
        let status = zx_socket_write(
            handle,
            0,
            bytes[written..].as_ptr(),
            bytes.len() - written,
            &mut actual,
        );
        if status == ZX_OK {
            written = written.checked_add(actual).ok_or(ZX_ERR_INTERNAL)?;
            continue;
        }
        if status == axle_types::status::ZX_ERR_SHOULD_WAIT {
            let mut observed = 0;
            let wait_status = zx_object_wait_one(
                handle,
                ZX_SOCKET_WRITABLE | ZX_SOCKET_PEER_CLOSED,
                ZX_TIME_INFINITE,
                &mut observed,
            );
            if wait_status != ZX_OK {
                return Err(wait_status);
            }
            if (observed & ZX_SOCKET_PEER_CLOSED) != 0 {
                return Err(axle_types::status::ZX_ERR_PEER_CLOSED);
            }
            continue;
        }
        return Err(status);
    }
    Ok(())
}

fn linux_errno(errno: i32) -> u64 {
    (-(i64::from(errno))) as u64
}

fn map_status_to_return_code(status: zx_status_t) -> i32 {
    if status == ZX_OK {
        0
    } else if status < 0 {
        -status
    } else {
        status
    }
}

fn stdout_mismatch_return_code(stdout: &[u8]) -> i32 {
    if stdout.is_empty() {
        return 2;
    }
    if stdout.len() != LINUX_HELLO_EXPECTED_STDOUT.len() {
        return 100 + i32::try_from(core::cmp::min(stdout.len(), 99)).unwrap_or(99);
    }
    let mismatch_index = stdout
        .iter()
        .zip(LINUX_HELLO_EXPECTED_STDOUT.iter())
        .position(|(got, want)| got != want)
        .unwrap_or(LINUX_HELLO_EXPECTED_STDOUT.len());
    200 + i32::try_from(core::cmp::min(mismatch_index, 99)).unwrap_or(99)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, zx_status_t> {
    let end = offset.checked_add(2).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    let slice = bytes.get(offset..end).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, zx_status_t> {
    let end = offset.checked_add(4).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    let slice = bytes.get(offset..end).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, zx_status_t> {
    let end = offset.checked_add(8).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    let slice = bytes.get(offset..end).ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}
