use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::status::{ZX_ERR_INTERNAL, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED, ZX_OK};
use axle_types::syscall_numbers::{
    AXLE_SYS_AX_PROCESS_PREPARE_START, AXLE_SYS_PROCESS_CREATE, AXLE_SYS_PROCESS_START,
    AXLE_SYS_TASK_KILL, AXLE_SYS_THREAD_CREATE,
};
use axle_types::{zx_handle_t, zx_status_t};
use libzircon::{zx_channel_create, zx_channel_write, zx_handle_close};
use nexus_component::{
    CapabilityKind, ComponentDecl, ComponentStartInfo, NamespaceEntry, NumberedHandle,
    ResolvedComponent,
};

use crate::resolver::lookup_use_decl;
use crate::{SELF_BINARY_PATH, STARTUP_HANDLE_COMPONENT_STATUS};

#[allow(dead_code)]
pub(crate) struct RunningComponent {
    pub(crate) process: zx_handle_t,
    pub(crate) controller: zx_handle_t,
    pub(crate) status: zx_handle_t,
}

pub(crate) struct RunnerRegistry {
    elf_runners: Vec<(String, ElfRunner)>,
}

impl RunnerRegistry {
    pub(crate) fn new() -> Self {
        Self {
            elf_runners: Vec::new(),
        }
    }

    pub(crate) fn insert_elf(&mut self, name: &str, runner: ElfRunner) {
        self.elf_runners.push((String::from(name), runner));
    }

    pub(crate) fn launch(
        &self,
        realm: &ComponentDecl,
        component: &ResolvedComponent,
        namespace_entries: Vec<NamespaceEntry>,
        outgoing_dir: Option<zx_handle_t>,
        child_marker: u64,
    ) -> Result<RunningComponent, zx_status_t> {
        let runner_name = component.decl.program.runner.as_str();
        lookup_use_decl(realm, CapabilityKind::Runner, Some(runner_name))?;
        let runner = self
            .elf_runners
            .iter()
            .find(|(name, _)| name == runner_name)
            .map(|(_, runner)| runner)
            .ok_or(ZX_ERR_NOT_FOUND)?;
        runner.launch(component, namespace_entries, outgoing_dir, child_marker)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ElfRunner {
    pub(crate) parent_process: zx_handle_t,
    pub(crate) image_vmo: zx_handle_t,
}

impl ElfRunner {
    fn launch(
        &self,
        component: &ResolvedComponent,
        namespace_entries: Vec<NamespaceEntry>,
        outgoing_dir: Option<zx_handle_t>,
        child_marker: u64,
    ) -> Result<RunningComponent, zx_status_t> {
        if component.decl.program.runner != "elf" {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        if component.decl.program.binary != SELF_BINARY_PATH {
            return Err(ZX_ERR_NOT_FOUND);
        }

        let mut process = ZX_HANDLE_INVALID;
        let mut root_vmar = ZX_HANDLE_INVALID;
        let status = ax_process_create(self.parent_process, 0, &mut process, &mut root_vmar);
        if status != ZX_OK {
            return Err(status);
        }

        let mut thread = ZX_HANDLE_INVALID;
        let status = ax_thread_create(process, 0, &mut thread);
        if status != ZX_OK {
            let _ = zx_handle_close(root_vmar);
            let _ = zx_handle_close(process);
            return Err(status);
        }

        let mut ignored_entry = 0u64;
        let mut stack = 0u64;
        let status =
            ax_process_prepare_start(process, self.image_vmo, 0, &mut ignored_entry, &mut stack);
        if status != ZX_OK {
            let _ = zx_handle_close(thread);
            let _ = zx_handle_close(root_vmar);
            let _ = zx_handle_close(process);
            return Err(status);
        }

        let mut bootstrap_parent = ZX_HANDLE_INVALID;
        let mut bootstrap_child = ZX_HANDLE_INVALID;
        let status = zx_channel_create(0, &mut bootstrap_parent, &mut bootstrap_child);
        if status != ZX_OK {
            let _ = zx_handle_close(thread);
            let _ = zx_handle_close(root_vmar);
            let _ = zx_handle_close(process);
            return Err(status);
        }

        let mut controller_parent = ZX_HANDLE_INVALID;
        let mut controller_child = ZX_HANDLE_INVALID;
        let status = zx_channel_create(0, &mut controller_parent, &mut controller_child);
        if status != ZX_OK {
            let _ = zx_handle_close(bootstrap_parent);
            let _ = zx_handle_close(bootstrap_child);
            let _ = zx_handle_close(thread);
            let _ = zx_handle_close(root_vmar);
            let _ = zx_handle_close(process);
            return Err(status);
        }

        let mut status_parent = ZX_HANDLE_INVALID;
        let mut status_child = ZX_HANDLE_INVALID;
        let status = zx_channel_create(0, &mut status_parent, &mut status_child);
        if status != ZX_OK {
            let _ = zx_handle_close(controller_parent);
            let _ = zx_handle_close(controller_child);
            let _ = zx_handle_close(bootstrap_parent);
            let _ = zx_handle_close(bootstrap_child);
            let _ = zx_handle_close(thread);
            let _ = zx_handle_close(root_vmar);
            let _ = zx_handle_close(process);
            return Err(status);
        }

        let start_info = ComponentStartInfo {
            args: component.decl.program.args.clone(),
            env: component.decl.program.env.clone(),
            namespace_entries,
            numbered_handles: vec![NumberedHandle {
                id: STARTUP_HANDLE_COMPONENT_STATUS,
                handle: status_child,
            }],
            outgoing_dir_server_end: outgoing_dir,
            controller_channel: Some(controller_child),
        };
        let child_stack = stack.checked_sub(8).ok_or(ZX_ERR_INTERNAL)?;
        let start_status = ax_process_start(
            process,
            thread,
            ignored_entry,
            child_stack,
            bootstrap_child,
            child_marker,
        );
        let _ = zx_handle_close(thread);
        let _ = zx_handle_close(root_vmar);
        if start_status != ZX_OK {
            let _ = zx_handle_close(bootstrap_parent);
            let _ = zx_handle_close(bootstrap_child);
            let _ = zx_handle_close(controller_parent);
            let _ = zx_handle_close(status_parent);
            let _ = zx_handle_close(process);
            return Err(start_status);
        }

        let encoded = start_info.encode_channel_message();
        let write_status = zx_channel_write(
            bootstrap_parent,
            0,
            encoded.bytes.as_ptr(),
            encoded.bytes.len() as u32,
            if encoded.handles.is_empty() {
                core::ptr::null()
            } else {
                encoded.handles.as_ptr()
            },
            encoded.handles.len() as u32,
        );
        let _ = zx_handle_close(bootstrap_parent);
        let _ = zx_handle_close(bootstrap_child);
        if write_status != ZX_OK {
            let _ = ax_task_kill(process);
            let _ = zx_handle_close(status_parent);
            let _ = zx_handle_close(controller_parent);
            let _ = zx_handle_close(process);
            return Err(write_status);
        }

        Ok(RunningComponent {
            process,
            controller: controller_parent,
            status: status_parent,
        })
    }
}

fn ax_process_create(
    parent_process: zx_handle_t,
    options: u32,
    out_process: &mut zx_handle_t,
    out_root_vmar: &mut zx_handle_t,
) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(
        AXLE_SYS_PROCESS_CREATE as u64,
        [
            parent_process as u64,
            0,
            0,
            options as u64,
            out_process as *mut zx_handle_t as u64,
            out_root_vmar as *mut zx_handle_t as u64,
        ],
    )
}

fn ax_thread_create(
    process: zx_handle_t,
    options: u32,
    out_thread: &mut zx_handle_t,
) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(
        AXLE_SYS_THREAD_CREATE as u64,
        [
            process as u64,
            0,
            0,
            options as u64,
            out_thread as *mut zx_handle_t as u64,
            0,
        ],
    )
}

fn ax_process_prepare_start(
    process: zx_handle_t,
    image_vmo: zx_handle_t,
    options: u32,
    out_entry: &mut u64,
    out_stack: &mut u64,
) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(
        AXLE_SYS_AX_PROCESS_PREPARE_START as u64,
        [
            process as u64,
            image_vmo as u64,
            options as u64,
            out_entry as *mut u64 as u64,
            out_stack as *mut u64 as u64,
            0,
        ],
    )
}

fn ax_process_start(
    process: zx_handle_t,
    thread: zx_handle_t,
    entry: u64,
    stack: u64,
    bootstrap_channel: zx_handle_t,
    arg1: u64,
) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(
        AXLE_SYS_PROCESS_START as u64,
        [
            process as u64,
            thread as u64,
            entry,
            stack,
            bootstrap_channel as u64,
            arg1,
        ],
    )
}

fn ax_task_kill(handle: zx_handle_t) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(AXLE_SYS_TASK_KILL as u64, [handle as u64, 0, 0, 0, 0, 0])
}
