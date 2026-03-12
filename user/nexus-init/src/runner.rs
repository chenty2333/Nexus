use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::rights::ZX_RIGHT_SAME_RIGHTS;
use axle_types::status::{ZX_ERR_INTERNAL, ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED, ZX_OK};
use axle_types::{zx_handle_t, zx_status_t};
use libax::compat::{
    ax_process_prepare_start, zx_channel_create, zx_channel_write, zx_handle_close,
    zx_handle_duplicate, zx_process_create, zx_process_start, zx_socket_create, zx_task_kill,
    zx_thread_create,
};
use nexus_component::{
    CapabilityKind, ComponentDecl, ComponentStartInfo, EncodedMessage, NamespaceEntry,
    NumberedHandle, ResolvedComponent,
};
use nexus_io::{FdOps, OpenFlags, VmoFlags};

use crate::resolver::lookup_use_decl;
use crate::{
    CHILD_MARKER_STARNIX_KERNEL, STARNIX_KERNEL_BINARY_PATH, STARTUP_HANDLE_COMPONENT_STATUS,
    STARTUP_HANDLE_STARNIX_IMAGE_VMO, STARTUP_HANDLE_STARNIX_PARENT_PROCESS,
    STARTUP_HANDLE_STARNIX_STDOUT,
};

#[allow(dead_code)]
pub(crate) struct RunningComponent {
    pub(crate) process: zx_handle_t,
    pub(crate) controller: zx_handle_t,
    pub(crate) status: zx_handle_t,
    pub(crate) stdout: Option<zx_handle_t>,
}

pub(crate) struct RunnerRegistry {
    elf_runners: Vec<(String, ElfRunner)>,
    starnix_runners: Vec<(String, StarnixRunner)>,
}

impl RunnerRegistry {
    pub(crate) fn new() -> Self {
        Self {
            elf_runners: Vec::new(),
            starnix_runners: Vec::new(),
        }
    }

    pub(crate) fn insert_elf(&mut self, name: &str, runner: ElfRunner) {
        self.elf_runners.push((String::from(name), runner));
    }

    pub(crate) fn insert_starnix(&mut self, name: &str, runner: StarnixRunner) {
        self.starnix_runners.push((String::from(name), runner));
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
        if let Some(runner) = self
            .elf_runners
            .iter()
            .find(|(name, _)| name == runner_name)
            .map(|(_, runner)| runner)
        {
            return runner.launch(component, namespace_entries, outgoing_dir, child_marker);
        }
        if let Some(runner) = self
            .starnix_runners
            .iter()
            .find(|(name, _)| name == runner_name)
            .map(|(_, runner)| runner)
        {
            return runner.launch(component, namespace_entries, outgoing_dir, child_marker);
        }
        Err(ZX_ERR_NOT_FOUND)
    }
}

#[derive(Clone)]
pub(crate) struct ElfRunner {
    pub(crate) parent_process: zx_handle_t,
    pub(crate) boot_root: Arc<dyn FdOps>,
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
        let image = open_binary(&*self.boot_root, component.decl.program.binary.as_str())?;
        let image_vmo = image.as_vmo(VmoFlags::READ | VmoFlags::EXECUTE)?;
        let start_info = ComponentStartInfo {
            args: component.decl.program.args.clone(),
            env: component.decl.program.env.clone(),
            namespace_entries,
            numbered_handles: vec![NumberedHandle {
                id: STARTUP_HANDLE_COMPONENT_STATUS,
                handle: ZX_HANDLE_INVALID,
            }],
            outgoing_dir_server_end: outgoing_dir,
            controller_channel: None,
        };
        launch_native_binary(self.parent_process, image_vmo, start_info, child_marker)
    }
}

#[derive(Clone)]
pub(crate) struct StarnixRunner {
    pub(crate) parent_process: zx_handle_t,
    pub(crate) boot_root: Arc<dyn FdOps>,
}

impl StarnixRunner {
    fn launch(
        &self,
        component: &ResolvedComponent,
        namespace_entries: Vec<NamespaceEntry>,
        outgoing_dir: Option<zx_handle_t>,
        _child_marker: u64,
    ) -> Result<RunningComponent, zx_status_t> {
        if component.decl.program.runner != "starnix" {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        let executive = open_binary(&*self.boot_root, STARNIX_KERNEL_BINARY_PATH)?;
        let executive_vmo = executive.as_vmo(VmoFlags::READ | VmoFlags::EXECUTE)?;
        let linux_image = open_binary(&*self.boot_root, component.decl.program.binary.as_str())?;
        let linux_image_vmo = linux_image.as_vmo(VmoFlags::READ | VmoFlags::EXECUTE)?;
        let mut parent_process_dup = ZX_HANDLE_INVALID;
        let duplicate_status = zx_handle_duplicate(
            self.parent_process,
            ZX_RIGHT_SAME_RIGHTS,
            &mut parent_process_dup,
        );
        if duplicate_status != ZX_OK {
            let _ = zx_handle_close(linux_image_vmo);
            let _ = zx_handle_close(executive_vmo);
            return Err(duplicate_status);
        }
        let mut stdout_parent = ZX_HANDLE_INVALID;
        let mut stdout_child = ZX_HANDLE_INVALID;
        let stdout_status = zx_socket_create(0, &mut stdout_parent, &mut stdout_child);
        if stdout_status != ZX_OK {
            let _ = zx_handle_close(parent_process_dup);
            let _ = zx_handle_close(linux_image_vmo);
            let _ = zx_handle_close(executive_vmo);
            return Err(stdout_status);
        }
        let start_info = ComponentStartInfo {
            args: component.decl.program.args.clone(),
            env: component.decl.program.env.clone(),
            namespace_entries,
            numbered_handles: vec![
                NumberedHandle {
                    id: STARTUP_HANDLE_COMPONENT_STATUS,
                    handle: ZX_HANDLE_INVALID,
                },
                NumberedHandle {
                    id: STARTUP_HANDLE_STARNIX_IMAGE_VMO,
                    handle: linux_image_vmo,
                },
                NumberedHandle {
                    id: STARTUP_HANDLE_STARNIX_PARENT_PROCESS,
                    handle: parent_process_dup,
                },
                NumberedHandle {
                    id: STARTUP_HANDLE_STARNIX_STDOUT,
                    handle: stdout_child,
                },
            ],
            outgoing_dir_server_end: outgoing_dir,
            controller_channel: None,
        };
        match launch_native_binary(
            self.parent_process,
            executive_vmo,
            start_info,
            CHILD_MARKER_STARNIX_KERNEL,
        ) {
            Ok(mut running) => {
                running.stdout = Some(stdout_parent);
                Ok(running)
            }
            Err(status) => {
                let _ = zx_handle_close(stdout_parent);
                Err(status)
            }
        }
    }
}

fn open_binary(boot_root: &dyn FdOps, path: &str) -> Result<Arc<dyn FdOps>, zx_status_t> {
    boot_root
        .openat(path, OpenFlags::READABLE)
        .map_err(|status| {
            if status == axle_types::status::ZX_ERR_NOT_DIR {
                ZX_ERR_NOT_FOUND
            } else {
                status
            }
        })
}

fn launch_native_binary(
    parent_process: zx_handle_t,
    image_vmo: zx_handle_t,
    mut start_info: ComponentStartInfo,
    child_marker: u64,
) -> Result<RunningComponent, zx_status_t> {
    let mut process = ZX_HANDLE_INVALID;
    let mut root_vmar = ZX_HANDLE_INVALID;
    let status = zx_process_create(parent_process, 0, &mut process, &mut root_vmar);
    if status != ZX_OK {
        return Err(status);
    }

    let mut thread = ZX_HANDLE_INVALID;
    let status = zx_thread_create(process, 0, &mut thread);
    if status != ZX_OK {
        let _ = zx_handle_close(root_vmar);
        let _ = zx_handle_close(process);
        return Err(status);
    }

    let mut ignored_entry = 0u64;
    let mut stack = 0u64;
    let status = ax_process_prepare_start(process, image_vmo, 0, &mut ignored_entry, &mut stack);
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

    for entry in &mut start_info.numbered_handles {
        if entry.id == STARTUP_HANDLE_COMPONENT_STATUS {
            entry.handle = status_child;
        }
    }
    start_info.controller_channel = Some(controller_child);

    let encoded = start_info.encode_channel_message();
    let child_stack = stack.checked_sub(8).ok_or(ZX_ERR_INTERNAL)?;
    let start_status = zx_process_start(
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

    let write_status = write_bootstrap_message(bootstrap_parent, &encoded);
    let _ = zx_handle_close(bootstrap_parent);
    let _ = zx_handle_close(bootstrap_child);
    if write_status != ZX_OK {
        let _ = zx_task_kill(process);
        let _ = zx_handle_close(status_parent);
        let _ = zx_handle_close(controller_parent);
        let _ = zx_handle_close(process);
        return Err(write_status);
    }

    Ok(RunningComponent {
        process,
        controller: controller_parent,
        status: status_parent,
        stdout: None,
    })
}

fn write_bootstrap_message(handle: zx_handle_t, encoded: &EncodedMessage) -> zx_status_t {
    zx_channel_write(
        handle,
        0,
        encoded.bytes.as_ptr(),
        encoded.bytes.len() as u32,
        if encoded.handles.is_empty() {
            core::ptr::null()
        } else {
            encoded.handles.as_ptr()
        },
        encoded.handles.len() as u32,
    )
}
