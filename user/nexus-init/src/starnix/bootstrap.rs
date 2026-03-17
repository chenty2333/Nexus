use super::*;

use nexus_component::{ComponentStartInfo, NumberedHandle};

use crate::lifecycle::{read_channel_alloc_blocking, send_controller_event, send_status_event};
use crate::services::{BootAssetEntry, BootstrapNamespace};
struct StarnixStartInfo {
    args: Vec<String>,
    env: Vec<String>,
    parent_process: zx_handle_t,
    linux_image_vmo: zx_handle_t,
    stdout_handle: Option<zx_handle_t>,
    status_handle: Option<zx_handle_t>,
    controller_handle: Option<zx_handle_t>,
}

struct ExecutiveBootstrapCleanup {
    parent_process: zx_handle_t,
    linux_image_vmo: zx_handle_t,
    port: zx_handle_t,
    stdout_handle: Option<zx_handle_t>,
}

impl ExecutiveBootstrapCleanup {
    const fn new(
        parent_process: zx_handle_t,
        linux_image_vmo: zx_handle_t,
        stdout_handle: Option<zx_handle_t>,
    ) -> Self {
        Self {
            parent_process,
            linux_image_vmo,
            port: ZX_HANDLE_INVALID,
            stdout_handle,
        }
    }
}

impl Drop for ExecutiveBootstrapCleanup {
    fn drop(&mut self) {
        if let Some(handle) = self.stdout_handle.take() {
            let _ = zx_handle_close(handle);
        }
        if self.port != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(self.port);
        }
        if self.linux_image_vmo != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(self.linux_image_vmo);
        }
        if self.parent_process != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(self.parent_process);
        }
    }
}

pub(in crate::starnix) fn program_start(bootstrap_channel: zx_handle_t) -> ! {
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

fn read_start_info(bootstrap_channel: zx_handle_t) -> Result<StarnixStartInfo, zx_status_t> {
    let (bytes, handles) = read_channel_alloc_blocking(bootstrap_channel)?;
    let start_info = ComponentStartInfo::decode_channel_message(&bytes, &handles)
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

fn build_starnix_namespace() -> Result<nexus_io::ProcessNamespace, zx_status_t> {
    let mut assets = Vec::new();
    if !LINUX_HELLO_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_HELLO_BINARY_PATH,
            LINUX_HELLO_BYTES,
        ));
    }
    if !LINUX_FD_SMOKE_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_FD_SMOKE_BINARY_PATH,
            LINUX_FD_SMOKE_BYTES,
        ));
    }
    if !LINUX_ROUND2_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND2_BINARY_PATH,
            LINUX_ROUND2_BYTES,
        ));
    }
    if !LINUX_ROUND3_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND3_BINARY_PATH,
            LINUX_ROUND3_BYTES,
        ));
    }
    if !LINUX_ROUND4_FUTEX_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND4_FUTEX_BINARY_PATH,
            LINUX_ROUND4_FUTEX_BYTES,
        ));
    }
    if !LINUX_ROUND4_SIGNAL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND4_SIGNAL_BINARY_PATH,
            LINUX_ROUND4_SIGNAL_BYTES,
        ));
    }
    if !LINUX_ROUND5_EPOLL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND5_EPOLL_BINARY_PATH,
            LINUX_ROUND5_EPOLL_BYTES,
        ));
    }
    if !LINUX_ROUND6_EVENTFD_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_EVENTFD_BINARY_PATH,
            LINUX_ROUND6_EVENTFD_BYTES,
        ));
    }
    if !LINUX_ROUND6_TIMERFD_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_TIMERFD_BINARY_PATH,
            LINUX_ROUND6_TIMERFD_BYTES,
        ));
    }
    if !LINUX_ROUND6_SIGNALFD_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_SIGNALFD_BINARY_PATH,
            LINUX_ROUND6_SIGNALFD_BYTES,
        ));
    }
    if !LINUX_ROUND6_FUTEX_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_FUTEX_BINARY_PATH,
            LINUX_ROUND6_FUTEX_BYTES,
        ));
    }
    if !LINUX_ROUND6_SCM_RIGHTS_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_SCM_RIGHTS_BINARY_PATH,
            LINUX_ROUND6_SCM_RIGHTS_BYTES,
        ));
    }
    if !LINUX_ROUND6_PIDFD_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_PIDFD_BINARY_PATH,
            LINUX_ROUND6_PIDFD_BYTES,
        ));
    }
    if !LINUX_ROUND6_PROC_JOB_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_PROC_JOB_BINARY_PATH,
            LINUX_ROUND6_PROC_JOB_BYTES,
        ));
    }
    if !LINUX_ROUND6_PROC_CONTROL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_PROC_CONTROL_BINARY_PATH,
            LINUX_ROUND6_PROC_CONTROL_BYTES,
        ));
    }
    if !LINUX_ROUND6_PROC_TTY_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_ROUND6_PROC_TTY_BINARY_PATH,
            LINUX_ROUND6_PROC_TTY_BYTES,
        ));
    }
    if !LINUX_RUNTIME_FD_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_FD_BINARY_PATH,
            LINUX_RUNTIME_FD_BYTES,
        ));
    }
    if !LINUX_RUNTIME_MISC_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_MISC_BINARY_PATH,
            LINUX_RUNTIME_MISC_BYTES,
        ));
    }
    if !LINUX_RUNTIME_PROCESS_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_PROCESS_BINARY_PATH,
            LINUX_RUNTIME_PROCESS_BYTES,
        ));
    }
    if !LINUX_RUNTIME_FS_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_FS_BINARY_PATH,
            LINUX_RUNTIME_FS_BYTES,
        ));
    }
    if !LINUX_RUNTIME_TLS_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_RUNTIME_TLS_BINARY_PATH,
            LINUX_RUNTIME_TLS_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_ELF_SMOKE_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_ELF_SMOKE_BINARY_PATH,
            LINUX_DYNAMIC_ELF_SMOKE_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_MAIN_BINARY_PATH,
            LINUX_DYNAMIC_MAIN_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_INTERP_BINARY_PATH,
            LINUX_DYNAMIC_INTERP_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_TLS_SMOKE_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_TLS_SMOKE_BINARY_PATH,
            LINUX_DYNAMIC_TLS_SMOKE_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_TLS_MAIN_BINARY_PATH,
            LINUX_DYNAMIC_TLS_MAIN_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_TLS_INTERP_BINARY_PATH,
            LINUX_DYNAMIC_TLS_INTERP_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_RUNTIME_SMOKE_BINARY_PATH,
            LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_RUNTIME_MAIN_BINARY_PATH,
            LINUX_DYNAMIC_RUNTIME_MAIN_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_RUNTIME_INTERP_BINARY_PATH,
            LINUX_DYNAMIC_RUNTIME_INTERP_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_PIE_SMOKE_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_PIE_SMOKE_BINARY_PATH,
            LINUX_DYNAMIC_PIE_SMOKE_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_PIE_MAIN_BINARY_PATH,
            LINUX_DYNAMIC_PIE_MAIN_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_DYNAMIC_PIE_INTERP_BINARY_PATH,
            LINUX_DYNAMIC_PIE_INTERP_BYTES,
        ));
    }
    if !LINUX_GLIBC_HELLO_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            LINUX_GLIBC_HELLO_BINARY_PATH,
            LINUX_GLIBC_HELLO_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_GLIBC_RUNTIME_INTERP_BINARY_PATH,
            LINUX_GLIBC_RUNTIME_INTERP_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            LINUX_GLIBC_RUNTIME_LIBC_BINARY_PATH,
            LINUX_GLIBC_RUNTIME_LIBC_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            crate::LINUX_GLIBC_RUNTIME_INTERP_CANONICAL_PATH,
            LINUX_GLIBC_RUNTIME_INTERP_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            crate::LINUX_GLIBC_RUNTIME_INTERP_LIB64_PATH,
            LINUX_GLIBC_RUNTIME_INTERP_BYTES,
        ));
        assets.push(BootAssetEntry::bytes(
            crate::LINUX_GLIBC_RUNTIME_LIBC_LIB64_PATH,
            LINUX_GLIBC_RUNTIME_LIBC_BYTES,
        ));
    }
    if !LINUX_HELLO_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-hello.nxcd",
            LINUX_HELLO_DECL_BYTES,
        ));
    }
    if !LINUX_FD_SMOKE_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-fd-smoke.nxcd",
            LINUX_FD_SMOKE_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND2_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round2-smoke.nxcd",
            LINUX_ROUND2_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND3_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round3-smoke.nxcd",
            LINUX_ROUND3_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND4_FUTEX_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round4-futex-smoke.nxcd",
            LINUX_ROUND4_FUTEX_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND4_SIGNAL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round4-signal-smoke.nxcd",
            LINUX_ROUND4_SIGNAL_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND5_EPOLL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round5-epoll-smoke.nxcd",
            LINUX_ROUND5_EPOLL_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_EVENTFD_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-eventfd-smoke.nxcd",
            LINUX_ROUND6_EVENTFD_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_TIMERFD_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-timerfd-smoke.nxcd",
            LINUX_ROUND6_TIMERFD_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_SIGNALFD_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-signalfd-smoke.nxcd",
            LINUX_ROUND6_SIGNALFD_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_FUTEX_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-futex-smoke.nxcd",
            LINUX_ROUND6_FUTEX_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_SCM_RIGHTS_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-scm-rights-smoke.nxcd",
            LINUX_ROUND6_SCM_RIGHTS_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_PIDFD_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-pidfd-smoke.nxcd",
            LINUX_ROUND6_PIDFD_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_PROC_JOB_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-proc-job-smoke.nxcd",
            LINUX_ROUND6_PROC_JOB_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_PROC_CONTROL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-proc-control-smoke.nxcd",
            LINUX_ROUND6_PROC_CONTROL_DECL_BYTES,
        ));
    }
    if !LINUX_ROUND6_PROC_TTY_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-round6-proc-tty-smoke.nxcd",
            LINUX_ROUND6_PROC_TTY_DECL_BYTES,
        ));
    }
    if !LINUX_RUNTIME_MISC_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-runtime-misc-smoke.nxcd",
            LINUX_RUNTIME_MISC_DECL_BYTES,
        ));
    }
    if !LINUX_RUNTIME_PROCESS_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-runtime-process-smoke.nxcd",
            LINUX_RUNTIME_PROCESS_DECL_BYTES,
        ));
    }
    if !LINUX_RUNTIME_FS_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-runtime-fs-smoke.nxcd",
            LINUX_RUNTIME_FS_DECL_BYTES,
        ));
    }
    if !LINUX_RUNTIME_TLS_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-runtime-tls-smoke.nxcd",
            LINUX_RUNTIME_TLS_DECL_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_RUNTIME_SMOKE_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-dynamic-runtime-smoke.nxcd",
            LINUX_DYNAMIC_RUNTIME_SMOKE_DECL_BYTES,
        ));
    }
    if !LINUX_DYNAMIC_PIE_SMOKE_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-dynamic-pie-smoke.nxcd",
            LINUX_DYNAMIC_PIE_SMOKE_DECL_BYTES,
        ));
    }
    if !LINUX_GLIBC_HELLO_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-glibc-hello.nxcd",
            LINUX_GLIBC_HELLO_DECL_BYTES,
        ));
    }
    let bootstrap = BootstrapNamespace::build(&assets)?;
    let mut mounts = bootstrap.namespace().mounts().clone();
    mounts.insert("/", bootstrap.boot_root())?;
    Ok(nexus_io::ProcessNamespace::new(mounts))
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
    let mut cleanup =
        ExecutiveBootstrapCleanup::new(parent_process, linux_image_vmo, stdout_handle);
    let namespace = match build_starnix_namespace() {
        Ok(namespace) => namespace,
        Err(status) => return map_status_to_return_code(status),
    };
    let (payload_path, payload_bytes) = match resolve_exec_payload_source(&namespace, &args) {
        Ok(payload) => payload,
        Err(status) => return map_status_to_return_code(status),
    };
    let mut port = ZX_HANDLE_INVALID;
    if zx_port_create(0, &mut port) != ZX_OK {
        return 1;
    }
    cleanup.port = port;
    let mut stack_random_state = seed_runtime_random_state(parent_process, port, 1);
    let mut stack_random = [0u8; 16];
    fill_random_bytes(&mut stack_random_state, &mut stack_random);
    let task_image = match build_task_image(
        payload_path.as_str(),
        &args,
        &env,
        payload_bytes.as_slice(),
        stack_random,
        |interp_path| {
            read_exec_image_bytes_from_namespace(&namespace, interp_path)
                .map(|(_resolved, bytes)| bytes)
        },
    ) {
        Ok(image) => image,
        Err(status) => return map_status_to_return_code(status),
    };
    let prepared = match prepare_process_carrier(
        parent_process,
        port,
        STARNIX_GUEST_PACKET_KEY,
        linux_image_vmo,
        &task_image.exec_blob,
    ) {
        Ok(prepared) => prepared,
        Err(status) => return map_status_to_return_code(status),
    };
    let _ = zx_handle_close(linux_image_vmo);
    cleanup.linux_image_vmo = ZX_HANDLE_INVALID;
    let stdout_handle = cleanup.stdout_handle.take();
    let mut resources = match ProcessResources::new(
        prepared.process_handle,
        prepared.root_vmar,
        stdout_handle,
        namespace,
    ) {
        Ok(resources) => resources,
        Err(status) => {
            prepared.close();
            return map_status_to_return_code(status);
        }
    };
    if let Err(status) = resources.install_exec_writable_ranges(&task_image.writable_ranges) {
        prepared.close();
        return map_status_to_return_code(status);
    }
    match resources.install_initial_tls(prepared.carrier.session_handle, &task_image) {
        Ok(Some(fs_base)) => {
            if let Err(status) = zx_status_result(ax_thread_set_guest_x64_fs_base(
                prepared.carrier.thread_handle,
                fs_base,
                0,
            )) {
                prepared.close();
                return map_status_to_return_code(status);
            }
        }
        Ok(None) => {}
        Err(status) => {
            prepared.close();
            return map_status_to_return_code(status);
        }
    }
    let regs = linux_guest_initial_regs(prepared.prepared_entry, prepared.prepared_stack);
    let (resources, carrier) = match start_prepared_carrier_guest(prepared, &regs, resources) {
        Ok(started) => started,
        Err(status) => return map_status_to_return_code(status),
    };
    let root_task = LinuxTask {
        tid: 1,
        tgid: 1,
        carrier,
        state: TaskState::Running,
        signals: TaskSignals::default(),
        clear_child_tid: 0,
        robust_list: None,
        active_signal: None,
    };
    let mut task_ids = BTreeSet::new();
    task_ids.insert(1);
    let root_group = LinuxThreadGroup {
        tgid: 1,
        leader_tid: 1,
        parent_tgid: None,
        pgid: 1,
        sid: 1,
        child_tgids: BTreeSet::new(),
        task_ids,
        state: ThreadGroupState::Running,
        last_stop_signal: None,
        stop_wait_pending: false,
        continued_wait_pending: false,
        shared_pending: 0,
        sigchld_info: None,
        sigactions: BTreeMap::new(),
        image: Some(task_image),
        resources: Some(resources),
    };
    let mut kernel = StarnixKernel::new(parent_process, port, root_task, root_group);
    kernel.run()
}

// Legacy embedded smoke payloads remain only as a bootstrap fallback while
// production exec is resolved from the startup namespace.
fn bootstrap_payload_bytes_for(args: &[String]) -> Option<&'static [u8]> {
    match args.first().map(String::as_str) {
        Some("linux-hello") | None => Some(LINUX_HELLO_BYTES),
        Some("linux-fd-smoke") => Some(LINUX_FD_SMOKE_BYTES),
        Some("linux-round2-smoke") => Some(LINUX_ROUND2_BYTES),
        Some("linux-round3-smoke") => Some(LINUX_ROUND3_BYTES),
        Some("linux-round4-futex-smoke") => Some(LINUX_ROUND4_FUTEX_BYTES),
        Some("linux-round4-signal-smoke") => Some(LINUX_ROUND4_SIGNAL_BYTES),
        Some("linux-round5-epoll-smoke") => Some(LINUX_ROUND5_EPOLL_BYTES),
        Some("linux-round6-eventfd-smoke") => Some(LINUX_ROUND6_EVENTFD_BYTES),
        Some("linux-round6-timerfd-smoke") => Some(LINUX_ROUND6_TIMERFD_BYTES),
        Some("linux-round6-signalfd-smoke") => Some(LINUX_ROUND6_SIGNALFD_BYTES),
        Some("linux-round6-futex-smoke") => Some(LINUX_ROUND6_FUTEX_BYTES),
        Some("linux-round6-scm-rights-smoke") => Some(LINUX_ROUND6_SCM_RIGHTS_BYTES),
        Some("linux-round6-pidfd-smoke") => Some(LINUX_ROUND6_PIDFD_BYTES),
        Some("linux-round6-proc-job-smoke") => Some(LINUX_ROUND6_PROC_JOB_BYTES),
        Some("linux-round6-proc-control-smoke") => Some(LINUX_ROUND6_PROC_CONTROL_BYTES),
        Some("linux-round6-proc-tty-smoke") => Some(LINUX_ROUND6_PROC_TTY_BYTES),
        Some("linux-runtime-fd-smoke") => Some(LINUX_RUNTIME_FD_BYTES),
        Some("linux-runtime-misc-smoke") => Some(LINUX_RUNTIME_MISC_BYTES),
        Some("linux-runtime-process-smoke") => Some(LINUX_RUNTIME_PROCESS_BYTES),
        Some("linux-runtime-fs-smoke") => Some(LINUX_RUNTIME_FS_BYTES),
        Some("linux-runtime-tls-smoke") => Some(LINUX_RUNTIME_TLS_BYTES),
        Some("linux-dynamic-elf-smoke") => Some(LINUX_DYNAMIC_ELF_SMOKE_BYTES),
        Some("linux-dynamic-tls-smoke") => Some(LINUX_DYNAMIC_TLS_SMOKE_BYTES),
        Some("linux-dynamic-runtime-smoke") => Some(LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES),
        Some("linux-dynamic-pie-smoke") => Some(LINUX_DYNAMIC_PIE_SMOKE_BYTES),
        Some("linux-glibc-hello") => Some(LINUX_GLIBC_HELLO_BYTES),
        Some(_) => None,
    }
}

fn bootstrap_payload_path_for(args: &[String]) -> Option<&'static str> {
    match args.first().map(String::as_str) {
        Some("linux-hello") | None => Some(LINUX_HELLO_BINARY_PATH),
        Some("linux-fd-smoke") => Some(LINUX_FD_SMOKE_BINARY_PATH),
        Some("linux-round2-smoke") => Some(LINUX_ROUND2_BINARY_PATH),
        Some("linux-round3-smoke") => Some(LINUX_ROUND3_BINARY_PATH),
        Some("linux-round4-futex-smoke") => Some(LINUX_ROUND4_FUTEX_BINARY_PATH),
        Some("linux-round4-signal-smoke") => Some(LINUX_ROUND4_SIGNAL_BINARY_PATH),
        Some("linux-round5-epoll-smoke") => Some(LINUX_ROUND5_EPOLL_BINARY_PATH),
        Some("linux-round6-eventfd-smoke") => Some(LINUX_ROUND6_EVENTFD_BINARY_PATH),
        Some("linux-round6-timerfd-smoke") => Some(LINUX_ROUND6_TIMERFD_BINARY_PATH),
        Some("linux-round6-signalfd-smoke") => Some(LINUX_ROUND6_SIGNALFD_BINARY_PATH),
        Some("linux-round6-futex-smoke") => Some(LINUX_ROUND6_FUTEX_BINARY_PATH),
        Some("linux-round6-scm-rights-smoke") => Some(LINUX_ROUND6_SCM_RIGHTS_BINARY_PATH),
        Some("linux-round6-pidfd-smoke") => Some(LINUX_ROUND6_PIDFD_BINARY_PATH),
        Some("linux-round6-proc-job-smoke") => Some(LINUX_ROUND6_PROC_JOB_BINARY_PATH),
        Some("linux-round6-proc-control-smoke") => Some(LINUX_ROUND6_PROC_CONTROL_BINARY_PATH),
        Some("linux-round6-proc-tty-smoke") => Some(LINUX_ROUND6_PROC_TTY_BINARY_PATH),
        Some("linux-runtime-fd-smoke") => Some(LINUX_RUNTIME_FD_BINARY_PATH),
        Some("linux-runtime-misc-smoke") => Some(LINUX_RUNTIME_MISC_BINARY_PATH),
        Some("linux-runtime-process-smoke") => Some(LINUX_RUNTIME_PROCESS_BINARY_PATH),
        Some("linux-runtime-fs-smoke") => Some(LINUX_RUNTIME_FS_BINARY_PATH),
        Some("linux-runtime-tls-smoke") => Some(LINUX_RUNTIME_TLS_BINARY_PATH),
        Some("linux-dynamic-elf-smoke") => Some(LINUX_DYNAMIC_ELF_SMOKE_BINARY_PATH),
        Some("linux-dynamic-tls-smoke") => Some(LINUX_DYNAMIC_TLS_SMOKE_BINARY_PATH),
        Some("linux-dynamic-runtime-smoke") => Some(LINUX_DYNAMIC_RUNTIME_SMOKE_BINARY_PATH),
        Some("linux-dynamic-pie-smoke") => Some(LINUX_DYNAMIC_PIE_SMOKE_BINARY_PATH),
        Some("linux-glibc-hello") => Some(LINUX_GLIBC_HELLO_BINARY_PATH),
        Some(_) => None,
    }
}

fn requested_exec_path(args: &[String]) -> Option<String> {
    match args.first().map(String::as_str) {
        Some("") => None,
        Some(path) if path.contains('/') => Some(String::from(path)),
        Some(name) => Some(format!("bin/{name}")),
        None => None,
    }
}

fn resolve_exec_payload_source(
    namespace: &nexus_io::ProcessNamespace,
    args: &[String],
) -> Result<(String, Vec<u8>), zx_status_t> {
    if let Some(path) = requested_exec_path(args) {
        match read_exec_image_bytes_from_namespace(namespace, path.as_str()) {
            Ok(source) => return Ok(source),
            Err(ZX_ERR_NOT_FOUND | ZX_ERR_NOT_DIR | ZX_ERR_BAD_PATH) => {}
            Err(status) => return Err(status),
        }
    }

    let path = bootstrap_payload_path_for(args).ok_or(ZX_ERR_NOT_SUPPORTED)?;
    let bytes = bootstrap_payload_bytes_for(args).ok_or(ZX_ERR_NOT_SUPPORTED)?;
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    owned.extend_from_slice(bytes);
    let stored_path = namespace
        .resolve_path(path)
        .unwrap_or_else(|_| String::from(path));
    Ok((stored_path, owned))
}
