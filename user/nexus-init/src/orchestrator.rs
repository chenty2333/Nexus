use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::signals::{ZX_SOCKET_PEER_CLOSED, ZX_SOCKET_READABLE};
use axle_types::status::{ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_SHOULD_WAIT, ZX_OK};
use axle_types::{zx_handle_t, zx_status_t};
use libax::compat::{
    ZX_TIME_INFINITE, zx_channel_create, zx_handle_close, zx_object_wait_one, zx_socket_read,
    zx_task_kill,
};
use nexus_component::{ControllerRequest, NamespaceEntry, ResolvedComponent, StartupMode};
use nexus_io::{FdFlags, FdOps, FdTable, OpenFlags, ProcessNamespace, RemoteDir};

use crate::fs::{
    proxy_directory_requests_until_peer_closed, read_directory_request_for_launch,
    root_directory_descriptor, run_echo_fs_provider,
};
use crate::lifecycle::{
    MinimalRole, read_component_start_info_minimal, read_controller_event_blocking,
    read_controller_request_blocking, run_controller_lifecycle_step, send_controller_event,
    send_status_event,
};
use crate::namespace::{CapabilityRegistry, build_namespace_entries, publish_protocols};
use crate::resolver::{ResolverRegistry, resolve_root_child};
use crate::runner::{ElfRunner, RunnerRegistry, StarnixRunner};
use crate::services::{BootAssetEntry, BootstrapNamespace, run_socket_fd_smoke, run_tmpfs_smoke};
use crate::*;

const SLOT_COMPONENT_FAILURE_STEP: usize = 578;
const SLOT_COMPONENT_RESOLVE_ROOT: usize = 579;
const SLOT_COMPONENT_RESOLVE_PROVIDER: usize = 580;
const SLOT_COMPONENT_RESOLVE_CLIENT: usize = 581;
const SLOT_COMPONENT_PROVIDER_OUTGOING_PAIR: usize = 582;
const SLOT_COMPONENT_PROVIDER_LAUNCH: usize = 583;
const SLOT_COMPONENT_CLIENT_ROUTE: usize = 584;
const SLOT_COMPONENT_CLIENT_LAUNCH: usize = 585;
const SLOT_COMPONENT_PROVIDER_EVENT_READ: usize = 586;
const SLOT_COMPONENT_PROVIDER_EVENT_CODE: usize = 587;
const SLOT_COMPONENT_CLIENT_EVENT_READ: usize = 588;
const SLOT_COMPONENT_CLIENT_EVENT_CODE: usize = 589;
const SLOT_COMPONENT_LAZY_PROVIDER_PRELAUNCH: usize = 590;
const SLOT_COMPONENT_LAZY_PROVIDER_ROUTE_LAUNCH: usize = 591;
const SLOT_COMPONENT_STOP_REQUEST: usize = 592;
const SLOT_COMPONENT_STOP_EVENT_READ: usize = 593;
const SLOT_COMPONENT_STOP_EVENT_CODE: usize = 594;
const SLOT_COMPONENT_STOP_WAIT_OBSERVED: usize = 595;
const SLOT_COMPONENT_KILL_REQUEST: usize = 596;
const SLOT_COMPONENT_KILL_EVENT_READ: usize = 597;
const SLOT_COMPONENT_KILL_EVENT_CODE: usize = 598;
const SLOT_COMPONENT_KILL_WAIT_OBSERVED: usize = 599;
const SLOT_COMPONENT_PROVIDER_OUTPUT_LEN: usize = 694;
const SLOT_COMPONENT_PROVIDER_OUTPUT_WORD_BASE: usize = 695;
const COMPONENT_PROVIDER_OUTPUT_WORDS: usize = 64;

const STEP_RESOLVE_ROOT: u64 = 1;
const STEP_RESOLVE_PROVIDER: u64 = 2;
const STEP_PROVIDER_OUTGOING_PAIR: u64 = 3;
const STEP_PROVIDER_LAUNCH: u64 = 4;
const STEP_CLIENT_ROUTE: u64 = 5;
const STEP_CLIENT_LAUNCH: u64 = 6;
const STEP_PROVIDER_EVENT: u64 = 7;
const STEP_CLIENT_EVENT: u64 = 8;
const STEP_BOOTSTRAP_NAMESPACE: u64 = 9;
const STEP_TMPFS_SMOKE: u64 = 10;
const STEP_SOCKET_SMOKE: u64 = 11;
const STEP_STARNIX_STDOUT: u64 = 12;
const STEP_ROOT_PANIC: u64 = u64::MAX;

#[derive(Clone, Copy, Default)]
pub(crate) struct ComponentSummary {
    pub(crate) failure_step: u64,
    resolve_root: i64,
    resolve_provider: i64,
    resolve_client: i64,
    provider_outgoing_pair: i64,
    provider_launch: i64,
    client_route: i64,
    client_launch: i64,
    provider_event_read: i64,
    provider_event_code: i64,
    client_event_read: i64,
    client_event_code: i64,
    lazy_provider_prelaunch: i64,
    lazy_provider_route_launch: i64,
    stop_request: i64,
    stop_event_read: i64,
    stop_event_code: i64,
    stop_wait_observed: u64,
    kill_request: i64,
    kill_event_read: i64,
    kill_event_code: i64,
    kill_wait_observed: u64,
}

impl ComponentSummary {
    pub(crate) fn bootstrap() -> Self {
        Self {
            failure_step: STEP_RESOLVE_ROOT,
            ..Self::default()
        }
    }
}

pub(crate) fn run_component_manager(summary: &mut ComponentSummary) -> i32 {
    *summary = ComponentSummary::default();
    let parent_process = read_slot(SLOT_SELF_PROCESS_H) as zx_handle_t;
    if parent_process == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_RESOLVE_ROOT;
        summary.resolve_root = ZX_ERR_INTERNAL as i64;
        return 1;
    }

    let bootstrap_namespace = match build_bootstrap_namespace() {
        Ok(namespace) => namespace,
        Err(status) => {
            summary.failure_step = STEP_BOOTSTRAP_NAMESPACE;
            summary.resolve_root = status as i64;
            return 1;
        }
    };
    if let Err(status) = run_tmpfs_smoke(bootstrap_namespace.namespace()) {
        summary.failure_step = STEP_TMPFS_SMOKE;
        summary.resolve_root = status as i64;
        return 1;
    }
    if let Err(status) = run_socket_fd_smoke() {
        summary.failure_step = STEP_SOCKET_SMOKE;
        summary.resolve_root = status as i64;
        return 1;
    }

    let resolvers = build_resolver_registry(bootstrap_namespace.boot_root());
    let root = match resolve_root_component(&resolvers) {
        Ok(component) => {
            summary.resolve_root = ZX_OK as i64;
            write_summary(summary);
            component
        }
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_ROOT;
            summary.resolve_root = status as i64;
            return 1;
        }
    };
    let runners = match build_runner_registry(parent_process, bootstrap_namespace.boot_root()) {
        Ok(runners) => runners,
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_ROOT;
            summary.resolve_root = status as i64;
            return 1;
        }
    };

    if root.decl.url == "boot://root-starnix" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_hello",
            STARNIX_HELLO_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-fd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_fd_smoke",
            STARNIX_FD_SMOKE_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round2" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round2_smoke",
            STARNIX_ROUND2_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round3" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round3_smoke",
            STARNIX_ROUND3_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round4-futex" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round4_futex_smoke",
            STARNIX_ROUND4_FUTEX_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round4-signal" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round4_signal_smoke",
            STARNIX_ROUND4_SIGNAL_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round5-epoll" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round5_epoll_smoke",
            STARNIX_ROUND5_EPOLL_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-eventfd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_eventfd_smoke",
            STARNIX_ROUND6_EVENTFD_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-timerfd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_timerfd_smoke",
            STARNIX_ROUND6_TIMERFD_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-signalfd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_signalfd_smoke",
            STARNIX_ROUND6_SIGNALFD_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-futex" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_futex_smoke",
            STARNIX_ROUND6_FUTEX_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-scm-rights" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_scm_rights_smoke",
            STARNIX_ROUND6_SCM_RIGHTS_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-pidfd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_pidfd_smoke",
            STARNIX_ROUND6_PIDFD_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-proc-job" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_proc_job_smoke",
            STARNIX_ROUND6_PROC_JOB_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-proc-control" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_proc_control_smoke",
            STARNIX_ROUND6_PROC_CONTROL_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-round6-proc-tty" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_round6_proc_tty_smoke",
            STARNIX_ROUND6_PROC_TTY_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-fd" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_fd_smoke",
            STARNIX_RUNTIME_FD_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-misc" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_misc_smoke",
            STARNIX_RUNTIME_MISC_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-process" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_process_smoke",
            STARNIX_RUNTIME_PROCESS_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-net" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_net_smoke",
            STARNIX_RUNTIME_NET_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-fs" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_fs_smoke",
            STARNIX_RUNTIME_FS_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-runtime-tls" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_runtime_tls_smoke",
            STARNIX_RUNTIME_TLS_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-dynamic" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_dynamic_elf_smoke",
            STARNIX_DYNAMIC_ELF_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-dynamic-tls" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_dynamic_tls_smoke",
            STARNIX_DYNAMIC_TLS_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-dynamic-runtime" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_dynamic_runtime_smoke",
            STARNIX_DYNAMIC_RUNTIME_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-dynamic-pie" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_dynamic_pie_smoke",
            STARNIX_DYNAMIC_PIE_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-glibc-hello" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_glibc_hello",
            STARNIX_GLIBC_HELLO_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-shell" {
        return run_starnix_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_busybox_shell",
            STARNIX_SHELL_EXPECTED_STDOUT,
            summary,
        );
    }
    if root.decl.url == "boot://root-starnix-net-shell" {
        return run_starnix_remote_shell_root_child(
            &root,
            &resolvers,
            &runners,
            "linux_busybox_socket_shell",
            summary,
        );
    }
    if root.decl.url == "boot://root-net-dataplane" {
        return net::run_root_dataplane();
    }
    if root.decl.url == "boot://root-vmo-shared" {
        return vmo::run_root_shared_source_contract();
    }

    let (provider, provider_startup) = match resolve_root_child(&root, &resolvers, "echo_provider")
    {
        Ok(component) => {
            summary.resolve_provider = ZX_OK as i64;
            write_summary(summary);
            component
        }
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            summary.resolve_provider = status as i64;
            return 1;
        }
    };
    let (client, _client_startup) = match resolve_root_child(&root, &resolvers, "echo_client") {
        Ok(component) => {
            summary.resolve_client = ZX_OK as i64;
            write_summary(summary);
            component
        }
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            summary.resolve_client = status as i64;
            return 1;
        }
    };

    if root.decl.url == "boot://root" {
        return run_static_echo_graph(&root, &provider, &client, &runners, summary);
    }

    run_dynamic_echo_graph(
        &root,
        &provider,
        provider_startup,
        &client,
        &runners,
        summary,
        &resolvers,
    )
}

pub(crate) fn write_summary(summary: &ComponentSummary) {
    write_slot(SLOT_COMPONENT_FAILURE_STEP, summary.failure_step);
    write_slot(SLOT_COMPONENT_RESOLVE_ROOT, summary.resolve_root as u64);
    write_slot(
        SLOT_COMPONENT_RESOLVE_PROVIDER,
        summary.resolve_provider as u64,
    );
    write_slot(SLOT_COMPONENT_RESOLVE_CLIENT, summary.resolve_client as u64);
    write_slot(
        SLOT_COMPONENT_PROVIDER_OUTGOING_PAIR,
        summary.provider_outgoing_pair as u64,
    );
    write_slot(
        SLOT_COMPONENT_PROVIDER_LAUNCH,
        summary.provider_launch as u64,
    );
    write_slot(SLOT_COMPONENT_CLIENT_ROUTE, summary.client_route as u64);
    write_slot(SLOT_COMPONENT_CLIENT_LAUNCH, summary.client_launch as u64);
    write_slot(
        SLOT_COMPONENT_PROVIDER_EVENT_READ,
        summary.provider_event_read as u64,
    );
    write_slot(
        SLOT_COMPONENT_PROVIDER_EVENT_CODE,
        summary.provider_event_code as u64,
    );
    write_slot(
        SLOT_COMPONENT_CLIENT_EVENT_READ,
        summary.client_event_read as u64,
    );
    write_slot(
        SLOT_COMPONENT_CLIENT_EVENT_CODE,
        summary.client_event_code as u64,
    );
    write_slot(
        SLOT_COMPONENT_LAZY_PROVIDER_PRELAUNCH,
        summary.lazy_provider_prelaunch as u64,
    );
    write_slot(
        SLOT_COMPONENT_LAZY_PROVIDER_ROUTE_LAUNCH,
        summary.lazy_provider_route_launch as u64,
    );
    write_slot(SLOT_COMPONENT_STOP_REQUEST, summary.stop_request as u64);
    write_slot(
        SLOT_COMPONENT_STOP_EVENT_READ,
        summary.stop_event_read as u64,
    );
    write_slot(
        SLOT_COMPONENT_STOP_EVENT_CODE,
        summary.stop_event_code as u64,
    );
    write_slot(
        SLOT_COMPONENT_STOP_WAIT_OBSERVED,
        summary.stop_wait_observed,
    );
    write_slot(SLOT_COMPONENT_KILL_REQUEST, summary.kill_request as u64);
    write_slot(
        SLOT_COMPONENT_KILL_EVENT_READ,
        summary.kill_event_read as u64,
    );
    write_slot(
        SLOT_COMPONENT_KILL_EVENT_CODE,
        summary.kill_event_code as u64,
    );
    write_slot(
        SLOT_COMPONENT_KILL_WAIT_OBSERVED,
        summary.kill_wait_observed,
    );
}

pub(crate) fn report_root_panic(bytes: &[u8]) -> ! {
    write_component_output_prefix(bytes);
    write_slot(SLOT_COMPONENT_FAILURE_STEP, STEP_ROOT_PANIC);
    write_slot(SLOT_OK, 0);
    axle_arch_x86_64::debug_break()
}

pub(crate) fn run_dedicated_child_component(
    bootstrap_channel: zx_handle_t,
    expected_role: MinimalRole,
    child_marker: u64,
) -> ! {
    ROLE.store(ROLE_CHILD, core::sync::atomic::Ordering::Relaxed);
    record_child_stage(child_marker, 1, ZX_OK);
    let _ = run_dedicated_child_component_inner(bootstrap_channel, expected_role, child_marker);
    loop {
        core::hint::spin_loop();
    }
}

fn build_runner_registry(
    parent_process: zx_handle_t,
    boot_root: Arc<dyn FdOps>,
) -> Result<RunnerRegistry, zx_status_t> {
    let mut runners = RunnerRegistry::new();
    runners.insert_elf(
        "elf",
        ElfRunner {
            parent_process,
            boot_root: Arc::clone(&boot_root),
        },
    );
    runners.insert_starnix(
        "starnix",
        StarnixRunner {
            parent_process,
            boot_root,
        },
    );
    Ok(runners)
}

pub(crate) fn build_bootstrap_namespace() -> Result<BootstrapNamespace, zx_status_t> {
    let self_code_vmo = read_slot(SLOT_SELF_CODE_VMO_H) as zx_handle_t;
    let provider_image_vmo = read_slot(SLOT_BOOT_IMAGE_ECHO_PROVIDER_VMO_H) as zx_handle_t;
    let client_image_vmo = read_slot(SLOT_BOOT_IMAGE_ECHO_CLIENT_VMO_H) as zx_handle_t;
    let controller_worker_image_vmo =
        read_slot(SLOT_BOOT_IMAGE_CONTROLLER_WORKER_VMO_H) as zx_handle_t;
    let starnix_kernel_image_vmo = read_slot(SLOT_BOOT_IMAGE_STARNIX_KERNEL_VMO_H) as zx_handle_t;
    if self_code_vmo == ZX_HANDLE_INVALID {
        return Err(ZX_ERR_INTERNAL);
    }

    let mut assets = Vec::new();
    assets.push(BootAssetEntry::vmo(ROOT_BINARY_PATH, self_code_vmo));
    assets.push(BootAssetEntry::vmo(
        STARNIX_KERNEL_BINARY_PATH,
        if starnix_kernel_image_vmo != ZX_HANDLE_INVALID {
            starnix_kernel_image_vmo
        } else {
            self_code_vmo
        },
    ));
    push_starnix_runtime_assets(&mut assets);
    push_root_manifest_assets(&mut assets);
    push_starnix_manifest_assets(&mut assets);
    push_component_decl_assets(&mut assets);
    if provider_image_vmo != ZX_HANDLE_INVALID {
        assets.push(BootAssetEntry::vmo(
            PROVIDER_BINARY_PATH,
            provider_image_vmo,
        ));
    }
    if client_image_vmo != ZX_HANDLE_INVALID {
        assets.push(BootAssetEntry::vmo(CLIENT_BINARY_PATH, client_image_vmo));
    }
    if controller_worker_image_vmo != ZX_HANDLE_INVALID {
        assets.push(BootAssetEntry::vmo(
            CONTROLLER_WORKER_BINARY_PATH,
            controller_worker_image_vmo,
        ));
    }

    BootstrapNamespace::build(&assets)
}

fn build_resolver_registry(boot_root: Arc<dyn FdOps>) -> ResolverRegistry {
    ResolverRegistry::new(boot_root)
}

fn resolve_root_component(resolvers: &ResolverRegistry) -> Result<ResolvedComponent, zx_status_t> {
    resolvers.resolve("boot-resolver", ROOT_COMPONENT_URL)
}

fn resolve_optional_root_child(
    root: &ResolvedComponent,
    resolvers: &ResolverRegistry,
    name: &str,
) -> Result<Option<(ResolvedComponent, StartupMode)>, zx_status_t> {
    match resolve_root_child(root, resolvers, name) {
        Ok(component) => Ok(Some(component)),
        Err(axle_types::status::ZX_ERR_NOT_FOUND) => Ok(None),
        Err(status) => Err(status),
    }
}

fn run_static_echo_graph(
    root: &ResolvedComponent,
    provider: &ResolvedComponent,
    client: &ResolvedComponent,
    runners: &RunnerRegistry,
    summary: &mut ComponentSummary,
) -> i32 {
    let mut capability_registry = CapabilityRegistry::new();
    let mut outgoing_client = ZX_HANDLE_INVALID;
    let mut outgoing_server = ZX_HANDLE_INVALID;
    let status = zx_channel_create(0, &mut outgoing_client, &mut outgoing_server);
    if status != ZX_OK {
        summary.provider_outgoing_pair = status as i64;
        summary.failure_step = STEP_PROVIDER_OUTGOING_PAIR;
        write_summary(summary);
        return 1;
    }
    summary.provider_outgoing_pair = ZX_OK as i64;
    write_summary(summary);
    publish_protocols(&provider.decl, &mut capability_registry, outgoing_client);

    let client_namespace = match build_namespace_entries(&client.decl, &mut capability_registry) {
        Ok(entries) => {
            summary.client_route = ZX_OK as i64;
            write_summary(summary);
            entries
        }
        Err(status) => {
            summary.client_route = status as i64;
            summary.failure_step = STEP_CLIENT_ROUTE;
            return 1;
        }
    };

    let provider_running = match runners.launch(
        &root.decl,
        provider,
        Vec::new(),
        Some(outgoing_server),
        CHILD_MARKER_PROVIDER,
    ) {
        Ok(running) => {
            summary.provider_launch = ZX_OK as i64;
            write_summary(summary);
            running
        }
        Err(status) => {
            summary.provider_launch = status as i64;
            summary.failure_step = STEP_PROVIDER_LAUNCH;
            return 1;
        }
    };

    let client_running = match runners.launch(
        &root.decl,
        client,
        client_namespace,
        None,
        CHILD_MARKER_CLIENT,
    ) {
        Ok(running) => {
            summary.client_launch = ZX_OK as i64;
            write_summary(summary);
            running
        }
        Err(status) => {
            summary.client_launch = status as i64;
            summary.failure_step = STEP_CLIENT_LAUNCH;
            return 1;
        }
    };

    match read_controller_event_blocking(client_running.controller, ZX_TIME_INFINITE) {
        Ok(return_code) => {
            summary.client_event_read = ZX_OK as i64;
            summary.client_event_code = return_code;
            if return_code != 0 {
                summary.failure_step = read_slot(SLOT_COMPONENT_FAILURE_STEP);
                return 1;
            }
        }
        Err(status) => {
            summary.client_event_read = status as i64;
            summary.failure_step = read_slot(SLOT_COMPONENT_FAILURE_STEP);
            return 1;
        }
    }
    match read_controller_event_blocking(provider_running.controller, ZX_TIME_INFINITE) {
        Ok(return_code) => {
            summary.provider_event_read = ZX_OK as i64;
            summary.provider_event_code = return_code;
            if return_code != 0 {
                summary.failure_step = read_slot(SLOT_COMPONENT_FAILURE_STEP);
                return 1;
            }
        }
        Err(status) => {
            summary.provider_event_read = status as i64;
            summary.failure_step = read_slot(SLOT_COMPONENT_FAILURE_STEP);
            return 1;
        }
    }
    0
}

fn run_dynamic_echo_graph(
    root: &ResolvedComponent,
    provider: &ResolvedComponent,
    provider_startup: StartupMode,
    client: &ResolvedComponent,
    runners: &RunnerRegistry,
    summary: &mut ComponentSummary,
    resolvers: &ResolverRegistry,
) -> i32 {
    let stop_worker_decl = match resolve_optional_root_child(root, resolvers, "stop_worker") {
        Ok(component) => component,
        Err(status) => {
            summary.failure_step = STEP_PROVIDER_LAUNCH;
            summary.provider_launch = status as i64;
            return 1;
        }
    };
    let kill_worker_decl = match resolve_optional_root_child(root, resolvers, "kill_worker") {
        Ok(component) => component,
        Err(status) => {
            summary.failure_step = STEP_CLIENT_LAUNCH;
            summary.client_launch = status as i64;
            return 1;
        }
    };

    let mut stop_worker = if let Some((component, startup)) = stop_worker_decl {
        if !matches!(startup, StartupMode::Eager) {
            summary.failure_step = STEP_PROVIDER_LAUNCH;
            summary.provider_launch = ZX_ERR_BAD_STATE as i64;
            return 1;
        }
        match runners.launch(
            &root.decl,
            &component,
            Vec::new(),
            None,
            CHILD_MARKER_CONTROLLER_WORKER,
        ) {
            Ok(running) => Some(running),
            Err(status) => {
                summary.failure_step = STEP_PROVIDER_LAUNCH;
                summary.provider_launch = status as i64;
                return 1;
            }
        }
    } else {
        None
    };
    let mut kill_worker = if let Some((component, startup)) = kill_worker_decl {
        if !matches!(startup, StartupMode::Eager) {
            summary.failure_step = STEP_CLIENT_LAUNCH;
            summary.client_launch = ZX_ERR_BAD_STATE as i64;
            return 1;
        }
        match runners.launch(
            &root.decl,
            &component,
            Vec::new(),
            None,
            CHILD_MARKER_CONTROLLER_WORKER,
        ) {
            Ok(running) => Some(running),
            Err(status) => {
                summary.failure_step = STEP_CLIENT_LAUNCH;
                summary.client_launch = status as i64;
                return 1;
            }
        }
    } else {
        None
    };

    summary.lazy_provider_prelaunch = i64::from(matches!(provider_startup, StartupMode::Eager));

    let (client_running, provider_running) = if matches!(provider_startup, StartupMode::Eager) {
        let mut capability_registry = CapabilityRegistry::new();
        let mut outgoing_client = ZX_HANDLE_INVALID;
        let mut outgoing_server = ZX_HANDLE_INVALID;
        let status = zx_channel_create(0, &mut outgoing_client, &mut outgoing_server);
        if status != ZX_OK {
            summary.provider_outgoing_pair = status as i64;
            summary.failure_step = STEP_PROVIDER_OUTGOING_PAIR;
            write_summary(summary);
            return 1;
        }
        summary.provider_outgoing_pair = ZX_OK as i64;
        write_summary(summary);
        publish_protocols(&provider.decl, &mut capability_registry, outgoing_client);

        let client_namespace = match build_namespace_entries(&client.decl, &mut capability_registry)
        {
            Ok(entries) => {
                summary.client_route = ZX_OK as i64;
                write_summary(summary);
                entries
            }
            Err(status) => {
                summary.client_route = status as i64;
                summary.failure_step = STEP_CLIENT_ROUTE;
                return 1;
            }
        };

        let provider_running = match runners.launch(
            &root.decl,
            provider,
            Vec::new(),
            Some(outgoing_server),
            CHILD_MARKER_PROVIDER,
        ) {
            Ok(running) => {
                summary.provider_launch = ZX_OK as i64;
                write_summary(summary);
                running
            }
            Err(status) => {
                summary.provider_launch = status as i64;
                summary.failure_step = STEP_PROVIDER_LAUNCH;
                return 1;
            }
        };

        let client_running = match runners.launch(
            &root.decl,
            client,
            client_namespace,
            None,
            CHILD_MARKER_CLIENT,
        ) {
            Ok(running) => {
                summary.client_launch = ZX_OK as i64;
                write_summary(summary);
                running
            }
            Err(status) => {
                summary.client_launch = status as i64;
                summary.failure_step = STEP_CLIENT_LAUNCH;
                return 1;
            }
        };

        (client_running, provider_running)
    } else {
        let mut svc_client = ZX_HANDLE_INVALID;
        let mut svc_server = ZX_HANDLE_INVALID;
        let status = zx_channel_create(0, &mut svc_client, &mut svc_server);
        if status != ZX_OK {
            summary.client_route = status as i64;
            summary.failure_step = STEP_CLIENT_ROUTE;
            write_summary(summary);
            return 1;
        }
        summary.client_route = ZX_OK as i64;
        write_summary(summary);

        let client_running = match runners.launch(
            &root.decl,
            client,
            vec![NamespaceEntry {
                path: String::from(SVC_NAMESPACE_PATH),
                handle: svc_client,
            }],
            None,
            CHILD_MARKER_CLIENT,
        ) {
            Ok(running) => {
                summary.client_launch = ZX_OK as i64;
                write_summary(summary);
                running
            }
            Err(status) => {
                summary.client_launch = status as i64;
                summary.failure_step = STEP_CLIENT_LAUNCH;
                return 1;
            }
        };

        let first_request = match read_directory_request_for_launch(svc_server) {
            Ok(Some(request)) => request,
            Ok(None) => {
                summary.client_route = ZX_ERR_BAD_STATE as i64;
                summary.failure_step = STEP_CLIENT_ROUTE;
                return 1;
            }
            Err(status) => {
                summary.client_route = status as i64;
                summary.failure_step = STEP_CLIENT_ROUTE;
                return 1;
            }
        };

        let mut provider_outgoing_client = ZX_HANDLE_INVALID;
        let mut provider_outgoing_server = ZX_HANDLE_INVALID;
        let status = zx_channel_create(
            0,
            &mut provider_outgoing_client,
            &mut provider_outgoing_server,
        );
        if status != ZX_OK {
            summary.provider_outgoing_pair = status as i64;
            summary.failure_step = STEP_PROVIDER_OUTGOING_PAIR;
            write_summary(summary);
            return 1;
        }
        summary.provider_outgoing_pair = ZX_OK as i64;
        write_summary(summary);

        let provider_running = match runners.launch(
            &root.decl,
            provider,
            Vec::new(),
            Some(provider_outgoing_server),
            CHILD_MARKER_PROVIDER,
        ) {
            Ok(running) => {
                summary.provider_launch = ZX_OK as i64;
                summary.lazy_provider_route_launch = ZX_OK as i64;
                write_summary(summary);
                running
            }
            Err(status) => {
                summary.provider_launch = status as i64;
                summary.lazy_provider_route_launch = status as i64;
                summary.failure_step = STEP_PROVIDER_LAUNCH;
                return 1;
            }
        };

        if let Err(status) = proxy_directory_requests_until_peer_closed(
            svc_server,
            provider_outgoing_client,
            Some(first_request),
        ) {
            summary.client_route = status as i64;
            summary.failure_step = STEP_CLIENT_ROUTE;
            return 1;
        }
        let _ = zx_handle_close(provider_outgoing_client);
        let _ = zx_handle_close(svc_server);

        (client_running, provider_running)
    };

    match read_controller_event_blocking(client_running.controller, ZX_TIME_INFINITE) {
        Ok(return_code) => {
            summary.client_event_read = ZX_OK as i64;
            summary.client_event_code = return_code;
            if return_code != 0 {
                summary.failure_step = STEP_CLIENT_EVENT;
                return 1;
            }
        }
        Err(status) => {
            summary.client_event_read = status as i64;
            summary.failure_step = STEP_CLIENT_EVENT;
            return 1;
        }
    }
    match read_controller_event_blocking(provider_running.controller, ZX_TIME_INFINITE) {
        Ok(return_code) => {
            summary.provider_event_read = ZX_OK as i64;
            summary.provider_event_code = return_code;
            if return_code != 0 {
                summary.failure_step = STEP_PROVIDER_EVENT;
                return 1;
            }
        }
        Err(status) => {
            summary.provider_event_read = status as i64;
            summary.failure_step = STEP_PROVIDER_EVENT;
            return 1;
        }
    }

    if let Some(component) = stop_worker.as_mut() {
        match run_controller_lifecycle_step(component, ControllerRequest::Stop) {
            Ok(code) => {
                summary.stop_request = ZX_OK as i64;
                summary.stop_event_read = ZX_OK as i64;
                summary.stop_event_code = code;
            }
            Err(status) => {
                summary.stop_request = status as i64;
                summary.failure_step = STEP_PROVIDER_EVENT;
                return 1;
            }
        }
    }
    if let Some(component) = kill_worker.as_mut() {
        match run_controller_lifecycle_step(component, ControllerRequest::Kill) {
            Ok(code) => {
                summary.kill_request = ZX_OK as i64;
                summary.kill_event_read = ZX_OK as i64;
                summary.kill_event_code = code;
            }
            Err(status) => {
                summary.kill_request = status as i64;
                summary.failure_step = STEP_CLIENT_EVENT;
                return 1;
            }
        }
    }

    0
}

fn run_starnix_root_child(
    root: &ResolvedComponent,
    resolvers: &ResolverRegistry,
    runners: &RunnerRegistry,
    child_name: &str,
    expected_stdout: &[u8],
    summary: &mut ComponentSummary,
) -> i32 {
    let (child, _startup) = match resolve_root_child(root, resolvers, child_name) {
        Ok(component) => {
            summary.resolve_provider = ZX_OK as i64;
            write_summary(summary);
            component
        }
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            summary.resolve_provider = status as i64;
            return 1;
        }
    };
    let running = match runners.launch(
        &root.decl,
        &child,
        Vec::new(),
        None,
        CHILD_MARKER_STARNIX_KERNEL,
    ) {
        Ok(running) => {
            summary.provider_launch = ZX_OK as i64;
            write_summary(summary);
            running
        }
        Err(status) => {
            summary.failure_step = STEP_PROVIDER_LAUNCH;
            summary.provider_launch = status as i64;
            return 1;
        }
    };
    let return_code = match read_controller_event_blocking(running.controller, ZX_TIME_INFINITE) {
        Ok(return_code) => {
            summary.provider_event_read = ZX_OK as i64;
            summary.provider_event_code = return_code;
            return_code
        }
        Err(status) => {
            summary.failure_step = STEP_PROVIDER_EVENT;
            summary.provider_event_read = status as i64;
            let _ = zx_handle_close(running.status);
            let _ = zx_handle_close(running.controller);
            if let Some(stdout) = running.stdout {
                let _ = zx_handle_close(stdout);
            }
            return 1;
        }
    };
    let stdout = match running.stdout {
        Some(stdout) => stdout,
        None => {
            summary.failure_step = STEP_STARNIX_STDOUT;
            let _ = zx_handle_close(running.status);
            let _ = zx_handle_close(running.controller);
            return 1;
        }
    };
    match read_socket_to_end(stdout) {
        Ok(bytes) => {
            if return_code != 0 {
                summary.failure_step = STEP_PROVIDER_EVENT;
                write_component_output_prefix(&bytes);
                let _ = zx_handle_close(stdout);
                let _ = zx_handle_close(running.status);
                let _ = zx_handle_close(running.controller);
                return 1;
            }
            if bytes != expected_stdout {
                summary.failure_step = STEP_STARNIX_STDOUT;
                write_component_output_prefix(&bytes);
                let _ = zx_handle_close(stdout);
                let _ = zx_handle_close(running.status);
                let _ = zx_handle_close(running.controller);
                return 1;
            }
        }
        Err(status) => {
            summary.failure_step = STEP_STARNIX_STDOUT;
            summary.client_route = status as i64;
            let _ = zx_handle_close(stdout);
            let _ = zx_handle_close(running.status);
            let _ = zx_handle_close(running.controller);
            return 1;
        }
    }
    let _ = zx_handle_close(stdout);
    let _ = zx_handle_close(running.status);
    let _ = zx_handle_close(running.controller);
    0
}

fn run_starnix_remote_shell_root_child(
    root: &ResolvedComponent,
    resolvers: &ResolverRegistry,
    runners: &RunnerRegistry,
    child_name: &str,
    summary: &mut ComponentSummary,
) -> i32 {
    let (child, _startup) = match resolve_root_child(root, resolvers, child_name) {
        Ok(component) => {
            summary.resolve_provider = ZX_OK as i64;
            write_summary(summary);
            component
        }
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            summary.resolve_provider = status as i64;
            return 1;
        }
    };
    let stdout_mode = if child
        .decl
        .program
        .env
        .iter()
        .any(|entry| entry == "NEXUS_STARNIX_STDIO=channel-tty")
    {
        remote_net::ShellStdoutMode::Channel
    } else {
        remote_net::ShellStdoutMode::Socket
    };
    let running = match runners.launch(
        &root.decl,
        &child,
        Vec::new(),
        None,
        CHILD_MARKER_STARNIX_KERNEL,
    ) {
        Ok(running) => {
            summary.provider_launch = ZX_OK as i64;
            write_summary(summary);
            running
        }
        Err(status) => {
            summary.failure_step = STEP_PROVIDER_LAUNCH;
            summary.provider_launch = status as i64;
            return 1;
        }
    };
    let stdout = match running.stdout {
        Some(stdout) => stdout,
        None => {
            summary.failure_step = STEP_STARNIX_STDOUT;
            if let Some(stdin) = running.stdin {
                let _ = zx_handle_close(stdin);
            }
            let _ = zx_handle_close(running.status);
            let _ = zx_handle_close(running.controller);
            return 1;
        }
    };
    let stdin = match running.stdin {
        Some(stdin) => stdin,
        None => {
            summary.failure_step = STEP_STARNIX_STDOUT;
            let _ = zx_handle_close(stdout);
            let _ = zx_handle_close(running.status);
            let _ = zx_handle_close(running.controller);
            return 1;
        }
    };
    let remote_result =
        match remote_net::run_remote_shell(stdin, stdout, running.controller, stdout_mode) {
            Ok(result) => result,
            Err(status) => {
                summary.failure_step = STEP_STARNIX_STDOUT;
                summary.client_route = status as i64;
                let _ = zx_handle_close(stdin);
                let _ = zx_handle_close(stdout);
                let _ = zx_task_kill(running.process);
                let _ = zx_handle_close(running.status);
                let _ = zx_handle_close(running.controller);
                let _ = zx_handle_close(running.process);
                return 1;
            }
        };
    let _ = zx_handle_close(stdin);
    let _ = zx_handle_close(stdout);
    let return_code = match remote_result {
        Some(return_code) => {
            summary.provider_event_read = ZX_OK as i64;
            summary.provider_event_code = return_code;
            return_code
        }
        None => match read_controller_event_blocking(running.controller, ZX_TIME_INFINITE) {
            Ok(return_code) => {
                summary.provider_event_read = ZX_OK as i64;
                summary.provider_event_code = return_code;
                return_code
            }
            Err(status) => {
                summary.failure_step = STEP_PROVIDER_EVENT;
                summary.provider_event_read = status as i64;
                let _ = zx_handle_close(running.status);
                let _ = zx_handle_close(running.controller);
                let _ = zx_handle_close(running.process);
                return 1;
            }
        },
    };
    let _ = zx_handle_close(running.status);
    let _ = zx_handle_close(running.controller);
    let _ = zx_handle_close(running.process);
    i32::from(return_code != 0)
}

fn read_socket_to_end(handle: zx_handle_t) -> Result<Vec<u8>, zx_status_t> {
    let mut out = Vec::new();
    let mut scratch = [0u8; 128];
    loop {
        let mut actual = 0usize;
        let status = zx_socket_read(handle, 0, scratch.as_mut_ptr(), scratch.len(), &mut actual);
        if status == ZX_OK {
            out.extend_from_slice(&scratch[..actual]);
            continue;
        }
        if status == ZX_ERR_SHOULD_WAIT {
            let mut observed = 0;
            let wait_status = zx_object_wait_one(
                handle,
                ZX_SOCKET_READABLE | ZX_SOCKET_PEER_CLOSED,
                ZX_TIME_INFINITE,
                &mut observed,
            );
            if wait_status != ZX_OK {
                return Err(wait_status);
            }
            if (observed & ZX_SOCKET_READABLE) != 0 {
                continue;
            }
            if (observed & ZX_SOCKET_PEER_CLOSED) != 0 {
                return Ok(out);
            }
            return Err(ZX_ERR_BAD_STATE);
        }
        if status == axle_types::status::ZX_ERR_PEER_CLOSED {
            return Ok(out);
        }
        return Err(status);
    }
}

fn write_component_output_prefix(bytes: &[u8]) {
    let prefix_len = core::cmp::min(bytes.len(), COMPONENT_PROVIDER_OUTPUT_WORDS * 8);
    write_slot(SLOT_COMPONENT_PROVIDER_OUTPUT_LEN, prefix_len as u64);
    for index in 0..COMPONENT_PROVIDER_OUTPUT_WORDS {
        let start = index * 8;
        let end = core::cmp::min(start + 8, prefix_len);
        let mut word = [0u8; 8];
        if start < end {
            word[..end - start].copy_from_slice(&bytes[start..end]);
        }
        write_slot(
            SLOT_COMPONENT_PROVIDER_OUTPUT_WORD_BASE + index,
            u64::from_le_bytes(word),
        );
    }
}

fn run_dedicated_child_component_inner(
    bootstrap_channel: zx_handle_t,
    expected_role: MinimalRole,
    child_marker: u64,
) -> i64 {
    let start_info = match read_component_start_info_minimal(bootstrap_channel) {
        Ok(start_info) => start_info,
        Err(status) => {
            record_child_stage(child_marker, 2, status);
            return 1;
        }
    };
    if start_info.role != expected_role {
        record_child_stage(child_marker, 2, ZX_ERR_BAD_STATE);
        return 1;
    }
    record_child_stage(child_marker, 3, ZX_OK);
    let status_channel = start_info.status;
    let controller = start_info.controller;

    let code = match expected_role {
        MinimalRole::Provider => run_echo_provider(&start_info),
        MinimalRole::Client => run_echo_client(&start_info),
        MinimalRole::ControllerWorker => run_controller_worker(&start_info),
        MinimalRole::Unknown => 1,
    };
    record_child_stage(child_marker, 7, code as zx_status_t);
    if let Some(handle) = status_channel {
        let _ = send_status_event(handle, code);
    }
    if let Some(handle) = controller {
        let send_status = send_controller_event(handle, code);
        record_child_stage(child_marker, 8, send_status);
    }
    i64::from(code)
}

fn run_echo_provider(start_info: &crate::lifecycle::MinimalStartInfo) -> i32 {
    record_child_stage(CHILD_MARKER_PROVIDER, 4, ZX_OK);
    let Some(outgoing) = start_info.outgoing else {
        return 1;
    };
    record_child_stage(CHILD_MARKER_PROVIDER, 5, ZX_OK);
    let code = run_echo_fs_provider(outgoing, ECHO_REQUEST);
    if code == 0 {
        record_child_stage(CHILD_MARKER_PROVIDER, 6, ZX_OK);
    }
    code
}

fn run_echo_client(start_info: &crate::lifecycle::MinimalStartInfo) -> i32 {
    record_child_stage(CHILD_MARKER_CLIENT, 4, ZX_OK);
    let svc = match start_info.svc {
        Some(handle) => handle,
        None => return 11,
    };
    let mut fd_table = FdTable::new();
    let svc_fd = match fd_table.open(
        Arc::new(RemoteDir::from_descriptor(svc, root_directory_descriptor())),
        OpenFlags::READABLE | OpenFlags::DIRECTORY,
        FdFlags::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => return 12,
    };

    let mut mounts = nexus_io::NamespaceTrie::<Arc<dyn FdOps>>::new();
    let svc_mount = match fd_table.get(svc_fd) {
        Some(entry) => Arc::clone(entry.description().ops()),
        None => return 14,
    };
    if mounts.insert(SVC_NAMESPACE_PATH, svc_mount).is_err() {
        return 15;
    }
    let namespace = ProcessNamespace::new(mounts);
    record_child_stage(CHILD_MARKER_CLIENT, 5, ZX_OK);

    let echo = match namespace.open(
        "/svc/nexus.echo.Echo",
        OpenFlags::READABLE | OpenFlags::WRITABLE,
    ) {
        Ok(ops) => ops,
        Err(_) => return 16,
    };
    let echo_fd = match fd_table.open(
        echo,
        OpenFlags::READABLE | OpenFlags::WRITABLE,
        FdFlags::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => return 17,
    };
    let echo_clone_fd = match fd_table.clone_fd(echo_fd, FdFlags::empty()) {
        Ok(fd) => fd,
        Err(_) => return 18,
    };

    if fd_table.write(echo_clone_fd, ECHO_REQUEST).is_err() {
        return 19;
    }
    let mut reply = [0u8; MAX_SMALL_CHANNEL_BYTES];
    let reply_len = match fd_table.read(echo_clone_fd, &mut reply) {
        Ok(actual) => actual,
        Err(_) => return 20,
    };
    record_child_stage(CHILD_MARKER_CLIENT, 6, ZX_OK);
    if &reply[..reply_len] != ECHO_REQUEST {
        return 21;
    }

    let _ = fd_table.close(echo_clone_fd);
    let _ = fd_table.close(echo_fd);
    let _ = fd_table.close(svc_fd);
    0
}

fn run_controller_worker(start_info: &crate::lifecycle::MinimalStartInfo) -> i32 {
    let Some(controller) = start_info.controller else {
        return 1;
    };
    match read_controller_request_blocking(controller, ZX_TIME_INFINITE) {
        Ok(ControllerRequest::Stop) => 0,
        Ok(ControllerRequest::Kill) => 137,
        Err(_) => 1,
    }
}

fn record_child_stage(child_marker: u64, stage: u64, status: zx_status_t) {
    let _ = (child_marker, stage, status);
}
