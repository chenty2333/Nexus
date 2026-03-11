//! Minimal `ElfRunner + nexus-init/service manager` smoke for Phase C.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::signals::{ZX_CHANNEL_PEER_CLOSED, ZX_CHANNEL_READABLE, ZX_TASK_TERMINATED};
use axle_types::status::{
    ZX_ERR_BAD_STATE, ZX_ERR_INTERNAL, ZX_ERR_INVALID_ARGS, ZX_ERR_IO_DATA_INTEGRITY,
    ZX_ERR_NOT_FOUND, ZX_ERR_NOT_SUPPORTED, ZX_ERR_SHOULD_WAIT, ZX_OK,
};
use axle_types::syscall_numbers::{
    AXLE_SYS_AX_PROCESS_PREPARE_START, AXLE_SYS_PROCESS_CREATE, AXLE_SYS_PROCESS_START,
    AXLE_SYS_TASK_KILL, AXLE_SYS_THREAD_CREATE,
};
use axle_types::{zx_handle_t, zx_signals_t, zx_status_t, zx_time_t};
use libzircon::{
    ZX_TIME_INFINITE, zx_channel_create, zx_channel_read, zx_channel_write, zx_handle_close,
    zx_object_wait_one,
};
use nexus_component::{
    CapabilityKind, ComponentDecl, ComponentStartInfo, ControllerEvent, ControllerRequest,
    DirectoryOpenRequest, NamespaceEntry, NumberedHandle, ResolvedComponent, ResolverRecord,
    ResolverTable, StartupMode, UseDecl,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0010_0000;
const SLOT_OK: usize = 0;
const SLOT_SELF_PROCESS_H: usize = 396;
const SLOT_SELF_CODE_VMO_H: usize = 506;
const SLOT_T0_NS: usize = 511;

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
const SLOT_COMPONENT_PROVIDER_STAGE: usize = 600;
const SLOT_COMPONENT_PROVIDER_STATUS: usize = 601;
const SLOT_COMPONENT_CLIENT_STAGE: usize = 602;
const SLOT_COMPONENT_CLIENT_STATUS: usize = 603;

const STEP_RESOLVE_ROOT: u64 = 1;
const STEP_RESOLVE_PROVIDER: u64 = 2;
const STEP_PROVIDER_OUTGOING_PAIR: u64 = 3;
const STEP_PROVIDER_LAUNCH: u64 = 4;
const STEP_CLIENT_ROUTE: u64 = 5;
const STEP_CLIENT_LAUNCH: u64 = 6;
const STEP_PROVIDER_EVENT: u64 = 7;
const STEP_CLIENT_EVENT: u64 = 8;
const STEP_ROOT_PANIC: u64 = u64::MAX;
const ROLE_NONE: usize = 0;
const ROLE_ROOT: usize = 1;
const ROLE_CHILD: usize = 2;

const ROOT_DECL_EAGER_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component.nxcd"));
const ROOT_DECL_ROUND3_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component_round3.nxcd"));
const PROVIDER_DECL_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/echo_provider.nxcd"));
const CLIENT_DECL_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/echo_client.nxcd"));
const CONTROLLER_WORKER_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/controller_worker.nxcd"));

const CHILD_ROLE_PROVIDER: &str = "echo-provider";
const CHILD_ROLE_CLIENT: &str = "echo-client";
const CHILD_ROLE_CONTROLLER_WORKER: &str = "controller-worker";
const SELF_BINARY_PATH: &str = "bin/nexus-self";
const SVC_NAMESPACE_PATH: &str = "/svc";
const ECHO_PROTOCOL_NAME: &str = "nexus.echo.Echo";
const ECHO_REQUEST: &[u8] = b"hello";
const CHILD_MARKER_PROVIDER: u64 = 0x4e58_4300_0000_0001;
const CHILD_MARKER_CLIENT: u64 = 0x4e58_4300_0000_0002;
const CHILD_MARKER_CONTROLLER_WORKER: u64 = 0x4e58_4300_0000_0003;
const COMPONENT_MESSAGE_MAGIC: &[u8; 4] = b"NXCM";
const COMPONENT_WIRE_VERSION: u16 = 1;
const MESSAGE_KIND_DIRECTORY_OPEN: u8 = 2;
const STARTUP_HANDLE_COMPONENT_STATUS: u32 = 1;
const MAX_BOOTSTRAP_MESSAGE_BYTES: usize = 512;
const MAX_BOOTSTRAP_MESSAGE_HANDLES: usize = 8;
const MAX_SMALL_CHANNEL_BYTES: usize = 128;
const MAX_SMALL_CHANNEL_HANDLES: usize = 1;

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

const HEAP_BYTES: usize = 256 * 1024;
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);
static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static ROLE: AtomicUsize = AtomicUsize::new(ROLE_NONE);

#[derive(Clone, Copy, PartialEq, Eq)]
enum SmokeMode {
    Eager,
    Round3,
}

impl SmokeMode {
    fn current() -> Self {
        match option_env!("AXLE_COMPONENT_SMOKE_MODE") {
            Some("round3") => Self::Round3,
            _ => Self::Eager,
        }
    }
}

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

// SAFETY: this allocator serves the single-threaded bootstrap component smoke in
// one process at a time. Allocations come from one fixed static buffer,
// deallocation is a no-op, and alignment is preserved by monotonic bumping.
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let size = layout.size();
        let mut current = HEAP_NEXT.load(Ordering::Relaxed);

        loop {
            let aligned = (current + align_mask) & !align_mask;
            let Some(next) = aligned.checked_add(size) else {
                return core::ptr::null_mut();
            };
            if next > HEAP_BYTES {
                return core::ptr::null_mut();
            }
            match HEAP_NEXT.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // SAFETY: `HEAP` is the dedicated backing storage for this bump allocator.
                    // Allocation is serialized by the atomic bump pointer, and callers only
                    // receive disjoint regions within this static buffer.
                    let base = unsafe { core::ptr::addr_of_mut!(HEAP.0).cast::<u8>() as usize };
                    return (base + aligned) as *mut u8;
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[derive(Clone, Copy, Default)]
struct ComponentSummary {
    failure_step: u64,
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

struct RunningComponent {
    process: zx_handle_t,
    controller: zx_handle_t,
    status: zx_handle_t,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MinimalRole {
    Provider,
    Client,
    ControllerWorker,
    Unknown,
}

struct MinimalStartInfo {
    role: MinimalRole,
    svc: Option<zx_handle_t>,
    status: Option<zx_handle_t>,
    outgoing: Option<zx_handle_t>,
    controller: Option<zx_handle_t>,
}

struct CapabilityRegistry {
    protocols: Vec<(String, zx_handle_t)>,
}

impl CapabilityRegistry {
    fn new() -> Self {
        Self {
            protocols: Vec::new(),
        }
    }

    fn publish_protocol(&mut self, name: &str, handle: zx_handle_t) {
        self.protocols.push((String::from(name), handle));
    }

    fn take_protocol(&mut self, name: &str) -> Result<zx_handle_t, zx_status_t> {
        let index = self
            .protocols
            .iter()
            .position(|(protocol, _)| protocol == name)
            .ok_or(ZX_ERR_NOT_FOUND)?;
        Ok(self.protocols.remove(index).1)
    }
}

struct ResolverRegistry {
    tables: Vec<(String, ResolverTable)>,
}

impl ResolverRegistry {
    fn new() -> Self {
        Self { tables: Vec::new() }
    }

    fn insert_record(&mut self, capability_name: &str, record: ResolverRecord) -> Result<(), ()> {
        if let Some((_, table)) = self
            .tables
            .iter_mut()
            .find(|(name, _)| name == capability_name)
        {
            return table.insert(record).map_err(|_| ());
        }
        let mut table = ResolverTable::new();
        table.insert(record).map_err(|_| ())?;
        self.tables.push((String::from(capability_name), table));
        Ok(())
    }

    fn resolve(&self, capability_name: &str, url: &str) -> Result<ResolvedComponent, zx_status_t> {
        let table = self
            .tables
            .iter()
            .find(|(name, _)| name == capability_name)
            .map(|(_, table)| table)
            .ok_or(ZX_ERR_NOT_FOUND)?;
        table.resolve(url).map_err(map_resolve_error)
    }
}

struct RunnerRegistry {
    elf_runners: Vec<(String, ElfRunner)>,
}

impl RunnerRegistry {
    fn new() -> Self {
        Self {
            elf_runners: Vec::new(),
        }
    }

    fn insert_elf(&mut self, name: &str, runner: ElfRunner) {
        self.elf_runners.push((String::from(name), runner));
    }

    fn launch(
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
struct ElfRunner {
    parent_process: zx_handle_t,
    image_vmo: zx_handle_t,
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

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_start(bootstrap_channel: zx_handle_t, arg1: u64) -> ! {
    if bootstrap_channel != ZX_HANDLE_INVALID
        && matches!(
            arg1,
            CHILD_MARKER_PROVIDER | CHILD_MARKER_CLIENT | CHILD_MARKER_CONTROLLER_WORKER
        )
    {
        ROLE.store(ROLE_CHILD, Ordering::Relaxed);
        run_child_component(bootstrap_channel, arg1);
        loop {
            core::hint::spin_loop();
        }
    }
    ROLE.store(ROLE_ROOT, Ordering::Relaxed);
    let mut summary = ComponentSummary::default();
    let status = run_component_manager_smoke(&mut summary);
    write_summary(&summary);
    write_slot(SLOT_OK, u64::from(status == 0));
    axle_arch_x86_64::debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    if ROLE.load(Ordering::Relaxed) == ROLE_ROOT {
        write_slot(SLOT_COMPONENT_FAILURE_STEP, STEP_ROOT_PANIC);
        write_slot(SLOT_OK, 0);
        axle_arch_x86_64::debug_break()
    }
    loop {
        core::hint::spin_loop();
    }
}

fn run_component_manager_smoke(summary: &mut ComponentSummary) -> i32 {
    match SmokeMode::current() {
        SmokeMode::Eager => run_component_manager_eager_smoke(summary),
        SmokeMode::Round3 => run_component_manager_round3_smoke(summary),
    }
}

fn run_component_manager_eager_smoke(summary: &mut ComponentSummary) -> i32 {
    *summary = ComponentSummary::default();
    let parent_process = read_slot(SLOT_SELF_PROCESS_H) as zx_handle_t;
    let self_code_vmo = read_slot(SLOT_SELF_CODE_VMO_H) as zx_handle_t;
    if parent_process == ZX_HANDLE_INVALID || self_code_vmo == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_RESOLVE_ROOT;
        summary.resolve_root = ZX_ERR_INTERNAL as i64;
        return 1;
    }

    let root_seed = match decode_resolved_component(ROOT_DECL_EAGER_BYTES) {
        Ok(component) => {
            summary.resolve_root = ZX_OK as i64;
            component
        }
        Err(status) => {
            summary.resolve_root = status as i64;
            summary.failure_step = STEP_RESOLVE_ROOT;
            return 1;
        }
    };
    let provider = match decode_resolved_component(PROVIDER_DECL_BYTES) {
        Ok(component) => {
            summary.resolve_provider = ZX_OK as i64;
            component
        }
        Err(status) => {
            summary.resolve_provider = status as i64;
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            return 1;
        }
    };
    let client = match decode_resolved_component(CLIENT_DECL_BYTES) {
        Ok(component) => {
            summary.resolve_client = ZX_OK as i64;
            component
        }
        Err(status) => {
            summary.resolve_client = status as i64;
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            return 1;
        }
    };

    let mut resolvers = ResolverRegistry::new();
    for component in [&root_seed, &provider, &client] {
        if resolvers
            .insert_record(
                "boot-resolver",
                ResolverRecord {
                    url: component.decl.url.clone(),
                    resolved: component.clone(),
                },
            )
            .is_err()
        {
            summary.resolve_root = ZX_ERR_INTERNAL as i64;
            summary.failure_step = STEP_RESOLVE_ROOT;
            return 1;
        }
    }

    let root = match resolve_with_realm(&root_seed.decl, &resolvers, root_seed.decl.url.as_str()) {
        Ok(component) => component,
        Err(status) => {
            summary.resolve_root = status as i64;
            summary.failure_step = STEP_RESOLVE_ROOT;
            return 1;
        }
    };
    let (provider, _provider_startup) = match resolve_root_child(&root, &resolvers, "echo_provider")
    {
        Ok(component) => component,
        Err(status) => {
            summary.resolve_provider = status as i64;
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            return 1;
        }
    };
    let (client, _client_startup) = match resolve_root_child(&root, &resolvers, "echo_client") {
        Ok(component) => component,
        Err(status) => {
            summary.resolve_client = status as i64;
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            return 1;
        }
    };

    let mut runners = RunnerRegistry::new();
    runners.insert_elf(
        "elf",
        ElfRunner {
            parent_process,
            image_vmo: self_code_vmo,
        },
    );
    let mut capability_registry = CapabilityRegistry::new();
    let mut outgoing_client = ZX_HANDLE_INVALID;
    let mut outgoing_server = ZX_HANDLE_INVALID;
    let status = zx_channel_create(0, &mut outgoing_client, &mut outgoing_server);
    if status != ZX_OK {
        summary.provider_outgoing_pair = status as i64;
        summary.failure_step = STEP_PROVIDER_OUTGOING_PAIR;
        return 1;
    }
    summary.provider_outgoing_pair = ZX_OK as i64;
    publish_protocols(&provider.decl, &mut capability_registry, outgoing_client);

    let client_namespace = match build_namespace_entries(&client.decl, &mut capability_registry) {
        Ok(entries) => {
            summary.client_route = ZX_OK as i64;
            entries
        }
        Err(status) => {
            summary.client_route = status as i64;
            summary.failure_step = STEP_CLIENT_ROUTE;
            return 1;
        }
    };

    let client_running = match runners.launch(
        &root.decl,
        &client,
        client_namespace,
        None,
        CHILD_MARKER_CLIENT,
    ) {
        Ok(running) => {
            summary.client_launch = ZX_OK as i64;
            running
        }
        Err(status) => {
            summary.client_launch = status as i64;
            summary.failure_step = STEP_CLIENT_LAUNCH;
            return 1;
        }
    };

    let provider_running = match runners.launch(
        &root.decl,
        &provider,
        Vec::new(),
        Some(outgoing_server),
        CHILD_MARKER_PROVIDER,
    ) {
        Ok(running) => {
            summary.provider_launch = ZX_OK as i64;
            running
        }
        Err(status) => {
            summary.provider_launch = status as i64;
            summary.failure_step = STEP_PROVIDER_LAUNCH;
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
    let _ = provider_running;
    let _ = client_running;
    0
}

fn run_component_manager_round3_smoke(summary: &mut ComponentSummary) -> i32 {
    *summary = ComponentSummary::default();
    write_slot(SLOT_COMPONENT_FAILURE_STEP, 101);
    let parent_process = read_slot(SLOT_SELF_PROCESS_H) as zx_handle_t;
    let self_code_vmo = read_slot(SLOT_SELF_CODE_VMO_H) as zx_handle_t;
    if parent_process == ZX_HANDLE_INVALID || self_code_vmo == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_RESOLVE_ROOT;
        summary.resolve_root = ZX_ERR_INTERNAL as i64;
        return 1;
    }

    let root_seed = match decode_resolved_component(ROOT_DECL_ROUND3_BYTES) {
        Ok(component) => {
            summary.resolve_root = ZX_OK as i64;
            write_slot(SLOT_COMPONENT_FAILURE_STEP, 102);
            component
        }
        Err(status) => {
            summary.resolve_root = status as i64;
            summary.failure_step = STEP_RESOLVE_ROOT;
            return 1;
        }
    };
    let provider_seed = match decode_resolved_component(PROVIDER_DECL_BYTES) {
        Ok(component) => {
            summary.resolve_provider = ZX_OK as i64;
            write_slot(SLOT_COMPONENT_FAILURE_STEP, 103);
            component
        }
        Err(status) => {
            summary.resolve_provider = status as i64;
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            return 1;
        }
    };
    let client_seed = match decode_resolved_component(CLIENT_DECL_BYTES) {
        Ok(component) => {
            summary.resolve_client = ZX_OK as i64;
            write_slot(SLOT_COMPONENT_FAILURE_STEP, 104);
            component
        }
        Err(status) => {
            summary.resolve_client = status as i64;
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            return 1;
        }
    };
    let worker_seed = match decode_resolved_component(CONTROLLER_WORKER_DECL_BYTES) {
        Ok(component) => component,
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_ROOT;
            summary.resolve_root = status as i64;
            return 1;
        }
    };

    let mut resolvers = ResolverRegistry::new();
    for component in [&root_seed, &provider_seed, &client_seed, &worker_seed] {
        if resolvers
            .insert_record(
                "boot-resolver",
                ResolverRecord {
                    url: component.decl.url.clone(),
                    resolved: component.clone(),
                },
            )
            .is_err()
        {
            summary.failure_step = STEP_RESOLVE_ROOT;
            summary.resolve_root = ZX_ERR_INTERNAL as i64;
            return 1;
        }
    }
    let root = match resolve_with_realm(&root_seed.decl, &resolvers, root_seed.decl.url.as_str()) {
        Ok(component) => component,
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_ROOT;
            summary.resolve_root = status as i64;
            return 1;
        }
    };
    let (provider, provider_startup) = match resolve_root_child(&root, &resolvers, "echo_provider")
    {
        Ok(component) => component,
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            summary.resolve_provider = status as i64;
            return 1;
        }
    };
    let (client, _client_startup) = match resolve_root_child(&root, &resolvers, "echo_client") {
        Ok(component) => component,
        Err(status) => {
            summary.failure_step = STEP_RESOLVE_PROVIDER;
            summary.resolve_client = status as i64;
            return 1;
        }
    };
    let (stop_worker_decl, stop_startup) =
        match resolve_root_child(&root, &resolvers, "stop_worker") {
            Ok(component) => component,
            Err(status) => {
                summary.failure_step = STEP_PROVIDER_LAUNCH;
                summary.provider_launch = status as i64;
                return 1;
            }
        };
    let (kill_worker_decl, kill_startup) =
        match resolve_root_child(&root, &resolvers, "kill_worker") {
            Ok(component) => component,
            Err(status) => {
                summary.failure_step = STEP_CLIENT_LAUNCH;
                summary.client_launch = status as i64;
                return 1;
            }
        };

    let mut runners = RunnerRegistry::new();
    runners.insert_elf(
        "elf",
        ElfRunner {
            parent_process,
            image_vmo: self_code_vmo,
        },
    );
    write_slot(SLOT_COMPONENT_FAILURE_STEP, 105);
    let mut stop_worker = if matches!(stop_startup, StartupMode::Eager) {
        write_slot(SLOT_COMPONENT_FAILURE_STEP, 106);
        match runners.launch(
            &root.decl,
            &stop_worker_decl,
            Vec::new(),
            None,
            CHILD_MARKER_CONTROLLER_WORKER,
        ) {
            Ok(running) => running,
            Err(status) => {
                summary.failure_step = STEP_PROVIDER_LAUNCH;
                summary.provider_launch = status as i64;
                return 1;
            }
        }
    } else {
        summary.failure_step = STEP_PROVIDER_LAUNCH;
        summary.provider_launch = ZX_ERR_BAD_STATE as i64;
        return 1;
    };
    let mut kill_worker = if matches!(kill_startup, StartupMode::Eager) {
        write_slot(SLOT_COMPONENT_FAILURE_STEP, 107);
        match runners.launch(
            &root.decl,
            &kill_worker_decl,
            Vec::new(),
            None,
            CHILD_MARKER_CONTROLLER_WORKER,
        ) {
            Ok(running) => running,
            Err(status) => {
                summary.failure_step = STEP_CLIENT_LAUNCH;
                summary.client_launch = status as i64;
                return 1;
            }
        }
    } else {
        summary.failure_step = STEP_CLIENT_LAUNCH;
        summary.client_launch = ZX_ERR_BAD_STATE as i64;
        return 1;
    };

    let mut svc_client = ZX_HANDLE_INVALID;
    let mut svc_server = ZX_HANDLE_INVALID;
    let status = zx_channel_create(0, &mut svc_client, &mut svc_server);
    if status != ZX_OK {
        summary.client_route = status as i64;
        summary.failure_step = STEP_CLIENT_ROUTE;
        return 1;
    }
    summary.client_route = ZX_OK as i64;
    summary.lazy_provider_prelaunch = i64::from(matches!(provider_startup, StartupMode::Eager));

    let client_running = match runners.launch(
        &root.decl,
        &client,
        vec![NamespaceEntry {
            path: String::from(SVC_NAMESPACE_PATH),
            handle: svc_client,
        }],
        None,
        CHILD_MARKER_CLIENT,
    ) {
        Ok(running) => {
            summary.client_launch = ZX_OK as i64;
            write_slot(SLOT_COMPONENT_FAILURE_STEP, 108);
            running
        }
        Err(status) => {
            summary.client_launch = status as i64;
            summary.failure_step = STEP_CLIENT_LAUNCH;
            return 1;
        }
    };

    let open_request = match read_directory_open_request_blocking(svc_server, ZX_TIME_INFINITE) {
        Ok(request) => request,
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
        return 1;
    }
    summary.provider_outgoing_pair = ZX_OK as i64;

    let provider_running = match runners.launch(
        &root.decl,
        &provider,
        Vec::new(),
        Some(provider_outgoing_server),
        CHILD_MARKER_PROVIDER,
    ) {
        Ok(running) => {
            summary.provider_launch = ZX_OK as i64;
            summary.lazy_provider_route_launch = ZX_OK as i64;
            write_slot(SLOT_COMPONENT_FAILURE_STEP, 109);
            running
        }
        Err(status) => {
            summary.provider_launch = status as i64;
            summary.lazy_provider_route_launch = status as i64;
            summary.failure_step = STEP_PROVIDER_LAUNCH;
            return 1;
        }
    };

    let status = forward_directory_open_request(provider_outgoing_client, open_request);
    if status != ZX_OK {
        summary.client_route = status as i64;
        summary.failure_step = STEP_CLIENT_ROUTE;
        return 1;
    }

    match read_controller_event_blocking(client_running.controller, ZX_TIME_INFINITE) {
        Ok(return_code) => {
            summary.client_event_read = ZX_OK as i64;
            summary.client_event_code = return_code;
            write_slot(SLOT_COMPONENT_FAILURE_STEP, 110);
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
            write_slot(SLOT_COMPONENT_FAILURE_STEP, 111);
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

    write_slot(SLOT_COMPONENT_FAILURE_STEP, 112);

    if run_controller_lifecycle_step(
        0x5354_4f50,
        &mut stop_worker,
        ControllerRequest::Stop,
        &mut summary.stop_request,
        &mut summary.stop_event_read,
        &mut summary.stop_event_code,
    )
    .is_err()
    {
        summary.failure_step = read_slot(SLOT_COMPONENT_FAILURE_STEP);
        return 1;
    }
    write_slot(SLOT_COMPONENT_FAILURE_STEP, 113);

    if run_controller_lifecycle_step(
        0x4b49_4c4c,
        &mut kill_worker,
        ControllerRequest::Kill,
        &mut summary.kill_request,
        &mut summary.kill_event_read,
        &mut summary.kill_event_code,
    )
    .is_err()
    {
        summary.failure_step = read_slot(SLOT_COMPONENT_FAILURE_STEP);
        return 1;
    }
    write_slot(SLOT_COMPONENT_FAILURE_STEP, 114);

    0
}

fn run_controller_lifecycle_step(
    wait_key: u64,
    component: &mut RunningComponent,
    request: ControllerRequest,
    request_status: &mut i64,
    event_read: &mut i64,
    event_code: &mut i64,
) -> Result<(), zx_status_t> {
    let (step_send, step_event, step_wait) = if wait_key == 0x5354_4f50 {
        (120, 121, 122)
    } else {
        (130, 131, 132)
    };
    let (slot_request, slot_event_read, slot_event_code) = if wait_key == 0x5354_4f50 {
        (
            SLOT_COMPONENT_STOP_REQUEST,
            SLOT_COMPONENT_STOP_EVENT_READ,
            SLOT_COMPONENT_STOP_EVENT_CODE,
        )
    } else {
        (
            SLOT_COMPONENT_KILL_REQUEST,
            SLOT_COMPONENT_KILL_EVENT_READ,
            SLOT_COMPONENT_KILL_EVENT_CODE,
        )
    };
    write_slot(SLOT_COMPONENT_FAILURE_STEP, step_send);
    let status = send_controller_request(component.controller, request);
    *request_status = i64::from(status);
    write_slot(slot_request, status as u64);
    if status != ZX_OK {
        return Err(status);
    }
    write_slot(SLOT_COMPONENT_FAILURE_STEP, step_event);
    let code = read_controller_event_blocking(component.controller, ZX_TIME_INFINITE)?;
    *event_read = i64::from(ZX_OK);
    *event_code = code;
    write_slot(slot_event_read, ZX_OK as u64);
    write_slot(slot_event_code, code as u64);
    write_slot(SLOT_COMPONENT_FAILURE_STEP, step_wait);
    Ok(())
}

fn run_child_component(bootstrap_channel: zx_handle_t, child_marker: u64) {
    record_child_stage(child_marker, 1, ZX_OK);
    let return_code = run_child_component_inner(bootstrap_channel, child_marker);
    if return_code < 0 {
        return;
    }
}

fn run_child_component_inner(bootstrap_channel: zx_handle_t, child_marker: u64) -> i64 {
    let start_info = match read_component_start_info_minimal(bootstrap_channel) {
        Ok(start_info) => start_info,
        Err(status) => {
            record_child_stage(child_marker, 2, status);
            return 1;
        }
    };
    record_child_stage(child_marker, 3, ZX_OK);
    let status_channel = start_info.status;
    let controller = start_info.controller;

    let code = match start_info.role {
        MinimalRole::Provider => run_echo_provider(&start_info),
        MinimalRole::Client => run_echo_client(&start_info),
        MinimalRole::ControllerWorker => run_controller_worker(&start_info),
        _ => 1,
    };
    record_child_stage(child_marker, 7, code as zx_status_t);
    if let Some(handle) = status_channel {
        let _ = send_status_event(handle, code);
    }
    if let Some(handle) = controller {
        let send_status = send_controller_event(handle, code);
        record_child_stage(child_marker, 8, send_status);
        if matches!(start_info.role, MinimalRole::ControllerWorker) {
            let _ = wait_for_channel_readable(handle, ZX_TIME_INFINITE);
        }
    }
    i64::from(code)
}

fn run_echo_provider(start_info: &MinimalStartInfo) -> i32 {
    record_child_stage(CHILD_MARKER_PROVIDER, 4, ZX_OK);
    let Some(outgoing) = start_info.outgoing else {
        return 1;
    };
    let (path_matches, object) = match read_directory_open_request_minimal(outgoing) {
        Ok(request) => request,
        Err(_) => return 1,
    };
    record_child_stage(CHILD_MARKER_PROVIDER, 5, ZX_OK);
    if !path_matches {
        let _ = zx_handle_close(object);
        return 1;
    }
    let mut bytes = [0u8; MAX_SMALL_CHANNEL_BYTES];
    let mut handles = [ZX_HANDLE_INVALID; MAX_SMALL_CHANNEL_HANDLES];
    let (actual_bytes, actual_handles) =
        match read_channel_blocking(object, &mut bytes, &mut handles) {
            Ok(message) => message,
            Err(_) => {
                return 1;
            }
        };
    record_child_stage(CHILD_MARKER_PROVIDER, 6, ZX_OK);
    if actual_handles != 0 || &bytes[..actual_bytes] != ECHO_REQUEST {
        return 1;
    }
    let status = zx_channel_write(
        object,
        0,
        bytes.as_ptr(),
        actual_bytes as u32,
        core::ptr::null(),
        0,
    );
    if status == ZX_OK { 0 } else { 1 }
}

fn run_echo_client(start_info: &MinimalStartInfo) -> i32 {
    record_child_stage(CHILD_MARKER_CLIENT, 4, ZX_OK);
    let svc = match start_info.svc {
        Some(handle) => handle,
        None => return 1,
    };

    let mut client_end = ZX_HANDLE_INVALID;
    let mut server_end = ZX_HANDLE_INVALID;
    if zx_channel_create(0, &mut client_end, &mut server_end) != ZX_OK {
        return 1;
    }
    let mut open_bytes = [0u8; MAX_SMALL_CHANNEL_BYTES];
    let open_len =
        match encode_directory_open_request_minimal(&mut open_bytes, ECHO_PROTOCOL_NAME, 0) {
            Ok(len) => len,
            Err(_) => {
                let _ = zx_handle_close(client_end);
                let _ = zx_handle_close(server_end);
                return 1;
            }
        };
    let mut open_handles = [server_end];
    let status = zx_channel_write(
        svc,
        0,
        open_bytes.as_ptr(),
        open_len as u32,
        open_handles.as_mut_ptr(),
        1,
    );
    if status != ZX_OK {
        let _ = zx_handle_close(client_end);
        return 1;
    }
    record_child_stage(CHILD_MARKER_CLIENT, 5, ZX_OK);

    let status = zx_channel_write(
        client_end,
        0,
        ECHO_REQUEST.as_ptr(),
        ECHO_REQUEST.len() as u32,
        core::ptr::null(),
        0,
    );
    if status != ZX_OK {
        let _ = zx_handle_close(client_end);
        return 1;
    }
    record_child_stage(CHILD_MARKER_CLIENT, 6, ZX_OK);

    let mut reply = [0u8; MAX_SMALL_CHANNEL_BYTES];
    let mut handles = [ZX_HANDLE_INVALID; MAX_SMALL_CHANNEL_HANDLES];
    let (reply_len, handle_count) =
        match read_channel_blocking(client_end, &mut reply, &mut handles) {
            Ok(message) => message,
            Err(_) => {
                return 1;
            }
        };
    if handle_count != 0 || &reply[..reply_len] != ECHO_REQUEST {
        return 1;
    }
    0
}

fn run_controller_worker(start_info: &MinimalStartInfo) -> i32 {
    let Some(controller) = start_info.controller else {
        return 1;
    };
    match read_controller_request_blocking(controller, ZX_TIME_INFINITE) {
        Ok(ControllerRequest::Stop) => 0,
        Ok(ControllerRequest::Kill) => 137,
        Err(_) => 1,
    }
}

fn read_component_start_info_minimal(
    bootstrap_channel: zx_handle_t,
) -> Result<MinimalStartInfo, zx_status_t> {
    let mut bytes = [0u8; MAX_BOOTSTRAP_MESSAGE_BYTES];
    let mut handles = [ZX_HANDLE_INVALID; MAX_BOOTSTRAP_MESSAGE_HANDLES];
    let (actual_bytes, actual_handles) =
        read_channel_blocking(bootstrap_channel, &mut bytes, &mut handles)?;
    let start_info = ComponentStartInfo::decode_channel_message(
        &bytes[..actual_bytes],
        &handles[..actual_handles],
    )
    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    minimal_start_info_from_component(start_info)
}

fn minimal_start_info_from_component(
    start_info: ComponentStartInfo,
) -> Result<MinimalStartInfo, zx_status_t> {
    let role = match start_info.args.first().map(String::as_str) {
        Some(CHILD_ROLE_PROVIDER) => MinimalRole::Provider,
        Some(CHILD_ROLE_CLIENT) => MinimalRole::Client,
        Some(CHILD_ROLE_CONTROLLER_WORKER) => MinimalRole::ControllerWorker,
        _ => MinimalRole::Unknown,
    };
    let mut svc = None;
    for entry in start_info.namespace_entries {
        let handle = entry.handle;
        let path = entry.path;
        if path == SVC_NAMESPACE_PATH {
            svc = Some(handle);
        }
    }
    let mut status = None;
    for entry in start_info.numbered_handles {
        match entry.id {
            STARTUP_HANDLE_COMPONENT_STATUS => status = Some(entry.handle),
            _ => {}
        }
    }
    Ok(MinimalStartInfo {
        role,
        svc,
        status,
        outgoing: start_info.outgoing_dir_server_end,
        controller: start_info.controller_channel,
    })
}

fn decode_resolved_component(bytes: &[u8]) -> Result<ResolvedComponent, zx_status_t> {
    let decl = ComponentDecl::decode_binary(bytes).map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok(ResolvedComponent {
        decl,
        package_dir: None,
        config_blob: None,
    })
}

fn lookup_use_decl<'a>(
    decl: &'a ComponentDecl,
    kind: CapabilityKind,
    source_name: Option<&str>,
) -> Result<&'a UseDecl, zx_status_t> {
    let use_decl = decl
        .uses
        .iter()
        .find(|use_decl| {
            use_decl.kind == kind
                && source_name.is_none_or(|name| use_decl.source_name.as_str() == name)
        })
        .ok_or(ZX_ERR_NOT_FOUND)?;
    match kind {
        CapabilityKind::Runner | CapabilityKind::Resolver => {
            if use_decl.target_path.is_some() {
                return Err(ZX_ERR_INVALID_ARGS);
            }
        }
        CapabilityKind::Protocol | CapabilityKind::Directory => {}
    }
    Ok(use_decl)
}

fn resolve_with_realm(
    realm: &ComponentDecl,
    resolvers: &ResolverRegistry,
    url: &str,
) -> Result<ResolvedComponent, zx_status_t> {
    let resolver = lookup_use_decl(realm, CapabilityKind::Resolver, None)?;
    resolvers.resolve(&resolver.source_name, url)
}

fn resolve_root_child(
    root: &ResolvedComponent,
    resolvers: &ResolverRegistry,
    name: &str,
) -> Result<(ResolvedComponent, StartupMode), zx_status_t> {
    let child = root
        .decl
        .children
        .iter()
        .find(|child| child.name == name)
        .ok_or(ZX_ERR_NOT_FOUND)?;
    let resolved = resolve_with_realm(&root.decl, resolvers, &child.url)?;
    Ok((resolved, child.startup))
}

fn map_resolve_error(error: nexus_component::ResolveError) -> zx_status_t {
    match error {
        nexus_component::ResolveError::InvalidUrl => ZX_ERR_INVALID_ARGS,
        nexus_component::ResolveError::UnsupportedScheme => ZX_ERR_NOT_SUPPORTED,
        nexus_component::ResolveError::NotFound => ZX_ERR_NOT_FOUND,
    }
}

fn build_namespace_entries(
    decl: &ComponentDecl,
    registry: &mut CapabilityRegistry,
) -> Result<Vec<NamespaceEntry>, zx_status_t> {
    let mut entries = Vec::new();
    for use_decl in &decl.uses {
        match use_decl.kind {
            CapabilityKind::Protocol | CapabilityKind::Directory => {
                let Some(path) = &use_decl.target_path else {
                    return Err(ZX_ERR_INVALID_ARGS);
                };
                let handle = registry.take_protocol(&use_decl.source_name)?;
                entries.push(NamespaceEntry {
                    path: path.clone(),
                    handle,
                });
            }
            CapabilityKind::Runner | CapabilityKind::Resolver => {}
        }
    }
    Ok(entries)
}

fn publish_protocols(
    decl: &ComponentDecl,
    registry: &mut CapabilityRegistry,
    outgoing: zx_handle_t,
) {
    for expose in &decl.exposes {
        if expose.target_name == ECHO_PROTOCOL_NAME {
            registry.publish_protocol(&expose.target_name, outgoing);
            return;
        }
    }
}

fn read_directory_open_request_minimal(
    handle: zx_handle_t,
) -> Result<(bool, zx_handle_t), zx_status_t> {
    let mut bytes = [0u8; MAX_SMALL_CHANNEL_BYTES];
    let mut handles = [ZX_HANDLE_INVALID; MAX_SMALL_CHANNEL_HANDLES];
    let (actual_bytes, actual_handles) = read_channel_blocking(handle, &mut bytes, &mut handles)?;
    let request = DirectoryOpenRequest::decode_channel_message(
        &bytes[..actual_bytes],
        &handles[..actual_handles],
    )
    .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    Ok((request.path == ECHO_PROTOCOL_NAME, request.object))
}

fn read_directory_open_request_blocking(
    handle: zx_handle_t,
    deadline: zx_time_t,
) -> Result<DirectoryOpenRequest, zx_status_t> {
    wait_for_channel_readable(handle, deadline)?;
    let mut bytes = [0u8; MAX_SMALL_CHANNEL_BYTES];
    let mut handles = [ZX_HANDLE_INVALID; MAX_SMALL_CHANNEL_HANDLES];
    let (actual_bytes, actual_handles) = read_channel_fixed(handle, &mut bytes, &mut handles)?;
    DirectoryOpenRequest::decode_channel_message(&bytes[..actual_bytes], &handles[..actual_handles])
        .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)
}

fn forward_directory_open_request(
    handle: zx_handle_t,
    request: DirectoryOpenRequest,
) -> zx_status_t {
    let encoded = request.encode_channel_message();
    zx_channel_write(
        handle,
        0,
        encoded.bytes.as_ptr(),
        encoded.bytes.len() as u32,
        encoded.handles.as_ptr(),
        encoded.handles.len() as u32,
    )
}

fn send_controller_event(handle: zx_handle_t, return_code: i32) -> zx_status_t {
    let encoded = ControllerEvent::OnTerminated {
        return_code: i64::from(return_code),
    }
    .encode_channel_message();
    zx_channel_write(
        handle,
        0,
        encoded.bytes.as_ptr(),
        encoded.bytes.len() as u32,
        core::ptr::null(),
        0,
    )
}

fn send_status_event(handle: zx_handle_t, return_code: i32) -> zx_status_t {
    let bytes = i64::from(return_code).to_le_bytes();
    zx_channel_write(
        handle,
        0,
        bytes.as_ptr(),
        bytes.len() as u32,
        core::ptr::null(),
        0,
    )
}

fn try_read_controller_event(handle: zx_handle_t) -> Result<Option<i64>, zx_status_t> {
    let mut bytes = [0u8; 32];
    let mut handles = [ZX_HANDLE_INVALID; MAX_SMALL_CHANNEL_HANDLES];
    let (actual_bytes, actual_handles) = match read_channel_fixed(handle, &mut bytes, &mut handles)
    {
        Ok(message) => message,
        Err(ZX_ERR_SHOULD_WAIT) => return Ok(None),
        Err(status) => return Err(status),
    };
    if actual_handles != 0 {
        return Err(ZX_ERR_IO_DATA_INTEGRITY);
    }
    let event = ControllerEvent::decode_channel_message(&bytes[..actual_bytes], &[])
        .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)?;
    match event {
        ControllerEvent::OnTerminated { return_code } => Ok(Some(return_code)),
    }
}

fn send_controller_request(handle: zx_handle_t, request: ControllerRequest) -> zx_status_t {
    let encoded = request.encode_channel_message();
    zx_channel_write(
        handle,
        0,
        encoded.bytes.as_ptr(),
        encoded.bytes.len() as u32,
        core::ptr::null(),
        0,
    )
}

fn read_controller_request_blocking(
    handle: zx_handle_t,
    deadline: zx_time_t,
) -> Result<ControllerRequest, zx_status_t> {
    wait_for_channel_readable(handle, deadline)?;
    let mut bytes = [0u8; 32];
    let mut handles = [ZX_HANDLE_INVALID; MAX_SMALL_CHANNEL_HANDLES];
    let (actual_bytes, actual_handles) = read_channel_fixed(handle, &mut bytes, &mut handles)?;
    ControllerRequest::decode_channel_message(&bytes[..actual_bytes], &handles[..actual_handles])
        .map_err(|_| ZX_ERR_IO_DATA_INTEGRITY)
}

fn read_controller_event_blocking(
    handle: zx_handle_t,
    deadline: zx_time_t,
) -> Result<i64, zx_status_t> {
    wait_for_channel_readable(handle, deadline)?;
    try_read_controller_event(handle)?.ok_or(axle_types::status::ZX_ERR_SHOULD_WAIT)
}

fn read_controller_event_polling(handle: zx_handle_t) -> Result<i64, zx_status_t> {
    for _ in 0..50_000_000 {
        if let Some(code) = try_read_controller_event(handle)? {
            return Ok(code);
        }
        core::hint::spin_loop();
    }
    Err(ZX_ERR_SHOULD_WAIT)
}

fn record_child_stage(child_marker: u64, stage: u64, status: zx_status_t) {
    let _ = (child_marker, stage, status);
}

fn read_channel_fixed(
    handle: zx_handle_t,
    bytes: &mut [u8],
    handles: &mut [zx_handle_t],
) -> Result<(usize, usize), zx_status_t> {
    let mut actual_bytes = 0u32;
    let mut actual_handles = 0u32;
    let status = zx_channel_read(
        handle,
        0,
        bytes.as_mut_ptr(),
        handles.as_mut_ptr(),
        bytes.len() as u32,
        handles.len() as u32,
        &mut actual_bytes,
        &mut actual_handles,
    );
    if status != ZX_OK {
        return Err(status);
    }
    Ok((actual_bytes as usize, actual_handles as usize))
}

fn read_channel_blocking(
    handle: zx_handle_t,
    bytes: &mut [u8],
    handles: &mut [zx_handle_t],
) -> Result<(usize, usize), zx_status_t> {
    loop {
        match read_channel_fixed(handle, bytes, handles) {
            Ok(message) => return Ok(message),
            Err(ZX_ERR_SHOULD_WAIT) => wait_for_channel_readable(handle, ZX_TIME_INFINITE)?,
            Err(status) => return Err(status),
        }
    }
}

fn wait_for_channel_readable(handle: zx_handle_t, deadline: zx_time_t) -> Result<(), zx_status_t> {
    let mut observed = 0;
    let status = zx_object_wait_one(
        handle,
        ZX_CHANNEL_READABLE | ZX_CHANNEL_PEER_CLOSED,
        deadline,
        &mut observed,
    );
    if status != ZX_OK {
        return Err(status);
    }
    if (observed & ZX_CHANNEL_READABLE) != 0 {
        return Ok(());
    }
    if (observed & ZX_CHANNEL_PEER_CLOSED) != 0 {
        return Err(axle_types::status::ZX_ERR_PEER_CLOSED);
    }
    Err(axle_types::status::ZX_ERR_SHOULD_WAIT)
}

fn wait_for_terminated(
    handle: zx_handle_t,
    deadline: zx_time_t,
) -> Result<zx_signals_t, zx_status_t> {
    let mut observed = 0u32;
    let status = zx_object_wait_one(handle, ZX_TASK_TERMINATED, deadline, &mut observed);
    if status != ZX_OK {
        return Err(status);
    }
    Ok(observed)
}

fn encode_directory_open_request_minimal(
    out: &mut [u8],
    path: &str,
    flags: u32,
) -> Result<usize, zx_status_t> {
    let mut writer = WireWriter::new(out);
    writer.write_message(MESSAGE_KIND_DIRECTORY_OPEN)?;
    writer.write_str(path)?;
    writer.write_u32(flags)?;
    Ok(writer.len())
}

struct WireWriter<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl<'a> WireWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write_message(&mut self, kind: u8) -> Result<(), zx_status_t> {
        self.write_bytes(COMPONENT_MESSAGE_MAGIC)?;
        self.write_u16(COMPONENT_WIRE_VERSION)?;
        self.write_u8(kind)
    }

    fn write_u8(&mut self, value: u8) -> Result<(), zx_status_t> {
        self.write_bytes(&[value])
    }

    fn write_u16(&mut self, value: u16) -> Result<(), zx_status_t> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_u32(&mut self, value: u32) -> Result<(), zx_status_t> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_str(&mut self, value: &str) -> Result<(), zx_status_t> {
        self.write_u32(value.len() as u32)?;
        self.write_bytes(value.as_bytes())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), zx_status_t> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
        let dst = self
            .bytes
            .get_mut(self.len..end)
            .ok_or(ZX_ERR_IO_DATA_INTEGRITY)?;
        dst.copy_from_slice(bytes);
        self.len = end;
        Ok(())
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

fn write_summary(summary: &ComponentSummary) {
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

fn read_slot(index: usize) -> u64 {
    // SAFETY: the kernel maps one shared result page at `USER_SHARED_BASE` for
    // the bootstrap userspace runner, and all indices in this file are within
    // the fixed slot table exported by `kernel/axle-kernel/src/userspace.rs`.
    unsafe { slot_ptr(index).read_volatile() }
}

fn write_slot(index: usize, value: u64) {
    // SAFETY: the kernel-owned shared result page is writable by the bootstrap
    // userspace runner for these fixed diagnostic slots.
    unsafe { slot_ptr(index).write_volatile(value) }
}

fn slot_ptr(index: usize) -> *mut u64 {
    (USER_SHARED_BASE as *mut u64).wrapping_add(index)
}
