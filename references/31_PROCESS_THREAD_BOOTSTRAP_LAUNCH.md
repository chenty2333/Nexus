# 31 - bootstrap launch

Part of the Axle process/thread subsystem.

See also:
- `10_ARCH_X86_64_STARTUP.md` - ring3 entry path
- `11_SYSCALL_DISPATCH.md` - process/thread syscalls
- `20_HANDLE_CAPABILITY.md` - seeded bootstrap handles and rights
- `21_OBJECT_MODEL.md` - process, thread, VMO, and VMAR objects
- `30_PROCESS_THREAD.md` - process/thread index
- `32_SCHEDULER_LIFECYCLE.md` - scheduler behavior after launch
- `40_VM.md` - process-image and address-space setup
- `41_VM_VMO_VMAR.md` - root VMAR and image mapping details
- `43_VM_EXEC_PAGER_DEVICE_VM.md` - execute and pager status

## Scope

This file describes the current bootstrap userspace launch path and process/thread creation model in the repository.

## Current boot path

The current BSP startup path is:

1. arch init
2. PMM and late heap init
3. syscall and trap init
4. timer init
5. bootstrap userspace preparation
6. SMP startup
7. ring3 entry into the bootstrap userspace runner

That path is wired from `kernel/axle-kernel/src/main.rs` and `kernel/axle-kernel/src/userspace.rs`.

## Bootstrap userspace image sources

Current bootstrap userspace code may come from:

- embedded user-code bytes
- a QEMU loader-provided blob

The current component bootstrap path also seeds extra boot-backed code-image
VMOs for the dedicated `echo-provider`, `echo-client`, and
`controller-worker` binaries. The kernel exports those VMO handles through the
fixed bootstrap shared-page slot table so `nexus-init` can pick a child image
by manifest `program.binary` path instead of only reusing its own image.
`nexus-init` now turns those seeded VMOs plus its compiled manifest blobs into
one local `/boot` asset tree, and both the built-in boot resolver and
`ElfRunner` consume that tree through the shared `FdOps` / namespace layer.
That local namespace layer now also carries one logical-root / `cwd` path-walk
helper and exposes read-only `GetVmo` handles for both the seeded code-image
VMOs and byte-backed boot/package assets such as compiled manifests.

`userspace.rs` contains the current image-loading and bootstrap page-population helpers.

The current QEMU loader layout for the component bootstrap path is:

- `nexus-init` at `0x0100_0000`
- `echo-provider` at `0x0180_0000`
- `echo-client` at `0x0200_0000`
- `controller-worker` at `0x0280_0000`

The kernel bootstrap PMM reserved floor now also tracks the observed end of
that loader-backed image span so those raw ELF bytes are not recycled as free
RAM before the pager-backed bootstrap VMOs are created. The current raw
loader-file bound is also wider than the earlier 4 MiB shape so the larger
Rust component binaries still import successfully in dev builds.

The bootstrap address space is prewired enough to exercise real VM behavior early:

- code and shared windows are mapped into the fixed bootstrap userspace range
- the fixed bootstrap code window is now wide enough for the Rust dispatcher/executor runner,
  so the shared summary pages sit above the loaded image instead of overlapping it
- the bootstrap stack is marked COW so the first write exercises the fault/COW path

## Process creation model

- `create_process()` creates:
  - one new process record
  - one new address space
  - one root VMAR handle
- The parent process handle authorizes creation; it is not currently a VM inheritance mechanism.
- `create_thread()` creates a `New` thread in a target process.
- `prepare_process_start()` now resolves a process image layout from either:
  - an imported metadata-backed image VMO
  - a directly parsed ELF64 ET_EXEC image VMO
  and returns prepared start parameters plus the initial user stack image.
- `start_process()` transitions the process from `Created` to `Started` and starts one thread.

## Thread start model

- `start_thread()` requires:
  - an existing thread object
  - a started process
  - a user entry that currently resolves to an executable mapping
  - a user stack that currently resolves to a writable mapping
- The thread receives a captured `UserContext` with:
  - entry RIP
  - user stack
  - two argument registers

## Process images

- The current kernel already has `ProcessImageLayout` and `ProcessImageSegment`.
- Imported bootstrap code VMOs can carry one image layout for later child-process setup.
- The current bootstrap registry can also publish pager-backed code-image VMOs
  for additional boot-loaded component binaries so generic child launch can use
  the same `prepare_process_start()` path as the root manager.
- VMOs without embedded layout metadata may now be parsed directly as ELF64 ET_EXEC images and
  converted into the same `ProcessImageLayout`.
- Direct ELF layout parsing now accepts non-page-aligned `PT_LOAD` segments as long as
  `p_vaddr % PAGE_SIZE == p_offset % PAGE_SIZE`; the kernel maps the page-aligned coverage and
  preserves the intra-page delta when copying private writable segments.
- Generic launch now builds one minimal SysV-style startup stack image containing:
  - `argc`
  - one synthetic `argv[0]`
  - empty `envp`
  - a small `auxv` set including `AT_PAGESZ`, `AT_ENTRY`, and ELF program-header metadata when available
- Generic child launch currently reserves one fixed multi-page initial stack window
  (currently 16 pages) above `USER_STACK_VA`; it is intentionally not yet a grow-on-demand stack.

## Phase-one gate contract

The first generic-launch contract is now implemented without changing syscall signatures.

- `prepare_process_start()` plus `start_process()` define the generic image-launch path.
- `ax_process_prepare_linux_exec()` is now a separate Linux / Starnix-facing launch helper so the
  generic path does not accumulate Linux `argv` / `envp` / `auxv` / vDSO policy.
- The current v1 contract keeps the blob intentionally opaque at the syscall layer, but the shared
  ABI now exposes one fixed header plus appended stack-image bytes. The kernel maps the ELF image
  using the normal process-image layout path and installs the caller-provided Linux stack image
  into the fixed startup stack VMO.
- The current Round-1 Starnix bootstrap path is the first consumer of that helper: the userspace
  executive prepares one Linux stack image, calls `ax_process_prepare_linux_exec()`, then starts
  the target thread with the returned entry and stack pointer.
- `ProcessImageLayout` is the common launch artifact for:
  - bootstrap image import
  - internal code-image VMOs
  - later ELF-loader output
- `start_process()` accepts a non-invalid `arg_handle`, snapshots it from the parent, installs it into the child process before first-thread start, and hands the child-side raw handle to the initial thread state.
- Generic launch must build one initial stack/register state for:
  - entry RIP
  - user stack
  - `argv`
  - `environ`
  - `auxv`
  - arg-handle handoff
- Child launch, exit, and reap semantics must no longer depend on a runner-specific path in `userspace.rs`.
- The bootstrap runner becomes one consumer of that path, not a separate launch mechanism.
- Conformance gate:
  - contract: `must.process.generic_launch_phase1`
  - minimal scenario: `kernel.process.generic_launch_phase1`

## Current limitations

- Generic init/service launching above the raw process API is not done yet.
- The phase-three component-manager contract is now frozen around that raw process API:
  `process_start(arg_handle)` is treated as "child bootstrap channel", and the
  higher-level start payload moves over that channel instead of adding new
  process-start syscall arguments.
- The current `nexus-init` root manager now chooses one root manifest URL at
  build/boot configuration time and resolves it through the built-in
  `boot-resolver` provider before launching child components.
- The built-in `boot-resolver` no longer reads from one in-memory resolver
  table; it now opens compiled manifests from the local `/boot/manifests/*`
  tree.
- The current eager-topology component smoke already exercises that contract:
  `nexus-init` launches dedicated boot-backed child images by sending
  `ComponentStartInfo` over the bootstrap channel and then observing controller
  events from the started child.
- The initial BSP ring3 entry still comes from bootstrap-specific bring-up plumbing, even though
  child process launch now uses the generic path.
- The current ELF parser is intentionally narrow:
  - ELF64
  - little-endian
  - x86_64
  - ET_EXEC
- The startup stack image is intentionally minimal today and does not yet carry the eventual full
  launcher-provided `argv` / `environ` contract.
- Linux exec-prepare currently supports one fixed startup stack VMO and an opaque v1 exec-spec
  header plus appended stack-image bytes; it is enough for the Round-1 Starnix bootstrap path but
  is not yet the final `execve()` replacement contract.
