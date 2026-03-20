use super::super::*;

use alloc::vec::Vec;

use crate::services::{BootAssetEntry, BootstrapNamespace};

pub(super) fn build_starnix_namespace() -> Result<nexus_io::ProcessNamespace, zx_status_t> {
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
    crate::push_busybox_shell_runtime_assets(&mut assets);
    crate::push_busybox_shell_decl_assets(&mut assets);
    let bootstrap = BootstrapNamespace::build(&assets)?;
    let mut mounts = bootstrap.namespace().mounts().clone();
    mounts.insert("/", bootstrap.boot_root())?;
    Ok(nexus_io::ProcessNamespace::new(mounts))
}
