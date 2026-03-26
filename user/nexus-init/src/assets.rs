use alloc::vec::Vec;

use crate::services::BootAssetEntry;

pub(crate) const ROOT_DECL_EAGER_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component.nxcd"));
pub(crate) const ROOT_DECL_ROUND3_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component_round3.nxcd"));
pub(crate) const ROOT_DECL_STARNIX_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component_starnix.nxcd"));
pub(crate) const ROOT_DECL_STARNIX_FD_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component_starnix_fd.nxcd"));
pub(crate) const ROOT_DECL_STARNIX_ROUND2_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round2.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND3_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round3.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND4_FUTEX_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round4_futex.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND4_SIGNAL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round4_signal.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND5_EPOLL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round5_epoll.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND6_EVENTFD_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_eventfd.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND6_TIMERFD_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_timerfd.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND6_SIGNALFD_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_signalfd.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND6_FUTEX_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_futex.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND6_SCM_RIGHTS_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_scm_rights.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND6_PIDFD_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_pidfd.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND6_PROC_JOB_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_proc_job.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND6_PROC_CONTROL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_proc_control.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_ROUND6_PROC_TTY_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_round6_proc_tty.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_RUNTIME_FD_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_fd.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_RUNTIME_MISC_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_misc.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_RUNTIME_PROCESS_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_process.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_RUNTIME_NET_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_net.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_RUNTIME_FS_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_fs.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_RUNTIME_TLS_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_runtime_tls.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_DYNAMIC_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_dynamic.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_DYNAMIC_TLS_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_dynamic_tls.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_DYNAMIC_RUNTIME_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_dynamic_runtime.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_DYNAMIC_PIE_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_dynamic_pie.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_GLIBC_HELLO_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_glibc_hello.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_SHELL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_shell.nxcd"
));
pub(crate) const ROOT_DECL_STARNIX_NET_SHELL_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_starnix_net_shell.nxcd"
));
pub(crate) const ROOT_DECL_NET_DATAPLANE_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/root_component_net_dataplane.nxcd"
));
pub(crate) const ROOT_DECL_VMO_SHARED_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/root_component_vmo_shared.nxcd"));
pub(crate) const PROVIDER_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/echo_provider.nxcd"));
pub(crate) const CLIENT_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/echo_client.nxcd"));
pub(crate) const CONTROLLER_WORKER_DECL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/controller_worker.nxcd"));

macro_rules! optional_embedded_bytes {
    ($cfg:meta, $name:ident, $path:literal) => {
        #[cfg($cfg)]
        pub(crate) const $name: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/", $path));
        #[cfg(not($cfg))]
        pub(crate) const $name: &[u8] = &[];
    };
}

optional_embedded_bytes!(
    nexus_init_embed_starnix_hello,
    LINUX_HELLO_DECL_BYTES,
    "linux_hello.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_fd,
    LINUX_FD_SMOKE_DECL_BYTES,
    "linux_fd_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round2,
    LINUX_ROUND2_DECL_BYTES,
    "linux_round2_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round3,
    LINUX_ROUND3_DECL_BYTES,
    "linux_round3_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round4_futex,
    LINUX_ROUND4_FUTEX_DECL_BYTES,
    "linux_round4_futex_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round4_signal,
    LINUX_ROUND4_SIGNAL_DECL_BYTES,
    "linux_round4_signal_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round5_epoll,
    LINUX_ROUND5_EPOLL_DECL_BYTES,
    "linux_round5_epoll_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_eventfd,
    LINUX_ROUND6_EVENTFD_DECL_BYTES,
    "linux_round6_eventfd_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_timerfd,
    LINUX_ROUND6_TIMERFD_DECL_BYTES,
    "linux_round6_timerfd_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_signalfd,
    LINUX_ROUND6_SIGNALFD_DECL_BYTES,
    "linux_round6_signalfd_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_futex,
    LINUX_ROUND6_FUTEX_DECL_BYTES,
    "linux_round6_futex_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_scm_rights,
    LINUX_ROUND6_SCM_RIGHTS_DECL_BYTES,
    "linux_round6_scm_rights_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_pidfd,
    LINUX_ROUND6_PIDFD_DECL_BYTES,
    "linux_round6_pidfd_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_proc_job,
    LINUX_ROUND6_PROC_JOB_DECL_BYTES,
    "linux_round6_proc_job_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_proc_control,
    LINUX_ROUND6_PROC_CONTROL_DECL_BYTES,
    "linux_round6_proc_control_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_proc_tty,
    LINUX_ROUND6_PROC_TTY_DECL_BYTES,
    "linux_round6_proc_tty_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_fd,
    LINUX_RUNTIME_FD_DECL_BYTES,
    "linux_runtime_fd_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_misc,
    LINUX_RUNTIME_MISC_DECL_BYTES,
    "linux_runtime_misc_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_process,
    LINUX_RUNTIME_PROCESS_DECL_BYTES,
    "linux_runtime_process_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_net,
    LINUX_RUNTIME_NET_DECL_BYTES,
    "linux_runtime_net_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_fs,
    LINUX_RUNTIME_FS_DECL_BYTES,
    "linux_runtime_fs_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_tls,
    LINUX_RUNTIME_TLS_DECL_BYTES,
    "linux_runtime_tls_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic,
    LINUX_DYNAMIC_ELF_SMOKE_DECL_BYTES,
    "linux_dynamic_elf_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_tls,
    LINUX_DYNAMIC_TLS_SMOKE_DECL_BYTES,
    "linux_dynamic_tls_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_runtime,
    LINUX_DYNAMIC_RUNTIME_SMOKE_DECL_BYTES,
    "linux_dynamic_runtime_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_pie,
    LINUX_DYNAMIC_PIE_SMOKE_DECL_BYTES,
    "linux_dynamic_pie_smoke.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_glibc_hello,
    LINUX_GLIBC_HELLO_DECL_BYTES,
    "linux_glibc_hello.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_shell,
    LINUX_BUSYBOX_SHELL_DECL_BYTES,
    "linux_busybox_shell.nxcd"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_net_shell,
    LINUX_BUSYBOX_SOCKET_SHELL_DECL_BYTES,
    "linux_busybox_socket_shell.nxcd"
);

optional_embedded_bytes!(
    nexus_init_embed_starnix_hello,
    LINUX_HELLO_BYTES,
    "linux-hello"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_fd,
    LINUX_FD_SMOKE_BYTES,
    "linux-fd-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round2,
    LINUX_ROUND2_BYTES,
    "linux-round2-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round3,
    LINUX_ROUND3_BYTES,
    "linux-round3-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round4_futex,
    LINUX_ROUND4_FUTEX_BYTES,
    "linux-round4-futex-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round4_signal,
    LINUX_ROUND4_SIGNAL_BYTES,
    "linux-round4-signal-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round5_epoll,
    LINUX_ROUND5_EPOLL_BYTES,
    "linux-round5-epoll-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_eventfd,
    LINUX_ROUND6_EVENTFD_BYTES,
    "linux-round6-eventfd-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_timerfd,
    LINUX_ROUND6_TIMERFD_BYTES,
    "linux-round6-timerfd-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_signalfd,
    LINUX_ROUND6_SIGNALFD_BYTES,
    "linux-round6-signalfd-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_futex,
    LINUX_ROUND6_FUTEX_BYTES,
    "linux-round6-futex-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_scm_rights,
    LINUX_ROUND6_SCM_RIGHTS_BYTES,
    "linux-round6-scm-rights-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_pidfd,
    LINUX_ROUND6_PIDFD_BYTES,
    "linux-round6-pidfd-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_proc_job,
    LINUX_ROUND6_PROC_JOB_BYTES,
    "linux-round6-proc-job-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_proc_control,
    LINUX_ROUND6_PROC_CONTROL_BYTES,
    "linux-round6-proc-control-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_round6_proc_tty,
    LINUX_ROUND6_PROC_TTY_BYTES,
    "linux-round6-proc-tty-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_fd,
    LINUX_RUNTIME_FD_BYTES,
    "linux-runtime-fd-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_misc,
    LINUX_RUNTIME_MISC_BYTES,
    "linux-runtime-misc-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_process,
    LINUX_RUNTIME_PROCESS_BYTES,
    "linux-runtime-process-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_net,
    LINUX_RUNTIME_NET_BYTES,
    "linux-runtime-net-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_fs,
    LINUX_RUNTIME_FS_BYTES,
    "linux-runtime-fs-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_runtime_tls,
    LINUX_RUNTIME_TLS_BYTES,
    "linux-runtime-tls-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic,
    LINUX_DYNAMIC_ELF_SMOKE_BYTES,
    "linux-dynamic-elf-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic,
    LINUX_DYNAMIC_MAIN_BYTES,
    "linux-dynamic-main"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic,
    LINUX_DYNAMIC_INTERP_BYTES,
    "ld-nexus-dynamic-smoke.so"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_tls,
    LINUX_DYNAMIC_TLS_SMOKE_BYTES,
    "linux-dynamic-tls-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_tls,
    LINUX_DYNAMIC_TLS_MAIN_BYTES,
    "linux-dynamic-tls-main"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_tls,
    LINUX_DYNAMIC_TLS_INTERP_BYTES,
    "ld-nexus-dynamic-tls.so"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_runtime,
    LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES,
    "linux-dynamic-runtime-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_runtime,
    LINUX_DYNAMIC_RUNTIME_MAIN_BYTES,
    "linux-dynamic-runtime-main"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_runtime,
    LINUX_DYNAMIC_RUNTIME_INTERP_BYTES,
    "ld-nexus-dynamic-runtime.so"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_pie,
    LINUX_DYNAMIC_PIE_SMOKE_BYTES,
    "linux-dynamic-pie-smoke"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_pie,
    LINUX_DYNAMIC_PIE_MAIN_BYTES,
    "linux-dynamic-pie-main"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_dynamic_pie,
    LINUX_DYNAMIC_PIE_INTERP_BYTES,
    "ld-nexus-dynamic-runtime.so"
);
optional_embedded_bytes!(
    nexus_init_embed_starnix_glibc_hello,
    LINUX_GLIBC_HELLO_BYTES,
    "linux-glibc-hello"
);

#[cfg(any(
    nexus_init_embed_starnix_glibc_hello,
    nexus_init_embed_starnix_shell,
    nexus_init_embed_starnix_net_shell
))]
pub(crate) const LINUX_GLIBC_RUNTIME_INTERP_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ld-nexus-glibc.so"));
#[cfg(not(any(
    nexus_init_embed_starnix_glibc_hello,
    nexus_init_embed_starnix_shell,
    nexus_init_embed_starnix_net_shell
)))]
pub(crate) const LINUX_GLIBC_RUNTIME_INTERP_BYTES: &[u8] = &[];

#[cfg(any(
    nexus_init_embed_starnix_glibc_hello,
    nexus_init_embed_starnix_shell,
    nexus_init_embed_starnix_net_shell
))]
pub(crate) const LINUX_GLIBC_RUNTIME_LIBC_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/libc.so.6"));
#[cfg(not(any(
    nexus_init_embed_starnix_glibc_hello,
    nexus_init_embed_starnix_shell,
    nexus_init_embed_starnix_net_shell
)))]
pub(crate) const LINUX_GLIBC_RUNTIME_LIBC_BYTES: &[u8] = &[];

#[cfg(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell))]
pub(crate) const LINUX_BUSYBOX_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/busybox"));
#[cfg(not(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell)))]
pub(crate) const LINUX_BUSYBOX_BYTES: &[u8] = &[];

#[cfg(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell))]
pub(crate) const LINUX_GLIBC_RUNTIME_LIBM_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/libm.so.6"));
#[cfg(not(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell)))]
pub(crate) const LINUX_GLIBC_RUNTIME_LIBM_BYTES: &[u8] = &[];

#[cfg(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell))]
pub(crate) const LINUX_GLIBC_RUNTIME_RESOLV_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/libresolv.so.2"));
#[cfg(not(any(nexus_init_embed_starnix_shell, nexus_init_embed_starnix_net_shell)))]
pub(crate) const LINUX_GLIBC_RUNTIME_RESOLV_BYTES: &[u8] = &[];

pub(crate) const CHILD_ROLE_PROVIDER: &str = "echo-provider";
pub(crate) const CHILD_ROLE_CLIENT: &str = "echo-client";
pub(crate) const CHILD_ROLE_CONTROLLER_WORKER: &str = "controller-worker";
pub(crate) const ROOT_COMPONENT_URL: &str = env!("NEXUS_INIT_ROOT_URL");
const _: &str = env!("NEXUS_INIT_EMBED_STAMP");
pub(crate) const ROOT_BINARY_PATH: &str = "bin/nexus-init";
pub(crate) const PROVIDER_BINARY_PATH: &str = "bin/echo-provider";
pub(crate) const CLIENT_BINARY_PATH: &str = "bin/echo-client";
pub(crate) const CONTROLLER_WORKER_BINARY_PATH: &str = "bin/controller-worker";
pub(crate) const STARNIX_KERNEL_BINARY_PATH: &str = "bin/starnix-kernel";
pub(crate) const LINUX_HELLO_BINARY_PATH: &str = "bin/linux-hello";
pub(crate) const LINUX_FD_SMOKE_BINARY_PATH: &str = "bin/linux-fd-smoke";
pub(crate) const LINUX_ROUND2_BINARY_PATH: &str = "bin/linux-round2-smoke";
pub(crate) const LINUX_ROUND3_BINARY_PATH: &str = "bin/linux-round3-smoke";
pub(crate) const LINUX_ROUND4_FUTEX_BINARY_PATH: &str = "bin/linux-round4-futex-smoke";
pub(crate) const LINUX_ROUND4_SIGNAL_BINARY_PATH: &str = "bin/linux-round4-signal-smoke";
pub(crate) const LINUX_ROUND5_EPOLL_BINARY_PATH: &str = "bin/linux-round5-epoll-smoke";
pub(crate) const LINUX_ROUND6_EVENTFD_BINARY_PATH: &str = "bin/linux-round6-eventfd-smoke";
pub(crate) const LINUX_ROUND6_TIMERFD_BINARY_PATH: &str = "bin/linux-round6-timerfd-smoke";
pub(crate) const LINUX_ROUND6_SIGNALFD_BINARY_PATH: &str = "bin/linux-round6-signalfd-smoke";
pub(crate) const LINUX_ROUND6_FUTEX_BINARY_PATH: &str = "bin/linux-round6-futex-smoke";
pub(crate) const LINUX_ROUND6_SCM_RIGHTS_BINARY_PATH: &str = "bin/linux-round6-scm-rights-smoke";
pub(crate) const LINUX_ROUND6_PIDFD_BINARY_PATH: &str = "bin/linux-round6-pidfd-smoke";
pub(crate) const LINUX_ROUND6_PROC_JOB_BINARY_PATH: &str = "bin/linux-round6-proc-job-smoke";
pub(crate) const LINUX_ROUND6_PROC_CONTROL_BINARY_PATH: &str =
    "bin/linux-round6-proc-control-smoke";
pub(crate) const LINUX_ROUND6_PROC_TTY_BINARY_PATH: &str = "bin/linux-round6-proc-tty-smoke";
pub(crate) const LINUX_RUNTIME_FD_BINARY_PATH: &str = "bin/linux-runtime-fd-smoke";
pub(crate) const LINUX_RUNTIME_MISC_BINARY_PATH: &str = "bin/linux-runtime-misc-smoke";
pub(crate) const LINUX_RUNTIME_PROCESS_BINARY_PATH: &str = "bin/linux-runtime-process-smoke";
pub(crate) const LINUX_RUNTIME_NET_BINARY_PATH: &str = "bin/linux-runtime-net-smoke";
pub(crate) const LINUX_RUNTIME_FS_BINARY_PATH: &str = "bin/linux-runtime-fs-smoke";
pub(crate) const LINUX_RUNTIME_TLS_BINARY_PATH: &str = "bin/linux-runtime-tls-smoke";
pub(crate) const LINUX_DYNAMIC_ELF_SMOKE_BINARY_PATH: &str = "bin/linux-dynamic-elf-smoke";
pub(crate) const LINUX_DYNAMIC_MAIN_BINARY_PATH: &str = "bin/linux-dynamic-main";
pub(crate) const LINUX_DYNAMIC_INTERP_BINARY_PATH: &str = "lib/ld-nexus-dynamic-smoke.so";
pub(crate) const LINUX_DYNAMIC_TLS_SMOKE_BINARY_PATH: &str = "bin/linux-dynamic-tls-smoke";
pub(crate) const LINUX_DYNAMIC_TLS_MAIN_BINARY_PATH: &str = "bin/linux-dynamic-tls-main";
pub(crate) const LINUX_DYNAMIC_TLS_INTERP_BINARY_PATH: &str = "lib/ld-nexus-dynamic-tls.so";
pub(crate) const LINUX_DYNAMIC_RUNTIME_SMOKE_BINARY_PATH: &str = "bin/linux-dynamic-runtime-smoke";
pub(crate) const LINUX_DYNAMIC_RUNTIME_MAIN_BINARY_PATH: &str = "bin/linux-dynamic-runtime-main";
pub(crate) const LINUX_DYNAMIC_RUNTIME_INTERP_BINARY_PATH: &str = "lib/ld-nexus-dynamic-runtime.so";
pub(crate) const LINUX_DYNAMIC_PIE_SMOKE_BINARY_PATH: &str = "bin/linux-dynamic-pie-smoke";
pub(crate) const LINUX_DYNAMIC_PIE_MAIN_BINARY_PATH: &str = "bin/linux-dynamic-pie-main";
pub(crate) const LINUX_DYNAMIC_PIE_INTERP_BINARY_PATH: &str = "lib/ld-nexus-dynamic-runtime.so";
pub(crate) const LINUX_GLIBC_HELLO_BINARY_PATH: &str = "bin/linux-glibc-hello";
pub(crate) const LINUX_BUSYBOX_BINARY_PATH: &str = "bin/busybox";
pub(crate) const LINUX_BUSYBOX_SHELL_BINARY_PATH: &str = "bin/sh";
pub(crate) const LINUX_BUSYBOX_LS_BINARY_PATH: &str = "bin/ls";
pub(crate) const LINUX_BUSYBOX_CAT_BINARY_PATH: &str = "bin/cat";
pub(crate) const LINUX_BUSYBOX_ECHO_BINARY_PATH: &str = "bin/echo";
pub(crate) const LINUX_BUSYBOX_MKDIR_BINARY_PATH: &str = "bin/mkdir";
pub(crate) const LINUX_BUSYBOX_RM_BINARY_PATH: &str = "bin/rm";
pub(crate) const LINUX_BUSYBOX_PS_BINARY_PATH: &str = "bin/ps";
pub(crate) const LINUX_BUSYBOX_PASSWD_PATH: &str = "etc/passwd";
pub(crate) const LINUX_GLIBC_RUNTIME_INTERP_BINARY_PATH: &str = "lib/ld-nexus-glibc.so";
pub(crate) const LINUX_GLIBC_RUNTIME_INTERP_CANONICAL_PATH: &str = "lib/ld-linux-x86-64.so.2";
pub(crate) const LINUX_GLIBC_RUNTIME_INTERP_LIB64_PATH: &str = "lib64/ld-linux-x86-64.so.2";
pub(crate) const LINUX_GLIBC_RUNTIME_LIBC_BINARY_PATH: &str = "lib/libc.so.6";
pub(crate) const LINUX_GLIBC_RUNTIME_LIBC_LIB64_PATH: &str = "lib64/libc.so.6";
pub(crate) const LINUX_GLIBC_RUNTIME_LIBM_BINARY_PATH: &str = "lib/libm.so.6";
pub(crate) const LINUX_GLIBC_RUNTIME_LIBM_LIB64_PATH: &str = "lib64/libm.so.6";
pub(crate) const LINUX_GLIBC_RUNTIME_RESOLV_BINARY_PATH: &str = "lib/libresolv.so.2";
pub(crate) const LINUX_GLIBC_RUNTIME_RESOLV_LIB64_PATH: &str = "lib64/libresolv.so.2";
pub(crate) const SVC_NAMESPACE_PATH: &str = "/svc";
pub(crate) const ECHO_PROTOCOL_NAME: &str = "nexus.echo.Echo";
pub(crate) const ECHO_REQUEST: &[u8] = b"hello";
pub(crate) const CHILD_MARKER_PROVIDER: u64 = 0x4e58_4300_0000_0001;
pub(crate) const CHILD_MARKER_CLIENT: u64 = 0x4e58_4300_0000_0002;
pub(crate) const CHILD_MARKER_CONTROLLER_WORKER: u64 = 0x4e58_4300_0000_0003;
pub(crate) const CHILD_MARKER_STARNIX_KERNEL: u64 = 0x4e58_4300_0000_0004;
pub(crate) const STARTUP_HANDLE_COMPONENT_STATUS: u32 = 1;
pub(crate) const STARTUP_HANDLE_STARNIX_IMAGE_VMO: u32 = 2;
pub(crate) const STARTUP_HANDLE_STARNIX_PARENT_PROCESS: u32 = 3;
pub(crate) const STARTUP_HANDLE_STARNIX_STDOUT: u32 = 4;
pub(crate) const STARTUP_HANDLE_STARNIX_STDIN: u32 = 5;
pub(crate) const MAX_SMALL_CHANNEL_BYTES: usize = 128;
pub(crate) const MAX_SMALL_CHANNEL_HANDLES: usize = 1;
pub(crate) const STARNIX_HELLO_EXPECTED_STDOUT: &[u8] = b"hello from linux-hello\n";
pub(crate) const STARNIX_FD_SMOKE_EXPECTED_STDOUT: &[u8] = b"pipe\nsock\n";
pub(crate) const STARNIX_ROUND2_EXPECTED_STDOUT: &[u8] = b"round2 ok\n";
pub(crate) const STARNIX_ROUND3_EXPECTED_STDOUT: &[u8] = b"hello from linux-hello\nround3 ok\n";
pub(crate) const STARNIX_ROUND4_FUTEX_EXPECTED_STDOUT: &[u8] = b"round4 futex ok\n";
pub(crate) const STARNIX_ROUND4_SIGNAL_EXPECTED_STDOUT: &[u8] = b"round4 signal ok\n";
pub(crate) const STARNIX_ROUND5_EPOLL_EXPECTED_STDOUT: &[u8] = b"round5 epoll ok\n";
pub(crate) const STARNIX_ROUND6_EVENTFD_EXPECTED_STDOUT: &[u8] = b"round6 eventfd ok\n";
pub(crate) const STARNIX_ROUND6_TIMERFD_EXPECTED_STDOUT: &[u8] = b"round6 timerfd ok\n";
pub(crate) const STARNIX_ROUND6_SIGNALFD_EXPECTED_STDOUT: &[u8] = b"round6 signalfd ok\n";
pub(crate) const STARNIX_ROUND6_FUTEX_EXPECTED_STDOUT: &[u8] = b"round6 futex ok\n";
pub(crate) const STARNIX_ROUND6_SCM_RIGHTS_EXPECTED_STDOUT: &[u8] = b"round6 scm_rights ok\n";
pub(crate) const STARNIX_ROUND6_PIDFD_EXPECTED_STDOUT: &[u8] = b"round6 pidfd ok\n";
pub(crate) const STARNIX_ROUND6_PROC_JOB_EXPECTED_STDOUT: &[u8] =
    b"proc-fd bridge ok\nround6 proc_job ok\n";
pub(crate) const STARNIX_ROUND6_PROC_CONTROL_EXPECTED_STDOUT: &[u8] = b"round6 proc_control ok\n";
pub(crate) const STARNIX_ROUND6_PROC_TTY_EXPECTED_STDOUT: &[u8] = b"tround6 proc_tty ok\n";
pub(crate) const STARNIX_RUNTIME_FD_EXPECTED_STDOUT: &[u8] = b"runtime fd ok\n";
pub(crate) const STARNIX_RUNTIME_MISC_EXPECTED_STDOUT: &[u8] = b"runtime misc ok\n";
pub(crate) const STARNIX_RUNTIME_PROCESS_EXPECTED_STDOUT: &[u8] = b"runtime process ok\n";
pub(crate) const STARNIX_RUNTIME_NET_EXPECTED_STDOUT: &[u8] = b"runtime net ok\n";
pub(crate) const STARNIX_RUNTIME_FS_EXPECTED_STDOUT: &[u8] = b"runtime fs ok\n";
pub(crate) const STARNIX_RUNTIME_TLS_EXPECTED_STDOUT: &[u8] = b"runtime tls ok\n";
pub(crate) const STARNIX_DYNAMIC_ELF_EXPECTED_STDOUT: &[u8] = b"dynamic interp ok\n";
pub(crate) const STARNIX_DYNAMIC_TLS_EXPECTED_STDOUT: &[u8] = b"dynamic tls ok\n";
pub(crate) const STARNIX_DYNAMIC_RUNTIME_EXPECTED_STDOUT: &[u8] = b"dynamic runtime ok\n";
pub(crate) const STARNIX_DYNAMIC_PIE_EXPECTED_STDOUT: &[u8] = b"dynamic pie ok\n";
pub(crate) const STARNIX_GLIBC_HELLO_EXPECTED_STDOUT: &[u8] = b"glibc hello\n";
pub(crate) const STARNIX_SHELL_EXPECTED_STDOUT: &[u8] = b"";
const LINUX_BUSYBOX_PASSWD_BYTES: &[u8] = b"root:x:0:0:root:/root:/bin/sh\n";

struct EmbeddedAsset {
    path: &'static str,
    bytes: &'static [u8],
}

fn push_embedded_assets(assets: &mut Vec<BootAssetEntry>, entries: &[EmbeddedAsset]) {
    for entry in entries {
        if !entry.bytes.is_empty() {
            assets.push(BootAssetEntry::bytes(entry.path, entry.bytes));
        }
    }
}

pub(crate) fn push_starnix_runtime_assets(assets: &mut Vec<BootAssetEntry>) {
    push_embedded_assets(
        assets,
        &[
            EmbeddedAsset {
                path: LINUX_HELLO_BINARY_PATH,
                bytes: LINUX_HELLO_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_FD_SMOKE_BINARY_PATH,
                bytes: LINUX_FD_SMOKE_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND2_BINARY_PATH,
                bytes: LINUX_ROUND2_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND3_BINARY_PATH,
                bytes: LINUX_ROUND3_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND4_FUTEX_BINARY_PATH,
                bytes: LINUX_ROUND4_FUTEX_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND4_SIGNAL_BINARY_PATH,
                bytes: LINUX_ROUND4_SIGNAL_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND5_EPOLL_BINARY_PATH,
                bytes: LINUX_ROUND5_EPOLL_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND6_EVENTFD_BINARY_PATH,
                bytes: LINUX_ROUND6_EVENTFD_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND6_TIMERFD_BINARY_PATH,
                bytes: LINUX_ROUND6_TIMERFD_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND6_SIGNALFD_BINARY_PATH,
                bytes: LINUX_ROUND6_SIGNALFD_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND6_FUTEX_BINARY_PATH,
                bytes: LINUX_ROUND6_FUTEX_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND6_SCM_RIGHTS_BINARY_PATH,
                bytes: LINUX_ROUND6_SCM_RIGHTS_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND6_PIDFD_BINARY_PATH,
                bytes: LINUX_ROUND6_PIDFD_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND6_PROC_JOB_BINARY_PATH,
                bytes: LINUX_ROUND6_PROC_JOB_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND6_PROC_CONTROL_BINARY_PATH,
                bytes: LINUX_ROUND6_PROC_CONTROL_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_ROUND6_PROC_TTY_BINARY_PATH,
                bytes: LINUX_ROUND6_PROC_TTY_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_RUNTIME_FD_BINARY_PATH,
                bytes: LINUX_RUNTIME_FD_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_RUNTIME_MISC_BINARY_PATH,
                bytes: LINUX_RUNTIME_MISC_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_RUNTIME_PROCESS_BINARY_PATH,
                bytes: LINUX_RUNTIME_PROCESS_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_RUNTIME_NET_BINARY_PATH,
                bytes: LINUX_RUNTIME_NET_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_RUNTIME_FS_BINARY_PATH,
                bytes: LINUX_RUNTIME_FS_BYTES,
            },
            EmbeddedAsset {
                path: LINUX_RUNTIME_TLS_BINARY_PATH,
                bytes: LINUX_RUNTIME_TLS_BYTES,
            },
        ],
    );

    if !LINUX_DYNAMIC_ELF_SMOKE_BYTES.is_empty() {
        push_embedded_assets(
            assets,
            &[
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_ELF_SMOKE_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_ELF_SMOKE_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_MAIN_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_MAIN_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_INTERP_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_INTERP_BYTES,
                },
            ],
        );
    }
    if !LINUX_DYNAMIC_TLS_SMOKE_BYTES.is_empty() {
        push_embedded_assets(
            assets,
            &[
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_TLS_SMOKE_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_TLS_SMOKE_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_TLS_MAIN_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_TLS_MAIN_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_TLS_INTERP_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_TLS_INTERP_BYTES,
                },
            ],
        );
    }
    if !LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES.is_empty() {
        push_embedded_assets(
            assets,
            &[
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_RUNTIME_SMOKE_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_RUNTIME_SMOKE_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_RUNTIME_MAIN_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_RUNTIME_MAIN_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_RUNTIME_INTERP_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_RUNTIME_INTERP_BYTES,
                },
            ],
        );
    }
    if !LINUX_DYNAMIC_PIE_SMOKE_BYTES.is_empty() {
        push_embedded_assets(
            assets,
            &[
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_PIE_SMOKE_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_PIE_SMOKE_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_PIE_MAIN_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_PIE_MAIN_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_DYNAMIC_PIE_INTERP_BINARY_PATH,
                    bytes: LINUX_DYNAMIC_PIE_INTERP_BYTES,
                },
            ],
        );
    }
    if !LINUX_GLIBC_HELLO_BYTES.is_empty() {
        push_embedded_assets(
            assets,
            &[
                EmbeddedAsset {
                    path: LINUX_GLIBC_HELLO_BINARY_PATH,
                    bytes: LINUX_GLIBC_HELLO_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_GLIBC_RUNTIME_INTERP_BINARY_PATH,
                    bytes: LINUX_GLIBC_RUNTIME_INTERP_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_GLIBC_RUNTIME_LIBC_BINARY_PATH,
                    bytes: LINUX_GLIBC_RUNTIME_LIBC_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_GLIBC_RUNTIME_INTERP_CANONICAL_PATH,
                    bytes: LINUX_GLIBC_RUNTIME_INTERP_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_GLIBC_RUNTIME_INTERP_LIB64_PATH,
                    bytes: LINUX_GLIBC_RUNTIME_INTERP_BYTES,
                },
                EmbeddedAsset {
                    path: LINUX_GLIBC_RUNTIME_LIBC_LIB64_PATH,
                    bytes: LINUX_GLIBC_RUNTIME_LIBC_BYTES,
                },
            ],
        );
    }
    push_busybox_shell_runtime_assets(assets);
}

pub(crate) fn push_starnix_manifest_assets(assets: &mut Vec<BootAssetEntry>) {
    push_embedded_assets(
        assets,
        &[
            EmbeddedAsset {
                path: "manifests/linux-hello.nxcd",
                bytes: LINUX_HELLO_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-fd-smoke.nxcd",
                bytes: LINUX_FD_SMOKE_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round2-smoke.nxcd",
                bytes: LINUX_ROUND2_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round3-smoke.nxcd",
                bytes: LINUX_ROUND3_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round4-futex-smoke.nxcd",
                bytes: LINUX_ROUND4_FUTEX_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round4-signal-smoke.nxcd",
                bytes: LINUX_ROUND4_SIGNAL_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round5-epoll-smoke.nxcd",
                bytes: LINUX_ROUND5_EPOLL_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round6-eventfd-smoke.nxcd",
                bytes: LINUX_ROUND6_EVENTFD_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round6-timerfd-smoke.nxcd",
                bytes: LINUX_ROUND6_TIMERFD_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round6-signalfd-smoke.nxcd",
                bytes: LINUX_ROUND6_SIGNALFD_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round6-futex-smoke.nxcd",
                bytes: LINUX_ROUND6_FUTEX_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round6-scm-rights-smoke.nxcd",
                bytes: LINUX_ROUND6_SCM_RIGHTS_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round6-pidfd-smoke.nxcd",
                bytes: LINUX_ROUND6_PIDFD_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round6-proc-job-smoke.nxcd",
                bytes: LINUX_ROUND6_PROC_JOB_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round6-proc-control-smoke.nxcd",
                bytes: LINUX_ROUND6_PROC_CONTROL_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-round6-proc-tty-smoke.nxcd",
                bytes: LINUX_ROUND6_PROC_TTY_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-runtime-fd-smoke.nxcd",
                bytes: LINUX_RUNTIME_FD_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-runtime-misc-smoke.nxcd",
                bytes: LINUX_RUNTIME_MISC_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-runtime-process-smoke.nxcd",
                bytes: LINUX_RUNTIME_PROCESS_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-runtime-net-smoke.nxcd",
                bytes: LINUX_RUNTIME_NET_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-runtime-fs-smoke.nxcd",
                bytes: LINUX_RUNTIME_FS_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-runtime-tls-smoke.nxcd",
                bytes: LINUX_RUNTIME_TLS_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-dynamic-elf-smoke.nxcd",
                bytes: LINUX_DYNAMIC_ELF_SMOKE_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-dynamic-tls-smoke.nxcd",
                bytes: LINUX_DYNAMIC_TLS_SMOKE_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-dynamic-runtime-smoke.nxcd",
                bytes: LINUX_DYNAMIC_RUNTIME_SMOKE_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-dynamic-pie-smoke.nxcd",
                bytes: LINUX_DYNAMIC_PIE_SMOKE_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/linux-glibc-hello.nxcd",
                bytes: LINUX_GLIBC_HELLO_DECL_BYTES,
            },
        ],
    );
    push_busybox_shell_decl_assets(assets);
}

pub(crate) fn push_root_manifest_assets(assets: &mut Vec<BootAssetEntry>) {
    push_embedded_assets(
        assets,
        &[
            EmbeddedAsset {
                path: "manifests/root.nxcd",
                bytes: ROOT_DECL_EAGER_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-round3.nxcd",
                bytes: ROOT_DECL_ROUND3_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix.nxcd",
                bytes: ROOT_DECL_STARNIX_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-fd.nxcd",
                bytes: ROOT_DECL_STARNIX_FD_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round2.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND2_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round3.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND3_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round4-futex.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND4_FUTEX_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round4-signal.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND4_SIGNAL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round5-epoll.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND5_EPOLL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round6-eventfd.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND6_EVENTFD_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round6-timerfd.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND6_TIMERFD_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round6-signalfd.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND6_SIGNALFD_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round6-futex.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND6_FUTEX_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round6-scm-rights.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND6_SCM_RIGHTS_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round6-pidfd.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND6_PIDFD_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round6-proc-job.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND6_PROC_JOB_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round6-proc-control.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND6_PROC_CONTROL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-round6-proc-tty.nxcd",
                bytes: ROOT_DECL_STARNIX_ROUND6_PROC_TTY_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-runtime-fd.nxcd",
                bytes: ROOT_DECL_STARNIX_RUNTIME_FD_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-runtime-misc.nxcd",
                bytes: ROOT_DECL_STARNIX_RUNTIME_MISC_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-runtime-process.nxcd",
                bytes: ROOT_DECL_STARNIX_RUNTIME_PROCESS_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-runtime-net.nxcd",
                bytes: ROOT_DECL_STARNIX_RUNTIME_NET_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-runtime-fs.nxcd",
                bytes: ROOT_DECL_STARNIX_RUNTIME_FS_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-runtime-tls.nxcd",
                bytes: ROOT_DECL_STARNIX_RUNTIME_TLS_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-dynamic.nxcd",
                bytes: ROOT_DECL_STARNIX_DYNAMIC_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-dynamic-tls.nxcd",
                bytes: ROOT_DECL_STARNIX_DYNAMIC_TLS_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-dynamic-runtime.nxcd",
                bytes: ROOT_DECL_STARNIX_DYNAMIC_RUNTIME_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-dynamic-pie.nxcd",
                bytes: ROOT_DECL_STARNIX_DYNAMIC_PIE_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-glibc-hello.nxcd",
                bytes: ROOT_DECL_STARNIX_GLIBC_HELLO_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-shell.nxcd",
                bytes: ROOT_DECL_STARNIX_SHELL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-starnix-net-shell.nxcd",
                bytes: ROOT_DECL_STARNIX_NET_SHELL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-net-dataplane.nxcd",
                bytes: ROOT_DECL_NET_DATAPLANE_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/root-vmo-shared.nxcd",
                bytes: ROOT_DECL_VMO_SHARED_BYTES,
            },
        ],
    );
}

pub(crate) fn push_component_decl_assets(assets: &mut Vec<BootAssetEntry>) {
    push_embedded_assets(
        assets,
        &[
            EmbeddedAsset {
                path: "manifests/echo-provider.nxcd",
                bytes: PROVIDER_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/echo-client.nxcd",
                bytes: CLIENT_DECL_BYTES,
            },
            EmbeddedAsset {
                path: "manifests/controller-worker.nxcd",
                bytes: CONTROLLER_WORKER_DECL_BYTES,
            },
        ],
    );
}

pub(crate) fn push_busybox_shell_runtime_assets(assets: &mut Vec<BootAssetEntry>) {
    if LINUX_BUSYBOX_BYTES.is_empty() {
        return;
    }
    for path in [
        LINUX_BUSYBOX_BINARY_PATH,
        LINUX_BUSYBOX_SHELL_BINARY_PATH,
        LINUX_BUSYBOX_LS_BINARY_PATH,
        LINUX_BUSYBOX_CAT_BINARY_PATH,
        LINUX_BUSYBOX_ECHO_BINARY_PATH,
        LINUX_BUSYBOX_MKDIR_BINARY_PATH,
        LINUX_BUSYBOX_RM_BINARY_PATH,
        LINUX_BUSYBOX_PS_BINARY_PATH,
    ] {
        assets.push(BootAssetEntry::bytes(path, LINUX_BUSYBOX_BYTES));
    }
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_INTERP_BINARY_PATH,
        LINUX_GLIBC_RUNTIME_INTERP_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_LIBC_BINARY_PATH,
        LINUX_GLIBC_RUNTIME_LIBC_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_INTERP_CANONICAL_PATH,
        LINUX_GLIBC_RUNTIME_INTERP_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_INTERP_LIB64_PATH,
        LINUX_GLIBC_RUNTIME_INTERP_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_LIBC_LIB64_PATH,
        LINUX_GLIBC_RUNTIME_LIBC_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_LIBM_BINARY_PATH,
        LINUX_GLIBC_RUNTIME_LIBM_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_LIBM_LIB64_PATH,
        LINUX_GLIBC_RUNTIME_LIBM_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_RESOLV_BINARY_PATH,
        LINUX_GLIBC_RUNTIME_RESOLV_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_GLIBC_RUNTIME_RESOLV_LIB64_PATH,
        LINUX_GLIBC_RUNTIME_RESOLV_BYTES,
    ));
    assets.push(BootAssetEntry::bytes(
        LINUX_BUSYBOX_PASSWD_PATH,
        LINUX_BUSYBOX_PASSWD_BYTES,
    ));
}

pub(crate) fn push_busybox_shell_decl_assets(assets: &mut Vec<BootAssetEntry>) {
    if !LINUX_BUSYBOX_SHELL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-busybox-shell.nxcd",
            LINUX_BUSYBOX_SHELL_DECL_BYTES,
        ));
    }
    if !LINUX_BUSYBOX_SOCKET_SHELL_DECL_BYTES.is_empty() {
        assets.push(BootAssetEntry::bytes(
            "manifests/linux-busybox-socket-shell.nxcd",
            LINUX_BUSYBOX_SOCKET_SHELL_DECL_BYTES,
        ));
    }
}
