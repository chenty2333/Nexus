use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    use std::fs;

    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let manifests_dir = manifest_dir.join("manifests");
    let linux_hello_source = manifest_dir.join("../linux-hello/hello.S");
    let linux_fd_smoke_source = manifest_dir.join("../linux-fd-smoke/fd_smoke.S");
    let linux_round2_source = manifest_dir.join("../linux-round2-smoke/round2_smoke.S");
    let linux_round3_source = manifest_dir.join("../linux-round3-smoke/round3_smoke.S");
    let linux_round4_futex_source =
        manifest_dir.join("../linux-round4-futex-smoke/round4_futex_smoke.S");
    let linux_round4_signal_source =
        manifest_dir.join("../linux-round4-signal-smoke/round4_signal_smoke.S");
    let linux_round5_epoll_source =
        manifest_dir.join("../linux-round5-epoll-smoke/round5_epoll_smoke.S");
    let linux_round6_eventfd_source =
        manifest_dir.join("../linux-round6-eventfd-smoke/round6_eventfd_smoke.S");
    let linux_round6_timerfd_source =
        manifest_dir.join("../linux-round6-timerfd-smoke/round6_timerfd_smoke.S");
    let linux_round6_signalfd_source =
        manifest_dir.join("../linux-round6-signalfd-smoke/round6_signalfd_smoke.S");
    let linux_round6_futex_source =
        manifest_dir.join("../linux-round6-futex-smoke/round6_futex_smoke.S");
    let linux_round6_scm_rights_source =
        manifest_dir.join("../linux-round6-scm-rights-smoke/round6_scm_rights_smoke.S");
    let linux_round6_pidfd_source =
        manifest_dir.join("../linux-round6-pidfd-smoke/round6_pidfd_smoke.S");
    let linux_round6_proc_job_source =
        manifest_dir.join("../linux-round6-proc-job-smoke/round6_proc_job_smoke.S");
    let linux_round6_proc_control_source =
        manifest_dir.join("../linux-round6-proc-control-smoke/round6_proc_control_smoke.S");
    let linux_round6_proc_tty_source =
        manifest_dir.join("../linux-round6-proc-tty-smoke/round6_proc_tty_smoke.S");
    let linux_runtime_fd_source = manifest_dir.join("../linux-runtime-fd-smoke/runtime_fd_smoke.S");
    let linux_runtime_misc_source =
        manifest_dir.join("../linux-runtime-misc-smoke/runtime_misc_smoke.S");
    let linux_runtime_process_source =
        manifest_dir.join("../linux-runtime-process-smoke/runtime_process_smoke.S");
    let linux_runtime_fs_source = manifest_dir.join("../linux-runtime-fs-smoke/runtime_fs_smoke.S");
    let linux_runtime_tls_source =
        manifest_dir.join("../linux-runtime-tls-smoke/runtime_tls_smoke.S");
    let linux_dynamic_elf_smoke_source =
        manifest_dir.join("../linux-dynamic-elf-smoke/dynamic_elf_smoke.S");
    let linux_dynamic_main_source = manifest_dir.join("../linux-dynamic-main/dynamic_main.S");
    let linux_dynamic_interp_source = manifest_dir.join("../linux-dynamic-interp/dynamic_interp.S");
    let linux_dynamic_tls_smoke_source =
        manifest_dir.join("../linux-dynamic-tls-smoke/dynamic_tls_smoke.S");
    let linux_dynamic_tls_main_source =
        manifest_dir.join("../linux-dynamic-tls-main/dynamic_tls_main.c");
    let linux_dynamic_tls_interp_source =
        manifest_dir.join("../linux-dynamic-tls-interp/dynamic_tls_interp.c");
    let linux_dynamic_runtime_smoke_source =
        manifest_dir.join("../linux-dynamic-runtime-smoke/dynamic_runtime_smoke.S");
    let linux_dynamic_runtime_main_source =
        manifest_dir.join("../linux-dynamic-runtime-main/dynamic_runtime_main.c");
    let linux_dynamic_runtime_interp_source =
        manifest_dir.join("../linux-dynamic-runtime-interp/dynamic_runtime_interp.c");
    let linux_dynamic_pie_smoke_source =
        manifest_dir.join("../linux-dynamic-pie-smoke/dynamic_pie_smoke.S");
    let linux_dynamic_pie_main_source =
        manifest_dir.join("../linux-dynamic-pie-main/dynamic_pie_main.c");
    let linux_glibc_hello_source = manifest_dir.join("../linux-glibc-hello/glibc_hello.c");

    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-env-changed=NEXUS_INIT_ROOT_URL");
    println!("cargo:rerun-if-changed={}", linux_hello_source.display());
    println!("cargo:rerun-if-changed={}", linux_fd_smoke_source.display());
    println!("cargo:rerun-if-changed={}", linux_round2_source.display());
    println!("cargo:rerun-if-changed={}", linux_round3_source.display());
    println!(
        "cargo:rerun-if-changed={}",
        linux_round4_futex_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round4_signal_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round5_epoll_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round6_eventfd_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round6_timerfd_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round6_signalfd_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round6_futex_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round6_scm_rights_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round6_pidfd_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round6_proc_job_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round6_proc_control_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_round6_proc_tty_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_runtime_fd_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_runtime_misc_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_runtime_process_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_runtime_fs_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_runtime_tls_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_elf_smoke_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_main_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_interp_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_tls_smoke_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_tls_main_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_tls_interp_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_runtime_smoke_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_runtime_main_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_runtime_interp_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_pie_smoke_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_dynamic_pie_main_source.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        linux_glibc_hello_source.display()
    );
    for manifest in [
        "root_component.toml",
        "root_component_round3.toml",
        "root_component_net_dataplane.toml",
        "root_component_starnix.toml",
        "root_component_starnix_fd.toml",
        "root_component_starnix_round2.toml",
        "root_component_starnix_round3.toml",
        "root_component_starnix_round4_futex.toml",
        "root_component_starnix_round4_signal.toml",
        "root_component_starnix_round5_epoll.toml",
        "root_component_starnix_round6_eventfd.toml",
        "root_component_starnix_round6_timerfd.toml",
        "root_component_starnix_round6_signalfd.toml",
        "root_component_starnix_round6_futex.toml",
        "root_component_starnix_round6_scm_rights.toml",
        "root_component_starnix_round6_pidfd.toml",
        "root_component_starnix_round6_proc_job.toml",
        "root_component_starnix_round6_proc_control.toml",
        "root_component_starnix_round6_proc_tty.toml",
        "root_component_starnix_runtime_fd.toml",
        "root_component_starnix_runtime_misc.toml",
        "root_component_starnix_runtime_process.toml",
        "root_component_starnix_runtime_fs.toml",
        "root_component_starnix_runtime_tls.toml",
        "root_component_starnix_dynamic.toml",
        "root_component_starnix_dynamic_tls.toml",
        "root_component_starnix_dynamic_runtime.toml",
        "root_component_starnix_dynamic_pie.toml",
        "root_component_starnix_glibc_hello.toml",
        "echo_provider.toml",
        "echo_client.toml",
        "controller_worker.toml",
        "linux_hello.toml",
        "linux_fd_smoke.toml",
        "linux_round2_smoke.toml",
        "linux_round3_smoke.toml",
        "linux_round4_futex_smoke.toml",
        "linux_round4_signal_smoke.toml",
        "linux_round5_epoll_smoke.toml",
        "linux_round6_eventfd_smoke.toml",
        "linux_round6_timerfd_smoke.toml",
        "linux_round6_signalfd_smoke.toml",
        "linux_round6_futex_smoke.toml",
        "linux_round6_scm_rights_smoke.toml",
        "linux_round6_pidfd_smoke.toml",
        "linux_round6_proc_job_smoke.toml",
        "linux_round6_proc_control_smoke.toml",
        "linux_round6_proc_tty_smoke.toml",
        "linux_runtime_fd_smoke.toml",
        "linux_runtime_misc_smoke.toml",
        "linux_runtime_process_smoke.toml",
        "linux_runtime_fs_smoke.toml",
        "linux_runtime_tls_smoke.toml",
        "linux_dynamic_elf_smoke.toml",
        "linux_dynamic_tls_smoke.toml",
        "linux_dynamic_runtime_smoke.toml",
        "linux_dynamic_pie_smoke.toml",
        "linux_glibc_hello.toml",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            manifests_dir.join(manifest).display()
        );
    }

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    for (input, output) in [
        ("root_component.toml", "root_component.nxcd"),
        ("root_component_round3.toml", "root_component_round3.nxcd"),
        (
            "root_component_net_dataplane.toml",
            "root_component_net_dataplane.nxcd",
        ),
        ("root_component_starnix.toml", "root_component_starnix.nxcd"),
        (
            "root_component_starnix_fd.toml",
            "root_component_starnix_fd.nxcd",
        ),
        (
            "root_component_starnix_round2.toml",
            "root_component_starnix_round2.nxcd",
        ),
        (
            "root_component_starnix_round3.toml",
            "root_component_starnix_round3.nxcd",
        ),
        (
            "root_component_starnix_round4_futex.toml",
            "root_component_starnix_round4_futex.nxcd",
        ),
        (
            "root_component_starnix_round4_signal.toml",
            "root_component_starnix_round4_signal.nxcd",
        ),
        (
            "root_component_starnix_round5_epoll.toml",
            "root_component_starnix_round5_epoll.nxcd",
        ),
        (
            "root_component_starnix_round6_eventfd.toml",
            "root_component_starnix_round6_eventfd.nxcd",
        ),
        (
            "root_component_starnix_round6_timerfd.toml",
            "root_component_starnix_round6_timerfd.nxcd",
        ),
        (
            "root_component_starnix_round6_signalfd.toml",
            "root_component_starnix_round6_signalfd.nxcd",
        ),
        (
            "root_component_starnix_round6_futex.toml",
            "root_component_starnix_round6_futex.nxcd",
        ),
        (
            "root_component_starnix_round6_scm_rights.toml",
            "root_component_starnix_round6_scm_rights.nxcd",
        ),
        (
            "root_component_starnix_round6_pidfd.toml",
            "root_component_starnix_round6_pidfd.nxcd",
        ),
        (
            "root_component_starnix_round6_proc_job.toml",
            "root_component_starnix_round6_proc_job.nxcd",
        ),
        (
            "root_component_starnix_round6_proc_control.toml",
            "root_component_starnix_round6_proc_control.nxcd",
        ),
        (
            "root_component_starnix_round6_proc_tty.toml",
            "root_component_starnix_round6_proc_tty.nxcd",
        ),
        (
            "root_component_starnix_runtime_fd.toml",
            "root_component_starnix_runtime_fd.nxcd",
        ),
        (
            "root_component_starnix_runtime_misc.toml",
            "root_component_starnix_runtime_misc.nxcd",
        ),
        (
            "root_component_starnix_runtime_process.toml",
            "root_component_starnix_runtime_process.nxcd",
        ),
        (
            "root_component_starnix_runtime_fs.toml",
            "root_component_starnix_runtime_fs.nxcd",
        ),
        (
            "root_component_starnix_runtime_tls.toml",
            "root_component_starnix_runtime_tls.nxcd",
        ),
        (
            "root_component_starnix_dynamic.toml",
            "root_component_starnix_dynamic.nxcd",
        ),
        (
            "root_component_starnix_dynamic_tls.toml",
            "root_component_starnix_dynamic_tls.nxcd",
        ),
        (
            "root_component_starnix_dynamic_runtime.toml",
            "root_component_starnix_dynamic_runtime.nxcd",
        ),
        (
            "root_component_starnix_dynamic_pie.toml",
            "root_component_starnix_dynamic_pie.nxcd",
        ),
        (
            "root_component_starnix_glibc_hello.toml",
            "root_component_starnix_glibc_hello.nxcd",
        ),
        ("echo_provider.toml", "echo_provider.nxcd"),
        ("echo_client.toml", "echo_client.nxcd"),
        ("controller_worker.toml", "controller_worker.nxcd"),
        ("linux_hello.toml", "linux_hello.nxcd"),
        ("linux_fd_smoke.toml", "linux_fd_smoke.nxcd"),
        ("linux_round2_smoke.toml", "linux_round2_smoke.nxcd"),
        ("linux_round3_smoke.toml", "linux_round3_smoke.nxcd"),
        (
            "linux_round4_futex_smoke.toml",
            "linux_round4_futex_smoke.nxcd",
        ),
        (
            "linux_round4_signal_smoke.toml",
            "linux_round4_signal_smoke.nxcd",
        ),
        (
            "linux_round5_epoll_smoke.toml",
            "linux_round5_epoll_smoke.nxcd",
        ),
        (
            "linux_round6_eventfd_smoke.toml",
            "linux_round6_eventfd_smoke.nxcd",
        ),
        (
            "linux_round6_timerfd_smoke.toml",
            "linux_round6_timerfd_smoke.nxcd",
        ),
        (
            "linux_round6_signalfd_smoke.toml",
            "linux_round6_signalfd_smoke.nxcd",
        ),
        (
            "linux_round6_futex_smoke.toml",
            "linux_round6_futex_smoke.nxcd",
        ),
        (
            "linux_round6_scm_rights_smoke.toml",
            "linux_round6_scm_rights_smoke.nxcd",
        ),
        (
            "linux_round6_pidfd_smoke.toml",
            "linux_round6_pidfd_smoke.nxcd",
        ),
        (
            "linux_round6_proc_job_smoke.toml",
            "linux_round6_proc_job_smoke.nxcd",
        ),
        (
            "linux_round6_proc_control_smoke.toml",
            "linux_round6_proc_control_smoke.nxcd",
        ),
        (
            "linux_round6_proc_tty_smoke.toml",
            "linux_round6_proc_tty_smoke.nxcd",
        ),
        ("linux_runtime_fd_smoke.toml", "linux_runtime_fd_smoke.nxcd"),
        (
            "linux_runtime_misc_smoke.toml",
            "linux_runtime_misc_smoke.nxcd",
        ),
        (
            "linux_runtime_process_smoke.toml",
            "linux_runtime_process_smoke.nxcd",
        ),
        ("linux_runtime_fs_smoke.toml", "linux_runtime_fs_smoke.nxcd"),
        (
            "linux_runtime_tls_smoke.toml",
            "linux_runtime_tls_smoke.nxcd",
        ),
        (
            "linux_dynamic_elf_smoke.toml",
            "linux_dynamic_elf_smoke.nxcd",
        ),
        (
            "linux_dynamic_tls_smoke.toml",
            "linux_dynamic_tls_smoke.nxcd",
        ),
        (
            "linux_dynamic_runtime_smoke.toml",
            "linux_dynamic_runtime_smoke.nxcd",
        ),
        (
            "linux_dynamic_pie_smoke.toml",
            "linux_dynamic_pie_smoke.nxcd",
        ),
        ("linux_glibc_hello.toml", "linux_glibc_hello.nxcd"),
    ] {
        let source_path = manifests_dir.join(input);
        let source = fs::read_to_string(&source_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", source_path.display()));
        let blob = nexus_manifestc::compile_manifest(&source)
            .unwrap_or_else(|err| panic!("compile {}: {err}", source_path.display()));
        fs::write(out_dir.join(output), blob)
            .unwrap_or_else(|err| panic!("write {}: {err}", out_dir.join(output).display()));
    }

    build_linux_hello(&linux_hello_source, &out_dir);
    build_linux_binary(&linux_fd_smoke_source, &out_dir.join("linux-fd-smoke"));
    build_linux_binary(&linux_round2_source, &out_dir.join("linux-round2-smoke"));
    build_linux_binary(&linux_round3_source, &out_dir.join("linux-round3-smoke"));
    build_linux_binary(
        &linux_round4_futex_source,
        &out_dir.join("linux-round4-futex-smoke"),
    );
    build_linux_binary(
        &linux_round4_signal_source,
        &out_dir.join("linux-round4-signal-smoke"),
    );
    build_linux_binary(
        &linux_round5_epoll_source,
        &out_dir.join("linux-round5-epoll-smoke"),
    );
    build_linux_binary(
        &linux_round6_eventfd_source,
        &out_dir.join("linux-round6-eventfd-smoke"),
    );
    build_linux_binary(
        &linux_round6_timerfd_source,
        &out_dir.join("linux-round6-timerfd-smoke"),
    );
    build_linux_binary(
        &linux_round6_signalfd_source,
        &out_dir.join("linux-round6-signalfd-smoke"),
    );
    build_linux_binary(
        &linux_round6_futex_source,
        &out_dir.join("linux-round6-futex-smoke"),
    );
    build_linux_binary(
        &linux_round6_scm_rights_source,
        &out_dir.join("linux-round6-scm-rights-smoke"),
    );
    build_linux_binary(
        &linux_round6_pidfd_source,
        &out_dir.join("linux-round6-pidfd-smoke"),
    );
    build_linux_binary(
        &linux_round6_proc_job_source,
        &out_dir.join("linux-round6-proc-job-smoke"),
    );
    build_linux_binary(
        &linux_round6_proc_control_source,
        &out_dir.join("linux-round6-proc-control-smoke"),
    );
    build_linux_binary(
        &linux_round6_proc_tty_source,
        &out_dir.join("linux-round6-proc-tty-smoke"),
    );
    build_linux_binary(
        &linux_runtime_fd_source,
        &out_dir.join("linux-runtime-fd-smoke"),
    );
    build_linux_binary(
        &linux_runtime_misc_source,
        &out_dir.join("linux-runtime-misc-smoke"),
    );
    build_linux_binary(
        &linux_runtime_process_source,
        &out_dir.join("linux-runtime-process-smoke"),
    );
    build_linux_binary(
        &linux_runtime_fs_source,
        &out_dir.join("linux-runtime-fs-smoke"),
    );
    build_linux_binary(
        &linux_runtime_tls_source,
        &out_dir.join("linux-runtime-tls-smoke"),
    );
    build_linux_binary(
        &linux_dynamic_elf_smoke_source,
        &out_dir.join("linux-dynamic-elf-smoke"),
    );
    build_linux_dynamic_binary(
        &linux_dynamic_main_source,
        &out_dir.join("linux-dynamic-main"),
        "/lib/ld-nexus-dynamic-smoke.so",
    );
    build_linux_shared_binary(
        &linux_dynamic_interp_source,
        &out_dir.join("ld-nexus-dynamic-smoke.so"),
        "ld-nexus-dynamic-smoke.so",
    );
    build_linux_binary(
        &linux_dynamic_tls_smoke_source,
        &out_dir.join("linux-dynamic-tls-smoke"),
    );
    build_linux_dynamic_binary(
        &linux_dynamic_tls_main_source,
        &out_dir.join("linux-dynamic-tls-main"),
        "/lib/ld-nexus-dynamic-tls.so",
    );
    build_linux_shared_binary(
        &linux_dynamic_tls_interp_source,
        &out_dir.join("ld-nexus-dynamic-tls.so"),
        "ld-nexus-dynamic-tls.so",
    );
    build_linux_binary(
        &linux_dynamic_runtime_smoke_source,
        &out_dir.join("linux-dynamic-runtime-smoke"),
    );
    build_linux_dynamic_binary(
        &linux_dynamic_runtime_main_source,
        &out_dir.join("linux-dynamic-runtime-main"),
        "/lib/ld-nexus-dynamic-runtime.so",
    );
    build_linux_shared_binary(
        &linux_dynamic_runtime_interp_source,
        &out_dir.join("ld-nexus-dynamic-runtime.so"),
        "ld-nexus-dynamic-runtime.so",
    );
    build_linux_binary(
        &linux_dynamic_pie_smoke_source,
        &out_dir.join("linux-dynamic-pie-smoke"),
    );
    build_linux_dynamic_pie_binary(
        &linux_dynamic_pie_main_source,
        &out_dir.join("linux-dynamic-pie-main"),
        "/lib/ld-nexus-dynamic-runtime.so",
    );
    build_linux_glibc_binary(
        &linux_glibc_hello_source,
        &out_dir.join("linux-glibc-hello"),
        "/lib/ld-nexus-glibc.so",
        "/lib:/lib64",
    );
    copy_linux_runtime_asset(
        &host_linux_runtime_path("libc.so.6"),
        &out_dir.join("libc.so.6"),
    );
    copy_linux_runtime_asset(
        &host_linux_runtime_path("ld-linux-x86-64.so.2"),
        &out_dir.join("ld-nexus-glibc.so"),
    );

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        // Link the bootstrap userspace binary at the fixed VA currently
        // expected by the kernel's early userspace loader.
        let script = manifest_dir.join("linker.ld");
        println!("cargo:rustc-link-arg=-T{}", script.display());
        println!("cargo:rustc-link-arg=-no-pie");
    }
    let root_url =
        std::env::var("NEXUS_INIT_ROOT_URL").unwrap_or_else(|_| String::from("boot://root"));
    let embed_stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    println!("cargo:rustc-env=NEXUS_INIT_EMBED_STAMP={embed_stamp}");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_hello)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_fd)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round2)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round3)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round4_futex)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round4_signal)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round5_epoll)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round6_eventfd)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round6_timerfd)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round6_signalfd)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round6_futex)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round6_scm_rights)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round6_pidfd)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round6_proc_job)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round6_proc_control)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round6_proc_tty)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_runtime_fd)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_runtime_misc)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_runtime_process)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_runtime_fs)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_runtime_tls)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_dynamic)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_dynamic_tls)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_dynamic_runtime)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_dynamic_pie)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_glibc_hello)");
    match root_url.as_str() {
        "boot://root-starnix" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_hello");
        }
        "boot://root-starnix-fd" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_fd");
        }
        "boot://root-starnix-round2" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_hello");
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round2");
        }
        "boot://root-starnix-round3" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_hello");
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round3");
        }
        "boot://root-starnix-round4-futex" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round4_futex");
        }
        "boot://root-starnix-round4-signal" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round4_signal");
        }
        "boot://root-starnix-round5-epoll" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_hello");
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round5_epoll");
        }
        "boot://root-starnix-round6-eventfd" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round6_eventfd");
        }
        "boot://root-starnix-round6-timerfd" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round6_timerfd");
        }
        "boot://root-starnix-round6-signalfd" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round6_signalfd");
        }
        "boot://root-starnix-round6-futex" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round6_futex");
        }
        "boot://root-starnix-round6-scm-rights" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round6_scm_rights");
        }
        "boot://root-starnix-round6-pidfd" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round6_pidfd");
        }
        "boot://root-starnix-round6-proc-job" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round6_proc_job");
        }
        "boot://root-starnix-round6-proc-control" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round6_proc_control");
        }
        "boot://root-starnix-round6-proc-tty" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_round6_proc_tty");
        }
        "boot://root-starnix-runtime-fd" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_runtime_fd");
        }
        "boot://root-starnix-runtime-misc" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_runtime_misc");
        }
        "boot://root-starnix-runtime-process" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_runtime_process");
        }
        "boot://root-starnix-runtime-fs" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_runtime_fs");
        }
        "boot://root-starnix-runtime-tls" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_runtime_tls");
        }
        "boot://root-starnix-dynamic" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_dynamic");
        }
        "boot://root-starnix-dynamic-tls" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_dynamic_tls");
        }
        "boot://root-starnix-dynamic-runtime" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_dynamic_runtime");
        }
        "boot://root-starnix-dynamic-pie" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_dynamic_pie");
        }
        "boot://root-starnix-glibc-hello" => {
            println!("cargo:rustc-cfg=nexus_init_embed_starnix_glibc_hello");
        }
        _ => {}
    }
    println!("cargo:rustc-env=NEXUS_INIT_ROOT_URL={root_url}");
}

fn build_linux_hello(source: &Path, out_dir: &Path) {
    build_linux_binary(source, &out_dir.join("linux-hello"));
}

fn build_linux_binary(source: &Path, output: &Path) {
    let clang = std::env::var("CLANG").unwrap_or_else(|_| String::from("clang"));
    let status = Command::new(&clang)
        .arg("--target=x86_64-unknown-linux-gnu")
        .arg("-nostdlib")
        .arg("-static")
        .arg("-no-pie")
        .arg("-fuse-ld=lld")
        .arg("-Wl,--entry=_start")
        .arg("-Wl,-z,noexecstack")
        .arg("-Wl,-z,max-page-size=4096")
        .arg("-Wl,--build-id=none")
        .arg("-Wl,--image-base=0x100000000")
        .arg("-o")
        .arg(output)
        .arg(source)
        .status()
        .unwrap_or_else(|err| panic!("spawn {clang}: {err}"));
    assert!(status.success(), "build {} failed", output.display());
}

fn build_linux_dynamic_binary(source: &Path, output: &Path, interp: &str) {
    let clang = std::env::var("CLANG").unwrap_or_else(|_| String::from("clang"));
    let dynamic_linker = format!("--dynamic-linker={interp}");
    let status = Command::new(&clang)
        .arg("--target=x86_64-unknown-linux-gnu")
        .arg("-nostdlib")
        .arg("-no-pie")
        .arg("-fuse-ld=lld")
        .arg("-Wl,--entry=_start")
        .arg("-Wl,-z,noexecstack")
        .arg("-Wl,-z,max-page-size=4096")
        .arg("-Wl,--build-id=none")
        .arg("-Wl,--image-base=0x100000000")
        .arg(format!("-Wl,{dynamic_linker}"))
        .arg("-o")
        .arg(output)
        .arg(source)
        .status()
        .unwrap_or_else(|err| panic!("spawn {clang}: {err}"));
    assert!(status.success(), "build {} failed", output.display());
}

fn build_linux_dynamic_pie_binary(source: &Path, output: &Path, interp: &str) {
    let clang = std::env::var("CLANG").unwrap_or_else(|_| String::from("clang"));
    let dynamic_linker = format!("--dynamic-linker={interp}");
    let status = Command::new(&clang)
        .arg("--target=x86_64-unknown-linux-gnu")
        .arg("-nostdlib")
        .arg("-fPIE")
        .arg("-pie")
        .arg("-fuse-ld=lld")
        .arg("-Wl,--entry=_start")
        .arg("-Wl,-z,noexecstack")
        .arg("-Wl,-z,max-page-size=4096")
        .arg("-Wl,--build-id=none")
        .arg(format!("-Wl,{dynamic_linker}"))
        .arg("-o")
        .arg(output)
        .arg(source)
        .status()
        .unwrap_or_else(|err| panic!("spawn {clang}: {err}"));
    assert!(status.success(), "build {} failed", output.display());
}

fn build_linux_glibc_binary(source: &Path, output: &Path, interp: &str, runpath: &str) {
    let cc = std::env::var("CC").unwrap_or_else(|_| String::from("cc"));
    let dynamic_linker = format!("-Wl,--dynamic-linker={interp}");
    let runpath_flag = format!("-Wl,-rpath,{runpath}");
    let status = Command::new(&cc)
        .arg("-fPIE")
        .arg("-pie")
        .arg("-Wl,-z,noexecstack")
        .arg("-Wl,--build-id=none")
        .arg(dynamic_linker)
        .arg(runpath_flag)
        .arg("-o")
        .arg(output)
        .arg(source)
        .status()
        .unwrap_or_else(|err| panic!("spawn {cc}: {err}"));
    assert!(status.success(), "build {} failed", output.display());
}

fn host_linux_runtime_path(name: &str) -> PathBuf {
    let cc = std::env::var("CC").unwrap_or_else(|_| String::from("cc"));
    let output = Command::new(&cc)
        .arg(format!("-print-file-name={name}"))
        .output()
        .unwrap_or_else(|err| panic!("spawn {cc} -print-file-name={name}: {err}"));
    assert!(
        output.status.success(),
        "{cc} -print-file-name={name} failed with status {:?}",
        output.status.code()
    );
    let printed = String::from_utf8(output.stdout)
        .unwrap_or_else(|err| panic!("decode {name} path from {cc}: {err}"));
    let path = PathBuf::from(printed.trim());
    assert!(
        path.is_absolute() && path.is_file(),
        "host runtime asset {name} not found: {}",
        path.display()
    );
    path
}

fn copy_linux_runtime_asset(source: &Path, output: &Path) {
    if output.exists() {
        std::fs::remove_file(output).unwrap_or_else(|err| {
            panic!(
                "remove existing runtime asset {} before copy: {err}",
                output.display()
            )
        });
    }
    std::fs::copy(source, output)
        .unwrap_or_else(|err| panic!("copy {} to {}: {err}", source.display(), output.display()));
}

fn build_linux_shared_binary(source: &Path, output: &Path, soname: &str) {
    let clang = std::env::var("CLANG").unwrap_or_else(|_| String::from("clang"));
    let soname_flag = format!("-Wl,-soname,{soname}");
    let status = Command::new(&clang)
        .arg("--target=x86_64-unknown-linux-gnu")
        .arg("-nostdlib")
        .arg("-shared")
        .arg("-fPIC")
        .arg("-fuse-ld=lld")
        .arg("-Wl,--entry=_start")
        .arg("-Wl,-z,noexecstack")
        .arg("-Wl,-z,max-page-size=4096")
        .arg("-Wl,--build-id=none")
        .arg(soname_flag)
        .arg("-o")
        .arg(output)
        .arg(source)
        .status()
        .unwrap_or_else(|err| panic!("spawn {clang}: {err}"));
    assert!(status.success(), "build {} failed", output.display());
}
