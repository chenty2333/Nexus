use std::path::{Path, PathBuf};
use std::process::Command;

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
    for manifest in [
        "root_component.toml",
        "root_component_round3.toml",
        "root_component_starnix.toml",
        "root_component_starnix_fd.toml",
        "root_component_starnix_round2.toml",
        "root_component_starnix_round3.toml",
        "root_component_starnix_round4_futex.toml",
        "root_component_starnix_round4_signal.toml",
        "root_component_starnix_round5_epoll.toml",
        "root_component_starnix_round6_eventfd.toml",
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

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        // Link the bootstrap userspace binary at the fixed VA currently
        // expected by the kernel's early userspace loader.
        let script = manifest_dir.join("linker.ld");
        println!("cargo:rustc-link-arg=-T{}", script.display());
        println!("cargo:rustc-link-arg=-no-pie");
    }
    let root_url =
        std::env::var("NEXUS_INIT_ROOT_URL").unwrap_or_else(|_| String::from("boot://root"));
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_hello)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_fd)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round2)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round3)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round4_futex)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round4_signal)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round5_epoll)");
    println!("cargo:rustc-check-cfg=cfg(nexus_init_embed_starnix_round6_eventfd)");
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
