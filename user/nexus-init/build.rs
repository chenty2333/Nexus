use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    use std::fs;

    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let manifests_dir = manifest_dir.join("manifests");
    let linux_hello_source = manifest_dir.join("../linux-hello/hello.S");

    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-env-changed=NEXUS_INIT_ROOT_URL");
    println!("cargo:rerun-if-changed={}", linux_hello_source.display());
    for manifest in [
        "root_component.toml",
        "root_component_round3.toml",
        "root_component_starnix.toml",
        "echo_provider.toml",
        "echo_client.toml",
        "controller_worker.toml",
        "linux_hello.toml",
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
        ("echo_provider.toml", "echo_provider.nxcd"),
        ("echo_client.toml", "echo_client.nxcd"),
        ("controller_worker.toml", "controller_worker.nxcd"),
        ("linux_hello.toml", "linux_hello.nxcd"),
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

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        // Link the bootstrap userspace binary at the fixed VA currently
        // expected by the kernel's early userspace loader.
        let script = manifest_dir.join("linker.ld");
        println!("cargo:rustc-link-arg=-T{}", script.display());
        println!("cargo:rustc-link-arg=-no-pie");
    }
    let root_url =
        std::env::var("NEXUS_INIT_ROOT_URL").unwrap_or_else(|_| String::from("boot://root"));
    println!("cargo:rustc-env=NEXUS_INIT_ROOT_URL={root_url}");
}

fn build_linux_hello(source: &Path, out_dir: &Path) {
    let output = out_dir.join("linux-hello");
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
        .arg(&output)
        .arg(source)
        .status()
        .unwrap_or_else(|err| panic!("spawn {clang}: {err}"));
    assert!(status.success(), "build {} failed", output.display());
}
