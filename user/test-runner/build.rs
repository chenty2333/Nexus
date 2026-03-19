fn main() {
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-env-changed=AXLE_TEST_RUNNER_ASM");
    println!("cargo:rerun-if-env-changed=AXLE_TEST_RUNNER_RUST_ENTRY");
    println!(
        "cargo:rustc-check-cfg=cfg(axle_test_runner_rust_entry, values(\"reactor_smoke\", \"component_smoke\", \"perf_smoke\", \"device_smoke\", \"net_smoke\", \"datagram_smoke\", \"smp_smoke\", \"vmo_info_smoke\", \"vmo_shared_smoke\", \"vmo_promotion_smoke\", \"vmo_private_clone_smoke\"))"
    );

    // Link the userspace runner at the fixed VA expected by the kernel bring-up
    // mapping in `kernel/axle-kernel/src/userspace.rs`.
    let script = manifest_dir.join("linker.ld");
    println!("cargo:rustc-link-arg=-T{}", script.display());
    println!("cargo:rustc-link-arg=-no-pie");
    if let Ok(entry) = std::env::var("AXLE_TEST_RUNNER_RUST_ENTRY") {
        match entry.as_str() {
            "reactor_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            "component_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            "perf_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            "device_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            "net_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            "datagram_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            "smp_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            "vmo_info_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            "vmo_shared_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            "vmo_promotion_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            "vmo_private_clone_smoke" => {
                println!("cargo:rustc-cfg=axle_test_runner_rust_entry=\"{entry}\"");
            }
            _ => panic!("unsupported AXLE_TEST_RUNNER_RUST_ENTRY={entry}"),
        }
        return;
    }
    let asm = std::env::var("AXLE_TEST_RUNNER_ASM")
        .map(|value| {
            let path = std::path::PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                workspace_root.join(path)
            }
        })
        .unwrap_or_else(|_| workspace_root.join("specs/conformance/runner/int80_conformance.S"));
    println!("cargo:rerun-if-changed={}", asm.display());
    let object = out_dir.join("conformance_runner.o");

    let compiler = cc::Build::new().get_compiler();
    let status = compiler
        .to_command()
        .arg("-c")
        .arg(&asm)
        .arg("-m64")
        .arg("-o")
        .arg(&object)
        .status()
        .expect("assemble int80 conformance runner");
    assert!(status.success(), "failed to assemble userspace runner");

    println!("cargo:rustc-link-arg={}", object.display());
}
