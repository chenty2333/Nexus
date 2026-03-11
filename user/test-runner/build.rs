fn main() {
    use std::fs;

    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let manifests_dir = manifest_dir.join("manifests");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-env-changed=AXLE_TEST_RUNNER_ASM");
    println!("cargo:rerun-if-env-changed=AXLE_TEST_RUNNER_RUST_ENTRY");
    println!(
        "cargo:rustc-check-cfg=cfg(axle_test_runner_rust_entry, values(\"reactor_smoke\", \"component_smoke\"))"
    );
    for manifest in [
        "root_component.toml",
        "echo_provider.toml",
        "echo_client.toml",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            manifests_dir.join(manifest).display()
        );
    }

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    for (input, output) in [
        ("root_component.toml", "root_component.nxcd"),
        ("echo_provider.toml", "echo_provider.nxcd"),
        ("echo_client.toml", "echo_client.nxcd"),
    ] {
        let source_path = manifests_dir.join(input);
        let source = fs::read_to_string(&source_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", source_path.display()));
        let blob = nexus_manifestc::compile_manifest(&source)
            .unwrap_or_else(|err| panic!("compile {}: {err}", source_path.display()));
        fs::write(out_dir.join(output), blob)
            .unwrap_or_else(|err| panic!("write {}: {err}", out_dir.join(output).display()));
    }

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
