fn main() {
    use std::fs;

    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let manifests_dir = manifest_dir.join("manifests");

    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-env-changed=NEXUS_INIT_ROOT_URL");
    for manifest in [
        "root_component.toml",
        "root_component_round3.toml",
        "echo_provider.toml",
        "echo_client.toml",
        "controller_worker.toml",
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
        ("echo_provider.toml", "echo_provider.nxcd"),
        ("echo_client.toml", "echo_client.nxcd"),
        ("controller_worker.toml", "controller_worker.nxcd"),
    ] {
        let source_path = manifests_dir.join(input);
        let source = fs::read_to_string(&source_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", source_path.display()));
        let blob = nexus_manifestc::compile_manifest(&source)
            .unwrap_or_else(|err| panic!("compile {}: {err}", source_path.display()));
        fs::write(out_dir.join(output), blob)
            .unwrap_or_else(|err| panic!("write {}: {err}", out_dir.join(output).display()));
    }

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
