fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    // Link the userspace runner at the fixed VA expected by the kernel bring-up
    // mapping in `kernel/axle-kernel/src/userspace.rs`.
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let script = manifest_dir.join("linker.ld");
    println!("cargo:rustc-link-arg=-T{}", script.display());
}
