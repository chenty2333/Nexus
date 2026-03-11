fn main() {
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let script = manifest_dir.join("linker.ld");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rustc-link-arg=-T{}", script.display());
    println!("cargo:rustc-link-arg=-no-pie");
}
