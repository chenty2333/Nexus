fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=../../specs/conformance/runner/int80_conformance.S");
    // Link the userspace runner at the fixed VA expected by the kernel bring-up
    // mapping in `kernel/axle-kernel/src/userspace.rs`.
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let script = manifest_dir.join("linker.ld");
    println!("cargo:rustc-link-arg=-T{}", script.display());
    let asm = manifest_dir.join("../../specs/conformance/runner/int80_conformance.S");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let object = out_dir.join("int80_conformance.o");

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
