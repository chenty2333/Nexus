{
  description = "NexusOS - Axle microkernel development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Single source of truth for the Rust toolchain in this repo.
        rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "llvm-tools"
            "clippy"
            "rustfmt"
            "miri"
          ];
          targets = [
            "x86_64-unknown-none"
          ];
        };

      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust
            rustToolchain

            # Testing
            cargo-nextest
            cargo-fuzz
            cargo-mutants
            cargo-llvm-cov
            cargo-watch

            # Fuzz dependencies (libFuzzer toolchain)
            llvmPackages.clang
            llvmPackages.llvm
            llvmPackages.lld
            binutils

            # Build
            mold

            # Virtualization
            qemu

            # Debug
            gdb

            # Boot (Limine ISO)
            limine
            xorriso
          ];

          shellHook = ''
            export DIRENV_LOG_FORMAT=""
            echo "NexusOS dev environment loaded"
            echo "Rust: $(rustc --version)"
          '';
        };
      }
    );
}
