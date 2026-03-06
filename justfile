set dotenv-load := false

default:
  @just --list

# Host-only gates for Phase A (contracts).
xlint:
  cargo clippy -p axle-types -p axle-core -p axle-mm -p axle-page-table -p axle-sync -p axle-conformance --all-targets -- -D warnings

xtest:
  cargo test -p axle-types -p axle-core -p axle-mm -p axle-page-table -p axle-sync -p axle-conformance

# Kernel conformance gate.
test-kernel:
  cargo run -p axle-conformance -- run

# Ensure contract catalog and scenario bindings remain complete.
check-conformance-contracts:
  cargo run -p axle-conformance -- check-contracts

# Optional: run everything in the workspace (will include `no_std` crates once they compile).
test-all:
  just check-syscalls
  just check-conformance-contracts
  just fmt-check
  just xlint
  just xtest
  just loom
  just fuzz-smoke
  just test-kernel

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

# Loom runs are slower; enable only when you need concurrency-model checking.
loom:
  cargo test -p axle-sync --features loom

# Short libFuzzer smoke run for the host-side semantic core.
fuzz-smoke:
  cargo fuzz run cspace_ops --fuzz-dir crates/axle-core/fuzz -D --sanitizer none -- -max_total_time=5
  cargo fuzz run addr_space_ops --fuzz-dir crates/axle-mm/fuzz -D --sanitizer none -- -max_total_time=5
  cargo fuzz run frame_table_ops --fuzz-dir crates/axle-mm/fuzz -D --sanitizer none -- -max_total_time=5

# Syscall ABI generation (Phase A bootstrap).
gen-syscalls:
  cargo run -p syscalls-gen -- syscalls/spec/syscalls.toml --out syscalls/generated

# Ensure generated syscall ABI files are up to date with spec.
check-syscalls:
  just gen-syscalls
  git diff --exit-code -- syscalls/generated/syscall_numbers.rs
