set dotenv-load := false

default:
  @just --list

# Host-only gates for Phase A (contracts).
xlint:
  cargo clippy -p axle-types -p axle-core -p axle-mm -p axle-page-table -p axle-sync -p libzircon -p nexus-rt -p axle-conformance -p axle-concurrency --all-targets -- -D warnings

xtest:
  cargo test -p axle-types -p axle-core -p axle-mm -p axle-page-table -p axle-sync -p libzircon -p nexus-rt -p axle-conformance -p axle-concurrency

# Kernel conformance gate.
test-kernel:
  cargo run -p axle-conformance -- run --retries 1

perf-smoke-qemu:
  cargo run -p axle-conformance -- run --scenario kernel.runtime.bootstrap_perf_smoke

perf-smoke-bundle:
  bash -lc 'set -euo pipefail; target_dir=target/perf-smoke-bundle; mkdir -p "$target_dir"; cargo build -p axle-kernel --target x86_64-unknown-none --target-dir "$target_dir"; AXLE_TEST_RUNNER_RUST_ENTRY=perf_smoke RUSTFLAGS="-C code-model=large" cargo build -p nexus-test-runner --target x86_64-unknown-none --target-dir "$target_dir"; cp "$target_dir/x86_64-unknown-none/debug/axle-kernel" "$target_dir/axle-kernel"; cp "$target_dir/x86_64-unknown-none/debug/nexus-test-runner" "$target_dir/nexus-test-runner"; printf "bundle_dir=%s\nkernel=%s\nrunner=%s\n" "$target_dir" "$target_dir/axle-kernel" "$target_dir/nexus-test-runner"'

perf-smoke-parse logfile:
  python tools/axle-conformance/scripts/extract_perf_smoke.py {{logfile}}

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
  just concurrency-smoke
  just test-kernel

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

# Loom runs are slower; enable only when you need concurrency-model checking.
loom:
  cargo test -p axle-sync --features loom
  cargo test -p axle-core --features loom
  cargo test -p axle-mm --features loom

concurrency-smoke:
  cargo run -p axle-concurrency -- smoke --iterations 64 --max-steps 32

concurrency-qemu-smoke:
  cargo run -p axle-concurrency -- smoke --iterations 8 --max-steps 24
  cargo run -p axle-concurrency -- qemu-triage --limit 1

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
