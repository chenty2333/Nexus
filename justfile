set dotenv-load := false

default:
  @just --list

# Host-only gates for Phase A (contracts).
xlint:
  cargo clippy -p axle-types -p axle-core -p axle-sync --all-targets -- -D warnings

xtest:
  cargo test -p axle-types -p axle-core -p axle-sync

# Optional: run everything in the workspace (will include `no_std` crates once they compile).
test-all:
  cargo test --workspace

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

# Loom runs are slower; enable only when you need concurrency-model checking.
loom:
  cargo test -p axle-sync --features loom

# Syscall ABI generation (Phase A bootstrap).
gen-syscalls:
  cargo run -p syscalls-gen -- syscalls/spec/syscalls.toml --out syscalls/generated

# Ensure generated syscall ABI files are up to date with spec.
check-syscalls:
  just gen-syscalls
  git diff --exit-code -- syscalls/generated/syscall_numbers.rs
