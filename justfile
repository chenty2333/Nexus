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
  bash -lc 'set -euo pipefail; target_dir=target/perf-smoke-bundle; mkdir -p "$target_dir"; nix develop -c cargo build -p axle-kernel --target x86_64-unknown-none --target-dir "$target_dir"; AXLE_TEST_RUNNER_RUST_ENTRY=perf_smoke RUSTFLAGS="-C code-model=large" nix develop -c cargo build -p nexus-test-runner --target x86_64-unknown-none --target-dir "$target_dir"; cp "$target_dir/x86_64-unknown-none/debug/axle-kernel" "$target_dir/axle-kernel"; cp "$target_dir/x86_64-unknown-none/debug/nexus-test-runner" "$target_dir/nexus-test-runner"; printf "bundle_dir=%s\nkernel=%s\nrunner=%s\n" "$target_dir" "$target_dir/axle-kernel" "$target_dir/nexus-test-runner"'

perf-smoke-kvm:
  bash -lc 'set -euo pipefail; just perf-smoke-bundle >/dev/null; target_dir=target/perf-smoke-bundle; run_dir=target/perf-smoke-kvm; mkdir -p "$run_dir"; runner="$run_dir/nexus-test-runner"; cp "$target_dir/nexus-test-runner" "$runner"; size=$(stat -c%s "$runner"); log="$run_dir/serial.log"; set +e; qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 256M -smp 2 -nographic -serial file:"$log" -monitor none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 -device loader,file="$runner",addr=0x7000000,force-raw=on -device loader,data=$size,data-len=8,addr=0x6fffff8 -kernel "$target_dir/axle-kernel"; qemu_code=$?; set -e; printf "serial_log=%s\nqemu_exit=%s\n" "$log" "$qemu_code"; [ "$qemu_code" -eq 33 ]; PYTHONDONTWRITEBYTECODE=1 python tools/axle-conformance/scripts/extract_perf_smoke.py "$log" > "$run_dir/perf-smoke.json"; PYTHONDONTWRITEBYTECODE=1 python tools/axle-conformance/scripts/perf_smoke_baseline.py "$log" > "$run_dir/baseline.json"; PYTHONDONTWRITEBYTECODE=1 python tools/axle-conformance/scripts/perf_smoke_perfetto.py "$log" "$run_dir/perfetto-trace.json"; cat "$run_dir/baseline.json"'

perf-smoke-parse logfile:
  PYTHONDONTWRITEBYTECODE=1 python tools/axle-conformance/scripts/extract_perf_smoke.py {{logfile}}

perf-smoke-perfetto logfile:
  PYTHONDONTWRITEBYTECODE=1 python tools/axle-conformance/scripts/perf_smoke_perfetto.py {{logfile}}

perf-smoke-archive logfile label cpuinfo='/proc/cpuinfo':
  PYTHONDONTWRITEBYTECODE=1 python tools/axle-conformance/scripts/archive_perf_smoke.py {{logfile}} target/perf-smoke-baselines {{label}} {{cpuinfo}}

perf-smoke-kvm-archive label='kvm-host':
  bash -lc 'set -euo pipefail; just perf-smoke-kvm >/dev/null; PYTHONDONTWRITEBYTECODE=1 python tools/axle-conformance/scripts/archive_perf_smoke.py target/perf-smoke-kvm/serial.log target/perf-smoke-baselines {{label}} /proc/cpuinfo'

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
