#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
image_key=$(sha256sum \
    "$root/Dockerfile" \
    "$root/.dockerignore" \
    "$root/rust-toolchain.toml" \
    "$root/.cargo/config.toml" \
    "$root/Cargo.toml" \
    "$root/Cargo.lock" \
    "$root/crates/cser-model/Cargo.toml" \
    "$root/tools/xtask/Cargo.toml" \
    "$root/tools/xtask/Cargo.lock" | cut -d ' ' -f1 | sha256sum | cut -c1-16)
image="nexus/cser-dev:$image_key"
spike="$root/experiments/ostd-cser-spike/x"

usage() {
    cat >&2 <<'EOF'
usage: ./x {fmt|check|test|model|spec|spike|verify|clean}

  fmt      format the Rust workspaces in the pinned development image
  check    check the no_std and std reference-model configurations
  test     run the reference-model test suite
  model    run every reference-model verification gate
  spec     check PlusCal translation drift and run TLC
  spike    run the pinned OSTD scheduler/fallback QEMU spike
  verify   run model, spec, and spike gates
  clean    remove root and OSTD-spike build artifacts
EOF
}

require_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "docker is required to run Nexus workflows" >&2
        exit 1
    fi
}

build_image() {
    docker build \
        --platform linux/amd64 \
        --tag "$image" \
        "$root"
}

ensure_image() {
    if [[ ${NEXUS_REBUILD:-0} == 1 ]] || ! docker image inspect "$image" >/dev/null 2>&1; then
        build_image
    fi
}

run_xtask() {
    local command=$1
    ensure_image
    docker run --rm \
        --platform linux/amd64 \
        --network none \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp/nexus-home \
        --tmpfs /tmp/nexus-home:rw,exec,nosuid,size=64m,mode=1777 \
        --env CARGO_TARGET_DIR=/work/target/docker \
        --volume "$root:/work:z" \
        --mount "type=bind,source=$root/Cargo.lock,target=/work/Cargo.lock,readonly" \
        --mount "type=bind,source=$root/tools/xtask/Cargo.lock,target=/work/tools/xtask/Cargo.lock,readonly" \
        --workdir /work \
        "$image" \
        cargo run --quiet --locked --manifest-path tools/xtask/Cargo.toml -- "$command"
}

run_spike() {
    if [[ ! -x "$spike" ]]; then
        echo "OSTD spike entrypoint is missing or not executable: $spike" >&2
        exit 1
    fi
    "$spike" test
}

clean_root() {
    rm -rf \
        "$root/target" \
        "$root/tools/xtask/target" \
        "$root/specs/cser/states"
    rm -f \
        "$root"/specs/cser/*_TTrace_*.bin \
        "$root"/specs/cser/*_TTrace_*.tla \
        "$root"/specs/cser/*.old
}

command=${1:-}
case "$command" in
    fmt|check|test|model|spec)
        require_docker
        run_xtask "$command"
        ;;
    spike)
        require_docker
        run_spike
        ;;
    verify)
        require_docker
        run_xtask verify
        # This is intentionally host-side. The OSTD spike owns a separate,
        # pinned OSDK image, so the root container never starts Docker.
        run_spike
        ;;
    clean)
        # Cleaning must remain available before Docker is installed and must
        # never pull or build an image merely to remove host-owned artifacts.
        clean_root
        "$spike" clean
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 2
        ;;
esac
