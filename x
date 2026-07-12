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
cser_spike="$root/experiments/ostd-cser-spike/x"
io_spike="$root/experiments/ostd-virtio-cser-spike/x"
composition_oracle="$root/experiments/ostd-cser-spike/scripts/assert-composition.sh"

usage() {
    cat >&2 <<'EOF'
usage: ./x {fmt|check|test|model|spec|spike|io-spike|composition|verify|clean}

  fmt      format the Rust workspaces in the pinned development image
  check    check the no_std and std reference-model configurations
  test     run the reference-model test suite
  model    run every reference-model verification gate
  spec     check PlusCal translation drift and run TLC
  spike    run the pinned OSTD five-domain composition/Linux QEMU spike
  io-spike run the pinned mediated VirtIO/reset/IOTLB QEMU spike
  composition
           cross-check retained OSTD and VirtIO logs for component consistency
  verify   run every model/spec/spike gate and the system composition oracle
  clean    remove root and both OSTD-spike build artifacts
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
    local entrypoint=$1
    local description=$2
    if [[ ! -x "$entrypoint" ]]; then
        echo "$description entrypoint is missing or not executable: $entrypoint" >&2
        exit 1
    fi
    "$entrypoint" test
}

expect_composition_reject() {
    local label=$1
    local composition_log=$2
    local virtio_log=$3
    if "$composition_oracle" "$composition_log" "$virtio_log" >/dev/null 2>&1; then
        echo "system composition oracle accepted negative mutation: $label" >&2
        return 1
    fi
    echo "system composition negative assertion: PASS $label=rejected"
}

run_composition_oracle() {
    local composition_log="$root/experiments/ostd-cser-spike/artifacts/serial.log"
    local virtio_log="$root/experiments/ostd-virtio-cser-spike/artifacts/kernel.log"
    local artifact="$root/target/verification/system-composition-oracle.log"

    mkdir -p "$(dirname "$artifact")"
    {
        if [[ ! -x "$composition_oracle" ]]; then
            echo "system composition oracle is missing or not executable: $composition_oracle" >&2
            exit 1
        fi
        if [[ ! -s "$composition_log" ]]; then
            echo "OSTD composition log is missing or empty: $composition_log" >&2
            exit 1
        fi
        if [[ ! -s "$virtio_log" ]]; then
            echo "mediated VirtIO kernel log is missing or empty: $virtio_log" >&2
            exit 1
        fi
        "$composition_oracle" "$composition_log" "$virtio_log"

        local mutation_dir
        mutation_dir=$(mktemp -d)
        trap 'rm -rf "$mutation_dir"' EXIT

        cp "$composition_log" "$mutation_dir/composition-duplicate-pass.log"
        grep -F -m1 'COMPOSITION_SLICE PASS ' "$composition_log" \
            >>"$mutation_dir/composition-duplicate-pass.log"
        expect_composition_reject \
            duplicate_composition_pass \
            "$mutation_dir/composition-duplicate-pass.log" \
            "$virtio_log"

        awk '
            !changed && /^COMPOSITION_REJECT / && /kind=stale_receipt/ {
                changed = sub(/mutation=false/, "mutation=true")
            }
            { print }
            END { if (!changed) exit 1 }
        ' "$composition_log" >"$mutation_dir/composition-stale-receipt.log"
        expect_composition_reject \
            mutating_stale_receipt \
            "$mutation_dir/composition-stale-receipt.log" \
            "$virtio_log"

        awk '
            !changed && /^COMPOSITION_CLOSURE (Issue|Receipt) / {
                changed = sub(/receipt_sequence=[0-9]+/, "receipt_sequence=999")
            }
            { print }
            END { if (!changed) exit 1 }
        ' "$composition_log" >"$mutation_dir/composition-wrong-sequence.log"
        expect_composition_reject \
            wrong_closure_sequence \
            "$mutation_dir/composition-wrong-sequence.log" \
            "$virtio_log"

        awk '
            !changed && /RESET Fence old_generation=2 new_generation=3/ {
                changed = sub(/new_generation=3/, "new_generation=4")
            }
            { print }
            END { if (!changed) exit 1 }
        ' "$virtio_log" >"$mutation_dir/virtio-wrong-generation.log"
        expect_composition_reject \
            wrong_virtio_generation \
            "$composition_log" \
            "$mutation_dir/virtio-wrong-generation.log"
    } 2>&1 | tee "$artifact"
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
        run_spike "$cser_spike" "OSTD five-domain composition/Linux spike"
        ;;
    io-spike)
        require_docker
        run_spike "$io_spike" "OSTD mediated VirtIO spike"
        ;;
    composition)
        run_composition_oracle
        ;;
    verify)
        require_docker
        run_xtask verify
        # These are intentionally host-side. Each OSTD spike owns a separate,
        # pinned OSDK image, so the root container never starts Docker.
        run_spike "$cser_spike" "OSTD five-domain composition/Linux spike"
        run_spike "$io_spike" "OSTD mediated VirtIO spike"
        run_composition_oracle
        ;;
    clean)
        # Cleaning must remain available before Docker is installed and must
        # never pull or build an image merely to remove host-owned artifacts.
        clean_root
        "$cser_spike" clean
        "$io_spike" clean
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 2
        ;;
esac
