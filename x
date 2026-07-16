#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "$0")" && pwd)
image=
kernel_backend="$root/kernel/nexus-ostd/x"
virtio_backend="$root/experiments/ostd-virtio-cser-spike/x"
composition_backend="$root/tools/workflow/system-composition.sh"
root_image_ready=false
backend_rebuild=
repo_lock="/tmp/nexus-workflow-${root//\//_}.lock"

usage() {
    cat >&2 <<'EOF'
usage: ./x COMMAND [TARGET]

Public commands:
  doctor                 validate Docker, repository layout, and pinned tools
  build [all|model|kernel|virtio]
                         build the selected artifact graph (default: all)
  test [--unit|--quick|--system|--full]
                         run a verification tier (default: --unit)
  run [composition|kernel|virtio]
                         run a QEMU receipt (default: composition)
  verify                 run the complete model/spec/QEMU/composition gate
  verify-bundle [DIRECTORY]
                         verify an existing evidence bundle without QEMU
  clean [--all]          remove build caches; --all also removes run evidence

Focused commands:
  fmt                     format Rust workspaces
  check                   run schema and Rust static checks
  quick                   run all non-TLA+, non-QEMU verification
  model                   alias for the complete reference-model gate
  spec                    check PlusCal drift and run all TLC families
  system                  run both QEMU receipts and composition oracle
  research production-identity
                          run the prospective v0.2 formal identity gate
  research handoff-admission
                          run the prospective RFC-0002 local handoff gate
EOF
}

die() {
    echo "x: $*" >&2
    exit 2
}

require_no_args() {
    if (( $# != 0 )); then
        die "unexpected arguments: $*"
    fi
}

require_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "docker is required to run Nexus workflows" >&2
        exit 1
    fi
}

require_command() {
    local command=$1
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required host command is unavailable: $command" >&2
        exit 1
    fi
}

acquire_repo_lock() {
    exec 9>"$repo_lock"
    flock 9
    export NEXUS_ROOT_LOCK_HELD=1
}

compute_image_identity() {
    if [[ -n $image ]]; then
        return
    fi
    local image_key
    image_key=$(sha256sum \
        "$root/Dockerfile" \
        "$root/.dockerignore" \
        "$root/third_party/tlaplus/1.8.0-227f61b/tla2tools-227f61b.jar" \
        "$root/third_party/tlaplus/1.8.0-227f61b/SHA256SUMS" \
        "$root/third_party/tlaplus/1.8.0-227f61b/PROVENANCE.json" \
        "$root/third_party/tlaplus/1.8.0-227f61b/LICENSE.upstream" \
        "$root/rust-toolchain.toml" \
        "$root/.cargo/config.toml" \
        "$root/Cargo.toml" \
        "$root/Cargo.lock" \
        "$root/crates/cser-model/Cargo.toml" \
        "$root/crates/cser-transition-gates/Cargo.toml" \
        "$root/crates/nexus-effect-peer/Cargo.toml" \
        "$root/tools/xtask/Cargo.toml" \
        "$root/tools/xtask/Cargo.lock" | cut -d ' ' -f1 | sha256sum | cut -c1-16)
    image="nexus/cser-dev:$image_key"
}

build_image() {
    local -a rebuild_args=()
    if [[ ${NEXUS_REBUILD:-0} == 1 ]]; then
        rebuild_args=(--no-cache)
    fi
    compute_image_identity
    docker build \
        "${rebuild_args[@]}" \
        --platform linux/amd64 \
        --tag "$image" \
        "$root"
}

ensure_image() {
    if [[ $root_image_ready == true ]]; then
        return
    fi
    compute_image_identity
    if [[ ${NEXUS_REBUILD:-0} == 1 ]] ||
        ! docker image inspect "$image" >/dev/null 2>&1; then
        build_image
    fi
    root_image_ready=true
}

run_xtask() {
    local command=$1
    shift
    local -a token_environment=()
    if [[ $command == begin || $command == complete || $command == manifest ]]; then
        if [[ ! ${verify_token:-} =~ ^[0-9a-f]{64}$ ]]; then
            echo "internal verification token is unavailable for $command" >&2
            exit 1
        fi
        token_environment=(--env "NEXUS_VERIFY_TOKEN=$verify_token")
    fi
    ensure_image
    docker run --rm \
        --init \
        --platform linux/amd64 \
        --network none \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp/nexus-home \
        --tmpfs /tmp/nexus-home:rw,exec,nosuid,size=64m,mode=1777 \
        --env CARGO_TARGET_DIR=/work/target/cargo \
        --env "NEXUS_REBUILD=${NEXUS_REBUILD:-0}" \
        --env "NEXUS_VERIFY_INVOCATION=${NEXUS_VERIFY_INVOCATION:-}" \
        "${token_environment[@]}" \
        --volume "$root:/work:z" \
        --mount "type=bind,source=$root/Cargo.lock,target=/work/Cargo.lock,readonly" \
        --mount "type=bind,source=$root/tools/xtask/Cargo.lock,target=/work/tools/xtask/Cargo.lock,readonly" \
        --workdir /work \
        "$image" \
        cargo run --quiet --locked --manifest-path tools/xtask/Cargo.toml -- "$command" "$@"
}

run_backend() {
    local entrypoint=$1
    local backend_command=$2
    local description=$3
    local rebuild=${backend_rebuild:-${NEXUS_REBUILD:-0}}
    if [[ ! -x "$entrypoint" ]]; then
        echo "$description entrypoint is missing or not executable: $entrypoint" >&2
        exit 1
    fi
    NEXUS_REBUILD=$rebuild "$entrypoint" "$backend_command"
}

prepare_cold_backend_images() {
    if [[ ${NEXUS_REBUILD:-0} != 1 ]]; then
        return
    fi
    backend_rebuild=1
    run_backend "$kernel_backend" image "Nexus OSTD kernel image"
    run_backend "$virtio_backend" image "OSTD mediated VirtIO image"
    # Every later backend process resolves the same content-addressed tag while
    # the repository lock prevents its input set from changing.
    backend_rebuild=0
}

run_composition_oracle() {
    bash "$composition_backend"
}

run_system() {
    run_backend "$kernel_backend" test "Nexus OSTD kernel"
    run_backend "$virtio_backend" test "OSTD mediated VirtIO"
    run_composition_oracle
}

run_same_boot_acceptance() {
    run_backend "$kernel_backend" test-same-boot "Nexus same-boot production filesystem"
    run_backend "$kernel_backend" test-same-boot-precommit "Nexus same-boot precommit revocation"
}

check_host_shell_sources() {
    local count=0
    local interpreter
    local relative
    local shebang
    while IFS= read -r -d '' relative; do
        if [[ ! -f "$root/$relative" ]]; then
            continue
        fi
        case "$relative" in
            x|*/x|*.sh) ;;
            *) continue ;;
        esac
        shebang=$(head -n 1 "$root/$relative")
        if [[ $shebang == *bash* ]]; then
            interpreter=bash
        elif [[ $shebang == *'/sh'* ]]; then
            interpreter=sh
        else
            echo "workflow shell source has no supported shebang: $relative" >&2
            exit 1
        fi
        "$interpreter" -n "$root/$relative"
        ((count += 1))
    done < <(git -C "$root" ls-files -z --cached --others --exclude-standard)
    if (( count == 0 )); then
        echo 'no shell workflow sources were discovered' >&2
        exit 1
    fi
    echo "HOST SHELL PASS sources=$count"
}

run_quick() {
    check_host_shell_sources
    run_xtask quick
    run_backend "$kernel_backend" check "Nexus OSTD kernel"
    run_backend "$virtio_backend" check "OSTD mediated VirtIO"
}

run_check() {
    check_host_shell_sources
    run_xtask check
    run_backend "$kernel_backend" check "Nexus OSTD kernel"
    run_backend "$virtio_backend" check "OSTD mediated VirtIO"
}

run_format() {
    run_xtask fmt
    run_backend "$kernel_backend" fmt "Nexus OSTD kernel"
    run_backend "$virtio_backend" fmt "OSTD mediated VirtIO"
}

verify_all() {
    local invocation=$1
    local verify_token
    verify_token=$(head -c 32 /dev/urandom | sha256sum | cut -d ' ' -f1)
    if [[ ! $verify_token =~ ^[0-9a-f]{64}$ ]]; then
        echo 'failed to generate the verification orchestration token' >&2
        exit 1
    fi
    export NEXUS_VERIFY_INVOCATION=$invocation
    require_docker
    check_host_shell_sources
    run_xtask begin
    run_xtask verify
    prepare_cold_backend_images
    # OSDK images remain host-side backends; the root verification image never
    # receives access to the Docker socket.
    run_system
    run_same_boot_acceptance
    run_backend "$kernel_backend" eval-stage7b "Nexus Stage 7B evaluator"
    run_xtask stage7b-evidence
    run_xtask complete
    run_xtask manifest
    run_xtask bundle
}

doctor_host() {
    for command in \
        awk bash chmod cp cut diff docker flock git grep head id mkdir mkfifo \
        mktemp rm sed sh sha256sum tail tee timeout tr wc; do
        require_command "$command"
    done
    docker info >/dev/null
    for entrypoint in \
        "$root/x" \
        "$kernel_backend" \
        "$virtio_backend" \
        "$composition_backend"; do
        if [[ ! -x "$entrypoint" ]]; then
            echo "required workflow entrypoint is missing or not executable: $entrypoint" >&2
            exit 1
        fi
    done
    echo "DOCTOR HOST PASS docker=true entrypoints=4 public_frontdoor=./x"
    run_xtask doctor
    run_backend "$kernel_backend" doctor "Nexus OSTD kernel"
    run_backend "$virtio_backend" doctor "OSTD mediated VirtIO"
}

clean_cache() {
    rm -rf \
        "$root/target/.rustc_info.json" \
        "$root/target/cargo" \
        "$root/target/debug" \
        "$root/target/docker" \
        "$root/target/release-api-test" \
        "$root/target/review" \
        "$root/target/tmp" \
        "$root/target/x86_64-unknown-none" \
        "$root/tools/xtask/target" \
        "$root/crates/nexus-ostd-virtio/target" \
        "$root/kernel/nexus-ostd/target" \
        "$root/kernel/nexus-ostd/userspace/personality/target" \
        "$root/experiments/ostd-virtio-cser-spike/target" \
        "$root/experiments/ostd-virtio-cser-spike/patch-work" \
        "$root/specs/cser/states"
    rm -f \
        "$root"/kernel/nexus-ostd/guest/*.bin \
        "$root"/kernel/nexus-ostd/guest/*.elf \
        "$root"/specs/cser/*_TTrace_*.bin \
        "$root"/specs/cser/*_TTrace_*.tla \
        "$root"/specs/cser/*.old
    echo 'CLEAN CACHE PASS evidence=preserved release=preserved docker_images=preserved'
}

clean_evidence() {
    rm -rf \
        "$root/target/scenario-artifacts" \
        "$root/target/verification" \
        "$root/target/research" \
        "$root/kernel/nexus-ostd/artifacts" \
        "$root/experiments/ostd-virtio-cser-spike/artifacts"
    echo 'CLEAN EVIDENCE PASS release=preserved docker_images=preserved'
}

command=${1:-}
if (( $# > 0 )); then
    shift
fi
case "$command" in
    doctor|build|test|run|fmt|check|quick|model|spec|system|research|verify|verify-bundle|clean)
        acquire_repo_lock
        ;;
esac
case "$command" in
    doctor)
        require_no_args "$@"
        require_docker
        doctor_host
        ;;
    build)
        require_docker
        target=${1:-all}
        if (( $# > 1 )); then
            die "build accepts at most one target"
        fi
        case "$target" in
            all)
                run_xtask build
                run_backend "$kernel_backend" build "Nexus OSTD kernel"
                run_backend "$virtio_backend" build "OSTD mediated VirtIO"
                ;;
            model) run_xtask build ;;
            kernel) run_backend "$kernel_backend" build "Nexus OSTD kernel" ;;
            virtio) run_backend "$virtio_backend" build "OSTD mediated VirtIO" ;;
            *) die "unknown build target: $target" ;;
        esac
        ;;
    test)
        require_docker
        profile=${1:---unit}
        if (( $# > 1 )); then
            die "test accepts at most one profile"
        fi
        case "$profile" in
            --unit) run_xtask test ;;
            --quick) run_quick ;;
            --system) run_system ;;
            --full) verify_all "./x test --full" ;;
            *) die "unknown test profile: $profile" ;;
        esac
        ;;
    run)
        require_docker
        target=${1:-composition}
        if (( $# > 1 )); then
            die "run accepts at most one target"
        fi
        case "$target" in
            composition) run_system ;;
            kernel) run_backend "$kernel_backend" run "Nexus OSTD kernel" ;;
            virtio) run_backend "$virtio_backend" run "OSTD mediated VirtIO" ;;
            *) die "unknown run target: $target" ;;
        esac
        ;;
    fmt)
        require_no_args "$@"
        require_docker
        run_format
        ;;
    check)
        require_no_args "$@"
        require_docker
        run_check
        ;;
    quick)
        require_no_args "$@"
        require_docker
        run_quick
        ;;
    model|spec)
        require_no_args "$@"
        require_docker
        run_xtask "$command"
        ;;
    system)
        require_no_args "$@"
        require_docker
        run_system
        ;;
    research)
        require_docker
        if (( $# != 1 )); then
            die "research requires exactly one target: production-identity or handoff-admission"
        fi
        case "$1" in
            production-identity) run_xtask research production-identity ;;
            handoff-admission) run_xtask research handoff-admission ;;
            *) die "unknown research target: $1" ;;
        esac
        ;;
    verify)
        require_no_args "$@"
        verify_all "./x verify"
        ;;
    verify-bundle)
        if (( $# > 1 )); then
            die "verify-bundle accepts at most one directory"
        fi
        bundle=${1:-target/verification/artifact-bundle}
        if [[ $bundle == /* || $bundle == .. || $bundle == ../* || $bundle == */../* || $bundle == */.. ]]; then
            die "verify-bundle directory must stay within the repository"
        fi
        require_docker
        run_xtask verify-bundle "$bundle"
        ;;
    clean)
        # Cleaning must remain available before Docker is installed and must
        # never pull or build an image merely to remove host-owned artifacts.
        mode=${1:-cache}
        if (( $# > 1 )); then
            die "clean accepts at most one option: --all"
        fi
        case "$mode" in
            cache) clean_cache ;;
            --all)
                clean_cache
                clean_evidence
                ;;
            *) die "unknown clean option: $mode" ;;
        esac
        ;;
    -h|--help|help)
        require_no_args "$@"
        usage
        ;;
    *)
        usage
        exit 2
        ;;
esac
