#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "$0")" && pwd)
image=
kernel_backend="$root/kernel/nexus-ostd/x"
root_image_ready=false
repo_lock="/tmp/nexus-workflow-${root//\//_}.lock"

usage() {
    cat >&2 <<'EOF'
usage: ./x COMMAND [TARGET]

Public commands:
  doctor                 validate Docker, repository layout, and pinned tools
  build [all|model|kernel]
                         build the selected artifact graph (default: all)
  test [--unit|--quick|--system|--full]
                         run a verification tier (default: --unit)
  run [kernel]            run the combined reply/DMA and four-boot recovery receipt
  verify                 seal the clean-revision core/oracle/Loom/production gate
  clean [--all]          remove build caches; --all also removes run evidence

Focused commands:
  fmt                     format Rust workspaces
  check                   run schema and Rust static checks
  quick                   run current non-QEMU verification
  model                   alias for the current host semantic gate
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
        "$root/rust-toolchain.toml" \
        "$root/.cargo/config.toml" \
        "$root/Cargo.toml" \
        "$root/Cargo.lock" \
        "$root/crates/cser-core/Cargo.toml" \
        "$root/crates/cser-model/Cargo.toml" \
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
    local -a git_mount=()
    local git_common_dir
    if [[ -f "$root/.git" ]]; then
        if ! git_common_dir=$(git -C "$root" rev-parse --path-format=absolute --git-common-dir) ||
            [[ ! -d $git_common_dir || $git_common_dir == *:* ]]; then
            echo "cannot resolve a mountable Git common directory for linked worktree: $root" >&2
            exit 1
        fi
        git_mount=(
            --volume "$git_common_dir:$git_common_dir:ro,z"
        )
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
        --volume "$root:/work:z" \
        "${git_mount[@]}" \
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
    local rebuild=${NEXUS_REBUILD:-0}
    if [[ ! -x "$entrypoint" ]]; then
        echo "$description entrypoint is missing or not executable: $entrypoint" >&2
        exit 1
    fi
    NEXUS_REBUILD=$rebuild "$entrypoint" "$backend_command"
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

check_host_cser_experiment() {
    require_command python3
    python3 -m unittest discover \
        -s "$root/kernel/nexus-ostd/tools/cser-experiment/tests" \
        -v
}

run_quick() {
    check_host_shell_sources
    check_host_cser_experiment
    run_xtask quick
    run_backend "$kernel_backend" check "Nexus OSTD kernel"
}

run_check() {
    check_host_shell_sources
    check_host_cser_experiment
    run_xtask check
    run_backend "$kernel_backend" check "Nexus OSTD kernel"
}

run_format() {
    run_xtask fmt
    run_backend "$kernel_backend" fmt "Nexus OSTD kernel"
}

verify_all() {
    require_docker
    check_host_shell_sources
    check_host_cser_experiment
    run_xtask verify
    # The production acceptance path exercises the focused reply/DMA guests,
    # then one recovered core owner across four real QEMU boots with the same
    # journal, outbox, and swtpm state.
    run_backend "$kernel_backend" seal-core-persistent-recovery "Nexus CSER core persistent production"
}

doctor_host() {
    for command in \
        awk bash chmod cp cut diff docker flock git grep head id mkdir mkfifo \
        mktemp rm sed sh sha256sum tail tee timeout tr wc; do
        require_command "$command"
    done
    docker info >/dev/null
    for entrypoint in "$root/x" "$kernel_backend"; do
        if [[ ! -x "$entrypoint" ]]; then
            echo "required workflow entrypoint is missing or not executable: $entrypoint" >&2
            exit 1
        fi
    done
    echo "DOCTOR HOST PASS docker=true entrypoints=2 public_frontdoor=./x"
    run_xtask doctor
    run_backend "$kernel_backend" doctor "Nexus OSTD kernel"
}

clean_cache() {
    rm -rf \
        "$root/target/.rustc_info.json" \
        "$root/target/cargo" \
        "$root/target/debug" \
        "$root/target/doc" \
        "$root/target/docker" \
        "$root/target/release-api-test" \
        "$root/target/review" \
        "$root/target/tmp" \
        "$root/target/x86_64-unknown-none" \
        "$root/tools/xtask/target" \
        "$root/crates/nexus-ostd-virtio/target" \
        "$root/kernel/nexus-ostd/target" \
        "$root/kernel/nexus-ostd/userspace/personality/target" \
        "$root/crates/nexus-ostd-virtio/target"
    rm -f \
        "$root"/kernel/nexus-ostd/guest/*.bin \
        "$root"/kernel/nexus-ostd/guest/*.elf
    echo 'CLEAN CACHE PASS evidence=preserved release=preserved docker_images=preserved'
}

clean_evidence() {
    rm -rf \
        "$root/target/scenario-artifacts" \
        "$root/target/verification" \
        "$root/target/research" \
        "$root/kernel/nexus-ostd/artifacts"
    echo 'CLEAN EVIDENCE PASS release=preserved docker_images=preserved'
}

command=${1:-}
if (( $# > 0 )); then
    shift
fi
case "$command" in
    doctor|build|test|run|fmt|check|quick|model|verify|clean)
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
                ;;
            model) run_xtask build ;;
            kernel) run_backend "$kernel_backend" build "Nexus OSTD kernel" ;;
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
            --system)
                run_backend "$kernel_backend" run-core-persistent-recovery \
                    "Nexus CSER core persistent production"
                ;;
            --full) verify_all ;;
            *) die "unknown test profile: $profile" ;;
        esac
        ;;
    run)
        require_docker
        target=${1:-kernel}
        if (( $# > 1 )); then
            die "run accepts at most one target"
        fi
        case "$target" in
            kernel)
                run_backend "$kernel_backend" run-core-persistent-recovery \
                    "Nexus CSER core persistent production"
                ;;
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
    model)
        require_no_args "$@"
        require_docker
        run_xtask "$command"
        ;;
    verify)
        require_no_args "$@"
        verify_all
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
