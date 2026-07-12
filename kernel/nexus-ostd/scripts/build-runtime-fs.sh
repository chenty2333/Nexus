#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_source_sha=c5a4014d88794ddccd1c5239957a43500a6637a433640c2293e699fea72b870f

die() {
    echo "runtime fs build: FAIL: $*" >&2
    exit 1
}

sha_file() {
    sha256sum "$1" | cut -d ' ' -f1
}

if (( $# < 1 || $# > 2 )); then
    die "usage: $0 OUTPUT_ELF [EXPECTED_ARTIFACT_SHA]"
fi

output=$1
expected_artifact_sha=${2-}
source_file=${NEXUS_RUNTIME_FS_SOURCE:-/repo/tests/guest/linux/sources/linux-runtime-fs-smoke/runtime_fs_smoke.S}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
oracle=${NEXUS_RUNTIME_FS_ARTIFACT_ORACLE:-$script_dir/assert-runtime-fs-artifacts.sh}

for command_name in bash clang cmp cp cut dirname mkdir mktemp rm sha256sum; do
    command -v "$command_name" >/dev/null 2>&1 || die "missing command: $command_name"
done
[[ -f "$source_file" && ! -L "$source_file" ]] ||
    die "missing retained regular source: $source_file"
[[ -f "$oracle" && ! -L "$oracle" ]] || die "missing artifact oracle: $oracle"

assert_artifact() {
    local artifact=$1

    if (( $# == 2 )); then
        bash "$oracle" "$source_file" "$artifact" "$2"
    elif (( $# == 1 )); then
        bash "$oracle" "$source_file" "$artifact"
    else
        die 'internal artifact assertion argument mismatch'
    fi
}

actual_source_sha=$(sha_file "$source_file")
[[ "$actual_source_sha" == "$expected_source_sha" ]] ||
    die "retained source SHA mismatch expected=$expected_source_sha actual=$actual_source_sha file=$source_file"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fixed_source="$tmp/linux-runtime-fs-smoke.S"
elf="$tmp/linux-runtime-fs-smoke.elf"

# A fixed basename prevents STT_FILE metadata from depending on whether the
# immutable input arrived through /repo or a Docker COPY location.
cp "$source_file" "$fixed_source"
cmp -s "$source_file" "$fixed_source" || die 'fixed-name source copy differs from retained input'
[[ $(sha_file "$fixed_source") == "$expected_source_sha" ]] ||
    die 'fixed-name source copy failed its immutable digest gate'

(
    cd "$tmp"
    clang \
        --target=x86_64-unknown-linux-gnu \
        -c \
        -fno-pie \
        linux-runtime-fs-smoke.S \
        -o linux-runtime-fs-smoke.o
    clang \
        --target=x86_64-unknown-linux-gnu \
        -nostdlib \
        -static \
        -fno-pie \
        -Wl,-no-pie \
        -Wl,--entry=_start \
        -Wl,--build-id=none \
        -Wl,-z,noexecstack \
        -Wl,-z,max-page-size=4096 \
        linux-runtime-fs-smoke.o \
        -o linux-runtime-fs-smoke.elf
)

# Omitting the expected digest uses the oracle's checked-in pin. Passing an
# explicitly empty digest deliberately fails after printing the reproducible
# candidate. No output is published until the independent oracle accepts it.
if (( $# == 2 )); then
    assert_artifact "$elf" "$expected_artifact_sha"
else
    assert_artifact "$elf"
fi

output_parent=$(dirname "$output")
mkdir -p "$output_parent"
[[ ! -L "$output" ]] || die "refusing to replace symlink output: $output"
cp "$elf" "$output"
if (( $# == 2 )); then
    assert_artifact "$output" "$expected_artifact_sha" >/dev/null
else
    assert_artifact "$output" >/dev/null
fi

artifact_sha=$(sha_file "$output")
echo "runtime fs build: PASS source_sha=$expected_source_sha artifact_sha=$artifact_sha fixed_source=linux-runtime-fs-smoke.S artifact=static-et-exec oracle=structural+digest output=$output"
